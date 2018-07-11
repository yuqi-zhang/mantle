// Copyright 2018 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"

	"github.com/coreos/mantle/kola/cluster"
	"github.com/coreos/mantle/kola/register"
	"github.com/coreos/mantle/lang/worker"
	"github.com/coreos/mantle/platform"
)

// simplifiedCrioInfo represents the results from crio info
type simplifiedCrioInfo struct {
	StorageDriver string `json:"storage_driver"`
	StorageRoot   string `json:"storage_root"`
	CgroupDriver  string `json:"cgroup_driver"`
}

// init runs when the package is imported and takes care of registering tests
func init() {
	register.Register(&register.Test{
		Run:         crioBaseTests,
		ClusterSize: 1,
		Name:        `crio.base`,
		Distros:     []string{"rhcos"},
	})
	register.Register(&register.Test{
		Run:         crioNetwork,
		ClusterSize: 2,
		Name:        "crio.network",
		Distros:     []string{"rhcos"},
	})

}

// genContainer makes a container out of binaries on the host. This function uses podman
func genContainer(c cluster.TestCluster, m platform.Machine, name string, binnames []string) {
	// TODO: do we need to copy the build into cri-o?
	cmd := `tmpdir=$(mktemp -d); cd $tmpdir; echo -e "FROM scratch\nCOPY . /" > Dockerfile;
	        b=$(which %s); libs=$(sudo ldd $b | grep -o /lib'[^ ]*' | sort -u);
	        sudo rsync -av --relative --copy-links $b $libs ./;
	        sudo podman build -t %s .`

	c.MustSSH(m, fmt.Sprintf(cmd, strings.Join(binnames, " "), name))
}

// crioBaseTests executes multiple tests under the "base" name
func crioBaseTests(c cluster.TestCluster) {
	c.Run("crio-info", testCrioInfo)
	c.Run("networks-reliably", crioNetworksReliably)
}

// crioNetwork ensures that crio containers can make network connections outside of the host
func crioNetwork(c cluster.TestCluster) {
	machines := c.Machines()
	src, dest := machines[0], machines[1]

	c.Log("creating ncat containers")

	genContainer(c, src, "ncat", []string{"ncat"})
	genContainer(c, dest, "ncat", []string{"ncat"})

	// TODO: run with cri-o
	listener := func(ctx context.Context) error {
		// Will block until a message is recieved
		out, err := c.SSH(dest,
			`echo "HELLO FROM SERVER" | sudo podman run -i -p 9988:9988 ncat ncat --idle-timeout 20 --listen 0.0.0.0 9988`,
		)
		if err != nil {
			return err
		}

		if !bytes.Equal(out, []byte("HELLO FROM CLIENT")) {
			return fmt.Errorf("unexpected result from listener: %q", out)
		}

		return nil
	}

	// TODO: run with cri-o
	talker := func(ctx context.Context) error {
		// Wait until listener is ready before trying anything
		for {
			_, err := c.SSH(dest, "sudo lsof -i TCP:9988 -s TCP:LISTEN | grep 9988 -q")
			if err == nil {
				break // socket is ready
			}

			exit, ok := err.(*ssh.ExitError)
			if !ok || exit.Waitmsg.ExitStatus() != 1 { // 1 is the expected exit of grep -q
				return err
			}

			select {
			case <-ctx.Done():
				return fmt.Errorf("timeout waiting for server")
			default:
				time.Sleep(100 * time.Millisecond)
			}
		}

		srcCmd := fmt.Sprintf(`echo "HELLO FROM CLIENT" | sudo podman run -i ncat ncat %s 9988`, dest.PrivateIP())
		out, err := c.SSH(src, srcCmd)
		if err != nil {
			return err
		}

		if !bytes.Equal(out, []byte("HELLO FROM SERVER")) {
			return fmt.Errorf(`unexpected result from listener: "%v"`, out)
		}

		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := worker.Parallel(ctx, listener, talker); err != nil {
		c.Fatal(err)
	}
}

// crioNetworksReliably verifies that crio containers have a reliable network
func crioNetworksReliably(c cluster.TestCluster) {
	m := c.Machines()[0]

	genContainer(c, m, "ping", []string{"sh", "ping"})

	// TODO: Run with cri-o
	output := c.MustSSH(m, `for i in $(seq 1 10); do
		echo -n "$i: "
		sudo podman run --rm ping sh -c 'ping -i 0.2 172.17.0.1 -w 1 >/dev/null && echo PASS || echo FAIL'
	done`)

	numPass := strings.Count(string(output), "PASS")

	if numPass != 100 {
		c.Fatalf("Expected 10 passes, but output was: %s", output)
	}

}

// getCrioInfo parses and returns the information crio provides via socket
func getCrioInfo(c cluster.TestCluster, m platform.Machine) (simplifiedCrioInfo, error) {
	target := simplifiedCrioInfo{}
	crioInfoJson, err := c.SSH(m, `sudo curl -s --unix-socket /var/run/crio/crio.sock http://crio/info`)

	if err != nil {
		return target, fmt.Errorf("could not get info: %v", err)
	}

	err = json.Unmarshal(crioInfoJson, &target)
	if err != nil {
		return target, fmt.Errorf("could not unmarshal info %q into known json: %v", string(crioInfoJson), err)
	}
	return target, nil
}

// testCrioInfo test that crio info's output is as expected.
func testCrioInfo(c cluster.TestCluster) {
	m := c.Machines()[0]

	info, err := getCrioInfo(c, m)
	if err != nil {
		c.Fatal(err)
	}
	expectedStorageDriver := "overlay"
	if info.StorageDriver != expectedStorageDriver {
		c.Errorf("unexpected storage driver: %v != %v", expectedStorageDriver, info.StorageDriver)
	}
	expectedStorageRoot := "/var/lib/containers/storage"
	if info.StorageRoot != expectedStorageRoot {
		c.Errorf("unexpected storage root: %v != %v", expectedStorageRoot, info.StorageRoot)
	}
	expectedCgroupDriver := "systemd"
	if info.CgroupDriver != expectedCgroupDriver {
		c.Errorf("unexpected cgroup driver: %v != %v", expectedCgroupDriver, info.CgroupDriver)
	}

}
