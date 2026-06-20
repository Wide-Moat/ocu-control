// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux

package operator

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestPeerCredReadsAttestedCredsOnLinux asserts the Linux SO_PEERCRED path reads
// the kernel-vouched peer credential of a real Unix-socket connection: the uid the
// kernel reports for the connecting process equals this process's own uid, proving
// the credential is kernel-attested and not asserted by the peer. A non-Unix
// connection fails closed.
func TestPeerCredReadsAttestedCredsOnLinux(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sock := filepath.Join(dir, "t.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })

	cred, err := peerCredOf(server)
	if err != nil {
		t.Fatalf("peerCredOf on a Unix socket = %v; want a kernel-attested credential", err)
	}
	if cred.UID != uint32(os.Getuid()) {
		t.Fatalf("attested uid = %d; want this process's uid %d", cred.UID, os.Getuid())
	}

	// A non-Unix connection has no SO_PEERCRED to read: fail closed.
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	if _, err := peerCredOf(c1); err == nil {
		t.Fatal("peerCredOf on a non-Unix conn returned nil; want a fail-closed error")
	}
}
