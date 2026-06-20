// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build !linux

package operator

import (
	"errors"
	"net"
	"testing"
)

// TestPeerCredFailsClosedOffLinux asserts the must-fix invariant: off Linux there
// is no SO_PEERCRED, so peerCredOf returns ErrPeerCredUnavailable and admits
// NOTHING. A dev fallback to a body-supplied id would be a privilege-escalation
// seam (NFR-SEC-43); this proves the attested-identity source is simply
// unreachable off Linux rather than degrading to a permissive default.
func TestPeerCredFailsClosedOffLinux(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })

	if _, err := peerCredOf(c1); !errors.Is(err, ErrPeerCredUnavailable) {
		t.Fatalf("peerCredOf off Linux = %v; want ErrPeerCredUnavailable (fail-closed)", err)
	}

	// connCredOf must propagate the fail-closed cause, so the listener refuses the
	// connection rather than carrying an attested ConnInfo.
	if _, err := connCredOf(c1); !errors.Is(err, ErrPeerCredUnavailable) {
		t.Fatalf("connCredOf off Linux = %v; want ErrPeerCredUnavailable (fail-closed)", err)
	}
}
