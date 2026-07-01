// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux

package operator

import (
	"fmt"
	"net"
	"syscall"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
)

// peerCredOf reads the kernel-vouched peer credentials of a Unix-socket
// connection via SO_PEERCRED. The kernel stamps the connecting peer's uid, gid,
// and pid onto the socket at connect time; reading them here means the identity
// is attested by the kernel, never asserted by the request. A non-Unix conn or a
// getsockopt failure returns the error so the resolver fails closed
// (ingress.ErrUnattested) — there is NO body fallback on this path.
//
// This file is the Linux half of a build-tagged pair: peercred_other.go provides
// the same function off Linux and returns ErrPeerCredUnavailable so a non-Linux
// build admits nothing. The dev-fallback-to-a-body-id escalation the design warns
// against is therefore unreachable under any production (Linux) build.
func peerCredOf(conn net.Conn) (ingress.PeerCred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		// The operator listener only ever accepts Unix-socket connections; a
		// non-Unix conn here is a wiring fault, refused fail-closed.
		return ingress.PeerCred{}, fmt.Errorf("%w: connection is not a Unix socket", ErrPeerCredUnavailable)
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return ingress.PeerCred{}, fmt.Errorf("%w: obtain raw conn: %w", ErrPeerCredUnavailable, err)
	}

	var (
		cred    *syscall.Ucred
		credErr error
	)
	// Control runs the getsockopt against the live socket fd under the runtime's
	// fd guard, so the fd cannot be closed out from under the call.
	if ctrlErr := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); ctrlErr != nil {
		return ingress.PeerCred{}, fmt.Errorf("%w: control fd: %w", ErrPeerCredUnavailable, ctrlErr)
	}
	if credErr != nil {
		return ingress.PeerCred{}, fmt.Errorf("%w: getsockopt SO_PEERCRED: %w", ErrPeerCredUnavailable, credErr)
	}
	if cred == nil {
		// Defensive: a nil cred with no error should not occur, but a nil here would
		// otherwise panic; treat it as unattested.
		return ingress.PeerCred{}, fmt.Errorf("%w: kernel returned no peer credentials", ErrPeerCredUnavailable)
	}

	return ingress.PeerCred{
		UID: cred.Uid,
		GID: cred.Gid,
		PID: cred.Pid,
	}, nil
}
