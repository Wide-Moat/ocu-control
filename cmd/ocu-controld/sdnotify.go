// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// sd_notify — the dependency-free systemd readiness/stopping notifier.
//
// The contrib/systemd unit declares Type=notify / NotifyAccess=main, which tells
// systemd to hold the unit in the "activating" state until the daemon reports
// READY=1 over its NOTIFY_SOCKET, and to expect STOPPING=1 the moment a
// host-initiated stop begins. This file makes the daemon code honour that
// contract WITHOUT pulling in a systemd library: it speaks the protocol directly
// as a single datagram write to the NOTIFY_SOCKET Unix socket systemd passes in
// the environment.
//
// Two properties are load-bearing:
//
//   - No-op without systemd. When NOTIFY_SOCKET is unset (any non-systemd run:
//     dev, CI, tests, a bare ./ocu-controld), every notify call returns nil
//     immediately and never dials anything. The daemon must not depend on systemd
//     being present.
//   - Best-effort, never fatal. sd_notify is advisory: a malformed socket
//     address, a failed dial, or a failed write is logged at WARN and otherwise
//     ignored. A notify failure must NEVER fail the daemon — sdNotify always
//     returns nil from the caller's perspective.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// notifyReady reports READY=1 to systemd. It is called once, as the last step of
// the boot readiness hook, after both ingress listeners have bound and begun
// accepting — so READY=1 is sent exactly when the daemon is serving, and never on
// a fail-closed boot abort (a bind failure returns before this is reached).
func notifyReady() { _ = sdNotify("READY=1") }

// notifyStopping reports STOPPING=1 to systemd. It is called once, at the instant
// the daemon observes the SIGINT/SIGTERM-cancelled process context, before the
// listeners finish draining — so systemd learns the graceful stop has begun. It is
// NOT sent on a serve-loop crash (that is not a host-initiated graceful stop).
func notifyStopping() { _ = sdNotify("STOPPING=1") }

// sdNotify writes a single state datagram to the systemd NOTIFY_SOCKET. It is the
// one primitive behind notifyReady/notifyStopping.
//
// When NOTIFY_SOCKET is unset it returns nil immediately WITHOUT dialing: the
// silent no-op that lets every non-systemd run skip the protocol entirely. When
// set, the address is either a filesystem path (leading '/') or the
// abstract-namespace form (leading '@', which systemd encodes as a NUL-prefixed
// name); anything else is malformed. A malformed address, a failed dial, or a
// failed write is logged at WARN and swallowed — sd_notify is best-effort, so
// sdNotify always returns nil and never fails the daemon.
func sdNotify(state string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		// No systemd in the environment: silent no-op, never dial.
		return nil
	}

	// systemd passes either a filesystem socket path ('/...') or an
	// abstract-namespace socket ('@...'), the latter encoded on the wire with a
	// leading NUL byte. Reject anything else as malformed rather than dialing a
	// path systemd never meant.
	name := sock
	switch {
	case strings.HasPrefix(sock, "@"):
		name = "\x00" + sock[1:]
	case strings.HasPrefix(sock, "/"):
		// Filesystem path: used verbatim.
	default:
		fmt.Fprintln(os.Stderr, "ocu-controld: WARNING: sd_notify ignoring malformed NOTIFY_SOCKET (expected a leading '/' or '@'); skipping notification")
		return nil
	}

	addr := &net.UnixAddr{Name: name, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ocu-controld: WARNING: sd_notify could not dial NOTIFY_SOCKET:", err)
		return nil
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(state)); err != nil {
		fmt.Fprintln(os.Stderr, "ocu-controld: WARNING: sd_notify could not write to NOTIFY_SOCKET:", err)
		return nil
	}
	return nil
}
