// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// This file is the Unix-domain-socket substrate for the exec channel. Only the
// byte stream changes: the dialer carries the verbatim frozen handshake and the
// transport-agnostic exec drive over a Unix socket instead of a TCP connection.
//
// Substrate rationale. The frozen exec-channel contract — WebSocket framing, the
// handshake, the 32 KiB read bound, the announce+binary stdio discipline — is
// transport-agnostic; nothing above the byte stream is aware of TCP versus UDS.
// Moving the dial onto a per-session Unix socket keeps the exec channel OFF the
// guest's own network stack: there is no listening TCP port and no published
// host port, so guest-originated code cannot reach the control/exec channel
// through the guest's network stack (NFR-SEC-43; spec invariant: the channel is
// not reachable via the guest's network). The trust gate for the socket is the
// host-owned per-session directory it lives in, not a network-layer check.

package dial

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/coder/websocket"
)

// udsScheme is the address scheme that selects the Unix-domain-socket substrate.
// A DialAddr of the form "unix://<path>" routes through DialUDS; anything else
// (a "ws://host:port/" loopback address) routes through the TCP Dial.
const udsScheme = "unix://"

// Open is the single dial entrypoint every consumer of a session DialAddr must
// use. It dispatches on the address scheme so no call site can hand a "unix://"
// address to the TCP WebSocket dialer (which would fail with "unexpected url
// scheme: unix"): a "unix://<path>" address routes to the WebSocket-over-UDS
// dialer (DialUDS), anything else to the TCP WebSocket dialer (Dial). Centralizing
// the scheme switch here means the gap cannot reopen at a call site.
//
// ctx bounds the dial; minter supplies msg1 at handshake time. The returned
// Channel is identical regardless of substrate — the byte stream above the dial
// is transport-agnostic.
func Open(ctx context.Context, addr string, minter Minter, opts ...Option) (*Channel, error) {
	if path, ok := strings.CutPrefix(addr, udsScheme); ok {
		return DialUDS(ctx, path, minter, opts...)
	}
	return Dial(ctx, addr, minter, opts...)
}

// UDSHTTPClient builds an *http.Client whose transport dials a fixed Unix-domain
// socket path, ignoring the network and address the WebSocket library passes.
// coder/websocket carries the HTTP Upgrade over whatever connection this client's
// DialContext returns, so the WebSocket handshake rides the Unix socket.
//
// It is exported because the control package's e2e readiness poll reuses it to
// probe a UDS-rung guest with the same dialer the real exec uses.
func UDSHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// The network and addr the library supplies are placeholders (the
			// dial URL host is "ocu-uds"); routing is done entirely here by
			// connecting the fixed Unix socket path.
			DialContext: func(ctx context.Context, _network, _addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// DialUDS opens a WebSocket connection to the guest over the Unix-domain socket
// at socketPath, sets the read limit to ReadLimitBytes, and returns a Channel
// ready for the verbatim handshake. The post-dial discipline is byte-for-byte
// identical to Dial: the only difference is the substrate.
//
// The dial URL host ("ocu-uds") is a placeholder — the guest does not validate
// Host, and routing is performed by the UDSHTTPClient's DialContext, not by DNS.
// ctx bounds the dial; pass a context with a timeout so a wedged peer yields a
// typed error rather than a hang. minter supplies msg1 at handshake time.
func DialUDS(ctx context.Context, socketPath string, minter Minter, opts ...Option) (*Channel, error) {
	conn, _, err := websocket.Dial(ctx, "ws://ocu-uds/", &websocket.DialOptions{
		HTTPClient: UDSHTTPClient(socketPath),
	})
	if err != nil {
		return nil, fmt.Errorf("dial: open uds %s: %w", socketPath, err)
	}
	conn.SetReadLimit(ReadLimitBytes)
	return newChannel(conn, minter, opts...), nil
}
