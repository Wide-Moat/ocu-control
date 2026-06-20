// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build !linux

package operator

import (
	"fmt"
	"net"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
)

// peerCredOf is the fail-closed off-Linux half of the build-tagged peer-cred
// pair. SO_PEERCRED is a Linux socket option; on every other platform there is no
// kernel-vouched peer credential to read, so this returns ErrPeerCredUnavailable
// and the resolver admits NOTHING. There is deliberately no body fallback: a
// dev-time fallback to a request-supplied id would be a privilege-escalation seam
// (NFR-SEC-43), so the production-attested identity source is simply unreachable
// off Linux and the operator listener refuses every connection there.
//
// The conn parameter is unused on this path — it is named with a leading
// underscore so the off-Linux build is clean — and exists only so the two halves
// of the pair share one signature.
func peerCredOf(_ net.Conn) (ingress.PeerCred, error) {
	return ingress.PeerCred{}, fmt.Errorf("%w: SO_PEERCRED is Linux-only; this platform attests no peer identity", ErrPeerCredUnavailable)
}
