// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestResolverRefusesNonOperatorChannel proves the operator resolver fails closed on
// a connection that did not arrive on the operator channel: identity is never
// derived off the operator socket.
func TestResolverRefusesNonOperatorChannel(t *testing.T) {
	t.Parallel()
	r := operator.NewPeerCredResolver(nil)
	conn := ingress.ConnInfo{Channel: ingress.ChannelGateway, PeerCred: &ingress.PeerCred{UID: 1000}}
	if _, err := r.Resolve(context.Background(), conn); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Resolve on a non-operator channel = %v; want ErrUnattested", err)
	}
}

// TestResolverRefusesMissingPeerCred proves the resolver fails closed when the
// connection carries no kernel-vouched credential (the off-Linux / getsockopt-fail
// case the listener stashes).
func TestResolverRefusesMissingPeerCred(t *testing.T) {
	t.Parallel()
	r := operator.NewPeerCredResolver(nil)
	conn := ingress.ConnInfo{Channel: ingress.ChannelOperator} // nil PeerCred
	if _, err := r.Resolve(context.Background(), conn); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Resolve with no PeerCred = %v; want ErrUnattested", err)
	}
}

// TestResolverMapperErrorRefuses proves a UIDMapper that refuses a uid (e.g. a uid
// not on the operator allowlist) fails the resolve closed.
func TestResolverMapperErrorRefuses(t *testing.T) {
	t.Parallel()
	denyMapper := func(ingress.PeerCred) (state.Identity, error) {
		return state.Identity{}, errors.New("uid not on the operator allowlist")
	}
	r := operator.NewPeerCredResolver(denyMapper)
	conn := ingress.ConnInfo{Channel: ingress.ChannelOperator, PeerCred: &ingress.PeerCred{UID: 4242}}
	if _, err := r.Resolve(context.Background(), conn); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Resolve with a refusing mapper = %v; want ErrUnattested", err)
	}
}

// TestResolverEmptyIdentityRefuses proves a mapper that returns an empty identity is
// treated as unattested: an empty identity must never seed a Key.
func TestResolverEmptyIdentityRefuses(t *testing.T) {
	t.Parallel()
	emptyMapper := func(ingress.PeerCred) (state.Identity, error) {
		return state.Identity{}, nil // empty, no error
	}
	r := operator.NewPeerCredResolver(emptyMapper)
	conn := ingress.ConnInfo{Channel: ingress.ChannelOperator, PeerCred: &ingress.PeerCred{UID: 7}}
	if _, err := r.Resolve(context.Background(), conn); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Resolve with an empty-identity mapper = %v; want ErrUnattested", err)
	}
}
