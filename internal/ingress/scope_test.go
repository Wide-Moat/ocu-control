// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestOperatorSeamMintsValidScope proves a seam from NewOperatorSeam mints an
// OperatorScope that Valid accepts: the genuine capability-by-possession path.
func TestOperatorSeamMintsValidScope(t *testing.T) {
	t.Parallel()
	seam := ingress.NewOperatorSeam()
	scope := seam.Mint()
	if !scope.Valid() {
		t.Fatalf("OperatorScope minted from NewOperatorSeam().Mint() is not Valid")
	}
}

// TestZeroOperatorScopeIsInvalid proves the inert zero-value OperatorScope (the only
// OperatorScope a foreign package could name, via the empty literal of an exported
// type) authorizes nothing: Valid reports false. This is the runtime backstop behind
// the compile seal.
func TestZeroOperatorScopeIsInvalid(t *testing.T) {
	t.Parallel()
	var zero ingress.OperatorScope
	if zero.Valid() {
		t.Fatalf("zero-value OperatorScope reports Valid; the inert scope must authorize nothing")
	}
}

// TestZeroOperatorSeamMintsInvalidScope proves the empty-literal hole is closed at
// the witness: a foreign package may write OperatorSeam{} (the zero value of any
// struct is constructible), but Mint on that forged zero seam yields an INVALID
// scope, so the forgery grants no authority even though the literal compiles.
func TestZeroOperatorSeamMintsInvalidScope(t *testing.T) {
	t.Parallel()
	var forged ingress.OperatorSeam
	scope := forged.Mint()
	if scope.Valid() {
		t.Fatalf("OperatorScope minted from a zero-value OperatorSeam reports Valid; the empty-literal hole is open")
	}
}

// TestServiceScopeForIsValid proves ServiceScopeFor mints a Valid ServiceScope (no
// seam required; the gateway transport already proved service identity).
func TestServiceScopeForIsValid(t *testing.T) {
	t.Parallel()
	if !ingress.ServiceScopeFor().Valid() {
		t.Fatalf("ServiceScopeFor() is not Valid")
	}
}

// TestZeroServiceScopeIsInvalid proves the inert zero-value ServiceScope authorizes
// nothing, symmetric to the operator backstop.
func TestZeroServiceScopeIsInvalid(t *testing.T) {
	t.Parallel()
	var zero ingress.ServiceScope
	if zero.Valid() {
		t.Fatalf("zero-value ServiceScope reports Valid; the inert scope must authorize nothing")
	}
}

// TestDistinctSeamsMintEquivalentlyValidScopes proves the genuine witness is a
// single sealed identity: two seams from NewOperatorSeam each mint a Valid scope.
// (There is exactly one genuine witness pointer; Mint propagates it.)
func TestDistinctSeamsMintEquivalentlyValidScopes(t *testing.T) {
	t.Parallel()
	a := ingress.NewOperatorSeam().Mint()
	b := ingress.NewOperatorSeam().Mint()
	if !a.Valid() || !b.Valid() {
		t.Fatalf("a seam minted by NewOperatorSeam must always mint a Valid scope: a=%v b=%v", a.Valid(), b.Valid())
	}
}

// TestChannelString pins the Channel labels the audit record carries and the
// fail-closed default for an out-of-range value.
func TestChannelString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ch   ingress.Channel
		want string
	}{
		{ingress.ChannelOperator, "operator"},
		{ingress.ChannelGateway, "gateway"},
		{ingress.Channel(200), "channel_unknown"},
	}
	for _, tc := range cases {
		if got := tc.ch.String(); got != tc.want {
			t.Errorf("Channel(%d).String() = %q, want %q", tc.ch, got, tc.want)
		}
	}
}

// TestAuthenticatedCallerCarriesHostIdentity proves the AuthenticatedCaller value
// type threads the host-derived Identity and the Channel a resolver set; this is the
// only identity the Manager acts on.
func TestAuthenticatedCallerCarriesHostIdentity(t *testing.T) {
	t.Parallel()
	ac := ingress.AuthenticatedCaller{
		Identity: state.Identity{Tenant: "tenant-a", Caller: "caller-1"},
		Channel:  ingress.ChannelGateway,
	}
	if ac.Identity.Tenant != "tenant-a" || ac.Identity.Caller != "caller-1" {
		t.Fatalf("AuthenticatedCaller did not carry the host-derived Identity: %+v", ac.Identity)
	}
	if ac.Channel != ingress.ChannelGateway {
		t.Fatalf("AuthenticatedCaller did not carry the Channel: %v", ac.Channel)
	}
}

// TestErrUnattestedIsMatchable proves the fail-closed identity refusal is a matchable
// sentinel a wrapping resolver can surface and a caller can branch on with errors.Is.
func TestErrUnattestedIsMatchable(t *testing.T) {
	t.Parallel()
	wrapped := errors.Join(errors.New("peercred: getsockopt failed"), ingress.ErrUnattested)
	if !errors.Is(wrapped, ingress.ErrUnattested) {
		t.Fatalf("a resolver error wrapping ErrUnattested does not match errors.Is")
	}
}

// staticResolver is a tiny IdentityResolver used to prove the port shape compiles
// and returns the resolved AuthenticatedCaller / the fail-closed sentinel. The two
// real resolvers (peer-cred, cert-SAN) live with their adapters; this only exercises
// the seam contract.
type staticResolver struct {
	caller ingress.AuthenticatedCaller
	err    error
}

func (r staticResolver) Resolve(_ context.Context, _ ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	return r.caller, r.err
}

// TestIdentityResolverPort exercises the resolver seam both ways: an attested
// resolution returns the host-derived caller; an unattested one returns ErrUnattested
// and a zero caller, proving the fail-closed shape the adapters implement.
func TestIdentityResolverPort(t *testing.T) {
	t.Parallel()
	want := ingress.AuthenticatedCaller{
		Identity: state.Identity{Tenant: "t", Caller: "c"},
		Channel:  ingress.ChannelOperator,
	}
	var ok ingress.IdentityResolver = staticResolver{caller: want}
	got, err := ok.Resolve(context.Background(), ingress.ConnInfo{
		Channel:  ingress.ChannelOperator,
		PeerCred: &ingress.PeerCred{UID: 1000, GID: 1000, PID: 4242},
	})
	if err != nil {
		t.Fatalf("attested Resolve returned error: %v", err)
	}
	if got != want {
		t.Fatalf("attested Resolve = %+v, want %+v", got, want)
	}

	var bad ingress.IdentityResolver = staticResolver{err: ingress.ErrUnattested}
	gotBad, errBad := bad.Resolve(context.Background(), ingress.ConnInfo{Channel: ingress.ChannelGateway})
	if !errors.Is(errBad, ingress.ErrUnattested) {
		t.Fatalf("unattested Resolve error = %v, want ErrUnattested", errBad)
	}
	if (gotBad != ingress.AuthenticatedCaller{}) {
		t.Fatalf("unattested Resolve returned a non-zero caller: %+v", gotBad)
	}
}
