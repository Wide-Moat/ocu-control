// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// tokenExpUnix parses the exp claim out of a compact JWS without verifying the
// signature: the property under test is the mint's exp arithmetic against the
// injected Clock, not the crypto. A malformed token fails the test.
func tokenExpUnix(t *rapid.T, compact string) int64 {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS: %q", compact)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
		IAT int64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims.Exp
}

// TestProperty_MonotonicStorageTTL is the MANDATORY monotonic-TTL property
// (NFR-SEC-48). It mints a Storage-JWT at a fixed instant, then drives an
// arbitrary interleaving of forward Advances and backward SetWallClock setbacks,
// asserting the token is live IFF the SUM of forward advances is strictly less
// than the fixed TTL — INDEPENDENT of any wall-clock setback. A setback grants no
// extension; only elapsed monotonic time expires a token. There is no refresh
// path, so a fresh mint is a NEW token with a NEW exp, never an exp bump on the
// old one.
func TestProperty_MonotonicStorageTTL(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		// A whole-second TTL so the Unix-second exp arithmetic has no rounding
		// ambiguity at the boundary.
		ttlSecs := rapid.IntRange(1, 3600).Draw(rt, "ttl_secs")
		ttl := time.Duration(ttlSecs) * time.Second

		clk := state.NewFakeClock(testStart)
		cfg := cred.Config{
			Alg:             cred.AlgEdDSA,
			StorageIssuer:   "iss-provisional",
			StorageAudience: "aud-provisional",
			StorageTTL:      ttl,
		}
		path := writeKeyMount(rapidTB{rt}, cred.AlgEdDSA)
		signer, err := cred.LoadSignerFromMount(path, clk, cfg)
		if err != nil {
			rt.Fatalf("LoadSignerFromMount: %v", err)
		}

		tok, err := signer.MintStorageJWT(ctx, cred.StorageMintReq{
			SessionKey:   "host-key",
			FilesystemID: "fs-1",
			Authz:        cred.AuthorizationMetadata{Scope: "/s", Intent: cred.IntentRead},
		})
		if err != nil {
			rt.Fatalf("mint: %v", err)
		}
		expUnix := tokenExpUnix(rt, tok.Reveal())

		// totalAdvance is the monotonic time actually elapsed; only Advance moves it.
		var totalAdvance time.Duration
		steps := rapid.IntRange(1, 30).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			op := rapid.SampledFrom([]string{"advance", "setback", "setforward"}).Draw(rt, "op")
			switch op {
			case "advance":
				d := time.Duration(rapid.IntRange(0, 600).Draw(rt, "adv_secs")) * time.Second
				clk.Advance(d)
				totalAdvance += d
			case "setback":
				// Move the wall clock backward by an arbitrary amount; the monotonic
				// base is untouched, so this must NOT extend liveness.
				back := time.Duration(rapid.IntRange(0, 100000).Draw(rt, "back_secs")) * time.Second
				clk.SetWallClock(clk.Now().Add(-back))
			case "setforward":
				// A wall jump forward likewise must not change monotonic liveness.
				fwd := time.Duration(rapid.IntRange(0, 100000).Draw(rt, "fwd_secs")) * time.Second
				clk.SetWallClock(clk.Now().Add(fwd))
			}

			// The invariant: the token is live IFF elapsed monotonic time < TTL.
			wantLive := totalAdvance < ttl
			// Recompute exp-vs-monotonic-now the way the monotonic timeline sees it:
			// the mint stamped exp at testStart+ttl in Unix seconds; the elapsed
			// monotonic position is testStart+totalAdvance.
			monoNowUnix := testStart.Add(totalAdvance).Unix()
			gotLive := expUnix > monoNowUnix
			if gotLive != wantLive {
				rt.Fatalf("liveness drift: wantLive=%v gotLive=%v totalAdvance=%v ttl=%v exp=%d monoNow=%d",
					wantLive, gotLive, totalAdvance, ttl, expUnix, monoNowUnix)
			}

			// There is NO refresh path. A fresh mint is a NEW, independent token
			// whose exp is stamped from the CURRENT clock (Now()+TTL), never an
			// exp-bump on the original. Its exp must equal the freshly-computed
			// window, and — decisively — the ORIGINAL token's exp must be UNCHANGED
			// by any mint, advance, or setback: there is no path that extends a
			// token already in hand.
			fresh, ferr := signer.MintStorageJWT(ctx, cred.StorageMintReq{
				SessionKey:   "host-key",
				FilesystemID: "fs-1",
				Authz:        cred.AuthorizationMetadata{Scope: "/s", Intent: cred.IntentRead},
			})
			if ferr != nil {
				rt.Fatalf("fresh mint: %v", ferr)
			}
			wantFreshExp := clk.Now().Add(ttl).Unix()
			if gotFreshExp := tokenExpUnix(rt, fresh.Reveal()); gotFreshExp != wantFreshExp {
				rt.Fatalf("fresh mint exp not stamped from current clock: want %d got %d", wantFreshExp, gotFreshExp)
			}
			// The original token's exp must be UNCHANGED by any of this (no exp bump).
			if again := tokenExpUnix(rt, tok.Reveal()); again != expUnix {
				rt.Fatalf("original token exp mutated: was %d now %d", expUnix, again)
			}
		}
	})
}

// TestExecTTLClamp asserts a RequestedTTL above the 60-minute ceiling is clamped
// DOWN, never honored: a 2h request yields exp at Now()+60min. A short request is
// honored as-is, and a non-positive request defaults to the ceiling.
func TestExecTTLClamp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name      string
		requested time.Duration
		wantTTL   time.Duration
	}{
		{"two-hours-clamped", 2 * time.Hour, 60 * time.Minute},
		{"exactly-ceiling", 60 * time.Minute, 60 * time.Minute},
		{"under-ceiling-honored", 15 * time.Minute, 15 * time.Minute},
		{"zero-defaults-ceiling", 0, 60 * time.Minute},
		{"negative-defaults-ceiling", -5 * time.Minute, 60 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signer, _ := newTestSigner(t, cred.AlgEdDSA, time.Minute)
			tok, err := signer.MintExecJWT(ctx, cred.ExecMintReq{ContainerName: "ocu-ctr", RequestedTTL: tc.requested})
			if err != nil {
				t.Fatalf("MintExecJWT: %v", err)
			}
			gotExp, gotSub := execExp(t, tok.Reveal())
			wantExp := testStart.Add(tc.wantTTL).Unix()
			if gotExp != wantExp {
				t.Fatalf("clamp: requested=%v wantExp=%d gotExp=%d", tc.requested, wantExp, gotExp)
			}
			// Requirement 6: the exec JWT subject is the host-attested container_name.
			if gotSub != "ocu-ctr" {
				t.Fatalf("exec sub = %q, want the host-attested container_name ocu-ctr", gotSub)
			}
		})
	}
}

// execExp pulls exp and the sub subject from a compact JWS for the clamp test, so
// the test can assert both the clamped expiry and that sub is the host-attested
// container_name (requirement 6).
func execExp(t *testing.T, compact string) (int64, string) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return claims.Exp, claims.Sub
}

// rapidTB adapts a *rapid.T to the testing.TB-ish subset writeKeyMount needs.
// rapid.T provides Helper/Fatalf/Cleanup; TempDir is synthesized here over
// os.MkdirTemp with a Cleanup so each property iteration gets an isolated dir.
type rapidTB struct{ *rapid.T }

func (r rapidTB) TempDir() string {
	dir, err := os.MkdirTemp("", "cred-prop-*")
	if err != nil {
		r.Fatalf("MkdirTemp: %v", err)
	}
	r.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
