// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// mintedIntent decodes the minted Storage-JWT the create pushed into the
// mount-config and returns its authz.intent claim. It is the OBSERVABLE end of the
// mint: the JWT the egress edge will key on, decoded exactly as the edge decodes it
// (the middle base64url segment of the compact token in mounts[0].auth_token). It
// does not verify the signature — the claim value, not the signature, is what this
// keystone asserts (a separate cred test proves the signature).
func mintedIntent(t *testing.T, cfgBytes []byte) string {
	t.Helper()
	var cfg struct {
		Mounts []struct {
			AuthToken string `json:"auth_token"`
		} `json:"mounts"`
	}
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("decode mount-config JSON: %v", err)
	}
	if len(cfg.Mounts) == 0 {
		t.Fatal("mount-config carried no mounts; nothing was minted")
	}
	tok := cfg.Mounts[0].AuthToken
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("auth_token is not a compact JWT (%d segments): %q", len(parts), tok)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload segment: %v", err)
	}
	var claims struct {
		Authz struct {
			Intent string `json:"intent"`
		} `json:"authz"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	return claims.Authz.Intent
}

// newIntentManager wires a create Manager exactly like the shipped compose — a REAL
// cred.Signer, a real Push, the deployment-fixed StorageScope — with the given
// -granted-intents ceiling, so the mint stage fires for real and the keystone reads
// the minted claim from the pushed config.
func newIntentManager(t *testing.T, pusher *recordingPusher, ceiling lifecycle.IntentCeiling) *lifecycle.Manager {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	provider := newRecordingProvider()
	sink := audit.NewRecordingFake()
	signer, _ := newTestSigner(t, clk)

	return lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:      registry.NewCustodian(store),
		Provider:       provider,
		Clock:          clk,
		Quota:          quota.NewGate(store, clk, generousLimits()),
		Handoff:        handoff.NewStager(t.TempDir()),
		Audit:          sink,
		Profile:        admission.ProfileTrustedOperator,
		Tier:           runtime.TierRunc,
		AllowedImages:  []string{testGuestImage},
		ExecVerifyKey:  pub32(),
		Signer:         signer,
		Push:           pusher,
		ServiceURL:     testServiceURL,
		CACertPEM:      testCACert,
		MountDefaults:  testMountDefaults(t),
		StorageScope:   lifecycle.StorageScope{Workspace: "ws", Org: "org", Intent: cred.IntentWrite},
		GrantedIntents: ceiling,
	})
}

// intentCreateInput builds a storage-scoped create whose mount posture is set by
// readOnly, so the mint stage derives the per-mount intent from it (ADR-0029).
func intentCreateInput(hint string, readOnly bool) lifecycle.CreateInput {
	return lifecycle.CreateInput{
		Caller:      testCaller,
		SessionHint: hint,
		Image:       testGuestImage,
		Mounts:      []runtime.MountIntent{{Destination: "/workspace", FilesystemID: "fs-1", ReadOnly: readOnly, CacheSeconds: 5}},
		Egress:      runtime.EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store", FilesystemID: "fs-1"},
		Resources:   runtime.ResourceCaps{CPUCores: 1, MemoryBytes: 1 << 30},
	}
}

// TestMintIntentDerivedFromMountReadOnly is the ADR-0029 control-half keystone: the
// Storage-JWT intent is derived from THIS session's mount posture, not the static
// deployment scope. A read-only mount (the uploads input leg) mints intent=read; a
// read-write mount (the outputs sink) mints intent=write. The deployment
// StorageScope.Intent is write for both; only a per-mount derive makes the RO mount
// come out read. Canon: ADR-0029 §Consequences component-02 —
// "mints the per-mount intent claim from the mount's host-set posture — the RW sink
// gets write, RO input mounts read".
func TestMintIntentDerivedFromMountReadOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// The ceiling admits both intents so the derive alone decides the claim.
	both := lifecycle.NewIntentCeiling(cred.IntentRead, cred.IntentWrite)

	t.Run("read-only mount mints intent=read", func(t *testing.T) {
		t.Parallel()
		pusher := newRecordingPusher()
		mgr := newIntentManager(t, pusher, both)

		if _, err := mgr.Create(ctx, intentCreateInput("ro-session", true)); err != nil {
			t.Fatalf("read-only storage-scoped Create: %v", err)
		}
		if got := mintedIntent(t, pusher.pushedConfig()); got != string(cred.IntentRead) {
			t.Fatalf("read-only mount minted intent=%q, want %q — the RO posture must derive read, not the static write scope", got, cred.IntentRead)
		}
	})

	t.Run("read-write mount mints intent=write", func(t *testing.T) {
		t.Parallel()
		pusher := newRecordingPusher()
		mgr := newIntentManager(t, pusher, both)

		if _, err := mgr.Create(ctx, intentCreateInput("rw-session", false)); err != nil {
			t.Fatalf("read-write storage-scoped Create: %v", err)
		}
		if got := mintedIntent(t, pusher.pushedConfig()); got != string(cred.IntentWrite) {
			t.Fatalf("read-write mount minted intent=%q, want %q", got, cred.IntentWrite)
		}
	})
}

// TestMintIntentOutsideCeilingRefused is the ceiling keystone: the -granted-intents
// flag is a CEILING, not a grant. A per-mount-derived intent OUTSIDE the deployment
// ceiling refuses the create fail-closed before any mount-config reaches the bind —
// no session state, no minted token leaks. Here the deployment serves only read; a
// read-write mount derives write, which the ceiling excludes, so the create is
// refused. Canon: ADR-0029 §Decision — "the effective intent is the intersection of
// the minted claim and that ceiling ... a claim outside the ceiling is refused".
func TestMintIntentOutsideCeilingRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A read-only deployment: the ceiling admits read alone.
	readOnlyDeployment := lifecycle.NewIntentCeiling(cred.IntentRead)
	pusher := newRecordingPusher()
	mgr := newIntentManager(t, pusher, readOnlyDeployment)

	// A read-write mount derives write — outside the read-only ceiling.
	_, err := mgr.Create(ctx, intentCreateInput("rw-over-ceiling", false))
	if err == nil {
		t.Fatal("read-write create under a read-only ceiling succeeded; want a fail-closed refusal — the derived write intent is outside -granted-intents")
	}
	if !errors.Is(err, lifecycle.ErrIntentOutsideCeiling) {
		t.Fatalf("ceiling refusal = %v, want ErrIntentOutsideCeiling", err)
	}
	// Fail-closed: nothing was pushed onto the bind before the refusal.
	if push, _ := pusher.counts(); push != 0 {
		t.Fatalf("Push called %d times on a ceiling-refused create, want 0 — the mint must refuse before render/push", push)
	}
}

// mintedIntents decodes EVERY mount entry's auth_token intent from the pushed
// mount-config, positionally - the two-mount keystone reads both claims.
func mintedIntents(t *testing.T, cfgBytes []byte) []string {
	t.Helper()
	var cfg struct {
		Mounts []struct {
			Destination string `json:"destination"`
			AuthToken   string `json:"auth_token"`
		} `json:"mounts"`
	}
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("decode mount-config JSON: %v", err)
	}
	intents := make([]string, 0, len(cfg.Mounts))
	for _, m := range cfg.Mounts {
		parts := strings.Split(m.AuthToken, ".")
		if len(parts) != 3 {
			t.Fatalf("auth_token for %s is not a compact JWT (%d segments)", m.Destination, len(parts))
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode JWT payload for %s: %v", m.Destination, err)
		}
		var claims struct {
			Authz struct {
				Intent string `json:"intent"`
			} `json:"authz"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("decode JWT claims for %s: %v", m.Destination, err)
		}
		intents = append(intents, claims.Authz.Intent)
	}
	return intents
}

// TestCreateTwoMountsMintsPerMountIntents is the two-mount keystone (ADR-0029):
// ONE create provisioning the uploads-RO + outputs-RW pair renders a mount-config
// with TWO entries, each carrying its own weak Storage-JWT whose intent claim is
// derived from THAT mount's posture - read for the RO uploads view, write for the
// RW outputs sink. Under the old single-mount wrap the second mount was silently
// impossible, so this test cannot pass against it.
func TestCreateTwoMountsMintsPerMountIntents(t *testing.T) {
	t.Parallel()
	pusher := newRecordingPusher()
	mgr := newIntentManager(t, pusher, lifecycle.NewIntentCeiling(cred.IntentRead, cred.IntentWrite))

	in := lifecycle.CreateInput{
		Caller:      testCaller,
		SessionHint: "two-mount-session",
		Image:       testGuestImage,
		Mounts: []runtime.MountIntent{
			{Destination: "/mnt/user-data/uploads", FilesystemID: "fs-1", ReadOnly: true, CacheSeconds: 5},
			{Destination: "/mnt/user-data/outputs", FilesystemID: "fs-1", ReadOnly: false, CacheSeconds: 5},
		},
		Egress:    runtime.EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store", FilesystemID: "fs-1"},
		Resources: runtime.ResourceCaps{CPUCores: 1, MemoryBytes: 1 << 30},
	}
	if _, err := mgr.Create(context.Background(), in); err != nil {
		t.Fatalf("two-mount create: %v", err)
	}
	cfgBytes := pusher.pushedConfig()
	if len(cfgBytes) == 0 {
		t.Fatal("no mount-config was pushed")
	}
	intents := mintedIntents(t, cfgBytes)
	if len(intents) != 2 {
		t.Fatalf("mount-config carries %d mounts, want 2 (uploads + outputs)", len(intents))
	}
	if intents[0] != "read" {
		t.Errorf("uploads (RO) mount minted intent %q, want read", intents[0])
	}
	if intents[1] != "write" {
		t.Errorf("outputs (RW) mount minted intent %q, want write", intents[1])
	}
}
