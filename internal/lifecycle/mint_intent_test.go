// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
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

// newDerivingIntentManager wires a create Manager exactly like newIntentManager but
// with DeriveChatScope ON (ADR-0030, D5), so the create pipeline rewrites each mount
// FilesystemID to "<base>-<hex>" before the mint. It exposes the Custodian so a
// keystone can drive the enriched status read directly. It returns both the Manager
// and the Custodian bound to the same store.
func newDerivingIntentManager(t *testing.T, pusher *recordingPusher) (*lifecycle.Manager, *registry.Custodian) {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	provider := newRecordingProvider()
	sink := audit.NewRecordingFake()
	signer, _ := newTestSigner(t, clk)
	cust := registry.NewCustodian(store)

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:       cust,
		Provider:        provider,
		Clock:           clk,
		Quota:           quota.NewGate(store, clk, generousLimits()),
		Handoff:         handoff.NewStager(t.TempDir()),
		Audit:           sink,
		Profile:         admission.ProfileTrustedOperator,
		Tier:            runtime.TierRunc,
		AllowedImages:   []string{testGuestImage},
		ExecVerifyKey:   pub32(),
		Signer:          signer,
		Push:            pusher,
		ServiceURL:      testServiceURL,
		CACertPEM:       testCACert,
		MountDefaults:   testMountDefaults(t),
		StorageScope:    lifecycle.StorageScope{Workspace: "ws", Org: "org", Intent: cred.IntentWrite},
		GrantedIntents:  lifecycle.NewIntentCeiling(cred.IntentRead, cred.IntentWrite),
		DeriveChatScope: true,
	})
	return mgr, cust
}

// mintedFsid decodes the filesystem_id claim from the minted Storage-JWT the create
// pushed into mounts[0].auth_token. It is the value the egress edge keys the
// credential on, so a per-chat-derived fsid here means a peer chat's guest gets a
// DIFFERENT credential.
func mintedFsid(t *testing.T, cfgBytes []byte) string {
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
	parts := strings.Split(cfg.Mounts[0].AuthToken, ".")
	if len(parts) != 3 {
		t.Fatalf("auth_token is not a compact JWT (%d segments)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload segment: %v", err)
	}
	var claims struct {
		FilesystemID string `json:"filesystem_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	return claims.FilesystemID
}

// wireFsid decodes the mounts[0].filesystem_id the create rendered onto the wire
// mount-config (the scope the in-guest mount client binds), so a keystone can assert
// the wire fsid matches the minted claim - the credential and the mount name the SAME
// derived scope.
func wireFsid(t *testing.T, cfgBytes []byte) string {
	t.Helper()
	var cfg struct {
		Mounts []struct {
			FilesystemID string `json:"filesystem_id"`
		} `json:"mounts"`
	}
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("decode mount-config JSON: %v", err)
	}
	if len(cfg.Mounts) == 0 {
		t.Fatal("mount-config carried no mounts")
	}
	return cfg.Mounts[0].FilesystemID
}

// derivedSuffixRe matches the 16-lowercase-hex suffix a per-chat derived scope
// carries: "<base>-<16hex>". The keystone asserts a derived fsid ends in exactly this.
var derivedSuffixRe = regexp.MustCompile(`^fs-1-[0-9a-f]{16}$`)

// TestTwoChatsMintDistinctDerivedScopes is the D5 acceptance keystone (ADR-0030):
// with -derive-chat-scope on, two chats of the SAME owner (distinct hints chat-a,
// chat-b) mint DISTINCT storage scopes. The keystone decodes the filesystem_id from
// BOTH the minted Storage-JWT claim AND the wire mount for each chat and asserts (1)
// the two claims differ, (2) each is "fs-1-<16hex>" (the base fixture "fs-1" plus the
// derived suffix), and (3) the wire fsid equals the minted claim (the credential and
// the mount name the same scope). The load-bearing property is (1): a peer chat's
// guest gets a different credential and physically cannot read another chat's objects.
func TestTwoChatsMintDistinctDerivedScopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	pusherA := newRecordingPusher()
	mgrA, _ := newDerivingIntentManager(t, pusherA)
	if _, err := mgrA.Create(ctx, intentCreateInput("chat-a", false)); err != nil {
		t.Fatalf("chat-a create: %v", err)
	}
	claimA := mintedFsid(t, pusherA.pushedConfig())
	wireA := wireFsid(t, pusherA.pushedConfig())

	pusherB := newRecordingPusher()
	mgrB, _ := newDerivingIntentManager(t, pusherB)
	if _, err := mgrB.Create(ctx, intentCreateInput("chat-b", false)); err != nil {
		t.Fatalf("chat-b create: %v", err)
	}
	claimB := mintedFsid(t, pusherB.pushedConfig())
	wireB := wireFsid(t, pusherB.pushedConfig())

	// (1) The load-bearing property: two chats -> two distinct minted scopes.
	if claimA == claimB {
		t.Fatalf("chat-a and chat-b minted the SAME filesystem_id %q; per-chat derivation must make them distinct (a peer chat would share the credential)", claimA)
	}
	// (2) Each is the base fixture plus a 16-hex derived suffix.
	if !derivedSuffixRe.MatchString(claimA) {
		t.Errorf("chat-a minted fsid %q is not the derived shape fs-1-<16hex>", claimA)
	}
	if !derivedSuffixRe.MatchString(claimB) {
		t.Errorf("chat-b minted fsid %q is not the derived shape fs-1-<16hex>", claimB)
	}
	// (3) The wire mount fsid equals the minted claim for each chat.
	if wireA != claimA {
		t.Errorf("chat-a wire fsid %q != minted claim %q (credential and mount must name the same scope)", wireA, claimA)
	}
	if wireB != claimB {
		t.Errorf("chat-b wire fsid %q != minted claim %q", wireB, claimB)
	}
}

// TestDeriveDisabledKeepsBaseScope is the degrade keystone: with -derive-chat-scope
// OFF (newIntentManager's default), two chats mint the BARE base "fs-1" - today's
// single-scope behaviour is preserved, no suffix, and the two chats share the scope.
func TestDeriveDisabledKeepsBaseScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	both := lifecycle.NewIntentCeiling(cred.IntentRead, cred.IntentWrite)

	pusherA := newRecordingPusher()
	mgrA := newIntentManager(t, pusherA, both)
	if _, err := mgrA.Create(ctx, intentCreateInput("chat-a", false)); err != nil {
		t.Fatalf("chat-a create: %v", err)
	}
	pusherB := newRecordingPusher()
	mgrB := newIntentManager(t, pusherB, both)
	if _, err := mgrB.Create(ctx, intentCreateInput("chat-b", false)); err != nil {
		t.Fatalf("chat-b create: %v", err)
	}

	if got := mintedFsid(t, pusherA.pushedConfig()); got != "fs-1" {
		t.Errorf("derivation off: chat-a minted fsid %q, want the bare base fs-1", got)
	}
	if got := mintedFsid(t, pusherB.pushedConfig()); got != "fs-1" {
		t.Errorf("derivation off: chat-b minted fsid %q, want the bare base fs-1", got)
	}
}

// TestEffectiveScopePersistedAndOnStatusEnriched is the B1-aware keystone (ADR-0030):
// after a deriving create, the caller's enriched status carries the per-chat
// effective_scope "fs-1-<hex>", and a DIFFERENT caller resolving the SAME hint gets
// ErrNotOwned (audience scoping). It drives StatusEnriched -> the ENRICHED read path,
// so a red-probe that routes the status verb through the non-enriched LookupForCaller
// reads an EnrichedSessionRow with a nil scope and REDs - proving the enriched path,
// not a stubbed recorder.
func TestEffectiveScopePersistedAndOnStatusEnriched(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	pusher := newRecordingPusher()
	mgr, _ := newDerivingIntentManager(t, pusher)
	if _, err := mgr.Create(ctx, intentCreateInput("chat-status", false)); err != nil {
		t.Fatalf("deriving create: %v", err)
	}
	minted := mintedFsid(t, pusher.pushedConfig())

	// The OWNER's enriched status carries the derived effective_scope.
	row, err := mgr.StatusEnriched(ctx, testCaller, "chat-status")
	if err != nil {
		t.Fatalf("StatusEnriched(owner): %v", err)
	}
	if row.EffectiveScope == nil {
		t.Fatal("owner StatusEnriched returned a nil effective_scope; the derived scope must be persisted and surfaced (a nil here is the B1 non-enriched-read defect)")
	}
	if *row.EffectiveScope != minted {
		t.Errorf("owner effective_scope %q != the minted claim %q", *row.EffectiveScope, minted)
	}
	if !derivedSuffixRe.MatchString(*row.EffectiveScope) {
		t.Errorf("effective_scope %q is not the derived shape fs-1-<16hex>", *row.EffectiveScope)
	}

	// A DIFFERENT caller resolving the SAME hint is refused ErrNotOwned - it can neither
	// read the scope nor probe the session's existence (NFR-SEC-43). DeriveKey mixes the
	// foreign owner in, so it lands on a different key and never on the victim's row.
	foreignCaller := ingress.AuthenticatedCaller{
		Identity: state.Identity{Tenant: "tenant-b", Caller: "caller-2"},
		Channel:  ingress.ChannelGateway,
	}
	if _, err := mgr.StatusEnriched(ctx, foreignCaller, "chat-status"); !errors.Is(err, registry.ErrNotOwned) {
		t.Fatalf("foreign StatusEnriched: want ErrNotOwned, got %v", err)
	}
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
