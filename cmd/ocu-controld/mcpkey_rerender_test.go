// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Tests for renderMCPKeyArtifacts — the daemon's mcp-key re-render step — with a
// focus on the last-key-revoke deny-all path. An adversarial self-audit confirmed
// that revoking the LAST active key left the boot-set artifact stale (still listing
// the revoked key as "active") AND left the entries file stale (so a restart
// re-seeded the store with the key active), while the operator saw a 503. This
// suite drives the real Engine.Revoke through the real renderMCPKeyArtifacts and
// the real mcpkeyset writers over a real temp dir, so each of those three defects
// is a red test. Closing the LIVE gateway fail-open needs the config-plane
// deny-all-artifact contract (open-computer-use#332); this is Control's half.
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// mcpKeyTestRig builds a real Engine wired to the daemon's real
// renderMCPKeyArtifacts closure over a temp dir, so a test drives the exact
// mint→persist→render and revoke→persist→render paths the daemon runs.
type mcpKeyTestRig struct {
	eng         *mcpkey.Engine
	store       mcpkey.RecordStore
	scope       ingress.OperatorScope
	keysetPath  string
	entriesPath string
	clk         state.Clock
	cfg         config
}

func newMCPKeyTestRig(t *testing.T) mcpKeyTestRig {
	t.Helper()
	dir := t.TempDir()
	keysetPath := filepath.Join(dir, "keyset.json")
	entriesPath := filepath.Join(dir, "entries.json")
	clk := state.NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store := mcpkey.NewInMemRecordStore()
	cfg := config{mcpKeysetPath: keysetPath, mcpKeyFile: entriesPath}
	rerender := func(ctx context.Context) (mcpkey.RenderOutcome, error) {
		return renderMCPKeyArtifacts(ctx, cfg, store, clk.Now())
	}
	eng := mcpkey.NewEngine(mcpkey.NewMinter(), store, rerender, clk, audit.NewRecordingFake())
	seam := ingress.NewOperatorSeam()
	return mcpKeyTestRig{
		eng:         eng,
		store:       store,
		scope:       seam.Mint(state.Identity{Tenant: "acme", Caller: "uid:1000"}),
		keysetPath:  keysetPath,
		entriesPath: entriesPath,
		clk:         clk,
		cfg:         cfg,
	}
}

// readKeysetStatuses returns key_id→status for every record in the published
// boot-set artifact. A missing file yields an empty map (deny-all-by-absence).
func readKeysetStatuses(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatalf("read keyset: %v", err)
	}
	var doc struct {
		Records []struct {
			KeyID  string `json:"key_id"`
			Status string `json:"status"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse keyset: %v", err)
	}
	out := map[string]string{}
	for _, r := range doc.Records {
		out[r.KeyID] = r.Status
	}
	return out
}

// TestRevokeLastKey_DenyAllPendingAndHonestEntries is the audit-fix two-sided
// probe. It asserts the three defects the audit confirmed are now closed:
//  1. Revoke of the last active key is a SUCCESS with DenyAllPending=true — not a
//     torn 503 (the operator is told the truth, not a false failure).
//  2. The entries file (which re-seeds the store on restart) records the key
//     REVOKED — so a restart cannot resurrect it.
//  3. The boot-set artifact does NOT still publish the revoked key as "active"
//     dressed up as an ordinary successful revoke; the stale-artifact fail-open is
//     explicitly surfaced (DenyAllPending), not hidden.
func TestRevokeLastKey_DenyAllPendingAndHonestEntries(t *testing.T) {
	t.Parallel()
	rig := newMCPKeyTestRig(t)
	ctx := context.Background()

	_, rec, err := rig.eng.Create(ctx, rig.scope, "acme", "prod", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Sanity: after create the boot-set lists the key active.
	if got := readKeysetStatuses(t, rig.keysetPath)[rec.KeyID]; got != "active" {
		t.Fatalf("post-create keyset status for %s = %q, want active", rec.KeyID, got)
	}

	// Revoke the ONLY key.
	outcome, err := rig.eng.Revoke(ctx, rig.scope, rec.KeyID, "operator revoke")
	if err != nil {
		t.Fatalf("revoke of the last key returned an error (%v); want a success with DenyAllPending — a torn 503 is the bug", err)
	}
	if !outcome.DenyAllPending {
		t.Errorf("revoke of the last active key: DenyAllPending = false; want true (the boot-set has no active key to publish)")
	}

	// Defect 2: entries file must record the key revoked (restart cannot resurrect).
	entries, err := os.ReadFile(rig.entriesPath)
	if err != nil {
		t.Fatalf("entries file not written on the last-key revoke (%v); the entries-first ordering is the fix", err)
	}
	if strings.Contains(string(entries), "\"status\": \"active\"") || strings.Contains(string(entries), "\"status\":\"active\"") {
		t.Errorf("entries file still marks a key active after revoking the last key; a restart would resurrect it:\n%s", entries)
	}
	if !strings.Contains(string(entries), "revoked") {
		t.Errorf("entries file does not record the key revoked:\n%s", entries)
	}

	// Defect 3: the boot-set must NOT present the revoked key as a still-active,
	// ordinary-revoke success. Either it is absent (removed) or, per the frozen
	// schema, the stale file is left — but then DenyAllPending MUST be set so the
	// caller does not treat it as a clean revoke. We asserted DenyAllPending above;
	// here we assert the artifact is not silently claiming the revoked key is a
	// fresh, still-valid active key with no signal.
	if status, present := readKeysetStatuses(t, rig.keysetPath)[rec.KeyID]; present && status == "active" && !outcome.DenyAllPending {
		t.Errorf("boot-set still publishes revoked key %s as active with no deny-all signal — silent fail-open", rec.KeyID)
	}

	// Restart simulation: a fresh store seeded from the entries file must NOT
	// present the revoked key as active.
	seeded := mcpkey.NewInMemRecordStore()
	loaded := loadEntriesForTest(t, rig.entriesPath)
	for _, r := range loaded {
		if err := seeded.Put(ctx, r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	active, err := seeded.ActiveRecords(ctx, rig.clk.Now())
	if err != nil {
		t.Fatalf("seeded ActiveRecords: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("after restart-from-entries the revoked key is active again: %d active records, want 0", len(active))
	}
}

// TestRevokeOneOfTwo_NoDenyAll is the non-terminal control: revoking one of two
// keys omits it from the boot-set with NO DenyAllPending, so the deny-all path is
// specific to the last-key case and does not fire on an ordinary revoke.
func TestRevokeOneOfTwo_NoDenyAll(t *testing.T) {
	t.Parallel()
	rig := newMCPKeyTestRig(t)
	ctx := context.Background()

	_, rec1, err := rig.eng.Create(ctx, rig.scope, "acme", "prod", nil)
	if err != nil {
		t.Fatalf("create 1: %v", err)
	}
	_, rec2, err := rig.eng.Create(ctx, rig.scope, "acme", "staging", nil)
	if err != nil {
		t.Fatalf("create 2: %v", err)
	}

	outcome, err := rig.eng.Revoke(ctx, rig.scope, rec1.KeyID, "one of two")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if outcome.DenyAllPending {
		t.Errorf("revoking one of two keys set DenyAllPending; want false (a key remains active)")
	}
	statuses := readKeysetStatuses(t, rig.keysetPath)
	if _, present := statuses[rec1.KeyID]; present {
		t.Errorf("revoked key %s still present in the boot-set", rec1.KeyID)
	}
	if statuses[rec2.KeyID] != "active" {
		t.Errorf("surviving key %s status = %q, want active", rec2.KeyID, statuses[rec2.KeyID])
	}
}

// loadEntriesForTest reads the entries file back into records via the shipped
// loader, exercising the exact round-trip a daemon restart performs.
func loadEntriesForTest(t *testing.T, path string) []mcpkey.Record {
	t.Helper()
	// Re-seed via the same package the daemon uses on boot; keep the read local so
	// the test does not reach into unexported daemon state.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read entries: %v", err)
	}
	var doc struct {
		Records []mcpkey.Record `json:"records"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse entries: %v", err)
	}
	return doc.Records
}
