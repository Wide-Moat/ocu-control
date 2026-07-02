// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// maxScopeLen mirrors the engine's cap (the frozen A2 maxLength 256 on
// $defs Tenant/Deployment). Kept here as a test-local literal so the boundary
// cases read explicitly; a drift between this and the engine const is caught by
// the 256-accepted / 257-refused pair below.
const maxScopeLen = 256

// TestEngine_Create_EmptyTenantRefused confirms Create refuses an empty tenant
// with ErrTenantMissing before any side effect: no mint escapes, no audit record
// is emitted, no re-render fires. The published A2 record pins tenant with
// minLength 1 (contracts/mcp/mcp-key-set.schema.json), so a record minted with
// an empty tenant would render a schema-invalid artifact — the mint path fails
// closed instead.
func TestEngine_Create_EmptyTenantRefused(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	sk, _, err := eng.Create(context.Background(), scope, "", "deploy-1", nil)
	if !errors.Is(err, mcpkey.ErrTenantMissing) {
		t.Fatalf("Create(empty tenant) err = %v, want ErrTenantMissing", err)
	}
	if !sk.IsZero() {
		t.Error("Create(empty tenant): returned non-zero SecretKey on refusal")
	}
	if sink.Len() != 0 {
		t.Errorf("Create(empty tenant): audit records emitted = %d, want 0", sink.Len())
	}
	if rerenderCount != 0 {
		t.Errorf("Create(empty tenant): re-renders = %d, want 0", rerenderCount)
	}
}

// TestEngine_Create_EmptyDeploymentRefused mirrors the tenant refusal for the
// deployment field: the canon create-request marks deployment required and the
// A2 record pins it with minLength 1, so an empty deployment is refused with
// ErrDeploymentMissing before mint, audit, or re-render.
func TestEngine_Create_EmptyDeploymentRefused(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	sk, _, err := eng.Create(context.Background(), scope, "tenant-a", "", nil)
	if !errors.Is(err, mcpkey.ErrDeploymentMissing) {
		t.Fatalf("Create(empty deployment) err = %v, want ErrDeploymentMissing", err)
	}
	if !sk.IsZero() {
		t.Error("Create(empty deployment): returned non-zero SecretKey on refusal")
	}
	if sink.Len() != 0 {
		t.Errorf("Create(empty deployment): audit records emitted = %d, want 0", sink.Len())
	}
	if rerenderCount != 0 {
		t.Errorf("Create(empty deployment): re-renders = %d, want 0", rerenderCount)
	}
}

// TestEngine_Create_OverLongTenantRefused confirms Create refuses a tenant longer
// than the frozen A2 maxLength (256) with ErrTenantTooLong before any side
// effect. Without this cap an operator-supplied over-long tenant mints a record
// the published artifact cannot legally render, and a strict gateway boot-loader
// rejects the WHOLE artifact — every key in the deployment stops validating off
// one bad mint. This is the maxLength half of the same guard as the empty check.
func TestEngine_Create_OverLongTenantRefused(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	overLong := strings.Repeat("t", maxScopeLen+1)
	sk, _, err := eng.Create(context.Background(), scope, overLong, "deploy-1", nil)
	if !errors.Is(err, mcpkey.ErrTenantTooLong) {
		t.Fatalf("Create(over-long tenant) err = %v, want ErrTenantTooLong", err)
	}
	if !sk.IsZero() {
		t.Error("Create(over-long tenant): returned non-zero SecretKey on refusal")
	}
	if sink.Len() != 0 {
		t.Errorf("Create(over-long tenant): audit records emitted = %d, want 0", sink.Len())
	}
	if rerenderCount != 0 {
		t.Errorf("Create(over-long tenant): re-renders = %d, want 0", rerenderCount)
	}
}

// TestEngine_Create_OverLongDeploymentRefused mirrors the tenant length cap for
// the deployment field (A2 maxLength 256), refused with ErrDeploymentTooLong
// before mint, audit, or re-render.
func TestEngine_Create_OverLongDeploymentRefused(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	overLong := strings.Repeat("d", maxScopeLen+1)
	sk, _, err := eng.Create(context.Background(), scope, "tenant-a", overLong, nil)
	if !errors.Is(err, mcpkey.ErrDeploymentTooLong) {
		t.Fatalf("Create(over-long deployment) err = %v, want ErrDeploymentTooLong", err)
	}
	if !sk.IsZero() {
		t.Error("Create(over-long deployment): returned non-zero SecretKey on refusal")
	}
	if sink.Len() != 0 {
		t.Errorf("Create(over-long deployment): audit records emitted = %d, want 0", sink.Len())
	}
	if rerenderCount != 0 {
		t.Errorf("Create(over-long deployment): re-renders = %d, want 0", rerenderCount)
	}
}

// TestEngine_Create_MaxLenBoundaryAccepted confirms the cap is an inclusive 256:
// a tenant and deployment of EXACTLY maxScopeLen runes are accepted (the record
// is minted), so the guard refuses only what the schema refuses — off-by-one in
// the cap would either reject a legal 256-rune scope or admit an illegal 257.
func TestEngine_Create_MaxLenBoundaryAccepted(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	atCap := strings.Repeat("x", maxScopeLen)
	_, rec, err := eng.Create(context.Background(), scope, atCap, atCap, nil)
	if err != nil {
		t.Fatalf("Create(256-rune tenant+deployment) err = %v, want nil (256 is within the cap)", err)
	}
	if rec.Tenant != atCap || rec.Deployment != atCap {
		t.Errorf("Create(at-cap): record scope not preserved")
	}
	if rerenderCount != 1 {
		t.Errorf("Create(at-cap): re-renders = %d, want 1 (mint succeeded)", rerenderCount)
	}
}
