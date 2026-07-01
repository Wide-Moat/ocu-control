// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

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
