// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package state

import (
	"strings"
	"testing"
)

// TestInMemory_BilledFacet pins the in-memory leg's billed-scope derivation: the
// lock domain a Charge serializes on is keyed on Identity.Caller for the
// per-caller create-rate dimension and on Identity.Tenant for every other
// dimension. The Postgres leg keys hash(dim, scope_id) on the same derived
// scope, so this is the in-memory realization of the shared contention surface.
// It is a white-box test: it reaches the unexported quotaScopeID directly, so it
// stays in package state rather than the black-box conformance suite.
func TestInMemory_BilledFacet(t *testing.T) {
	t.Parallel()

	id := Identity{Tenant: "the-tenant", Caller: "the-caller"}

	// The create-rate scope id carries the caller, not the tenant.
	createRate := quotaScopeID(QuotaKey{Dim: DimCallerCreateRate, Identity: id, Window: "w"})
	if !strings.Contains(createRate, "the-caller") {
		t.Fatalf("create-rate must bill the caller: scope id %q lacks the caller", createRate)
	}
	if strings.Contains(createRate, "the-tenant") {
		t.Fatalf("create-rate must not bill the tenant: scope id %q carries the tenant", createRate)
	}

	// Every other dimension bills the tenant.
	for _, dim := range []QuotaDim{DimConcurrentSessions, DimMCPCallsPerMin, DimStorageGB, DimEgressBytesPerDay} {
		scope := quotaScopeID(QuotaKey{Dim: dim, Identity: id, Window: "w"})
		if !strings.Contains(scope, "the-tenant") {
			t.Fatalf("dim %d must bill the tenant: scope id %q lacks the tenant", dim, scope)
		}
		if strings.Contains(scope, "the-caller") {
			t.Fatalf("dim %d must not bill the caller: scope id %q carries the caller", dim, scope)
		}
	}
}
