// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey_test

import (
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey/mcpkeytest"
)

// TestInMemConformance is the canonical in-memory leg runner for the shared
// RecordStore conformance suite. It mirrors the pattern
// internal/state/inmem_test.go uses to run statetest.RunConformance: a fresh
// store per test via a factory lambda, hermetic subtests, and the shared suite
// covering the full behavioural contract.
func TestInMemConformance(t *testing.T) {
	mcpkeytest.RunConformance(t, func() mcpkey.RecordStore {
		return mcpkey.NewInMemRecordStore()
	})
}
