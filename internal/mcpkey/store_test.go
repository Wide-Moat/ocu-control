// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey_test

import (
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey/mcpkeytest"
)

// TestInMemStoreConformance wires the in-memory RecordStore leg to the shared
// conformance suite. All behavioural contract cases run against the in-memory
// impl; the Postgres leg (internal/mcpkey/postgres) runs the identical suite
// against a live database. This is the SOLE in-memory runner (a former duplicate
// runner was removed — two identical runners add no marginal coverage).
func TestInMemStoreConformance(t *testing.T) {
	mcpkeytest.RunConformance(t, func() mcpkey.RecordStore {
		return mcpkey.NewInMemRecordStore()
	})
}
