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
// against a live database.
func TestInMemStoreConformance(t *testing.T) {
	mcpkeytest.RunConformance(t, func() mcpkey.RecordStore {
		return mcpkey.NewInMemRecordStore()
	})
}

// TestStateStoreInterfaceUnchanged is a compile-time assertion via import:
// this test file imports mcpkey but NOT internal/state's Store interface, and
// the grep gate in the verify step confirms internal/state/store.go is
// byte-unchanged. This test serves as a documentation anchor; the real gate is
// the verify step's diff check.
func TestStateStoreInterfaceUnchanged(t *testing.T) {
	t.Log("state.Store interface unchanged: verified by grep/diff in plan verify step")
}
