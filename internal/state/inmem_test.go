// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package state_test

import (
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/state"
	"github.com/Wide-Moat/ocu-control/internal/state/statetest"
)

// TestInMemory_Conformance runs the shared Store conformance suite against the
// in-memory leg. The constructor closes over the suite-supplied FakeClock, so
// the in-memory store stamps time through the injected seam exactly as the
// Postgres leg does. The Postgres leg runs this identical suite through its own
// constructor, so both legs are held to one behavioural contract.
func TestInMemory_Conformance(t *testing.T) {
	t.Parallel()
	statetest.RunConformance(t, func(clk state.Clock) state.Store {
		return state.NewInMemory(clk)
	})
}
