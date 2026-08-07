// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestNewHandlersAppliesTheContractReplayWindow pins the default a deployment
// gets when it configures nothing.
//
// The window is checked by BEHAVIOUR — an issuance just inside it is admitted,
// one just outside is refused — rather than by reading the constant back.
// Asserting the constant would leave a zeroed default undetected: every
// functional replay test builds its guard directly with an explicit window, so
// none of them exercises the defaulting path at all.
func TestNewHandlersAppliesTheContractReplayWindow(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	h := NewHandlers(Deps{Clock: clk})

	if h.replay == nil {
		t.Fatal("NewHandlers wired no replay guard; the SOAR path would serve " +
			"revokes that stay presentable for the life of their window")
	}

	inside := rfc3339(replayStart.Add(-(defaultSOARReplayWindow - time.Second)))
	if err := h.replay.admit(inside, []byte("sig-inside")); err != nil {
		t.Errorf("an issuance inside the default window was refused: %v — a zero or "+
			"narrowed default refuses legitimate revokes from any peer whose clock "+
			"is not the host's exact instant", err)
	}

	outside := rfc3339(replayStart.Add(-(defaultSOARReplayWindow + time.Second)))
	if err := h.replay.admit(outside, []byte("sig-outside")); err == nil {
		t.Error("an issuance beyond the default window was admitted; a widened " +
			"default keeps a captured revoke presentable for longer")
	}
}

// TestNewHandlersHonoursAnExplicitReplayWindow pins that the tunable is read.
// Without it the field could be ignored and the default silently applied to
// every deployment.
func TestNewHandlersHonoursAnExplicitReplayWindow(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	h := NewHandlers(Deps{Clock: clk, SOARReplayWindow: 10 * time.Second})

	// Inside the configured 10s but far inside the 300s default: it must be
	// refused, which it can only be if the explicit value took effect.
	beyond := rfc3339(replayStart.Add(-60 * time.Second))
	if err := h.replay.admit(beyond, []byte("sig")); err == nil {
		t.Error("an issuance outside the CONFIGURED window was admitted; the " +
			"SOARReplayWindow tunable is ignored and every deployment silently " +
			"runs the default")
	}
}
