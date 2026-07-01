// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"context"
	"errors"
	"testing"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// privilegedActionGen draws an arbitrary enumerated privileged Action so the
// generated spine spans the whole audited verb surface, not just create/destroy.
func privilegedActionGen() *rapid.Generator[audit.Action] {
	priv := audit.PrivilegedActions()
	return rapid.Custom(func(rt *rapid.T) audit.Action {
		i := rapid.IntRange(0, len(priv)-1).Draw(rt, "action_idx")
		return priv[i]
	})
}

// recordGen draws a Record with arbitrary host-derived identity fields so the
// canonical event bytes vary across the spine, giving the hash something to chain.
func recordGen() *rapid.Generator[audit.Record] {
	return rapid.Custom(func(rt *rapid.T) audit.Record {
		return audit.Record{
			Action:  privilegedActionGen().Draw(rt, "action"),
			Channel: rapid.SampledFrom([]string{"operator", "gateway"}).Draw(rt, "channel"),
			Key:     rapid.StringMatching(`[a-z0-9-]{0,24}`).Draw(rt, "key"),
			Caller:  rapid.StringMatching(`[a-z0-9-]{1,24}`).Draw(rt, "caller"),
			Tenant:  rapid.StringMatching(`[a-z0-9-]{1,24}`).Draw(rt, "tenant"),
			Reason:  rapid.StringMatching(`[a-zA-Z0-9 .-]{0,48}`).Draw(rt, "reason"),
		}
	})
}

// emitSpine drives N Emits through a fresh ChainSink over a capturing writer and
// returns the captured envelopes. It is the SOURCE the property mutates.
func emitSpine(rt *rapid.T, n int) []ocsf.ChainEnvelope {
	w := &capturingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")
	ctx := context.Background()
	for i := 0; i < n; i++ {
		rec := recordGen().Draw(rt, "record")
		if err := sink.Emit(ctx, rec); err != nil {
			rt.Fatalf("Emit %d: %v", i, err)
		}
	}
	return w.snapshot()
}

// TestProperty_ChainTamperEvidence is the MANDATORY tamper-evidence property: a spine
// the sink built validates, and ANY single mutation of an earlier event (a payload
// byte flip, a swap of two events, or an edited sequence) breaks ValidateChain. The
// link cascade is the evidence: mutating event i breaks the recompute of event i and,
// via the prior-hash link, every event after it.
func TestProperty_ChainTamperEvidence(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(2, 12).Draw(rt, "n")
		envs := emitSpine(rt, n)

		// The freshly built spine validates.
		if err := ocsf.ValidateChain(envs); err != nil {
			rt.Fatalf("ValidateChain over freshly emitted spine = %v, want nil", err)
		}

		// Choose a mutation kind and apply it to a copy.
		mutated := make([]ocsf.ChainEnvelope, len(envs))
		copy(mutated, envs)

		switch rapid.SampledFrom([]string{"flip_byte", "swap", "edit_sequence", "edit_prior"}).Draw(rt, "mutation") {
		case "flip_byte":
			// Flip one byte of one event's payload.
			idx := rapid.IntRange(0, len(mutated)-1).Draw(rt, "idx")
			payload := make([]byte, len(mutated[idx].Event))
			copy(payload, mutated[idx].Event)
			pos := rapid.IntRange(0, len(payload)-1).Draw(rt, "byte_pos")
			payload[pos] ^= 0xFF
			mutated[idx].Event = payload
		case "swap":
			// Swap two distinct events (their payloads/hashes no longer line up).
			i := rapid.IntRange(0, len(mutated)-1).Draw(rt, "swap_i")
			j := rapid.IntRange(0, len(mutated)-1).Draw(rt, "swap_j")
			if i == j {
				j = (j + 1) % len(mutated)
			}
			mutated[i], mutated[j] = mutated[j], mutated[i]
		case "edit_sequence":
			idx := rapid.IntRange(0, len(mutated)-1).Draw(rt, "seq_idx")
			mutated[idx].Sequence += uint64(rapid.IntRange(1, 100).Draw(rt, "seq_delta"))
		case "edit_prior":
			// Corrupt a prior-hash link on a non-genesis event by rotating its first hex
			// digit to a different valid hex character — the link check (and, failing
			// that, the recompute) trips, both reporting ErrChainInvalid.
			idx := rapid.IntRange(1, len(mutated)-1).Draw(rt, "prior_idx")
			b := []byte(mutated[idx].PriorHash)
			if b[0] == '0' {
				b[0] = '1'
			} else {
				b[0] = '0'
			}
			mutated[idx].PriorHash = string(b)
		}

		if err := ocsf.ValidateChain(mutated); !errors.Is(err, ocsf.ErrChainInvalid) {
			rt.Fatalf("ValidateChain over mutated spine = %v, want ErrChainInvalid (tamper evidence)", err)
		}
	})
}

// TestProperty_ChainSinkSpineAlwaysMonotonic drives a random count of Emits and
// asserts the emitted spine always validates with a strictly 1..N monotonic
// sequence — the sink never produces a gap, duplicate, or broken link on the success
// path.
func TestProperty_ChainSinkSpineAlwaysMonotonic(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 20).Draw(rt, "n")
		envs := emitSpine(rt, n)
		if len(envs) != n {
			rt.Fatalf("emitted %d envelopes, want %d", len(envs), n)
		}
		for i, e := range envs {
			if e.Sequence != uint64(i+1) {
				rt.Fatalf("envelope[%d].sequence = %d, want %d", i, e.Sequence, i+1)
			}
		}
		if err := ocsf.ValidateChain(envs); err != nil {
			rt.Fatalf("ValidateChain = %v, want nil", err)
		}
	})
}
