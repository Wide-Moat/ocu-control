// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestValidateChainEmpty proves an empty input is a valid (empty) chain.
func TestValidateChainEmpty(t *testing.T) {
	t.Parallel()
	if err := ValidateChain(nil); err != nil {
		t.Fatalf("ValidateChain(nil) = %v, want nil", err)
	}
}

// buildEnvelopes constructs n well-linked envelopes with deterministic payloads so
// the unit tests can mutate a known-good chain and assert the failure surfaces.
func buildEnvelopes(t *testing.T, n int) []ChainEnvelope {
	t.Helper()
	envs := make([]ChainEnvelope, 0, n)
	prior := genesisPriorHash
	for i := 0; i < n; i++ {
		payload, err := json.Marshal(map[string]int{"i": i})
		if err != nil {
			t.Fatalf("marshal payload %d: %v", i, err)
		}
		seq := uint64(i + 1)
		hash, err := computeHash(prior, seq, payload)
		if err != nil {
			t.Fatalf("computeHash %d: %v", i, err)
		}
		envs = append(envs, ChainEnvelope{
			Source: "test", Sequence: seq, PriorHash: prior, Hash: hash, Event: payload,
		})
		prior = hash
	}
	return envs
}

// TestValidateChainAcceptsWellLinked proves a correctly built spine validates.
func TestValidateChainAcceptsWellLinked(t *testing.T) {
	t.Parallel()
	envs := buildEnvelopes(t, 5)
	if err := ValidateChain(envs); err != nil {
		t.Fatalf("ValidateChain(well-linked) = %v, want nil", err)
	}
}

// TestValidateChainRejectsMutatedPayload proves a single-byte mutation of an earlier
// event breaks validation: the recomputed hash no longer matches the stored one.
func TestValidateChainRejectsMutatedPayload(t *testing.T) {
	t.Parallel()
	envs := buildEnvelopes(t, 4)
	envs[1].Event = json.RawMessage(`{"i":999}`) // mutate event 1's payload
	err := ValidateChain(envs)
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("ValidateChain(mutated payload) = %v, want ErrChainInvalid", err)
	}
}

// TestValidateChainRejectsBrokenPriorLink proves editing an envelope's prior_hash
// breaks the link check against the previous event's hash.
func TestValidateChainRejectsBrokenPriorLink(t *testing.T) {
	t.Parallel()
	envs := buildEnvelopes(t, 3)
	envs[2].PriorHash = genesisPriorHash // wrong: should be envs[1].Hash
	err := ValidateChain(envs)
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("ValidateChain(broken link) = %v, want ErrChainInvalid", err)
	}
}

// TestValidateChainRejectsNonMonotonicSequence proves a non +1 sequence is rejected.
func TestValidateChainRejectsNonMonotonicSequence(t *testing.T) {
	t.Parallel()
	envs := buildEnvelopes(t, 3)
	envs[2].Sequence = 99 // gap, not +1
	err := ValidateChain(envs)
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("ValidateChain(seq gap) = %v, want ErrChainInvalid", err)
	}
}

// TestValidateChainRejectsBadGenesisSequence proves the first event must be seq 1.
func TestValidateChainRejectsBadGenesisSequence(t *testing.T) {
	t.Parallel()
	envs := buildEnvelopes(t, 2)
	envs[0].Sequence = 5
	// Re-link with the bad genesis sequence so only the genesis-seq check trips.
	hash, err := computeHash(envs[0].PriorHash, envs[0].Sequence, envs[0].Event)
	if err != nil {
		t.Fatalf("computeHash: %v", err)
	}
	envs[0].Hash = hash
	if err := ValidateChain(envs); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("ValidateChain(genesis seq != 1) = %v, want ErrChainInvalid", err)
	}
}

// TestComputeHashRejectsMalformedPriorHash proves a non-hex prior_hash is a hard
// error, never silently hashing the hex text.
func TestComputeHashRejectsMalformedPriorHash(t *testing.T) {
	t.Parallel()
	_, err := computeHash("not-hex-zz", 1, []byte(`{}`))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("computeHash(bad prior) = %v, want ErrChainInvalid", err)
	}
}

// TestCanonicalizeDeterministic proves equal events serialize to identical bytes,
// the property the hash relies on.
func TestCanonicalizeDeterministic(t *testing.T) {
	t.Parallel()
	ev := OCSFEvent{ClassUID: classUIDAPIActivity, ActivityID: activityCreate}
	a, err := canonicalize(ev)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	b, err := canonicalize(ev)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonicalize not deterministic:\n a=%s\n b=%s", a, b)
	}
}
