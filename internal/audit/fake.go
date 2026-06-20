// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import (
	"context"
	"fmt"
	"sync"
)

// RecordingFake is the test AuditSink. It records every Record passed to a
// successful Emit, in order, so a test can assert the exact privileged events a
// flow attested and in what sequence. It also carries a FAULT mode so the
// fail-closed deny branch on every privileged op is exercised against a real
// failing sink rather than asserted on faith: with a fault armed, Emit returns a
// wrapped ErrAuditWriteFailed and records NOTHING, modelling a sink that could
// not make the record durable. It is safe for concurrent use.
//
// This is a leaf test double — it ships in the non-test build so the layers above
// can construct it in their own tests without a test-only build tag, mirroring
// the in-tree fakes the other seams ship.
type RecordingFake struct {
	mu sync.Mutex
	// records holds every Record a successful Emit accepted, in call order.
	records []Record
	// fault, when non-nil, makes every Emit fail closed: it returns a wrapped
	// ErrAuditWriteFailed and records nothing. cause supplies the underlying
	// reason wrapped into the sentinel.
	fault bool
	cause error
}

// NewRecordingFake returns an empty RecordingFake in success mode: Emit records
// and returns nil until SetFault arms the fault.
func NewRecordingFake() *RecordingFake {
	return &RecordingFake{}
}

// SetFault arms or disarms the fault mode. When armed (on true), every subsequent
// Emit fails closed with a wrapped ErrAuditWriteFailed and records nothing; cause
// is the underlying reason wrapped into the sentinel, and a nil cause is replaced
// by a default so the wrap is always meaningful. Passing false disarms the fault
// and restores success mode.
func (f *RecordingFake) SetFault(on bool, cause error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = on
	if on && cause == nil {
		cause = fmt.Errorf("recording fake fault armed")
	}
	f.cause = cause
}

// Emit records rec and returns nil in success mode. With the fault armed it
// returns a wrapped ErrAuditWriteFailed (so errors.Is(err, ErrAuditWriteFailed)
// holds) and records nothing, so the caller's fail-closed deny branch runs and a
// later Records() assertion proves no event was attested for the denied action.
func (f *RecordingFake) Emit(ctx context.Context, rec Record) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: context: %w", ErrAuditWriteFailed, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fault {
		return fmt.Errorf("%w: %w", ErrAuditWriteFailed, f.cause)
	}
	f.records = append(f.records, rec)
	return nil
}

// Records returns a copy of every Record a successful Emit accepted, in call
// order. The copy is independent of the fake's internal slice, so a caller may
// inspect it without racing a concurrent Emit.
func (f *RecordingFake) Records() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Record, len(f.records))
	copy(out, f.records)
	return out
}

// Len returns the number of records a successful Emit has accepted so far.
func (f *RecordingFake) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}
