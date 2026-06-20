// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle

import (
	"context"
	"fmt"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/runtimemap"
)

// stageResolveIdentity (S1) takes the host-derived identity from the resolved
// AuthenticatedCaller, mints an opaque host handle seeded by — but not equal to —
// the body SessionHint, and computes the host-derived Key. A missing/empty host
// identity is a HARD reject before any host state. Because registry.Key has no
// raw-string constructor and DeriveKey mixes the owner Identity in, a body id can
// NEVER become the key — a compile fact. Read-only: no compensator.
func stageResolveIdentity(_ context.Context, _ *Manager, st *createState) (compensator, error) {
	owner := st.in.Caller.Identity
	if owner.Caller == "" || owner.Tenant == "" {
		// Fail closed before any host state: an unattested caller seeds no Key.
		return nil, ErrUnattested
	}
	st.owner = owner
	st.handle = mintHandle(st.in.SessionHint)
	st.key = registry.DeriveKey(owner, st.handle)
	if st.key.IsZero() {
		// DeriveKey never produces a zero Key for a non-empty owner+handle; this is
		// the defensive backstop so a malformed key never reaches a Store call.
		return nil, ErrUnattested
	}
	return nil, nil
}

// stageAdmit (S2) calls admission.Decide(profile, tier) — both deployment-fixed,
// neither request-supplied. A not-admitted decision returns
// admission.RejectedError{Reason} wrapping ErrAdmissionRejected. It runs BEFORE any
// host state. Pure; no compensator.
func stageAdmit(_ context.Context, m *Manager, _ *createState) (compensator, error) {
	decision := admission.Decide(m.profile, m.tier)
	if !decision.Admitted {
		return nil, admission.RejectedError{Reason: decision.Reason}
	}
	return nil, nil
}

// stageQuotaCharge (S3) charges the two create-time quota dimensions atomically
// (create-rate windowed THEN concurrent level), refusing-not-queuing on
// ErrQuotaExceeded with zero net counter movement (ChargeCreate refunds any partial
// charge itself). It NEVER reads-then-charges (TOCTOU). On success it pushes
// Receipt.Apply as the compensator. Still before host-visible state (counters are
// internal accounting).
func stageQuotaCharge(ctx context.Context, m *Manager, st *createState) (compensator, error) {
	receipt, err := m.quota.ChargeCreate(ctx, st.owner)
	if err != nil {
		// Refused-not-queued: the typed error (ErrQuotaExceeded or ErrStoreUnavailable)
		// propagates unchanged; ChargeCreate already refunded any partial charge.
		return nil, err
	}
	// The receipt refunds EXACTLY the two cells charged; pushing it onto the unwind
	// stack means a downstream failure decrements only what this stage incremented.
	return receipt.Apply, nil
}

// stageReserve (S4) writes the first DURABLE host state via the Custodian (the SOLE
// Store-mutator caller). Reserve re-checks the deny posture inside its
// advisory-locked critical section, so a revoke landing between S2 and S4 still
// refuses here (ErrKillSwitchEngaged / ErrSessionDenied) and writes no row. On
// success it pushes Release as the compensator.
func stageReserve(ctx context.Context, m *Manager, st *createState) (compensator, error) {
	row, err := m.reg.Reserve(ctx, st.key, st.owner)
	if err != nil {
		// A deny landing mid-create, an existing reservation, or a store fault all
		// surface their typed error unchanged; no row was written.
		return nil, err
	}
	st.row = row
	key := st.key
	owner := st.owner
	return func(cctx context.Context) error {
		// Release drives the row to the RELEASED tombstone, the correct terminal for a
		// reserved-then-failed row. It is idempotent against an already-released row.
		if _, err := m.reg.Release(cctx, key, owner); err != nil {
			return fmt.Errorf("lifecycle: unwind release reservation: %w", err)
		}
		return nil
	}, nil
}

// stageStageHandoff (S5) writes container_info.json, the raw 32-byte Ed25519 PUBLIC
// key, and the 0700 host sockdir, returning handoff.Staged. The MountIntent AuthToken
// stays a later-phase placeholder. A short write or a non-32-byte key fails closed
// here. On success it pushes Unstage as the compensator.
func stageStageHandoff(ctx context.Context, m *Manager, st *createState) (compensator, error) {
	name := runtime.SessionName(st.key.String())
	mounts := []runtime.MountIntent{st.in.Mount}
	staged, err := m.handoff.Stage(ctx, name, st.in.ControlPubKey, mounts)
	if err != nil {
		// A bad key or short write fails closed; Stage removed any partial root, so
		// nothing half-written survives and no compensator is owed.
		return nil, err
	}
	st.staged = staged
	return func(cctx context.Context) error {
		if err := m.handoff.Unstage(cctx, staged); err != nil {
			return fmt.Errorf("lifecycle: unwind unstage handoff: %w", err)
		}
		return nil
	}, nil
}

// stageMaterialize (S6) builds the substrate-neutral SessionSpec and calls
// Materialize. The provider does its OWN internal rollback on a partial create and
// returns ErrMaterialize (no orphan below the seam). On success it pushes a
// force-kill teardown as the compensator (force-remove-authoritative, idempotent).
func stageMaterialize(ctx context.Context, m *Manager, st *createState) (compensator, error) {
	spec := runtime.SessionSpec{
		SchemaVersion: runtime.SchemaV1Alpha,
		Name:          runtime.SessionName(st.key.String()),
		Owner:         runtimemap.IdentityFromState(st.owner),
		Image:         st.in.Image,
		Mounts:        []runtime.MountIntent{st.in.Mount},
		Egress:        st.in.Egress,
		Resources:     st.in.Resources,
		Handoff:       st.staged.Material,
	}
	st.spec = spec
	sandbox, err := m.provider.Materialize(ctx, spec)
	if err != nil {
		// The provider rolled back its own partial create; the error is surfaced and no
		// teardown compensator is owed (nothing survives below the seam).
		return nil, err
	}
	st.sandbox = sandbox
	return func(cctx context.Context) error {
		// Force-remove is authoritative and idempotent: an already-gone container maps
		// to ErrNoSuchContainer, which is a satisfied kill, not a failure.
		if err := m.provider.Teardown().ForceKill(cctx, sandbox); err != nil {
			return fmt.Errorf("lifecycle: unwind force-kill sandbox: %w", err)
		}
		return nil
	}, nil
}

// stageCommit (S7) promotes the reservation RESERVED → ACTIVE via the Custodian,
// then emits the create-commit audit record FAIL-CLOSED: a write failure DENIES the
// create and unwinds (the single privileged create checkpoint that must be audited
// before ack). A commit conflict fails closed and unwinds S6..S3. No NEW
// compensator: S4's Release already drives a committed-then-failed row to the
// RELEASED tombstone, the correct terminal.
func stageCommit(ctx context.Context, m *Manager, st *createState) (compensator, error) {
	row, err := m.reg.Commit(ctx, st.key, st.owner)
	if err != nil {
		// A commit conflict (already-committed, owner mismatch) or a store fault fails
		// closed; the unwind reverses S6..S3.
		return nil, err
	}
	st.row = row

	// Audit FIRST, fail-closed: the record must be durable before the create is
	// acknowledged. A write failure denies the create and triggers the unwind.
	rec := audit.Record{
		Action:  audit.ActionCreateCommit,
		Channel: st.in.Caller.Channel.String(),
		Key:     st.key.String(),
		Caller:  st.owner.Caller,
		Tenant:  st.owner.Tenant,
	}
	if err := m.audit.Emit(ctx, rec); err != nil {
		return nil, fmt.Errorf("lifecycle: commit audit: %w", err)
	}
	return nil, nil
}

// stageBind (S8) records the host-assigned runtime container identity write-once via
// the Custodian — the host-attested predicate later host connections validate
// against. ErrBindingExists fails closed and unwinds. On success the create is
// COMPLETE and the unwind stack is discarded. The bound row becomes the Create
// result. No compensator (the bind is the terminal success step; a failure after it
// would be reversed by the prior stages' compensators, but there is no later stage).
func stageBind(ctx context.Context, m *Manager, st *createState) (compensator, error) {
	containerName := st.sandbox.RuntimeID
	if containerName == "" {
		// The provider should always assign a runtime id on a successful Materialize;
		// fall back to the host-derived name so the write-once bind still has a stable,
		// host-derived predicate rather than an empty string.
		containerName = st.key.String()
	}
	row, err := m.reg.BindContainerName(ctx, st.key, st.owner, containerName)
	if err != nil {
		// A rebind-poison attempt or a name already claimed elsewhere fails closed and
		// unwinds S7..S3.
		return nil, err
	}
	st.row = row
	return nil, nil
}
