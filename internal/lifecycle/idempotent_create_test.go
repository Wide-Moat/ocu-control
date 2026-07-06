// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestCreateResumesActiveSessionOnHintCollision is the Finding #5 keystone K1. A
// gateway that reuses a stable per-chat session_hint sends the SAME hint on every
// tool-call in an agent loop. Because the host handle is deterministic in the hint
// and the Key mixes the host-attested owner in, the second create derives the SAME
// Key as the first — so S4 Reserve currently fails ErrReservationExists and the
// ingress maps it to an opaque 409, breaking the multi-step chat.
//
// The fix makes create idempotent by (owner, hint): a second create whose derived
// Key already names the caller's OWN, ACTIVE session RESUMES it — it returns the
// existing row (the guest is already up) instead of 409. This test creates twice
// with the same hint and asserts the second returns the SAME key and an ACTIVE
// state, not an error. Remove the resume guard and the second create reds with
// ErrReservationExists.
func TestCreateResumesActiveSessionOnHintCollision(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	first, err := h.mgr.Create(ctx, input("chat-42"))
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if first.State != state.StateActive {
		t.Fatalf("first row state = %v, want ACTIVE", first.State)
	}

	// Same caller, same hint: the agent loop's second tool-call. This must RESUME the
	// live session, not 409.
	second, err := h.mgr.Create(ctx, input("chat-42"))
	if err != nil {
		t.Fatalf("second Create (same hint) must resume, not error: %v", err)
	}
	if second.Key != first.Key {
		t.Fatalf("resume returned a different key: first=%q second=%q (must address the SAME session)", first.Key, second.Key)
	}
	if second.State != state.StateActive {
		t.Fatalf("resumed row state = %v, want ACTIVE", second.State)
	}
	// The resume reuses the existing container — no second one was materialized.
	if got := h.provider.liveCount(); got != 1 {
		t.Fatalf("provider live containers = %d, want 1 (resume must not materialize a second)", got)
	}
}

// TestCreateResumeEmitsDurableAudit is the boundary-#4 keystone: a resume is not a
// silent read. The operator must see that a session was RESUMED (reused), not
// created anew — a distinct OCSF action, emitted fail-closed before the row is
// returned. This asserts the second create emits an ActionCreateResume record with
// the host-attested owner and the session key.
func TestCreateResumeEmitsDurableAudit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	first, err := h.mgr.Create(ctx, input("chat-7"))
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	// The first create emitted its own commit record; the resume's records are
	// everything AFTER that, so the assertion isolates exactly what the resume attests.
	afterFirst := h.audit.Len()

	if _, err := h.mgr.Create(ctx, input("chat-7")); err != nil {
		t.Fatalf("second Create (resume): %v", err)
	}

	resumeRecs := h.audit.Records()[afterFirst:]
	if len(resumeRecs) != 1 {
		t.Fatalf("resume audit records = %d, want exactly 1", len(resumeRecs))
	}
	rec := resumeRecs[0]
	if rec.Action != audit.ActionCreateResume {
		t.Fatalf("resume audit action = %v, want ActionCreateResume", rec.Action)
	}
	if rec.Key != first.Key {
		t.Fatalf("resume audit key = %q, want %q (the resumed session)", rec.Key, first.Key)
	}
	if rec.Caller != testCaller.Identity.Caller || rec.Tenant != testCaller.Identity.Tenant {
		t.Fatalf("resume audit actor = %s/%s, want the host-attested owner %s/%s",
			rec.Tenant, rec.Caller, testCaller.Identity.Tenant, testCaller.Identity.Caller)
	}
}

// TestCreateResumeDoesNotChargeConcurrency is the Finding #5 keystone K2 and the
// load-bearing boundary #3. A resume must NOT charge the DimConcurrentSessions cell
// a second time — the live session already holds its one slot. Charging again is the
// exact create-abort double-charge leak (#4-class): the cell would drift above the
// true live count and eventually wedge the tier cap with phantom charges.
//
// The proof is that the cell does not MOVE across the resume: the counter after the
// second create equals the counter after the first — it never dips and re-charges,
// it simply is not touched (a clean skip of S3, not a charge-then-refund). Remove the
// resume guard's bypass of the charge stage and the cell climbs to 2 — this reds.
func TestCreateResumeDoesNotChargeConcurrency(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()
	owner := testCaller.Identity

	if _, err := h.mgr.Create(ctx, input("chat-99")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	afterFirst := concurrentCount(t, h.store, owner)
	if afterFirst != 1 {
		t.Fatalf("concurrency cell after first create = %d, want 1", afterFirst)
	}

	if _, err := h.mgr.Create(ctx, input("chat-99")); err != nil {
		t.Fatalf("second Create (resume): %v", err)
	}
	afterSecond := concurrentCount(t, h.store, owner)
	if afterSecond != afterFirst {
		t.Fatalf("concurrency cell after resume = %d, want %d (resume must NOT charge — the slot is already held)",
			afterSecond, afterFirst)
	}
}

// TestCreateDoesNotResumeForeignOwner is the Finding #5 keystone K3 and the
// load-bearing boundary #1. Resume is scoped to the caller's OWN session: a
// DIFFERENT owner presenting the SAME hint must NOT resume the first owner's session
// — it gets its own, separate session. This is a direct consequence of DeriveKey
// mixing the host-attested owner into the Key (NFR-SEC-43): the two callers derive
// DIFFERENT keys, so the second's lookup finds nothing of its own to resume and runs
// a normal create. This asserts the foreign caller's session has a different key and
// that two live containers exist. Remove the owner scoping and the foreign caller
// resumes the victim's session (one container, shared key) — this reds.
func TestCreateDoesNotResumeForeignOwner(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	first, err := h.mgr.Create(ctx, input("shared-hint"))
	if err != nil {
		t.Fatalf("first Create (owner A): %v", err)
	}

	// A second, DIFFERENT owner presents the identical hint.
	foreign := input("shared-hint")
	foreign.Caller = ingress.AuthenticatedCaller{
		Identity: state.Identity{Tenant: "tenant-b", Caller: "caller-2"},
		Channel:  ingress.ChannelGateway,
	}
	second, err := h.mgr.Create(ctx, foreign)
	if err != nil {
		t.Fatalf("foreign Create must run a normal create, not error: %v", err)
	}
	if second.Key == first.Key {
		t.Fatalf("foreign owner resumed the victim's session: both keys = %q (owner scoping breached)", first.Key)
	}
	if got := h.provider.liveCount(); got != 2 {
		t.Fatalf("provider live containers = %d, want 2 (two distinct owners = two sessions)", got)
	}
}
