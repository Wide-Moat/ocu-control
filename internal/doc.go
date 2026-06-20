// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package internal is the layout anchor for ocu-control's private packages.
//
// Landed (Phase 1 — the control-plane spine):
//
//	internal/state           — the state.Store seam: the session registry, the
//	                           denylist / kill-switch deny posture, and the quota
//	                           counters, behind one interface. In-memory (minimal
//	                           shelf) and Postgres implementations pass one shared
//	                           conformance suite.
//	internal/state/postgres  — the Postgres state.Store: advisory-lock
//	                           row-as-reservation, durable deny posture, atomic
//	                           quota counters. The only package that imports pgx.
//	internal/state/statetest — the cross-implementation conformance + property +
//	                           race suite, importable by both legs' tests (so the
//	                           production state package never imports testing).
//	internal/boot            — the kill-switch-first boot sequencer: load the deny
//	                           posture and engage DENY-ALL before any listener
//	                           binds, fail-closed on an unavailable store, and the
//	                           /healthz readiness gate.
//	internal/runtime         — the RuntimeProvider seam: one coarse Materialize +
//	                           the canon-fixed teardown pair + Reconcile, behind a
//	                           substrate-neutral descriptor. The k8s and Firecracker
//	                           backends are NotImplemented stubs.
//	internal/runtime/docker  — the v1 Docker backend (the only package that imports
//	                           the Docker SDK): the HOST-01 hardened HostConfig, the
//	                           embedded deny-default seccomp profile, the atomic
//	                           Materialize with rollback, and the NFR-SEC-65 ordered
//	                           teardown finalizer.
//	internal/runtimemap      — the single mapping between state.Identity and the
//	                           runtime seam's leaf-local Identity, with a
//	                           compile-time field-parity guard.
//	internal/admission       — the workload-trust-profile × runtime-tier matrix as
//	                           a total, fail-closed data table (NFR-SEC-38).
//	internal/quota           — the create-time quota gate: atomic check-and-charge
//	                           over the Store counters, refused-not-queued.
//	internal/registry        — the session-registry sole custodian: the only caller
//	                           of the Store reservation mutators; the host-derived
//	                           Key that a body id can never become.
//	internal/handoff         — stages the non-secret handoff material (info JSON,
//	                           the Ed25519 public key, the 0700 sock dir).
//	internal/audit           — the fail-closed AuditSink port; the deny-on-emit
//	                           branch ships now, the OCSF serializer is later.
//	internal/ingress         — the capability scope seam: an OperatorScope is
//	                           mintable only by possessing the OperatorSeam, so the
//	                           gateway cannot call an operator route at compile time.
//	internal/ingress/operator — the operator/lifecycle Unix-socket ingress (holds
//	                           the OperatorSeam; SO_PEERCRED-attested + SOAR).
//	internal/ingress/gateway — the gateway service-identity ingress (mTLS cert-SAN;
//	                           no operator scope).
//	internal/lifecycle       — the create→destroy pipeline: an ordered []stage with
//	                           a LIFO unwind stack so a failed create leaves no orphan.
//	internal/killswitch      — the host-initiated revoke engine (one/all), audit-first
//	                           fail-closed, reachable only on the operator scope.
//
// The coverage floor and the mutation scope (.gremlins.yaml) are declared
// against these paths so they ratchet as the code arrives.
package internal
