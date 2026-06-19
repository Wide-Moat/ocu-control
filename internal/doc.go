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
//
// Lands as the later phases fill in (each behind a narrow seam, per
// component-02):
//
//	internal/runtime      — the RuntimeProvider seam (Docker is the v1 backend)
//	internal/admission    — the workload-trust-profile × runtime-tier matrix,
//	                        run fail-closed at the top of Create
//	internal/ingress      — the two listeners (operator + gateway), distinct
//	                        endpoints, no cross-route
//
// The coverage floor and the mutation scope (.gremlins.yaml) are declared
// against these paths so they ratchet as the code arrives.
package internal
