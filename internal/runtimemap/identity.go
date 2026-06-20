// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package runtimemap is the lifecycle-layer bridge between the two leaf seams
// internal/state and internal/runtime. Neither leaf imports the other:
// internal/runtime is a leaf that re-declares its own Identity (Tenant, Caller)
// so the provider carries no dependency on the durable-state package, and
// internal/state owns the authoritative host-derived caller identity. This
// package is the single, named place the host-derived state.Identity is mapped
// into the runtime.Identity the provider labels a session with, so the two can
// never drift unobserved: a compile-time field-parity test in this package fails
// to build the moment either struct grows, loses, renames, or re-types a field.
//
// The mapping is a pure relabelling — it derives no authority. runtime.Identity
// is opaque labelling material to the provider (NFR-SEC-43); the authority
// decision keyed on the identity has already been made in internal/state by the
// time the lifecycle layer calls Materialize. This is the only function in the
// tree that constructs a runtime.Identity from a state.Identity; keeping it
// single makes the parity contract enforceable in one spot.
package runtimemap

import (
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// IdentityFromState maps the host-derived state.Identity into the leaf-seam
// runtime.Identity the provider labels a session with. It is a field-for-field
// relabelling and derives no authority: the runtime layer treats the result as
// opaque labelling material (NFR-SEC-43). This is the ONLY constructor of a
// runtime.Identity from a state.Identity, so the field-parity test in this
// package guards the single point the two seams meet.
func IdentityFromState(id state.Identity) runtime.Identity {
	return runtime.Identity{
		Tenant: id.Tenant,
		Caller: id.Caller,
	}
}
