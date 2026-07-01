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

// CapsFromState maps the recorded-data state.Caps into the leaf-seam
// runtime.ResourceCaps, the inverse direction of the durable read-surface. It is
// the same single-point relabelling discipline as IdentityFromState: state owns
// the durable recorded caps (read by the admin surface) and runtime owns the
// provider's hard-cap primitive, neither leaf imports the other, and this package
// is the one named place they meet. PidsLimit is carried as a pointer (nil means
// unset); the value is copied so the result does not alias the source's pointer.
// The field-parity test in this package fails to build the moment either struct
// grows, loses, renames, or re-types a field.
func CapsFromState(c state.Caps) runtime.ResourceCaps {
	out := runtime.ResourceCaps{
		CPUCores:    c.CPUCores,
		MemoryBytes: c.MemoryBytes,
	}
	if c.PidsLimit != nil {
		p := *c.PidsLimit
		out.PidsLimit = &p
	}
	return out
}

// CapsToState maps the leaf-seam runtime.ResourceCaps the provider stamped into
// the recorded-data state.Caps the durable read-surface persists. This is the
// direction the lifecycle activation uses: it takes the caps it just handed the
// provider on the SessionSpec and records them on the row via RecordActivation. It
// is a pure relabelling and derives no authority — the caps are recorded data the
// admin surface renders, never an authority predicate (NFR-SEC-43). PidsLimit is
// copied so the result does not alias the source's pointer.
func CapsToState(c runtime.ResourceCaps) state.Caps {
	out := state.Caps{
		CPUCores:    c.CPUCores,
		MemoryBytes: c.MemoryBytes,
	}
	if c.PidsLimit != nil {
		p := *c.PidsLimit
		out.PidsLimit = &p
	}
	return out
}
