// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package runtimemap

import (
	"reflect"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// compile-time field-parity guards. Each variable constructs its struct with a
// KEYED literal that names EVERY field. If either struct grows a field, loses a
// field, or renames a field, one of these literals stops compiling — the parity
// contract is enforced at build time, before any test runs, so the leaf-seam
// runtime.Identity can never silently drift from the authoritative
// state.Identity (and vice-versa). The values are arbitrary; only the field set
// matters.
var (
	_ = state.Identity{Tenant: "", Caller: ""}
	_ = runtime.Identity{Tenant: "", Caller: ""}

	_ = state.Caps{CPUCores: 0, MemoryBytes: 0, PidsLimit: nil}
	_ = runtime.ResourceCaps{CPUCores: 0, MemoryBytes: 0, PidsLimit: nil}
)

// TestIdentity_FieldParity asserts at test time (the structural complement of the
// compile-time keyed literals above) that state.Identity and runtime.Identity
// have the SAME set of exported fields by name AND by type. A type change that a
// keyed literal would not catch (e.g. Tenant string -> Tenant fmt.Stringer) fails
// here, so the two seams cannot diverge in shape without a red test.
func TestIdentity_FieldParity(t *testing.T) {
	st := reflect.TypeOf(state.Identity{})
	rt := reflect.TypeOf(runtime.Identity{})

	if st.NumField() != rt.NumField() {
		t.Fatalf("field-count drift: state.Identity has %d fields, runtime.Identity has %d",
			st.NumField(), rt.NumField())
	}

	stFields := fieldMap(st)
	rtFields := fieldMap(rt)

	for name, stType := range stFields {
		rtType, ok := rtFields[name]
		if !ok {
			t.Errorf("state.Identity field %q has no counterpart on runtime.Identity", name)
			continue
		}
		if stType != rtType {
			t.Errorf("field %q type drift: state.Identity has %s, runtime.Identity has %s",
				name, stType, rtType)
		}
	}
	for name := range rtFields {
		if _, ok := stFields[name]; !ok {
			t.Errorf("runtime.Identity field %q has no counterpart on state.Identity", name)
		}
	}
}

// fieldMap returns name -> kind-string for every field of a struct type, for the
// parity comparison.
func fieldMap(t reflect.Type) map[string]string {
	out := make(map[string]string, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		out[f.Name] = f.Type.String()
	}
	return out
}

// TestCaps_FieldParity asserts state.Caps and runtime.ResourceCaps have the SAME
// set of exported fields by name AND by type, the structural complement of the
// keyed literals above. The durable recorded-data caps (read by the admin
// surface) and the provider's hard-cap primitive cannot diverge in shape without
// a red test.
func TestCaps_FieldParity(t *testing.T) {
	st := reflect.TypeOf(state.Caps{})
	rt := reflect.TypeOf(runtime.ResourceCaps{})

	if st.NumField() != rt.NumField() {
		t.Fatalf("field-count drift: state.Caps has %d fields, runtime.ResourceCaps has %d",
			st.NumField(), rt.NumField())
	}

	stFields := fieldMap(st)
	rtFields := fieldMap(rt)

	for name, stType := range stFields {
		rtType, ok := rtFields[name]
		if !ok {
			t.Errorf("state.Caps field %q has no counterpart on runtime.ResourceCaps", name)
			continue
		}
		if stType != rtType {
			t.Errorf("field %q type drift: state.Caps has %s, runtime.ResourceCaps has %s",
				name, stType, rtType)
		}
	}
	for name := range rtFields {
		if _, ok := stFields[name]; !ok {
			t.Errorf("runtime.ResourceCaps field %q has no counterpart on state.Caps", name)
		}
	}
}

// TestCapsRoundTrips asserts both mapping directions carry EVERY field value
// through unchanged (a pure relabelling), and that the PidsLimit pointer is copied
// (not aliased) so a later mutation of one side cannot mutate the other.
func TestCapsRoundTrips(t *testing.T) {
	pids := int64(512)
	src := state.Caps{CPUCores: 2.5, MemoryBytes: 1 << 30, PidsLimit: &pids}

	rt := CapsFromState(src)
	if rt.CPUCores != src.CPUCores || rt.MemoryBytes != src.MemoryBytes {
		t.Errorf("CapsFromState scalar drift: got %+v from %+v", rt, src)
	}
	if rt.PidsLimit == nil || *rt.PidsLimit != *src.PidsLimit {
		t.Fatalf("CapsFromState PidsLimit: want %d, got %v", *src.PidsLimit, rt.PidsLimit)
	}
	if rt.PidsLimit == src.PidsLimit {
		t.Error("CapsFromState aliased the PidsLimit pointer; want a copy")
	}

	back := CapsToState(rt)
	if back.CPUCores != src.CPUCores || back.MemoryBytes != src.MemoryBytes {
		t.Errorf("CapsToState scalar drift: got %+v from %+v", back, rt)
	}
	if back.PidsLimit == nil || *back.PidsLimit != *src.PidsLimit {
		t.Fatalf("CapsToState PidsLimit: want %d, got %v", *src.PidsLimit, back.PidsLimit)
	}
	if back.PidsLimit == rt.PidsLimit {
		t.Error("CapsToState aliased the PidsLimit pointer; want a copy")
	}

	// Exhaustiveness: every exported field of the destination must be non-zero
	// after mapping a fully-populated source, so a newly-added unmapped field is
	// caught here rather than silently dropped.
	rv := reflect.ValueOf(rt)
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).IsZero() {
			t.Errorf("mapped runtime.ResourceCaps field %q is zero after mapping a fully-populated state.Caps; the mapping likely forgot it",
				rv.Type().Field(i).Name)
		}
	}

	// A nil PidsLimit must map to a nil PidsLimit on both sides (unset stays
	// unset).
	if got := CapsFromState(state.Caps{CPUCores: 1}); got.PidsLimit != nil {
		t.Errorf("CapsFromState nil PidsLimit: want nil, got %v", got.PidsLimit)
	}
	if got := CapsToState(runtime.ResourceCaps{CPUCores: 1}); got.PidsLimit != nil {
		t.Errorf("CapsToState nil PidsLimit: want nil, got %v", got.PidsLimit)
	}
}

// TestIdentityFromState_RoundTrips asserts the single mapping function carries
// EVERY field value through unchanged (a pure relabelling). If a future field is
// added to both structs and parity passes but the mapping forgets to copy it,
// this round-trip catches the dropped field.
func TestIdentityFromState_RoundTrips(t *testing.T) {
	src := state.Identity{Tenant: "tenant-7", Caller: "caller-9"}
	got := IdentityFromState(src)

	if got.Tenant != src.Tenant {
		t.Errorf("Tenant: want %q, got %q", src.Tenant, got.Tenant)
	}
	if got.Caller != src.Caller {
		t.Errorf("Caller: want %q, got %q", src.Caller, got.Caller)
	}

	// Exhaustiveness: every exported field of the destination must be non-zero
	// after mapping a fully-populated source, so a newly-added unmapped field
	// (left at its zero value) is caught here rather than silently dropped.
	rv := reflect.ValueOf(got)
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).IsZero() {
			t.Errorf("mapped runtime.Identity field %q is zero after mapping a fully-populated state.Identity; the mapping likely forgot it",
				rv.Type().Field(i).Name)
		}
	}
}
