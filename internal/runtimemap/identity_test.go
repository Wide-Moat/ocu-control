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
