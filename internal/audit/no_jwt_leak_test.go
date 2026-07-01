// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// suspiciousFieldNameMarkers are lowercased substrings that, in a field NAME, mark a
// raw credential leaking onto the persisted-reservation or audit-record path.
var suspiciousFieldNameMarkers = []string{
	"jwt", "token", "credential", "secret", "authtoken", "bearer",
}

// suspiciousTypeMarkers are substrings that, in a field TYPE string, mark a credential
// type — catching e.g. a field typed cred.Token whose NAME ("Storage") would not, or
// a field typed mcpkey.SecretKey whose name might be innocuous ("Key").
var suspiciousTypeMarkers = []string{
	"Token", "JWT", "SecretKey",
}

// TestNoRawJWTOnPersistedOrAuditRecord pins Invariant VII — no raw Storage-JWT (or any
// credential) ever rides the create-response / audit path. That invariant is true TODAY
// only by type-absence: SessionRow, EnrichedSessionRow, and Record simply have no
// credential field. This guard reflects over all three and fails RED the moment one
// grows a field that, by NAME or by TYPE, looks like a credential — so a future
// `JWT string` on the response row or a `Token cred.Token` on the audit record fails
// immediately, not in review.
//
// The walk RECURSES into nested struct fields (through pointers and slices): SessionRow
// carries `Owner Identity` and EnrichedSessionRow carries `Caps *Caps` + the embedded
// row, and Identity is exactly the host-derived-authority type a future author might be
// tempted to staple a minted token onto. A top-level-only walk would let a credential
// hide one level down; the path Invariant VII protects includes those nested fields, so
// the guard descends into them. A cycle guard (visited set) keeps a self-referential
// type from looping.
//
// Unlike read_test.go's TestReadHandlers_HoldNoMutatingCapability, which bounds a small
// KNOWN type-set with a POSITIVE allow-list, the fields here are open-ended business
// data (keys, owners, reasons), so an allow-list would have to enumerate every benign
// field and churn on every legitimate addition. The right tool for an open field set is
// a NEGATIVE marker-denylist: it lets benign fields through and trips only on
// credential-shaped ones. It mirrors that test's anti-vacuity discipline — the top-level
// type is proven a non-empty struct before any field is judged, so the guard cannot pass
// by checking nothing. The denylist's ceiling is honest: a raw JWT typed as a bare
// `string` with a benign name (no jwt/token/... marker) is not caught by either arm —
// the NAME discipline is the real protection, the TYPE arm only adds the named-credential
// (cred.Token) case.
func TestNoRawJWTOnPersistedOrAuditRecord(t *testing.T) {
	t.Parallel()

	// Each top-level type must be a reachable, non-empty struct, or the reflection walk
	// would be vacuous — passing because it iterated zero fields.
	assertCredentialFree(t, reflect.TypeOf(state.SessionRow{}), "state.SessionRow")
	assertCredentialFree(t, reflect.TypeOf(state.EnrichedSessionRow{}), "state.EnrichedSessionRow")
	assertCredentialFree(t, reflect.TypeOf(audit.Record{}), "audit.Record")

	// NFR-SEC-87 extension: the mcp-key Record holds salted-hash credentials,
	// never the raw sk-ocu- SecretKey. The guard walks mcpkey.Record to prove no
	// field typed mcpkey.SecretKey (or with a credential-shaped name) is present.
	// The audit Record's Key field (a correlation string carrying key_id) is benign;
	// the type guard catches a hypothetical SecretKey-typed field that would be a
	// direct no-leak violation.
	assertCredentialFree(t, reflect.TypeOf(mcpkey.Record{}), "mcpkey.Record")
}

// assertCredentialFree fails if the top-level type is not a non-empty struct (the
// anti-vacuity gate), then walks its fields — recursing into nested struct fields — and
// fails on any field that is credential-shaped by NAME or by TYPE.
func assertCredentialFree(t *testing.T, typ reflect.Type, label string) {
	t.Helper()
	if typ == nil || typ.Kind() != reflect.Struct {
		t.Fatalf("%s is not a reachable struct type (%v); the credential-leak guard is vacuous", label, typ)
	}
	if typ.NumField() == 0 {
		t.Fatalf("%s has no fields; the credential-leak guard is vacuous", label)
	}
	walkFieldsForCredential(t, typ, label, map[reflect.Type]bool{})
}

// walkFieldsForCredential judges every field of typ by NAME and TYPE marker, then
// descends into any field whose underlying type is a struct (unwrapping pointers and
// slice/array element types). visited breaks a reference cycle so the walk terminates.
func walkFieldsForCredential(t *testing.T, typ reflect.Type, label string, visited map[reflect.Type]bool) {
	t.Helper()
	if visited[typ] {
		return
	}
	visited[typ] = true
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		lowerName := strings.ToLower(f.Name)
		for _, marker := range suspiciousFieldNameMarkers {
			if strings.Contains(lowerName, marker) {
				t.Errorf("%s field %q has a credential-shaped NAME (contains %q): Invariant VII forbids a raw "+
					"Storage-JWT or any credential on the create-response / audit path. If this is genuinely not a "+
					"credential, rename it; the binding is the host-derived Storage-JWT, minted out of band, never "+
					"persisted on the row or the audit record.", label, f.Name, marker)
			}
		}
		typeStr := f.Type.String()
		for _, marker := range suspiciousTypeMarkers {
			if strings.Contains(typeStr, marker) {
				t.Errorf("%s field %q has a credential-shaped TYPE (%s contains %q): Invariant VII forbids a "+
					"credential type (e.g. cred.Token) on the create-response / audit path. The Storage-JWT is "+
					"minted and handed out of band, never carried on this record.", label, f.Name, typeStr, marker)
			}
		}
		// Descend into a nested struct so a credential cannot hide one level down (e.g.
		// on SessionRow.Owner Identity). Unwrap a pointer or slice/array element first.
		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			walkFieldsForCredential(t, ft, label+"."+f.Name, visited)
		}
	}
}
