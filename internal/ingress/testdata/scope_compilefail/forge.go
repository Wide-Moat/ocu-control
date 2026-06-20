// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build ignore

// This file is a NEGATIVE compile fixture, not built by the package. It is the
// load-bearing proof of the capability seal: every statement below is a forgery a
// gateway-shaped caller (which holds a ServiceScope and no OperatorSeam) might
// attempt, and EACH must fail to compile. The sibling go-build test
// (scope_compilefail_test.go) runs `go build` on this file and asserts a non-zero
// exit whose diagnostics name these forbidden constructs. If any line below ever
// starts compiling, the scope separation has regressed from a compile fact to a
// runtime hope and the test goes red.
//
// The build tag keeps `go test`, `go build ./...`, and the linters from ever
// compiling this file as part of the package; it is reachable only by the explicit
// `go build` the seal test invokes on this exact path.
package scopecompilefail

import "github.com/Wide-Moat/ocu-control/internal/ingress"

// operatorOnly stands in for the operator-only surface the kill-switch Engine
// exposes (RevokeOne/RevokeAll/denylist-edit/quota-override): each such method
// REQUIRES an ingress.OperatorScope parameter, so this models that exact gate.
func operatorOnly(_ ingress.OperatorScope) {}

// forgeScopeByLiteral tries to fabricate an OperatorScope with a composite literal.
// FORBIDDEN: the witness field is unexported, so a foreign package cannot name it —
// "unknown field w in struct literal" / "cannot refer to unexported field".
func forgeScopeByLiteral() ingress.OperatorScope {
	return ingress.OperatorScope{w: nil}
}

// forgeWitnessType tries to name the unexported witness the scope wraps. FORBIDDEN:
// operatorWitness is unexported and undefined outside the package.
func forgeWitnessType() {
	_ = ingress.operatorWitness{}
}

// forgeSeamField tries to set the seam's unexported mint pointer to bootstrap a
// genuine scope from a hand-built seam. FORBIDDEN: the mint field is unexported.
func forgeSeamField() ingress.OperatorScope {
	return ingress.OperatorSeam{mint: nil}.Mint()
}

// callOperatorOnlyWithServiceScope tries to invoke the operator-only surface with a
// ServiceScope — the precise move a gateway caller would make. FORBIDDEN: the
// argument type is ServiceScope, the parameter type is OperatorScope, and there is
// no conversion between them — "cannot use ... (ServiceScope) as OperatorScope".
func callOperatorOnlyWithServiceScope() {
	operatorOnly(ingress.ServiceScopeFor())
}

// convertServiceToOperator tries to convert a ServiceScope to an OperatorScope.
// FORBIDDEN: the two are distinct struct types wrapping distinct unexported witness
// types; the conversion is not permitted.
func convertServiceToOperator() ingress.OperatorScope {
	return ingress.OperatorScope(ingress.ServiceScopeFor())
}
