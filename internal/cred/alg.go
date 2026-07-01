// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred

import "errors"

// Alg is the JWT signing algorithm for the Storage-JWT signing-key layer. It is
// CONFIG-DRIVEN, not hardcoded: the signing-key requirement names the
// Ed25519-family for the Storage-JWT signing key, while the frozen mount-config
// schema's auth_token text names ES256 only as an example — two DISTINCT key
// layers, so the alg is chosen per deployment and written per key in the
// keyset. AlgEdDSA is the default; AlgES256 is supported for a deployment that
// matches the schema example. The control-WS verify-key is a separate Ed25519
// key layer handled by the handoff push, not by this Alg.
type Alg uint8

const (
	// AlgEdDSA is Ed25519 signing, the deployment default for the Storage-JWT
	// signing key.
	AlgEdDSA Alg = iota
	// AlgES256 is ECDSA over P-256, supported for a deployment matching the
	// mount-config schema example.
	AlgES256
)

// ErrUnknownAlg is returned when an unrecognized or unsupported Alg is asked to
// resolve a JWT method or JWK parameter.
var ErrUnknownAlg = errors.New("cred: unknown or unsupported JWT signing algorithm")

// valid reports whether a is one of the two supported algorithms.
func (a Alg) valid() bool { return a == AlgEdDSA || a == AlgES256 }

// JWTMethod returns the JWS "alg" header value (the golang-jwt method name) for
// a. An unknown Alg returns the empty string; callers that must fail-closed
// check Valid() first. The JWKS publisher reads this for the JWK "alg".
func (a Alg) JWTMethod() string {
	switch a {
	case AlgEdDSA:
		return "EdDSA"
	case AlgES256:
		return "ES256"
	default:
		return ""
	}
}

// JWKCrv returns the JWK "crv" parameter for a, consumed by the JWKS publisher.
func (a Alg) JWKCrv() string {
	switch a {
	case AlgEdDSA:
		return "Ed25519"
	case AlgES256:
		return "P-256"
	default:
		return ""
	}
}

// JWKKty returns the JWK "kty" key-type parameter for a, consumed by the JWKS
// publisher.
func (a Alg) JWKKty() string {
	switch a {
	case AlgEdDSA:
		return "OKP"
	case AlgES256:
		return "EC"
	default:
		return ""
	}
}

// Valid reports whether a is one of the two supported algorithms. Exported so a
// downstream publisher can reject an unknown alg without reaching into the
// custody core's internals.
func (a Alg) Valid() bool { return a.valid() }

// String renders a for diagnostics; it returns the JWS method name, or a
// bracketed sentinel for an unknown value.
func (a Alg) String() string {
	if m := a.JWTMethod(); m != "" {
		return m
	}
	return "Alg(unknown)"
}
