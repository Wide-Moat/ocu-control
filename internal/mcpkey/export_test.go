// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// export_test.go exposes package-internal helpers to the external test package
// (mcpkey_test). Compiled only during tests; never part of the production build.
package mcpkey

// NewSecretKeyForTest calls the unexported newSecretKey constructor so that
// external tests can build a SecretKey with a known raw body and drive every
// redaction surface without going through the full mint path.
func NewSecretKeyForTest(raw string) SecretKey { return newSecretKey(raw) }

// ZeroSecretKey returns the zero-value SecretKey for IsZero tests.
func ZeroSecretKey() SecretKey { return SecretKey{} }
