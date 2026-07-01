// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// export_test.go exposes package-internal helpers to the external test package
// (mcpkey_test). Compiled only during tests; never part of the production build.
package mcpkey

import (
	"errors"
	"io"
)

// NewSecretKeyForTest calls the unexported newSecretKey constructor so that
// external tests can build a SecretKey with a known raw body and drive every
// redaction surface without going through the full mint path.
func NewSecretKeyForTest(raw string) SecretKey { return newSecretKey(raw) }

// ZeroSecretKey returns the zero-value SecretKey for IsZero tests.
func ZeroSecretKey() SecretKey { return SecretKey{} }

// DefaultMinter returns a Minter backed by crypto/rand.Reader (the production
// reader) for use in external tests.
func DefaultMinter() *Minter { return NewMinter() }

// NewMinterWithReader returns a Minter that reads from r instead of
// crypto/rand.Reader. Used by tests to inject fault-injecting or deterministic
// fake readers.
func NewMinterWithReader(r io.Reader) *Minter { return &Minter{rand: r} }

// NewFakeReader returns an io.Reader that cycles through the given bytes. Each
// Read call fills p from the sequence; it wraps around after the slice is
// exhausted.
func NewFakeReader(b []byte) io.Reader { return &cycleReader{data: b} }

// NewErrorReader returns an io.Reader that always fails with err.
func NewErrorReader(err error) io.Reader { return &errReader{err: err} }

// NewShortReader returns an io.Reader that returns exactly n bytes then io.EOF.
func NewShortReader(n int) io.Reader { return &shortReader{n: n} }

// -- internal fake readers ---------------------------------------------------

// cycleReader cycles through data, providing each byte in sequence and wrapping.
type cycleReader struct {
	data []byte
	pos  int
}

func (c *cycleReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, errors.New("cycleReader: empty data")
	}
	for i := range p {
		p[i] = c.data[c.pos%len(c.data)]
		c.pos++
	}
	return len(p), nil
}

// errReader always returns an error on Read.
type errReader struct{ err error }

func (e *errReader) Read(_ []byte) (int, error) { return 0, e.err }

// shortReader returns n bytes then io.EOF.
type shortReader struct {
	n    int
	sent int
}

func (s *shortReader) Read(p []byte) (int, error) {
	if s.sent >= s.n {
		return 0, io.EOF
	}
	toWrite := len(p)
	if toWrite > s.n-s.sent {
		toWrite = s.n - s.sent
	}
	s.sent += toWrite
	return toWrite, nil
}
