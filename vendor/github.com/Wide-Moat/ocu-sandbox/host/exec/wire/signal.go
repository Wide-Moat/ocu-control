// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package wire

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// signalNamePattern bounds a POSIX-style signal name on the wire.
var signalNamePattern = regexp.MustCompile(`^SIG[A-Z0-9]{1,12}$`)

// Signal is a process signal carried on the wire as either an integer (1..64) or
// a POSIX name string ("SIGKILL", "SIGTERM", ...). Exactly one of Num or Name is
// set; the wire form is the scalar itself (e.g. 9 or "SIGKILL"), not an object —
// the discriminator is the enclosing message key, not this value's type.
type Signal struct {
	Num  *uint8
	Name *string
}

// NumSignal builds a numeric Signal.
func NumSignal(n uint8) Signal {
	return Signal{Num: &n}
}

// NamedSignal builds a named Signal.
func NamedSignal(name string) Signal {
	return Signal{Name: &name}
}

// MarshalJSON renders the integer when Num is set, the string when Name is set,
// and errors when neither is set.
func (s Signal) MarshalJSON() ([]byte, error) {
	switch {
	case s.Num != nil:
		return json.Marshal(*s.Num)
	case s.Name != nil:
		return json.Marshal(*s.Name)
	default:
		return nil, fmt.Errorf("wire: empty Signal (neither Num nor Name set)")
	}
}

// UnmarshalJSON accepts either an integer or a string. The integer form is tried
// first; a string is the fallback. Anything else is an error.
func (s *Signal) UnmarshalJSON(b []byte) error {
	var n uint8
	if err := json.Unmarshal(b, &n); err == nil {
		s.Num = &n
		s.Name = nil
		return nil
	}
	var name string
	if err := json.Unmarshal(b, &name); err == nil {
		s.Name = &name
		s.Num = nil
		return nil
	}
	return fmt.Errorf("wire: Signal is neither integer nor string: %s", b)
}

// Validate enforces the schema bounds: a numeric signal in 1..64, or a name
// matching ^SIG[A-Z0-9]{1,12}$. The schema is the authoritative oracle; this is
// a pre-wire guard so out-of-range values are caught before they are emitted.
func (s Signal) Validate() error {
	switch {
	case s.Num != nil:
		if *s.Num < 1 || *s.Num > 64 {
			return fmt.Errorf("wire: signal number %d out of range 1..64", *s.Num)
		}
		return nil
	case s.Name != nil:
		if !signalNamePattern.MatchString(*s.Name) {
			return fmt.Errorf("wire: signal name %q does not match %s", *s.Name, signalNamePattern)
		}
		return nil
	default:
		return fmt.Errorf("wire: empty Signal (neither Num nor Name set)")
	}
}
