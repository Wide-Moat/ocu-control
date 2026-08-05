// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mountcfg renders the file-operation mount-config the control plane
// pushes into the host-owned handoff bind before the in-guest mount client
// boots. The rendered shape is field-identical to the frozen
// contracts/storage/mount-config.schema.json (additionalProperties:false): the
// schema is the only source of the wire surface; this package never invents a
// field. The weak Storage-JWT auth_token is held as a secret cred.Token on the
// render INPUT only — it never enters the marshaled struct as a Token; the raw
// JWT reaches the wire solely through the private wire struct's plain-string
// field, populated via Token.Reveal at the single Marshal boundary. A logged
// Config therefore redacts, while the pushed bytes carry the real token.
package mountcfg

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// ErrBadOctal is returned when a permission value is not the frozen Octal shape
// (^0[0-7]{3}$): a leading zero then three octal digits, e.g. 0755 or 0644.
var ErrBadOctal = errors.New("mountcfg: dir_perms/file_perms must match ^0[0-7]{3}$")

// ErrBadByteSize is returned when a cache cap is not the frozen ByteSize shape
// (^[0-9]+(B|K|M|G|T)?$), e.g. 1G or 512M or a bare integer.
var ErrBadByteSize = errors.New("mountcfg: vfs_cache_max_size must match ^[0-9]+(B|K|M|G|T)?$")

// ErrBadVfsCacheMode is returned when a cache mode is outside the frozen enum
// {off, minimal, writes, full}.
var ErrBadVfsCacheMode = errors.New("mountcfg: vfs_cache_mode must be one of off|minimal|writes|full")

// ErrBadCacheDuration is returned when a per-mount cache window is negative; the
// frozen CacheDurationSeconds is a non-negative integer of whole seconds.
var ErrBadCacheDuration = errors.New("mountcfg: cache_duration_s must be a non-negative integer of seconds")

// ErrBadDestination is returned when a mountpoint is not an absolute guest path
// (the frozen destination pattern is ^/.+).
var ErrBadDestination = errors.New("mountcfg: destination must be an absolute guest path matching ^/.+")

// ErrBadWriteBackDelay is returned when a write-back delay is not the frozen
// WriteBackDelay shape (^[0-9]+(\.[0-9]+)?(ms|s|m|h)$), e.g. 500ms or 1s. The
// pattern is deliberately NARROWER than what the guest mounter itself accepts: a
// producer that cannot express a value is a config we never send, whereas a value
// the guest rejects is a mount that fails to come up.
var ErrBadWriteBackDelay = errors.New(`mountcfg: vfs_write_back must match ^[0-9]+(\.[0-9]+)?(ms|s|m|h)$`)

// The compiled mirrors of the frozen $defs patterns. They are anchored exactly as
// the schema anchors them, so a value this package accepts is a value the schema
// accepts; the go:embed schema-validation test is the cross-check that the two
// never drift.
var (
	octalPattern     = regexp.MustCompile(`^0[0-7]{3}$`)
	byteSizePattern  = regexp.MustCompile(`^[0-9]+(B|K|M|G|T)?$`)
	destPattern      = regexp.MustCompile(`^/.+`)
	writeBackPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(ms|s|m|h)$`)
)

// Octal is a host-set POSIX permission string mirroring the frozen Octal $def.
// The constructor refuses a value outside ^0[0-7]{3}$ so a malformed permission
// can never reach the rendered config.
type Octal string

// NewOctal validates s against the frozen Octal pattern and returns it as an
// Octal, or ErrBadOctal.
func NewOctal(s string) (Octal, error) {
	if !octalPattern.MatchString(s) {
		return "", fmt.Errorf("%w: %q", ErrBadOctal, s)
	}
	return Octal(s), nil
}

// ByteSize is a local VFS cache cap mirroring the frozen ByteSize $def
// (^[0-9]+(B|K|M|G|T)?$). The constructor refuses a malformed size.
type ByteSize string

// NewByteSize validates s against the frozen ByteSize pattern and returns it, or
// ErrBadByteSize.
func NewByteSize(s string) (ByteSize, error) {
	if !byteSizePattern.MatchString(s) {
		return "", fmt.Errorf("%w: %q", ErrBadByteSize, s)
	}
	return ByteSize(s), nil
}

// WriteBackDelay is how long the guest VFS holds a dirty file before writing it
// back to the broker. It is OPTIONAL: the empty value omits the key entirely and
// the guest keeps its own registered default.
//
// The value is bounded from above by something outside this repo. A session's
// guest agent forwards SIGTERM to the mount boot-child but stops waiting for it
// after roughly two seconds, so whatever is still queued when a session is torn
// down is discarded. A delay at or above that ceiling means the most recent write
// of every session is lost on teardown; a delay well below it leaves the upload
// room to finish inside the window. Raising this value without re-measuring that
// teardown window reintroduces the loss.
type WriteBackDelay string

// NewWriteBackDelay validates s against the frozen WriteBackDelay pattern and
// returns it, or ErrBadWriteBackDelay. The empty string is NOT accepted here: an
// omitted delay is expressed by leaving the field zero, never by constructing one.
//
// A pattern-shaped ZERO ("0s", "0ms") is refused as well. The pattern alone cannot
// express "positive", and the guest mounter rejects a non-positive delay outright —
// emitting one would not degrade the mount, it would stop the mount coming up at
// all. Refusing here keeps that failure on the host, at construction, where it is
// a startup panic with a name instead of a session that never gets its storage.
func NewWriteBackDelay(s string) (WriteBackDelay, error) {
	if !writeBackPattern.MatchString(s) {
		return "", fmt.Errorf("%w: %q", ErrBadWriteBackDelay, s)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrBadWriteBackDelay, s)
	}
	if d <= 0 {
		return "", fmt.Errorf("%w: %q must be positive", ErrBadWriteBackDelay, s)
	}
	return WriteBackDelay(s), nil
}

// VfsCacheMode is the page-cache policy mirroring the frozen VfsCacheMode enum.
type VfsCacheMode string

const (
	VfsCacheOff     VfsCacheMode = "off"
	VfsCacheMinimal VfsCacheMode = "minimal"
	VfsCacheWrites  VfsCacheMode = "writes"
	VfsCacheFull    VfsCacheMode = "full"
)

// valid reports whether m is one of the four frozen cache modes.
func (m VfsCacheMode) valid() bool {
	switch m {
	case VfsCacheOff, VfsCacheMinimal, VfsCacheWrites, VfsCacheFull:
		return true
	default:
		return false
	}
}

// NewVfsCacheMode validates s against the frozen enum and returns it as a
// VfsCacheMode, or ErrBadVfsCacheMode.
func NewVfsCacheMode(s string) (VfsCacheMode, error) {
	m := VfsCacheMode(s)
	if !m.valid() {
		return "", fmt.Errorf("%w: %q", ErrBadVfsCacheMode, s)
	}
	return m, nil
}
