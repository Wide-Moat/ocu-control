// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

var (
	// ErrNoCredential is returned when a mount is asked to render with a zero
	// (never-minted) auth_token. The renderer refuses rather than ship an empty
	// auth_token the schema's minLength:1 would reject and the egress edge could
	// not validate.
	ErrNoCredential = errors.New("mountcfg: refused to render a mount with no auth_token")
	// ErrBadScope is returned when a mount does not carry EXACTLY one of
	// filesystem_id / memory_store_id (the frozen oneOf). Both-set or neither-set
	// is refused before render.
	ErrBadScope = errors.New("mountcfg: mount must carry exactly one of filesystem_id / memory_store_id")
	// ErrTokenCountMismatch is returned when the number of minted tokens does not
	// match the number of mount intents: each intent renders against its own
	// positionally-paired weak Storage-JWT.
	ErrTokenCountMismatch = errors.New("mountcfg: token count must equal mount intent count")
	// ErrNoMounts is returned when Render is asked for a session with no mounts;
	// the schema requires a mounts array, and a session with zero mounts has no
	// storage surface to provision.
	ErrNoMounts = errors.New("mountcfg: refused to render a config with no mounts")
	// ErrBadServiceURL is returned when the service_url is not an https URL (the
	// frozen pattern is ^https://).
	ErrBadServiceURL = errors.New("mountcfg: service_url must be an https:// URL")
	// ErrBadCACert is returned when the ca_cert_pem does not look like a PEM
	// certificate (the frozen pattern requires a BEGIN CERTIFICATE marker).
	ErrBadCACert = errors.New("mountcfg: ca_cert_pem must be a PEM certificate")
)

// MountDefaults carries the deployment-fixed, schema-validated per-mount knobs
// that the substrate-neutral runtime.MountIntent does not name: the VFS cache
// policy, the cache cap, and the host-set permission bits. They are constructed
// through the validating Octal/ByteSize/VfsCacheMode constructors, so a malformed
// value cannot reach Render — the type itself is the proof the value matches the
// frozen $def. These are host-chosen posture, never request-body hints.
type MountDefaults struct {
	VfsCacheMode    VfsCacheMode
	VfsCacheMaxSize ByteSize
	DirPerms        Octal
	FilePerms       Octal
}

// validate confirms the defaults were built through the validating constructors
// (a zero-value MountDefaults, e.g. from a struct literal that skipped them, is
// refused). It guards the render path against a caller that bypassed New*.
func (d MountDefaults) validate() error {
	if !d.VfsCacheMode.valid() {
		return fmt.Errorf("%w: %q", ErrBadVfsCacheMode, d.VfsCacheMode)
	}
	if !byteSizePattern.MatchString(string(d.VfsCacheMaxSize)) {
		return fmt.Errorf("%w: %q", ErrBadByteSize, d.VfsCacheMaxSize)
	}
	if !octalPattern.MatchString(string(d.DirPerms)) {
		return fmt.Errorf("%w: dir_perms %q", ErrBadOctal, d.DirPerms)
	}
	if !octalPattern.MatchString(string(d.FilePerms)) {
		return fmt.Errorf("%w: file_perms %q", ErrBadOctal, d.FilePerms)
	}
	return nil
}

// mountInput is the secret-bearing INPUT shape one mount renders from. It holds
// the secret cred.Token; it NEVER marshals — Render maps it into the private
// wireMount whose auth_token is a plain string filled via Token.Reveal at the
// single Marshal boundary. Keeping the Token off the marshaled struct is what
// makes the redaction structural: there is no json-tagged Token field a reflective
// encoder could reach.
type mountInput struct {
	destination     string
	authToken       cred.Token
	filesystemID    string
	memoryStoreID   string
	readOnly        bool
	vfsCacheMode    VfsCacheMode
	cacheDurationS  int
	vfsCacheMaxSize ByteSize
	dirPerms        Octal
	filePerms       Octal
}

// Config is the rendered, ready-to-push mount-config a caller holds. It carries
// the secret-bearing mountInputs, so an accidental %v or json.Marshal of a Config
// redacts every auth_token (the Token's own redaction surfaces fire). The only
// path that materializes the real tokens is Marshal, the single Reveal boundary.
// Config has no exported fields: a caller obtains one only from Render and emits
// the wire bytes only through Marshal.
//
// Redaction on a Config is STRUCTURAL, not delegated: although each mountInput
// holds a redacting cred.Token, Go's fmt and json reflect THROUGH an unexported
// field and do NOT invoke the Token's own Format/String/MarshalJSON on a value
// read from an unexported field — so a bare %v would otherwise reach Token.raw.
// Config therefore implements its own String/GoString/Format/LogValue/MarshalJSON
// surfaces (mirroring the Token's own set) so every fmt/slog/json emit path on a
// Config short-circuits to a redacted form before any reflection can reach a
// token. The ONLY path that materializes a token is Marshal.
type Config struct {
	serviceURL string
	caCertPEM  string
	mounts     []mountInput
}

// configRedaction is the sentinel a logged/printed Config emits. It names the
// shape without any token: a reviewer sees a Config was logged, never a JWT.
const configRedaction = "mountcfg.Config(REDACTED)"

// String redacts: a %s or Stringer caller on a Config yields the sentinel, never
// a field dump that would reach a token through reflection.
func (Config) String() string { return configRedaction }

// GoString redacts the %#v path the same way.
func (Config) GoString() string { return configRedaction }

// Format routes every fmt verb (%v, %+v, %#v, %s, ...) through the single
// redacting sink, so no verb can reflect into the token-bearing fields.
func (Config) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(configRedaction)) }

// LogValue redacts under slog: a Config logged as an attribute value emits the
// sentinel, not its fields.
func (Config) LogValue() slog.Value { return slog.StringValue(configRedaction) }

// MarshalJSON redacts the accidental json.Marshal(cfg) path: it emits the
// sentinel string, NOT the wire config. The real wire bytes (with the revealed
// tokens) come ONLY from Marshal, never from a reflective json encode of a
// Config. This is what makes "a logged Config redacts while Marshal carries the
// real token" hold structurally.
func (Config) MarshalJSON() ([]byte, error) { return json.Marshal(configRedaction) }

// Compile-time assertions that Config satisfies every redacting surface, so a
// refactor that drops one fails the build rather than leaking at runtime.
var (
	_ fmt.Stringer   = Config{}
	_ fmt.GoStringer = Config{}
	_ fmt.Formatter  = Config{}
	_ slog.LogValuer = Config{}
	_ json.Marshaler = Config{}
)

// Render builds ONE Config per session from the substrate-neutral MountIntents,
// the freshly minted weak Tokens (one per intent, positionally), and the
// deployment-fixed MountDefaults. It chooses filesystem_id XOR memory_store_id
// from each intent (ErrBadScope on both-or-neither), refuses a zero Token
// (ErrNoCredential), and validates service_url / ca_cert_pem against the frozen
// top-level patterns. The render is total: every field the schema requires is
// populated from a validated source, so the schema-validation test asserts every
// rendered Config validates.
func Render(serviceURL, caCertPEM string, mounts []runtime.MountIntent, tokens []cred.Token, defaults MountDefaults) (Config, error) {
	if !httpsPrefix(serviceURL) {
		return Config{}, fmt.Errorf("%w: %q", ErrBadServiceURL, serviceURL)
	}
	if !pemCertMarker(caCertPEM) {
		return Config{}, ErrBadCACert
	}
	if len(mounts) == 0 {
		return Config{}, ErrNoMounts
	}
	if len(tokens) != len(mounts) {
		return Config{}, fmt.Errorf("%w: %d tokens, %d mounts", ErrTokenCountMismatch, len(tokens), len(mounts))
	}
	if err := defaults.validate(); err != nil {
		return Config{}, err
	}

	inputs := make([]mountInput, 0, len(mounts))
	for i, m := range mounts {
		in, err := renderMount(m, tokens[i], defaults)
		if err != nil {
			return Config{}, fmt.Errorf("mount %d (%s): %w", i, m.Destination, err)
		}
		inputs = append(inputs, in)
	}
	return Config{serviceURL: serviceURL, caCertPEM: caCertPEM, mounts: inputs}, nil
}

// renderMount validates and maps one substrate-neutral intent plus its token into
// a secret-bearing mountInput. Scope is exactly one of filesystem_id /
// memory_store_id; the token must be non-zero; the cache window must be
// non-negative; the destination must be an absolute guest path.
func renderMount(m runtime.MountIntent, tok cred.Token, defaults MountDefaults) (mountInput, error) {
	if tok.IsZero() {
		return mountInput{}, ErrNoCredential
	}
	hasFS := m.FilesystemID != ""
	hasMem := m.MemoryStoreID != ""
	if hasFS == hasMem { // both set or neither set
		return mountInput{}, ErrBadScope
	}
	if !destPattern.MatchString(m.Destination) {
		return mountInput{}, fmt.Errorf("%w: %q", ErrBadDestination, m.Destination)
	}
	if m.CacheSeconds < 0 {
		return mountInput{}, fmt.Errorf("%w: %d", ErrBadCacheDuration, m.CacheSeconds)
	}
	return mountInput{
		destination:     m.Destination,
		authToken:       tok,
		filesystemID:    m.FilesystemID,
		memoryStoreID:   m.MemoryStoreID,
		readOnly:        m.ReadOnly,
		vfsCacheMode:    defaults.VfsCacheMode,
		cacheDurationS:  m.CacheSeconds,
		vfsCacheMaxSize: defaults.VfsCacheMaxSize,
		dirPerms:        defaults.DirPerms,
		filePerms:       defaults.FilePerms,
	}, nil
}

// Marshal serializes the Config into the private wireConfig, calling
// Token.Reveal() into each auth_token ONLY here — this is the single render-path
// Reveal call site, the one place the raw JWT materializes into bytes. The
// returned bytes are the host-only provisioning-push payload and carry the real
// tokens; logging the Config (not these bytes) redacts. backend_cache_ttl is left
// absent (omitempty), per the schema's x-ocu-tbd encoding.
func (c Config) Marshal() ([]byte, error) {
	wm := make([]wireMount, 0, len(c.mounts))
	for _, in := range c.mounts {
		wm = append(wm, wireMount{
			Destination:     in.destination,
			AuthToken:       in.authToken.Reveal(), // single render-path Reveal boundary
			FilesystemID:    in.filesystemID,
			MemoryStoreID:   in.memoryStoreID,
			ReadOnly:        in.readOnly,
			VfsCacheMode:    string(in.vfsCacheMode),
			CacheDurationS:  in.cacheDurationS,
			VfsCacheMaxSize: string(in.vfsCacheMaxSize),
			DirPerms:        string(in.dirPerms),
			FilePerms:       string(in.filePerms),
		})
	}
	wc := wireConfig{
		SchemaVersion: schemaVersion,
		ServiceURL:    c.serviceURL,
		CACertPEM:     c.caCertPEM,
		Mounts:        wm,
		// BackendCacheTTL intentionally nil: absent by default (x-ocu-tbd).
	}
	b, err := json.Marshal(wc)
	if err != nil {
		return nil, fmt.Errorf("mountcfg: marshal: %w", err)
	}
	return b, nil
}

// httpsPrefix reports whether s begins with the https scheme the frozen
// service_url pattern (^https://) requires, with at least one host character
// after it. A prefix check mirrors the schema's anchored pattern without pulling
// in a URL parser the schema itself does not require.
func httpsPrefix(s string) bool {
	const p = "https://"
	return len(s) > len(p) && strings.HasPrefix(s, p)
}

// pemCertMarker reports whether s contains the BEGIN CERTIFICATE marker the
// frozen ca_cert_pem pattern requires. The schema matches the marker as a
// substring, not an anchored prefix, so a leading comment line is tolerated.
func pemCertMarker(s string) bool {
	return strings.Contains(s, "-----BEGIN CERTIFICATE-----")
}
