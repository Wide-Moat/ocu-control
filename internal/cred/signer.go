// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

var (
	// ErrSigningKeyMissing is returned when the -jwt-signing-key mount path is
	// absent or unreadable. The daemon refuses to construct a Signer (fail-closed):
	// there is no daemon-default key.
	ErrSigningKeyMissing = errors.New("cred: signing key absent or unreadable from mount")
	// ErrSigningKeyInvalid is returned when the mounted bytes are not a valid PKCS8
	// private key for the configured Alg.
	ErrSigningKeyInvalid = errors.New("cred: signing key not a valid PKCS8 private key for the configured alg")
	// ErrNoActiveKey is returned when a mint is attempted with no active key.
	ErrNoActiveKey = errors.New("cred: no active signing key in keyset")
	// ErrMintScope is returned when a mint is refused for a missing or invalid
	// scope (empty filesystem_id, invalid intent, or a downloadable-true default).
	ErrMintScope = errors.New("cred: refused to mint, missing or invalid scope")
	// ErrMintIdentity is returned when an exec mint is asked for an empty
	// container_name (the host-attested subject must be present).
	ErrMintIdentity = errors.New("cred: refused to mint, missing host-attested identity")
	// ErrConfig is returned when the Signer Config is structurally invalid (an
	// unknown Alg or a non-positive storage TTL).
	ErrConfig = errors.New("cred: invalid signer configuration")
)

// Intent is the AuthorizationMetadata access axis: the egress edge keys on it to
// decide whether a token may read, write, or preview the scoped filesystem.
type Intent string

const (
	IntentRead    Intent = "read"
	IntentWrite   Intent = "write"
	IntentPreview Intent = "preview"
)

// valid reports whether i is one of the three recognized intents.
func (i Intent) valid() bool {
	return i == IntentRead || i == IntentWrite || i == IntentPreview
}

// AuthorizationMetadata is the 3-axis claim the egress edge keys on. Downloadable
// is not defaulted true by the mint above a public scope; a caller must ask for
// it explicitly, and the mint refuses a downloadable-true with an empty scope.
type AuthorizationMetadata struct {
	Scope        string `json:"scope"`
	Intent       Intent `json:"intent"`
	Downloadable bool   `json:"downloadable"`
}

// StorageClaims is the weak Storage-JWT body. iss/aud are CONFIG-DRIVEN and
// provisional (PIN-PENDING a later contract pin); they are never hardcoded and
// no test golden-asserts them. JTI is the host-derived revocation handle the
// below-seam finalizer revokes by.
type StorageClaims struct {
	Issuer       string                `json:"iss"`
	Audience     string                `json:"aud"`
	FilesystemID string                `json:"filesystem_id"`
	Workspace    string                `json:"workspace"`
	Org          string                `json:"org"`
	Authz        AuthorizationMetadata `json:"authz"`
	IssuedAtUnix int64                 `json:"iat"`
	ExpiryUnix   int64                 `json:"exp"`
	JTI          string                `json:"jti"`
}

// StorageMintReq is the weak Storage-JWT mint request. SessionKey is the
// host-derived registry key that seeds the jti — never a body hint (NFR-SEC-43).
// Scope/Workspace/Org are host-derived (deployment-fixed config plus the
// host-derived session identity), not request-body values.
type StorageMintReq struct {
	SessionKey   string
	FilesystemID string
	Workspace    string
	Org          string
	Authz        AuthorizationMetadata
}

// ExecMintReq is the per-dial exec JWT mint. ContainerName is the host-attested
// subject; RequestedTTL is clamped down to execMaxTTL, never honored beyond it.
type ExecMintReq struct {
	ContainerName string
	RequestedTTL  time.Duration
}

// Config carries the provisional iss/aud, the fixed Storage-JWT TTL, and the
// chosen Alg. These are deployment parameters, not sourced values.
type Config struct {
	Alg             Alg
	StorageIssuer   string        // provisional, PIN-PENDING
	StorageAudience string        // provisional, PIN-PENDING
	ExecIssuer      string        // provisional, PIN-PENDING
	ExecAudience    string        // provisional, PIN-PENDING
	StorageTTL      time.Duration // SHORT fixed window
}

// execMaxTTL is the clamp ceiling for the per-dial exec JWT: a longer
// RequestedTTL is clamped DOWN to this, never honored. The signing seed never
// enters the guest; the guest only ever receives the minted compact token.
const execMaxTTL = 60 * time.Minute

// Signer is the SOLE custodian of the Storage-JWT signing key. It loads the key
// from the MOUNT path, holds NO listener and no network issuance endpoint
// (issuance is an in-process method call, enforced by the importgraph test),
// mints the weak Storage-JWT and the per-dial exec JWT, and reads every TTL and
// clamp window from the injected monotonic Clock. It is the only type that ever
// calls newToken.
type Signer struct {
	clk  state.Clock
	cfg  Config
	keys *KeySet
	// revoker, when attached, records each minted Storage-JWT's jti against the
	// mint's host-derived session key so the below-seam finalizer can revoke it
	// without the frozen session row persisting the jti. It is nil until the daemon
	// wires the shared Revoker via UseRevoker; a nil revoker is the test/library
	// default (no recording, the mint still succeeds).
	revoker *Revoker
}

// UseRevoker attaches the shared monotonic Revoker the daemon also hands the
// below-seam finalizer, so every Storage-JWT mint records its jti against the
// host-derived session key the create path supplied. The same *Revoker instance
// is passed to docker.Deps, so the recording (create path) and the revoke
// (teardown step-1) consult one index. It is set once at daemon boot, before any
// mint, and never reassigned at runtime; passing nil is a no-op.
func (s *Signer) UseRevoker(r *Revoker) { s.revoker = r }

// LoadSignerFromMount reads the PKCS8 private key from the -jwt-signing-key
// MOUNT path and constructs a Signer with one active key. It is fail-closed: a
// missing or unreadable file is ErrSigningKeyMissing, and bytes that are not a
// valid PKCS8 key of the configured Alg are ErrSigningKeyInvalid — there is no
// daemon-default key and no fallback. Only the public half ever leaves the
// process, via the KeySet to the JWKS publisher.
func LoadSignerFromMount(path string, clk state.Clock, cfg Config) (*Signer, error) {
	if clk == nil {
		return nil, fmt.Errorf("%w: nil clock", ErrConfig)
	}
	if !cfg.Alg.valid() {
		return nil, fmt.Errorf("%w: unsupported alg %v", ErrConfig, cfg.Alg)
	}
	if cfg.StorageTTL <= 0 {
		return nil, fmt.Errorf("%w: storage TTL must be positive", ErrConfig)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningKeyMissing, err)
	}
	priv, err := parsePKCS8Signer(raw, cfg.Alg)
	if err != nil {
		return nil, err
	}

	key := signingKey{
		kid:      kidFor(priv.Public()),
		alg:      cfg.Alg,
		priv:     priv,
		pub:      priv.Public(),
		bornMark: clk.Now(),
	}
	return &Signer{clk: clk, cfg: cfg, keys: newKeySet(clk, key)}, nil
}

// parsePKCS8Signer decodes a PEM-or-DER PKCS8 private key and asserts it matches
// the configured Alg (Ed25519 for AlgEdDSA, ECDSA P-256 for AlgES256). Any
// mismatch is ErrSigningKeyInvalid so a deployment cannot silently run a key of
// the wrong family.
func parsePKCS8Signer(raw []byte, alg Alg) (crypto.Signer, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningKeyInvalid, err)
	}
	switch alg {
	case AlgEdDSA:
		ed, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: key is not Ed25519", ErrSigningKeyInvalid)
		}
		return ed, nil
	case AlgES256:
		ec, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: key is not ECDSA", ErrSigningKeyInvalid)
		}
		if ec.Curve != ellipticP256() {
			return nil, fmt.Errorf("%w: ECDSA key is not on P-256", ErrSigningKeyInvalid)
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownAlg, alg)
	}
}

// MintStorageJWT mints and signs the weak, edge-only Storage-JWT. exp is
// clk.Now() plus the fixed cfg.StorageTTL; the jti is derived from
// req.SessionKey so the below-seam finalizer can revoke by jti without the
// session row persisting it. It refuses (ErrMintScope) an empty FilesystemID, an
// invalid Intent, or a downloadable-true with an empty scope. The returned Token
// redacts on every emit surface; the raw JWT is reachable only via Reveal. There
// is NO refresh path — a fresh token before expiry is a new mint, never an exp
// bump.
func (s *Signer) MintStorageJWT(ctx context.Context, req StorageMintReq) (Token, error) {
	if err := ctx.Err(); err != nil {
		return Token{}, err
	}
	if req.FilesystemID == "" {
		return Token{}, fmt.Errorf("%w: empty filesystem_id", ErrMintScope)
	}
	if !req.Authz.Intent.valid() {
		return Token{}, fmt.Errorf("%w: invalid intent %q", ErrMintScope, req.Authz.Intent)
	}
	if req.Authz.Downloadable && req.Authz.Scope == "" {
		return Token{}, fmt.Errorf("%w: downloadable requires an explicit scope", ErrMintScope)
	}

	now := s.clk.Now()
	jti := deriveJTI(req.SessionKey, req.FilesystemID, now)
	claims := StorageClaims{
		Issuer:       s.cfg.StorageIssuer,
		Audience:     s.cfg.StorageAudience,
		FilesystemID: req.FilesystemID,
		Workspace:    req.Workspace,
		Org:          req.Org,
		Authz:        req.Authz,
		IssuedAtUnix: now.Unix(),
		ExpiryUnix:   now.Add(s.cfg.StorageTTL).Unix(),
		JTI:          jti,
	}
	tok, err := s.sign(claims)
	if err != nil {
		return Token{}, err
	}
	// Record the jti against the host-derived session key so the below-seam
	// finalizer (which re-derives the same key from the session row) can revoke
	// this exact mint. The bind is keyed on the session key, not the request body
	// (NFR-SEC-43). A nil revoker (library/test default) skips the recording; the
	// mint still succeeds.
	if s.revoker != nil {
		s.revoker.Record(req.SessionKey, jti)
	}
	return tok, nil
}

// execClaims is the per-dial exec JWT body: the host-attested container subject,
// provisional iss/aud, and a clamped exp.
type execClaims struct {
	Issuer       string `json:"iss"`
	Audience     string `json:"aud"`
	Subject      string `json:"sub"`
	IssuedAtUnix int64  `json:"iat"`
	ExpiryUnix   int64  `json:"exp"`
}

// MintExecJWT mints the per-dial, container-bound exec JWT: sub is the
// host-attested ContainerName, and exp is clk.Now() plus min(RequestedTTL,
// execMaxTTL) — a longer requested TTL is CLAMPED down, never honored. A
// non-positive RequestedTTL is treated as the ceiling so the advisory dial
// always carries a usable token. The signing seed never enters the guest; the
// guest receives only this compact token.
func (s *Signer) MintExecJWT(ctx context.Context, req ExecMintReq) (Token, error) {
	if err := ctx.Err(); err != nil {
		return Token{}, err
	}
	if req.ContainerName == "" {
		return Token{}, fmt.Errorf("%w: empty container_name", ErrMintIdentity)
	}
	ttl := req.RequestedTTL
	if ttl <= 0 || ttl > execMaxTTL {
		ttl = execMaxTTL
	}
	now := s.clk.Now()
	claims := execClaims{
		Issuer:       s.cfg.ExecIssuer,
		Audience:     s.cfg.ExecAudience,
		Subject:      req.ContainerName,
		IssuedAtUnix: now.Unix(),
		ExpiryUnix:   now.Add(ttl).Unix(),
	}
	return s.sign(claims)
}

// sign serializes claims into a compact JWS under the active key, sets the kid
// header, and wraps the result in a Token. It is the single signing chokepoint
// for both mint paths.
func (s *Signer) sign(claims any) (Token, error) {
	key := s.keys.mintKey()
	if key.priv == nil {
		return Token{}, ErrNoActiveKey
	}
	method := jwt.GetSigningMethod(key.alg.JWTMethod())
	if method == nil {
		return Token{}, fmt.Errorf("%w: %v", ErrUnknownAlg, key.alg)
	}
	tok := jwt.NewWithClaims(method, jwt.MapClaims(toMap(claims)))
	tok.Header["kid"] = key.kid
	compact, err := tok.SignedString(key.priv)
	if err != nil {
		return Token{}, fmt.Errorf("cred: sign: %w", err)
	}
	return newToken(compact), nil
}

// ActiveKID returns the kid the next mint uses (the newest key). The JWKS
// publishes the active key plus, during the overlap, the previous key.
func (s *Signer) ActiveKID() string { return s.keys.mintKey().kid }

// PublicKeys returns the public halves the JWKS publisher renders (active plus
// overlap-previous). No private material crosses this boundary.
func (s *Signer) PublicKeys() []PublicKey { return s.keys.PublicKeys() }

// KeySet exposes the keyset for the rotation seam and the JWKS publisher.
func (s *Signer) KeySet() *KeySet { return s.keys }

// StorageTTL reports the fixed Storage-JWT window, for callers that compute an
// expiry preview without minting.
func (s *Signer) StorageTTL() time.Duration { return s.cfg.StorageTTL }

// deriveJTI builds the host-derived revocation handle from the host-derived
// session key, the filesystem id, and the mint instant. It is deterministic per
// (sessionKey, filesystemID, instant) so the finalizer that holds the
// FilesystemID can locate the jti the Revoker recorded at mint, while two mints
// for the same session at distinct instants get distinct handles.
func deriveJTI(sessionKey, filesystemID string, at time.Time) string {
	h := sha256.New()
	h.Write([]byte(sessionKey))
	h.Write([]byte{0})
	h.Write([]byte(filesystemID))
	h.Write([]byte{0})
	var nano [8]byte
	n := at.UnixNano()
	for i := 0; i < 8; i++ {
		// gosec: explicit byte extraction, no narrowing conversion of a wide int.
		nano[i] = byte(n >> (8 * i) & 0xff)
	}
	h.Write(nano[:])
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
