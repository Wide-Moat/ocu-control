// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/jwtmint"
)

// ExecSigner mints the per-dial, container-bound exec Session JWT the guest
// verifies on the exec channel (ADR-0024). It holds a DEPLOYMENT-WIDE exec
// signing key that is SEPARATE from the Storage-JWT keyring the *Signer holds
// (ADR-0013 key separation: the storage-JWT key and the control/exec-channel key
// never share material — an exec token must not verify under the JWKS the Egress
// trust-edge validates, and vice versa). The public half of THIS key is what the
// host stages as the guest's --auth-public-key verify file; a create body never
// supplies it.
//
// The token shape is exactly what the guest verifies: a keyless EdDSA JWS with
// claims {sub, iat, exp} and NOTHING else — no aud, no iss, no kid. It is minted
// through the canon jwtmint minter so the wire bytes are byte-identical to what
// the guest's verifier expects.
type ExecSigner struct {
	priv ed25519.PrivateKey
}

// NewExecSigner builds an ExecSigner over the deployment-wide exec private key.
// The public half (priv.Public()) is the value the handoff stages as the guest's
// verify key.
func NewExecSigner(priv ed25519.PrivateKey) *ExecSigner {
	return &ExecSigner{priv: priv}
}

// VerifyKey returns the public half of the exec signing key — the raw 32-byte
// Ed25519 public key the host stages as the guest's --auth-public-key verify file.
// A token minted by this signer verifies under exactly this key; nothing else does.
func (s *ExecSigner) VerifyKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// LoadExecSignerFromMount loads the SEPARATE exec-channel Ed25519 signing key from
// a PKCS8 PEM mount (the same on-disk format the fleet provisions the storage key
// as, so one key-init path serves both) and returns an ExecSigner over it. It is
// FAIL-CLOSED: a missing or garbage key aborts boot before any listener binds. The
// key is DISTINCT from the Storage-JWT keyring (ADR-0013): a deployment mounts it
// at a separate path so the exec-channel key and the storage key never share
// material.
func LoadExecSignerFromMount(path string) (*ExecSigner, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningKeyMissing, err)
	}
	signer, err := parsePKCS8Signer(raw, AlgEdDSA)
	if err != nil {
		return nil, err
	}
	ed, ok := signer.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: exec key is not Ed25519", ErrSigningKeyInvalid)
	}
	return &ExecSigner{priv: ed}, nil
}

// MintExecJWT mints the container-bound exec Session JWT: sub is the host-attested
// ContainerName, exp is clamped by the jwtmint minter's own hard cap, and the
// claim set is {sub, iat, exp} EdDSA with no aud/iss/kid. It satisfies the same
// narrow execMinter seam *Signer.MintExecJWT did, so the guestexec driver and the
// control-RPC dialer wire to it unchanged — but the signing key is the SEPARATE
// exec key, and the token verifies under the guest's staged verify key.
//
// The signing key never leaves this process; the returned Token redacts on every
// emit surface and reveals the raw JWS only at the single dial handshake.
func (s *ExecSigner) MintExecJWT(ctx context.Context, req ExecMintReq) (Token, error) {
	if err := ctx.Err(); err != nil {
		return Token{}, err
	}
	if req.ContainerName == "" {
		return Token{}, fmt.Errorf("%w: empty container_name", ErrMintIdentity)
	}
	ttl := req.RequestedTTL
	if ttl <= 0 {
		ttl = execMaxTTL
	}
	// jwtmint.NewSigner clamps ttl to its own 60-minute cap and emits the exact
	// {sub,iat,exp} EdDSA JWS the guest verifies (no aud/iss/kid).
	raw, err := jwtmint.NewSigner(s.priv, req.ContainerName).Mint(ttl)
	if err != nil {
		return Token{}, fmt.Errorf("cred: mint exec jwt: %w", err)
	}
	return newToken(raw), nil
}
