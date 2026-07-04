// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package controlrpc_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// newControlSigner builds a real cred.ExecSigner over a freshly generated exec
// Ed25519 key, so a dial mints a genuine per-dial exec JWT in the {sub,iat,exp}
// EdDSA shape the guest verifies. The dial only reaches the wire if the mint
// succeeds, so a real ExecSigner keeps the integration test end-to-end rather than
// stubbing the custody seam.
func newControlSigner(t *testing.T) *cred.ExecSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return cred.NewExecSigner(priv)
}
