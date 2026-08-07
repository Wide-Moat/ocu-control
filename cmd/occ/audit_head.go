// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// runAuditHead reads a retained audit spine, validates it, accumulates the
// Merkle head over it, and writes the signed submission envelope to stdout
// (NFR-SEC-03).
//
// ADR-0009 splits the work: the accumulator and the envelope signature are
// OCU's, the transparency-log submission is the customer's. So this emits the
// envelope and stops — piping it at a submission step is the deployment's
// choice, which is also why stdout carries the envelope alone and nothing else.
//
// It reads a LOCAL file and needs no daemon socket, the same shape as
// `occ audit verify`.
func runAuditHead(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("occ audit head", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("file", "", "path to the OCSF audit file to accumulate over (required)")
	keyPath := fs.String("signing-key", "", "path to the PEM PKCS#8 Ed25519 envelope signing key (required)")
	if err := fs.Parse(args); err != nil {
		return usageError("occ audit head --file <path> --signing-key <path>")
	}
	if *file == "" {
		return usageError("occ audit head requires --file <path>")
	}
	if *keyPath == "" {
		return usageError("occ audit head requires --signing-key <path>")
	}

	signer, err := loadHeadSigningKey(*keyPath)
	if err != nil {
		return err
	}

	envs, err := ocsf.ReadChainFile(*file)
	if err != nil {
		return fmt.Errorf("read audit file: %w", err)
	}

	// HeadOverSpine validates before it accumulates, so a tampered spine is
	// refused here rather than signed. Nothing is written to out on this path:
	// a partial envelope on stdout could be piped onward as if it were valid.
	head, err := ocsf.HeadOverSpine(envs)
	if err != nil {
		return fmt.Errorf("accumulate head: %w", err)
	}

	env, err := ocsf.SignHead(head, signer)
	if err != nil {
		return fmt.Errorf("sign head: %w", err)
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	fmt.Fprintf(out, "%s\n", body)
	return nil
}

// errSigningKey is the fail-closed key-intake verdict.
var errSigningKey = errors.New("envelope signing key")

// loadHeadSigningKey reads a PEM PKCS#8 Ed25519 private key.
//
// Key CUSTODY is a customer seam (ADR-0009): a file is the host-local reference
// default, and an HSM-rooted PKCS#11 / KMIP path is the enterprise alternative.
// This intake accepts the reference form and names the mismatch when handed
// anything else, rather than producing an envelope no verifier can check.
func loadHeadSigningKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", errSigningKey, path, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: %s holds no PEM block", errSigningKey, path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a PKCS#8 key: %w", errSigningKey, path, err)
	}

	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s holds a %T; the head envelope is signed with ed25519",
			errSigningKey, path, key)
	}
	return priv, nil
}
