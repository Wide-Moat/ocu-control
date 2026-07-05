// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// baseServeArgs is a minimal valid serving invocation the gateway-mTLS tests
// extend, so a validate() call exercises only the flag under test.
func baseServeArgs() []string {
	return []string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
	}
}

// TestGatewayTLSFlagsAllOrNone proves the boot validation: none of the three
// -gateway-tls-* flags validates (the stubbed plain-TCP posture), all three
// validate (real mTLS), and any PARTIAL set is refused fail-closed — a
// misconfiguration must never silently degrade to plain TCP.
func TestGatewayTLSFlagsAllOrNone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		extra   []string
		wantErr bool
	}{
		{"none-set", nil, false},
		{"all-three-set", []string{"-gateway-tls-cert", "c.pem", "-gateway-tls-key", "k.pem", "-gateway-client-ca", "ca.pem"}, false},
		{"only-cert", []string{"-gateway-tls-cert", "c.pem"}, true},
		{"cert-and-key-no-ca", []string{"-gateway-tls-cert", "c.pem", "-gateway-tls-key", "k.pem"}, true},
		{"only-client-ca", []string{"-gateway-client-ca", "ca.pem"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, _, err := parse(append(baseServeArgs(), tc.extra...))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = validate(cfg)
			if tc.wantErr && err == nil {
				t.Fatal("validate = nil; want a fail-closed all-or-none refusal")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validate = %v; want nil", err)
			}
			if tc.wantErr && !errors.Is(err, errRequiredFlagMissing) {
				t.Fatalf("validate err = %v; want errRequiredFlagMissing", err)
			}
		})
	}
}

// TestBuildGatewayTLSConfig proves the TLS build: unset flags yield a nil config
// (the plain-TCP posture), and a valid cert/key/client-CA yields a config that
// REQUIRES AND VERIFIES a client cert at a TLS 1.3 floor — the keystone that makes
// a connection's SAN a host-attested identity. An unreadable key pair or an
// unparseable client-CA fails closed.
func TestBuildGatewayTLSConfig(t *testing.T) {
	t.Parallel()

	t.Run("unset yields nil (plain-TCP posture)", func(t *testing.T) {
		t.Parallel()
		got, err := buildGatewayTLSConfig(config{})
		if err != nil {
			t.Fatalf("buildGatewayTLSConfig(unset) err = %v; want nil", err)
		}
		if got != nil {
			t.Fatal("buildGatewayTLSConfig(unset) = non-nil; want nil (plain-TCP)")
		}
	})

	t.Run("valid pems build a require-and-verify TLS 1.3 config", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		certPath, keyPath := writeServerCert(t, dir)
		caPath := writeCACert(t, dir)

		cfg := config{gatewayTLSCert: certPath, gatewayTLSKey: keyPath, gatewayClientCA: caPath}
		got, err := buildGatewayTLSConfig(cfg)
		if err != nil {
			t.Fatalf("buildGatewayTLSConfig: %v", err)
		}
		if got == nil {
			t.Fatal("buildGatewayTLSConfig = nil; want a config")
		}
		if got.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("ClientAuth = %v; want RequireAndVerifyClientCert (the keystone — a client without a cert must be rejected)", got.ClientAuth)
		}
		if got.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %x; want TLS 1.3", got.MinVersion)
		}
		if got.ClientCAs == nil {
			t.Fatal("ClientCAs is nil; the client cert has no trust anchor")
		}
		if len(got.Certificates) != 1 {
			t.Fatalf("Certificates = %d; want 1 server cert", len(got.Certificates))
		}
	})

	t.Run("unreadable key pair fails closed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		caPath := writeCACert(t, dir)
		cfg := config{
			gatewayTLSCert:  filepath.Join(dir, "absent-cert.pem"),
			gatewayTLSKey:   filepath.Join(dir, "absent-key.pem"),
			gatewayClientCA: caPath,
		}
		if _, err := buildGatewayTLSConfig(cfg); err == nil {
			t.Fatal("buildGatewayTLSConfig with an absent cert = nil error; want fail-closed")
		}
	})

	t.Run("unparseable client-CA fails closed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		certPath, keyPath := writeServerCert(t, dir)
		badCA := filepath.Join(dir, "bad-ca.pem")
		if err := os.WriteFile(badCA, []byte("not a pem cert"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		cfg := config{gatewayTLSCert: certPath, gatewayTLSKey: keyPath, gatewayClientCA: badCA}
		if _, err := buildGatewayTLSConfig(cfg); err == nil {
			t.Fatal("buildGatewayTLSConfig with an unparseable client-CA = nil error; want fail-closed")
		}
	})
}

// writeServerCert writes a self-signed server cert+key PEM pair and returns their
// paths.
func writeServerCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gateway.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, "server-cert.pem")
	keyPath = filepath.Join(dir, "server-key.pem")
	writePEM(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

// writeCACert writes a self-signed CA cert PEM and returns its path.
func writeCACert(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ocu-fleet-ca.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caPath := filepath.Join(dir, "client-ca.pem")
	writePEM(t, caPath, "CERTIFICATE", der)
	return caPath
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
