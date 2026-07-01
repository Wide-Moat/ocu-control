// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeDialFunc returns a dialFunc that builds an http.Client routing to the
// given httptest.Server instead of a real Unix socket. This lets the unit tests
// exercise the full request-build → flag-parse → render path without a live
// daemon or socket. The socket argument is ignored; all requests are rewritten
// to hit the test server's TCP address regardless of the http://unix/ host.
func fakeDialFunc(srv *httptest.Server) dialFunc {
	return func(_ string) *http.Client {
		srvAddr := srv.Listener.Addr().String()
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", srvAddr)
				},
			},
		}
	}
}

// Test_run_UnknownSubcommand asserts an unknown subcommand returns a usageError.
func Test_run_UnknownSubcommand(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"bogus"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("run() returned nil on an unknown subcommand; want usageError")
	}
	var ue usageError
	if !isUsageError(err, &ue) {
		t.Fatalf("run() error %T (%v) is not a usageError", err, err)
	}
	if !strings.Contains(err.Error(), "unknown subcommand") {
		t.Fatalf("run() error %q does not name 'unknown subcommand'", err)
	}
}

// Test_run_NoArgs asserts a bare `occ` invocation with no subcommand returns a
// usageError — the binary must name the expected subcommand in the error.
func Test_run_NoArgs(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("run() returned nil on no args; want usageError")
	}
	var ue usageError
	if !isUsageError(err, &ue) {
		t.Fatalf("run() error %T (%v) is not a usageError", err, err)
	}
}

// Test_MCPKey_Create_MissingTenant asserts mcp-key create returns usageError
// when --tenant is absent.
func Test_MCPKey_Create_MissingTenant(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"mcp-key", "create"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("mcp-key create without --tenant returned nil; want usageError")
	}
	var ue usageError
	if !isUsageError(err, &ue) {
		t.Fatalf("error %T (%v) is not a usageError", err, err)
	}
	if !strings.Contains(err.Error(), "--tenant") {
		t.Fatalf("usageError %q does not name '--tenant'", err)
	}
}

// Test_MCPKey_Create_MissingDeployment mirrors the tenant check: the canon
// create-request marks deployment required (ADR-0027) and the daemon refuses
// an empty one with 400, so the CLI refuses before dialing.
func Test_MCPKey_Create_MissingDeployment(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"mcp-key", "create", "--tenant", "acme"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("mcp-key create without --deployment returned nil; want usageError")
	}
	var ue usageError
	if !isUsageError(err, &ue) {
		t.Fatalf("error %T (%v) is not a usageError", err, err)
	}
	if !strings.Contains(err.Error(), "--deployment") {
		t.Fatalf("usageError %q does not name '--deployment'", err)
	}
}

// Test_MCPKey_Create_BadExpires asserts an invalid --expires duration returns
// a non-usage error.
func Test_MCPKey_Create_BadExpires(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"mcp-key", "create", "--tenant", "acme", "--deployment", "prod", "--expires", "notaduration"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("mcp-key create with invalid --expires returned nil; want error")
	}
	if strings.Contains(err.Error(), "--tenant") {
		t.Fatalf("error %q names '--tenant', want a duration-parse error", err)
	}
}

// Test_MCPKey_Create_HappyPath drives the full mcp-key create flag-parse and
// shown-once render path with a fake HTTP server. It asserts:
//  1. The request body carries the correct tenant/deployment/expires_at fields.
//  2. The rendered output contains the raw key, the key_id, and the store-now note.
//  3. The raw key appears EXACTLY ONCE in the output.
func Test_MCPKey_Create_HappyPath(t *testing.T) {
	t.Parallel()

	const wantRawKey = "sk-ocu-TestKey1234567890ABCDEFGHIJK"
	const wantKeyID = "kid-test-abc"
	const wantTenant = "acme"

	var gotBody mcpKeyCreateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		resp := mcpKeyCreateResponse{
			RawKey: wantRawKey,
			KeyID:  wantKeyID,
			Tenant: wantTenant,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	var out bytes.Buffer
	err := run(context.Background(), []string{
		"mcp-key", "create",
		"--tenant", wantTenant,
		"--deployment", "prod",
	}, &out, fakeDialFunc(srv))
	if err != nil {
		t.Fatalf("mcp-key create happy path = %v; want nil", err)
	}

	// Request body assertions.
	if gotBody.Tenant != wantTenant {
		t.Errorf("request body tenant = %q, want %q", gotBody.Tenant, wantTenant)
	}
	if gotBody.Deployment != "prod" {
		t.Errorf("request body deployment = %q, want %q", gotBody.Deployment, "prod")
	}
	if gotBody.ExpiresAt != nil {
		t.Errorf("request body expires_at = %v, want nil (non-expiring)", gotBody.ExpiresAt)
	}

	output := out.String()

	// Raw key appears exactly once.
	count := strings.Count(output, wantRawKey)
	if count != 1 {
		t.Errorf("raw key appears %d times in output; want exactly 1 (shown-once invariant)\noutput:\n%s", count, output)
	}

	// Key ID appears in the output.
	if !strings.Contains(output, wantKeyID) {
		t.Errorf("output does not contain key_id %q\noutput:\n%s", wantKeyID, output)
	}

	// The "store now" note is present.
	if !strings.Contains(output, "STORE THIS KEY NOW") {
		t.Errorf("output does not contain the store-now note\noutput:\n%s", output)
	}
	if !strings.Contains(output, "will NOT be shown again") {
		t.Errorf("output does not contain 'will NOT be shown again'\noutput:\n%s", output)
	}
}

// Test_MCPKey_Create_DaemonRefusal asserts a non-201 daemon response is
// surfaced as a descriptive error (not a nil return or a panic).
func Test_MCPKey_Create_DaemonRefusal(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "route not mounted yet", http.StatusNotFound)
	}))
	defer srv.Close()

	var out bytes.Buffer
	err := run(context.Background(), []string{
		"mcp-key", "create", "--tenant", "acme", "--deployment", "prod",
	}, &out, fakeDialFunc(srv))
	if err == nil {
		t.Fatal("mcp-key create with a 404 response returned nil; want error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error %q does not name the HTTP status code", err)
	}
}

// Test_MCPKey_Revoke_MissingID asserts mcp-key revoke without --id returns a
// usageError naming --id.
func Test_MCPKey_Revoke_MissingID(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"mcp-key", "revoke"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("mcp-key revoke without --id returned nil; want usageError")
	}
	var ue usageError
	if !isUsageError(err, &ue) {
		t.Fatalf("error %T (%v) is not a usageError", err, err)
	}
	if !strings.Contains(err.Error(), "--id") {
		t.Fatalf("usageError %q does not name '--id'", err)
	}
}

// Test_MCPKey_Revoke_HappyPath drives the full mcp-key revoke flag-parse and
// confirmation render with a fake HTTP server.
func Test_MCPKey_Revoke_HappyPath(t *testing.T) {
	t.Parallel()

	const wantKeyID = "kid-test-xyz"
	const wantReason = "operator drill"

	var gotBody mcpKeyRevokeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "revoked")
	}))
	defer srv.Close()

	var out bytes.Buffer
	err := run(context.Background(), []string{
		"mcp-key", "revoke",
		"--id", wantKeyID,
		"--reason", wantReason,
	}, &out, fakeDialFunc(srv))
	if err != nil {
		t.Fatalf("mcp-key revoke happy path = %v; want nil", err)
	}

	// Request body assertions.
	if gotBody.KeyID != wantKeyID {
		t.Errorf("request body key_id = %q, want %q", gotBody.KeyID, wantKeyID)
	}
	if gotBody.Reason != wantReason {
		t.Errorf("request body reason = %q, want %q", gotBody.Reason, wantReason)
	}

	// Confirmation output.
	output := out.String()
	if !strings.Contains(output, wantKeyID) {
		t.Errorf("output does not contain key_id %q\noutput:\n%s", wantKeyID, output)
	}
	if !strings.Contains(output, "revoked") {
		t.Errorf("output does not confirm revocation\noutput:\n%s", output)
	}
}

// Test_MCPKey_Revoke_DaemonRefusal asserts a non-200 revoke response is
// surfaced as an error.
func Test_MCPKey_Revoke_DaemonRefusal(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "route not mounted yet", http.StatusNotFound)
	}))
	defer srv.Close()

	var out bytes.Buffer
	err := run(context.Background(), []string{
		"mcp-key", "revoke", "--id", "kid-xyz",
	}, &out, fakeDialFunc(srv))
	if err == nil {
		t.Fatal("mcp-key revoke with a 404 response returned nil; want error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error %q does not name the HTTP status code", err)
	}
}

// Test_MCPKey_UnknownVerb asserts an unknown mcp-key verb returns a usageError.
func Test_MCPKey_UnknownVerb(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"mcp-key", "delete"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("mcp-key delete returned nil; want usageError")
	}
	var ue usageError
	if !isUsageError(err, &ue) {
		t.Fatalf("error %T (%v) is not a usageError", err, err)
	}
}

// Test_renderCreateResult is a directed render test: it asserts the shown-once
// raw key appears EXACTLY ONCE and the store-now note is present. The test drives
// renderCreateResult directly — without a network call — so the shown-once
// invariant is a unit-level fact independent of the transport.
func Test_renderCreateResult(t *testing.T) {
	t.Parallel()
	const rawKey = "sk-ocu-UniqueTestKeyABCD1234567890XYZ"
	const keyID = "kid-render-test"

	var out bytes.Buffer
	renderCreateResult(&out, mcpKeyCreateResponse{
		RawKey: rawKey,
		KeyID:  keyID,
		Tenant: "test-tenant",
	})

	output := out.String()
	count := strings.Count(output, rawKey)
	if count != 1 {
		t.Errorf("raw key appears %d times in render output; want exactly 1\noutput:\n%s", count, output)
	}
	if !strings.Contains(output, "STORE THIS KEY NOW") {
		t.Errorf("render output missing store-now note\noutput:\n%s", output)
	}
	if !strings.Contains(output, "will NOT be shown again") {
		t.Errorf("render output missing 'will NOT be shown again'\noutput:\n%s", output)
	}
	if !strings.Contains(output, keyID) {
		t.Errorf("render output missing key_id %q\noutput:\n%s", keyID, output)
	}
}

// isUsageError is a helper that checks whether err is (or wraps) a usageError and
// writes the matched value to *ue. It uses errors.As so a wrapped usageError still
// matches — the errorlint-clean form of the earlier bare type assertion.
func isUsageError(err error, ue *usageError) bool {
	return errors.As(err, ue)
}
