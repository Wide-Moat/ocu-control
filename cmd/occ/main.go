// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// occ — the operator CLI for the Control plane (component-02).
//
// occ is a thin client over the operator Unix socket (the SAME transport the
// admin-API/CLI channel already uses). It adds NO third listener — the two-listener
// invariant (NFR-SEC-52) is untouched. Usage:
//
//	occ mcp-key create --tenant <T> [--deployment <D>] [--expires <dur>]
//	occ mcp-key revoke --id <ID> [--reason <R>]
//
// The operator socket is addressed by the -socket flag (default:
// /run/ocu-control/operator.sock). The daemon side wires the mcp-key routes when
// the architect's canon wire-freeze lands (Q7 of 08-RESEARCH.md); until then the
// command plumbing + flag parsing + shown-once render are fully tested and ready.
//
// Security notes:
//   - The raw sk-ocu- key is SHOWN ONCE on stdout at create time; the operator is
//     responsible for recording it immediately. It is never shown again.
//   - The operator socket is host-owned 0700; only the host operator reaches it.
//   - No body field carries the acting caller's identity — that is derived from
//     SO_PEERCRED by the daemon (NFR-SEC-43).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// defaultSocket is the default operator socket path. It mirrors the minimal-shelf
// socket path in the shipped manifests and the daemon's own default.
const defaultSocket = "/run/ocu-control/operator.sock"

// dialTimeout is the per-connection dial timeout for the operator socket.
const dialTimeout = 5 * time.Second

// requestTimeout is the per-request timeout including the dial.
const requestTimeout = 30 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, unixHTTPClient)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "occ:", err)
		os.Exit(1)
	}
}

// unixHTTPClient is the production dial function that builds an HTTP client over
// a Unix socket. The socketPath is embedded in the DialContext so the caller
// needs no further configuration.
var unixHTTPClient dialFunc = func(socketPath string) *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: dialTimeout}
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// dialFunc is the seam for the HTTP client factory. The production implementation
// returns a client dialling the operator Unix socket; tests inject a fake client.
type dialFunc func(socketPath string) *http.Client

// run parses argv and dispatches the subcommand. It writes to out (os.Stdout
// in production; a buffer in tests) so the shown-once key render is testable.
func run(ctx context.Context, args []string, out io.Writer, dial dialFunc) error {
	fs := flag.NewFlagSet("occ", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", defaultSocket, "path to the operator Unix socket")

	if err := fs.Parse(args); err != nil || fs.NArg() < 1 {
		return usageError("expected a subcommand: mcp-key")
	}

	switch fs.Arg(0) {
	case "mcp-key":
		return runMCPKey(ctx, fs.Args()[1:], *socket, out, dial)
	default:
		return usageError(fmt.Sprintf("unknown subcommand %q: expected mcp-key", fs.Arg(0)))
	}
}

// runMCPKey dispatches the mcp-key subcommand family.
func runMCPKey(ctx context.Context, args []string, socket string, out io.Writer, dial dialFunc) error {
	if len(args) < 1 {
		return usageError("expected a mcp-key verb: create | revoke")
	}
	switch args[0] {
	case "create":
		return runMCPKeyCreate(ctx, args[1:], socket, out, dial)
	case "revoke":
		return runMCPKeyRevoke(ctx, args[1:], socket, out, dial)
	default:
		return usageError(fmt.Sprintf("unknown mcp-key verb %q: expected create or revoke", args[0]))
	}
}

// mcpKeyCreateRequest is the JSON body the occ CLI sends to the daemon for
// mcp-key create. The wire route is deferred (Q7); the body shape mirrors the
// daemon-side handler signature (tenant, deployment, expires_at).
//
// The field names are stable in-process names — the A2 wire-freeze maps them to
// canon field names at the checkpoint; do not treat them as a frozen wire contract.
type mcpKeyCreateRequest struct {
	Tenant     string `json:"tenant"`
	Deployment string `json:"deployment,omitempty"`
	// ExpiresAt is omitted when zero (non-expiring key, ADR-0027).
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// mcpKeyCreateResponse is the minimal response the daemon sends back on a
// successful mcp-key create. RawKey is the shown-once sk-ocu- key (Reveal()
// was called on the daemon side before serialization). KeyID is the public
// handle for subsequent revoke --id calls.
//
// Like the request body, these are in-process field names pending the wire-freeze.
type mcpKeyCreateResponse struct {
	RawKey string `json:"raw_key"`
	KeyID  string `json:"key_id"`
	Tenant string `json:"tenant"`
}

// mcpKeyRevokeRequest is the JSON body for mcp-key revoke.
type mcpKeyRevokeRequest struct {
	KeyID  string `json:"key_id"`
	Reason string `json:"reason,omitempty"`
}

// runMCPKeyCreate parses the mcp-key create flags, builds the request body,
// POSTs it to the operator socket, and prints the result. The raw key is shown
// ONCE on stdout with a "store this now" note.
func runMCPKeyCreate(ctx context.Context, args []string, socket string, out io.Writer, dial dialFunc) error {
	fs := flag.NewFlagSet("occ mcp-key create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	tenant := fs.String("tenant", "", "target tenant the new key is scoped to (required)")
	deployment := fs.String("deployment", "", "deployment scope within the tenant (optional)")
	expires := fs.String("expires", "", "key expiry as a Go duration (e.g. 720h); absent means non-expiring")

	if err := fs.Parse(args); err != nil {
		return usageError(fmt.Sprintf("mcp-key create: %v", err))
	}
	if *tenant == "" {
		return usageError("mcp-key create: --tenant is required")
	}

	req := mcpKeyCreateRequest{
		Tenant:     *tenant,
		Deployment: *deployment,
	}
	if *expires != "" {
		d, err := time.ParseDuration(*expires)
		if err != nil {
			return fmt.Errorf("mcp-key create: --expires %q is not a valid duration: %w", *expires, err)
		}
		t := time.Now().UTC().Add(d)
		req.ExpiresAt = &t
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("mcp-key create: marshal request: %w", err)
	}

	client := dial(socket)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1alpha/mcp-keys", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("mcp-key create: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("mcp-key create: dial operator socket %q: %w", socket, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("mcp-key create: read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("mcp-key create: daemon refused (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var created mcpKeyCreateResponse
	if err := json.Unmarshal(raw, &created); err != nil {
		return fmt.Errorf("mcp-key create: parse response: %w", err)
	}

	// Shown-once render: the raw sk-ocu- key is displayed exactly here, once.
	// After this function returns the raw key is no longer accessible. The caller
	// must record it immediately — the daemon will not serve it again.
	renderCreateResult(out, created)
	return nil
}

// renderCreateResult writes the shown-once create result to out. It is a
// separate function so the unit test can assert the exact output without
// a live socket. The raw key is printed once with a prominent store-now note.
func renderCreateResult(out io.Writer, resp mcpKeyCreateResponse) {
	fmt.Fprintln(out, "MCP API key created.")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  Key ID  :", resp.KeyID)
	fmt.Fprintln(out, "  Tenant  :", resp.Tenant)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  Raw key :", resp.RawKey)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  !!! STORE THIS KEY NOW — it will NOT be shown again. !!!")
	fmt.Fprintln(out, "  Use `occ mcp-key revoke --id", resp.KeyID, "` to revoke it.")
}

// runMCPKeyRevoke parses the mcp-key revoke flags, builds the request body,
// POSTs it to the operator socket, and confirms the revocation.
func runMCPKeyRevoke(ctx context.Context, args []string, socket string, out io.Writer, dial dialFunc) error {
	fs := flag.NewFlagSet("occ mcp-key revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	keyID := fs.String("id", "", "key_id to revoke (required, from `occ mcp-key create` output)")
	reason := fs.String("reason", "", "operator-supplied reason for the audit trail (optional)")

	if err := fs.Parse(args); err != nil {
		return usageError(fmt.Sprintf("mcp-key revoke: %v", err))
	}
	if *keyID == "" {
		return usageError("mcp-key revoke: --id is required")
	}

	req := mcpKeyRevokeRequest{
		KeyID:  *keyID,
		Reason: *reason,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("mcp-key revoke: marshal request: %w", err)
	}

	client := dial(socket)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1alpha/mcp-keys/revoke", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("mcp-key revoke: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("mcp-key revoke: dial operator socket %q: %w", socket, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("mcp-key revoke: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mcp-key revoke: daemon refused (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	fmt.Fprintf(out, "MCP API key %q revoked.\n", *keyID)
	return nil
}

// usageError wraps a usage message so callers can distinguish a flag-parse
// or missing-arg error from a runtime error.
type usageError string

func (e usageError) Error() string { return string(e) }
