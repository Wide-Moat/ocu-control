// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Contract tests: the occ CLI against the REAL daemon operator surface.
//
// Both ends of the operator wire live in this repository — the occ client here
// and the daemon's mcp-key routes in internal/ingress/operator — yet until this
// file no test ever connected them: every occ unit test rewrote the dial to a
// TCP httptest server with a hand-rolled handler, so the shipped Unix-socket
// transport, the -socket flag plumbing, the frozen route paths, and the
// CLI↔daemon wire-type identity were all unproven. The daemon decodes with
// DisallowUnknownFields, so a JSON tag drift between the hand-mirrored types is
// a production 400 that keeps both unit suites green. These tests close that
// class: they bind the real operator Listener on a real Unix socket and drive
// the SHIPPED occ path (run → unixHTTPClient → real mux → decodeJSON → real
// mcp-key engine), so any drift on either end goes red here.
package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// fixedResolver is a test IdentityResolver returning a fixed host-derived
// operator identity, injected through the production Deps.Resolver field — the
// same seam the daemon's own transport tests use. It is what lets the full
// transport + handler path run on darwin AND linux: SO_PEERCRED is Linux-only,
// so over a real Unix socket the off-Linux ConnContext hook stashes an
// unattested ConnInfo and the real resolver would refuse everything. Like the
// production peer-cred resolver it derives identity from host-attested
// transport facts, never from a request body, and refuses any non-operator
// channel fail-closed.
type fixedResolver struct {
	id state.Identity
}

func (r fixedResolver) Resolve(_ context.Context, conn ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	if conn.Channel != ingress.ChannelOperator {
		return ingress.AuthenticatedCaller{}, ingress.ErrUnattested
	}
	return ingress.AuthenticatedCaller{Identity: r.id, Channel: ingress.ChannelOperator}, nil
}

// shortSocketPath returns a Unix-socket path under a 0700 directory short
// enough to stay under the platform's sun_path limit (~104 bytes on darwin,
// ~108 on Linux), which the long per-test t.TempDir() path on macOS exceeds.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	root := os.TempDir()
	if goruntime.GOOS == "darwin" {
		// /tmp is a short symlink on macOS, unlike the long $TMPDIR path.
		if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
			root = "/tmp"
		}
	}
	dir, err := os.MkdirTemp(root, "occop")
	if err != nil {
		t.Fatalf("mkdir short temp: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod short temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "op.sock")
}

// startRealOperator binds the real operator Listener on a real Unix socket with
// a real mcp-key engine (in-memory record store, no-op rerender) and serves it
// until the test ends. Every collaborator is the shipped constructor — the only
// injected piece is the fixedResolver above, for cross-platform attestation.
// Readiness is polled through the SHIPPED unixHTTPClient, so even the wait
// exercises the production dial path.
func startRealOperator(t *testing.T) string {
	t.Helper()
	socket := shortSocketPath(t)
	deps := operator.Deps{
		Resolver: fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}},
		Seam:     ingress.NewOperatorSeam(),
		MCPKeyEngine: mcpkey.NewEngine(
			mcpkey.NewMinter(),
			mcpkey.NewInMemRecordStore(),
			func(context.Context) error { return nil },
			state.SystemClock(),
			audit.NewRecordingFake(),
		),
		Healthz: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	}

	l := operator.NewListener(socket, deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- l.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve returned %v; want nil on clean shutdown", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Serve did not return after context cancel")
		}
	})

	client := unixHTTPClient(socket)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://unix/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return socket
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("real operator listener did not become ready within the deadline")
	return ""
}

// fieldFromOutput extracts the value of a "Label : value" line from the CLI's
// rendered output, so the contract tests read the key id and raw key from the
// same shipped render the operator reads.
func fieldFromOutput(output, label string) string {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, label) {
			continue
		}
		if _, value, found := strings.Cut(trimmed, ":"); found {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// Test_MCPKey_CreateThenRevoke_AgainstRealDaemon drives the SHIPPED occ path
// end to end against the real daemon surface: run() with a real --socket flag,
// the production unixHTTPClient dialling a real Unix socket, the daemon's real
// mux (so the frozen route paths are load-bearing), the daemon's real
// decodeJSON (so an unknown-field wire drift on either hand-mirrored type is a
// 400 and a red test), and the real mcp-key engine behind it. The returned
// key_id is then revoked over the same path, proving the create was durably
// accepted, and the shown-once invariant is asserted against the real
// response rather than a fake one.
func Test_MCPKey_CreateThenRevoke_AgainstRealDaemon(t *testing.T) {
	t.Parallel()
	socket := startRealOperator(t)
	ctx := context.Background()

	var out bytes.Buffer
	// The -socket flag lives on the top-level FlagSet, so it precedes the
	// subcommand — the same argv shape an operator types.
	err := run(ctx, []string{
		"--socket", socket,
		"mcp-key", "create",
		"--tenant", "acme",
		"--deployment", "prod",
		"--expires", "720h",
	}, &out, unixHTTPClient)
	if err != nil {
		t.Fatalf("mcp-key create against the real daemon = %v; want nil", err)
	}
	output := out.String()

	rawKey := fieldFromOutput(output, "Raw key")
	if !strings.HasPrefix(rawKey, "sk-ocu-") {
		t.Fatalf("rendered raw key %q does not carry the sk-ocu- prefix\noutput:\n%s", rawKey, output)
	}
	if count := strings.Count(output, rawKey); count != 1 {
		t.Errorf("raw key appears %d times in output; want exactly 1 (shown-once invariant)\noutput:\n%s", count, output)
	}
	keyID := fieldFromOutput(output, "Key ID")
	if keyID == "" {
		t.Fatalf("rendered output carries no key id\noutput:\n%s", output)
	}

	out.Reset()
	err = run(ctx, []string{
		"--socket", socket,
		"mcp-key", "revoke",
		"--id", keyID,
		"--reason", "contract test",
	}, &out, unixHTTPClient)
	if err != nil {
		t.Fatalf("mcp-key revoke against the real daemon = %v; want nil", err)
	}
	if !strings.Contains(out.String(), "revoked") {
		t.Errorf("revoke output does not confirm revocation\noutput:\n%s", out.String())
	}
}
