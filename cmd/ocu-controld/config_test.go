// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/mcpkeyset"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// Test_parse_MCPKeysetPath proves the -mcp-keyset-path flag is a clean no-op
// when unset: parse() accepts an invocation without it and config.mcpKeysetPath
// is empty. This mirrors the -jwks-path OPTIONAL semantics.
func Test_parse_MCPKeysetPath_Unset(t *testing.T) {
	t.Parallel()
	args := []string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
	}
	cfg, mode, err := parse(args)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if mode != modeServe {
		t.Fatalf("mode = %v, want modeServe", mode)
	}
	if cfg.mcpKeysetPath != "" {
		t.Fatalf("mcpKeysetPath = %q, want empty (unset = no-op)", cfg.mcpKeysetPath)
	}
}

// Test_parse_MCPKeysetPath_Set proves the -mcp-keyset-path flag is parsed into
// config.mcpKeysetPath when supplied.
func Test_parse_MCPKeysetPath_Set(t *testing.T) {
	t.Parallel()
	want := "/run/ocu-control/mcp-keyset.json"
	args := []string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
		"-mcp-keyset-path", want,
	}
	cfg, _, err := parse(args)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.mcpKeysetPath != want {
		t.Fatalf("mcpKeysetPath = %q, want %q", cfg.mcpKeysetPath, want)
	}
}

// Test_parse_MCPKeyFile_Unset proves the -mcp-key-file flag defaults to empty
// (in-memory-only storage, the minimal shelf default).
func Test_parse_MCPKeyFile_Unset(t *testing.T) {
	t.Parallel()
	args := []string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
	}
	cfg, _, err := parse(args)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.mcpKeyFile != "" {
		t.Fatalf("mcpKeyFile = %q, want empty (unset = in-memory-only)", cfg.mcpKeyFile)
	}
}

// Test_parse_MCPKeyFile_Set proves the -mcp-key-file flag is parsed into
// config.mcpKeyFile when supplied.
func Test_parse_MCPKeyFile_Set(t *testing.T) {
	t.Parallel()
	want := "/etc/ocu-control/mcp-keys.json"
	args := []string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
		"-mcp-key-file", want,
	}
	cfg, _, err := parse(args)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.mcpKeyFile != want {
		t.Fatalf("mcpKeyFile = %q, want %q", cfg.mcpKeyFile, want)
	}
}

// Test_buildMCPKeyEngine_NoFile proves buildMCPKeyEngine succeeds when
// -mcp-key-file is unset: the engine is constructed over an in-memory store
// with no entries file interaction.
func Test_buildMCPKeyEngine_NoFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")
	writeTestKey(t, keyPath)
	cfg := config{
		jwtSigningKey: keyPath,
		jwtAlg:        "eddsa",
		auditSink:     "none",
		// mcpKeysetPath and mcpKeyFile are intentionally unset.
	}
	clk := state.SystemClock()
	aw, err := buildAuditWriter(cfg.auditSink)
	if err != nil {
		t.Fatalf("buildAuditWriter: %v", err)
	}
	_, _, _, _, auditSink := compose(state.NewInMemory(clk), clk, nil, 0, 0, nil, aw, cfg)

	eng, err := buildMCPKeyEngine(context.Background(), cfg, clk, auditSink)
	if err != nil {
		t.Fatalf("buildMCPKeyEngine with no file = %v; want nil", err)
	}
	if eng == nil {
		t.Fatal("buildMCPKeyEngine returned nil engine")
	}
}

// Test_buildMCPKeyEngine_LoosePermAbortsBoot proves a -mcp-key-file with
// permissions looser than 0600 causes buildMCPKeyEngine to fail closed,
// wrapping mcpkeyset.ErrLoosePermissions. This is the boot-abort gate that
// mirrors the kill-switch-first discipline.
func Test_buildMCPKeyEngine_LoosePermAbortsBoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	entriesPath := filepath.Join(dir, "entries.json")
	// Write a valid but world-readable entries file.
	if err := os.WriteFile(entriesPath, []byte(`{"version":1,"records":[]}`+"\n"), 0o644); err != nil {
		t.Fatalf("write entries file: %v", err)
	}

	keyPath := filepath.Join(dir, "jwt.key")
	writeTestKey(t, keyPath)
	cfg := config{
		jwtSigningKey: keyPath,
		jwtAlg:        "eddsa",
		auditSink:     "none",
		mcpKeyFile:    entriesPath,
	}
	clk := state.SystemClock()
	aw, err := buildAuditWriter(cfg.auditSink)
	if err != nil {
		t.Fatalf("buildAuditWriter: %v", err)
	}
	_, _, _, _, auditSink := compose(state.NewInMemory(clk), clk, nil, 0, 0, nil, aw, cfg)

	_, bootErr := buildMCPKeyEngine(context.Background(), cfg, clk, auditSink)
	if bootErr == nil {
		t.Fatal("buildMCPKeyEngine with a 0644 entries file returned nil; want a boot-abort error")
	}
	if !errors.Is(bootErr, mcpkeyset.ErrLoosePermissions) {
		t.Fatalf("buildMCPKeyEngine error = %v; want a boot abort wrapping ErrLoosePermissions", bootErr)
	}
}

// Test_buildMCPKeyEngine_AbsentFileIsCleanStart proves an absent -mcp-key-file
// is a clean start (not an error): no prior entries exist, the engine is
// constructed over an empty in-memory store, and buildMCPKeyEngine returns nil.
func Test_buildMCPKeyEngine_AbsentFileIsCleanStart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")
	writeTestKey(t, keyPath)
	cfg := config{
		jwtSigningKey: keyPath,
		jwtAlg:        "eddsa",
		auditSink:     "none",
		mcpKeyFile:    filepath.Join(dir, "absent.json"), // never written
	}
	clk := state.SystemClock()
	aw, err := buildAuditWriter(cfg.auditSink)
	if err != nil {
		t.Fatalf("buildAuditWriter: %v", err)
	}
	_, _, _, _, auditSink := compose(state.NewInMemory(clk), clk, nil, 0, 0, nil, aw, cfg)

	eng, bootErr := buildMCPKeyEngine(context.Background(), cfg, clk, auditSink)
	if bootErr != nil {
		t.Fatalf("buildMCPKeyEngine with absent entries file = %v; want nil (clean start)", bootErr)
	}
	if eng == nil {
		t.Fatal("buildMCPKeyEngine returned nil engine on clean start")
	}
}

// Test_buildMCPKeyEngine_LoadsExistingEntries proves an existing 0600
// -mcp-key-file is loaded into the in-memory store at boot: the number of
// records seeded equals the number written to the file, so a daemon restart
// preserves the minimal-shelf MCP key set.
func Test_buildMCPKeyEngine_LoadsExistingEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	entriesPath := filepath.Join(dir, "entries.json")

	// Write a minimal valid entries file with one placeholder record so the
	// load path exercises the seed loop (a real Create is not needed here).
	raw := `{"version":1,"records":[` +
		`{"key_id":"kid-test","key_hash":"YQ==","salt":"YQ==","tenant":"acme","deployment":"","status":"active",` +
		`"created_at":"2025-01-01T00:00:00Z","expires_at":"0001-01-01T00:00:00Z"}` +
		`]}` + "\n"
	if err := os.WriteFile(entriesPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write entries file: %v", err)
	}

	keyPath := filepath.Join(dir, "jwt.key")
	writeTestKey(t, keyPath)
	cfg := config{
		jwtSigningKey: keyPath,
		jwtAlg:        "eddsa",
		auditSink:     "none",
		mcpKeyFile:    entriesPath,
	}
	clk := state.SystemClock()
	aw, err := buildAuditWriter(cfg.auditSink)
	if err != nil {
		t.Fatalf("buildAuditWriter: %v", err)
	}
	_, _, _, _, auditSink := compose(state.NewInMemory(clk), clk, nil, 0, 0, nil, aw, cfg)

	eng, bootErr := buildMCPKeyEngine(context.Background(), cfg, clk, auditSink)
	if bootErr != nil {
		t.Fatalf("buildMCPKeyEngine with existing entries = %v; want nil", bootErr)
	}
	if eng == nil {
		t.Fatal("buildMCPKeyEngine returned nil engine")
	}
}
