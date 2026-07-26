// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	sink, err := buildResumedChainSink(context.Background(), clk, aw, cfg.auditSink)
	if err != nil {
		t.Fatalf("buildResumedChainSink: %v", err)
	}
	_, _, _, _, auditSink := compose(state.NewInMemory(clk), clk, nil, 0, 0, nil, nil, sink, "", cfg)

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
	sink, err := buildResumedChainSink(context.Background(), clk, aw, cfg.auditSink)
	if err != nil {
		t.Fatalf("buildResumedChainSink: %v", err)
	}
	_, _, _, _, auditSink := compose(state.NewInMemory(clk), clk, nil, 0, 0, nil, nil, sink, "", cfg)

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
	sink, err := buildResumedChainSink(context.Background(), clk, aw, cfg.auditSink)
	if err != nil {
		t.Fatalf("buildResumedChainSink: %v", err)
	}
	_, _, _, _, auditSink := compose(state.NewInMemory(clk), clk, nil, 0, 0, nil, nil, sink, "", cfg)

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
	sink, err := buildResumedChainSink(context.Background(), clk, aw, cfg.auditSink)
	if err != nil {
		t.Fatalf("buildResumedChainSink: %v", err)
	}
	_, _, _, _, auditSink := compose(state.NewInMemory(clk), clk, nil, 0, 0, nil, nil, sink, "", cfg)

	eng, bootErr := buildMCPKeyEngine(context.Background(), cfg, clk, auditSink)
	if bootErr != nil {
		t.Fatalf("buildMCPKeyEngine with existing entries = %v; want nil", bootErr)
	}
	if eng == nil {
		t.Fatal("buildMCPKeyEngine returned nil engine")
	}
}

// Test_storageTTL_FlagRestoresDeployedSurface covers the -storage-ttl flag recovered
// from the deployed fleet binary (docs/recovery-fleet-binary-2026-07-26.md). The
// running stand passes `-storage-ttl 2h`; a build from this tree that did not define
// the flag would abort on it, because Go's flag package terminates on an undefined
// flag. So this test is the thing that keeps the tree able to produce the binary that
// is deployed.
//
// It also pins the two decisions the recovery had to make, since neither is
// observable from the artifact: an unset flag falls back to the short default (a
// deployment that omits it keeps today's behaviour), and a value well above that
// default is ACCEPTED (the stand's own 2h must not be refused by its own binary).
// A negative value is refused pre-bind, because a negative window mints an
// already-expired token while the daemon looks healthy.
func Test_storageTTL_FlagRestoresDeployedSurface(t *testing.T) {
	t.Parallel()
	base := []string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
	}
	withArgs := func(extra ...string) []string {
		return append(append([]string{}, base...), extra...)
	}

	t.Run("accepts-the-deployed-value", func(t *testing.T) {
		t.Parallel()
		cfg, _, err := parse(withArgs("-storage-ttl", "2h"))
		if err != nil {
			t.Fatalf("parse -storage-ttl 2h: %v (the deployed stand passes exactly this)", err)
		}
		if err := validate(cfg); err != nil {
			t.Fatalf("validate with -storage-ttl 2h: %v (the stand's own value must not be refused)", err)
		}
		if got := resolveStorageTTL(cfg); got != 2*time.Hour {
			t.Fatalf("resolveStorageTTL = %v, want 2h", got)
		}
	})

	t.Run("unset-falls-back-to-the-short-default", func(t *testing.T) {
		t.Parallel()
		cfg, _, err := parse(withArgs())
		if err != nil {
			t.Fatalf("parse without -storage-ttl: %v", err)
		}
		if got := resolveStorageTTL(cfg); got != defaultStorageTTL {
			t.Fatalf("resolveStorageTTL with the flag unset = %v, want the %v default", got, defaultStorageTTL)
		}
	})

	t.Run("negative-refused-pre-bind", func(t *testing.T) {
		t.Parallel()
		cfg, _, err := parse(withArgs("-storage-ttl", "-1s"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := validate(cfg); !errors.Is(err, errStorageTTLNegative) {
			t.Fatalf("validate with -storage-ttl -1s = %v, want errStorageTTLNegative", err)
		}
	})
}

// Test_announceStorageTTL_StatesTheEffectiveWindow covers the boot-time
// observability the uncapped -storage-ttl requires. With no ceiling, "how wide is the
// credential window here" must be answerable from the daemon's own output rather than
// by reading argv against the source -- an unannounced window is how a very wide
// credential lifetime ends up running with nothing saying so.
//
// The three cases are distinct on purpose: an unset flag says it took the default, a
// value at or under the default is reported plainly, and a WIDER value is warned
// about, because that is the case nobody meant to configure.
func Test_announceStorageTTL_StatesTheEffectiveWindow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		ttl         time.Duration
		wantSubstrs []string
		wantWarn    bool
	}{
		{"unset-says-default", 0, []string{defaultStorageTTL.String(), "default"}, false},
		{"narrower-reported-plainly", time.Minute, []string{"1m0s", "-storage-ttl"}, false},
		{"wider-is-warned", 2 * time.Hour, []string{"2h0m0s", "WIDER", "no refresh path"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			announceStorageTTL(&buf, config{storageTTL: tc.ttl})
			got := buf.String()
			for _, want := range tc.wantSubstrs {
				if !strings.Contains(got, want) {
					t.Errorf("announcement %q does not contain %q", got, want)
				}
			}
			if warned := strings.Contains(got, "WARNING"); warned != tc.wantWarn {
				t.Errorf("announcement %q warned=%v, want %v (only a window wider than the default warrants a warning)", got, warned, tc.wantWarn)
			}
		})
	}
}
