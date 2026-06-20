// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// repoRoot walks up from the test's working directory (cmd/ocu-controld) to the
// repository root so the shipped manifests are read from their committed paths.
// Anchoring on go.mod makes the test independent of how deep the package nests.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (no go.mod found walking up)")
		}
		dir = parent
	}
}

// manifestArgv is one shipped deployment manifest plus the serving argv extracted
// from it. The extractor reads the EXACT committed file so the test tracks the real
// manifest — a flag dropped from a manifest is caught here, not in a stale copy.
type manifestArgv struct {
	name string
	path string
	argv []string
}

// loadManifestArgvs extracts the serving argv from each shipped manifest by reading
// its committed file. Each extractor is deliberately narrow (it pulls the daemon's
// own flag tokens, dropping orchestration scaffolding like the leading binary path,
// YAML list punctuation, and systemd line continuations) so the resulting argv is
// exactly what the daemon's flag parser receives at boot.
func loadManifestArgvs(t *testing.T) []manifestArgv {
	t.Helper()
	root := repoRoot(t)
	return []manifestArgv{
		{
			name: "docker-compose",
			path: filepath.Join(root, "deploy", "docker-compose.yml"),
			argv: extractComposeCommand(t, filepath.Join(root, "deploy", "docker-compose.yml")),
		},
		{
			name: "k8s-deployment",
			path: filepath.Join(root, "examples", "k8s", "control-deployment.yaml"),
			argv: extractK8sArgs(t, filepath.Join(root, "examples", "k8s", "control-deployment.yaml")),
		},
		{
			name: "systemd-unit",
			path: filepath.Join(root, "contrib", "systemd", "ocu-controld.service"),
			argv: extractSystemdExecStart(t, filepath.Join(root, "contrib", "systemd", "ocu-controld.service")),
		},
	}
}

// extractComposeCommand reads the controld service's `command:` YAML list. The list
// is a block sequence of `- token` items beginning at the `command:` key and ending
// at the next same-or-shallower-indent key. Each item is the daemon's own argv
// token; environment-substitution syntax (${VAR:-default}) is resolved to the
// documented default so the extracted token is a literal the flag parser accepts.
func extractComposeCommand(t *testing.T, path string) []string {
	t.Helper()
	lines := readFileLines(t, path)
	return extractYAMLBlockSequence(t, lines, "command:")
}

// extractK8sArgs reads the container's `args:` YAML list the same way the compose
// extractor reads `command:` — a block sequence of `- token` items.
func extractK8sArgs(t *testing.T, path string) []string {
	t.Helper()
	lines := readFileLines(t, path)
	return extractYAMLBlockSequence(t, lines, "args:")
}

// extractYAMLBlockSequence pulls the `- token` items of the FIRST block sequence
// introduced by key, stopping at the first line whose indentation is at or below the
// key's own and which is not a sequence item or a comment/blank. Comment-only and
// blank lines inside the sequence are skipped. Each token has surrounding quotes
// stripped and env-substitution defaults resolved.
func extractYAMLBlockSequence(t *testing.T, lines []string, key string) []string {
	t.Helper()
	keyIndent := -1
	collecting := false
	var argv []string
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if !collecting {
			if strings.TrimSpace(raw) == key || strings.HasPrefix(trimmed, key) && strings.HasSuffix(trimmed, ":") {
				keyIndent = indentOf(raw)
				collecting = true
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // skip blanks and comment-only lines inside the sequence
		}
		if !strings.HasPrefix(trimmed, "- ") && trimmed != "-" {
			// A non-sequence line. If it is indented deeper than the key it is a nested
			// mapping we do not expect here; if at/under the key indent the sequence ended.
			if indentOf(raw) <= keyIndent {
				break
			}
			continue
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		item = stripInlineComment(item)
		item = unquoteYAML(item)
		item = resolveEnvDefault(item)
		argv = append(argv, item)
	}
	if len(argv) == 0 {
		t.Fatalf("extracted no argv for key %q (manifest format changed?)", key)
	}
	return argv
}

// extractSystemdExecStart reads the ExecStart= directive, joining its `\`-continued
// lines, dropping the leading binary path, and splitting the remaining flag tokens
// on whitespace. systemd uses no env-substitution syntax here, so the tokens are
// literals.
func extractSystemdExecStart(t *testing.T, path string) []string {
	t.Helper()
	lines := readFileLines(t, path)
	var b strings.Builder
	collecting := false
	for _, raw := range lines {
		line := raw
		if !collecting {
			if !strings.HasPrefix(strings.TrimSpace(line), "ExecStart=") {
				continue
			}
			collecting = true
			line = strings.TrimSpace(line)
			line = strings.TrimPrefix(line, "ExecStart=")
		} else {
			line = strings.TrimSpace(line)
		}
		cont := strings.HasSuffix(line, "\\")
		line = strings.TrimSuffix(line, "\\")
		b.WriteString(" ")
		b.WriteString(line)
		if !cont {
			break
		}
	}
	fields := strings.Fields(b.String())
	if len(fields) == 0 {
		t.Fatal("extracted no ExecStart tokens (manifest format changed?)")
	}
	// Drop the leading binary path; the rest is the daemon argv.
	return fields[1:]
}

// readFileLines returns the file's lines, failing the test on a read error.
func readFileLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open manifest %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan manifest %q: %v", path, err)
	}
	return lines
}

// indentOf returns the count of leading spaces on a line.
func indentOf(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

// stripInlineComment removes a trailing ` # ...` comment from a YAML scalar. It only
// trims a comment that is space-delimited, so a `#` inside a value is preserved.
func stripInlineComment(s string) string {
	if i := strings.Index(s, " #"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// unquoteYAML strips a single pair of surrounding single or double quotes.
func unquoteYAML(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// resolveEnvDefault resolves a ${VAR:-default} or ${VAR-default} shell-style
// substitution to its default, mirroring how Compose expands it when the env var is
// unset. A bare ${VAR} with no default resolves to empty (an unset var), which would
// itself be a manifest bug; the manifests under test always provide a default.
func resolveEnvDefault(s string) string {
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
		return s
	}
	inner := s[2 : len(s)-1]
	for _, sep := range []string{":-", "-"} {
		if i := strings.Index(inner, sep); i >= 0 {
			return inner[i+len(sep):]
		}
	}
	return "" // ${VAR} with no default
}

// Test_Manifests_ClearFlagValidation_InProcess is the always-on regression guard the
// readiness review demanded: it extracts EACH shipped manifest's exact argv from its
// committed file and asserts the daemon's own parse()+validate() pipeline accepts it
// — i.e. no manifest exits 1 on a missing or invalid REQUIRED flag. This runs with
// no binary build, no Docker, and no socket: it exercises the SAME flag surface the
// real boot runs, so a flag dropped from any manifest (e.g. -workload-profile) fails
// this test loudly.
func Test_Manifests_ClearFlagValidation_InProcess(t *testing.T) {
	t.Parallel()
	for _, m := range loadManifestArgvs(t) {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			cfg, mode, err := parse(m.argv)
			if err != nil {
				t.Fatalf("%s argv %v failed flag parse: %v", m.path, m.argv, err)
			}
			if mode != modeServe {
				t.Fatalf("%s argv parsed to mode %v, want a serving invocation (modeServe)", m.path, mode)
			}
			if err := validate(cfg); err != nil {
				t.Fatalf("%s argv %v did NOT clear flag validation: %v", m.path, m.argv, err)
			}
			// Cross-check EVERY flag the validator declares required is present, so a
			// future required flag added to the validator is caught in the manifests too.
			assertAllRequiredFlagsPresent(t, m)
		})
	}
}

// assertAllRequiredFlagsPresent independently confirms each manifest argv carries
// every flag in the validator's required set with a non-empty value. validate()
// already enforces this, but asserting it explicitly documents the cross-check the
// review asked for and pins exactly which flags a manifest must carry.
func assertAllRequiredFlagsPresent(t *testing.T, m manifestArgv) {
	t.Helper()
	required := []string{
		"-operator-listen",
		"-gateway-listen",
		"-runtime-tier",
		"-runtime-provider",
		"-workload-profile",
		"-jwt-signing-key",
		"-audit-sink",
	}
	present := map[string]string{}
	for i := 0; i < len(m.argv); i++ {
		tok := m.argv[i]
		if strings.HasPrefix(tok, "-") && i+1 < len(m.argv) {
			present[tok] = m.argv[i+1]
		}
	}
	for _, req := range required {
		val, ok := present[req]
		if !ok {
			t.Fatalf("%s manifest is missing required flag %s (would exit 1 at boot)", m.name, req)
		}
		if strings.TrimSpace(val) == "" {
			t.Fatalf("%s manifest has empty value for required flag %s", m.name, req)
		}
	}
}

// Test_Manifests_ClearFlagValidation_RealBinary boots the REAL daemon binary with
// each manifest's exact argv and asserts it gets PAST flag validation: stderr never
// carries a flag-validation sentinel. The binary may still fail LATER (the signing
// key path, the socket directory, or Docker are absent in the test env), which is
// expected and fine — the assertion is only that no manifest exits on a missing or
// invalid REQUIRED flag. It runs only when OCU_CONTROL_BIN points at a built binary,
// matching the e2e leg convention; otherwise it loud-skips.
func Test_Manifests_ClearFlagValidation_RealBinary(t *testing.T) {
	t.Parallel()
	bin := os.Getenv("OCU_CONTROL_BIN")
	if bin == "" {
		t.Skip("OCU_CONTROL_BIN unset: skipping the real-binary manifest smoke (run `make bin` and export it)")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("OCU_CONTROL_BIN=%q not usable: %v", bin, err)
	}

	// The flag-validation sentinels the daemon prints on a refused invocation. None of
	// these may appear when a manifest argv clears flag validation.
	flagValidationSentinels := []string{
		"required flag missing or invalid",
		"unknown runtime tier",
		"unknown runtime provider",
		"unknown workload profile",
		"unknown jwt signing algorithm",
	}

	for _, m := range loadManifestArgvs(t) {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			// A short bound: a valid invocation proceeds to boot (which then fails on the
			// absent signing key / socket dir essentially immediately, or starts serving).
			// Either way the flag-validation verdict is decided long before this fires.
			out, _ := runBinary(t, bin, m.argv, 4*time.Second)
			for _, sentinel := range flagValidationSentinels {
				if strings.Contains(out, sentinel) {
					t.Fatalf("%s manifest argv tripped flag validation (%q):\n%s", m.name, sentinel, out)
				}
			}
		})
	}
}

// runBinary runs bin with argv, bounded by timeout, and returns combined output. A
// timeout is not an error here: a manifest whose argv clears flag validation reaches
// the serve path, which may run until the bound. The caller asserts only on output
// content, never the exit code, because a valid-but-unbootable invocation (no
// signing key, no Docker) exits non-zero for a NON-flag reason.
func runBinary(t *testing.T, bin string, argv []string, timeout time.Duration) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, argv...)
	out := &strings.Builder{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return out.String(), errors.New("timeout")
	}
}
