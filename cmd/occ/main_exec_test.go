// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Re-exec tests: the SHIPPED main() entrypoint, argv to exit code.
//
// main() owns the error→stderr→os.Exit(1) mapping and the signal wiring; run()
// tests cannot reach any of it, so until this file a main() that exited 0 on
// every failure kept the suite green. These tests re-exec the test binary with
// OCC_MAIN_HELPER=1 so the real main() runs in a subprocess, and assert the
// process-level contract: exit 1 with the "occ:" stderr prefix on failure, and
// exit 0 with the shown-once key render on a create against the real daemon.
package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// occMainArgsSep separates argv words in the OCC_MAIN_ARGS env var handed to
// the re-exec helper. A unit separator cannot collide with flag values.
const occMainArgsSep = "\x1f"

// Test_Main_ReexecHelper is the re-exec trampoline, not a test: in a normal run
// the env guard makes it a no-op pass, and when the driving tests below spawn
// the test binary with OCC_MAIN_HELPER=1 it replaces os.Args and hands control
// to the SHIPPED main(). The error path never returns (os.Exit inside main);
// the success path returns here and the subprocess exits 0 through the normal
// test-binary epilogue.
func Test_Main_ReexecHelper(t *testing.T) {
	if os.Getenv("OCC_MAIN_HELPER") != "1" {
		return
	}
	os.Args = append([]string{"occ"}, strings.Split(os.Getenv("OCC_MAIN_ARGS"), occMainArgsSep)...)
	main()
}

// reexecMain spawns the test binary as an occ process running the shipped
// main() with the given argv, returning the captured stdio and process error.
func reexecMain(t *testing.T, args []string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=Test_Main_ReexecHelper$")
	cmd.Env = append(os.Environ(),
		"OCC_MAIN_HELPER=1",
		"OCC_MAIN_ARGS="+strings.Join(args, occMainArgsSep),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// Test_Main_FailureExitsOneWithStderr asserts the shipped failure contract: a
// bad invocation makes the occ PROCESS exit 1 and name the error on stderr
// with the occ: prefix. This is the exact line an operator's shell script
// checks; run()-level tests cannot see it.
func Test_Main_FailureExitsOneWithStderr(t *testing.T) {
	t.Parallel()
	stdout, stderr, err := reexecMain(t, []string{"bogus"})

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("main() with a bad subcommand exited cleanly (err=%v); want exit code 1", err)
	}
	if code := exitErr.ExitCode(); code != 1 {
		t.Fatalf("main() exit code = %d; want 1", code)
	}
	if !strings.Contains(stderr, "occ:") {
		t.Errorf("stderr %q does not carry the occ: error prefix", stderr)
	}
	if !strings.Contains(stderr, "unknown subcommand") {
		t.Errorf("stderr %q does not name the unknown subcommand", stderr)
	}
	if strings.Contains(stdout, "occ:") {
		t.Errorf("error text leaked to stdout %q; the error contract is stderr-only", stdout)
	}
}

// Test_Main_CreateSuccessExitsZeroShownOnce asserts the shipped success
// contract against the real daemon: the occ PROCESS exits 0 and renders the
// shown-once raw key on stdout. The subprocess dials the same real operator
// socket the contract tests use, so the whole argv→main→run→unix-dial→real-mux
// chain is one observable fact.
func Test_Main_CreateSuccessExitsZeroShownOnce(t *testing.T) {
	t.Parallel()
	socket := startRealOperator(t)

	stdout, stderr, err := reexecMain(t, []string{
		"--socket", socket,
		"mcp-key", "create",
		"--tenant", "acme",
		"--deployment", "prod",
	})
	if err != nil {
		t.Fatalf("main() create against the real daemon exited %v; want 0\nstderr:\n%s", err, stderr)
	}

	rawKey := fieldFromOutput(stdout, "Raw key")
	if !strings.HasPrefix(rawKey, "sk-ocu-") {
		t.Fatalf("stdout raw key %q does not carry the sk-ocu- prefix\nstdout:\n%s", rawKey, stdout)
	}
	if count := strings.Count(stdout, rawKey); count != 1 {
		t.Errorf("raw key appears %d times on stdout; want exactly 1 (shown-once invariant)\nstdout:\n%s", count, stdout)
	}
	if !strings.Contains(stdout, "STORE THIS KEY NOW") {
		t.Errorf("stdout does not carry the store-now note\nstdout:\n%s", stdout)
	}
}
