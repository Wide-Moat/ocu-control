// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// validArgs is a fully-valid serving invocation EXCEPT it binds nothing (Phase
// 1 opens no socket). Individual cases append or perturb one field. The
// listen/jwt/audit values are never dialled or opened on the paths these tests
// exercise: the static gates pass, boot runs against the in-memory default
// store, and either the kill-switch-first create refusal or the bind stub is
// reached — none of which touches those paths.
func validArgs() []string {
	return []string{
		"-operator-listen", "unix:///tmp/ocu-test-operator.sock",
		"-gateway-listen", "unix:///tmp/ocu-test-gateway.sock",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-jwt-signing-key", "/tmp/ocu-test-jwt.key",
		"-audit-sink", "/tmp/ocu-test-audit.jsonl",
	}
}

// Test_run_MissingRequiredFlag asserts the first absent required flag is named
// and the typed sentinel is returned, the smoke's load-bearing substring.
func Test_run_MissingRequiredFlag(t *testing.T) {
	t.Parallel()
	err := run(context.Background(), []string{"-runtime-tier", "runc"})
	if err == nil {
		t.Fatal("run() returned nil on a missing required flag; want a refusal")
	}
	if !errors.Is(err, errRequiredFlagMissing) {
		t.Fatalf("run() error does not match errRequiredFlagMissing: %v", err)
	}
	if !strings.Contains(err.Error(), "-operator-listen") {
		t.Fatalf("run() error %q does not name the first missing flag -operator-listen", err)
	}
}

// Test_run_UnknownRuntimeTier asserts an unknown tier is refused pre-bind,
// before any Store is constructed.
func Test_run_UnknownRuntimeTier(t *testing.T) {
	t.Parallel()
	args := validArgs()
	args[5] = "bogus" // -runtime-tier value
	err := run(context.Background(), args)
	if !errors.Is(err, errUnknownRuntimeTier) {
		t.Fatalf("run() error does not match errUnknownRuntimeTier: %v", err)
	}
}

// Test_run_UnknownRuntimeProvider asserts an unknown provider is refused
// pre-bind.
func Test_run_UnknownRuntimeProvider(t *testing.T) {
	t.Parallel()
	args := validArgs()
	args[7] = "podman" // -runtime-provider value
	err := run(context.Background(), args)
	if !errors.Is(err, errUnknownProvider) {
		t.Fatalf("run() error does not match errUnknownProvider: %v", err)
	}
}

// Test_run_KillSwitchFirst drives -create-on-start through the REAL boot path
// with the default in-memory store: boot engages the deployment-wide
// kill-switch, AdmitCreate refuses through a real Store.Reserve, and run()
// surfaces the refusal wrapped under errKillSwitchFirst with the load-bearing
// NFR-SEC-01 substring.
func Test_run_KillSwitchFirst(t *testing.T) {
	t.Parallel()
	args := append(validArgs(), "-create-on-start")
	err := run(context.Background(), args)
	if err == nil {
		t.Fatal("run() returned nil on -create-on-start; want a kill-switch-first refusal")
	}
	if !errors.Is(err, errKillSwitchFirst) {
		t.Fatalf("run() error does not wrap errKillSwitchFirst: %v", err)
	}
	if !strings.Contains(err.Error(), "NFR-SEC-01") {
		t.Fatalf("run() error %q does not name NFR-SEC-01", err)
	}
}

// Test_run_KillSwitchFirst_ExplicitInMemory documents that an explicit empty
// -state-dsn (the in-memory default) refuses identically, mirroring the smoke's
// explicit-empty assertion.
func Test_run_KillSwitchFirst_ExplicitInMemory(t *testing.T) {
	t.Parallel()
	args := append(validArgs(), "-state-dsn", "", "-create-on-start")
	err := run(context.Background(), args)
	if !errors.Is(err, errKillSwitchFirst) {
		t.Fatalf("run() with explicit empty -state-dsn does not wrap errKillSwitchFirst: %v", err)
	}
	if !strings.Contains(err.Error(), "NFR-SEC-01") {
		t.Fatalf("run() error %q does not name NFR-SEC-01", err)
	}
}

// Test_run_CleanBoot_ReachesBindStub asserts a clean, create-free boot loads the
// deny posture and reaches the Phase-1 bind stub (which is not yet wired), not a
// static-gate or fail-closed error. This proves the bind step is reachable only
// after a successful boot.
func Test_run_CleanBoot_ReachesBindStub(t *testing.T) {
	t.Parallel()
	err := run(context.Background(), validArgs())
	if err == nil {
		t.Fatal("run() returned nil; want the bind-not-wired stub error")
	}
	if !strings.Contains(err.Error(), "listener bind not yet wired") {
		t.Fatalf("run() error %q is not the expected bind stub", err)
	}
}

// Test_run_Version returns the version with no boot.
func Test_run_Version(t *testing.T) {
	t.Parallel()
	if err := run(context.Background(), []string{"-version"}); err != nil {
		t.Fatalf("run(-version): %v", err)
	}
}
