// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// baseArgs is the minimal valid serving invocation the -granted-intents tests
// extend; every required flag is present so parse/validate reach the flag under test.
func grantedIntentsBaseArgs(extra ...string) []string {
	return append([]string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
	}, extra...)
}

// Test_resolveGrantedIntents_UnsetDefaultsToReadWrite proves the minimal shelf runs
// zero-config: an unset -granted-intents resolves to the pinned default ceiling,
// which admits exactly the two intents control derives from a mount posture (read,
// write) and refuses preview until a deployment names it (ADR-0029 §Decision "the
// default map ships pinned, so the minimal shelf runs zero-config").
func Test_resolveGrantedIntents_UnsetDefaultsToReadWrite(t *testing.T) {
	t.Parallel()
	cfg, _, err := parse(grantedIntentsBaseArgs())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ceiling, err := resolveGrantedIntents(cfg)
	if err != nil {
		t.Fatalf("resolveGrantedIntents(unset): %v", err)
	}
	if !ceiling.Admits(cred.IntentRead) || !ceiling.Admits(cred.IntentWrite) {
		t.Fatal("default ceiling must admit read and write (the two derivable intents)")
	}
	if ceiling.Admits(cred.IntentPreview) {
		t.Fatal("default ceiling must NOT admit preview — it is out of scope until a deployment names it")
	}
}

// Test_resolveGrantedIntents_NarrowsToNamed proves the flag is a ceiling that
// NARROWS: naming only read yields a ceiling that admits read and refuses write, so
// a write-deriving mount is refused fail-closed downstream (the flag never grants —
// it only removes intents from the served set).
func Test_resolveGrantedIntents_NarrowsToNamed(t *testing.T) {
	t.Parallel()
	cfg, _, err := parse(grantedIntentsBaseArgs("-granted-intents", "read"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ceiling, err := resolveGrantedIntents(cfg)
	if err != nil {
		t.Fatalf("resolveGrantedIntents(read): %v", err)
	}
	if !ceiling.Admits(cred.IntentRead) {
		t.Fatal("ceiling named read must admit read")
	}
	if ceiling.Admits(cred.IntentWrite) {
		t.Fatal("ceiling named read must NOT admit write — the flag narrows the served set")
	}
}

// Test_resolveGrantedIntents_UnknownRefused proves an unknown intent aborts boot
// fail-closed rather than being silently dropped — a typo in -granted-intents must
// not silently serve a narrower-or-wider set than the operator believes (the enum
// discipline mirroring -runtime-tier). The refusal is typed for the boot path.
func Test_resolveGrantedIntents_UnknownRefused(t *testing.T) {
	t.Parallel()
	cfg, _, err := parse(grantedIntentsBaseArgs("-granted-intents", "read,delete"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := resolveGrantedIntents(cfg); !errors.Is(err, errUnknownIntent) {
		t.Fatalf("resolveGrantedIntents(read,delete) err = %v, want errUnknownIntent", err)
	}
}

// Test_validate_RejectsUnknownGrantedIntent proves the unknown-intent refusal runs
// in the pre-bind validate() gate, so a malformed -granted-intents aborts boot
// before any Store is built or listener bound (fail-closed, no partial daemon).
func Test_validate_RejectsUnknownGrantedIntent(t *testing.T) {
	t.Parallel()
	cfg, _, err := parse(grantedIntentsBaseArgs("-granted-intents", "write,bogus"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := validate(cfg); !errors.Is(err, errUnknownIntent) {
		t.Fatalf("validate with a bogus -granted-intents = %v, want errUnknownIntent", err)
	}
}
