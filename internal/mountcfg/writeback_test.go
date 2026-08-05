// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/mountcfg"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// writeBackFixture renders a two-mount config with the given write-back default
// and returns the marshaled bytes plus the compiled frozen schema, so each test
// below can assert on the WIRE and on schema acceptance from the same render.
func writeBackFixture(t *testing.T, delay mountcfg.WriteBackDelay) ([]byte, map[string]any) {
	t.Helper()
	signer := signerForTest(t)
	mounts := []runtime.MountIntent{
		{Destination: "/workspace/out", FilesystemID: "session_01HXYZ_out", ReadOnly: false, CacheSeconds: 3600},
		{Destination: "/workspace/mem", MemoryStoreID: "mem_01HXYZ", ReadOnly: true, CacheSeconds: 3},
	}
	tokens := []cred.Token{
		mintFor(t, signer, "session_01HXYZ_out", cred.IntentWrite),
		mintFor(t, signer, "session_01HXYZ_mem", cred.IntentRead),
	}
	defaults := defaultsForTest(t)
	defaults.VfsWriteBack = delay

	cfg, err := mountcfg.Render(testServiceURL, testCACert, mounts, tokens, defaults)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal rendered config: %v", err)
	}
	return b, generic
}

// mountsOf pulls the mounts array out of a generically-decoded config.
func mountsOf(t *testing.T, generic map[string]any) []map[string]any {
	t.Helper()
	raw, ok := generic["mounts"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("rendered config has no mounts array; every assertion below would be vacuous")
	}
	out := make([]map[string]any, 0, len(raw))
	for i, m := range raw {
		mm, ok := m.(map[string]any)
		if !ok {
			t.Fatalf("mounts[%d] is not an object", i)
		}
		out = append(out, mm)
	}
	return out
}

// TestWriteBackDelayReachesTheWireAndTheSchemaAcceptsIt is the load-bearing test.
//
// It fails in BOTH directions that matter, which is why it is one test and not two:
// if the renderer drops the value the key assertion fails, and if the frozen schema
// forbids the key the validation fails. Before this change the second half could not
// pass at all — the schema's Mount object is additionalProperties:false and carried
// no vfs_write_back, so the delay the guest mounter has always accepted was one no
// producer was permitted to send.
//
// The value matters, not just the key: the guest agent stops waiting for its mount
// boot-child after roughly two seconds, so a delay at or above that window means the
// most recent write of every session is discarded at teardown. Asserting the exact
// string is what keeps a later "tidy-up" from raising it back over the window.
func TestWriteBackDelayReachesTheWireAndTheSchemaAcceptsIt(t *testing.T) {
	const delay = "500ms"

	wb, err := mountcfg.NewWriteBackDelay(delay)
	if err != nil {
		t.Fatalf("NewWriteBackDelay(%q): %v", delay, err)
	}
	b, generic := writeBackFixture(t, wb)

	for i, m := range mountsOf(t, generic) {
		got, present := m["vfs_write_back"]
		if !present {
			t.Errorf("mounts[%d] has no vfs_write_back key: the renderer dropped the delay, so the "+
				"guest keeps its own default and the teardown window still truncates the queue", i)
			continue
		}
		if got != delay {
			t.Errorf("mounts[%d] vfs_write_back = %v; want %q", i, got, delay)
		}
	}

	sch := compileFrozenSchema(t)
	if err := validateAgainstFrozen(t, sch, b); err != nil {
		t.Fatalf("a config carrying vfs_write_back does not validate against the frozen schema: %v", err)
	}
}

// TestUnsetWriteBackOmitsTheKeyEntirely pins the additive half of the change: a
// deployment that never sets the delay must render exactly what it rendered before
// the field existed. An empty string reaching the wire as "vfs_write_back":"" would
// be a schema violation AND would hand the guest a value it refuses, so "unset" has
// to mean absent, not empty.
func TestUnsetWriteBackOmitsTheKeyEntirely(t *testing.T) {
	b, generic := writeBackFixture(t, "")

	for i, m := range mountsOf(t, generic) {
		if v, present := m["vfs_write_back"]; present {
			t.Errorf("mounts[%d] carries vfs_write_back = %v with no delay configured; "+
				"an unset delay must omit the key, never emit an empty one", i, v)
		}
	}
	if strings.Contains(string(b), "vfs_write_back") {
		t.Errorf("the marshaled bytes mention vfs_write_back with no delay configured")
	}

	sch := compileFrozenSchema(t)
	if err := validateAgainstFrozen(t, sch, b); err != nil {
		t.Fatalf("the unchanged render no longer validates: %v", err)
	}
}

// TestNewWriteBackDelayRefusesUnusableValues covers the constructor's negative half.
// The zero cases are the ones worth spelling out: they MATCH the frozen pattern, so
// the regex alone lets them through, and the guest mounter refuses a non-positive
// delay outright — a mount that never comes up rather than one that flushes late.
func TestNewWriteBackDelayRefusesUnusableValues(t *testing.T) {
	for _, bad := range []string{
		"",        // the omitted state, expressed by leaving the field zero — never constructed
		"0s",      // pattern-shaped zero
		"0ms",     // pattern-shaped zero
		"0.0s",    // pattern-shaped zero with a fraction
		"5",       // bare number, no unit
		"5 s",     // embedded space
		"-1s",     // negative
		"1d",      // not a Go duration unit
		"1s ",     // trailing space
		"forever", // not a duration at all
	} {
		if got, err := mountcfg.NewWriteBackDelay(bad); err == nil {
			t.Errorf("NewWriteBackDelay(%q) = %q, nil; want ErrBadWriteBackDelay", bad, got)
		} else if !errors.Is(err, mountcfg.ErrBadWriteBackDelay) {
			t.Errorf("NewWriteBackDelay(%q) error = %v; want ErrBadWriteBackDelay", bad, err)
		}
	}

	for _, good := range []string{"500ms", "1s", "1.5s", "250ms", "1m"} {
		if _, err := mountcfg.NewWriteBackDelay(good); err != nil {
			t.Errorf("NewWriteBackDelay(%q): %v", good, err)
		}
	}
}
