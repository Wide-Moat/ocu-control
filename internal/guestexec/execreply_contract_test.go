// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package guestexec

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// execReplySchemaPath is the vendored canon contract for the F5 reply envelope.
// The contract-identity gate keeps it byte-identical to canon, so reading it here
// reads the frozen wire rather than a local copy of it.
const execReplySchemaPath = "../../contracts/exec/exec-reply.schema.json"

// TestStdioCapMatchesTheFrozenReplyCeiling binds defaultStdioCap to the contract.
//
// The cap and the gateway's read bound are set in different repositories, and
// when they diverged — 64 KiB read against an 8 MiB capture — a large output was
// read to the limit, its JSON truncated mid-string, and the whole result dropped
// as a 502 rather than delivered as a truncated success. Nothing detected the
// divergence, because each side was internally consistent.
//
// The contract now states the ceiling once, as base64(cap) on each stream. This
// test is the half of the binding that lives here: raise defaultStdioCap and the
// published schema no longer describes what this code emits, so the test reds
// before a caller ever sees a reply the far side refuses to read.
func TestStdioCapMatchesTheFrozenReplyCeiling(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Clean(execReplySchemaPath))
	if err != nil {
		t.Fatalf("read the vendored exec-reply contract: %v", err)
	}
	var schema struct {
		Defs struct {
			Base64Stream struct {
				MaxLength *int `json:"maxLength"`
			} `json:"Base64Stream"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("the vendored exec-reply contract is not parseable JSON: %v", err)
	}

	got := schema.Defs.Base64Stream.MaxLength
	if got == nil {
		t.Fatal("the contract pins no maxLength on a reply stream; the cap is unbound and this test would be vacuous")
	}

	// The contract bounds the ENCODED stream, this code bounds the raw bytes, so
	// the comparison runs through the same encoding the reply uses.
	want := base64.StdEncoding.EncodedLen(defaultStdioCap)
	if *got != want {
		t.Errorf("defaultStdioCap is %d bytes, which encodes to %d base64 characters, but the frozen contract pins maxLength %d.\n"+
			"One of the two moved without the other. Changing the cap is a wire change: re-freeze the contract in canon, "+
			"re-vendor it here and in the gateway, and check the gateway's read bound still clears 2*maxLength plus the envelope.",
			defaultStdioCap, want, *got)
	}
}

// TestReplyCeilingLeavesRoomForTwoStreams checks the other half of the sizing
// invariant the contract records: a legal reply carries base64(stdout) AND
// base64(stderr) plus a JSON envelope, so a reader bounded below that truncates
// the JSON and fails the whole reply.
//
// It asserts the shape of the arithmetic rather than the gateway's constant,
// which lives in another repository and cannot be imported. What it catches is a
// cap raised to a value where no plausible reader bound could hold: the pair of
// streams alone must stay well inside the 256 KiB the gateway reads today.
func TestReplyCeilingLeavesRoomForTwoStreams(t *testing.T) {
	t.Parallel()

	const gatewayReadBound = 256 << 10 // ocu-mcp-gateway maxReplyBytes

	perStream := base64.StdEncoding.EncodedLen(defaultStdioCap)
	twoStreams := 2 * perStream
	if twoStreams >= gatewayReadBound {
		t.Fatalf("two encoded streams are %d bytes against a %d-byte reader bound: a legal reply cannot be read whole, "+
			"which is the large-output 502 class returning", twoStreams, gatewayReadBound)
	}
	// Envelope headroom: the field names, the exit code, and the two booleans.
	// A few hundred bytes suffice, so anything under 1 KiB of slack means the
	// caps were sized against each other with no margin at all.
	if slack := gatewayReadBound - twoStreams; slack < 1<<10 {
		t.Errorf("only %d bytes of headroom for the JSON envelope; the reply would parse only for the smallest field set", slack)
	}
}
