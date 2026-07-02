// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// PREFIX-INTEGRITY CAVEAT (a documented v1 limitation). Resume-from-tip and the whole
// hash-chain prove PREFIX-integrity, not COMPLETENESS: a chain is tamper-evident
// against a mutated, reordered, or spliced record, and ErrTipDecoupled catches a torn
// (mid-record) truncation. But it does NOT detect a CLEAN truncation at a record
// boundary — if an attacker deletes whole trailing records, the remaining prefix is
// still a perfectly valid chain, and a resume continues from the (now-earlier) tip as
// though nothing were missing. Detecting a clean-boundary truncation needs an anchor
// OUTSIDE the file — a monotonically-advancing tip checkpoint (last sequence + hash)
// persisted in the control DB and compared at boot, or the downstream Merkle-head
// submission that seals each segment. That external anchor is tracked as a follow-up
// (see docs/notes) and is out of scope for v1, where the hot spine is short-lived. The
// chain still delivers the ADR-0009 minimal-shelf detective posture for every tamper
// class EXCEPT clean-boundary trailing-truncation.

// ErrTipDecoupled is the resume verdict when an existing audit file's tail cannot be
// read as a valid chain tip: the last line does not parse as a ChainEnvelope, or its
// stored Hash does not match a recompute over its own (prior_hash, sequence, event).
// A caller MUST NOT silently re-anchor at genesis on this error — that would hide a
// truncation or a mid-write crash behind a fresh spine. The discontinuity is surfaced
// so the boot path records it as an explicit, post-hoc-detectable chain break
// (component-07 invariant: the chain has zero UNEXPLAINED breaks; a break is always
// detectable after the fact).
var ErrTipDecoupled = errors.New("ocsf: audit file tail is not a valid chain tip (decoupled)")

// Tip is the resume anchor read from an existing audit file: the last committed
// event's sequence and hash. A ChainSink constructed with these continues the SAME
// per-source spine across a restart, so the sequence stays strictly monotonic and the
// prior-hash link is unbroken — the single continuous spine ADR-0009 and component-07
// require (chain order derives from the per-source monotonic sequence; the chain has
// zero breaks).
type Tip struct {
	// LastSeq is the sequence of the last committed envelope, or 0 for an empty/absent
	// file (the genesis state, where the next event is sequence 1).
	LastSeq uint64
	// PriorTip is the hash of the last committed envelope, or genesisPriorHash for an
	// empty/absent file. The next event's PriorHash links to this.
	PriorTip string
	// Fresh is true when the file was empty or absent, so the resumed sink starts at
	// genesis LEGITIMATELY (a first boot), distinct from a decoupled tail (which is an
	// error, never a silent genesis).
	Fresh bool
}

// genesisTip is the resume anchor for an empty or absent audit file: the first event
// written will be sequence 1 linking to genesisPriorHash.
func genesisTip() Tip {
	return Tip{LastSeq: 0, PriorTip: genesisPriorHash, Fresh: true}
}

// ReadChainFile reads every ChainEnvelope from the audit file at path, in order, for a
// full-spine ValidateChain (the boot-time and on-demand tamper-evidence check). An
// absent file is a valid empty chain (nil, nil). A line that is not a ChainEnvelope is
// a hard error — a malformed audit file is a tamper/corruption signal, not something to
// skip. It reads the whole file; the cost note on the boot caller documents why that is
// acceptable in v1 (the hot spine stays small until the cold-tier rotation seam lands).
func ReadChainFile(path string) ([]ChainEnvelope, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ocsf: open audit file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var envs []ChainEnvelope
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxEnvelopeLine)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var env ChainEnvelope
		if err := json.Unmarshal(b, &env); err != nil {
			return nil, fmt.Errorf("ocsf: audit file %q line %d is not a ChainEnvelope: %w", path, line, err)
		}
		envs = append(envs, env)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ocsf: read audit file %q: %w", path, err)
	}
	return envs, nil
}

// ReadTip reads the resume anchor from an existing audit file at path. It returns:
//   - genesisTip() (Fresh=true) when the file is absent or empty — a legitimate first
//     boot;
//   - a Tip carrying the last envelope's Sequence and Hash when the tail is a valid,
//     self-consistent chain tip — the restart continues the spine;
//   - ErrTipDecoupled when the file is non-empty but its last line is not a valid,
//     hash-consistent ChainEnvelope — the caller records an explicit chain break rather
//     than re-anchoring silently.
//
// It validates ONLY the tail (the last line), not the whole file: a resume needs the
// continuation point, and full-file tamper verification is ValidateChain's job (run
// at boot and on demand). Reading the tail is O(1)-ish over the file size via a
// streaming scan that keeps only the last non-empty line.
func ReadTip(path string) (Tip, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return genesisTip(), nil
	}
	if err != nil {
		return Tip{}, fmt.Errorf("ocsf: open audit file for resume %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	lastLine, err := lastNonEmptyLine(f)
	if err != nil {
		return Tip{}, fmt.Errorf("ocsf: read audit file tail %q: %w", path, err)
	}
	if lastLine == nil {
		// The file exists but holds no complete line (empty, or only whitespace): treat
		// as a legitimate genesis start, not a decoupled tail — there is no prior event
		// to continue from and nothing was truncated away.
		return genesisTip(), nil
	}

	env, err := parseValidTip(lastLine)
	if err != nil {
		return Tip{}, fmt.Errorf("%w: %v", ErrTipDecoupled, err)
	}
	return Tip{LastSeq: env.Sequence, PriorTip: env.Hash, Fresh: false}, nil
}

// parseValidTip parses one line as a ChainEnvelope and asserts it is self-consistent:
// its stored Hash equals a recompute over its own (PriorHash, Sequence, Event). A
// self-consistent tail is a safe continuation point; an inconsistent one means the
// last write was torn or the tail was tampered, so it is not a usable tip.
func parseValidTip(line []byte) (ChainEnvelope, error) {
	var env ChainEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return ChainEnvelope{}, fmt.Errorf("tail is not a ChainEnvelope: %w", err)
	}
	if env.Sequence == 0 {
		return ChainEnvelope{}, errors.New("tail sequence is 0 (a committed envelope is >= 1)")
	}
	want, err := computeHash(env.PriorHash, env.Sequence, env.Event)
	if err != nil {
		return ChainEnvelope{}, fmt.Errorf("tail hash unrecomputable: %w", err)
	}
	if want != env.Hash {
		return ChainEnvelope{}, fmt.Errorf("tail hash %q != recomputed %q (torn write or tamper)", env.Hash, want)
	}
	return env, nil
}

// lastNonEmptyLine streams r and returns the last non-empty line (without its
// trailing newline), or nil when there is no non-empty line. It scans forward with a
// large buffer so a long JSON envelope line is never split; the audit file grows
// append-only, so forward-scanning the whole file is the simple, correct read (a
// tail-seek optimization is a later concern the boot-cost note documents).
func lastNonEmptyLine(r io.Reader) ([]byte, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxEnvelopeLine)
	var last []byte
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		// Copy: Scanner reuses its buffer on the next Scan, so the retained line must
		// own its bytes.
		last = append(last[:0], b...)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if last == nil {
		return nil, nil
	}
	out := make([]byte, len(last))
	copy(out, last)
	return out, nil
}

// maxEnvelopeLine bounds a single audit line the scanner will read. An OCSF event
// envelope is small (a fixed-shape event plus fixed chain metadata); 1 MiB is far
// above any real envelope and guards a corrupt file with no newline from an unbounded
// read.
const maxEnvelopeLine = 1024 * 1024
