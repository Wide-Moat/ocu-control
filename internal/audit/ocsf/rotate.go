// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Hot-to-cold segment rotation (NFR-COMP-01's two-tier split).
//
// Component-07 owns the tier boundary; WHERE a sealed segment ultimately lands
// is a customer seam (ADR-0009 gives the solo reference as a plain directory and
// the full shelf as the customer's S3 Object Lock / Ceph RGW). So rotation seals
// a segment into a destination directory and stops. It knows nothing about
// object locks, uploads, or a bus.
//
// Rotation is not deletion. A segment rotates while it is deep inside the
// retention floor — that is what a hot tier is for — and the only removal here
// is of the hot COPY, after the cold copy is durable.
//
// It is load-bearing for the daemon as well as for compliance: boot-time
// validation reads the whole hot file, which is acceptable only while rotation
// bounds it.

// ErrNothingToRotate refuses to seal an empty hot file. An empty segment
// validates trivially and yields a head over no events, so a scheduler that ran
// twice would file a witness of nothing.
var ErrNothingToRotate = errors.New("ocsf: hot file holds no events to rotate")

// ErrSegmentExists refuses a rotation whose target name is occupied by a file
// this run did not write. Deleting it to make room would destroy retained
// history to resolve a name collision.
var ErrSegmentExists = errors.New("ocsf: a foreign file occupies the segment path")

// RotateSegment seals the hot file at path into a segment under coldDir and
// leaves path empty and resumable. It returns the sealed segment's path.
//
// The ordering is the crash-safety property: the cold copy is written and
// fsynced BEFORE the hot file is truncated. A crash between the two leaves a
// sealed segment and an untruncated hot file — a duplicate, which is
// recoverable — rather than neither, which loses the window permanently while
// both surviving files still validate.
func RotateSegment(path, coldDir string) (string, error) {
	envs, err := ReadChainFile(path)
	if err != nil {
		return "", fmt.Errorf("read hot file %q: %w", path, err)
	}
	if len(envs) == 0 {
		return "", ErrNothingToRotate
	}

	// Validate before sealing. A broken chain sealed into the cold tier becomes
	// the archived record of truth, and the tamper is then indistinguishable
	// from history.
	if err := ValidateChain(envs); err != nil {
		return "", fmt.Errorf("hot file %q: %w", path, err)
	}

	if err := os.MkdirAll(coldDir, 0o700); err != nil {
		return "", fmt.Errorf("prepare cold dir %q: %w", coldDir, err)
	}

	// The segment is named for the sequence range it covers, so its extent is
	// readable without opening it and two rotations cannot collide.
	first, last := envs[0].Sequence, envs[len(envs)-1].Sequence
	sealed := filepath.Join(coldDir,
		fmt.Sprintf("%s.%020d-%020d.jsonl", envs[0].Source, first, last))

	// A file already at this name is the debris of an interrupted run: the
	// sealing is create-then-truncate, so a crash between the two leaves a
	// segment and an untruncated hot file. Refusing here would turn one crash
	// into a permanent outage, because the retry recomputes the same name and
	// the boot path that calls this fails closed.
	//
	// The two crash windows are distinguishable and resolve oppositely. A
	// COMPLETE segment means the previous run sealed successfully and only the
	// truncate is missing: finish it. A partial or invalid one is a crash during
	// the copy: replace it, which is safe precisely because the hot file still
	// holds every event.
	switch resumable, err := inspectExistingSegment(sealed, envs); {
	case err != nil:
		return "", err
	case resumable:
		// Already sealed and verified by the interrupted run. Re-apply the two
		// steps that follow it; both are idempotent.
		if err := os.Chmod(sealed, 0o400); err != nil {
			return "", fmt.Errorf("seal segment %q read-only: %w", sealed, err)
		}
		if err := os.Truncate(path, 0); err != nil {
			return "", fmt.Errorf("truncate hot file %q: %w", path, err)
		}
		return sealed, nil
	}

	if err := copyAndSync(path, sealed); err != nil {
		return "", err
	}

	// From here on the cold copy exists. Any failure must remove it: a partial or
	// unverified file left in the archive is named for a legitimate sequence
	// range, so an operator inventorying the cold tier reads it as retained
	// history and the next rotation of that range collides with it.
	discard := func(cause error) (string, error) {
		_ = os.Remove(sealed)
		return "", cause
	}

	// Read the cold copy back before touching the hot file. A short write, a
	// full disk, or a silent truncation would otherwise be discovered only after
	// the source was gone.
	coldEnvs, err := ReadChainFile(sealed)
	if err != nil {
		return discard(fmt.Errorf("verify sealed segment %q: %w", sealed, err))
	}
	if len(coldEnvs) != len(envs) {
		return discard(fmt.Errorf("sealed segment %q holds %d events, the hot file held %d",
			sealed, len(coldEnvs), len(envs)))
	}
	if err := ValidateChain(coldEnvs); err != nil {
		return discard(fmt.Errorf("sealed segment %q: %w", sealed, err))
	}

	// A finished segment is read-only: an append after sealing is covered by no
	// head, since the head was computed over what was sealed.
	if err := os.Chmod(sealed, 0o400); err != nil {
		return discard(fmt.Errorf("seal segment %q read-only: %w", sealed, err))
	}

	// Only now is the hot copy safe to drop.
	if err := os.Truncate(path, 0); err != nil {
		return "", fmt.Errorf("truncate hot file %q: %w", path, err)
	}
	return sealed, nil
}

// inspectExistingSegment classifies a file already sitting at the segment path.
//
// resumable=true means that file IS this rotation's own output: a valid chain
// carrying exactly the envelopes about to be sealed. The interrupted run got as
// far as a durable, verified copy, so the retry finishes rather than repeats it.
//
// Anything else is refused, not deleted. An unrecognised file under the archive
// path may be another run's output, a restored backup, or an operator's copy;
// removing it to make room would destroy retained history to resolve a name
// collision. The one exception is a PREFIX of what we are about to write — a
// crash partway through this same copy, which is provably ours and provably
// incomplete.
//
// A missing file is the ordinary case: resumable=false, no error.
func inspectExistingSegment(sealed string, envs []ChainEnvelope) (bool, error) {
	if _, err := os.Stat(sealed); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat existing segment %q: %w", sealed, err)
	}

	existing, err := ReadChainFile(sealed)
	if err != nil {
		// Not a chain at all. It is not ours to interpret, let alone remove.
		return false, fmt.Errorf("%w: a file at %q is not a readable chain: %w",
			ErrSegmentExists, sealed, err)
	}

	// Our own partial copy: a strict prefix of the envelopes we are sealing,
	// matching hash for hash. Only this is safe to replace, and only because the
	// hot file still holds every event.
	if len(existing) < len(envs) && envelopePrefix(existing, envs) {
		_ = os.Chmod(sealed, 0o600)
		if err := os.Remove(sealed); err != nil {
			return false, fmt.Errorf("remove partial segment %q: %w", sealed, err)
		}
		return false, nil
	}

	if len(existing) != len(envs) || !envelopePrefix(existing, envs) {
		return false, fmt.Errorf("%w: %q holds %d event(s) that are not the %d being "+
			"sealed; refusing to replace archived history to resolve a name collision",
			ErrSegmentExists, sealed, len(existing), len(envs))
	}
	if err := ValidateChain(existing); err != nil {
		return false, fmt.Errorf("%w: %q does not validate: %w", ErrSegmentExists, sealed, err)
	}
	return true, nil
}

// envelopePrefix reports whether got is a hash-for-hash prefix of want.
func envelopePrefix(got, want []ChainEnvelope) bool {
	if len(got) > len(want) {
		return false
	}
	for i := range got {
		if got[i].Hash != want[i].Hash {
			return false
		}
	}
	return true
}

// copyAndSync writes src to dst and fsyncs both the file and its directory, so
// the segment survives a crash before the hot file is truncated.
func copyAndSync(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open hot file %q: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create sealed segment %q: %w", dst, err)
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("write sealed segment %q: %w", dst, err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("sync sealed segment %q: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close sealed segment %q: %w", dst, err)
	}

	// The file's own fsync does not guarantee its directory entry is durable.
	dir, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return fmt.Errorf("open cold dir for sync: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync cold dir: %w", err)
	}
	return nil
}

// ResumeTipAfterRotation returns the tip a sink must resume from once the hot
// file has been rotated.
//
// The hot file is empty after rotation, so reading its own tip would report a
// legitimate genesis and the next event would restart the chain. The tip comes
// from the sealed segment instead, which is what keeps the seam unbroken.
//
// When the hot file is NOT empty — a crash after sealing but before truncation,
// or a call at the wrong moment — its own tip wins: it is the later state, and
// resuming from the segment would reuse sequence numbers the hot file already
// committed.
func ResumeTipAfterRotation(hotPath, sealedPath string) (Tip, error) {
	hotTip, err := ReadTip(hotPath)
	if err != nil {
		return Tip{}, err
	}
	if !hotTip.Fresh {
		return hotTip, nil
	}

	sealedTip, err := ReadTip(sealedPath)
	if err != nil {
		return Tip{}, err
	}
	if sealedTip.Fresh {
		return Tip{}, fmt.Errorf("%w: sealed segment %q holds no events to resume from",
			ErrNothingToRotate, sealedPath)
	}
	return sealedTip, nil
}
