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
