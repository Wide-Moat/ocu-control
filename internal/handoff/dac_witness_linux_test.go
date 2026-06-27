// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux

package handoff_test

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// TestDACWitness_NonOwnerUidIsDeniedByMode is the runtime-posture WITNESS for the
// handoff perms fix: it proves that the on-disk mode bits actually DENY a
// non-owner uid the read and the bind under ordinary DAC (no CAP_DAC_OVERRIDE /
// CAP_DAC_READ_SEARCH), and that the chosen modes (0644 files, 0777 sock leaf)
// actually GRANT them. This is distinct from — and not substitutable for — the
// permanence mode-assertion in TestStageWritesAllArtifacts: that proves the bits
// ARE 0644/0777; THIS proves a genuine non-owner uid is denied at 0600/0700 and
// allowed at 0644/0777. "the bits are 0644" does not prove "a non-owner uid can
// read it" — only an actual EACCES-vs-OK delta from a different uid does.
//
// WHY OS-LEVEL, NOT IN-CONTAINER USERNS. A pure-Go in-process user-namespace
// witness is not achievable: a self-map plus setuid to an unmapped uid is EINVAL,
// a bare unprivileged non-self uid_map is EPERM (Go writes /proc/<pid>/uid_map
// directly and never shells out to newuidmap), and the external-newuidmap path
// leaves the child with overflow creds fixed at clone, mapping back to a vacuous
// owner==reader. The honest non-owner DAC delta is an OS-level chown-two-uids +
// seteuid, which requires root.
//
// GATE — root-required, skip-clean when non-root (NOT fail-loud). chown to a
// foreign uid and seteuid both require root; without it the witness genuinely
// cannot run, so it skips. This skip is NOT the skip-green sin: the witness IS
// run and recorded — a firsthand sudo-root run on the Lima VM is the ship
// proof-of-record (the architect's "concrete peer on a concrete machine", not a
// "guaranteed root CI lane"). The IT/Docker lanes reach Docker via the socket as
// a docker-GROUP non-root user (uid != 0), so a fail-loud-if-non-root check would
// wrongly redden every ordinary IT run — root-capability is socket-group access,
// not euid 0. The non-skip-green guarantee is therefore the recorded root run
// plus the permanence mode-assertion in TestStageWritesAllArtifacts, which runs
// everywhere non-root and reds if the bits ever regress.
func TestDACWitness_NonOwnerUidIsDeniedByMode(t *testing.T) {
	// OS-level seteuid/chown semantics are Linux's (the //go:build linux tag keeps
	// this file off Darwin entirely); the runtime check is belt-and-suspenders.
	if runtime.GOOS != "linux" {
		t.Skipf("DAC witness is Linux-only (GOOS=%s)", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("DAC witness needs root to chown a foreign uid and seteuid; run via sudo " +
			"(e.g. `sudo -E go test -run TestDACWitness ./internal/handoff/` on the Lima VM)")
	}

	// Two DISTINCT non-root uids: the files are owned by uidA, the probe runs as
	// uidB. uidB != uidA is what makes the denial a genuine non-owner test rather
	// than a vacuous owner-reads-own-file. 65530/65531 are high, unprivileged, and
	// not the root-owned-file owner.
	const uidA = 65530 // the file/dir owner
	const uidB = 65531 // the non-owner probe uid
	const gidB = 65531

	root := t.TempDir() // owned by the real test uid (root here)

	// Make the scratch parent chain TRAVERSABLE (0711) by the seteuid'd probe.
	// t.TempDir under sudo-root yields /tmp/TestX/NNN with BOTH levels 0700
	// root-owned, so uidB has no search bit to traverse INTO root — it would EACCES
	// reaching even the 0644 fixture, a RED for the wrong reason (parent traversal,
	// not the file mode) that would MASK whether the 0644 fix actually grants the
	// read. 0711 = traversable-but-not-listable: uidB can reach the fixtures, and the
	// PER-FILE mode (0600 vs 0644) is then what gates the read — exactly the delta
	// this witness must isolate. This is SCRATCH-DIR-ONLY: the production Stage root
	// stays 0700 (the trust gate; the guest reaches /run/ocu via the bind mount, not
	// via host-parent traversal, so production is unaffected). Walk up to (not
	// including) the system temp dir so every Go-created ancestor is traversable.
	for d := root; d != "" && d != os.TempDir() && d != filepath.Dir(d); d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o711); err != nil {
			t.Fatalf("chmod scratch ancestor %s to 0711: %v", d, err)
		}
	}

	// A helper that, as uidB, attempts an op against a path owned by uidA at a given
	// mode and reports whether it was permitted. seteuid is process-global, so this
	// must run with the goroutine locked to its OS thread and the euid restored
	// immediately after the single syscall.
	asUidB := func(t *testing.T, fn func() error) error {
		t.Helper()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		// Drop the supplementary groups and gid first, then the euid; restore in
		// reverse on the way out. Setegid before seteuid (once euid is non-root you
		// can no longer change gid).
		if err := syscall.Setegid(gidB); err != nil {
			t.Fatalf("setegid(%d): %v", gidB, err)
		}
		if err := syscall.Seteuid(uidB); err != nil {
			_ = syscall.Setegid(0)
			t.Fatalf("seteuid(%d): %v", uidB, err)
		}
		opErr := fn()
		// Restore root euid first (needs to happen before regid), then gid.
		if err := syscall.Seteuid(0); err != nil {
			t.Fatalf("restore seteuid(0): %v", err)
		}
		if err := syscall.Setegid(0); err != nil {
			t.Fatalf("restore setegid(0): %v", err)
		}
		return opErr
	}

	// isEACCES asserts the error is specifically EACCES (13), not any non-zero
	// error: a chown/seteuid slip can surface EPERM or ENOENT, which would be a RED
	// for the wrong reason — itself a fake-green.
	isEACCES := func(err error) bool {
		return errors.Is(err, syscall.EACCES)
	}

	// --- READ delta: a 0600 file owned by uidA is denied to uidB; a 0644 file is allowed. ---
	writeOwned := func(t *testing.T, name string, perm os.FileMode) string {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte("payload"), perm); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		// WriteFile is umask-masked; chmod lands the exact mode.
		if err := os.Chmod(p, perm); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
		if err := os.Chown(p, uidA, uidA); err != nil {
			t.Fatalf("chown %s to %d: %v", name, uidA, err)
		}
		return p
	}

	file0600 := writeOwned(t, "ro-0600", 0o600)
	file0644 := writeOwned(t, "ro-0644", 0o644)

	readAs := func(p string) error {
		return asUidB(t, func() error {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_ = f.Close()
			return nil
		})
	}

	if err := readAs(file0600); !isEACCES(err) {
		t.Fatalf("read of a 0600 uidA-owned file as uidB = %v; want EACCES (the read-side denial the 0644 fix prevents)", err)
	}
	if err := readAs(file0644); err != nil {
		t.Fatalf("read of a 0644 uidA-owned file as uidB = %v; want success (the read the guest needs)", err)
	}

	// --- BIND delta: bind(2) in a 0700 uidA-owned dir is denied to uidB; a 0777 dir is allowed. ---
	mkOwnedDir := func(t *testing.T, name string, perm os.FileMode) string {
		t.Helper()
		d := filepath.Join(root, name)
		if err := os.Mkdir(d, perm); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.Chmod(d, perm); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
		if err := os.Chown(d, uidA, uidA); err != nil {
			t.Fatalf("chown %s to %d: %v", name, uidA, err)
		}
		return d
	}

	dir0700 := mkOwnedDir(t, "sock-0700", 0o700)
	dir0777 := mkOwnedDir(t, "sock-0777", 0o777)

	bindAs := func(dir string) error {
		return asUidB(t, func() error {
			// A short UDS path inside dir; the bind needs write+exec(search) on dir.
			ln, err := net.Listen("unix", filepath.Join(dir, "s.sock"))
			if err != nil {
				return err
			}
			_ = ln.Close()
			return nil
		})
	}

	if err := bindAs(dir0700); !isEACCES(err) {
		t.Fatalf("bind(2) in a 0700 uidA-owned dir as uidB = %v; want EACCES (the bind denial the 0777 leaf fix prevents)", err)
	}
	if err := bindAs(dir0777); err != nil {
		t.Fatalf("bind(2) in a 0777 uidA-owned dir as uidB = %v; want success (the bind the guest needs)", err)
	}
}
