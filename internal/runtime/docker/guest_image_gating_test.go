// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Re-exec test: requireGuestImage must FAIL (not skip) on a broken guest image in
// the gating context. requireGuestImage calls t.Fatalf, which cannot be observed
// from the same test process (it kills the calling goroutine), so this drives it
// in a subprocess and asserts the process-level outcome — the standard idiom for
// exercising a t.Fatal path.
//
// requireGuestImage is ALWAYS reached after requireIT, which skips unless
// OCU_RUNTIME_IT=1. So by construction the env is present ("gating context") by the
// time requireGuestImage runs, and an empty or busybox OCU_RUNTIME_IT_IMAGE there is
// a broken CI build, not a dev skip. This test pins that: a busybox image in the
// gating context reds a test rather than passing as a green skip. If the guard is
// reverted to t.Skip, the helper subprocess exits 0 (a skip is a pass) and this
// test goes RED — the keystone-neuter.
package docker

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRequireGuestImageHelperSubprocess is the re-exec trampoline, not a test on
// its own: in a normal run the env guard makes it a no-op pass, and when the
// driving test below spawns the binary with GUEST_IMAGE_HELPER=1 it invokes
// requireGuestImage with the broken image the parent chose. A Fatal there fails
// this subprocess test → the subprocess exits non-zero, which the parent asserts.
func TestRequireGuestImageHelperSubprocess(t *testing.T) {
	if os.Getenv("GUEST_IMAGE_HELPER") != "1" {
		return
	}
	// The parent sets OCU_RUNTIME_IT_IMAGE to the broken value under test. In the
	// production flow requireIT (which gates on OCU_RUNTIME_IT=1) runs first; here
	// we invoke requireGuestImage directly with the same "gating context" the
	// ordering guarantees, to isolate its broken-image branch.
	requireGuestImage(t)
}

// TestRequireGuestImage_BrokenImageInGatingContextFails asserts the guard: with a
// busybox (or empty) OCU_RUNTIME_IT_IMAGE, requireGuestImage FAILS the test rather
// than skipping it. The subprocess must exit non-zero AND its output must name the
// gating-context misconfiguration, so a plain non-zero exit for an unrelated reason
// cannot masquerade as the guard firing.
func TestRequireGuestImage_BrokenImageInGatingContextFails(t *testing.T) {
	t.Parallel()
	for _, img := range []string{"busybox:latest", ""} {
		img := img
		name := img
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command(os.Args[0], "-test.run=TestRequireGuestImageHelperSubprocess$", "-test.v")
			cmd.Env = append(os.Environ(),
				"GUEST_IMAGE_HELPER=1",
				"OCU_RUNTIME_IT_IMAGE="+img,
			)
			out, err := cmd.CombinedOutput()

			if err == nil {
				t.Fatalf("requireGuestImage with a %q image in the gating context exited 0 (a skip or pass); want a FAIL (non-zero exit). A green here means a broken guest-image build would ship as a skip.\noutput:\n%s", img, out)
			}
			if !strings.Contains(string(out), "broken build/wiring in the gating job") {
				t.Errorf("subprocess failed but not via the guest-image guard (missing the gating-misconfig message); the non-zero exit may be unrelated.\noutput:\n%s", out)
			}
		})
	}
}

// TestRequireGuestImage_ValidImagePasses is the other half: a NON-broken image is
// accepted (returned), so the guard does not over-fire on a correctly-built image.
// This runs in-process (a valid image takes neither the skip nor the fatal branch).
func TestRequireGuestImage_ValidImagePasses(t *testing.T) {
	t.Setenv("OCU_RUNTIME_IT_IMAGE", "guest-exec-server:prod")
	got := requireGuestImage(t)
	if got != "guest-exec-server:prod" {
		t.Errorf("requireGuestImage with a valid image = %q, want it returned unchanged", got)
	}
}
