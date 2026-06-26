// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handoff_test

import (
	"context"
	"os"
	"testing"
)

// TestStageBindSourcesExistOnHost is the anti-fake-green guard for the
// control->guest handoff. The Docker provider's buildHostConfig consumes three
// fields of the staged HandoffMaterial as the SOURCE side of its bind mounts
// (docker.go binds: ContainerInfoHostPath, PublicKeyHostPath, HostSockDir). A
// bind source must be a real path on the HOST filesystem — the daemon mounts the
// host path the source names into the container. If the source does not exist,
// Docker silently auto-creates it as an empty directory, so the guest receives
// an empty key (fail-closed boot crash) and an empty container_info (silent JWT
// 'sub' break). A test that only asserts the bind STRING shape cannot catch
// this, because the string is well-formed over a source path that is never
// staged.
//
// This guard runs the REAL Stager and os.Stats each bind SOURCE the resulting
// material yields. The staged tree lives under the Stager's base (a t.TempDir),
// so a host-source path resolves under that base and exists; a guest-path
// source (/etc/ocu/...) does NOT exist under the base and the Stat fails.
func TestStageBindSourcesExistOnHost(t *testing.T) {
	t.Parallel()

	// Run the real Stager exactly as the create path does: a per-session root
	// under a fresh host-owned base, a valid 32-byte key, no mounts this phase.
	s := newStager(t)
	pub := freshPubKey(t)

	st, err := s.Stage(context.Background(), "sess-bind-source", pub, nil)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	// Derive the THREE bind SOURCE paths exactly as docker.go's buildHostConfig
	// reads them off the material: the host-source fields. These are the
	// left-hand side of each bind ("source:target[:ro]") — the host path the
	// daemon mounts in.
	bindSources := []struct {
		field  string
		source string
	}{
		{"container_info.json", st.Material.ContainerInfoHostPath},
		{"auth_public_key", st.Material.PublicKeyHostPath},
		{"sock dir", st.Material.HostSockDir},
	}

	for _, bs := range bindSources {
		// The assertion is host-source FILE EXISTENCE, not bind-string shape: the
		// daemon can only mount a path that exists on the host. A source the Stager
		// never wrote (the guest mountpoint /etc/ocu/...) fails this Stat even
		// though the bind string built from it is perfectly well-formed.
		if _, err := os.Stat(bs.source); err != nil {
			t.Errorf("bind SOURCE for %s does not exist on the host filesystem: %q: %v\n"+
				"the Docker daemon mounts this host path into the guest; a missing source is "+
				"silently auto-created as an empty dir, breaking guest boot. The Stager must "+
				"return the per-session host path it actually wrote, not the in-guest mountpoint.",
				bs.field, bs.source, err)
		}
	}
}
