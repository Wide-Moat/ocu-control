// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handoff_test

import (
	"context"
	"testing"
)

// TestStageGuestTargetPathsPinned is the re-drift guard for the per-artifact bind
// TARGETS. Each handoff bind is "host-source:guest-target": the guest-target is the
// in-guest mountpoint the guest actually reads from, and it must match the guest
// image's own hardcoded expectations exactly. Two values are load-bearing and a
// silent drift in either one re-opens the original break:
//
//   - container_info.json reads from the filesystem ROOT default, "/container_info.json".
//     The earlier value "/etc/ocu/container_info.json" was the BUG: the guest never
//     read it, fell back to load-tolerant defaults, bound an empty name, and the JWT
//     'sub' check silently broke.
//   - the public key is read from "/etc/ocu/auth_public_key", the value also carried
//     on the guest's --auth-public-key argv; a drift here makes the guest verify
//     signatures against a key it cannot find (fail-closed boot) or, worse, none.
//
// The guard pins both via the REAL Stager output, so a future edit to the guest-path
// constants fails this test instead of shipping a guest that reads the wrong path.
func TestStageGuestTargetPathsPinned(t *testing.T) {
	t.Parallel()

	s := newStager(t)
	pub := freshPubKey(t)

	st, err := s.Stage(context.Background(), "sess-guest-target", pub, nil)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	const (
		wantContainerInfoGuest = "/container_info.json"
		wantPublicKeyGuest     = "/etc/ocu/auth_public_key"
	)
	if got := st.Material.ContainerInfoGuestPath; got != wantContainerInfoGuest {
		t.Errorf("ContainerInfoGuestPath = %q, want %q (the guest's root default-read path; "+
			"a drift to /etc/ocu/... silently breaks the JWT 'sub' bind)", got, wantContainerInfoGuest)
	}
	if got := st.Material.PublicKeyGuestPath; got != wantPublicKeyGuest {
		t.Errorf("PublicKeyGuestPath = %q, want %q (the fleet-canon key path, also the "+
			"--auth-public-key argv value)", got, wantPublicKeyGuest)
	}
}
