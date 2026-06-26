// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// validSpec builds a SessionSpec that passes validateSpec, for the happy-path and
// field-assertion tests. Callers mutate one field to drive a negative case.
func validSpec() runtime.SessionSpec {
	pub := make([]byte, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	pids := int64(128)
	return runtime.SessionSpec{
		SchemaVersion: runtime.SchemaV1Alpha,
		Name:          "sess-a",
		Owner:         runtime.Identity{Tenant: "t-1", Caller: "c-1"},
		Image:         "ocu/sandbox:v1",
		Egress: runtime.EgressPolicy{
			DefaultDeny:     true,
			AllowedUpstream: "objectstore.internal",
			FilesystemID:    "fs-1",
		},
		Resources: runtime.ResourceCaps{
			CPUCores:    2,
			MemoryBytes: 512 << 20,
			PidsLimit:   &pids,
		},
		Handoff: runtime.HandoffMaterial{
			ContainerInfoJSON:      []byte(`{"k":"v"}`),
			ContainerInfoHostPath:  "/var/run/ocu/sess-a/container_info.json",
			ContainerInfoGuestPath: "/container_info.json",
			PublicKeyEd25519:       pub,
			PublicKeyHostPath:      "/var/run/ocu/sess-a/auth_public_key",
			PublicKeyGuestPath:     "/etc/ocu/auth_public_key",
			HostSockDir:            "/var/run/ocu/sess-a/sock",
		},
	}
}

// TestBuildHostConfig_HOST01 asserts EVERY HOST-01 hardening field on the produced
// *container.HostConfig — the verbatim hardening surface (requirement 5). It builds
// under TierRunc; the gVisor case is the same surface plus the Runtime string, which
// TestBuildHostConfig_RuntimeByTier and TestBuildHostConfig_HardeningIdenticalAcrossTiers
// cover.
func TestBuildHostConfig_HOST01(t *testing.T) {
	spec := validSpec()
	hc, err := buildHostConfig(spec, runtime.TierRunc)
	if err != nil {
		t.Fatalf("buildHostConfig: unexpected error %v", err)
	}

	// Under TierRunc the Runtime string is empty — the daemon default (runc). The
	// gVisor arm is asserted separately; here we pin that runc adds NOTHING.
	if hc.Runtime != "" {
		t.Errorf("Runtime under TierRunc: want empty (daemon default), got %q", hc.Runtime)
	}

	// CapDrop == ["ALL"].
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop: want [ALL], got %v", hc.CapDrop)
	}

	// SecurityOpt contains exactly no-new-privileges:true AND a non-empty seccomp=
	// entry whose value EQUALS json.Compact of the embedded default.json.
	var sawNNP bool
	var seccompVal string
	for _, opt := range hc.SecurityOpt {
		switch {
		case opt == "no-new-privileges:true":
			sawNNP = true
		case strings.HasPrefix(opt, "seccomp="):
			seccompVal = strings.TrimPrefix(opt, "seccomp=")
		default:
			t.Errorf("SecurityOpt: unexpected entry %q", opt)
		}
	}
	if !sawNNP {
		t.Errorf("SecurityOpt: missing no-new-privileges:true, got %v", hc.SecurityOpt)
	}
	if seccompVal == "" {
		t.Fatalf("SecurityOpt: missing/empty seccomp= entry, got %v", hc.SecurityOpt)
	}
	if seccompVal == "{}" {
		t.Fatalf("SecurityOpt: seccomp= is the empty/daemon-default profile, must be the explicit deny-default")
	}
	if !json.Valid([]byte(seccompVal)) {
		t.Fatalf("SecurityOpt: seccomp= value is not valid JSON: %q", seccompVal)
	}
	var want bytes.Buffer
	if err := json.Compact(&want, defaultSeccomp); err != nil {
		t.Fatalf("compact embed: %v", err)
	}
	if seccompVal != want.String() {
		t.Errorf("seccomp= value != json.Compact(default.json):\n got %q\nwant %q", seccompVal, want.String())
	}

	// ReadonlyRootfs == true.
	if !hc.ReadonlyRootfs {
		t.Errorf("ReadonlyRootfs: want true")
	}

	// Tmpfs["/tmp"] is the bounded noexec/nosuid/nodev 64m mount.
	if got := hc.Tmpfs["/tmp"]; got != "rw,noexec,nosuid,nodev,size=64m" {
		t.Errorf("Tmpfs[/tmp]: want rw,noexec,nosuid,nodev,size=64m, got %q", got)
	}

	// Exactly THREE binds, each "host-source:guest-target[:ro]": the SOURCE is the
	// per-session host path the Stager wrote, the TARGET is the in-guest mountpoint.
	// The info target is the guest's root default-read path; the key target is the
	// fleet-canon /etc/ocu path; the sock dir is RW at /run/ocu (no :ro).
	wantBinds := []string{
		"/var/run/ocu/sess-a/container_info.json:/container_info.json:ro",
		"/var/run/ocu/sess-a/auth_public_key:/etc/ocu/auth_public_key:ro",
		"/var/run/ocu/sess-a/sock:/run/ocu",
	}
	if len(hc.Binds) != 3 {
		t.Fatalf("Binds: want 3, got %d (%v)", len(hc.Binds), hc.Binds)
	}
	for i, w := range wantBinds {
		if hc.Binds[i] != w {
			t.Errorf("Binds[%d]: want %q, got %q", i, w, hc.Binds[i])
		}
	}
	// The sock dir bind is RW: no :ro suffix.
	if strings.HasSuffix(hc.Binds[2], ":ro") {
		t.Errorf("Binds[2] (sock dir) must be RW, got %q", hc.Binds[2])
	}

	// NetworkMode == the per-session bridge name.
	if string(hc.NetworkMode) != networkName(spec.Name) {
		t.Errorf("NetworkMode: want %q, got %q", networkName(spec.Name), hc.NetworkMode)
	}

	// Resources: NanoCPUs is the HARD cap, CPUShares is 0 (never a relative weight).
	if hc.Resources.NanoCPUs != int64(spec.Resources.CPUCores*1e9) {
		t.Errorf("NanoCPUs: want %d, got %d", int64(spec.Resources.CPUCores*1e9), hc.Resources.NanoCPUs)
	}
	if hc.Resources.CPUShares != 0 {
		t.Errorf("CPUShares: want 0 (hard cap, never shares), got %d", hc.Resources.CPUShares)
	}
	if hc.Resources.Memory != spec.Resources.MemoryBytes {
		t.Errorf("Memory: want %d, got %d", spec.Resources.MemoryBytes, hc.Resources.Memory)
	}
	if hc.Resources.PidsLimit == nil || *hc.Resources.PidsLimit != *spec.Resources.PidsLimit {
		t.Errorf("PidsLimit: want %v, got %v", spec.Resources.PidsLimit, hc.Resources.PidsLimit)
	}

	// No PortBindings on any production path.
	if len(hc.PortBindings) != 0 {
		t.Errorf("PortBindings: want empty, got %v", hc.PortBindings)
	}
}

// TestDockerRuntimeForTier asserts the pure tier→runtime-string mapper: TierGvisor
// asks dockerd for the gVisor sentry ("runsc"), TierRunc uses the daemon default
// (""), and TierFirecracker falls into the safe empty default (it never reaches
// this code because Materialize aborts before buildHostConfig, but the mapper is
// total and must not panic for it). This is the unit that makes the policy↔OCI gap
// observable independent of the HostConfig wiring.
func TestDockerRuntimeForTier(t *testing.T) {
	cases := []struct {
		name string
		tier runtime.RuntimeTier
		want string
	}{
		{"gvisor asks for the runsc sentry", runtime.TierGvisor, "runsc"},
		{"runc uses the daemon default (empty)", runtime.TierRunc, ""},
		{"firecracker falls into the safe empty default", runtime.TierFirecracker, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dockerRuntimeForTier(c.tier); got != c.want {
				t.Errorf("dockerRuntimeForTier(%v): want %q, got %q", c.tier, c.want, got)
			}
		})
	}
}

// TestBuildHostConfig_RuntimeByTier is the NON-VACUOUS key test: it asserts the
// REAL buildHostConfig path stamps HostConfig.Runtime per tier — "runsc" for
// TierGvisor, "" for TierRunc. Before the fix the field was never set, so the
// gVisor case was empty (the daemon default, bare runc) even though admission
// admitted the workload expecting the sentry: this assertion is RED on that tree
// and GREEN with the fix, which is the proof the gap was real.
func TestBuildHostConfig_RuntimeByTier(t *testing.T) {
	gv, err := buildHostConfig(validSpec(), runtime.TierGvisor)
	if err != nil {
		t.Fatalf("buildHostConfig(TierGvisor): unexpected error %v", err)
	}
	if gv.Runtime != "runsc" {
		t.Errorf("TierGvisor HostConfig.Runtime: want %q (the gVisor sentry), got %q — "+
			"the gVisor admission decision is NOT enforced at the OCI layer", "runsc", gv.Runtime)
	}

	rc, err := buildHostConfig(validSpec(), runtime.TierRunc)
	if err != nil {
		t.Fatalf("buildHostConfig(TierRunc): unexpected error %v", err)
	}
	if rc.Runtime != "" {
		t.Errorf("TierRunc HostConfig.Runtime: want empty (daemon default), got %q", rc.Runtime)
	}
}

// TestBuildHostConfig_HardeningIdenticalAcrossTiers proves the tier adds ONLY the
// Runtime string: a gVisor HostConfig is byte-identical to the runc one in EVERY
// other hardening field (CapDrop, SecurityOpt incl. seccomp=, ReadonlyRootfs,
// Tmpfs, the three Binds, NetworkMode, NanoCPUs/Memory/PidsLimit, no PortBindings),
// so gVisor runs the SAME hardened HostConfig — the fix changes the OCI runtime,
// not the hardening posture.
func TestBuildHostConfig_HardeningIdenticalAcrossTiers(t *testing.T) {
	rc, err := buildHostConfig(validSpec(), runtime.TierRunc)
	if err != nil {
		t.Fatalf("buildHostConfig(TierRunc): %v", err)
	}
	gv, err := buildHostConfig(validSpec(), runtime.TierGvisor)
	if err != nil {
		t.Fatalf("buildHostConfig(TierGvisor): %v", err)
	}

	// The ONLY field that may differ is Runtime; normalize it and require the rest
	// to be deeply equal. (Comparing the whole struct after zeroing Runtime catches
	// any future field that silently diverges across tiers.)
	rc.Runtime = ""
	gv.Runtime = ""
	if !reflect.DeepEqual(rc, gv) {
		t.Errorf("HostConfig differs across tiers in a field OTHER than Runtime:\n runc:   %+v\n gvisor: %+v", rc, gv)
	}
}

// TestBuildContainerConfig_EnvEmpty asserts Env is empty (no secret rides Env) and
// the reconciler labels are stamped.
func TestBuildContainerConfig_EnvEmpty(t *testing.T) {
	spec := validSpec()
	cfg := buildContainerConfig(spec)
	if len(cfg.Env) != 0 {
		t.Errorf("Env: want empty (no secret in Env), got %v", cfg.Env)
	}
	if cfg.Image != spec.Image {
		t.Errorf("Image: want %q, got %q", spec.Image, cfg.Image)
	}
	if cfg.Labels[labelManaged] != managedLabelValue {
		t.Errorf("label %q: want %q, got %q", labelManaged, managedLabelValue, cfg.Labels[labelManaged])
	}
	if cfg.Labels[labelSessionName] != string(spec.Name) {
		t.Errorf("label %q: want %q, got %q", labelSessionName, spec.Name, cfg.Labels[labelSessionName])
	}
}

// valueAfterFlag scans an exec-form argv for flag and returns (value, true) where
// value is the IMMEDIATELY following element. It enforces the exec-form contract:
// the flag and its value are SEPARATE slice elements. A single joined element such
// as "--auth-public-key /etc/ocu/auth_public_key" never matches flag, so a regression
// that space-joins the pair into one token is caught here (there is no shell in the
// FROM-scratch guest to re-split it). Returns ("", false) when the flag is absent or
// is the last element with no value following it.
func valueAfterFlag(argv []string, flag string) (string, bool) {
	for i, tok := range argv {
		if tok == flag {
			if i+1 >= len(argv) {
				return "", false
			}
			return argv[i+1], true
		}
	}
	return "", false
}

// TestBuildContainerConfigCmd_CarriesAuthPublicKey is failure-mode (A): keyless
// fail-OPEN. The FROM-scratch guest runs in keyless dev mode when --auth-public-key
// is absent and then NEVER checks Session JWT signatures — silently disabling
// admission. Mounting the key (buildHostConfig binds it :ro) but omitting the flag
// is exactly as unauthenticated as not mounting it at all. The prod create path must
// therefore ALWAYS emit --auth-public-key, and its value must be the SAME
// spec.Handoff.PublicKeyGuestPath docker.go binds the key :ro AT (single source —
// NOT a hardcoded literal, NOT empty). This guards CONSTITUTION invariant V (the host-derived
// identity binding, NFR-SEC-43): a guest that never verifies the JWT cannot enforce
// the host-attested caller identity the Session JWT carries.
func TestBuildContainerConfigCmd_CarriesAuthPublicKey(t *testing.T) {
	spec := validSpec()
	cfg := buildContainerConfig(spec)

	val, ok := valueAfterFlag(cfg.Cmd, "--auth-public-key")
	if !ok {
		t.Fatalf("Cmd is missing --auth-public-key (keyless fail-OPEN: the guest never checks Session JWT signatures): got %v", cfg.Cmd)
	}
	if val != spec.Handoff.PublicKeyGuestPath {
		t.Errorf("--auth-public-key value: want spec.Handoff.PublicKeyGuestPath %q (single source, the same in-guest path the key is bound :ro at), got %q",
			spec.Handoff.PublicKeyGuestPath, val)
	}
	if val == "" {
		t.Errorf("--auth-public-key value is empty (keyless fail-OPEN)")
	}
	// The value must be DERIVED from the spec, not a hardcoded literal: prove it by
	// mutating PublicKeyGuestPath and re-deriving the Cmd. A literal would not move.
	spec2 := validSpec()
	spec2.Handoff.PublicKeyGuestPath = "/some/other/derived/key.pub"
	val2, ok2 := valueAfterFlag(buildContainerConfig(spec2).Cmd, "--auth-public-key")
	if !ok2 || val2 != spec2.Handoff.PublicKeyGuestPath {
		t.Errorf("--auth-public-key value is not derived from spec.Handoff.PublicKeyGuestPath: want %q, got %q (ok=%v)",
			spec2.Handoff.PublicKeyGuestPath, val2, ok2)
	}
}

// TestBuildContainerConfigCmd_CarriesListener is failure-mode (B): listener
// fail-STOP. --listen-uds / --addr / --dial-uds form a required listener ArgGroup;
// with none of them set the guest clap-exits before binding (crash loop) — which is
// today's real prod-create failure with argv=[]. The non-negotiable listener token
// is --listen-uds (NOT --control-listen-uds, which is additive for advisory
// /shutdown per ADR-0018), and its value is the in-guest exec.sock path derived from
// the same sock-dir mountpoint docker.go binds RW at /run/ocu.
func TestBuildContainerConfigCmd_CarriesListener(t *testing.T) {
	cfg := buildContainerConfig(validSpec())

	val, ok := valueAfterFlag(cfg.Cmd, "--listen-uds")
	if !ok {
		t.Fatalf("Cmd is missing --listen-uds (listener fail-STOP: the guest clap-exits before binding, crash loop): got %v", cfg.Cmd)
	}
	wantExecSock := guestSockDir + "/" + execSockName
	if val != wantExecSock {
		t.Errorf("--listen-uds value: want the in-guest exec.sock path %q, got %q", wantExecSock, val)
	}
}

// TestBuildContainerConfigCmd_ExecFormShape pins the exec-form contract and the
// forbidden-flag boundary on the prod Cmd. There is no shell in the FROM-scratch
// guest, so (1) the Cmd is a []string of SEPARATE tokens and (2) no token is a
// space-joined "flag value" element. It also asserts the Cmd carries NONE of the
// forbidden flags: --addr (opens a forbidden TCP perimeter on a UDS-only guest),
// --block-local-connections (a TCP-only no-op), and the NotImplemented flags
// --listen-vsock-port / --firecracker-init / --control-server-addr (the guest bails
// if any is set).
func TestBuildContainerConfigCmd_ExecFormShape(t *testing.T) {
	spec := validSpec()
	cfg := buildContainerConfig(spec)

	if len(cfg.Cmd) == 0 {
		t.Fatalf("Cmd is empty: the guest crash-loops (no listener) and runs keyless (no key)")
	}

	// Exec-form: every token is a distinct element; no element smuggles a flag and
	// its value joined by a space (no shell exists to split it).
	for i, tok := range cfg.Cmd {
		if strings.Contains(tok, " ") {
			t.Errorf("Cmd[%d] = %q contains a space: exec-form requires flag and value as SEPARATE elements", i, tok)
		}
	}

	// Both load-bearing flags carry a separate value element (re-checks the pair
	// shape independently of the per-mode tests above).
	for _, flag := range []string{"--auth-public-key", "--listen-uds"} {
		if _, ok := valueAfterFlag(cfg.Cmd, flag); !ok {
			t.Errorf("Cmd must carry %s followed by a SEPARATE value element, got %v", flag, cfg.Cmd)
		}
	}

	// Forbidden flags must NOT appear anywhere in the Cmd.
	forbidden := []string{
		"--addr",
		"--block-local-connections",
		"--listen-vsock-port",
		"--firecracker-init",
		"--control-server-addr",
	}
	for _, tok := range cfg.Cmd {
		for _, bad := range forbidden {
			if tok == bad {
				t.Errorf("Cmd carries forbidden flag %q (breaks the UDS-only guest perimeter / is a NotImplemented bail): %v", bad, cfg.Cmd)
			}
		}
	}
}

// TestValidateSpec_EmptyPubkeyRejectsBeforeCmd asserts the keyless-key material is
// rejected fail-closed at validateSpec BEFORE any Cmd would be emitted. validateSpec
// already forces a non-empty PublicKeyGuestPath (the "missing pubkey guest bind" row
// of TestValidateSpec_FailClosed), so this does NOT duplicate the check: it pins the
// ORDERING — a prod spec with an empty PublicKeyGuestPath never reaches buildContainerConfig,
// so the Cmd can never carry an empty --auth-public-key value derived from it.
func TestValidateSpec_EmptyPubkeyRejectsBeforeCmd(t *testing.T) {
	spec := validSpec()
	spec.Handoff.PublicKeyGuestPath = ""

	// validateSpec rejects the empty key path fail-closed (the gate Materialize runs
	// before buildContainerConfig is ever called).
	if err := validateSpec(spec); !errors.Is(err, runtime.ErrUnsupportedSpec) {
		t.Fatalf("validateSpec with empty PublicKeyGuestPath: want ErrUnsupportedSpec (before any Cmd is emitted), got %v", err)
	}

	// Materialize must reject with ZERO substrate calls — no ContainerCreate, so no
	// Cmd is ever handed to the daemon with an empty key value.
	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	if _, merr := p.Materialize(context.Background(), spec); !errors.Is(merr, runtime.ErrUnsupportedSpec) {
		t.Errorf("Materialize with empty PublicKeyGuestPath: want ErrUnsupportedSpec, got %v", merr)
	}
	if got := len(fake.ops()); got != 0 {
		t.Errorf("empty-PublicKeyGuestPath Materialize issued %d substrate calls (want 0 — no Cmd emitted): %v", got, fake.ops())
	}
}

// TestSeccomp_CompactedEqualsEmbed asserts the package-init compaction equals
// json.Compact of the embedded profile (not "{}", not the daemon default).
func TestSeccomp_CompactedEqualsEmbed(t *testing.T) {
	var want bytes.Buffer
	if err := json.Compact(&want, defaultSeccomp); err != nil {
		t.Fatalf("compact embed: %v", err)
	}
	if compactSeccomp != want.String() {
		t.Errorf("compactSeccomp != json.Compact(embed):\n got %q\nwant %q", compactSeccomp, want.String())
	}
	if compactSeccomp == "" || compactSeccomp == "{}" {
		t.Errorf("compactSeccomp is the empty/daemon-default profile: %q", compactSeccomp)
	}
}

// TestMustCompact_FailClosed asserts a malformed profile is a fail-closed panic
// naming ErrSeccompProfileMissing — no container is ever built with the daemon
// default.
func TestMustCompact_FailClosed(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("mustCompact: want panic on malformed profile, got none")
		}
		if !strings.Contains(toString(r), runtime.ErrSeccompProfileMissing.Error()) {
			t.Errorf("mustCompact panic must name ErrSeccompProfileMissing, got %v", r)
		}
	}()
	_ = mustCompact([]byte("{not json"))
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}

// TestBuildHostConfig_SeccompFailClosed asserts buildHostConfig REFUSES to
// construct a HostConfig when the compacted deny-default profile is unavailable:
// it returns ErrSeccompProfileMissing and NO HostConfig, so a container is never
// emitted with the daemon default. This is the construction-refusal complement of
// TestMustCompact_FailClosed (which covers the package-init panic on a malformed
// embed); together they prove neither path can ever reach the daemon default.
func TestBuildHostConfig_SeccompFailClosed(t *testing.T) {
	// Swap the package-init compacted profile to empty (the absent/invalid-embed
	// post-condition) and restore it. Not t.Parallel: it mutates a package var the
	// other tests read.
	saved := compactSeccomp
	compactSeccomp = ""
	t.Cleanup(func() { compactSeccomp = saved })

	hc, err := buildHostConfig(validSpec(), runtime.TierRunc)
	if !errors.Is(err, runtime.ErrSeccompProfileMissing) {
		t.Errorf("buildHostConfig with empty profile: want ErrSeccompProfileMissing, got %v", err)
	}
	if hc != nil {
		t.Errorf("buildHostConfig must return NO HostConfig on a missing profile, got %+v", hc)
	}
}

// TestMaterialize_SeccompFailClosed_ZeroCalls asserts that when the compacted
// profile is unavailable Materialize refuses with ErrSeccompProfileMissing and
// issues ZERO substrate calls — no network and no container is created without the
// explicit profile (the daemon default is never used).
func TestMaterialize_SeccompFailClosed_ZeroCalls(t *testing.T) {
	saved := compactSeccomp
	compactSeccomp = ""
	t.Cleanup(func() { compactSeccomp = saved })

	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	if _, merr := p.Materialize(context.Background(), validSpec()); !errors.Is(merr, runtime.ErrSeccompProfileMissing) {
		t.Errorf("Materialize with empty profile: want ErrSeccompProfileMissing, got %v", merr)
	}
	if got := len(fake.ops()); got != 0 {
		t.Errorf("seccomp-missing Materialize issued %d substrate calls (want 0): %v", got, fake.ops())
	}
}

// TestNetworkCreate_Internal asserts Materialize creates the per-session bridge
// with Internal:true (the deny-all posture, stronger than a plain bridge) and the
// reconciler labels — the create-side complement of the HOST-01 NetworkMode
// assertion in TestBuildHostConfig_HOST01.
func TestNetworkCreate_Internal(t *testing.T) {
	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	spec := validSpec()
	if _, merr := p.Materialize(context.Background(), spec); merr != nil {
		t.Fatalf("Materialize: %v", merr)
	}
	opt, ok := fake.netCreateOpts[networkName(spec.Name)]
	if !ok {
		t.Fatalf("NetworkCreate was not called for %q: ops=%v", networkName(spec.Name), fake.ops())
	}
	if !opt.Internal {
		t.Errorf("per-session bridge must be Internal:true (deny-all), got Internal=%v", opt.Internal)
	}
	if opt.Labels[labelManaged] != managedLabelValue {
		t.Errorf("bridge label %q: want %q, got %q", labelManaged, managedLabelValue, opt.Labels[labelManaged])
	}
	if opt.Labels[labelSessionName] != string(spec.Name) {
		t.Errorf("bridge label %q: want %q, got %q", labelSessionName, spec.Name, opt.Labels[labelSessionName])
	}
}

// TestMaterialize_GvisorRuntimeOnHostConfig proves the WIRING end to end (p.tier →
// buildHostConfig → ContainerCreate): a provider bound to TierGvisor hands
// ContainerCreate a HostConfig whose Runtime is "runsc", and a TierRunc provider
// hands one whose Runtime is "". It asserts on the EXACT HostConfig the provider
// would send to the daemon (captured by the fake), not on the mapper in isolation —
// so a regression that drops the wiring while keeping the mapper still fails here.
func TestMaterialize_GvisorRuntimeOnHostConfig(t *testing.T) {
	cases := []struct {
		name string
		tier runtime.RuntimeTier
		want string
	}{
		{"gvisor provider sends runsc", runtime.TierGvisor, "runsc"},
		{"runc provider sends the daemon default", runtime.TierRunc, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := newFakeAPI()
			p, err := NewDockerProvider(c.tier, Deps{API: fake})
			if err != nil {
				t.Fatalf("NewDockerProvider: %v", err)
			}
			if _, merr := p.Materialize(context.Background(), validSpec()); merr != nil {
				t.Fatalf("Materialize: %v", merr)
			}
			hc := fake.lastHostConfig
			if hc == nil {
				t.Fatalf("fake captured no HostConfig from ContainerCreate")
			}
			if hc.Runtime != c.want {
				t.Errorf("HostConfig.Runtime sent to ContainerCreate: want %q, got %q", c.want, hc.Runtime)
			}
		})
	}
}

// TestAdmissionGvisorCellsAgreeWithOCIRuntime is the regression guard for the gap:
// for EVERY (profile, tier) pairing admission ADMITS at TierGvisor, the Docker
// provider's tier→runtime mapper must yield "runsc". This binds the policy decision
// (admission admits the workload expecting the gVisor sentry) to the OCI reality
// (dockerd is asked for runsc), so there is no path where admission admits a gVisor
// workload but the container is created on bare runc. The admission import is
// test-only — production docker never imports admission, keeping the RuntimeProvider
// seam decoupled from the admission package.
func TestAdmissionGvisorCellsAgreeWithOCIRuntime(t *testing.T) {
	profiles := []admission.WorkloadProfile{
		admission.ProfileTrustedOperator,
		admission.ProfileInternalWorkforce,
		admission.ProfileUntrusted,
	}
	tiers := []runtime.RuntimeTier{runtime.TierRunc, runtime.TierGvisor, runtime.TierFirecracker}

	sawAdmittedGvisor := false
	for _, prof := range profiles {
		for _, tier := range tiers {
			if !admission.Decide(prof, tier).Admitted {
				continue
			}
			if tier != runtime.TierGvisor {
				continue
			}
			sawAdmittedGvisor = true
			if rt := dockerRuntimeForTier(tier); rt != "runsc" {
				t.Errorf("admission admits (%s, gvisor) but the OCI runtime would be %q, not \"runsc\": "+
					"the gVisor isolation decision would not be enforced", prof, rt)
			}
		}
	}
	// Guard the guard: if no gVisor cell is admitted the loop above is vacuous, which
	// would silently disable the regression check.
	if !sawAdmittedGvisor {
		t.Fatalf("expected at least one admission-admitted TierGvisor cell; the consistency check was vacuous")
	}
}

// TestValidateSpec_FailClosed asserts every malformed-spec case rejects with
// ErrUnsupportedSpec and that Materialize issues ZERO substrate calls on each.
func TestValidateSpec_FailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *runtime.SessionSpec)
	}{
		{"unknown schema version", func(s *runtime.SessionSpec) { s.SchemaVersion = "v0bogus" }},
		{"empty schema version", func(s *runtime.SessionSpec) { s.SchemaVersion = "" }},
		{"non-32-byte key (short)", func(s *runtime.SessionSpec) { s.Handoff.PublicKeyEd25519 = make([]byte, 31) }},
		{"non-32-byte key (long)", func(s *runtime.SessionSpec) { s.Handoff.PublicKeyEd25519 = make([]byte, 33) }},
		{"nil key", func(s *runtime.SessionSpec) { s.Handoff.PublicKeyEd25519 = nil }},
		{"permissive egress (DefaultDeny false)", func(s *runtime.SessionSpec) { s.Egress.DefaultDeny = false }},
		{"missing container_info host source", func(s *runtime.SessionSpec) { s.Handoff.ContainerInfoHostPath = "" }},
		{"missing container_info guest target", func(s *runtime.SessionSpec) { s.Handoff.ContainerInfoGuestPath = "" }},
		{"missing pubkey host source", func(s *runtime.SessionSpec) { s.Handoff.PublicKeyHostPath = "" }},
		{"missing pubkey guest target", func(s *runtime.SessionSpec) { s.Handoff.PublicKeyGuestPath = "" }},
		{"missing sock dir bind", func(s *runtime.SessionSpec) { s.Handoff.HostSockDir = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := validSpec()
			c.mutate(&spec)

			// Direct validateSpec call.
			if err := validateSpec(spec); !errors.Is(err, runtime.ErrUnsupportedSpec) {
				t.Errorf("validateSpec: want ErrUnsupportedSpec, got %v", err)
			}

			// Materialize must reject with ZERO substrate calls.
			fake := newFakeAPI()
			p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
			if err != nil {
				t.Fatalf("NewDockerProvider: %v", err)
			}
			if _, merr := p.Materialize(context.Background(), spec); !errors.Is(merr, runtime.ErrUnsupportedSpec) {
				t.Errorf("Materialize: want ErrUnsupportedSpec, got %v", merr)
			}
			if got := len(fake.ops()); got != 0 {
				t.Errorf("Materialize on malformed spec issued %d substrate calls (want 0): %v", got, fake.ops())
			}
		})
	}
}

// TestMaterialize_TierFirecracker_ZeroCalls asserts a Docker provider bound to
// TierFirecracker aborts Materialize with ErrNotImplemented and issues ZERO
// substrate calls (no insecure fallback to a weaker tier).
func TestMaterialize_TierFirecracker_ZeroCalls(t *testing.T) {
	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierFirecracker, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	_, merr := p.Materialize(context.Background(), validSpec())
	if !errors.Is(merr, runtime.ErrNotImplemented) {
		t.Errorf("Materialize(TierFirecracker): want ErrNotImplemented, got %v", merr)
	}
	if got := len(fake.ops()); got != 0 {
		t.Errorf("TierFirecracker abort issued %d substrate calls (want 0): %v", got, fake.ops())
	}
}

// TestMaterialize_HappyPath asserts the create sequence and the returned Sandbox
// handle on success.
func TestMaterialize_HappyPath(t *testing.T) {
	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	spec := validSpec()
	sb, merr := p.Materialize(context.Background(), spec)
	if merr != nil {
		t.Fatalf("Materialize: unexpected error %v", merr)
	}
	wantSeq := []string{"NetworkCreate", "ContainerCreate", "ContainerStart"}
	if got := fake.ops(); !equalSeq(got, wantSeq) {
		t.Errorf("create sequence: want %v, got %v", wantSeq, got)
	}
	if sb.Name != spec.Name {
		t.Errorf("Sandbox.Name: want %q, got %q", spec.Name, sb.Name)
	}
	if sb.RuntimeID != fake.nextID {
		t.Errorf("Sandbox.RuntimeID: want %q, got %q", fake.nextID, sb.RuntimeID)
	}
	if sb.Egress.FilesystemID != spec.Egress.FilesystemID {
		t.Errorf("Sandbox.Egress.FilesystemID: want %q, got %q", spec.Egress.FilesystemID, sb.Egress.FilesystemID)
	}
	if sb.Tier != runtime.TierRunc {
		t.Errorf("Sandbox.Tier: want TierRunc, got %v", sb.Tier)
	}
	if fake.holdsAnyFor(networkName(spec.Name), fake.nextID) != true {
		t.Errorf("happy path: substrate should hold both network and container")
	}
}

// TestForceKill_IdempotentNotFound asserts a ContainerRemove that returns a
// not-found is treated as a SATISFIED kill (ForceKill returns nil) AND that
// NetworkRemove still runs after it; a second ForceKill is also clean.
func TestForceKill_IdempotentNotFound(t *testing.T) {
	fake := newFakeAPI()
	fake.errOn["ContainerRemove"] = newNotFound("no such container")
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sb := runtime.Sandbox{Name: "sess-a", RuntimeID: "ctr-x", Egress: runtime.EgressBinding{Name: "sess-a", FilesystemID: "fs-1"}}

	if ferr := p.Teardown().ForceKill(context.Background(), sb); ferr != nil {
		t.Errorf("ForceKill on not-found container: want nil, got %v", ferr)
	}
	// NetworkRemove must still have run after the (satisfied) force-remove.
	ri := fake.indexOf("ContainerRemove")
	ni := fake.indexOf("NetworkRemove")
	if ri < 0 || ni < 0 {
		t.Fatalf("expected both ContainerRemove and NetworkRemove, got %v", fake.ops())
	}
	if ni < ri {
		t.Errorf("NetworkRemove must follow ContainerRemove, got %v", fake.ops())
	}

	// A second ForceKill is also clean (idempotent re-run).
	if ferr := p.Teardown().ForceKill(context.Background(), sb); ferr != nil {
		t.Errorf("second ForceKill: want nil, got %v", ferr)
	}
}

// TestReconcile_ReDerivesSandbox asserts the reconciler lists by the ocu-session
// label and re-derives a finalizer-drivable Sandbox from the labels + names.
func TestReconcile_ReDerivesSandbox(t *testing.T) {
	fake := newFakeAPI()
	fake.listResult = []container.Summary{
		{
			ID: "ctr-1",
			Labels: map[string]string{
				labelManaged:      managedLabelValue,
				labelSessionName:  "sess-x",
				labelFilesystemID: "fs-x",
			},
		},
		{
			// A managed container with no session-name label is skipped (cannot be
			// re-derived to a finalizer-drivable Sandbox).
			ID:     "ctr-2",
			Labels: map[string]string{labelManaged: managedLabelValue},
		},
	}
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sbs, rerr := p.Reconcile(context.Background())
	if rerr != nil {
		t.Fatalf("Reconcile: %v", rerr)
	}
	if len(sbs) != 1 {
		t.Fatalf("Reconcile: want 1 re-derived sandbox, got %d (%v)", len(sbs), sbs)
	}
	// The re-derived Egress.FilesystemID is the host-derived session key (==
	// labelSessionName == row.Key), the revoke-record key the create-path mint
	// recorded the jti under — NOT the filesystem_id label, which seeds the egress
	// scope. See TestReconcileDerivesRevokeKeyFromSessionName for the
	// distinct-label regression guard on this binding.
	if sbs[0].Name != "sess-x" || sbs[0].RuntimeID != "ctr-1" || sbs[0].Egress.FilesystemID != "sess-x" {
		t.Errorf("re-derived sandbox mismatch: %+v", sbs[0])
	}
}

// equalSeq is a small ordered-slice equality for op-sequence assertions.
func equalSeq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
