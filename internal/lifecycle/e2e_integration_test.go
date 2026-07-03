// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/provisioning"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/runtime/docker"
	"github.com/Wide-Moat/ocu-control/internal/state"
	"github.com/Wide-Moat/ocu-control/internal/state/postgres"
)

// TestE2E_CreateDestroy_RealBackends is the milestone capstone: the whole lifecycle
// pipeline driven against a REAL Postgres state.Store AND a REAL Docker
// RuntimeProvider together — no in-memory store, no fake provider — PLUS the
// Phase-4 mount-config push and the Phase-5 chain-linked OCSF audit, all on the
// same real backends. It proves that admission → quota → reserve → stage-handoff →
// render+push mount-config → materialize → commit → bind composes correctly across
// the real backends, that destroy tears the real container down and tombstones the
// real row, and — as the release-gating Phase-5 assertions:
//
//   - the rendered mount-config landed on the host-owned handoff bind BEFORE
//     materialize, carrying the weak Bearer (auth_token) and NO backend filestore
//     credential (the Egress trust-edge exchanges the weak JWT for the real cred
//     in-guest; Control never holds the filestore credential);
//   - a chain-linked OCSF audit event was emitted for create AND destroy under the
//     host-attested identity, the create→destroy spine validates (tamper-evident),
//     and the minted weak Storage-JWT NEVER appears in any emitted event (the
//     no-token grep over the captured envelope bytes).
//
// It gates on BOTH OCU_TEST_DATABASE_URL (a reachable Postgres) and OCU_RUNTIME_IT=1
// (a reachable Docker daemon); without either it live-skips, so the default
// `go test ./...` stays green everywhere. On a remote daemon (a VM-hosted Docker
// reached over a forwarded socket on a dev laptop) the HOST-01 bind sources are
// resolved by the daemon, so set OCU_RUNTIME_IT_STAGE_DIR to a path visible to both
// this process and the daemon (a shared mount); it defaults to t.TempDir for a
// local daemon (CI). This is the single release-gating e2e — the e2e.yml job runs
// it with no continue-on-error.
func TestE2E_CreateDestroy_RealBackends(t *testing.T) {
	dsn := os.Getenv("OCU_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("e2e: OCU_TEST_DATABASE_URL unset (a real Postgres is required) — skipping")
	}
	if os.Getenv("OCU_RUNTIME_IT") != "1" {
		t.Skip("e2e: OCU_RUNTIME_IT=1 unset (a real Docker daemon is required) — skipping")
	}
	requireGuestImage(t)

	ctx := context.Background()
	clk := state.SystemClock()

	// REAL Postgres store. The shared test database accumulates a global
	// kill-switch row across runs (the boot + conformance suites engage it), so
	// clear the global deny posture to give this create→destroy test a clean
	// slate — a stale DENY-ALL is correctly honored by the create path and would
	// otherwise refuse the reserve. This is test hygiene on a shared DB, not a
	// product concern: the kill-switch-first refusal itself is proven elsewhere.
	store, err := postgres.Open(ctx, dsn, clk)
	if err != nil {
		t.Skipf("e2e: Postgres not reachable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = closeStore(store) })
	if err := store.ClearDeny(ctx, state.ScopeGlobal, ""); err != nil {
		t.Fatalf("e2e: clear stale global kill-switch: %v", err)
	}

	// REAL Docker provider at the trusted_operator×runc admit cell.
	dockerProvider, err := docker.NewDockerProvider(runtime.TierRunc, docker.Deps{})
	if err != nil {
		t.Fatalf("e2e: NewDockerProvider: %v", err)
	}

	// A real cred.Signer over a freshly generated key mints the weak Storage-JWT; the
	// capturing Pusher lands the rendered config on the real host-owned bind so the
	// Phase-4 render+push stage actually fires (a nil Signer/Push would no-op it).
	signer, _ := newTestSigner(t, clk)
	pusher := newCapturingPusher()
	// orderingProvider wraps the real Docker provider to record, at the instant
	// Materialize is first called, that the mount-config push already happened and
	// the config is physically on the host-owned bind — proving the must-fix
	// ordering (config on the bind before the container is materialized).
	provider := &orderingProvider{inner: dockerProvider, pusher: pusher}

	// The REAL OCSF chain sink over a capturing writer: every privileged Emit
	// serializes an OCSF event, assigns a per-source monotonic sequence, links the
	// prior hash, and we capture the envelope bytes for spine validation + the
	// no-token grep. This is the Phase-5 chain exercised end-to-end (not the unit
	// RecordingFake), so what the release gate proves is the real serializer.
	auditWriter := &capturingEventWriter{}
	auditSink := ocsf.NewChainSink(clk, auditWriter, "control")

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: registry.NewCustodian(store),
		Provider:  provider,
		Clock:     clk,
		// generousLimits is shared with manager_test.go in this package.
		Quota:         quota.NewGate(store, clk, generousLimits()),
		Handoff:       handoff.NewStager(e2eStageDir(t)),
		Audit:         auditSink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		Signer:        signer,
		Push:          pusher,
		ServiceURL:    testServiceURL,
		CACertPEM:     testCACert,
		MountDefaults: testMountDefaults(t),
		StorageScope:  lifecycle.StorageScope{Workspace: "ws", Org: "org", Intent: cred.IntentWrite},
	})

	caller := ingress.AuthenticatedCaller{
		Identity: state.Identity{Tenant: "e2e-tenant", Caller: "e2e-caller"},
		Channel:  ingress.ChannelOperator,
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("e2e: generate key: %v", err)
	}

	pidsLimit := int64(128)
	in := lifecycle.CreateInput{
		Caller:      caller,
		SessionHint: "e2e-session",
		Image:       itImage(),
		Mount: runtime.MountIntent{
			Destination:  "/workspace",
			FilesystemID: "e2e-fs",
			ReadOnly:     false,
			// AuthToken is the Phase-4 weak-JWT placeholder on this path; the real
			// weak Bearer is minted by the Signer and rendered into the mount-config.
			AuthToken:    "phase4-placeholder",
			CacheSeconds: 30,
		},
		Egress: runtime.EgressPolicy{
			DefaultDeny:     true,
			AllowedUpstream: "objectstore.internal",
			FilesystemID:    "e2e-fs",
		},
		Resources: runtime.ResourceCaps{
			CPUCores:    1,
			MemoryBytes: 256 << 20,
			PidsLimit:   &pidsLimit,
		},
		ControlPubKey: pub,
	}

	// CREATE against the real backends.
	row, err := mgr.Create(ctx, in)
	if err != nil {
		t.Fatalf("e2e: Create against real Postgres+Docker: %v", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("e2e: created row state = %v, want ACTIVE", row.State)
	}
	if row.ContainerName == "" {
		t.Fatal("e2e: created row has no bound container_name (BindContainerName did not run)")
	}

	// The row is durable in REAL Postgres: a fresh lookup returns it ACTIVE.
	got, err := store.LookupSession(ctx, row.Key)
	if err != nil {
		t.Fatalf("e2e: durable lookup of the created row: %v", err)
	}
	if got.State != state.StateActive || got.ContainerName != row.ContainerName {
		t.Fatalf("e2e: durable row = {state:%v name:%q}, want {ACTIVE %q}", got.State, got.ContainerName, row.ContainerName)
	}

	// (1) The mount-config push landed on the host-owned bind BEFORE materialize.
	if !provider.pushedBeforeMat.Load() {
		t.Fatal("e2e: mount-config was NOT pushed before materialize (must-fix ordering violated)")
	}
	if !provider.configOnDiskAtMt.Load() {
		t.Fatal("e2e: rendered mount-config was not physically on the handoff bind at materialize time")
	}
	pushed, cfgBytes, _ := pusher.snapshot()
	if !pushed {
		t.Fatal("e2e: capturing pusher never observed a Push")
	}
	// The config carries the weak Bearer and NO backend filestore credential.
	assertMountConfigShape(t, cfgBytes)

	// (2) A chain-linked OCSF audit event was emitted for create; the spine validates
	// and links to the genesis-zero prior hash at sequence 1.
	createEnvs := auditWriter.snapshot()
	if len(createEnvs) == 0 {
		t.Fatal("e2e: no audit event emitted for create — the fail-closed chain did not fire")
	}
	if err := ocsf.ValidateChain(createEnvs); err != nil {
		t.Fatalf("e2e: ValidateChain over the create spine = %v, want nil", err)
	}
	assertHasAction(t, createEnvs, audit.ActionCreateCommit)

	// DESTROY: the host-driven finalizer removes the real container and the row is
	// tombstoned RELEASED. Destroy resolves the session from the same host-derived
	// caller + hint, so the body hint is a correlation seed, never the authority.
	if err := mgr.Destroy(ctx, caller, in.SessionHint); err != nil {
		t.Fatalf("e2e: Destroy against real Postgres+Docker: %v", err)
	}

	after, err := store.LookupSession(ctx, row.Key)
	if err != nil {
		t.Fatalf("e2e: post-destroy lookup: %v", err)
	}
	if after.State != state.StateReleased {
		t.Fatalf("e2e: post-destroy row state = %v, want RELEASED (tombstone)", after.State)
	}

	// A chain-linked OCSF audit event was emitted for destroy; the full spine still
	// validates — create + destroy are LINKED (destroy's prior_hash == create's
	// hash, sequence 2), tamper-evident on a real run.
	allEnvs := auditWriter.snapshot()
	if len(allEnvs) <= len(createEnvs) {
		t.Fatalf("e2e: destroy emitted no additional audit event (had %d, now %d)", len(createEnvs), len(allEnvs))
	}
	if err := ocsf.ValidateChain(allEnvs); err != nil {
		t.Fatalf("e2e: ValidateChain over the create+destroy spine = %v, want nil", err)
	}
	assertHasAction(t, allEnvs, audit.ActionDestroy)

	// (3) The create-time weak Storage-JWT NEVER appears in any emitted audit event.
	// We grep the ACTUAL rendered auth_token from the pushed mount-config (the real
	// credential that flowed at create) across every captured envelope's bytes — not
	// a fresh re-mint, which would be byte-different and vacuous.
	assertNoMintedTokenInEvents(t, cfgBytes, allEnvs)
}

// capturingEventWriter records every ChainEnvelope the OCSF chain sink writes, so the
// e2e can validate the emitted spine and grep the raw envelope bytes for a minted
// token. It is safe for concurrent use.
type capturingEventWriter struct {
	mu   sync.Mutex
	envs []ocsf.ChainEnvelope
}

func (w *capturingEventWriter) Write(_ context.Context, env ocsf.ChainEnvelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.envs = append(w.envs, env)
	return nil
}

func (w *capturingEventWriter) snapshot() []ocsf.ChainEnvelope {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]ocsf.ChainEnvelope, len(w.envs))
	copy(out, w.envs)
	return out
}

// capturingPusher wraps the real filesystem Pusher to capture the rendered
// mount-config bytes and the host-side path they landed at, and to record that the
// push HAPPENED (so the e2e can assert the config is on the bind before materialize).
type capturingPusher struct {
	inner  provisioning.Pusher
	mu     sync.Mutex
	pushed bool
	bytes  []byte
	path   string
}

func newCapturingPusher() *capturingPusher {
	return &capturingPusher{inner: provisioning.NewPusher()}
}

func (p *capturingPusher) Push(ctx context.Context, staged handoff.Staged, cfgBytes []byte) (provisioning.Pushed, error) {
	out, err := p.inner.Push(ctx, staged, cfgBytes)
	if err == nil {
		p.mu.Lock()
		p.pushed = true
		p.bytes = append([]byte(nil), cfgBytes...)
		p.path = out.Path
		p.mu.Unlock()
	}
	return out, err
}

func (p *capturingPusher) Scrub(ctx context.Context, pushed provisioning.Pushed) error {
	return p.inner.Scrub(ctx, pushed)
}

func (p *capturingPusher) snapshot() (pushed bool, cfgBytes []byte, path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pushed, append([]byte(nil), p.bytes...), p.path
}

// orderingProvider wraps the real Docker provider and records whether the push had
// already happened (observed via the shared pushed flag) at the instant Materialize
// is first called, so the e2e proves the must-fix ordering: the mount-config lands on
// the bind BEFORE the container is materialized.
type orderingProvider struct {
	inner            runtime.RuntimeProvider
	pusher           *capturingPusher
	pushedBeforeMat  atomic.Bool
	configOnDiskAtMt atomic.Bool
	materialized     atomic.Bool
}

func (p *orderingProvider) Materialize(ctx context.Context, spec runtime.SessionSpec) (runtime.Sandbox, error) {
	if !p.materialized.Swap(true) {
		// First Materialize: snapshot the push state. The config must already be pushed
		// and physically on the host-owned bind before the container is created.
		pushed, _, path := p.pusher.snapshot()
		p.pushedBeforeMat.Store(pushed)
		if path != "" {
			if _, err := os.Stat(path); err == nil {
				p.configOnDiskAtMt.Store(true)
			}
		}
	}
	return p.inner.Materialize(ctx, spec)
}

func (p *orderingProvider) Teardown() runtime.RuntimeTeardown { return p.inner.Teardown() }
func (p *orderingProvider) Reconcile(ctx context.Context) ([]runtime.Sandbox, error) {
	return p.inner.Reconcile(ctx)
}

// assertMountConfigShape parses the pushed mount-config and asserts it carries a
// non-empty auth_token (the weak Bearer) and NO backend filestore credential field —
// the config is the weak-JWT-only handoff the Egress trust-edge exchanges, never the
// real filestore credential.
func assertMountConfigShape(t *testing.T, cfgBytes []byte) {
	t.Helper()
	if len(cfgBytes) == 0 {
		t.Fatal("e2e: pushed mount-config is empty")
	}
	var generic map[string]any
	if err := json.Unmarshal(cfgBytes, &generic); err != nil {
		t.Fatalf("e2e: unmarshal pushed mount-config: %v", err)
	}
	mounts, ok := generic["mounts"].([]any)
	if !ok || len(mounts) == 0 {
		t.Fatalf("e2e: pushed mount-config has no mounts: %s", cfgBytes)
	}
	m0, ok := mounts[0].(map[string]any)
	if !ok {
		t.Fatalf("e2e: pushed mount[0] is not an object: %s", cfgBytes)
	}
	tok, _ := m0["auth_token"].(string)
	if tok == "" {
		t.Fatal("e2e: pushed mount-config carries no weak auth_token (Bearer)")
	}
	// No backend filestore credential field may appear anywhere in the config: the
	// mount runs in-guest and exchanges the weak JWT for the real credential there.
	for _, forbidden := range []string{
		"backend_credential", "filestore_credential", "secret_key",
		"access_key", "service_account_key", "password",
	} {
		if bytes.Contains(cfgBytes, []byte(forbidden)) {
			t.Fatalf("e2e: pushed mount-config carries a backend credential field %q: %s", forbidden, cfgBytes)
		}
	}
}

// assertHasAction asserts at least one captured envelope decodes to an OCSF event
// whose unmapped.action equals the wanted Action label.
func assertHasAction(t *testing.T, envs []ocsf.ChainEnvelope, want audit.Action) {
	t.Helper()
	for _, e := range envs {
		var ev struct {
			Metadata struct {
				Unmapped struct {
					Action string `json:"action"`
				} `json:"unmapped"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(e.Event, &ev); err != nil {
			t.Fatalf("e2e: unmarshal captured event: %v", err)
		}
		if ev.Metadata.Unmapped.Action == want.String() {
			return
		}
	}
	t.Fatalf("e2e: no emitted audit event for action %q", want.String())
}

// assertNoMintedTokenInEvents asserts the ACTUAL create-time weak Storage-JWT —
// the auth_token the create path minted and rendered into the pushed
// mount-config — appears in NO captured envelope's bytes. It greps the REAL
// create-time credential (extracted from the pushed config bytes), NOT a fresh
// re-mint: the signer stamps clk.Now() into iat/exp and folds it into the jti, so
// a token minted here (seconds after create, post-destroy) is byte-different from
// the create-time one — a re-mint grep can never match a real leak and is
// vacuous. Grepping the config's own auth_token closes that: if the create-time
// credential leaked into any event, this fails.
func assertNoMintedTokenInEvents(t *testing.T, cfgBytes []byte, envs []ocsf.ChainEnvelope) {
	t.Helper()
	raw := authTokenFromMountConfig(t, cfgBytes)
	if raw == "" {
		t.Fatal("e2e: the pushed mount-config carried no auth_token — the grep would be vacuous")
	}
	// The signature segment is the highest-entropy secret slice; grep both the whole
	// compact JWT and its signature segment across every captured envelope.
	sigSeg := raw
	if i := lastDot(raw); i >= 0 && i+1 < len(raw) {
		sigSeg = raw[i+1:]
	}
	for _, e := range envs {
		if bytes.Contains(e.Event, []byte(raw)) {
			t.Fatalf("e2e: the create-time weak Storage-JWT leaked into an audit event: %s", e.Event)
		}
		if len(sigSeg) > 8 && bytes.Contains(e.Event, []byte(sigSeg)) {
			t.Fatalf("e2e: the create-time weak Storage-JWT signature leaked into an audit event: %s", e.Event)
		}
	}
}

// authTokenFromMountConfig extracts the rendered weak Bearer (auth_token) from
// the pushed mount-config bytes — the ACTUAL create-time credential, so the
// no-leak grep searches for what really flowed, not a byte-different re-mint.
func authTokenFromMountConfig(t *testing.T, cfgBytes []byte) string {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal(cfgBytes, &generic); err != nil {
		t.Fatalf("e2e: unmarshal pushed mount-config for the auth_token: %v", err)
	}
	mounts, ok := generic["mounts"].([]any)
	if !ok || len(mounts) == 0 {
		t.Fatalf("e2e: pushed mount-config has no mounts to read the auth_token from: %s", cfgBytes)
	}
	m0, ok := mounts[0].(map[string]any)
	if !ok {
		t.Fatalf("e2e: pushed mount[0] is not an object: %s", cfgBytes)
	}
	tok, _ := m0["auth_token"].(string)
	return tok
}

// lastDot returns the index of the last '.' in s, or -1.
func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

// e2eStageDir mirrors the docker integration leg's daemon-visible staging: the
// HOST-01 bind sources are resolved by the daemon, so a remote daemon needs a
// shared path. Defaults to t.TempDir for a local daemon.
func e2eStageDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv("OCU_RUNTIME_IT_STAGE_DIR")
	if base == "" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp(base, "ocu-e2e-")
	if err != nil {
		t.Fatalf("e2e: stage dir under OCU_RUNTIME_IT_STAGE_DIR=%q: %v", base, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// itImage is the small image the e2e materializes; overridable for a constrained
// mirror, defaulting to the canonical small busybox the docker leg also uses.
func itImage() string {
	if v := os.Getenv("OCU_RUNTIME_IT_IMAGE"); v != "" {
		return v
	}
	return "busybox:latest"
}

// requireGuestImage gates the create→destroy capstone on a guest image whose
// ENTRYPOINT is process_api. Materialize builds the provider Cmd as ARGUMENTS to
// that ENTRYPOINT ([--listen-uds … --auth-public-key …]); the default busybox has
// no such ENTRYPOINT, so the container would exec `--listen-uds` as argv[0] and
// die on init, making the lifecycle spine vacuous. The real guest image ships
// from ocu-sandbox (with the guest-image merge, #47); until OCU_RUNTIME_IT_IMAGE
// names it, this SKIPS with an explicit reason — a declared skip, not a fake
// green. Mirrors requireGuestImage in internal/runtime/docker.
func requireGuestImage(t *testing.T) {
	t.Helper()
	img := os.Getenv("OCU_RUNTIME_IT_IMAGE")
	if img == "" || img == "busybox:latest" {
		t.Skip("e2e: set OCU_RUNTIME_IT_IMAGE to a process_api-ENTRYPOINT guest image; " +
			"the default busybox has no such ENTRYPOINT, so Materialize's flags-as-args " +
			"Cmd would die on init and the create→destroy spine would be vacuous. The real " +
			"guest image ships from ocu-sandbox (needs the guest-image merge, #47) — skipping")
	}
}

// closeStore best-effort closes a store that exposes an io.Closer-like Close.
func closeStore(s state.Store) error {
	type closer interface{ Close() error }
	if c, ok := s.(closer); ok {
		return c.Close()
	}
	return nil
}
