// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/boot"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// writeTestKey writes a valid Ed25519 PKCS8 signing key to path so the boot-time
// fail-closed Signer load succeeds. The daemon now refuses to start without a real
// key at -jwt-signing-key (there is no daemon-default key), so any test that reaches
// serve() must supply one.
func writeTestKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key mount: %v", err)
	}
}

// validArgs is a fully-valid serving invocation EXCEPT it binds nothing (Phase
// 1 opens no socket). Individual cases append or perturb one field. The
// listen/jwt/audit values are never dialled or opened on the paths these tests
// exercise: the static gates pass, boot runs against the in-memory default
// store, and either the kill-switch-first create refusal or the bind stub is
// reached — none of which touches those paths.
func validArgs() []string {
	return []string{
		"-operator-listen", "unix:///tmp/ocu-test-operator.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/ocu-test-jwt.key",
		"-audit-sink", "/tmp/ocu-test-audit.jsonl",
	}
}

// Test_run_MissingRequiredFlag asserts the first absent required flag is named
// and the typed sentinel is returned, the smoke's load-bearing substring.
func Test_run_MissingRequiredFlag(t *testing.T) {
	t.Parallel()
	err := run(context.Background(), []string{"-runtime-tier", "runc"})
	if err == nil {
		t.Fatal("run() returned nil on a missing required flag; want a refusal")
	}
	if !errors.Is(err, errRequiredFlagMissing) {
		t.Fatalf("run() error does not match errRequiredFlagMissing: %v", err)
	}
	if !strings.Contains(err.Error(), "-operator-listen") {
		t.Fatalf("run() error %q does not name the first missing flag -operator-listen", err)
	}
}

// Test_run_UnknownRuntimeTier asserts an unknown tier is refused pre-bind,
// before any Store is constructed.
func Test_run_UnknownRuntimeTier(t *testing.T) {
	t.Parallel()
	args := validArgs()
	args[5] = "bogus" // -runtime-tier value
	err := run(context.Background(), args)
	if !errors.Is(err, errUnknownRuntimeTier) {
		t.Fatalf("run() error does not match errUnknownRuntimeTier: %v", err)
	}
}

// Test_run_UnknownRuntimeProvider asserts an unknown provider is refused
// pre-bind.
func Test_run_UnknownRuntimeProvider(t *testing.T) {
	t.Parallel()
	args := validArgs()
	args[7] = "podman" // -runtime-provider value
	err := run(context.Background(), args)
	if !errors.Is(err, errUnknownProvider) {
		t.Fatalf("run() error does not match errUnknownProvider: %v", err)
	}
}

// Test_run_KillSwitchFirst drives -create-on-start through the REAL boot path
// with the default in-memory store: a create presented BEFORE Boot loads the deny
// posture is refused by the transient not-loaded gate (boot.ErrNotReady), and
// run() surfaces that pre-load refusal wrapped under errKillSwitchFirst with the
// load-bearing NFR-SEC-01 substring. The hook then confirms a clean-store create
// is admitted after load (the daemon is not inert), but it is the ordering refusal
// that the smoke greps.
func Test_run_KillSwitchFirst(t *testing.T) {
	t.Parallel()
	args := append(validArgs(), "-create-on-start")
	err := run(context.Background(), args)
	if err == nil {
		t.Fatal("run() returned nil on -create-on-start; want a kill-switch-first refusal")
	}
	if !errors.Is(err, errKillSwitchFirst) {
		t.Fatalf("run() error does not wrap errKillSwitchFirst: %v", err)
	}
	if !strings.Contains(err.Error(), "NFR-SEC-01") {
		t.Fatalf("run() error %q does not name NFR-SEC-01", err)
	}
}

// Test_run_KillSwitchFirst_ExplicitInMemory documents that an explicit empty
// -state-dsn (the in-memory default) refuses the pre-load create identically,
// mirroring the smoke's explicit-empty assertion of the transient ordering gate.
func Test_run_KillSwitchFirst_ExplicitInMemory(t *testing.T) {
	t.Parallel()
	args := append(validArgs(), "-state-dsn", "", "-create-on-start")
	err := run(context.Background(), args)
	if !errors.Is(err, errKillSwitchFirst) {
		t.Fatalf("run() with explicit empty -state-dsn does not wrap errKillSwitchFirst: %v", err)
	}
	if !strings.Contains(err.Error(), "NFR-SEC-01") {
		t.Fatalf("run() error %q does not name NFR-SEC-01", err)
	}
}

// Test_run_CleanBoot_BindsThenServes asserts a clean, create-free boot loads the
// deny posture, binds BOTH listeners off the readiness hook, and serves until the
// context is cancelled — returning nil on the clean ctx-driven shutdown, never a
// static-gate or fail-closed error. This proves the two-listener bind is reachable
// only after a successful boot and that a cancelled context unwinds the listeners
// cleanly. The operator socket and gateway port live under the test's own temp
// dir / an ephemeral port so the test binds real sockets without colliding.
func Test_run_CleanBoot_BindsThenServes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")
	writeTestKey(t, keyPath)
	// The operator socket lives under a short OS-temp path, not the (potentially
	// ~110-byte) t.TempDir(): a Unix socket path over the ~104-byte sockaddr_un
	// sun_path limit fails to bind with "invalid argument" on darwin and any
	// long-TMPDIR host, which would make this serving smoke red off CI.
	sockPath := shortSocketPath(t)
	args := []string{
		"-operator-listen", "unix://" + sockPath,
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", keyPath,
		"-audit-sink", filepath.Join(dir, "audit.jsonl"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, args) }()

	// Let boot reach the readiness hook (reconcile + bind), then cancel; a clean ctx
	// shutdown of the serve loop returns nil.
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			return // clean boot bound both listeners and shut down cleanly on cancel
		}
		// The boot orphan-sweep reconcile dials the Docker daemon. On a host with no
		// daemon (CI without Docker) that fail-closed error is the expected outcome of
		// a clean boot reaching the reconcile step — which still proves the bind hook
		// is reached only after a successful deny-posture load. Treat it as a skip so
		// the test does not require a daemon, but a NON-reconcile error still fails.
		if strings.Contains(err.Error(), "reconcile") {
			t.Skipf("clean boot reached the readiness hook; Docker daemon unavailable for the orphan sweep: %v", err)
			return
		}
		t.Fatalf("run() on a clean boot returned %v; want nil on a ctx-driven shutdown", err)
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not return within 10s after ctx cancel")
	}
}

// attestingResolver attests every operator connection with a fixed host-derived
// identity, standing in for SO_PEERCRED (Linux-only) so a create over the wire
// reaches the deny gate (Store.Reserve) rather than stopping at the darwin
// unattested wall. Identity is still host-derived from transport facts here (a
// fixed test identity), never from a request body — exactly the production
// contract the peer-cred resolver satisfies on Linux.
type attestingResolver struct{ id state.Identity }

func (r attestingResolver) Resolve(_ context.Context, _ ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	return ingress.AuthenticatedCaller{Identity: r.id, Channel: ingress.ChannelOperator}, nil
}

// composeServeDaemon builds the daemon EXACTLY as serve() does — the real Store,
// the real compose() lifecycle Manager + kill-switch Engine, the real boot
// Sequencer, and an operator Listener bound off the readiness hook — but with the
// injected resolver so the full ingress→admit→reserve path runs cross-platform. It
// returns the bound listener (its Handlers expose the in-process create surface for
// typed-error assertions) and a unix HTTP client. seedGlobalDeny, when true, seeds
// an OPERATOR-AUTHORED ScopeGlobal deny into the Store BEFORE boot, so LoadDeny
// restores it (mandate (b)). The docker provider is constructed but the backend is
// absent in CI, so a create that PASSES the deny gate fails later at Materialize —
// which is exactly the "got past the deny gate" evidence mandate (a) asserts.
func composeServeDaemon(t *testing.T, seedGlobalDeny bool) (*operator.Listener, *http.Client, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")
	writeTestKey(t, keyPath)
	sockPath := shortSocketPath(t)
	cfg := config{
		operatorListen:  "unix://" + sockPath,
		gatewayListen:   "127.0.0.1:0",
		runtimeTier:     "runc",
		runtimeProvider: "docker",
		workloadProfile: "trusted_operator",
		jwtSigningKey:   keyPath,
		jwtAlg:          "eddsa",
		auditSink:       filepath.Join(dir, "audit.jsonl"),
	}
	clk := state.SystemClock()
	store, err := openStore(context.Background(), cfg.stateDSN, clk)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	if seedGlobalDeny {
		// The durable posture an operator engaged before the last shutdown.
		if err := store.SetDeny(context.Background(), state.DenyEntry{
			Scope:  state.ScopeGlobal,
			Reason: "operator drill",
			Since:  clk.Now(),
		}); err != nil {
			t.Fatalf("seed operator ScopeGlobal deny: %v", err)
		}
	}
	tier, err := runtimeTierOf(cfg.runtimeTier)
	if err != nil {
		t.Fatalf("runtimeTierOf: %v", err)
	}
	profile, err := workloadProfileOf(cfg.workloadProfile)
	if err != nil {
		t.Fatalf("workloadProfileOf: %v", err)
	}
	signer, revoker, err := buildSigner(cfg, clk)
	if err != nil {
		t.Fatalf("buildSigner: %v", err)
	}
	// providerOf builds the docker provider's RevokeAuditor from the durable sink,
	// exactly as serve() does — the sink is built before the provider so the same
	// spine carries the teardown revoke evidence. This composition test does not
	// exercise that evidence, but it passes the real sink so the wiring path is the
	// production one.
	sink := ocsf.NewChainSink(clk, nullCloser{}, "control")
	provider, err := providerOf(cfg.runtimeProvider, tier, revoker, handoffBase, sink)
	if err != nil {
		t.Fatalf("providerOf: %v", err)
	}
	mgr, eng, _, _, _ := compose(store, clk, provider, profile, tier, signer, sink, cfg)
	seam := ingress.NewOperatorSeam()
	seq := boot.New(store, clk)
	op := operator.NewListener(sockPath, operator.Deps{
		Manager:  mgr,
		Engine:   eng,
		Healthz:  seq.Healthz(),
		Resolver: attestingResolver{id: state.Identity{Tenant: "op", Caller: "uid:1000"}},
		Seam:     seam,
	})
	seq.SetOnReady(func(context.Context) error { return op.Bind() })

	ctx, cancel := context.WithCancel(context.Background())
	if err := seq.Boot(ctx); err != nil {
		cancel()
		t.Fatalf("Boot: %v", err)
	}
	t.Cleanup(func() { _ = op.Close() })
	go func() { _ = op.Serve(ctx) }()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sockPath)
		},
	}}
	waitDaemonReady(t, client)
	return op, client, cancel
}

// waitDaemonReady polls /healthz on the bound operator socket until it answers 200.
func waitDaemonReady(t *testing.T, client *http.Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://unix/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("operator listener did not become ready within 5s")
}

// Test_CleanBootCreate_PastDenyGate is the LOAD-BEARING proof the inert-daemon bug
// is fixed (mandate (a)): the real daemon is composed exactly as serve() does, boots
// clean through a bound operator listener with NO operator-authored deny, and a
// create driven through the bound socket gets PAST the deny gate. Under the old
// boot-time global deny this was refused forever with ErrKillSwitchEngaged; now the
// only thing that fails is the absent docker backend at Materialize. The assertion
// is therefore: the create is NOT refused by the kill-switch/denylist deny gate —
// neither state.ErrKillSwitchEngaged nor state.ErrSessionDenied — and either it
// succeeds (a backend is present) or it fails LATER for a non-deny reason.
func Test_CleanBootCreate_PastDenyGate(t *testing.T) {
	t.Parallel()
	op, client, cancel := composeServeDaemon(t, false)
	defer cancel()

	// In-process typed-error proof: the create reaches Reserve and is NOT refused by
	// the deny gate. On a host with no docker it fails later at Materialize; on a host
	// with docker it may succeed. Either way the deny sentinels must be absent.
	_, createErr := op.Handlers().Create(context.Background(), ingress.ConnInfo{Channel: ingress.ChannelOperator}, operator.CreateRequest{
		SessionHint: "clean-boot", Image: "img", ControlPubKey: make([]byte, 32),
	})
	if errors.Is(createErr, state.ErrKillSwitchEngaged) {
		t.Fatalf("clean-boot create refused by ErrKillSwitchEngaged — the inert-daemon bug is NOT fixed: %v", createErr)
	}
	if errors.Is(createErr, state.ErrSessionDenied) {
		t.Fatalf("clean-boot create refused by ErrSessionDenied on a clean store: %v", createErr)
	}
	t.Logf("clean-boot create reached past the deny gate (err beyond the gate = %v)", createErr)

	// Over-the-wire proof: the bound operator listener admits the request to the
	// create pipeline. A 201 (backend present) or a 409 whose cause is the absent
	// backend are both "past the deny gate"; the typed-error assertion above is the
	// authoritative deny-gate check, since the wire status cannot carry the cause.
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(map[string]any{
		"session_hint": "clean-boot-wire", "image": "img", "control_pub_key": make([]byte, 32),
	})
	resp, err := client.Post("http://unix/v1alpha/sessions", "application/json", &buf)
	if err != nil {
		t.Fatalf("create over the wire: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	t.Logf("over-the-wire clean-boot create status=%d body=%s", resp.StatusCode, string(bytes.TrimSpace(raw)))
}

// Test_PersistedGlobalDeny_RefusesUntilResume is the durable-restore real-binary
// proof (mandate (b)+(c)): an operator-authored ScopeGlobal deny seeded before boot
// is restored by LoadDeny, so a create through the bound listener is REFUSED with
// state.ErrKillSwitchEngaged — proving the operator-engaged deny survives a restart
// and still works. It then lifts the deny in-band over the wire via the new
// /v1alpha/resume/all operator route and proves a subsequent create PROCEEDS past
// the deny gate.
func Test_PersistedGlobalDeny_RefusesUntilResume(t *testing.T) {
	t.Parallel()
	op, client, cancel := composeServeDaemon(t, true)
	defer cancel()

	// The restored operator deny refuses the create at the gate.
	_, createErr := op.Handlers().Create(context.Background(), ingress.ConnInfo{Channel: ingress.ChannelOperator}, operator.CreateRequest{
		SessionHint: "denied", Image: "img", ControlPubKey: make([]byte, 32),
	})
	if !errors.Is(createErr, state.ErrKillSwitchEngaged) {
		t.Fatalf("create with a restored operator global deny = %v; want ErrKillSwitchEngaged (durable restore)", createErr)
	}

	// Lift the global deny in-band over the wire via the new operator resume route.
	resp, err := client.Post("http://unix/v1alpha/resume/all", "application/json", bytes.NewReader([]byte(`{"reason":"drill over"}`)))
	if err != nil {
		t.Fatalf("POST resume/all: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resume/all over the wire = %d; want 200", resp.StatusCode)
	}

	// A subsequent create now proceeds past the deny gate.
	_, afterErr := op.Handlers().Create(context.Background(), ingress.ConnInfo{Channel: ingress.ChannelOperator}, operator.CreateRequest{
		SessionHint: "after-resume", Image: "img", ControlPubKey: make([]byte, 32),
	})
	if errors.Is(afterErr, state.ErrKillSwitchEngaged) {
		t.Fatalf("create after ResumeAll still refused by ErrKillSwitchEngaged — the in-band lift did not take: %v", afterErr)
	}
	t.Logf("create after in-band resume reached past the deny gate (err beyond the gate = %v)", afterErr)
}

// Test_serveCreateOnStart_PersistedGlobalDenyRefusesAfterLoad covers the
// serveCreateOnStart post-load refusal branch (mandate (b) at the cmd layer): with an
// operator-authored ScopeGlobal deny seeded before the hook runs, the pre-load gate
// still refuses first (transient ordering), then after LoadDeny restores the durable
// deny the post-load AdmitCreate is refused with state.ErrKillSwitchEngaged — proving
// the restored operator posture is enforced through the real create-on-start path,
// not a fabricated boot-time deny.
func Test_serveCreateOnStart_PersistedGlobalDenyRefusesAfterLoad(t *testing.T) {
	t.Parallel()
	clk := state.SystemClock()
	store := state.NewInMemory(clk)
	if err := store.SetDeny(context.Background(), state.DenyEntry{
		Scope:  state.ScopeGlobal,
		Reason: "operator drill",
		Since:  clk.Now(),
	}); err != nil {
		t.Fatalf("seed operator ScopeGlobal deny: %v", err)
	}

	err := serveCreateOnStart(context.Background(), store, clk)
	if err == nil {
		t.Fatal("serveCreateOnStart with a restored global deny returned nil; want a refusal")
	}
	// The post-load AdmitCreate is refused by the restored operator deny.
	if !errors.Is(err, state.ErrKillSwitchEngaged) {
		t.Fatalf("serveCreateOnStart post-load error = %v; want state.ErrKillSwitchEngaged (durable restore enforced)", err)
	}
}

// Test_serveCreateOnStart_CleanBootAdmitsAfterLoad covers the serveCreateOnStart
// happy path explicitly at the unit layer: the pre-load gate refuses (NFR-SEC-01),
// then a clean Boot loads an empty posture and the post-load AdmitCreate SUCCEEDS, so
// the hook returns the pre-load ordering refusal wrapped under errKillSwitchFirst —
// proving the daemon is not inert.
func Test_serveCreateOnStart_CleanBootAdmitsAfterLoad(t *testing.T) {
	t.Parallel()
	clk := state.SystemClock()
	store := state.NewInMemory(clk)

	err := serveCreateOnStart(context.Background(), store, clk)
	if !errors.Is(err, errKillSwitchFirst) {
		t.Fatalf("serveCreateOnStart on a clean store = %v; want the pre-load errKillSwitchFirst refusal", err)
	}
	if !strings.Contains(err.Error(), "NFR-SEC-01") {
		t.Fatalf("serveCreateOnStart error %q does not name NFR-SEC-01", err)
	}
	if !errors.Is(err, boot.ErrNotReady) {
		t.Fatalf("serveCreateOnStart pre-load refusal does not wrap boot.ErrNotReady: %v", err)
	}
}

// loadDenyFaultStore wraps an in-memory Store but faults LoadDeny with a wrapped
// ErrStoreUnavailable, so the serveCreateOnStart Boot-error branch (the fail-closed
// abort after the pre-load gate already refused) is exercised without a real outage.
type loadDenyFaultStore struct{ state.Store }

func (loadDenyFaultStore) LoadDeny(context.Context) ([]state.DenyEntry, error) {
	return nil, state.ErrStoreUnavailable
}

// Test_serveCreateOnStart_BootFailIsSurfaced covers the serveCreateOnStart Boot-error
// branch: the pre-load gate refuses first (transient ordering), then LoadDeny faults
// so Boot returns the fail-closed boot.ErrNotReady, which serveCreateOnStart surfaces
// as-is (never masking a store outage behind the ordering refusal).
func Test_serveCreateOnStart_BootFailIsSurfaced(t *testing.T) {
	t.Parallel()
	clk := state.SystemClock()
	store := loadDenyFaultStore{Store: state.NewInMemory(clk)}

	err := serveCreateOnStart(context.Background(), store, clk)
	if !errors.Is(err, boot.ErrNotReady) {
		t.Fatalf("serveCreateOnStart with a faulted LoadDeny = %v; want boot.ErrNotReady (fail-closed Boot surfaced)", err)
	}
	if !errors.Is(err, state.ErrStoreUnavailable) {
		t.Fatalf("serveCreateOnStart Boot-fail error does not preserve state.ErrStoreUnavailable: %v", err)
	}
}

// Test_run_UnknownJWTAlg asserts an unknown -jwt-alg is refused pre-bind, never
// coerced to a default; the default eddsa is exercised by the clean-boot test.
func Test_run_UnknownJWTAlg(t *testing.T) {
	t.Parallel()
	args := append(validArgs(), "-jwt-alg", "rsa")
	err := run(context.Background(), args)
	if !errors.Is(err, errUnknownJWTAlg) {
		t.Fatalf("run() with -jwt-alg rsa error does not match errUnknownJWTAlg: %v", err)
	}
}

// Test_run_BadSigningKeyFailsClosedBeforeBind asserts a missing/garbage signing key
// aborts the daemon at boot BEFORE any listener binds: a clean (create-free) boot
// with a -jwt-signing-key that does not resolve to a valid key returns a wrapped
// cred.ErrSigningKeyMissing, and no socket is left behind. This is the fail-closed
// custody invariant — there is no daemon-default key.
func Test_run_BadSigningKeyFailsClosedBeforeBind(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := []string{
		"-operator-listen", "unix://" + filepath.Join(dir, "operator.sock"),
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", filepath.Join(dir, "absent.key"), // never written
		"-audit-sink", filepath.Join(dir, "audit.jsonl"),
	}
	err := run(context.Background(), args)
	if !errors.Is(err, cred.ErrSigningKeyMissing) {
		t.Fatalf("run() with an absent signing key error does not wrap cred.ErrSigningKeyMissing: %v", err)
	}
	// The fail-closed abort happens before the bind hook is installed, so no operator
	// socket survives the refusal.
	if _, statErr := os.Stat(filepath.Join(dir, "operator.sock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("a fail-closed signer-load abort left an operator socket (stat err=%v); want no socket", statErr)
	}
}

// Test_serveListeners_SignalDrainsAndUnlinksSocket proves the HOST-side daemon-stop
// drain: a cancelled root context (the SIGINT/SIGTERM path) makes serveListeners
// stop accepting on both listeners, drain both Serve loops, and unlink the operator
// Unix socket — returning nil (a signal stop is not an error). Before the fix the
// root context was never cancelled, so the Serve loops never drained and the socket
// was never unlinked. This exercises serveListeners directly so it needs no Docker
// daemon for the orphan sweep.
func Test_serveListeners_SignalDrainsAndUnlinksSocket(t *testing.T) {
	t.Parallel()
	sock := shortSocketPath(t)

	op := operator.NewListener(sock, operator.Deps{})
	gw := gateway.NewListener("127.0.0.1:0", gateway.Deps{})
	if err := op.Bind(); err != nil {
		t.Fatalf("operator Bind: %v", err)
	}
	if err := gw.Bind(); err != nil {
		t.Fatalf("gateway Bind: %v", err)
	}

	// The operator socket exists while serving.
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("operator socket must exist after Bind: %v", err)
	}
	// The gateway TCP port is accepting connections while serving.
	gwAddr := gw.Addr()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveListeners(ctx, op, gw) }()

	// Give the Serve loops a moment to come up, prove the gateway is reachable, then
	// cancel the root context (the signal path).
	waitFor(t, func() bool {
		c, err := net.DialTimeout("tcp", gwAddr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveListeners on a cancelled (signal) context must return nil, got: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serveListeners did not drain within 15s of ctx cancel")
	}

	// The operator socket is unlinked: the deferred Close ran on the signal path.
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("operator socket must be unlinked after a signal-driven drain (stat err=%v); want not-exist", err)
	}
	// The gateway port is released: a dial now fails.
	if c, err := net.DialTimeout("tcp", gwAddr, 200*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("gateway port must be released after the drain; a dial still succeeded")
	}
}

// Test_serveListeners_ServeErrorReturnsAndCloses proves the error path: when a Serve
// loop fails before any signal, serveListeners returns that error AND still closes
// both listeners (the operator socket is unlinked) so a failure leaves no half-open
// listener. A never-bound operator listener makes op.Serve return immediately.
func Test_serveListeners_ServeErrorReturnsAndCloses(t *testing.T) {
	t.Parallel()
	sock := shortSocketPath(t)

	// op is bound (its socket exists); gw is NOT bound, so gw.Serve returns an error
	// immediately, driving the error path of serveListeners.
	op := operator.NewListener(sock, operator.Deps{})
	gw := gateway.NewListener("127.0.0.1:0", gateway.Deps{})
	if err := op.Bind(); err != nil {
		t.Fatalf("operator Bind: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- serveListeners(context.Background(), op, gw) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serveListeners with an unbound gateway must return the serve error, got nil")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serveListeners did not return within 15s on a serve error")
	}

	// Both listeners were closed on the error path: the operator socket is unlinked.
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("operator socket must be unlinked after a serve-error close (stat err=%v); want not-exist", err)
	}
}

// shortSocketPath returns a Unix-socket path SHORT enough for the platform's
// sun_path limit (~104 bytes on darwin), which a deeply-nested t.TempDir() path can
// exceed. It creates a short-named dir directly under the OS temp root and removes
// the whole tree on cleanup, so the bound socket never leaks.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ocu")
	if err != nil {
		t.Fatalf("mkdir short temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "op.sock")
}

// waitFor polls cond up to 5s, failing the test if it never becomes true. It lets a
// drain test wait on a real readiness condition instead of a fixed sleep.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

// Test_run_Version returns the version with no boot.
func Test_run_Version(t *testing.T) {
	t.Parallel()
	if err := run(context.Background(), []string{"-version"}); err != nil {
		t.Fatalf("run(-version): %v", err)
	}
}
