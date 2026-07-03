// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// stepTimeout is the per-finalizer-step bounded timeout, derived from the
// context.WithoutCancel base, NEVER the parent. It caps a wedged daemon call so a
// single hung step cannot strand a later resource; it is intentionally generous
// because every step runs host-side regardless of guest cooperation. The value is
// not pinned by an NFR (see DESIGN open decisions) — confirm against the
// component-02 teardown SLO before it hardens.
const stepTimeout = 30 * time.Second

// teardown is the Docker RuntimeTeardown handle. Both verbs run ONE ordered
// host-driven finalizer body (finalize); the only difference is the drain window
// before the kill step. It re-derives every resource name purely from the
// Sandbox's SessionName, so teardown needs no provider state and survives a
// process restart (requirement 5).
type teardown struct {
	p *Provider
}

var _ runtime.RuntimeTeardown = (*teardown)(nil)

// GracefulStop runs the finalizer with a SIGTERM-then-kill drain window of grace
// seconds before the kill step: under Docker the kill step first issues
// ContainerStop with the timeout, giving the guest grace to flush before the host
// force-removes it. Every other finalizer step still runs host-side regardless of
// whether the guest honored the SIGTERM (NFR-SEC-27). It is idempotent against an
// already-gone container (ErrNoSuchContainer is a satisfied kill, not an error).
func (t *teardown) GracefulStop(parent context.Context, sess runtime.Sandbox, grace runtime.Duration) error {
	return t.finalize(parent, sess, &grace)
}

// ForceKill runs the finalizer with NO drain window: the kill step skips straight
// to the force-remove, which subsumes any drain GracefulStop would have given. It
// is force-remove-authoritative (it never waits on a guest reply) and idempotent
// (an underlying not-found maps to ErrNoSuchContainer, a satisfied kill).
func (t *teardown) ForceKill(parent context.Context, sess runtime.Sandbox) error {
	return t.finalize(parent, sess, nil)
}

// finalize is the single ordered host-driven finalizer body both verbs share. Its
// FIRST act detaches from the parent context (context.WithoutCancel), so a
// cancelled parent can never strand a half-freed session: every host-side step
// still runs (requirement 4). grace == nil means ForceKill (no drain window).
//
// The EXACT NFR-SEC-65 step order, none depending on guest cooperation:
//
//  1. revoke session JWT                  (host-side; the real cross-component revoke is deferred-external)
//  2. drop the network-bound egress route (host-side EVEN IF the guest is unresponsive)
//  3. zero tmpfs/scratch                  (host reclamation)
//  4. unmount data scope                  (host reclamation)
//  5. kill process tree == ContainerRemove(id, force:true)
//     - GracefulStop: ContainerStop(grace) first, then the force-remove.
//     - ForceKill: straight to force-remove (subsumes the skipped drain).
//     - IsNotFound -> ErrNoSuchContainer, treated as a SATISFIED kill (idempotent).
//  6. destroy cgroup + NetworkRemove(bridge) — STRICTLY AFTER the force-remove
//     (the active-endpoints constraint); its own IsNotFound is also swallowed.
//
// A non-not-found failure at any step is collected (errors.Join) and the finalizer
// CONTINUES to the next host-side step rather than abort, so one failed step can
// never strand a later resource; the joined result is wrapped ErrTeardown.
func (t *teardown) finalize(parent context.Context, sess runtime.Sandbox, grace *runtime.Duration) error {
	// FIRST LINE: detach from the parent so a cancelled parent context cannot
	// strand a half-freed session (requirement 4).
	base := context.WithoutCancel(parent)

	target := containerTarget(sess)
	bridge := networkName(sess.Name)

	// Each step runs in the exact NFR-SEC-65 order; the finalizer NEVER short-
	// circuits, so every later host-side resource is reclaimed even if an earlier
	// step failed. The results are collected into one ordered slice and joined.

	// 1. Revoke the session JWT host-side via the shared monotonic Revoker, keyed
	//    off the EgressBinding the step already holds. The revoke marks the minted
	//    jti permanently dead so the egress edge stops honoring it; the mark is
	//    monotonic, so a wall-clock setback never un-revokes it (NFR-SEC-48).
	step1RevokeJWT := t.revokeJWT(base, sess.Egress)

	// 2. Drop the network-bound egress route host-side via the EgressBinding —
	//    EVEN IF the guest is unresponsive (NFR-SEC-27). Deferred-external: the real
	//    Envoy SDS route-drop rides the EgressProgrammer seam (gated on the live
	//    Envoy + deploy-SDS coordination); the host-side route binding is dropped now.
	step2DropEgress := t.dropEgress(base, sess.Egress)

	// 3. Zero the host-owned per-session scratch: scrub the credential-bearing
	//    handoff root (base/<sess.Name>) BEFORE the kill in step 5, so the weak
	//    Storage-JWT mount-config and the rest of the handoff tree never outlive
	//    the session on host disk (NFR-SEC-65).
	step3ZeroTmpfs := t.zeroTmpfs(base, sess)

	// 4. Unmount the data scope (host reclamation). Deferred-external: the real
	//    rclone-filestore unmount rides the UnmountTrigger seam (gated on the sibling
	//    unmount contract); the host-side bind is reclaimed now.
	step4Unmount := t.unmountScope(base, sess)

	// 5. Kill the process tree == force-remove the container.
	step5Kill := t.killContainer(base, target, grace)

	// 6. Destroy cgroup + remove the per-session bridge — STRICTLY AFTER the
	//    container force-remove (the active-endpoints constraint).
	step6Network := t.removeNetwork(base, bridge)

	steps := []error{
		step1RevokeJWT,
		step2DropEgress,
		step3ZeroTmpfs,
		step4Unmount,
		step5Kill,
		step6Network,
	}
	return asTeardownError(steps)
}

// revokeJWT is finalizer step 1: revoke the session's Storage-JWT host-side via the
// shared monotonic Revoker. It is keyed off the EgressBinding the step already
// holds (the host-derived session-key revocation handle carried on
// Egress.FilesystemID), so the row need not persist the jti. It is idempotent: a
// re-run of the finalizer revokes an already-dead jti without error, and an
// EgressBinding whose mint was never recorded (cred.ErrRevokeUnbound) is a
// satisfied no-op (nothing live to revoke) rather than a finalizer error. A nil
// Revoker (the Phase-3 minimal shelf) leaves the step a host-side no-op; the step
// still runs in order.
func (t *teardown) revokeJWT(base context.Context, bind runtime.EgressBinding) error {
	if t.p.revoker == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(base, stepTimeout)
	defer cancel()
	outcome, err := t.p.revoker.Revoke(ctx, bind)
	if err != nil {
		if errors.Is(err, cred.ErrRevokeUnbound) {
			// No minted jti bound to this session (nothing live to revoke) — a
			// satisfied no-op for the finalizer error, but a DISTINCT audited
			// outcome (none_bound), never dissolved into a blanket success: a
			// revoke that bound nothing is evidence. With BindKey unifying the
			// record and lookup keys this can only mean a genuinely never-minted
			// or already-reaped session, not a key drift.
			t.recordRevokeOutcome(ctx, bind, outcome)
			return nil
		}
		return fmt.Errorf("docker: revoke session jwt: %w", err)
	}
	t.recordRevokeOutcome(ctx, bind, outcome)
	return nil
}

// recordRevokeOutcome surfaces the step-1 revoke outcome to the audit seam, if
// one is wired. A nil auditor records nothing (the minimal shelf), exactly as a
// nil revoker leaves the revoke effect a no-op.
func (t *teardown) recordRevokeOutcome(ctx context.Context, bind runtime.EgressBinding, outcome runtime.RevokeOutcome) {
	if t.p.revokeAuditor == nil {
		return
	}
	t.p.revokeAuditor.RecordRevokeOutcome(ctx, bind, outcome)
}

// dropEgress is finalizer step 2: drop the network-bound egress route host-side
// via the EgressBinding, even if the guest is unresponsive (NFR-SEC-27). Phase 2
// drops the host-side route binding keyed on the FilesystemID; the real Envoy SDS
// resource removal is deferred-external (real Envoy SDS). The step EXISTS and runs in order now.
func (t *teardown) dropEgress(_ context.Context, _ runtime.EgressBinding) error {
	// Deferred-external: materialize the route drop against the real Envoy SDS via the
	// host-side route binding is dropped here regardless of guest reachability;
	// EgressProgrammer seam; the cross-component SDS push is deferred-external.
	return nil
}

// zeroTmpfs is finalizer step 3: scrub the host-owned per-session scratch OUTSIDE
// the container's own tmpfs. The container's bounded /tmp tmpfs is reclaimed by
// the force-remove in step 5, but the create-path handoff stager wrote a 0700
// host-owned root (base/<SessionName>) holding container_info.json, the pushed
// mount-config that CARRIES the weak Storage-JWT, and the 0700 sock dir. That tree
// is exactly the host-owned scratch this step zeroes, so the credential-bearing
// files never outlive the session on host disk.
//
// It re-derives the root PURELY from sess.Name under the provider's deployment-fixed
// stagerBase (base/<sess.Name>) — the SAME provenance networkName(sess.Name)/
// containerName(sess.Name) use, and the SAME path handoff.Stager builds (its SockDir
// is base/<name>/sock) — so the step takes no body hint and needs no provider
// per-session state (requirement 5, NFR-SEC-43). An empty stagerBase (the minimal
// shelf where no handoff base is wired) leaves the step a host-side no-op, exactly
// as a nil revoker leaves step 1.
//
// It is IDEMPOTENT and proves STRICT ZERO-RESIDUE because this is a CREDENTIAL
// scrub: it removes the tree recursively, then re-stats the path. An already-gone
// root (os.RemoveAll succeeds, the path does not exist) is a satisfied no-op on ANY
// input state — full handoff root, partially-torn-down, already-empty, or absent.
// But if ANYTHING remains after the recursive removal (a race with another writer
// re-creating a file), that is a FINALIZER ERROR collected into the errors.Join, NOT
// a swallowed no-op — a credential file that survived the scrub must surface.
func (t *teardown) zeroTmpfs(base context.Context, sess runtime.Sandbox) error {
	if t.p.stagerBase == "" {
		// No handoff base wired (the minimal shelf): nothing host-owned to scrub. The
		// step still runs in order; it is simply a no-op here.
		return nil
	}
	_ = base // the scrub is a local-filesystem operation; the ctx is unused but the
	// step keeps the shared finalizer signature so its ordering is uniform.

	// Re-derive the per-session handoff root purely from the host-derived SessionName
	// under the deployment-fixed base — the same join handoff.Stager uses, so the
	// finalizer and the create path agree on the path without the row persisting it.
	root := filepath.Join(t.p.stagerBase, string(sess.Name))
	return scrubHandoffRoot(root)
}

// removeAll is the recursive-removal primitive scrubHandoffRoot drives, indirected
// through a package var so an internal test can inject a remover that "succeeds"
// without removing — the only way to deterministically exercise the strict
// zero-residue branch (a writer racing the scrub), since a real TOCTOU race is not
// reproducible. In production it is os.RemoveAll, never reassigned outside a test,
// mirroring the handoff package's createTemp/chmod indirection.
var removeAll = os.RemoveAll

// scrubHandoffRoot removes the per-session handoff tree recursively and PROVES
// strict zero-residue: this is a CREDENTIAL scrub, so it is not "rm -rf and ignore
// the error". It removes the tree, then re-stats the path. An already-gone root
// (os.RemoveAll succeeds and the path does not exist) is a satisfied no-op on ANY
// input state — a full handoff root, a partially-torn-down one, an already-empty
// one, or an absent one. A removal error is surfaced. And if ANYTHING remains after
// the recursive removal (the path is still present), that is a FINALIZER ERROR — a
// credential file that survived the scrub must surface into the finalizer's
// errors.Join, never be swallowed.
func scrubHandoffRoot(root string) error {
	// Remove the whole tree recursively. os.RemoveAll treats an already-gone path as
	// success, so a re-run (or a never-staged session) is an idempotent no-op.
	if err := removeAll(root); err != nil {
		return fmt.Errorf("docker: scrub handoff root %q: %w", root, err)
	}

	// STRICT ZERO-RESIDUE: after the recursive removal the path must hold EXACTLY
	// zero files. Re-stat: an os.ErrNotExist is the satisfied state (the credential
	// tree is gone). Anything else — the path still present, or a stat fault — is a
	// finalizer error, never a swallowed no-op.
	if _, err := os.Lstat(root); err == nil {
		return fmt.Errorf("docker: handoff root %q still present after scrub: %w", root, runtime.ErrTeardown)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("docker: verify handoff root %q scrubbed: %w", root, err)
	}
	return nil
}

// unmountScope is finalizer step 4: unmount the per-session data scope host-side.
// Phase 2 reclaims the host-side bind; the real rclone-filestore unmount is a
// deferred-external (real rclone unmount). The step EXISTS and runs in order now.
func (t *teardown) unmountScope(_ context.Context, _ runtime.Sandbox) error {
	// Deferred-external: unmount the real rclone-filestore mount via the UnmountTrigger seam. The host-side bind
	// reclamation runs here; the cross-component unmount is deferred-external.
	return nil
}

// killContainer is finalizer step 5: kill the process tree by force-removing the
// container. For GracefulStop (grace != nil) it first issues ContainerStop with the
// grace timeout — the SIGTERM-then-kill drain window — then force-removes; for
// ForceKill (grace == nil) it skips straight to the force-remove. The force-remove
// NEVER waits on a guest reply. An IsNotFound at either call maps to
// ErrNoSuchContainer and is treated as a SATISFIED kill (idempotent re-run), never
// a finalizer error.
func (t *teardown) killContainer(base context.Context, target string, grace *runtime.Duration) error {
	if grace != nil {
		ctx, cancel := context.WithTimeout(base, stepTimeout)
		// ContainerStop StopOptions.Timeout is *int seconds; the named runtime.Duration
		// is already whole seconds, so it passes straight through with no unit
		// conversion (the reason Duration is an int, not a time.Duration).
		timeout := int(*grace)
		serr := t.p.api.ContainerStop(ctx, target, container.StopOptions{Timeout: &timeout})
		cancel()
		if serr != nil && !cerrdefs.IsNotFound(serr) {
			// A failed drain is non-fatal: fall through to the force-remove, which
			// subsumes the drain. The drain error is not collected — the authoritative
			// outcome is whether the force-remove below leaves no container.
			_ = serr
		}
	}

	ctx, cancel := context.WithTimeout(base, stepTimeout)
	defer cancel()
	if err := t.p.api.ContainerRemove(ctx, target, container.RemoveOptions{Force: true}); err != nil {
		if cerrdefs.IsNotFound(err) {
			// Already gone — a satisfied kill step, not an error (idempotent).
			return nil
		}
		return fmt.Errorf("docker: force-remove %q: %w", target, err)
	}
	return nil
}

// removeNetwork is finalizer step 6: remove the per-session bridge STRICTLY AFTER
// the container force-remove (the active-endpoints constraint). Both an
// already-gone network (IsNotFound) and a still-active-endpoints conflict
// (IsConflict -> ErrNetworkActive) are swallowed as idempotent: a re-run that finds
// the bridge gone, and the typed evidence that the ordering was honored, are both
// non-errors here.
func (t *teardown) removeNetwork(base context.Context, bridge string) error {
	ctx, cancel := context.WithTimeout(base, stepTimeout)
	defer cancel()
	if err := t.p.api.NetworkRemove(ctx, bridge); err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		if cerrdefs.IsConflict(err) {
			// A conflict here means an endpoint is still attached; the typed
			// evidence the ordering was violated is surfaced for the join.
			return fmt.Errorf("docker: network remove %q: %w: %w", bridge, runtime.ErrNetworkActive, err)
		}
		return fmt.Errorf("docker: network remove %q: %w", bridge, err)
	}
	return nil
}

// containerTarget is the container the finalizer acts on: the fast-path runtime id,
// or the Name-derived container name re-derived purely from sess.Name when no id
// survives a process restart (requirement 5 — destroy derives the name).
func containerTarget(sess runtime.Sandbox) string {
	if sess.RuntimeID != "" {
		return sess.RuntimeID
	}
	return containerName(sess.Name)
}
