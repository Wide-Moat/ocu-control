// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle

import (
	"context"
	"fmt"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// ExecRequest is the substrate-neutral exec request the Manager routes to the
// driver: the command vector and its optional environment, working directory,
// stdin bytes, and timeout. It carries NO credential and NO addressing authority
// — the session is addressed by the caller through the host-derived row, and the
// driver mints the container-bound token itself.
type ExecRequest struct {
	Argv     []string
	Env      map[string]string
	Cwd      string
	Stdin    []byte
	TimeoutS uint32
}

// ExecResult is the completed exec: the guest child's exit code and the captured,
// per-stream-bounded output.
type ExecResult struct {
	ExitCode        uint8
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
}

// ExecDriver is the NARROW seam the exec path reaches the guest exec channel
// through (ADR-0024). It is satisfied by *guestexec.Driver but names only Exec so
// the pure-domain Manager depends on the exec verb, not on the WebSocket dialer,
// the JWT minter, or any container SDK. sockDir and containerName are BOTH
// host-derived (the handoff sock dir for the session key, and the row's container
// name) — never a body value. A nil ExecDriver (a deployment without the exec
// channel, or the minimal shelf) makes Exec a fail-closed refusal.
type ExecDriver interface {
	Exec(ctx context.Context, sockDir, containerName string, req ExecRequest) (ExecResult, error)
}

// errExecUnavailable is returned when Exec is called on a Manager with no exec
// driver wired — the exec channel is not available in this deployment, so the
// request is refused fail-closed rather than silently succeeding.
var errExecUnavailable = fmt.Errorf("lifecycle: exec channel not available")

// Exec runs one command in the caller's own session guest. It mirrors Destroy's
// addressing and audit discipline: derive the Key from the host-minted handle the
// hint addresses, audience-scoped-look-up the row via the Custodian (ErrNotOwned
// for a non-owned or absent row — a foreign hint is indistinguishable from
// not-found), emit the ActionExec record FAIL-CLOSED (F10: the host authors the
// tool-call record and a write failure denies the exec), then route to the driver
// with the host-derived sock dir and the row's container name. The addressing
// authority is the host-derived caller, never a body value (NFR-SEC-43).
func (m *Manager) Exec(ctx context.Context, caller ingress.AuthenticatedCaller, sessionHint string, req ExecRequest) (ExecResult, error) {
	owner := caller.Identity
	if owner.Caller == "" || owner.Tenant == "" {
		return ExecResult{}, ErrUnattested
	}
	if m.execDriver == nil {
		return ExecResult{}, errExecUnavailable
	}
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		return ExecResult{}, fmt.Errorf("lifecycle: exec: empty argv")
	}

	// The body hint only ADDRESSES the row through the derived key; owner is the
	// host-derived authority the row is gated on. The same deterministic transform
	// the create used re-derives the handle, then DeriveKey mixes the owner in — so
	// a foreign caller deriving from the same hint lands on a DIFFERENT key and can
	// never address the victim's row.
	key := registry.DeriveKey(owner, mintHandle(sessionHint))
	row, err := m.reg.LookupForCaller(ctx, key, owner)
	if err != nil {
		return ExecResult{}, fmt.Errorf("lifecycle: exec lookup: %w", err)
	}

	// Audit FIRST, fail-closed (F10): the host authors the tool-call record and it
	// must be durable before the exec is acknowledged. A write failure denies the
	// exec and dials no guest.
	rec := audit.Record{
		Action:  audit.ActionExec,
		Channel: caller.Channel.String(),
		Key:     key.String(),
		Caller:  owner.Caller,
		Tenant:  owner.Tenant,
	}
	if err := m.audit.Emit(ctx, rec); err != nil {
		return ExecResult{}, fmt.Errorf("lifecycle: exec audit: %w", err)
	}

	// The sock dir is re-derived PURELY from the host-derived session key (the same
	// pure function the create-path handoff stager used), and the container name is
	// the host-attested row value — never a body hint (NFR-SEC-43).
	sockDir := m.handoff.SockDir(runtime.SessionName(row.Key))
	res, err := m.execDriver.Exec(ctx, sockDir, row.ContainerName, req)
	if err != nil {
		return ExecResult{}, err
	}

	// A successful exec is activity: advance the row's last-activity stamp so the
	// idle-reaper measures idleness from THIS exec, not from creation — a session that
	// keeps exec'ing is never reaped. The stamp is Clock.Now() (the reaper compares two
	// in-process Clock readings, never a persisted timestamp: NFR-SEC-48). The touch is
	// NON-FATAL: the exec already succeeded and its result is owed to the caller, so a
	// touch failure (or a Store without the ActivityToucher capability) is swallowed —
	// the session simply keeps its prior stamp and may be reaped one idle window early
	// at worst, never a failed exec.
	_ = m.reg.TouchActivity(ctx, key, m.clk.Now())
	return res, nil
}
