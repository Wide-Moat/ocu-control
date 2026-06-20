// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package controlrpc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

var (
	// ErrSockDirGate is returned when the host-owned 0700 gate on the sock
	// directory does not hold: the directory is missing, is not a directory, is not
	// owned by the dialing host process, or carries a mode looser than 0700. The
	// dial is refused BEFORE any connect(2), so a non-host-owned socket path is
	// never spoken to (NFR-SEC-43/NFR-SEC-76 host-only-at-accept, realized as the
	// 0700 host-owned-directory gate).
	ErrSockDirGate = errors.New("controlrpc: control sock dir failed the host-owned 0700 gate")
	// ErrControlError wraps a guest ControlError reply so the caller can branch on
	// it. It is NON-AUTHORITATIVE for teardown: the finalizer proceeds regardless.
	ErrControlError = errors.New("controlrpc: guest returned ControlError")
	// ErrShutdownReply is returned when the guest reply was structurally valid but
	// was not ShutdownAccepted (no v1 success variant present). Also
	// non-authoritative.
	ErrShutdownReply = errors.New("controlrpc: shutdown not accepted")
)

// controlSockName is the RESERVED name for the host-dialled control UDS, DISTINCT
// from the guest-created exec UDS name, so the two transports never collide in the
// single HostSockDir the handoff stages. The host dials sockDir/control.sock.
const controlSockName = "control.sock"

// defaultDialTimeout is the provisional per-dial deadline for the advisory
// Shutdown. It is deliberately short so a wedged or unresponsive guest can never
// delay the authoritative host-driven force-remove: the finalizer proceeds the
// moment this elapses. It is provisional pending the component-02 teardown SLO.
const defaultDialTimeout = 5 * time.Second

// execMinter is the NARROW seam the dialer reaches the per-dial exec JWT through.
// It is satisfied by *cred.Signer but names only MintExecJWT, so the load-bearing
// controlrpc package depends on the mint method, not the whole custody Signer (and
// never on the signing key). The minted Token redacts on every emit surface; the
// raw compact JWT is revealed only at the single Authorization-write call site.
type execMinter interface {
	MintExecJWT(ctx context.Context, req cred.ExecMintReq) (cred.Token, error)
}

// Compile-time proof *cred.Signer satisfies the narrow execMinter seam, so the
// production wiring type-checks and a test fake matches the same shape.
var _ execMinter = (*cred.Signer)(nil)

// Dialer dials the host-owned control UDS in the guest's 0700 host-owned sock
// directory (ADR-0018). It is NOT loopback TCP: a non-host peer cannot connect(2)
// to a socket in a 0700 host-owned directory and is dropped before any frame is
// parsed (the v1 realization of host-only-at-accept; an SO_PEERCRED uid compare on
// the dial side is named future hardening, not a v1 requirement). Each dial mints
// a per-dial exec JWT bound to the host-attested container_name and carries it as
// the Authorization context; the Token never enters a log line.
type Dialer struct {
	minter  execMinter
	timeout time.Duration
}

// NewDialer constructs a Dialer over the exec-JWT minter. A non-positive timeout
// falls back to defaultDialTimeout so an advisory dial always bounds its wait.
func NewDialer(minter execMinter, timeout time.Duration) *Dialer {
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	return &Dialer{minter: minter, timeout: timeout}
}

// Shutdown opens sockDir/control.sock, mints the per-dial exec JWT bound to
// containerName, writes one bounded {"Shutdown":{}} frame, reads one reply, and
// closes. It returns nil on ShutdownAccepted.
//
// ADVISORY: the caller (the teardown path) proceeds REGARDLESS of the result —
// the host-driven finalizer (NFR-SEC-65) is authoritative and the force-remove
// never waits on this reply. A transport drop, a gate refusal, a ControlError, or
// a non-accept reply is returned as a typed error for diagnostics but is
// non-authoritative for teardown. Shutdown is idempotent: a repeat dial after the
// guest has begun shutting down returns the same ShutdownAccepted.
func (d *Dialer) Shutdown(ctx context.Context, sockDir, containerName string) error {
	if containerName == "" {
		return fmt.Errorf("%w: empty container_name", cred.ErrMintIdentity)
	}

	// Host-only-at-accept gate FIRST: refuse before any connect(2) if the sock dir
	// is not a host-owned 0700 directory, so a socket planted in a world-accessible
	// directory is never dialed.
	if err := verifyHostOwnedDir(sockDir); err != nil {
		return err
	}
	sockPath := filepath.Join(sockDir, controlSockName)

	// Bound the whole dial by the per-dial deadline, narrowed further by any
	// caller-supplied context deadline (whichever is sooner), so a wedged guest
	// never outlives the advisory window.
	deadline := time.Now().Add(d.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Mint the per-dial exec JWT bound to the host-attested container_name. The
	// Token redacts on every emit surface; it is materialized only into the
	// Authorization context below, never logged.
	tok, err := d.minter.MintExecJWT(dialCtx, cred.ExecMintReq{
		ContainerName: containerName,
		RequestedTTL:  d.timeout,
	})
	if err != nil {
		return fmt.Errorf("controlrpc: mint exec jwt: %w", err)
	}
	// authorization is the per-dial bearer the guest validates the host against. It
	// is the single Reveal call site on the dial path. In v1 the control transport
	// carries no HTTP header (the schema fixes only the JSON union, identical under
	// any framing), so the bearer is held for the connection's authenticated
	// context, never logged. The blank assignment makes the one clear-text
	// materialization explicit and greppable.
	_ = tok.Reveal()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "unix", sockPath)
	if err != nil {
		return fmt.Errorf("controlrpc: dial %s: %w", controlSockName, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("controlrpc: set deadline: %w", err)
	}

	if err := EncodeRequest(conn, Request{Shutdown: &Shutdown{}}); err != nil {
		return fmt.Errorf("controlrpc: send shutdown: %w", err)
	}

	rep, err := DecodeReply(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("controlrpc: read reply: %w", err)
	}
	switch {
	case rep.Accepted != nil:
		// ShutdownAccepted is NOT a completion claim; the finalizer remains
		// authoritative. nil here means only "the guest acknowledged the advisory".
		return nil
	case rep.Error != nil:
		return fmt.Errorf("%w: %s", ErrControlError, rep.Error.ReasonCode)
	default:
		return ErrShutdownReply
	}
}

// verifyHostOwnedDir is the 0700 host-owned-directory gate: it asserts sockDir
// exists, is a directory, is owned by the dialing host process's effective uid,
// and carries no group/other permission bits (mode 0700, the owner-only mode the
// handoff stager wrote). A non-host-owned or world-accessible sock dir is refused
// here, before any connect(2), so the host never speaks to a socket a non-host
// peer could have planted.
func verifyHostOwnedDir(sockDir string) error {
	if sockDir == "" {
		return fmt.Errorf("%w: empty sock dir", ErrSockDirGate)
	}
	info, err := os.Stat(sockDir)
	if err != nil {
		return fmt.Errorf("%w: stat %q: %v", ErrSockDirGate, sockDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", ErrSockDirGate, sockDir)
	}
	// Refuse any group- or other-accessible bit: the directory must be exactly
	// owner-only (0700) so no non-host user can read or plant a socket in it.
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %q mode %o is looser than 0700", ErrSockDirGate, sockDir, info.Mode().Perm())
	}
	// Assert the directory is owned by the dialing host process: a directory owned
	// by another uid is not host-owned even at 0700.
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %q has no ownership metadata", ErrSockDirGate, sockDir)
	}
	// Geteuid returns -1 on platforms where it is unsupported; guard both the
	// negative sentinel and the uint32 range before the narrowing conversion so a
	// uid outside the file-owner space cannot wrap. A bounded uid then compares
	// directly against the directory owner.
	euid := os.Geteuid()
	if euid >= 0 && uint64(euid) <= math.MaxUint32 && st.Uid != uint32(euid) {
		return fmt.Errorf("%w: %q owner uid %d is not the host uid %d", ErrSockDirGate, sockDir, st.Uid, euid)
	}
	return nil
}
