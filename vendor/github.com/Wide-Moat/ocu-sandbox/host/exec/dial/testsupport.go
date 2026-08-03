// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// TEST-SUPPORT ONLY (T-14-06-PAD). The methods in this file are consumed by the
// `control` package's daemon-gated integration tests (a DIFFERENT package), so
// they cannot live in a `dial` `_test.go` file — Go does not export a package's
// `_test.go` symbols across package boundaries — nor behind a build tag, because
// the single `-coverpkg=./internal/...` coverage command must BOTH compile those
// control tests AND exclude this scaffolding from the production count, which a
// tag cannot do in one command. Instead the honest coverage profile DROPS this
// file's lines before the floor is computed (the `go-coverage` job in
// .github/workflows/e2e.yml filters `internal/dial/testsupport.go` out of
// cover.out): it is test scaffolding, not production surface, so counting it
// would pad the number. The exclusion is the mechanism the measured baseline
// endorses ("honest, not gaming"). Keep this file's contents test-support only;
// nothing in production imports these methods (the production dial path uses
// Handshake + DriveExec).

package dial

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/wire"
	"github.com/coder/websocket"
)

// This file is TEST-SUPPORT ONLY. It adds NO new wire behavior and NO new wire
// variant: it surfaces the EXISTING single-writer text-frame primitives
// (writeText/readText) so a test can drive frames OUTSIDE the single-exec
// DriveExec loop — specifically the concurrent second-attach, where one
// connection must send a bare ProcessConnection (a reattach msg2) and then read
// the server's attach outcome (ProcessAlreadyAttached) without DriveExec's
// stdio dispatch in the way.
//
// Every method here marshals/decodes a shape the frozen exec-channel contract
// already defines. The single-writer discipline is preserved: the caller's
// goroutine owns every write, and no method spawns a second writer. These
// methods are exported so the control-package integration test (a different Go
// package) can call them; they exist for tests, not for production callers,
// which use Handshake + DriveExec.

// Mint presents msg1 (the compact JWS) as a single text frame, exactly as the
// production Handshake does, without sending msg2 or reading the capabilities
// reply. It lets a test stage the auth frame and then drive msg2 / reads itself.
// The minted token is never logged nor embedded in an error (the same secrecy
// discipline as Handshake). TEST-SUPPORT ONLY: it adds no wire behavior.
func (c *Channel) Mint(ctx context.Context) error {
	token, err := c.minter.Mint(handshakeTTL)
	if err != nil {
		// The token never reaches this error; only the mint failure does.
		return fmt.Errorf("dial: mint session token: %w", err)
	}
	if err := c.writeText(ctx, []byte(token)); err != nil {
		return fmt.Errorf("dial: write msg1: %w", err)
	}
	return nil
}

// SendBare marshals v to JSON and writes it as a single text frame via the
// existing single-writer path. It sends a BARE, externally-untagged object — the
// shape msg2 takes (a ProcessConnection with no {"ProcessConnection":...}
// wrapper). A reattach msg2 is exactly a wire.ProcessConnection with no
// CreateReq, which a test passes here. TEST-SUPPORT ONLY: no new wire behavior;
// it writes a frame the contract already defines.
func (c *Channel) SendBare(ctx context.Context, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("dial: marshal bare frame: %w", err)
	}
	if err := c.writeText(ctx, b); err != nil {
		return fmt.Errorf("dial: write bare frame: %w", err)
	}
	return nil
}

// SendClient marshals a wire.ClientMessage (a single-key tagged union) and
// writes it as one text frame. It drives a client control frame (e.g. Detach)
// outside DriveExec. TEST-SUPPORT ONLY.
func (c *Channel) SendClient(ctx context.Context, msg wire.ClientMessage) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("dial: marshal client message: %w", err)
	}
	if err := c.writeText(ctx, b); err != nil {
		return fmt.Errorf("dial: write client message: %w", err)
	}
	return nil
}

// ReadServer reads one text frame and decodes it through the wire.ServerMessage
// union, returning the parsed message. A binary frame where a control frame is
// required is a protocol error (out-of-band binary), wrapping ErrProtocol, the
// same as readText enforces. The read is bounded by ctx. TEST-SUPPORT ONLY: it
// decodes a frame the contract already defines; it adds no wire behavior.
func (c *Channel) ReadServer(ctx context.Context) (wire.ServerMessage, error) {
	data, err := c.readText(ctx)
	if err != nil {
		return wire.ServerMessage{}, err
	}
	var sm wire.ServerMessage
	if err := json.Unmarshal(data, &sm); err != nil {
		return wire.ServerMessage{}, fmt.Errorf("%w: server frame is not a ServerMessage: %v", ErrProtocol, err)
	}
	return sm, nil
}

// ReadFrame reads one raw frame (text or binary) and returns its WebSocket
// message type and bytes, bounded by ctx. It surfaces the channel's existing
// bounded read so a test can consume the announce -> binary stdio discipline
// (an ExpectStdOut text announce followed by one binary stdout frame) outside
// DriveExec — needed by the reattach-resume e2e, which must read the post-
// reattach stdout while also distinguishing the AttachedToProcess control frame.
// TEST-SUPPORT ONLY: it reads a frame the contract already defines; no new wire
// behavior.
func (c *Channel) ReadFrame(ctx context.Context) (websocket.MessageType, []byte, error) {
	return c.readFrame(ctx)
}
