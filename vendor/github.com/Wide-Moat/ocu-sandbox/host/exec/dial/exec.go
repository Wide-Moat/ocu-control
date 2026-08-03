// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package dial

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/wire"
	"github.com/coder/websocket"
)

// stream identifies which stdio sink a pending announce refers to.
type stream int

const (
	streamNone stream = iota
	streamOut
	streamErr
)

// DriveExec drives one exec to completion against a guest that has already
// completed the handshake. It reads ServerMessage frames in a loop, dispatching
// strictly on the WebSocket message type:
//
//   - A text frame is parsed through wire.ServerMessage and matched on its single
//     set tag.
//   - A binary frame is the payload for the most recent ExpectStdOut/ExpectStdErr
//     announce, written to stdout or stderr respectively. A binary frame with no
//     preceding announce is an out-of-band protocol error (ErrProtocol).
//
// The announce tag immediately precedes exactly one binary frame; after the
// binary frame the announce is consumed. StdOutEOF/StdErrEOF end the
// corresponding stream. The loop continues until ProcessExited
// (drain-before-exit: it does not stop on the first idle frame) and returns
// ProcessExited.Code as the exec exit code.
//
// Every read is bounded by ctx, so a wedged peer yields a typed error rather
// than a hang. In addition to the caller's ctx (which carries the Manager's
// execChannelTimeout total cap), each individual read is bounded by an
// idle-reset deadline of c.idleWindow re-armed every iteration (LIVE-02 host
// direction, D-02a): a received server frame makes the read return and the next
// iteration re-arms a fresh idle window, so a stream kept busy by periodic
// server frames stays open while a silent stream is cut at the idle window with
// a typed deadline error via classifyReadError. The idle-reset deadline measures
// the GAP between frames, not total lifetime; it is layered on top of the total
// cap, not a replacement for it. An oversized binary frame (> ReadLimitBytes)
// trips websocket.ErrMessageTooBig from the library and is surfaced as a
// protocol error. A malformed control frame (not a valid single-key
// ServerMessage, or a known tag the driver does not expect at that point) is a
// protocol error.
//
// For the lifetime of the drive a keepalive ticker emits the wire's existing
// client->server KeepAlive frame every c.keepAlive (LIVE-02 guest direction):
// the guest closes a channel whose READ half is silent for one guest idle
// window, so a long but quiet exec (no stdin, output flowing server->host only)
// would otherwise be killed by the guest's own deadline. A non-positive
// c.keepAlive disables the ticker.
//
// When stdin is non-nil the host ALSO pumps it to the guest: a second goroutine
// runs PumpStdIn(stdin), emitting the frozen ExpectStdIn -> binary -> StdInEOF
// frames (PTY-02) over the SAME channel. With both the keepalive ticker and the
// pump writing concurrently there are two writer goroutines; the channel's
// writeMu serializes their writes so coder/websocket's one-writer-at-a-time rule
// holds. Both writer goroutines are stopped and JOINED before the read loop's
// own deferred write (the protocol-error close), so that close is never racing a
// concurrent writer (single-writer-at-a-time discipline). When stdin is nil the
// behaviour is byte-identical to a plain drive: no pump goroutine, no
// ExpectStdIn/StdInEOF frame is ever emitted.
func (c *Channel) DriveExec(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) (code uint8, err error) {
	// Build the per-message zstd codec ONLY when compression was negotiated on for
	// this channel (FID-01). Off (the default), codec stays nil and the stdio path
	// is byte-for-byte uncompressed — no codec is constructed and the read loop and
	// stdin pump take their verbatim paths. The codec (decoder + encoder) is closed
	// when the drive returns, after the writers are joined.
	var codec *stdioCodec
	if c.compressionActive {
		codec, err = newStdioCodec()
		if err != nil {
			return 0, err
		}
		defer codec.close()
	}

	// Stop and JOIN every concurrent writer (the keepalive ticker and, when
	// stdin is supplied, the stdin pump) before this function performs any write
	// of its own (the deferred CloseProtocolError below) so there is never a
	// concurrent second writer at close time. Each Done channel is closed once
	// its goroutine has fully returned; a nil/disabled writer makes the join a
	// no-op via an already-closed sentinel.
	kaCtx, stopKeepAlive := context.WithCancel(ctx)
	keepAliveDone := c.startKeepAlive(kaCtx)

	stdinCtx, stopStdin := context.WithCancel(ctx)
	stdinDone := c.startStdInPump(stdinCtx, stdin, codec)

	joinWriters := func() {
		stopKeepAlive()
		stopStdin()
		<-keepAliveDone
		<-stdinDone
	}

	// On a contract breach by the peer, signal a protocol-error close so the
	// peer observes a clean close rather than a dropped socket (T-03-10/-11).
	// The close itself is best-effort; the returned error is the source of truth.
	// Joining the writers first guarantees the close is the sole writer.
	defer func() {
		joinWriters()
		if errors.Is(err, ErrProtocol) {
			_ = c.CloseProtocolError("exec-channel protocol error")
		}
	}()

	var pending stream // which stream the next binary frame belongs to

	for {
		typ, data, err := c.readFrame(ctx)
		if err != nil {
			return 0, c.classifyReadError(err)
		}

		switch typ {
		case websocket.MessageBinary:
			sink, err := sinkFor(pending, stdout, stderr)
			if err != nil {
				return 0, err
			}
			// When compression is negotiated, every inbound stdio binary frame is
			// ONE self-contained zstd frame: decode it (bounded window + bounded
			// output) back to the child bytes before writing to the sink. The
			// websocket read limit already bounds the COMPRESSED frame at
			// ReadLimitBytes; the codec's output cap bounds the DECOMPRESSED size,
			// closing the zip-bomb gap. A decode error is a fail-closed ErrProtocol
			// teardown, never a partial write. Off, codec is nil and data is written
			// verbatim — byte-for-byte today.
			payload := data
			if codec != nil {
				decoded, derr := codec.decode(data)
				if derr != nil {
					return 0, derr
				}
				payload = decoded
			}
			if _, werr := sink.Write(payload); werr != nil {
				return 0, fmt.Errorf("dial: write stdio sink: %w", werr)
			}
			// The announce is consumed by exactly one binary frame.
			pending = streamNone

		case websocket.MessageText:
			tag, perr := singleKeyTag(data)
			if perr != nil {
				return 0, perr
			}
			var sm wire.ServerMessage
			if uerr := json.Unmarshal(data, &sm); uerr != nil {
				return 0, fmt.Errorf("%w: ServerMessage is not valid JSON: %v", ErrProtocol, uerr)
			}
			if sm == (wire.ServerMessage{}) {
				// The frame carried a single tag that matches no v1 union
				// field: a future/v2 message. The contract requires unknown
				// variants to be ignored, not to break the drive (forward
				// compatibility) — skip and keep reading.
				continue
			}
			code, terminal, herr := c.handleServerMessage(tag, sm, &pending)
			if herr != nil {
				return 0, herr
			}
			if terminal {
				return code, nil
			}

		default:
			return 0, fmt.Errorf("%w: unknown WebSocket message type %v", ErrProtocol, typ)
		}
	}
}

// keepAliveFrame is the wire's existing client->server KeepAlive control frame,
// marshaled once: {"KeepAlive":null}. It is an EXISTING variant of the frozen
// ClientMessage union (no new wire shape); the host writes it on a cadence to
// keep the guest's read-half idle deadline from cutting a quiet exec.
var keepAliveFrame = mustMarshalKeepAlive()

func mustMarshalKeepAlive() []byte {
	b, err := json.Marshal(wire.ClientMessage{KeepAlive: &wire.Null{}})
	if err != nil {
		// Marshaling a fixed, well-formed union value cannot fail; a panic here
		// would mean the wire package itself is broken at build time.
		panic(fmt.Sprintf("dial: marshal KeepAlive frame: %v", err))
	}
	return b
}

// startKeepAlive launches the keepalive ticker goroutine and returns a channel
// that is closed once the goroutine has fully returned (so DriveExec can JOIN it
// before doing any write of its own, preserving the single-writer discipline).
//
// The goroutine writes keepAliveFrame as a text frame every c.keepAlive until
// ctx is cancelled (the drive ended) or a write fails (the peer is gone — the
// read loop will surface the authoritative error). A non-positive c.keepAlive
// disables keepalives: the returned channel is already closed, so the join is a
// no-op and no second writer ever exists.
func (c *Channel) startKeepAlive(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	if c.keepAlive <= 0 {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		t := time.NewTicker(c.keepAlive)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// Bound the write by ctx; on cancel or peer loss the write
				// returns an error and the ticker winds down. The error is
				// intentionally discarded: the read loop owns the authoritative
				// failure, and a lost KeepAlive is self-correcting on the next
				// tick.
				if err := c.writeText(ctx, keepAliveFrame); err != nil {
					return
				}
			}
		}
	}()
	return done
}

// startStdInPump launches the host stdin pump goroutine and returns a channel
// closed once the goroutine has fully returned (so DriveExec can JOIN it before
// doing any write of its own, preserving the one-writer-at-a-time discipline
// against the deferred protocol-error close).
//
// A nil stdin reader (the common case: no stdin source) disables the pump: the
// returned channel is already closed, the join is a no-op, and NO ExpectStdIn /
// StdInEOF frame is ever emitted (the drive is byte-identical to today). When
// stdin is non-nil the goroutine runs PumpStdIn, which emits the frozen
// ExpectStdIn -> binary -> StdInEOF frames over the writeMu-serialized write
// path. A pump error is intentionally discarded here: the read loop owns the
// authoritative drive outcome, and a stdin write failure means the peer is gone,
// which the read half surfaces. The goroutine returns when PumpStdIn finishes
// (src EOF -> StdInEOF sent) or when ctx is cancelled (the drive ended).
func (c *Channel) startStdInPump(ctx context.Context, stdin io.Reader, codec *stdioCodec) <-chan struct{} {
	done := make(chan struct{})
	if stdin == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		// PumpStdIn is ctx-bounded; on drive end (ctx cancel) or peer loss it
		// returns and the goroutine winds down. The error is the read loop's to
		// own, so it is not propagated from here. codec (non-nil only when
		// compression is negotiated) compresses each stdin chunk symmetrically with
		// the inbound decode; nil leaves stdin byte-for-byte uncompressed.
		_ = c.PumpStdIn(ctx, stdin, codec)
	}()
	return done
}

// readFrame reads one server frame under a FRESH idle-reset deadline (D-02a): it
// derives a child context carrying c.idleWindow and reads under it, so a silent
// gap longer than the idle window trips context.DeadlineExceeded while any
// received frame returns and lets the next iteration re-arm a new window. The
// child context is cancelled before returning so it never outlives the read. The
// parent ctx (with the Manager's execChannelTimeout total cap) still bounds the
// whole drive — whichever deadline fires first wins. A non-positive idleWindow
// disables the idle-reset bound and falls back to the parent ctx alone (so an
// unconfigured Channel still behaves as a plain ctx-bounded read).
func (c *Channel) readFrame(ctx context.Context) (websocket.MessageType, []byte, error) {
	if c.idleWindow <= 0 {
		return c.conn.Read(ctx)
	}
	readCtx, cancel := context.WithTimeout(ctx, c.idleWindow)
	defer cancel()
	return c.conn.Read(readCtx)
}

// singleKeyTag enforces the union's single-key invariant on the decode side and
// returns the lone tag name: the schema mandates exactly one tag per frame
// (minProperties:1, maxProperties:1). A zero-key or multi-key object is a
// malformed ServerMessage (N6) and a protocol error, caught before the lenient
// field decode (which would otherwise silently accept the first matching tag of
// a two-key frame).
func singleKeyTag(data []byte) (string, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("%w: ServerMessage is not a JSON object: %v", ErrProtocol, err)
	}
	if len(probe) != 1 {
		return "", fmt.Errorf("%w: ServerMessage must carry exactly one tag, got %d", ErrProtocol, len(probe))
	}
	for tag := range probe {
		return tag, nil
	}
	return "", nil // unreachable: len == 1
}

// sinkFor returns the io.Writer the next binary frame must be written to, given
// the pending announce. A binary frame with no preceding announce is an
// out-of-band protocol error (N7).
func sinkFor(pending stream, stdout, stderr io.Writer) (io.Writer, error) {
	switch pending {
	case streamOut:
		return stdout, nil
	case streamErr:
		return stderr, nil
	default:
		return nil, fmt.Errorf("%w: binary frame with no preceding ExpectStdOut/ExpectStdErr announce", ErrProtocol)
	}
}

// classifyReadError maps a coder/websocket read error to a typed dial error. An
// oversized-frame trip (the read returns an error wrapping
// websocket.ErrMessageTooBig, and the connection is closed with
// StatusMessageTooBig) becomes a protocol error; any other read failure
// (deadline, transport close) is wrapped as-is so the caller sees the cause.
func (c *Channel) classifyReadError(err error) error {
	if errors.Is(err, websocket.ErrMessageTooBig) ||
		websocket.CloseStatus(err) == websocket.StatusMessageTooBig {
		// Report the limit actually in force: a compression-negotiated channel
		// admits a wire frame up to the zstd worst-case expansion bound.
		limit := ReadLimitBytes
		if c.compressionActive {
			limit = compressedFrameBound
		}
		return fmt.Errorf("%w: inbound frame exceeded the %d-byte read limit", ErrProtocol, limit)
	}
	return fmt.Errorf("dial: read exec frame: %w", err)
}

// handleServerMessage acts on one parsed ServerMessage frame. It returns the
// exit code and terminal=true when the frame is ProcessExited; otherwise it
// updates the pending-announce state. A known v1 tag that is out of place for
// the exec drive is a protocol error naming the tag; unknown (v2) tags never
// reach here — the read loop skips them for forward compatibility.
func (c *Channel) handleServerMessage(tag string, sm wire.ServerMessage, pending *stream) (code uint8, terminal bool, err error) {
	m := sm
	switch {
	case m.ProcessCreated != nil:
		// Acknowledged; no stdio yet. Nothing to do.
		return 0, false, nil

	case m.ExpectStdOut != nil:
		if *pending != streamNone {
			return 0, false, fmt.Errorf("%w: ExpectStdOut announce while a prior announce is unconsumed", ErrProtocol)
		}
		*pending = streamOut
		return 0, false, nil

	case m.ExpectStdErr != nil:
		if *pending != streamNone {
			return 0, false, fmt.Errorf("%w: ExpectStdErr announce while a prior announce is unconsumed", ErrProtocol)
		}
		*pending = streamErr
		return 0, false, nil

	case m.StdOutEOF != nil:
		*pending = streamNone
		return 0, false, nil

	case m.StdErrEOF != nil:
		*pending = streamNone
		return 0, false, nil

	case m.SignalSent != nil:
		// The guest's acknowledgement that a host SendSignal was delivered (the
		// frozen SignalSent tag). It is non-terminal: a signalled child still ends
		// the drive via ProcessExited (e.g. exit 143 for SIGTERM). The drive
		// acknowledges and keeps reading until the terminal frame.
		return 0, false, nil

	case m.AttachedToProcess != nil:
		// A reattach acknowledgement (the frozen AttachedToProcess tag): a host
		// that reattaches a detached process drives the resumed stream through the
		// same loop. It is non-terminal — live stdio and the eventual
		// ProcessExited follow. Tolerated so a reattach-resume drive does not trip
		// the unhandled-tag guard.
		return 0, false, nil

	case m.ProcessExited != nil:
		return m.ProcessExited.Code, true, nil

	default:
		// A KNOWN v1 tag the tracer-slice drive does not handle (failure and
		// limit terminals such as FailedToStart, InfraError, ProcessTimedOut,
		// ShuttingDown, ...) ends the drive with a typed error naming the tag.
		// Phase 4/5 extend the handled set; unknown v2 tags are skipped in the
		// read loop and never reach this point.
		return 0, false, fmt.Errorf("%w: unhandled ServerMessage tag %q during exec drive", ErrProtocol, tag)
	}
}
