// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package dial

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/wire"
)

// StdInChunkBytes is the maximum size of a single stdin binary frame the host
// emits. It is pinned to ReadLimitBytes (32768, NFR-SEC-46) so a host stdin
// frame never exceeds the same bound the peer enforces on its inbound read
// limit: the pump chunks a source at this size, never larger.
const StdInChunkBytes = ReadLimitBytes

// expectStdInFrame is the wire's existing client->server ExpectStdIn control
// frame, marshaled once: {"ExpectStdIn":null}. It is an EXISTING variant of the
// frozen ClientMessage union (no new wire shape); the host writes it to announce
// that exactly one stdin binary frame follows, mirroring the server's
// ExpectStdOut/ExpectStdErr announce discipline.
var expectStdInFrame = mustMarshalClientNull(func(m *wire.ClientMessage) { m.ExpectStdIn = &wire.Null{} }, "ExpectStdIn")

// stdInEOFFrame is the wire's existing client->server StdInEOF control frame,
// marshaled once: {"StdInEOF":null}. It is an EXISTING variant of the frozen
// ClientMessage union (no new wire shape); the host writes it once when its
// stdin source ends, signalling end-of-input to the guest child (PTY-02, D-02).
var stdInEOFFrame = mustMarshalClientNull(func(m *wire.ClientMessage) { m.StdInEOF = &wire.Null{} }, "StdInEOF")

// mustMarshalClientNull marshals a single null-bodied ClientMessage tag once at
// package init, mirroring the mustMarshalKeepAlive precedent. set populates the
// lone tag; tag names it for the panic message. Marshaling a fixed, well-formed
// union value cannot fail, so a panic here would mean the wire package itself is
// broken at build time.
func mustMarshalClientNull(set func(*wire.ClientMessage), tag string) []byte {
	var m wire.ClientMessage
	set(&m)
	b, err := json.Marshal(m)
	if err != nil {
		panic(fmt.Sprintf("dial: marshal %s frame: %v", tag, err))
	}
	return b
}

// WriteStdIn writes one stdin payload to the guest: an ExpectStdIn text announce
// frame ({"ExpectStdIn":null}) immediately followed by exactly one binary frame
// carrying p, mirroring the server's announce->binary discipline. The RAW p MUST be
// no larger than StdInChunkBytes (the caller chunks; PumpStdIn does so); a larger
// payload is rejected before any frame is written so the contract bound is never
// breached on the wire. Both frames are bounded by ctx so a wedged peer yields a
// typed error rather than a hang.
//
// When codec is non-nil (compression negotiated on), the RAW chunk is compressed
// into ONE self-contained zstd frame before it is sent, mirroring the guest's
// inbound bounded decode (the guest decompresses under the same pinned window and
// output bound). The raw-size bound is checked BEFORE compression so the contract's
// per-chunk source bound is enforced on the plaintext (StdInChunkBytes = MAX_FRAME).
// The COMPRESSED frame is NOT necessarily smaller: zstd does not shrink
// incompressible input, so a full StdInChunkBytes chunk of already-compressed,
// encrypted, or random bytes encodes LARGER than StdInChunkBytes (up to
// compressedFrameBound). The guest's compression-ON read limit admits exactly that
// ceiling (Finding 1), so the larger compressed frame is within the negotiated wire
// bound; the guest still decompresses under its unchanged MAX_FRAME output bound.
// Off (codec nil) the chunk is sent byte-for-byte uncompressed under the
// StdInChunkBytes wire bound.
//
// Frame-atomic: the ExpectStdIn announce and its binary payload are written under
// a SINGLE writeMu critical section (writeAnnouncedBinary), so a concurrent writer
// goroutine (the keepalive ticker or a SendSignal) can NEVER inject a text frame
// between the announce and the payload. The frozen contract requires the frame
// immediately following ExpectStdIn to be the binary stdin chunk; holding the
// lock across the pair guarantees that even with the pump and the ticker running
// as separate writer goroutines over the same channel.
func (c *Channel) WriteStdIn(ctx context.Context, p []byte, codec *stdioCodec) error {
	if len(p) > StdInChunkBytes {
		return fmt.Errorf("dial: stdin chunk %d exceeds the %d-byte frame bound", len(p), StdInChunkBytes)
	}
	payload := p
	if codec != nil {
		payload = codec.encode(p)
	}
	if err := c.writeAnnouncedBinary(ctx, expectStdInFrame, payload); err != nil {
		return fmt.Errorf("dial: write ExpectStdIn announce + stdin payload: %w", err)
	}
	return nil
}

// SendStdInEOF writes exactly one {"StdInEOF":null} text frame (the frozen
// ClientMessage StdInEOF tag), signalling end-of-input to the guest child. It is
// bounded by ctx.
//
// Single-writer discipline: it writes through c.writeText and MUST be invoked on
// the goroutine that owns the channel's writes; it never spawns a second writer.
func (c *Channel) SendStdInEOF(ctx context.Context) error {
	if err := c.writeText(ctx, stdInEOFFrame); err != nil {
		return fmt.Errorf("dial: write StdInEOF: %w", err)
	}
	return nil
}

// PumpStdIn reads src in chunks of at most StdInChunkBytes and writes each chunk
// via WriteStdIn (one ExpectStdIn announce + one binary frame per chunk), then,
// when src returns io.EOF, writes exactly one StdInEOF frame and returns nil.
//
// A zero-length read that is NOT io.EOF is skipped (never emitted as an empty
// stdin frame the guest would treat as a no-op write); only io.EOF triggers
// SendStdInEOF. Any read error other than io.EOF, and any write error, is
// returned without sending StdInEOF.
//
// ctx-interruptible read: src.Read is a plain blocking call that ctx cancellation
// cannot itself interrupt (os.Stdin, an open pipe, or a network conn may block
// with neither data nor EOF). PumpStdIn therefore runs each read in a short-lived
// child goroutine and selects on ctx.Done(), so cancelling stdinCtx makes
// PumpStdIn RETURN promptly even while a read is parked — the parked read drains
// into a buffered channel and is discarded. This is what lets DriveExec's
// joinWriters (<-stdinDone) complete instead of wedging forever on a blocked
// reader, preserving the mandatory total-timeout safety cap. The pump is the sole
// writer of stdin frames; its writes go through the frame-atomic WriteStdIn.
func (c *Channel) PumpStdIn(ctx context.Context, src io.Reader, codec *stdioCodec) error {
	type readResult struct {
		n   int
		err error
	}
	buf := make([]byte, StdInChunkBytes)
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("dial: stdin pump: %w", err)
		}
		// Buffered so the read goroutine never blocks on send after we have
		// already returned on ctx cancellation (no goroutine leak on the send).
		done := make(chan readResult, 1)
		go func() {
			n, err := src.Read(buf)
			done <- readResult{n, err}
		}()

		var res readResult
		select {
		case <-ctx.Done():
			// Cancelled while a read is in flight: return immediately. The read
			// goroutine will eventually unblock (or stay parked on a dead reader)
			// and send into the buffered channel, which is then garbage-collected;
			// it never touches the channel again, so this is safe to abandon.
			return fmt.Errorf("dial: stdin pump: %w", ctx.Err())
		case res = <-done:
		}

		if res.n > 0 {
			if werr := c.WriteStdIn(ctx, buf[:res.n], codec); werr != nil {
				return werr
			}
		}
		if res.err != nil {
			if res.err == io.EOF {
				return c.SendStdInEOF(ctx)
			}
			return fmt.Errorf("dial: read stdin source: %w", res.err)
		}
		// A non-EOF zero read is a transient empty read (io.Reader is permitted
		// to return (0, nil)); skip it and read again rather than emit an empty
		// frame.
	}
}
