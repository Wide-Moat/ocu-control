// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package dial is the host side of the exec channel: a coder/websocket dialer
// that speaks the frozen handshake verbatim and drives one exec over the wire
// union, propagating the process exit code.
//
// Frame discipline. Control frames (the compact JWS, the ProcessConnection, and
// every ServerMessage/ClientMessage union tag) are WebSocket text frames; stdio
// payload is binary. The driver dispatches strictly on the WebSocket message
// type returned by Read: a text frame is parsed through wire.ServerMessage, a
// binary frame is the payload for the most recent ExpectStdOut/ExpectStdErr
// announce. An announce immediately precedes exactly one binary frame.
//
// Single-writer discipline. coder/websocket permits one concurrent reader and
// one writer. This package keeps a single logical writer: the handshake and the
// exec drive run on one goroutine that owns every Write, so the
// msg1 -> msg2 -> drive ordering can never be reordered. No second goroutine
// writes to the connection.
//
// Bounds. The dialer read limit is set to 32 KiB (NFR-SEC-46): an inbound
// message larger than the limit trips a typed error from the websocket library
// and the connection is closed, so a malicious or buggy peer cannot force
// unbounded buffering. Every read and write is bounded by a context with a
// timeout, so no operation blocks indefinitely.
//
// Secrecy. The minted Session JWT (msg1) is never logged and never embedded in
// an error string; this mirrors the guest's slog discipline.
package dial

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// ReadLimitBytes is the maximum size of a single inbound WebSocket message
// (NFR-SEC-46). It bounds both control frames and stdio binary frames; an
// oversized frame trips websocket.ErrMessageTooBig and closes the connection.
const ReadLimitBytes = 32768

// execIdleWindow is the production default for the exec-channel idle-reset read
// deadline (LIVE-02 host direction, D-02a). It is the maximum tolerated GAP
// between two received server frames, NOT a total cap on the exec: every
// received server frame re-arms it (any frame counts as activity), so a
// legitimately quiet-but-live exec stays open as long as the guest emits
// anything within the window, while a guest that goes fully silent is cut at the
// window with a typed deadline error via classifyReadError.
//
// The frozen wire has no server->host KeepAlive frame, so this is an
// activity-reset deadline over the existing server frames, not a new wire
// message. The window is generous (a quiet-but-live exec is rare and any output
// re-arms it) yet bounds a hung guest; it is distinct from and layered on top of
// the Manager's execChannelTimeout total cap (D-02a permits a cap on top).
//
// It is a field on the Channel (defaulting to this const in Dial/DialUDS) so a
// test can inject a short window through the same seam the production path uses.
const execIdleWindow = 60 * time.Second

// keepAliveInterval is the cadence at which DriveExec emits the wire's existing
// client->server KeepAlive frame for the lifetime of the drive (LIVE-02 guest
// direction). The guest arms an idle deadline on its READ half and closes a
// channel that goes silent for one guest idle window; a legitimately long but
// quiet exec (no stdin, no client control frames) would otherwise be killed by
// that deadline even while output streams server->host. The host therefore
// keeps the guest's read half active with a periodic KeepAlive.
//
// It is set to execIdleWindow/3 (20 s) so two consecutive lost/late KeepAlives
// still leave a frame inside the guest's idle window — a comfortable margin
// without chattiness. The frame already exists in the frozen contract
// ({"KeepAlive":null}); this adds NO wire variant, only a host write cadence.
// coder/websocket permits one concurrent reader and one writer, and DriveExec's
// read loop performs no writes, so a single keepalive writer goroutine running
// alongside the read loop respects the single-writer discipline.
//
// It is a field on the Channel (defaulting to this const in Dial/DialUDS) so a
// test can inject a short interval through the same seam as the idle window.
const keepAliveInterval = execIdleWindow / 3

// ErrProtocol marks a violation of the frozen exec-channel contract by the peer:
// a malformed control frame, an out-of-band binary frame, an unexpected frame
// type, or an oversized frame. It is the typed sentinel every contract breach
// wraps, so callers can match the class without string-matching.
var ErrProtocol = errors.New("dial: exec-channel protocol error")

// ErrAuthRefused marks a PRE-CAPABILITIES CLOSE by the peer: the connection
// closed before the guest emitted ConnectionCapabilities. This is the observable
// shape of every auth/binding refusal (expired token, wrong sub, wrong
// expected_container_name, plain-JSON downgrade, forged signature, alg:none,
// wrong verifying key) — the guest reads the credential and the
// ProcessConnection and then closes without acknowledging — whether the close
// arrives as a read-close (Handshake's capabilities read) or as a write-close
// (the guest closes faster than the host finishes flushing msg1/msg2;
// classifyHandshakeWriteError). It is a host-driver classification of the close,
// NOT a wire message: the frozen contract has no "rejected" frame; a refusal IS
// the pre-capabilities close.
//
// SCOPE — not an auth-ONLY signal. A pre-capabilities close has the SAME
// observable shape whether the cause is a credential rejection or a non-auth
// event the host cannot tell apart from the close alone: the guest dropping a
// connection under pre-auth handshake saturation, a handshake-deadline reap of a
// slow peer, a clean peer shutdown while awaiting msg2, or a transport fault
// breaking the pipe before the guest even evaluated the credential. All surface
// as ErrAuthRefused. A consumer must therefore read this sentinel as
// "refused-or-dropped before capabilities," NOT as a pure credential-attack
// indicator: an ErrAuthRefused spike can be a pre-auth DoS flood, not only forged
// credentials. (No such consumer exists today; the sentinel is matched only by
// the negative-auth tests, which assert the security postcondition — no
// capabilities, no exec — that holds for every cause above.)
//
// Handshake wraps the close in this sentinel so a caller can distinguish a
// pre-capabilities close (errors.Is(err, ErrAuthRefused)) from a
// malformed-but-present reply (ErrProtocol) and from a HANG
// (context.DeadlineExceeded / context.Canceled) — the last of which is never an
// ErrAuthRefused on either the read or the write path, so a wedged guest cannot
// be mis-scored as "refused".
var ErrAuthRefused = errors.New("dial: peer refused before capabilities")

// Minter mints the Session JWT presented as msg1. jwtmint.Signer satisfies it.
// The dialer depends on this narrow interface rather than the concrete signer so
// the handshake can be exercised without key custody in a test.
type Minter interface {
	// Mint returns the compact JWS Session JWT. ttl bounds the token lifetime;
	// the minter clamps it to its own hard cap. The returned token is never
	// logged by this package.
	Mint(ttl time.Duration) (string, error)
}

// Channel wraps a coder/websocket connection with the single-writer discipline
// the handshake and exec drive require. All writes happen on the goroutine that
// owns the Channel; no method spawns a second writer.
type Channel struct {
	conn   *websocket.Conn
	minter Minter
	// writeMu serializes every WebSocket write on the channel. The tracer-slice
	// design kept a single logical writer goroutine (the DriveExec read loop did
	// no writes; only the keepalive ticker wrote). The host stdin pump (PTY-02)
	// adds a SECOND concurrent writer goroutine alongside the keepalive ticker:
	// coder/websocket permits one concurrent reader and one concurrent writer, so
	// two writer goroutines must serialize. This mutex makes every text write
	// (writeText) and the stdin binary write mutually exclusive, so the single-
	// WRITER-at-a-time discipline holds even with the pump goroutine present. The
	// read loop never takes it (reads and writes may proceed concurrently), so it
	// does not serialize a write against a read.
	writeMu sync.Mutex
	// idleWindow is the exec-channel idle-reset read deadline (LIVE-02 host
	// direction, D-02a): the maximum tolerated gap between received server
	// frames in the DriveExec read loop. Dial/DialUDS set it to execIdleWindow;
	// a test injects a short window through the same field.
	idleWindow time.Duration
	// keepAlive is the cadence at which DriveExec emits the wire's existing
	// client->server KeepAlive frame to keep the guest's read-half idle deadline
	// from cutting a long but quiet exec (LIVE-02 guest direction). Dial/DialUDS
	// set it to keepAliveInterval; a test injects a short interval through the
	// same field. A non-positive value disables the keepalive ticker.
	keepAlive time.Duration
	// acceptCompression is the per-dial go-live switch for frame compression
	// (FID-01). It defaults to FALSE: a Channel built without WithCompression
	// advertises accept_compression=false (omitted) in msg2, the guest answers
	// supports_compression=false, and the stdio path is byte-for-byte uncompressed —
	// the non-regression default every existing caller (and the production manager)
	// observes. WithCompression flips it to true, so msg2 carries
	// accept_compression=true and the guest may negotiate compression on.
	acceptCompression bool
	// compressionActive is the NEGOTIATED outcome for this channel, set by Handshake
	// from the guest's ConnectionCapabilities reply: true ONLY when this dial
	// advertised accept_compression AND the guest answered supports_compression=true.
	// DriveExec reads it to gate the inbound stdio decode and outbound stdin encode;
	// false means the stdio path is byte-for-byte uncompressed. It is never set true
	// for a dial that did not advertise compression — that asymmetric case is a hard
	// ErrProtocol close in Handshake, never a silent activation.
	compressionActive bool
	// acceptTraces is the per-dial go-live switch for ##TRACE##-derived TraceEvent
	// frames (FID-01), symmetric to acceptCompression. It defaults to FALSE: a
	// Channel built without WithTraces advertises want_trace_events=false (omitted)
	// in msg2, the guest answers supports_traces=false, and no TraceEvent frame is
	// ever derived — the non-regression default. WithTraces flips it to true, so msg2
	// carries want_trace_events=true and the guest may negotiate trace emission on.
	acceptTraces bool
	// tracesActive is the NEGOTIATED traces outcome for this channel, set by
	// Handshake from the guest's ConnectionCapabilities reply: true ONLY when this
	// dial advertised want_trace_events AND the guest answered supports_traces=true.
	// It is never set true for a dial that did not advertise traces — that asymmetric
	// case is a hard ErrProtocol close in Handshake, never a silent activation,
	// mirroring the compression guard.
	tracesActive bool
}

// Option customizes a Channel at dial time. Options are applied in order after the
// Channel's production defaults are set, so a later option overrides an earlier
// one. The zero options (no Option passed) yield the byte-for-byte default channel
// every existing caller relies on.
type Option func(*Channel)

// WithCompression advertises accept_compression=true in the msg2 ProcessConnection,
// opting this dial into frame compression (FID-01). It is the single go-live switch:
// without it a Channel advertises no compression and the guest answers
// supports_compression=false, so nothing compresses. With it, the guest MAY answer
// supports_compression=true, and Handshake then activates the symmetric zstd codec
// on the exec stdio path. The negotiation still governs the outcome — advertising
// does not force compression on; the guest's reply does.
func WithCompression() Option {
	return func(c *Channel) { c.acceptCompression = true }
}

// CompressionActive reports whether frame compression was NEGOTIATED on for this
// channel (the dial advertised accept_compression AND the guest answered
// supports_compression=true). It is only meaningful after a successful Handshake.
func (c *Channel) CompressionActive() bool { return c.compressionActive }

// WithTraces advertises want_trace_events=true in the msg2 ProcessConnection,
// opting this dial into ##TRACE##-derived TraceEvent frames (FID-01), symmetric to
// WithCompression. Without it a Channel advertises no traces and the guest answers
// supports_traces=false, so no TraceEvent is ever derived. With it, the guest MAY
// answer supports_traces=true; the negotiation still governs the outcome —
// advertising does not force traces on; the guest's reply does.
func WithTraces() Option {
	return func(c *Channel) { c.acceptTraces = true }
}

// TracesActive reports whether TraceEvent emission was NEGOTIATED on for this
// channel (the dial advertised want_trace_events AND the guest answered
// supports_traces=true). It is only meaningful after a successful Handshake.
func (c *Channel) TracesActive() bool { return c.tracesActive }

// DialOptions are unused for the tracer slice but reserved so callers do not
// depend on a bare websocket.DialOptions at the boundary.
//
// Dial opens a WebSocket connection to addr (e.g. "ws://127.0.0.1:<port>/"),
// sets the read limit to ReadLimitBytes, and returns a Channel ready for the
// handshake. ctx bounds the dial; pass a context with a timeout so a wedged
// peer yields a typed error rather than a hang. minter supplies msg1 at
// handshake time.
func Dial(ctx context.Context, addr string, minter Minter, opts ...Option) (*Channel, error) {
	conn, _, err := websocket.Dial(ctx, addr, &websocket.DialOptions{})
	if err != nil {
		return nil, fmt.Errorf("dial: open %s: %w", addr, err)
	}
	conn.SetReadLimit(ReadLimitBytes)
	return newChannel(conn, minter, opts...), nil
}

// newChannel builds a Channel with the production defaults, then applies opts in
// order. Centralizing construction here keeps Dial and DialUDS from drifting in the
// defaults they set or the order options apply (the substrate is the only thing
// that differs between them).
func newChannel(conn *websocket.Conn, minter Minter, opts ...Option) *Channel {
	c := &Channel{
		conn:       conn,
		minter:     minter,
		idleWindow: execIdleWindow,
		keepAlive:  keepAliveInterval,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Close closes the underlying connection with a normal-closure status. It is
// safe to call after any handshake or drive outcome.
func (c *Channel) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "")
}

// CloseProtocolError closes the connection signalling a protocol violation. The
// driver uses it when it rejects a contract breach so the peer observes a clean
// close rather than a dropped socket.
func (c *Channel) CloseProtocolError(reason string) error {
	return c.conn.Close(websocket.StatusProtocolError, reason)
}

// readText reads one frame and asserts it is a text frame, returning the bytes.
// A binary frame where text is required is a protocol error (out-of-band
// binary). The read is bounded by ctx.
func (c *Channel) readText(ctx context.Context) ([]byte, error) {
	typ, data, err := c.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageText {
		return nil, fmt.Errorf("%w: expected a text control frame, got %s", ErrProtocol, typ)
	}
	return data, nil
}

// writeText writes one text frame, bounded by ctx. It is the single write path
// for control frames; the writeMu serializes it against the concurrent stdin
// binary write and any other writer goroutine (the keepalive ticker and, when
// the host pumps stdin, the pump goroutine) so coder/websocket's one-writer-at-a-
// time rule holds.
func (c *Channel) writeText(ctx context.Context, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.Write(ctx, websocket.MessageText, data)
}

// writeAnnouncedBinary writes a text announce frame IMMEDIATELY followed by its
// binary payload as ONE atomic critical section: writeMu is held across BOTH
// frames, so no concurrent writer (the keepalive ticker or a SendSignal) can
// inject a text frame BETWEEN the announce and the payload. This is the frozen
// contract's ExpectStdIn -> binary pairing: "the next binary frame carries stdin
// bytes; a non-binary follow-up is an error." Locking each frame separately
// would leave a window where a KeepAlive text frame lands after the announce and
// before the payload, making the announce's follow-up a TEXT frame — a contract
// violation a conformant peer is entitled to reject. Holding the lock across the
// pair closes that window.
func (c *Channel) writeAnnouncedBinary(ctx context.Context, announce, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.Write(ctx, websocket.MessageText, announce); err != nil {
		return err
	}
	return c.conn.Write(ctx, websocket.MessageBinary, payload)
}
