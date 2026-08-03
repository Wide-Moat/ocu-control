// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package dial

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/wire"
)

// handshakeTTL is the lifetime requested for the per-dial Session JWT. The
// minter clamps it to its own hard cap (60 min, AUTH-04); this value keeps the
// token short-lived for a single exec.
const handshakeTTL = 5 * time.Minute

// Handshake performs the frozen prod handshake verbatim and returns once the
// server has acknowledged with ConnectionCapabilities.
//
// Sequence (all bounded by ctx):
//  1. msg1 (text): the compact JWS minted by the Channel's Minter. The token's
//     first byte is 'e' (the guest's prod dispatch byte); it is written exactly
//     as minted — no JSON wrapping, no quoting — and never logged.
//  2. msg2 (text): the BARE ProcessConnection object (process_id, optional
//     create_req, optional expected_container_name), marshalled directly — NOT
//     externally tagged (no {"ProcessConnection":...} wrapper).
//  3. read one text frame, parse it through the wire.ServerMessage union, and
//     assert SEMANTICALLY that it is ConnectionCapabilities. Each negotiated bit
//     (supports_traces, supports_compression) may be true ONLY when THIS dial
//     advertised the matching flag (want_trace_events / accept_compression); a true
//     reply for a capability the client never advertised is a hard ErrProtocol close
//     (the asymmetric-capability downgrade-confusion guard, T-17-02). Key order in
//     the reply is a serializer detail and is never byte-compared.
//
// A non-ConnectionCapabilities reply, a malformed frame, or a binary frame
// where text is required is a protocol error (wrapping ErrProtocol).
func (c *Channel) Handshake(ctx context.Context, conn wire.ProcessConnection) error {
	token, err := c.minter.Mint(handshakeTTL)
	if err != nil {
		// The token never reaches this error; only the mint failure does.
		return fmt.Errorf("dial: mint session token: %w", err)
	}

	// msg1: the compact JWS, exactly as minted (text frame, first byte 'e').
	if err := c.writeText(ctx, []byte(token)); err != nil {
		return classifyHandshakeWriteError("write msg1", err)
	}

	// msg2: the BARE ProcessConnection object (not externally tagged).
	//
	// Normalize a nil CreateReq.Args before marshaling: the frozen schema lists
	// args as REQUIRED and typed as an array, so a command with no arguments is an
	// EMPTY array, never null/absent. A Go nil slice marshals to JSON null (the
	// field has no omitempty), which the guest rejects at deserialization (its
	// args is a non-defaulted Vec<String>): the guest would close the connection
	// before ConnectionCapabilities, surfacing as a pre-capabilities refusal. The
	// normalization runs on a COPY (CreateReq is a pointer; mutating it would be a
	// caller-visible side effect) so the wire frame always carries args:[] for the
	// no-args case while the caller's struct is untouched. This emits a
	// contract-legal frame for every dial caller (centralizing the per-call guard
	// callers previously applied); it changes only the host-emitted JSON for the
	// no-args case (null -> []), not the wire contract.
	conn = normalizeConnArgs(conn)
	// Compression advertisement (FID-01): the default-OFF Channel option is the
	// single go-live switch. When this dial opted in (WithCompression), the msg2
	// ProcessConnection carries accept_compression=true so the guest may negotiate
	// compression on; otherwise the field is left as the caller set it (normally
	// absent/false), so a default channel advertises no compression and the guest
	// answers supports_compression=false — the byte-for-byte non-regression path.
	// conn is already a normalize COPY, so setting the field here never mutates the
	// caller's struct.
	if c.acceptCompression {
		accept := true
		conn.AcceptCompression = &accept
	}
	// Trace advertisement (FID-01), symmetric to compression: the default-OFF
	// Channel option is the single go-live switch. When this dial opted in
	// (WithTraces), the msg2 ProcessConnection carries want_trace_events=true so the
	// guest may negotiate ##TRACE##-derived TraceEvent emission on; otherwise the
	// field is left as the caller set it (normally absent/false), so a default
	// channel advertises no traces and the guest answers supports_traces=false — the
	// non-regression path. conn is already a normalize COPY, so setting the field
	// here never mutates the caller's struct.
	if c.acceptTraces {
		want := true
		conn.WantTraceEvents = &want
	}
	connJSON, err := json.Marshal(conn)
	if err != nil {
		return fmt.Errorf("dial: marshal ProcessConnection: %w", err)
	}
	if err := c.writeText(ctx, connJSON); err != nil {
		return classifyHandshakeWriteError("write msg2", err)
	}

	// Read the capabilities reply and assert it semantically.
	reply, err := c.readText(ctx)
	if err != nil {
		// Distinguish a HANG from a REFUSAL. A context deadline (the guest never
		// answered) propagates as context.DeadlineExceeded so a caller's
		// negative-auth assertion can fail a hang rather than score it as
		// rejected. Any other read failure here is the peer closing BEFORE
		// emitting capabilities — the observable shape of every pre-capabilities
		// auth/binding refusal — so it is classified as ErrAuthRefused (a
		// host-driver classification of the close; no wire message). readText also
		// rejects an out-of-band binary frame as ErrProtocol, which is preserved.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return fmt.Errorf("dial: read capabilities: %w", err)
		}
		if errors.Is(err, ErrProtocol) {
			return fmt.Errorf("dial: read capabilities: %w", err)
		}
		return fmt.Errorf("%w: %v", ErrAuthRefused, err)
	}
	var sm wire.ServerMessage
	if err := json.Unmarshal(reply, &sm); err != nil {
		return fmt.Errorf("%w: capabilities frame is not a ServerMessage: %v", ErrProtocol, err)
	}
	caps := sm.ConnectionCapabilities
	if caps == nil {
		return fmt.Errorf("%w: first server frame is not ConnectionCapabilities", ErrProtocol)
	}
	// Semantic assertion (do NOT byte-compare key order).
	//
	// supports_traces: accept true ONLY when THIS dial advertised want_trace_events,
	// symmetric to the compression guard below. The negotiation contract is symmetric
	// — the guest answers supports_traces=true iff the client advertised
	// want_trace_events=true — so a server answering true WITHOUT the client ever
	// asking is a downgrade-confusion / spoofing vector (T-17-02), NOT a benign
	// capability. It stays a HARD ErrProtocol close (this guard must never be
	// weakened): a peer cannot push trace emission onto a channel that did not opt in.
	// When the dial DID advertise, a true reply negotiates TraceEvent emission on; a
	// false reply (the guest declined or does not support it) leaves the channel
	// trace-free, which is always legal.
	if caps.SupportsTraces && !c.acceptTraces {
		return fmt.Errorf("%w: server answered supports_traces=true without the client advertising want_trace_events (asymmetric capability)", ErrProtocol)
	}
	// supports_compression: accept true ONLY when THIS dial advertised
	// accept_compression. The negotiation contract is symmetric — the guest answers
	// supports_compression=true iff the client advertised accept_compression=true —
	// so a server answering true WITHOUT the client ever asking is a
	// downgrade-confusion / spoofing vector (T-17-02), NOT a benign capability. It
	// stays a HARD ErrProtocol close (this guard must never be weakened): a peer
	// cannot push compression onto a channel that did not opt in. When the dial DID
	// advertise, a true reply activates the symmetric zstd codec on the exec path;
	// a false reply (the guest declined or does not support it) leaves the channel
	// uncompressed, which is always legal.
	if caps.SupportsCompression && !c.acceptCompression {
		return fmt.Errorf("%w: server answered supports_compression=true without the client advertising accept_compression (asymmetric capability)", ErrProtocol)
	}
	// Record the negotiated outcomes: each capability is active iff advertised AND
	// the guest answered true. DriveExec reads compressionActive to gate the stdio
	// codec; tracesActive surfaces the negotiated traces bit to the caller. Neither
	// can be true without the matching advertisement — the asymmetric cases above are
	// hard ErrProtocol closes, so reaching here means any true reply was solicited.
	c.compressionActive = caps.SupportsCompression
	c.tracesActive = caps.SupportsTraces

	// Raise the inbound read limit to the compressed-frame wire bound ONLY on the
	// compression-ON path (Finding 1). zstd does not shrink incompressible input, so
	// a full MAX_FRAME chunk of already-compressed/encrypted/random child output
	// encodes to a frame LARGER than ReadLimitBytes (up to compressedFrameBound). The
	// websocket read limit is the wire-frame bound the library enforces BEFORE the
	// stdio codec runs, so under compression it must admit the larger compressed
	// frame; the codec's output cap still bounds the DECOMPRESSED size at
	// maxDecompressedFrame (the zip-bomb guard, unchanged). The OFF path keeps the
	// exact ReadLimitBytes (32768) wire bound set at Dial — the uncompressed wire
	// bound is never loosened.
	if c.compressionActive {
		c.conn.SetReadLimit(compressedFrameBound)
	}
	return nil
}

// classifyHandshakeWriteError maps a failure WRITING a pre-capabilities
// handshake frame (msg1 or msg2) into the same rejection taxonomy the
// capabilities READ uses, closing a race window that would otherwise leak a raw
// transport error.
//
// A pre-capabilities refusal is observable in TWO shapes, not one. The guest
// reads msg1, rejects the credential (expired, wrong sub, forged/none-alg,
// plain-JSON downgrade, wrong key) or rejects the msg2 binding, and CLOSES. If
// the host has already finished writing msg2, it observes the close on the
// capabilities READ (handled above) and classifies it ErrAuthRefused. But if the
// guest closes FASTER than the host finishes writing — the host is still
// flushing msg2 (or even msg1) when the peer's FIN/RST arrives — the host
// observes the close as a WRITE error ("broken pipe"/"connection reset"), not a
// read error. Both are the SAME security event: the peer refused before
// capabilities. Classifying only the read-close path as ErrAuthRefused and
// leaking the write-close path as a raw error makes the refusal class
// nondeterministic, dependent purely on the write/close race the host does not
// control — a caller's negative-auth assertion (errors.Is(err, ErrAuthRefused))
// would pass or fail by timing alone.
//
// The rule mirrors the read path exactly: a context deadline or cancellation is
// a HANG (the write blocked, the peer never consumed it), propagated as-is so a
// hang is never mis-scored as a rejection; ANY other write failure is the peer's
// pre-capabilities close, classified ErrAuthRefused. This is a host-driver
// classification of the close, identical in meaning to the read-close
// classification; it adds no wire message.
func classifyHandshakeWriteError(stage string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("dial: %s: %w", stage, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrAuthRefused, stage, err)
}

// normalizeConnArgs returns a copy of conn in which a spawn request's nil Args
// slice is replaced by a non-nil empty slice, so msg2 marshals "args":[] rather
// than the contract-illegal "args":null for a command with no arguments. The
// frozen schema requires args to be a (possibly empty) array; a nil Go slice
// would emit null, which the guest rejects before ConnectionCapabilities. The
// copy keeps CreateReq (a pointer the caller still holds) free of any mutation:
// only the marshaled frame differs, never the caller's struct. A reattach (nil
// CreateReq) or an already-non-nil Args is returned unchanged.
func normalizeConnArgs(conn wire.ProcessConnection) wire.ProcessConnection {
	if conn.CreateReq == nil || conn.CreateReq.Args != nil {
		return conn
	}
	cr := *conn.CreateReq // shallow copy: Args is the only field we rewrite
	cr.Args = []string{}
	conn.CreateReq = &cr
	return conn
}
