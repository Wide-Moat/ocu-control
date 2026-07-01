// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package controlrpc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// maxFrameBytes caps a single newline-delimited frame. The wire is one compact
// JSON object plus a '\n'; a guest that emits an unbounded no-newline frame
// cannot wedge the host read because the bounded reader stops at this cap and
// returns ErrProtocol rather than buffering without limit. 64 KiB is far above
// the largest legitimate v1 frame (a ControlError with a 256-rune message) while
// still bounding a hostile peer's memory pressure on the host.
const maxFrameBytes = 64 << 10

// readFrame reads one newline-delimited frame from r, bounded to maxFrameBytes.
// It returns the frame bytes WITHOUT the trailing newline. A frame that reaches
// the cap without a newline is ErrProtocol (the decoder is not wedged: the next
// call starts fresh on the underlying reader, though a caller treats a protocol
// error as fatal for the dial). A clean io.EOF before any byte is surfaced as
// io.EOF so a caller can distinguish a closed peer from a malformed frame.
func readFrame(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		if buf.Len() > maxFrameBytes {
			return nil, fmt.Errorf("%w: frame exceeds %d bytes", ErrProtocol, maxFrameBytes)
		}
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if buf.Len() == 0 {
					return nil, io.EOF
				}
				// A frame without a terminating newline is malformed: the peer closed
				// mid-frame or never delimited. Fail closed rather than accept a
				// possibly-truncated body.
				return nil, fmt.Errorf("%w: unterminated frame at EOF", ErrProtocol)
			}
			return nil, fmt.Errorf("controlrpc: read frame: %w", err)
		}
		if b == '\n' {
			// Enforce the cap on the body itself (the newline does not count toward
			// the payload budget) so a 64 KiB+'\n' frame is still rejected.
			if buf.Len() > maxFrameBytes {
				return nil, fmt.Errorf("%w: frame exceeds %d bytes", ErrProtocol, maxFrameBytes)
			}
			return buf.Bytes(), nil
		}
		buf.WriteByte(b)
	}
}

// writeFrame writes one compact JSON frame followed by a single '\n'. It rejects
// a payload that overruns maxFrameBytes before any byte reaches the wire, so the
// host never emits a frame the peer's symmetric bound would reject.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameBytes {
		return fmt.Errorf("%w: outbound frame exceeds %d bytes", ErrProtocol, maxFrameBytes)
	}
	// One Write of payload+'\n' keeps the frame atomic against a concurrent writer
	// on the same conn (there is none in v1, but the single-write keeps the '\n'
	// from being split out of the buffer).
	out := make([]byte, 0, len(payload)+1)
	out = append(out, payload...)
	out = append(out, '\n')
	n, err := w.Write(out)
	if err != nil {
		return fmt.Errorf("controlrpc: write frame: %w", err)
	}
	if n != len(out) {
		return fmt.Errorf("controlrpc: short frame write: wrote %d of %d", n, len(out))
	}
	return nil
}

// EncodeRequest marshals req to a compact JSON frame and writes it with the
// trailing newline. It is the symmetric counterpart of DecodeRequest; both are
// exercised by the closed-union property test.
func EncodeRequest(w io.Writer, req Request) error {
	b, err := req.MarshalJSON()
	if err != nil {
		return err
	}
	return writeFrame(w, b)
}

// EncodeReply marshals rep to a compact JSON frame and writes it with the
// trailing newline. Symmetric with DecodeReply.
func EncodeReply(w io.Writer, rep Reply) error {
	b, err := rep.MarshalJSON()
	if err != nil {
		return err
	}
	return writeFrame(w, b)
}

// DecodeRequest reads one bounded, newline-delimited request frame and parses it
// through the closed-union UnmarshalJSON (DisallowUnknownFields inside). An
// oversize frame, a null/multi/unknown tag, or a non-empty body is ErrProtocol;
// a clean EOF before any byte is io.EOF.
func DecodeRequest(r *bufio.Reader) (Request, error) {
	frame, err := readFrame(r)
	if err != nil {
		return Request{}, err
	}
	var req Request
	if err := req.UnmarshalJSON(frame); err != nil {
		return Request{}, err
	}
	return req, nil
}

// DecodeReply reads one bounded, newline-delimited reply frame and parses it
// through the closed-union UnmarshalJSON. Same hard-error discipline as
// DecodeRequest.
func DecodeReply(r *bufio.Reader) (Reply, error) {
	frame, err := readFrame(r)
	if err != nil {
		return Reply{}, err
	}
	var rep Reply
	if err := rep.UnmarshalJSON(frame); err != nil {
		return Reply{}, err
	}
	return rep, nil
}
