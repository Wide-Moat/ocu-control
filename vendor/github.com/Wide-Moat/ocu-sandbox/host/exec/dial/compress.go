// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package dial

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// compressionWindowLog mirrors the guest's pinned WINDOW_LOG (2^17 = 128 KiB). The
// host decoder rejects any inbound frame whose declared window exceeds this bound,
// matching the guest's WindowLogMax, so a peer cannot force a large decode window
// (T-17-01). The host encoder pins the SAME window so a frame it produces is never
// rejected by the guest's equally-pinned decoder.
const compressionWindowLog = 17

// compressionMaxWindow is the byte-valued window cap derived from
// compressionWindowLog: 1<<17 = 131072 bytes.
const compressionMaxWindow = 1 << compressionWindowLog

// maxDecompressedFrame caps the DECOMPRESSED output of a single inbound stdio
// frame. It mirrors the guest's MAX_FRAME (and the contract's per-frame stdio
// bound, 32 KiB): a decoded frame can never exceed one stdio frame's worth of
// bytes. Bounding the output — not just the window — is the zip-bomb defence: a
// tiny compressed frame that would expand past this cap is rejected before the
// overshooting bytes are materialized.
const maxDecompressedFrame = 32 * 1024

// compressedFrameBound is the zstd worst-case expansion of a maxDecompressedFrame
// input: the maximum size ONE per-message zstd stdio frame can reach on the wire.
//
// zstd does NOT shrink incompressible input — already-compressed, encrypted, or
// random bytes encode to slightly MORE than the input. A full maxDecompressedFrame
// chunk of such data therefore encodes to a frame LARGER than maxDecompressedFrame,
// so a receiver that has negotiated compression must accept a binary frame up to
// this size BEFORE it decodes (the DECODED output stays bounded at
// maxDecompressedFrame — the zip-bomb guard, unchanged). The value is pinned to
// equal the guest's COMPRESSED_FRAME_BOUND = zstd ZSTD_COMPRESSBOUND(32768) =
// 32768 + (32768>>8) + ((128 KiB - 32768)>>11) = 32944, so BOTH sides agree on one
// wire bound. The host's klauspost EncodeAll worst-case incompressible frame
// (32782) sits comfortably under this ceiling, so a frame the host produces is
// always within the bound the guest accepts and vice-versa.
//
// TestCompressedFrameBoundMatchesZstd pins this against klauspost's actual
// worst-case output so an encoder upgrade that changed the expansion would turn it
// RED rather than silently desync the wire bound.
const compressedFrameBound = 32944

// stdioCodec is the host's per-message zstd codec for the exec stdio path, used
// only when compression is negotiated on for the channel (FID-01). It is built from
// klauspost/compress/zstd — a pure-Go implementation, NO cgo — matching the host's
// cgo-free build posture. Encoding and decoding are per MESSAGE (each stdio binary
// frame is one self-contained zstd frame), so DecodeAll/EncodeAll (the stateless,
// concurrency-safe API) is the exact fit; no streaming state crosses frames.
type stdioCodec struct {
	dec *zstd.Decoder
	enc *zstd.Encoder
}

// newStdioCodec builds the host stdio codec with the decode window and output bound
// pinned to mirror the guest. The decoder pins WithDecoderMaxWindow(1<<17) (the
// window bound) and WithDecodeAllCapLimit(true) (so DecodeAll honours the capacity
// of the destination buffer as a hard output ceiling — the zip-bomb output guard).
// Concurrency is pinned to 1: each channel decodes one frame at a time on its read
// loop, so a single decoder goroutine is all that is needed and keeps memory flat.
func newStdioCodec() (*stdioCodec, error) {
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderMaxWindow(compressionMaxWindow),
		zstd.WithDecodeAllCapLimit(true),
		zstd.WithDecoderConcurrency(1),
	)
	if err != nil {
		return nil, fmt.Errorf("dial: build zstd decoder: %w", err)
	}
	enc, err := zstd.NewWriter(nil,
		zstd.WithWindowSize(compressionMaxWindow),
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		dec.Close()
		return nil, fmt.Errorf("dial: build zstd encoder: %w", err)
	}
	return &stdioCodec{dec: dec, enc: enc}, nil
}

// decode decompresses one inbound stdio frame, capping the DECOMPRESSED output at
// maxDecompressedFrame bytes. The destination is allocated with len 0 and cap
// maxDecompressedFrame; with WithDecodeAllCapLimit(true) the decoder refuses to
// produce more than cap(dst) bytes, so a frame expanding past the bound returns an
// error rather than materializing the whole expansion (the zip-bomb teeth). An
// over-window or malformed frame likewise returns an error. The caller treats any
// error as a fail-closed protocol reject — never a partial write.
func (c *stdioCodec) decode(frame []byte) ([]byte, error) {
	dst := make([]byte, 0, maxDecompressedFrame)
	out, err := c.dec.DecodeAll(frame, dst)
	if err != nil {
		return nil, fmt.Errorf("%w: inbound stdio frame failed bounded zstd decode: %v", ErrProtocol, err)
	}
	return out, nil
}

// encode compresses one outbound stdin payload into a single self-contained zstd
// frame, mirroring the guest's per-message encode. The guest decodes it under the
// same pinned window. EncodeAll is stateless per call, so no frame poisons the next.
func (c *stdioCodec) encode(payload []byte) []byte {
	return c.enc.EncodeAll(payload, nil)
}

// Close releases the codec's decoder and encoder. It is safe to call once after the
// drive completes; a nil codec (compression off) makes the call a no-op for the
// caller that guards on it.
func (c *stdioCodec) close() {
	c.dec.Close()
	_ = c.enc.Close()
}
