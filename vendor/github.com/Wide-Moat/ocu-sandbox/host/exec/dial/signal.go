// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package dial

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/wire"
)

// SendSignal writes exactly one {"SendSignal": <signal>} text frame to the guest,
// carrying sig as the body (an integer or a POSIX name — wire.Signal renders the
// scalar directly). It is the host-driver send of the EXISTING, already-frozen
// SendSignal ClientMessage tag (host/internal/wire/union.go): it adds NO new wire
// message and NO new wire variant — it constructs a frame the frozen contract
// already defines.
//
// sig is validated against the schema bounds (numeric 1..64, or ^SIG[A-Z0-9]{1,12}$)
// before any frame is written, so an out-of-range signal is rejected on the host
// side rather than emitted on the wire. The guest's acknowledgement (the frozen
// SignalSent server tag, or a FailedToSendSignal/InvalidSignal terminal) is read
// on the channel's read path (DriveExec's handleServerMessage / a test's
// ReadServer), not here — SendSignal is the write half only.
//
// Single-writer discipline: SendSignal writes through c.writeText, which takes
// the channel's writeMu, so it is safe to call concurrently with the keepalive
// ticker and the stdin pump (the one-writer-at-a-time rule is preserved by the
// mutex). The write is bounded by ctx so a wedged peer yields a typed error
// rather than a hang.
func (c *Channel) SendSignal(ctx context.Context, sig wire.Signal) error {
	if err := sig.Validate(); err != nil {
		return fmt.Errorf("dial: send signal: %w", err)
	}
	frame, err := json.Marshal(wire.ClientMessage{SendSignal: &sig})
	if err != nil {
		return fmt.Errorf("dial: marshal SendSignal frame: %w", err)
	}
	if err := c.writeText(ctx, frame); err != nil {
		return fmt.Errorf("dial: write SendSignal: %w", err)
	}
	return nil
}
