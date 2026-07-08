// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// Per-mount Storage-JWT intent derivation and the deployment intent ceiling
// (ADR-0029). The intent a session's Storage-JWT carries is derived from THAT
// session's mount posture — the read-only uploads input leg mints read, the
// read-write outputs sink mints write — not from a single deployment-wide scope.
// The -granted-intents ceiling names the intents the deployment serves; it never
// grants, and a derived intent outside it refuses the mint fail-closed. The
// filestore engine (ADR-0029 component-04) consumes the minted claim and resolves
// the backend subtree from it; this file mints the claim, it does not enforce the
// subtree.

package lifecycle

import (
	"errors"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// ErrIntentOutsideCeiling is the fail-closed refusal a create returns when the
// per-mount-derived intent is not admitted by the deployment -granted-intents
// ceiling. It mirrors the mint's own ErrMintScope refusal: nothing external was
// effected (the refusal is before render/push), so the create fails closed with no
// leaked token and no bound state.
var ErrIntentOutsideCeiling = errors.New("lifecycle: refused to mint, derived intent outside the -granted-intents ceiling")

// deriveMountIntent maps a mount's host-set read-only posture to the Storage-JWT
// intent the egress edge keys on (ADR-0029 §Decision map, control half): a
// read-only mount is the uploads input leg (read), a read-write mount is the
// outputs sink (write). The posture is host-enforced and the agent cannot flip it
// (runtime.MountIntent.ReadOnly), so the derived intent is host-authoritative, not
// a body hint (NFR-SEC-43). preview is deliberately NOT derivable here: read and
// preview share the uploads subtree and differ only on the downloadable axis, which
// a bare read-only bool does not carry — preview arrives when the wire carries an
// explicit preview position (an ADR-0029 follow-on), and until then control mints
// read|write only.
func deriveMountIntent(readOnly bool) cred.Intent {
	if readOnly {
		return cred.IntentRead
	}
	return cred.IntentWrite
}

// IntentCeiling is the deployment-fixed set of intents the -granted-intents flag
// names — the intents the deployment serves. It is a CEILING, never a grant: the
// effective intent is the intersection of the per-mount-derived claim and this set,
// so a derived intent the set does not admit is refused, and no ceiling value
// substitutes for a missing claim. The Control-minted claim is the grant (ADR-0029
// §Decision). A zero IntentCeiling admits nothing; construct one with
// NewIntentCeiling or DefaultIntentCeiling.
type IntentCeiling struct {
	// admitted is the closed set of intents the deployment serves. A nil map (the
	// zero value) admits nothing, so a ceiling must be explicitly constructed — a
	// missing ceiling never silently widens to admit every intent.
	admitted map[cred.Intent]bool
}

// NewIntentCeiling builds a ceiling admitting exactly the given intents. Duplicates
// collapse; an empty argument list yields a ceiling that admits nothing (every mint
// then refuses fail-closed), so an operator who wants a serving deployment must name
// at least one intent — the default-serving posture ships via DefaultIntentCeiling.
func NewIntentCeiling(intents ...cred.Intent) IntentCeiling {
	admitted := make(map[cred.Intent]bool, len(intents))
	for _, i := range intents {
		admitted[i] = true
	}
	return IntentCeiling{admitted: admitted}
}

// DefaultIntentCeiling is the minimal-shelf ceiling: it admits the two intents
// control derives from a mount posture today — read (the RO uploads leg) and write
// (the RW outputs sink). It ships pinned so the minimal shelf runs zero-config while
// still enforcing the ceiling — every derived intent is admitted, so no legitimate
// create is refused, but the ceiling is real and a future preview derive is refused
// until the deployment explicitly names it (ADR-0029 §Decision "the default map
// ships pinned, so the minimal shelf runs zero-config").
func DefaultIntentCeiling() IntentCeiling {
	return NewIntentCeiling(cred.IntentRead, cred.IntentWrite)
}

// Admits reports whether the ceiling serves the given intent. A zero (nil-map)
// ceiling admits nothing, so an unconstructed ceiling fails every mint closed rather
// than silently serving all intents. The mint stage consults it before minting; the
// daemon consults it to validate the -granted-intents flag it parsed.
func (c IntentCeiling) Admits(i cred.Intent) bool {
	return c.admitted[i]
}
