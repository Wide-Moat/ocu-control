// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mcpkey owns the sk-ocu- credential class: the CSPRNG mint, the
// structurally redacting SecretKey type, the salted-hash Record, the RecordStore
// seam, and the operator Engine. Each piece is a direct composition of an
// existing seam in the control plane — mint mirrors cred.Signer, SecretKey
// mirrors cred.Token, the RecordStore seam mirrors the EnrichedLister precedent,
// and the Engine follows the killswitch.Engine OperatorScope discipline.
//
// Plans 08-02 and 08-04 extend this package with the Record and RecordStore seam
// and the operator Engine. Plan 08-01 (this wave) delivers only the mint
// foundation: SecretKey and Minter.
package mcpkey
