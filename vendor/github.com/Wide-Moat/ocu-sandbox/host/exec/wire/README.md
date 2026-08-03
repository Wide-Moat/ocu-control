# wire — the exec-channel control contract, in Go

This package mirrors the frozen exec-channel control union as host-side Go types:
the `ProcessConnection` handshake, the `ServerMessage` and `ClientMessage`
single-key tagged unions, the `Signal` scalar, `CreateProcess`, and the small
body structs they share.

The contract is the law. These types are kept honest by validating serialized
samples — and the shared golden fixtures — against the **identical schema bytes**
that the other-language mirror validates against. That byte-for-byte sameness is
the cross-language equivalence proof.

## Layout

- `wire.go` — base structs (`ProcessConnection`, `CreateProcess`,
  `ConnectionCapabilities`, `ProcessExited`, `SignalSent`, `Resize`,
  `BoundedReason`) and the `Null` body type.
- `signal.go` — `Signal`, an integer-or-name scalar with custom marshalling.
- `union.go` — `ServerMessage` / `ClientMessage`, one pointer field per tag, with
  a `MarshalJSON` guard that enforces exactly one variant per frame.
- `embed.go` — embeds the schema and fixtures for hermetic conformance tests.
- `schema/`, `testdata/` — **generated** copies of the canonical schema and the
  shared fixtures. Never hand-edit them; the single source of truth lives in the
  repo-root `contracts/` tree, and these copies are regenerated with:

  ```sh
  go generate ./internal/wire/...
  ```

  CI asserts the copy is byte-identical to the canonical source.

## Forward compatibility

An unknown top-level tag unmarshals into the union struct leaving every known
field nil, with no error — the frame is recognised as unknown and ignored, and
the channel survives. Only v1 tags are emitted; the V2 and trace tags are modeled
but never produced.
