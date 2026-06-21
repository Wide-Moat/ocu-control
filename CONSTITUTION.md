<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# ocu-control Constitution

These are the load-bearing invariants of the Open Computer Use control plane
(component-02). They are not style preferences; each is a security or custody
property the rest of the system is allowed to assume holds. Every invariant
below is mechanically enforced — by a type shape, an import-graph test, a
compile-fail fixture, or a boot ordering gate — not by reviewer vigilance alone.

A change that weakens one of these is not a normal change. It must update the
enforcing test in the same commit, and any behaviour an Architecture Decision
Record (ADR) or a frozen wire contract fixed must change in the architecture
canon first. If you are about to delete or relax a guard named here, stop and
escalate instead.

The enforcing artefact is named for each invariant so the claim is checkable,
not asserted. If an enforcing file is renamed or moved, update this document in
the same change.

---

## I. Control imports no concrete substrate SDK above its seam

Control logic depends on interfaces, never on a concrete container SDK or
database driver. The Docker SDK is imported only below the `RuntimeProvider`
seam (`internal/runtime/docker`); `pgx`/`database/sql` are imported only inside
`internal/state/postgres`, behind the `state.Store` seam. The provider is
chosen behind the `RuntimeProvider` interface so control logic never names a
concrete runtime, and runtime tier is a deployment-wide choice, never a
per-request one (ADR-0003, ADR-0012).

- **Seam:** `internal/runtime/provider.go` (`RuntimeProvider`),
  `internal/state/store.go` (`Store`).
- **Enforcement:** seam isolation — control packages import the interface, not
  the impl. *(Note: unlike invariants III and II, this one has no dedicated
  import-graph test yet; it is held by the seam shape. The compile-test upgrade —
  a runtime/state import-graph test at parity with `cred`'s
  `TestCredHoldsNoListener` and `ingress`'s `TestGatewayCannotReachOperatorSeam`
  — is a tracked guard-strength item, scheduled as Phase 7 of the roadmap. This
  caveat closes when that test lands; until then, do not assume the test is
  present.)*

## II. The gateway can never reach the operator surface (NFR-SEC-52, NFR-SEC-26)

There are two listeners on distinct endpoints: an operator/lifecycle ingress
and a gateway service-identity ingress. The kill-switch, force-kill, and the
operator-only mutating routes exist only on the operator ingress. The gateway
adapter holds only a service scope and has no syntactic or transitive route to
the operator-seam mint path. This is a *compile fact*, not a runtime check: a
missed separation fails CI, never production.

- **Enforcement:** `internal/ingress/importgraph_test.go`
  (`TestGatewayCannotReachOperatorSeam`) — an AST scan rejects the operator-seam
  symbols (`OperatorSeam`, `NewOperatorSeam`, `OperatorScope`) in gateway source,
  and a `go list -deps` check asserts the gateway's transitive closure excludes
  `internal/ingress/operator` and `internal/killswitch`. The compile-fail fixture
  `internal/ingress/scope_compilefail_test.go` proves the forgery attempts do not
  build.

## III. The Storage-JWT signing key lives in a closure that holds no listener

Control holds the signing key, mints the weak `filesystem_id`-scoped session
JWT, and publishes a JWKS the Egress trust-edge validates against. It does *not*
hold the real filestore credential and does *not* speak the filestore protocol;
the mount runs inside the sandbox. The package that custodies the signing key
imports no listener — it cannot open a socket and therefore cannot become an
unintended exfiltration surface for the key.

- **Enforcement:** `internal/cred/importgraph_test.go`
  (`TestCredHoldsNoListener`) — the package's transitive closure excludes
  `net/http`, and an AST scan rejects the `Listen`/`Listener`/`Server`
  identifiers in `internal/cred` source.

## IV. Kill-switch-first boot: DENY-ALL before any listener admits a create

Boot loads the denylist and kill-switch state and engages DENY-ALL *before* any
listener binds. Readiness flips only after the deny state is durably loaded; the
listener-bind hook runs strictly inside the readiness callback. A create
arriving before the deny state is loaded is refused fail-closed and writes no
host state. The kill-switch is a host-initiated stop, not a cooperative guest
action — an unreachable control channel grants the guest no new authority
(NFR-SEC-01).

- **Enforcement:** `internal/boot/boot.go` (`Boot` orders `LoadDeny` →
  readiness → `onReady` bind hook); `internal/boot/boot_test.go`
  (`Test_Boot_Ordering`, `Test_AdmitCreate_DenyAllUntilLoaded`,
  `Test_AdmitCreate_DurableGlobalDenyRestored`). The listener bind in
  `cmd/ocu-controld/main.go` is installed only inside the readiness callback.

## V. A body-supplied id is a hint, never the authority (NFR-SEC-43)

The caller is derived from the operator transport's attested peer credential
(SO_PEERCRED on the host-owned operator socket). A request body carries only
hints — a `session_hint`, an image ref, mount/egress/resource intents, a reason.
No body field names a caller, tenant, session-authority, or `container_name`
id. The session key is host-derived from the attested owner identity; the body
hint only seeds a human-correlation handle and never becomes the binding key. A
foreign or unknown hint resolves to a not-found-shaped deny, so a probe cannot
distinguish another principal's row from absence.

- **Enforcement:** `internal/ingress/operator/resolver.go` (`PeerCredResolver`
  — the kernel-vouched uid/gid is the only identity source); the key is built by
  `registry.DeriveKey(owner, handle)` in `internal/lifecycle/stages.go`, which
  mixes the host-attested owner and has no raw-string key constructor.

## VI. Every privileged action is audit-gated before acknowledgement (NFR-SEC-45)

Every privileged operator/SOAR action emits a chain-linked OCSF event *before*
the action is acknowledged; the action is denied if the audit write fails
(fail-closed). The order is Emit → check the write → only then mutate
authoritative state. A 2xx on a privileged route therefore means the action took
effect *and* was recorded; an audit-write failure is a refusal, not a silent
loss.

- **Enforcement:** `internal/audit/audit.go` (the fail-closed contract);
  `internal/lifecycle/stages.go` (`stageCommit` audits first, unwinds on
  failure); `internal/killswitch/killswitch.go` (`RevokeOne`/`RevokeAll`/
  `ResumeAll`/`LiftDeny` emit before the authoritative `SetDeny`).

## VII. No raw Storage-JWT on the create response or the audit path

The minted weak Storage-JWT is custody-separated: it is pushed on the
mount-config plane, never returned on the create response and never written into
an audit record. The create response (`SessionHandle`/`SessionRow`) and the
audit `Record` have no JWT field by type. A create body that carried the
credential, or a response that echoed it, would be a custody leak; the wire
shapes make that impossible to express.

- **Enforcement:** `internal/state/store.go` (`SessionRow` has no JWT field);
  `internal/audit/audit.go` (`Record` has no JWT field); the JWT is minted in
  `internal/cred` and recorded only as a revocation `jti`, never persisted on the
  row or the event.

---

## Read before changing any of the above

- The architecture and specifications are the source of truth and live in the
  `open-computer-use` canon under `docs/architecture/`. Do not re-decide here
  what an ADR already decided; if a decision must change, it changes in the
  architecture canon first.
- The frozen wire contracts under `contracts/` (the control-RPC schema, the
  exec-channel schema, the mount-config schema, and the operator-REST OpenAPI)
  pin the discriminator union, the operation names, and the response envelope.
  Deferred verbs stay deferred until the contract pins them.
- All committed content is English only. State facts in this project's own
  words; the specs, ADRs, and frozen contracts are the only citable sources for
  behaviour.
