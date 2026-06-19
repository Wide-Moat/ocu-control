# Security Policy

## Supported Versions

This project is pre-release (no stable version has been published). The table
below reflects the honest current state:

| Version range | Supported |
|---|---|
| `main` (pre-release, unreleased) | Yes — fixes target this branch |
| Any tagged pre-release (`v0.x.y`) | Rolling — superseded by the next tag; no backports during pre-release |
| None | A stable `v1.0` support window will be defined at first stable release |

Until a `v1.0.0` tag is cut, this project makes no long-term backport
commitment. Security fixes land on `main` and are included in the next
release tag.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a suspected security vulnerability.**
Public disclosure before a fix is available puts users and the project at
risk.

### Primary channel — GitHub Private Vulnerability Reporting

Use **GitHub's built-in private vulnerability reporting** mechanism:

1. Navigate to the repository on GitHub.
2. Click the **Security** tab.
3. Click **Report a vulnerability** (under "Advisories").
4. Fill in the advisory form and submit.

This creates a private Security Advisory that is visible only to repository
maintainers. Maintainers must have "Private vulnerability reporting" enabled
in repository settings — if the button is absent, that setting has not yet
been activated; contact a maintainer directly via a GitHub DM or by opening
a blank issue asking them to enable it, without disclosing vulnerability
details.

There is no security email alias for this project. The GitHub private
reporting mechanism is the only supported channel.

### What to include

A useful report typically contains:

- A concise description of the class of vulnerability.
- Steps to reproduce, or a minimal reproducer if possible.
- The component, file, or interface where the issue manifests.
- Your assessment of the impact and, if relevant, the conditions required.
- Any suggested fix or mitigation, if you have one.

## Response Expectations

These are good-faith intentions appropriate to an early-stage open-source
project, not contractual SLAs.

| Stage | Target |
|---|---|
| Initial acknowledgement | Within 5 business days of receipt |
| Triage and severity assessment | Within 10 business days |
| Fix or mitigation | Depends on severity and complexity; critical issues are prioritised |
| Coordinated disclosure | Maintainers aim to coordinate a public disclosure date with the reporter before publishing a fix |

Maintainers will keep reporters informed of progress. If a report has not
been acknowledged within 5 business days, feel free to follow up in the same
advisory thread.

**Credit:** Reporters who disclose responsibly will be credited in the
Security Advisory and, at their preference, in the release notes when the
fix ships.

## Coordinated Disclosure

This project follows a coordinated (responsible) disclosure model. Reporters
are asked to:

- Avoid public disclosure until a fix has been released or a coordinated
  disclosure date has been agreed with the maintainers.
- Refrain from exploiting the vulnerability beyond what is needed to
  demonstrate it.
- Not access, modify, or delete data belonging to other users.

Maintainers will make every reasonable effort to resolve valid reports
quickly and to keep reporters informed throughout the process.

## In-Scope Vulnerability Classes

The following classes are of especially high value given that this component
is the only door to create or manage a session and the custodian of the
Storage-JWT signing key. Reports in these classes are particularly welcomed.

### Admission, reservation, or quota bypass

Admission (the workload-trust-profile × runtime-tier matrix) and per-caller /
per-tenant quota run fail-closed before any host state exists — no handoff
directory, no network, no container until they pass. Any path that creates or
routes a session without a passing admission check, that exceeds a per-caller
create-rate or per-tenant quota, or that lets a body-supplied
session/tenant/`container_name` id (a hint, never the authority) bind or address
another session, is in scope.

### Kill-switch or denylist bypass

The kill-switch is a host-initiated stop and DENY-ALL engages before any
listener admits a create. Any path that lets a session survive a kill, that
lets an unreachable or stalled control channel grant the guest new authority,
that defeats the kill-switch's reserved-capacity SLA under a create flood, or
that lets a gateway service identity reach the operator-only kill-switch /
force-kill routes, is in scope.

### Supervision or teardown escape

Control supervises and tears down every per-session executor through a
host-driven finalizer. Any path that leaves a session's container, network, or
writable surface live after teardown, that lets a guest reply mark teardown
complete when the host-executed steps did not run, or that orphans resources
across a daemon restart, is in scope.

### Control-channel-direction violation

The host dials the guest; the guest never dials Control. Any path that lets a
guest open or drive a connection to Control, that reverses the dial direction,
or that exposes a lifecycle/denylist/kill-switch route on a guest-reachable
surface, is in scope.

### Credential or secret leak from the control plane

Control holds the Storage-JWT signing seed, mints the weak session JWT, installs
the control-WS verify-key into guests, and accepts the exec-JWT and operator
credentials. Any path that causes the Storage-JWT signing key, the exec-JWT, the
control-WS verify-key, an operator credential, or any derivative secret to appear
in logs, error messages, audit records, metrics labels, or HTTP responses, or to
reach a party other than its intended recipient, is in scope. The real filestore
credential never reaches Control or the guest; a path that routes it through
either is in scope.

## Out of Scope

The following are generally not considered security vulnerabilities for this
project:

- Missing features not yet on the implementation roadmap.
- Issues that require physical access to the host machine.
- Vulnerabilities in dependencies, unless this project exposes them in a
  security-relevant way (report those upstream first; mention them here if
  they affect the in-scope classes above).
- Denial-of-service scenarios that require a valid operator credential and a
  physical operator account.
