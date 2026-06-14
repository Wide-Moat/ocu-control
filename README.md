# ocu-control

Control plane for [Open Computer Use](https://github.com/Wide-Moat/open-computer-use) (`next/v1` architecture).

One per deployment. It manages sandbox session lifecycle (provision, quota, teardown), holds the kill-switch / session denylist, and relays each session's pre-signed, `filesystem_id`-scoped storage credential into the sandbox at provisioning time. It **holds no signing key**: the storage credential is signed off-box by a separate issuer, and the control plane only delivers it.

This repository is carved out of [`ocu-sandbox`](https://github.com/Wide-Moat/ocu-sandbox), which narrows to the per-session executor. The boundary is recorded in [ADR-0017](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0017-control-plane-repo-boundary.md); the component spec is [`02-control-operator-api.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/components/02-control-operator-api.md).

Status: scaffolding. No implementation yet.

## License

FSL-1.1-Apache-2.0. See the upstream [LICENSE](https://github.com/Wide-Moat/open-computer-use/blob/main/LICENSE).
