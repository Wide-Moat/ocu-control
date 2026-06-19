# Kubernetes deployment examples — ocu-controld

Applyable Kubernetes manifests for the control plane (`ocu-controld`,
component-02). These are scaffold stubs: the flag surface tracks the scaffold
daemon, and the daemon refuses with "serve not implemented" until the lifecycle
PRs land. The shape — one-per-deployment, single replica, hardened
securityContext, exec health-probe — is the real target.

Questions or issues: developer@widemoat.ai

---

## File index

| File | Purpose |
|------|---------|
| `control-deployment.yaml` | Deployment running the single control plane |

---

## Apply order

The Storage-JWT signing key is a Secret the Deployment mounts read-only; create
it before applying the Deployment:

```sh
kubectl create secret generic ocu-control-jwt-signing-key \
  --from-file=storage-jwt-signing.key=./storage-jwt-signing.key
kubectl apply -f examples/k8s/control-deployment.yaml
```

---

## One control plane per deployment

The control plane is the sole custodian of the session registry and the
denylist, and the single Storage-JWT signer. A second live instance would
split-brain that state. The Deployment pins `replicas: 1` and
`strategy.type: Recreate` so there is exactly one custodian at every instant.
**Do not increase `replicas`.**

The kill-switch-under-saturation target reserves admission priority for the
revoke route rather than scaling out (component-02 Operational concerns), so a
single instance is the design, not a limitation to grow past.

## Storage-JWT signing key

Control holds the Storage-JWT signing key as a read-only Secret mount; it mints
the weak, `filesystem_id`-scoped session JWT and publishes a JWKS the Egress
trust-edge validates against. The key is never baked into the image and never
written by the daemon. Control does not hold the real filestore credential and
does not speak the filestore protocol — the mount runs inside the sandbox
(`ocu-rclone-filestore`).

## securityContext and seccomp

Every container runs with the full hardened securityContext: `runAsNonRoot`,
`runAsUser: 65532`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
all capabilities dropped, and a seccomp profile.

The manifest uses `seccompProfile.type: RuntimeDefault` as the portable
default. For tighter confinement, deploy the shipped
`deploy/seccomp/ocu-controld.json` to each node's seccomp directory and switch
to a `Localhost` profile:

```yaml
seccompProfile:
  type: Localhost
  localhostProfile: ocu-controld/ocu-controld.json
```

## Liveness and readiness probes

Both probes exec the daemon's own `-health-check` self-probe mode — **not**
`httpGet`. The ops listener binds loopback only; a kubelet `httpGet` probe is
issued from the node and `host: 127.0.0.1` resolves to the node's loopback,
never the pod's network namespace, so an `httpGet` probe of a loopback-bound
listener never succeeds. An `exec` probe runs inside the container, where
`127.0.0.1` is the pod's own loopback. The distroless image has no shell or
`curl`, so the daemon binary serves as its own prober.

## RuntimeProvider endpoint

The control plane drives per-session executor containers through the
RuntimeProvider seam; Docker is the v1 provider. Supplying the runtime endpoint
to the pod (a brokered/rootless socket, never the raw node socket in a hardened
deployment) is a deployment-specific decision left to the operator and is not
wired into this stub.
