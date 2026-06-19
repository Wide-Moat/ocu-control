# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Multi-stage build for the ocu-controld control-plane daemon (component-02).
# The builder stage cross-compiles a static binary with the SAME flags the
# release pipeline uses (CGO_ENABLED=0, -trimpath, -s -w, main.version stamped
# via the VERSION build-arg), so the container binary and the released binary
# are build-identical. The final stage is distroless static running as nonroot:
# no shell, no package manager, no libc — the daemon is the only thing in the
# image.
#
# Both base images are pinned by multi-arch index digest (covers linux/amd64
# and linux/arm64); bumping a base is an explicit, reviewable diff.

# --- builder: runs on the build host's native platform and cross-compiles
#     for the target (Go needs no emulation to cross-compile), so a
#     multi-arch build never pays the QEMU tax in the compile stage.
FROM --platform=$BUILDPLATFORM golang:1.26.4@sha256:87a41d2539e5671777734e91f467499ed5eafb1fb1f77221dff2744db7a51775 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

# Module graph first: the download layer caches independently of source edits.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/ocu-controld ./cmd/ocu-controld

# Skeleton for the writable mount points: distroless has no shell to mkdir
# with, so the directories are staged here and copied in owned by the nonroot
# uid (65532). A named volume initialized from the image inherits this
# ownership, which the daemon needs to write the audit sink and to read the
# Storage-JWT signing key mounted alongside it.
RUN mkdir -p /skel/var/log/ocu-control \
             /skel/run/ocu-control

# --- final: distroless static, nonroot (uid 65532), digest-pinned.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/Wide-Moat/ocu-control" \
      org.opencontainers.image.description="Open Computer Use control plane (component-02): one-per-deployment session-lifecycle daemon, host-dials-guest, Storage-JWT signer" \
      org.opencontainers.image.licenses="FSL-1.1-Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build --chown=65532:65532 /skel/var/log/ocu-control /var/log/ocu-control
COPY --from=build --chown=65532:65532 /skel/run/ocu-control /run/ocu-control
COPY --from=build /out/ocu-controld /usr/local/bin/ocu-controld

# The mutable surfaces the daemon writes (everything else stays read-only): the
# fail-closed audit sink directory and the runtime directory for the operator
# ingress socket. The Storage-JWT signing key and the operator credential are
# read-only secret mounts the deployment supplies; they are not baked here.
VOLUME ["/var/log/ocu-control", "/run/ocu-control"]

USER nonroot:nonroot

# HEALTHCHECK uses the daemon's own -health-check self-probe mode: it dials the
# loopback ops listener and exits 0 (alive) or non-zero (unreachable). The
# distroless image has no shell or curl, so the daemon binary serves as its own
# liveness probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/ocu-controld", "-health-check"]

ENTRYPOINT ["/usr/local/bin/ocu-controld"]
