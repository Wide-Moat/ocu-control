// Module path reflects this public repo's control-plane module. Each
// dependency arrives through the architecture repo's dependency policy
// (license gate + supply-chain gate); see NOTICE for third-party license
// notices.
//
// Expected runtime dependencies as the implementation lands (none are wired
// yet — this is scaffolding, so the require block stays empty until real code
// imports them):
//   - github.com/docker/docker      — the v1 RuntimeProvider backend (behind
//                                      the seam; control logic imports the
//                                      provider interface, never the SDK)
//   - github.com/golang-jwt/jwt/v5  — minting/signing the weak Storage-JWT and
//                                      publishing the JWKS
//   - github.com/prometheus/client_golang — ops-listener metrics
//   - pgregory.net/rapid            — property tests (test binaries only)
module github.com/Wide-Moat/ocu-control

go 1.26.4

require (
	github.com/containerd/errdefs v1.0.0
	github.com/docker/docker v28.5.2+incompatible
	github.com/jackc/pgx/v5 v5.10.0
	pgregory.net/rapid v1.3.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.69.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)
