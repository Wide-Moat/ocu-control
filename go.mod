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
	github.com/jackc/pgx/v5 v5.10.0
	pgregory.net/rapid v1.3.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)
