// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// Flag surface and pre-bind validation for ocu-controld. The validation order
// here is the load-bearing pre-bind gate: required-flag presence and enum
// membership are checked before any Store is constructed, so a malformed
// invocation never builds a Store and the kill-switch-first create refusal can
// originate in the real boot path rather than a hardcoded branch. No network
// endpoint is opened on any path through this file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"time"
)

type runMode int

const (
	modeServe runMode = iota
	modeVersion
	modeHealthCheck
)

// config is the parsed serving invocation — the daemon's full flag surface.
type config struct {
	operatorListen   string        // operator/lifecycle ingress endpoint (distinct from gateway)
	gatewayListen    string        // gateway service-identity ingress endpoint
	runtimeTier      string        // deployment-wide isolation tier; never per-request
	runtimeProvider  string        // container backend behind the RuntimeProvider seam
	workloadProfile  string        // deployment-declared trust profile feeding the admission matrix; never per-request
	guestImage       string        // deployment-declared default guest image a create runs when the body names none (ADR-0020 inject-at-materialize); the body image is an override; unset + no body image is a fail-closed 400
	guestImageAllow  string        // comma-separated exact-match allow-list of guest images a create BODY may override the default with (ADR-0020 BYO rung); the default is implicitly allowed; empty = default-only (deny-by-default)
	grantedIntents   string        // comma-separated Storage-JWT intent ceiling (read|write|preview) the deployment serves (ADR-0029); empty = the pinned default (read,write); a claim outside it is refused fail-closed. The flag never grants, only narrows.
	jwtSigningKey    string        // path to the Storage-JWT signing key (config/secret mount)
	execSigningKey   string        // path to the SEPARATE exec-channel Ed25519 signing key (ADR-0013 key separation); OPTIONAL — unset disables the exec channel
	gatewayTLSCert   string        // OPTIONAL gateway mTLS server-cert PEM; all-or-none with key+client-ca — unset keeps the stubbed fail-closed plain-TCP posture
	gatewayTLSKey    string        // OPTIONAL gateway mTLS server-key PEM (all-or-none)
	gatewayClientCA  string        // OPTIONAL gateway mTLS client-CA PEM the verified client-cert SAN is anchored against (all-or-none)
	jwtAlg           string        // Storage-JWT signing algorithm: eddsa|es256 (default eddsa)
	storageIssuer    string        // provisional Storage-JWT iss (PIN-PENDING; never hardcoded)
	storageAudience  string        // provisional Storage-JWT aud (PIN-PENDING)
	execIssuer       string        // provisional exec-JWT iss (PIN-PENDING)
	execAudience     string        // provisional exec-JWT aud (PIN-PENDING)
	serviceURL       string        // filestore service_url rendered into every mount-config
	caCert           string        // path to the CA certificate PEM rendered into every mount-config
	egressNetwork    string        // OPTIONAL docker network a storage-scoped guest joins to reach the egress edge; unset keeps every session on its per-session Internal bridge
	edgeHost         string        // OPTIONAL IP the storage guest's static `edge` ExtraHosts entry resolves to (gVisor cannot reach docker embedded DNS); unset adds no entry
	auditSink        string        // OCSF audit fan-in sink
	stateDSN         string        // Postgres DSN for durable state; empty selects the in-memory store
	jwksPath         string        // OPTIONAL path to the static JWKS artifact the deploy layer serves at the egress edge's remote_jwks URI
	mcpKeysetPath    string        // OPTIONAL path to write the static hashed-key-set artifact (Control→gateway config plane); unset = no-op
	mcpKeyFile       string        // OPTIONAL path to the minimal-shelf 0600 hashed-entries file; unset = in-memory-only
	sessionIdleTTL   time.Duration // OPTIONAL idle-session reaper window; 0 = unset (shelf-split resolution in resolveIdleTTL: off on the minimal shelf, ≤15 min ceiling on the full shelf per NFR-SEC-40)
	deriveChatScope  bool          // per-chat storage-scope derivation (ADR-0030, D5); default false = today's single static scope. When on, control rewrites each mount FilesystemID to "<base>-<hex>" before minting the Storage-JWT, so two chats mint distinct scopes
	storageScopeBase string        // OPTIONAL deployment-declared storage-scope base fsid the derivation suffixes; unset = the base rides each create request's mount. When -derive-chat-scope is on, a base already carrying a 16-hex suffix is refused (no double-derivation)
	create           bool          // a create request presented at startup (smoke hook)
}

// derivedScopeSuffixRe matches a storage-scope base that already carries a
// 16-hex-char derivation suffix ("<base>-[0-9a-f]{16}$"). When -derive-chat-scope
// is on, a base of this shape is refused at boot: deriving a second suffix onto an
// already-derived base ("<base>-<hex>-<hex>") is a double-derivation config error
// (ADR-0030), and the north-face shape guard would also mis-classify it. The check
// is on the deployment-fixed service scope, not any request body.
var derivedScopeSuffixRe = regexp.MustCompile(`-[0-9a-f]{16}$`)

// errBaseAlreadyDerived is the typed refusal for a storage-scope base that already
// looks derived when -derive-chat-scope is on. It is refused, not silently
// double-derived, so an operator cannot stack suffixes into an unreachable subtree.
var errBaseAlreadyDerived = errors.New("storage-scope base already carries a 16-hex derivation suffix; -derive-chat-scope would double-derive it")

// sessionIdleCeiling is the maximum idle-session window the full shelf permits
// (NFR-SEC-40). An idle ACTIVE session is terminated and its concurrency slot
// returned once it exceeds its resolved window; the full shelf may only tune the
// window DOWN from this ceiling, never up (regulator-anchored session-timeout bound).
const sessionIdleCeiling = 15 * time.Minute

// errIdleTTLAboveCeiling is the typed refusal for a -session-idle-ttl above the
// NFR-SEC-40 ceiling on the full shelf. The value is REFUSED, not silently clamped:
// a silent clamp would let an operator believe a wider idle window is in force than
// the one actually applied — a config-integrity lie. The boot aborts loud instead.
var errIdleTTLAboveCeiling = errors.New("session idle-TTL exceeds the full-shelf ceiling (NFR-SEC-40: ≤15 min, tunable down not up)")

// errIdleTTLNegative is the typed refusal for a negative -session-idle-ttl on either
// shelf. A negative window is meaningless (it would reap every session immediately or
// never), so it is refused rather than coerced.
var errIdleTTLNegative = errors.New("session idle-TTL must not be negative")

// resolveIdleTTL applies the NFR-SEC-40 shelf split to the raw -session-idle-ttl
// flag and returns the effective idle window (0 meaning the reaper does not run).
//
// The shelf is read from -state-dsn: an empty DSN is the in-memory minimal/solo shelf,
// a set DSN is the durable full shelf (the SAME signal openStore uses to pick the
// backend). On the minimal shelf the idle timeout is OFF-legal — unset stays off, and
// a positive value is an explicit opt-in that is honored. On the full shelf the idle
// timeout is MANDATORY: an unset window resolves UP to the ≤15 min ceiling (so the
// reaper runs — unset is not off), a value at-or-below the ceiling is honored (tunable
// down), and a value ABOVE the ceiling is REFUSED, not clamped. A negative value is
// refused on either shelf. Resolution is pure and side-effect-free, so it can run in
// the pre-bind validate() gate.
func resolveIdleTTL(cfg config) (time.Duration, error) {
	if cfg.sessionIdleTTL < 0 {
		return 0, fmt.Errorf("%w: %v", errIdleTTLNegative, cfg.sessionIdleTTL)
	}
	fullShelf := cfg.stateDSN != ""
	if !fullShelf {
		// Minimal/solo shelf: off is legal. Unset (0) stays off; a positive opt-in is
		// honored as-is (a solo operator may choose any window).
		return cfg.sessionIdleTTL, nil
	}
	// Full shelf: the idle timeout is mandatory and ceiling-bounded.
	if cfg.sessionIdleTTL == 0 {
		return sessionIdleCeiling, nil // unset resolves UP to the ceiling — the reaper runs
	}
	if cfg.sessionIdleTTL > sessionIdleCeiling {
		return 0, fmt.Errorf("%w: %v > %v", errIdleTTLAboveCeiling, cfg.sessionIdleTTL, sessionIdleCeiling)
	}
	return cfg.sessionIdleTTL, nil
}

// parse reads argv into a config plus the run mode. Unknown -runtime-tier and
// -runtime-provider values are refused here (not defaulted). flag parse errors
// are wrapped as a missing/invalid-required-flag refusal.
func parse(args []string) (config, runMode, error) {
	var (
		cfg         config
		showVersion bool
		healthCheck bool
	)

	fs := flag.NewFlagSet("ocu-controld", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we render our own typed refusals, not flag's usage dump
	fs.StringVar(&cfg.operatorListen, "operator-listen", "", "operator/lifecycle ingress endpoint (required)")
	fs.StringVar(&cfg.gatewayListen, "gateway-listen", "", "gateway service-identity ingress endpoint (required)")
	fs.StringVar(&cfg.runtimeTier, "runtime-tier", "", "deployment-wide isolation tier: runc|gvisor|firecracker (required)")
	fs.StringVar(&cfg.runtimeProvider, "runtime-provider", "", "container backend behind the RuntimeProvider seam: docker|k8s (required)")
	fs.StringVar(&cfg.workloadProfile, "workload-profile", "", "deployment-declared trust profile: trusted_operator|internal_workforce|untrusted (required)")
	fs.StringVar(&cfg.guestImage, "guest-image", "", "default guest image a create runs when the body names none (ADR-0020 inject-at-materialize); a body image overrides it; unset + no body image is refused 400")
	fs.StringVar(&cfg.guestImageAllow, "guest-image-allow", "", "comma-separated exact-match allow-list of images a create body may override the default with (ADR-0020 BYO rung); the default is implicitly allowed; empty = default-only, a non-allowed override is refused 400")
	fs.StringVar(&cfg.grantedIntents, "granted-intents", "", "comma-separated Storage-JWT intent ceiling the deployment serves: read|write|preview (ADR-0029). Empty = the pinned default (read,write) for the zero-config minimal shelf; the flag NEVER grants, only narrows — a per-mount-derived intent outside the ceiling refuses the create fail-closed. An unknown intent aborts boot")
	fs.StringVar(&cfg.jwtSigningKey, "jwt-signing-key", "", "path to the Storage-JWT signing key (required)")
	fs.StringVar(&cfg.execSigningKey, "exec-signing-key", "", "path to the SEPARATE exec-channel Ed25519 signing key mount (ADR-0013 key separation); unset disables the exec channel")
	fs.StringVar(&cfg.gatewayTLSCert, "gateway-tls-cert", "", "gateway mTLS server-cert PEM (all-or-none with -gateway-tls-key/-gateway-client-ca); unset keeps the stubbed plain-TCP fail-closed posture")
	fs.StringVar(&cfg.gatewayTLSKey, "gateway-tls-key", "", "gateway mTLS server-key PEM (all-or-none)")
	fs.StringVar(&cfg.gatewayClientCA, "gateway-client-ca", "", "gateway mTLS client-CA PEM the verified client SAN is anchored against (all-or-none)")
	fs.StringVar(&cfg.jwtAlg, "jwt-alg", "eddsa", "Storage-JWT signing algorithm: eddsa|es256 (default eddsa, NFR-SEC-11)")
	fs.StringVar(&cfg.storageIssuer, "storage-issuer", "", "provisional Storage-JWT issuer (PIN-PENDING; never hardcoded)")
	fs.StringVar(&cfg.storageAudience, "storage-audience", "", "provisional Storage-JWT audience (PIN-PENDING)")
	fs.StringVar(&cfg.execIssuer, "exec-issuer", "", "provisional exec-JWT issuer (PIN-PENDING)")
	fs.StringVar(&cfg.execAudience, "exec-audience", "", "provisional exec-JWT audience (PIN-PENDING)")
	fs.StringVar(&cfg.serviceURL, "service-url", "", "filestore service_url rendered into every mount-config (https://)")
	fs.StringVar(&cfg.caCert, "ca-cert", "", "path to the CA certificate PEM rendered into every mount-config")
	fs.StringVar(&cfg.egressNetwork, "egress-network", "", "OPTIONAL docker network a storage-scoped guest joins to reach the egress edge (edge is multi-homed onto it); unset keeps every session on its per-session Internal deny-all bridge")
	fs.StringVar(&cfg.edgeHost, "edge-host", "", "OPTIONAL IP the storage guest's static `edge` ExtraHosts entry resolves to (a gVisor guest cannot use docker's embedded DNS at 127.0.0.11); unset adds no entry")
	fs.StringVar(&cfg.auditSink, "audit-sink", "", "OCSF audit fan-in sink (required)")
	fs.StringVar(&cfg.stateDSN, "state-dsn", "", "Postgres DSN for durable state; empty selects the in-memory store (minimal shelf)")
	fs.StringVar(&cfg.jwksPath, "jwks-path", "",
		"OPTIONAL path to write the static JWKS artifact the deploy layer serves at the "+
			"egress edge's remote_jwks URI (ADR-0019 §35); unset disables the emit. Control "+
			"adds NO listener — it writes a file the deploy layer serves")
	fs.StringVar(&cfg.mcpKeysetPath, "mcp-keyset-path", "",
		"OPTIONAL path to write the static hashed-key-set artifact the deploy layer serves "+
			"to the gateway's config plane; unset disables the emit. Control adds NO listener — "+
			"it writes a file atomically (temp+fsync+rename). The artifact is re-rendered on "+
			"every mcp-key create/revoke. Mirrors -jwks-path (ADR-0027)")
	fs.StringVar(&cfg.mcpKeyFile, "mcp-key-file", "",
		"OPTIONAL path to the minimal-shelf 0600 root-owned hashed-entries file; unset selects "+
			"in-memory-only storage (the minimal shelf default). If set and the file exists on boot, "+
			"it is loaded fail-closed (looser-than-0600 perms abort boot). Written on every "+
			"mcp-key create/revoke via a full atomic temp+fsync+rename rewrite")
	fs.DurationVar(&cfg.sessionIdleTTL, "session-idle-ttl", 0,
		"OPTIONAL idle-session reaper window (NFR-SEC-40). Unset (0) is off on the minimal "+
			"shelf (empty -state-dsn) and resolves to the ≤15 min ceiling on the full shelf; a "+
			"full-shelf value above the ceiling is refused, not clamped. An idle ACTIVE session "+
			"past its window is force-killed and its concurrency slot returned")
	fs.BoolVar(&cfg.deriveChatScope, "derive-chat-scope", false,
		"per-chat storage-scope derivation (ADR-0030, D5). Default false = today's single static scope. "+
			"When true, control rewrites each storage mount FilesystemID to \"<base>-<16hex>\" before minting "+
			"the Storage-JWT, so two chats of one owner mint DISTINCT scopes and a peer chat's guest gets a "+
			"different credential. The suffix is derived from the host-attested owner and host-minted handle, "+
			"never a request body (NFR-SEC-43)")
	fs.StringVar(&cfg.storageScopeBase, "storage-scope-base", "",
		"OPTIONAL deployment-declared storage-scope base fsid the -derive-chat-scope suffix is appended to; "+
			"unset means the base rides each create request's mount. When -derive-chat-scope is on, a base that "+
			"already carries a 16-hex derivation suffix is refused at boot (no double-derivation)")
	fs.BoolVar(&cfg.create, "create-on-start", false, "present a session-create request at startup (kill-switch-first smoke hook)")
	fs.BoolVar(&showVersion, "version", false, "print the version and exit")
	fs.BoolVar(&healthCheck, "health-check", false, "self-probe the ops listener and exit 0 (alive) or non-zero")

	if err := fs.Parse(args); err != nil {
		return config{}, modeServe, fmt.Errorf("%w: %v", errRequiredFlagMissing, err)
	}

	switch {
	case showVersion:
		return cfg, modeVersion, nil
	case healthCheck:
		return cfg, modeHealthCheck, nil
	}
	return cfg, modeServe, nil
}

// validate runs the pre-bind static gates in order: required-flag presence and
// enum membership. These run BEFORE any Store is constructed, so a malformed
// invocation never builds a Store. It returns the first refusal and touches no
// network, so a refusal leaves no listener and no socket. The kill-switch-first
// create gate is NOT here any more — it now flows through the real boot path in
// serve(), so the refusal originates in the Store, not a hardcoded branch.
func validate(cfg config) error {
	// 1. Required-flag presence — the first missing flag is named so an
	//    operator sees exactly what to supply. -state-dsn is deliberately NOT in
	//    this loop: empty is the valid default (the in-memory minimal shelf).
	for _, req := range []struct {
		name  string
		value string
	}{
		{"operator-listen", cfg.operatorListen},
		{"gateway-listen", cfg.gatewayListen},
		{"runtime-tier", cfg.runtimeTier},
		{"runtime-provider", cfg.runtimeProvider},
		{"workload-profile", cfg.workloadProfile},
		{"jwt-signing-key", cfg.jwtSigningKey},
		{"audit-sink", cfg.auditSink},
	} {
		if req.value == "" {
			return fmt.Errorf("%w: -%s", errRequiredFlagMissing, req.name)
		}
	}

	// 2. Enum membership — an unknown tier/provider/profile is refused, never
	//    coerced to a default. The workload profile is closed-enum exactly like the
	//    tier: an omitted profile is caught by the required-flag loop above, and an
	//    unknown one is refused here, never silently defaulted to a permissive
	//    profile (a defaulted profile would silently widen the admission matrix).
	if !knownRuntimeTiers[cfg.runtimeTier] {
		return fmt.Errorf("%w: %q (choose runc|gvisor|firecracker)", errUnknownRuntimeTier, cfg.runtimeTier)
	}
	if !knownRuntimeProviders[cfg.runtimeProvider] {
		return fmt.Errorf("%w: %q (choose docker|k8s)", errUnknownProvider, cfg.runtimeProvider)
	}
	if !knownWorkloadProfiles[cfg.workloadProfile] {
		return fmt.Errorf("%w: %q (choose trusted_operator|internal_workforce|untrusted)", errUnknownWorkloadProfile, cfg.workloadProfile)
	}
	// -jwt-alg is a closed enum with a default of eddsa (NFR-SEC-11); an unknown
	// alg is refused, never coerced. iss/aud/service-url/ca-cert are PROVISIONAL
	// (PIN-PENDING) and deliberately NOT required — they default to empty and are
	// not enum-checked, so a deployment without storage provisioning still validates.
	if !knownJWTAlgs[cfg.jwtAlg] {
		return fmt.Errorf("%w: %q (choose eddsa|es256)", errUnknownJWTAlg, cfg.jwtAlg)
	}

	// Gateway mTLS is ALL-OR-NONE: either all three of -gateway-tls-cert/-key and
	// -gateway-client-ca are set (real mTLS) or none is (the stubbed plain-TCP
	// fail-closed posture, which admits no verified SAN so every Resolve fails
	// closed). A PARTIAL set is a misconfiguration refused fail-closed at boot — it
	// must never silently degrade to plain TCP while the operator believes mTLS is
	// on.
	set := 0
	for _, v := range []string{cfg.gatewayTLSCert, cfg.gatewayTLSKey, cfg.gatewayClientCA} {
		if v != "" {
			set++
		}
	}
	if set != 0 && set != 3 {
		return fmt.Errorf("%w: gateway mTLS is all-or-none — set all of -gateway-tls-cert/-gateway-tls-key/-gateway-client-ca or none", errRequiredFlagMissing)
	}

	// The idle-reaper window is shelf-split validated here, pre-bind: a negative window
	// (either shelf) or a full-shelf window above the NFR-SEC-40 ceiling is refused
	// before any Store is built, so a misconfigured idle timeout never binds a listener.
	// The resolved value itself is recomputed in serve() to drive the reaper tick.
	if _, err := resolveIdleTTL(cfg); err != nil {
		return err
	}

	// The -granted-intents ceiling is parsed and enum-checked here, pre-bind: an
	// unknown intent aborts boot before any Store is built, so a typo never binds a
	// listener while silently serving a narrower set than the operator named. The
	// resolved ceiling itself is recomputed in the Manager build (serve()); this call
	// is purely the fail-closed enum gate.
	if _, err := resolveGrantedIntents(cfg); err != nil {
		return err
	}

	// When -derive-chat-scope is on and the deployment declares a fixed base fsid, a
	// base already carrying a 16-hex derivation suffix is refused pre-bind: deriving a
	// second suffix onto "<base>-<hex>" would produce an unreachable "<base>-<hex>-<hex>"
	// subtree (ADR-0030 double-derivation), so the misconfiguration aborts boot loudly
	// rather than silently minting into a subtree no chat can address. An empty base
	// (the default: the base rides each request) skips the check.
	if cfg.deriveChatScope && cfg.storageScopeBase != "" && derivedScopeSuffixRe.MatchString(cfg.storageScopeBase) {
		return fmt.Errorf("%w: -storage-scope-base %q", errBaseAlreadyDerived, cfg.storageScopeBase)
	}

	return nil
}
