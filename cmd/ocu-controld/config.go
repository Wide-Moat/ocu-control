// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// Flag surface and pre-bind validation for ocu-controld. The validation order
// here is the load-bearing part of the scaffold: required-flag presence and
// enum membership are checked, then the KILL-SWITCH-FIRST gate refuses a
// create before any listener could bind. No network endpoint is opened on any
// path through this file.

package main

import (
	"flag"
	"fmt"
	"io"
)

type runMode int

const (
	modeServe runMode = iota
	modeVersion
	modeHealthCheck
)

// config is the parsed serving invocation. Fields mirror the scaffold flag
// surface; the real config grows with the implementation.
type config struct {
	operatorListen  string // operator/lifecycle ingress endpoint (distinct from gateway)
	gatewayListen   string // gateway service-identity ingress endpoint
	runtimeTier     string // deployment-wide isolation tier; never per-request
	runtimeProvider string // container backend behind the RuntimeProvider seam
	workloadProfile string // deployment-declared trust profile feeding the admission matrix; never per-request
	jwtSigningKey   string // path to the Storage-JWT signing key (config/secret mount)
	auditSink       string // OCSF audit fan-in sink
	stateDSN        string // Postgres DSN for durable state; empty selects the in-memory store
	create          bool   // a create request presented at startup (smoke hook)
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
	fs.StringVar(&cfg.jwtSigningKey, "jwt-signing-key", "", "path to the Storage-JWT signing key (required)")
	fs.StringVar(&cfg.auditSink, "audit-sink", "", "OCSF audit fan-in sink (required)")
	fs.StringVar(&cfg.stateDSN, "state-dsn", "", "Postgres DSN for durable state; empty selects the in-memory store (minimal shelf)")
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

	return nil
}
