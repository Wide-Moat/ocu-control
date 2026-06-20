// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// The -health-check sub-command: a thin client that dials the already-running
// daemon's operator /healthz over the operator Unix socket and exits 0 iff the
// daemon reports ready. It is the exact transport the operator listener serves
// (HTTP-over-UDS), so a container/orchestrator probe (the Dockerfile HEALTHCHECK,
// the compose healthcheck, both k8s exec probes) reuses the daemon binary as its
// own probe with no shell or curl in a distroless image.
//
// It is a CLIENT only: it never constructs the Store, the listeners, the signer, or
// any host state — it opens one connection to the socket the serving daemon already
// bound and reads one response. A connection refused (no daemon, or not yet bound), a
// non-200 (not-ready: the readiness enum has not flipped), or a timeout is a non-nil
// error the caller maps to a non-zero exit, which is exactly the red a liveness/
// readiness probe must see.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// healthCheckTimeout bounds the whole probe — dial, request, and response read. It
// is short because a healthy daemon answers /healthz from an in-memory readiness
// enum essentially instantly; a probe that cannot get an answer in this window is
// reporting an unhealthy daemon, which is the point. The orchestrator's own probe
// timeout (compose timeout: 5s, k8s timeoutSeconds: 5) sits above this.
const healthCheckTimeout = 3 * time.Second

// errHealthCheckNoSocket is returned when -operator-listen was not supplied to the
// health-check invocation, so there is no socket path to dial. The probe in every
// shipped manifest passes -operator-listen alongside -health-check precisely so the
// probe dials the SAME socket the serving container bound.
var errHealthCheckNoSocket = errors.New("health-check: -operator-listen is required so the probe dials the same operator socket the daemon serves")

// healthCheck dials the operator /healthz over the Unix socket re-derived from the
// operator-listen endpoint (the SAME flag the serving path binds) and returns nil
// iff the daemon answers 200. It boots nothing: it is a one-connection HTTP-over-UDS
// client. A missing endpoint, a refused/failed dial, a non-200, or a timeout is a
// non-nil error the caller turns into a non-zero exit.
func healthCheck(ctx context.Context, operatorListen string) error {
	socket := socketPathOf(operatorListen)
	if socket == "" {
		return errHealthCheckNoSocket
	}

	probeCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()

	// A dedicated transport that ignores the URL host and dials the operator Unix
	// socket directly — the same HTTP-over-UDS shape operator.Serve answers on. The
	// "http://unix/healthz" URL host is a placeholder the DialContext discards.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(dialCtx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
	}

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://unix/healthz", nil)
	if err != nil {
		return fmt.Errorf("health-check: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Connection refused (no daemon / socket not yet bound), a dial timeout, or any
		// transport failure is an unhealthy verdict.
		return fmt.Errorf("health-check: dial operator /healthz at %q: %w", socket, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// A non-200 is the readiness handler reporting not-ready (503) or any other
		// non-healthy status: a red probe, not a daemon-absent error.
		return fmt.Errorf("health-check: operator /healthz returned %d, want 200", resp.StatusCode)
	}
	return nil
}
