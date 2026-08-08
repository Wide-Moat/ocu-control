// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package publish is Control's client for the central audit ingest: the transport
// half of the F10 fan-in whose composite writer lives in internal/audit/ocsf.
//
// WHERE EACH RULE COMES FROM. The vendored contract
// (contracts/audit/audit-fanin.asyncapi.yaml) is authoritative for WHAT is sent: the
// channel address, mTLS source identity, the seven mandatory envelope fields with
// their bounds and the outcome enum, and the fact that prev_hash/chain_hash are
// authored by the pipeline and never published by a source. The contract
// deliberately does NOT pin the transport -- it says the substrate is a
// component-spec choice and leaves the binding protocol-agnostic -- so the HTTP
// binding below (route shape, method, status semantics) comes from the ingest
// component's own surface. That split is why validation here is written against the
// contract and not against whatever the far side happens to accept today: a server
// that grew looser than the contract must not silently widen what Control emits.
package publish

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

var (
	// ErrEnvelope is a refusal to SEND: the envelope violates the contract, so the
	// event is rejected here rather than shipped for the far side to reject. It is
	// still a publish failure, so the composite writer still fails closed.
	ErrEnvelope = errors.New("publish: envelope violates the audit fan-in contract")
	// ErrSequenceConflict is the ingest reporting that the per-source sequence did not
	// advance. It is NOT a benign duplicate: a duplicate of an already-committed
	// sequence is acknowledged. A conflict means the ordering input broke, which is
	// the one thing the per-source chain cannot repair by itself, so it fails closed
	// like every other non-acknowledgement.
	ErrSequenceConflict = errors.New("publish: ingest rejected the sequence as non-monotonic")
	// ErrNotCommitted is any other non-acknowledgement: a rejected envelope, a missing
	// or unauthorized client certificate, an unknown channel, a durable-commit failure
	// at the far side, or a transport error.
	ErrNotCommitted = errors.New("publish: ingest did not commit the event")
	// ErrConfig is a refusal to CONSTRUCT: a client that cannot possibly publish
	// (no endpoint, no channel, unusable key material) is refused at boot rather than
	// failing on the first privileged action.
	ErrConfig = errors.New("publish: invalid client configuration")
)

// Contract-derived envelope bounds (NFR-SEC-51 in the AsyncAPI). They are enforced
// BEFORE the request is built so an over-long field is a local, named refusal rather
// than a remote 400 the operator has to correlate back to a field.
const (
	maxTraceID   = 128
	maxSessionID = 128
	maxActorID   = 256
	maxResource  = 1024
	maxAction    = 128
)

// outcomes is the contract's closed enum for the outcome field. A value outside it
// is refused: the field aligns the OCSF status_id downstream, so a free-form string
// would survive publication and degrade the SIEM view instead of failing here.
var outcomes = map[string]bool{"success": true, "failure": true, "unknown": true}

// ControlPlaneChannel is Control's channel address from the contract. A source may
// publish only to its own channel; the far side binds the channel to the verified
// peer identity, so naming another component's channel is refused there, not here.
const ControlPlaneChannel = "audit.ingest.control-plane"

// routePrefix is the ingest's path prefix under the HTTP binding; the channel
// address is the remaining path segment.
const routePrefix = "/v1alpha/audit/"

// Config is the deployment-supplied wiring for the central ingest leg.
type Config struct {
	// BaseURL is the ingest origin, e.g. https://audit.internal:8443.
	BaseURL string
	// Channel is the source's channel address; empty means ControlPlaneChannel.
	Channel string
	// ClientCertPath / ClientKeyPath are Control's mTLS identity. The verified peer
	// identity IS the audit source (the contract makes payload source-like fields
	// untrusted), so these are not optional: without them the far side cannot attribute
	// the event and refuses it.
	ClientCertPath string
	ClientKeyPath  string
	// CACertPath anchors the ingest's server certificate.
	CACertPath string
	// Timeout bounds one publish attempt; zero selects defaultTimeout.
	Timeout time.Duration
}

// defaultTimeout bounds a publish so a wedged ingest cannot hold a privileged action
// open indefinitely. The action is denied on timeout (fail-closed), so this is a
// bound on how long the denial takes, not a window in which the event might sneak in.
const defaultTimeout = 10 * time.Second

// Client publishes one pre-chain event per call over mTLS. It is safe for concurrent
// use (http.Client is), holds no state between calls, and never retries: a retry
// would re-send a sequence the caller may have already advanced past, and the
// caller's fail-closed denial is the correct response to a failed publish.
type Client struct {
	http    *http.Client
	url     string
	channel string
}

// New builds a Client, loading the mTLS material eagerly so a misconfigured
// deployment fails at boot rather than on the first privileged action.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("%w: empty base URL", ErrConfig)
	}
	if cfg.ClientCertPath == "" || cfg.ClientKeyPath == "" {
		return nil, fmt.Errorf("%w: mTLS client certificate and key are required -- the verified peer identity IS the audit source", ErrConfig)
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: load client keypair: %v", ErrConfig, err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read CA certificate: %v", ErrConfig, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: CA certificate file contains no usable certificate", ErrConfig)
		}
		tlsCfg.RootCAs = pool
	}
	channel := cfg.Channel
	if channel == "" {
		channel = ControlPlaneChannel
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		url:     strings.TrimRight(cfg.BaseURL, "/") + routePrefix + channel,
		channel: channel,
	}, nil
}

// NewWithHTTPClient builds a Client over a caller-supplied http.Client. It exists so
// a test can drive the real request-building, validation, and status handling against
// a local server without provisioning a certificate authority -- the code under test
// is then the same code that runs in production, minus only the TLS material.
func NewWithHTTPClient(hc *http.Client, baseURL, channel string) (*Client, error) {
	if hc == nil {
		return nil, fmt.Errorf("%w: nil http client", ErrConfig)
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("%w: empty base URL", ErrConfig)
	}
	if channel == "" {
		channel = ControlPlaneChannel
	}
	return &Client{http: hc, url: strings.TrimRight(baseURL, "/") + routePrefix + channel, channel: channel}, nil
}

// Publish sends one event and returns nil ONLY if the ingest acknowledged a durable
// commit. Every other outcome is an error, deliberately without exception: the
// composite writer treats a non-nil error as "not committed" and denies the
// privileged action, so any status quietly mapped to nil here would be an action
// acknowledged with no central record of it.
func (c *Client) Publish(ctx context.Context, wire ocsf.PublishWire) error {
	if err := validate(wire); err != nil {
		return err
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("%w: marshal envelope: %v", ErrEnvelope, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrNotCommitted, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotCommitted, err)
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused; the body is a short
		// status string on every path.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// Acknowledged: durably committed, or recognised as an already-committed
		// duplicate. Both mean the event is in the central log.
		return nil
	case http.StatusConflict:
		return fmt.Errorf("%w: channel %s sequence %d", ErrSequenceConflict, c.channel, wire.Sequence)
	default:
		return fmt.Errorf("%w: channel %s returned HTTP %d", ErrNotCommitted, c.channel, resp.StatusCode)
	}
}

// validate enforces the contract's envelope rules before anything leaves the process.
// It is a fail-closed refusal, not a sanitiser: nothing is truncated or defaulted,
// because a silently shortened actor_id or a coerced outcome would publish a record
// that misrepresents what happened.
func validate(w ocsf.PublishWire) error {
	for _, f := range []struct {
		name  string
		value string
		max   int
	}{
		{"trace_id", w.TraceID, maxTraceID},
		{"session_id", w.SessionID, maxSessionID},
		{"actor_id", w.ActorID, maxActorID},
		{"resource", w.Resource, maxResource},
		{"action", w.Action, maxAction},
	} {
		if f.value == "" {
			return fmt.Errorf("%w: %s is required", ErrEnvelope, f.name)
		}
		if len(f.value) > f.max {
			return fmt.Errorf("%w: %s is %d bytes, over the %d-byte bound", ErrEnvelope, f.name, len(f.value), f.max)
		}
	}
	if !outcomes[w.Outcome] {
		return fmt.Errorf("%w: outcome %q is outside the enum (success|failure|unknown)", ErrEnvelope, w.Outcome)
	}
	if len(w.Payload) == 0 {
		return fmt.Errorf("%w: payload is required", ErrEnvelope)
	}
	return nil
}
