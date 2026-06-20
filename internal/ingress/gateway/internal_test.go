// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
)

// errUnclassified is a refusal that is neither unattested nor not-owned, so
// writeServiceError maps it to the default 409.
var errUnclassified = errors.New("gateway_internal_test: unclassified refusal")

// contextWithGatewayMarker stamps the same ConnContext marker Serve stamps, so
// connInfoFromRequest treats the request as served through Serve.
func contextWithGatewayMarker(r *http.Request) context.Context {
	return context.WithValue(r.Context(), connInfoKey{}, ingress.ChannelGateway)
}

// TestVerifiedSANsOfNilAndEmpty proves verifiedSANsOf fails closed on a nil state
// and a handshake state with no verified chain: both yield no SAN, so the resolver
// refuses.
func TestVerifiedSANsOfNilAndEmpty(t *testing.T) {
	t.Parallel()
	if sans := verifiedSANsOf(nil); sans != nil {
		t.Fatalf("verifiedSANsOf(nil) = %v; want nil", sans)
	}
	if sans := verifiedSANsOf(&tls.ConnectionState{}); sans != nil {
		t.Fatalf("verifiedSANsOf(empty state) = %v; want nil (no verified chain)", sans)
	}
}

// TestVerifiedSANsOfReadsVerifiedChain proves verifiedSANsOf reads ONLY the leaf of
// the first verified chain (DNS + URI SANs), never the raw presented cert: a
// populated VerifiedChains yields its leaf's SANs.
func TestVerifiedSANsOfReadsVerifiedChain(t *testing.T) {
	t.Parallel()
	uri, _ := url.Parse("spiffe://td.test/acme/worker-7")
	leaf := &x509.Certificate{
		DNSNames: []string{"svc.internal"},
		URIs:     []*url.URL{uri},
	}
	st := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	sans := verifiedSANsOf(st)
	if len(sans) != 2 {
		t.Fatalf("verifiedSANsOf = %v; want the DNS and URI SANs", sans)
	}
	if sans[0] != "svc.internal" || sans[1] != "spiffe://td.test/acme/worker-7" {
		t.Fatalf("verifiedSANsOf = %v; want [svc.internal spiffe://td.test/acme/worker-7]", sans)
	}
}

// TestConnInfoFromRequestAbsentMarker proves connInfoFromRequest fails closed for a
// request not served through Serve (no channel marker on the context): it yields a
// gateway-channel ConnInfo with no SANs, so the resolver refuses.
func TestConnInfoFromRequestAbsentMarker(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/v1alpha/sessions", nil)
	info := connInfoFromRequest(r)
	if info.Channel != ingress.ChannelGateway {
		t.Fatalf("ConnInfo channel = %v; want ChannelGateway", info.Channel)
	}
	if len(info.CertSANs) != 0 {
		t.Fatalf("ConnInfo CertSANs = %v; want none (request not served through Serve)", info.CertSANs)
	}
}

// TestConnInfoFromRequestWithMarkerAndTLS proves connInfoFromRequest derives the
// verified SANs from r.TLS when the channel marker is present: the marked,
// handshake-complete request carries the verified leaf's SANs.
func TestConnInfoFromRequestWithMarkerAndTLS(t *testing.T) {
	t.Parallel()
	uri, _ := url.Parse("spiffe://td.test/acme/worker-7")
	leaf := &x509.Certificate{URIs: []*url.URL{uri}}
	r := httptest.NewRequest(http.MethodPost, "/v1alpha/sessions", nil)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	// Mark the request as served through Serve (the ConnContext marker).
	ctx := contextWithGatewayMarker(r)
	info := connInfoFromRequest(r.WithContext(ctx))
	if len(info.CertSANs) != 1 || info.CertSANs[0] != "spiffe://td.test/acme/worker-7" {
		t.Fatalf("ConnInfo CertSANs = %v; want the verified URI SAN", info.CertSANs)
	}
}

// TestWriteServiceErrorDefaultIs409 proves writeServiceError maps an unclassified
// refusal (neither unattested nor not-owned) to 409.
func TestWriteServiceErrorDefaultIs409(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeServiceError(rec, errUnclassified)
	if rec.Code != http.StatusConflict {
		t.Fatalf("writeServiceError(unclassified) = %d; want 409", rec.Code)
	}
}

// TestDecodeJSONEmptyAndNilBody proves decodeJSON treats a nil body and an empty
// body as the zero value (no error), so a parameterless POST decodes cleanly.
func TestDecodeJSONEmptyAndNilBody(t *testing.T) {
	t.Parallel()
	var v hintBody
	rNil := httptest.NewRequest(http.MethodPost, "/x", nil)
	rNil.Body = nil
	if err := decodeJSON(rNil, &v); err != nil {
		t.Fatalf("decodeJSON(nil body) = %v; want nil", err)
	}
	rEmpty := httptest.NewRequest(http.MethodPost, "/x", http.NoBody)
	if err := decodeJSON(rEmpty, &v); err != nil {
		t.Fatalf("decodeJSON(empty body) = %v; want nil", err)
	}
}
