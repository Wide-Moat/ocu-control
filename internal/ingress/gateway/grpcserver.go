// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sessionv1 "github.com/Wide-Moat/ocu-control/gen/proto/ocu/control/session/v1"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// The generated session-setup gRPC surface (G1, 08-contracts §1: "Session
// set-up RPC: Protobuf/gRPC"), dual-served on the SAME mTLS listener as the
// JSON wire: the connection-manager muxes by protocol, the TLS identity and
// the per-connection ConnInfo derivation are shared, and the service exposes
// EXACTLY Create / Route / Destroy — force-kill, denylist-edit, and
// quota-override are absent by construction (NFR-SEC-26; the absence is the
// invariant).

// grpcConnInfoKey carries the request-derived host-attested ConnInfo into the
// gRPC method context. The mux wrapper stamps it from the SAME
// connInfoFromRequest the JSON handlers use, so the two wires cannot diverge
// on identity derivation.
type grpcConnInfoKey struct{}

// setupServer implements sessionv1.SessionSetupServer over the same Handlers
// the JSON routes drive.
type setupServer struct {
	sessionv1.UnimplementedSessionSetupServer
	handlers *Handlers
	scope    ingress.ServiceScope
	// selfEndpoint is the per-session control endpoint returned to callers:
	// v1 serves ONE shared control endpoint — this listener's own advertised
	// address, the real routing target for every subsequent session RPC.
	selfEndpoint string
}

// connInfoFromContext reads the mux-stamped ConnInfo. Absent means the RPC
// did not come through the listener's mux (a direct in-process call): the
// zero ConnInfo carries no verified SAN and fails closed at the resolver,
// the same posture as the JSON path.
func connInfoFromContext(ctx context.Context) ingress.ConnInfo {
	info, ok := ctx.Value(grpcConnInfoKey{}).(ingress.ConnInfo)
	if !ok {
		return ingress.ConnInfo{Channel: ingress.ChannelGateway}
	}
	return info
}

// grpcStatusFromError maps the SAME service-error taxonomy writeServiceError
// maps for the JSON wire onto gRPC codes, keeping the two wires' refusal
// semantics aligned: not-owned collapses to NotFound (NFR-SEC-43
// indistinguishability), unattested to Unauthenticated, request-derived
// invalid arguments to InvalidArgument with a FIXED message (the wrapped
// detail folds caller-supplied bytes; echoing it would reflect
// attacker-controlled input), everything else a detail-free refusal.
func grpcStatusFromError(err error) error {
	switch {
	case errors.Is(err, ingress.ErrUnattested) || errors.Is(err, lifecycle.ErrUnattested):
		return status.Error(codes.Unauthenticated, "caller identity unattested")
	case errors.Is(err, registry.ErrNotOwned):
		return status.Error(codes.NotFound, "session not addressable")
	case errors.Is(err, lifecycle.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, "invalid request argument")
	default:
		return status.Error(codes.FailedPrecondition, "request refused")
	}
}

// Create admits and materializes a session from the FROZEN proto shape. The
// image is deliberately absent from the wire (reserved 6, PIN-PENDING #205):
// it comes from the deployment pin (ADR-0020 inject-at-materialize), so the
// in-process Image stays empty here and the lifecycle applies the deployment
// default or refuses fail-closed when none is configured.
func (s *setupServer) Create(ctx context.Context, req *sessionv1.CreateRequest) (*sessionv1.CreateResponse, error) {
	if req.GetWorkloadTrustProfile() == sessionv1.WorkloadTrustProfile_WORKLOAD_TRUST_PROFILE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "workload_trust_profile is required (UNSPECIFIED refuses fail-closed)")
	}
	conn := connInfoFromContext(ctx)
	in := CreateRequest{
		SessionHint: req.GetSessionHint(),
		Mount:       mountIntentFromProto(req.GetMountIntent()),
		Egress:      egressPolicyFromProto(req.GetEgressPolicy()),
		Resources:   resourceCapsFromProto(req.GetResourceCaps()),
	}
	row, err := s.handlers.Create(ctx, s.scope, conn, in)
	if err != nil {
		return nil, grpcStatusFromError(err)
	}
	return &sessionv1.CreateResponse{
		SessionId:       row.Key,
		ControlEndpoint: s.selfEndpoint,
	}, nil
}

// Route resolves the caller's OWN session to its control endpoint. Ownership
// keys on the host-attested caller (h.Status already enforces it); a foreign
// or absent id is NotFound, indistinguishable (NFR-SEC-43).
func (s *setupServer) Route(ctx context.Context, req *sessionv1.RouteRequest) (*sessionv1.RouteResponse, error) {
	conn := connInfoFromContext(ctx)
	if _, err := s.handlers.Status(ctx, s.scope, conn, req.GetSessionId()); err != nil {
		return nil, grpcStatusFromError(err)
	}
	return &sessionv1.RouteResponse{ControlEndpoint: s.selfEndpoint}, nil
}

// Destroy tears down the caller's OWN session — the cooperative service
// teardown, never the operator force path (NFR-SEC-26).
func (s *setupServer) Destroy(ctx context.Context, req *sessionv1.DestroyRequest) (*sessionv1.DestroyResponse, error) {
	conn := connInfoFromContext(ctx)
	if err := s.handlers.Destroy(ctx, s.scope, conn, req.GetSessionId()); err != nil {
		return nil, grpcStatusFromError(err)
	}
	return &sessionv1.DestroyResponse{}, nil
}

// mountIntentFromProto, egressPolicyFromProto, resourceCapsFromProto convert
// the frozen wire messages to the in-process runtime types field-for-field.
func mountIntentFromProto(m *sessionv1.MountIntent) runtime.MountIntent {
	if m == nil {
		return runtime.MountIntent{}
	}
	return runtime.MountIntent{
		Destination:   m.GetDestination(),
		FilesystemID:  m.GetFilesystemId(),
		MemoryStoreID: m.GetMemoryStoreId(),
		ReadOnly:      m.GetReadOnly(),
	}
}

func egressPolicyFromProto(e *sessionv1.EgressPolicy) runtime.EgressPolicy {
	if e == nil {
		return runtime.EgressPolicy{}
	}
	return runtime.EgressPolicy{
		DefaultDeny:     e.GetDefaultDeny(),
		AllowedUpstream: e.GetAllowedUpstream(),
		FilesystemID:    e.GetFilesystemId(),
	}
}

func resourceCapsFromProto(rc *sessionv1.ResourceCaps) runtime.ResourceCaps {
	if rc == nil {
		return runtime.ResourceCaps{}
	}
	caps := runtime.ResourceCaps{
		CPUCores:    rc.GetCpuCores(),
		MemoryBytes: rc.GetMemoryBytes(),
	}
	if rc.PidsLimit != nil {
		v := rc.GetPidsLimit()
		caps.PidsLimit = &v
	}
	return caps
}

// newGRPCServer builds the gRPC server carrying ONLY the SessionSetup
// service. No reflection service is registered: the surface is the frozen
// contract, not a discovery endpoint.
func newGRPCServer(h *Handlers, scope ingress.ServiceScope, selfEndpoint string) *grpc.Server {
	// nosemgrep: go.grpc.security.grpc-server-insecure-connection.grpc-server-insecure-connection
	// This server deliberately carries NO grpc.Creds(): it serves via
	// ServeHTTP over the shared gateway listener, which is already a
	// tls.NewListener terminating mTLS 1.3 with RequireAndVerifyClientCert
	// (gateway.go Bind, ServerTLSConfig). Adding transport credentials here
	// would attempt a SECOND TLS handshake over an already-encrypted, already
	// client-authenticated connection — breaking the wire, not securing it.
	// The encryption + peer verification the rule demands live in the
	// listener, which is where the two wires share one TLS identity.
	srv := grpc.NewServer()
	sessionv1.RegisterSessionSetupServer(srv, &setupServer{
		handlers:     h,
		scope:        scope,
		selfEndpoint: selfEndpoint,
	})
	return srv
}

// grpcMux routes gRPC traffic (HTTP/2 + application/grpc) to the gRPC server
// with the host-attested ConnInfo stamped into the method context, and
// everything else to the JSON mux. One listener, one TLS identity, two wires.
func grpcMux(grpcSrv *grpc.Server, jsonMux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			ctx := context.WithValue(r.Context(), grpcConnInfoKey{}, connInfoFromRequest(r))
			grpcSrv.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		jsonMux.ServeHTTP(w, r)
	})
}

// ensure the interface stays satisfied as the generated surface evolves.
var _ sessionv1.SessionSetupServer = (*setupServer)(nil)

// sessionRowSanity keeps the state import honest (row fields feed both wires).
var _ = state.SessionRow{}
