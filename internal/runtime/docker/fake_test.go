// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"fmt"
	"sync"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

// notFoundError is a typed not-found that cerrdefs.IsNotFound recognizes, so the
// fake can drive the provider's idempotent IsNotFound -> ErrNoSuchContainer path
// without a live daemon.
type notFoundError struct{ msg string }

func (e notFoundError) Error() string { return e.msg }
func (notFoundError) NotFound()       {}
func newNotFound(m string) error      { return notFoundError{msg: m} }

// conflictError is a typed conflict that cerrdefs.IsConflict recognizes, so the
// fake can drive the network-active (IsConflict -> ErrNetworkActive) path.
type conflictError struct{ msg string }

func (e conflictError) Error() string { return e.msg }
func (conflictError) Conflict()       {}
func newConflict(m string) error      { return conflictError{msg: m} }

// Compile-time proof the fake's typed errors satisfy the containerd/errdefs
// predicates the provider branches on; if the interface contract drifts these
// stop compiling.
var (
	_ = func() bool { return cerrdefs.IsNotFound(notFoundError{}) }
	_ = func() bool { return cerrdefs.IsConflict(conflictError{}) }
)

// call records a single observed SDK invocation, in order, so a test can assert
// the create/teardown call sequence (e.g. NetworkRemove strictly after
// ContainerRemove) without a live daemon.
type call struct {
	op     string // "NetworkCreate" | "ContainerCreate" | ... — the SDK method name.
	target string // container id/name or network name, where meaningful.
}

// fakeAPI is the recording dockerAPI fake. It logs every call in order and lets a
// test inject a per-op error (and, for the substrate-state assertions, tracks which
// networks/containers it currently "holds" so a no-orphan invariant is checkable).
type fakeAPI struct {
	mu sync.Mutex

	// calls is the ordered log of observed SDK invocations.
	calls []call

	// errOn maps an op name to the error its NEXT invocation returns; a nil entry
	// (or absent key) means success. Keys: NetworkCreate, ContainerCreate,
	// ContainerStart, ContainerStop, ContainerRemove, NetworkRemove, ContainerList.
	errOn map[string]error

	// networks / containers track the substrate objects the fake currently holds,
	// so a test asserts the no-orphan post-condition (after a failed Materialize or
	// a teardown the fake holds neither object).
	networks   map[string]bool
	containers map[string]bool

	// nextID is the container id the fake's ContainerCreate hands back.
	nextID string

	// listResult is what ContainerList returns (the reconciler input).
	listResult []container.Summary

	// netCreateOpts records, per bridge name, the network.CreateOptions the
	// provider passed, so a test can assert Internal:true and the labels without a
	// daemon.
	netCreateOpts map[string]network.CreateOptions

	// lastHostConfig captures the *container.HostConfig of the MOST RECENT
	// ContainerCreate, so a test can assert on the exact HostConfig the provider
	// would send to the daemon (e.g. the tier-derived Runtime string). It is an
	// additive observation field — it changes no recorded-call behavior.
	lastHostConfig *container.HostConfig
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		errOn:         map[string]error{},
		networks:      map[string]bool{},
		containers:    map[string]bool{},
		nextID:        "ctr-deadbeef",
		netCreateOpts: map[string]network.CreateOptions{},
	}
}

// record appends an observed call under the lock.
func (f *fakeAPI) record(op, target string) {
	f.calls = append(f.calls, call{op: op, target: target})
}

// ops returns the ordered list of op names observed, for sequence assertions.
func (f *fakeAPI) ops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	for i := range f.calls {
		out[i] = f.calls[i].op
	}
	return out
}

// countOp returns how many times op was observed.
func (f *fakeAPI) countOp(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for i := range f.calls {
		if f.calls[i].op == op {
			n++
		}
	}
	return n
}

// indexOf returns the index of the first observed call with the given op, or -1.
func (f *fakeAPI) indexOf(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.calls {
		if f.calls[i].op == op {
			return i
		}
	}
	return -1
}

func (f *fakeAPI) NetworkCreate(_ context.Context, name string, options network.CreateOptions) (network.CreateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("NetworkCreate", name)
	f.netCreateOpts[name] = options
	if err := f.errOn["NetworkCreate"]; err != nil {
		return network.CreateResponse{}, err
	}
	f.networks[name] = true
	return network.CreateResponse{ID: "net-" + name}, nil
}

func (f *fakeAPI) NetworkRemove(_ context.Context, networkID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("NetworkRemove", networkID)
	if err := f.errOn["NetworkRemove"]; err != nil {
		// A not-found means the object was already gone (removed out-of-band): model
		// that by dropping it, so the no-orphan post-condition reflects reality.
		if cerrdefs.IsNotFound(err) {
			delete(f.networks, networkID)
		}
		return err
	}
	delete(f.networks, networkID)
	return nil
}

func (f *fakeAPI) ContainerCreate(_ context.Context, _ *container.Config, hostConfig *container.HostConfig, _ *network.NetworkingConfig, _ *ocispecPlatform, name string) (container.CreateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ContainerCreate", name)
	f.lastHostConfig = hostConfig
	if err := f.errOn["ContainerCreate"]; err != nil {
		return container.CreateResponse{}, err
	}
	f.containers[f.nextID] = true
	return container.CreateResponse{ID: f.nextID}, nil
}

func (f *fakeAPI) ContainerStart(_ context.Context, containerID string, _ container.StartOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ContainerStart", containerID)
	return f.errOn["ContainerStart"]
}

func (f *fakeAPI) ContainerStop(_ context.Context, containerID string, _ container.StopOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ContainerStop", containerID)
	return f.errOn["ContainerStop"]
}

func (f *fakeAPI) ContainerRemove(_ context.Context, containerID string, _ container.RemoveOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ContainerRemove", containerID)
	if err := f.errOn["ContainerRemove"]; err != nil {
		// A not-found means the container was already gone (removed out-of-band):
		// model that by dropping it, so the no-orphan post-condition reflects reality.
		if cerrdefs.IsNotFound(err) {
			delete(f.containers, containerID)
		}
		return err
	}
	delete(f.containers, containerID)
	return nil
}

func (f *fakeAPI) ContainerList(_ context.Context, _ container.ListOptions) ([]container.Summary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ContainerList", "")
	if err := f.errOn["ContainerList"]; err != nil {
		return nil, err
	}
	return f.listResult, nil
}

// holdsAnyFor reports whether the fake still holds the network or container for a
// session name (the no-orphan check). The container id the fake mints is nextID;
// the bridge name is the pure-function networkName(name).
func (f *fakeAPI) holdsAnyFor(bridge, ctrID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.networks[bridge] || f.containers[ctrID]
}

// String renders the observed op sequence for test failure messages.
func (f *fakeAPI) String() string {
	return fmt.Sprintf("%v", f.ops())
}
