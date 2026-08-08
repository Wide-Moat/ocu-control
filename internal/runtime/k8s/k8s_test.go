// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// fakeAPI is a recording, in-memory kubeAPI: it stores created objects, replays
// a caller-scriptable readiness for GetPod, and records the ordered sequence of
// verbs so a test can assert create/rollback/teardown ORDER, not just the final
// state. It is the k8s analog of the docker recording fake.
type fakeAPI struct {
	mu       sync.Mutex
	pods     map[string]*corev1.Pod
	policies map[string]*netv1.NetworkPolicy
	secrets  map[string]*corev1.Secret
	calls    []string

	// readyPod, when set, is returned by GetPod already Ready. Otherwise GetPod
	// returns whatever is stored (a freshly created pod is not Ready), so a test
	// that wants Materialize to succeed marks it ready via markReady.
	failOn map[string]error
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		pods:     map[string]*corev1.Pod{},
		policies: map[string]*netv1.NetworkPolicy{},
		secrets:  map[string]*corev1.Secret{},
		failOn:   map[string]error{},
	}
}

func (f *fakeAPI) record(v string) { f.calls = append(f.calls, v) }

func (f *fakeAPI) CreateSecret(_ context.Context, s *corev1.Secret) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreateSecret:" + s.Name)
	if err := f.failOn["CreateSecret"]; err != nil {
		return err
	}
	f.secrets[s.Name] = s
	return nil
}

func (f *fakeAPI) CreateNetworkPolicy(_ context.Context, p *netv1.NetworkPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreateNetworkPolicy:" + p.Name)
	if err := f.failOn["CreateNetworkPolicy"]; err != nil {
		return err
	}
	f.policies[p.Name] = p
	return nil
}

func (f *fakeAPI) CreatePod(_ context.Context, p *corev1.Pod) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreatePod:" + p.Name)
	if err := f.failOn["CreatePod"]; err != nil {
		return err
	}
	f.pods[p.Name] = p.DeepCopy()
	return nil
}

func (f *fakeAPI) GetPod(_ context.Context, name string) (*corev1.Pod, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetPod:" + name)
	if err := f.failOn["GetPod"]; err != nil {
		return nil, err
	}
	p, ok := f.pods[name]
	if !ok {
		return nil, notFound(name)
	}
	return p, nil
}

func (f *fakeAPI) DeletePod(_ context.Context, name string, grace *int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := "nil"
	if grace != nil {
		g = itoa(*grace)
	}
	f.record("DeletePod:" + name + ":grace=" + g)
	if err := f.failOn["DeletePod"]; err != nil {
		return err
	}
	if _, ok := f.pods[name]; !ok {
		return notFound(name)
	}
	delete(f.pods, name)
	return nil
}

func (f *fakeAPI) DeleteNetworkPolicy(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DeleteNetworkPolicy:" + name)
	if _, ok := f.policies[name]; !ok {
		return notFound(name)
	}
	delete(f.policies, name)
	return nil
}

func (f *fakeAPI) DeleteSecret(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DeleteSecret:" + name)
	if _, ok := f.secrets[name]; !ok {
		return notFound(name)
	}
	delete(f.secrets, name)
	return nil
}

func (f *fakeAPI) ListManagedPods(_ context.Context) ([]corev1.Pod, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ListManagedPods")
	out := make([]corev1.Pod, 0, len(f.pods))
	for _, p := range f.pods {
		out = append(out, *p)
	}
	return out, nil
}

// markReady flips a stored pod to Ready with an IP so waitReady returns.
func (f *fakeAPI) markReady(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.pods[name]
	p.Status.PodIP = "10.1.2.3"
	p.Status.Phase = corev1.PodRunning
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
}

func notFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, name)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func newTestProvider(t *testing.T, api kubeAPI, tier runtime.RuntimeTier) *Provider {
	t.Helper()
	p, err := New(tier, Deps{API: api, RuntimeClass: "gvisor", Namespace: "ocu-sessions"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// TestMaterialize_CreatesAllThreeObjectsInOrderAndReturnsHandle is the create
// happy path: secret, then policy, then pod, then a readiness wait; the returned
// Sandbox carries the host-derived name and the pure-function pod name as the
// RuntimeID.
func TestMaterialize_CreatesAllThreeObjectsInOrderAndReturnsHandle(t *testing.T) {
	api := newFakeAPI()
	p := newTestProvider(t, api, runtime.TierGvisor)

	// Make the pod Ready as soon as it is created so waitReady returns on the
	// first poll: pre-arm by marking on the first GetPod via a goroutine is
	// overkill; instead create, then the provider's first GetPod sees a
	// not-ready pod, so we drive readiness by marking before Materialize returns.
	// Simplest deterministic approach: run Materialize in a goroutine and mark
	// ready once the pod exists.
	done := make(chan struct {
		sb  runtime.Sandbox
		err error
	}, 1)
	go func() {
		sb, err := p.Materialize(context.Background(), goodSpec())
		done <- struct {
			sb  runtime.Sandbox
			err error
		}{sb, err}
	}()

	// Spin until the pod exists, then mark it ready.
	for {
		api.mu.Lock()
		_, ok := api.pods["ocu-sess-sess-abc"]
		api.mu.Unlock()
		if ok {
			api.markReady("ocu-sess-sess-abc")
			break
		}
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("Materialize: %v", res.err)
	}
	if res.sb.Name != "sess-abc" {
		t.Errorf("Sandbox.Name = %q, want the host-derived name", res.sb.Name)
	}
	if res.sb.RuntimeID != "ocu-sess-sess-abc" {
		t.Errorf("Sandbox.RuntimeID = %q, want the pure-function pod name", res.sb.RuntimeID)
	}
	if res.sb.Egress.Name != "sess-abc" {
		t.Errorf("Sandbox.Egress.Name = %q, want the host-derived session key (the revoke handle)", res.sb.Egress.Name)
	}

	// Order: secret before policy before pod.
	assertOrder(t, api.calls, "CreateSecret:ocu-sess-sess-abc", "CreateNetworkPolicy:ocu-net-sess-abc", "CreatePod:ocu-sess-sess-abc")
}

// TestMaterialize_RollsBackInReverseOnPodFailure is the atomicity keystone: when
// the pod create fails after the secret and policy were created, the provider
// deletes them in REVERSE order (policy, then secret) so no orphan survives, and
// returns ErrMaterialize.
func TestMaterialize_RollsBackInReverseOnPodFailure(t *testing.T) {
	api := newFakeAPI()
	api.failOn["CreatePod"] = errors.New("apiserver refused the pod")
	p := newTestProvider(t, api, runtime.TierGvisor)

	_, err := p.Materialize(context.Background(), goodSpec())
	if !errors.Is(err, runtime.ErrMaterialize) {
		t.Fatalf("Materialize error = %v, want ErrMaterialize", err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.secrets) != 0 {
		t.Error("handoff secret survived a failed create — orphan")
	}
	if len(api.policies) != 0 {
		t.Error("egress policy survived a failed create — orphan")
	}
	if len(api.pods) != 0 {
		t.Error("pod survived its own failed create — orphan")
	}
	// The rollback ran the compensators in reverse: policy delete before secret delete.
	assertOrder(t, api.calls, "CreatePod:ocu-sess-sess-abc", "DeleteNetworkPolicy:ocu-net-sess-abc", "DeleteSecret:ocu-sess-sess-abc")
}

// TestMaterialize_AbortsFirecrackerWithZeroSubstrateCalls pins the fail-closed
// tier gate: a TierFirecracker provider returns ErrNotImplemented having issued
// ZERO API calls — no insecure fallback to a weaker tier.
func TestMaterialize_AbortsFirecrackerWithZeroSubstrateCalls(t *testing.T) {
	api := newFakeAPI()
	p := newTestProvider(t, api, runtime.TierFirecracker)

	// A bounded context so a REGRESSED gate (one that falls through to the
	// never-ready waitReady poll) fails the test on the deadline instead of
	// hanging — the gate must abort before any substrate call, deadline or not.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := p.Materialize(ctx, goodSpec())
	if !errors.Is(err, runtime.ErrNotImplemented) {
		t.Fatalf("Materialize error = %v, want ErrNotImplemented", err)
	}
	if len(api.calls) != 0 {
		t.Errorf("firecracker abort issued %d substrate calls, want ZERO: %v", len(api.calls), api.calls)
	}
}

// TestMaterialize_RejectsMalformedSpecBeforeAnyCall pins fail-closed validation:
// a bad spec is refused with ErrUnsupportedSpec and ZERO substrate calls.
func TestMaterialize_RejectsMalformedSpecBeforeAnyCall(t *testing.T) {
	api := newFakeAPI()
	p := newTestProvider(t, api, runtime.TierGvisor)

	spec := goodSpec()
	spec.Egress.DefaultDeny = false // not deny-default

	_, err := p.Materialize(context.Background(), spec)
	if !errors.Is(err, runtime.ErrUnsupportedSpec) {
		t.Fatalf("Materialize error = %v, want ErrUnsupportedSpec", err)
	}
	if len(api.calls) != 0 {
		t.Errorf("rejected spec issued %d substrate calls, want ZERO", len(api.calls))
	}
}

func assertOrder(t *testing.T, calls []string, want ...string) {
	t.Helper()
	idx := 0
	for _, c := range calls {
		if idx < len(want) && c == want[idx] {
			idx++
		}
	}
	if idx != len(want) {
		t.Errorf("calls %v do not contain the ordered subsequence %v (matched %d)", calls, want, idx)
	}
}
