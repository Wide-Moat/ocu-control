// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"encoding/json"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ADR-0044: the OCSF class follows the record's own semantics, and the event
// carries that class's required objects. Every control-plane record used to
// emit API Activity (6003) — a class this source's fan-in channel does not
// declare, and one the events did not conform to anyway: 6003 carries its
// operation in an `api` object, there was none, and the verb lived in
// metadata.unmapped, the bucket OCSF reserves for what could not be mapped.
//
// These bind the mapping per record family, so a new action cannot inherit a
// class by default.

// TestEveryActionMapsToItsHonestClass is the keystone. The session lifecycle
// and the enumerated privileged actions are entity management (3004) — the
// session, the denylist, the quota, the retention policy and the API key are
// all entities this plane manages. The executed tool call is the one genuinely
// API-shaped record, and stays 6003.
func TestEveryActionMapsToItsHonestClass(t *testing.T) {
	for _, tc := range []struct {
		action audit.Action
		want   uint32
	}{
		{audit.ActionCreateCommit, classUIDEntityManagement},
		{audit.ActionDestroy, classUIDEntityManagement},
		{audit.ActionCreateResume, classUIDEntityManagement},
		{audit.ActionReconcileReclaim, classUIDEntityManagement},
		{audit.ActionCreateRejected, classUIDEntityManagement},
		{audit.ActionRevokeOne, classUIDEntityManagement},
		{audit.ActionRevokeAll, classUIDEntityManagement},
		{audit.ActionEditDenylist, classUIDEntityManagement},
		{audit.ActionOverrideQuota, classUIDEntityManagement},
		{audit.ActionRetentionPolicy, classUIDEntityManagement},
		{audit.ActionResumeGlobal, classUIDEntityManagement},
		{audit.ActionMCPKeyCreate, classUIDEntityManagement},
		{audit.ActionMCPKeyRevoke, classUIDEntityManagement},
		{audit.ActionExec, classUIDAPIActivity},
	} {
		t.Run(tc.action.String(), func(t *testing.T) {
			if got := classFor(tc.action); got != tc.want {
				t.Errorf("classFor(%s) = %d, want %d", tc.action, got, tc.want)
			}
		})
	}
}

// TestClassAndCategoryAgree pins the pair. category_uid is not free-standing —
// it names the OCSF category the class belongs to, and a mismatched pair
// describes an event that exists in no schema.
func TestClassAndCategoryAgree(t *testing.T) {
	for _, a := range []audit.Action{audit.ActionExec, audit.ActionDestroy} {
		class := classFor(a)
		got := categoryFor(class)
		want := class / 1000
		if uint32(got) != want {
			t.Errorf("%s: class %d sits in category %d; the class uid says %d",
				a, class, got, want)
		}
	}
}

// TestEntityEventsCarryTheEntityObject is the conformance half for 3004. A
// 3004 event without an entity names no subject, so a reviewer filtering on
// "which denylist changed" reads nothing.
func TestEntityEventsCarryTheEntityObject(t *testing.T) {
	for _, a := range []audit.Action{
		audit.ActionEditDenylist, audit.ActionOverrideQuota,
		audit.ActionCreateCommit, audit.ActionMCPKeyRevoke,
	} {
		t.Run(a.String(), func(t *testing.T) {
			ev := eventForAction(t, a)
			if ev.Entity == nil {
				t.Fatalf("%s emits class %d with no entity object; the record names no "+
					"subject, so a detection cannot say WHICH entity changed", a, ev.ClassUID)
			}
			if ev.Entity.Type == "" {
				t.Errorf("%s: entity.type is empty; the type is what discriminates a "+
					"denylist edit from a quota override within the class", a)
			}
			if ev.API != nil {
				t.Errorf("%s is entity management but carries an api object, which "+
					"belongs to API Activity", a)
			}
		})
	}
}

// TestExecCarriesTheAPIObject is the conformance half for 6003, and the reason
// the old mapping was not merely on the wrong channel: the class requires this
// object, and without it the verb had nowhere to live but unmapped.
func TestExecCarriesTheAPIObject(t *testing.T) {
	ev := eventForAction(t, audit.ActionExec)
	if ev.API == nil {
		t.Fatal("exec emits API Activity with no api object; OCSF carries the " +
			"operation there, so the event is not conformant 6003")
	}
	if ev.API.Operation == "" {
		t.Error("api.operation is empty; the operation is the primary discriminator " +
			"of an API Activity event")
	}
	if ev.Entity != nil {
		t.Error("exec is API activity but carries an entity object, which belongs " +
			"to Entity Management")
	}
}

// TestVerbIsNotOnlyInUnmapped is the property that survives a class change.
// metadata.unmapped is where OCSF puts fields it could not map; a record whose
// verb lives ONLY there has been given the wrong class, whichever class it is.
//
// This is deliberately separate from the class assertions: those compare a
// number, and a build that returned the right numbers while still parking the
// verb in unmapped would satisfy every one of them.
func TestVerbIsNotOnlyInUnmapped(t *testing.T) {
	for _, a := range []audit.Action{audit.ActionEditDenylist, audit.ActionExec} {
		t.Run(a.String(), func(t *testing.T) {
			ev := eventForAction(t, a)
			raw, err := json.Marshal(ev)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			// Strip metadata entirely: what remains is the class-native surface.
			delete(doc, "metadata")
			rest, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("remarshal: %v", err)
			}
			if !containsSubject(string(rest), a) {
				t.Errorf("%s: nothing outside metadata names the record's subject — "+
					"the discriminator lives only in unmapped, which is where OCSF puts "+
					"what it could NOT map. Body was: %s", a, rest)
			}
		})
	}
}

// TestEntityTypeDiscriminatesWithinTheClass is the invariant every other test
// here misses. Once the class is right and the entity object is present with a
// non-empty type, a build that returned the SAME type for every record would
// satisfy all of them — and would have destroyed the thing entity.type exists
// for. A denylist edit and a quota override are both 3004; the type is what
// tells a detection which one it is looking at.
//
// Mutation testing found this: collapsing entityTypeFor to a single return
// value left the whole suite green.
func TestEntityTypeDiscriminatesWithinTheClass(t *testing.T) {
	// Actions that act on genuinely different entities. If any two report the
	// same type, the field has stopped discriminating.
	distinct := []audit.Action{
		audit.ActionEditDenylist,
		audit.ActionOverrideQuota,
		audit.ActionRetentionPolicy,
		audit.ActionMCPKeyCreate,
		audit.ActionDestroy,
	}

	seen := map[string]audit.Action{}
	for _, a := range distinct {
		got := eventForAction(t, a).Entity.Type
		if prior, dup := seen[got]; dup {
			t.Errorf("%s and %s both report entity.type %q; the field no longer "+
				"distinguishes them, so a detection keyed on it cannot tell a %s from "+
				"a %s", prior, a, got, prior, a)
			continue
		}
		seen[got] = a
	}

	// The session-scoped actions SHOULD share a type — they act on the same kind
	// of entity — so a build that made every action's type unique would be just
	// as wrong. This is the control on the assertion above.
	if a, b := eventForAction(t, audit.ActionCreateCommit).Entity.Type,
		eventForAction(t, audit.ActionCreateResume).Entity.Type; a != b {
		t.Errorf("create_commit reports %q and create_resume %q; both act on a "+
			"session, so a per-action type would be naming the verb, not the entity", a, b)
	}
}

// eventForAction builds one event through the production path, so these tests
// see what the emitter emits rather than a fixture assembled here.
func eventForAction(t *testing.T, a audit.Action) OCSFEvent {
	t.Helper()
	return buildEvent(state.NewFakeClock(fixedStart), audit.Record{
		Action:  a,
		Channel: "operator",
		Key:     "sess-key-1",
		Caller:  "op-caller",
		Tenant:  "tenant-9",
		Reason:  "test",
	})
}

// containsSubject reports whether the class-native surface names what the
// record is about: the entity type for 3004, the operation for 6003.
func containsSubject(body string, a audit.Action) bool {
	if a == audit.ActionExec {
		return jsonHasNonEmpty(body, "operation")
	}
	return jsonHasNonEmpty(body, "type")
}

func jsonHasNonEmpty(body, key string) bool {
	var walk func(any) bool
	walk = func(v any) bool {
		switch t := v.(type) {
		case map[string]any:
			for k, sub := range t {
				if k == key {
					if s, ok := sub.(string); ok && s != "" {
						return true
					}
				}
				if walk(sub) {
					return true
				}
			}
		case []any:
			for _, sub := range t {
				if walk(sub) {
					return true
				}
			}
		}
		return false
	}
	var doc any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return false
	}
	return walk(doc)
}
