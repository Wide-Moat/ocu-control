// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"encoding/binary"
	"hash/fnv"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// Label and annotation keys the provider stamps on every session object. The
// managed label is the reconciler's list selector; the session-name label
// carries the host-derived identity for human debugging only — teardown and
// Reconcile re-derive every name purely from SessionName (the statelessness
// requirement), never trusting a label to grant authority (NFR-SEC-43).
const (
	// labelManaged marks an object this provider owns; Reconcile lists by it.
	labelManaged = "ocu.dev/session"
	// managedLabelValue is the fixed presence value of labelManaged.
	managedLabelValue = "true"
	// labelSessionName carries an FNV-1a hash of the host-derived SessionName.
	// A session name can exceed or violate the 63-char RFC-1123 label-value
	// constraint; a fixed-length hash never does, and it is the SAME value the
	// per-session NetworkPolicy podSelector matches, so the two can never drift.
	labelSessionName = "ocu.dev/session-name-hash"
	// labelFilesystemID records the egress SCOPE as a hash, for debugging only.
	labelFilesystemID = "ocu.dev/filesystem-id-hash"
	// annotationSessionName carries the full host-derived SessionName as an
	// annotation (no length limit), so a human can map a pod back to its session
	// without reversing the hash. It is never read as authority.
	annotationSessionName = "ocu.dev/session-name"
)

// podName is the pure function from session name to Pod name. Pod names are
// RFC-1123 subdomains (<=253 chars, lowercase alphanumeric plus '-'/'.'); the
// host-derived SessionName is already a lowercase key, so the deterministic
// "ocu-sess-<name>" is a valid name teardown and Reconcile re-derive without a
// lookup — the k8s analog of the Docker containerName pure function.
func podName(name runtime.SessionName) string { return "ocu-sess-" + string(name) }

// policyName is the pure function from session name to the per-session
// NetworkPolicy name.
func policyName(name runtime.SessionName) string { return "ocu-net-" + string(name) }

// nameHash is the fixed-length FNV-1a hash used as a label value. It is
// collision-resistant enough for a selector key and always a legal 16-char
// label value regardless of the input's length or characters.
func nameHash(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], h.Sum64())
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 16)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}

// sessionLabels is the label set stamped on every object of one session. The
// managed label drives Reconcile; the two hash labels are the podSelector the
// per-session NetworkPolicy matches and a debugging aid.
func sessionLabels(spec runtime.SessionSpec) map[string]string {
	return map[string]string{
		labelManaged:      managedLabelValue,
		labelSessionName:  nameHash(string(spec.Name)),
		labelFilesystemID: nameHash(spec.Egress.FilesystemID),
	}
}
