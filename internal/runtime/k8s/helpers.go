// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/api/resource"
)

func boolPtr(b bool) *bool    { return &b }
func int32Ptr(i int32) *int32 { return &i }
func quantityPtr(n int64) *metav1.Quantity {
	q := metav1.NewQuantity(n, metav1.BinarySI)
	return q
}

// parentDir returns the directory portion of an absolute path (everything
// before the last '/'), or "/" for a top-level path. It is a small pure helper
// used to derive the handoff mount directory from a guest file path without
// pulling in path/filepath's OS-specific semantics.
func parentDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}
