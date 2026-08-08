// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/api/resource"
)

func boolPtr(b bool) *bool    { return &b }
func int32Ptr(i int32) *int32 { return &i }
func quantityPtr(n int64) *metav1.Quantity {
	q := metav1.NewQuantity(n, metav1.BinarySI)
	return q
}
