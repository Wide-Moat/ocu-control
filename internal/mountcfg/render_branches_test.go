// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg_test

import (
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/mountcfg"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestRenderRefusesMalformedTopLevel covers Render's fail-closed top-level guards:
// a non-https service_url, a ca_cert_pem missing the BEGIN CERTIFICATE marker, an
// empty mounts slice, and a token/mount count mismatch each refuse with the typed
// sentinel before any mount is mapped.
func TestRenderRefusesMalformedTopLevel(t *testing.T) {
	t.Parallel()
	defaults := defaultsForTest(t)
	signer := signerForTest(t)
	goodMount := runtime.MountIntent{Destination: "/workspace", FilesystemID: "fs-1", CacheSeconds: 1}
	goodTok := mintFor(t, signer, "fs-1", cred.IntentRead)

	cases := []struct {
		name    string
		url     string
		ca      string
		mounts  []runtime.MountIntent
		tokens  []cred.Token
		wantErr error
	}{
		{
			name:    "non-https service url",
			url:     "http://storage.internal",
			ca:      testCACert,
			mounts:  []runtime.MountIntent{goodMount},
			tokens:  []cred.Token{goodTok},
			wantErr: mountcfg.ErrBadServiceURL,
		},
		{
			name:    "ca cert missing marker",
			url:     testServiceURL,
			ca:      "not a pem",
			mounts:  []runtime.MountIntent{goodMount},
			tokens:  []cred.Token{goodTok},
			wantErr: mountcfg.ErrBadCACert,
		},
		{
			name:    "no mounts",
			url:     testServiceURL,
			ca:      testCACert,
			mounts:  nil,
			tokens:  nil,
			wantErr: mountcfg.ErrNoMounts,
		},
		{
			name:    "token count mismatch",
			url:     testServiceURL,
			ca:      testCACert,
			mounts:  []runtime.MountIntent{goodMount},
			tokens:  []cred.Token{goodTok, goodTok},
			wantErr: mountcfg.ErrTokenCountMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mountcfg.Render(tc.url, tc.ca, tc.mounts, tc.tokens, defaults)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Render error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestRenderRefusesPerMountFaults covers renderMount's fail-closed per-mount guards
// reached through Render: a non-absolute destination and a negative cache window
// each refuse with the typed sentinel, wrapped with the mount index for diagnostics.
func TestRenderRefusesPerMountFaults(t *testing.T) {
	t.Parallel()
	defaults := defaultsForTest(t)
	signer := signerForTest(t)
	tok := mintFor(t, signer, "fs-1", cred.IntentRead)

	cases := []struct {
		name    string
		mount   runtime.MountIntent
		wantErr error
	}{
		{
			name:    "relative destination",
			mount:   runtime.MountIntent{Destination: "workspace", FilesystemID: "fs-1", CacheSeconds: 1},
			wantErr: mountcfg.ErrBadDestination,
		},
		{
			name:    "negative cache duration",
			mount:   runtime.MountIntent{Destination: "/workspace", FilesystemID: "fs-1", CacheSeconds: -1},
			wantErr: mountcfg.ErrBadCacheDuration,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mountcfg.Render(testServiceURL, testCACert, []runtime.MountIntent{tc.mount}, []cred.Token{tok}, defaults)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Render error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestRenderRefusesZeroValueDefaults covers MountDefaults.validate reached through
// Render: a zero-value MountDefaults (a struct literal that skipped the New*
// constructors) is refused on the FIRST invalid axis (the vfs_cache_mode), so a
// caller cannot bypass the validating constructors.
func TestRenderRefusesZeroValueDefaults(t *testing.T) {
	t.Parallel()
	signer := signerForTest(t)
	mount := runtime.MountIntent{Destination: "/workspace", FilesystemID: "fs-1", CacheSeconds: 1}
	tok := mintFor(t, signer, "fs-1", cred.IntentRead)

	_, err := mountcfg.Render(testServiceURL, testCACert, []runtime.MountIntent{mount}, []cred.Token{tok}, mountcfg.MountDefaults{})
	if !errors.Is(err, mountcfg.ErrBadVfsCacheMode) {
		t.Fatalf("Render with zero defaults = %v, want ErrBadVfsCacheMode", err)
	}
}

// TestValidateRejectsEachDefaultsAxis covers the byte-size, dir-perms, and
// file-perms branches of MountDefaults.validate independently: a defaults value
// valid on every axis EXCEPT one is refused with that axis's sentinel, proving each
// guard fires on its own field rather than only the first.
func TestValidateRejectsEachDefaultsAxis(t *testing.T) {
	t.Parallel()
	signer := signerForTest(t)
	mount := runtime.MountIntent{Destination: "/workspace", FilesystemID: "fs-1", CacheSeconds: 1}
	tok := mintFor(t, signer, "fs-1", cred.IntentRead)
	base := defaultsForTest(t)

	cases := []struct {
		name    string
		mutate  func(mountcfg.MountDefaults) mountcfg.MountDefaults
		wantErr error
	}{
		{
			name:    "bad byte size",
			mutate:  func(d mountcfg.MountDefaults) mountcfg.MountDefaults { d.VfsCacheMaxSize = "not-a-size"; return d },
			wantErr: mountcfg.ErrBadByteSize,
		},
		{
			name:    "bad dir perms",
			mutate:  func(d mountcfg.MountDefaults) mountcfg.MountDefaults { d.DirPerms = "999"; return d },
			wantErr: mountcfg.ErrBadOctal,
		},
		{
			name:    "bad file perms",
			mutate:  func(d mountcfg.MountDefaults) mountcfg.MountDefaults { d.FilePerms = "xyz"; return d },
			wantErr: mountcfg.ErrBadOctal,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.mutate(base)
			_, err := mountcfg.Render(testServiceURL, testCACert, []runtime.MountIntent{mount}, []cred.Token{tok}, d)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Render error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestConfigGoStringRedacts covers the %#v redaction surface: GoString must emit the
// sentinel, never a field dump that reflection could read a token through. (The
// String path is covered elsewhere; this fills the GoString gap.)
func TestConfigGoStringRedacts(t *testing.T) {
	t.Parallel()
	defaults := defaultsForTest(t)
	signer := signerForTest(t)
	mount := runtime.MountIntent{Destination: "/workspace", FilesystemID: "fs-1", CacheSeconds: 1}
	tok := mintFor(t, signer, "fs-1", cred.IntentRead)

	cfg, err := mountcfg.Render(testServiceURL, testCACert, []runtime.MountIntent{mount}, []cred.Token{tok}, defaults)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	const sentinel = "mountcfg.Config(REDACTED)"
	if got := cfg.GoString(); got != sentinel {
		t.Fatalf("GoString() = %q, want %q", got, sentinel)
	}
}
