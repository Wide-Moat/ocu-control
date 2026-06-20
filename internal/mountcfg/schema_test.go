// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/mountcfg"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// frozenSchemaRelPath is the path, from the repo root, of the frozen mount-config
// contract this package renders against. The test reads the canonical file in
// place (resolved by walking up to the go.mod root) rather than embedding a copy,
// so the validation can never drift from the vendored canon.
const frozenSchemaRelPath = "contracts/storage/mount-config.schema.json"

// repoRoot walks up from the test working directory (the package dir under
// `go test`) until it finds the go.mod, so the frozen schema is read from its one
// canonical location with no embedded copy to drift.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (go.mod) above the test directory")
		}
		dir = parent
	}
}

// compileFrozenSchema compiles the frozen mount-config schema with the v6
// compiler, reading the canonical file from the repo root.
func compileFrozenSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join(repoRoot(t), frozenSchemaRelPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frozen schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	const url = "mem://mount-config.schema.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

// validateAgainstFrozen unmarshals b into the generic instance the v6 validator
// consumes and validates it against the compiled frozen schema.
func validateAgainstFrozen(t *testing.T, sch *jsonschema.Schema, b []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("unmarshal instance: %v", err)
	}
	return sch.Validate(inst)
}

// signerForTest loads a real Signer over a fresh Ed25519 key so the rendered
// auth_token is a genuine compact JWT (the schema's minLength:1 is satisfied by a
// real token, and the redact-vs-reveal test drives a real JWT).
func signerForTest(t *testing.T) *cred.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key mount: %v", err)
	}
	signer, err := cred.LoadSignerFromMount(path, state.NewFakeClock(time.Unix(1_700_000_000, 0)), cred.Config{
		Alg:             cred.AlgEdDSA,
		StorageIssuer:   "https://control.example/provisional",
		StorageAudience: "egress.provisional",
		ExecIssuer:      "https://control.example/exec-provisional",
		ExecAudience:    "guest.exec.provisional",
		StorageTTL:      15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("LoadSignerFromMount: %v", err)
	}
	return signer
}

func mintFor(t *testing.T, signer *cred.Signer, filesystemID string, intent cred.Intent) cred.Token {
	t.Helper()
	tok, err := signer.MintStorageJWT(context.Background(), cred.StorageMintReq{
		SessionKey:   "sess-key-host-derived",
		FilesystemID: filesystemID,
		Workspace:    "ws-1",
		Org:          "org-1",
		Authz:        cred.AuthorizationMetadata{Scope: filesystemID, Intent: intent},
	})
	if err != nil {
		t.Fatalf("MintStorageJWT: %v", err)
	}
	return tok
}

// defaultsForTest builds a valid MountDefaults through the validating
// constructors.
func defaultsForTest(t *testing.T) mountcfg.MountDefaults {
	t.Helper()
	mode, err := mountcfg.NewVfsCacheMode("writes")
	if err != nil {
		t.Fatalf("NewVfsCacheMode: %v", err)
	}
	size, err := mountcfg.NewByteSize("1G")
	if err != nil {
		t.Fatalf("NewByteSize: %v", err)
	}
	dirPerms, err := mountcfg.NewOctal("0755")
	if err != nil {
		t.Fatalf("NewOctal dir: %v", err)
	}
	filePerms, err := mountcfg.NewOctal("0644")
	if err != nil {
		t.Fatalf("NewOctal file: %v", err)
	}
	return mountcfg.MountDefaults{
		VfsCacheMode:    mode,
		VfsCacheMaxSize: size,
		DirPerms:        dirPerms,
		FilePerms:       filePerms,
	}
}

const testCACert = "-----BEGIN CERTIFICATE-----\nMIIBfakecertbytesforthetest==\n-----END CERTIFICATE-----\n"
const testServiceURL = "https://storage.internal"

// TestRenderedConfigValidates renders a config with a filesystem-scoped RW mount
// and a memory-scoped RO mount, then asserts the marshaled bytes validate against
// the FROZEN schema. This is the canon cross-check: every required field is
// present, vfs_cache_mode is in the enum, the perms match the Octal pattern, and
// exactly one of filesystem_id / memory_store_id is set per mount.
func TestRenderedConfigValidates(t *testing.T) {
	sch := compileFrozenSchema(t)
	signer := signerForTest(t)

	mounts := []runtime.MountIntent{
		{Destination: "/workspace/out", FilesystemID: "session_01HXYZ_out", ReadOnly: false, CacheSeconds: 3600},
		{Destination: "/workspace/mem", MemoryStoreID: "mem_01HXYZ", ReadOnly: true, CacheSeconds: 3},
	}
	tokens := []cred.Token{
		mintFor(t, signer, "session_01HXYZ_out", cred.IntentWrite),
		mintFor(t, signer, "session_01HXYZ_mem", cred.IntentRead),
	}

	cfg, err := mountcfg.Render(testServiceURL, testCACert, mounts, tokens, defaultsForTest(t))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := validateAgainstFrozen(t, sch, b); err != nil {
		t.Fatalf("rendered config does not validate against frozen schema: %v", err)
	}
}

// TestMissingAuthTokenFails confirms the additionalProperties:false +
// minLength:1 + required surface rejects a config whose auth_token has been
// stripped. We render a valid config, drop auth_token from the marshaled bytes,
// and assert the frozen schema rejects it — proving the schema is the gate, not
// just our renderer.
func TestMissingAuthTokenFails(t *testing.T) {
	sch := compileFrozenSchema(t)
	b := renderOne(t, signerForTest(t))

	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal rendered: %v", err)
	}
	mounts := generic["mounts"].([]any)
	mount := mounts[0].(map[string]any)
	delete(mount, "auth_token")
	stripped, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal stripped: %v", err)
	}
	if err := validateAgainstFrozen(t, sch, stripped); err == nil {
		t.Fatal("frozen schema accepted a config with no auth_token")
	}
}

// TestExtraKeyFails confirms additionalProperties:false rejects a config with a
// stray top-level key the schema does not name.
func TestExtraKeyFails(t *testing.T) {
	sch := compileFrozenSchema(t)
	b := renderOne(t, signerForTest(t))

	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal rendered: %v", err)
	}
	generic["unexpected_extra"] = "boom"
	withExtra, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if err := validateAgainstFrozen(t, sch, withExtra); err == nil {
		t.Fatal("frozen schema accepted a config with an extra top-level key")
	}
}

// TestBothScopeIDsFails confirms the per-mount oneOf rejects a mount that sets
// BOTH filesystem_id and memory_store_id. The renderer refuses this at
// Render-time (ErrBadScope); this test additionally proves the FROZEN schema
// rejects it, so the canon and the renderer agree on the oneOf.
func TestBothScopeIDsFails(t *testing.T) {
	sch := compileFrozenSchema(t)
	b := renderOne(t, signerForTest(t))

	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal rendered: %v", err)
	}
	mount := generic["mounts"].([]any)[0].(map[string]any)
	mount["memory_store_id"] = "mem_also_set"
	both, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if err := validateAgainstFrozen(t, sch, both); err == nil {
		t.Fatal("frozen schema accepted a mount with both filesystem_id and memory_store_id")
	}
}

// renderOne renders a single-mount config and returns its marshaled bytes; the
// negative tests mutate these bytes to drive a schema rejection.
func renderOne(t *testing.T, signer *cred.Signer) []byte {
	t.Helper()
	mounts := []runtime.MountIntent{
		{Destination: "/workspace/out", FilesystemID: "session_01HXYZ_out", ReadOnly: false, CacheSeconds: 3600},
	}
	tokens := []cred.Token{mintFor(t, signer, "session_01HXYZ_out", cred.IntentWrite)}
	cfg, err := mountcfg.Render(testServiceURL, testCACert, mounts, tokens, defaultsForTest(t))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

// TestRenderRefusesZeroToken asserts the renderer fails closed on a never-minted
// (zero) Token rather than shipping an empty auth_token.
func TestRenderRefusesZeroToken(t *testing.T) {
	mounts := []runtime.MountIntent{
		{Destination: "/workspace/out", FilesystemID: "session_01HXYZ_out", CacheSeconds: 1},
	}
	tokens := []cred.Token{{}} // zero token
	if _, err := mountcfg.Render(testServiceURL, testCACert, mounts, tokens, defaultsForTest(t)); !errors.Is(err, mountcfg.ErrNoCredential) {
		t.Fatalf("Render error = %v, want ErrNoCredential", err)
	}
}

// TestRenderRefusesBadScope asserts the renderer refuses a mount that sets both
// or neither of filesystem_id / memory_store_id (the oneOf, enforced before
// render).
func TestRenderRefusesBadScope(t *testing.T) {
	signer := signerForTest(t)
	cases := []struct {
		name  string
		mount runtime.MountIntent
	}{
		{"neither", runtime.MountIntent{Destination: "/d", CacheSeconds: 1}},
		{"both", runtime.MountIntent{Destination: "/d", FilesystemID: "fs", MemoryStoreID: "mem", CacheSeconds: 1}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tokens := []cred.Token{mintFor(t, signer, "fs-for-token", cred.IntentRead)}
			_, err := mountcfg.Render(testServiceURL, testCACert, []runtime.MountIntent{tc.mount}, tokens, defaultsForTest(t))
			if !errors.Is(err, mountcfg.ErrBadScope) {
				t.Fatalf("Render error = %v, want ErrBadScope", err)
			}
		})
	}
}
