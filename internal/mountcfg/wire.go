// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg

// schemaVersion is the interface version this renderer emits, mirroring the
// frozen SchemaVersion $def (^v[0-9]+(alpha|beta)?[0-9]*$). It is a fixed
// deployment value, not a sourced one; a breaking change to the wire surface
// increments it in lockstep with the frozen schema.
const schemaVersion = "v1alpha"

// wireMount is the PRIVATE marshaled shape of one mount, field-identical to the
// frozen Mount $def. Its auth_token is a PLAIN STRING, not a cred.Token: the real
// JWT is written here only at the single Marshal boundary, via Token.Reveal. The
// json tags are exactly the frozen field names; filesystem_id and memory_store_id
// are omitempty so exactly one is emitted (the schema's oneOf), and every other
// field is required and always present. additionalProperties:false in the schema
// means a stray field fails validation, so this struct carries no extra members.
type wireMount struct {
	Destination     string `json:"destination"`
	AuthToken       string `json:"auth_token"`
	FilesystemID    string `json:"filesystem_id,omitempty"`
	MemoryStoreID   string `json:"memory_store_id,omitempty"`
	ReadOnly        bool   `json:"readonly"`
	VfsCacheMode    string `json:"vfs_cache_mode"`
	CacheDurationS  int    `json:"cache_duration_s"`
	VfsCacheMaxSize string `json:"vfs_cache_max_size"`
	DirPerms        string `json:"dir_perms"`
	FilePerms       string `json:"file_perms"`
}

// wireConfig is the PRIVATE marshaled top-level shape, field-identical to the
// frozen config object. backend_cache_ttl is a *int with omitempty so it is
// ABSENT by default: the schema marks both its encoding and its placement
// x-ocu-tbd, so the renderer never freezes a value or even its presence. The
// other four members are the frozen required set.
type wireConfig struct {
	SchemaVersion   string      `json:"schema_version"`
	ServiceURL      string      `json:"service_url"`
	CACertPEM       string      `json:"ca_cert_pem"`
	Mounts          []wireMount `json:"mounts"`
	BackendCacheTTL *int        `json:"backend_cache_ttl,omitempty"`
}
