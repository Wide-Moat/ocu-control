// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build ignore

// Command devsecrets materializes the local development Storage-JWT signing key
// for the first-run quickstart and the compose default mount source. It is a
// thin wrapper over internal/devsecrets.GenerateDevSigningKey — the same code
// path the test exercises — invoked by the `make dev-secrets` target.
//
// It carries the //go:build ignore tag so it is NOT compiled into
// `go build ./...`, `go vet ./...`, or the coverage scope: it adds no production
// package and no daemon binary path. The Makefile runs it with the explicit-file
// form `go run cmd/devsecrets/main.go <dest>` because the build-ignore tag hides
// it from package-form `go run ./cmd/devsecrets`.
//
// This is a DEV key only. Production provisions the signing key out of band.
package main

import (
	"fmt"
	"os"

	"github.com/Wide-Moat/ocu-control/internal/devsecrets"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <dest-path>\n", os.Args[0])
		os.Exit(2)
	}
	dest := os.Args[1]

	created, err := devsecrets.GenerateDevSigningKey(dest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "devsecrets: %v\n", err)
		os.Exit(1)
	}
	if !created {
		fmt.Fprintf(os.Stderr, "dev key already present at %s; not overwriting\n", dest)
		return
	}
	fmt.Fprintf(os.Stderr, "wrote dev Storage-JWT signing key (0600) to %s\n", dest)
}
