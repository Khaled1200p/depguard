//go:build tools

package main

// Keeps bpf2go in go.mod so `go generate` works after `go mod tidy`.
import _ "github.com/cilium/ebpf/cmd/bpf2go"
