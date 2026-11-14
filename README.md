# DepGuard – Runtime Dependency Provenance & Shadow-Path Auditor

Static scanners verify lockfiles *before* execution. DepGuard verifies what is **actually loaded** at run time:
`SHADOW_DEPENDENCY`, `CACHE_TAMPERING`, `VERSION_CONFLICT`.

```
depguard/
├── cmd/depguard-gen/main.go      # Go: lockfile+disk → depguard.baseline.json (+ keygen, signing)
├── pkg/baseline/baseline.go      # shared format, Merkle root, ed25519 sign/verify
├── agents/python/sitecustomize.py# zero-dep MetaPathFinder hook (PYTHONPATH autoload)
├── agents/node/{loader.js,core.cjs,esm-hooks.mjs}
├── sensor/{openat.bpf.c,main.go,go.mod}   # Tier B: eBPF + Go daemon (separate module: cilium/ebpf)
├── test/attack_simulation.sh     # shadow-injection + cache-poisoning demo
└── docs/{ARCHITECTURE.md,PERFORMANCE.md}
```

## Quick start
```bash
make gen
bin/depguard-gen keygen -out keys
bin/depguard-gen -root ./app -sign-key keys/depguard.key -out app/depguard.baseline.json

# Python (no code change)
PYTHONPATH=$PWD/agents/python:$PYTHONPATH DEPGUARD_BASELINE=app/depguard.baseline.json \
DEPGUARD_MODE=enforce python app/main.py

# Node (no code change; CJS + ESM + native addons)
DEPGUARD_BASELINE=app/depguard.baseline.json DEPGUARD_MODE=enforce DEPGUARD_PUBKEY=keys/depguard.pub \
node --require $PWD/agents/node/loader.js app/index.js

# Tier B (root; Linux ≥ 5.8)
make sensor
sudo bin/depguard-sensor -baseline app/depguard.baseline.json -pubkey keys/depguard.pub \
     -cgroup /sys/fs/cgroup/system.slice/docker-<id>.scope -mode audit -log /var/log/depguard.jsonl
```
`--mode` equivalent for the in-process agents is `DEPGUARD_MODE` (they have no CLI).
Run `make test` (or `sudo make test` to include eBPF).

## Status
Tested here: Python + Node agents (CJS, ESM, enforce/audit, baseline forgery) via `test/attack_simulation.sh`.
**Not compiled/run in the authoring sandbox (no Go/clang/root):** `depguard-gen`, `sensor/`. Expect to fix small
compile/verifier issues on first build (`go vet`, `go mod tidy`, kernel-specific verifier messages).
