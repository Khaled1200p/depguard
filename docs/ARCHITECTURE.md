# DepGuard architecture

```
 BUILD / CI (trusted)                          RUNTIME (untrusted)
 ┌──────────────────────────────┐
 │ requirements.txt / poetry.lock│
 │ package-lock.json            │
 │ + installed site-packages /  │
 │   node_modules               │
 └──────────────┬───────────────┘
                ▼
        ┌───────────────┐   ed25519 sig + merkle_root
        │ depguard-gen  │──────────────────────────────┐
        └───────────────┘                              ▼
                                        depguard.baseline.json
                                   {abs_realpath: {package,version,sha256}}
                                                       │ read-only mount / signed
          ┌────────────────────────────┬───────────────┴───────────────┐
          ▼                            ▼                               ▼
 ┌─────────────────┐        ┌────────────────────┐          ┌──────────────────────┐
 │ Tier A: Python  │        │ Tier A: Node.js    │          │ Tier B: depguard-    │
 │ sitecustomize.py│        │ loader.js+core.cjs │          │ sensor (Go) + eBPF   │
 │ MetaPathFinder  │        │ Module._extensions │          │ tp/sys_enter_openat  │
 │ (in-process)    │        │ dlopen, ESM load() │          │ (kernel, host-wide)  │
 └────────┬────────┘        └─────────┬──────────┘          └──────────┬───────────┘
          │ verify BEFORE exec        │                                │ SIGSTOP → verify → CONT/KILL
          ▼                           ▼                                ▼
   SHADOW_DEPENDENCY | CACHE_TAMPERING | VERSION_CONFLICT  (audit: log / enforce: block)
          └───────────────┬───────────┴────────────────────────────────┘
                          ▼
              JSON lines  (stderr | DEPGUARD_LOG | file → Fluent Bit/Vector → SIEM)
   {timestamp,agent,type,severity,mode,action,pid,process,file,package,version,
    expected_sha256,actual_sha256,...}
```

## Decision rule (identical in all three sensors)
1. `realpath(file)` in baseline → hash must match, else `CACHE_TAMPERING`.
   Same package already loaded at another version → `VERSION_CONFLICT` (non-blocking by default).
2. Not in baseline and path contains `/node_modules/`, `/site-packages/`, `/dist-packages/` → `SHADOW_DEPENDENCY`.
3. Not in baseline, outside those, under stdlib / first-party root (baseline `root`) / system lib dirs → allowed.
4. Anything else (`/tmp`, `$HOME`, odd `PYTHONPATH`/`NODE_PATH`) → `SHADOW_DEPENDENCY`.

## Honest limits
* **Tier A lives inside the process it protects.** Code that already runs there can unhook it, and
  `python -S/-I`, `node` without `--require`, or a sanitized env skip it entirely. Use Tier B as the
  tamper-resistant layer; use Tier A for precise, zero-race, pre-execution blocking.
* **Tier A TOCTOU:** a file can change between our hash and the interpreter's read (microsecond window).
  Mitigations: read-only filesystem for site-packages/node_modules, or Tier B.
* **.pyc:** Python may load cached bytecode instead of re-reading source. We verify the source file
  (`.py`) and flag sourceless `.pyc` in third-party dirs; set `PYTHONDONTWRITEBYTECODE=1` or ship
  pre-compiled, baselined bytecode if you need pyc integrity.
* **Tier B enforce is stop-the-world gating, not an LSM.** The probe SIGSTOPs the caller on
  open; it is stopped before it can read/mmap, then resumed or killed. If the ring buffer overflows the
  event is dropped (counter reported at exit) and the load is not verified. For hard guarantees
  use BPF-LSM (`lsm/file_open`) + fs-verity/IMA.
* Python `import` probes many non-existent `.py` paths; in enforce mode those still stop the process
  briefly (ENOENT → immediately resumed). Prefer audit mode for Tier B on hot hosts, or restrict by cgroup.
* First-party application code is not hashed; only third-party packages are baselined.
