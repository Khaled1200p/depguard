# Performance notes

| Technique | Where | Effect |
|---|---|---|
| **Stat fast-path** `(dev, ino, size, mtime_ns, ctime_ns)` of last *verified* state | all sensors | Re-checks of an unchanged file cost 1 `stat`, not a read+SHA-256. `ctime` can't be set from userspace, so `touch -r` mtime forgery doesn't bypass it. Signature is captured *before* hashing (conservative). |
| **Bounded LRU** of verified files (`DEPGUARD_CACHE_MAX`, `--cache`, default 65 536) | all sensors | Constant memory on huge dependency trees. |
| **Per-process module cache is free** | Tier A | `sys.modules` / `require.cache` mean each file is vetted once per process; the finder only runs on first import. |
| **Streaming 1 MiB-chunk hashing** | all | No whole-file buffering for large `.so`/`.node`. |
| **realpath memoization** | Tier A | Avoids repeated symlink walks. |
| **Merkle root check once at start** | all | O(n) over the map at boot (~ms for 50k files); detects an edited baseline. Ed25519 signature check adds one verify (Node via `DEPGUARD_PUBKEY`, Go sensor via `--pubkey`). |
| **In-kernel filtering** | Tier B | Only monitored PIDs/cgroups, only code-looking suffixes reach the ring buffer; per-CPU scratch buffer, no stack copies. 16 MiB ring buffer. |
| **Worker pool** (`--workers`) | Tier B | Hashing off the ring-buffer read loop. |
| **Parallel hashing** (`--workers`) | depguard-gen | Baseline of 100k files is I/O-bound. |

Further ideas: pre-warm the fast-path cache at container start; mount dependency dirs read-only
(drops the TOCTOU window and lets you skip rehashing entirely); persist the verified-cache across
short-lived processes keyed by container image digest; make the baseline a per-image artifact.
