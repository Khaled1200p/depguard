#!/usr/bin/env bash
# DepGuard attack simulation: Shadow Dependency Injection + Local Cache Poisoning.
# Builds a throw-away project, baselines it, then attacks it and shows the alerts.
#   ./test/attack_simulation.sh            # Tier A (Python + Node if available)
#   sudo ./test/attack_simulation.sh       # + Tier B eBPF if bin/depguard-sensor exists
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0

if [ -z "${DEPGUARD_GEN:-}" ]; then
  mkdir -p "$BIN"
  (cd "$ROOT" && go build -o "$BIN/depguard-gen" ./cmd/depguard-gen) || { echo "go build failed"; exit 1; }
  DEPGUARD_GEN="$BIN/depguard-gen"
fi

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
has()  { grep -q "\"type\":\"$1\"" "$2" 2>/dev/null; }
hdr()  { printf '\n=== %s ===\n' "$1"; }
# forge-proof tamper: modify content, then restore mtime (defeats mtime-based scanners)
tamper() { local ref="$WORK/.ref"; touch -r "$1" "$ref"; printf '\nprint("PWNED: attacker code running")\n' >> "$1"; touch -r "$ref" "$1"; }
tamper_js() { local ref="$WORK/.ref"; touch -r "$1" "$ref"; printf '\nconsole.log("PWNED: attacker code running");\n' >> "$1"; touch -r "$ref" "$1"; }

# ------------------------------------------------------------------ Python
hdr "Python (Tier A: sitecustomize.py)"
PROJ="$WORK/py/project"; SITE="$WORK/py/venv/lib/python3/site-packages"; EVIL="$WORK/py/evil"
mkdir -p "$PROJ" "$SITE/democlib" "$SITE/democlib-1.0.0.dist-info" "$EVIL/democlib"
echo 'democlib==1.0.0' > "$PROJ/requirements.txt"
printf 'def hello():\n    return "legit democlib 1.0.0"\n' > "$SITE/democlib/__init__.py"
printf 'democlib/__init__.py,,\ndemoclib-1.0.0.dist-info/METADATA,,\ndemoclib-1.0.0.dist-info/RECORD,,\n' > "$SITE/democlib-1.0.0.dist-info/RECORD"
printf 'Name: democlib\nVersion: 1.0.0\n' > "$SITE/democlib-1.0.0.dist-info/METADATA"
printf 'import democlib\nprint(democlib.hello())\n' > "$PROJ/app.py"
printf 'def hello():\n    return "MALICIOUS shadow copy"\nprint("PWNED: shadow module executing")\n' > "$EVIL/democlib/__init__.py"

"$DEPGUARD_GEN" -root "$PROJ" -site-packages "$SITE" -out "$PROJ/depguard.baseline.json" 2>&1 | sed 's/^/  gen: /'

run_py() { # $1=PYTHONPATH tail  $2=mode  $3=log
  ( cd "$PROJ" && PYTHONPATH="$ROOT/agents/python:$1" DEPGUARD_BASELINE="$PROJ/depguard.baseline.json" \
    DEPGUARD_MODE="$2" DEPGUARD_LOG="$3" python3 app.py 2>&1 )
}

echo "-- 0. clean run (must stay silent)"
L="$WORK/py0.log"; out=$(run_py "$SITE" enforce "$L"); echo "  app: $out"
[ ! -s "$L" ] && [[ "$out" == *"legit"* ]] && ok "clean app runs, zero alerts" || bad "clean run alerted: $(cat "$L" 2>/dev/null)"

echo "-- 1. Shadow Dependency Injection (PYTHONPATH prepended with attacker dir)"
L="$WORK/py1a.log"; out=$(run_py "$EVIL:$SITE" audit "$L"); echo "  audit app: $(echo "$out" | head -2 | tr '\n' ' ')"
has SHADOW_DEPENDENCY "$L" && ok "audit: SHADOW_DEPENDENCY logged (app still ran)" || bad "audit: no SHADOW_DEPENDENCY"
cat "$L" | head -1 | sed 's/^/    alert: /'
L="$WORK/py1b.log"; out=$(run_py "$EVIL:$SITE" enforce "$L"); rc=$?
[[ "$out" != *"PWNED"* ]] && has SHADOW_DEPENDENCY "$L" && ok "enforce: shadow module blocked BEFORE execution" || bad "enforce: shadow module executed"

echo "-- 2. Local Cache Poisoning (site-packages file modified, mtime restored)"
tamper "$SITE/democlib/__init__.py"
L="$WORK/py2a.log"; out=$(run_py "$SITE" audit "$L")
has CACHE_TAMPERING "$L" && ok "audit: CACHE_TAMPERING logged" || bad "audit: no CACHE_TAMPERING"
head -1 "$L" | sed 's/^/    alert: /'
L="$WORK/py2b.log"; out=$(run_py "$SITE" enforce "$L")
[[ "$out" != *"PWNED"* ]] && has CACHE_TAMPERING "$L" && ok "enforce: poisoned module blocked BEFORE execution" || bad "enforce: poisoned code ran"

echo "-- 3. Baseline tampering (attacker edits the baseline to bless their file)"
python3 - "$PROJ/depguard.baseline.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
for k in d["files"]: d["files"][k]["sha256"] = "0" * 64
json.dump(d, open(p, "w"))
PY
L="$WORK/py3.log"; out=$(run_py "$SITE" enforce "$L"); rc=$?
has BASELINE_ERROR "$L" && [ "$rc" -ne 0 ] && ok "enforce: forged baseline detected, process refused to start (fail-closed)" || bad "forged baseline accepted"

# -------------------------------------------------------------------- Node
if command -v node >/dev/null 2>&1; then
  hdr "Node.js (Tier A: --require loader.js + ESM hooks)"
  NP="$WORK/node/project"; GLOBAL="$WORK/node/global/node_modules"
  mkdir -p "$NP/node_modules/demo-lib" "$GLOBAL/phantom-lib"
  cat > "$NP/package-lock.json" <<'JSON'
{"name":"app","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app"},"node_modules/demo-lib":{"version":"1.0.0"}}}
JSON
  echo 'module.exports = { hello: () => "legit demo-lib 1.0.0" };' > "$NP/node_modules/demo-lib/index.js"
  echo '{"name":"demo-lib","version":"1.0.0","main":"index.js"}' > "$NP/node_modules/demo-lib/package.json"
  echo 'console.log("PWNED: phantom dependency executing"); module.exports = {};' > "$GLOBAL/phantom-lib/index.js"
  printf 'console.log(require("demo-lib").hello());\ntry { require("phantom-lib"); } catch (e) { console.log("blocked:", e.code); }\n' > "$NP/app.js"
  printf 'import { createRequire } from "node:module";\nconst r = createRequire(import.meta.url);\nconsole.log(r("demo-lib").hello());\nconst m = await import("demo-lib");\nconsole.log("esm ok");\n' > "$NP/app.mjs"

  "$DEPGUARD_GEN" -root "$NP" -out "$NP/depguard.baseline.json" 2>&1 | sed 's/^/  gen: /'
  run_node() { # $1=mode $2=log $3=script  [NODE_PATH from env]
    ( cd "$NP" && DEPGUARD_BASELINE="$NP/depguard.baseline.json" DEPGUARD_MODE="$1" DEPGUARD_LOG="$2" \
      node --require "$ROOT/agents/node/loader.js" "$3" 2>&1 )
  }

  echo "-- 0. clean run"
  L="$WORK/n0.log"; out=$(run_node enforce "$L" app.js); echo "  app: $(echo "$out" | head -1)"
  [[ "$out" == *"legit"* ]] && ! has SHADOW_DEPENDENCY "$L" && ok "clean app runs, zero alerts" || bad "clean run alerted"

  echo "-- 1. Shadow Dependency Injection (NODE_PATH points at attacker node_modules)"
  L="$WORK/n1a.log"; out=$(NODE_PATH="$GLOBAL" run_node audit "$L" app.js)
  has SHADOW_DEPENDENCY "$L" && ok "audit: SHADOW_DEPENDENCY logged" || bad "audit: no SHADOW_DEPENDENCY"
  head -1 "$L" | sed 's/^/    alert: /'
  L="$WORK/n1b.log"; out=$(NODE_PATH="$GLOBAL" run_node enforce "$L" app.js)
  [[ "$out" != *"PWNED"* ]] && has SHADOW_DEPENDENCY "$L" && ok "enforce: phantom package blocked BEFORE execution" || bad "enforce: phantom code ran"

  echo "-- 2. Local Cache Poisoning (node_modules file modified, mtime restored)"
  tamper_js "$NP/node_modules/demo-lib/index.js"
  L="$WORK/n2a.log"; out=$(run_node audit "$L" app.js)
  has CACHE_TAMPERING "$L" && ok "audit: CACHE_TAMPERING logged" || bad "audit: no CACHE_TAMPERING"
  L="$WORK/n2b.log"; out=$(run_node enforce "$L" app.js)
  [[ "$out" != *"PWNED"* ]] && has CACHE_TAMPERING "$L" && ok "enforce: poisoned module blocked BEFORE execution (CJS)" || bad "enforce: poisoned CJS code ran"
  L="$WORK/n2c.log"; out=$(run_node enforce "$L" app.mjs)
  [[ "$out" != *"PWNED"* ]] && has CACHE_TAMPERING "$L" && ok "enforce: poisoned module blocked (ESM entry path)" || bad "enforce: poisoned code ran via ESM: $out"
else
  echo "(node not found - skipping Node scenarios)"
fi

# ------------------------------------------------------------------- eBPF
if [ "$(id -u)" = 0 ] && [ -x "$BIN/depguard-sensor" ]; then
  hdr "Tier B: eBPF sensor (kernel-level, cannot be bypassed by in-process tricks)"
  # fresh python project, tamper AFTER baseline, victim runs with python -S -I (Tier A is off!)
  P2="$WORK/ebpf"; S2="$P2/site-packages"; mkdir -p "$P2/proj" "$S2/democlib" "$S2/democlib-1.0.0.dist-info"
  echo 'democlib==1.0.0' > "$P2/proj/requirements.txt"
  printf 'def hello():\n    return "legit"\n' > "$S2/democlib/__init__.py"
  printf 'democlib/__init__.py,,\n' > "$S2/democlib-1.0.0.dist-info/RECORD"
  "$DEPGUARD_GEN" -root "$P2/proj" -site-packages "$S2" -out "$P2/base.json" 2>/dev/null
  tamper "$S2/democlib/__init__.py"
  python3 -S -I -c "import time,sys; time.sleep(4); sys.path.insert(0,'$S2'); import democlib" >"$P2/victim.out" 2>&1 &
  VPID=$!
  "$BIN/depguard-sensor" -baseline "$P2/base.json" -pid "$VPID" -mode audit -log "$P2/ebpf.log" 2>"$P2/sensor.err" &
  SPID=$!
  wait "$VPID" 2>/dev/null; sleep 1; kill -INT "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null
  has CACHE_TAMPERING "$P2/ebpf.log" && ok "eBPF: tampered file caught even with python -S -I (no sitecustomize)" || bad "eBPF: tamper not seen ($(cat "$P2/sensor.err"))"
  head -1 "$P2/ebpf.log" | sed 's/^/    alert: /'
else
  echo; echo "(Tier B skipped: needs root and bin/depguard-sensor; build with 'make sensor')"
fi

echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
