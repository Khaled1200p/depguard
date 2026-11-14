'use strict';
/**
 * DepGuard Tier-A core for Node.js (zero dependencies). Shared by the CommonJS
 * hooks (loader.js, main thread) and the ESM hooks (esm-hooks.mjs, loader thread).
 *
 * Env: DEPGUARD_BASELINE, DEPGUARD_MODE=audit|enforce, DEPGUARD_LOG,
 *      DEPGUARD_FIRST_PARTY (path-delimited), DEPGUARD_PUBKEY (ed25519 PEM, optional),
 *      DEPGUARD_BLOCK_CONFLICT=1, DEPGUARD_CACHE_MAX.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const ENFORCE = (process.env.DEPGUARD_MODE || 'audit').toLowerCase() === 'enforce';
const BLOCK_CONFLICT = process.env.DEPGUARD_BLOCK_CONFLICT === '1';
const LOG_PATH = process.env.DEPGUARD_LOG || '';
const THIRD_PARTY = ['/node_modules/', '/site-packages/', '/dist-packages/'];
const CACHE_MAX = parseInt(process.env.DEPGUARD_CACHE_MAX || '65536', 10);
const HOST = os.hostname();

let logFd = null;
function write(obj) {
  const line = JSON.stringify(obj) + '\n';
  try {
    if (LOG_PATH) {
      if (logFd === null) logFd = fs.openSync(LOG_PATH, 'a', 0o640);
      fs.writeSync(logFd, line);
    } else {
      fs.writeSync(2, line);
    }
  } catch (_) { /* never let telemetry break the app */ }
}

function merkle(files) {
  const keys = Object.keys(files).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const h = crypto.createHash('sha256');
  for (const k of keys) h.update(`${files[k].sha256}  ${k}\n`);
  return h.digest('hex');
}

let FILES = new Map();
let FIRST_PARTY = [];
let ENABLED = false;

function boot() {
  const p = path.resolve(process.env.DEPGUARD_BASELINE || 'depguard.baseline.json');
  try {
    const data = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (merkle(data.files) !== data.merkle_root) throw new Error('merkle root mismatch (baseline modified)');
    if (process.env.DEPGUARD_PUBKEY) {
      const pub = crypto.createPublicKey(fs.readFileSync(process.env.DEPGUARD_PUBKEY));
      const ok = crypto.verify(null, Buffer.from(data.merkle_root), pub, Buffer.from(data.signature || '', 'base64'));
      if (!ok) throw new Error('baseline signature invalid');
    }
    FILES = new Map(Object.entries(data.files));
    FIRST_PARTY = [data.root, ...(process.env.DEPGUARD_FIRST_PARTY || '').split(path.delimiter)]
      .filter(Boolean).map((r) => { try { return fs.realpathSync(r); } catch (_) { return r; } });
    ENABLED = true;
  } catch (err) {
    write({ timestamp: new Date().toISOString(), agent: 'depguard-node', type: 'BASELINE_ERROR',
      severity: 'critical', mode: ENFORCE ? 'enforce' : 'audit', pid: process.pid,
      error: String(err.message || err), baseline: p });
    if (ENFORCE) process.exit(97); // fail closed
  }
}

// ---- hashing with inode/mtime/ctime fast path + LRU -----------------------
const verified = new Map(); // realpath -> signature of last verified stat
const realCache = new Map();
const seenAlerts = new Set();
const loadedPkgs = new Map(); // "eco:pkg" -> {version, file}

function sha256File(p) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(p, 'r');
  try {
    const buf = Buffer.allocUnsafe(1 << 20);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally { fs.closeSync(fd); }
  return h.digest('hex');
}

function verify(real, expected) {
  let st;
  try { st = fs.statSync(real, { bigint: true }); } catch (_) { return { ok: false, actual: null }; }
  const sig = `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`;
  if (verified.get(real) === sig) { verified.delete(real); verified.set(real, sig); return { ok: true, actual: expected }; }
  let actual;
  try { actual = sha256File(real); } catch (_) { return { ok: false, actual: null }; }
  if (actual === expected) {
    verified.delete(real); verified.set(real, sig);
    while (verified.size > CACHE_MAX) verified.delete(verified.keys().next().value);
  }
  return { ok: actual === expected, actual };
}

function underAny(p, prefixes) {
  return prefixes.some((r) => p === r || p.startsWith(r.replace(/\/+$/, '') + '/'));
}

function fail(type, real, expected, actual, entry, blockedDefault, severity) {
  const blocked = ENFORCE && blockedDefault;
  const key = `${type}|${real}|${actual}`;
  if (!seenAlerts.has(key)) {
    seenAlerts.add(key);
    write({
      timestamp: new Date().toISOString(), agent: 'depguard-node', type, severity: severity || 'high',
      mode: ENFORCE ? 'enforce' : 'audit', action: blocked ? 'blocked' : 'logged',
      pid: process.pid, process: path.basename(process.argv0 || process.execPath), cmdline: process.argv,
      host: HOST, file: real, package: entry ? entry.package : null, version: entry ? entry.version : null,
      expected_sha256: expected, actual_sha256: actual,
    });
  }
  if (blocked) {
    const e = new Error(`DepGuard blocked ${type}: ${real}`);
    e.code = 'DEPGUARD_VIOLATION';
    throw e;
  }
}

/** Vet one file about to be executed/loaded. Throws in enforce mode. */
function check(file) {
  if (!ENABLED || typeof file !== 'string') return;
  if (file.startsWith('file:')) file = require('url').fileURLToPath(file);
  if (file.startsWith('node:') || file.startsWith('internal/')) return;
  file = path.resolve(file);
  let real = realCache.get(file);
  if (real === undefined) {
    try { real = fs.realpathSync(file); } catch (_) { real = file; }
    realCache.set(file, real);
  }
  const entry = FILES.get(real);
  if (entry) {
    const { ok, actual } = verify(real, entry.sha256);
    if (!ok) return fail('CACHE_TAMPERING', real, entry.sha256, actual, entry, true);
    const key = `${entry.ecosystem}:${entry.package}`;
    const prev = loadedPkgs.get(key);
    if (!prev) { loadedPkgs.set(key, { version: entry.version, file: real }); return; }
    if (prev.version !== entry.version) {
      return fail('VERSION_CONFLICT', real, prev.version, entry.version, entry, BLOCK_CONFLICT, 'medium');
    }
    return;
  }
  const norm = real.split(path.sep).join('/');
  if (!THIRD_PARTY.some((m) => norm.includes(m)) && underAny(norm, FIRST_PARTY)) return;
  let actual = null;
  try { actual = sha256File(real); } catch (_) { /* unreadable */ }
  return fail('SHADOW_DEPENDENCY', real, null, actual, null, true);
}

boot();
module.exports = { check, ENFORCE, get enabled() { return ENABLED; } };
