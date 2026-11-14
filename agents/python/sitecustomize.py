"""DepGuard Tier-A: zero-dependency Python runtime interceptor.

Loaded automatically by the interpreter's `site` module - no application change:

    PYTHONPATH=/opt/depguard/agents/python:$PYTHONPATH \\
    DEPGUARD_BASELINE=/app/depguard.baseline.json \\
    DEPGUARD_MODE=enforce  python app.py

Environment:
    DEPGUARD_BASELINE     path to depguard.baseline.json   (default ./depguard.baseline.json)
    DEPGUARD_MODE         audit | enforce                  (default audit)
    DEPGUARD_LOG          append JSON-lines alerts here    (default stderr)
    DEPGUARD_FIRST_PARTY  extra first-party roots (os.pathsep separated)
    DEPGUARD_BLOCK_CONFLICT=1  also block VERSION_CONFLICT in enforce mode
    DEPGUARD_CACHE_MAX    verified-hash LRU size           (default 65536)

Decision per loaded file (.py .pyc .so .pyd), after realpath():
    in baseline, hash differs        -> CACHE_TAMPERING
    in baseline, hash ok             -> allowed (VERSION_CONFLICT if another version of
                                        the same package was already loaded)
    not in baseline:
        under site-packages/dist-packages/node_modules  -> SHADOW_DEPENDENCY
        under stdlib or a first-party root              -> allowed
        anywhere else (/tmp, $HOME, odd PYTHONPATH...)  -> SHADOW_DEPENDENCY
"""
import datetime
import hashlib
import importlib.abc
import json
import os
import socket
import sys
import sysconfig
import threading
from collections import OrderedDict

_ENFORCE = os.environ.get("DEPGUARD_MODE", "audit").strip().lower() == "enforce"
_BLOCK_CONFLICT = os.environ.get("DEPGUARD_BLOCK_CONFLICT") == "1"
_LOG_PATH = os.environ.get("DEPGUARD_LOG")
_WATCH_EXT = (".py", ".pyc", ".so", ".pyd")
_THIRD_PARTY = ("/site-packages/", "/dist-packages/", "/node_modules/")
_CACHE_MAX = int(os.environ.get("DEPGUARD_CACHE_MAX", "65536"))
_HOST = socket.gethostname()

_lock = threading.RLock()
_hash_cache = OrderedDict()   # realpath -> stat signature of last *verified* state
_real_cache = {}              # origin -> realpath
_seen_alerts = set()
_loaded = {}                  # (ecosystem, package) -> (version, path)
_state = threading.local()
_BASE = {}
_FIRST_PARTY = []
_STDLIB = []
_log_fd = None


class DepGuardViolation(ImportError):
    """Raised in enforce mode when a load is blocked."""


# ----------------------------------------------------------------- telemetry
def _write(line):
    global _log_fd
    data = (line + "\n").encode()
    try:
        if _LOG_PATH:
            if _log_fd is None:
                _log_fd = os.open(_LOG_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            os.write(_log_fd, data)
        else:
            os.write(2, data)
    except OSError:
        pass


def _emit(vtype, path, expected, actual, entry, modname, blocked, severity="high"):
    key = (vtype, path, actual)
    with _lock:
        if key in _seen_alerts:
            return
        _seen_alerts.add(key)
    _write(json.dumps({
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
        "agent": "depguard-python",
        "type": vtype,
        "severity": severity,
        "mode": "enforce" if _ENFORCE else "audit",
        "action": "blocked" if blocked else "logged",
        "pid": os.getpid(),
        "process": os.path.basename(sys.executable or "python"),
        "cmdline": sys.argv,
        "host": _HOST,
        "module": modname,
        "file": path,
        "package": (entry or {}).get("package"),
        "version": (entry or {}).get("version"),
        "expected_sha256": expected,
        "actual_sha256": actual,
    }, separators=(",", ":")))


# ------------------------------------------------------------------ hashing
def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _verify(real, expected):
    """Returns (ok, actual). Fast path: identical (dev, ino, size, mtime, ctime)
    to a previously verified state => skip hashing. ctime cannot be forged from
    userspace, so resetting mtime does not defeat the fast path check."""
    try:
        st = os.stat(real)
    except OSError:
        return False, None
    sig = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    with _lock:
        if _hash_cache.get(real) == sig:
            _hash_cache.move_to_end(real)
            return True, expected
    try:
        actual = _sha256(real)
    except OSError:
        return False, None
    if actual == expected:
        with _lock:
            _hash_cache[real] = sig  # stat taken BEFORE hashing: conservative
            _hash_cache.move_to_end(real)
            while len(_hash_cache) > _CACHE_MAX:
                _hash_cache.popitem(last=False)
    return actual == expected, actual


# ------------------------------------------------------------------- policy
def _under_any(path, prefixes):
    for p in prefixes:
        if path == p or path.startswith(p.rstrip("/") + "/"):
            return True
    return False


def _fail(vtype, real, expected, actual, entry, modname, blocked_default=True, severity="high"):
    blocked = _ENFORCE and blocked_default
    _emit(vtype, real, expected, actual, entry, modname, blocked, severity)
    if blocked:
        raise DepGuardViolation("DepGuard blocked %s: %s" % (vtype, real))


def _inspect(modname, origin):
    if not origin or not origin.endswith(_WATCH_EXT):
        return
    real = _real_cache.get(origin)
    if real is None:
        try:
            real = os.path.realpath(origin)
        except OSError:
            real = origin
        _real_cache[origin] = real

    entry = _BASE.get(real)
    if entry is not None:
        ok, actual = _verify(real, entry["sha256"])
        if not ok:
            _fail("CACHE_TAMPERING", real, entry["sha256"], actual, entry, modname)
            return
        key = (entry.get("ecosystem"), entry["package"])
        with _lock:
            prev = _loaded.get(key)
            if prev is None:
                _loaded[key] = (entry["version"], real)
                return
        if prev[0] != entry["version"]:
            _fail("VERSION_CONFLICT", real, prev[0], entry["version"], entry, modname,
                  blocked_default=_BLOCK_CONFLICT, severity="medium")
        return

    norm = real.replace(os.sep, "/")
    if not any(m in norm for m in _THIRD_PARTY):
        if _under_any(norm, _STDLIB) or _under_any(norm, _FIRST_PARTY):
            return
    try:
        actual = _sha256(real)
    except OSError:
        actual = None
    _fail("SHADOW_DEPENDENCY", real, None, actual, None, modname)


class _Finder(importlib.abc.MetaPathFinder):
    """Sits first on sys.meta_path, delegates to the real finders, then vets the
    resulting spec *before* the loader executes anything."""

    def find_spec(self, fullname, path=None, target=None):
        if getattr(_state, "busy", False):
            return None
        _state.busy = True
        try:
            spec = None
            for finder in list(sys.meta_path):
                if finder is self:
                    continue
                fs = getattr(finder, "find_spec", None)
                if fs is None:
                    continue
                spec = fs(fullname, path, target)
                if spec is not None:
                    break
        finally:
            _state.busy = False
        if spec is not None and spec.has_location:
            _inspect(fullname, spec.origin)
        return spec


# --------------------------------------------------------------------- boot
def _merkle(files):
    h = hashlib.sha256()
    for k in sorted(files, key=lambda s: s.encode("utf-8")):
        h.update(("%s  %s\n" % (files[k]["sha256"], k)).encode("utf-8"))
    return h.hexdigest()


def _boot():
    global _BASE
    path = os.environ.get("DEPGUARD_BASELINE", "depguard.baseline.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        files = data["files"]
        if _merkle(files) != data.get("merkle_root"):
            raise ValueError("merkle root mismatch (baseline modified)")
    except Exception as exc:  # fail closed in enforce mode, open (but loud) in audit
        _write(json.dumps({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
            "agent": "depguard-python", "type": "BASELINE_ERROR", "severity": "critical",
            "mode": "enforce" if _ENFORCE else "audit", "pid": os.getpid(),
            "error": str(exc), "baseline": path}, separators=(",", ":")))
        if _ENFORCE:
            os._exit(97)
        return
    _BASE = files
    roots = [data.get("root", "")] + [p for p in os.environ.get("DEPGUARD_FIRST_PARTY", "").split(os.pathsep) if p]
    _FIRST_PARTY.extend(os.path.realpath(p) for p in roots if p)
    for key in ("stdlib", "platstdlib"):
        p = sysconfig.get_paths().get(key)
        if p:
            _STDLIB.append(os.path.realpath(p))
    sys.meta_path.insert(0, _Finder())


_boot()
