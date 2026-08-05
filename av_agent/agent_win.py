"""Padakhep Sentinel — Windows AV/EDR agent (stdlib + ctypes + PowerShell).

Same control-plane protocol as the Linux agent (enroll -> pull policy ->
scan -> report), adapted to Windows:

  * file scan  : SHA-256 IOC match + YARA match (real `yara` if bundled,
                 else a lightweight AND-of-strings matcher)
  * process    : command-line behavior regex via Win32_Process (WMI/CIM)
  * brute force: Security log failed-logons (event ID 4625)
  * telemetry  : CPU/memory via ctypes (no external deps)
  * isolation  : Windows Defender Firewall network quarantine (reversible)

Run once:  python -m av_agent.agent_win --once
Service:   packaged to sentinel-av.exe (PyInstaller) and run via a
           Scheduled Task / Windows service (see docs/DEPLOYMENT_WINDOWS.md).
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import ipaddress
import json
import os
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Control plane is baked in so the exe works with zero configuration; override
# with the SENTINEL_API env var only if your server address differs.
DEFAULT_API = "http://192.168.39.32:8080"
API = os.environ.get("SENTINEL_API", DEFAULT_API)
NAME = os.environ.get("AGENT_NAME", socket.gethostname())
# Lean default scan scope (high-risk drop zones) — realtime catches new files
# anywhere here without re-hashing whole user profiles. Override with SENTINEL_SCAN_DIRS.
_HOME = os.path.expanduser("~")
_DEF_DIRS = ";".join([r"C:\Windows\Temp", r"C:\ProgramData", r"C:\Users\Public",
                      os.path.join(_HOME, "Downloads"), os.path.join(_HOME, "Desktop")])
SCAN_DIRS = [d for d in os.environ.get("SENTINEL_SCAN_DIRS", _DEF_DIRS).split(";") if d]
STATE = os.environ.get("SENTINEL_AV_STATE",
                       os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                    "PadakhepSentinel", "state.json"))
INTERVAL = int(os.environ.get("SENTINEL_AV_INTERVAL", "60"))
POLICY_EVERY = int(os.environ.get("SENTINEL_AV_POLICY_INTERVAL", "300"))
# Realtime: watch scan dirs via ReadDirectoryChangesW and scan only changed
# files, instead of re-walking + re-hashing everything each cycle.
REALTIME = os.environ.get("SENTINEL_AV_REALTIME", "1") not in ("0", "false", "")
FULLSCAN_EVERY = int(os.environ.get("SENTINEL_AV_FULLSCAN", "900"))
MAX_FILE = int(os.environ.get("SENTINEL_AV_MAXFILE", str(16 * 1024 * 1024)))
# Rootkit / host-anomaly detection (rootcheck): local consistency/trust checks, no feed.
ROOTCHECK = os.environ.get("SENTINEL_ROOTCHECK", "1") not in ("0", "false", "")
ROOTCHECK_EVERY = int(os.environ.get("SENTINEL_ROOTCHECK_INTERVAL", "600"))
TOKEN = os.environ.get("SENTINEL_API_TOKEN", "")
# SEN-006 TLS: verify the server cert when API is https (pin via SENTINEL_CA_CERT);
# SENTINEL_TLS_INSECURE=1 disables verification (lab only). SEN-007: per-agent secret.
CA_CERT = os.environ.get("SENTINEL_CA_CERT", "")
TLS_INSECURE = os.environ.get("SENTINEL_TLS_INSECURE", "0") not in ("0", "false", "")
AGENT_SECRET = ""
_SSL_CTX = None
VERSION = "0.3.16-win"
_SEEN_MAX = 20000
INSTALL_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "PadakhepSentinel")
INSTALL_EXE = os.path.join(INSTALL_DIR, "sentinel-av.exe")
# Drives to report. Empty (default) = all fixed local drives (C:, D:, E: …);
# or set a ";"-separated list of roots (e.g. "C:\\;D:\\") to report exactly those.
DISK_PATHS = [d for d in os.environ.get("SENTINEL_AV_DISK", "").split(";") if d]

# False-positive control (Windows generates far more FPs than Linux because the
# scan roots contain signed OS/vendor binaries and other AVs' data files):
#   1) trust validly code-signed files -> skip fuzzy YARA/string matching on them
#      (exact hash-IOC matches are ALWAYS still reported);
#   2) never scan other security products' trees (their logs/quarantine are full
#      of malware strings by design and would false-positive constantly).
TRUST_SIGNED = os.environ.get("SENTINEL_TRUST_SIGNED", "1") not in ("0", "false", "")
_DEF_EXCLUDE = [
    r"\windows defender", r"\microsoft\windows defender", r"\windows\windows defender",
    r"\eset", r"\kaspersky", r"\bitdefender", r"\mcafee", r"\avast", r"\avg",
    r"\malwarebytes", r"\sophos", r"\trend micro", r"\norton", r"\symantec",
    r"\crowdstrike", r"\sentinelone", r"\padakhepsentinel", r"\quarantine",
]
_EXCLUDE = _DEF_EXCLUDE + [e.strip().lower() for e in
                          os.environ.get("SENTINEL_SCAN_EXCLUDE", "").split(";") if e.strip()]

# executable extensions worth hashing/scanning (skip the rest for speed)
_SCAN_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".ps1", ".psm1", ".vbs", ".js",
             ".jse", ".wsf", ".hta", ".bat", ".cmd", ".jar", ".msi", ".lnk", ".bin",
             ".dat", ".tmp", ".php", ".asp", ".aspx", ".jsp", ".py", ".dropper"}
_SKIP_DIRS = {"$recycle.bin", "windows.old", "system volume information"}

_CREATE_NO_WINDOW = 0x08000000

# optional real YARA engine (bundled into the exe when available)
try:
    import yara  # type: ignore
    _HAVE_YARA = True
except Exception:
    yara = None
    _HAVE_YARA = False

# externals referenced by many community rules — defined so they compile;
# real per-file values are passed at match time.
_YARA_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "",
                   "owner": "", "md5": ""}


def log(m: str) -> None:
    print(f"[{datetime.now(timezone.utc).astimezone().isoformat()}] av-win: {m}", flush=True)


# --------------------------------------------------------------------------- update signature (Ed25519, SEN-002)
# Builds are signed OFFLINE (tools/sign_agent.py); this pinned public key verifies
# them so a compromised/MITM'd control plane cannot push code the agent runs as
# SYSTEM. Pure stdlib; empty key = signing disabled.
SIGNING_PUBKEY = os.environ.get(
    "SENTINEL_SIGNING_PUBKEY", "be543ff77fecad7256c60bbdd892d6380acf816599d66b9d417224f04a7fdbcd")
_q255 = 2 ** 255 - 19


def _inv255(x): return pow(x, _q255 - 2, _q255)


_d255 = (-121665 * _inv255(121666)) % _q255
_I255 = pow(2, (_q255 - 1) // 4, _q255)


def _xrec255(y):
    xx = (y * y - 1) * _inv255(_d255 * y * y + 1)
    x = pow(xx, (_q255 + 3) // 8, _q255)
    if (x * x - xx) % _q255 != 0:
        x = (x * _I255) % _q255
    return _q255 - x if x % 2 else x


_B255 = (_xrec255((4 * _inv255(5)) % _q255) % _q255, (4 * _inv255(5)) % _q255)


def _edw255(P, Q):
    x1, y1 = P
    x2, y2 = Q
    dd = _d255 * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * _inv255(1 + dd) % _q255,
            (y1 * y2 + x1 * x2) * _inv255(1 - dd) % _q255)


def _smul255(P, e):
    if e == 0:
        return (0, 1)
    Q = _smul255(P, e // 2)
    Q = _edw255(Q, Q)
    return _edw255(Q, P) if e & 1 else Q


def _bit255(h, i): return (h[i // 8] >> (i % 8)) & 1


def _decp255(s):
    y = sum(2 ** i * _bit255(s, i) for i in range(255))
    x = _xrec255(y)
    if x & 1 != _bit255(s, 255):
        x = _q255 - x
    if (-x * x + y * y - 1 - _d255 * x * x * y * y) % _q255 != 0:
        raise ValueError("point off curve")
    return (x, y)


def ed25519_verify(pub_hex: str, sig: bytes, msg: bytes) -> bool:
    try:
        pub = bytes.fromhex(pub_hex)
        if len(sig) != 64 or len(pub) != 32:
            return False
        R = _decp255(sig[:32])
        A = _decp255(pub)
        S = sum(2 ** i * _bit255(sig[32:], i) for i in range(256))
        h = sum(2 ** i * _bit255(hashlib.sha512(sig[:32] + pub + msg).digest(), i) for i in range(512))
        return _smul255(_B255, S) == _edw255(R, _smul255(A, h))
    except Exception:
        return False


# --------------------------------------------------------------------------- HTTP
def _ssl_ctx():
    """SSL context for https endpoints (None for http). Verifies the server cert;
    pins to SENTINEL_CA_CERT when provided (SEN-006)."""
    global _SSL_CTX
    if not API.lower().startswith("https"):
        return None
    if _SSL_CTX is None:
        ctx = ssl.create_default_context()
        if CA_CERT:
            try:
                ctx.load_verify_locations(CA_CERT)
            except Exception as exc:
                log(f"TLS: could not load CA {CA_CERT} ({exc!r})")
        if TLS_INSECURE:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        _SSL_CTX = ctx
    return _SSL_CTX


def _req(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN
    if AGENT_SECRET:
        headers["X-Agent-Secret"] = AGENT_SECRET
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=25, context=_ssl_ctx()) as resp:
        return json.loads(resp.read().decode() or "{}")


# --------------------------------------------------------------------------- helpers
def _ps(script: str, timeout: int = 40) -> str:
    """Run a PowerShell snippet hidden, return stdout ('' on failure)."""
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
        return p.stdout or ""
    except Exception as exc:
        log(f"powershell error: {exc!r}")
        return ""


def _run(args: list, timeout: int = 30) -> tuple:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           creationflags=_CREATE_NO_WINDOW)
        return p.returncode, p.stdout or "", p.stderr or ""
    except Exception as exc:
        return 1, "", repr(exc)


# --------------------------------------------------------------------------- code-signing trust (WinVerifyTrust)
# Native Authenticode verification via WinTrust — no subprocess, evaluated only
# on a signature match, and cached per path. res == 0 (ERROR_SUCCESS) means the
# file is signed and its chain terminates at a trusted root (Microsoft, Lenovo,
# ESET, etc.) — i.e. a legitimate certified binary we should not fuzzy-flag.
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


_WINTRUST_ACTION = _GUID(0xAAC56B, 0xCD44, 0x11D0,
                         (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))


class _WTFI(ctypes.Structure):
    _fields_ = [("cbStruct", wt.DWORD), ("pcwszFilePath", wt.LPCWSTR),
                ("hFile", wt.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]


class _WTD(ctypes.Structure):
    _fields_ = [("cbStruct", wt.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wt.DWORD),
                ("fdwRevocationChecks", wt.DWORD), ("dwUnionChoice", wt.DWORD),
                ("pFile", ctypes.POINTER(_WTFI)), ("dwStateAction", wt.DWORD),
                ("hWVTStateData", wt.HANDLE), ("pwszURLReference", wt.LPCWSTR),
                ("dwProvFlags", wt.DWORD), ("dwUIContext", wt.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


try:
    _WVT = ctypes.WinDLL("wintrust").WinVerifyTrust
    _WVT.argtypes = [wt.HANDLE, ctypes.POINTER(_GUID), ctypes.c_void_p]
    _WVT.restype = ctypes.c_long
except Exception:
    _WVT = None

_sig_cache: dict = {}


def is_signed_trusted(path: str) -> bool:
    if _WVT is None:
        return False
    hit = _sig_cache.get(path)
    if hit is not None:
        return hit
    ok = False
    try:
        fi = _WTFI(); fi.cbStruct = ctypes.sizeof(_WTFI); fi.pcwszFilePath = path
        wd = _WTD(); wd.cbStruct = ctypes.sizeof(_WTD)
        wd.dwUIChoice = 2                 # WTD_UI_NONE
        wd.fdwRevocationChecks = 0        # WTD_REVOKE_NONE (offline-safe)
        wd.dwUnionChoice = 1             # WTD_CHOICE_FILE
        wd.dwStateAction = 1             # WTD_STATEACTION_VERIFY
        wd.pFile = ctypes.pointer(fi)
        wd.dwProvFlags = 0x100 | 0x1000  # SAFER | CACHE_ONLY_URL_RETRIEVAL (no network)
        ok = _WVT(None, ctypes.byref(_WINTRUST_ACTION), ctypes.byref(wd)) == 0
        wd.dwStateAction = 2             # WTD_STATEACTION_CLOSE (free state)
        _WVT(None, ctypes.byref(_WINTRUST_ACTION), ctypes.byref(wd))
    except Exception:
        ok = False
    if len(_sig_cache) < 40000:
        _sig_cache[path] = ok
    return ok


_dir_trust: dict = {}


def dir_is_certified(path: str) -> bool:
    """True if the file's directory contains at least one validly code-signed
    binary — i.e. it's a certified application's install folder — so unsigned
    third-party helper libraries shipped alongside it (Vanara, LiteDB, SDL2, …)
    are trusted too, instead of tripping generic YARA rules. Cached per directory."""
    d = os.path.dirname(path)
    hit = _dir_trust.get(d)
    if hit is not None:
        return hit
    ok, n = False, 0
    try:
        for fn in os.listdir(d):
            if os.path.splitext(fn)[1].lower() in (".exe", ".dll", ".sys"):
                n += 1
                if is_signed_trusted(os.path.join(d, fn)):
                    ok = True
                    break
                if n >= 25:                  # bounded probe, keep it cheap
                    break
    except OSError:
        ok = False
    _dir_trust[d] = ok
    return ok


def _excluded(path: str) -> bool:
    """Path under another security product's tree (never our job to scan)."""
    p = path.lower()
    return any(x in p for x in _EXCLUDE)


# --------------------------------------------------------------------------- state / enroll
def load_state() -> dict:
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(s: dict) -> None:
    os.makedirs(os.path.dirname(STATE) or ".", exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f)
    os.replace(tmp, STATE)


_primary_ip_cache = ""


def primary_ip() -> str:
    global _primary_ip_cache
    if _primary_ip_cache:
        return _primary_ip_cache
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        _primary_ip_cache = ip
        return ip
    except OSError:
        return ""


def os_caption() -> str:
    try:
        import platform
        return platform.platform()
    except Exception:
        return "Windows"


def enroll(state: dict) -> str:
    global AGENT_SECRET
    import platform
    body = {"name": NAME, "ip": primary_ip(), "os": os_caption(),
            "kernel": platform.version(), "version": VERSION,
            "agent_id": state.get("agent_id"), "proto": 2}   # proto 2 = supports per-agent secret
    r = _req("POST", "/api/enroll", body)
    state["agent_id"] = r["agent_id"]
    if r.get("agent_secret"):
        AGENT_SECRET = r["agent_secret"]
        state["agent_secret"] = AGENT_SECRET
    save_state(state)
    log(f"enrolled: agent_id={r['agent_id']} name={NAME}")
    return r["agent_id"]


# --------------------------------------------------------------------------- policy
def pull_policy(agent_id: str = "") -> dict:
    p = _req("GET", "/api/sync/policy" + (f"?agent_id={urllib.parse.quote(agent_id)}" if agent_id else ""))
    hashes = {(i.get("value") or "").lower() for i in p.get("iocs", []) if i.get("type") == "hash"}
    ips = {i.get("value") for i in p.get("iocs", []) if i.get("type") == "ip"}
    raw_sigs = p.get("signatures", [])
    sigs = []               # lightweight string sets (fallback matcher)
    for s in raw_sigs:
        content = s.get("content", "")
        m = re.search(r"strings:(.*?)condition:", content, re.S | re.I)
        seg = m.group(1) if m else content
        toks = []
        for tok in re.findall(r'"((?:[^"\\]|\\.)+)"', seg):
            try:
                tok = tok.encode().decode("unicode_escape")
            except Exception:
                pass
            if len(tok) >= 8:
                toks.append(tok)
        if toks:
            sigs.append({"name": s["name"], "severity": s.get("severity", "HIGH"),
                         "mitre": s.get("mitre", []), "strings": toks})
    compiled = _compile_yara(raw_sigs) if _HAVE_YARA else None
    behaviors = p.get("behaviors", [])
    blocked = [b for b in p.get("blocked_ips", []) if b]
    closed_ports = p.get("closed_ports", [])
    proc_rules = []                              # compile cmdline regexes once here
    for b in behaviors:
        r = b.get("rule", {})
        if r.get("type") == "regex" and r.get("field") == "cmdline":
            try:
                proc_rules.append((b, re.compile(r["pattern"], re.I)))
            except re.error:
                continue
    log_rules = []                               # log-based IDS ruleset (log-ids)
    for lr in p.get("log_rules", []):
        try:
            lr = dict(lr)
            lr["rx"] = re.compile(lr["pattern"])
            log_rules.append(lr)
        except (re.error, KeyError):
            continue
    log(f"policy v{p.get('policy_version')}: {len(hashes)} hash IOCs, {len(ips)} ip IOCs, "
        f"{len(raw_sigs)} signatures ({'real-yara' if compiled else 'lite'}), {len(behaviors)} behaviors, "
        f"{len(blocked)} blocked IPs, {len(closed_ports)} closed ports, {len(log_rules)} log rules")
    return {"hashes": hashes, "ips": ips, "sigs": sigs, "yara": compiled,
            "behaviors": behaviors, "blocked": blocked, "closed_ports": closed_ports,
            "proc_rules": proc_rules, "log_rules": log_rules,
            # optional operator-supplied rootcheck extensions (paths + driver names)
            "rootkit_artifacts": p.get("rootkit_artifacts", []),
            "bad_drivers": p.get("bad_drivers", [])}


def _compile_yara(raw_sigs: list):
    """Compile all YARA signatures into one ruleset; skip individually-broken ones."""
    if not _HAVE_YARA:
        return None
    sources, meta = {}, {}
    for s in raw_sigs:
        name = s.get("name", "")
        content = s.get("content", "")
        if not name or "rule" not in content:
            continue
        try:
            yara.compile(source=content, externals=_YARA_EXTERNALS)   # validate in isolation
            sources[name] = content
            meta[name] = {"severity": s.get("severity", "HIGH"), "mitre": s.get("mitre", [])}
        except Exception:
            continue
    if not sources:
        return None
    try:
        rules = yara.compile(sources={k: v for k, v in sources.items()}, externals=_YARA_EXTERNALS)
    except Exception as exc:
        log(f"yara bulk-compile failed ({exc!r}); using lite matcher")
        return None
    return {"rules": rules, "meta": meta}


# --------------------------------------------------------------------------- detection event
def make_event(agent_id, etype, ioc_value, ioc_type, severity, confidence, details, mitre):
    now = datetime.now(timezone.utc).astimezone().isoformat()
    return {
        "schema_version": "3.0", "timestamp": now,
        "instance": {"device_name": NAME, "uuid": agent_id, "ip_address": primary_ip(), "platform": "windows"},
        "ioc": {"value": ioc_value, "type": ioc_type},
        "event": {"type": etype, "action_taken": "DETECTED", "mode": "DETECT",
                  "severity": severity, "confidence": confidence, "details": details},
        "mitre_attack": {"technique_ids": mitre},
        "integrity": {"producer": "av-agent-win"},
    }


# --------------------------------------------------------------------------- scanners
def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 256), b""):
            h.update(chunk)
    return h.hexdigest()


def _scan_file(agent_id, policy, seen, p, fn=None) -> list:
    """Scan a single file: SHA-256 IOC match, then YARA / lite-string signatures."""
    fn = fn or os.path.basename(p)
    dets = []
    if _excluded(p):                             # another security product's tree
        return dets
    try:
        if not os.path.isfile(p) or os.path.getsize(p) > MAX_FILE:
            return dets
        digest = _sha256(p)
    except OSError:
        return dets
    if digest in policy["hashes"] and (p, "hash") not in seen:
        seen.add((p, "hash"))
        dets.append(make_event(agent_id, "MALICIOUS_FILE_HASH", digest, "hash",
                               "CRITICAL", 95, {"file": p, "sha256": digest}, ["T1204"]))
        log(f"DETECT malicious hash: {p}")
        return dets
    # Fuzzy signature matching (YARA / strings) is the false-positive source. A
    # validly code-signed file — or an unsigned helper lib inside a certified
    # app's folder — is trusted and must not be fuzzy-flagged (the exact hash
    # check above already ran). This kills the vendor FP flood (Defender, Lenovo
    # Vantage's bundled OSS DLLs, etc.) while still catching unsigned/loose files.
    if TRUST_SIGNED and (is_signed_trusted(p) or dir_is_certified(p)):
        return dets
    try:
        with open(p, "rb") as f:
            blob = f.read(MAX_FILE)
    except OSError:
        return dets
    yc = policy.get("yara")
    if yc is not None:                           # real YARA
        ext = {"filename": fn, "filepath": p,
               "extension": os.path.splitext(fn)[1].lstrip("."),
               "filetype": "", "owner": "", "md5": ""}
        try:
            for match in yc["rules"].match(data=blob, externals=ext):
                if (p, match.rule) in seen:
                    continue
                seen.add((p, match.rule))
                md = yc["meta"].get(match.rule, {})
                dets.append(make_event(agent_id, "SIGNATURE_MATCH", match.rule, "signature",
                                       md.get("severity", "HIGH"), 90,
                                       {"file": p, "signature": match.rule}, md.get("mitre", [])))
                log(f"DETECT yara {match.rule}: {p}")
        except Exception:
            pass
    else:                                        # lite AND-of-strings
        for sig in policy["sigs"]:
            if all(s.encode("utf-8", "ignore") in blob for s in sig["strings"]):
                if (p, sig["name"]) in seen:
                    continue
                seen.add((p, sig["name"]))
                dets.append(make_event(agent_id, "SIGNATURE_MATCH", sig["name"], "signature",
                                       sig["severity"], 90, {"file": p, "signature": sig["name"]},
                                       sig["mitre"]))
                log(f"DETECT signature {sig['name']}: {p}")
    return dets


def _scannable(fn) -> bool:
    ext = os.path.splitext(fn)[1].lower()
    return not ext or ext in _SCAN_EXT


def scan_paths(agent_id, policy, seen, paths, cache) -> list:
    """Realtime handler: scan just the files that changed."""
    dets = []
    for p in paths:
        if not _scannable(os.path.basename(p)):
            continue
        try:
            st = os.stat(p)
        except OSError:
            cache.pop(p, None)
            continue
        cache[p] = (st.st_size, int(st.st_mtime))
        dets += _scan_file(agent_id, policy, seen, p)
    return dets


def scan_files(agent_id, policy, seen, cache) -> list:
    """Incremental full walk: only (re)hash files whose size/mtime changed."""
    dets = []
    for base in SCAN_DIRS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True):
            dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS
                       and not _excluded(os.path.join(root, d))]
            for fn in files:
                if not _scannable(fn):
                    continue
                p = os.path.join(root, fn)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                sig = (st.st_size, int(st.st_mtime))
                if cache.get(p) == sig:
                    continue
                cache[p] = sig
                dets += _scan_file(agent_id, policy, seen, p, fn)
    return dets


def scan_processes(agent_id, policy, seen) -> list:
    compiled = policy.get("proc_rules", [])       # precompiled at policy pull
    if not compiled:
        return []
    out = _ps("Get-CimInstance Win32_Process | "
              "Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress")
    if not out.strip():
        return []
    try:
        procs = json.loads(out)
    except ValueError:
        return []
    if isinstance(procs, dict):
        procs = [procs]
    dets = []
    for pr in procs:
        cmd = (pr.get("CommandLine") or pr.get("Name") or "").strip()
        pid = str(pr.get("ProcessId", ""))
        if not cmd:
            continue
        for b, rx in compiled:
            if rx.search(cmd) and ("proc", pid, b["name"]) not in seen:
                seen.add(("proc", pid, b["name"]))
                dets.append(make_event(agent_id, "SUSPICIOUS_PROCESS", b["name"], "behavior",
                                       b.get("severity", "HIGH"), 70,
                                       {"pid": pid, "cmdline": cmd[:400], "behavior": b["name"]},
                                       b.get("mitre", [])))
                log(f"DETECT behavior {b['name']}: pid {pid}")
    return dets


# --------------------------------------------------------------------------- rootkit / anomaly detection (rootcheck)
# Windows rootkit detection is consistency/trust based, not IOC-feed based:
#  - process cross-view: a PID visible to one enumeration API but hidden from
#    another (WMI Win32_Process vs Get-Process) is a user-mode-hooking tell;
#  - kernel drivers: a running driver that is NOT Authenticode-valid (catalog
#    aware via Get-AuthenticodeSignature), or whose file name matches a known
#    abused (BYOVD) / rootkit driver;
#  - known rootkit artifact paths (curated + policy-extensible).
# All local — no threat feed, no internet.
_ROOTKIT_ARTIFACTS_WIN = [
    r"C:\Windows\System32\drivers\mimidrv.sys",
    r"C:\Windows\System32\drivers\dbutil_2_3.sys",
    r"C:\Windows\System32\drivers\capcom.sys",
    r"C:\Windows\System32\drivers\RwDrv.sys",
    r"C:\Windows\System32\drivers\gdrv.sys",
    r"C:\Windows\Temp\.hidden",
]
# Known-abused / BYOVD / rootkit driver file names (lowercase). A running kernel
# driver matching one of these warrants investigation even if signed.
_BAD_DRIVERS_WIN = {
    "mimidrv.sys", "dbutil_2_3.sys", "capcom.sys", "rwdrv.sys", "gdrv.sys",
    "iqvw64e.sys", "rtcore64.sys", "winring0x64.sys", "winring0.sys", "winio.sys",
    "ntiolib.sys", "asrdrv.sys", "atillk64.sys", "physmem.sys", "speedfan.sys",
    "procexp152.sys", "kprocesshacker.sys", "msio64.sys", "gmer.sys", "aswarpot.sys",
}
# Runtime-resolved driver list with catalog-aware signature status.
_DRIVER_PS = r'''$ErrorActionPreference='SilentlyContinue'
Get-CimInstance Win32_SystemDriver | Where-Object {$_.State -eq 'Running'} | ForEach-Object {
  $p = $_.PathName
  if($p){
    $p = $p.Replace('\??\','')
    if($p.StartsWith('\SystemRoot\')){ $p = $env:SystemRoot + '\' + $p.Substring(12) }
    elseif($p -notmatch '^[A-Za-z]:\\'){ $p = $env:SystemRoot + '\System32\drivers\' + [System.IO.Path]::GetFileName($p) }
  }
  $st = 'NA'
  if($p -and (Test-Path $p)){ $st = (Get-AuthenticodeSignature $p).Status.ToString() }
  [pscustomobject]@{Name=$_.Name; Path=$p; Sig=$st}
} | ConvertTo-Json -Compress'''
_PROC_PS = ("$w=@(Get-CimInstance Win32_Process|% ProcessId);"
            "$p=@(Get-Process|% Id);"
            "[pscustomobject]@{wmi=$w;proc=$p}|ConvertTo-Json -Compress")


def _rcw_procsnap():
    out = _ps(_PROC_PS)
    if not out.strip():
        return None, None
    try:
        o = json.loads(out)
    except ValueError:
        return None, None
    w, p = o.get("wmi") or [], o.get("proc") or []
    if isinstance(w, int):
        w = [w]
    if isinstance(p, int):
        p = [p]
    return set(w), set(p)


def _rcw_hidden_processes(agent_id, seen) -> list:
    """Process cross-view: PIDs seen by one enumeration path but not the other
    (WMI vs Get-Process). A second confirming snapshot sheds short-lived races;
    a durable one-sided PID suggests process hiding."""
    dets = []
    w1, p1 = _rcw_procsnap()
    if w1 is None:
        return dets
    cand = ((w1 - p1) | (p1 - w1)) - {0, 4}           # exclude Idle(0)/System(4)
    if not cand:
        return dets
    w2, p2 = _rcw_procsnap()                           # confirm — drop race artifacts
    if w2 is None:
        return dets
    for pid in sorted(cand & ((w2 - p2) | (p2 - w2))):
        if ("rootkit", "hidproc", pid) in seen:
            continue
        seen.add(("rootkit", "hidproc", pid))
        source = "WMI-only (hidden from Get-Process)" if pid in (w1 & w2) else "Get-Process-only (hidden from WMI)"
        dets.append(make_event(agent_id, "HIDDEN_PROCESS", str(pid), "behavior", "HIGH", 78,
                               {"pid": pid, "visible_to": source,
                                "note": "PID visible to one process-enumeration API but hidden from the other"},
                               ["T1014", "T1564"]))
        log(f"ROOTCHECK hidden process: pid {pid} ({source})")
    return dets


def _rcw_drivers(agent_id, policy, seen) -> list:
    """Running kernel drivers that fail Authenticode validation (catalog-aware),
    or whose file name matches a known-abused (BYOVD) / rootkit driver."""
    dets = []
    out = _ps(_DRIVER_PS, timeout=120)
    if not out.strip():
        return dets
    try:
        drivers = json.loads(out)
    except ValueError:
        return dets
    if isinstance(drivers, dict):
        drivers = [drivers]
    extra = {str(x).lower() for x in (policy.get("bad_drivers", []) if isinstance(policy, dict) else [])}
    bad = set(_BAD_DRIVERS_WIN) | extra
    for d in drivers:
        path = (d.get("Path") or "").strip()
        name = (os.path.basename(path) if path else (d.get("Name") or "")).lower()
        if name and not name.endswith(".sys"):
            name += ".sys"
        if name in bad and ("rootkit", "baddrv", name) not in seen:
            seen.add(("rootkit", "baddrv", name))
            dets.append(make_event(agent_id, "KNOWN_VULNERABLE_DRIVER", name, "behavior", "HIGH", 85,
                                   {"driver": name, "path": path,
                                    "note": "running kernel driver matches a known-abused / BYOVD / rootkit driver"},
                                   ["T1014", "T1068"]))
            log(f"ROOTCHECK known-abused kernel driver: {name}")
            continue
        sig = str(d.get("Sig") or "")
        # NA/Valid/UnknownError are not actionable; NotSigned/HashMismatch/NotTrusted are.
        if sig in ("NotSigned", "HashMismatch", "NotTrusted") and path:
            if ("rootkit", "unsigneddrv", path) in seen:
                continue
            seen.add(("rootkit", "unsigneddrv", path))
            dets.append(make_event(agent_id, "UNSIGNED_DRIVER", name or path, "behavior", "HIGH", 80,
                                   {"driver": name, "path": path, "signature": sig,
                                    "note": f"running kernel driver failed Authenticode validation ({sig})"},
                                   ["T1014"]))
            log(f"ROOTCHECK untrusted kernel driver: {path} ({sig})")
    return dets


def _rcw_artifacts(agent_id, policy, seen) -> list:
    """Presence of a path known to be dropped by a specific rootkit (curated list
    plus any operator-supplied paths distributed via policy)."""
    dets = []
    extra = policy.get("rootkit_artifacts", []) if isinstance(policy, dict) else []
    for path in list(_ROOTKIT_ARTIFACTS_WIN) + [a for a in (extra or []) if a]:
        try:
            if not os.path.exists(path):
                continue
        except OSError:
            continue
        if ("rootkit", "artifact", path) in seen:
            continue
        seen.add(("rootkit", "artifact", path))
        dets.append(make_event(agent_id, "KNOWN_ROOTKIT_ARTIFACT", path, "behavior", "CRITICAL", 90,
                               {"path": path, "note": "path matches a known rootkit artifact"},
                               ["T1014"]))
        log(f"ROOTCHECK known rootkit artifact present: {path}")
    return dets


def rootcheck_scan(agent_id, policy, seen, state) -> list:
    """Run all Windows host-based rootkit / anomaly checks. Fully local — no
    threat feed. Each sub-check is isolated so one failure can't sink the rest."""
    if not ROOTCHECK:
        return []
    dets = []
    for chk in (lambda: _rcw_hidden_processes(agent_id, seen),
                lambda: _rcw_drivers(agent_id, policy, seen),
                lambda: _rcw_artifacts(agent_id, policy, seen)):
        try:
            dets += chk()
        except Exception as exc:
            log(f"rootcheck sub-check error: {exc!r}")
    if dets:
        log(f"rootcheck: {len(dets)} anomaly detection(s)")
    return dets


def scan_security_log(agent_id, policy, seen) -> list:
    """Failed logons (Security event 4625) -> brute-force by source IP."""
    beh = next((b for b in policy["behaviors"] if b.get("name") == "multiple_failed_logins"), None)
    threshold = int((beh or {}).get("rule", {}).get("count", 5))
    window = int((beh or {}).get("rule", {}).get("window_seconds", 600))
    mitre = (beh or {}).get("mitre", ["T1110"])
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$s=(Get-Date).AddSeconds(-{max(window, INTERVAL)});"
        "$e=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$s} -MaxEvents 500;"
        "$ips=foreach($x in $e){ $xml=[xml]$x.ToXml();"
        "($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text' };"
        "$ips | Where-Object {$_ -and $_ -ne '-'} | ConvertTo-Json -Compress"
    )
    out = _ps(script)
    if not out.strip():
        return []
    try:
        ips = json.loads(out)
    except ValueError:
        return []
    if isinstance(ips, str):
        ips = [ips]
    counts = {}
    for ip in ips:
        counts[ip] = counts.get(ip, 0) + 1
    dets, host_ip = [], primary_ip()
    for ip, n in counts.items():
        if n >= threshold and ("bruteforce", ip) not in seen:
            seen.add(("bruteforce", ip))
            dets.append(make_event(agent_id, "BRUTE_FORCE_SOURCE", ip, "ip", "HIGH", 80,
                                   {"source_ip": ip, "dest_ip": host_ip, "failed_attempts": n,
                                    "log": "Security/4625"}, mitre))
            log(f"DETECT brute force: {ip} -> {host_ip} ({n} failed logons)")
    return dets


# --------------------------------------------------------------------------- log-based IDS (general)
_WIN_LOG_LABEL = {"Security": "winsec", "System": "winsys",
                  "Microsoft-Windows-Sysmon/Operational": "sysmon"}

# (rendered label, EventData field) — Security + Sysmon superset. Only non-empty
# fields are rendered so rules can match `Field=value` tokens on one line.
_WIN_FIELDS = [
    ("Account", "acct"), ("Address", "addr"), ("Subject", "subj"), ("Service", "svc"),
    ("Process", "proc"), ("Cmd", "cmd"), ("LogonType", "ltype"), ("Group", "grp"),
    ("TktEnc", "tenc"), ("Image", "img"), ("Parent", "parent"), ("Target", "timg"),
    ("Dst", "dst"), ("DstPort", "dport"), ("File", "tfile"), ("Reg", "tobj"),
    ("Query", "query"), ("Access", "gacc"), ("User", "usr"), ("Pipe", "pipe"),
]


def _win_event_line(e: dict) -> str:
    parts = ["EventID=%s" % e.get("id")]
    for label, key in _WIN_FIELDS:
        v = (e.get(key) or "").strip()
        if v and v != "-":
            parts.append("%s=%s" % (label, v[:500]))
    return " ".join(parts)


def _win_recent_events(window_sec: int) -> list:
    """Recent Security / System / Sysmon events with fields extracted. Sysmon is
    queried too (no-op if not installed). Bounded by MaxEvents + a time window."""
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$s=(Get-Date).AddSeconds(-{max(window_sec, INTERVAL)});"
        "$o=@();foreach($ln in 'Security','System','Microsoft-Windows-Sysmon/Operational'){"
        "$e=Get-WinEvent -FilterHashtable @{LogName=$ln;StartTime=$s} -MaxEvents 500;"
        "foreach($x in $e){$d=@{};try{$xml=[xml]$x.ToXml();"
        "foreach($n in $xml.Event.EventData.Data){if($n.Name){$d[$n.Name]=[string]$n.'#text'}}}catch{};"
        "$o+=[pscustomobject]@{log=$ln;id=[int]$x.Id;rid=[long]$x.RecordId;"
        "acct=[string]$d['TargetUserName'];addr=[string]$d['IpAddress'];"
        "subj=[string]$d['SubjectUserName'];svc=[string]$d['ServiceName'];"
        "proc=[string]$d['NewProcessName'];cmd=[string]$d['CommandLine'];"
        "ltype=[string]$d['LogonType'];grp=[string]$d['GroupName'];tenc=[string]$d['TicketEncryptionType'];"
        "img=[string]$d['Image'];parent=[string]$d['ParentImage'];timg=[string]$d['TargetImage'];"
        "dst=[string]$d['DestinationIp'];dport=[string]$d['DestinationPort'];tfile=[string]$d['TargetFilename'];"
        "tobj=[string]$d['TargetObject'];query=[string]$d['QueryName'];gacc=[string]$d['GrantedAccess'];"
        "usr=[string]$d['User'];pipe=[string]$d['PipeName']}}}"
        "$o|ConvertTo-Json -Compress"
    )
    out = _ps(script, timeout=75)
    if not out.strip():
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return []
    return [data] if isinstance(data, dict) else data


def _logids_event_win(agent_id, rule, entity, logname, line, host_ip, count):
    entity = entity or ""
    ioc_type = "ip" if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", entity) else "log"
    sev = rule.get("severity", "MEDIUM")
    conf = {"CRITICAL": 90, "HIGH": 80, "MEDIUM": 65, "LOW": 40}.get(str(sev).upper(), 60)
    details = {"rule": rule.get("name"), "source": logname, "match": line[:400],
               "entity": entity, "count": count, "dest_ip": host_ip}
    ev = make_event(agent_id, rule.get("event_type", "LOG_MATCH"), entity or rule.get("name"),
                    ioc_type, sev, conf, details, rule.get("mitre", []))
    ev["integrity"]["producer"] = "log-ids"       # so SRS Logs show/filter "log-ids"
    return ev


def log_ids_scan_win(agent_id, policy, state) -> list:
    """General Windows event-log IDS (producer=log-ids): render Security/System
    events to normalized lines and match the distributed ruleset with threshold
    correlation. Only NEW events (RecordId beyond last-seen) are processed; the
    first sighting of a log establishes a baseline without alerting on history."""
    rules = [r for r in policy.get("log_rules", []) if r.get("source") in ("winsec", "winsys", "any")]
    if not rules:
        return []
    window = max((int(r.get("window_sec", 300) or 300) for r in rules), default=300)
    events = _win_recent_events(window)
    if not events:
        return []
    events.sort(key=lambda e: int(e.get("rid", 0) or 0))
    last = state.setdefault("winlog_last", {})
    win = state.setdefault("logids_win", {})
    now = time.time()
    baseline = {e.get("log", "") for e in events if e.get("log", "") not in last}
    dets, host_ip = [], primary_ip()
    for e in events:
        lg = e.get("log", "")
        rid = int(e.get("rid", 0) or 0)
        if lg in baseline or rid <= int(last.get(lg, 0) or 0):
            continue                                   # baseline / already processed
        label = _WIN_LOG_LABEL.get(lg, "winsec")
        line = _win_event_line(e)
        for r in rules:
            if r.get("source") not in ("any", label):
                continue
            m = r["rx"].search(line)
            if not m:
                continue
            grp, entity = int(r.get("entity_group", 0) or 0), ""
            if grp:
                try:
                    entity = m.group(grp) or ""
                except IndexError:
                    entity = ""
            if entity in ("-", ""):
                entity = e.get("acct") or ""           # fall back to account when no source IP
            threshold = int(r.get("threshold", 1) or 1)
            if threshold <= 1:
                dets.append(_logids_event_win(agent_id, r, entity, lg, line, host_ip, 1))
                continue
            key = r["name"] + "\x00" + entity
            w = int(r.get("window_sec", 300) or 300)
            stamps = [t for t in win.get(key, []) if now - t <= w]
            stamps.append(now)
            if len(stamps) >= threshold:
                dets.append(_logids_event_win(agent_id, r, entity, lg, line, host_ip, len(stamps)))
                win[key] = []
            else:
                win[key] = stamps
    for e in events:                                   # advance last-seen (incl. baseline logs)
        lg, rid = e.get("log", ""), int(e.get("rid", 0) or 0)
        if rid > int(last.get(lg, 0) or 0):
            last[lg] = rid
    if len(win) > 5000:
        state["logids_win"] = {}
    save_state(state)
    if dets:
        log(f"log-ids: {len(dets)} detection(s) from Windows event logs")
    return dets


# --------------------------------------------------------------------------- telemetry (ctypes)
class _MEMSTATEX(ctypes.Structure):
    _fields_ = [("dwLength", wt.DWORD), ("dwMemoryLoad", wt.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def mem_percent() -> int:
    try:
        m = _MEMSTATEX()
        m.dwLength = ctypes.sizeof(_MEMSTATEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return int(m.dwMemoryLoad)
    except Exception:
        return 0


_prev_cpu = {"idle": 0, "kernel": 0, "user": 0}


def _filetime_to_int(ft) -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def cpu_percent() -> int:
    """System CPU busy %% between calls via GetSystemTimes."""
    try:
        idle, kernel, user = wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
        ok = ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel),
                                                   ctypes.byref(user))
        if not ok:
            return 0
        i, k, u = _filetime_to_int(idle), _filetime_to_int(kernel), _filetime_to_int(user)
        di = i - _prev_cpu["idle"]
        dk = k - _prev_cpu["kernel"]
        du = u - _prev_cpu["user"]
        _prev_cpu.update(idle=i, kernel=k, user=u)
        total = dk + du                       # kernel already includes idle
        if total <= 0:
            return 0
        busy = total - di
        return int(round(max(0.0, min(100.0, 100.0 * busy / total))))
    except Exception:
        return 0


_DRIVE_FIXED = 3


def _fixed_drives() -> list:
    """All local fixed-disk roots (C:\\, D:\\, E:\\ …). Excludes removable/network/CD."""
    if DISK_PATHS:
        return DISK_PATHS
    roots = []
    try:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        mask = k.GetLogicalDrives()
        for i in range(26):
            if not (mask >> i) & 1:
                continue
            root = "%c:\\" % (ord("A") + i)
            if k.GetDriveTypeW(root) == _DRIVE_FIXED:
                roots.append(root)
    except Exception:
        pass
    return roots or [os.environ.get("SystemDrive", "C:") + "\\"]


def disk_usage() -> tuple:
    """Aggregate all fixed drives -> (% used, total GB, free GB, per-drive list)."""
    total = free = 0
    detail = []
    for root in _fixed_drives():
        try:
            u = shutil.disk_usage(root)
        except OSError:
            continue
        total += u.total
        free += u.free
        detail.append({"drive": root.rstrip("\\"), "total_gb": int(round(u.total / (1024 ** 3))),
                       "free_gb": int(round(u.free / (1024 ** 3)))})
    if not total:
        return 0, 0, 0, []
    pct = int(round(100.0 * (total - free) / total))
    return max(0, min(100, pct)), int(round(total / (1024 ** 3))), int(round(free / (1024 ** 3))), detail


# Suricata IDS/IPS is a Linux (inline NFQUEUE) capability; report it as such so
# the console can disable the toggle for Windows endpoints.
_NIDS_STATUS_WIN = {"installed": False, "running": False, "mode": "off", "engine": "",
                    "rules": 0, "note": "Suricata IDS/IPS runs on Linux endpoints"}


def heartbeat(agent_id, policy_version=0, ports=None) -> dict:
    disk_pct, disk_total, disk_free, disk_drives = disk_usage()
    body = {"status": "online", "policy_version": policy_version, "version": VERSION,
            "cpu": cpu_percent(), "mem": mem_percent(), "disk": disk_pct,
            "disk_total": disk_total, "disk_free": disk_free, "disk_drives": disk_drives,
            "nids_status": _NIDS_STATUS_WIN}
    if ports is not None:
        body["ports"] = ports
    try:
        return _req("POST", f"/api/agents/{agent_id}/heartbeat", body) or {}
    except Exception as exc:
        log(f"heartbeat failed: {exc!r}")
        return {}


UPDATE_TASK = os.environ.get("SENTINEL_TASK_NAME", "PadakhepSentinelAV")


def _is_elevated() -> bool:
    """True only if this process runs elevated / as SYSTEM (high integrity)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _harden_install_dir() -> None:
    """SEN-011: lock the install dir so a standard user cannot pre-plant/race a
    malicious sentinel-update.cmd / .exe that the agent would then execute (local
    privilege escalation). Grant write only to SYSTEM + Administrators.

    CRITICAL: only do this when the agent itself runs ELEVATED / as SYSTEM —
    otherwise the admin-only DACL would lock the (non-elevated) agent out of its
    own dir/state and it could not run or self-update. A non-elevated agent is not
    the LPE target this addresses, so skipping is safe; run the agent as SYSTEM
    (scheduled task) to get the hardening. Idempotent."""
    if not os.path.isdir(INSTALL_DIR):
        return
    if not _is_elevated():
        log("install-dir hardening skipped (SEN-011): agent not elevated — run as SYSTEM "
            "(scheduled task) to lock the install dir to SYSTEM+Administrators.")
        return
    try:
        subprocess.run(["icacls", INSTALL_DIR, "/inheritance:r",
                        "/grant:r", "*S-1-5-18:(OI)(CI)F",      # NT AUTHORITY\SYSTEM
                        "/grant:r", "*S-1-5-32-544:(OI)(CI)F",  # BUILTIN\Administrators
                        "/T", "/C", "/Q"], capture_output=True, timeout=40)
    except Exception as exc:
        log(f"install-dir hardening failed ({exc!r})")


def _install_dir_user_writable() -> bool:
    """True if a non-admin principal (Users / Authenticated Users / Everyone) holds
    write/modify/full on the install dir — i.e. the SEN-011 pre-plant risk remains."""
    try:
        r = subprocess.run(["icacls", INSTALL_DIR], capture_output=True, timeout=20, text=True)
        for line in (r.stdout or "").splitlines():
            if re.search(r"(BUILTIN\\Users|Authenticated Users|Everyone)\S*:\([^)]*[WMF]", line):
                return True
    except Exception:
        pass
    return False


def _defender_exclude_self() -> None:
    """Best-effort: exempt only OUR signed exe (not the whole directory — SEN-011)
    from Defender so a freshly swapped, re-hashed build isn't heuristically
    quarantined during self-update. File-scoped so the directory is not a malware
    safe-harbor. Needs SYSTEM/admin; silently no-ops otherwise."""
    if not getattr(sys, "frozen", False):
        return
    try:
        exe = os.path.abspath(sys.executable)
        _ps(f"Add-MpPreference -ExclusionPath '{exe}' -ErrorAction SilentlyContinue", timeout=20)
    except Exception:
        pass


def self_update(directive) -> None:
    """Apply an operator-pushed build. Frozen exe -> staged swap via a helper
    .cmd (a running exe can't overwrite itself); source mode -> in-place re-exec."""
    url = API + "/api/agent/download/windows"        # SEN-002: never trust a server-supplied URL
    want, ver = directive.get("sha256", ""), directive.get("version", "?")
    log(f"update requested -> v{ver}; downloading {url}")
    try:
        with urllib.request.urlopen(url, timeout=120, context=_ssl_ctx()) as r:
            data = r.read()
    except Exception as exc:
        log(f"update download failed: {exc!r}"); return
    if not want:                                     # never accept an unverified build
        log("update aborted: directive carried no sha256"); return
    if hashlib.sha256(data).hexdigest() != want:
        log("update aborted: sha256 mismatch"); return
    if SIGNING_PUBKEY:                               # authenticity, not just integrity
        sig = directive.get("signature") or ""
        try:
            ok = bool(sig) and ed25519_verify(SIGNING_PUBKEY, bytes.fromhex(sig), data)
        except ValueError:
            ok = False
        if not ok:
            log("update aborted: missing/invalid Ed25519 signature (unsigned or tampered build)")
            return
        log("update signature verified (Ed25519)")

    if getattr(sys, "frozen", False):
        exe = sys.executable                          # current sentinel-av.exe
        newexe = exe + ".new"
        try:
            with open(newexe, "wb") as f:
                f.write(data)
        except OSError as exc:
            log(f"update aborted: cannot stage new exe ({exc!r})"); return
        cmd_path = os.path.join(os.path.dirname(exe), "sentinel-update.cmd")
        exename = os.path.basename(exe)
        # Self-healing swap: back up the old exe, swap in the new one, start it, and
        # verify it actually comes up. If it doesn't (AV quarantine, task issue),
        # ROLL BACK to the old exe and restart it — never leave the host unprotected.
        script = (
            "@echo off\r\n"
            "ping 127.0.0.1 -n 4 >nul\r\n"                     # let this process fully exit
            f'copy /y "{exe}" "{exe}.bak" >nul 2>&1\r\n'       # rollback copy
            f'move /y "{newexe}" "{exe}" >nul 2>&1\r\n'
            f'schtasks /run /tn "{UPDATE_TASK}" >nul 2>&1\r\n'
            "ping 127.0.0.1 -n 21 >nul\r\n"                    # ~20s: did the new agent come up?
            f'tasklist /fi "imagename eq {exename}" 2>nul | find /i "{exename}" >nul\r\n'
            "if not errorlevel 1 goto done\r\n"
            f'schtasks /run /tn "{UPDATE_TASK}" >nul 2>&1 || start "" "{exe}" --run\r\n'
            "ping 127.0.0.1 -n 16 >nul\r\n"                    # retry + wait ~15s more
            f'tasklist /fi "imagename eq {exename}" 2>nul | find /i "{exename}" >nul\r\n'
            "if not errorlevel 1 goto done\r\n"
            f'copy /y "{exe}.bak" "{exe}" >nul 2>&1\r\n'       # ROLLBACK to the known-good exe
            f'schtasks /run /tn "{UPDATE_TASK}" >nul 2>&1 || start "" "{exe}" --run\r\n'
            ":done\r\n"
            'del "%~f0" >nul 2>&1\r\n'
        )
        try:
            with open(cmd_path, "w", encoding="ascii") as f:
                f.write(script)
        except OSError as exc:
            log(f"update aborted: cannot write updater ({exc!r})"); return
        DETACHED = 0x00000008 | 0x00000200            # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        try:
            subprocess.Popen(["cmd", "/c", cmd_path], creationflags=DETACHED, close_fds=True,
                             cwd=os.path.dirname(exe))
        except Exception as exc:
            log(f"update aborted: cannot launch updater ({exc!r})"); return
        log(f"staged v{ver}; exiting so the updater can swap and restart")
        sys.exit(0)
    else:                                             # running from source (python -m)
        try:
            compile(data, "agent_win.py", "exec")
        except SyntaxError as exc:
            log(f"update aborted: new code does not compile ({exc})"); return
        path = os.path.abspath(__file__)
        try:
            tmp = path + ".new"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except OSError as exc:
            log(f"update aborted: write failed ({exc!r})"); return
        log(f"updated to v{ver}; re-executing")
        os.execv(sys.executable, [sys.executable, "-m", "av_agent.agent_win"])


def report(agent_id, dets, producer="av-agent-win") -> None:
    if not dets:
        return
    try:
        r = _req("POST", "/api/detections", {"producer": producer, "agent_id": agent_id, "events": dets})
        log(f"reported {r.get('ingested', 0)} detection(s)")
    except Exception as exc:
        log(f"report failed: {exc!r}")


# --------------------------------------------------------------------------- endpoint isolation
# Guarded quarantine via Windows Defender Firewall: block all inbound+outbound
# except loopback (implicit), the control plane, and management (RDP/WinRM/SSH).
_FW_GROUP = "PadakhepSentinelQuarantine"


def _ctrl_ip() -> str:
    try:
        return urllib.parse.urlsplit(API).hostname or ""
    except ValueError:
        return ""


def apply_isolation() -> bool:
    # allowlist: control plane + optional operator jump host(s). No RDP/WinRM/SSH
    # carve-out -> the host is cut from the LAN too (stops lateral movement).
    allow = [_ctrl_ip()] + [c.strip() for c in os.environ.get("SENTINEL_ISOLATION_ALLOW", "").split(",")]
    allow = [a for a in allow if a]
    rc, _, err = _run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                       "blockinbound,blockoutbound"])
    if rc != 0:
        log(f"isolation firewallpolicy error: {err.strip()}")
        return False
    if allow:
        remoteip = ",".join(allow)
        _run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PadakhepSentinel-IsoOut",
              "dir=out", "action=allow", "enable=yes", f"group={_FW_GROUP}", f"remoteip={remoteip}"])
        _run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PadakhepSentinel-IsoIn",
              "dir=in", "action=allow", "enable=yes", f"group={_FW_GROUP}", f"remoteip={remoteip}"])
    log(f"ENDPOINT ISOLATED: full firewall quarantine (LAN cut); reachable only from {allow}")
    return True


def remove_isolation() -> bool:
    # restore normal posture and drop our allow rules
    _run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
          "blockinbound,allowoutbound"])
    _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"group={_FW_GROUP}"])
    log("endpoint isolation lifted: firewall quarantine removed")
    return True


def enforce_isolation(desired, state: dict) -> None:
    desired, applied = bool(desired), bool(state.get("isolated_applied"))
    if desired == applied:
        return
    ok = apply_isolation() if desired else remove_isolation()
    if ok:
        state["isolated_applied"] = desired
        save_state(state)


# --------------------------------------------------------------------------- IP blocklist enforcement
_BL_GROUP = "PadakhepSentinelBlocklist"


def enforce_blocklist(ips, state: dict) -> None:
    """Block traffic to/from the blocked IPs via Windows Firewall rules. Never
    blocks the control-plane IP so the agent stays manageable."""
    ctrl = _ctrl_ip()
    try:
        ctrl_addr = ipaddress.ip_address(ctrl) if ctrl else None
    except ValueError:
        ctrl_addr = None
    valid = set()
    for i in (ips or []):
        i = (i or "").strip()
        if not i or ":" in i:
            continue
        try:
            net = ipaddress.ip_network(i, strict=False)   # defence-in-depth: validate locally
        except ValueError:
            continue
        if net.prefixlen == 0 or net.num_addresses > 65536:   # never self-strand (SEN-009/010)
            continue
        if ctrl_addr is not None and ctrl_addr in net:        # never block the control plane
            continue
        valid.add(i)
    wanted = sorted(valid)
    if wanted == state.get("blocklist_applied", []):
        return
    _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"group={_BL_GROUP}"])  # clear prior
    if wanted:
        remoteip = ",".join(wanted)
        _run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PadakhepSentinel-BlockOut",
              "dir=out", "action=block", "enable=yes", f"group={_BL_GROUP}", f"remoteip={remoteip}"])
        _run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PadakhepSentinel-BlockIn",
              "dir=in", "action=block", "enable=yes", f"group={_BL_GROUP}", f"remoteip={remoteip}"])
        log(f"blocklist: enforcing {len(wanted)} IP(s) via Windows Firewall")
    else:
        log("blocklist: cleared (no blocked IPs)")
    state["blocklist_applied"] = wanted
    save_state(state)


# --------------------------------------------------------------------------- open-port inventory
def observe_ports() -> list:
    """Listening TCP + bound UDP sockets with owning process names."""
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$pm=@{};Get-Process|ForEach-Object{$pm[[int]$_.Id]=$_.ProcessName};"
        "$o=@();"
        "Get-NetTCPConnection -State Listen|ForEach-Object{"
        "$o+=[pscustomobject]@{port=[int]$_.LocalPort;proto='tcp';laddr=[string]$_.LocalAddress;proc=[string]$pm[[int]$_.OwningProcess]}};"
        "Get-NetUDPEndpoint|ForEach-Object{"
        "$o+=[pscustomobject]@{port=[int]$_.LocalPort;proto='udp';laddr=[string]$_.LocalAddress;proc=[string]$pm[[int]$_.OwningProcess]}};"
        "$o|Sort-Object proto,port -Unique|ConvertTo-Json -Compress"
    )
    out = _ps(script)
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            rows = [{"port": int(d.get("port", 0)), "proto": d.get("proto", "tcp"),
                     "laddr": d.get("laddr", ""), "proc": d.get("proc", "")}
                    for d in data if d.get("port")]
            if rows:
                return rows
        except (ValueError, TypeError):
            pass
    return _observe_ports_netstat()


def _observe_ports_netstat() -> list:
    """Fallback for older Windows without Get-NetTCPConnection: parse netstat."""
    rc, out, _ = _run(["netstat", "-ano", "-p", "TCP"])
    rows, seen = [], set()
    if rc == 0:
        for ln in out.splitlines():
            c = ln.split()
            if len(c) >= 4 and c[0].upper() == "TCP" and c[3].upper() == "LISTENING":
                laddr, _, port_s = c[1].rpartition(":")
                if port_s.isdigit() and ("tcp", int(port_s)) not in seen:
                    seen.add(("tcp", int(port_s)))
                    rows.append({"port": int(port_s), "proto": "tcp", "laddr": laddr, "proc": ""})
    return sorted(rows, key=lambda x: x["port"])


# --------------------------------------------------------------------------- closed-port enforcement
# Operator-closed host ports -> inbound block rules in Windows Firewall. Opening
# a port removes it from the set on the next sync.
_PORT_GROUP = "PadakhepSentinelPorts"


def enforce_ports(closed, state: dict) -> None:
    want = sorted({(str(c.get("proto", "tcp")).lower(), int(c["port"]))
                   for c in (closed or []) if c.get("port")})
    if want == [tuple(x) for x in state.get("ports_applied", [])]:
        return
    _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"group={_PORT_GROUP}"])  # clear prior
    if want:
        for proto in ("tcp", "udp"):
            ports = [str(p) for pr, p in want if pr == proto]
            if not ports:
                continue
            _run(["netsh", "advfirewall", "firewall", "add", "rule",
                  f"name=PadakhepSentinel-Port-{proto}", "dir=in", "action=block", "enable=yes",
                  f"group={_PORT_GROUP}", f"protocol={proto.upper()}", "localport=" + ",".join(ports)])
        log(f"ports: closing {len(want)} port(s) via Windows Firewall "
            f"({', '.join(f'{pr}/{p}' for pr, p in want)})")
    else:
        log("ports: no closed ports (all open)")
    state["ports_applied"] = [list(x) for x in want]
    save_state(state)


# --------------------------------------------------------------------------- realtime watcher (ReadDirectoryChangesW)
_FILE_LIST_DIRECTORY = 0x0001
_FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_NOTIFY_FLAGS = 0x1 | 0x8 | 0x10 | 0x40    # FILE_NAME | SIZE | LAST_WRITE | CREATION
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class NullWatcher:
    active = False

    def wait(self, timeout):
        if timeout > 0:
            time.sleep(timeout)
        return []

    def close(self):
        pass


class WinWatcher:
    """Realtime file monitoring via a ReadDirectoryChangesW thread per scan dir."""

    def __init__(self, dirs):
        self.active = False
        self.q: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._threads = []
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = wt.HANDLE
        k.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                  wt.DWORD, wt.DWORD, wt.HANDLE]
        k.ReadDirectoryChangesW.restype = wt.BOOL
        k.ReadDirectoryChangesW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, wt.BOOL,
                                            wt.DWORD, ctypes.POINTER(wt.DWORD),
                                            ctypes.c_void_p, ctypes.c_void_p]
        k.CloseHandle.restype = wt.BOOL
        k.CloseHandle.argtypes = [wt.HANDLE]
        self._k = k
        for base in dirs:
            if os.path.isdir(base):
                t = threading.Thread(target=self._watch, args=(base,), daemon=True)
                t.start()
                self._threads.append(t)
                self.active = True

    def _watch(self, base):
        handle = self._k.CreateFileW(base, _FILE_LIST_DIRECTORY, _FILE_SHARE_ALL, None,
                                     _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS, None)
        if not handle or handle == _INVALID_HANDLE:
            return
        buf = ctypes.create_string_buffer(65536)
        nb = wt.DWORD()
        try:
            while not self._stop.is_set():
                ok = self._k.ReadDirectoryChangesW(
                    handle, buf, len(buf), True, _NOTIFY_FLAGS, ctypes.byref(nb), None, None)
                if not ok or nb.value == 0:
                    continue
                raw = buf.raw[:nb.value]
                off = 0
                while off + 12 <= len(raw):
                    next_off, action, namelen = struct.unpack_from("III", raw, off)
                    try:
                        name = raw[off + 12:off + 12 + namelen].decode("utf-16-le")
                    except Exception:
                        name = ""
                    if name and action in (1, 3, 5):   # added / modified / renamed-new
                        self.q.put(os.path.join(base, name))
                    if next_off == 0:
                        break
                    off += next_off
        finally:
            try:
                self._k.CloseHandle(handle)
            except Exception:
                pass

    def wait(self, timeout):
        paths = []
        try:
            paths.append(self.q.get(timeout=max(0.0, timeout)))
            while True:
                paths.append(self.q.get_nowait())
        except queue.Empty:
            pass
        return list(dict.fromkeys(paths))

    def close(self):
        self._stop.set()


def make_watcher():
    if not REALTIME:
        return NullWatcher()
    try:
        w = WinWatcher(SCAN_DIRS)
        if w.active:
            log(f"realtime file monitoring active (ReadDirectoryChangesW): {len(w._threads)} dir(s)")
            return w
    except Exception as exc:
        log(f"realtime watcher unavailable ({exc!r}); using periodic incremental scan")
    return NullWatcher()


# --------------------------------------------------------------------------- main
def _apply_hb(hb, state) -> None:
    """React to a heartbeat response: update / isolate / blocklist / closed ports."""
    if hb.get("update"):
        self_update(hb["update"])                   # re-execs / exits on success
    enforce_isolation(hb.get("isolate"), state)
    if "blocked" in hb:                             # guarded: absent on a failed beat
        enforce_blocklist(hb["blocked"], state)
    if "closed_ports" in hb:
        enforce_ports(hb["closed_ports"], state)


def _single_instance() -> bool:
    """Prevent a second agent (e.g. logon launcher + a manual run) via a mutex."""
    try:
        h = ctypes.windll.kernel32.CreateMutexW(None, False, "PadakhepSentinelAV_singleton")
        if h and ctypes.windll.kernel32.GetLastError() == 183:   # ERROR_ALREADY_EXISTS
            return False
        globals()["_MUTEX"] = h                                  # keep the handle alive
    except Exception:
        pass
    return True


def _write_autostart(exe: str) -> str:
    """Silent per-user logon launcher (hidden, no console). Returns its path."""
    startup = os.path.join(os.environ.get("APPDATA", ""),
                           r"Microsoft\Windows\Start Menu\Programs\Startup")
    os.makedirs(startup, exist_ok=True)
    vbs = os.path.join(startup, "PadakhepSentinelAV.vbs")
    with open(vbs, "w", encoding="ascii") as f:
        f.write("' Padakhep Sentinel AV - silent logon launcher (auto-generated)\r\n"
                'Set sh = CreateObject("WScript.Shell")\r\n'
                'sh.Run """' + exe + '"" --run", 0, False\r\n')
    return vbs


def _register_system_task(exe: str) -> bool:
    """Register the agent as a SYSTEM scheduled task (runs at boot, highest privs).
    Running as SYSTEM makes remote-update relaunch reliable (the updater does
    `schtasks /run /tn <task>`) and lets the SEN-011 dir hardening apply without
    locking the agent out. Needs admin; returns True on success."""
    try:
        r = subprocess.run(["schtasks", "/create", "/tn", UPDATE_TASK,
                            "/tr", f'"{exe}" --run', "/sc", "onstart",
                            "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"],
                           capture_output=True, timeout=30, text=True)
        if r.returncode != 0:
            log(f"schtasks create failed: {(r.stderr or r.stdout or '').strip()[:120]}")
        return r.returncode == 0
    except Exception as exc:
        log(f"schtasks create error ({exc!r})")
        return False


def _relaunch_elevated_install() -> bool:
    """Re-run this exe elevated (UAC) to perform the SYSTEM install. >32 = launched."""
    try:
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "--install-system", None, 0)
        return int(r) > 32
    except Exception:
        return False


def _remove_user_autostart() -> None:
    try:
        vbs = os.path.join(os.environ.get("APPDATA", ""),
                           r"Microsoft\Windows\Start Menu\Programs\Startup", "PadakhepSentinelAV.vbs")
        if os.path.isfile(vbs):
            os.remove(vbs)
    except OSError:
        pass


def install_and_launch(system: bool = False) -> None:
    """First-run setup: copy into ProgramData and register autostart.

    Default (``--install`` / first run): a **per-user logon launcher** — the proven,
    non-privileged path. The agent runs as the logged-in user and the SEN-011 dir
    hardening self-skips, so it can never lock itself out.

    Opt-in (``--install-system`` / ``SENTINEL_INSTALL_SYSTEM=1``): register a SYSTEM
    scheduled task (runs at boot, highest privileges) — reliable remote-update relaunch
    plus SEN-011 hardening. Needs admin; if not already elevated it self-elevates once
    via UAC and, if that is declined, falls back to the per-user launcher. This is a
    deliberate action (not auto-triggered on every install) so a plain install never
    springs an unexpected UAC prompt. Idempotent."""
    system = system or os.environ.get("SENTINEL_INSTALL_SYSTEM", "0") in ("1", "true", "yes")
    elevated = _is_elevated()
    if system and not elevated:
        if _relaunch_elevated_install():
            log("install: relaunching elevated to register the SYSTEM service…")
            return                                        # the elevated instance finishes the install
        log("install: SYSTEM install requested but UAC unavailable/declined — using per-user autostart.")
        system = False
    exe = INSTALL_EXE
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        if os.path.abspath(sys.executable).lower() != os.path.abspath(exe).lower():
            shutil.copy2(sys.executable, exe)             # copy self into place
    except Exception as exc:
        log(f"install: copy failed ({exc!r}); running from current location")
        exe = sys.executable

    if system and elevated and _register_system_task(exe):
        _remove_user_autostart()                          # avoid a second (user) instance
        _harden_install_dir()                             # SEN-011: safe now — agent runs as SYSTEM
        try:
            subprocess.run(["schtasks", "/run", "/tn", UPDATE_TASK], capture_output=True, timeout=30)
        except Exception:
            pass
        log(f"installed as SYSTEM scheduled task '{UPDATE_TASK}' -> {INSTALL_DIR}")
    else:
        # Default / fallback: per-user logon launcher (agent runs as the user;
        # SEN-011 hardening self-skips so it can't lock itself out).
        if system and elevated:
            log("install: SYSTEM task registration failed — falling back to per-user autostart.")
        elif not system:
            log("install: per-user autostart (default). "
                "For the SYSTEM service + SEN-011 hardening, run: sentinel-av.exe --install-system (as Administrator).")
        try:
            _write_autostart(exe)
        except Exception as exc:
            log(f"install: autostart registration failed ({exc!r})")
        try:
            subprocess.Popen([exe, "--run"], close_fds=True,
                             creationflags=_CREATE_NO_WINDOW | 0x00000008)   # DETACHED_PROCESS
        except Exception as exc:
            log(f"install: could not start agent ({exc!r})"); return
        log(f"Padakhep Sentinel AV installed (per-user) -> {INSTALL_DIR}")
    log(f"reporting to {API}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-av-win")
    ap.add_argument("--once", action="store_true", help="run a single scan pass then exit")
    ap.add_argument("--run", action="store_true", help="run the agent loop (skip first-run install)")
    ap.add_argument("--install", action="store_true", help="install (per-user autostart) + start in background, then exit")
    ap.add_argument("--install-system", dest="install_system", action="store_true",
                    help="install as a SYSTEM scheduled task (self-elevates via UAC; boot start + SEN-011 hardening)")
    args = ap.parse_args()
    frozen = getattr(sys, "frozen", False)
    # A packaged exe launched with no flags = first-run install (copy + per-user
    # autostart + start hidden). The autostart launcher and updater call it with --run.
    if args.install or args.install_system or (frozen and not args.run and not args.once):
        install_and_launch(system=args.install_system)
        return
    if not args.once and not _single_instance():
        log("another instance is already running; exiting")
        return
    log(f"starting Windows AV agent v{VERSION} -> {API}; yara={'on' if _HAVE_YARA else 'lite'}; "
        f"realtime={'on' if REALTIME else 'off'}; trust_signed={'on' if TRUST_SIGNED else 'off'}; "
        f"scan_dirs={SCAN_DIRS}")
    _harden_install_dir()         # SEN-011: re-assert the restrictive DACL every start (only when elevated)
    if _is_elevated() and _install_dir_user_writable():
        log("WARNING: install dir is user-writable after hardening — possible SEN-011 pre-plant risk; "
            "investigate ACLs on " + INSTALL_DIR)
    _defender_exclude_self()      # keep future self-updates from being quarantined (exe-scoped)
    state = load_state()
    global AGENT_SECRET
    AGENT_SECRET = state.get("agent_secret", "")   # so re-enroll proves ownership (SEN-007)
    for _ in range(30):
        try:
            agent_id = enroll(state)
            break
        except Exception as exc:
            log(f"enroll retry ({exc!r})")
            if args.once:
                return
            time.sleep(10)
    else:
        return
    seen: set = set()
    scan_cache: dict = {}
    policy = {"hashes": set(), "ips": set(), "sigs": [], "yara": None, "behaviors": [], "proc_rules": []}
    cpu_percent()

    # Initial policy + baseline (incremental) scan before switching to realtime.
    try:
        policy = pull_policy(agent_id)
        enforce_blocklist(policy.get("blocked", []), state)
        enforce_ports(policy.get("closed_ports", []), state)
    except Exception as exc:
        log(f"initial policy pull failed: {exc!r}")
    report(agent_id, scan_files(agent_id, policy, seen, scan_cache))
    report(agent_id, scan_processes(agent_id, policy, seen))
    report(agent_id, log_ids_scan_win(agent_id, policy, state), producer="log-ids")
    report(agent_id, rootcheck_scan(agent_id, policy, seen, state), producer="rootcheck")
    _apply_hb(heartbeat(agent_id, ports=observe_ports()), state)

    if args.once:
        return

    watcher = make_watcher()
    last_policy = last_beat = last_full = last_aux = last_rootcheck = time.time()
    try:
        while True:
            due = min(POLICY_EVERY - (time.time() - last_policy),
                      INTERVAL - (time.time() - last_beat),
                      FULLSCAN_EVERY - (time.time() - last_full))
            changed = watcher.wait(max(1.0, min(due, INTERVAL)))
            if changed:
                try:
                    report(agent_id, scan_paths(agent_id, policy, seen, changed, scan_cache))
                except Exception as exc:
                    log(f"realtime scan error: {exc!r}")

            now = time.time()
            if now - last_policy >= POLICY_EVERY or not policy.get("behaviors"):
                try:
                    policy = pull_policy(agent_id)
                    enforce_blocklist(policy.get("blocked", []), state)
                    enforce_ports(policy.get("closed_ports", []), state)
                except Exception as exc:
                    log(f"policy pull failed: {exc!r}")
                last_policy = now
            if now - last_aux >= INTERVAL:
                try:
                    report(agent_id, scan_processes(agent_id, policy, seen))
                    report(agent_id, log_ids_scan_win(agent_id, policy, state), producer="log-ids")
                except Exception as exc:
                    log(f"aux scan error: {exc!r}")
                last_aux = now
            if now - last_full >= FULLSCAN_EVERY or not watcher.active:
                try:
                    report(agent_id, scan_files(agent_id, policy, seen, scan_cache))
                except Exception as exc:
                    log(f"full scan error: {exc!r}")
                last_full = now
            if now - last_rootcheck >= ROOTCHECK_EVERY:
                try:                                 # host rootkit / anomaly checks (local, no feed)
                    report(agent_id, rootcheck_scan(agent_id, policy, seen, state), producer="rootcheck")
                except Exception as exc:
                    log(f"rootcheck error: {exc!r}")
                last_rootcheck = now
            if now - last_beat >= INTERVAL:
                try:
                    _apply_hb(heartbeat(agent_id, ports=observe_ports()), state)
                except Exception as exc:
                    log(f"heartbeat error: {exc!r}")
                last_beat = now
            if len(seen) > _SEEN_MAX:
                seen = set()
    finally:
        watcher.close()


if __name__ == "__main__":
    main()
