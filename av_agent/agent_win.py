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
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import warnings
from datetime import datetime, timezone

# Control plane is baked in so the exe works with zero configuration; override
# with the SENTINEL_API env var only if your server address differs.
DEFAULT_API = "http://192.168.39.32:8080"
API = os.environ.get("SENTINEL_API", DEFAULT_API)
NAME = os.environ.get("AGENT_NAME", socket.gethostname())
# Lean default scan scope (high-risk drop zones) — realtime catches new files
# anywhere here without re-hashing whole user profiles. Override with SENTINEL_SCAN_DIRS.
_HOME = os.path.expanduser("~")


def _enum_user_dropzones() -> list:
    """Every real per-user Downloads/Desktop. Running as SYSTEM, expanduser('~')
    resolves to C:\\Windows\\System32\\config\\systemprofile (empty), so a SYSTEM
    agent would otherwise MISS exactly the user folders where delivered malware
    lands — enumerate the actual profiles instead. Unreadable/denied dirs are
    silently skipped (harmless in per-user mode)."""
    out = []
    users = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
    skip = {"public", "default", "default user", "all users", "defaultappuser", "wdagutilityaccount"}
    try:
        for name in os.listdir(users):
            if name.lower() in skip:
                continue
            for sub in ("Downloads", "Desktop"):
                p = os.path.join(users, name, sub)
                if os.path.isdir(p):
                    out.append(p)
    except OSError:
        pass
    return out


def _default_scan_dirs() -> list:
    base = [r"C:\Windows\Temp", r"C:\ProgramData", r"C:\Users\Public"]
    dz = _enum_user_dropzones() or [os.path.join(_HOME, "Downloads"), os.path.join(_HOME, "Desktop")]
    seen, res = set(), []
    for d in base + dz:                                   # de-dup, keep order
        if d.lower() not in seen:
            seen.add(d.lower()); res.append(d)
    return res


SCAN_DIRS = [d for d in os.environ.get("SENTINEL_SCAN_DIRS", ";".join(_default_scan_dirs())).split(";") if d]
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
# Windows telemetry (Sysmon + ETW channels) & enforcement (Firewall/WFP) status: how often
# to re-measure it for the heartbeat, and whether the installer provisions it (Sysmon config,
# ETW channels, script-block logging, firewall-on). Provisioning needs elevation (SYSTEM install).
WIN_TELEMETRY_EVERY = int(os.environ.get("SENTINEL_WIN_TELEMETRY_INTERVAL", "300"))
PROVISION_TELEMETRY = os.environ.get("SENTINEL_WIN_PROVISION", "1") not in ("0", "false", "")
TOKEN = os.environ.get("SENTINEL_API_TOKEN", "")
# SEN-006 TLS: verify the server cert when API is https (pin via SENTINEL_CA_CERT);
# SENTINEL_TLS_INSECURE=1 disables verification (lab only). SEN-007: per-agent secret.
CA_CERT = os.environ.get("SENTINEL_CA_CERT", "")
TLS_INSECURE = os.environ.get("SENTINEL_TLS_INSECURE", "0") not in ("0", "false", "")
AGENT_SECRET = ""
_SSL_CTX = None
VERSION = "0.5.0-win"
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
                # rule strings legitimately contain non-Python escapes (e.g. \s, \d);
                # unicode_escape would emit a DeprecationWarning per token — silence it.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
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
            "bad_drivers": p.get("bad_drivers", []),
            # LOLDrivers BYOVD known-bad driver hashes (content match beats a name list)
            "bad_driver_hashes": p.get("bad_driver_hashes", [])}


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

# System pseudo-processes that legitimately appear in some enumerators but not
# others (protected / minimal-process) — excluded so the cross-view stays low-FP.
_PSEUDO_PROC = {"registry", "memory compression", "secure system", "system", "idle",
                "vmmem", "vmmemwsl", "system idle process"}


def _rcw_pids_toolhelp():
    """Kernel32 Toolhelp32 process snapshot — a NATIVE enumeration source independent
    of WMI and Get-Process, so a user-mode hook must spoof THREE APIs, not one. Returns
    (set_of_pids, {pid: exe_name_lower}) or (None, {})."""
    try:
        TH32CS_SNAPPROCESS = 0x2

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                        ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD),
                        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                        ("szExeFile", ctypes.c_wchar * 260)]
        k = ctypes.windll.kernel32
        k.CreateToolhelp32Snapshot.restype = wt.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
        snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snap or snap == ctypes.c_void_p(-1).value:
            return None, {}
        pids, names = set(), {}
        try:
            e = PROCESSENTRY32W(); e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            k.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            k.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            ok = k.Process32FirstW(snap, ctypes.byref(e))
            while ok:
                pids.add(int(e.th32ProcessID)); names[int(e.th32ProcessID)] = (e.szExeFile or "").lower()
                ok = k.Process32NextW(snap, ctypes.byref(e))
        finally:
            k.CloseHandle(snap)
        return pids, names
    except Exception:
        return None, {}


# Known Windows system-process image names (lowercase). Used ONLY by the trust stage to
# avoid crying rootkit on a system process that a snapshot API briefly didn't list.
_WIN_SYSTEM_PROCS = {"system", "registry", "memory compression", "secure system", "idle",
    "system idle process", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
    "taskhostw.exe", "spoolsv.exe", "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
    "wudfhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "searchindexer.exe"}

_ROOTKIT_MIN_CONF = int(os.environ.get("SENTINEL_ROOTKIT_MIN_CONFIDENCE", "70"))


def _rcw_kernel_pids(cap):
    """The set of PIDs the KERNEL confirms exist, via a brute-force OpenProcess over the
    PID space (a direct kernel query, NOT a snapshot that races). Counts only a SUCCESSFUL
    open (a non-null handle == the process definitely exists) — deliberately NOT relying on
    GetLastError/ACCESS_DENIED, which is unreliable via ctypes windll and massively
    over-counts. A protected process that denies the open is still listed by the
    enumeration APIs, so it can't become a false candidate. Returns a set or None."""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k = ctypes.windll.kernel32
    try:
        k.OpenProcess.restype = wt.HANDLE
        k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    except Exception:
        return None
    pids = set()
    for pid in range(4, cap + 1, 4):                   # Windows PIDs are multiples of 4
        h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h:
            pids.add(pid); k.CloseHandle(h)
    return pids


def _rcw_proc_image(pid):
    """(exists, image_path) via OpenProcess + QueryFullProcessImageNameW. exists is True
    only on a successful open; a live process resolves a real image path."""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k = ctypes.windll.kernel32
    try:
        k.OpenProcess.restype = wt.HANDLE
        k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not h:
            return False, ""
        try:
            buf = ctypes.create_unicode_buffer(32768); size = wt.DWORD(32768)
            k.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
            ok = k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
            return True, (buf.value if ok else "")
        finally:
            k.CloseHandle(h)
    except Exception:
        return False, ""


def _rcw_visible_pids():
    """Union of the standard enumeration APIs (Toolhelp32 + WMI + Get-Process) — the set
    a normal process appears in. A PID absent from ALL of these is 'not enumerated'."""
    th, names = _rcw_pids_toolhelp()
    vis = set(th) if th is not None else set()
    out = _ps(_PROC_PS)
    if out.strip():
        try:
            o = json.loads(out)
            for kk in ("wmi", "proc"):
                v = o.get(kk) or []
                vis |= set([v] if isinstance(v, int) else v)
        except ValueError:
            pass
    if th is None and not vis:
        return None, {}
    return vis, (names or {})


def _rcw_hidden_processes(agent_id, seen) -> list:
    """Confidence-scored hidden-process detection:
      1) EXISTENCE ANOMALY   — a PID the kernel confirms (OpenProcess) that NO enumeration
         API (Toolhelp/WMI/Get-Process) lists;
      2) VISIBILITY VALIDATION — re-confirm after a settle delay so transient start/exit
         races drop out (this is what killed the false positives);
      3) TRUST EVALUATION    — Authenticode (WinVerifyTrust), image path, and known
         system-process name + Windows-dir location;
      4) CONFIDENCE SCORE    — emit only >= SENTINEL_ROOTKIT_MIN_CONFIDENCE, severity scaled
         by confidence. System processes score low and are suppressed."""
    dets = []
    vis1, names = _rcw_visible_pids()
    if vis1 is None:
        return dets
    cap = int(os.environ.get("SENTINEL_ROOTKIT_PIDMAX_WIN", "262144"))
    kernel = _rcw_kernel_pids(cap)
    if kernel is None:
        return dets
    cand = kernel - vis1 - {0, 4}
    if not cand:
        return dets
    time.sleep(1.5)                                    # settle, then re-validate
    vis2, names2 = _rcw_visible_pids()
    vis2 = vis2 or set()
    for pid in sorted(cand):
        if pid in vis2:                                # now enumerated -> transient, not hidden
            continue
        exists, path = _rcw_proc_image(pid)
        if not exists or not path:                     # gone, or no resolvable image -> not a flaggable hidden process
            continue
        if ("rootkit", "hidproc", pid) in seen:
            continue
        name = os.path.basename(path).lower()
        if name in _PSEUDO_PROC:                        # protected minimal process
            continue
        # ---- trust evaluation + rootkit confidence ----
        # A VALIDATED-hidden process (kernel-confirmed, absent from every enumeration API,
        # persisted, with a real image) is inherently high-signal — nothing legitimate is
        # hidden from all three APIs. So the base is HIGH; trust only *subtracts* for the
        # specific benign quirk classes (a known system process / a signed binary under
        # C:\Windows). FP-avoidance is done by the validation stage above, not by
        # under-scoring — otherwise a real hidden threat gets missed.
        conf, reasons = 70, ["validated hidden: kernel-confirmed (OpenProcess) but absent from Toolhelp+WMI+Get-Process, persisted across re-sample"]
        low = path.lower()
        in_win = low.startswith("c:\\windows\\")
        known_sys = name in _WIN_SYSTEM_PROCS
        signed = is_signed_trusted(path)
        if _WIN_SUSP_PATH_RE.search(path):
            conf += 25; reasons.append("+25 image in a user-writable/temp path")
        if known_sys and not in_win:
            conf += 20; reasons.append("+20 system-process name outside C:\\Windows (masquerade)")
        if known_sys and in_win:
            conf -= 55; reasons.append("-55 known system process under C:\\Windows (benign enumeration quirk)")
        elif signed and in_win:
            conf -= 35; reasons.append("-35 Authenticode-signed binary under C:\\Windows")
        elif signed:
            conf -= 10; reasons.append("-10 Authenticode-signed image (still odd that it is hidden)")
        conf = max(5, min(100, conf))
        sev = "CRITICAL" if conf >= 85 else "HIGH" if conf >= 70 else "MEDIUM" if conf >= 55 else "LOW"
        if conf < _ROOTKIT_MIN_CONF:
            log(f"rootcheck: hidden-proc candidate pid {pid} ({name or '?'}) conf={conf} < {_ROOTKIT_MIN_CONF} — suppressed")
            continue
        seen.add(("rootkit", "hidproc", pid))
        dets.append(make_event(agent_id, "HIDDEN_PROCESS", str(pid), "behavior", sev, conf,
                               {"pid": pid, "name": name or "?", "path": path, "signed": signed,
                                "confidence": conf, "reasons": reasons,
                                "note": "kernel-confirmed process hidden from all enumeration APIs"},
                               ["T1014", "T1564"]))
        log(f"ROOTCHECK hidden process: pid {pid} ({name or '?'}) conf={conf} sev={sev} path={path or '?'}")
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
    bad_hashes = {str(h).lower() for h in (policy.get("bad_driver_hashes", []) if isinstance(policy, dict) else [])}
    for d in drivers:
        path = (d.get("Path") or "").strip()
        name = (os.path.basename(path) if path else (d.get("Name") or "")).lower()
        if name and not name.endswith(".sys"):
            name += ".sys"
        # Strongest signal: content hash vs the LOLDrivers BYOVD set (a renamed driver
        # still matches, unlike the name list below).
        if bad_hashes and path:
            try:
                h = _sha256(path).lower()
            except OSError:
                h = ""
            if h and h in bad_hashes and ("rootkit", "drvhash", h) not in seen:
                seen.add(("rootkit", "drvhash", h))
                dets.append(make_event(agent_id, "KNOWN_MALICIOUS_DRIVER", name or path, "behavior", "CRITICAL", 95,
                                       {"driver": name, "path": path, "sha256": h,
                                        "note": "loaded kernel driver hash matches the LOLDrivers known-vulnerable/malicious (BYOVD) set"},
                                       ["T1014", "T1068", "T1211"]))
                log(f"ROOTCHECK BYOVD driver (LOLDrivers hash match): {path}")
                continue
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


# Persistence / ASEP enumeration: highest-signal, lowest-FP autostart surfaces.
_PERSIST_PS = r'''$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{wmi=@();run=@()}
foreach($c in Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer){
  $cmd = if($c.CommandLineTemplate){$c.CommandLineTemplate}elseif($c.ScriptText){$c.ScriptText}else{''}
  $o.wmi += [pscustomobject]@{name=[string]$c.Name;class=[string]$c.CimClass.CimClassName;cmd=[string]$cmd}
}
$keys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
      'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
foreach($k in $keys){ $p=Get-ItemProperty -Path $k -ErrorAction SilentlyContinue; if($p){
  $p.PSObject.Properties|?{$_.Name -notlike 'PS*'}|%{ $o.run+=[pscustomobject]@{key=$k;name=$_.Name;val=[string]$_.Value} } } }
[pscustomobject]$o | ConvertTo-Json -Compress -Depth 4'''

_WIN_FILELESS_RE = re.compile(
    r'-enc\b|-encodedcommand|downloadstring|frombase64string|\biex\b|mshta\s+https?://|'
    r'regsvr32.*(/i:)?https?://|rundll32.*javascript|certutil.*-urlcache|bitsadmin\s+/transfer', re.I)
_WIN_SUSP_PATH_RE = re.compile(
    r'\\(temp|tmp)\\|\\appdata\\local\\temp\\|\\users\\public\\|\\programdata\\[^\\]*\.(exe|dll|ps1|vbs|bat|scr)|'
    r'\\downloads\\|\\windows\\temp\\', re.I)


def _rcw_persistence(agent_id, seen) -> list:
    """WMI permanent event-consumer persistence + fileless/obfuscated or user-writable
    autorun (Run/RunOnce) commands — classic fileless-implant persistence surfaces."""
    dets = []
    out = _ps(_PERSIST_PS, timeout=60)
    if not out.strip():
        return dets
    try:
        o = json.loads(out)
    except ValueError:
        return dets
    wmi = o.get("wmi") or []
    if isinstance(wmi, dict):
        wmi = [wmi]
    for c in wmi:
        cls = str(c.get("class") or "")
        if cls not in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
            continue                                   # LogFile/NTEventLog consumers are benign
        nm = str(c.get("name") or "")
        if ("rootkit", "wmiper", nm, cls) in seen:
            continue
        seen.add(("rootkit", "wmiper", nm, cls))
        dets.append(make_event(agent_id, "WMI_PERSISTENCE", nm or cls, "behavior", "HIGH", 82,
                               {"consumer": nm, "class": cls, "command": str(c.get("cmd") or "")[:400],
                                "note": "WMI permanent event-consumer persistence (fileless autostart)"},
                               ["T1546.003"]))
        log(f"ROOTCHECK WMI persistence: {nm} ({cls})")
    run = o.get("run") or []
    if isinstance(run, dict):
        run = [run]
    for r in run:
        val = str(r.get("val") or ""); nm = str(r.get("name") or "")
        if "padakhepsentinel" in val.lower():          # our own launcher, not malicious
            continue
        if not (_WIN_FILELESS_RE.search(val) or _WIN_SUSP_PATH_RE.search(val)):
            continue
        if ("rootkit", "autorun", r.get("key", ""), nm) in seen:
            continue
        seen.add(("rootkit", "autorun", r.get("key", ""), nm))
        dets.append(make_event(agent_id, "SUSPICIOUS_AUTORUN", nm or val[:60], "behavior", "HIGH", 80,
                               {"key": str(r.get("key")), "name": nm, "command": val[:400],
                                "note": "Run/RunOnce autorun with a fileless/obfuscated command or a payload in a user-writable/temp path"},
                               ["T1547.001", "T1059"]))
        log(f"ROOTCHECK suspicious autorun: {nm}")
    return dets


def rootcheck_scan(agent_id, policy, seen, state) -> list:
    """Run all Windows host-based rootkit / anomaly checks. Fully local — no
    threat feed. Each sub-check is isolated so one failure can't sink the rest."""
    if not ROOTCHECK:
        return []
    dets = []
    for chk in (lambda: _rcw_hidden_processes(agent_id, seen),
                lambda: _rcw_drivers(agent_id, policy, seen),
                lambda: _rcw_persistence(agent_id, seen),
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
# Event-log channels the agent reads. Security/System/Sysmon plus ETW-backed
# operational channels (label "etw"): PowerShell script-block, WMI-Activity, Defender.
# Absent/disabled channels simply return nothing (they cost nothing until provisioned).
_WIN_LOG_LABEL = {"Security": "winsec", "System": "winsys",
                  "Microsoft-Windows-Sysmon/Operational": "sysmon",
                  "Microsoft-Windows-PowerShell/Operational": "etw",
                  "Microsoft-Windows-WMI-Activity/Operational": "etw",
                  "Microsoft-Windows-Windows Defender/Operational": "etw"}
_WIN_LOGS = list(_WIN_LOG_LABEL.keys())

# (rendered label, EventData field) — Security + Sysmon + ETW superset. Only non-empty
# fields are rendered so rules can match `Field=value` tokens on one line.
_WIN_FIELDS = [
    ("Account", "acct"), ("Address", "addr"), ("Subject", "subj"), ("Service", "svc"),
    ("Process", "proc"), ("Cmd", "cmd"), ("LogonType", "ltype"), ("Group", "grp"),
    ("TktEnc", "tenc"), ("Image", "img"), ("Parent", "parent"), ("Target", "timg"),
    ("Source", "ssrc"), ("Dst", "dst"), ("DstPort", "dport"), ("File", "tfile"),
    ("Reg", "tobj"), ("Query", "query"), ("Access", "gacc"), ("User", "usr"),
    ("Pipe", "pipe"), ("Script", "sbt"),
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
    channels = ",".join("'%s'" % c for c in _WIN_LOGS)
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$s=(Get-Date).AddSeconds(-{max(window_sec, INTERVAL)});"
        f"$o=@();foreach($ln in {channels}){{"
        "$e=Get-WinEvent -FilterHashtable @{LogName=$ln;StartTime=$s} -MaxEvents 500;"
        "foreach($x in $e){$d=@{};try{$xml=[xml]$x.ToXml();"
        "foreach($n in $xml.Event.EventData.Data){if($n.Name){$d[$n.Name]=[string]$n.'#text'}}}catch{};"
        "$sbt=[string]$d['ScriptBlockText'];if($sbt.Length -gt 500){$sbt=$sbt.Substring(0,500)};"
        "$o+=[pscustomobject]@{log=$ln;id=[int]$x.Id;rid=[long]$x.RecordId;"
        "acct=[string]$d['TargetUserName'];addr=[string]$d['IpAddress'];"
        "subj=[string]$d['SubjectUserName'];svc=[string]$d['ServiceName'];"
        "proc=[string]$d['NewProcessName'];cmd=[string]$d['CommandLine'];"
        "ltype=[string]$d['LogonType'];grp=[string]$d['GroupName'];tenc=[string]$d['TicketEncryptionType'];"
        "img=[string]$d['Image'];parent=[string]$d['ParentImage'];timg=[string]$d['TargetImage'];"
        "ssrc=[string]$d['SourceImage'];"
        "dst=[string]$d['DestinationIp'];dport=[string]$d['DestinationPort'];tfile=[string]$d['TargetFilename'];"
        "tobj=[string]$d['TargetObject'];query=[string]$d['QueryName'];gacc=[string]$d['GrantedAccess'];"
        "usr=[string]$d['User'];pipe=[string]$d['PipeName'];sbt=$sbt}}}"
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
    rules = [r for r in policy.get("log_rules", [])
             if r.get("source") in ("winsec", "winsys", "sysmon", "etw", "any")]
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


# --------------------------------------------------------------------------- Windows telemetry & enforcement status
# What the admin sees per Windows device in the console: is Sysmon installed/running and
# flowing, which ETW-backed channels are enabled, and is the Windows Firewall on + is this
# host under Sentinel enforcement (isolation). Measured on a slow cadence (WIN_TELEMETRY_EVERY)
# and attached to the heartbeat — the same pattern as the Suricata nids_status snapshot.
_WIN_TELEMETRY: dict = {"collected": False}
_win_tele_last = 0.0

# Enhanced Sysmon config the installer applies. Superset of deploy/sysmon/padakhep-sysmon.xml
# (adds ProcessTampering=25 for hollowing). Kept compact + signal-focused, not a full baseline.
_SYSMON_CONFIG = r"""<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="proc" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\SearchIndexer.exe</Image>
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="net" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is">169.254.169.254</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
    <RuleGroup name="rt" groupRelation="or">
      <CreateRemoteThread onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="lsass" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    <RuleGroup name="file" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
      </FileCreate>
    </RuleGroup>
    <RuleGroup name="reg" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="pipe" groupRelation="or">
      <PipeEvent onmatch="include">
        <PipeName condition="begin with">\MSSE-</PipeName>
        <PipeName condition="begin with">\postex_</PipeName>
        <PipeName condition="begin with">\status_</PipeName>
        <PipeName condition="begin with">\msagent_</PipeName>
      </PipeEvent>
    </RuleGroup>
    <RuleGroup name="dns" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.microsoft.com</QueryName>
        <QueryName condition="end with">.windows.com</QueryName>
      </DnsQuery>
    </RuleGroup>
    <RuleGroup name="tamper" groupRelation="or">
      <ProcessTampering onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""


def _win_telemetry_collect(state: dict) -> dict:
    """Measure Sysmon / ETW-channel / firewall status via one PowerShell pass."""
    ps = r"""$ErrorActionPreference='SilentlyContinue'
$svc=Get-Service -Name Sysmon64,Sysmon | Select-Object -First 1
$drv=Get-Service -Name SysmonDrv
$run=($svc -and $svc.Status -eq 'Running')
$since=(Get-Date).AddHours(-1)
$sc=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';StartTime=$since} -MaxEvents 1).Count
function EN($n){ $l=Get-WinEvent -ListLog $n; if($l){[bool]$l.IsEnabled}else{$false} }
$sbl=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging').EnableScriptBlockLogging
$fm=@{}; foreach($p in (Get-NetFirewallProfile)){$fm[[string]$p.Name]=[bool]$p.Enabled}
[pscustomobject]@{
 sysmon=[pscustomobject]@{installed=[bool]$svc;running=[bool]$run;driver=[bool]$drv;events_1h=[int]$sc}
 etw=[pscustomobject]@{powershell=(EN 'Microsoft-Windows-PowerShell/Operational');wmi=(EN 'Microsoft-Windows-WMI-Activity/Operational');defender=(EN 'Microsoft-Windows-Windows Defender/Operational');script_block_logging=[bool]$sbl}
 firewall=[pscustomobject]@{domain=[bool]$fm['Domain'];private=[bool]$fm['Private'];public=[bool]$fm['Public']}
} | ConvertTo-Json -Compress -Depth 4"""
    data: dict = {}
    try:
        out = _ps(ps, timeout=60)
        if out.strip():
            data = json.loads(out)
    except (ValueError, OSError) as exc:
        log(f"win-telemetry: collect error ({exc!r})")
    if not isinstance(data, dict):
        data = {}
    data.setdefault("sysmon", {})
    data.setdefault("etw", {})
    fw = data.setdefault("firewall", {})
    fw["isolated"] = bool(state.get("isolated_applied"))
    fw["blocked_ips"] = len(state.get("blocklist_applied") or [])
    fw["closed_ports"] = len(state.get("ports_applied") or [])
    fw["enforcing"] = bool(fw["isolated"] or fw["blocked_ips"] or fw["closed_ports"])
    data["elevated"] = _is_elevated()
    data["collected"] = True
    return data


def win_telemetry_status(state: dict, force: bool = False) -> dict:
    """Return the cached Windows telemetry status, refreshing on WIN_TELEMETRY_EVERY."""
    global _WIN_TELEMETRY, _win_tele_last
    if force or not _WIN_TELEMETRY.get("collected") or (time.time() - _win_tele_last) >= WIN_TELEMETRY_EVERY:
        try:
            _WIN_TELEMETRY = _win_telemetry_collect(state)
        except Exception as exc:                     # never let status collection break the loop
            log(f"win-telemetry: unexpected error ({exc!r})")
        _win_tele_last = time.time()
    return _WIN_TELEMETRY


def _download(url: str, dst: str, timeout: int = 90) -> bool:
    req = urllib.request.Request(url, headers={"User-Agent": "PadakhepSentinel"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dst, "wb") as f:  # nosec - sysinternals over TLS
        shutil.copyfileobj(r, f)
    return os.path.isfile(dst) and os.path.getsize(dst) > 0


def _provision_sysmon() -> None:
    """Write our Sysmon config and install/update Sysmon if a binary is available.
    Best-effort: if no binary is present and it can't be fetched, leave a clear log so
    an operator can deploy Sysmon via GPO/SCCM — the status panel will show it missing."""
    cfg = os.path.join(INSTALL_DIR, "padakhep-sysmon.xml")
    os.makedirs(INSTALL_DIR, exist_ok=True)
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(_SYSMON_CONFIG)
    exe = None
    for cand in ("Sysmon64.exe", "Sysmon.exe"):
        p = shutil.which(cand) or os.path.join(INSTALL_DIR, cand)
        if os.path.isfile(p):
            exe = p
            break
    if exe is None:                                  # best-effort fetch from Sysinternals
        try:
            dst = os.path.join(INSTALL_DIR, "Sysmon64.exe")
            if _download("https://live.sysinternals.com/Sysmon64.exe", dst):
                exe = dst
        except Exception as exc:
            log(f"win-telemetry: Sysmon download unavailable ({exc!r})")
    if exe is None:
        log("win-telemetry: Sysmon binary not present — deploy Sysmon (GPO/SCCM) to enable EID 1/3/8/10/22/25 telemetry")
        return
    installed = (_run(["sc", "query", "Sysmon64"])[0] == 0) or (_run(["sc", "query", "Sysmon"])[0] == 0)
    if installed:
        _run([exe, "-c", cfg]); log("win-telemetry: Sysmon present — applied Padakhep config")
    else:
        _run([exe, "-accepteula", "-i", cfg]); log("win-telemetry: Sysmon installed with Padakhep config")


def provision_win_telemetry() -> None:
    """Installer step (elevated): make the Windows telemetry + enforcement layer ready in
    one shot — Windows Firewall on, ETW operational channels + PowerShell script-block
    logging enabled, Sysmon installed with our config. Idempotent; each step isolated."""
    if not PROVISION_TELEMETRY:
        return
    if not _is_elevated():
        log("win-telemetry: provisioning skipped (needs elevation / SYSTEM install)")
        return
    try:
        _run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
    except Exception as exc:
        log(f"win-telemetry: firewall enable failed ({exc!r})")
    try:
        for ch in ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-WMI-Activity/Operational"):
            _run(["wevtutil", "sl", ch, "/e:true"])
        _ps(r"$k='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';"
            r"New-Item -Path $k -Force | Out-Null;"
            r"Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1 -Type DWord", timeout=25)
    except Exception as exc:
        log(f"win-telemetry: ETW channel enable failed ({exc!r})")
    try:
        _provision_sysmon()
    except Exception as exc:
        log(f"win-telemetry: sysmon provisioning failed ({exc!r})")
    log("win-telemetry: provisioning complete (firewall on, ETW channels enabled, Sysmon best-effort)")


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
    if _WIN_TELEMETRY.get("collected"):          # Sysmon/ETW/Firewall status snapshot
        body["win_telemetry"] = _WIN_TELEMETRY
    if ports is not None:
        body["ports"] = ports
    try:
        return _req("POST", f"/api/agents/{agent_id}/heartbeat", body) or {}
    except Exception as exc:
        log(f"heartbeat failed: {exc!r}")
        return {}


UPDATE_TASK = os.environ.get("SENTINEL_TASK_NAME", "PadakhepSentinelAV")
WATCHDOG_TASK = UPDATE_TASK + "-Watchdog"


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
        # Step 1: lock the DIR to SYSTEM + Administrators with INHERITABLE ACEs.
        # NOTE: do NOT use /T here. `/inheritance:r /T` strips each child file's
        # inherited ACEs, and because the (OI)(CI) grant is invalid on a FILE the
        # grant is skipped there — leaving child files (the exe AND state.json) with
        # an EMPTY DACL that even SYSTEM cannot read/execute. That broke exe launch
        # (task 0x80070005) and, worse, made state.json unreadable so the agent
        # re-enrolled with a NEW id on every restart/update (duplicate-record churn).
        subprocess.run(["icacls", INSTALL_DIR, "/inheritance:r",
                        "/grant:r", "*S-1-5-18:(OI)(CI)F",      # NT AUTHORITY\SYSTEM
                        "/grant:r", "*S-1-5-32-544:(OI)(CI)F",  # BUILTIN\Administrators
                        "/C", "/Q"], capture_output=True, timeout=40)
        # Step 2: make ALL existing children RE-INHERIT from the now-hardened dir, so
        # the exe + state.json get a working (inherited) SYSTEM+Administrators DACL
        # instead of an empty one. New files created later inherit the same ACEs.
        subprocess.run(["icacls", os.path.join(INSTALL_DIR, "*"),
                        "/reset", "/T", "/C", "/Q"], capture_output=True, timeout=40)
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


def _ver_tuple(v) -> tuple:
    """Numeric version tuple for comparison; () if unparseable ('0.3.20-win'->(0,3,20))."""
    try:
        return tuple(int(x) for x in str(v).split("-")[0].split(".") if x != "")
    except (ValueError, AttributeError):
        return ()


def self_update(directive) -> None:
    """Apply an operator-pushed build. Frozen exe -> staged swap via a helper
    .cmd (a running exe can't overwrite itself); source mode -> in-place re-exec."""
    url = API + "/api/agent/download/windows"        # SEN-002: never trust a server-supplied URL
    want, ver = directive.get("sha256", ""), directive.get("version", "?")
    # Anti-rollback: refuse a build that is not strictly newer than the running one,
    # so a replayed old-but-validly-signed directive cannot downgrade the agent.
    tgt, cur = _ver_tuple(ver), _ver_tuple(VERSION)
    # Anti-rollback: reject an UNPARSEABLE target (a crafted/garbage version must not
    # skip the check) and any target older than the running build. (Full anti-downgrade
    # also needs the version bound INTO the signature — tracked in SECURITY.md; a
    # compromised control plane could still replay an old signed build with an inflated
    # version string until then.)
    if not tgt:
        log(f"update rejected: unparseable target version {ver!r} (anti-rollback)")
        return
    if cur and tgt < cur:
        log(f"update rejected: target v{ver} < current v{VERSION} (anti-rollback)")
        return
    # Rollout jitter: de-synchronise the fleet so a push to thousands of endpoints
    # doesn't stampede the download endpoint. Honour an optional signed rollout_delay.
    try:
        cap = int(directive.get("rollout_delay", os.environ.get("SENTINEL_UPDATE_JITTER", "20")))
    except (TypeError, ValueError):
        cap = 20
    # Hard-cap the jitter well under a heartbeat so a large (unauthenticated) rollout_delay
    # can't stall the single-threaded loop; enforcement already ran (see _apply_hb order).
    if cap > 0:
        time.sleep(random.uniform(0, min(cap, 60)))
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
        exedir = os.path.dirname(exe)
        # Clean stale artifacts from any prior interrupted update. A leftover
        # sentinel-update*.cmd held open by a hung updater used to lock the path and
        # abort every subsequent swap (leaving the host on the old build); removing
        # them first, plus a per-attempt unique .cmd name below, makes that impossible.
        for name in os.listdir(exedir):
            low = name.lower()
            if (low.startswith("sentinel-update") and low.endswith(".cmd")) or low.endswith(".exe.bak"):
                try:
                    os.remove(os.path.join(exedir, name))
                except OSError:
                    pass
        newexe = exe + ".new"
        try:
            with open(newexe, "wb") as f:
                f.write(data)
        except OSError as exc:
            log(f"update aborted: cannot stage new exe ({exc!r})"); return
        cmd_path = os.path.join(exedir, f"sentinel-update-{os.getpid()}.cmd")   # unique per attempt
        exename = os.path.basename(exe)
        # Self-healing swap: back up the old exe, swap in the new one (retrying while
        # the onefile bootstrap releases its file lock), start it, and verify it comes
        # up. If it doesn't (AV quarantine, lock, task issue), ROLL BACK to the old exe
        # and restart it — never leave the host unprotected.
        # Relaunch: SYSTEM installs use the scheduled task; per-user installs need a
        # hidden, detached start that works from a console-less batch — a bare `start`
        # does not, so fall back to PowerShell Start-Process (reliable in the user
        # session). This was the missing piece that left the host down after a swap.
        relaunch = (f'schtasks /run /tn "{UPDATE_TASK}" >nul 2>&1 || '
                    f'powershell -NoProfile -WindowStyle Hidden -Command '
                    f'"Start-Process -FilePath \'{exe}\' -ArgumentList \'--run\' -WindowStyle Hidden"')
        script = (
            "@echo off\r\n"
            "ping 127.0.0.1 -n 6 >nul\r\n"                     # ~5s: let this process release the exe lock
            f'copy /y "{exe}" "{exe}.bak" >nul 2>&1\r\n'       # rollback copy
            "set _n=0\r\n"
            ":swap\r\n"
            f'move /y "{newexe}" "{exe}" >nul 2>&1\r\n'
            f'if not exist "{newexe}" goto started\r\n'        # move succeeded (staged file gone)
            "set /a _n+=1\r\n"
            "if %_n% geq 12 goto rollback\r\n"                 # ~24s of retries, then give up -> rollback
            "ping 127.0.0.1 -n 3 >nul\r\n"
            "goto swap\r\n"
            ":started\r\n"
            f'{relaunch}\r\n'
            "ping 127.0.0.1 -n 21 >nul\r\n"                    # ~20s: did the new agent come up?
            f'tasklist /fi "imagename eq {exename}" 2>nul | find /i "{exename}" >nul\r\n'
            "if not errorlevel 1 goto done\r\n"
            f'{relaunch}\r\n'                                  # retry relaunch
            "ping 127.0.0.1 -n 16 >nul\r\n"                    # + ~15s more
            f'tasklist /fi "imagename eq {exename}" 2>nul | find /i "{exename}" >nul\r\n'
            "if not errorlevel 1 goto done\r\n"
            ":rollback\r\n"
            f'copy /y "{exe}.bak" "{exe}" >nul 2>&1\r\n'       # ROLLBACK to the known-good exe
            f'del "{newexe}" >nul 2>&1\r\n'
            f'{relaunch}\r\n'
            ":done\r\n"
            f'del "{exe}.bak" >nul 2>&1\r\n'
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
        # NOTE: `netsh advfirewall firewall add rule` has NO `group=` parameter — passing
        # one makes netsh reject the whole command (rc!=0), so rules were never created.
        # Use fixed rule NAMES (added/deleted by name) instead. Clear any stale copy first.
        for nm in ("PadakhepSentinel-IsoOut", "PadakhepSentinel-IsoIn"):
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nm}"])
        ro, _, eo = _run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PadakhepSentinel-IsoOut",
                          "dir=out", "action=allow", "enable=yes", f"remoteip={remoteip}"])
        ri, _, ei = _run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PadakhepSentinel-IsoIn",
                          "dir=in", "action=allow", "enable=yes", f"remoteip={remoteip}"])
        if ro != 0 or ri != 0:
            log(f"isolation: WARNING control-plane allow-rule add failed ({(eo or ei).strip()[:120]}); "
                "host is isolated but may be unmanageable — investigate")
    log(f"ENDPOINT ISOLATED: full firewall quarantine (LAN cut); reachable only from {allow}")
    return True


def remove_isolation() -> bool:
    # restore normal posture and drop our allow rules (by name — netsh has no group=)
    rc, _, err = _run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                       "blockinbound,allowoutbound"])
    if rc != 0:
        # Do NOT report un-isolated — the host is still quarantined; leave state so the
        # next sync retries (mirrors apply_isolation's rc gate).
        log(f"un-isolate firewallpolicy error: {err.strip()[:120]} — host stays isolated, will retry")
        return False
    for nm in ("PadakhepSentinel-IsoOut", "PadakhepSentinel-IsoIn"):
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nm}"])
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
    # Clear prior rules BY NAME (netsh add/delete have no `group=` parameter — using one
    # made netsh reject the command so blocks were never actually enforced).
    for nm in ("PadakhepSentinel-BlockOut", "PadakhepSentinel-BlockIn"):
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nm}"])
    ok = True
    if wanted:
        remoteip = ",".join(wanted)
        rc1, _, e1 = _run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PadakhepSentinel-BlockOut",
                           "dir=out", "action=block", "enable=yes", f"remoteip={remoteip}"])
        rc2, _, e2 = _run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PadakhepSentinel-BlockIn",
                           "dir=in", "action=block", "enable=yes", f"remoteip={remoteip}"])
        ok = (rc1 == 0 and rc2 == 0)
        if ok:
            log(f"blocklist: enforcing {len(wanted)} IP(s) via Windows Firewall")
        else:
            # Do NOT record as applied — the console must not show a block that isn't
            # really in force. netsh add is admin-only; a non-elevated agent lands here.
            log(f"blocklist: FAILED to enforce {len(wanted)} IP(s) — netsh denied "
                f"(agent not elevated? run as SYSTEM): {(e1 or e2).strip()[:120]}")
    else:
        log("blocklist: cleared (no blocked IPs)")
    if ok:
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
    # Clear prior rules BY NAME (netsh has no `group=` — that made the command fail).
    for proto in ("tcp", "udp"):
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=PadakhepSentinel-Port-{proto}"])
    ok = True
    if want:
        last_err = ""
        for proto in ("tcp", "udp"):
            ports = [str(p) for pr, p in want if pr == proto]
            if not ports:
                continue
            rc, _, err = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                               f"name=PadakhepSentinel-Port-{proto}", "dir=in", "action=block", "enable=yes",
                               f"protocol={proto.upper()}", "localport=" + ",".join(ports)])
            if rc != 0:
                ok = False; last_err = err or last_err
        if ok:
            log(f"ports: closing {len(want)} port(s) via Windows Firewall "
                f"({', '.join(f'{pr}/{p}' for pr, p in want)})")
        else:
            # Not really enforced (netsh admin-only) — don't record false success.
            log(f"ports: FAILED to close {len(want)} port(s) — netsh denied "
                f"(agent not elevated? run as SYSTEM): {last_err.strip()[:120]}")
    else:
        log("ports: no closed ports (all open)")
    if ok:
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
    # Apply incident-response FIRST — a queued self_update exits the process, so isolate/
    # blocklist/port-close must run before it or they'd be deferred a whole update cycle.
    enforce_isolation(hb.get("isolate"), state)
    if "blocked" in hb:                             # guarded: absent on a failed beat
        enforce_blocklist(hb["blocked"], state)
    if "closed_ports" in hb:
        enforce_ports(hb["closed_ports"], state)
    if hb.get("update"):
        self_update(hb["update"])                   # re-execs / exits on success


_MUTEX_LOCAL = "PadakhepSentinelAV_singleton"
_MUTEX_GLOBAL = "Global\\PadakhepSentinelAV_singleton"
_SYNCHRONIZE = 0x00100000
_ERROR_ALREADY_EXISTS = 183


def _mutex_kernel32():
    """kernel32 with the mutex APIs typed so the 64-bit HANDLE isn't truncated."""
    k = ctypes.windll.kernel32
    k.CreateMutexW.restype = wt.HANDLE
    k.CreateMutexW.argtypes = [wt.LPVOID, wt.BOOL, wt.LPCWSTR]
    k.OpenMutexW.restype = wt.HANDLE
    k.OpenMutexW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
    return k


def _global_mutex_sa():
    """SECURITY_ATTRIBUTES granting Everyone SYNCHRONIZE on the Global\\ mutex, so an
    unprivileged agent can *detect* a SYSTEM-created instance (via OpenMutexW) instead
    of being denied — required for the cross-session exclusion to actually hold."""
    try:
        conv = ctypes.windll.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
        conv.restype = wt.BOOL
        conv.argtypes = [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(ctypes.c_void_p), wt.LPVOID]
        psd = ctypes.c_void_p()
        if not conv("D:(A;;0x100001;;;WD)", 1, ctypes.byref(psd), None):   # WD=Everyone: SYNCHRONIZE|QUERY
            return None

        class _SA(ctypes.Structure):
            _fields_ = [("nLength", wt.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                        ("bInheritHandle", wt.BOOL)]
        sa = _SA(); sa.nLength = ctypes.sizeof(_SA); sa.lpSecurityDescriptor = psd; sa.bInheritHandle = False
        return sa
    except Exception:
        return None


def _single_instance() -> bool:
    """Prevent a second agent (SYSTEM service + a stray per-user agent) via a mutex.
    A SYSTEM agent creates the ``Global\\`` mutex with an Everyone-SYNCHRONIZE DACL. A
    non-elevated agent can't create in the Global namespace (no SeCreateGlobalPrivilege),
    so it *probes* the Global mutex with OpenMutexW — if a SYSTEM instance holds it, the
    per-user agent bails. Only if no Global instance exists does it fall back to a
    session-local mutex. (A onefile PyInstaller agent shows as parent+child = one instance.)"""
    k = _mutex_kernel32()
    sa = _global_mutex_sa()
    try:
        h = k.CreateMutexW(ctypes.byref(sa) if sa else None, False, _MUTEX_GLOBAL)
        err = k.GetLastError()
        if h:
            if err == _ERROR_ALREADY_EXISTS:
                return False                       # another (Global) instance holds it
            globals()["_MUTEX"] = h                # we own the Global singleton (SYSTEM path)
            return True
    except Exception:
        pass
    # Global create failed (unprivileged / denied): a SYSTEM instance may still hold it —
    # probe read-only; if it exists, do not start a duplicate.
    try:
        oh = k.OpenMutexW(_SYNCHRONIZE, False, _MUTEX_GLOBAL)
        if oh:
            k.CloseHandle(oh)
            return False
    except Exception:
        pass
    # No Global instance: fall back to a session-local singleton for this session.
    try:
        h = k.CreateMutexW(None, False, _MUTEX_LOCAL)
        if h and k.GetLastError() == _ERROR_ALREADY_EXISTS:
            return False
        globals()["_MUTEX"] = h
    except Exception:
        pass
    return True                                    # mutex unavailable -> don't block startup


def _agent_already_running() -> bool:
    """Non-destructively test whether a live agent holds the singleton mutex
    (used by --ensure so the watchdog never spawns a second instance)."""
    k = ctypes.windll.kernel32
    SYNCHRONIZE = 0x00100000
    for name in (_MUTEX_GLOBAL, _MUTEX_LOCAL):
        try:
            h = k.OpenMutexW(SYNCHRONIZE, False, name)
            if h:
                k.CloseHandle(h)
                return True
        except Exception:
            pass
    return False


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


_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Padakhep Sentinel AV/EDR agent</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{cmd}</Command><Arguments>--run</Arguments></Exec>
  </Actions>
</Task>
"""


def _register_system_task(exe: str) -> bool:
    """Register the agent as a boot-start SYSTEM scheduled task (service-equivalent,
    stdlib-only — no pywin32/SCM). Running as SYSTEM makes remote-update relaunch
    reliable (`schtasks /run /tn <task>`), gives full EDR privilege, and lets SEN-011
    dir hardening apply without locking the agent out. Prefer a hardened XML task
    (BootTrigger + RestartOnFailure + StartWhenAvailable + unbounded run time); fall
    back to the plain onstart form if XML registration fails. Needs admin."""
    try:
        xml = _TASK_XML.format(cmd=exe)
        # schtasks wants a UTF-16 XML file; write one and register it.
        fd, path = tempfile.mkstemp(suffix=".xml", prefix="sentinel-task-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(xml.encode("utf-16"))
            r = subprocess.run(["schtasks", "/create", "/tn", UPDATE_TASK, "/xml", path, "/f"],
                               capture_output=True, timeout=40, text=True)
            if r.returncode == 0:
                return True
            log(f"schtasks XML create failed ({(r.stderr or r.stdout or '').strip()[:120]}); "
                "falling back to plain onstart task")
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    except Exception as exc:
        log(f"schtasks XML create error ({exc!r}); trying plain onstart task")
    # Fallback: simple onstart SYSTEM task (no restart-on-failure).
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


def _register_watchdog_task(exe: str) -> None:
    """Companion watchdog: a SYSTEM task that runs `--ensure` every 10 min and
    restarts the agent if it is not running (covers a silently hung/AV-killed
    process that Task Scheduler's RestartOnFailure — which only fires on task-instance
    exit — cannot catch). --ensure is mutex-guarded so it never spawns a duplicate."""
    try:
        subprocess.run(["schtasks", "/create", "/tn", WATCHDOG_TASK,
                        "/tr", f'"{exe}" --ensure', "/sc", "minute", "/mo", "10",
                        "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"],
                       capture_output=True, timeout=30)
    except Exception as exc:
        log(f"watchdog task registration failed ({exc!r})")


def _relaunch_elevated_install() -> bool:
    """Re-run this exe elevated (UAC) to perform the SYSTEM install. >32 = launched."""
    try:
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "--install-system", None, 0)
        return int(r) > 32
    except Exception:
        return False


def _remove_user_autostart() -> None:
    """Delete the per-user logon launcher from EVERY user profile (not just the
    installing account), so a SYSTEM agent and a leftover per-user .vbs on another
    account cannot both run against the same state.json / firewall rule groups."""
    rel = r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\PadakhepSentinelAV.vbs"
    candidates = []
    ad = os.environ.get("APPDATA", "")
    if ad:
        candidates.append(os.path.join(ad, r"Microsoft\Windows\Start Menu\Programs\Startup",
                                       "PadakhepSentinelAV.vbs"))
    users = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
    try:
        for name in os.listdir(users):
            candidates.append(os.path.join(users, name, rel))
    except OSError:
        pass
    for vbs in candidates:
        try:
            if os.path.isfile(vbs):
                os.remove(vbs)
        except OSError:
            pass


def install_and_launch(system: bool = False, explicit_user: bool = False) -> None:
    """First-run setup: copy into ProgramData and register autostart.

    Mode selection (the fleet default is now SYSTEM):
      * ``--install-system`` (or ``SENTINEL_INSTALL_SYSTEM=1``) -> SYSTEM, self-elevating.
      * ``--install`` / ``--install-user`` -> EXPLICIT per-user (stays per-user even if
        the installer happens to be elevated) — the BYOD / unmanaged fallback.
      * a bare frozen first-run (double-click, or a management channel like
        Intune/SCCM/GPO/RMM that already runs the payload AS SYSTEM) ->
          - ELEVATED  -> SYSTEM scheduled task (boot start, full privilege, reliable
            remote update). No UAC is shown because it is already elevated.
          - NON-elevated -> safe per-user logon launcher, no surprise UAC prompt.

    Only a SYSTEM install yields an always-on, fully-privileged agent that can be
    remotely updated from the control plane with no further machine access; the
    per-user mode runs only while one user is interactively logged in and cannot do
    the privileged EDR response actions. Idempotent."""
    env_system = os.environ.get("SENTINEL_INSTALL_SYSTEM", "0") in ("1", "true", "yes")
    elevated = _is_elevated()
    want_system = system or env_system or (elevated and not explicit_user)
    if want_system and not elevated:
        # Only reached via an explicit SYSTEM request (a bare non-elevated first-run
        # resolves to per-user above), so self-elevating here never surprises a
        # double-click user.
        if _relaunch_elevated_install():
            log("install: relaunching elevated to register the SYSTEM service…")
            return                                        # the elevated instance finishes the install
        log("install: SYSTEM install requested but UAC unavailable/declined — using per-user autostart.")
        want_system = False
    exe = INSTALL_EXE
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        if os.path.abspath(sys.executable).lower() != os.path.abspath(exe).lower():
            shutil.copy2(sys.executable, exe)             # copy self into place
    except Exception as exc:
        log(f"install: copy failed ({exc!r}); running from current location")
        exe = sys.executable

    if want_system and elevated and _register_system_task(exe):
        _remove_user_autostart()                          # remove per-user launchers on ALL profiles
        _harden_install_dir()                             # SEN-011: safe now — agent runs as SYSTEM
        _register_watchdog_task(exe)                      # crash/AV-kill resilience
        try:                                              # exclude the installed exe before its first start
            _ps(f"Add-MpPreference -ExclusionPath '{exe}' -ErrorAction SilentlyContinue", timeout=20)
        except Exception:
            pass
        try:                                              # arm Windows telemetry + enforcement in one shot
            provision_win_telemetry()
        except Exception as exc:
            log(f"win-telemetry: provisioning error ({exc!r})")
        try:
            subprocess.run(["schtasks", "/run", "/tn", UPDATE_TASK], capture_output=True, timeout=30)
        except Exception:
            pass
        log(f"installed as SYSTEM scheduled task '{UPDATE_TASK}' (+ watchdog) -> {INSTALL_DIR}")
    else:
        # Per-user logon launcher (explicit --install/--install-user, non-elevated
        # first run, or SYSTEM-task failure). Agent runs as the user; SEN-011 hardening
        # self-skips so it can't lock itself out. DEGRADED: no isolation/blocklist/
        # port-close, no Security/Sysmon log visibility, alive only while logged in.
        if want_system and elevated:
            log("install: SYSTEM task registration failed — falling back to per-user autostart.")
        else:
            log("install: per-user autostart (degraded/unmanaged). For the always-on, fully-privileged "
                "SYSTEM service run elevated (Intune/SCCM/GPO/RMM) or: sentinel-av.exe --install-system.")
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


def uninstall() -> None:
    """Cleanly decommission the agent from this host: stop + delete both scheduled
    tasks, kill the INSTALLED agent process (by its exe path, never this uninstaller),
    remove per-user logon launchers on ALL profiles, drop the Defender exclusion, and
    delete the install directory. Best-effort and idempotent; the SYSTEM task + hardened
    dir require admin/SYSTEM to remove (run elevated). Run: sentinel-av.exe --uninstall"""
    for tn in (WATCHDOG_TASK, UPDATE_TASK):
        try:
            subprocess.run(["schtasks", "/end", "/tn", tn], capture_output=True, timeout=20)
            subprocess.run(["schtasks", "/delete", "/f", "/tn", tn], capture_output=True, timeout=20)
        except Exception:
            pass
    _remove_user_autostart()
    try:
        _ps(f"Remove-MpPreference -ExclusionPath '{INSTALL_EXE}' -ErrorAction SilentlyContinue", timeout=20)
    except Exception:
        pass
    # Kill the INSTALLED agent by exe path, EXCLUDING this uninstaller's own process tree
    # (when run as the installed exe, our own PID+parent share INSTALL_EXE — path equality
    # alone would kill us before the dir/state removal below).
    me, parent = os.getpid(), os.getppid()
    try:
        _ps("Get-CimInstance Win32_Process -Filter \"name='sentinel-av.exe'\" | "
            f"Where-Object {{ $_.ExecutablePath -eq '{INSTALL_EXE}' -and "
            f"$_.ProcessId -ne {me} -and $_.ProcessId -ne {parent} }} | "
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }", timeout=30)
    except Exception:
        pass
    time.sleep(2)
    # Unlock (undo SEN-011 hardening) then remove the install dir + state.
    try:
        if os.path.isdir(INSTALL_DIR):
            subprocess.run(["icacls", INSTALL_DIR, "/reset", "/T", "/C", "/Q"], capture_output=True, timeout=40)
            shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    except Exception as exc:
        log(f"uninstall: dir removal issue ({exc!r})")
    left = "still present" if os.path.isdir(INSTALL_DIR) else "removed"
    log(f"uninstalled: tasks + autostart cleared; install dir {left} ({INSTALL_DIR}). "
        "Delete the agent's record from the console to finish decommissioning.")


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-av-win")
    ap.add_argument("--once", action="store_true", help="run a single scan pass then exit")
    ap.add_argument("--run", action="store_true", help="run the agent loop (skip first-run install)")
    ap.add_argument("--install", action="store_true",
                    help="install: SYSTEM scheduled task if elevated (managed deploy), else per-user")
    ap.add_argument("--install-system", dest="install_system", action="store_true",
                    help="force a SYSTEM scheduled task install (self-elevates via UAC; boot start + SEN-011 hardening)")
    ap.add_argument("--install-user", dest="install_user", action="store_true",
                    help="force a per-user (unmanaged/BYOD) install even when elevated — degraded, no privileged response")
    ap.add_argument("--ensure", action="store_true",
                    help="watchdog: start the agent via its scheduled task if it is not already running, then exit")
    ap.add_argument("--uninstall", action="store_true",
                    help="cleanly decommission: stop/delete tasks, kill the agent, remove autostart + install dir")
    args = ap.parse_args()
    frozen = getattr(sys, "frozen", False)
    if args.uninstall:
        uninstall()
        return
    # Watchdog entry (SYSTEM task, every ~10 min): mutex-guarded so it never spawns a
    # duplicate; if the agent is down, re-trigger its main task (or launch directly).
    if args.ensure:
        if _agent_already_running():
            return
        try:
            r = subprocess.run(["schtasks", "/run", "/tn", UPDATE_TASK], capture_output=True, timeout=30)
            if r.returncode != 0 and os.path.isfile(INSTALL_EXE):
                subprocess.Popen([INSTALL_EXE, "--run"], close_fds=True,
                                 creationflags=_CREATE_NO_WINDOW | 0x00000008)
        except Exception as exc:
            log(f"watchdog --ensure error ({exc!r})")
        return
    # A packaged exe launched with no flags = first-run install. The autostart
    # launcher, scheduled task, and updater call it with --run.
    if args.install or args.install_system or args.install_user or (frozen and not args.run and not args.once):
        # `--install` and a bare frozen first-run follow the elevation default (SYSTEM when
        # elevated, else per-user). Only `--install-user` forces per-user; `--install-system`
        # forces SYSTEM. This keeps `--install` consistent with its --help for managed deploys.
        install_and_launch(system=args.install_system, explicit_user=args.install_user)
        return
    if not args.once and not _single_instance():
        log("another instance is already running; exiting")
        return
    _priv = "SYSTEM/elevated (full access)" if _is_elevated() else "user (DEGRADED: no isolation/blocklist/port-close, limited log+process visibility)"
    log(f"starting Windows AV agent v{VERSION} -> {API}; privilege={_priv}; "
        f"yara={'on' if _HAVE_YARA else 'lite'}; "
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
    # --run must NEVER give up permanently: after a control-plane outage or a mass
    # reboot storm across the fleet, a bounded retry that exits would silently drop
    # the host off the update channel. Retry indefinitely with capped backoff + jitter.
    # --once keeps the old bounded behaviour so a single pass can't hang forever.
    agent_id = None
    attempt = 0
    while True:
        try:
            agent_id = enroll(state)
            break
        except Exception as exc:
            attempt += 1
            log(f"enroll retry #{attempt} ({exc!r})")
            if args.once:
                if attempt >= 30:
                    return
            delay = min(300, 10 * (2 ** min(attempt - 1, 5)))     # 10s -> cap 300s
            time.sleep(delay + random.uniform(0, delay * 0.2))    # +0-20% jitter (fleet de-sync)
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
    win_telemetry_status(state, force=True)              # measure Sysmon/ETW/Firewall for the first heartbeat
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
                    win_telemetry_status(state)      # self-throttled: refreshes only every WIN_TELEMETRY_EVERY
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
