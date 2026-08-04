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
import json
import os
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("SENTINEL_API", "http://127.0.0.1:8080")
NAME = os.environ.get("AGENT_NAME", socket.gethostname())
_DEF_DIRS = r"C:\Users;C:\Windows\Temp;C:\ProgramData;C:\Users\Public"
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
TOKEN = os.environ.get("SENTINEL_API_TOKEN", "")
VERSION = "0.3.3-win"
_SEEN_MAX = 20000
DISK_PATH = os.environ.get("SENTINEL_AV_DISK", os.environ.get("SystemDrive", "C:") + "\\")

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


# --------------------------------------------------------------------------- HTTP
def _req(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=25) as resp:
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
    import platform
    body = {"name": NAME, "ip": primary_ip(), "os": os_caption(),
            "kernel": platform.version(), "version": VERSION,
            "agent_id": state.get("agent_id")}
    r = _req("POST", "/api/enroll", body)
    state["agent_id"] = r["agent_id"]
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
    log(f"policy v{p.get('policy_version')}: {len(hashes)} hash IOCs, {len(ips)} ip IOCs, "
        f"{len(raw_sigs)} signatures ({'real-yara' if compiled else 'lite'}), {len(behaviors)} behaviors, "
        f"{len(blocked)} blocked IPs, {len(closed_ports)} closed ports")
    return {"hashes": hashes, "ips": ips, "sigs": sigs, "yara": compiled,
            "behaviors": behaviors, "blocked": blocked, "closed_ports": closed_ports,
            "proc_rules": proc_rules}


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


def disk_usage() -> tuple:
    """(% used, total GB) of the system drive."""
    try:
        u = shutil.disk_usage(DISK_PATH)
        pct = int(round(100.0 * (u.total - u.free) / u.total)) if u.total else 0
        return max(0, min(100, pct)), int(round(u.total / (1024 ** 3)))
    except OSError:
        return 0, 0


def heartbeat(agent_id, policy_version=0, ports=None) -> dict:
    disk_pct, disk_total = disk_usage()
    body = {"status": "online", "policy_version": policy_version, "version": VERSION,
            "cpu": cpu_percent(), "mem": mem_percent(), "disk": disk_pct, "disk_total": disk_total}
    if ports is not None:
        body["ports"] = ports
    try:
        return _req("POST", f"/api/agents/{agent_id}/heartbeat", body) or {}
    except Exception as exc:
        log(f"heartbeat failed: {exc!r}")
        return {}


UPDATE_TASK = os.environ.get("SENTINEL_TASK_NAME", "PadakhepSentinelAV")


def _defender_exclude_self() -> None:
    """Best-effort: exempt our install dir from Windows Defender so a freshly
    swapped (re-hashed) exe isn't heuristically quarantined during self-update.
    Works when the agent runs as SYSTEM/admin (the scheduled task does); it
    silently no-ops otherwise."""
    if not getattr(sys, "frozen", False):
        return
    try:
        d = os.path.dirname(os.path.abspath(sys.executable))
        _ps(f"Add-MpPreference -ExclusionPath '{d}' -ErrorAction SilentlyContinue", timeout=20)
    except Exception:
        pass


def self_update(directive) -> None:
    """Apply an operator-pushed build. Frozen exe -> staged swap via a helper
    .cmd (a running exe can't overwrite itself); source mode -> in-place re-exec."""
    url = API + directive.get("url", "")
    want, ver = directive.get("sha256", ""), directive.get("version", "?")
    log(f"update requested -> v{ver}; downloading {url}")
    try:
        with urllib.request.urlopen(url, timeout=120) as r:
            data = r.read()
    except Exception as exc:
        log(f"update download failed: {exc!r}"); return
    if want and hashlib.sha256(data).hexdigest() != want:
        log("update aborted: sha256 mismatch"); return

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
            f'schtasks /run /tn "{UPDATE_TASK}" >nul 2>&1 || start "" "{exe}"\r\n'
            "ping 127.0.0.1 -n 16 >nul\r\n"                    # retry + wait ~15s more
            f'tasklist /fi "imagename eq {exename}" 2>nul | find /i "{exename}" >nul\r\n'
            "if not errorlevel 1 goto done\r\n"
            f'copy /y "{exe}.bak" "{exe}" >nul 2>&1\r\n'       # ROLLBACK to the known-good exe
            f'schtasks /run /tn "{UPDATE_TASK}" >nul 2>&1 || start "" "{exe}"\r\n'
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


def report(agent_id, dets) -> None:
    if not dets:
        return
    try:
        r = _req("POST", "/api/detections", {"producer": "av-agent-win", "agent_id": agent_id, "events": dets})
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
    wanted = sorted({i.strip() for i in (ips or []) if i and ":" not in i and i.strip() != ctrl})
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


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-av-win")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    log(f"starting Windows AV agent v{VERSION} -> {API}; yara={'on' if _HAVE_YARA else 'lite'}; "
        f"realtime={'on' if REALTIME else 'off'}; trust_signed={'on' if TRUST_SIGNED else 'off'}; "
        f"scan_dirs={SCAN_DIRS}")
    _defender_exclude_self()      # keep future self-updates from being quarantined
    state = load_state()
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
    report(agent_id, scan_security_log(agent_id, policy, seen))
    _apply_hb(heartbeat(agent_id, ports=observe_ports()), state)

    if args.once:
        return

    watcher = make_watcher()
    last_policy = last_beat = last_full = last_aux = time.time()
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
                    report(agent_id, scan_security_log(agent_id, policy, seen))
                except Exception as exc:
                    log(f"aux scan error: {exc!r}")
                last_aux = now
            if now - last_full >= FULLSCAN_EVERY or not watcher.active:
                try:
                    report(agent_id, scan_files(agent_id, policy, seen, scan_cache))
                except Exception as exc:
                    log(f"full scan error: {exc!r}")
                last_full = now
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
