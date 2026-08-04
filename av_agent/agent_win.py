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
import re
import socket
import subprocess
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
MAX_FILE = int(os.environ.get("SENTINEL_AV_MAXFILE", str(16 * 1024 * 1024)))
TOKEN = os.environ.get("SENTINEL_API_TOKEN", "")
VERSION = "0.1.0-win"

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


def primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
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
def pull_policy() -> dict:
    p = _req("GET", "/api/sync/policy")
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
    log(f"policy v{p.get('policy_version')}: {len(hashes)} hash IOCs, {len(ips)} ip IOCs, "
        f"{len(raw_sigs)} signatures ({'real-yara' if compiled else 'lite'}), {len(behaviors)} behaviors")
    return {"hashes": hashes, "ips": ips, "sigs": sigs, "yara": compiled, "behaviors": behaviors}


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


def scan_files(agent_id, policy, seen) -> list:
    dets = []
    yc = policy.get("yara")
    for base in SCAN_DIRS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True):
            dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
            for fn in files:
                ext = os.path.splitext(fn)[1].lower()
                if ext and ext not in _SCAN_EXT:
                    continue
                p = os.path.join(root, fn)
                try:
                    if not os.path.isfile(p) or os.path.getsize(p) > MAX_FILE:
                        continue
                    digest = _sha256(p)
                except OSError:
                    continue
                if digest in policy["hashes"] and (p, "hash") not in seen:
                    seen.add((p, "hash"))
                    dets.append(make_event(agent_id, "MALICIOUS_FILE_HASH", digest, "hash",
                                           "CRITICAL", 95, {"file": p, "sha256": digest}, ["T1204"]))
                    log(f"DETECT malicious hash: {p}")
                    continue
                try:
                    with open(p, "rb") as f:
                        blob = f.read(MAX_FILE)
                except OSError:
                    continue
                if yc is not None:                       # real YARA
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
                else:                                    # lite AND-of-strings
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


def scan_processes(agent_id, policy, seen) -> list:
    rules = [b for b in policy["behaviors"] if b.get("rule", {}).get("type") == "regex"
             and b.get("rule", {}).get("field") == "cmdline"]
    if not rules:
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
    compiled = []
    for b in rules:
        try:
            compiled.append((b, re.compile(b["rule"]["pattern"], re.I)))
        except re.error:
            continue
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
    dets = []
    for ip, n in counts.items():
        if n >= threshold and ("bruteforce", ip) not in seen:
            seen.add(("bruteforce", ip))
            dets.append(make_event(agent_id, "BRUTE_FORCE_SOURCE", ip, "ip", "HIGH", 80,
                                   {"source_ip": ip, "failed_attempts": n, "log": "Security/4625"}, mitre))
            log(f"DETECT brute force: {ip} ({n} failed logons)")
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


def heartbeat(agent_id, policy_version=0) -> dict:
    try:
        return _req("POST", f"/api/agents/{agent_id}/heartbeat",
                    {"status": "online", "policy_version": policy_version,
                     "cpu": cpu_percent(), "mem": mem_percent()}) or {}
    except Exception as exc:
        log(f"heartbeat failed: {exc!r}")
        return {}


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
    ctrl = _ctrl_ip()
    # default-deny both directions
    rc, _, err = _run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                       "blockinbound,blockoutbound"])
    if rc != 0:
        log(f"isolation firewallpolicy error: {err.strip()}")
        return False
    # allow management + control plane so the box stays reachable / reversible
    rules = [
        ["name=PadakhepSentinel-CtrlOut", "dir=out", "action=allow", "enable=yes",
         f"group={_FW_GROUP}", f"remoteip={ctrl}"] if ctrl else None,
        ["name=PadakhepSentinel-CtrlIn", "dir=in", "action=allow", "enable=yes",
         f"group={_FW_GROUP}", f"remoteip={ctrl}"] if ctrl else None,
        ["name=PadakhepSentinel-MgmtIn", "dir=in", "action=allow", "enable=yes",
         f"group={_FW_GROUP}", "protocol=TCP", "localport=3389,5985,5986,22"],
    ]
    for r in rules:
        if r:
            _run(["netsh", "advfirewall", "firewall", "add", "rule"] + r)
    log(f"ENDPOINT ISOLATED: firewall quarantine applied (allow control-plane {ctrl}, RDP/WinRM/SSH)")
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


# --------------------------------------------------------------------------- main
def cycle(agent_id, policy, seen) -> dict:
    dets = []
    dets += scan_files(agent_id, policy, seen)
    dets += scan_processes(agent_id, policy, seen)
    dets += scan_security_log(agent_id, policy, seen)
    report(agent_id, dets)
    return heartbeat(agent_id)


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-av-win")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    log(f"starting Windows AV agent v{VERSION} -> {API}; yara={'on' if _HAVE_YARA else 'lite'}; "
        f"scan_dirs={SCAN_DIRS}")
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
    policy = {"hashes": set(), "ips": set(), "sigs": [], "yara": None, "behaviors": []}
    last_policy = 0.0
    cpu_percent()
    while True:
        now = time.time()
        if now - last_policy >= POLICY_EVERY or not policy["behaviors"]:
            try:
                policy = pull_policy()
                last_policy = now
            except Exception as exc:
                log(f"policy pull failed: {exc!r}")
        try:
            hb = cycle(agent_id, policy, seen)
            enforce_isolation(hb.get("isolate"), state)
        except Exception as exc:
            log(f"scan cycle error: {exc!r}")
        if args.once:
            break
        if len(seen) > 20000:      # keep the dedupe set bounded on long runs
            seen = set()
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
