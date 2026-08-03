"""Minimal Linux AV agent — stdlib only.

Loop: enroll -> pull policy -> scan (file hash + signature + behavior) -> report.
Run once:  python3 -m av_agent.agent --once
Daemon:    python3 -m av_agent.agent
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import time
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("SENTINEL_API", "http://127.0.0.1:8080")
NAME = os.environ.get("AGENT_NAME", socket.gethostname())
SCAN_DIRS = [d for d in os.environ.get("SENTINEL_SCAN_DIRS", "/tmp:/var/tmp:/home:/opt/suspect").split(":") if d]
AUTH_LOG = os.environ.get("SENTINEL_AUTH_LOG", "/var/log/auth.log")
STATE = os.environ.get("SENTINEL_AV_STATE", "/var/lib/sentinel-av/state.json")
INTERVAL = int(os.environ.get("SENTINEL_AV_INTERVAL", "60"))
POLICY_EVERY = int(os.environ.get("SENTINEL_AV_POLICY_INTERVAL", "300"))
MAX_FILE = int(os.environ.get("SENTINEL_AV_MAXFILE", str(8 * 1024 * 1024)))
TOKEN = os.environ.get("SENTINEL_API_TOKEN", "")
VERSION = "0.1.0"

_SKIP_DIRS = {"proc", "sys", "snap", "dev", "run", ".git", "__pycache__"}


def log(m: str) -> None:
    print(f"[{datetime.now(timezone.utc).astimezone().isoformat()}] av: {m}", flush=True)


# --------------------------------------------------------------------------- HTTP
def _req(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode() or "{}")


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


def enroll(state: dict) -> str:
    body = {"name": NAME, "ip": primary_ip(), "os": platform.platform(),
            "kernel": platform.release(), "version": VERSION,
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
    sigs = []
    for s in p.get("signatures", []):
        content = s.get("content", "")
        m = re.search(r"strings:(.*?)condition:", content, re.S | re.I)
        seg = m.group(1) if m else content
        raw = re.findall(r'"((?:[^"\\]|\\.)+)"', seg)
        strings = []
        for tok in raw:
            try:
                tok = tok.encode().decode("unicode_escape")
            except Exception:
                pass
            if len(tok) >= 8:
                strings.append(tok)
        if strings:
            sigs.append({"name": s["name"], "severity": s.get("severity", "HIGH"),
                         "mitre": s.get("mitre", []), "strings": strings})
    behaviors = p.get("behaviors", [])
    log(f"policy v{p.get('policy_version')}: {len(hashes)} hash IOCs, {len(ips)} ip IOCs, "
        f"{len(sigs)} signatures, {len(behaviors)} behaviors")
    return {"hashes": hashes, "ips": ips, "sigs": sigs, "behaviors": behaviors}


# --------------------------------------------------------------------------- detection event
def make_event(agent_id, etype, ioc_value, ioc_type, severity, confidence, details, mitre):
    now = datetime.now(timezone.utc).astimezone().isoformat()
    mitre = mitre or []
    return {
        "schema_version": "3.0", "timestamp": now,
        "instance": {"device_name": NAME, "uuid": agent_id},
        "ioc": {"value": ioc_value, "type": ioc_type, "confidence": confidence},
        "event": {"type": etype, "action_taken": "DETECTED", "mode": "DETECT",
                  "severity": severity, "confidence": confidence, "details": details},
        "mitre_attack": {"technique_ids": mitre, "technique_id": (mitre[0] if mitre else None)},
        "policy": {"allowlisted": False, "matching_ioc_type": ioc_type.upper(),
                   "ioc_confidence": confidence, "mode": "DETECT"},
        "integrity": {"producer": "av-agent"},
    }


# --------------------------------------------------------------------------- scanners
def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(262144), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_files(agent_id, policy, seen) -> list:
    dets = []
    for base in SCAN_DIRS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not os.path.islink(os.path.join(root, d))]
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    if os.path.getsize(p) > MAX_FILE:
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


_FAILED = re.compile(r"(Failed password|authentication failure|Invalid user).*?(?:from\s+)?(\d{1,3}(?:\.\d{1,3}){3})")


def scan_auth_log(agent_id, policy, seen) -> list:
    beh = next((b for b in policy["behaviors"] if b.get("name") == "multiple_failed_logins"), None)
    threshold = int((beh or {}).get("rule", {}).get("count", 5))
    mitre = (beh or {}).get("mitre", ["T1110"])
    if not os.path.exists(AUTH_LOG):
        return []
    counts: dict[str, int] = {}
    try:
        with open(AUTH_LOG, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-5000:]
    except OSError:
        return []
    for ln in lines:
        m = _FAILED.search(ln)
        if m:
            counts[m.group(2)] = counts.get(m.group(2), 0) + 1
    dets = []
    for ip, n in counts.items():
        if n >= threshold and ("bf", ip) not in seen:
            seen.add(("bf", ip))
            dets.append(make_event(agent_id, "BRUTE_FORCE_SOURCE", ip, "ip", "HIGH", 80,
                                   {"source_ip": ip, "failed_attempts": n, "log": AUTH_LOG}, mitre))
            log(f"DETECT brute force: {ip} ({n} failed logins)")
    return dets


def scan_processes(agent_id, policy, seen) -> list:
    rules = [b for b in policy["behaviors"] if b.get("rule", {}).get("type") == "regex"
             and b.get("rule", {}).get("field") == "cmdline"]
    if not rules or not os.path.isdir("/proc"):
        return []
    compiled = [(b, re.compile(b["rule"]["pattern"], re.I)) for b in rules]
    dets = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
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


def report(agent_id, dets) -> None:
    if not dets:
        return
    r = _req("POST", "/api/detections", {"producer": "av-agent", "agent_id": agent_id, "events": dets})
    log(f"reported {r.get('ingested', 0)} detection(s)")


_prev_cpu = {"idle": 0, "total": 0}


def cpu_percent() -> int:
    """CPU busy %% since the previous call (from /proc/stat)."""
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            vals = [int(x) for x in f.readline().split()[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        di, dt = idle - _prev_cpu["idle"], total - _prev_cpu["total"]
        _prev_cpu["idle"], _prev_cpu["total"] = idle, total
        if dt <= 0:
            return 0
        return int(round(max(0.0, min(100.0, 100.0 * (1.0 - di / dt)))))
    except (OSError, ValueError, IndexError):
        return 0


def mem_percent() -> int:
    try:
        info = {}
        with open("/proc/meminfo", encoding="utf-8") as f:
            for ln in f:
                k, _, rest = ln.partition(":")
                info[k] = int(rest.strip().split()[0])
        total = info.get("MemTotal", 1) or 1
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        return int(round(max(0.0, min(100.0, 100.0 * (1.0 - avail / total)))))
    except (OSError, ValueError):
        return 0


def heartbeat(agent_id, policy_version=0) -> None:
    try:
        _req("POST", f"/api/agents/{agent_id}/heartbeat",
             {"status": "online", "policy_version": policy_version,
              "cpu": cpu_percent(), "mem": mem_percent()})
    except Exception as exc:
        log(f"heartbeat failed: {exc!r}")


# --------------------------------------------------------------------------- main
def cycle(agent_id, policy, seen) -> None:
    dets = []
    dets += scan_files(agent_id, policy, seen)
    dets += scan_auth_log(agent_id, policy, seen)
    dets += scan_processes(agent_id, policy, seen)
    report(agent_id, dets)
    heartbeat(agent_id)


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-av")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    log(f"starting AV agent v{VERSION} -> {API}; scan_dirs={SCAN_DIRS}")
    state = load_state()
    agent_id = state.get("agent_id")
    for _ in range(30):
        try:
            agent_id = enroll(state)
            break
        except Exception as exc:
            log(f"enroll retry ({exc!r})")
            if args.once:
                return
            time.sleep(10)
    seen: set = set()
    policy = {"hashes": set(), "ips": set(), "sigs": [], "behaviors": []}
    last_policy = 0.0
    cpu_percent()  # prime the CPU delta baseline
    while True:
        now = time.time()
        if now - last_policy >= POLICY_EVERY or not policy["behaviors"]:
            try:
                policy = pull_policy()
                last_policy = now
            except Exception as exc:
                log(f"policy pull failed: {exc!r}")
        try:
            cycle(agent_id, policy, seen)
        except Exception as exc:
            log(f"scan cycle error: {exc!r}")
        if args.once:
            break
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
