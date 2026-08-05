"""Minimal Linux AV agent — stdlib only.

Loop: enroll -> pull policy -> scan (file hash + signature + behavior) -> report.
Run once:  python3 -m av_agent.agent --once
Daemon:    python3 -m av_agent.agent
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import ipaddress
import json
import os
import platform
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("SENTINEL_API", "http://127.0.0.1:8080")
NAME = os.environ.get("AGENT_NAME", socket.gethostname())
SCAN_DIRS = [d for d in os.environ.get("SENTINEL_SCAN_DIRS", "/tmp:/var/tmp:/home:/opt/suspect").split(":") if d]
AUTH_LOG = os.environ.get("SENTINEL_AUTH_LOG", "/var/log/auth.log")
STATE = os.environ.get("SENTINEL_AV_STATE", "/var/lib/sentinel-av/state.json")
INTERVAL = int(os.environ.get("SENTINEL_AV_INTERVAL", "60"))
POLICY_EVERY = int(os.environ.get("SENTINEL_AV_POLICY_INTERVAL", "300"))
# Realtime: watch scan dirs with inotify and scan only files as they change,
# instead of re-walking + re-hashing everything each cycle (far less CPU/IO).
REALTIME = os.environ.get("SENTINEL_AV_REALTIME", "1") not in ("0", "false", "")
# Safety-net full (incremental) rescan cadence — catches anything inotify missed.
FULLSCAN_EVERY = int(os.environ.get("SENTINEL_AV_FULLSCAN", "900"))
MAX_FILE = int(os.environ.get("SENTINEL_AV_MAXFILE", str(8 * 1024 * 1024)))
# Rootkit / host-anomaly detection (rootcheck): local consistency checks, no feed.
ROOTCHECK = os.environ.get("SENTINEL_ROOTCHECK", "1") not in ("0", "false", "")
ROOTCHECK_EVERY = int(os.environ.get("SENTINEL_ROOTCHECK_INTERVAL", "600"))
TOKEN = os.environ.get("SENTINEL_API_TOKEN", "")
# SEN-006 TLS: when API is https, verify the server cert against the system CAs
# (or a pinned CA/cert via SENTINEL_CA_CERT). SENTINEL_TLS_INSECURE=1 disables
# verification (lab only). http endpoints ignore all of this.
CA_CERT = os.environ.get("SENTINEL_CA_CERT", "")
TLS_INSECURE = os.environ.get("SENTINEL_TLS_INSECURE", "0") not in ("0", "false", "")
# SEN-007: per-agent secret. Loaded from state at startup and refreshed at enroll;
# sent as X-Agent-Secret so a guessed agent_id can't drive this agent's identity.
AGENT_SECRET = ""
_SSL_CTX = None
# Filesystems to report. Empty (default) = auto-discover all real mounts;
# or set a ":"-separated list of mount points to report exactly those.
DISK_PATHS = [d for d in os.environ.get("SENTINEL_AV_DISK", "").split(":") if d]
VERSION = "0.3.15"

# --- IDS/IPS (Suricata) ---
NIDS_LOGDIR = os.environ.get("SENTINEL_NIDS_LOG", "/var/log/sentinel-suricata")
SURICATA_YAML = os.environ.get("SENTINEL_SURICATA_YAML", "/etc/suricata/suricata.yaml")
NIDS_QUEUE = int(os.environ.get("SENTINEL_NIDS_QUEUE", "0"))
NIDS_TABLE = "sentinel_nids"
NIDS_MAX_PER_CYCLE = int(os.environ.get("SENTINEL_NIDS_MAX", "100"))
_NIDS_RULES = ["/var/lib/suricata/rules/suricata.rules", "/etc/suricata/rules/suricata.rules"]
# central ruleset (community + operator custom) pushed from the control plane,
# loaded into Suricata in addition to its local ET Open rules.
NIDS_RULESFILE = os.path.join(os.path.dirname(STATE) or ".", "sentinel.rules")
NIDS_PIDFILE = os.path.join(NIDS_LOGDIR, "suricata.pid")

_SKIP_DIRS = {"proc", "sys", "snap", "dev", "run", ".git", "__pycache__"}
_SEEN_MAX = 20000               # keep the dedupe set bounded on long runs

# optional real YARA engine — used when python3-yara / yara-python is installed,
# otherwise we fall back to the lightweight AND-of-strings matcher below.
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
    print(f"[{datetime.now(timezone.utc).astimezone().isoformat()}] av: {m}", flush=True)


# --------------------------------------------------------------------------- update signature (Ed25519, SEN-002)
# Builds are signed OFFLINE (tools/sign_agent.py); this pinned public key verifies
# them. The agent refuses any self-update whose bytes lack a valid signature from
# this key — so a compromised or MITM'd control plane cannot push code to run as
# root. Pure stdlib (Python's fast built-in pow()); empty key = signing disabled.
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


def os_name() -> str:
    """Friendly OS label for the console. Prefer the distro's PRETTY_NAME from
    /etc/os-release (e.g. 'Ubuntu 24.04.1 LTS'); fall back to the raw platform
    string only if that is unavailable. The kernel is reported separately."""
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, encoding="utf-8") as f:
                for ln in f:
                    if ln.startswith("PRETTY_NAME="):
                        val = ln.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return val
        except OSError:
            continue
    return platform.platform()


def enroll(state: dict) -> str:
    global AGENT_SECRET
    body = {"name": NAME, "ip": primary_ip(), "os": os_name(),
            "kernel": platform.release(), "version": VERSION,
            "agent_id": state.get("agent_id"), "proto": 2}   # proto 2 = supports per-agent secret
    r = _req("POST", "/api/enroll", body)
    state["agent_id"] = r["agent_id"]
    if r.get("agent_secret"):                # issued on first enrollment / migration
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
    sigs = []
    for s in raw_sigs:
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
    compiled = _compile_yara(raw_sigs) if _HAVE_YARA else None
    behaviors = p.get("behaviors", [])
    blocked = [b for b in p.get("blocked_ips", []) if b]
    closed_ports = p.get("closed_ports", [])
    # compile the cmdline behavior regexes once here (not every scan cycle)
    proc_rules = []
    for b in behaviors:
        r = b.get("rule", {})
        if r.get("type") == "regex" and r.get("field") == "cmdline":
            try:
                proc_rules.append((b, re.compile(r["pattern"], re.I)))
            except re.error:
                continue
    # Log-based IDS ruleset: compile each rule's regex once (log-ids).
    log_rules = []
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
            # optional operator-supplied extra rootkit artifact paths (rootcheck)
            "rootkit_artifacts": p.get("rootkit_artifacts", [])}


def _compile_yara(raw_sigs: list):
    """Compile all valid YARA signatures into one ruleset; skip broken ones."""
    if not _HAVE_YARA:
        return None
    sources, meta = {}, {}
    for s in raw_sigs:
        name, content = s.get("name", ""), s.get("content", "")
        if not name or "rule" not in content:
            continue
        try:
            yara.compile(source=content, externals=_YARA_EXTERNALS)
            sources[name] = content
            meta[name] = {"severity": s.get("severity", "HIGH"), "mitre": s.get("mitre", [])}
        except Exception:
            continue
    if not sources:
        return None
    try:
        return {"rules": yara.compile(sources=sources, externals=_YARA_EXTERNALS), "meta": meta}
    except Exception as exc:
        log(f"yara bulk-compile failed ({exc!r}); using lite matcher")
        return None


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


def _scan_file(agent_id, policy, seen, p, fn=None) -> list:
    """Scan a single file: SHA-256 IOC match, then YARA / lite-string signatures."""
    fn = fn or os.path.basename(p)
    dets = []
    try:
        if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p) > MAX_FILE:
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
    try:
        with open(p, "rb") as f:
            blob = f.read(MAX_FILE)
    except OSError:
        return dets
    yc = policy.get("yara")
    if yc is not None:                           # real YARA engine
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
    else:                                        # lightweight AND-of-strings fallback
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


def scan_paths(agent_id, policy, seen, paths, cache) -> list:
    """Realtime path handler: scan just the files that changed."""
    dets = []
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            cache.pop(p, None)
            continue
        sig = (st.st_size, int(st.st_mtime))
        cache[p] = sig                           # a change event: always (re)scan
        dets += _scan_file(agent_id, policy, seen, p)
    return dets


def scan_files(agent_id, policy, seen, cache) -> list:
    """Incremental full walk: only (re)hash files whose size/mtime changed since
    we last saw them — a safety net for anything the realtime watcher missed."""
    dets = []
    for base in SCAN_DIRS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not os.path.islink(os.path.join(root, d))]
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                sig = (st.st_size, int(st.st_mtime))
                if cache.get(p) == sig:          # unchanged since last scan -> skip the hash
                    continue
                cache[p] = sig
                dets += _scan_file(agent_id, policy, seen, p, fn)
    return dets


_FAILED = re.compile(r"(Failed password|authentication failure|Invalid user).*?(?:from\s+)?(\d{1,3}(?:\.\d{1,3}){3})")


def scan_auth_log(agent_id, policy, seen, state) -> list:
    """Detect SSH brute force from NEW failed logins only.

    We track the auth.log read offset (+ inode, to survive rotation) in the agent
    state, so historical entries are never re-alerted — including across restarts.
    Failed-login counts per source IP accumulate across scans and reset once an
    alert fires (so a later burst re-alerts). The alert's timestamp therefore
    reflects when the attack actually happened, not when the agent started.
    """
    beh = next((b for b in policy["behaviors"] if b.get("name") == "multiple_failed_logins"), None)
    threshold = int((beh or {}).get("rule", {}).get("count", 5))
    mitre = (beh or {}).get("mitre", ["T1110"])
    if not os.path.exists(AUTH_LOG):
        return []
    try:
        st = os.stat(AUTH_LOG)
    except OSError:
        return []
    inode, size = st.st_ino, st.st_size
    # first observation of this host: start at end-of-file. An EDR alerts on NEW
    # activity, not on log history that predates it.
    if "authlog_inode" not in state:
        state["authlog_inode"], state["authlog_offset"] = inode, size
        save_state(state)
        return []
    off = int(state.get("authlog_offset", 0))
    if state.get("authlog_inode") != inode or off > size:      # rotated or truncated
        off = 0
    try:
        with open(AUTH_LOG, "r", encoding="utf-8", errors="replace") as f:
            f.seek(off)
            new_lines = f.readlines()
            state["authlog_offset"] = f.tell()
    except OSError:
        return []
    state["authlog_inode"] = inode
    bf = state.get("bf_counts", {})
    for ln in new_lines:                                       # count NEW failures only
        m = _FAILED.search(ln)
        if m:
            bf[m.group(2)] = bf.get(m.group(2), 0) + 1
    dets, host_ip = [], primary_ip()
    for ip, n in list(bf.items()):
        if n >= threshold:
            dets.append(make_event(agent_id, "BRUTE_FORCE_SOURCE", ip, "ip", "HIGH", 80,
                                   {"source_ip": ip, "dest_ip": host_ip, "failed_attempts": n,
                                    "log": AUTH_LOG}, mitre))
            log(f"DETECT brute force: {ip} -> {host_ip} ({n} failed logins)")
            bf[ip] = 0                                         # reset window after alerting
    state["bf_counts"] = bf
    save_state(state)
    return dets


# --------------------------------------------------------------------------- log-based IDS (general)
# Logical log sources -> the files that back them on this host. "web" is
# overridable via SENTINEL_WEB_LOGS (":"-separated).
LOG_SOURCE_FILES = {
    "auth": [AUTH_LOG, "/var/log/secure"],
    "syslog": ["/var/log/syslog", "/var/log/messages"],
    "auditd": [os.environ.get("SENTINEL_AUDITD_LOG", "/var/log/audit/audit.log")],
    "web": [w for w in os.environ.get(
        "SENTINEL_WEB_LOGS", "/var/log/nginx/access.log:/var/log/apache2/access.log").split(":") if w],
}


def _tail_new_lines(path: str, state: dict) -> list:
    """NEW lines appended to `path` since the last scan, tracking (inode, offset)
    in state so history is never re-alerted and rotation/truncation is handled.
    First sighting of a file starts at end-of-file (an EDR alerts on new activity)."""
    off_map = state.setdefault("logids_off", {})
    try:
        st = os.stat(path)
    except OSError:
        return []
    inode, size = st.st_ino, st.st_size
    rec = off_map.get(path)
    if rec is None:
        off_map[path] = {"inode": inode, "offset": size}
        return []
    off = int(rec.get("offset", 0))
    if rec.get("inode") != inode or off > size:            # rotated / truncated
        off = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(off)
            lines = f.readlines()
            off_map[path] = {"inode": inode, "offset": f.tell()}
    except OSError:
        return []
    return lines


def _logids_event(agent_id, rule, entity, path, line, host_ip, count):
    entity = entity or ""
    ioc_type = "ip" if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", entity) else "log"
    sev = rule.get("severity", "MEDIUM")
    conf = {"CRITICAL": 90, "HIGH": 80, "MEDIUM": 65, "LOW": 40}.get(str(sev).upper(), 60)
    details = {"rule": rule.get("name"), "source": path, "match": line.strip()[:400],
               "entity": entity, "count": count, "dest_ip": host_ip}
    ev = make_event(agent_id, rule.get("event_type", "LOG_MATCH"), entity or rule.get("name"),
                    ioc_type, sev, conf, details, rule.get("mitre", []))
    ev["integrity"]["producer"] = "log-ids"       # so SRS Logs show/filter "log-ids"
    return ev


def log_ids_scan(agent_id, policy, state) -> list:
    """General log decoder + ruleset engine (producer=log-ids): tail each relevant
    log source and match decoded lines against the distributed log-IDS ruleset.
    Single-shot rules alert per match; threshold rules correlate N matches per
    entity within a window. Supersedes the old single hard-coded SSH scan."""
    rules = policy.get("log_rules", [])
    if not rules:
        return []
    labels = {r.get("source", "any") for r in rules}
    need_any = "any" in labels
    files = {}                                             # path -> logical source label
    for label, paths in LOG_SOURCE_FILES.items():
        if need_any or label in labels:
            for pth in paths:
                files[pth] = label
    now = time.time()
    win = state.setdefault("logids_win", {})
    dets, host_ip = [], primary_ip()
    for path, label in files.items():
        lines = _tail_new_lines(path, state)
        if not lines:
            continue
        applicable = [r for r in rules if r.get("source") in ("any", label)]
        for ln in lines:
            for r in applicable:
                m = r["rx"].search(ln)
                if not m:
                    continue
                grp, entity = int(r.get("entity_group", 0) or 0), ""
                if grp:
                    try:
                        entity = m.group(grp) or ""
                    except IndexError:
                        entity = ""
                threshold = int(r.get("threshold", 1) or 1)
                if threshold <= 1:
                    dets.append(_logids_event(agent_id, r, entity, path, ln, host_ip, 1))
                    continue
                key = r["name"] + "\x00" + entity
                window = int(r.get("window_sec", 300) or 300)
                stamps = [t for t in win.get(key, []) if now - t <= window]
                stamps.append(now)
                if len(stamps) >= threshold:
                    dets.append(_logids_event(agent_id, r, entity, path, ln, host_ip, len(stamps)))
                    win[key] = []                          # reset window after alerting
                else:
                    win[key] = stamps
    if len(win) > 5000:                                    # bound correlation state
        state["logids_win"] = {}
    save_state(state)
    if dets:
        log(f"log-ids: {len(dets)} detection(s) across {len(files)} source(s)")
    return dets


def scan_processes(agent_id, policy, seen) -> list:
    compiled = policy.get("proc_rules", [])       # precompiled at policy pull
    if not compiled or not os.path.isdir("/proc"):
        return []
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


# --------------------------------------------------------------------------- rootkit / anomaly detection (rootcheck)
# Rootkit detection is CONSISTENCY-based, not IOC-feed based: a rootkit betrays
# itself through the discrepancies it creates while hiding — a PID reachable by
# direct /proc access but missing from readdir; a listening port the kernel (ss)
# reports but /proc/net hides; a loaded module invisible to lsmod; a NIC in
# promiscuous mode; a process running from a deleted binary in a world-writable
# dir. These checks run ENTIRELY LOCALLY — no threat feed, no internet. A small
# curated known-artifacts list (paths/module names dropped by known Linux
# rootkits) supplements them and is extendable from the control plane via policy.
_ROOTKIT_ARTIFACTS = [
    "/dev/.hidden", "/dev/.lib", "/dev/.udev.tmp", "/dev/ttyop", "/dev/ttyoa",
    "/dev/ttyof", "/dev/hdx1", "/dev/hdx2", "/dev/xdf1", "/dev/xdf2", "/dev/saux",
    "/usr/share/.aPa", "/etc/rc.d/init.d/rc.modules", "/usr/lib/.fx",
    "/usr/bin/.etc", "/etc/.pwd.lock2", "/reptile", "/etc/reptile",
    "/lib/udev/reptile", "/usr/bin/reptile", "/dev/shm/.x",
    "/usr/include/.wormie", "/lib/libworm.so", "/usr/include/.gasf",
]
# LKM / userland-implant names seen in the wild; a loaded module or ld.so.preload
# entry matching these is a strong signal on its own.
_ROOTKIT_MODULES = {
    "diamorphine", "reptile", "reptile_module", "suterusu", "khook", "modhide",
    "azazel", "beurk", "jynx", "jynx2", "vlany", "bdvl", "bedevil", "knark",
    "adore", "adore_ng", "enyelkm", "sutek", "rkduck", "nuk3gh0st", "brootkit",
    "wukong", "rootedbox",
}
_WORLD_WRITABLE = ("/tmp", "/var/tmp", "/dev/shm", "/run/shm")
_IFF_PROMISC = 0x100


def _rc_run(cmd, timeout=8) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else ""
    except Exception:
        return ""


def _rc_pidmax() -> int:
    try:
        with open("/proc/sys/kernel/pid_max", encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 32768


def _rc_hidden_processes(agent_id, seen) -> list:
    """Cross-view PID reconciliation. A PID directly accessible under /proc but
    absent from the /proc directory listing (or from `ps`) is the classic
    process-hiding rootkit tell (e.g. Diamorphine's getdents hook)."""
    dets = []
    try:
        listed = {int(p) for p in os.listdir("/proc") if p.isdigit()}
    except OSError:
        return dets
    cap = min(_rc_pidmax(), int(os.environ.get("SENTINEL_ROOTCHECK_PIDMAX", "131072")))
    suspects = set()
    for pid in range(1, cap + 1):                     # brute-force direct /proc access
        if pid not in listed and os.path.exists(f"/proc/{pid}/stat"):
            suspects.add(pid)
    for ln in _rc_run(["ps", "-eo", "pid="]).splitlines():   # PIDs ps sees but readdir doesn't
        ln = ln.strip()
        if ln.isdigit() and int(ln) not in listed:
            suspects.add(int(ln))
    for pid in sorted(suspects):
        try:                                          # re-verify: shed procs that raced start/exit
            if str(pid) in os.listdir("/proc") or not os.path.exists(f"/proc/{pid}/stat"):
                continue
        except OSError:
            continue
        if ("rootkit", "hidproc", pid) in seen:
            continue
        seen.add(("rootkit", "hidproc", pid))
        cmd, exe = "", ""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            pass
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass
        dets.append(make_event(agent_id, "HIDDEN_PROCESS", str(pid), "behavior", "CRITICAL", 90,
                               {"pid": pid, "cmdline": cmd[:400], "exe": exe,
                                "note": "PID reachable directly but hidden from /proc listing / ps"},
                               ["T1014", "T1564"]))
        log(f"ROOTCHECK hidden process: pid {pid} exe={exe or '?'}")
    return dets


def _rc_hidden_ports(agent_id, seen) -> list:
    """Ports the kernel reports as LISTEN via `ss` (netlink) but which are absent
    from /proc/net/tcp indicate a port-hiding rootkit hooking /proc."""
    dets = []
    proc_ports = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for port, _laddr in _proc_net(path, {_TCP_LISTEN}):
            proc_ports.add(port)
    out = _rc_run(["ss", "-H", "-tln"])
    if not out:
        return dets                                   # no ss → can't cross-check safely
    ss_ports = set()
    for ln in out.splitlines():
        cols = ln.split()
        if len(cols) >= 4:
            p = cols[3].rsplit(":", 1)[-1]
            if p.isdigit():
                ss_ports.add(int(p))
    for port in sorted(ss_ports - proc_ports):        # kernel: listening; /proc: hidden
        if ("rootkit", "hidport", port) in seen:
            continue
        seen.add(("rootkit", "hidport", port))
        dets.append(make_event(agent_id, "HIDDEN_PORT", str(port), "behavior", "HIGH", 80,
                               {"port": port, "note": "listening per ss but absent from /proc/net/tcp"},
                               ["T1014"]))
        log(f"ROOTCHECK hidden port: {port}")
    return dets


def _rc_preload(agent_id, seen) -> list:
    """/etc/ld.so.preload is the canonical userland-rootkit hook. Flag any entry
    (strongly if it lives in a world-writable/hidden path, is missing, or matches
    a known implant)."""
    dets = []
    try:
        with open("/etc/ld.so.preload", encoding="utf-8", errors="replace") as f:
            entries = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return dets
    for lib in entries:
        low = lib.lower()
        suspicious = (lib.startswith(_WORLD_WRITABLE) or "/." in lib
                      or os.path.basename(lib).startswith(".")
                      or not os.path.exists(lib)
                      or any(m in low for m in _ROOTKIT_MODULES))
        if ("rootkit", "preload", lib) in seen:
            continue
        seen.add(("rootkit", "preload", lib))
        sev, conf = ("CRITICAL", 92) if suspicious else ("MEDIUM", 60)
        dets.append(make_event(agent_id, "PRELOAD_HIJACK", lib, "behavior", sev, conf,
                               {"file": "/etc/ld.so.preload", "entry": lib, "suspicious": suspicious,
                                "note": "shared-library preload hook (LD preload rootkit vector)"},
                               ["T1574.006"]))
        log(f"ROOTCHECK ld.so.preload entry: {lib} (suspicious={suspicious})")
    return dets


def _rc_hidden_modules(agent_id, seen) -> list:
    """A loadable kernel module present in /sys/module (initstate=live) but hidden
    from /proc/modules (lsmod) is a hidden LKM. Also flag any known implant name."""
    dets = []
    proc_mods = set()
    try:
        with open("/proc/modules", encoding="utf-8") as f:
            for ln in f:
                parts = ln.split()
                if parts:
                    proc_mods.add(parts[0])
    except OSError:
        pass
    try:
        sys_mods = set(os.listdir("/sys/module"))
    except OSError:
        sys_mods = set()
    for name in sorted(sys_mods - proc_mods):
        base = f"/sys/module/{name}"
        istate = os.path.join(base, "initstate")
        if not os.path.exists(istate):               # built-ins have no initstate → skip (not loadable)
            continue
        try:
            with open(istate, encoding="utf-8") as f:
                if f.read().strip() != "live":
                    continue
        except OSError:
            continue
        if ("rootkit", "hidmod", name) in seen:
            continue
        seen.add(("rootkit", "hidmod", name))
        dets.append(make_event(agent_id, "HIDDEN_MODULE", name, "behavior", "HIGH", 82,
                               {"module": name, "note": "live in /sys/module but hidden from /proc/modules (lsmod)"},
                               ["T1547.006", "T1014"]))
        log(f"ROOTCHECK hidden kernel module: {name}")
    for name in sorted(proc_mods | sys_mods):
        if name.lower().replace("-", "_") in _ROOTKIT_MODULES and ("rootkit", "badmod", name) not in seen:
            seen.add(("rootkit", "badmod", name))
            dets.append(make_event(agent_id, "KNOWN_ROOTKIT_MODULE", name, "behavior", "CRITICAL", 95,
                                   {"module": name, "note": "module name matches a known rootkit LKM"},
                                   ["T1014", "T1547.006"]))
            log(f"ROOTCHECK known rootkit module: {name}")
    return dets


def _rc_promisc(agent_id, seen) -> list:
    """A NIC in promiscuous mode (outside a bridge/bond master) suggests a packet
    sniffer. Suppressed by the caller while Suricata IDS/IPS is running."""
    dets = []
    base = "/sys/class/net"
    try:
        ifaces = os.listdir(base)
    except OSError:
        return dets
    for ifc in ifaces:
        if ifc == "lo" or os.path.exists(os.path.join(base, ifc, "bridge")):
            continue
        try:
            with open(os.path.join(base, ifc, "flags"), encoding="utf-8") as f:
                flags = int(f.read().strip(), 16)
        except (OSError, ValueError):
            continue
        if flags & _IFF_PROMISC and ("rootkit", "promisc", ifc) not in seen:
            seen.add(("rootkit", "promisc", ifc))
            dets.append(make_event(agent_id, "PROMISC_IFACE", ifc, "behavior", "MEDIUM", 65,
                                   {"iface": ifc, "note": "interface in promiscuous mode (possible sniffer)"},
                                   ["T1040"]))
            log(f"ROOTCHECK promiscuous interface: {ifc}")
    return dets


def _rc_deleted_running(agent_id, seen) -> list:
    """Processes executing from a deleted binary that originally lived in a
    world-writable dir — a strong fileless / anti-forensics signal. (Package
    upgrades also leave deleted exes, so we scope to risky paths to cut noise.)"""
    dets = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return dets
    for pid in pids:
        try:
            target = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        if not target.endswith(" (deleted)"):
            continue
        orig = target[:-len(" (deleted)")]
        if not orig.startswith(_WORLD_WRITABLE):
            continue
        if ("rootkit", "deleted", pid, orig) in seen:
            continue
        seen.add(("rootkit", "deleted", pid, orig))
        cmd = ""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            pass
        dets.append(make_event(agent_id, "DELETED_BINARY_RUNNING", orig, "behavior", "HIGH", 80,
                               {"pid": int(pid), "deleted_exe": orig, "cmdline": cmd[:400],
                                "note": "process running from a deleted binary in a world-writable path"},
                               ["T1620", "T1070.004"]))
        log(f"ROOTCHECK deleted-binary process: pid {pid} {orig}")
    return dets


def _rc_suid(agent_id, seen) -> list:
    """SUID-root executables staged in world-writable dirs — a common privesc
    drop / backdoor. Cheap, high-signal."""
    dets = []
    for base in _WORLD_WRITABLE:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                if (st.st_mode & 0o4000) and st.st_uid == 0 and ("rootkit", "suid", p) not in seen:
                    seen.add(("rootkit", "suid", p))
                    dets.append(make_event(agent_id, "SUSPICIOUS_SUID", p, "behavior", "HIGH", 80,
                                           {"file": p, "note": "SUID-root binary in a world-writable directory"},
                                           ["T1548.001"]))
                    log(f"ROOTCHECK suid-root in world-writable dir: {p}")
    return dets


def _rc_artifacts(agent_id, policy, seen) -> list:
    """Presence of a path known to be dropped by a specific rootkit (curated list
    plus any operator-supplied paths distributed via policy)."""
    dets = []
    extra = policy.get("rootkit_artifacts", []) if isinstance(policy, dict) else []
    for path in list(_ROOTKIT_ARTIFACTS) + [a for a in (extra or []) if a]:
        try:
            if not os.path.lexists(path):
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
    """Run all host-based rootkit / anomaly consistency checks. Fully local — no
    threat feed. Each sub-check is isolated so one failure can't sink the rest."""
    if not ROOTCHECK or not os.path.isdir("/proc"):
        return []
    checks = [
        lambda: _rc_hidden_processes(agent_id, seen),
        lambda: _rc_hidden_ports(agent_id, seen),
        lambda: _rc_preload(agent_id, seen),
        lambda: _rc_hidden_modules(agent_id, seen),
        lambda: _rc_deleted_running(agent_id, seen),
        lambda: _rc_suid(agent_id, seen),
        lambda: _rc_artifacts(agent_id, policy, seen),
    ]
    # Suricata IDS/IPS legitimately puts the capture NIC in promiscuous mode, so
    # only run that check when the engine is off.
    if state.get("nids_applied", "off") == "off":
        checks.append(lambda: _rc_promisc(agent_id, seen))
    dets = []
    for chk in checks:
        try:
            dets += chk()
        except Exception as exc:
            log(f"rootcheck sub-check error: {exc!r}")
    if dets:
        log(f"rootcheck: {len(dets)} anomaly detection(s)")
    return dets


def report(agent_id, dets, producer="av-agent") -> None:
    if not dets:
        return
    r = _req("POST", "/api/detections", {"producer": producer, "agent_id": agent_id, "events": dets})
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


_PSEUDO_FS = {"proc", "sysfs", "tmpfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
              "overlay", "squashfs", "autofs", "mqueue", "debugfs", "tracefs",
              "securityfs", "pstore", "bpf", "configfs", "fusectl", "ramfs",
              "hugetlbfs", "efivarfs", "nsfs", "binfmt_misc", "fuse.gvfsd-fuse",
              "rpc_pipefs", "selinuxfs"}


def _real_mounts() -> list:
    """Distinct real (block-device) mount points, de-duplicated by device."""
    if DISK_PATHS:
        return DISK_PATHS
    mounts, seen = [], set()
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for ln in f:
                parts = ln.split()
                if len(parts) < 3:
                    continue
                dev, mnt, fstype = parts[0], parts[1], parts[2]
                if fstype in _PSEUDO_FS or not dev.startswith("/dev/") or dev in seen:
                    continue
                seen.add(dev)
                mounts.append(mnt.replace("\\040", " "))
    except OSError:
        pass
    return mounts or ["/"]


def disk_usage() -> tuple:
    """Aggregate all fixed filesystems -> (% used, total GB, free GB, per-fs list)."""
    total = free = 0
    detail = []
    for mnt in _real_mounts():
        try:
            u = shutil.disk_usage(mnt)
        except OSError:
            continue
        total += u.total
        free += u.free
        detail.append({"drive": mnt, "total_gb": int(round(u.total / (1024 ** 3))),
                       "free_gb": int(round(u.free / (1024 ** 3)))})
    if not total:
        return 0, 0, 0, []
    pct = int(round(100.0 * (total - free) / total))
    return max(0, min(100, pct)), int(round(total / (1024 ** 3))), int(round(free / (1024 ** 3))), detail


def heartbeat(agent_id, policy_version=0, ports=None, nids=None) -> dict:
    disk_pct, disk_total, disk_free, disk_drives = disk_usage()
    body = {"status": "online", "policy_version": policy_version, "version": VERSION,
            "cpu": cpu_percent(), "mem": mem_percent(), "disk": disk_pct,
            "disk_total": disk_total, "disk_free": disk_free, "disk_drives": disk_drives}
    if ports is not None:
        body["ports"] = ports
    if nids is not None:
        body["nids_status"] = nids
    try:
        return _req("POST", f"/api/agents/{agent_id}/heartbeat", body) or {}
    except Exception as exc:
        log(f"heartbeat failed: {exc!r}")
        return {}


def self_update(directive) -> None:
    """Download the operator-pushed agent build, verify it, replace this file,
    and re-exec. Aborts (keeps running the old code) on any integrity failure."""
    # SEN-002: build the download URL locally (never trust a server-supplied
    # authority) — the server only tells us there IS an update.
    url = API + "/api/agent/download/linux"
    want, ver = directive.get("sha256", ""), directive.get("version", "?")
    log(f"update requested -> v{ver}; downloading {url}")
    try:
        with urllib.request.urlopen(url, timeout=90, context=_ssl_ctx()) as r:
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
    try:
        compile(data, "agent.py", "exec")            # never install broken code
    except SyntaxError as exc:
        log(f"update aborted: new code does not compile ({exc})"); return
    path = os.path.abspath(__file__)
    try:
        try:
            with open(path, "rb") as f:
                with open(path + ".bak", "wb") as b:
                    b.write(f.read())                # rollback copy
        except OSError:
            pass
        tmp = path + ".new"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except OSError as exc:
        log(f"update aborted: write failed ({exc!r})"); return
    log(f"updated to v{ver}; re-executing")
    try:
        os.execv(sys.executable, [sys.executable, "-m", "av_agent.agent"])
    except Exception as exc:
        log(f"re-exec failed ({exc!r}); exiting for supervisor restart")
        sys.exit(3)


# --------------------------------------------------------------------------- endpoint isolation
# FULL network quarantine: drop ALL traffic in/out (LAN included — this stops
# lateral movement inside the office network too) EXCEPT loopback, the control
# plane (so the agent can still receive un-isolate), and an optional operator
# allowlist (SENTINEL_ISOLATION_ALLOW = comma-separated IPs/CIDRs, e.g. a jump
# host). No SSH/RDP carve-out and no established pass-through, so existing LAN
# sessions are cut too. Priority -300 (before other firewalls) so the drop wins.
NFT_TABLE = "sentinel_quarantine"


def _isolation_allow() -> list:
    allow = [_ctrl_ip()]
    allow += [c.strip() for c in os.environ.get("SENTINEL_ISOLATION_ALLOW", "").split(",")]
    return [a for a in allow if a]


def _ctrl_ip() -> str:
    try:
        return urllib.parse.urlsplit(API).hostname or ""
    except ValueError:
        return ""


def _nft(script: str) -> bool:
    try:
        subprocess.run(["nft", "-f", "-"], input=script.encode(), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return True
    except Exception as exc:
        log(f"isolation nft error: {exc!r}")
        return False


def _drop_table() -> bool:
    # create-then-delete so removal is idempotent even if the table is absent
    return _nft(f"table inet {NFT_TABLE} {{}}\ndelete table inet {NFT_TABLE}")


def apply_isolation() -> bool:
    allow = _isolation_allow()
    in_rules = "".join(f"    ip saddr {a} accept\n" for a in allow)
    out_rules = "".join(f"    ip daddr {a} accept\n" for a in allow)
    script = (
        f"table inet {NFT_TABLE} {{\n"
        f"  chain input {{\n"
        f"    type filter hook input priority -300; policy drop;\n"
        f'    iif "lo" accept\n'
        f"{in_rules}"
        f"  }}\n"
        f"  chain output {{\n"
        f"    type filter hook output priority -300; policy drop;\n"
        f'    oif "lo" accept\n'
        f"{out_rules}"
        f"  }}\n"
        f"}}\n"
    )
    _drop_table()                       # clear any stale copy first
    if _nft(script):
        log(f"ENDPOINT ISOLATED: full quarantine (LAN cut); reachable only from {allow}")
        return True
    return False


def enforce_isolation(desired, state: dict) -> None:
    desired, applied = bool(desired), bool(state.get("isolated_applied"))
    if desired == applied:
        return
    ok = apply_isolation() if desired else _drop_table()
    if not desired and ok:
        log("endpoint isolation lifted: quarantine removed")
    if ok:
        state["isolated_applied"] = desired
        save_state(state)


# --------------------------------------------------------------------------- IP blocklist enforcement
BL_TABLE = "sentinel_blocklist"


def enforce_blocklist(ips, state: dict) -> None:
    """Drop traffic to/from the blocked IPs via an additive nftables set. Never
    blocks the control-plane IP (keeps the agent manageable / able to un-block)."""
    ctrl = _ctrl_ip()
    try:
        ctrl_addr = ipaddress.ip_address(ctrl) if ctrl else None
    except ValueError:
        ctrl_addr = None
    valid = set()
    for i in (ips or []):
        i = (i or "").strip()
        if not i or ":" in i:                         # IPv4 only here
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
    v4 = sorted(valid)
    if v4 == state.get("blocklist_applied", []):
        return
    _nft(f"table inet {BL_TABLE} {{}}\ndelete table inet {BL_TABLE}")     # clear any prior copy
    if v4:
        elems = ", ".join(v4)
        script = (
            f"table inet {BL_TABLE} {{\n"
            f"  set b4 {{ type ipv4_addr; flags interval; elements = {{ {elems} }} }}\n"
            f"  chain input {{\n"
            f"    type filter hook input priority -140; policy accept;\n"
            f"    ip saddr @b4 drop\n"
            f"  }}\n"
            f"  chain output {{\n"
            f"    type filter hook output priority -140; policy accept;\n"
            f"    ip daddr @b4 drop\n"
            f"  }}\n"
            f"}}\n"
        )
        if _nft(script):
            log(f"blocklist: enforcing {len(v4)} IP(s) via nftables")
        else:
            return
    else:
        log("blocklist: cleared (no blocked IPs)")
    state["blocklist_applied"] = v4
    save_state(state)


# --------------------------------------------------------------------------- open-port inventory
_TCP_LISTEN = "0A"          # /proc/net/tcp state for LISTEN


def _proc_net(path: str, want_states: set) -> list:
    """Parse /proc/net/{tcp,tcp6,udp,udp6}; return [(port, laddr)] for wanted states."""
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            next(f, None)                        # header
            for ln in f:
                parts = ln.split()
                if len(parts) < 4:
                    continue
                local, st = parts[1], parts[3]
                if st not in want_states:
                    continue
                addr_hex, _, port_hex = local.partition(":")
                try:
                    port = int(port_hex, 16)
                except ValueError:
                    continue
                # decode the local address (little-endian hex) for display
                laddr = "0.0.0.0"
                try:
                    if len(addr_hex) == 8:
                        b = bytes.fromhex(addr_hex)[::-1]
                        laddr = ".".join(str(x) for x in b)
                    else:
                        laddr = "::"
                except ValueError:
                    pass
                out.append((port, laddr))
    except (OSError, StopIteration):
        pass
    return out


def observe_ports() -> list:
    """Listening TCP + bound UDP sockets, with process name when `ss` is available."""
    # Prefer `ss -H -tulnp` (fast, gives the owning process); fall back to /proc/net.
    try:
        p = subprocess.run(["ss", "-H", "-tulnp"], capture_output=True, text=True, timeout=8)
        if p.returncode == 0 and p.stdout.strip():
            seen, out = set(), []
            for ln in p.stdout.splitlines():
                cols = ln.split()
                if len(cols) < 5:
                    continue
                proto = cols[0].lower()
                if proto not in ("tcp", "udp"):
                    continue
                local = cols[4]
                port_s = local.rsplit(":", 1)[-1]
                if not port_s.isdigit():
                    continue
                port = int(port_s)
                laddr = local.rsplit(":", 1)[0].strip("[]") or "0.0.0.0"
                proc = ""
                m = re.search(r'\("([^"]+)"', ln)
                if m:
                    proc = m.group(1)
                key = (proto, port)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"port": port, "proto": proto, "laddr": laddr, "proc": proc})
            if out:
                return sorted(out, key=lambda x: (x["proto"], x["port"]))
    except Exception:
        pass
    # fallback: /proc/net (no process names)
    rows, seen = [], set()
    for path, proto, states in (("/proc/net/tcp", "tcp", {_TCP_LISTEN}),
                                ("/proc/net/tcp6", "tcp", {_TCP_LISTEN}),
                                ("/proc/net/udp", "udp", {"07"}),
                                ("/proc/net/udp6", "udp", {"07"})):
        for port, laddr in _proc_net(path, states):
            key = (proto, port)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"port": port, "proto": proto, "laddr": laddr, "proc": ""})
    return sorted(rows, key=lambda x: (x["proto"], x["port"]))


# --------------------------------------------------------------------------- closed-port enforcement
# The operator can close host ports from the console. We drop inbound traffic to
# those ports via a dedicated nftables table (priority -130, before generic
# firewalls). Opening a port simply removes it from the set on the next sync.
PORT_TABLE = "sentinel_ports"


def enforce_ports(closed, state: dict) -> None:
    want = sorted({(str(c.get("proto", "tcp")).lower(), int(c["port"]))
                   for c in (closed or []) if c.get("port")})
    if want == [tuple(x) for x in state.get("ports_applied", [])]:
        return
    _nft(f"table inet {PORT_TABLE} {{}}\ndelete table inet {PORT_TABLE}")   # clear prior copy
    if want:
        tcp = [str(p) for pr, p in want if pr == "tcp"]
        udp = [str(p) for pr, p in want if pr == "udp"]
        rules = ""
        if tcp:
            rules += f"    tcp dport {{ {', '.join(tcp)} }} drop\n"
        if udp:
            rules += f"    udp dport {{ {', '.join(udp)} }} drop\n"
        script = (
            f"table inet {PORT_TABLE} {{\n"
            f"  chain input {{\n"
            f"    type filter hook input priority -130; policy accept;\n"
            f"{rules}"
            f"  }}\n"
            f"}}\n"
        )
        if _nft(script):
            log(f"ports: closing {len(want)} port(s) via nftables ({', '.join(f'{pr}/{p}' for pr, p in want)})")
        else:
            return
    else:
        log("ports: no closed ports (all open)")
    state["ports_applied"] = [list(x) for x in want]
    save_state(state)


# --------------------------------------------------------------------------- IDS/IPS (Suricata)
# We orchestrate the Suricata engine rather than reimplement it: the agent starts
# it in IDS (af-packet, detect-only) or IPS (inline via nftables NFQUEUE) mode,
# uses whatever rules Suricata has (ET Open via suricata-update), and forwards
# eve.json alerts to the control plane as detections. Mode is set from the console.
def _which(name: str) -> str:
    for d in (os.environ.get("PATH") or "/usr/sbin:/usr/bin:/sbin:/bin").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return ""


def nids_engine() -> tuple:
    """(installed, version) of the Suricata binary."""
    b = _which("suricata")
    if not b:
        return False, ""
    try:
        out = subprocess.run([b, "-V"], capture_output=True, text=True, timeout=8).stdout
        m = re.search(r"version\s+([\d.]+)", out or "")
        return True, (m.group(1) if m else "")
    except Exception:
        return True, ""


def _nids_iface() -> str:
    env = os.environ.get("SENTINEL_NIDS_IFACE")
    if env:
        return env
    try:                                    # default-route interface from /proc/net/route
        with open("/proc/net/route", encoding="utf-8") as f:
            next(f, None)
            for ln in f:
                parts = ln.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    return parts[0]
    except OSError:
        pass
    return "eth0"


def _nids_rules_count() -> int:
    for p in _NIDS_RULES:
        try:
            n = sum(1 for ln in open(p, encoding="utf-8", errors="replace")
                    if ln.strip() and not ln.startswith("#"))
            if n:
                return n
        except OSError:
            continue
    return 0


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def _nids_running_pid(state: dict) -> int:
    """Resolve the running Suricata pid: tracked pid -> pidfile -> pgrep.
    Caches the result back into state so status/idempotency stay consistent."""
    pid = state.get("nids_pid")
    if pid and _pid_alive(pid):
        return int(pid)
    try:
        with open(NIDS_PIDFILE, encoding="utf-8") as f:
            p = int(f.read().strip())
        if _pid_alive(p):
            state["nids_pid"] = p
            return p
    except (OSError, ValueError):
        pass
    try:                                   # match OUR suricata by its -l log dir (comm is "Suricata-Main")
        out = subprocess.run(["pgrep", "-f", NIDS_LOGDIR], capture_output=True,
                             text=True, timeout=5).stdout.split()
        if out:
            state["nids_pid"] = int(out[0])
            return int(out[0])
    except Exception:
        pass
    return 0


def _nids_stop(state: dict) -> None:
    pid = _nids_running_pid(state)
    if pid:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except OSError:
            pass
    # sweep ALL suricata instances we started (kill orphans/duplicates), matched
    # by our unique -l log dir so we never touch an unrelated suricata.
    try:
        subprocess.run(["pkill", "-f", NIDS_LOGDIR], capture_output=True, timeout=10)
    except Exception:
        pass
    state["nids_pid"] = None
    try:
        os.path.exists(NIDS_PIDFILE) and os.remove(NIDS_PIDFILE)
    except OSError:
        pass
    _nft(f"table inet {NIDS_TABLE} {{}}\ndelete table inet {NIDS_TABLE}")   # drop any inline NFQUEUE rules


def _nids_nfqueue() -> bool:
    # send input/forward/output through NFQUEUE so Suricata sees traffic inline;
    # `bypass` = if Suricata isn't reading the queue, traffic passes (fail-open).
    script = (
        f"table inet {NIDS_TABLE} {{\n"
        f"  chain inp {{ type filter hook input priority -150; policy accept; queue num {NIDS_QUEUE} bypass }}\n"
        f"  chain fwd {{ type filter hook forward priority -150; policy accept; queue num {NIDS_QUEUE} bypass }}\n"
        f"  chain outp {{ type filter hook output priority -150; policy accept; queue num {NIDS_QUEUE} bypass }}\n"
        f"}}\n"
    )
    return _nft(script)


_nids_install_tried = False


def _nids_install_engine() -> bool:
    """Auto-install Suricata + ET Open rules (root + internet).

    SEN-013: a control-plane NIDS-mode change must NOT be able to run the package
    manager as root on every endpoint. Auto-install is therefore OFF unless the
    host operator opts in locally with SENTINEL_NIDS_AUTOINSTALL=1; otherwise the
    agent just reports the engine missing and Suricata is provisioned out of band
    (av_agent/install_suricata.sh)."""
    if os.environ.get("SENTINEL_NIDS_AUTOINSTALL", "0") not in ("1", "true", "yes"):
        log("NIDS: engine missing; auto-install disabled (SEN-013). Provision out of band "
            "(av_agent/install_suricata.sh) or set SENTINEL_NIDS_AUTOINSTALL=1 on this host.")
        return False
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if _which("apt-get"):
        cmds = [["apt-get", "update", "-y"], ["apt-get", "install", "-y", "suricata", "suricata-update"]]
    elif _which("dnf"):
        cmds = [["dnf", "install", "-y", "suricata", "suricata-update"]]
    elif _which("yum"):
        cmds = [["yum", "install", "-y", "suricata"]]
    else:
        log("NIDS: no supported package manager for auto-install")
        return False
    for c in cmds:
        try:
            r = subprocess.run(c, capture_output=True, timeout=600, env=env)
            if r.returncode != 0:
                log(f"NIDS: auto-install '{c[0]} {c[1]}' rc={r.returncode}")
        except Exception as exc:
            log(f"NIDS: auto-install error ({exc!r})")
            return False
    if _which("suricata-update"):
        try:
            subprocess.run(["suricata-update", "--no-test", "-q"], capture_output=True, timeout=300, env=env)
        except Exception:
            pass
    try:
        subprocess.run(["systemctl", "disable", "--now", "suricata"], capture_output=True, timeout=30)
    except Exception:
        pass
    return bool(_which("suricata"))


def _nids_validate_rules(path: str) -> bool:
    """SEN-005: validate a ruleset file with `suricata -T` before it is loaded by
    the root engine. Returns True if Suricata accepts it (or if Suricata isn't
    installed — nothing to break yet). Bounded so a pathological ruleset can't hang."""
    b = _which("suricata")
    if not b:
        return True                      # no engine present; server already sanitized
    try:
        r = subprocess.run([b, "-T", "-c", SURICATA_YAML, "-S", path, "-l", NIDS_LOGDIR],
                           capture_output=True, timeout=90)
        if r.returncode == 0:
            return True
        tail = (r.stderr or r.stdout or b"").decode("utf-8", "replace").strip().splitlines()[-3:]
        log("NIDS: suricata -T rejected ruleset: " + " | ".join(tail))
        return False
    except subprocess.TimeoutExpired:
        log("NIDS: suricata -T timed out validating ruleset")
        return False
    except Exception as exc:
        log(f"NIDS: suricata -T error ({exc!r})")
        return False


def nids_sync_rules(agent_id, state: dict) -> bool:
    """Pull the central ruleset (community + custom) and, if changed, write it to
    disk and live-reload Suricata (SIGUSR2). Returns True on change."""
    try:
        r = _req("GET", "/api/nids/ruleset" +
                 (f"?agent_id={urllib.parse.quote(agent_id)}" if agent_id else ""))
    except Exception:
        return False
    ver, text = r.get("version"), r.get("ruleset", "")
    if not ver or ver == state.get("nids_rules_ver"):
        return False
    try:
        os.makedirs(os.path.dirname(NIDS_RULESFILE) or ".", exist_ok=True)
        tmp = NIDS_RULESFILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as exc:
        log(f"NIDS: could not write ruleset ({exc!r})")
        return False
    # SEN-005: never load an untrusted ruleset into the root engine unvalidated.
    # Test it with `suricata -T` first; on failure keep the last-good file.
    if not _nids_validate_rules(tmp):
        log(f"NIDS: ruleset v{ver} FAILED suricata -T — keeping last-good, not applying")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False
    try:
        os.replace(tmp, NIDS_RULESFILE)
    except OSError as exc:
        log(f"NIDS: could not install ruleset ({exc!r})")
        return False
    state["nids_rules_ver"] = ver
    save_state(state)
    log(f"NIDS: central ruleset updated (v{ver}, validated)")
    pid = _nids_running_pid(state)
    if pid:
        try:
            os.kill(int(pid), signal.SIGUSR2)      # Suricata: live rule reload
            log("NIDS: reloaded Suricata rules (SIGUSR2)")
        except OSError:
            pass
    return True


def nids_apply(mode: str, state: dict, agent_id: str = "") -> None:
    """Enforce the desired Suricata mode (off | ids | ips). Safe/idempotent."""
    mode = mode if mode in ("off", "ids", "ips") else "off"
    applied = state.get("nids_applied", "off")
    if mode == applied and (mode == "off" or _nids_running_pid(state)):
        return                              # already in the desired state — don't restart
    _nids_stop(state)
    if mode == "off":
        state["nids_applied"] = "off"
        save_state(state)
        if applied != "off":
            log("NIDS: disabled")
        return
    b = _which("suricata")
    if not b:
        # Auto-install the engine on first enable (root + internet needed). Tried
        # once per agent run to avoid apt spam; restart the agent to retry.
        global _nids_install_tried
        if not _nids_install_tried:
            _nids_install_tried = True
            log("NIDS: Suricata not installed — attempting automatic install…")
            if _nids_install_engine():
                b = _which("suricata")
                log(f"NIDS: Suricata installed automatically (v{nids_engine()[1]})")
        if not b:
            state["nids_applied"] = "off"
            save_state(state)
            log(f"NIDS: {mode} requested but Suricata unavailable — run av_agent/install_suricata.sh")
            return
    os.makedirs(NIDS_LOGDIR, exist_ok=True)
    if _nids_rules_count() == 0 and _which("suricata-update"):
        try:
            log("NIDS: fetching ET Open ruleset (suricata-update)…")
            subprocess.run(["suricata-update", "--no-test", "-q"], capture_output=True, timeout=300)
        except Exception:
            pass
    # stop a distro-managed suricata so we don't fight over the interface/queue
    try:
        subprocess.run(["systemctl", "stop", "suricata"], capture_output=True, timeout=20)
    except Exception:
        pass
    nids_sync_rules(agent_id, state)      # ensure the central ruleset is on disk
    extra = ["-s", NIDS_RULESFILE] if os.path.exists(NIDS_RULESFILE) else []
    iface = _nids_iface()
    base = [b, "-c", SURICATA_YAML, "--pidfile", NIDS_PIDFILE] + extra + ["-l", NIDS_LOGDIR, "-D"]
    if mode == "ips":
        if not _nids_nfqueue():
            state["nids_applied"] = "off"; save_state(state)
            log("NIDS: could not program NFQUEUE; IPS not enabled"); return
        cmd = base + ["-q", str(NIDS_QUEUE)]
    else:
        cmd = base + ["--af-packet=" + iface]
    try:
        os.path.exists(NIDS_PIDFILE) and os.remove(NIDS_PIDFILE)   # clear stale pidfile
    except OSError:
        pass
    try:
        subprocess.run(cmd, capture_output=True, timeout=120)     # -D daemonizes and returns
    except Exception as exc:
        _nids_stop(state); state["nids_applied"] = "off"; save_state(state)
        log(f"NIDS: Suricata failed to start ({exc!r})"); return
    state["nids_applied"] = mode
    save_state(state)
    pid = 0
    for _ in range(10):                     # daemon writes the pidfile shortly after fork
        pid = _nids_running_pid(state)
        if pid:
            break
        time.sleep(1)
    log(f"NIDS: {mode.upper()} active on {iface} via Suricata (pid {pid or '?'})")


def nids_status(state: dict) -> dict:
    installed, ver = nids_engine()
    return {"installed": installed, "engine": ver,
            "running": bool(_nids_running_pid(state)),
            "mode": state.get("nids_applied", "off"),
            "rules": _nids_rules_count(), "iface": _nids_iface(),
            "alerts": int(state.get("nids_alert_total", 0))}


_SURI_SEV = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


def nids_collect(agent_id, state: dict) -> list:
    """Read new Suricata eve.json alert lines and map them to v3 detections."""
    path = os.path.join(NIDS_LOGDIR, "eve.json")
    try:
        st = os.stat(path)
    except OSError:
        return []
    off = int(state.get("nids_eve_offset", 0))
    if state.get("nids_eve_inode") != st.st_ino or off > st.st_size:
        off = 0                                # rotated/truncated -> restart
    dets = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(off)
            for line in f:
                if len(dets) >= NIDS_MAX_PER_CYCLE:
                    break
                line = line.strip()
                if not line or '"alert"' not in line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("event_type") != "alert":
                    continue
                a = ev.get("alert", {}) or {}
                blocked = a.get("action") == "blocked"
                sev = _SURI_SEV.get(int(a.get("severity", 3) or 3), "MEDIUM")
                det = make_event(
                    agent_id, "IPS_DROP" if blocked else "IDS_ALERT",
                    a.get("signature", "Suricata alert"), "signature",
                    sev, 85 if blocked else 75,
                    {"engine": "suricata", "signature": a.get("signature"),
                     "sid": a.get("signature_id"), "category": a.get("category"),
                     "action": a.get("action", "allowed"), "src_ip": ev.get("src_ip"),
                     "dest_ip": ev.get("dest_ip"), "dest_port": ev.get("dest_port"),
                     "proto": ev.get("proto"), "app_proto": ev.get("app_proto")}, [])
                det["integrity"]["producer"] = "suricata"   # so SRS Logs show/filter "suricata"
                dets.append(det)
            state["nids_eve_offset"] = f.tell()
        state["nids_eve_inode"] = st.st_ino
        state["nids_alert_total"] = int(state.get("nids_alert_total", 0)) + len(dets)
        save_state(state)
    except OSError:
        return []
    if dets:
        log(f"NIDS: {len(dets)} Suricata alert(s)")
    return dets


# --------------------------------------------------------------------------- realtime watcher (inotify)
# Event-driven file monitoring via the kernel's inotify API, reached through
# ctypes so the agent stays stdlib-only. Idle cost is ~zero (we block in
# select()); only changed files are scanned, so there's no periodic re-hash storm.
_IN_MODIFY = 0x00000002
_IN_CLOSE_WRITE = 0x00000008
_IN_MOVED_TO = 0x00000080
_IN_CREATE = 0x00000100
_IN_ISDIR = 0x40000000
_IN_NONBLOCK = 0x00000800
_WATCH_MASK = _IN_CLOSE_WRITE | _IN_MOVED_TO | _IN_CREATE
_EVENT_HDR = struct.Struct("iIII")   # wd, mask, cookie, len


class NullWatcher:
    """Fallback when inotify is unavailable: wait() just sleeps."""
    active = False

    def refresh(self, dirs):
        pass

    def wait(self, timeout):
        if timeout > 0:
            time.sleep(timeout)
        return []

    def close(self):
        pass


class INotifyWatcher:
    def __init__(self):
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        self._libc = ctypes.CDLL(libc_name, use_errno=True)
        self._libc.inotify_init1.argtypes = [ctypes.c_int]
        self._libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.fd = self._libc.inotify_init1(_IN_NONBLOCK)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.active = True
        self.wd_path: dict[int, str] = {}

    def _add(self, path):
        wd = self._libc.inotify_add_watch(self.fd, path.encode("utf-8", "surrogateescape"), _WATCH_MASK)
        if wd >= 0:
            self.wd_path[wd] = path

    def refresh(self, dirs):
        """(Re)watch every existing subdirectory of the scan dirs."""
        watched = set(self.wd_path.values())
        for base in dirs:
            if not os.path.isdir(base):
                continue
            if base not in watched:
                self._add(base)
            for root, subs, _files in os.walk(base):
                subs[:] = [d for d in subs if d not in _SKIP_DIRS
                           and not os.path.islink(os.path.join(root, d))]
                for d in subs:
                    dp = os.path.join(root, d)
                    if dp not in watched:
                        self._add(dp)

    def wait(self, timeout):
        """Block up to `timeout`s; return changed file paths (dirs auto-watched)."""
        try:
            r, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        except OSError:
            return []
        if not r:
            return []
        try:
            data = os.read(self.fd, 65536)
        except (BlockingIOError, OSError):
            return []
        paths, i, n = [], 0, len(data)
        new_dirs = False
        while i + _EVENT_HDR.size <= n:
            wd, mask, _cookie, ln = _EVENT_HDR.unpack_from(data, i)
            i += _EVENT_HDR.size
            name = data[i:i + ln].split(b"\x00", 1)[0].decode("utf-8", "replace") if ln else ""
            i += ln
            base = self.wd_path.get(wd)
            if not base:
                continue
            full = os.path.join(base, name) if name else base
            if mask & _IN_ISDIR:
                if mask & (_IN_CREATE | _IN_MOVED_TO) and os.path.isdir(full):
                    self._add(full)                # watch newly created subdirs
                    new_dirs = True
                continue
            if name:
                paths.append(full)
        if new_dirs:
            self.refresh(SCAN_DIRS)                 # pick up files created inside new dirs
        # de-dup while preserving order
        return list(dict.fromkeys(paths))

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


def make_watcher():
    if not REALTIME:
        return NullWatcher()
    try:
        w = INotifyWatcher()
        w.refresh(SCAN_DIRS)
        log(f"realtime file monitoring active (inotify): {len(w.wd_path)} dir(s) watched")
        return w
    except Exception as exc:
        log(f"inotify unavailable ({exc!r}); falling back to periodic incremental scan")
        return NullWatcher()


# --------------------------------------------------------------------------- main
def _apply_hb(hb, state, agent_id="") -> None:
    """React to a heartbeat response: update / isolate / blocklist / closed ports."""
    if hb.get("update"):
        self_update(hb["update"])                   # re-execs on success
    enforce_isolation(hb.get("isolate"), state)
    if "blocked" in hb:                             # guarded: absent on a failed beat
        enforce_blocklist(hb["blocked"], state)
    if "closed_ports" in hb:
        enforce_ports(hb["closed_ports"], state)
    if "nids_mode" in hb:
        nids_apply(hb["nids_mode"], state, agent_id)   # off | ids | ips (Suricata)


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-av")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    log(f"starting AV agent v{VERSION} -> {API}; realtime={'on' if REALTIME else 'off'}; "
        f"scan_dirs={SCAN_DIRS}")
    state = load_state()
    global AGENT_SECRET
    AGENT_SECRET = state.get("agent_secret", "")   # so re-enroll proves ownership (SEN-007)
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
    scan_cache: dict = {}
    policy = {"hashes": set(), "ips": set(), "sigs": [], "behaviors": [], "proc_rules": []}
    cpu_percent()  # prime the CPU delta baseline

    # Initial policy + full (incremental) baseline scan so pre-existing threats
    # are caught before we switch to event-driven monitoring.
    try:
        policy = pull_policy(agent_id)
        enforce_blocklist(policy.get("blocked", []), state)
        enforce_ports(policy.get("closed_ports", []), state)
    except Exception as exc:
        log(f"initial policy pull failed: {exc!r}")
    report(agent_id, scan_files(agent_id, policy, seen, scan_cache))
    report(agent_id, log_ids_scan(agent_id, policy, state), producer="log-ids")
    report(agent_id, scan_processes(agent_id, policy, seen))
    report(agent_id, rootcheck_scan(agent_id, policy, seen, state), producer="rootcheck")
    _apply_hb(heartbeat(agent_id, ports=observe_ports(), nids=nids_status(state)), state, agent_id)

    if args.once:
        return

    watcher = make_watcher()
    last_policy = last_beat = last_full = last_aux = last_rootcheck = time.time()
    try:
        while True:
            # sleep until the next scheduled task, but wake instantly on file events
            due = min(POLICY_EVERY - (time.time() - last_policy),
                      INTERVAL - (time.time() - last_beat),
                      FULLSCAN_EVERY - (time.time() - last_full))
            changed = watcher.wait(max(1.0, min(due, INTERVAL)))
            if changed:
                # realtime: scan only what changed and report immediately
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
                    if state.get("nids_applied", "off") != "off":
                        nids_sync_rules(agent_id, state)   # refresh Suricata rules
                    watcher.refresh(SCAN_DIRS)       # cover any newly created trees
                except Exception as exc:
                    log(f"policy pull failed: {exc!r}")
                last_policy = now
            if now - last_aux >= INTERVAL:           # cheap host telemetry scans
                try:
                    report(agent_id, log_ids_scan(agent_id, policy, state), producer="log-ids")
                    report(agent_id, scan_processes(agent_id, policy, seen))
                    report(agent_id, nids_collect(agent_id, state), producer="suricata")
                except Exception as exc:
                    log(f"aux scan error: {exc!r}")
                last_aux = now
            if now - last_full >= FULLSCAN_EVERY or not watcher.active:
                try:                                 # incremental safety-net walk
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
                    _apply_hb(heartbeat(agent_id, ports=observe_ports(), nids=nids_status(state)),
                              state, agent_id)
                except Exception as exc:
                    log(f"heartbeat error: {exc!r}")
                last_beat = now
            if len(seen) > _SEEN_MAX:                # keep the dedupe set bounded
                seen = set()
    finally:
        watcher.close()


if __name__ == "__main__":
    main()
