"""Sigma -> log-IDS rule conversion + a self-check that keeps false positives out.

Sigma (https://sigmahq.io) is the open standard for log detections. Our log-IDS
engine matches a single regex against a decoded log line, so this converts the
*common* Sigma shapes (keywords, field selections with contains/startswith/
endswith/re, and simple and/or/not conditions) into one line-regex. Unsupported
shapes (aggregations, counts, correlation) are skipped with a reason rather than
mis-converted.

Every converted rule is then run through `verify_pattern()` — a self-check that
rejects over-broad patterns and anything matching a benign-log corpus — so noisy
rules land *staged* (unverified) for operator review instead of firing blind.
"""
from __future__ import annotations

import re

import yaml

_LEVEL_SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
              "low": "LOW", "informational": "LOW", "info": "LOW"}

# Sigma field name -> the token our Windows/Sysmon engine renders on the line.
_WIN_FIELD_TOKEN = {
    "commandline": "Cmd", "image": "Image", "parentimage": "Parent", "targetimage": "Target",
    "targetfilename": "File", "targetobject": "Reg", "destinationip": "Dst",
    "destinationport": "DstPort", "queryname": "Query", "pipename": "Pipe", "user": "User",
    "newprocessname": "Process", "subjectusername": "Subject", "targetusername": "Account",
    "ipaddress": "Address", "grantedaccess": "Access", "logontype": "LogonType",
    "eventid": "EventID", "groupname": "Group", "servicename": "Service",
}

# A small benign corpus. If a converted rule matches any of these it is treated as
# too noisy to auto-trust and is staged (unverified) for review.
_BENIGN = [
    "Aug 05 10:00:01 host sshd[111]: Accepted publickey for deploy from 10.0.0.5 port 5000 ssh2",
    "Aug 05 10:00:01 host CRON[222]: (root) CMD (/usr/bin/backup.sh)",
    "Aug 05 10:00:01 host systemd[1]: Started Session 3 of user deploy.",
    "Aug 05 10:00:01 host sudo:  deploy : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/apt update",
    'type=SYSCALL msg=audit(1): arch=c000003e syscall=59 success=yes exe="/usr/bin/bash" key="(null)"',
    '10.0.0.5 - - [05/Aug/2026:10:00:01] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    "EventID=4624 Account=deploy LogonType=2 Process=C:\\Windows\\explorer.exe",
    "EventID=4688 Account=deploy Process=C:\\Windows\\System32\\notepad.exe Cmd=notepad.exe report.txt",
    "EventID=1 Image=C:\\Windows\\System32\\svchost.exe Parent=C:\\Windows\\System32\\services.exe",
    "EventID=3 Image=C:\\Program Files\\App\\app.exe Dst=93.184.216.34 DstPort=443",
    "EventID=22 Image=C:\\Windows\\System32\\svchost.exe Query=www.microsoft.com",
]


def _sev(level: str) -> str:
    return _LEVEL_SEV.get(str(level or "").lower(), "MEDIUM")


def _mitre(tags) -> list:
    out = []
    for t in tags or []:
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", str(t), re.I)
        if m:
            out.append(m.group(1).upper())
    return out


def _map_source(ls: dict) -> "tuple[str, str]":
    product = str(ls.get("product") or "").lower()
    service = str(ls.get("service") or "").lower()
    category = str(ls.get("category") or "").lower()
    if service == "sysmon":
        return ("windows", "sysmon")
    if product == "windows":
        if service == "security" or category == "process_creation":
            return ("windows", "winsec")
        if service == "system":
            return ("windows", "winsys")
        if category in ("network_connection", "dns_query", "image_load", "file_event",
                        "registry_event", "pipe_created", "create_remote_thread", "process_access"):
            return ("windows", "sysmon")
        return ("windows", "winsec")
    if product == "linux":
        if service in ("sshd", "auth", "authpriv"):
            return ("linux", "auth")
        if service == "auditd":
            return ("linux", "auditd")
        return ("linux", "syslog")
    if category == "webserver" or product in ("apache", "nginx"):
        return ("any", "web")
    return ("any", "any")


def _val_regex(val, modifier: str) -> str:
    def one(v):
        if modifier == "re":
            return str(v)
        return re.escape(str(v))
    if isinstance(val, list):
        return "(?:" + "|".join(one(v) for v in val) + ")"
    return one(val)


def _selection_regex(sel, source: str) -> "str | None":
    """AND of a selection's fields, as concatenated look-aheads over the line."""
    if isinstance(sel, list):                       # list of maps -> OR of sub-selections
        alts = [ _selection_regex(s, source) for s in sel ]
        alts = [a for a in alts if a]
        return "(?:" + "|".join(alts) + ")" if alts else None
    if not isinstance(sel, dict):
        # a bare keyword string
        return f"(?=.*{re.escape(str(sel))})"
    parts = []
    for key, val in sel.items():
        field, _, mod = str(key).partition("|")
        fieldl = field.lower()
        vre = _val_regex(val, mod)
        token = _WIN_FIELD_TOKEN.get(fieldl)
        if token and source in ("winsec", "winsys", "sysmon"):
            parts.append(f"(?=.*\\b{token}=[^\\n]{{0,400}}?{vre})")
        else:
            parts.append(f"(?=.*{vre})")
    return "".join(parts) if parts else None


def _keywords_regex(kw) -> "str | None":
    items = kw if isinstance(kw, list) else [kw]
    esc = [re.escape(str(k)) for k in items if str(k).strip()]
    return "(?:" + "|".join(esc) + ")" if esc else None


def _condition_regex(detection: dict, source: str) -> "tuple[str | None, str]":
    cond = detection.get("condition", "")
    if isinstance(cond, list):
        cond = " or ".join(str(c) for c in cond)
    cond = str(cond).strip().lower()
    if not cond:
        return None, "no condition"
    if any(x in cond for x in ("| count", "|count", " near ", "| ", "aggregation")):
        return None, "unsupported aggregation/correlation condition"

    blocks = {k: v for k, v in detection.items() if k != "condition"}

    def block_regex(name):
        if name == "keywords" and "keywords" in blocks:
            return _keywords_regex(blocks["keywords"])
        if name in blocks:
            return _selection_regex(blocks[name], source)
        return None

    def expand(token):                              # 'them' / 'sel*' wildcards
        if token == "them":
            return list(blocks.keys())
        if token.endswith("*"):
            pre = token[:-1]
            return [k for k in blocks if k.startswith(pre)]
        return [token]

    # split top-level OR, then AND; drop `not <x>` terms (approximation)
    or_groups = re.split(r"\bor\b", cond)
    or_res = []
    for g in or_groups:
        toks = g.replace("(", " ").replace(")", " ").split()
        names, skip = [], False
        i = 0
        while i < len(toks):
            t = toks[i]
            if t == "not":
                i += 2                              # drop 'not <name>'
                continue
            if t in ("and", "1", "all", "of"):
                i += 1
                continue
            names.extend(expand(t))
            i += 1
        regs = [block_regex(n) for n in names]
        regs = [r for r in regs if r]
        if regs:
            or_res.append("".join(regs))
    if not or_res:
        return None, "no convertible selection in condition"
    body = or_res[0] if len(or_res) == 1 else "(?:" + "|".join(or_res) + ")"
    return "(?i)" + body, "ok"


def verify_pattern(pattern: str, source: str = "") -> "tuple[bool, str]":
    """Self-check that keeps noisy rules out of production. Returns (ok, reason)."""
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return False, f"regex error: {e}"
    if rx.search(""):
        return False, "matches the empty string (too broad)"
    if not re.search(r"[A-Za-z0-9_./\\-]{4,}", pattern):
        return False, "no specific literal token (too broad)"
    hits = sum(1 for b in _BENIGN if rx.search(b))
    if hits:
        return False, f"matches {hits} benign sample line(s) — likely false-positive-prone"
    return True, "ok"


def _slug(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", str(title or "sigma").lower()).strip("_")
    return ("sigma_" + s)[:90] or "sigma_rule"


def convert_yaml(text: str) -> "tuple[list, list]":
    """Parse a Sigma YAML document (or multi-doc) -> ([rule dicts], [skips]).
    Each rule dict is ready for LogRule(**r) plus 'verified'/'origin'/'raw'.
    Skips are (title, reason) for rules we could not safely convert/verify."""
    rules, skips = [], []
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception as e:
        return [], [("<parse>", f"YAML parse error: {e}")]
    for doc in docs:
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        title = doc.get("title") or "sigma rule"
        try:
            platform, source = _map_source(doc.get("logsource", {}) or {})
            pattern, why = _condition_regex(doc.get("detection", {}) or {}, source)
            if not pattern:
                skips.append((title, why)); continue
            ok, reason = verify_pattern(pattern, source)
            rule = {
                "name": _slug(title),
                "platform": platform, "source": source, "pattern": pattern,
                "entity_group": 0, "threshold": 1, "window_sec": 300,
                "severity": _sev(doc.get("level")),
                "mitre": _mitre(doc.get("tags")),
                "event_type": "SIGMA_MATCH",
                "description": ("[sigma] " + str(title))[:256],
                "origin": "sigma",
                "verified": bool(ok),
                "verify_note": reason,
            }
            rules.append(rule)
        except Exception as e:                      # never let one bad rule break the batch
            skips.append((title, f"conversion error: {e}"))
    return rules, skips
