"""
Alert calibration — the analyst-in-a-box.

When a detection first triggers, a senior analyst does NOT take the raw severity at
face value. They investigate before giving a verdict:

  * Precision  — is this an EXACT match (a known file hash / known-bad IP) or a
                 FUZZY heuristic (a YARA string, a command-line pattern) that also
                 fires on benign software?
  * Reputation — is the indicator in our threat-intel store / flagged by VirusTotal,
                 or is it operator-allowlisted / our own infrastructure?
  * Context    — does the file live in a system/package path (benign) or a
                 user-writable/temp path (suspicious)? Is it Authenticode-signed?
  * Corroboration — are there OTHER, independent alerts on the same host right now
                 (a real intrusion lights up several), or is this a lone one-off?
  * Prevalence — does this exact signal fire constantly across the fleet
                 (environmental noise) or is it rare (signal)?

Then they render a verdict — confirmed threat / likely threat / inconclusive /
likely noise / benign noise — and RE-SET the severity so the queue can be triaged
by tier instead of everything screaming CRITICAL.

This module codifies that process. `calibrate(db, det)` runs automatically at
ingest (invisible) and can be re-run on demand. It is deliberately FAIL-SAFE — the
mistakes a good analyst refuses to make are encoded as hard rules:

  * an EXACT match (file hash, or an IP/hash already in the IOC store) is NEVER
    downgraded below its triggered severity — precise evidence is trusted;
  * when the evidence is thin or contradictory the verdict is `inconclusive` and
    the raw severity is KEPT — calibration never silently buries a possible threat;
  * own-infrastructure / operator-allowlisted indicators are pinned to benign;
  * it performs NO blocking network I/O — reputation comes only from the local IOC
    store and threat-intel cache, so it is safe to run inline on every ingest.

`gather_context()` (DB reads) and `evaluate()` (pure verdict logic) are split so the
verdict logic can be unit-tested with synthetic evidence — see tests/test_calibrate.py.
"""
from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from . import models

CALIBRATION_VERSION = 1

# --------------------------------------------------------------------------- scales
_SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RSEV = {v: k for k, v in _SEV.items()}


def _rank(s: str) -> int:
    return _SEV.get((s or "").strip().upper(), 2)


def _name(r: float) -> str:
    return _RSEV[max(0, min(4, int(round(r))))]


# --------------------------------------------------------------------------- context vocab
# Trusted locations: package-managed system dirs + Windows system/Program-Files.
# A fuzzy hit here is almost always benign (same list the agents trust for YARA).
_TRUST_DIR = (
    "/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/libexec", "/usr/share", "/var/lib/dpkg", "/var/lib/apt", "/var/cache", "/snap",
    "/boot", "/opt/padakhep-sentinel", "/var/ossec",
    "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
)
_INITRAMFS = re.compile(r"/(?:mkinitramfs|dracut|initramfs)[^/]*/", re.I)
# User-writable / staging locations where real droppers land.
_TEMP_DIR = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/run/user/", "/var/www/",
    "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\", "\\programdata\\",
    "\\windows\\temp\\",
)
# Transport/remote-exec wrappers whose argv carries a command the *child* runs.
_TRANSPORT = {
    "ssh", "sshd", "plink", "scp", "sftp", "rsync", "ansible", "ansible-playbook",
    "kubectl", "docker", "containerd", "git", "salt", "salt-minion", "puppet",
    "chef-client", "wsl", "conhost",
}

# Own infrastructure — never a threat (mirror of threathunter policy; env-additive).
OWN_INFRA = {"118.179.149.162"} | {
    ip.strip() for ip in os.environ.get("SENTINEL_OWN_INFRA", "").split(",") if ip.strip()
}

# Noise thresholds (identical events across the fleet, trailing 7 days).
_PREV_NOISE = int(os.environ.get("SENTINEL_CAL_PREV_NOISE", "25"))
_PREV_COMMON = int(os.environ.get("SENTINEL_CAL_PREV_COMMON", "8"))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _basename(p: str) -> str:
    return re.split(r"[\\/]", (p or "").strip())[-1].lower()


def _trusted_path(p: str) -> bool:
    pl = (p or "").lower()
    if not pl:
        return False
    # a specific, legitimate initramfs/dracut rebuild is trusted even under /var/tmp
    if _INITRAMFS.search(pl):
        return True
    # user-writable / staging dirs are NEVER trusted, whatever the file is named — a
    # ".so"/".dll" in /dev/shm, Downloads or \windows\temp is a red flag, not a lib.
    # (This also removes the old "extension alone = trusted" bypass.)
    if _temp_path(pl):
        return False
    return any(pl.startswith(d) for d in _TRUST_DIR)


def _temp_path(p: str) -> bool:
    pl = (p or "").lower()
    return bool(pl) and any(s in pl for s in _TEMP_DIR)


# --------------------------------------------------------------------------- evidence gathering (DB)
def gather_context(db, det: dict) -> dict:
    """Collect the facts an analyst would pull before judging one detection.

    DB-only, read-only, no network. Every lookup is defensive: a failure degrades
    the corresponding signal to 'unknown', never breaks calibration."""
    ev = det.get("event") or {}
    e = (ev.get("event") or {}) if isinstance(ev, dict) else {}
    details = e.get("details") if isinstance(e.get("details"), dict) else {}
    details = details or {}
    ioc_value = det.get("ioc_value") or ""
    ioc_type = (det.get("ioc_type") or "").lower()
    device = det.get("device_name") or ""
    event_type = det.get("event_type") or ""

    path = details.get("path") or details.get("target") or details.get("file") or details.get("image") or ""
    # Two hash notions, deliberately different trust levels:
    #  * sha_trust — the AUTHORITATIVE hash of the artifact the detection is about
    #    (the indicator value on a hash-type event). Only this may SUPPRESS via the
    #    allowlist, so a compromised agent can't attach an allowlisted hash as a
    #    decorative detail to force a real detection benign.
    #  * sha_lookup — includes the self-reported details.sha256 too, used ONLY to
    #    RAISE (match known-bad threat intel). Escalation on a spoofed hash is not an
    #    attacker win, so the wider net is safe here.
    sha_trust = ioc_value if ioc_type == "hash" else ""
    sha_lookup = details.get("sha256") or details.get("hash") or sha_trust
    sha = sha_trust

    ctx = {
        "ioc_conf": None,      # confidence of matching IOC in our store, or None
        "vt_malicious": 0,     # VirusTotal engines flagging it (from IOC store)
        "allowlisted": False,
        "own_infra": False,
        "corroboration": 0,    # total other detections on this host / 24h
        "related_types": 0,    # distinct event types on this host / 24h
        "prevalence": 0,       # identical (event_type,ioc) across fleet / 7d
        "abuse_score": None,   # cached AbuseIPDB score, if any
        "path": path, "sha": sha, "ioc_type": ioc_type, "details": details,
        "event_type": event_type,
    }

    # --- threat-intel store: is the indicator (or the file's hash) known-bad? ---
    try:
        vals = [v for v in {ioc_value, sha_lookup} if v]   # escalation net (wide)
        if vals:
            hit = db.execute(
                select(models.Ioc).where(models.Ioc.active.is_(True), models.Ioc.value.in_(vals))
            ).scalars().first()
            if hit is not None:
                ctx["ioc_conf"] = int(hit.confidence or 0)
                ctx["vt_malicious"] = int(getattr(hit, "vt_malicious", 0) or 0)
    except Exception:
        pass

    # --- operator allowlist wins over everything ---
    try:
        allow = db.execute(
            select(models.AllowlistEntry).where(models.AllowlistEntry.active.is_(True))
        ).scalars().all()
        for a in allow:
            if a.kind == "binary" and sha and a.sha256 and a.sha256.lower() == sha.lower():
                ctx["allowlisted"] = True
            if a.kind == "ip" and ioc_type == "ip" and ioc_value:
                try:
                    if ipaddress.ip_address(ioc_value) in ipaddress.ip_network(a.value, strict=False):
                        ctx["allowlisted"] = True
                except ValueError:
                    pass
    except Exception:
        pass

    if ioc_type == "ip" and ioc_value in OWN_INFRA:
        ctx["own_infra"] = True

    # --- corroboration: other alerts on this host in the last 24h ---
    try:
        if device:
            since = _utcnow() - timedelta(hours=24)
            types = db.execute(
                select(models.Detection.event_type).where(
                    models.Detection.device_name == device,
                    models.Detection.ts >= since,
                    models.Detection.id != det.get("id", -1),
                )
            ).scalars().all()
            ctx["corroboration"] = len(types)
            ctx["related_types"] = len({t for t in types if t})
    except Exception:
        pass

    # --- prevalence: how common is this EXACT signal across the fleet (7d)? ---
    # Only meaningful with a concrete indicator. Without one (many behaviour alerts
    # carry no ioc_value), counting by event_type alone would demote the entire
    # heuristic class once the fleet warms up — so we leave prevalence at 0 instead.
    try:
        if ioc_value:
            since7 = _utcnow() - timedelta(days=7)
            q = select(func.count()).select_from(models.Detection).where(
                models.Detection.event_type == event_type,
                models.Detection.ioc_value == ioc_value,
                models.Detection.ts >= since7,
            )
            ctx["prevalence"] = int(db.execute(q).scalar() or 0)
    except Exception:
        pass

    # --- cached IP reputation only (never a live/blocking lookup here) ---
    try:
        if ioc_type == "ip" and ioc_value and hasattr(models, "ThreatIntelCache"):
            c = db.get(models.ThreatIntelCache, ioc_value)
            if c is not None and getattr(c, "abuse_score", None) is not None:
                ctx["abuse_score"] = int(c.abuse_score)
    except Exception:
        pass

    return ctx


# --------------------------------------------------------------------------- verdict logic (pure)
def evaluate(det: dict, ctx: dict) -> dict:
    """Given a detection + gathered context, return the calibrated verdict.

    Pure and deterministic — no DB, no clock, no I/O — so it is unit-testable with
    synthetic context. Returns {verdict, severity, raw_severity, confidence, delta,
    review, reasons[...], version}."""
    raw = _rank(det.get("severity"))
    etype = (det.get("event_type") or "").upper()
    ioc_type = (ctx.get("ioc_type") or "").lower()
    details = ctx.get("details") or {}
    path = ctx.get("path") or ""
    plow = path.lower()
    _raw_beh = details.get("all_behaviors")
    behaviors = [str(b) for b in _raw_beh] if isinstance(_raw_beh, list) else []  # coerce: attacker can't crash us
    signed = bool(details.get("signed"))
    proc_name = _basename(details.get("name") or details.get("process") or path)
    is_process = etype == "SUSPICIOUS_PROCESS" or ioc_type == "process"
    raw_conf = int(det.get("confidence", 0) or 0)

    reasons: list[dict] = []
    delta = 0.0
    floor: float | None = None
    ceil: float | None = None
    force_benign = False
    review = False

    def add(signal: str, effect: float, note: str) -> None:
        nonlocal delta
        delta += effect
        reasons.append({"signal": signal, "effect": round(effect, 2), "note": note})

    # "Soft" negatives are keyed off endpoint-self-reported fields (signed / path /
    # process name) — trustworthy on a healthy host, forgeable on a compromised one.
    # We collect them separately and CAP their total, so a compromised agent can lower
    # priority by at most two tiers and can never bury a real CRITICAL at the bottom.
    soft: list[dict] = []

    def soft_neg(signal: str, effect: float, note: str) -> None:
        soft.append({"signal": signal, "effect": round(effect, 2), "note": note})

    # An "exact" match is precise evidence: a file hash, or an indicator already in
    # our IOC store. Precise evidence is trusted and never suppressed by heuristics.
    known_bad = ctx.get("ioc_conf") is not None
    exact = known_bad or ioc_type == "hash" or "HASH" in etype
    # "Strong" escalation is REPUTATION only — the one evidence class an attacker on a
    # compromised endpoint cannot fake in their own favour. Only this may lift a
    # calibrated alert to CRITICAL; host context can raise, but caps at HIGH.
    strong_up = ctx.get("vt_malicious", 0) >= 3 or (ctx.get("ioc_conf") or 0) >= 80 or \
        (ctx.get("abuse_score") or 0) >= 75

    # ---- reputation / precision (raise) ----
    if known_bad:
        floor = max(floor or 0, 3)  # a known IOC is never below HIGH
        add("known-bad-ioc", +1.0,
            f"indicator is in the threat-intel store (confidence {ctx.get('ioc_conf')})")
        if ctx.get("vt_malicious", 0) >= 3:
            add("vt-corroborated", +0.5,
                f"corroborated by {ctx['vt_malicious']} VirusTotal engines")
    if ctx.get("abuse_score") is not None and ctx["abuse_score"] >= 75:
        add("abuse-reputation", +0.5, f"AbuseIPDB confidence {ctx['abuse_score']}")
        floor = max(floor or 0, 3)
    if ioc_type == "hash" or "HASH" in etype:
        floor = max(floor or 0, raw)
        reasons.append({"signal": "exact-hash", "effect": 0,
                        "note": "exact file-hash match — precise, not downgraded"})

    # ---- known-good context (lower) ----
    # own-infra / allowlist are server-side facts (an operator decision / our own IP
    # set), not endpoint self-report — so they remain hard suppressors.
    if ctx.get("own_infra"):
        force_benign = True
        add("own-infra", -4.0, "own infrastructure — never a threat")
    if ctx.get("allowlisted"):
        force_benign = True
        add("allowlisted", -4.0, "operator-allowlisted indicator")
    # signed / path / process-name are endpoint self-report → soft (capped) negatives,
    # and never applied to a precise (exact/known-bad) detection.
    if signed and not exact:
        soft_neg("signed", -1.0, "reported as an Authenticode-signed binary")
    if _trusted_path(plow) and not exact:
        soft_neg("system-path", -1.5, "file reported in a system/package location")
    proc_stem = proc_name[:-4] if proc_name.endswith(".exe") else proc_name
    if is_process and not exact and (proc_stem in _TRANSPORT or proc_name in _TRANSPORT):
        soft_neg("transport-tool", -2.0,
                 "SSH/remote-exec transport tool — its argv carries a command the child "
                 "process runs and is scanned separately")

    # ---- asset/location risk (raise) ----
    if path and _temp_path(plow) and not _trusted_path(plow):
        add("writable-path", +1.0, "file/executable in a user-writable or temporary path")
    if not path and is_process:
        add("no-image", +0.5, "process image path unavailable (possible deleted/hollowed image)")
    if len({b for b in behaviors}) > 1:
        add("multi-behaviour", +0.5,
            f"{len(set(behaviors))} distinct suspicious behaviours on one process")

    # ---- corroboration ----
    # A modest, capped nudge — many distinct alert types on one host in 24h is weak
    # evidence (baseline telemetry alone clears 3), so it can only ADD half a tier and,
    # via the CRITICAL cap below, can never by itself confirm. Its opposite, a lone
    # low-confidence heuristic, is eased down.
    if ctx.get("related_types", 0) >= 4:
        add("corroborated", +0.5,
            f"{ctx['related_types']} distinct alert types on this host in 24h")
    elif ctx.get("corroboration", 0) <= 1 and not exact and raw >= 3 and raw_conf < 60:
        add("isolated", -1.0, "isolated, low-confidence heuristic with no corroboration")

    # ---- prevalence / environmental noise ----
    prev = ctx.get("prevalence", 0)
    if not exact and prev >= _PREV_NOISE:
        add("high-prevalence", -1.5,
            f"very common signal ({prev} identical events in 7d) — environmental noise")
    elif not exact and prev >= _PREV_COMMON:
        add("prevalent", -0.75, f"frequently-seen signal ({prev} identical events in 7d)")

    # ---- Bangladesh-conservative for IP indicators (per operator policy) ----
    country = (details.get("country") or details.get("geo") or details.get("geo_country") or "").upper()
    if ioc_type == "ip" and country in ("BD", "BANGLADESH") and not known_bad and ctx.get("vt_malicious", 0) < 3:
        ceil = 2 if ceil is None else min(ceil, 2)
        review = True
        add("bd-conservative", 0.0,
            "Bangladesh IP with weak reputation — capped at MEDIUM and flagged for "
            "manual review (per operator policy)")

    # ---- apply the capped soft (self-reported) negatives ----
    soft_sum = sum(s["effect"] for s in soft)
    if soft_sum < -2.0:
        soft.append({"signal": "soft-neg-cap", "effect": round(-2.0 - soft_sum, 2),
                     "note": "self-reported context capped at a two-tier downgrade "
                             "(anti-evasion: a compromised agent cannot bury a real alert)"})
        soft_sum = -2.0
    delta += soft_sum
    reasons.extend(soft)

    # ---- resolve severity ----
    score = raw + delta
    if floor is not None:
        score = max(score, floor)
    # CRITICAL cap: context heuristics may raise priority but must NOT manufacture the
    # top tier — only hard reputation can. This keeps CRITICAL meaningful and stops a
    # busy host from turning every HIGH into CRITICAL.
    if not (known_bad or strong_up):
        score = min(score, max(float(raw), 3.0))
    if ceil is not None:
        score = min(score, ceil)
    score = max(0.0, min(4.0, score))
    cal_rank = int(round(score))

    # Conflict: an allowlisted / own-infra indicator that ALSO matches high-confidence
    # threat intel. Don't silently suppress it — surface it for the operator to review.
    allowlist_conflict = force_benign and known_bad and strong_up
    if allowlist_conflict:
        review = True
        reasons.append({"signal": "allowlist-conflict", "effect": 0,
                        "note": "allowlisted/own-infra indicator also matches high-confidence "
                                "threat intel — review the allowlist entry"})

    # ---- verdict ----
    if force_benign and not allowlist_conflict:
        # operator-allowlisted / own infrastructure — definitively benign.
        verdict = "benign-noise"
        cal_rank = 0
    elif known_bad and (strong_up or cal_rank >= 4):
        verdict = "confirmed-threat"
    elif known_bad:
        verdict = "likely-threat"
    elif exact and cal_rank >= 3:
        # exact file-hash match against a known-bad signature — precise, real.
        verdict = "confirmed-threat" if strong_up else "likely-threat"
    elif cal_rank > raw:
        verdict = "confirmed-threat" if strong_up else "likely-threat"
    elif cal_rank < raw:
        # a genuine tier drop (negative evidence or a policy cap). If it was capped
        # for manual review (BD policy), the severity eases but a human still decides.
        verdict = "inconclusive" if review else "likely-noise"
    else:
        # kept at the triggered level with no decisive evidence either way — exactly
        # the case a human should eyeball. Fail-safe: keep the raw severity.
        verdict = "inconclusive"
        cal_rank = raw

    cal_sev = _name(cal_rank)

    # ---- confidence in the VERDICT (not the raw detector) ----
    if verdict == "benign-noise":
        conf = 95
    elif verdict == "confirmed-threat":
        conf = min(97, 70 + (ctx.get("ioc_conf") or 0) // 5 + 5 * min(ctx.get("related_types", 0), 4))
    elif verdict == "likely-noise":
        conf = min(90, 60 + int(abs(delta) * 10))
    elif verdict == "likely-threat":
        conf = 65
    else:  # inconclusive — the whole point is that we are NOT sure
        conf = 45

    if not reasons:
        reasons.append({"signal": "no-context", "effect": 0,
                        "note": "no distinguishing evidence found — kept at triggered severity for human review"})

    return {
        "verdict": verdict,
        "severity": cal_sev,
        "raw_severity": _name(raw),
        "confidence": conf,
        "delta": round(cal_rank - raw, 2),
        "review": review,
        "reasons": reasons,
        "version": CALIBRATION_VERSION,
    }


def calibrate(db, det: dict) -> dict:
    """Full pipeline: gather DB context, then render the analyst verdict.

    Never raises — on any internal error returns an `uncalibrated` result that keeps
    the raw severity, so a calibration bug can never drop or corrupt an ingest."""
    try:
        ctx = gather_context(db, det)
        return evaluate(det, ctx)
    except Exception as exc:  # bulletproof: calibration must never break ingest
        return {
            "verdict": "uncalibrated",
            "severity": det.get("severity") or "MEDIUM",
            "raw_severity": det.get("severity") or "MEDIUM",
            "confidence": int(det.get("confidence", 0) or 0),
            "delta": 0, "review": False,
            "reasons": [{"signal": "error", "effect": 0, "note": f"calibration skipped: {exc}"}],
            "version": CALIBRATION_VERSION,
        }
