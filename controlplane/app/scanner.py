"""Detection Funnel Scanner — score every detection instance for precision vs. noise.

The "funnel" idea: raw telemetry -> rules -> alerts -> real incidents. A good rule
sits high in the funnel (precise, rarely wrong); a noisy rule floods the bottom.
This scanner grades each saved detection instance (log rule, YARA signature,
behaviour rule, Suricata rule) on a 0-100 **precision score** and classifies it:

    GOLDEN (>=80)  — precise, correlated, ATT&CK-mapped, low false-positive risk
    GOOD   (60-79) — solid; keep
    REVIEW (40-59) — needs tuning
    NOISY  (<40)   — over-broad or high-firing; likely drowns real events

Scoring blends *static* quality (specificity, breadth self-check, correlation,
ATT&CK mapping, severity) with *behavioural* evidence (how often it has actually
fired, and at what confidence, from the detections table). The output feeds a
short pass/failed view and a "golden rules" list. Read-only and side-effect free.
"""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import func, select

from . import models
from .sigma import verify_pattern

_SEV_W = {"CRITICAL": 40, "HIGH": 32, "MEDIUM": 22, "LOW": 12}


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _specificity(pattern: str) -> int:
    """+points for distinct, meaningful literal tokens (a proxy for precision)."""
    lits = set(re.findall(r"[A-Za-z0-9_./\\:-]{4,}", pattern or ""))
    noise = {"http", "https", "true", "false", "null", "name", "path"}
    lits -= noise
    return min(22, len(lits) * 4)


def _fire_stats(db, rule_name: str, days: int = 30):
    """(fire_count, avg_confidence) for a rule over the window (from detections)."""
    since = _now() - timedelta(days=days)
    rows = db.execute(
        select(models.Detection.confidence, models.Detection.event)
        .where(models.Detection.ts >= since)).all()
    n, conf_sum = 0, 0
    for confidence, event in rows:
        det = ((event or {}).get("event", {}) or {}).get("details", {}) if isinstance(event, dict) else {}
        if isinstance(det, dict) and det.get("rule") == rule_name:
            n += 1
            conf_sum += int(confidence or 0)
    return n, (conf_sum / n if n else 0)


def _verdict(score: int) -> str:
    if score >= 80:
        return "golden"
    if score >= 60:
        return "good"
    if score >= 40:
        return "review"
    return "noisy"


def _score_log_rule(db, r) -> dict:
    reasons, score = [], _SEV_W.get(str(r.severity).upper(), 18)
    sp = _specificity(r.pattern)
    score += sp
    if sp >= 12:
        reasons.append(f"+{sp} specific literals")
    else:
        reasons.append("broad pattern (few literals)")
    ok, why = verify_pattern(r.pattern, r.source)
    if not ok:
        score -= 40
        reasons.append("FP self-check FAILED: " + why)
    else:
        score += 8
        reasons.append("+8 passed FP self-check")
    if int(getattr(r, "threshold", 1) or 1) > 1:
        score += 10
        reasons.append("+10 threshold-correlated")
    if getattr(r, "mitre", None):
        score += 6
        reasons.append("+6 ATT&CK-mapped")
    if not getattr(r, "verified", True):
        score -= 15
        reasons.append("staged/unverified")
    fires, avg_conf = _fire_stats(db, r.name)
    if fires == 0:
        reasons.append("no fires in 30d (untested / telemetry off)")
    elif fires > 200:
        pen = min(35, int((fires - 200) / 40) + 10)
        score -= pen
        reasons.append(f"-{pen} high volume ({fires}/30d — noisy)")
    else:
        bonus = min(12, 4 + fires // 10)
        score += bonus
        reasons.append(f"+{bonus} healthy volume ({fires}/30d, avg conf {int(avg_conf)})")
    score = max(0, min(100, score))
    return {"kind": "log_rule", "name": r.name, "platform": r.platform, "source": r.source,
            "severity": r.severity, "score": score, "verdict": _verdict(score),
            "fires_30d": fires, "reasons": reasons}


def _score_signature(db, s) -> dict:
    reasons, score = [], _SEV_W.get(str(s.severity).upper(), 18)
    strings = re.findall(r'"((?:[^"\\]|\\.)+)"', s.content or "")
    long = [t for t in strings if len(t) >= 6]
    score += min(28, len(long) * 8)
    if not long:
        score -= 20
        reasons.append("no long string literals (broad)")
    else:
        reasons.append(f"+{min(28, len(long)*8)} {len(long)} specific string(s)")
    if re.search(r"all of them|and", s.content or ""):
        score += 8
        reasons.append("+8 multi-condition")
    if getattr(s, "mitre", None):
        score += 6
        reasons.append("+6 ATT&CK-mapped")
    score = max(0, min(100, score))
    return {"kind": "signature", "name": s.name, "platform": "-", "source": "yara",
            "severity": s.severity, "score": score, "verdict": _verdict(score),
            "fires_30d": None, "reasons": reasons}


def _score_behavior(db, b) -> dict:
    reasons, score = [], _SEV_W.get(str(b.severity).upper(), 18)
    rule = b.rule or {}
    pat = rule.get("pattern", "") if isinstance(rule, dict) else ""
    if pat:
        sp = _specificity(pat)
        score += sp
        ok, why = verify_pattern("(?i)" + pat, "")
        if not ok:
            score -= 30
            reasons.append("FP self-check: " + why)
        else:
            score += 8
            reasons.append(f"+{sp} specific, +8 passed FP self-check")
    if isinstance(rule, dict) and rule.get("type") == "threshold":
        score += 8
        reasons.append("+8 threshold-correlated")
    if getattr(b, "mitre", None):
        score += 6
    score = max(0, min(100, score))
    return {"kind": "behavior", "name": b.name, "platform": "-", "source": "behavior",
            "severity": b.severity, "score": score, "verdict": _verdict(score),
            "fires_30d": None, "reasons": reasons}


def _score_suricata(db, r) -> dict:
    reasons, score = [], 30
    raw = r.raw or ""
    has_content = bool(re.search(r"\bcontent:", raw))
    has_pcre = bool(re.search(r"\bpcre:", raw))
    if has_content and has_pcre:
        score += 30
        reasons.append("+30 content + pcre (very specific)")
    elif has_content or has_pcre:
        score += 22
        reasons.append("+22 content/pcre match (specific)")
    else:
        score -= 15
        reasons.append("no content/pcre (broad)")
    if re.search(r"\b(reference|metadata|classtype):", raw):
        score += 6
        reasons.append("+6 curated (reference/classtype)")
    if (r.action or "").lower() in ("drop", "reject"):
        score += 6
    if r.msg and len(r.msg) > 12:
        score += 8
    if not r.enabled:
        reasons.append("disabled (not distributed)")
    score = max(0, min(100, score))
    return {"kind": "suricata", "name": (r.msg or ("sid:" + str(r.sid)))[:60], "platform": "-",
            "source": r.source or "suricata", "severity": "-", "score": score,
            "verdict": _verdict(score), "fires_30d": None, "reasons": reasons}


def run_scan(db, targets=None, sample_suricata: int = 300) -> dict:
    """Score the requested target types. Returns a structured report."""
    targets = targets or ["log_rule", "signature", "behavior", "suricata"]
    items = []
    if "log_rule" in targets:
        for r in db.execute(select(models.LogRule)).scalars().all():
            items.append(_score_log_rule(db, r))
    if "signature" in targets:
        for s in db.execute(select(models.Signature)).scalars().all():
            items.append(_score_signature(db, s))
    if "behavior" in targets:
        for b in db.execute(select(models.Behavior)).scalars().all():
            items.append(_score_behavior(db, b))
    if "suricata" in targets:
        rows = db.execute(select(models.SuricataRule).where(models.SuricataRule.enabled.is_(True))
                          .limit(sample_suricata)).scalars().all()
        for r in rows:
            items.append(_score_suricata(db, r))
    items.sort(key=lambda x: -x["score"])
    passed = [i for i in items if i["score"] >= 60]
    failed = [i for i in items if i["score"] < 60]
    golden = [i for i in items if i["verdict"] == "golden"]
    by_kind = {}
    for i in items:
        by_kind.setdefault(i["kind"], {"total": 0, "passed": 0})
        by_kind[i["kind"]]["total"] += 1
        if i["score"] >= 60:
            by_kind[i["kind"]]["passed"] += 1
    return {
        "ran_at": _now().isoformat(),
        "summary": {"total": len(items), "passed": len(passed), "failed": len(failed),
                    "golden": len(golden), "by_kind": by_kind},
        "golden": golden[:50],
        "failed": failed[:50],
        "items": items,
    }
