"""Parse/load YARA + behavior rule packs from av_content/ into the database.

YARA files may contain a shared `import "..."` preamble followed by many
`rule <name> { ... }` blocks. We split them into standalone signatures (each
carrying the preamble so it compiles on its own) and upsert by name.
"""

from __future__ import annotations

import json
import os
import re

from sqlalchemy import select

from . import models

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
CONTENT_DIR = os.environ.get("SENTINEL_CONTENT", os.path.join(_REPO_ROOT, "av_content"))

_SEV_MAP = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}


def _norm_sev(s: str) -> str:
    return _SEV_MAP.get((s or "").strip().lower(), "HIGH")


def split_yara(text: str) -> list:
    """Return [(name, standalone_source, severity, mitre_list), ...] for one file."""
    seen_imp, imp_lines = set(), []
    for imp in re.findall(r'(?m)^\s*import\s+"[^"]+"', text):
        key = imp.strip()
        if key not in seen_imp:
            seen_imp.add(key)
            imp_lines.append(key)
    imports = "\n".join(imp_lines)
    # rule blocks start at column 0 with `rule <ident>`; slice between starts
    starts = [m.start() for m in re.finditer(r"(?m)^rule\s+\w", text)]
    out = []
    for i, s in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        block = text[s:end].rstrip()
        nm = re.match(r"rule\s+(\w+)", block)
        if not nm:
            continue
        name = nm.group(1)
        sev = _norm_sev((re.search(r'severity\s*=\s*"([^"]*)"', block) or [None, ""])[1])
        mitre_raw = (re.search(r'mitre\s*=\s*"([^"]*)"', block) or [None, ""])[1]
        mitre = [t.strip() for t in re.split(r"[,\s]+", mitre_raw) if t.strip()]
        source = ((imports + "\n\n") if imports else "") + block + "\n"
        out.append((name, source, sev, mitre))
    return out


def _blob_text() -> str:
    """Decode the AV-safe rule pack blob (gzip+base64) to plaintext YARA, or ''.

    The rules are shipped as an opaque blob so endpoint antivirus doesn't
    quarantine the repo/files for containing malware signature strings.
    """
    import base64
    import gzip
    blob = os.path.join(CONTENT_DIR, "rulepack.b64")
    if not os.path.isfile(blob):
        return ""
    try:
        with open(blob, "rb") as f:
            return gzip.decompress(base64.b64decode(f.read())).decode("utf-8", "replace")
    except Exception:
        return ""


def _iter_yara_texts(directory: str) -> list:
    """Rule text sources: prefer the packed blob, else raw .yar files."""
    blob = _blob_text()
    if blob:
        return [("pack:rulepack", blob)]
    out = []
    if os.path.isdir(directory):
        for fn in sorted(os.listdir(directory)):
            if fn.endswith(".yar"):
                try:
                    with open(os.path.join(directory, fn), encoding="utf-8") as f:
                        out.append(("pack:" + fn[:-4], f.read()))
                except OSError:
                    continue
    return out


def load_yara_dir(db, directory: str | None = None) -> int:
    directory = directory or os.path.join(CONTENT_DIR, "yara")
    have = set(db.execute(select(models.Signature.name)).scalars().all())
    added = 0
    for src, text in _iter_yara_texts(directory):
        for name, source, sev, mitre in split_yara(text):
            if name in have:
                continue
            have.add(name)
            db.add(models.Signature(name=name, kind="yara", content=source,
                                    severity=sev, mitre=mitre, source=src))
            added += 1
    if added:
        db.commit()
    return added


def _behaviors_items() -> list:
    """Behavior patterns: prefer the AV-safe blob, else the plaintext JSON."""
    import base64
    import gzip
    blob = os.path.join(CONTENT_DIR, "behaviors.b64")
    if os.path.isfile(blob):
        try:
            with open(blob, "rb") as f:
                return json.loads(gzip.decompress(base64.b64decode(f.read())).decode("utf-8"))
        except Exception:
            return []
    path = os.path.join(CONTENT_DIR, "behaviors.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def load_behaviors_json(db, path: str | None = None) -> int:
    items = _behaviors_items()
    if not items:
        return 0
    have = set(db.execute(select(models.Behavior.name)).scalars().all())
    added = 0
    for b in items:
        name = b.get("name")
        rule = b.get("rule")
        if not name or not isinstance(rule, dict) or name in have:
            continue
        have.add(name)
        db.add(models.Behavior(name=name, description=b.get("description", ""), rule=rule,
                               severity=_norm_sev(b.get("severity", "MEDIUM")),
                               mitre=b.get("mitre", []) or []))
        added += 1
    if added:
        db.commit()
    return added


def load_all(db) -> dict:
    return {"yara": load_yara_dir(db), "behaviors": load_behaviors_json(db)}
