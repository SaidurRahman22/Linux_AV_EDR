"""Control-plane settings (env-overridable). Prod = PostgreSQL; dev fallback = SQLite."""

from __future__ import annotations

import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))   # .../<repo>


class Settings:
    # PostgreSQL in production; set SENTINEL_DB_URL=sqlite:///./sentinel.db for local dev.
    DATABASE_URL: str = os.environ.get(
        "SENTINEL_DB_URL",
        "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel",
    )
    HOST: str = os.environ.get("SENTINEL_HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("SENTINEL_PORT", "8080"))

    # Directory of the self-contained dashboard (served at /).
    WEBUI_DIR: str = os.environ.get("SENTINEL_WEBUI", os.path.join(_REPO_ROOT, "webui"))

    # Threat-intel beacon.
    BEACON_INTERVAL: int = int(os.environ.get("SENTINEL_BEACON_INTERVAL", "3600"))  # seconds
    IOC_TTL_DAYS: int = int(os.environ.get("SENTINEL_IOC_TTL", "30"))
    BEACON_MAX_PER_SOURCE: int = int(os.environ.get("SENTINEL_BEACON_MAX", "500"))

    # Third-party feed API keys — PLACEHOLDERS. Provide via env when available.
    VT_API_KEY: str = os.environ.get("VT_API_KEY", "")               # VirusTotal
    ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "")  # AbuseIPDB
    OTX_API_KEY: str = os.environ.get("OTX_API_KEY", "")             # AlienVault OTX

    # VirusTotal free tier is rate-limited (4/min, 500/day) — enrich, don't harvest.
    VT_PER_RUN: int = int(os.environ.get("VT_PER_RUN", "6"))          # hashes verified per beacon run
    VT_DAILY_CAP: int = int(os.environ.get("VT_DAILY_CAP", "450"))    # stay under the 500/day quota
    VT_MIN_INTERVAL: float = float(os.environ.get("VT_MIN_INTERVAL", "16"))  # seconds (<=4/min)
    OTX_MAX: int = int(os.environ.get("OTX_MAX", "1000"))
    URLHAUS_MAX: int = int(os.environ.get("URLHAUS_MAX", "1500"))   # live malicious URLs to import
    ABUSEIPDB_MAX: int = int(os.environ.get("ABUSEIPDB_MAX", "2000"))   # blacklist size to import
    ABUSEIPDB_MIN_CONF: int = int(os.environ.get("ABUSEIPDB_MIN_CONF", "90"))
    # AbuseIPDB free tier is quota-limited: pulling the blacklist every hour trips
    # HTTP 429. The blacklist changes slowly, so gate it to a few pulls per day.
    ABUSEIPDB_INTERVAL_H: int = int(os.environ.get("ABUSEIPDB_INTERVAL_H", "12"))

    # Scheduled YARA-rule-repo sync (pull community rules into the signatures table).
    # Default OFF (SEN-014): community rules are a supply-chain surface — opt in explicitly.
    YARA_REPO_ENABLED: bool = os.environ.get("SENTINEL_YARA_REPO", "0") not in ("0", "false", "")
    # GitHub "contents" API URL(s) of a directory of .yar files, comma-separated.
    YARA_REPO_API: str = os.environ.get(
        "SENTINEL_YARA_REPO_API",
        "https://api.github.com/repos/Yara-Rules/rules/contents/malware",
    )
    YARA_REPO_MAX_FILES: int = int(os.environ.get("SENTINEL_YARA_REPO_MAX_FILES", "80"))
    YARA_REPO_MAX_RULES: int = int(os.environ.get("SENTINEL_YARA_REPO_MAX_RULES", "500"))
    YARA_REPO_INTERVAL_H: int = int(os.environ.get("SENTINEL_YARA_REPO_INTERVAL_H", "24"))
    GITHUB_TOKEN: str = os.environ.get("GITHUB_TOKEN", "")           # optional: higher rate limit

    # Simple shared-secret for agent/producer calls (mTLS comes in a later increment).
    API_TOKEN: str = os.environ.get("SENTINEL_API_TOKEN", "")        # operator token; empty = open (dev only)
    # Separate lower-privilege token for AGENT calls (enroll/heartbeat/policy/detections/
    # download). Falls back to API_TOKEN if unset. A leaked agent token can NOT drive the
    # operator/destructive endpoints (SEN-001 RBAC-lite).
    AGENT_TOKEN: str = os.environ.get("SENTINEL_AGENT_TOKEN", "")
    # Fail-closed switch: when set, the app refuses to start without an API_TOKEN.
    REQUIRE_AUTH: bool = os.environ.get("SENTINEL_REQUIRE_AUTH", "0") not in ("0", "false", "")
    # CORS: comma-separated exact origins allowed to call the API cross-origin.
    # Empty (default) = no cross-origin access (the dashboard is served same-origin).
    CORS_ORIGINS: str = os.environ.get("SENTINEL_CORS_ORIGINS", "")

    @property
    def repo_root(self) -> str:
        return _REPO_ROOT


settings = Settings()
