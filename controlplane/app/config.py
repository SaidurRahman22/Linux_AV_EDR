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
    OTX_MAX: int = int(os.environ.get("OTX_MAX", "400"))

    # Simple shared-secret for agent/producer calls (mTLS comes in a later increment).
    API_TOKEN: str = os.environ.get("SENTINEL_API_TOKEN", "")        # empty = open (dev)

    @property
    def repo_root(self) -> str:
        return _REPO_ROOT


settings = Settings()
