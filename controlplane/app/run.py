"""Entrypoint that launches the control-plane API, enabling TLS when configured.

SEN-006: when SENTINEL_SSL_CERT and SENTINEL_SSL_KEY are set the API serves HTTPS
directly; otherwise it serves plaintext HTTP (dev, or behind a TLS-terminating
reverse proxy). New installs are pointed here so TLS is a one-env-var switch.

    python -m controlplane.app.run
"""
from __future__ import annotations

import uvicorn

from .config import settings


def main() -> None:
    kwargs = {"host": settings.HOST, "port": settings.PORT}
    if settings.SSL_CERT and settings.SSL_KEY:
        kwargs["ssl_certfile"] = settings.SSL_CERT
        kwargs["ssl_keyfile"] = settings.SSL_KEY
        print(f"control plane serving HTTPS on {settings.HOST}:{settings.PORT}", flush=True)
    else:
        print(f"control plane serving HTTP on {settings.HOST}:{settings.PORT} "
              "(set SENTINEL_SSL_CERT/KEY for TLS, or terminate TLS at a proxy)", flush=True)
    uvicorn.run("controlplane.app.main:app", **kwargs)


if __name__ == "__main__":
    main()
