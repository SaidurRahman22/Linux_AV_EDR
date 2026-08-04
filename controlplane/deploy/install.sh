#!/usr/bin/env bash
#
# install.sh — install the Padakhep Sentinel control plane (API + beacon) on the
# Wazuh VM. Runs from a git checkout of this repo.
#
#   sudo bash controlplane/deploy/install.sh
#
# Creates a venv, installs deps, sets up PostgreSQL (if available), writes an env
# file, and installs+starts the sentinel-api and sentinel-beacon systemd services.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV="$REPO_ROOT/controlplane/.venv"
ENVFILE="/etc/padakhep-sentinel.env"
PORT="${SENTINEL_PORT:-8080}"
DB_NAME="sentinel"; DB_USER="sentinel"; DB_PASS="${SENTINEL_DB_PASS:-sentinel}"

log()  { printf '\033[1;36m[cp-install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[cp-install]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[cp-install] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash controlplane/deploy/install.sh)"
PY="$(command -v python3 || true)"; [ -x "$PY" ] || die "python3 not found"

# --- venv + deps ---
log "creating venv at $VENV"
"$PY" -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
log "installing requirements (fastapi, uvicorn, sqlalchemy, psycopg, pydantic)"
"$VENV/bin/pip" install -q -r "$REPO_ROOT/controlplane/requirements.txt"

# --- PostgreSQL (best-effort; falls back to a note if psql absent) ---
DB_URL="postgresql+psycopg://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}"
if command -v psql >/dev/null 2>&1; then
  log "ensuring PostgreSQL role + database exist"
  sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 \
    || sudo -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';" || warn "role create skipped"
  sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 \
    || sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" || warn "db create skipped"
else
  warn "psql not found — install PostgreSQL and create db '${DB_NAME}', or set SENTINEL_DB_URL"
  warn "for a quick start you can use SQLite: SENTINEL_DB_URL=sqlite:///$REPO_ROOT/controlplane/sentinel.db"
fi

# --- env file (don't clobber) ---
if [ -f "$ENVFILE" ]; then
  warn "keeping existing $ENVFILE"
else
  log "writing $ENVFILE"
  cat > "$ENVFILE" <<EOF
SENTINEL_DB_URL=${SENTINEL_DB_URL:-$DB_URL}
SENTINEL_PORT=${PORT}
SENTINEL_WEBUI=${REPO_ROOT}/webui
SENTINEL_BEACON_INTERVAL=3600
SENTINEL_IOC_TTL=30
SENTINEL_BEACON_MAX=500
# --- third-party feed API keys (placeholders; fill when available) ---
VT_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
# --- optional shared secret for agent/producer POSTs (empty = open) ---
SENTINEL_API_TOKEN=
EOF
fi

# --- systemd units ---
render() { sed -e "s|__ROOT__|$REPO_ROOT|g" -e "s|__VENV__|$VENV|g" -e "s|__ENVFILE__|$ENVFILE|g" "$1" > "$2"; }
log "installing systemd units"
render "$REPO_ROOT/controlplane/deploy/sentinel-api.service"    /etc/systemd/system/sentinel-api.service
render "$REPO_ROOT/controlplane/deploy/sentinel-beacon.service" /etc/systemd/system/sentinel-beacon.service
systemctl daemon-reload
systemctl enable --now sentinel-api.service
systemctl enable --now sentinel-beacon.service
sleep 2

log "done."
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

------------------------------------------------------------------
 Padakhep Sentinel control plane is up.

   Dashboard : http://${IP:-<vm-ip>}:${PORT}/
   API docs  : http://${IP:-<vm-ip>}:${PORT}/docs
   Health    : curl http://localhost:${PORT}/healthz
   Logs      : journalctl -u sentinel-api -f   |   journalctl -u sentinel-beacon -f

 The beacon fills the IOC database on a schedule; the dashboard shows it live.
 To trigger a collection now:
   sudo systemctl start sentinel-beacon      # (already looping)
 Config/keys: $ENVFILE  (add VT/AbuseIPDB/OTX keys, then: systemctl restart sentinel-beacon)
------------------------------------------------------------------
EOF
