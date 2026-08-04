#!/usr/bin/env bash
#
# install.sh - install wazuh_rulegen as a background systemd service on a
#              Wazuh manager (Linux).
#
# What it does:
#   * copies the tool to /opt/wazuh-rulegen
#   * writes a production config to /etc/wazuh-rulegen/config.json
#   * installs & starts the wazuh-rulegen systemd service (runs `run` daemon)
#
# Safety: generated rules are written to the STAGING dir /opt/wazuh-rulegen/output
# and are NOT loaded by the manager automatically. Review them, then use
# deploy/promote.sh to copy a reviewed file into /var/ossec/etc/rules and restart.
#
set -euo pipefail

APP="wazuh-rulegen"
PREFIX="/opt/wazuh-rulegen"
CONFDIR="/etc/wazuh-rulegen"
UNIT="/etc/systemd/system/${APP}.service"
ALERTS="/var/ossec/logs/alerts/alerts.json"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[install] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "please run as root (sudo ./deploy/install.sh)"

# --- python ---
PY="$(command -v python3 || true)"
[ -n "$PY" ] || PY="/var/ossec/framework/python/bin/python3"   # Wazuh's bundled python
[ -x "$PY" ] || die "python3 not found; install python3 (>=3.8)"
"$PY" - <<'PYV' || die "python >= 3.8 required"
import sys; sys.exit(0 if sys.version_info[:2] >= (3, 8) else 1)
PYV
log "using python: $PY"

# --- service account: prefer the wazuh (or ossec) user so it can read alerts ---
SVC_USER="root"; SVC_GROUP="root"
for u in wazuh ossec; do
  if id "$u" >/dev/null 2>&1; then SVC_USER="$u"; SVC_GROUP="$u"; break; fi
done
log "service account: ${SVC_USER}:${SVC_GROUP}"

[ -f "$ALERTS" ] || warn "alerts file not found yet at $ALERTS (ok - the daemon will wait for it)"

# --- lay down files ---
# Safe to re-run as an UPDATER: code is overwritten; existing feed files and
# config are preserved (so auto-updated IOCs are not clobbered on upgrade).
log "installing to $PREFIX"
mkdir -p "$PREFIX" "$PREFIX/output" "$PREFIX/data/threat_intel" "$CONFDIR"
rm -rf "$PREFIX/wazuh_rulegen"                      # drop stale modules / __pycache__
cp -r "$REPO_ROOT/wazuh_rulegen" "$PREFIX/"
cp    "$REPO_ROOT/run.py"        "$PREFIX/" 2>/dev/null || true
cp    "$REPO_ROOT/deploy/promote.sh" "$PREFIX/" 2>/dev/null && chmod +x "$PREFIX/promote.sh" || true
[ -f "$REPO_ROOT/README.md" ] && cp "$REPO_ROOT/README.md" "$PREFIX/" || true
# feed files: only seed if missing; never overwrite an existing (possibly updated) feed
for f in "$REPO_ROOT"/data/threat_intel/*; do
  [ -e "$f" ] || continue
  dst="$PREFIX/data/threat_intel/$(basename "$f")"
  if [ -f "$dst" ]; then warn "keeping existing feed: $(basename "$f")"; else cp "$f" "$dst"; fi
done

# --- config (don't clobber an existing one) ---
if [ -f "$CONFDIR/config.json" ]; then
  warn "keeping existing config: $CONFDIR/config.json"
else
  log "writing config: $CONFDIR/config.json"
  cat > "$CONFDIR/config.json" <<JSON
{
  "alerts_file": "$ALERTS",
  "alerts_log_fallback": "/var/ossec/logs/alerts/alerts.log",
  "ip_feeds": ["$PREFIX/data/threat_intel/malicious_ips.txt"],
  "hash_feeds": ["$PREFIX/data/threat_intel/malicious_hashes.txt"],
  "ip_allowlist": ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "output_dir": "$PREFIX/output",
  "state_file": "$PREFIX/output/.wazuh_rulegen_state.json",
  "id_base": 100000,
  "id_max": 120000,
  "write_cdb_lists": true,
  "poll_interval": 2.0,
  "flush_interval": 15.0,
  "detectors": {
    "bruteforce":        { "enabled": true, "min_auth_failures": 6, "min_flood_events": 50, "timeframe_seconds": 300, "per_user_spray_users": 5, "level": 12 },
    "malicious_ip":      { "enabled": true, "high_severity_level": 10, "volume_threshold": 100, "level": 12 },
    "malicious_artifact":{ "enabled": true, "detect_registry_persistence": false, "detect_suspicious_paths": false, "level": 12 }
  }
}
JSON
fi

# --- ownership ---
chown -R "${SVC_USER}:${SVC_GROUP}" "$PREFIX" "$CONFDIR" 2>/dev/null || true
touch /var/log/${APP}.log && chown "${SVC_USER}:${SVC_GROUP}" /var/log/${APP}.log || true

# --- systemd units (daemon + feed-update timer) ---
render_unit() {  # <src> <dest>
  sed -e "s|__USER__|${SVC_USER}|g" -e "s|__GROUP__|${SVC_GROUP}|g" -e "s|__PY__|${PY}|g" \
      "$1" > "$2"
}
log "installing systemd unit: $UNIT"
render_unit "$REPO_ROOT/deploy/wazuh-rulegen.service" "$UNIT"
render_unit "$REPO_ROOT/deploy/wazuh-rulegen-feedupdate.service" "/etc/systemd/system/${APP}-feedupdate.service"
cp "$REPO_ROOT/deploy/wazuh-rulegen-feedupdate.timer" "/etc/systemd/system/${APP}-feedupdate.timer"

systemctl daemon-reload
systemctl enable "${APP}.service" >/dev/null 2>&1 || true
systemctl restart "${APP}.service"
# feed auto-updater timer (every 6h). Disable with: systemctl disable --now ${APP}-feedupdate.timer
systemctl enable "${APP}-feedupdate.timer" >/dev/null 2>&1 || true
systemctl start "${APP}-feedupdate.timer" || true
sleep 1

log "done."
echo
systemctl --no-pager --full status "${APP}.service" | sed -n '1,8p' || true
cat <<EOF

------------------------------------------------------------------
 wazuh_rulegen is now running in the background.

   logs      : journalctl -u ${APP} -f   (or /var/log/${APP}.log)
   config    : $CONFDIR/config.json
   generated : $PREFIX/output/wazuh_rulegen_generated_rules.xml   (STAGING)
   feeds     : auto-refreshed every 6h by ${APP}-feedupdate.timer
               (run now: sudo systemctl start ${APP}-feedupdate.service)

 The generated rules are NOT active yet. Review the staging file, then run:

   sudo $PREFIX/promote.sh

 to copy the reviewed rules into /var/ossec/etc/rules and restart the manager.
------------------------------------------------------------------
EOF
