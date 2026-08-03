#!/usr/bin/env bash
#
# uninstall.sh - stop and remove the wazuh-rulegen service.
#   sudo deploy/uninstall.sh [--purge]
#
# --purge also deletes /opt/wazuh-rulegen and /etc/wazuh-rulegen.
# Rules already promoted into /var/ossec/etc/rules are left untouched.
#
set -euo pipefail

APP="wazuh-rulegen"
UNIT="/etc/systemd/system/${APP}.service"
PURGE="no"
for a in "$@"; do [ "$a" = "--purge" ] && PURGE="yes"; done

log() { printf '\033[1;32m[uninstall]\033[0m %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "please run as root" >&2; exit 1; }

log "stopping service + feed-update timer"
systemctl stop "${APP}.service" 2>/dev/null || true
systemctl disable "${APP}.service" 2>/dev/null || true
systemctl disable --now "${APP}-feedupdate.timer" 2>/dev/null || true
systemctl stop "${APP}-feedupdate.service" 2>/dev/null || true
rm -f "$UNIT" "/etc/systemd/system/${APP}-feedupdate.service" "/etc/systemd/system/${APP}-feedupdate.timer"
systemctl daemon-reload 2>/dev/null || true

if [ "$PURGE" = "yes" ]; then
  log "purging /opt/wazuh-rulegen and /etc/wazuh-rulegen"
  rm -rf /opt/wazuh-rulegen /etc/wazuh-rulegen /var/log/${APP}.log
else
  log "left /opt/wazuh-rulegen and /etc/wazuh-rulegen in place (use --purge to remove)"
fi
log "done. (any rules already promoted into /var/ossec/etc/rules were NOT removed)"
