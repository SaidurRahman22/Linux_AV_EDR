#!/usr/bin/env bash
#
# Enable auditd telemetry for Padakhep Sentinel's log-IDS engine (Linux).
# Run as root on each Linux endpoint. Idempotent.
#
#   sudo bash deploy/auditd/install_auditd.sh
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi

# 1. ensure auditd is present
if ! command -v auditctl >/dev/null 2>&1; then
  echo "[*] installing auditd"
  (apt-get update -y && apt-get install -y auditd) 2>/dev/null \
    || dnf install -y audit 2>/dev/null || yum install -y audit 2>/dev/null || {
      echo "could not install auditd automatically; install the 'auditd'/'audit' package"; exit 1; }
fi

# 2. drop our rules and (re)load
install -m 640 "$HERE/padakhep-auditd.rules" /etc/audit/rules.d/padakhep.rules
systemctl enable --now auditd 2>/dev/null || service auditd start 2>/dev/null || true
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/padakhep.rules 2>/dev/null || true
echo "[*] loaded rules with keys:"; auditctl -l | grep -o 'key=sentinel_[a-z_]*' | sort -u | sed 's/^/    /'

# 3. the agent tails /var/log/audit/audit.log (source "auditd") automatically.
echo "[+] done — auditd events now feed the log-IDS 'auditd' rules."
