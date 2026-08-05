#!/usr/bin/env bash
#
# Wire Padakhep Sentinel AV/EDR detections into a co-located Wazuh manager.
# Run as root ON the Wazuh manager host. Idempotent (safe to re-run).
#
#   sudo bash deploy/wazuh/install_wazuh_integration.sh
#
# What it does:
#   1. Ensures the JSON log the control plane writes exists and is world-readable.
#   2. Installs padakhep_rules.xml into Wazuh's custom rules.
#   3. Adds a <localfile> block (log_format json) to ossec.conf, once.
#   4. Restarts wazuh-manager.
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="${SENTINEL_WAZUH_LOG:-/var/log/padakhep-sentinel/sentinel.json}"
OSSEC="${WAZUH_HOME:-/var/ossec}"

if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi
if [ ! -d "$OSSEC" ]; then echo "Wazuh not found at $OSSEC (set WAZUH_HOME)"; exit 1; fi

# 1. log file the control plane appends to
mkdir -p "$(dirname "$LOG")"
[ -f "$LOG" ] || : > "$LOG"
chmod 644 "$LOG"
echo "[*] log file: $LOG"

# 2. custom rules (readable by the wazuh service account)
cp "$HERE/padakhep_rules.xml" "$OSSEC/etc/rules/padakhep_rules.xml"
chmod 660 "$OSSEC/etc/rules/padakhep_rules.xml"
chown root:wazuh "$OSSEC/etc/rules/padakhep_rules.xml" 2>/dev/null \
  || chown root:ossec "$OSSEC/etc/rules/padakhep_rules.xml" 2>/dev/null || true
echo "[*] installed rules -> $OSSEC/etc/rules/padakhep_rules.xml (ids 100200-100299)"

# 3. localfile block (idempotent)
if grep -qF "$LOG" "$OSSEC/etc/ossec.conf"; then
  echo "[*] ossec.conf already reads $LOG"
else
  cp "$OSSEC/etc/ossec.conf" "$OSSEC/etc/ossec.conf.padakhep.bak"
  cat >> "$OSSEC/etc/ossec.conf" <<EOF

<ossec_config>
  <!-- Padakhep Sentinel AV/EDR detections -->
  <localfile>
    <log_format>json</log_format>
    <location>$LOG</location>
  </localfile>
</ossec_config>
EOF
  echo "[*] added <localfile> for $LOG (backup: ossec.conf.padakhep.bak)"
fi

# 4. reload
systemctl restart wazuh-manager
echo "[+] done — Sentinel detections now flow into Wazuh (rule ids 100200-100299)."
