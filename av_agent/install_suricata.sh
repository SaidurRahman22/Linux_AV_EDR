#!/usr/bin/env bash
# Install the Suricata engine so the Padakhep Sentinel agent can run IDS/IPS.
# The agent orchestrates Suricata (starts it in IDS af-packet or IPS NFQUEUE mode
# and forwards eve.json alerts); this script just provides the engine + rules.
#
#   sudo bash av_agent/install_suricata.sh
#
# After this, set the endpoint to IDS or IPS from the console (IDS / IPS page).
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root:  sudo bash $0" >&2
  exit 1
fi

echo "[*] Installing Suricata + suricata-update ..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y suricata suricata-update || apt-get install -y suricata
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y suricata
elif command -v yum >/dev/null 2>&1; then
  yum install -y suricata
elif command -v zypper >/dev/null 2>&1; then
  zypper --non-interactive install suricata
else
  echo "Unsupported package manager — install 'suricata' manually, then re-run." >&2
  exit 1
fi

echo "[*] Fetching the ET Open ruleset (suricata-update) ..."
if command -v suricata-update >/dev/null 2>&1; then
  suricata-update --no-test -q || suricata-update || true
else
  echo "    (suricata-update not present; the agent will use whatever rules Suricata ships)"
fi

echo "[*] Disabling the distro Suricata service — the Sentinel agent manages the engine ..."
systemctl disable --now suricata >/dev/null 2>&1 || true

mkdir -p /var/log/sentinel-suricata

echo
echo "[+] Suricata installed:"
suricata -V 2>/dev/null || true
RULES=$( { cat /var/lib/suricata/rules/suricata.rules 2>/dev/null; cat /etc/suricata/rules/suricata.rules 2>/dev/null; } | grep -cvE '^\s*(#|$)' || true )
echo "[+] Rules available: ${RULES:-0}"
echo "[+] Done. Open the console → IDS / IPS and switch this host to IDS (safe) or IPS (inline)."
