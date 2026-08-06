#!/usr/bin/env bash
# Padakhep Sentinel — one-step Linux endpoint installer.
# Installs the AV/EDR agent (systemd service) AND the Suricata IDS/IPS engine +
# rules AND the eBPF behavioural tracer in a single run — run it once and the
# endpoint is fully armed. After this the Sentinel agent fully controls Suricata
# (pushes rules, reads eve.json, drives detection/prevention) and runs the light
# eBPF syscall tracer (bpftrace) in base mode.
#
#   sudo bash av_agent/install_linux.sh [CONTROL_PLANE_URL] [AGENT_NAME]
#   e.g.  sudo bash av_agent/install_linux.sh http://192.168.39.32:8080 web-prod-01
#
# Opt-outs / opt-ins (env):
#   SENTINEL_EBPF=0        skip the eBPF tracer entirely
#   SENTINEL_EBPF_EXEC=1   also trace exec/argv + memfd (heavier; for endpoints)
#
# (Windows endpoints use sentinel-av.exe instead — see docs/DEPLOYMENT_WINDOWS.md.)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Please run as root:  sudo bash $0" >&2; exit 1; }

API="${1:-${SENTINEL_API:-http://192.168.39.32:8080}}"
NAME="${2:-${AGENT_NAME:-$(hostname)}}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"          # repo root (parent of av_agent/)
SCAN_DIRS="${SENTINEL_SCAN_DIRS:-/tmp:/var/tmp:/home:/opt/suspect}"

echo "[*] Padakhep Sentinel — Linux install"
echo "    control plane : $API"
echo "    agent name    : $NAME"
echo "    repo root     : $ROOT"

# 1) Python 3 (the agent is stdlib-only — no pip packages)
if ! command -v python3 >/dev/null 2>&1; then
  echo "[*] Installing python3 ..."
  if command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y python3
  elif command -v dnf >/dev/null 2>&1; then dnf install -y python3
  elif command -v yum >/dev/null 2>&1; then yum install -y python3; fi
fi

# 2) Suricata engine + ET Open ruleset (agent takes over control afterwards)
echo "[*] Installing the Suricata IDS/IPS engine ..."
bash "$ROOT/av_agent/install_suricata.sh" \
  || echo "  ! Suricata install had issues — the agent will report 'not installed'; re-run install_suricata.sh later."

# 2b) eBPF behavioural tracer (bpftrace). Base mode is light (~0.4% CPU) so it's on by
#     default; enablement is via the env file below, so we only PROVISION the engine here.
EBPF="${SENTINEL_EBPF:-1}"
EBPF_EXEC="${SENTINEL_EBPF_EXEC:-0}"
if [ "$EBPF" != "0" ]; then
  echo "[*] Provisioning the eBPF tracer (bpftrace) ..."
  SENTINEL_EBPF_PROVISION_ONLY=1 bash "$ROOT/av_agent/install_ebpf.sh" \
    || { echo "  ! eBPF provisioning had issues (kernel BTF / bpftrace) — disabling it for this host."; EBPF=0; }
fi

# 3) Agent configuration
umask 077
cat >/etc/sentinel-av.env <<EOF
SENTINEL_API=$API
AGENT_NAME=$NAME
SENTINEL_SCAN_DIRS=$SCAN_DIRS
SENTINEL_API_TOKEN=${SENTINEL_API_TOKEN:-}
SENTINEL_EBPF=$EBPF
SENTINEL_EBPF_EXEC=$EBPF_EXEC
EOF
chown root:root /etc/sentinel-av.env 2>/dev/null || true
chmod 600 /etc/sentinel-av.env
mkdir -p /var/lib/sentinel-av /var/log/sentinel-suricata

# 4) systemd service (runs as root: needs auth.log, /proc, nftables, Suricata)
sed "s|__ROOT__|$ROOT|g" "$ROOT/av_agent/deploy/sentinel-av.service" \
  > /etc/systemd/system/sentinel-av.service
systemctl daemon-reload
systemctl enable --now sentinel-av
sleep 3

echo
systemctl --no-pager --full status sentinel-av 2>/dev/null | head -5 || true
echo "[+] Done — the agent is running and will appear in the console Fleet within ~1 min."
if [ "$EBPF" != "0" ]; then
  echo "[+] eBPF tracer: ON (base mode — ptrace-injection + kernel-module load)$([ "$EBPF_EXEC" != "0" ] && echo " + exec/argv+memfd")."
else
  echo "[+] eBPF tracer: off."
fi
echo "[+] Turn on IDS or IPS for this host from the console → IDS / IPS page."
