#!/usr/bin/env bash
# Provision the eBPF behavioural tracer for the Padakhep Sentinel Linux agent.
# The agent orchestrates bpftrace (iovisor/bpftrace): the eBPF program runs IN-KERNEL.
# BASE mode (what this script enables) traces only RARE, high-signal syscalls with no
# argv join — ptrace(POKETEXT/POKEDATA) process injection and init/finit_module kernel-
# module loads — so the agent stays a thin, ~0% CPU consumer on any host. exec/argv +
# memfd tracing is a separate opt-in (SENTINEL_EBPF_EXEC=1) for lower-exec endpoints.
# This script just provides the engine (like install_suricata.sh provides Suricata).
#
#   sudo bash av_agent/install_ebpf.sh              # base mode (light, recommended)
#   SENTINEL_EBPF_EXEC=1 sudo -E bash av_agent/install_ebpf.sh   # also trace exec/argv
#
# Requirements: a modern kernel with BTF (/sys/kernel/btf/vmlinux) — standard on
# Ubuntu 20.10+/Debian 11+/RHEL 8.2+. The agent must run as root (it already does).
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root:  sudo bash $0" >&2
  exit 1
fi

echo "[*] Installing bpftrace..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y bpftrace
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y bpftrace
elif command -v yum >/dev/null 2>&1; then
  yum install -y bpftrace
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm bpftrace
else
  echo "[!] No supported package manager found — install 'bpftrace' manually, then re-run." >&2
  exit 1
fi

command -v bpftrace >/dev/null 2>&1 || { echo "[!] bpftrace not on PATH after install" >&2; exit 1; }

echo "[*] Checking kernel BTF (required for CO-RE tracing)..."
if [ ! -e /sys/kernel/btf/vmlinux ]; then
  echo "[!] /sys/kernel/btf/vmlinux missing — your kernel lacks BTF. Install the matching" >&2
  echo "    kernel headers / a BTF-enabled kernel, or the tracer cannot attach." >&2
  exit 1
fi

echo "[*] Smoke-testing bpftrace..."
if ! bpftrace -e 'BEGIN { exit(); }' >/dev/null 2>&1; then
  echo "[!] bpftrace failed to run (needs CAP_BPF/CAP_SYS_ADMIN + a compatible kernel)." >&2
  exit 1
fi

# Enable the engine for the agent. If the systemd unit exists, drop in the env var;
# otherwise print how to set it. Default is OFF, so this opt-in step is what turns it on.
UNIT="$(systemctl show -p FragmentPath --value sentinel-av 2>/dev/null || true)"
if [ -n "${UNIT:-}" ] && systemctl list-unit-files sentinel-av.service >/dev/null 2>&1; then
  mkdir -p /etc/systemd/system/sentinel-av.service.d
  {
    echo "[Service]"
    echo "Environment=SENTINEL_EBPF=1"
    if [ "${SENTINEL_EBPF_EXEC:-0}" != "0" ]; then echo "Environment=SENTINEL_EBPF_EXEC=1"; fi
  } > /etc/systemd/system/sentinel-av.service.d/ebpf.conf
  systemctl daemon-reload
  systemctl restart sentinel-av
  if [ "${SENTINEL_EBPF_EXEC:-0}" != "0" ]; then
    echo "[+] Enabled SENTINEL_EBPF=1 + SENTINEL_EBPF_EXEC=1 (exec/argv tracing) and restarted sentinel-av."
  else
    echo "[+] Enabled SENTINEL_EBPF=1 (light base mode) and restarted sentinel-av."
  fi
else
  echo "[+] bpftrace ready. Enable the tracer by setting  SENTINEL_EBPF=1  in the agent's"
  echo "    environment (e.g. a systemd drop-in) and restarting it."
fi

echo "[+] Done. The agent's eBPF engine emits producer=ebpf detections (console: SRS Logs)."
echo "    Base mode = ptrace-injection + kernel-module-load (light). Add exec/argv + memfd"
echo "    with SENTINEL_EBPF_EXEC=1. Tune SENTINEL_EBPF_MAX_PER_SEC (backpressure, default 300)."
