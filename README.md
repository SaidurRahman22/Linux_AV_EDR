# Padakhep Sentinel — Installers

This branch contains **only** the install/deploy files, kept separate from the
full project on `main`. Check it out to deploy an endpoint or the server without
pulling the whole codebase. It is generated from `main`'s install files — it is
not a fork of the application code.

## Linux endpoint (AV/EDR agent + Suricata IDS/IPS)
```bash
sudo bash av_agent/install_linux.sh [CONTROL_PLANE_URL] [AGENT_NAME]
```
- `av_agent/install_linux.sh` — installs the agent (systemd) **and** the Suricata engine
- `av_agent/install_suricata.sh` — installs just the Suricata engine + ET Open rules
- `av_agent/deploy/sentinel-av.service` — systemd unit

## Windows endpoint
- `av_agent/build_windows.ps1` — build `sentinel-av.exe` (PyInstaller)

Run `sentinel-av.exe` once and it self-installs (silent autostart). The prebuilt
binary is published via **GitHub Releases** (binaries aren't tracked in git).
See `docs/DEPLOYMENT_WINDOWS.md`.

## Control plane (API + dashboard + 24/7 threat-intel beacon)
```bash
sudo bash controlplane/deploy/install.sh
```
- `controlplane/deploy/install.sh`, `sentinel-api.service`, `sentinel-beacon.service`

## Wazuh rule generator (on the Wazuh manager)
- `deploy/install.sh`, `deploy/promote.sh`, `deploy/uninstall.sh` + systemd unit/timer

## Docs
- `docs/DEPLOYMENT.md` — control-plane + Linux AV runbook
- `docs/DEPLOYMENT_WINDOWS.md` — Windows agent install
- `docs/IDS_IPS.md` — Suricata IDS/IPS setup

---
_Maintained from `main`; re-synced whenever an installer changes._
