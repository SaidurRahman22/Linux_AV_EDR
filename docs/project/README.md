# Padakhep Sentinel — Documentation

> **Documentation set:** v1.5.0 · **Last updated:** 2026-08-05 · **Status:** Current
> **Applies to:** Control plane v1.5.0 · Agents — Linux `0.3.14`, Windows `0.3.13-win`

Padakhep Sentinel is a self-hosted **AV + EDR platform** for Linux and Windows endpoints,
built around a central control plane, stdlib-only endpoint agents, a 24/7 threat-intelligence
beacon, an embedded Suricata IDS/IPS orchestrator, and a single-file web console — designed to
sit alongside a **Wazuh** SIEM deployment rather than replace it.

This is the authoritative, versioned project documentation set (docs/project/). It is **versioned** (see
[Versioning](#versioning) and [CHANGELOG.md](CHANGELOG.md)) and each document carries a header
stating the version, status, and the component versions it applies to.

---

## Documentation map

| Document | What it covers | Audience |
|---|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, components, data flows, trust boundaries, threat model | Engineers, architects |
| [API_REFERENCE.md](API_REFERENCE.md) | Control-plane HTTP API, the agent enrollment/heartbeat protocol, auth model | Integrators, agent devs |
| [DETECTIONS.md](DETECTIONS.md) | Log-based IDS detection coverage (ATT&CK matrix, ~75 rules) | Detection engineers / SOC |
| [SECURITY.md](SECURITY.md) | Security controls, cryptography, and the SEN-001…019 remediation register | Security engineers, auditors |
| [OPERATIONS.md](OPERATIONS.md) | Runbooks: deploy, TLS, feeds, NIDS, allow-list, agent rollout & signing, incident actions | Operators / SOC |
| [DEPLOYMENT.md](../DEPLOYMENT.md) | Linux control-plane + agent install (baseline) | Operators |
| [DEPLOYMENT_WINDOWS.md](../DEPLOYMENT_WINDOWS.md) | Windows agent packaging & install | Operators |
| [IDS_IPS.md](../IDS_IPS.md) | Suricata IDS/IPS design notes | Engineers |
| [../deploy/wazuh/README.md](../../deploy/wazuh/README.md) | Wazuh integration (forward AV/EDR detections into Wazuh) | Operators |
| [SECURITY_AUDIT.html](../SECURITY_AUDIT.html) | The original 10-agent security audit report (point-in-time snapshot) | Security |
| [SRS_Padakhep_Sentinel_v3.md](../SRS_Padakhep_Sentinel_v3.md) | Software Requirements Specification (v3) | All |
| [CHANGELOG.md](CHANGELOG.md) | Version history of the platform and this documentation set | All |

> **Living vs. point-in-time.** `ARCHITECTURE`, `API_REFERENCE`, `SECURITY`, and `OPERATIONS`
> are **living documents** — they track the current state of `main`. `SECURITY_AUDIT.html` and
> the `SRS_*` files are **point-in-time** records and are not edited retroactively; their findings
> are carried forward in `SECURITY.md`'s remediation register.

---

## What the platform is (one screen)

- **Control plane** — a FastAPI service (`controlplane/app`) backed by PostgreSQL (SQLite in dev).
  It stores IOCs, signatures, agents, detections, blocklists, allow-list, Suricata rules, and the
  audit trail; distributes policy to agents; and serves the web console.
- **Endpoint agents** — pure-stdlib Python (`av_agent/agent.py` for Linux, `av_agent/agent_win.py`
  compiled to `sentinel-av.exe` for Windows). They enroll, pull policy, scan (hash + YARA + behaviour),
  watch the filesystem in realtime, enforce a firewall blocklist / port closures / network isolation,
  orchestrate Suricata, run a general **log-based IDS** (multi-source decoder + distributed ruleset),
  and self-update from Ed25519-signed builds.
- **Threat-intel beacon** — a 24/7 worker (`controlplane/beacon`) that pulls IOCs from open and keyed
  feeds and scrapes open Suricata rulesets.
- **Wazuh rule generator** — `wazuh_rulegen`, which turns collected intel into Wazuh detection rules.
- **Web console** — a single self-contained file (`webui/index.html`) rendering the whole dashboard.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full picture.

---

## Versioning

The platform follows **Semantic Versioning** (`MAJOR.MINOR.PATCH`) at two levels:

1. **Platform / documentation version** — tracked in [CHANGELOG.md](CHANGELOG.md). The documentation
   set version at the top of each file matches the platform release it describes. `v1.0.0` is the
   first consolidated release, covering everything on `main` as of 2026-08-05.
2. **Agent build versions** — each agent embeds its own `VERSION` string (Linux `0.3.14`, Windows
   `0.3.11-win`). Agents are shipped as **Ed25519-signed** builds; the control-plane manifest advertises
   the current version, sha256, and signature per platform. Bumping an agent = edit `VERSION`, sign
   (`tools/sign_agent.py`), deploy the build + `.sig`, then push-update from the console.

**Change process:** every functional or security change lands on `main` with a descriptive commit,
and any change that affects behaviour, the API, or the security posture is reflected in the relevant
living document **and** recorded in `CHANGELOG.md` under the next version. Documentation edits ship in
the same commit as the code they describe wherever practical.

---

## Conventions used in these docs

- **Endpoint hosts** in examples: control plane `192.168.39.32:8080`; three managed endpoints
  (`wazuh-vm-av`, `scweb`, `windows-endpoint-01`) are used illustratively.
- **Secrets are never committed.** SSH/sudo credentials, API tokens, agent secrets, and the Ed25519
  private key (`tools/keys/`) live outside the repo. Examples use placeholders.
- Code references use repo-relative paths, e.g. `controlplane/app/main.py`.
