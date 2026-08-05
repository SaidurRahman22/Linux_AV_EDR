# Security Model & Remediation Register

> **Documentation set:** v1.3.0 · **Last updated:** 2026-08-05 · **Status:** Current (living)
> **Applies to:** Control plane v1.3.0 · Agents — Linux `0.3.13`, Windows `0.3.12-win`

This is the authoritative, living record of Padakhep Sentinel's security posture: the controls in
force, the cryptography they rely on, and the status of every finding from the security audit
(`SECURITY_AUDIT.html`, a point-in-time snapshot that is **not** edited retroactively).

---

## 1. Security model

Padakhep Sentinel is an EDR: its agents run as **root/SYSTEM** and can quarantine files, rewrite host
firewalls, and execute self-updates. That power defines the threat model — the highest-value target is
the **control plane → agent** channel, because whoever controls it controls every endpoint at the
highest privilege. The design therefore prioritises, in order:

1. **Code authenticity** — an agent must never run code that isn't signed by the offline key, even if
   the server or network is fully compromised. *(SEN-002 — in force everywhere.)*
2. **Identity** — the server must know which agent it is talking to, and an agent's record must not be
   hijackable. *(SEN-007 — per-agent secret, in force fleet-wide.)*
3. **Least authority** — a leaked agent token cannot drive destructive operator actions. *(SEN-001 —
   RBAC-lite.)*
4. **Input distrust** — community rules and IOCs are untrusted input to root engines and are
   validated/sanitised before use. *(SEN-005, SEN-009.)*
5. **Availability safety** — response actions cannot silently strand the fleet. *(SEN-010, partial.)*
6. **Confidentiality/integrity in transit** — TLS and read-auth, enforced when configured. *(SEN-006,
   SEN-008.)*

### Backward-compatibility stance
Auth (tokens) and TLS are implemented but **enforced only when configured**, so the existing fleet
keeps running during migration. New installs are **fail-closed** (the installer provisions a random DB
password + API token, writes a `chmod 600` env file, and sets `SENTINEL_REQUIRE_AUTH=1`). The
per-agent secret (SEN-007) is enforced *unconditionally* but uses a protocol-version gate +
trust-on-first-use so no legacy agent is ever locked out.

---

## 2. Cryptographic controls

| Control | Algorithm | Where | Notes |
|---|---|---|---|
| **Agent build signing** | Ed25519 (pure-stdlib impl) | `tools/sign_agent.py` (sign) → embedded verifier in both agents | Private key lives offline in `tools/keys/` (git-ignored, never on the server). Public key pinned in the agents. Manifest carries `<build>.sig`; `self_update` requires a valid signature over the exact downloaded bytes. |
| **Build integrity** | SHA-256 | manifest + agents | Downloaded build must match the advertised sha256 **and** verify against the signature. |
| **Per-agent secret** | 256-bit random, stored as SHA-256 | `agents.agent_secret` | Issued once at enrolment (`proto>=2`); sent as `X-Agent-Secret`; compared in constant time. |
| **Token comparison** | `hmac.compare_digest` | `main.py:_bearer_in`, `_agent_secret_ok` | Constant-time, avoids timing oracles (SEN-019). |
| **Transport** | TLS 1.2+ (opt-in) | uvicorn `--ssl-*` via `controlplane.app.run`; agent verifying `ssl` context | Agent verifies the server cert against system CAs or a pinned `SENTINEL_CA_CERT`. PostgreSQL `sslmode` via `SENTINEL_DB_SSLMODE`. |

**Why a home-grown Ed25519?** The agents are constrained to the standard library (no pip). The signer
and the embedded verifier are a public-domain reference Ed25519 implemented on Python's big-int `pow()`
— used **only** for signature verification of our own builds against a pinned key, not for protecting
data in transit (TLS does that).

---

## 3. Remediation register (SEN-001 … SEN-019)

Status legend: **Fixed** · **Partial** (meaningful mitigation in place, hardening remains) · **Open**
(tracked, not yet started).

| ID | Sev | Finding (abridged) | Status | Where / how |
|----|-----|--------------------|--------|-------------|
| SEN-001 | Critical | Control plane unauthenticated by default; destructive endpoints open | **Fixed** | Uniform `/api/*` gate + agent/operator token split + `SENTINEL_REQUIRE_AUTH` fail-closed |
| SEN-002 | Critical | Agent self-update = fleet root RCE; no code signing | **Fixed** | Offline Ed25519 signing; pinned key; signed-only self-update |
| SEN-003 | Critical | Systemic stored XSS in the console | **Fixed** | Global `esc()` on sinks + CSP/X-Frame/nosniff headers + server-side field sanitisation |
| SEN-004 | Critical | SRS §8 safe-response controls unenforced | **Partial** | Allow-list precedence now enforced (allow-listed IPs removed from distributed blocklist); over-broad-block guards. TTL / confidence-gating / kill-switch / HITL still open |
| SEN-005 | Critical | Unvalidated Suricata rules to a root engine | **Fixed** | Server `sanitize_suricata_rules()` (deny lua/dataset/filestore, force `alert`, size caps) + agent `suricata -T` with keep-last-good |
| SEN-006 | High | No transport security (plaintext HTTP) | **Fixed (opt-in)** | HTTPS launcher, agent cert verify/pin, PG sslmode. Live fleet still HTTP by choice |
| SEN-007 | High | Unauthenticated enroll/heartbeat; record hijack | **Fixed** | Per-agent secret required on heartbeat/policy/re-enroll; enroll can't overwrite an identity without it |
| SEN-008 | High | All read endpoints unauthenticated | **Fixed** | Middleware gates all `/api/*` reads (when a token is set); `/api/sync/policy` scoped to the authenticated agent; `/healthz` exempt |
| SEN-009 | High | nftables injection via unvalidated blocklist entries | **Fixed** | Agent validates every entry with `ipaddress` before nftables; drops malformed / over-broad / control-plane-covering |
| SEN-010 | High | Response actions can strand the fleet | **Partial** | Server + agent reject `/0`, over-broad CIDRs, and ranges covering the control plane. Isolation TTL / SSH break-glass / dead-man's-switch still open |
| SEN-011 | High | Windows ProgramData dir unhardened + Defender-excluded | **Open** | DACL hardening + scoped exclusion planned |
| SEN-012 | High | Client-attributed, mutable audit records | **Partial** | Agent events now bound to an authenticated identity (SEN-007); device name server-stamped. Append-only + hash-chaining still open |
| SEN-013 | High | NIDS mode change triggers root package install | **Open** | Move Suricata to out-of-band provisioning; agent should only report "engine missing" |
| SEN-014 | High | Unpinned deps + community feeds enabled by default | **Partial** | YARA-repo sync default **off**; scraped Suricata rules default `enabled=False`. Hash-locked dependency pinning still open |
| SEN-015 | Medium | SSRF in feed/rule collectors | **Open** | Scheme/host allow-list on collectors planned |
| SEN-016 | Medium | Weak default DB creds + world-readable env | **Fixed** | Installer generates a random DB password + API token; env file `chmod 600` |
| SEN-017 | Medium | Services run as root/SYSTEM, no systemd hardening | **Partial** | `NoNewPrivileges=true` on the API unit. Broader sandboxing / privilege separation open |
| SEN-018 | Medium | Permissive wildcard CORS | **Fixed** | CORS restricted to `SENTINEL_CORS_ORIGINS` (none by default; console is same-origin) |
| SEN-019 | Low | Robustness cluster (timing, ReDoS, update-URL confusion, rollback) | **Partial** | Constant-time compare + agent builds the update URL locally + self-update compile-check rollback. Remaining items tracked |

**Scorecard:** of 19 findings — **11 Fixed**, **5 Partial**, **3 Open**. All 5 Criticals are Fixed or
Partial; SEN-004 is the only Critical still Partial (safe-response guardrails).

---

## 4. Operational security notes

- **Secrets never enter the repo.** SSH/sudo creds, API/agent tokens, and the Ed25519 private key
  (`tools/keys/`) are git-ignored. The env file is root-owned `chmod 600` — ad-hoc reads require sudo.
- **Enabling auth fleet-wide** requires setting the *same* token on every agent host **and** the
  console, then flipping the server token — see [OPERATIONS.md](OPERATIONS.md#enabling-authentication).
- **Enabling TLS** is a per-env switch (`SENTINEL_SSL_CERT/KEY`) plus pointing agents at `https://`
  with a pinned CA — see [OPERATIONS.md](OPERATIONS.md#enabling-tls).
- **Rolling a signed agent build**: edit `VERSION` → `python tools/sign_agent.py sign …` → deploy the
  build **and** its `.sig` → push-update from the console. An agent will refuse an unsigned/mismatched
  build and keep running the old one.

---

## 5. Reporting

Security issues should be handled privately by the maintainer. This document and
[CHANGELOG.md](CHANGELOG.md) are updated whenever a finding's status changes or a new control ships.
