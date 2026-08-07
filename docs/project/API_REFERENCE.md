# Control-Plane API Reference

> **Documentation set:** v1.11.0 · **Last updated:** 2026-08-07 · **Status:** Current (living)
> **Applies to:** Control plane v1.11.0 · Agents — Linux `0.4.8`, Windows `0.5.2-win`

All routes are served by `controlplane/app/main.py` under `http(s)://<host>:8080`. JSON in/out.

---

## 1. Authentication model

Two credentials, checked by a single middleware over `/api/*`:

- **Operator token** (`SENTINEL_API_TOKEN`) — full access, required for all state-changing/"operator"
  routes. Presented as `Authorization: Bearer <token>`.
- **Agent token** (`SENTINEL_AGENT_TOKEN`, falls back to the operator token) — accepted **only** on the
  agent-protocol routes below, never on operator routes (SEN-001 RBAC-lite).
- **Per-agent secret** (`X-Agent-Secret`) — a per-agent credential minted at enrolment and required on
  that agent's heartbeat / policy-sync / re-enrolment (SEN-007), independent of the tokens.

**When no operator token is configured, the `/api/*` gate is open** (development / the current live
fleet). The per-agent secret check is always active but is trust-on-first-use for `proto>=2` agents so
legacy agents are never locked out. `/healthz` and `/` (console) are always reachable.

Agent-protocol routes (accept the agent token): `POST /api/enroll`,
`POST /api/agents/{id}/heartbeat`, `POST /api/detections`, `GET /api/sync/policy`,
`GET /api/nids/ruleset`, `GET /api/agent/manifest`, `GET /api/agent/download/{platform}`.

Security headers (CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`) are stamped on every response.

---

## 2. Agent protocol (the enrolment/heartbeat lifecycle)

```
enroll(proto:2)  ──▶  { agent_id, agent_secret? }        # secret returned once, then stored by the agent
      │
      ├─ heartbeat(X-Agent-Secret)  ──▶  { isolate, blocked, closed_ports, nids_mode, update?, rescan_ports? }
      ├─ GET /api/sync/policy(X-Agent-Secret)  ──▶  { iocs, signatures, behaviors, blocked_ips, allowlist_ips, log_rules, closed_ports, rootkit_artifacts?, bad_drivers?, bad_driver_hashes? (windows: LOLDrivers BYOVD) }
      ├─ GET /api/nids/ruleset  ──▶  { version, ruleset }   # sanitised; agent runs `suricata -T` before load
      ├─ POST /api/detections   ──▶  persists v3 events (device_name stamped from the agent record)
      └─ self-update: GET /api/agent/manifest ─▶ download build ─▶ verify sha256 + Ed25519 sig ─▶ re-exec
```

**`POST /api/enroll`** — body `{name, ip, os, kernel, version, agent_id?, proto}`.
- First contact (or a `proto>=2` legacy migration): the server mints a secret and returns
  `agent_secret` once. The agent persists it and sends it as `X-Agent-Secret` thereafter.
- Re-enrol of an identity that already has a secret **requires** the matching `X-Agent-Secret` (else
  `403`). The operator-assigned **name is never overwritten** on re-enrol (rename is authoritative);
  `ip/os/kernel/version` are refreshed.

**`POST /api/agents/{id}/heartbeat`** — telemetry up (cpu/mem/disk, `ports`, `nids_status`, `version`);
directives down. Requires `X-Agent-Secret` once the agent has one.

---

## 3. Route catalogue (49 routes)

Legend: 🔒 = operator-gated (requires the operator token when auth is configured); 🤖 = agent-protocol
route (accepts the agent token / uses the per-agent secret); open reads are gated only when a token is set.

### Health & console
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/healthz` | `healthz` | Always open; liveness probe |
| GET | `/` | `dashboard_root` | Serves the single-file web console |

### Fleet & agents
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/api/agents` | `list_agents` | Fleet inventory + telemetry + manifest |
| POST 🤖 | `/api/enroll` | `enroll` | Enrolment + per-agent secret issuance |
| POST 🤖 | `/api/agents/{id}/heartbeat` | `heartbeat` | Telemetry/directives; secret-bound |
| POST 🔒 | `/api/agents/{id}/rename` | `rename_agent` | Authoritative rename; propagates to detections |
| GET | `/api/groups` | `list_groups` | Device groups + live device-count (also in `/api/agents` + `/api/dashboard`) |
| POST 🔒 | `/api/groups` · `/api/groups/{id}/rename` | `create_group` / `rename_group` | Create / rename an organizational device group (unique name) |
| DELETE 🔒 | `/api/groups/{id}` | `delete_group` | Delete a group; its devices are un-grouped (never removed) |
| POST 🔒 | `/api/agents/{id}/group` · `/api/groups/{id}/members` | `set_agent_group` / `set_group_members` | Assign one device (`{group_id}`, null clears) / bulk-assign many (`{agent_ids}`) |
| DELETE 🔒 | `/api/agents/{id}` | `remove_agent` | Remove/decommission an agent record (prunes stale/duplicate; keeps detection history) |
| POST 🔒 | `/api/agents/{id}/isolate` · `/unisolate` | `isolate_agent` / `unisolate_agent` | Network quarantine (guarded) |
| POST 🔒 | `/api/agents/{id}/update` · `/update/cancel` | `request_update` / `cancel_update` | Push a signed build / cancel |
| POST 🔒 | `/api/agents/update-all` | `request_update_all` | Fleet-wide update |
| GET 🤖 | `/api/agent/manifest` | `agent_manifest` | Current build per platform (version, sha256, signature) |
| GET 🤖 | `/api/agent/download/{platform}` | `agent_download` | Signed build download |

### Policy, IOCs, signatures, behaviours
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET 🤖 | `/api/sync/policy` | `sync_policy` | Agent policy; scoped to the authenticated agent (SEN-008) |
| GET / POST 🔒 | `/api/iocs` | `list_iocs` / `add_iocs` | Indicators (true totals in `/api/dashboard`) |
| GET / POST 🔒 | `/api/signatures` | `list_signatures` / `add_signature` | YARA/regex signatures |
| GET | `/api/behaviors` | `list_behaviors` | Behavioural rules |

### Detections & audit
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/api/detections` | `list_detections` | Detection + audit trail; each row carries `verdict`, `calibrated_severity`, `calibration{score,delta,confidence,reasons[]}` |
| POST 🔒🤖 | `/api/detections` | `ingest_detections` | v3 events; device_name stamped from the agent record; **each event is calibrated at ingest** (analyst-in-a-box) |
| POST 🔒 | `/api/detections/{id}/recalibrate` | `recalibrate_detection` | Re-run the analyst-in-a-box on one alert |
| POST 🔒 | `/api/detections/recalibrate` | `recalibrate_recent` | Fold calibration over the backlog (`?limit=N`); returns before/after severity + verdict distribution |
| POST 🔒 | `/api/detections/{id}/acknowledge` | `acknowledge_detection` | Operator marks an alert triaged → it leaves the active-critical queue; `?ack=false` reverses it |

> **Calibration** (`controlplane/app/calibrate.py`): every detection is re-scored at ingest into a `verdict` (`confirmed-threat`/`likely-threat`/`inconclusive`/`likely-noise`/`benign-noise`) and a `calibrated_severity`, with the full rationale in `calibration.reasons[]`. Fail-safe (exact/known-bad never downgraded; unknown → `inconclusive` keeps raw; self-reported downgrades capped; only reputation reaches CRITICAL) — see DETECTIONS § *Alert calibration*.

### Response — blocklist & allow-list
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/api/blocked` | `list_blocked` | Active IP blocklist |
| POST 🔒 | `/api/blocked` · `/api/blocked/{id}/unblock` | `add_blocked` / `unblock_ip` | Guards reject `/0`, over-broad, control-plane CIDRs |
| GET | `/api/blocked/processes` | `list_blocked_processes` | Active blocked-process list |
| POST 🔒 | `/api/blocked/processes` · `/api/blocked/processes/{id}/release` | `add_blocked_process` / `release_blocked_process` | Block by `name`/`path`/`hash`; agents terminate matches (`PROCESS_BLOCKED`). Protected-process guard; release logs an audit event |
| GET | `/api/allowlist` | `list_allowlist` | IP/CIDR + trusted binaries |
| POST 🔒 | `/api/allowlist` | `add_allowlist` | Validates IP/CIDR & sha256 |
| DELETE 🔒 | `/api/allowlist/{id}` | `remove_allowlist` | |

### Ports
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/api/ports` · `/api/agents/{id}/ports` | `list_ports` / `agent_ports` | Observed listening sockets |
| POST 🔒 | `/api/agents/{id}/ports/close` · `/open` · `/scan` | `close_port` / `open_port` / `scan_ports` | Per-device firewall + on-demand scan |

### NIDS (Suricata)
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/api/nids` | `list_nids` | Per-agent NIDS mode/status |
| POST 🔒 | `/api/agents/{id}/nids` | `set_nids_mode` | OFF / IDS / IPS |
| GET | `/api/suricata-rules` | `list_suricata_rules` | Scraped/curated rules (true total + capped preview) |
| GET / POST 🔒 | `/api/nids/custom` | `get_custom_rules` / `set_custom_rules` | Operator rules — **sanitised** (SEN-005); `allow_drop` opt-in |
| GET 🤖 | `/api/nids/ruleset` | `nids_ruleset` | Merged, sanitised ruleset for agents |

### Log-based IDS rules
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/api/log-rules` | `list_log_rules` | Full log-IDS ruleset |
| POST 🔒 | `/api/log-rules` | `add_log_rule` | Add/update (regex validated); fields: source, pattern, entity_group, threshold, window_sec, severity, mitre, event_type |
| POST 🔒 | `/api/log-rules/{id}/toggle` | `toggle_log_rule` | Enable/disable |
| POST 🔒 | `/api/log-rules/sigma` | `import_sigma_rules` | Convert Sigma YAML → rules; FP self-check; noisy → staged |
| POST 🔒 | `/api/log-rules/{id}/verify` | `verify_log_rule` | Operator-promote a staged rule (returns the FP advisory) |
| DELETE 🔒 | `/api/log-rules/{id}` | `delete_log_rule` | Remove |

Enabled rules are distributed via `GET /api/sync/policy` (`log_rules`, scoped to the agent platform)
and shown in `/api/dashboard`. Agents compile each regex once and match decoded log lines locally.

**Rootcheck (host rootkit/anomaly detection).** Runs autonomously on the agent — there is no rule-set
to manage, so no dedicated endpoint. Findings are posted to `POST /api/detections` with
`producer=rootcheck` (filterable in *SRS Logs* → **ROOTCHECK**). Two **optional** policy fields let the
control plane extend the agent's embedded lists without a schema change: `rootkit_artifacts` (a list of
paths, any platform) and `bad_drivers` (a list of driver file names, Windows). Both default to empty in
`GET /api/sync/policy`; when absent the agent uses only its embedded curated defaults.

### Threat-intel feeds & stats
| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/api/stats` · `/api/dashboard` | `stats` / `dashboard_data` | Aggregates; dashboard carries true IOC totals (incl. `drivers` = LOLDrivers BYOVD hashes) + allow-list + feeds |
| GET / POST 🔒 | `/api/feeds/sync` | `sync_feeds_status` / `sync_feeds` | On-demand beacon pull + status |

IOC types: `ip`, `hash`, `domain`, `url`, and **`driver`** (LOLDrivers BYOVD SHA-256; `source=LOLDrivers`,
served to Windows agents as `bad_driver_hashes`, not in the general file-hash set).

### Detection Funnel Scanner (optional)
| Method | Path | Handler | Notes |
|---|---|---|---|
| POST 🔒 | `/api/scanner/run` | `scanner_run` | Score rules for precision; returns summary (incl. `duplicates`), golden, failed, duplicate groups |
| POST 🔒 | `/api/scanner/promote` | `scanner_promote` | **Enable** golden log-rules / signatures / behaviours so agents enforce them (read-only scan → production) |
| GET / POST 🔒 | `/api/scanner/tasks` · `/api/scanner/tasks/{id}/run` · `/api/scanner/runs` | scheduled scans + run history |

---

## 4. Conventions & limits

- List endpoints cap rows (e.g. IOCs 1,500/type, Suricata 500) and return a **true total** separately;
  the console shows "newest N of M".
- All agent-reported strings are sanitised server-side (control chars + `<>` stripped, length-capped)
  before storage (SEN-003).
- `agent_id` is restricted to hex/dash; blocklist CIDRs are validated with `ipaddress` and rejected if
  degenerate or control-plane-covering (SEN-009/010).

