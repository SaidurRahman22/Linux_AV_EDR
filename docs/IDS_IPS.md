# Padakhep Sentinel — IDS / IPS (Suricata)

Padakhep Sentinel does not reimplement network intrusion detection — it
**orchestrates the Suricata engine** and turns its alerts into Sentinel
detections, controlled per-device from the console (SRS v3 §2.2/§14).

## Modes (console → **IDS / IPS** page, 3-way toggle)

| Mode | What runs | Effect |
|------|-----------|--------|
| **OFF** | nothing | Suricata stopped; no inline hooks. Default. |
| **IDS** | `suricata --af-packet -i <iface>` | **Detect-only** — passively sniffs the interface, raises alerts. Non-disruptive. |
| **IPS** | `suricata -q 0` + nftables NFQUEUE | **Inline** — traffic passes through Suricata, which **can drop** packets matching `drop` rules. Enable deliberately. |

Everything defaults to **OFF**. IPS is inline and can affect connectivity, so the
console asks for confirmation before enabling it, and the NFQUEUE rules use
`bypass` (fail-open: if Suricata isn't reading the queue, traffic still flows).

## Rules

The agent uses whatever rules Suricata has. `install_suricata.sh` runs
`suricata-update`, which fetches the free **Emerging Threats (ET) Open** ruleset
to `/var/lib/suricata/rules/suricata.rules`. Point `suricata-update` at other
sources (or drop custom `.rules`) to extend coverage; the rule count is reported
back to the console.

## Install the engine (Linux endpoint)

```bash
sudo bash av_agent/install_suricata.sh
```

This installs `suricata` + `suricata-update`, pulls ET Open, and disables the
distro Suricata service (the Sentinel agent manages the engine itself). Then set
the host to **IDS** or **IPS** on the console — it applies within ~1 heartbeat.

## Alerts

Suricata writes `eve.json` to `/var/log/sentinel-suricata/`. The agent tails it
and forwards each alert as a v3 detection:

- **IDS_ALERT** — a Suricata alert (detect mode or an allowed packet).
- **IPS_DROP** — an alert whose action was `blocked` (inline drop).

They appear in the **IDS / IPS** page (Recent Suricata Alerts) and the SRS Logs,
with signature, category, `src → dest`, action, and severity. Volume is capped
per cycle (`SENTINEL_NIDS_MAX`, default 100) to avoid flooding on chatty rulesets.

## Config (env on the endpoint)

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_NIDS_IFACE` | default-route NIC | Interface to inspect (IDS af-packet) |
| `SENTINEL_NIDS_LOG` | `/var/log/sentinel-suricata` | eve.json output dir |
| `SENTINEL_SURICATA_YAML` | `/etc/suricata/suricata.yaml` | Suricata base config |
| `SENTINEL_NIDS_QUEUE` | `0` | NFQUEUE number (IPS) |
| `SENTINEL_NIDS_MAX` | `100` | Max alerts forwarded per cycle |

## Notes

- **Linux only.** Suricata inline IPS uses NFQUEUE; Windows endpoints report the
  feature as unsupported and the console disables the toggle for them.
- Needs **root** (the agent already runs as root/SYSTEM for auth-log + firewall).
- On a busy host the ET Open ruleset uses real memory/CPU — enable IDS/IPS where
  it's worth it, not blindly fleet-wide.
