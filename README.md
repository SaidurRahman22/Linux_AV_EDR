# wazuh_rulegen — Wazuh Detection-Rule Generator

Reads a Wazuh **manager's** alert stream, finds suspicious activity
(**brute force**, **malicious IPs**, **malicious artifacts**), and generates
ready-to-use **Wazuh XML detection rules** + **CDB IOC lists** in a separate
output directory.

It runs in two ways:

| Mode | Command | Use |
|------|---------|-----|
| **scan** | `python run.py scan` | one-shot batch over existing `alerts.json` |
| **run**  | `python run.py run`  | background **daemon** that tails `alerts.json` and generates rules **in real time** |
| **update-feeds** | `python run.py update-feeds` | fetch public threat-intel feeds and merge into the feed files |

On Linux it installs as a hardened **systemd service** that follows
`/var/ossec/logs/alerts/alerts.json` and writes rules as new threats appear.

> **Zero dependencies** — pure Python 3.8+ standard library. Nothing to `pip install`.

---

## Why the manager's alert log?

A Wazuh **agent** only forwards raw events; it does no detection. The **manager**
decodes those events, matches its ruleset, and writes structured alerts (with
`srcip`, `dstuser`, `rule.id`, `syscheck` hashes, MITRE mappings, …) to
`/var/ossec/logs/alerts/alerts.json` — **one JSON object per line**. That decoded
stream is exactly what a rule generator should mine, so it is this tool's input.

---

## How it works

```
alerts.json ──▶ sources ──▶ normalize ──▶ detectors ──▶ indicators ──▶ rulegen ──▶ rules.xml
 (tail/batch)             (Event)      (rolling win)   (merge/IOC)    (Wazuh XML)   + CDB lists
```

1. **sources** — batch-reads `alerts.json(.gz)` or *tails* the live file,
   surviving log rotation/truncation (tracks inode + offset).
2. **normalize** — turns each alert into an `Event` (strips the `:port` Wazuh
   appends to `srcip`, pulls out users, file paths/hashes, command lines, MITRE).
3. **detectors** — three detectors keep rolling per-IOC state:
   - **Brute force** — repeated auth failures *or* same-source scan/attack floods
     within a timeframe (password-spray aware).
   - **Malicious IP** — source IPs matching a threat-intel feed (IP/CIDR), seen in
     high-severity alerts, or exceeding an attack-volume threshold.
   - **Malicious artifact** — known-bad file **hashes** (FIM/Sysmon) and
     suspicious **command-line signatures** (encoded PowerShell, certutil/bitsadmin
     download, mimikatz, reverse shells, shadow-copy deletion, …).
     Noisy registry/path heuristics are **opt-in**.
4. **rulegen** — merges indicators so **one IOC → one rule** even if several
   detectors flag it, assigns stable IDs (**≥ 100000**), renders valid Wazuh XML
   with evidence comments + MITRE tags, **validates** it, and writes **atomically**.

Each generated rule carries the evidence that produced it:

```xml
<!-- 105 attack/scan alerts within 300s from 103.202.222.186 (automated abuse) -->
<!-- evidence: IOC=103.202.222.186 | type=bruteforce/scan_flood+volume | confidence=high
     | observations=210 | window=... | source_rules=[31101] | agents=[Innovace_Server] -->
<rule id="100002" level="12">
  <srcip>103.202.222.186</srcip>
  <description>Brute-force / abusive source detected [auto-generated]: 103.202.222.186</description>
  <mitre><id>T1595</id></mitre>
  <group>authentication_failures,attack,generated,wazuh_rulegen,</group>
</rule>
```

---

## Quick start (test it anywhere)

A copy of a real manager's logs is bundled under `logs/`, so you can run it on
any machine with Python — no Wazuh required:

```bash
python run.py scan -c config.local.json
```

Outputs land in `output/`:

- `wazuh_rulegen_generated_rules.xml` — the rules
- `generated_malicious_ip.list` / `generated_malicious_hash.list` — CDB IOC lists
- `wazuh_rulegen_report.json` — machine-readable report of every indicator + its rule id

Run the tests:

```bash
python -m unittest discover -s tests -v
```

---

## Install on a Wazuh manager (background service)

From a copy of this repo **on the manager** (using `bash` avoids needing the
execute bit set after copying from another OS):

```bash
sudo bash deploy/install.sh
```

This:
- copies the tool to `/opt/wazuh-rulegen`,
- writes `/etc/wazuh-rulegen/config.json` (pointing at `/var/ossec/logs/alerts/alerts.json`),
- installs & starts the **`wazuh-rulegen`** systemd service as the `wazuh` user,
- generates rules to the **staging** dir `/opt/wazuh-rulegen/output/` (see safety below).

Watch it work:

```bash
journalctl -u wazuh-rulegen -f
```

### Activating generated rules (deliberate step)

Generated rules are **not** loaded automatically — the daemon never edits the live
ruleset on its own. Review the staging file, then:

```bash
sudo /opt/wazuh-rulegen/promote.sh        # copies to /var/ossec/etc/rules, validates, restarts manager
```

`promote.sh` runs `wazuh-analysisd -t` first and refuses to restart if the ruleset
fails validation.

### Uninstall

```bash
sudo bash deploy/uninstall.sh            # keep files
sudo bash deploy/uninstall.sh --purge    # remove everything
```

---

## Configuration

`config.json` (production) / `config.local.json` (bundled logs). Key fields:

| Field | Meaning |
|-------|---------|
| `alerts_file` | path to `alerts.json` (default `/var/ossec/logs/alerts/alerts.json`) |
| `ip_feeds` / `hash_feeds` | threat-intel files (see `data/threat_intel/`) |
| `ip_allowlist` | never generate rules for these IPs/CIDRs (RFC1918 by default) |
| `output_dir` | where rules/lists/report/state are written |
| `id_base` / `id_max` | rule-ID range (**must be ≥ 100000**) |
| `flush_interval` | daemon: seconds between rule-file rewrites |
| `detectors.bruteforce.min_auth_failures` | auth failures → brute force |
| `detectors.bruteforce.min_flood_events` | same-source attack alerts → scan flood |
| `detectors.malicious_ip.volume_threshold` | attack alerts from one IP → malicious |
| `detectors.malicious_ip.high_severity_level` | alert level that marks an IP suspect |
| `detectors.malicious_artifact.detect_registry_persistence` | opt-in registry rules |

Override at the CLI too: `--alerts`, `--output`, `--id-base`, `--ip-feed`, `--hash-feed`.

**Threat feeds** accept one indicator per line with an optional note, `#` for
comments, and CIDR ranges:

```
45.155.205.0/24     Known scanning infrastructure
185.177.72.5        High-volume web scanner
275a021b...fd0f     EICAR-Test-File (sha256)
```

---

## Keeping threat-intel feeds fresh (automated)

You do **not** need to hand-copy feed files from your dev machine. The Wazuh box
refreshes IOCs itself:

```bash
python -m wazuh_rulegen update-feeds -c /etc/wazuh-rulegen/config.json
```

This fetches public feeds (Feodo Tracker, ThreatFox, MalwareBazaar, Emerging
Threats — no API key needed), validates + dedupes them, and merges them into your
feed files. The installer sets this to run **every 6 hours** via a systemd timer
(`wazuh-rulegen-feedupdate.timer`), and the daemon **hot-reloads** the files within
~30 s — no restart required.

- Everything **above** the `# === AUTO-UPDATED IOCs ===` marker (your header + any
  IOCs you add by hand) is **preserved**; only the section below it is refreshed, so
  the file stays bounded across runs.
- Tune volume with `--max-per-source N`; add your own sources via `feed_sources` in
  the config; run once immediately with `sudo systemctl start wazuh-rulegen-feedupdate.service`.
- **VirusTotal / MISP** need API keys or a private instance — not included; add them
  as extra `feed_sources` if you have access.

### Syncing the *tool* (code) from your dev machine → Wazuh box

Feeds self-update on the box, but when **you change the code** on your dev machine,
push it with either:

- **git**: keep the repo in git; on the box `git pull` (optionally via cron) then
  re-run `sudo bash deploy/install.sh`.
- **rsync/scp**: `rsync -az --exclude logs --exclude output ./ user@wazuh:/opt/wazuh-rulegen/`
  (or a scheduled `scp`), then `sudo systemctl restart wazuh-rulegen`.

## What it found in the sample data (21,660 real alerts)

- **13 brute-force / scan-flood sources** — e.g. `185.177.72.5` (6000 attack alerts,
  `curl` probing `/config/upload/...`), `185.177.72.12` (427), `103.202.222.186` (210).
- **4 malicious IPs** — 2 from the threat-intel feed, 2 seen only in high-severity alerts.
- IOCs flagged by multiple detectors are **merged into a single rule** — `185.177.72.5`
  became one rule tagged `scan_flood+threat_feed+high_severity+volume`.

> **Tune, don't trust blindly.** Some high-volume sources in real traffic are
> mis-behaving *legitimate* clients (e.g. a mobile app mass-hitting an API with
> expired tokens → many 401s), not attackers. That is why rules go to staging for
> **analyst review** before activation, and why thresholds live in `config.json`.

---

## Project layout

```
wazuh_rulegen/        the package
  sources.py          batch reader + real-time tailer (rotation-safe)
  normalize.py        alert dict -> Event
  intel.py            IP/CIDR + hash feed matching
  detectors.py        brute force / malicious IP / malicious artifact
  rulegen.py          Wazuh XML + CDB lists (merge, validate, atomic write)
  engine.py           scan + daemon orchestration, state persistence
  cli.py              argparse CLI
config.json           production config (/var/ossec paths)
config.local.json     testing config (bundled ./logs)
data/threat_intel/    sample IP & hash feeds
deploy/               install.sh, uninstall.sh, promote.sh, systemd unit
tests/                unittest suite
logs/                 bundled real manager logs for testing
output/               generated rules land here
```

## Requirements

- Python **3.8+** (standard library only)
- To *activate* rules: a Wazuh manager (rules go in `/var/ossec/etc/rules/`)
