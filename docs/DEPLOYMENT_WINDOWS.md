# Padakhep Sentinel — Windows Agent Deployment

The Windows agent (`sentinel-av.exe`) speaks the same control-plane protocol as
the Linux agent: enroll → pull policy → scan (file hash + real YARA + process
behavior + failed-logon brute force) → report → optional network isolation.

## 1. Install — just run the exe

**Copy `sentinel-av.exe` to the machine and run it once.** No configuration, no
environment variables, no installer. On first run it:

1. copies itself to `C:\ProgramData\PadakhepSentinel\sentinel-av.exe`,
2. registers a **silent** logon launcher (hidden — no console window ever pops up),
3. starts running in the background, and
4. enrolls to the control plane and appears in the dashboard **Fleet** within ~1 min.

The control-plane address (`http://192.168.39.32:8080`) is **baked into the build**,
so nothing needs to be set. That's the whole install.

> The prebuilt exe is `av_agent/dist/sentinel-av.exe`. Rebuild with
> `powershell -ExecutionPolicy Bypass -File av_agent\build_windows.ps1`. If your
> control plane lives somewhere else, either set `SENTINEL_API` (below) or change
> `DEFAULT_API` in `av_agent/agent_win.py` and rebuild.

Command-line flags (you normally don't need these): run with **no flags** = the
first-run install above; `--run` = run the agent loop (used by the autostart
launcher); `--once` = a single scan pass for testing; `--install` = force the
install step. A mutex keeps a single instance, so double-launches are harmless.

## 2. Configuration (all optional — sensible defaults)

Set any of these as environment variables only if you want to override a default:

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_API` | `http://192.168.39.32:8080` (baked in) | Control-plane URL |
| `AGENT_NAME` | hostname | Name shown in the dashboard |
| `SENTINEL_SCAN_DIRS` | `C:\Windows\Temp;C:\ProgramData;C:\Users\Public;%USERPROFILE%\Downloads;%USERPROFILE%\Desktop` | `;`-separated scan roots (lean by default; realtime covers new files) |
| `SENTINEL_AV_REALTIME` | `1` | Event-driven scanning (ReadDirectoryChangesW) |
| `SENTINEL_AV_FULLSCAN` | `900` | Seconds between incremental safety-net full scans |
| `SENTINEL_AV_INTERVAL` | `60` | Seconds between heartbeats / telemetry scans |
| `SENTINEL_AV_POLICY_INTERVAL` | `300` | Seconds between policy refreshes |
| `SENTINEL_TRUST_SIGNED` | `1` | Skip fuzzy YARA/string matches on validly code-signed files + certified app folders (kills vendor false positives) |
| `SENTINEL_SCAN_EXCLUDE` | (built-in AV dirs) | Extra `;`-separated path substrings to never scan |
| `SENTINEL_AV_DISK` | (all fixed drives) | `;`-separated drive roots to report storage for |
| `SENTINEL_API_TOKEN` | (empty) | Shared secret if the control plane requires one |

Quick test (one pass, prints to console, does not install):

```powershell
.\sentinel-av.exe --once
```

## 3. Always-on as SYSTEM (optional — needed for prevention)

The one-step install (§1) runs the agent **per-user** and does full detection +
reporting. Two things require **SYSTEM/Admin**: reading failed-logons (Security
event 4625) and enforcing firewall actions (**closing ports / isolating** the
host). For those, install it as a SYSTEM scheduled task from an **elevated**
PowerShell instead:

```powershell
$exe = "C:\ProgramData\PadakhepSentinel\sentinel-av.exe"
$action  = New-ScheduledTaskAction -Execute $exe -Argument "--run"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "PadakhepSentinelAV" -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings
# remove the per-user logon launcher so it doesn't double-run:
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\PadakhepSentinelAV.vbs" -EA SilentlyContinue
Start-ScheduledTask -TaskName "PadakhepSentinelAV"
```

## 4. Endpoint isolation

From the dashboard, open the endpoint and click **Isolate Endpoint**. The agent
applies a Windows Defender Firewall quarantine that blocks all traffic **except**
loopback, established connections, the control plane, and management
(RDP/WinRM/SSH) — so the host stays reachable and isolation is reversible.

## 5. Antivirus false positives (important)

Third-party AV (ESET, Defender, etc.) may:

- **Quarantine plaintext `.yar` rule files** — because they legitimately contain
  malware *signature strings*. That is why this repo ships the rules only as an
  opaque packed blob (`av_content/rulepack.b64`), never as plaintext on disk. If
  you unpack them for editing (`python tools/rulepack.py unpack`), do it in an
  AV-excluded folder and re-pack (`python tools/rulepack.py pack`) before commit.
- **Heuristically flag `sentinel-av.exe`** — PyInstaller one-file exes are a
  common heuristic FP. The exe has no malicious content. Add an exclusion:

  ```powershell
  Add-MpPreference -ExclusionPath "C:\ProgramData\PadakhepSentinel"   # Defender
  ```

  ESET: *Advanced setup → Detection engine → Exclusions → add the folder*, or via
  `eShell`: `set av exclusions process add "C:\ProgramData\PadakhepSentinel\sentinel-av.exe"`.

These are the expected trade-offs of running security tooling that must carry
malware indicators; they do not indicate a real infection.
