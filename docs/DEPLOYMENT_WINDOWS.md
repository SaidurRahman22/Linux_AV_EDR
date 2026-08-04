# Padakhep Sentinel — Windows Agent Deployment

The Windows agent (`sentinel-av.exe`) speaks the same control-plane protocol as
the Linux agent: enroll → pull policy → scan (file hash + real YARA + process
behavior + failed-logon brute force) → report → optional network isolation.

## 1. Build (or use the prebuilt exe)

Prebuilt: `av_agent/dist/sentinel-av.exe`.

Rebuild from source:

```powershell
powershell -ExecutionPolicy Bypass -File av_agent\build_windows.ps1
```

The build bundles the **real YARA engine** (yara-python). The exe itself contains
**no malware strings** — the ~200 YARA rules and 100 behavior patterns are pulled
from the control plane at runtime.

## 2. Configure

The agent reads environment variables (set them for the service/user):

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_API` | `http://127.0.0.1:8080` | Control-plane URL (e.g. `http://192.168.39.32:8080`) |
| `AGENT_NAME` | hostname | Name shown in the dashboard |
| `SENTINEL_SCAN_DIRS` | `C:\Users;C:\Windows\Temp;C:\ProgramData;C:\Users\Public` | `;`-separated scan roots |
| `SENTINEL_AV_INTERVAL` | `60` | Seconds between scan cycles |
| `SENTINEL_AV_POLICY_INTERVAL` | `300` | Seconds between policy refreshes |
| `SENTINEL_API_TOKEN` | (empty) | Shared secret if the control plane requires one |

Quick test (one cycle):

```powershell
$env:SENTINEL_API="http://192.168.39.32:8080"
$env:AGENT_NAME="win-lab-01"
.\sentinel-av.exe --once
```

## 3. Run continuously (Scheduled Task, runs as SYSTEM)

Failed-logon (Security 4625) reading and firewall isolation require SYSTEM/Admin.

```powershell
$exe = "C:\Program Files\PadakhepSentinel\sentinel-av.exe"
$action  = New-ScheduledTaskAction -Execute $exe
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "PadakhepSentinelAV" -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings
Start-ScheduledTask -TaskName "PadakhepSentinelAV"
```

Set the environment variables machine-wide first (so the task inherits them):

```powershell
[Environment]::SetEnvironmentVariable("SENTINEL_API","http://192.168.39.32:8080","Machine")
[Environment]::SetEnvironmentVariable("AGENT_NAME","win-lab-01","Machine")
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
  Add-MpPreference -ExclusionPath "C:\Program Files\PadakhepSentinel"   # Defender
  ```

  ESET: *Advanced setup → Detection engine → Exclusions → add the folder*, or via
  `eShell`: `set av exclusions process add "C:\Program Files\PadakhepSentinel\sentinel-av.exe"`.

These are the expected trade-offs of running security tooling that must carry
malware indicators; they do not indicate a real infection.
