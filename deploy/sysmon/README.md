# Sysmon telemetry for the Windows log-IDS

The Windows agent reads the `Microsoft-Windows-Sysmon/Operational` channel (source
`sysmon`). **Sysmon is not installed by default** — until it is, the Sysmon rules simply stay quiet
(the Security/System-log rules keep working). Installing Sysmon unlocks the highest-value Windows
detections: process lineage, LSASS access (credential dumping), injection, autoruns, C2 named pipes,
and DNS.

## Install

1. Download **Sysmon** from Microsoft Sysinternals (`sysmon64.exe`).
2. Install with the starter config:

   ```powershell
   .\sysmon64.exe -accepteula -i deploy\sysmon\padakhep-sysmon.xml
   # later, to update the config:
   .\sysmon64.exe -c deploy\sysmon\padakhep-sysmon.xml
   ```

3. Confirm events flow: `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5`.

The agent picks them up on its next scan cycle — no agent change needed.

## What the starter config captures

| Sysmon EID | What | Sentinel rule(s) |
|---|---|---|
| 1 | Process create (parent/child + command line) | office/server-spawns-shell, encoded PowerShell, LOLBins |
| 3 | Network connect (metadata endpoint) | cloud-metadata access |
| 8 | CreateRemoteThread | process injection |
| 10 | Process access → LSASS | credential dumping |
| 11 | File create in Startup | startup persistence |
| 12/13 | Registry Run keys | autorun persistence |
| 17/18 | Named pipes (CS/Meterpreter defaults) | C2 named pipe |
| 22 | DNS query | suspicious DNS (dyndns / abuse TLDs) |

## Production tuning

This config is tuned for **signal over completeness**. For a full baseline, merge with a maintained
community config and re-point the agent's rules as needed:

- **SwiftOnSecurity/sysmon-config** — a well-commented general baseline.
- **Olaf Hartong/sysmon-modular** — modular, ATT&CK-tagged, generates a merged config.

Sysmon's own event volume is managed by its config (include/exclude), so tune there; the log-IDS rules
then match on the fields (`Image`, `Cmd`, `Parent`, `Target`, `Dst`, `File`, `Reg`, `Query`, `Pipe`).
