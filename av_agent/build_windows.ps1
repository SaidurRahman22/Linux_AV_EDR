# Build the Padakhep Sentinel Windows AV agent into a single sentinel-av.exe.
#
#   powershell -ExecutionPolicy Bypass -File av_agent\build_windows.ps1
#
# Requires Python 3.9+ on PATH. Creates a throwaway venv, installs yara-python
# (real YARA engine, bundled into the exe) + pyinstaller, then builds.
#
# NOTE: PyInstaller one-file exes are frequently flagged heuristically by AV
# (ESET/Defender). The exe contains NO malware strings — detection rules are
# pulled from the control plane at runtime. If your AV quarantines it, add an
# exclusion for the install path (see docs/DEPLOYMENT_WINDOWS.md).

$ErrorActionPreference = "Stop"
$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$venv  = Join-Path $env:TEMP "sentinel-build-venv"

Write-Host "[*] Creating build venv at $venv"
python -m venv $venv
$py = Join-Path $venv "Scripts\python.exe"

Write-Host "[*] Installing yara-python + pyinstaller"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet yara-python pyinstaller

Write-Host "[*] Building sentinel-av.exe"
& (Join-Path $venv "Scripts\pyinstaller.exe") `
    --onefile --console --name sentinel-av --clean `
    --collect-submodules yara `
    --distpath (Join-Path $here "dist") `
    --workpath (Join-Path $env:TEMP "sentinel-build") `
    --specpath (Join-Path $env:TEMP "sentinel-spec") `
    (Join-Path $here "agent_win.py")

Write-Host "[+] Done: $(Join-Path $here 'dist\sentinel-av.exe')"
