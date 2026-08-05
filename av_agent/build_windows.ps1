# Build the Padakhep Sentinel Windows AV/EDR agent into a single sentinel-av.exe.
#
#   powershell -ExecutionPolicy Bypass -File av_agent\build_windows.ps1
#
# SEN-014 (supply-chain hardening): build dependencies are PINNED to exact versions
# (build-requirements.txt), the interpreter is resolved by absolute path (not PATH),
# the build runs in a fresh randomized ACL-restricted venv dir that is removed after,
# and the produced artifact's SHA-256 is recorded. Optional Authenticode signing runs
# when a cert is provided (SENTINEL_SIGN_* below) so the first drop and every
# self-updated onefile are trusted by Defender/SmartScreen.
#
# Optional env:
#   SENTINEL_BUILD_PYTHON  absolute path to the python.exe used to create the build venv
#   SENTINEL_SIGN_PFX      path to a code-signing .pfx (enables Authenticode signing)
#   SENTINEL_SIGN_PASS     password for the .pfx
#   SENTINEL_SIGN_AUTO=1   sign using the best matching cert in the store (signtool /a)
#   SENTINEL_SIGN_TSA      RFC3161 timestamp URL (default http://timestamp.digicert.com)
#
# NOTE: PyInstaller one-file exes are frequently flagged heuristically by AV
# (ESET/Defender). The exe contains NO malware strings — detection rules are pulled
# from the control plane at runtime. Authenticode signing (above) is the real fix;
# otherwise add an exclusion for the install path (see docs/DEPLOYMENT_WINDOWS.md).

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- resolve the interpreter by an ABSOLUTE path (SEN-014: not PATH-resolved) ---
$sysPy = $env:SENTINEL_BUILD_PYTHON
if (-not $sysPy) { $sysPy = (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $sysPy -or -not (Test-Path $sysPy)) { throw "Python interpreter not found; set SENTINEL_BUILD_PYTHON to an absolute python.exe path." }
$sysPy = (Resolve-Path $sysPy).Path
Write-Host "[*] Interpreter: $sysPy"

# --- fresh, randomized, ACL-restricted build dir (SEN-014) ---
$venv = Join-Path $env:TEMP ("sentinel-build-" + [guid]::NewGuid().ToString('N'))
$work = Join-Path $venv "work"
$spec = Join-Path $venv "spec"
Write-Host "[*] Build dir: $venv"
New-Item -ItemType Directory -Force -Path $venv | Out-Null
# lock the build dir to SYSTEM + Administrators + the building user (no other principals).
# If the ACL lockdown fails we must NOT silently build in a world-writable TEMP dir.
icacls $venv /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "could not ACL-restrict the build dir $venv (SEN-014) - aborting" }

try {
    Write-Host "[*] Creating build venv"
    & $sysPy -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed (exit $LASTEXITCODE)" }
    $py = Join-Path $venv "Scripts\python.exe"

    # SEN-014: install ONLY the exact pinned set with --no-deps (build-requirements.txt lists
    # every transitive dep explicitly), so nothing floats. Do NOT run pip install --upgrade pip
    # here - that would pull an unpinned pip from PyPI into the build toolchain. Use the venv's
    # bundled pip. (CI residual: add --require-hashes with a --generate-hashes lockfile.)
    Write-Host "[*] Installing PINNED build deps (build-requirements.txt, --no-deps)"
    & $py -m pip install --quiet --no-input --require-virtualenv --no-deps -r (Join-Path $here "build-requirements.txt")
    if ($LASTEXITCODE -ne 0) { throw "pinned dependency install failed (exit $LASTEXITCODE)" }

    Write-Host "[*] Building sentinel-av.exe"
    & (Join-Path $venv "Scripts\pyinstaller.exe") `
        --onefile --console --name sentinel-av --clean `
        --collect-submodules yara `
        --distpath (Join-Path $here "dist") `
        --workpath $work `
        --specpath $spec `
        (Join-Path $here "agent_win.py")
    if ($LASTEXITCODE -ne 0) { throw "pyinstaller build failed (exit $LASTEXITCODE)" }

    $exe = Join-Path $here "dist\sentinel-av.exe"

    # --- optional Authenticode signing (SEN-014 / Defender+SmartScreen trust) ---
    $tsa = $env:SENTINEL_SIGN_TSA; if (-not $tsa) { $tsa = "http://timestamp.digicert.com" }
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
    if ($env:SENTINEL_SIGN_PFX -and (Test-Path $env:SENTINEL_SIGN_PFX)) {
        if (-not $signtool) { throw "SENTINEL_SIGN_PFX set but signtool.exe not found (install the Windows SDK)." }
        Write-Host "[*] Authenticode signing with $($env:SENTINEL_SIGN_PFX)"
        & $signtool sign /fd sha256 /tr $tsa /td sha256 /f $env:SENTINEL_SIGN_PFX /p $env:SENTINEL_SIGN_PASS $exe
        if ($LASTEXITCODE -ne 0) { throw "signtool signing failed (exit $LASTEXITCODE)" }
    } elseif ($env:SENTINEL_SIGN_AUTO -eq "1" -and $signtool) {
        Write-Host "[*] Authenticode signing with best matching store cert (/a)"
        & $signtool sign /a /fd sha256 /tr $tsa /td sha256 $exe
        if ($LASTEXITCODE -ne 0) { throw "signtool signing failed (exit $LASTEXITCODE)" }
    } else {
        Write-Host "[!] Authenticode signing SKIPPED (no SENTINEL_SIGN_PFX / SENTINEL_SIGN_AUTO)."
        Write-Host "    Production fleets SHOULD code-sign so Defender/SmartScreen trust the drop + every self-update."
    }

    # --- record the produced artifact hash (SEN-014 reproducibility/verification) ---
    $sha = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    Set-Content -Path "$exe.sha256" -Value $sha -Encoding ascii
    Write-Host "[+] Done: $exe"
    Write-Host "[+] SHA-256: $sha"
    Write-Host "    (now run: python tools/sign_agent.py sign av_agent/dist/sentinel-av.exe  # offline Ed25519)"
}
finally {
    # remove the randomized build dir (defense-in-depth; ignore failures)
    try { Remove-Item -Recurse -Force $venv -ErrorAction SilentlyContinue } catch {}
}
