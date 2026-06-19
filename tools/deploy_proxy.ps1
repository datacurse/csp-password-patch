# Deploy the search-order-proxy payload (run elevated). Exe is left untouched.
# Handles two cases:
#   - shadowing an existing install-dir DLL (backs it up first), or
#   - shadow-ADD of a non-KnownDLL system DLL (no existing file; pure additive).
param([string]$Stem = "SHFolder")
$ErrorActionPreference = "Stop"
try { Start-Transcript -Path (Join-Path $PSScriptRoot "output\deploy_log.txt") -Force | Out-Null } catch {}

$Install = "C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
$Staged  = Join-Path $PSScriptRoot "output\proxy"

$real   = Join-Path $Install "$Stem.dll"
$backup = Join-Path $Install "$Stem.dll.itzmx-backup"

if (Test-Path $real) {
    if (-not (Test-Path $backup)) {
        Copy-Item $real $backup -Force
        Write-Output "Backed up existing $Stem.dll -> $backup"
    } else {
        Write-Output "Backup already exists -> $backup (left untouched)"
    }
} else {
    Write-Output "No existing $Stem.dll in install dir -> pure additive shadow (no backup needed)"
}

Copy-Item (Join-Path $Staged "$Stem`_orig.dll") (Join-Path $Install "$Stem`_orig.dll") -Force
Write-Output "Deployed $Stem`_orig.dll (renamed real)"
foreach ($f in @("deitzmx.dll","deitzmx.config","deitzmx_hook.js")) {
    Copy-Item (Join-Path $Staged $f) (Join-Path $Install $f) -Force
    Write-Output "Deployed $f"
}
Copy-Item (Join-Path $Staged "$Stem.dll") $real -Force
Write-Output "Deployed proxy $Stem.dll"
Write-Output "DONE"
try { Stop-Transcript | Out-Null } catch {}
