# Restore: undo deploy_proxy. Run elevated.
#   - if a backup exists, restore the original DLL from it;
#   - otherwise (pure additive shadow) delete the proxy DLL we added.
# Always removes the staged sidecar files.
param([string]$Stem = "SHFolder")
$ErrorActionPreference = "Stop"

$Install = "C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
$real   = Join-Path $Install "$Stem.dll"
$backup = Join-Path $Install "$Stem.dll.itzmx-backup"

if (Test-Path $backup) {
    Copy-Item $backup $real -Force
    Remove-Item $backup -Force
    Write-Output "Restored original $Stem.dll from backup"
} elseif (Test-Path $real) {
    Remove-Item $real -Force
    Write-Output "Removed additive shadow $Stem.dll"
}
foreach ($f in @("$Stem`_orig.dll","deitzmx.dll","deitzmx.config","deitzmx_hook.js")) {
    $p = Join-Path $Install $f
    if (Test-Path $p) { Remove-Item $p -Force; Write-Output "Removed $f" }
}
Write-Output "DONE"
