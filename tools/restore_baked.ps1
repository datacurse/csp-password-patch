# Restore the original CSP exe and remove the baked payload (run elevated).
$ErrorActionPreference = "Stop"

$Install = "C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
$Backup  = Join-Path $Install "CLIPStudioPaint.exe.itzmx-backup"
$exe     = Join-Path $Install "CLIPStudioPaint.exe"

if (Test-Path $Backup) {
    Copy-Item $Backup $exe -Force
    Write-Output "Restored original exe from backup"
} else {
    Write-Output "WARNING: no backup found at $Backup"
}

foreach ($f in @("deitzmx_helper.dll", "deitzmx.dll", "deitzmx.config", "deitzmx_hook.js")) {
    $p = Join-Path $Install $f
    if (Test-Path $p) { Remove-Item $p -Force; Write-Output "Removed $f" }
}
Write-Output "DONE"
