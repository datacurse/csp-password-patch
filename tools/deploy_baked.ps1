# Deploy the baked de-itzmx payload into the CSP install dir (run elevated).
# Backs up the original exe once, then copies the 5 staged files.
$ErrorActionPreference = "Stop"
try { Start-Transcript -Path (Join-Path $PSScriptRoot "output\deploy_log.txt") -Force | Out-Null } catch {}

$Install = "C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
$Staged  = Join-Path $PSScriptRoot "output\baked"
$Backup  = Join-Path $Install "CLIPStudioPaint.exe.itzmx-backup"

$exe = Join-Path $Install "CLIPStudioPaint.exe"
if (-not (Test-Path $Backup)) {
    Copy-Item $exe $Backup -Force
    Write-Output "Backed up original exe -> $Backup"
} else {
    Write-Output "Backup already exists -> $Backup (left untouched)"
}

$files = @("CLIPStudioPaint.exe", "deitzmx_helper.dll", "deitzmx.dll", "deitzmx.config", "deitzmx_hook.js")
foreach ($f in $files) {
    $src = Join-Path $Staged $f
    $dst = Join-Path $Install $f
    Copy-Item $src $dst -Force
    Write-Output "Deployed $f"
}
Write-Output "DONE"
try { Stop-Transcript | Out-Null } catch {}
