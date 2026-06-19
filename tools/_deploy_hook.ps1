# Copy the clean (no-marker) hook into the install dir. Hardcoded paths to avoid
# space-splitting issues. Run elevated.
$ErrorActionPreference = "Stop"
$src = Join-Path $PSScriptRoot "output\proxy\deitzmx_hook.js"
$dst = "C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\deitzmx_hook.js"
Copy-Item $src $dst -Force
# Clean up the stray "C:\Program" file created by an earlier mis-quoted copy.
if (Test-Path -LiteralPath "C:\Program") { Remove-Item -LiteralPath "C:\Program" -Force }
"deployed clean hook @ $(Get-Date -Format o)" | Set-Content (Join-Path $PSScriptRoot "output\hook_deploy_log.txt")
