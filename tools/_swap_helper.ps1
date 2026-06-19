param([string]$Src)
$ErrorActionPreference = "Stop"
$dst = "C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\deitzmx_helper.dll"
Copy-Item $Src $dst -Force
Set-Content -Path (Join-Path $PSScriptRoot "output\swap_log.txt") -Value "swapped from $Src @ $(Get-Date -Format o)"
