# Elevated: advance clock +1 day, run the spawn-based prompt verification, restore.
$ErrorActionPreference = "Continue"
$repo = Split-Path $PSScriptRoot -Parent
$out  = Join-Path $PSScriptRoot "output\verify_prompt_log.txt"

Get-Process CLIPStudioPaint -ErrorAction SilentlyContinue | Stop-Process -Force
try { Set-Date -Adjust (New-TimeSpan -Days 1) | Out-Null } catch { "clock adv err $($_.Exception.Message)" | Out-File $out }
"clock now $(Get-Date -Format o)" | Out-File $out

Push-Location $repo
& python "tools\verify_prompt.py" *>> $out
Pop-Location

Get-Process CLIPStudioPaint -ErrorAction SilentlyContinue | Stop-Process -Force
try { Set-Date -Adjust (New-TimeSpan -Days -1) | Out-Null } catch { "clock restore err $($_.Exception.Message)" | Add-Content $out }
"clock restored $(Get-Date -Format o)" | Add-Content $out
