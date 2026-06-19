# Elevated end-to-end verification of the baked suppression.
# Advances the clock +1 day to force the daily password/splash, launches CSP
# (pure double-click path - NO frida injection), records a window timeline to see
# whether the prompts appear and get auto-dismissed, then restores the clock.
$ErrorActionPreference = "Continue"
$log = Join-Path $PSScriptRoot "output\verify_timeline.txt"
"=== verify start $(Get-Date -Format o) ===" | Set-Content $log

Add-Type @"
using System;using System.Text;using System.Runtime.InteropServices;
public class WT{
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f,IntPtr l);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
 public delegate bool EnumProc(IntPtr h,IntPtr l);
}
"@

function Get-CspPids {
  $ids=@{}
  Get-Process CLIPStudioPaint -ErrorAction SilentlyContinue | ForEach-Object { $ids[[uint32]$_.Id]=$true }
  return $ids
}
function Snapshot($pids){
  $res=@{}
  $cb=[WT+EnumProc]{ param($h,$l)
    $op=0;[WT]::GetWindowThreadProcessId($h,[ref]$op)|Out-Null
    if($pids.ContainsKey([uint32]$op) -and [WT]::IsWindowVisible($h)){
      $t=New-Object Text.StringBuilder 400;[WT]::GetWindowTextW($h,$t,400)|Out-Null
      $c=New-Object Text.StringBuilder 200;[WT]::GetClassNameW($h,$c,200)|Out-Null
      $res["$($c.ToString())|$($t.ToString())"]=$true
    }
    return $true }
  [WT]::EnumWindows($cb,[IntPtr]::Zero)|Out-Null
  return $res
}

# 1) advance clock
$before=Get-Date
try { Set-Date -Adjust (New-TimeSpan -Days 1) | Out-Null; "clock advanced -> $(Get-Date -Format o)" | Add-Content $log }
catch { "ERROR advancing clock: $($_.Exception.Message)" | Add-Content $log }

# 2) launch CSP (double-click path)
Get-Process CLIPStudioPaint -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
$marker="$env:TEMP\deitzmx_marker.txt"; Remove-Item $marker -ErrorAction SilentlyContinue
$exe="C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
$proc=Start-Process $exe -PassThru
"launched pid=$($proc.Id)" | Add-Content $log

# 3) timeline (diff appear/disappear) for ~22s
$t0=Get-Date; $prev=@{}
for($i=0;$i -lt 74;$i++){
  Start-Sleep -Milliseconds 300
  $pids=Get-CspPids
  $now=Snapshot $pids
  $ms=[int]((Get-Date)-$t0).TotalMilliseconds
  foreach($k in $now.Keys){ if(-not $prev.ContainsKey($k)){ "+$ms ms  APPEAR  $k" | Add-Content $log } }
  foreach($k in $prev.Keys){ if(-not $now.ContainsKey($k)){ "-$ms ms  GONE    $k" | Add-Content $log } }
  $prev=$now
}
"marker_written=$(Test-Path $marker)" | Add-Content $log
"proc_alive=$(-not $proc.HasExited)" | Add-Content $log

# 4) cleanup + restore clock
Get-Process CLIPStudioPaint -ErrorAction SilentlyContinue | Stop-Process -Force
try { Set-Date -Adjust (New-TimeSpan -Days -1) | Out-Null; "clock restored -> $(Get-Date -Format o)" | Add-Content $log }
catch { "ERROR restoring clock: $($_.Exception.Message)" | Add-Content $log }
"=== verify end $(Get-Date -Format o) ===" | Add-Content $log
