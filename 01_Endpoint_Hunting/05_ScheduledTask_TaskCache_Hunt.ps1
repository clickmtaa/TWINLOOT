<#
.SYNOPSIS
    TWINLOOT Runbook - Phase 8: Scheduled Task / TaskCache Integrity Hunt
.DESCRIPTION
    Compares tasks visible via Get-ScheduledTask against the raw TaskCache registry
    hive to surface hidden/orphaned tasks, and flags tasks whose action launches
    python/powershell/wscript/cscript/cmd/mshta from user-writable locations.
.OUTPUTS
    Two CSV reports: TaskCache discrepancies + suspicious task actions.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "."
)

$ErrorActionPreference = 'SilentlyContinue'
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFileTasks = Join-Path $OutputPath "TWINLOOT_SuspiciousTasks_${hostname}_${timestamp}.csv"
$outFileCache = Join-Path $OutputPath "TWINLOOT_TaskCacheRaw_${hostname}_${timestamp}.csv"

Write-Host "[*] TWINLOOT - Scheduled Task Hunt starting on $hostname" -ForegroundColor Cyan

$suspiciousTokens = 'python|pythonw|powershell|wscript|cscript|cmd\.exe|mshta'
$userWritable = 'AppData|Temp|Downloads|ProgramData'

# 1) Enumerate real scheduled tasks and flag risky actions
$suspiciousTasks = New-Object System.Collections.Generic.List[Object]

Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actions = $task.Actions
    foreach ($a in $actions) {
        $exe = $a.Execute
        $taskArgs = $a.Arguments
        $combined = "$exe $taskArgs"
        if (($combined -match $suspiciousTokens) -and ($combined -match $userWritable)) {
            $suspiciousTasks.Add([PSCustomObject]@{
                Hostname   = $hostname
                TaskName   = $task.TaskName
                TaskPath   = $task.TaskPath
                State      = $task.State
                Execute    = $exe
                Arguments  = $taskArgs
                Author     = $task.Author
            })
        }
    }
}

$suspiciousTasks | Export-Csv -Path $outFileTasks -NoTypeInformation -Encoding UTF8

# 2) Dump raw TaskCache Tree names for manual diff against Get-ScheduledTask output
$taskCachePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
$cacheEntries = New-Object System.Collections.Generic.List[Object]

if (Test-Path $taskCachePath) {
    Get-ChildItem -Path $taskCachePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $cacheEntries.Add([PSCustomObject]@{
            Hostname = $hostname
            KeyPath  = ($_.Name -replace 'HKEY_LOCAL_MACHINE', 'HKLM:')
        })
    }
}
$cacheEntries | Export-Csv -Path $outFileCache -NoTypeInformation -Encoding UTF8

Write-Host "[*] Suspicious task actions found: $($suspiciousTasks.Count)" -ForegroundColor Yellow
Write-Host "[*] Reports written: $outFileTasks , $outFileCache" -ForegroundColor Green
Write-Host "[i] Manually diff TaskCache paths against 'Get-ScheduledTask | Select TaskPath,TaskName' to find hidden/orphaned tasks (Runbook Section 17)." -ForegroundColor Cyan
