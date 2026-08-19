<#
.SYNOPSIS
    TWINLOOT Runbook - Section 13: Microsoft Edge Command-Line Hunt
.DESCRIPTION
    Inspects currently running msedge.exe processes (and, if a Sysmon/Security
    event log with process command-line auditing is present, recent historical
    launches) for --headless, --remote-debugging-port/pipe, and unusual
    --user-data-dir usage. Also flags python.exe -> msedge.exe parent/child chains,
    the "golden detection" in Runbook Section 46.
.OUTPUTS
    CSV report of matching Edge process instances.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [int]$LookbackHours = 24
)

$ErrorActionPreference = 'SilentlyContinue'
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path $OutputPath "TWINLOOT_EdgeCmdLine_${hostname}_${timestamp}.csv"

Write-Host "[*] TWINLOOT - Edge Command-Line Hunt starting on $hostname" -ForegroundColor Cyan

$results = New-Object System.Collections.Generic.List[Object]

# --- Live process check ---
$edgeProcs = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue
foreach ($p in $edgeProcs) {
    $cmd = $p.CommandLine
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue

    $headless   = $cmd -match '--headless'
    $remoteDbg  = $cmd -match '--remote-debugging-port|--remote-debugging-pipe'
    $userDataDir= $cmd -match '--user-data-dir'
    $pythonParent = $parent.Name -match 'python'

    if ($headless -or $remoteDbg -or $userDataDir -or $pythonParent) {
        $severity = 'Medium'
        if ($remoteDbg -and $pythonParent) { $severity = 'Critical' }
        elseif ($remoteDbg -or ($headless -and $pythonParent)) { $severity = 'High' }

        $results.Add([PSCustomObject]@{
            Hostname       = $hostname
            PID            = $p.ProcessId
            ParentPID      = $p.ParentProcessId
            ParentName     = $parent.Name
            ParentCmdLine  = $parent.CommandLine
            CommandLine    = $cmd
            Headless       = $headless
            RemoteDebugging= $remoteDbg
            UnusualUserDataDir = $userDataDir
            PythonParent   = $pythonParent
            Severity       = $severity
        })
    }
}

# --- Historical check via Security 4688 (if process command-line auditing is enabled) ---
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = (Get-Date).AddHours(-$LookbackHours)
    } -ErrorAction Stop | Where-Object { $_.Message -match 'msedge\.exe' -and $_.Message -match '--headless|--remote-debugging' }

    foreach ($e in $events) {
        $results.Add([PSCustomObject]@{
            Hostname       = $hostname
            PID            = 'historical'
            ParentPID      = ''
            ParentName     = ''
            ParentCmdLine  = ''
            CommandLine    = ($e.Message -split "`n" | Select-String 'Process Command Line' -SimpleMatch)
            Headless       = $true
            RemoteDebugging= $true
            UnusualUserDataDir = $null
            PythonParent   = $null
            Severity       = 'High-Historical'
        })
    }
} catch {
    Write-Host "[i] No 4688 command-line events available (enable command-line process auditing to extend historical coverage)." -ForegroundColor DarkGray
}

$results | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8

Write-Host "[*] Matching Edge events: $($results.Count)" -ForegroundColor Yellow
Write-Host "[*] Report written to: $outFile" -ForegroundColor Green
if (($results | Where-Object Severity -eq 'Critical').Count -gt 0) {
    Write-Host "[!] CRITICAL: python.exe -> msedge.exe --remote-debugging pattern detected. Isolate and investigate per Runbook Section 5 & 46." -ForegroundColor Red
}
