<#
.SYNOPSIS
    TWINLOOT Runbook - Phase 2/9: Enterprise Python Hunt
.DESCRIPTION
    Locates python.exe / pythonw.exe / py.exe / pyw.exe binaries under user-writable
    locations, computes SHA256, and flags high-risk indicators (recent creation,
    user-writable path, unsigned/unexpected parent). Read-only - takes no remediation
    action. Run with an account that has read access to target user profiles.
.NOTES
    Runbook reference: Section 8 & 9 (Phase 2 - Enterprise Python Hunt / Python Triage)
    Run as: Local admin or EDR-deployed script (Kaspersky/SCCM/Intune remote script)
.OUTPUTS
    CSV report: .\TWINLOOT_PythonHunt_<hostname>_<timestamp>.csv
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [int]$RecentDays = 14
)

$ErrorActionPreference = 'SilentlyContinue'
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path $OutputPath "TWINLOOT_PythonHunt_${hostname}_${timestamp}.csv"

Write-Host "[*]  TWINLOOT - Python Hunt starting on $hostname" -ForegroundColor Cyan

# User-writable locations of interest (runbook Section 8.1)
$searchRoots = @(
    "C:\Users"
    "C:\ProgramData"
)

$results = New-Object System.Collections.Generic.List[Object]

foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }

    $files = Get-ChildItem -Path $root -Include python.exe, pythonw.exe, py.exe, pyw.exe `
        -Recurse -Force -ErrorAction SilentlyContinue

    foreach ($f in $files) {

        $isUserWritable = $f.FullName -match '\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)\\' -or
                           $f.FullName -match '\\ProgramData\\[^\\]+\\python'
        $isProgramFiles  = $f.FullName -match '^C:\\Program Files'
        $isRecent        = $f.CreationTime -gt (Get-Date).AddDays(-$RecentDays)

        $hash = $null
        try { $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}

        $sig = $null
        try { $sig = (Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction Stop).Status } catch {}

        # Attempt to find any currently running process using this binary
        $proc = Get-CimInstance Win32_Process -Filter "ExecutablePath='$($f.FullName -replace "\\","\\\\")'" -ErrorAction SilentlyContinue

        $severity = "Low"
        if ($isUserWritable -and $isRecent) { $severity = "Critical" }
        elseif ($isUserWritable) { $severity = "High" }
        elseif (-not $isProgramFiles) { $severity = "Medium" }

        $results.Add([PSCustomObject]@{
            Hostname          = $hostname
            FullName          = $f.FullName
            SizeBytes         = $f.Length
            CreationTime      = $f.CreationTime
            LastWriteTime     = $f.LastWriteTime
            IsUserWritablePath= $isUserWritable
            IsRecent          = $isRecent
            SHA256            = $hash
            SignatureStatus   = $sig
            RunningPID        = $proc.ProcessId -join ','
            ParentProcessId   = $proc.ParentProcessId -join ','
            CommandLine       = ($proc.CommandLine -join ' | ')
            Severity          = $severity
        })
    }
}

$results | Sort-Object Severity -Descending | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8

Write-Host "[*] Found $($results.Count) Python binaries." -ForegroundColor Yellow
Write-Host "[*] Report written to: $outFile" -ForegroundColor Green

if (($results | Where-Object Severity -eq 'Critical').Count -gt 0) {
    Write-Host "[!] CRITICAL findings present - do not delete files, preserve evidence, escalate to InfoSec (Runbook Section 9 & 47)." -ForegroundColor Red
}
