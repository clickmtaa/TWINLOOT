<#
.SYNOPSIS
    TWINLOOT Runbook - Phase 5: NTUSER.MAN Hunt
.DESCRIPTION
    Searches all local user profiles for NTUSER.MAN (mandatory profile hive) files,
    which TWINLOOT reportedly abuses for persistence. Read-only - does NOT delete
    or modify anything found. Preserves metadata for evidence per Section 14 & 47.
.OUTPUTS
    CSV report + optional evidence copy (hash only, file NOT copied by default).
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "."
)

$ErrorActionPreference = 'SilentlyContinue'
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path $OutputPath "TWINLOOT_NTUSERMAN_${hostname}_${timestamp}.csv"

Write-Host "[*]  TWINLOOT - NTUSER.MAN Hunt starting on $hostname" -ForegroundColor Cyan

$findings = Get-ChildItem -Path "C:\Users" -Filter "NTUSER.MAN" -Recurse -Force -ErrorAction SilentlyContinue

$results = foreach ($f in $findings) {
    $acl = $null
    try { $acl = (Get-Acl $f.FullName).Owner } catch {}

    $hash = $null
    try { $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}

    [PSCustomObject]@{
        Hostname      = $hostname
        FullName      = $f.FullName
        SizeBytes     = $f.Length
        CreationTime  = $f.CreationTime
        LastWriteTime = $f.LastWriteTime
        Owner         = $acl
        SHA256        = $hash
    }
}

if ($results) {
    $results | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    Write-Host "[!] CRITICAL: NTUSER.MAN found. DO NOT DELETE. Preserve evidence and escalate immediately (Runbook Section 14 & 48)." -ForegroundColor Red
    Write-Host "[*] Report written to: $outFile" -ForegroundColor Green
} else {
    "No NTUSER.MAN files found on $hostname at $(Get-Date)" | Out-File $outFile
    Write-Host "[*] No NTUSER.MAN files found." -ForegroundColor Green
}
