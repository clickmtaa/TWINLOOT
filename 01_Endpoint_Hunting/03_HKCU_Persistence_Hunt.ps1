<#
.SYNOPSIS
     TWINLOOT Runbook - Phase 6: HKCU Run/RunOnce Persistence Hunt
.DESCRIPTION
    Inspects HKCU Run/RunOnce keys (current user and all loaded user hives) for
    entries referencing python/powershell/cmd/wscript/cscript/mshta/script extensions,
    and flags names masquerading as legitimate update services.
.OUTPUTS
    CSV report of all Run/RunOnce entries with a Suspicious flag.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "."
)

$ErrorActionPreference = 'SilentlyContinue'
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path $OutputPath "TWINLOOT_HKCU_Persistence_${hostname}_${timestamp}.csv"

Write-Host "[*]  TWINLOOT - HKCU Persistence Hunt starting on $hostname" -ForegroundColor Cyan

$suspiciousTokens = 'python|pythonw|powershell|cmd\.exe|wscript|cscript|mshta|\.py\b|\.pyc\b|\.vbs\b|\.js\b|\.sct\b'
$masqueradeNames  = 'UserExperienceSync|WindowsUpdate|MicrosoftUpdate|OneDriveUpdate|TeamsUpdate|OfficeUpdate'

$results = New-Object System.Collections.Generic.List[Object]

function Get-RunKeyEntries {
    param($HivePath, $SidOrUser)

    foreach ($subkey in @('Software\Microsoft\Windows\CurrentVersion\Run',
                          'Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
        $full = Join-Path $HivePath $subkey
        if (Test-Path $full) {
            $props = Get-ItemProperty -Path $full -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider)$' } |
                    ForEach-Object {
                        $name = $_.Name
                        $value = $_.Value
                        $suspicious = ($value -match $suspiciousTokens) -or ($name -match $masqueradeNames)
                        [PSCustomObject]@{
                            Hostname   = $hostname
                            User       = $SidOrUser
                            RegistryKey= $subkey
                            ValueName  = $name
                            ValueData  = $value
                            Suspicious = $suspicious
                        }
                    }
            }
        }
    }
}

# Current user hive
Get-RunKeyEntries -HivePath 'HKCU:' -SidOrUser $env:USERNAME | ForEach-Object { $results.Add($_) }

# Other loaded hives under HKEY_USERS (covers logged-in / mounted profiles)
Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-.*[^_Classes]$' } |
    ForEach-Object {
        $hive = "Registry::HKEY_USERS\$($_.PSChildName)"
        Get-RunKeyEntries -HivePath $hive -SidOrUser $_.PSChildName | ForEach-Object { $results.Add($_) }
    }

$results | Sort-Object Suspicious -Descending | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8

$susCount = ($results | Where-Object Suspicious).Count
Write-Host "[*] Total Run/RunOnce entries: $($results.Count). Suspicious: $susCount" -ForegroundColor Yellow
Write-Host "[*] Report written to: $outFile" -ForegroundColor Green
if ($susCount -gt 0) {
    Write-Host "[!] Validate executable paths for flagged entries before taking action (Runbook Section 15)." -ForegroundColor Red
}
