<#
.SYNOPSIS
    TWINLOOT Runbook - Phase 7: COM / TypeLib Persistence Hunt
.DESCRIPTION
    Inspects HKCU\Software\Classes\TypeLib and HKCU\Software\Classes\CLSID for
    scriptlet-based persistence (script:, scrobj.dll, .sct files in AppData/Temp/
    ProgramData), a known LOLBIN persistence technique.
.OUTPUTS
    CSV report of suspicious COM/TypeLib registrations.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "."
)

$ErrorActionPreference = 'SilentlyContinue'
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path $OutputPath "TWINLOOT_COM_TypeLib_${hostname}_${timestamp}.csv"

Write-Host "[*] TWINLOOT - COM/TypeLib Persistence Hunt starting on $hostname" -ForegroundColor Cyan

$pattern = 'script:|scrobj\.dll|\.sct'
$pathPattern = 'AppData|Temp|ProgramData'

$results = New-Object System.Collections.Generic.List[Object]

foreach ($root in @('HKCU:\Software\Classes\TypeLib', 'HKCU:\Software\Classes\CLSID')) {
    if (-not (Test-Path $root)) { continue }

    Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $key = $_
        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        $default = $props.'(default)'

        Get-ChildItem -Path $key.PSPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $sub = $_
            $subProps = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
            $subDefault = $subProps.'(default)'

            if (($subDefault -match $pattern) -or ($subDefault -match $pathPattern)) {
                $results.Add([PSCustomObject]@{
                    Hostname   = $hostname
                    RootKey    = $root
                    KeyPath    = $key.Name
                    SubKeyPath = $sub.Name
                    Value      = $subDefault
                    Suspicious = $true
                })
            }
        }
    }
}

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    Write-Host "[!] HIGH: $($results.Count) suspicious COM/TypeLib entries found. Escalate per Runbook Section 16." -ForegroundColor Red
} else {
    "No suspicious COM/TypeLib scriptlet persistence found on $hostname at $(Get-Date)" | Out-File $outFile
    Write-Host "[*] No suspicious entries found." -ForegroundColor Green
}
Write-Host "[*] Report written to: $outFile" -ForegroundColor Green
