<#
.SYNOPSIS
    TWINLOOT Runbook - Phase 4: Microsoft Edge Hardening
.DESCRIPTION
    Sets the Microsoft Edge enterprise policies HeadlessModeEnabled and
    RemoteDebuggingAllowed to Disabled via registry (equivalent to the Intune/GPO
    ADMX settings). 

    PREFERRED DEPLOYMENT: push via Intune/GPO ADMX (msedge.admx) rather than this
    script where central management is available. This script is provided for
    pilot testing on individual machines or environments without central MDM.
.NOTES
    Requires local administrator rights. Changes apply on next Edge browser restart.
    Maintain documented exceptions for legitimate automation/testing before 100% rollout.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$WhatIfOnly
)

$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

if (-not (Test-Path $edgePolicyPath)) {
    if ($PSCmdlet.ShouldProcess($edgePolicyPath, "Create registry key")) {
        New-Item -Path $edgePolicyPath -Force | Out-Null
    }
}

$settings = @{
    HeadlessModeEnabled    = 0   # 0 = Disabled
    RemoteDebuggingAllowed = 0   # 0 = Disabled
}

foreach ($name in $settings.Keys) {
    $value = $settings[$name]
    if ($PSCmdlet.ShouldProcess("$edgePolicyPath\$name", "Set DWORD to $value")) {
        Set-ItemProperty -Path $edgePolicyPath -Name $name -Value $value -Type DWord -Force
        Write-Host "[*] Set $name = $value (Disabled) under $edgePolicyPath" -ForegroundColor Green
    }
}

Write-Host "[i] Restart Microsoft Edge (or reboot) for policy to take effect." -ForegroundColor Cyan
Write-Host "[i] Verify at edge://policy in the browser." -ForegroundColor Cyan
Write-Host "[i] For fleet-wide rollout, prefer Intune Administrative Templates / GPO msedge.admx over this script." -ForegroundColor Yellow
