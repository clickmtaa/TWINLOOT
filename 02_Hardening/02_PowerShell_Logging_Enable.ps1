<#
.SYNOPSIS
    TWINLOOT Runbook - Section 10: Enable PowerShell Logging
.DESCRIPTION
    Enables PowerShell Script Block Logging, Module Logging, and Transcription via
    registry (local policy equivalent). PREFERRED: deploy via GPO
    "Administrative Templates > Windows Components > Windows PowerShell" for
    fleet-wide consistency. This script is for pilot/standalone testing.
.NOTES
    Requires local administrator rights.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TranscriptOutputDir = "C:\ProgramData\MY_PSLogs"
)

$paths = @{
    ScriptBlockLogging = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    ModuleLogging       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    Transcription        = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
}

foreach ($p in $paths.Values) {
    if (-not (Test-Path $p)) {
        if ($PSCmdlet.ShouldProcess($p, "Create registry key")) {
            New-Item -Path $p -Force | Out-Null
        }
    }
}

if ($PSCmdlet.ShouldProcess($paths.ScriptBlockLogging, "Enable Script Block Logging")) {
    Set-ItemProperty -Path $paths.ScriptBlockLogging -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
}

if ($PSCmdlet.ShouldProcess($paths.ModuleLogging, "Enable Module Logging")) {
    Set-ItemProperty -Path $paths.ModuleLogging -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
    $moduleNamesPath = Join-Path $paths.ModuleLogging "ModuleNames"
    if (-not (Test-Path $moduleNamesPath)) { New-Item -Path $moduleNamesPath -Force | Out-Null }
    Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String -Force
}

if ($PSCmdlet.ShouldProcess($paths.Transcription, "Enable Transcription")) {
    if (-not (Test-Path $TranscriptOutputDir)) {
        New-Item -Path $TranscriptOutputDir -ItemType Directory -Force | Out-Null
        # Lock down so standard users cannot tamper with transcripts
        icacls $TranscriptOutputDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    }
    Set-ItemProperty -Path $paths.Transcription -Name "EnableTranscripting" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $paths.Transcription -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $paths.Transcription -Name "OutputDirectory" -Value $TranscriptOutputDir -Type String -Force
}

Write-Host "[*] PowerShell Script Block Logging, Module Logging, and Transcription enabled." -ForegroundColor Green
Write-Host "[i] Script block events log to Microsoft-Windows-PowerShell/Operational (Event ID 4104)." -ForegroundColor Cyan
Write-Host "[i] Transcripts written to: $TranscriptOutputDir" -ForegroundColor Cyan
Write-Host "[i] Also enable AMSI and process-creation command-line auditing (Local Security Policy / GPO: 'Include command line in process creation events') for full coverage per Runbook Section 10." -ForegroundColor Yellow
