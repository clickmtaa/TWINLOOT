<#
.SYNOPSIS
    TWINLOOT Runbook  Entra ID Application, Service
    Principal, and OAuth Consent Audit.
.DESCRIPTION
    Uses the Microsoft Graph PowerShell SDK to build the application inventory
    to flag recently created/modified appregistrations, list service principals with credentials/expiry, and flag
    high-risk OAuth permission grants (Mail.*, Files.*, Sites.*, *.All).
.PREREQUISITES
    Install-Module Microsoft.Graph -Scope CurrentUser
    Connect-Graph with an account holding at least:
      Application.Read.All, Directory.Read.All, DelegatedPermissionGrant.Read.All,
      AppRoleAssignment.ReadWrite.All (read-only usage here only requires *.Read.All)
.OUTPUTS
    Three CSVs: application inventory, service principal register, high-risk OAuth grants.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [int]$RecentDays = 30
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$requiredScopes = @(
    "Application.Read.All",
    "Directory.Read.All",
    "DelegatedPermissionGrant.Read.All"
)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Host "[!] Microsoft.Graph module not found. Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Red
    return
}

Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

Connect-MgGraph -Scopes $requiredScopes -NoWelcome

Write-Host "[*] TWINLOOT - Entra Application / OAuth Audit starting" -ForegroundColor Cyan

# --- 1. Application Registration Inventory (Runbook Section 18) ---
$apps = Get-MgApplication -All -Property Id,AppId,DisplayName,CreatedDateTime,SignInAudience,RequiredResourceAccess,KeyCredentials,PasswordCredentials

$appInventory = foreach ($a in $apps) {
    $isRecent = $a.CreatedDateTime -gt (Get-Date).AddDays(-$RecentDays)
    $credExpiries = @()
    $credExpiries += $a.PasswordCredentials | ForEach-Object { $_.EndDateTime }
    $credExpiries += $a.KeyCredentials | ForEach-Object { $_.EndDateTime }

    [PSCustomObject]@{
        DisplayName        = $a.DisplayName
        AppId               = $a.AppId
        CreatedDateTime      = $a.CreatedDateTime
        RecentlyCreated       = $isRecent
        SignInAudience         = $a.SignInAudience
        SecretCount             = ($a.PasswordCredentials | Measure-Object).Count
        CertCount                 = ($a.KeyCredentials | Measure-Object).Count
        EarliestCredentialExpiry   = ($credExpiries | Sort-Object | Select-Object -First 1)
        RequiredResourceAccessCount = ($a.RequiredResourceAccess | Measure-Object).Count
    }
}
$appInventoryFile = Join-Path $OutputPath "TWINLOOT_EntraAppInventory_${timestamp}.csv"
$appInventory | Sort-Object RecentlyCreated -Descending | Export-Csv -Path $appInventoryFile -NoTypeInformation -Encoding UTF8

# --- 2. Service Principal Register (Runbook Section 20) ---
$sps = Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,ServicePrincipalType,AccountEnabled,KeyCredentials,PasswordCredentials,Tags

$spRegister = foreach ($sp in $sps) {
    $credExpiries = @()
    $credExpiries += $sp.PasswordCredentials | ForEach-Object { $_.EndDateTime }
    $credExpiries += $sp.KeyCredentials | ForEach-Object { $_.EndDateTime }

    [PSCustomObject]@{
        DisplayName    = $sp.DisplayName
        AppId          = $sp.AppId
        Type           = $sp.ServicePrincipalType
        AccountEnabled = $sp.AccountEnabled
        SecretCount    = ($sp.PasswordCredentials | Measure-Object).Count
        CertCount      = ($sp.KeyCredentials | Measure-Object).Count
        EarliestCredentialExpiry = ($credExpiries | Sort-Object | Select-Object -First 1)
    }
}
$spFile = Join-Path $OutputPath "TWINLOOT_ServicePrincipalRegister_${timestamp}.csv"
$spRegister | Export-Csv -Path $spFile -NoTypeInformation -Encoding UTF8

# --- 3. High-risk OAuth Consent Grants (Runbook Section 19) ---
$highRiskScopes = @(
    'Mail.Read','Mail.ReadWrite','Mail.Send',
    'Files.Read','Files.ReadWrite',
    'Sites.Read.All','Sites.ReadWrite.All',
    'User.Read.All','Group.Read.All','Directory.Read.All'
)

$grants = Get-MgOauth2PermissionGrant -All

$riskyGrants = foreach ($g in $grants) {
    $scopes = ($g.Scope -split ' ')
    $matched = $scopes | Where-Object { $_ -in $highRiskScopes }
    if ($matched) {
        $clientSp = Get-MgServicePrincipal -ServicePrincipalId $g.ClientId -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            ClientAppDisplayName = $clientSp.DisplayName
            ClientAppId          = $clientSp.AppId
            ConsentType          = $g.ConsentType
            PrincipalId          = $g.PrincipalId
            ResourceId            = $g.ResourceId
            HighRiskScopes         = ($matched -join ', ')
            AllScopes                = $g.Scope
        }
    }
}
$grantsFile = Join-Path $OutputPath "TWINLOOT_HighRiskOAuthGrants_${timestamp}.csv"
$riskyGrants | Export-Csv -Path $grantsFile -NoTypeInformation -Encoding UTF8

Write-Host "[*] Application inventory: $appInventoryFile ($($appInventory.Count) apps, $((($appInventory|Where-Object RecentlyCreated).Count)) recent)" -ForegroundColor Green
Write-Host "[*] Service principal register: $spFile ($($spRegister.Count) principals)" -ForegroundColor Green
Write-Host "[*] High-risk OAuth grants: $grantsFile ($($riskyGrants.Count) flagged)" -ForegroundColor Green
Write-Host "[i] Cross-reference recently created apps + broad Graph permissions + unknown owner = High severity per Runbook Section 19." -ForegroundColor Yellow

Disconnect-MgGraph | Out-Null
