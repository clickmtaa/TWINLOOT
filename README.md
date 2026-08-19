# NSSF TWINLOOT Mitigation & Detection – Script Pack

Companion scripts for `NSSF_TWINLOOT_Mitigation_Detection_Runbook.md` (v1.0, 18 Aug 2026).
All scripts are PowerShell 5.1+ compatible. Hunt scripts are **read-only** unless
explicitly noted; hardening and containment scripts change system state and are
marked accordingly.

**Before running anything in production:** complete Runbook Section 6 (Phase 0 –
InfoSec Engagement) and Section 4 (Roles and Responsibilities). Pilot on a small
representative endpoint set first (Runbook Section 12 rollout model), then scale.

## Folder structure

### `01_Endpoint_Hunting/` (read-only, run per Runbook Section 41 "24-Hour Action Plan")
| Script | Runbook Section | What it does |
|---|---|---|
| `01_Python_Hunt.ps1` | 8, 9 | Finds python.exe/pythonw.exe/py.exe/pyw.exe, hashes them, flags user-writable/recent binaries |
| `02_NTUSER_MAN_Hunt.ps1` | 14 | Searches for NTUSER.MAN mandatory-profile hive artifacts |
| `03_HKCU_Persistence_Hunt.ps1` | 15 | Audits HKCU Run/RunOnce for script-based persistence and masquerading names |
| `04_COM_TypeLib_Hunt.ps1` | 16 | Audits HKCU TypeLib/CLSID for scriptlet (`.sct`) persistence |
| `05_ScheduledTask_TaskCache_Hunt.ps1` | 17 | Flags risky scheduled task actions + dumps raw TaskCache for manual diff |
| `06_Edge_CommandLine_Hunt.ps1` | 13, 46 | Flags `msedge.exe --headless` / `--remote-debugging-*`, especially with a python.exe parent (the "golden detection") |

Run individually with `-OutputPath <folder>`, or all at once via the orchestrator.

### `02_Hardening/` (changes system/policy state — pilot first)
| Script | Runbook Section | What it does |
|---|---|---|
| `01_Edge_Hardening_Policy.ps1` | 12 | Sets `HeadlessModeEnabled` and `RemoteDebuggingAllowed` to Disabled. Prefer Intune/GPO ADMX for fleet rollout; this script is for pilot/standalone use. Supports `-WhatIf`. |
| `02_PowerShell_Logging_Enable.ps1` | 10 | Enables Script Block Logging, Module Logging, Transcription. Prefer GPO for fleet rollout. Supports `-WhatIf`. |

Kaspersky Application Control (Runbook Section 27–28) and FortiGate policy changes
are console-managed and not scripted here — see the Detection Matrix (Section 39)
for what to configure in each console.

### `03_Entra_Identity/` (cloud-side, requires Microsoft Graph / Teams PowerShell)
| Script | Runbook Section | What it does |
|---|---|---|
| `01_Entra_App_OAuth_Audit.ps1` | 18, 19, 20 | Builds app registration inventory, service principal register, and flags high-risk OAuth consent grants (Mail.*, Files.*, Sites.*, *.All) |
| `02_Teams_External_Access_Review.ps1` | 22 | Reports current Teams federation/external-access configuration for the allowlist planning exercise |

Requires: `Install-Module Microsoft.Graph -Scope CurrentUser` and
`Install-Module MicrosoftTeams -Scope CurrentUser`, plus an account with the
read scopes noted in each script's header.

### `04_Network/`
| Script | Runbook Section | What it does |
|---|---|---|
| `01_Endpoint_LateralMovement_Hunt.ps1` | 26 | Per-host check of outbound SMB/RDP/WinRM/RPC/MSSQL/LDAP/SSH connections and fan-out, flagging python/powershell-owned connections |
| `02_FortiGate_Log_Hunt.ps1` | 1, 12, 24, 25 | Processes an exported FortiGate/FortiAnalyzer traffic-log CSV against reported IOCs, lateral-movement fan-out, and unknown-SharePoint-tenant logic. **Adjust `$ColumnMap` to match your export's actual column headers before running.** |

### `05_Evidence_IR/`
| Script | Runbook Section | What it does |
|---|---|---|
| `01_Evidence_Collection.ps1` | 47 | Read-only collection of the Section 47 evidence checklist into one zipped, timestamped case folder |
| `02_Isolate_Endpoint.ps1` | 34, 48 | **Containment action.** Applies local firewall isolation rules. Requires `-Confirm`; supports `-Rollback`. Prefer centrally-managed EDR isolation (Kaspersky/Defender) where available. |
| `03_Credential_Compromise_Response.ps1` | 16, 31, 32 | Revokes a user's cloud sessions, optionally forces password reset, and reports MFA methods/registered devices for manual review |

### `06_Orchestrator/`
| Script | What it does |
|---|---|
| `Run_All_Endpoint_Hunts.ps1` | Runs all six `01_Endpoint_Hunting` scripts plus the endpoint lateral-movement hunt, consolidates output into one timestamped folder per host, and prints a severity roll-up |

## Suggested deployment order (mirrors Runbook Section 51)

1. **P1 – Immediate:** `01_Endpoint_Hunting/*` (or `06_Orchestrator/Run_All_Endpoint_Hunts.ps1`) on representative endpoints; `03_Entra_Identity/01_Entra_App_OAuth_Audit.ps1`; `04_Network/02_FortiGate_Log_Hunt.ps1` against recent logs.
2. **P2 – 24–48h:** `02_Hardening/*` pilot rollout; `03_Entra_Identity/02_Teams_External_Access_Review.ps1`.
3. **P3 – 7 days:** Wire `04_Network/02_FortiGate_Log_Hunt.ps1` into a scheduled job against daily log exports; build the Zabbix dashboard/triggers described in Runbook Sections 37–38 (not scripted here — Zabbix-side configuration).
4. **P4 – 30 days:** Broaden Kaspersky Application Control per Section 28; phishing-resistant MFA rollout.

If evidence collection or containment scripts turn up a confirmed finding, stop,
preserve evidence with `05_Evidence_IR/01_Evidence_Collection.ps1`, and escalate
to InfoSec per Runbook Section 48 **before** further action — do not delete
suspicious files or reimage without sign-off (Runbook Section 35).
# TWINLOOT
# TWINLOOT
# TWINLOOT
# TWINLOOT
# TWINLOOT
