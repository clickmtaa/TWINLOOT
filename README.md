#  TWINLOOT Mitigation & Detection – Script Pack

All scripts are PowerShell 5.1+ compatible. Hunt scripts are **read-only** unless
explicitly noted; hardening and containment scripts change system state and are
marked accordingly.


## Folder structure

### `01_Endpoint_Hunting/` (read-only)
| Script  | What it does |
|---|---|
| `01_Python_Hunt.ps1` |  Finds python.exe/pythonw.exe/py.exe/pyw.exe, hashes them, flags user-writable/recent binaries |
| `02_NTUSER_MAN_Hunt.ps1` | Searches for NTUSER.MAN mandatory-profile hive artifacts |
| `03_HKCU_Persistence_Hunt.ps1` |  Audits HKCU Run/RunOnce for script-based persistence and masquerading names |
| `04_COM_TypeLib_Hunt.ps1` |  Audits HKCU TypeLib/CLSID for scriptlet (`.sct`) persistence |
| `05_ScheduledTask_TaskCache_Hunt.ps1` |  Flags risky scheduled task actions + dumps raw TaskCache for manual diff |
| `06_Edge_CommandLine_Hunt.ps1` |  Flags `msedge.exe --headless` / `--remote-debugging-*`, especially with a python.exe parent (the "golden detection") |


### `02_Hardening/` (changes system/policy state — pilot first)
| Script |  What it does |
|---|---|
| `01_Edge_Hardening_Policy.ps1` | Sets `HeadlessModeEnabled` and `RemoteDebuggingAllowed` to Disabled. Prefer Intune/GPO ADMX for fleet rollout; this script is for pilot/standalone use. Supports `-WhatIf`. |
| `02_PowerShell_Logging_Enable.ps1` | Enables Script Block Logging, Module Logging, Transcription. Prefer GPO for fleet rollout. Supports `-WhatIf`. |






-Graham
