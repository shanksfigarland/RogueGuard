# RogueGuard

RogueGuard is a simple PowerShell defender script for detecting and optionally containing RoguePlanet-style Windows Defender local privilege escalation staging.

## What it checks

- `\\.\pipe\RoguePlanet` named pipe
- `%TEMP%\RP_*` staging folders
- suspicious `wermgr.exe`, `conhost.exe`, or `RoguePlanet.exe` activity from temp paths
- mounted disk images from temp/RP paths
- recent Microsoft Defender events related to `EICAR`, `RP_`, `RoguePlanet`, or `wermgr.exe`
- Windows Error Reporting `QueueReporting` scheduled task status

## Commands

Audit only:

```powershell
.\RogueGuard.ps1
```

Quarantine obvious staging artifacts:

```powershell
.\RogueGuard.ps1 -Mitigate -Quarantine
```

Aggressive containment:

```powershell
.\RogueGuard.ps1 -Mitigate -Quarantine -DetachSuspiciousDiskImages -DisableWerQueueReporting
```

## Notes

Run from elevated PowerShell. Default mode is audit-only and does not remove files or disable tasks.
