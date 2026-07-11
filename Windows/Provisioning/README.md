# Provisioning — Windows

Provisioning and maintenance tools for Windows system hardening, deployment, and recurring upkeep.

## Contents

- `Deploy-OSMaintenanceTask.ps1` — Registers a weekly, SYSTEM-context scheduled task that performs TRIM, DNS cache flushing, `chkdsk` health checks, `SFC`/`DISM` repair attempts, and temporary-file cleanup. On supported systems it can also register a companion auto-update task for `winget` and Windows Update.
- `Windows-Deployment-Tool/` — A modular, flag-driven deployment framework for fresh Windows installs (see the tool's README in the folder).

## Purpose

Automate routine OS maintenance, support long-term upkeep, and provide a flexible deployment framework for provisioning Windows systems.

## Usage

1. Review the included README for `Windows-Deployment-Tool` before running.
2. Run the maintenance task registration with administrative privileges:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Deploy-OSMaintenanceTask.ps1
```

3. The script is idempotent and will replace any existing maintenance task with the same name before re-registering it.

## Notes

- The maintenance task runs as `NT AUTHORITY\SYSTEM` and is scheduled weekly.
- Many provisioning scripts are destructive or perform wide-reaching changes; test in VMs before production use.
- Review scheduled task parameters, randomized delays, and execution context before deployment.
