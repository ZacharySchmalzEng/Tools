# Provisioning — Windows

Provisioning tools for Windows system maintenance and large-scale deployments.

## Contents

- `Deploy-OSMaintenanceTask.ps1` — Registers an idempotent scheduled maintenance task that performs SFC, DISM, chkdsk, and component cleanup.
- `Windows-Deployment-Tool/` — A modular, flag-driven deployment framework for fresh Windows installs (see the tool's README in the folder).

## Purpose

Automate routine OS maintenance and provide a flexible deployment framework for provisioning Windows systems.

## Usage

1. Review the included README for `Windows-Deployment-Tool` before running.

2. Run maintenance task registration with administrative privileges:

```powershell
.\Deploy-OSMaintenanceTask.ps1 -Install
```

## Notes

- Many provisioning scripts are destructive or perform wide-reaching changes; test in VMs before production use.
- Review scheduled task parameters, randomized delays, and execution context before deployment.
