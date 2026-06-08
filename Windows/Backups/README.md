# Backups — Windows

Scripts to deploy automated, VSS-enabled backups targeting cloud remotes on Windows platforms.

## Contents

- `deploy-restic-gdrive.ps1` — Deploys a Restic backup pipeline using `rclone` for Google Drive. Registers a SYSTEM-context Scheduled Task and leverages VSS to snapshot locked files.

## Purpose

Provide a repeatable Windows-native deployment for Restic-based offsite backups that safely handle open/locked files.

## Prerequisites

- PowerShell (Windows PowerShell or PowerShell 7+)
- Restic and Rclone binaries available on the system
- Administrative privileges to register scheduled tasks and access VSS

## Usage

1. Inspect the script and run in an elevated PowerShell session to deploy the scheduled task:

```powershell
.\deploy-restic-gdrive.ps1 -Install
```

2. The script supports configuration for retention, randomized delays to avoid API rate limits, and repository bootstrap options.

## Safety

- Review credentials and secrets handling before deploying in production.
- The scheduled task runs as SYSTEM by default; confirm environment-specific requirements.
