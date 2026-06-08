# Backups — Linux

This folder contains scripts and helpers to deploy and manage encrypted, offsite backups for Fedora/RHEL systems.

## Contents

- `deploy-restic-gdrive.sh` — Deploys an automated Restic backup pipeline using `rclone` (Google Drive remote). The script bootstraps the repository, registers a systemd timer/service for scheduled runs, and configures retention and pruning policies.

## Purpose

Provide a reproducible, zero-knowledge encrypted backup architecture using Restic + Rclone that can be deployed to fresh systems with minimal interaction.

## Prerequisites

- `restic` and `rclone` installed
- Google Drive remote configured in `rclone` (or edit the script to use another remote)
- Sufficient disk space and network access for initial repository uploads

## Usage

1. Make the script executable:

```bash
chmod +x deploy-restic-gdrive.sh
```

2. Inspect and edit configuration variables at the top of the script (repository path, retention, remote name).

3. Run interactively for the first time to initialize the repo and verify connectivity:

```bash
sudo ./deploy-restic-gdrive.sh --init
```

4. The script can register a systemd service/timer for scheduled backups; review the `--install-systemd` flag and logs under `journalctl -u restic-backup.service`.

## Security & Safety

- Keep your Restic repository password and `rclone` credentials secure; avoid storing secrets in plaintext.
- Review the script before running on production systems. Running as `root` is required to snapshot system files.

## Notes

- Designed for Fedora/RHEL but portable to other Linux distributions with minor edits.
- If you prefer another cloud provider, update the `rclone` remote and any provider-specific options.
