# Gaming — Linux

This folder contains tools to provision and configure a dedicated Fedora gaming environment.

## Contents

- `InstallBaseGamingFedora41+.sh` — Automated post-install setup for Fedora 41+ gaming machines. Installs drivers, gaming platforms, and common runtime dependencies.

## Purpose

Provide a quick, idempotent script to get a fresh Fedora desktop ready for gaming, including graphics drivers, Vulkan support, and platform installers.

## Prerequisites

- Fresh Fedora 41+ installation
- Internet connectivity and access to RPM Fusion repositories (script can enable them)

## Usage

1. Make the script executable:

```bash
chmod +x InstallBaseGamingFedora41+.sh
```

2. Run with sudo to install packages and configure drivers:

```bash
sudo ./InstallBaseGamingFedora41+.sh
```

3. Review the script flags and comments at the top for optional behaviors (driver selection, desktop tweaks, and post-install cleanup).

## Notes

- The script is opinionated but modular; edit the package lists to match your hardware and preferences.
- Use snapshots or backups before making large system changes on production machines.
