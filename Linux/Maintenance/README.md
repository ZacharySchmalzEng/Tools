# Maintenance — Linux

This folder includes maintenance helpers for system updates and targeted package transitions.

## Contents

- `updatesAllMethods.sh` — A universal update alias that updates DNF, Flatpak, and Snap packages in sequence.
- `FedoraDiscordUpdate.sh` — Automates migrating Discord from Flatpak to the native RPM package via RPM Fusion.

## Purpose

Provide small, focused scripts to keep Fedora systems updated and to perform common maintenance tasks reliably.

## Usage

1. Make scripts executable:

```bash
chmod +x updatesAllMethods.sh FedoraDiscordUpdate.sh
```

2. Run with sudo when system-level package operations are required:

```bash
sudo ./updatesAllMethods.sh
```

3. `FedoraDiscordUpdate.sh` is intended for interactive or staged execution; review the script before running to confirm desired behavior.

## Notes

- `updatesAllMethods.sh` supports `-y` (auto-install) and `-d` (download-only) flags — check the script header for detailed options.
- Always review transaction prompts when running package managers on production systems.
