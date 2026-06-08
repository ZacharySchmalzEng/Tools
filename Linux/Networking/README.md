# Networking — Linux

Networking helpers for provisioning secure remote access on Fedora/RHEL systems.

## Contents

- `FedoraEnableSSH.sh` — Installs, enables, and validates the OpenSSH server with optional hardening checks.

## Purpose

Quickly provision secure SSH access and perform idempotent checks to avoid reconfiguring existing installations.

## Usage

1. Make executable and run with sudo:

```bash
chmod +x FedoraEnableSSH.sh
sudo ./FedoraEnableSSH.sh
```

2. The script will enable and start `sshd`, open the firewall port if required, and validate active listeners.

## Notes

- The script may offer optional MFA or PAM hardening steps; review and opt-in as needed.
- Test connectivity locally or from a trusted network before relying on remote access.
