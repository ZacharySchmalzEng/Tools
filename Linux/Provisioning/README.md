# Linux Provisioning

This folder contains tools for preparing and configuring Linux systems.

## Linux Deployment Tool

The [Linux Deployment Tool](Linux-Deployment-Tool/README.md) is a modular Bash utility for provisioning a workstation. It supports Fedora and Nobara, Fedora Atomic variants, Arch Linux, SteamOS, openSUSE, and Debian/Ubuntu, with options for applications, development tools, gaming and GPU drivers, SSH, and security hardening.

Version 2.1 adds `--reinstall` and `--rebuild`, which can be combined with module options. `--reinstall` uses package-manager reinstall operations; `--rebuild` also rebuilds supported GPU kernel modules and initramfs images. For example:

```bash
sudo ./Linux-Deployment-Tool.sh --gaming --reinstall -y
sudo ./Linux-Deployment-Tool.sh --gaming --rebuild -y
```

On Fedora Atomic, `--gaming --rebuild` clears the pending rpm-ostree deployment, including unrelated staged changes, before normal idempotent NVIDIA layering; it cannot force-reinstall host-image drivers. Bazzite does not support host-image NVIDIA driver rebuilds. The modes do not bypass package-manager locks. On Arch Linux and SteamOS, `--rebuild` uses Pacman's `--overwrite '*'` only for GPU-driver package transactions, so use it only when repairing those drivers.

See the [full command reference](Linux-Deployment-Tool/README.md) for prerequisites, modules, and supported options.
