# Changelog — Linux Automated Deployment & Provisioning Tool

All notable security updates, defect resolutions, and feature enhancements for the production monolithic `Linux-Deployment-Tool.sh` are documented in this file.

> [!NOTE]
> For the new modular **v3.x Beta Suite**, release notes and version updates are tracked separately in the beta directory at **[`Beta/CHANGELOG.md`](./Beta/CHANGELOG.md)**.

---

## [v2.1] — Multi-Tier Recovery Engine & Hybrid GPU Detection

### Feature Enhancements
- **Multi-Tier Reinstall Engine:** Added `--reinstall` for native package-manager reinstalls and `--rebuild` for supported DKMS/akmods and initramfs recovery. Pacman file overwrites are limited to GPU-driver transactions; Atomic NVIDIA rebuilds clear pending `rpm-ostree` changes and warn that unrelated staged changes are discarded.
- **DNF Network Resilience:** Added 10 retries and a 60-second timeout (`--setopt=retries=10 --setopt=timeout=60`) to DNF package and metadata operations to better tolerate slow or intermittently unreachable mirrors.
- **Split Installed/Missing Package Routing:** Added `rpm -q` state inspection in `pkg_install()` so DNF cleanly splits mixed package arrays into separate `install` and `reinstall` transactions without failing on missing packages.
- **System Administration Module (`--sysadmin`):** Added dedicated operations and observability toolkit including `remmina`, `tmux`, `wireshark`, `nmap`, `tcpdump`, `bind-utils`, `mtr`, `iperf3`, `sysstat`, `iotop`, `ncdu`, `smartmontools`, `lsof`, and `strace`.

### Defect Resolutions & Bug Fixes
- **Fixed Hybrid GPU Detection:** Inspects all `lspci` display-controller entries (`VGA|3D controller|Display controller`) and falls back to `sysfs` (`/sys/bus/pci/devices/*/vendor`), preventing an Intel iGPU from masking a supported NVIDIA or AMD discrete GPU.

---

## [v2.0.2] — Package Routing & Strict Mode Hardening

### Defect Resolutions & Bug Fixes
- **Resolved Flatpak Non-Zero Exit Abort:** Updated `install_flatpak_app()` to gracefully warn and return `0` on skipped or failed Flatpak installations rather than triggering the `ERR` trap under strict `set -e` mode.
- **Resolved Wireshark-Qt Package Resolution Failure:** Mapped `wireshark-qt` to `wireshark` for Fedora/RPM distros and added `--skip-unavailable` to `dnf` package transactions.
- **Resolved Multiline Array Logging:** Restored standard `IFS` parsing so array expansion logs cleanly with space separators instead of newlines.
- **Resolved Top-Level Local Keyword Errors:** Removed invalid top-level `local` declarations from hardening, Discord, and gaming configuration blocks.

---

## [v2.0.1] — Nobara Linux & Atomic OSTree Hardening

### Defect Resolutions & Bug Fixes
- **Nobara NVIDIA Conflicting Transaction Fix:** Fixed a package conflict where `Linux-Deployment-Tool.sh` attempted to pull `akmod-nvidia` via RPM Fusion on Nobara Linux. Nobara utilizes a custom kernel with pre-packaged `dkms-nvidia` from the `nobara-nvidia-production` repository. Nobara is now explicitly identified via `/etc/os-release`, safely skipping redundant akmod installations.
- **Steam Deck & SteamOS Immutable Root Protection:** Added detection for SteamOS (`steamos-readonly`). Automatically unlocks root filesystem overlay (`steamos-readonly disable`) during package installation, initializes the pacman keyring, and restores read-only protection (`steamos-readonly enable`) via signal traps.
- **Fedora Atomic (Silverblue / Kinoite / Bazzite) Support:** Added native `rpm-ostree` layering and Flatpak enforcement for immutable workstations.
- **openSUSE Tumbleweed & Leap Compatibility:** Added native Zypper transaction engine, automatic Packman repository configuration for multimedia codecs, and AppArmor profile management.
- **CVE-2024-6387 (regreSSHion) Mitigation:** Proactively tuned `LoginGraceTime` to `20s` in `/etc/ssh/sshd_config` to neutralize the race condition window for unauthenticated remote code execution.

---

## [v2.0] — Multi-Distribution Architectural Overhaul

### Feature Enhancements
- Unified codebase across RPM (Fedora, RHEL, CentOS), Arch Linux, SteamOS, openSUSE, and Debian/Ubuntu.
- Signal restoration traps (`EXIT`, `INT`, `TERM`, `HUP`) and automatic temporary directory cleanup.
- Added `--reinstall`, `--rebuild`, `--unattended`, and `--debug` execution flags.
- Comprehensive logging to `InstallerLogs/installer_log_<timestamp>.log`.

---

## [v1.0] — Initial Release
- Baseline flag-based provisioning script for Fedora Linux.
