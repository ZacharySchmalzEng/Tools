# Changelog — Linux Automated Deployment & Provisioning Tool

All notable security updates, defect resolutions, and feature enhancements for the production monolithic `Linux-Deployment-Tool.sh` are documented in this file.

> [!NOTE]
> For the new modular **v3.x Beta Suite**, release notes and version updates are tracked separately in the beta directory at **[`Beta/CHANGELOG.md`](./Beta/CHANGELOG.md)**.

---

## [v2.1] — Multi-Tier Recovery Engine & Hybrid GPU Detection

### Feature Enhancements
- **Multi-Tier Reinstall Engine:** Added `--reinstall` for native package-manager reinstalls and `--rebuild` for supported DKMS/akmods and initramfs recovery. Fedora Atomic and Bazzite cannot force-reinstall host-image drivers; Ubuntu reinstalls its currently installed NVIDIA stack or selects a recommended driver when none is installed. Pacman file overwrites are limited to GPU-driver transactions; Atomic NVIDIA rebuilds clear pending `rpm-ostree` changes and warn that unrelated staged changes are discarded.
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

## [v2.0.1] — Nobara Linux, Flatpak App ID Migration & Atomic OSTree Hardening

### Defect Resolutions & Bug Fixes
- **Flathub OrcaSlicer App ID Migration:** Migrated package identifier from deprecated `com.softfever.OrcaSlicer` to `com.orcaslicer.OrcaSlicer`, with automated legacy fallback in `install_flatpak_app()` to prevent `error: Nothing matches in remote flathub`.
- **Fatal `sed /etc/dnf/automatic.conf` Crash (Exit Code 2):** Added auto-creation of missing `/etc/dnf/automatic.conf` templates on fresh/minimal systems, guarded against service modification in download-only mode (`-d`), and added dual timer support for both `dnf-automatic.timer` and modern `dnf5-automatic.timer`.
- **Nobara NVIDIA Conflicting Transaction Fix:** Fixed a package conflict where `Linux-Deployment-Tool.sh` attempted to pull `akmod-nvidia` via RPM Fusion on Nobara Linux. Nobara utilizes a custom kernel with pre-packaged `dkms-nvidia` from the `nobara-nvidia-production` repository. Nobara is now explicitly identified via `/etc/os-release`, safely skipping redundant akmod installations.
- **Steam Deck & SteamOS Immutable Root Protection:** Added detection for SteamOS (`steamos-readonly`). Automatically unlocks root filesystem overlay (`steamos-readonly disable`) during package installation, initializes the pacman keyring, and restores read-only protection (`steamos-readonly enable`) via signal traps.
- **Fedora Atomic (Silverblue / Kinoite / Bazzite) Support:** Added native `rpm-ostree` layering and Flatpak enforcement for immutable workstations.
- **openSUSE Tumbleweed & Leap Compatibility:** Added native Zypper transaction engine, automatic Packman repository configuration for multimedia codecs, and AppArmor profile management.
- **CVE-2024-6387 (regreSSHion) Mitigation:** Proactively tuned `LoginGraceTime` to `20s` in `/etc/ssh/sshd_config` to neutralize the race condition window for unauthenticated remote code execution.

---

## [v2.0] — Multi-Distribution Architectural Overhaul

### Feature Enhancements
- **Multi-Distribution Engine:** Unified codebase with native specialized handling for Fedora Atomic (Silverblue, Bazzite, Kinoite), Arch Linux, SteamOS (Steam Deck), openSUSE (Tumbleweed & Leap), Nobara, Fedora/RHEL, and Debian/Ubuntu.
- **Distro Override CLI Flags:** Added `--atomic`, `--bazzite`, `--silverblue`, `--arch`, `--steamos`, `--opensuse`, and `--distro=<name>` flags with auto-detection fallbacks, alongside `--unattended` and `--debug` execution modifiers.
- **SteamOS Root Lifecycle:** Automated `steamos-readonly disable` and `steamos-readonly enable` state management with signal restoration traps (`EXIT`, `INT`, `TERM`, `HUP`) and automatic temporary directory cleanup.
- **Zero On-Box Dependencies:** Automatic self-bootstrapping installs missing core utilities (`curl`, `pciutils`, `flatpak`) at runtime.
- **Comprehensive Transcript Logging:** Detailed execution logging to `InstallerLogs/installer_log_<timestamp>.log`.

### Defect Resolutions & Bug Fixes
- **PowerShell 404 Download Failures:** Replaced hardcoded/brittle GitHub RPM URLs with official Microsoft repository registration (`packages.microsoft.com`) and Flathub fallback.
- **ShellCheck SC2155 Subshell Masking:** Split `readonly SCRIPT_DIR` declaration and assignment to preserve subshell exit code visibility.
- **SteamOS GPG Keyring Initialization:** Automates `pacman-key --init` and `--populate archlinux holo` before package transactions to avoid GPG verification aborts.
- **Debian/Ubuntu Debconf Freezes:** Enforces non-interactive frontends (`DEBIAN_FRONTEND=noninteractive`) across all `apt-get` operations.

---

## [v1.0] — Initial Release
- Baseline flag-based provisioning script for Fedora Linux.
