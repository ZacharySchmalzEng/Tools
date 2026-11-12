# Changelog — Linux Automated Deployment & Provisioning Tool

All notable security updates, defect resolutions, and feature enhancements for `Linux-Deployment-Tool.sh` and its modular child scripts are documented in this file.

---

## [v3.0-beta] — Modular On-Demand Architecture & Standalone Child Scripts

### Feature Enhancements
- **Modular Child Script Architecture (`Beta/`):** Decomposed the monolithic deployment script into a main orchestrator (`Linux-Deployment-Tool.sh`), a shared core library (`lib/common.sh`), and 12 standalone child module scripts (`modules/mod-*.sh`).
- **Independent & Orchestrated Execution:** Every child script in `modules/` can be invoked independently from the command line (e.g., `sudo ./modules/mod-gaming.sh --rebuild -y`) or orchestrated via the main entry point (`sudo ./Linux-Deployment-Tool.sh --gaming --ssh -y`).
- **Lazy Flag-Driven GitHub Sync:** Missing child scripts and the shared library are downloaded on-demand from the GitHub repository (`main` branch) only when their corresponding CLI flags are invoked, and cached locally in `./lib/` and `./modules/` for subsequent runs.
- **Standalone Changelog Extraction:** Separated historical release notes, CVE mitigations, and defect resolutions from script header comments into a dedicated `CHANGELOG.md` file.

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

## [v2.0.1] — Production Hotfix Release

### Defect Resolutions & Bug Fixes
- **Resolved Flathub OrcaSlicer App ID Not Found:** Migrated package identifier from deprecated `com.softfever.OrcaSlicer` to `com.orcaslicer.OrcaSlicer` with automated legacy fallback in `install_flatpak_app()`.
- **Resolved Fatal `sed /etc/dnf/automatic.conf` Crash (Exit code 2):** Added auto-creation of missing `/etc/dnf/automatic.conf` template on fresh/minimal systems, guarded against uninstalled configuration modifications in download-only mode (`-d`), and added dual timer support for both `dnf-automatic.timer` and modern `dnf5-automatic.timer`.

---

## [v2.0] — Multi-Distro Engine, Multi-DE Support & SecOps Hardening

### Security Updates & CVE Mitigations
- **CVE-2024-6387 (OpenSSH "regreSSHion"):** Mitigated remote code execution vulnerability by tuning `LoginGraceTime` to `20s`, capping `MaxAuthTries` to `3`, `MaxSessions` to `4`, `MaxStartups` to `10:30:60`, and setting `ClientAliveInterval` to `300`.
- **Interruption & SteamOS Lock Traps:** Implemented `cleanup_handler` across `EXIT`, `INT`, `TERM`, and `HUP` to guarantee immediate re-locking of SteamOS immutable root protection (`steamos-readonly enable`) and secure removal of temporary directories.
- **Ambient File Mode Hardening:** Enforced strict global `umask 077` at script entry; strictly enforced `0700` permissions on `$LOG_DIR` and `0600` on `$LOG_FILE`.
- **CIS Level 2 Kernel Sysctl Hardening:** Blocked SUID memory core dumps (`fs.suid_dumpable = 0`), enforced complete ASLR (`kernel.randomize_va_space = 2`), enabled `log_martians` and reverse path filtering (`rp_filter = 1`), and dropped ICMP redirects and source routes.
- **Privilege & Identity Auditd Rules:** Applied high-fidelity audit monitoring rules for `/etc/sudoers`, `/etc/shadow`, `/etc/passwd`, `/etc/gshadow`, and `/etc/ssh/sshd_config`.
- **PAM SSH 2FA Protection:** Configured `pam_google_authenticator` with `nullok` during provisioning to eliminate administrator lockout prior to OTP key generation.

### Feature Enhancements
- **Multi-Distro Engine:** Added native support for Fedora Atomic variants (Silverblue, Bazzite, Kinoite), Arch Linux, SteamOS (Steam Deck), and openSUSE (Tumbleweed & Leap).
- **Distro Override CLI Flags:** Added `--atomic`, `--bazzite`, `--silverblue`, `--arch`, `--steamos`, `--opensuse`, and `--distro=<name>` manual override flags with auto-detection fallbacks.
- **Expanded Desktop Environment Suite:** Added native support, auto-detection, and tailored QoL modules for COSMIC Desktop (System76 Rust Epoch), XFCE, and Cinnamon alongside GNOME and KDE Plasma.
- **Desktop Environment CLI Flags:** Added `--gnome`, `--kde`, `--cosmic`, `--xfce`, `--cinnamon`, and `--de=<name>` flags for fully automated non-interactive provisioning.
- **SteamOS Lifecycle:** Added automated `steamos-readonly disable/enable` state machine.
- **Package Router:** Implemented unified `pkg_install()` supporting `dnf`, `rpm-ostree`, `pacman`, `zypper`, and `apt-get` with auto-healing cache updates.
- **Zero-Dependency Auto-Bootstrap:** Implemented `bootstrap_prerequisites()` for bare-metal installs.

### Defect Resolutions & Bug Fixes
- **Resolved Nobara NVIDIA Driver Packaging Collision:** Bypassed manual RPM Fusion `akmod-nvidia` installation on Nobara Linux to eliminate fatal conflicts with pre-installed `dkms-nvidia` packages from the `nobara-nvidia-production` repository.
- **Resolved PowerShell 404 Download Failures:** Replaced unversioned GitHub RPM release downloads with official Microsoft package repositories and Flathub fallback.
- **Resolved ShellCheck SC2155 Warning:** Split `readonly SCRIPT_DIR` declaration and subshell assignment to prevent masking subshell exit codes.
- **Resolved SteamOS GPG Signature Failures:** Added automated `pacman-key --init` and `--populate archlinux holo` initialization prior to running `pacman` transactions.
- **Resolved Non-interactive Debian Debconf Stalls:** Exported `DEBIAN_FRONTEND=noninteractive` during `apt-get` invocations.

---

## [v1.2] — Self-Healing Cache & Debian Unattended Mode
- Added automated self-healing package cache and non-interactive Debian mode.

## [v1.0] — Initial Release
- Initial modular deployment release.
