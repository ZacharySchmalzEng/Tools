# Linux Automated Deployment & Provisioning Tool (Beta)

> [!IMPORTANT]
> 🧪 **BETA RELEASE (`v3.1.0-beta` — Modular Suite)**: This directory contains the next-generation **3.x Beta** architecture of the Linux Automated Deployment & Provisioning Tool. It decomposes the monolithic script into a top-level orchestrator (`Linux-Deployment-Tool.sh`), a shared core library (`lib/common.sh`), and 11 standalone child modules (`modules/mod-*.sh`) with on-demand GitHub fetching and SHA-256 self-updating. For the stable monolithic `v2.1` release, see **[`../README.md`](../README.md)**.

Version `3.1.0-beta` provides a modular, self-bootstrapping deployment tool with multi-distribution handling, on-demand GitHub module synchronization, and hardware-aware driver orchestration. For questions, bug reports, and feature requests, use [GitHub Issues](https://github.com/ZacharySchmalzEng/Tools/issues).

**`Linux-Deployment-Tool.sh`** is a highly modular, flag-based Bash orchestrator designed to transform a fresh Linux installation into a hardened, fully configured power-user workstation. You can run the top-level orchestrator to dynamically fetch and execute only the modules you select, or invoke individual child scripts in `modules/mod-*.sh` directly.

## 📋 Release Summary (v3.1.0-beta)

* **SecOps Hardening & SSH Rollback Protection (`v3.1.0-beta`):** Added `sshd -t` pre-flight validation with automatic `/etc/ssh/sshd_config` backup restoration on error, atomic temp-file shebang (`#!`) verification across all standalone module bootstraps, and strict regex sanitization on deprecation registries.
* **Cross-Distro Dependency & Shell Logic Sweep (`v3.1.0-beta`):** Fixed always-true `if ... || true` pipeline conditions in `mod-gaming.sh` and `mod-ssh.sh`, unified `dnf-automatic` / `dnf5-plugin-automatic` installation for Fedora 41+, mapped `snap` to `snapd` on RPM/Arch/openSUSE, and added `sha256sum`, `awk`, and `gpg` to prerequisite self-bootstrapping.
* **Gaming Module Consolidation & Deprecation Framework (`v3.0.2-beta`):** Merged Discord provisioning into `mod-gaming.sh` (`--gaming`), introduced the interactive Module Deprecation & Redirect Handler (`DEPRECATED_MODULES_REGISTRY`), added 3-way GitHub update prompts (`[y] Update / [n] Abort & run as-is / [q] Quit`), and hardened DNF5 mirror failover (`timeout=15`, `minrate=1000`, automatic metadata cache refresh).
* **Modular Architecture & Non-Root Log Accessibility (`v3.0.0-beta`–`v3.0.1-beta`):** Split the monolithic engine into `Linux-Deployment-Tool.sh`, `lib/common.sh`, and standalone `modules/mod-*.sh` scripts with SHA-256 GitHub self-updating and `0666` (`+rw`) installer transcripts.

> 📖 **Full Release History:** See **[`CHANGELOG.md`](./CHANGELOG.md)** for complete `v3.x-beta` modular release notes, or **[`../CHANGELOG.md`](../CHANGELOG.md)** for `v1.x–v2.x` monolithic production release history.

## ✨ Features

* **Modular On-Demand Architecture (Beta):** Run the full `./Beta` suite from `Linux-Deployment-Tool-Beta.tar.gz`, run `Linux-Deployment-Tool.sh` by itself to lazily download only requested `modules/mod-*.sh` scripts from GitHub, or execute any child module standalone.
* **Automated GitHub Self-Update Engine (Beta):** Compares local and remote SHA-256 checksums on startup for `Linux-Deployment-Tool.sh`, `lib/common.sh`, and active `modules/mod-*.sh` scripts, prompting to update in place, abort updates and run as-is, or bypass checks via `--no-update-check`.
* **Zero On-Box Dependencies (Self-Bootstrapping):** Automatically pulls down and installs all prerequisite tools (`curl`, `pciutils`/`lspci`, `ca-certificates`, `flatpak`, `coreutils`/`sha256sum`, `gawk`, `gnupg`, and package manager plugins) upon invocation.
* **Strict Mode & Atomic Execution:** Built with `set -euo pipefail`, atomic temp-file downloads with `#!` shebang verification, and signal restoration traps (`EXIT`, `INT`, `TERM`, `HUP`) to ensure fail-fast reliability.
* **Multi-Distribution Engine:** Native special-handling engines for **Fedora / RHEL** (`dnf` with rapid mirror failover), **Nobara Linux** (gaming kernel & DKMS bypass), **Fedora Atomic / Bazzite / Silverblue** (`rpm-ostree` layering & Flatpak containment), **Arch Linux** (`pacman`), **SteamOS** (`steamos-readonly` lifecycle unlocking), **openSUSE Tumbleweed & Leap** (`zypper` & Packman essentials), and **Debian / Ubuntu** (`apt`).
* **GPU-Aware Driver Selection & Nobara Safeguard:** Auto-probes all PCI display controllers via `lspci` and `sysfs`. On Nobara, skips conflicting RPM Fusion `akmod-nvidia` packages to protect `nobara-nvidia-production` DKMS drivers. On Bazzite/SteamOS, respects containerized images and AMD APU hardware.
* **Tiered Security Hardening with SSH Rollback Guard:** Choose between a safe baseline (`--harden`) with SELinux/AppArmor enforcement or a strict zero-trust posture (`--harden-advanced`) that deploys `auditd`, modifies kernel sysctl routing, and disables SSH passwords. All `/etc/ssh/sshd_config` changes are validated via `sshd -t` before daemon restart and automatically rolled back on syntax errors.
* **Native MFA Integration:** Enforce Google Authenticator 2FA on the OpenSSH daemon with a single flag (`--2fa`).
* **Desktop Environment Aware:** Dynamically detects (or prompts for) your Desktop Environment (GNOME or KDE) to install the correct native Quality of Life tools and desktop launchers.
* **Unattended Mode:** Bypasses interactive prompts, auto-redirects deprecated module flags, skips interactive GitHub update prompts, and answers "yes" to package-manager and Flatpak transactions.

## 📂 Beta Architecture & Directory Layout

```text
Beta/
├── Linux-Deployment-Tool.sh          # Main orchestrator at the top of ./Beta
├── CHANGELOG.md                      # Full v3.x-beta security, defect, and feature changelog
├── README.md                         # Beta architecture & usage documentation
├── Linux-Deployment-Tool-Beta.tar.gz # Pre-packaged downloadable tarball of ./Beta
├── lib/
│   └── common.sh                     # Shared core library (distro routing, updates, SSH rollback, traps)
└── modules/
    ├── mod-update.sh                 # --update          (System, Flatpak, Snap upgrades + distro-sync)
    ├── mod-apps.sh                   # --apps            (Core QoL CLI/GUI utilities + DE tools)
    ├── mod-devapps.sh                # --devapps         (Git, jq, fzf, tealdeer, rsync, pwsh, VS Code)
    ├── mod-sysadmin.sh               # --sysadmin        (Remmina, tmux, network/disk/process tools)
    ├── mod-cyber.sh                  # --cyber           (Wireshark, Nmap, TCPDump, Ncat)
    ├── mod-maker.sh                  # --maker           (PrusaSlicer, OrcaSlicer, BambuStudio)
    ├── mod-creators.sh               # --creators        (GIMP, Krita, Blender, Audacity, Inkscape, OBS)
    ├── mod-harden.sh                 # --harden          (SELinux/AppArmor, auto-updates, CIS SSH)
    ├── mod-harden-adv.sh             # --harden-advanced (CIS L2 sysctl, auditd rules, no password SSH)
    ├── mod-ssh.sh                    # --ssh [--2fa]     (OpenSSH Server + optional Google Auth PAM MFA)
    └── mod-gaming.sh                 # --gaming          (Steam, Lutris, Discord, GameMode, GPU Drivers)
```

## 🚀 Usage

### Prerequisites
* **OS**: Fedora, Nobara, Fedora Atomic (Silverblue/Bazzite), Arch Linux, SteamOS (Steam Deck), openSUSE (Tumbleweed/Leap), or Debian/Ubuntu (Zero manual package dependencies required).
* **Privileges**: Must be executed with **root/sudo** privileges.
* **Internet**: Active connection required for package repositories, Flatpak runtimes, and on-demand module fetching.

### Three Ways to Deploy the Beta Suite

All deployment methods share the same universal `./Linux-Deployment-Tool.sh` flag syntax (`--all`, `--apps`, etc.):

#### 1. Tarball Extraction (Full `./Beta` Suite)
Extract the complete Beta directory (`Linux-Deployment-Tool.sh`, `lib/common.sh`, and all `modules/mod-*.sh` scripts) locally:
```bash
curl -fsSL https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta/Linux-Deployment-Tool-Beta.tar.gz | tar -xz
chmod +x Linux-Deployment-Tool.sh
sudo ./Linux-Deployment-Tool.sh --all        # Run all standard modules
sudo ./Linux-Deployment-Tool.sh --apps -y    # Or run a specific module (e.g., --apps)
```

#### 2. Lightweight Main Runner (On-Demand GitHub Module Fetching)
Download only `Linux-Deployment-Tool.sh`; it uses the exact same syntax and automatically fetches `lib/common.sh` plus only the `modules/mod-*.sh` scripts matching your flags:
```bash
curl -fsSL https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta/Linux-Deployment-Tool.sh -o Linux-Deployment-Tool.sh
chmod +x Linux-Deployment-Tool.sh
sudo ./Linux-Deployment-Tool.sh --all        # Run all standard modules
sudo ./Linux-Deployment-Tool.sh --apps -y    # Or run a specific module (e.g., --apps)
```

#### 3. Standalone Child Module Execution
Every child module in `modules/mod-*.sh` can also be executed directly on its own without the main runner:
```bash
sudo ./modules/mod-apps.sh -y
```

### Quick Start Examples
```bash
chmod +x Linux-Deployment-Tool.sh

sudo ./Linux-Deployment-Tool.sh --help                              # Displays the help menu
sudo ./Linux-Deployment-Tool.sh --all                               # The Universal Baseline (All standard modules)
sudo ./Linux-Deployment-Tool.sh --all --no-update-check             # Run all modules without checking GitHub for script updates
sudo ./Linux-Deployment-Tool.sh --all --bazzite                     # Force Bazzite / Fedora Atomic engine
sudo ./Linux-Deployment-Tool.sh --all --steamos                     # Force SteamOS (handles steamos-readonly)
sudo ./Linux-Deployment-Tool.sh --all --opensuse                    # Force openSUSE (Packman repos & Zypper)
sudo ./Linux-Deployment-Tool.sh --all --arch                        # Force Arch Linux (Pacman & multilib)
sudo ./Linux-Deployment-Tool.sh --all --2fa --unattended            # Hands-free deployment with MFA SSH
sudo ./Linux-Deployment-Tool.sh --sysadmin --unattended             # Install the operations and diagnostics toolkit
sudo ./Linux-Deployment-Tool.sh --gaming --reinstall -y             # Reinstall selected gaming, Discord, and driver packages
sudo ./Linux-Deployment-Tool.sh --gaming --rebuild -y               # Reinstall and rebuild supported driver modules/initramfs
sudo ./Linux-Deployment-Tool.sh --update --harden-advanced --debug  # Update, strict harden, and trace commands
sudo ./Linux-Deployment-Tool.sh --all -d                            # Dry-run: Resolve and download packages only
```

## ⚙️ Command-Line Flags

### Core Modules
| Flag | Child Script | Description |
| :--- | :--- | :--- |
| `--update` | `mod-update.sh` | Sequentially upgrades package manager (DNF, rpm-ostree, Pacman, Zypper, APT), Flatpak, and Snap packages. |
| `--apps` | `mod-apps.sh` | **System & Utilities:** Browsers (Brave, Chrome), Obsidian, Signal, Timeshift, btop, eza, plocate, and DE-specific tools (baobab/filelight). |
| `--devapps` | `mod-devapps.sh` | **Development Stack:** Git, jq, fzf, tealdeer, rsync, Python 3, OpenSSL, VS Code, and Microsoft PowerShell (pwsh via official repos / Flathub fallback). |
| `--cyber` | `mod-cyber.sh` | **Security Analysis:** Wireshark (adds user to group), Nmap, TCPDump, and Ncat. |
| `--sysadmin` | `mod-sysadmin.sh` | **System Administration:** Remmina, tmux, Wireshark, Nmap, TCPDump, DNS/network diagnostics (dig, mtr, iperf3), system/disk observability (sysstat, iotop, ncdu, smartmontools), and process tracing (lsof, strace). |
| `--maker` | `mod-maker.sh` | **3D Printing:** PrusaSlicer, OrcaSlicer, and Bambu Studio. |
| `--creators` | `mod-creators.sh` | **Creative Suite:** GIMP, Krita, Blender, Audacity, Inkscape, and OBS Studio. |
| `--gaming` | `mod-gaming.sh` | **Gaming, Discord & Drivers:** Configures package sources (RPM Fusion, Packman, Multilib), installs Steam/Lutris/Bottles, Discord (native RPM on standard Fedora; Flatpak on Atomic/SteamOS/others), GameMode, MangoHud, and auto-detects/installs GPU driver stacks with Nobara safeguards. *(Also catches legacy `--discord` via deprecation redirect).* |
| `--ssh` | `mod-ssh.sh` | Installs, enables, and verifies the OpenSSH daemon with `sshd -t` config validation. |

### Distribution Overrides (Auto-Detected if Omitted)
| Flag | Target Platform | Specific Behavior |
| :--- | :--- | :--- |
| `--atomic` / `--silverblue` | Fedora Silverblue / Kinoite | Uses `rpm-ostree install --idempotent`, Flatpak-first containment, and scheduled reboots. |
| `--bazzite` | Bazzite (Fedora Atomic Gaming) | Protects pre-baked gaming container image; skips host driver layering. |
| `--arch` | Arch Linux / Manjaro / EndeavourOS | Utilizes `pacman -S --needed`, enables `multilib` repository for 32-bit gaming runtimes. |
| `--steamos` | SteamOS (Steam Deck) | Unlocks `/usr` via `steamos-readonly disable`, synchronizes pacman keys, and re-locks read-only integrity upon completion. |
| `--opensuse` | openSUSE Tumbleweed & Leap | Utilizes `zypper` engine, installs the Packman Essentials repository, and enforces AppArmor. |
| `--distro=<name>` | Custom Override | Forces specific engine (`atomic`, `bazzite`, `arch`, `steamos`, `opensuse`, `nobara`, `rpm`, `deb`). |

### Security & Hardening Tiers
| Flag | Child Script | Description |
| :--- | :--- | :--- |
| `--harden` | `mod-harden.sh` | **The Safe Baseline:** Verifies SELinux/AppArmor where available, configures unattended background security patching (`dnf-automatic` / `dnf5-plugin-automatic` / `unattended-upgrades`), and disables direct root login over SSH. |
| `--harden-advanced` | `mod-harden-adv.sh` | **The Strict Posture:** *Warning: Disables SSH Password Auth.* Deploys `auditd` with high-fidelity credential rules, and modifies sysctl to drop ICMP (Ping) requests and enforce strict reverse path forwarding. |
| `--2fa` | `mod-ssh.sh` | Integrates with `--ssh` to install `google-authenticator` and configure PAM/SSHD to enforce Multi-Factor Authentication for remote logins. |

### Global Modifiers
| Flag | Description |
| :--- | :--- |
| `--all` | Executes all standard modules, including `--sysadmin`. *(Note: Intentionally excludes `--harden-advanced` and `--2fa` to prevent accidental lockouts).* |
| `--reinstall` | Reinstalls packages selected by other modules using native package-manager operations. Can be combined with module flags such as `--gaming`; Flatpak apps are reinstalled when selected. |
| `--rebuild` | Includes `--reinstall` and rebuilds supported DKMS/akmods modules and initramfs images. On Arch Linux and SteamOS, Pacman's `--overwrite '*'` is limited to explicit GPU-driver package transactions. On Fedora Atomic, `--gaming --rebuild` clears the pending rpm-ostree deployment before normal idempotent NVIDIA layering. Bazzite does not support host-image NVIDIA driver rebuilds. |
| `--no-update-check` | Skips the startup GitHub SHA-256 version check for `Linux-Deployment-Tool.sh`, `lib/common.sh`, and `modules/mod-*.sh`. |
| `-y` | Auto-install (answers yes to all package manager prompts). |
| `-d` | Download only (applies to DNF updates, excellent for dry-run validations). |
| `--unattended` | Bypasses the DE prompt (defaults to KDE), suppresses the reboot and GitHub update prompts, auto-redirects deprecated flags, and applies `-y` automatically. |
| `--debug` | Enables `set -x` to print a trace of simple commands directly to the console and log file for deep troubleshooting. |

## 📝 Important Notes

* **Log Files (`0666` Non-Root Accessible)**: Execution generates a detailed transcript in the `InstallerLogs` directory (`0777`) created alongside the script with `0666` (`+rw`) file permissions so non-root desktop users and editors can inspect logs without `sudo`.
* **SSH Config Rollback Protection**: Whenever `--harden`, `--harden-advanced`, or `--ssh` modifies `/etc/ssh/sshd_config`, the suite validates the configuration with `sshd -t` prior to restarting the service and automatically restores the pre-change backup if validation fails.
* **The `--harden-advanced` Flag**: If you use this flag, you **must** have an SSH Public Key (`id_rsa.pub` or `id_ed25519.pub`) copied to the machine's `~/.ssh/authorized_keys` file before closing your terminal session, as password authentication will be disabled.
* **Driver Auto-Selection**: The gaming module detects the GPU vendor across all PCI display controllers and installs the appropriate NVIDIA or AMD driver stack for the current Linux distribution.

## ⚠️ Disclaimer
This **Beta** script modifies kernel parameters, PAM authentication, and core system utilities. Please review the code in `Linux-Deployment-Tool.sh`, `lib/common.sh`, and `modules/mod-*.sh` to ensure the configurations match your personal environment needs before executing.

## 👤 Author & Community

* **Author**: Zachary Schmalz
* **GitHub Repository**: [ZacharySchmalzEng/Tools](https://github.com/ZacharySchmalzEng/Tools/)
* **Bug Reports & Feature Requests**: Please submit all issues, questions, and feature requests via the [GitHub Issues Tracker](https://github.com/ZacharySchmalzEng/Tools/issues). Contributions and PRs are always welcome!
