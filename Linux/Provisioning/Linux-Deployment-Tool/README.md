# Linux Automated Deployment & Provisioning Tool

Version 2.1 provides a modular, self-bootstrapping deployment tool with multi-distribution handling and hardware-aware driver orchestration. For questions, bug reports, and feature requests, use [GitHub Issues](https://github.com/ZacharySchmalzEng/Tools/issues).

**`Linux-Deployment-Tool.sh`** is a highly modular, flag-based Bash script designed to transform a fresh Linux installation into a hardened, fully configured power-user workstation.

Rather than a monolithic installation script, this tool uses command-line flags to let you pick and choose exactly which application stacks, system tweaks, and security hardening tiers you want to deploy.

## 📋 Release Changelog (v2.1)

### 🚀 Feature Enhancements
* **Multi-Tier Recovery Modes (v2.1):** Added `--reinstall` for package-manager reinstall operations and `--rebuild` to also rebuild supported GPU kernel modules and initramfs images. Fedora Atomic and Bazzite cannot force-reinstall host-image drivers; Ubuntu reinstalls its currently installed NVIDIA stack or selects a recommended driver when none is installed.
* **DNF Network Retries (v2.1):** DNF package and metadata operations allow up to 10 retries with a 60-second timeout to better tolerate slow or intermittently unreachable mirrors.

### 🐛 Defect Resolutions & Bug Fixes
* **Flathub OrcaSlicer App ID Migration (v2.0.1):** Migrated package identifier from deprecated `com.softfever.OrcaSlicer` to `com.orcaslicer.OrcaSlicer`, with automated legacy fallback in `install_flatpak_app()` to prevent `error: Nothing matches in remote flathub`.
* **Fatal sed /etc/dnf/automatic.conf Crash (Exit code 2) (v2.0.1):** Added auto-creation of missing `/etc/dnf/automatic.conf` templates on fresh/minimal systems, guarded against service modification in download-only mode (`-d`), and added dual timer support for both `dnf-automatic.timer` and modern `dnf5-automatic.timer`.
* **Nobara Linux NVIDIA Packaging Conflict (v2.0):** Bypasses manual RPM Fusion `akmod-nvidia` on Nobara to prevent fatal package transaction collisions with pre-installed `dkms-nvidia` from `nobara-nvidia-production`.
* **PowerShell 404 Download Failures (v2.0):** Replaced hardcoded/brittle GitHub RPM URLs with official Microsoft repository registration (`packages.microsoft.com`) and Flathub fallback.
* **ShellCheck SC2155 Subshell Masking (v2.0):** Split `readonly SCRIPT_DIR` declaration and assignment to preserve subshell exit code visibility.
* **SteamOS GPG Keyring Initialization (v2.0):** Automates `pacman-key --init` and `--populate archlinux holo` before package transactions to avoid GPG verification aborts.
* **Debian/Ubuntu Debconf Freezes (v2.0):** Enforces non-interactive frontends (`DEBIAN_FRONTEND=noninteractive`) across all `apt-get` operations.

### 🚀 Feature Enhancements
* **Multi-Distribution Engine:** Native specialized handling for Fedora Atomic (Silverblue, Bazzite, Kinoite), Arch Linux, SteamOS (Steam Deck), openSUSE (Tumbleweed & Leap), Nobara, Fedora, and Debian/Ubuntu.
* **Distro Override CLI Flags:** Added `--atomic`, `--bazzite`, `--silverblue`, `--arch`, `--steamos`, `--opensuse`, and `--distro=<name>` flags with auto-detection fallbacks.
* **SteamOS Root Lifecycle:** Automated `steamos-readonly disable` and `steamos-readonly enable` state management.
* **Zero On-Box Dependencies:** Automatic self-bootstrapping installs missing core utilities (`curl`, `pciutils`, `flatpak`) at runtime.

## ✨ Features

* **Zero On-Box Dependencies (Self-Bootstrapping):** Automatically pulls down and installs all prerequisite tools (`curl`, `pciutils`/`lspci`, `ca-certificates`, `flatpak`, and package manager plugins) upon invocation. No manual package pre-requisites are needed on a fresh machine.
* **Strict Mode Execution:** Built with `set -euo pipefail` to ensure "fail-fast" reliability. If a critical pipeline fails, the script safely halts rather than leaving the system in an unpredictable state.
* **Multi-Distribution Engine:** Native special-handling engines for **Fedora / RHEL** (`dnf`), **Nobara Linux** (gaming kernel & DKMS bypass), **Fedora Atomic / Bazzite / Silverblue** (`rpm-ostree` layering & Flatpak containment), **Arch Linux** (`pacman`), **SteamOS** (`steamos-readonly` lifecycle unlocking), **openSUSE Tumbleweed & Leap** (`zypper` & Packman essentials), and **Debian / Ubuntu** (`apt`).
* **GPU-Aware Driver Selection & Nobara Safeguard:** Auto-probes hardware via PCI bus or sysfs. On Nobara, skips conflicting RPM Fusion `akmod-nvidia` packages to protect the pre-packaged `nobara-nvidia-production` DKMS driver stack. On Bazzite/SteamOS, respects containerized images and AMD APU hardware.
* **Tiered Security Hardening:** Choose between a safe baseline (`--harden`) with SELinux/AppArmor enforcement or a strict, zero-trust posture (`--harden-advanced`) that deploys `auditd`, modifies kernel sysctl routing, and disables SSH passwords.
* **Native MFA Integration:** Easily enforce Google Authenticator 2FA on the OpenSSH daemon with a single flag (`--2fa`).
* **Desktop Environment Aware:** Dynamically detects (or prompts for) your Desktop Environment (GNOME or KDE) to install the correct native Quality of Life tools.
* **Unattended Mode:** Bypasses all interactive prompts and automatically answers "yes" to package-manager and Flatpak transactions, making it perfect for rapid VM testing or automated bare-metal deployments.

## 🚀 Usage

### Prerequisites
* **OS**: Fedora, Nobara, Fedora Atomic (Silverblue/Bazzite), Arch Linux, SteamOS (Steam Deck), openSUSE (Tumbleweed/Leap), or Debian/Ubuntu (Zero manual package dependencies required).
* **Privileges**: Must be executed with **root/sudo** privileges.
* **Internet**: Active connection required for package repositories and Flatpak runtimes.

### Quick Start
Before running the script, ensure it has the proper execution permissions:
```bash
chmod +x Linux-Deployment-Tool.sh

sudo ./Linux-Deployment-Tool.sh --help                              # Displays the help menu
sudo ./Linux-Deployment-Tool.sh --all                               # The Universal Baseline (All standard modules)
sudo ./Linux-Deployment-Tool.sh --all --bazzite                     # Force Bazzite / Fedora Atomic engine
sudo ./Linux-Deployment-Tool.sh --all --steamos                     # Force SteamOS (handles steamos-readonly)
sudo ./Linux-Deployment-Tool.sh --all --opensuse                    # Force openSUSE (Packman repos & Zypper)
sudo ./Linux-Deployment-Tool.sh --all --arch                        # Force Arch Linux (Pacman & multilib)
sudo ./Linux-Deployment-Tool.sh --all --2fa --unattended            # Hands-free deployment with MFA SSH
sudo ./Linux-Deployment-Tool.sh --gaming --reinstall -y            # Reinstall selected gaming and driver packages
sudo ./Linux-Deployment-Tool.sh --gaming --rebuild -y              # Reinstall and rebuild supported driver modules/initramfs
sudo ./Linux-Deployment-Tool.sh --update --harden-advanced --debug  # Update, strict harden, and trace commands
sudo ./Linux-Deployment-Tool.sh --all -d                            # Dry-run: Resolve and download packages only
```
## ⚙️ Command-Line Flags

### Core Modules
| Flag | Description |
| :--- | :--- |
| `--update` | Sequentially upgrades package manager (DNF, rpm-ostree, Pacman, Zypper, APT), Flatpak, and Snap packages. |
| `--apps` | **System & Utilities:** Browsers (Brave, Chrome), Obsidian, Signal, Timeshift, btop, eza, plocate, and DE-specific tools (baobab/filelight). |
| `--devapps` | **Development Stack:** Python 3, OpenSSL, VS Code, GitHub Desktop, Microsoft PowerShell (pwsh via official repos / Flathub fallback), and Remmina. |
| `--cyber` | **Security Analysis:** Wireshark (adds user to group), Nmap, TCPDump, and Ncat. |
| `--maker` | **3D Printing:** PrusaSlicer, OrcaSlicer, and Bambu Studio. |
| `--creators` | **Creative Suite:** Blender, Darktable, Audacity, Inkscape, and OBS Studio. |
| `--gaming` | **Gaming & Drivers:** Configures the appropriate package sources (RPM Fusion, Packman, Multilib), installs Steam/Lutris/Bottles, and auto-detects/installs GPU driver stacks with Nobara safeguards. |
| `--ssh` | Installs, enables, and verifies the OpenSSH daemon. |
| `--discord` | Configures Discord (Native RPM on standard Fedora; sandboxed Flatpak on Atomic and SteamOS). |

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
| Flag | Description |
| :--- | :--- |
| `--harden` | **The Safe Baseline:** Verifies SELinux where available, configures unattended background security patching, and disables direct root login over SSH. |
| `--harden-advanced` | **The Strict Posture:** *Warning: Disables SSH Password Auth.* Deploys `auditd` with high-fidelity credential rules, and modifies sysctl to drop ICMP (Ping) requests and enforce strict reverse path forwarding. |
| `--2fa` | Integrates with `--ssh` to install `google-authenticator` and configure PAM/SSHD to enforce Multi-Factor Authentication for remote logins. |

### Global Modifiers
| Flag | Description |
| :--- | :--- |
| `--all` | Executes all standard modules. *(Note: Intentionally excludes `--harden-advanced` and `--2fa` to prevent accidental lockouts).* |
| `--reinstall` | Reinstalls packages selected by other modules using native package-manager operations. Can be combined with module flags such as `--gaming`; Flatpak apps are reinstalled when selected. |
| `--rebuild` | Includes `--reinstall` and rebuilds supported DKMS/akmods modules and initramfs images. It does not bypass package-manager locks. On Arch Linux and SteamOS, Pacman's `--overwrite '*'` is limited to explicit GPU-driver package transactions; use this mode only when repairing those drivers. On Fedora Atomic, `--gaming --rebuild` clears the pending rpm-ostree deployment, including unrelated staged changes, before normal idempotent NVIDIA layering; it cannot force-reinstall host-image drivers. Bazzite does not support host-image NVIDIA driver rebuilds. |
| `-y` | Auto-install (answers yes to all package manager prompts). |
| `-d` | Download only (applies to DNF updates, excellent for dry-run validations). |
| `--unattended` | Bypasses the DE prompt (defaults to KDE), suppresses the reboot prompt, and applies `-y` automatically. |
| `--debug` | Enables `set -x` to print a trace of simple commands directly to the console and log file for deep troubleshooting. |

## 📝 Important Notes

* **Log Files**: Execution generates a detailed transcript in the `InstallerLogs` directory created alongside the script. Both standard output and errors are captured here.
* **The `--harden-advanced` Flag**: If you use this flag, you **must** have an SSH Public Key (`id_rsa.pub` or `id_ed25519.pub`) copied to the machine's `~/.ssh/authorized_keys` file before closing your terminal session, as password authentication will be disabled.
* **Driver Auto-Selection**: The gaming module detects the GPU vendor and installs the appropriate NVIDIA or AMD driver stack for the current Linux distribution.

## ⚠️ Disclaimer
This script modifies kernel parameters, PAM authentication, and core system utilities. Please review the code to ensure the configurations match your personal environment needs before executing.

## 👤 Author & Community

* **Author**: Zachary Schmalz
* **GitHub Repository**: [ZacharySchmalzEng/Tools](https://github.com/ZacharySchmalzEng/Tools/)
* **Bug Reports & Feature Requests**: Please submit all issues, questions, and feature requests via the [GitHub Issues Tracker](https://github.com/ZacharySchmalzEng/Tools/issues). Contributions and PRs are always welcome!