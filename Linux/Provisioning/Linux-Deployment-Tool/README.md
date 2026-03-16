# Fedora 41+ Automated Deployment & Provisioning Tool

> ⚠️ **BETA STATUS (v1.0 Beta):** This provisioning tool is currently in its initial beta testing phase. Because it actively modifies kernel parameters, PAM authentication, and core system utilities, it is highly recommended to perform an initial test run in a Virtual Machine (using the `--unattended` and `-d` dry-run flags) before deploying it to your primary bare-metal environment.

**`fedora-deployment-tool.sh`** is a highly modular, flag-based Bash script designed to transform a fresh Fedora Linux installation into a hardened, fully configured power-user workstation.

Rather than a monolithic installation script, this tool uses command-line flags to let you pick and choose exactly which application stacks, system tweaks, and security hardening tiers you want to deploy. 

## ✨ Features

* **Strict Mode Execution:** Built with `set -euo pipefail` to ensure "fail-fast" reliability. If a critical pipeline fails, the script safely halts rather than leaving the system in an unpredictable state.
* **Tiered Security Hardening:** Choose between a safe baseline (`--harden`) or a strict, zero-trust posture (`--harden-advanced`) that deploys `auditd`, modifies kernel sysctl routing, and disables SSH passwords.
* **Native MFA Integration:** Easily enforce Google Authenticator 2FA on the OpenSSH daemon with a single flag (`--2fa`).
* **Desktop Environment Aware:** Dynamically detects (or prompts for) your Desktop Environment (GNOME or KDE) to install the correct native Quality of Life tools.
* **Unattended Mode:** Bypasses all interactive prompts and automatically answers "yes" to DNF/Flatpak transactions, making it perfect for rapid VM testing or automated bare-metal deployments.

## 🚀 Usage

### Prerequisites
* **OS**: Fedora Workstation 41 or newer.
* **Privileges**: Must be executed with **root/sudo** privileges.
* **Internet**: Active connection required for DNF, Flatpak, and COPR repositories.

### Quick Start
Before running the script, ensure it has the proper execution permissions:
```bash
chmod +x fedora-deployment-tool.sh

sudo ./fedora-deployment-tool.sh --help                              # Displays the help menu
sudo ./fedora-deployment-tool.sh --all                               # The Universal Baseline (All standard modules)
sudo ./fedora-deployment-tool.sh --all --2fa --unattended            # Hands-free deployment with MFA SSH
sudo ./fedora-deployment-tool.sh --update --harden-advanced --debug  # Update, strict harden, and trace commands
sudo ./fedora-deployment-tool.sh --all -d                            # Dry-run: Resolve and download packages only
```
## ⚙️ Command-Line Flags

### Core Modules
| Flag | Description |
| :--- | :--- |
| `--update` | Sequentially upgrades DNF, Flatpak, and Snap packages. |
| `--apps` | **System & Utilities:** Browsers (Brave, Chrome), Obsidian, Signal, Timeshift, btop, eza, plocate, and DE-specific tools (baobab/filelight). |
| `--devapps` | **Development Stack:** Python 3, OpenSSL, VS Code, GitHub Desktop, PowerShell, and Remmina. |
| `--cyber` | **Security Analysis:** Wireshark (adds user to group), Nmap, TCPDump, and Ncat. |
| `--maker` | **3D Printing:** PrusaSlicer, OrcaSlicer, and Bambu Studio. |
| `--creators` | **Creative Suite:** Blender, Darktable, Audacity, Inkscape, and OBS Studio. |
| `--gaming` | **Gaming & Drivers:** Configures RPM Fusion/Flathub, installs Steam, Lutris, Bottles, ProtonUp-Qt, and auto-detects/installs the Nvidia proprietary driver stack. |
| `--ssh` | Installs, enables, and verifies the `sshd` daemon. |
| `--discord` | Silently uninstalls the Flatpak version of Discord (if present) and replaces it with the native RPM package via RPM Fusion. |

### Security & Hardening Tiers
| Flag | Description |
| :--- | :--- |
| `--harden` | **The Safe Baseline:** Verifies SELinux is Enforcing, configures `dnf-automatic` for unattended background security patching, and disables direct root login over SSH. |
| `--harden-advanced` | **The Strict Posture:** *Warning: Disables SSH Password Auth.* Deploys `auditd` with high-fidelity credential rules, and modifies sysctl to drop ICMP (Ping) requests and enforce strict reverse path forwarding. |
| `--2fa` | Integrates with `--ssh` to install `google-authenticator` and configure PAM/SSHD to enforce Multi-Factor Authentication for remote logins. |

### Global Modifiers
| Flag | Description |
| :--- | :--- |
| `--all` | Executes all standard modules. *(Note: Intentionally excludes `--harden-advanced` and `--2fa` to prevent accidental lockouts).* |
| `-y` | Auto-install (answers yes to all package manager prompts). |
| `-d` | Download only (applies to DNF updates, excellent for dry-run validations). |
| `--unattended` | Bypasses the DE prompt (defaults to KDE), suppresses the reboot prompt, and applies `-y` automatically. |
| `--debug` | Enables `set -x` to print a trace of simple commands directly to the console and log file for deep troubleshooting. |

## 📝 Important Notes

* **Log Files**: Execution generates a detailed transcript in the `InstallerLogs` directory created alongside the script. Both standard output and errors are captured here.
* **The `--harden-advanced` Flag**: If you use this flag, you **must** have an SSH Public Key (`id_rsa.pub` or `id_ed25519.pub`) copied to the machine's `~/.ssh/authorized_keys` file before closing your terminal session, as password authentication will be disabled.
* **Nvidia Auto-Installer**: The gaming module uses the `t0xic0der/nvidia-auto-installer-for-fedora` COPR repository. It will automatically detect your GPU architecture and deploy the correct proprietary driver, CUDA, and Vulkan stack if compatible.

## ⚠️ Disclaimer
This script modifies kernel parameters, PAM authentication, and core system utilities. Please review the code to ensure the configurations match your personal environment needs before executing.