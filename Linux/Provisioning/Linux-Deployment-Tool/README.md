# Linux Automated Deployment & Provisioning Tool

> **Version 1.3:** This provisioning tool configures system packages, security settings, SSH/PAM, Secure Boot, and shared NTFS partitions. Test it in a virtual machine first and review the selected modules before running them on a primary system.

[`Linux-Deployment-Tool.sh`](./Linux-Deployment-Tool.sh) is a modular, flag-based Bash script for provisioning Fedora/RHEL-family and Debian/Ubuntu-family Linux systems. Select individual modules or run the standard set with `--all`.

## Features

* **Distro-aware package management:** Uses DNF on RPM-family systems and APT on Debian-family systems, with Flatpak and Snap updates where available.
* **Dual-boot and Secure Boot setup:** Can prepare Fedora akmods Machine Owner Key (MOK) enrollment, set the hardware clock to local time, and configure non-system NTFS partitions for mounting.
* **Gaming and graphics setup:** Installs gaming tools and selects NVIDIA or AMD drivers based on detected hardware.
* **Tiered hardening:** Choose the baseline `--harden` module or the more restrictive `--harden-advanced` module.
* **SSH and Google Authenticator:** Install OpenSSH and optionally configure PAM/SSHD for Google Authenticator MFA.
* **Desktop-specific utilities:** The script prompts you to choose GNOME or KDE when run interactively. `--unattended` skips that prompt and selects KDE.
* **Unattended execution:** Automatically answers yes to supported package-manager and Flatpak prompts and skips the interactive reboot prompt.

## Requirements and cautions

* Run as root, typically with `sudo`.
* Bash and an active internet connection are required.
* Supported package-manager families are Fedora/RHEL-style (DNF) and Debian/Ubuntu-style (APT) distributions.
* The script modifies system configuration, including SSH/PAM, sysctl, audit, `/etc/fstab`, and hardware clock settings, depending on selected modules. Review the options and test in a VM before applying them to a system you rely on.
* `--harden-advanced` disables SSH password authentication when OpenSSH is installed. Confirm key-based access works before disconnecting.
* `--dualboot` may require follow-up steps to disable Windows Fast Startup and enroll a MOK in UEFI.
* `--2fa` configures Google Authenticator for SSH; before ending your current session, generate a token for the account that will log in using `google-authenticator`.

## Usage

Run commands from this directory:

```bash
chmod +x Linux-Deployment-Tool.sh

sudo ./Linux-Deployment-Tool.sh --help
sudo ./Linux-Deployment-Tool.sh --apps
sudo ./Linux-Deployment-Tool.sh --ssh --2fa
sudo ./Linux-Deployment-Tool.sh --update -d
sudo ./Linux-Deployment-Tool.sh --all --unattended
```

`--update -d` downloads DNF/APT system package updates without installing those updates; Flatpak upgrades and Snap refreshes still run normally when available. **This is not a general dry-run mode.** If `-d` is combined with other modules, those modules still run and may make system changes. For example, `--all -d` still performs the other `--all` actions.

## Command-line options

### Modules

| Option | Description |
| :--- | :--- |
| `--update` | Updates system packages, then Flatpak and Snap packages when available. |
| `--dualboot` | Prepares Secure Boot MOK enrollment on supported RPM systems, sets the hardware RTC to local time, and configures detected non-Windows-system NTFS partitions for automounting. |
| `--secureboot` | Alias for `--dualboot`. |
| `--apps` | Installs system utilities such as Timeshift, btop, bat, eza, plocate, VLC, and archive tools; also installs Brave, Chrome, Obsidian, and Signal through Flatpak, plus GNOME- or KDE-specific utilities. |
| `--devapps` | Installs Python, pip, OpenSSL, Remmina, VS Code and GitHub Desktop via Flatpak, and native PowerShell on RPM systems. |
| `--cyber` | Installs Wireshark, Nmap, TCPDump, and Ncat. When invoked with `sudo`, adds the invoking user to the Wireshark group. |
| `--maker` | Installs PrusaSlicer, OrcaSlicer, and Bambu Studio. |
| `--creators` | Installs Blender, Darktable, Audacity, Inkscape, and OBS Studio. |
| `--gaming` | Installs gaming tools, configures RPM Fusion on RPM systems, applies a gaming sysctl setting, and attempts GPU-specific NVIDIA or AMD driver setup. |
| `--ssh` | Installs OpenSSH Server if needed, enables its service, and verifies its status. Combine with `--2fa` to configure Google Authenticator MFA. |
| `--discord` | Replaces the Discord Flatpak with the native RPM package when run on an RPM-family system. The transition is not implemented for Debian-family systems. |

### Security and hardening

| Option | Description |
| :--- | :--- |
| `--harden` | Baseline hardening: enables SELinux enforcement when available on RPM systems, configures automatic security updates, and disables direct root SSH login when OpenSSH is installed. |
| `--harden-advanced` | Advanced hardening: configures auditd rules and restrictive network sysctl settings, including disabling ICMP echo responses. When OpenSSH is installed, also disables SSH password authentication and X11 forwarding. Ensure SSH key access works first. |
| `--2fa` | Configures Google Authenticator PAM and SSH settings. Use with `--ssh` so the SSH module installs the needed package and applies the configuration. |
| `--mfa` | Alias for `--2fa`. |

### Global options

| Option | Description |
| :--- | :--- |
| `--all` | Runs all standard modules, including `--dualboot` and `--harden`; excludes `--harden-advanced` and `--2fa`. |
| `-y` | Automatically answers yes to supported package-manager prompts. |
| `-d` | Requests download-only behavior for system package updates (`--update`): DNF on RPM systems or APT on Debian systems. It does not prevent other selected modules from making changes. |
| `--unattended` | Skips the GNOME/KDE prompt, selects KDE, applies `-y`, and skips the interactive reboot prompt. |
| `--debug` | Enables Bash command tracing for troubleshooting. |
| `--help`, `-h` | Displays the help menu. |

## After running

* **Logs:** The script writes its output to timestamped log files in the `InstallerLogs` directory alongside the script.
* **Secure Boot:** If MOK enrollment is needed, follow the script's post-run instructions and confirm enrollment in UEFI's MokManager after reboot. In unattended mode, the script skips the interactive MOK import and prints the command to run manually.
* **Dual boot:** If Windows Fast Startup prevents shared NTFS partitions from being accessed reliably, disable it from an elevated Windows PowerShell session with `powercfg /h off`.
* **SSH MFA:** Generate the Google Authenticator token for the login account with `google-authenticator` before relying on MFA for remote access.
* **Reboot:** Interactive runs may offer a reboot at the end. Unattended runs skip that prompt; restart manually when appropriate.

## Disclaimer

This tool can alter authentication, kernel/network settings, package sources, and filesystem configuration. Review the script and selected options before execution; use it only on systems for which you are authorized to make these changes.
