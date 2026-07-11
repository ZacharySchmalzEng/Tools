# System Provisioning & Automation Tools

A centralized repository of PowerShell and Bash scripts designed to automate OS deployment, environment configuration, and routine maintenance across Windows 11 Pro and Fedora Linux.

These tools are built with a focus on modularity, zero-trust security principles, and reducing the friction of rebuilding bare-metal or virtualized environments from scratch.

## 📂 Repository Structure

The repository is logically segregated by Operating System and functional domain:

### 🐧 Linux (Fedora/RHEL)

* **`/Linux/Backups/`**
  * `deploy-restic-gdrive.sh`: Deploys an automated, zero-knowledge encrypted backup infrastructure using Restic and Rclone.
* **`/Linux/Gaming/`**
  * `InstallBaseGamingFedora41+.sh`: Automates the installation of core gaming dependencies, Vulkan drivers, and performance tweaks on fresh Fedora installs. Includes automated systemd timer registration for 30-day retention policies and an interactive disaster recovery mode.
* **`/Linux/Maintenance/`**
  * `updatesAllMethods.sh`: A universal update alias script that sequentially updates DNF, Flatpak, and Snap packages.
  * `FedoraDiscordUpdate.sh`: Automates the transition from the Flatpak version of Discord to the native RPM package via RPM Fusion.
* **`/Linux/Networking/`**
  * `FedoraEnableSSH.sh`: Silently installs, configures, and validates the OpenSSH Server daemon. Features idempotency checks, Google Authenticator MFA PAM module enforcement, and automated configuration rollbacks.
* **`/Linux/Provisioning/`**
  * `fedora-deployment-tool.sh`: A comprehensive, modular deployment script for fresh Fedora 41+ installations. Features tiered security hardening, MFA SSH integration, and dynamic software stack provisioning via command-line flags. *(See the dedicated README inside this folder for usage flags).*

### 🪟 Windows (Windows 11 Pro)

* **`/Windows/Backups/`**
  * `Deploy-ResticGDrive.ps1`: Native Windows port of the Restic/Rclone backup infrastructure. Executes via Task Scheduler under `NT AUTHORITY\SYSTEM` and leverages Volume Shadow Copy Service (VSS) to bypass locked-file exceptions.
* **`/Windows/Data_Management/`**
  * `Invoke-ProfileMerge.ps1`: Resolves scattered user profiles from disorganized backups. Scans NTFS volumes for overlaps and utilizes SHA-256 cryptographic hashing to safely merge directories and deduplicate data.
* **`/Windows/Provisioning/`**
  * `Deploy-OSMaintenanceTask.ps1`: Registers a weekly, SYSTEM-context maintenance task that performs TRIM, DNS cache flushing, `chkdsk` health checks, `SFC`/`DISM` repair attempts, and temporary-file cleanup. It can also register a companion auto-update task for supported Windows systems.
  * `Windows-Deployment-Tool.ps1`: A massive, flag-based modular deployment script. Capable of debloating the OS, applying registry tweaks, hardening security/telemetry, and dynamically fetching/installing specific software stacks (Cybersecurity tools, 3D Printing slicers, Developer environments, etc.). *(See the dedicated README inside this folder for usage flags).*

---

## 🚀 Getting Started

To utilize these tools, clone the repository to your local execution environment:
```bash
git clone [https://github.com/ZacharySchmalzEng/Tools.git](https://github.com/ZacharySchmalzEng/Tools.git)