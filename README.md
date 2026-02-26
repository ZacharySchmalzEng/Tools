# System Provisioning & Automation Tools

A centralized repository of PowerShell and Bash scripts designed to automate OS deployment, environment configuration, and routine maintenance across Windows 11 Pro and Fedora Linux.

These tools are built with a focus on modularity, security, and reducing the friction of rebuilding bare-metal environments from scratch.

## 📂 Repository Structure

The repository is divided by Operating System and function:

### 🐧 Linux (Fedora/RHEL)
* **`/Linux/Gaming/`**
  * `InstallBaseGamingFedora41+.sh`: Automates the installation of core gaming dependencies, Vulkan drivers, and performance tweaks on fresh Fedora installs.
* **`/Linux/Maintenance/`**
  * `updatesAllMethods.sh`: A universal update alias script that sequentially updates DNF, Flatpak, and Snap packages.
  * `FedoraDiscordUpdate.sh`: Automates the transition from the Flatpak version of Discord to the native RPM package via RPM Fusion.
* **`/Linux/Networking/`**
  * `FedoraEnableSSH.sh`: Silently installs, configures, and validates the OpenSSH Server daemon.

### 🪟 Windows (Windows 11 Pro)
* **`/Windows/Provisioning/`**
  * `Win11-Pro-Deploy.ps1`: A massive, flag-based modular deployment script. Capable of debloating the OS, applying registry tweaks, hardening security/telemetry, and dynamically fetching/installing specific software stacks (Cybersecurity tools, 3D Printing slicers, Developer environments, etc.). *(See the dedicated README inside this folder for usage flags).*

---

## 🚀 Getting Started

To use these tools, clone the repository to your local machine:
```bash
git clone [https://github.com/ZacharySchmalzEng/Tools.git](https://github.com/ZacharySchmalzEng/Tools.git)