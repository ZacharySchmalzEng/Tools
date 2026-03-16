# Linux Automation & Provisioning Tools

This directory contains a collection of Bash scripts designed to configure, maintain, and optimize Fedora and RHEL-based Linux environments. 

Whether you are deploying a completely fresh Fedora installation, configuring a dedicated gaming machine, or automating your daily package updates, these tools provide quick, reproducible results.

## 📂 Directory Structure

### 🚀 Provisioning
* **`fedora-deployment-tool.sh`** *(v1.0 Beta)*
  * **Purpose:** A highly modular, automated deployment tool for fresh Fedora 41+ installations.
  * **Actions:** Uses command-line flags to selectively deploy application stacks (Apps, Dev, Cyber, Maker, Gaming), configure Desktop Environment QoL features, and apply tiered security hardening (including `auditd`, network sysctl drops, and MFA for SSH).

### 🎮 Gaming
* **`InstallBaseGamingFedora41+.sh`**
  * **Purpose:** Automates the post-installation setup for a dedicated Fedora gaming machine.
  * **Actions:** Enables third-party repositories (like RPM Fusion), installs core gaming dependencies, Vulkan drivers, and deploys necessary gaming platforms (Steam, Lutris, Wine).

### 🛠️ Maintenance
* **`updatesAllMethods.sh`**
  * **Purpose:** A universal system update alias.
  * **Actions:** Sequentially upgrades DNF, Flatpak, and Snap packages in a single run. Supports `-y` (auto-install) and `-d` (download only) flags.
* **`FedoraDiscordUpdate.sh`**
  * **Purpose:** Transitions Discord from a Flatpak to a native RPM.
  * **Actions:** Silently uninstalls the Discord Flatpak, configures RPM Fusion Free/Nonfree repositories, and installs the native RPM package via DNF.

### 🌐 Networking
* **`FedoraEnableSSH.sh`**
  * **Purpose:** Rapidly provisions secure shell access.
  * **Actions:** Checks for existing OpenSSH installations, installs `openssh-server`, enables and starts the systemd daemon, and validates active listening ports.

---

## 🚀 Usage Guide

Because these scripts manage system-level packages, services, and repositories, they **must be executed with root/sudo privileges**.

### 1. Make the Script Executable
Before running a script for the first time, ensure it has the proper execution permissions:
```bash
chmod +x <script_name>.sh