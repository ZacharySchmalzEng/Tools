# Windows 11 Pro Automated Deployment & Provisioning

**`Win11-Pro-Deploy.ps1`** is a highly modular, automated PowerShell script designed to transform a fresh Windows 11 Pro installation into a hardened, debloated, and fully configured power-user environment. 

Rather than a "one-size-fits-all" approach, this script uses command-line flags to let you pick and choose exactly which system tweaks, security policies, and software stacks you want to deploy. It also features pre-configured "Deployment Profiles" to establish a quick baseline.

## ✨ Features
* **Deployment Profiles**: Run `-Standard` for a universal daily-driver baseline, or `-Complete` for a heavy-duty workstation setup. 
* **Smart Provisioning**: Checks for existing installations and downloaded files to prevent redundant network calls and save time on reruns.
* **Dynamic Web Scraping**: Bypasses Winget limitations by dynamically scraping NVIDIA's official site to fetch and silently install the absolute latest NVIDIA App.
* **Proprietary Install Bypasses**: Uses custom override flags to force strictly GUI-based installers (like Blizzard Battle.net) into silent unattended installations.
* **Native WSL Dual-Boot Mounting**: Generates scheduled tasks to automatically mount physical Linux partitions (ext4/btrfs) directly into Windows File Explorer via WSL.

---

## 🚀 Usage

### Prerequisites
* **OS**: Windows 11 Pro
* **Privileges**: Must be run in an **Administrator** PowerShell terminal.
* **Internet**: Active connection required for Winget and dynamic downloads.

### Quick Start
To view the help menu and see all available options, run the script with no arguments:
```powershell
.\Win11-Pro-Deploy.ps1