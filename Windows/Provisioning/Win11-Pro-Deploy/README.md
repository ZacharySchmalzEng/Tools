# Windows 11 Pro Automated Deployment & Provisioning

**`Win11-Pro-Deploy.ps1`** is a highly modular, automated PowerShell script designed to transform a fresh Windows 11 Pro installation into a hardened, debloated, and fully configured power-user environment. 

Rather than a "one-size-fits-all" approach, this script uses command-line flags to let you pick and choose exactly which system tweaks, security policies, and software stacks you want to deploy. It also features pre-configured "Deployment Profiles" to establish a quick baseline.

## ✨ Features

* **Deployment Profiles**: Run `-Standard` for a universal daily-driver baseline, or `-Complete` for a heavy-duty workstation setup. 
* **Smart Provisioning**: Checks for existing installations and downloaded files to prevent redundant network calls and save time on reruns.
* **Dynamic Web Scraping**: Bypasses Winget limitations by dynamically scraping NVIDIA's official site to fetch and silently install the absolute latest NVIDIA App.
* **Proprietary Install Bypasses**: Uses custom override flags to force strictly GUI-based installers (like Blizzard Battle.net) into silent unattended installations.
* **Native WSL Dual-Boot Mounting**: Generates scheduled tasks to automatically mount physical Linux partitions (ext4/btrfs) directly into Windows File Explorer via WSL.

## 🚀 Usage

### Prerequisites
* **OS**: Windows 11 Pro
* **Privileges**: Must be run in an **Administrator** PowerShell terminal.
* **Internet**: Active connection required for Winget and dynamic downloads.

### Quick Start
To view the help menu and see all available options, run the script with no arguments:

```powershell
.\Win11-Pro-Deploy.ps1             # Displays the help menu and available flags
.\Win11-Pro-Deploy.ps1 -Standard   # Universal Baseline (Laptops, VMs, secondary workstations)
.\Win11-Pro-Deploy.ps1 -Complete   # Heavy Workstation (Standard + Cyber, Maker, Gaming, Nvidia)
.\Win11-Pro-Deploy.ps1 -System     # Example: Run a single specific module individually
```

## ⚙️ Command-Line Flags

**All Available Flags (Quick Reference):**
`-Standard`, `-Complete`, `-System`, `-Debloat`, `-Security`, `-Dev`, `-DualBoot`, `-Apps`, `-DevApps`, `-Cyber`, `-Maker`, `-Gaming`, `-Nvidia`, `-Help`

### Deployment Profiles
| Flag | Description |
| :--- | :--- |
| `-Standard` | **The Universal Baseline.** Executes: System, Debloat, Security, Dev, Apps, and DevApps. |
| `-Complete` | **The Heavy Workstation.** Executes everything in Standard, PLUS: Cyber, Maker, Gaming, and Nvidia. |
| *(Note)* | *Both profiles intentionally exclude `-DualBoot` to prevent hardware-specific task errors on single-OS systems.* |

### Core OS Options
| Flag | Description |
| :--- | :--- |
| `-System` | Disables OneDrive/Telemetry prompts, restores the classic Windows 10 Context Menu, enables Win32 Long Paths, sets Explorer tweaks (shows hidden files/extensions, aligns taskbar left), and enables the Ultimate Performance Power Plan. |
| `-Debloat` | Silently uninstalls Windows Widgets, disables Windows Consumer Features (stops Candy Crush auto-installs), and removes base Microsoft Appx bloatware. |
| `-Security` | Disables OS Telemetry via Group Policy, enables Windows Defender PUA (Potentially Unwanted App) Protection, and installs/runs the `PSWindowsUpdate` module. |
| `-Dev` | Enables Windows Optional Features including WSL (Windows Subsystem for Linux), Windows Sandbox, and configures the native OpenSSH Client & Server. |
| `-DualBoot` | Generates a persistent helper script (`C:\Scripts\Mount-Linux.ps1`) and registers an automated Scheduled Task to mount physical Linux partitions via WSL at logon. *(Requires manual verification of drive numbers via `wsl --mount --list`)*. |

### Software Provisioning Options
| Flag | Associated Software |
| :--- | :--- |
| `-Apps` | Brave, Chrome, Firefox, Opera, 7-Zip, VLC, Discord, Obsidian, Signal, WhatsApp (via Store ID), TreeSize Free, CrystalDiskInfo, PowerToys, Everything, Windows Terminal, Rufus. |
| `-DevApps` | VS Code, Python 3.13, GitHub Desktop, Notepad++, PuTTY, PowerShell 7. |
| `-Cyber` | Wireshark, Nmap, Advanced IP Scanner. |
| `-Maker` | PrusaSlicer, OrcaSlicer, Bambu Studio, Autodesk Fusion 360. |
| `-Gaming` | Steam, OBS Studio, Blizzard Battle.net. |
| `-Nvidia` | Dynamically fetches and installs the latest NVIDIA App directly from Nvidia's servers. |

## 📝 Important Notes

* **Execution Policy**: The script automatically attempts to bypass the execution policy for the current process scope. You do not need to globally alter your system execution policy to run this.
* **Log Rotation**: All actions are thoroughly logged to an `InstallerLogs` directory created in the same folder as the script. The script retains the 10 most recent logs and automatically purges older ones.
* **The Dual-Boot Task**: The `-DualBoot` flag assumes a standard drive topology (Drive 1, Partition 2, btrfs). If your Linux drive is located elsewhere, simply open `C:\Scripts\Mount-Linux.ps1` and adjust the variables at the top of the file.

## ⚠️ Disclaimer

This script modifies the system registry, uninstalls provisioned Windows packages, and alters security policies. Please review the code to ensure the configurations match your personal environment needs before executing.