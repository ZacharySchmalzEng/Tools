# Windows 10/11 Pro & Server Automated Deployment & Provisioning

**`Windows-Deployment-Tool.ps1`** is a highly modular, automated PowerShell script designed to transform a fresh Windows 10, Windows 11 Pro, or Windows Server installation into a hardened, debloated, and fully configured power-user environment.

Rather than a "one-size-fits-all" approach, this script uses command-line flags to let you pick and choose exactly which system tweaks, security policies, and software stacks you want to deploy. It also features pre-configured "Deployment Profiles" to establish a quick baseline.

## ✨ Features

* **Deployment Profiles**: Run `-Standard` for a universal daily-driver baseline, or `-Complete` for a heavy-duty workstation setup. 
* **Smart Provisioning**: Checks for existing installations and downloaded files to prevent redundant network calls and save time on reruns.
* **Dynamic Web Scraping**: Bypasses Winget limitations by dynamically scraping NVIDIA's official site to fetch and silently install the absolute latest NVIDIA App.
* **Proprietary Install Bypasses**: Uses custom override flags to force strictly GUI-based installers (like Blizzard Battle.net) into silent unattended installations.
* **Server OS Aware**: Automatically detects Windows Server environments and substitutes incompatible packages (e.g., dynamically swapping TreeSize Free for WinDirStat).
* **Native WSL Dual-Boot Mounting**: Features dynamic hardware auto-discovery to find non-Windows partitions, generating idempotent scheduled tasks to mount them (ext4/btrfs) directly into Windows File Explorer via WSL.

## 🚀 Usage

### Prerequisites
* **OS**: Windows 11 Pro or Windows Server (Limited support for Windows 10)
* **Privileges**: Must be run in an **Administrator** PowerShell terminal.
* **Internet**: Active connection required for Winget and dynamic downloads.

### Quick Start
To view the help menu and see all available options, run the script with the Execution Policy bypass:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Windows-Deployment-Tool.ps1             # Displays the help menu
powershell.exe -ExecutionPolicy Bypass -File .\Windows-Deployment-Tool.ps1 -Standard   # Universal Baseline
powershell.exe -ExecutionPolicy Bypass -File .\Windows-Deployment-Tool.ps1 -Complete   # Heavy Workstation
powershell.exe -ExecutionPolicy Bypass -File .\Windows-Deployment-Tool.ps1 -System     # Run a single module
```

## ⚙️ Command-Line Flags

**All Available Flags (Quick Reference):**
`-Standard`, `-Complete`, `-System`, `-Debloat`, `-Security`, `-Dev`, `-DualBoot`, `-Apps`, `-DevApps`, `-Creators`, `-Cyber`, `-Maker`, `-Gaming`, `-Nvidia`, `-Help`

### Deployment Profiles
| Flag | Description |
| :--- | :--- |
| `-Standard` | **The Universal Baseline.** Executes: System, Debloat, Security, Dev, Apps, and DevApps. |
| `-Complete` | **The Heavy Workstation.** Executes everything in Standard, PLUS: Cyber, Maker, Gaming, Creators, and Nvidia. |
 `-DualBoot` to prevent hardware-specific task errors on single-OS systems.* |

### Core OS Options
| Flag | Description |
| :--- | :--- |
| `-System` | Disables OneDrive/Telemetry prompts, restores the classic Windows 10 Context Menu, enables Win32 Long Paths, sets Explorer tweaks (shows hidden files/extensions, aligns taskbar left), and enables the Ultimate Performance Power Plan. |
| `-Debloat` | Silently uninstalls Windows Widgets, disables Windows Consumer Features (stops Candy Crush auto-installs), and removes base Microsoft Appx bloatware. |
| `-Security` | Disables OS Telemetry via Group Policy, enables Windows Defender PUA (Potentially Unwanted App) Protection, and installs/runs the `PSWindowsUpdate` module. |
| `-Dev` | Enables Windows Optional Features including WSL (Windows Subsystem for Linux), Windows Sandbox, and configures the native OpenSSH Client & Server. |
| `-DualBoot` | Dynamically scans physical disks for Linux partitions, generates a persistent helper script (`C:\Scripts\Mount-Linux.ps1`), and registers an automated Scheduled Task to mount them via WSL at logon. *(Overwrites existing configs to ensure accuracy if drives change)*. |

### Software Provisioning Options
| Flag | Associated Software |
| :--- | :--- |
| `-Apps` | Brave, Chrome, Firefox, Opera, 7-Zip, VLC, Discord, Obsidian, Signal, WhatsApp (via Store ID), CrystalDiskInfo, PowerToys, Everything, Windows Terminal, Rufus. *(Installs TreeSize Free on Desktop OS, WinDirStat on Server OS).* |
| `-DevApps` | VS Code, Python 3.13, GitHub Desktop, Notepad++, PuTTY, PowerShell 7, **OpenSSL** (FireDaemon). |
| `-Creators` | **darktable** (Photo), **Blender** (3D), **HandBrake** (Video), **Audacity** (Audio), **Inkscape** (Vector). |
| `-Cyber` | Wireshark, Nmap, Advanced IP Scanner. |
| `-Maker` | PrusaSlicer, OrcaSlicer, Bambu Studio, Autodesk Fusion 360. |
| `-Gaming` | Steam, OBS Studio, Blizzard Battle.net. |
| `-Nvidia` | Dynamically fetches and installs the latest NVIDIA App directly from Nvidia's servers. |

## 📝 Important Notes

* **Execution Policy**: You **must** invoke the script using `powershell.exe -ExecutionPolicy Bypass -File .\Windows-Deployment-Tool.ps1`. The script no longer attempts to bypass the policy internally, as strictly restricted systems will block the file from loading before the internal bypass function can even execute.
* **Idempotent & Fast**: The script is designed to be completely idempotent. It takes a lightning-fast memory snapshot of your installed Winget packages and reads current registry values before making changes. You can safely run this script repeatedly without wasting time, duplicating installs, or overwriting identical configurations.
* **Log Rotation**: All actions are thoroughly logged to an `InstallerLogs` directory created in the same folder as the script. The script retains the 10 most recent logs and automatically purges older ones.
* **Server OS Compatibility**: The script detects if it is running on a Windows Server kernel and will dynamically adjust package selections (like using WinDirStat) to prevent licensing or installer failures.
* **The Dual-Boot Task (`-DualBoot`)**: This module features **Auto-Discovery**. It scans for non-Windows partitions and targets the most likely Linux candidate. **Note:** Running this module will automatically overwrite any existing `C:\Scripts\Mount-Linux.ps1` file and re-register the `Mount-Linux-WSL` scheduled task to ensure the configuration matches your current hardware state.
## ⚠️ Disclaimer

This script modifies the system registry, uninstalls provisioned Windows packages, and alters security policies. Please review the code to ensure the configurations match your personal environment needs before executing.