import { ScriptItem } from '../types';
import repoScriptsRaw from './repoScripts.json';

export const RAW_SCRIPTS: Record<string, { path: string; content: string }> = repoScriptsRaw;

export const SCRIPT_CATALOG: ScriptItem[] = [
  {
    id: 'linux-deployment-tool',
    name: 'Linux-Deployment-Tool.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Linux-Deployment-Tool.sh',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Modular flag-based deployment tool for fresh Linux installations. Features distro-aware package management, GPU driver auto-selection, and tiered security hardening.',
    version: '1.3 Beta',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'Nobara / Nobaru', 'RHEL', 'CentOS', 'Rocky', 'AlmaLinux', 'Debian', 'Ubuntu', 'Linux Mint', 'Pop!_OS'],
    keyFeatures: [
      'Strict Mode Execution (set -euo pipefail)',
      'Distro-Aware Package Management (Fedora, Nobara/Nobaru, RHEL & APT parity)',
      'Nobara / Nobaru native gaming tweaks & repository auto-detection',
      'GPU-Aware Driver Stack (NVIDIA akmod vs AMD mesa-vulkan)',
      'Tiered Security Hardening (SELinux baseline or strict auditd & sysctl drop)',
      'Native MFA OpenSSH Integration (Google Authenticator PAM)',
      'Desktop Environment Aware (KDE Plasma vs GNOME QoL tools)',
      'Unattended & Dry-Run (-d) modes'
    ],
    flags: [
      { flag: '--all', name: 'Universal Baseline', description: 'Executes all standard modules. Intentionally excludes --harden-advanced and --2fa to prevent accidental lockout.', category: 'profile' },
      { flag: '--update', name: 'Update Packages', description: 'Sequentially upgrades DNF/APT, Flatpak, and Snap packages.', category: 'core' },
      { flag: '--apps', name: 'System & Utilities', description: 'Brave, Chrome, Obsidian, Signal, Timeshift, btop, eza, plocate, 7zip, vlc, baobab/filelight.', category: 'apps', associatedSoftware: ['Brave Browser', 'Google Chrome', 'Obsidian', 'Signal Desktop', 'Timeshift', 'btop', 'eza', 'plocate', 'VLC Media Player'] },
      { flag: '--devapps', name: 'Developer Stack', description: 'Python 3, OpenSSL, VS Code, GitHub Desktop, PowerShell, and Remmina.', category: 'apps', associatedSoftware: ['VS Code', 'Python 3', 'GitHub Desktop', 'PowerShell 7', 'Remmina Remote Desktop', 'OpenSSL'] },
      { flag: '--cyber', name: 'Cybersecurity Suite', description: 'Wireshark (adds user to wireshark group), Nmap, TCPDump, and Ncat.', category: 'apps', associatedSoftware: ['Wireshark', 'Nmap', 'TCPDump', 'Ncat'] },
      { flag: '--maker', name: '3D Printing & CAD', description: 'PrusaSlicer, OrcaSlicer, and Bambu Studio.', category: 'apps', associatedSoftware: ['PrusaSlicer', 'OrcaSlicer', 'Bambu Studio'] },
      { flag: '--creators', name: 'Creative Production', description: 'Blender, Darktable, Audacity, Inkscape, and OBS Studio.', category: 'apps', associatedSoftware: ['Blender', 'Darktable', 'Audacity', 'Inkscape', 'OBS Studio'] },
      { flag: '--gaming', name: 'Gaming & GPU Drivers', description: 'Steam, Lutris, Bottles, and auto-detects/installs NVIDIA or AMD driver stacks.', category: 'apps', associatedSoftware: ['Steam', 'Lutris', 'Bottles', 'NVIDIA akmod / AMD Mesa Vulkan'] },
      { flag: '--ssh', name: 'OpenSSH Server', description: 'Installs, enables, and verifies the OpenSSH daemon with socket validation.', category: 'core' },
      { flag: '--discord', name: 'Native Discord', description: 'Replaces Flatpak Discord with native RPM/DEB package.', category: 'apps' },
      { flag: '--harden', name: 'Safe Baseline Hardening', description: 'Verifies SELinux/AppArmor, configures automated security patching, and disables direct root login over SSH.', category: 'security' },
      { flag: '--harden-advanced', name: 'Strict Zero-Trust Posture', description: 'Deploys auditd credential monitoring, drops ICMP pings, enforces strict rp_filter, and disables SSH password authentication.', category: 'security', dangerous: true, warningNote: 'Requires an active SSH public key in ~/.ssh/authorized_keys before closing terminal!' },
      { flag: '--2fa', name: 'MFA OpenSSH Daemon', description: 'Enforces Google Authenticator MFA PAM module on SSH logins.', category: 'security' },
      { flag: '-y', name: 'Auto-Install', description: 'Answers yes to all package manager and repository prompts.', category: 'modifier' },
      { flag: '-d', name: 'Download Only', description: 'Dry-run validation: resolves and downloads packages without executing changes.', category: 'modifier' },
      { flag: '--unattended', name: 'Unattended Mode', description: 'Bypasses DE and reboot prompts, applies -y automatically.', category: 'modifier' },
      { flag: '--debug', name: 'Debug Trace', description: 'Enables set -x shell execution tracing to console and log files.', category: 'modifier' }
    ]
  },
  {
    id: 'windows-deployment-tool',
    name: 'Windows-Deployment-Tool.ps1',
    path: 'Windows/Provisioning/Windows-Deployment-Tool/Windows-Deployment-Tool.ps1',
    os: 'windows',
    category: 'Provisioning',
    language: 'powershell',
    description: 'Modular, flag-based deployment framework for fresh Windows 10, 11 Pro, and Windows Server installations. Idempotent memory snapshotting, telemetry hardening, and software provisioning.',
    version: '2.0',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Windows 11 Pro', 'Windows 10 Pro', 'Windows Server 2022', 'Windows Server 2025'],
    keyFeatures: [
      'Pre-Configured Deployment Profiles (-Standard, -Complete, -Light)',
      'Smart Idempotency (takes Winget memory snapshot before touching disk)',
      'Dynamic Web Scraping for latest NVIDIA App installer',
      'Proprietary Install Bypasses (forces GUI installers like Battle.net into silent mode)',
      'Server OS Aware (substitutes incompatible packages like TreeSize -> WinDirStat)',
      'Native WSL Dual-Boot Auto-Discovery (scans and mounts ext4/btrfs partitions)',
      'Automated Teardown via -Uninstall modifier',
      'Automatic Log Rotation (retains 10 most recent logs in InstallerLogs/)'
    ],
    flags: [
      { flag: '-Standard', name: 'Universal Baseline Profile', description: 'Executes System, Debloat, Security, Apps, AutoUpdate, and Maintenance.', category: 'profile' },
      { flag: '-Complete', name: 'Heavy Workstation Profile', description: 'Executes Standard + Dev, Cyber, Maker, Gaming, Creators, and Nvidia.', category: 'profile' },
      { flag: '-Light', name: 'Lightweight Baseline Profile', description: 'Executes only System, Debloat, and Security with no application installs.', category: 'profile' },
      { flag: '-System', name: 'System & Explorer Tweaks', description: 'Disables OneDrive/Telemetry prompts, restores Win10 context menu, enables Win32 Long Paths, shows hidden files/extensions, aligns taskbar left, enables Ultimate Performance Power Plan.', category: 'core' },
      { flag: '-Debloat', name: 'OS Debloat & Bloatware Removal', description: 'Silently uninstalls Windows Widgets, disables Windows Consumer Features (Candy Crush), removes provisioned Appx bloat.', category: 'core' },
      { flag: '-Security', name: 'Security & Telemetry Hardening', description: 'Disables telemetry via Group Policy, enables Defender PUA protection, installs and runs PSWindowsUpdate.', category: 'security' },
      { flag: '-Dev', name: 'Developer Platform Features', description: 'Enables WSL (Windows Subsystem for Linux), Windows Sandbox, and native OpenSSH Client & Server.', category: 'core' },
      { flag: '-DualBoot', name: 'Dual-Boot WSL Partition Mounting', description: 'Scans physical disks for Linux partitions, generates C:\\Scripts\\Mount-Linux.ps1, registers Mount-Linux-WSL scheduled task.', category: 'core' },
      { flag: '-Apps', name: 'Standard Software Suite', description: 'Brave, Chrome, Firefox, Opera, 7-Zip, VLC, Discord, Obsidian, Signal, WhatsApp, CrystalDiskInfo, PowerToys, Everything, Windows Terminal, Rufus.', category: 'apps', associatedSoftware: ['Brave', 'Google Chrome', 'Mozilla Firefox', 'Opera', '7-Zip', 'VLC Media Player', 'Discord', 'Obsidian', 'Signal', 'WhatsApp', 'CrystalDiskInfo', 'PowerToys', 'Everything', 'Windows Terminal', 'Rufus', 'TreeSize Free / WinDirStat'] },
      { flag: '-DevApps', name: 'Developer Toolchain', description: 'VS Code, Python 3.13, GitHub Desktop, Notepad++, PuTTY, PowerShell 7, OpenSSL (FireDaemon).', category: 'apps', associatedSoftware: ['VS Code', 'Python 3.13', 'GitHub Desktop', 'Notepad++', 'PuTTY', 'PowerShell 7', 'OpenSSL'] },
      { flag: '-Creators', name: 'Creator & Media Stack', description: 'darktable, Blender, HandBrake, Audacity, Inkscape.', category: 'apps', associatedSoftware: ['darktable', 'Blender', 'HandBrake', 'Audacity', 'Inkscape'] },
      { flag: '-Cyber', name: 'Cybersecurity Tools', description: 'Wireshark, Nmap, Advanced IP Scanner.', category: 'apps', associatedSoftware: ['Wireshark', 'Nmap', 'Advanced IP Scanner'] },
      { flag: '-Maker', name: '3D Printing & CAD', description: 'PrusaSlicer, OrcaSlicer, Bambu Studio, Autodesk Fusion 360.', category: 'apps', associatedSoftware: ['PrusaSlicer', 'OrcaSlicer', 'Bambu Studio', 'Autodesk Fusion 360'] },
      { flag: '-Gaming', name: 'Gaming Essentials', description: 'Steam, OBS Studio, Blizzard Battle.net.', category: 'apps', associatedSoftware: ['Steam', 'OBS Studio', 'Battle.net'] },
      { flag: '-Nvidia', name: 'Dynamic NVIDIA App', description: 'Scrapes NVIDIA portal for latest installer and executes silent setup.', category: 'apps' },
      { flag: '-AutoUpdate', name: 'Automated Update Task', description: 'Registers weekly SYSTEM scheduled task for winget upgrades and Windows Updates.', category: 'core' },
      { flag: '-Maintenance', name: 'Automated Maintenance Task', description: 'Registers weekly SYSTEM scheduled task for TRIM, DNS flush, chkdsk, SFC/DISM, temp cleanup.', category: 'core' },
      { flag: '-Uninstall', name: 'Teardown / Rollback', description: 'Reverts configurations and uninstalls applications matching selected modules.', category: 'modifier' }
    ]
  },
  {
    id: 'deploy-restic-gdrive-linux',
    name: 'deploy-restic-gdrive.sh',
    path: 'Linux/Backups/deploy-restic-gdrive.sh',
    os: 'linux',
    category: 'Backups',
    language: 'bash',
    description: 'Zero-touch automated Restic backup deployment with Google Drive backend via Rclone. Supports both standard and Atomic (Silverblue/Kinoite) Fedora variants with systemd timers.',
    version: '1.0',
    author: 'Zachary Schmalz',
    requiresElevation: false,
    supportedDistrosOrEditions: ['Fedora Workstation', 'Fedora Silverblue', 'Fedora Kinoite', 'Debian', 'Ubuntu'],
    keyFeatures: [
      'Zero-knowledge client-side encryption via Restic',
      'Google Drive cloud backend via Rclone remote',
      'Atomic / Immutable OS detection (rpm-ostree vs dnf)',
      'Systemd user service & timer with randomized execution delay',
      'Automatic retention pruning (7 daily, 4 weekly, 12 monthly, 1 yearly)'
    ]
  },
  {
    id: 'deploy-restic-gdrive-win',
    name: 'deploy-restic-gdrive.ps1',
    path: 'Windows/Backups/deploy-restic-gdrive.ps1',
    os: 'windows',
    category: 'Backups',
    language: 'powershell',
    description: 'Native Windows automated Restic backup deployment to Google Drive. Executes via Task Scheduler under NT AUTHORITY\\SYSTEM and leverages VSS to bypass locked-file exceptions.',
    version: '1.0',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Windows 11 Pro', 'Windows 10 Pro', 'Windows Server'],
    keyFeatures: [
      'Volume Shadow Copy Service (VSS) via --use-fs-snapshot to capture open/locked files',
      'SYSTEM context execution prevents user-permission interruptions',
      'Multi-machine randomized delay prevents Google Drive API rate limits',
      'Self-contained setup script installs rclone & restic via winget if absent',
      'Custom secure password vault storage'
    ]
  },
  {
    id: 'profile-merge',
    name: 'ProfileMerge.ps1',
    path: 'Windows/Data_Management/ProfileMerge.ps1',
    os: 'windows',
    category: 'Data Management',
    language: 'powershell',
    description: 'Unified state-driven deduplication engine for cross-OS user profile consolidation. Employs SHA-256 cryptographic hashing, Destination Memory Shield, and .NET Reparse Point detachment.',
    version: '2.0',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Windows 11 Pro', 'Windows 10', 'Windows Server'],
    keyFeatures: [
      'Two-Phase Architecture: -Plan (read-only CSV report) and -Apply (execution)',
      'Cryptographic SHA-256 deduplication across collided profile directories',
      'Destination Memory Shield: Prevents dangerous accidental self-overwrites',
      '.NET Reparse Point Detachment: Navigates OneDrive junctions without PS 5.1 recursion bugs',
      'Requires explicit -AutoPruneDuplicates authorization before deleting true duplicates'
    ]
  },
  {
    id: 'deploy-os-maintenance-task',
    name: 'Deploy-OSMaintenanceTask.ps1',
    path: 'Windows/Provisioning/Deploy-OSMaintenanceTask.ps1',
    os: 'windows',
    category: 'Maintenance',
    language: 'powershell',
    description: 'Registers a weekly, SYSTEM-context maintenance task that performs SSD TRIM optimization, DNS cache flushing, chkdsk volume health checks, SFC / DISM component repair, and temp cleanup.',
    version: '1.1',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Windows 11 Pro', 'Windows 10', 'Windows Server'],
    keyFeatures: [
      'SSD TRIM & Volume Optimization (Optimize-Volume)',
      'DNS Cache Flush & Network Stack Hygiene',
      'Chkdsk Read-Only Volume Health Check',
      'SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth repair',
      'Purges User and System Temp directories',
      'Optional companion AutoUpdate task registration'
    ]
  },
  {
    id: 'deploy-auto-update-task',
    name: 'Deploy-AutoUpdateTask.ps1',
    path: 'Windows/Provisioning/Deploy-AutoUpdateTask.ps1',
    os: 'windows',
    category: 'Maintenance',
    language: 'powershell',
    description: 'Registers a weekly, SYSTEM-context scheduled task for unattended Winget package upgrades and Windows Update orchestration via PSWindowsUpdate.',
    version: '1.0',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Windows 11 Pro', 'Windows 10', 'Windows Server'],
    keyFeatures: [
      'Silent winget upgrade --all --include-unknown --silent',
      'Automated PSWindowsUpdate module bootstrap',
      'Captures stdout and stderr in rotatable system transcripts',
      'Idempotent Task Scheduler registration under NT AUTHORITY\\SYSTEM'
    ]
  },
  {
    id: 'install-gaming-fedora',
    name: 'InstallBaseGamingFedora41+.sh',
    path: 'Linux/Gaming/InstallBaseGamingFedora41+.sh',
    os: 'linux',
    category: 'Gaming',
    language: 'bash',
    description: 'Automates post-install setup for a dedicated Fedora 41+ gaming rig. Enables RPM Fusion, installs Vulkan drivers, Steam, Lutris, Bottles, Wine, and 30-day retention policies.',
    version: '1.0',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora 41+', 'Fedora Workstation'],
    keyFeatures: [
      'RPM Fusion Free & Non-Free repository setup',
      'Core 32-bit and 64-bit Vulkan drivers and Mesa libraries',
      'Steam, Lutris, Bottles gaming runtime stacks',
      'Gamemode and kernel performance tweaks',
      'Interactive disaster recovery mode'
    ]
  },
  {
    id: 'fedora-discord-update',
    name: 'FedoraDiscordUpdate.sh',
    path: 'Linux/Maintenance/FedoraDiscordUpdate.sh',
    os: 'linux',
    category: 'Maintenance',
    language: 'bash',
    description: 'Automates the transition from the Flatpak version of Discord to the native RPM package via RPM Fusion to improve system tray, audio capture, and hotkey support.',
    version: '1.0',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora 40+', 'RHEL / AlmaLinux'],
    keyFeatures: [
      'Detects and removes Flatpak Discord if installed',
      'Enables RPM Fusion Non-Free repositories',
      'Installs native Discord RPM package via DNF',
      'Fixes screen-sharing audio capture and Wayland keyboard bindings'
    ]
  },
  {
    id: 'updates-all-methods',
    name: 'updatesAllMethods.sh',
    path: 'Linux/Maintenance/updatesAllMethods.sh',
    os: 'linux',
    category: 'Maintenance',
    language: 'bash',
    description: 'Universal update script that sequentially upgrades DNF/APT packages, Flatpak runtimes, and Snap packages in a single pass. Designed for terminal aliases.',
    version: '1.0',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'RHEL', 'Debian', 'Ubuntu'],
    keyFeatures: [
      'Sequential multi-tier update (DNF/APT -> Flatpak -> Snap)',
      'Supports -y flag for automated non-interactive upgrades',
      'Supports -d flag for download-only / bandwidth caching',
      'Clean ANSI terminal status formatting'
    ]
  },
  {
    id: 'fedora-enable-ssh',
    name: 'FedoraEnableSSH.sh',
    path: 'Linux/Networking/FedoraEnableSSH.sh',
    os: 'linux',
    category: 'Networking',
    language: 'bash',
    description: 'Provisions and hardens OpenSSH Server on Fedora/RHEL. Features idempotency checks, optional Google Authenticator 2FA PAM enforcement, firewall openings, and daemon validation.',
    version: '1.1',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'RHEL', 'CentOS', 'Rocky Linux'],
    keyFeatures: [
      'Idempotent OpenSSH server check and DNF install',
      'Optional Google Authenticator 2FA integration for PAM and sshd_config',
      'Firewalld service enablement (firewall-cmd --add-service=ssh --permanent)',
      'Enables and restarts sshd systemd daemon',
      'Verification of active listening sockets (ss -tulpn)'
    ]
  }
];
