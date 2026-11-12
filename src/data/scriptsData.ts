import { ScriptItem } from '../types';
import repoScriptsRaw from './repoScripts.json';
import linuxDeploymentScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Linux-Deployment-Tool.sh?raw';
import linuxBetaRunnerScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/Linux-Deployment-Tool.sh?raw';
import linuxChangelog from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/CHANGELOG.md?raw';
import commonLibScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/lib/common.sh?raw';
import modUpdateScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-update.sh?raw';
import modAppsScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-apps.sh?raw';
import modDevAppsScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-devapps.sh?raw';
import modSysadminScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-sysadmin.sh?raw';
import modCyberScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-cyber.sh?raw';
import modMakerScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-maker.sh?raw';
import modCreatorsScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-creators.sh?raw';
import modHardenScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-harden.sh?raw';
import modHardenAdvScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-harden-adv.sh?raw';
import modSshScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-ssh.sh?raw';
import modDiscordScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-discord.sh?raw';
import modGamingScript from '../../Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-gaming.sh?raw';

export const RAW_SCRIPTS: Record<string, { path: string; content: string }> = {
  ...repoScriptsRaw,
  'Linux-Deployment-Tool.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Linux-Deployment-Tool.sh',
    content: linuxDeploymentScript
  },
  'Beta/Linux-Deployment-Tool.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/Linux-Deployment-Tool.sh',
    content: linuxBetaRunnerScript
  },
  'CHANGELOG.md': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/CHANGELOG.md',
    content: linuxChangelog
  },
  'common.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/lib/common.sh',
    content: commonLibScript
  },
  'mod-update.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-update.sh',
    content: modUpdateScript
  },
  'mod-apps.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-apps.sh',
    content: modAppsScript
  },
  'mod-devapps.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-devapps.sh',
    content: modDevAppsScript
  },
  'mod-sysadmin.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-sysadmin.sh',
    content: modSysadminScript
  },
  'mod-cyber.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-cyber.sh',
    content: modCyberScript
  },
  'mod-maker.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-maker.sh',
    content: modMakerScript
  },
  'mod-creators.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-creators.sh',
    content: modCreatorsScript
  },
  'mod-harden.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-harden.sh',
    content: modHardenScript
  },
  'mod-harden-adv.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-harden-adv.sh',
    content: modHardenAdvScript
  },
  'mod-ssh.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-ssh.sh',
    content: modSshScript
  },
  'mod-discord.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-discord.sh',
    content: modDiscordScript
  },
  'mod-gaming.sh': {
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-gaming.sh',
    content: modGamingScript
  }
};

export const SCRIPT_CATALOG: ScriptItem[] = [
  {
    id: 'linux-deployment-tool-beta',
    name: 'Beta/Linux-Deployment-Tool.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/Linux-Deployment-Tool.sh',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Modular v3.0.1-beta main runner located at the top of the ./Beta directory (branch main). Can be downloaded as a simple tarball (Linux-Deployment-Tool-Beta.tar.gz) or run standalone to fetch missing child modules on-demand from GitHub only when their flags are called.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz (github.com/ZacharySchmalzEng/Tools)',
    requiresElevation: true,
    supportedDistrosOrEditions: [
      'Fedora Workstation',
      'Nobara / Nobaru Linux',
      'Fedora Atomic (Silverblue / Bazzite / Kinoite)',
      'Arch Linux & Manjaro',
      'SteamOS (Steam Deck)',
      'openSUSE (Tumbleweed & Leap)',
      'RHEL / CentOS / Rocky',
      'Debian / Ubuntu / Linux Mint'
    ],
    keyFeatures: [
      'Top-of-Beta Main Runner: Positioned at ./Beta/Linux-Deployment-Tool.sh for clean tarball packaging (Linux-Deployment-Tool-Beta.tar.gz)',
      'Startup GitHub Update Check & "Run As-Is" Control: Compares SHA-256 hashes and lets users [y] update, [n] abort updates & run local scripts as-is, or [q] quit',
      'Module Deprecation & Redirect Handlers: Declarative registry (ready for wrapping --discord into --gaming) with interactive redirect, run-as-is, and local file cleanup/stubbing',
      'Lazy On-Demand GitHub Sync: Only downloads ./Beta/modules/mod-<name>.sh scripts whose CLI flags are actively invoked',
      'Standalone Child Module Execution: All 12 child scripts in ./Beta/modules/ can run independently or via the main runner',
      'Relaxed Permissions (+rw): Logs created with 0666 and libraries/modules with 0755 under umask 0022 so non-root users can inspect logs'
    ],
    flags: [
      { flag: '--all', name: 'Universal Baseline', description: 'Executes all standard child modules. Intentionally excludes --harden-advanced and --2fa to prevent accidental lockout.', category: 'profile' },
      { flag: '--update', name: 'Update Packages (mod-update.sh)', description: 'Upgrades package manager (DNF, rpm-ostree, Pacman, Zypper, APT), Flatpak, and Snap packages.', category: 'core' },
      { flag: '--apps', name: 'System & Utilities (mod-apps.sh)', description: 'Brave, Chrome, Obsidian, Signal, Timeshift, btop, eza, plocate, 7zip, vlc, baobab/filelight/cosmic-files.', category: 'apps', associatedSoftware: ['Brave Browser', 'Google Chrome', 'Obsidian', 'Signal Desktop', 'Timeshift', 'btop', 'eza', 'plocate', 'VLC Media Player'] },
      { flag: '--devapps', name: 'Developer Stack (mod-devapps.sh)', description: 'Git, jq, fzf, tealdeer, rsync, Python 3, OpenSSL, VS Code, and Microsoft PowerShell (pwsh).', category: 'apps', associatedSoftware: ['Git', 'jq', 'fzf', 'tealdeer', 'rsync', 'VS Code', 'Python 3', 'PowerShell 7 (pwsh)', 'OpenSSL'] },
      { flag: '--cyber', name: 'Cybersecurity Suite (mod-cyber.sh)', description: 'Wireshark (adds user to wireshark group), Nmap, TCPDump, and Ncat.', category: 'apps', associatedSoftware: ['Wireshark', 'Nmap', 'TCPDump', 'Ncat'] },
      { flag: '--sysadmin', name: 'System Administration (mod-sysadmin.sh)', description: 'Remmina, tmux, Wireshark, Nmap, TCPDump, DNS and network diagnostics, disk observability, and process tracing.', category: 'apps', associatedSoftware: ['Remmina', 'tmux', 'Wireshark', 'Nmap', 'TCPDump', 'dig', 'mtr', 'iperf3', 'sysstat', 'iotop', 'ncdu', 'smartmontools', 'lsof', 'strace'] },
      { flag: '--maker', name: '3D Printing & CAD (mod-maker.sh)', description: 'PrusaSlicer, OrcaSlicer, and Bambu Studio.', category: 'apps', associatedSoftware: ['PrusaSlicer', 'OrcaSlicer', 'Bambu Studio'] },
      { flag: '--creators', name: 'Creative Production (mod-creators.sh)', description: 'GIMP, Krita, Blender, Audacity, Inkscape, and OBS Studio.', category: 'apps', associatedSoftware: ['GIMP', 'Krita', 'Blender', 'Audacity', 'Inkscape', 'OBS Studio'] },
      { flag: '--gaming', name: 'Gaming & GPU Drivers (mod-gaming.sh)', description: 'Steam, Lutris, Bottles, GameMode, MangoHud, and auto-detected GPU drivers with Nobara safeguards.', category: 'apps', associatedSoftware: ['Steam', 'Lutris', 'Bottles', 'GameMode', 'MangoHud', 'NVIDIA akmod/DKMS / AMD Mesa Vulkan'] },
      { flag: '--ssh', name: 'OpenSSH Server (mod-ssh.sh)', description: 'Installs, enables, and verifies the OpenSSH daemon with socket validation.', category: 'core' },
      { flag: '--discord', name: 'Discord Configuration (mod-discord.sh)', description: 'Configures native RPM on standard Fedora; sandboxed Flathub package on Atomic and SteamOS.', category: 'apps' },
      { flag: '--reinstall', name: 'Safe Package Reinstall', description: 'Reinstalls already-installed packages selected by active modules while installing missing ones.', category: 'modifier' },
      { flag: '--rebuild', name: 'Deep Driver & Initramfs Rebuild', description: 'Forces GPU kernel module rebuilds (dkms, akmods) and initramfs regeneration (dracut, mkinitcpio, update-initramfs).', category: 'modifier' },
      { flag: '--harden', name: 'Safe Baseline Hardening (mod-harden.sh)', description: 'Verifies SELinux/AppArmor, configures automated security patching, and disables direct root login over SSH.', category: 'security' },
      { flag: '--harden-advanced', name: 'Strict Zero-Trust Posture (mod-harden-adv.sh)', description: 'Deploys auditd credential monitoring, drops ICMP pings, enforces strict rp_filter, and disables SSH password authentication.', category: 'security', dangerous: true, warningNote: 'Requires an active SSH public key in ~/.ssh/authorized_keys before closing terminal!' },
      { flag: '--2fa', name: 'MFA OpenSSH Daemon', description: 'Enforces Google Authenticator MFA PAM module on SSH logins.', category: 'security' },
      { flag: '--no-update-check', name: 'Skip GitHub Check', description: 'Bypasses the automatic GitHub startup check for runner, library, and child module updates.', category: 'modifier' }
    ]
  },
  {
    id: 'linux-deployment-tool',
    name: 'Linux-Deployment-Tool.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Linux-Deployment-Tool.sh',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Production v2.1 single-file deployment script with separated CHANGELOG.md header reference. Features multi-distro special handling (Atomic, SteamOS, Arch, openSUSE), Nobara GPU protection, --sysadmin, and --reinstall/--rebuild recovery.',
    version: '2.1',
    author: 'Zachary Schmalz (github.com/ZacharySchmalzEng/Tools)',
    requiresElevation: true,
    supportedDistrosOrEditions: [
      'Fedora Workstation',
      'Nobara / Nobaru Linux',
      'Fedora Atomic (Silverblue / Bazzite / Kinoite)',
      'Arch Linux & Manjaro',
      'SteamOS (Steam Deck)',
      'openSUSE (Tumbleweed & Leap)',
      'RHEL / CentOS / Rocky',
      'Debian / Ubuntu / Linux Mint'
    ],
    keyFeatures: [
      'Zero Manual On-Box Dependencies (Auto-bootstraps curl, pciutils, ca-certificates, flatpak)',
      'Strict Mode Execution (set -euo pipefail) & separated CHANGELOG.md header reference',
      'Multi-Distro Engines: Fedora/RHEL (DNF), Atomic/Bazzite (rpm-ostree), Arch (Pacman), SteamOS (Readonly toggle), openSUSE (Zypper), Debian (APT)',
      'Nobara NVIDIA Safeguard & --reinstall / --rebuild GPU recovery workflows',
      'SteamOS Lifecycle Management: Handles steamos-readonly disable/enable and pacman keyring initialization',
      'openSUSE Packman Essentials: Automatically wires multimedia & gaming codec repositories',
      'Microsoft PowerShell (pwsh) Orchestration: Configures official vendor repositories with automatic Flathub fallback',
      'Tiered Security Hardening (SELinux / AppArmor baseline or strict auditd & sysctl drop)',
      'Native MFA OpenSSH Integration (Google Authenticator PAM)',
      'Desktop Environment Aware: Auto-detects and provisions GNOME, KDE Plasma, COSMIC (System76 Rust), XFCE, and Cinnamon with tailored QoL tools'
    ],
    flags: [
      { flag: '--all', name: 'Universal Baseline', description: 'Executes all standard modules. Intentionally excludes --harden-advanced and --2fa to prevent accidental lockout.', category: 'profile' },
      { flag: '--update', name: 'Update Packages', description: 'Sequentially upgrades package manager (DNF, rpm-ostree, Pacman, Zypper, APT), Flatpak, and Snap packages.', category: 'core' },
      { flag: '--apps', name: 'System & Utilities', description: 'Brave, Chrome, Obsidian, Signal, Timeshift, btop, eza, plocate, 7zip, vlc, baobab/filelight/cosmic-files.', category: 'apps', associatedSoftware: ['Brave Browser', 'Google Chrome', 'Obsidian', 'Signal Desktop', 'Timeshift', 'btop', 'eza', 'plocate', 'VLC Media Player'] },
      { flag: '--devapps', name: 'Developer Stack', description: 'Git, jq, fzf, tealdeer, rsync, Python 3, OpenSSL, VS Code, and Microsoft PowerShell (pwsh).', category: 'apps', associatedSoftware: ['Git', 'jq', 'fzf', 'tealdeer', 'rsync', 'VS Code', 'Python 3', 'PowerShell 7 (pwsh)', 'OpenSSL'] },
      { flag: '--cyber', name: 'Cybersecurity Suite', description: 'Wireshark (adds user to wireshark group), Nmap, TCPDump, and Ncat.', category: 'apps', associatedSoftware: ['Wireshark', 'Nmap', 'TCPDump', 'Ncat'] },
      { flag: '--sysadmin', name: 'System Administration', description: 'Remmina, tmux, Wireshark, Nmap, TCPDump, DNS and network diagnostics, disk observability, and process tracing.', category: 'apps', associatedSoftware: ['Remmina', 'tmux', 'Wireshark', 'Nmap', 'TCPDump', 'dig', 'mtr', 'iperf3', 'sysstat', 'iotop', 'ncdu', 'smartmontools', 'lsof', 'strace'] },
      { flag: '--maker', name: '3D Printing & CAD', description: 'PrusaSlicer, OrcaSlicer, and Bambu Studio.', category: 'apps', associatedSoftware: ['PrusaSlicer', 'OrcaSlicer', 'Bambu Studio'] },
      { flag: '--creators', name: 'Creative Production', description: 'GIMP, Krita, Blender, Audacity, Inkscape, and OBS Studio.', category: 'apps', associatedSoftware: ['GIMP', 'Krita', 'Blender', 'Audacity', 'Inkscape', 'OBS Studio'] },
      { flag: '--gaming', name: 'Gaming & GPU Drivers', description: 'Steam, Lutris, Bottles, GameMode, MangoHud, and auto-detected GPU drivers with Nobara safeguards.', category: 'apps', associatedSoftware: ['Steam', 'Lutris', 'Bottles', 'GameMode', 'MangoHud', 'NVIDIA akmod/DKMS / AMD Mesa Vulkan'] },
      { flag: '--ssh', name: 'OpenSSH Server', description: 'Installs, enables, and verifies the OpenSSH daemon with socket validation.', category: 'core' },
      { flag: '--discord', name: 'Discord Configuration', description: 'Configures native RPM on standard Fedora; sandboxed Flathub package on Atomic and SteamOS.', category: 'apps' },
      { flag: '--reinstall', name: 'Safe Package Reinstall', description: 'Reinstalls packages selected by other modules where supported.', category: 'modifier' },
      { flag: '--rebuild', name: 'Deep Driver Rebuild', description: 'Reinstalls packages and rebuilds supported GPU modules and initramfs images.', category: 'modifier' },
      { flag: '--atomic', name: 'Fedora Atomic Mode', description: 'Force rpm-ostree package layering, Flatpak containment, and scheduled reboots.', category: 'modifier' },
      { flag: '--bazzite', name: 'Bazzite Gaming Mode', description: 'Force Bazzite containerized OS mode; protects pre-baked gaming drivers.', category: 'modifier' },
      { flag: '--silverblue', name: 'Silverblue Mode', description: 'Alias for --atomic rpm-ostree immutable deployment.', category: 'modifier' },
      { flag: '--arch', name: 'Arch Linux Mode', description: 'Force Arch Linux pacman engine with multilib repository verification.', category: 'modifier' },
      { flag: '--steamos', name: 'SteamOS Engine', description: 'Toggles steamos-readonly filesystem protection, populates pacman keys, and re-locks upon completion.', category: 'modifier' },
      { flag: '--opensuse', name: 'openSUSE Engine', description: 'Force Zypper engine, wire Packman Essentials repositories, and enforce AppArmor.', category: 'modifier' },
      { flag: '--distro=<name>', name: 'Distro Override', description: 'Explicit distribution engine override (atomic|bazzite|arch|steamos|opensuse|nobara|rpm|deb).', category: 'modifier' },
      { flag: '--gnome', name: 'GNOME Desktop', description: 'Target GNOME desktop environment and deploy gnome-tweaks and baobab disk usage analyzer.', category: 'core', associatedSoftware: ['gnome-tweaks', 'baobab'] },
      { flag: '--kde', name: 'KDE Plasma Desktop', description: 'Target KDE Plasma desktop environment and deploy filelight disk analyzer.', category: 'core', associatedSoftware: ['filelight'] },
      { flag: '--cosmic', name: 'COSMIC Desktop', description: 'Target System76 COSMIC desktop environment (Rust Epoch) and deploy cosmic-files, cosmic-term, and cosmic-edit utilities.', category: 'core', associatedSoftware: ['cosmic-files', 'cosmic-term', 'cosmic-edit'] },
      { flag: '--xfce', name: 'XFCE Desktop', description: 'Target lightweight modular XFCE desktop environment with xfce4-taskmanager and baobab.', category: 'core', associatedSoftware: ['xfce4-taskmanager', 'baobab'] },
      { flag: '--cinnamon', name: 'Cinnamon Desktop', description: 'Target Cinnamon desktop environment and deploy nemo and baobab tools.', category: 'core', associatedSoftware: ['nemo', 'baobab'] },
      { flag: '--de=<name>', name: 'Desktop Override', description: 'Explicit desktop environment profile override (gnome|kde|cosmic|xfce|cinnamon).', category: 'modifier' },
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
    id: 'ldt-common-lib',
    name: 'common.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/lib/common.sh',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Shared core library for v3.0.1-beta Modular Linux Deployment Tool. Provides multi-distro package routing, SteamOS read-only protection traps, INI/sshd config mutators, GitHub update checking, module deprecation handlers, and standalone child script bootstrapping.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'Nobara', 'Fedora Atomic / Bazzite', 'Arch Linux', 'SteamOS', 'openSUSE', 'Debian / Ubuntu'],
    keyFeatures: [
      'Centralized detect_distro, pkg_install, update_system, and resolve_package_name engines',
      'DEPRECATED_MODULES_REGISTRY, resolve_deprecated_flags, check_deprecated_local_modules, and handle_deprecated_module_stub',
      'Signal & error traps (cleanup_handler) guaranteeing SteamOS read-only restoration',
      'ensure_remote_script() & check_remote_script_update() for GitHub SHA-256 verification and on-demand fetching',
      'init_standalone_module() enabling any child module to run directly from the CLI'
    ]
  },
  {
    id: 'ldt-changelog',
    name: 'CHANGELOG.md',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/CHANGELOG.md',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Separated release changelog documenting all security updates, defect resolutions, and feature enhancements from v1.0 through v3.0.1-beta.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz',
    requiresElevation: false,
    supportedDistrosOrEditions: ['All Supported Linux Distributions'],
    keyFeatures: [
      'Extracted from script headers to keep runner and child modules concise',
      'Tracks CVE-2024-6387 mitigations, SteamOS trap guards, and v3.0.1-beta modular breakdown',
      'Documents v2.1 --sysadmin, --reinstall, and --rebuild additions'
    ]
  },
  {
    id: 'ldt-mod-gaming',
    name: 'mod-gaming.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-gaming.sh',
    os: 'linux',
    category: 'Gaming',
    language: 'bash',
    description: 'Standalone & orchestrated Gaming & GPU Driver child module (--gaming). Configures RPM Fusion, Packman, or multilib, installs Steam/Lutris/Bottles, and provisions NVIDIA/AMD drivers with --rebuild recovery.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'Nobara', 'Atomic / Bazzite', 'Arch', 'SteamOS', 'openSUSE', 'Debian / Ubuntu'],
    keyFeatures: [
      'Can be executed standalone (sudo ./modules/mod-gaming.sh --rebuild -y) or via main runner',
      'Auto-downloads ./Beta/lib/common.sh from GitHub if missing locally',
      'Hybrid lspci + /sys/bus/pci/devices GPU hardware detection',
      'Full --reinstall and --rebuild kernel module (dkms/akmods) and initramfs regeneration'
    ]
  },
  {
    id: 'ldt-mod-sysadmin',
    name: 'mod-sysadmin.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-sysadmin.sh',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Standalone & orchestrated System Administration child module (--sysadmin). Installs Remmina, tmux, Wireshark, Nmap, TCPDump, mtr, iperf3, sysstat, iotop, ncdu, smartmontools, lsof, and strace.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'Nobara', 'Atomic / Bazzite', 'Arch', 'SteamOS', 'openSUSE', 'Debian / Ubuntu'],
    keyFeatures: [
      'Independent or orchestrated execution with automatic common.sh bootstrap',
      'Cross-distro package translation (bind-utils/dnsutils, wireshark-qt, nmap-ncat)',
      'Automatically grants SUDO_USER membership in the wireshark capture group'
    ]
  },
  {
    id: 'ldt-mod-harden',
    name: 'mod-harden.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-harden.sh',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Standalone & orchestrated Standard Hardening child module (--harden). Enforces SELinux/AppArmor, configures automatic security updates, and applies CIS OpenSSH + CVE-2024-6387 mitigations.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'Nobara', 'Atomic / Bazzite', 'Arch', 'SteamOS', 'openSUSE', 'Debian / Ubuntu'],
    keyFeatures: [
      'Enforces SELinux on RPM/Atomic and AppArmor on Debian/openSUSE',
      'Configures dnf-automatic, rpm-ostreed-automatic, or unattended-upgrades',
      'Applies Match-block safe sshd_config hardening and LoginGraceTime 20s'
    ]
  },
  {
    id: 'ldt-mod-apps',
    name: 'mod-apps.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-apps.sh',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Standalone & orchestrated System QoL & Desktop Apps child module (--apps). Installs CLI/GUI utilities, Desktop Environment tools (GNOME, KDE, COSMIC, XFCE, Cinnamon), and Flathub desktop apps.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'Nobara', 'Atomic / Bazzite', 'Arch', 'SteamOS', 'openSUSE', 'Debian / Ubuntu'],
    keyFeatures: [
      'Auto-detects or prompts for Desktop Environment (GNOME, KDE, COSMIC, XFCE, Cinnamon)',
      'Installs timeshift, btop, bat, eza, plocate, mediawriter, p7zip, and vlc',
      'Deploys Brave, Chrome, Obsidian, and Signal via Flathub'
    ]
  },
  {
    id: 'ldt-mod-devapps',
    name: 'mod-devapps.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-devapps.sh',
    os: 'linux',
    category: 'Provisioning',
    language: 'bash',
    description: 'Standalone & orchestrated Developer Stack child module (--devapps). Installs Python 3, OpenSSL, Git, jq, fzf, tealdeer, rsync, Microsoft PowerShell (pwsh), and VS Code.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'Nobara', 'Atomic / Bazzite', 'Arch', 'SteamOS', 'openSUSE', 'Debian / Ubuntu'],
    keyFeatures: [
      'Installs modern CLI productivity tools (jq, fzf, tealdeer, rsync, git)',
      'Orchestrates Microsoft PowerShell native repository setup with Flathub fallback',
      'Deploys Visual Studio Code via Flathub'
    ]
  },
  {
    id: 'ldt-mod-ssh',
    name: 'mod-ssh.sh',
    path: 'Linux/Provisioning/Linux-Deployment-Tool/Beta/modules/mod-ssh.sh',
    os: 'linux',
    category: 'Networking',
    language: 'bash',
    description: 'Standalone & orchestrated OpenSSH + 2FA child module (--ssh [--2fa]). Installs OpenSSH Server, configures optional Google Authenticator PAM MFA, and validates socket listeners.',
    version: '3.0.1-beta',
    author: 'Zachary Schmalz',
    requiresElevation: true,
    supportedDistrosOrEditions: ['Fedora', 'Nobara', 'Atomic / Bazzite', 'Arch', 'SteamOS', 'openSUSE', 'Debian / Ubuntu'],
    keyFeatures: [
      'Idempotent OpenSSH Server installation and systemd enablement',
      'Optional --2fa Google Authenticator PAM injection with nullok transition protection',
      'Active socket verification via ss -lt'
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
