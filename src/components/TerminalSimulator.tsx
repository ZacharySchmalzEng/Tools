import React, { useState, useEffect, useRef } from 'react';
import { 
  Terminal as TerminalIcon, Play, Pause, RotateCcw, Download, Copy, Check, 
  Filter, FastForward, CheckCircle2, AlertTriangle, ShieldCheck, Cpu, HardDrive
} from 'lucide-react';
import { SCRIPT_CATALOG } from '../data/scriptsData';

interface TerminalSimulatorProps {
  initialScriptId?: string;
  initialCommand?: string;
  initialFlags?: string[];
}

interface LogLine {
  id: number;
  timestamp: string;
  type: 'info' | 'success' | 'warn' | 'error' | 'cmd' | 'header';
  text: string;
}

export const TerminalSimulator: React.FC<TerminalSimulatorProps> = ({
  initialScriptId = 'linux-deployment-tool',
  initialCommand,
  initialFlags
}) => {
  const [selectedScriptId, setSelectedScriptId] = useState<string>(initialScriptId);
  const [customCommand, setCustomCommand] = useState<string>(
    initialCommand || 'sudo ./Linux-Deployment-Tool.sh --apps --gaming -d'
  );
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [filterType, setFilterType] = useState<string>('all');
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);
  const [copiedLog, setCopiedLog] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [completedStats, setCompletedStats] = useState<{
    exitCode: number;
    packagesProcessed: number;
    securityRulesEnforced: number;
    durationSeconds: number;
  } | null>(null);

  const logsEndRef = useRef<HTMLDivElement>(null);
  const simulationTimeoutRef = useRef<any>(null);

  useEffect(() => {
    if (initialCommand) {
      setCustomCommand(initialCommand);
    }
    if (initialScriptId) {
      setSelectedScriptId(initialScriptId);
    }
  }, [initialCommand, initialScriptId]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Generate synthetic but authentic log sequence based on script & flags
  const generateScriptLogs = (scriptId: string, cmd: string): { type: LogLine['type']; text: string }[] => {
    const isWindows = scriptId.includes('windows') || scriptId.includes('win') || scriptId.includes('profile');
    const isRestic = scriptId.includes('restic');
    const isMaintenance = scriptId.includes('maintenance') || scriptId.includes('update');
    const isSSH = scriptId.includes('ssh');

    if (scriptId === 'linux-deployment-tool') {
      const hasApps = cmd.includes('--apps') || cmd.includes('--all');
      const hasDevApps = cmd.includes('--devapps') || cmd.includes('--all');
      const hasCreators = cmd.includes('--creators') || cmd.includes('--all');
      const hasSysadmin = cmd.includes('--sysadmin') || cmd.includes('--all');
      const hasGaming = cmd.includes('--gaming') || cmd.includes('--all');
      const hasStrict = cmd.includes('--harden-advanced');
      const hasHarden = cmd.includes('--harden') || cmd.includes('--all');
      const has2FA = cmd.includes('--2fa');
      const isDryRun = cmd.includes('-d');

      const isNobara = cmd.toLowerCase().includes('nobara') || cmd.toLowerCase().includes('nobaru');
      const isSteamOS = cmd.includes('--steamos') || cmd.includes('steamos');
      const isBazzite = cmd.includes('--bazzite') || cmd.includes('--atomic');
      const isArch = cmd.includes('--arch') || cmd.includes('arch');
      const isOpenSUSE = cmd.includes('--opensuse') || cmd.includes('suse');

      const isCosmic = cmd.includes('--cosmic') || cmd.includes('--de=cosmic');
      const isXfce = cmd.includes('--xfce') || cmd.includes('--de=xfce');
      const isCinnamon = cmd.includes('--cinnamon') || cmd.includes('--de=cinnamon');
      const isGnome = cmd.includes('--gnome') || cmd.includes('--de=gnome');

      let deName = 'KDE Plasma';
      let deQoLText = '[Desktop QoL] Profile: KDE Plasma -> Deployed filelight analyzer.';
      if (isCosmic) {
        deName = 'COSMIC Desktop (System76 Rust Epoch)';
        deQoLText = '[Desktop QoL] Profile: COSMIC -> Deployed cosmic-files, cosmic-term, and cosmic-edit utilities.';
      } else if (isXfce) {
        deName = 'XFCE';
        deQoLText = '[Desktop QoL] Profile: XFCE -> Deployed xfce4-taskmanager and baobab.';
      } else if (isCinnamon) {
        deName = 'Cinnamon';
        deQoLText = '[Desktop QoL] Profile: Cinnamon -> Deployed nemo and baobab.';
      } else if (isGnome) {
        deName = 'GNOME';
        deQoLText = '[Desktop QoL] Profile: GNOME -> Deployed baobab and gnome-tweaks.';
      }

      let distroStr = 'Detected: Fedora Linux 41 (Workstation Edition x86_64), Linux 6.11.4';
      let engineStr = 'Package manager selected: DNF5 (RPM family parity)';

      if (isSteamOS) {
        distroStr = 'Detected: SteamOS 3.6 Holo (Steam Deck), Linux 6.5.0-valve';
        engineStr = 'Package engine: Pacman with steamos-readonly integrity lifecycle';
      } else if (isBazzite) {
        distroStr = 'Detected: Bazzite 41 (KDE Atomic x86_64), Linux 6.11.4-bazzite';
        engineStr = 'Package engine: rpm-ostree container tree & Flathub containment';
      } else if (isArch) {
        distroStr = 'Detected: Arch Linux (Rolling Release x86_64), Linux 6.11.7-arch';
        engineStr = 'Package engine: Pacman with [multilib] 32-bit gaming runtimes';
      } else if (isOpenSUSE) {
        distroStr = 'Detected: openSUSE Tumbleweed (Rolling Release), Linux 6.11.6';
        engineStr = 'Package engine: Zypper with Packman Essentials & AppArmor';
      } else if (isNobara) {
        distroStr = 'Detected: Nobara Linux 41 (Gaming Edition x86_64), Linux 6.11.4-nobara';
        engineStr = 'Nobara detected: Native gaming kernel tweaks & DKMS Nvidia drivers active.';
      }

      const lines: { type: LogLine['type']; text: string }[] = [
        { type: 'cmd', text: cmd },
        { type: 'header', text: '=== Linux Automated Deployment & Provisioning Tool v2.1 ===' },
        { type: 'info', text: 'Initializing execution context with strict mode (set -euo pipefail, umask 077)...' },
        { type: 'info', text: 'Registering signal recovery traps (SteamOS auto-relock & temp directory garbage collection)...' },
        { type: 'info', text: 'Validating root / superuser execution privileges...' },
        { type: 'success', text: 'Root authorization verified (EUID=0).' },
        { type: 'info', text: 'Auto-bootstrapping base dependencies (curl, pciutils, ca-certificates, flatpak)...' },
        { type: 'success', text: 'Zero on-box dependency check passed: Core utilities verified.' },
        { type: 'info', text: 'Detecting Linux distribution family and kernel release...' },
        { type: 'success', text: distroStr },
        { type: 'info', text: engineStr },
        { type: 'info', text: `Configuring Desktop Environment target: ${deName}...` },
        { type: 'info', text: 'Auto-probing PCI hardware bus for GPU vendor...' },
        { type: 'success', text: 'Found GPU: NVIDIA GeForce RTX 4070 (vendor 10de: device 2786)' },
        { type: 'info', text: isNobara ? 'Nobara detected: NVIDIA proprietary drivers pre-packaged via DKMS / nobara-nvidia-production. Skipping manual akmod-nvidia to prevent conflict.' : (isSteamOS ? 'SteamOS detected: Custom Valve Linux kernel targets AMD APU. Skipping NVIDIA desktop drivers.' : 'Selecting NVIDIA driver stack: akmod-nvidia & CUDA tools') },
        { type: 'info', text: 'Creating audit transcript: /var/log/InstallerLogs/Deploy_20261103_0637.log (mode 0600)' },
        { type: 'info', text: 'Refreshing package repository metadata...' },
        { type: 'success', text: isSteamOS ? 'Synchronized SteamOS Pacman holo & archlinux keyrings.' : (isOpenSUSE ? 'Packman Essentials and openSUSE Tumbleweed repos refreshed.' : 'Repository metadata cache synchronized.') },
      ];

      if (isDryRun) {
        lines.push({ type: 'warn', text: 'DRY-RUN / DOWNLOAD-ONLY MODE (-d) ACTIVE. No changes will be committed to disk.' });
      }

      if (hasApps) {
        lines.push(
          { type: 'info', text: '[Apps Module] Resolving utility packages: btop, eza, plocate, p7zip, vlc, timeshift...' },
          { type: 'success', text: '[Apps Module] Downloaded & staged: btop (v1.4.0), eza (v0.20.1), plocate, vlc' },
          { type: 'success', text: deQoLText },
          { type: 'info', text: '[Apps Module] Querying Flatpak remote flathub for: Obsidian, Signal Desktop, Brave...' },
          { type: 'success', text: '[Apps Module] Flatpak applications verified and staged.' }
        );
      }

      if (hasDevApps) {
        lines.push(
          { type: 'info', text: '[Dev Apps Module] Installing baseline CLI and development tools...' },
          { type: 'success', text: '[Dev Apps Module] Staged: git, jq, fzf, tealdeer, rsync, python3, openssl, PowerShell, VS Code' }
        );
      }

      if (hasCreators) {
        lines.push(
          { type: 'info', text: '[Creators Module] Installing creative production tools...' },
          { type: 'success', text: '[Creators Module] Staged: gimp, krita, blender, audacity, inkscape, obs-studio' }
        );
      }

      if (hasGaming) {
        lines.push(
          { type: 'info', text: '[Gaming Module] Configuring RPM Fusion non-free-tainted repository...' },
          { type: 'info', text: '[Gaming Module] Installing 32-bit & 64-bit Vulkan ICDs and Mesa drivers...' },
          { type: 'success', text: '[Gaming Module] Staged: steam, lutris, wine, gamemode, mangohud, vulkan-tools' }
        );
      }

      if (hasSysadmin) {
        lines.push(
          { type: 'info', text: '[Sysadmin Module] Resolving remote access, session, network, disk, and process diagnostics...' },
          { type: 'success', text: '[Sysadmin Module] Staged: remmina, tmux, wireshark, nmap, tcpdump, bind-utils, mtr, iperf3, sysstat, iotop, ncdu, smartmontools, lsof, strace' }
        );
      }

      if (hasHarden) {
        lines.push(
          { type: 'info', text: '[Security Baseline] Verifying SELinux enforcement state...' },
          { type: 'success', text: '[Security Baseline] SELinux is active (Enforcing mode).' },
          { type: 'info', text: '[Security Baseline] Enforcing unattended security updates policy...' },
          { type: 'info', text: '[Security Baseline] Modifying /etc/ssh/sshd_config: PermitRootLogin no' }
        );
      }

      if (hasStrict) {
        lines.push(
          { type: 'warn', text: '[STRICT POSTURE] Applying auditd credential monitors (/etc/audit/rules.d/audit.rules)...' },
          { type: 'warn', text: '[STRICT POSTURE] Hardening sysctl: net.ipv4.conf.all.rp_filter=1, icmp_echo_ignore_all=1' },
          { type: 'warn', text: '[STRICT POSTURE] DISABLING SSH PASSWORD AUTHENTICATION: PasswordAuthentication no' },
          { type: 'success', text: '[STRICT POSTURE] Verified SSH authorized_keys presence for current user.' }
        );
      }

      if (has2FA) {
        lines.push(
          { type: 'info', text: '[2FA Module] Installing google-authenticator PAM module...' },
          { type: 'info', text: '[2FA Module] Updating /etc/pam.d/sshd with auth required pam_google_authenticator.so' },
          { type: 'success', text: '[2FA Module] Multi-Factor Authentication active for OpenSSH daemon.' }
        );
      }

      lines.push(
        { type: 'info', text: 'Validating systemd service integrity...' },
        { type: 'success', text: 'Service sshd.service: Active (running) on [::]:22' },
        { type: 'success', text: 'All requested modules completed idempotently.' },
        { type: 'header', text: '=== Deployment Complete! Exit Code 0. Transcript saved. ===' }
      );

      return lines;
    }

    if (scriptId === 'windows-deployment-tool') {
      const hasApps = cmd.includes('-Apps') || cmd.includes('-Standard') || cmd.includes('-Complete');
      const hasDebloat = cmd.includes('-Debloat') || cmd.includes('-Standard') || cmd.includes('-Complete');
      const hasDev = cmd.includes('-Dev') || cmd.includes('-Complete');
      const hasDualBoot = cmd.includes('-DualBoot') || cmd.includes('-Complete');
      const hasNvidia = cmd.includes('-Nvidia') || cmd.includes('-Complete');
      const isUninstall = cmd.includes('-Uninstall');

      const lines: { type: LogLine['type']; text: string }[] = [
        { type: 'cmd', text: cmd },
        { type: 'header', text: '=== Windows 10/11 Pro & Server Deployment Tool v2.0 ===' },
        { type: 'info', text: 'Verifying administrative execution context (Administrator)...' },
        { type: 'success', text: 'Elevated token verified. Running as NT AUTHORITY\\SYSTEM / Elevated Admin.' },
        { type: 'info', text: 'Detecting operating system edition and build version...' },
        { type: 'success', text: 'Detected: Windows 11 Pro 23H2 (OS Build 22631.4317)' },
        { type: 'info', text: 'Taking in-memory snapshot of installed Winget packages for idempotency...' },
        { type: 'success', text: 'Winget cache initialized: 84 existing packages cataloged in 184ms.' },
      ];

      if (isUninstall) {
        lines.push(
          { type: 'warn', text: 'REVERSAL / UNINSTALL MODE ACTIVE (-Uninstall). Reverting configurations...' }
        );
      }

      if (hasDebloat) {
        lines.push(
          { type: 'info', text: '[Debloat] Disabling Windows Consumer Features (Cloud Content / Auto-Apps)...' },
          { type: 'success', text: 'Set HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\\DisableWindowsConsumerFeatures = 1' },
          { type: 'info', text: '[Debloat] Removing Windows Widgets and Bing Search integrations...' },
          { type: 'success', text: 'Removed AppxPackage: MicrosoftWindows.Client.WebExperience' }
        );
      }

      lines.push(
        { type: 'info', text: '[System Tweaks] Enabling Win32 Long Paths (filesystem limit bypass)...' },
        { type: 'success', text: 'Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\\LongPathsEnabled = 1' },
        { type: 'info', text: '[System Tweaks] Restoring classic Windows 10 context menu...' },
        { type: 'success', text: 'Registered HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' }
      );

      if (hasDev) {
        lines.push(
          { type: 'info', text: '[Dev Module] Enabling Windows Optional Feature: Microsoft-Windows-Subsystem-Linux...' },
          { type: 'info', text: '[Dev Module] Enabling Windows Optional Feature: Windows-Sandbox...' },
          { type: 'success', text: 'Optional features enabled. OpenSSH Client and Server configured.' }
        );
      }

      if (hasDualBoot) {
        lines.push(
          { type: 'info', text: '[DualBoot] Scanning physical disks for non-Windows (ext4/btrfs) partitions...' },
          { type: 'success', text: 'Found Linux Partition: Disk 1, Partition 2 (Type: Linux Filesystem, Size: 512GB)' },
          { type: 'info', text: '[DualBoot] Generating persistent helper script: C:\\Scripts\\Mount-Linux.ps1' },
          { type: 'success', text: 'Registered Scheduled Task: "Mount-Linux-WSL" at user logon.' }
        );
      }

      if (hasApps) {
        lines.push(
          { type: 'info', text: '[Software Provisioning] Checking Winget: Brave, 7-Zip, VLC, Discord, Obsidian...' },
          { type: 'info', text: 'Installing Brave.Brave via Winget silent switch...' },
          { type: 'success', text: 'Brave installed successfully (already latest).' },
          { type: 'info', text: 'Installing 7zip.7zip...' },
          { type: 'success', text: '7-Zip installed successfully.' },
          { type: 'info', text: 'Installing VideoLAN.VLC...' },
          { type: 'success', text: 'VLC installed successfully.' }
        );
      }

      if (hasNvidia) {
        lines.push(
          { type: 'info', text: '[Nvidia Scraper] Querying official NVIDIA portal for latest NVIDIA App...' },
          { type: 'success', text: 'Discovered latest URL: https://international.download.nvidia.com/.../NVIDIA_App_v11.0.exe' },
          { type: 'info', text: 'Downloading NVIDIA App to temporary staging folder...' },
          { type: 'success', text: 'Executed silent installer: NVIDIA_App.exe -s' }
        );
      }

      lines.push(
        { type: 'info', text: 'Cleaning up transient installer artifacts...' },
        { type: 'success', text: 'Log written: .\\InstallerLogs\\Deployment_20261021_151244.log' },
        { type: 'header', text: '=== Windows Provisioning Execution Finished Successfully! ===' }
      );

      return lines;
    }

    if (isRestic) {
      return [
        { type: 'cmd', text: cmd },
        { type: 'header', text: '=== Zero-Touch Restic Google Drive Backup Deployment ===' },
        { type: 'info', text: 'Checking required binaries: rclone and restic...' },
        { type: 'success', text: 'rclone found: v1.68.1, restic found: v0.17.1' },
        { type: 'info', text: 'Testing connection to Rclone remote: "gdrive"...' },
        { type: 'success', text: 'Google Drive backend reachable (Available space: 1.84 TB)' },
        { type: 'info', text: 'Initializing Restic encrypted repository at: rclone:gdrive:FedoraBackup...' },
        { type: 'success', text: 'Repository verified with Argon2id client-side encryption.' },
        { type: 'info', text: 'Calculating randomized backup delay (0 - 1800s) to prevent Google Drive rate limit throttling...' },
        { type: 'success', text: 'Assigned random host offset delay: 420 seconds' },
        { type: 'info', text: 'Registering systemd user service & timer: restic-gdrive-backup.timer...' },
        { type: 'success', text: 'Timer active: Next trigger at 03:07:00 UTC (Daily with 7d, 4w, 12m retention)' },
        { type: 'header', text: '=== Backup Infrastructure Deployed Successfully! ===' }
      ];
    }

    if (scriptId === 'profile-merge') {
      return [
        { type: 'cmd', text: cmd },
        { type: 'header', text: '=== ProfileMerge.ps1 — Cryptographic Deduplication Engine ===' },
        { type: 'info', text: 'Phase: -Plan (Deterministic Read-Only State Analysis)' },
        { type: 'info', text: 'Applying Destination Memory Shield to prevent accidental self-overwrite...' },
        { type: 'success', text: 'Memory shield active. Source and Destination volumes isolated.' },
        { type: 'info', text: 'Detaching .NET Reparse Points (safe traversal over OneDrive & Symlinks)...' },
        { type: 'info', text: 'Scanning source profile: D:\\Backup_2024\\ZSchmalz...' },
        { type: 'info', text: 'Cataloging 14,820 files; computing SHA-256 cryptographic hashes...' },
        { type: 'success', text: 'Detected 4,120 exact SHA-256 duplicate matches with target profile.' },
        { type: 'warn', text: 'Generated State Plan: C:\\Scripts\\ProfileMerge_Plan.csv (Read-only)' },
        { type: 'info', text: 'To commit merges: ProfileMerge.ps1 -Apply -AutoPruneDuplicates -StateFilePath C:\\Scripts\\ProfileMerge_Plan.csv' },
        { type: 'header', text: '=== Plan Complete: 14.8 GB can be safely reclaimed. ===' }
      ];
    }

    // Default generic
    return [
      { type: 'cmd', text: cmd },
      { type: 'info', text: `Executing ${scriptId}...` },
      { type: 'success', text: 'Permissions verified.' },
      { type: 'info', text: 'Task completed successfully.' },
      { type: 'header', text: '=== Process Finished (Exit 0) ===' }
    ];
  };

  const handleStartSimulation = () => {
    if (isRunning) return;
    setIsRunning(true);
    setIsPaused(false);
    setLogs([]);
    setProgress(0);
    setCompletedStats(null);

    const generatedLines = generateScriptLogs(selectedScriptId, customCommand);
    let currentIndex = 0;

    const tick = () => {
      if (currentIndex < generatedLines.length) {
        const item = generatedLines[currentIndex];
        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

        setLogs(prev => [
          ...prev,
          {
            id: currentIndex + 1,
            timestamp: timeStr,
            type: item.type,
            text: item.text
          }
        ]);

        currentIndex++;
        const pct = Math.round((currentIndex / generatedLines.length) * 100);
        setProgress(pct);

        const delay = playbackSpeed === 999 ? 10 : Math.max(30, 260 / playbackSpeed);
        simulationTimeoutRef.current = setTimeout(tick, delay);
      } else {
        setIsRunning(false);
        setCompletedStats({
          exitCode: 0,
          packagesProcessed: Math.floor(Math.random() * 15) + 12,
          securityRulesEnforced: 6,
          durationSeconds: Number((generatedLines.length * 0.28).toFixed(1))
        });
      }
    };

    tick();
  };

  const handleStop = () => {
    if (simulationTimeoutRef.current) {
      clearTimeout(simulationTimeoutRef.current);
    }
    setIsRunning(false);
    setIsPaused(false);
  };

  const handleReset = () => {
    handleStop();
    setLogs([]);
    setProgress(0);
    setCompletedStats(null);
  };

  const copyLogs = () => {
    const text = logs.map(l => `[${l.timestamp}] ${l.text}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedLog(true);
    setTimeout(() => setCopiedLog(false), 2000);
  };

  const downloadLogFile = () => {
    const text = logs.map(l => `[${l.timestamp}] ${l.text}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `InstallerLogs_Simulator_${new Date().toISOString().slice(0, 10)}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredLogs = logs.filter(l => {
    if (filterType === 'all') return true;
    if (filterType === 'info') return l.type === 'info';
    if (filterType === 'success') return l.type === 'success';
    if (filterType === 'warn') return l.type === 'warn';
    if (filterType === 'cmd') return l.type === 'cmd' || l.type === 'header';
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Simulator Control Header */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-md space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <TerminalIcon className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-slate-100">Interactive Terminal & Simulation Runner</h2>
              <p className="text-xs text-slate-400">Emulate script runs, idempotency checks, and inspect authentic log transcripts.</p>
            </div>
          </div>

          {/* Quick Script Selector */}
          <div className="flex items-center space-x-2 w-full sm:w-auto">
            <select
              value={selectedScriptId}
              onChange={(e) => {
                const id = e.target.value;
                setSelectedScriptId(id);
                if (id === 'linux-deployment-tool') {
                  setCustomCommand('sudo ./Linux-Deployment-Tool.sh --apps --gaming -d');
                } else if (id === 'windows-deployment-tool') {
                  setCustomCommand('powershell.exe -ExecutionPolicy Bypass -File .\\Windows-Deployment-Tool.ps1 -Standard');
                } else if (id === 'deploy-restic-gdrive-linux') {
                  setCustomCommand('./deploy-restic-gdrive.sh');
                } else if (id === 'deploy-restic-gdrive-win') {
                  setCustomCommand('.\\deploy-restic-gdrive.ps1');
                } else if (id === 'profile-merge') {
                  setCustomCommand('.\\ProfileMerge.ps1 -Plan -SourcePath "D:\\Backups\\User" -DestinationPath "C:\\Users\\ZSchmalz"');
                }
              }}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 w-full sm:w-64"
            >
              {SCRIPT_CATALOG.map(s => (
                <option key={s.id} value={s.id}>{s.name} ({s.os})</option>
              ))}
            </select>
          </div>
        </div>

        {/* Command Input Box */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-2 border-t border-slate-800/80">
          <div className="flex-1 flex items-center bg-slate-950 border border-slate-800 rounded-lg px-3 py-2">
            <span className="text-cyan-400 font-mono text-xs mr-2 font-bold select-none">
              {selectedScriptId.includes('windows') || selectedScriptId.includes('profile') ? 'PS >' : '$'}
            </span>
            <input
              type="text"
              value={customCommand}
              onChange={(e) => setCustomCommand(e.target.value)}
              className="w-full bg-transparent text-xs font-mono text-slate-200 focus:outline-none"
              placeholder="Enter command line flags..."
            />
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleStartSimulation}
              disabled={isRunning}
              className={`flex items-center space-x-1.5 px-4 py-2 rounded-lg text-xs font-semibold shadow-md transition-all ${
                isRunning
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/20'
              }`}
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isRunning ? 'Running...' : 'Run Simulation'}</span>
            </button>

            <button
              onClick={handleReset}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
              title="Reset Terminal"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Speed & Filter Controls */}
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs pt-1 text-slate-400">
          <div className="flex items-center space-x-3">
            <span className="text-slate-500">Speed:</span>
            {[
              { label: '1x', val: 1 },
              { label: '2x', val: 2 },
              { label: '5x', val: 5 },
              { label: 'Instant', val: 999 },
            ].map(s => (
              <button
                key={s.label}
                onClick={() => setPlaybackSpeed(s.val)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                  playbackSpeed === s.val
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>

          <div className="flex items-center space-x-2">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-slate-500">Filter:</span>
            {['all', 'info', 'success', 'warn', 'cmd'].map(f => (
              <button
                key={f}
                onClick={() => setFilterType(f)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase transition-colors ${
                  filterType === f
                    ? 'bg-slate-700 text-white'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={copyLogs}
              disabled={logs.length === 0}
              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition-colors disabled:opacity-50"
            >
              {copiedLog ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedLog ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={downloadLogFile}
              disabled={logs.length === 0}
              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition-colors disabled:opacity-50"
            >
              <Download className="w-3 h-3" />
              <span>Export .log</span>
            </button>
          </div>
        </div>
      </div>

      {/* Progress Bar */}
      {isRunning && (
        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden border border-slate-800">
          <div
            className="bg-gradient-to-r from-cyan-500 to-emerald-500 h-1.5 transition-all duration-200"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {/* Interactive Terminal Screen */}
      <div className="rounded-xl bg-[#090d16] border border-slate-800/80 shadow-2xl overflow-hidden font-mono text-xs">
        {/* Terminal Title Bar */}
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/90 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-rose-500/80" />
            <div className="w-3 h-3 rounded-full bg-amber-500/80" />
            <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
            <span className="ml-2 text-slate-400 text-[11px]">
              {selectedScriptId.includes('windows') || selectedScriptId.includes('profile') ? 'Administrator: Windows PowerShell' : 'root@fedora-workstation:~ (bash)'}
            </span>
          </div>

          <div className="flex items-center space-x-3 text-[11px] text-slate-500">
            <span>Encoding: UTF-8</span>
            <span>Lines: {filteredLogs.length}</span>
            {isRunning && (
              <span className="flex items-center space-x-1 text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span>STREAMING</span>
              </span>
            )}
          </div>
        </div>

        {/* Terminal Content Screen */}
        <div className="p-4 min-h-[380px] max-h-[520px] overflow-y-auto space-y-1.5">
          {logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-slate-600 space-y-3">
              <TerminalIcon className="w-10 h-10 stroke-[1.5]" />
              <p className="text-center max-w-sm">
                Ready to simulate execution. Select flags or customize the command above, then click <strong className="text-slate-400">"Run Simulation"</strong>.
              </p>
            </div>
          ) : (
            filteredLogs.map(log => {
              if (log.type === 'cmd') {
                return (
                  <div key={log.id} className="py-1 text-slate-300 font-semibold flex items-center space-x-2">
                    <span className="text-cyan-400">❯</span>
                    <span>{log.text}</span>
                  </div>
                );
              }
              if (log.type === 'header') {
                return (
                  <div key={log.id} className="py-2 text-cyan-300 font-bold border-y border-cyan-500/20 my-2">
                    {log.text}
                  </div>
                );
              }
              if (log.type === 'success') {
                return (
                  <div key={log.id} className="text-emerald-400 flex items-start space-x-2 leading-relaxed">
                    <span className="text-slate-600 select-none">[{log.timestamp}]</span>
                    <span>{log.text}</span>
                  </div>
                );
              }
              if (log.type === 'warn') {
                return (
                  <div key={log.id} className="text-amber-300 flex items-start space-x-2 leading-relaxed bg-amber-950/20 px-1 rounded">
                    <span className="text-slate-600 select-none">[{log.timestamp}]</span>
                    <span>{log.text}</span>
                  </div>
                );
              }
              if (log.type === 'error') {
                return (
                  <div key={log.id} className="text-rose-400 flex items-start space-x-2 leading-relaxed bg-rose-950/20 px-1 rounded">
                    <span className="text-slate-600 select-none">[{log.timestamp}]</span>
                    <span>{log.text}</span>
                  </div>
                );
              }
              return (
                <div key={log.id} className="text-slate-300 flex items-start space-x-2 leading-relaxed">
                  <span className="text-slate-600 select-none">[{log.timestamp}]</span>
                  <span>{log.text}</span>
                </div>
              );
            })
          )}
          <div ref={logsEndRef} />
        </div>
      </div>

      {/* Completed Metrics Summary Card */}
      {completedStats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs">
          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 text-[11px] block">Exit Status</span>
            <span className="font-mono font-bold text-emerald-400 text-sm flex items-center space-x-1.5 mt-0.5">
              <CheckCircle2 className="w-4 h-4" />
              <span>SUCCESS (Code {completedStats.exitCode})</span>
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 text-[11px] block">Packages Evaluated</span>
            <span className="font-mono font-bold text-cyan-300 text-sm mt-0.5 block">
              {completedStats.packagesProcessed} items
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 text-[11px] block">Security Postures Enforced</span>
            <span className="font-mono font-bold text-purple-300 text-sm flex items-center space-x-1 mt-0.5">
              <ShieldCheck className="w-4 h-4" />
              <span>{completedStats.securityRulesEnforced} policies</span>
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 text-[11px] block">Emulated Duration</span>
            <span className="font-mono font-bold text-slate-300 text-sm mt-0.5 block">
              {completedStats.durationSeconds}s
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
