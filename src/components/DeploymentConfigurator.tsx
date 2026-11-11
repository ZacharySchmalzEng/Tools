import React, { useState } from 'react';
import { 
  Play, Copy, Check, Download, AlertTriangle, Shield, CheckCircle2, 
  Terminal, Monitor, Sparkles, Layers, Sliders, Info, Server, Cpu
} from 'lucide-react';
import { WindowsDeploymentConfig, LinuxDeploymentConfig } from '../types';

interface DeploymentConfiguratorProps {
  onRunSimulation: (scriptId: string, command: string, flags: string[]) => void;
  onViewScript: (scriptId: string) => void;
}

export const DeploymentConfigurator: React.FC<DeploymentConfiguratorProps> = ({
  onRunSimulation,
  onViewScript
}) => {
  const [selectedOS, setSelectedOS] = useState<'windows' | 'linux'>('windows');
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [showDetailsModal, setShowDetailsModal] = useState(false);

  // Windows State
  const [winConfig, setWinConfig] = useState<WindowsDeploymentConfig>({
    profile: 'Standard',
    system: true,
    debloat: true,
    security: true,
    dev: false,
    dualBoot: false,
    apps: true,
    devApps: false,
    creators: false,
    cyber: false,
    maker: false,
    gaming: false,
    nvidia: false,
    autoUpdate: true,
    maintenance: true,
    uninstall: false,
  });

  // Linux State
  const [linuxConfig, setLinuxConfig] = useState<LinuxDeploymentConfig>({
    preset: 'baseline',
    distro: 'rpm',
    gpu: 'nvidia',
    desktopEnv: 'kde',
    all: true,
    update: true,
    apps: true,
    devapps: true,
    cyber: false,
    sysadmin: false,
    maker: false,
    creators: false,
    gaming: false,
    ssh: true,
    discord: false,
    harden: true,
    hardenAdvanced: false,
    twoFactor: false,
    autoYes: true,
    downloadOnly: false,
    unattended: false,
    debug: false,
  });

  // Windows Preset Handler
  const applyWinProfile = (profile: 'Standard' | 'Complete' | 'Light' | 'Custom') => {
    if (profile === 'Standard') {
      setWinConfig({
        profile: 'Standard',
        system: true,
        debloat: true,
        security: true,
        dev: false,
        dualBoot: false,
        apps: true,
        devApps: false,
        creators: false,
        cyber: false,
        maker: false,
        gaming: false,
        nvidia: false,
        autoUpdate: true,
        maintenance: true,
        uninstall: false,
      });
    } else if (profile === 'Complete') {
      setWinConfig({
        profile: 'Complete',
        system: true,
        debloat: true,
        security: true,
        dev: true,
        dualBoot: true,
        apps: true,
        devApps: true,
        creators: true,
        cyber: true,
        maker: true,
        gaming: true,
        nvidia: true,
        autoUpdate: true,
        maintenance: true,
        uninstall: false,
      });
    } else if (profile === 'Light') {
      setWinConfig({
        profile: 'Light',
        system: true,
        debloat: true,
        security: true,
        dev: false,
        dualBoot: false,
        apps: false,
        devApps: false,
        creators: false,
        cyber: false,
        maker: false,
        gaming: false,
        nvidia: false,
        autoUpdate: false,
        maintenance: false,
        uninstall: false,
      });
    } else {
      setWinConfig(prev => ({ ...prev, profile: 'Custom' }));
    }
  };

  // Linux Preset Handler
  const applyLinuxPreset = (preset: 'baseline' | 'strict' | 'gaming' | 'developer' | 'custom') => {
    if (preset === 'baseline') {
      setLinuxConfig(prev => ({
        ...prev,
        preset: 'baseline',
        all: true,
        update: true,
        apps: true,
        devapps: true,
        cyber: false,
        sysadmin: false,
        maker: false,
        creators: false,
        gaming: false,
        ssh: true,
        discord: false,
        harden: true,
        hardenAdvanced: false,
        twoFactor: false,
        downloadOnly: false,
      }));
    } else if (preset === 'strict') {
      setLinuxConfig(prev => ({
        ...prev,
        preset: 'strict',
        all: false,
        update: true,
        apps: true,
        devapps: true,
        cyber: true,
        sysadmin: false,
        maker: false,
        creators: false,
        gaming: false,
        ssh: true,
        discord: false,
        harden: false,
        hardenAdvanced: true,
        twoFactor: true,
        downloadOnly: false,
      }));
    } else if (preset === 'gaming') {
      setLinuxConfig(prev => ({
        ...prev,
        preset: 'gaming',
        all: false,
        update: true,
        apps: true,
        devapps: false,
        cyber: false,
        sysadmin: false,
        maker: false,
        creators: false,
        gaming: true,
        ssh: false,
        discord: true,
        harden: true,
        hardenAdvanced: false,
        twoFactor: false,
        downloadOnly: false,
      }));
    } else if (preset === 'developer') {
      setLinuxConfig(prev => ({
        ...prev,
        preset: 'developer',
        all: false,
        update: true,
        apps: true,
        devapps: true,
        cyber: true,
        sysadmin: false,
        maker: true,
        creators: true,
        gaming: false,
        ssh: true,
        discord: false,
        harden: true,
        hardenAdvanced: false,
        twoFactor: false,
        downloadOnly: false,
      }));
    } else {
      setLinuxConfig(prev => ({ ...prev, preset: 'custom' }));
    }
  };

  // Generate Windows Command
  const getWindowsCommandLine = () => {
    const flags: string[] = [];
    if (winConfig.profile === 'Standard' && !winConfig.uninstall) {
      return { cmd: 'powershell.exe -ExecutionPolicy Bypass -File .\\Windows-Deployment-Tool.ps1 -Standard', flags: ['-Standard'] };
    }
    if (winConfig.profile === 'Complete' && !winConfig.uninstall) {
      return { cmd: 'powershell.exe -ExecutionPolicy Bypass -File .\\Windows-Deployment-Tool.ps1 -Complete', flags: ['-Complete'] };
    }
    if (winConfig.profile === 'Light' && !winConfig.uninstall) {
      return { cmd: 'powershell.exe -ExecutionPolicy Bypass -File .\\Windows-Deployment-Tool.ps1 -Light', flags: ['-Light'] };
    }

    if (winConfig.system) flags.push('-System');
    if (winConfig.debloat) flags.push('-Debloat');
    if (winConfig.security) flags.push('-Security');
    if (winConfig.dev) flags.push('-Dev');
    if (winConfig.dualBoot) flags.push('-DualBoot');
    if (winConfig.apps) flags.push('-Apps');
    if (winConfig.devApps) flags.push('-DevApps');
    if (winConfig.creators) flags.push('-Creators');
    if (winConfig.cyber) flags.push('-Cyber');
    if (winConfig.maker) flags.push('-Maker');
    if (winConfig.gaming) flags.push('-Gaming');
    if (winConfig.nvidia) flags.push('-Nvidia');
    if (winConfig.autoUpdate) flags.push('-AutoUpdate');
    if (winConfig.maintenance) flags.push('-Maintenance');
    if (winConfig.uninstall) flags.push('-Uninstall');

    const flagStr = flags.length > 0 ? ' ' + flags.join(' ') : '';
    return {
      cmd: `powershell.exe -ExecutionPolicy Bypass -File .\\Windows-Deployment-Tool.ps1${flagStr}`,
      flags: flags.length > 0 ? flags : ['-Help']
    };
  };

  // Generate Linux Command
  const getLinuxCommandLine = () => {
    const flags: string[] = [];

    if (linuxConfig.all) {
      flags.push('--all');
    } else {
      if (linuxConfig.update) flags.push('--update');
      if (linuxConfig.apps) flags.push('--apps');
      if (linuxConfig.devapps) flags.push('--devapps');
      if (linuxConfig.cyber) flags.push('--cyber');
      if (linuxConfig.sysadmin) flags.push('--sysadmin');
      if (linuxConfig.maker) flags.push('--maker');
      if (linuxConfig.creators) flags.push('--creators');
      if (linuxConfig.gaming) flags.push('--gaming');
      if (linuxConfig.ssh) flags.push('--ssh');
      if (linuxConfig.discord) flags.push('--discord');
    }

    // Distro Manual Target (Auto-detected if standard)
    if (linuxConfig.distro === 'nobara') flags.push('--distro=nobara');
    else if (linuxConfig.distro === 'atomic') flags.push('--atomic');
    else if (linuxConfig.distro === 'arch') flags.push('--arch');
    else if (linuxConfig.distro === 'steamos') flags.push('--steamos');
    else if (linuxConfig.distro === 'opensuse') flags.push('--opensuse');
    else if (linuxConfig.distro === 'deb') flags.push('--distro=deb');

    // Desktop Environment Target
    if (linuxConfig.desktopEnv === 'cosmic') flags.push('--cosmic');
    else if (linuxConfig.desktopEnv === 'xfce') flags.push('--xfce');
    else if (linuxConfig.desktopEnv === 'cinnamon') flags.push('--cinnamon');
    else if (linuxConfig.desktopEnv === 'gnome') flags.push('--gnome');
    else if (linuxConfig.desktopEnv === 'kde') flags.push('--kde');

    // Security
    if (linuxConfig.hardenAdvanced) {
      flags.push('--harden-advanced');
    } else if (linuxConfig.harden && !linuxConfig.all) {
      flags.push('--harden');
    }

    if (linuxConfig.twoFactor) flags.push('--2fa');

    // Modifiers
    if (linuxConfig.downloadOnly) flags.push('-d');
    if (linuxConfig.autoYes && !linuxConfig.unattended) flags.push('-y');
    if (linuxConfig.unattended) flags.push('--unattended');
    if (linuxConfig.debug) flags.push('--debug');

    const flagStr = flags.length > 0 ? ' ' + flags.join(' ') : '';
    return {
      cmd: `sudo ./Linux-Deployment-Tool.sh${flagStr}`,
      flags: flags.length > 0 ? flags : ['--help']
    };
  };

  const currentCommand = selectedOS === 'windows' ? getWindowsCommandLine() : getLinuxCommandLine();

  const copyCommand = () => {
    navigator.clipboard.writeText(currentCommand.cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const handleExecuteSimulation = () => {
    const scriptId = selectedOS === 'windows' ? 'windows-deployment-tool' : 'linux-deployment-tool';
    onRunSimulation(scriptId, currentCommand.cmd, currentCommand.flags);
  };

  return (
    <div className="space-y-6">
      {/* OS Mode Switcher Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Sliders className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-100">Visual Deployment Configurator</h2>
            <p className="text-xs text-slate-400">Select modules, hardening tiers, and flags to generate idempotent commands.</p>
          </div>
        </div>

        {/* OS Toggle */}
        <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setSelectedOS('windows')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs sm:text-sm font-medium transition-all ${
              selectedOS === 'windows'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Monitor className="w-4 h-4" />
            <span>Windows 11 / Server</span>
          </button>
          <button
            onClick={() => setSelectedOS('linux')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs sm:text-sm font-medium transition-all ${
              selectedOS === 'linux'
                ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Linux (Fedora & Debian)</span>
          </button>
        </div>
      </div>

      {/* WINDOWS CONFIGURATOR */}
      {selectedOS === 'windows' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Controls (2 cols) */}
          <div className="lg:col-span-2 space-y-6">
            {/* Profile Presets */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                  <span>Deployment Profile Presets</span>
                </span>
                <span className="text-xs text-slate-500 font-mono">Windows-Deployment-Tool.ps1 v2.0</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                {[
                  { id: 'Standard', label: '-Standard', desc: 'Universal Baseline (Daily Driver)', color: 'border-blue-500/40 bg-blue-500/10 text-blue-300' },
                  { id: 'Complete', label: '-Complete', desc: 'Heavy Workstation (All Stacks)', color: 'border-purple-500/40 bg-purple-500/10 text-purple-300' },
                  { id: 'Light', label: '-Light', desc: 'Minimal (No App Installs)', color: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300' },
                  { id: 'Custom', label: 'Custom', desc: 'Granular Flag Selection', color: 'border-amber-500/40 bg-amber-500/10 text-amber-300' },
                ].map(p => (
                  <button
                    key={p.id}
                    onClick={() => applyWinProfile(p.id as any)}
                    className={`p-3 rounded-lg text-left border transition-all ${
                      winConfig.profile === p.id
                        ? `${p.color} ring-1 ring-blue-500`
                        : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="font-mono text-sm font-semibold">{p.label}</div>
                    <div className="text-[11px] text-slate-500 mt-1 leading-snug">{p.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Core OS & System Options */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                <span>Core OS & System Options</span>
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {[
                  {
                    key: 'system',
                    flag: '-System',
                    name: 'System & Explorer Tweaks',
                    desc: 'Classic Win10 context menu, Win32 Long Paths, Explorer show hidden/ext, Ultimate Performance power plan, disable telemetry prompts.'
                  },
                  {
                    key: 'debloat',
                    flag: '-Debloat',
                    name: 'OS Debloat & Clean Up',
                    desc: 'Disables Windows Consumer Features (Candy Crush), uninstalls Windows Widgets, removes base Microsoft Appx bloat.'
                  },
                  {
                    key: 'security',
                    flag: '-Security',
                    name: 'Security & Telemetry Hardening',
                    desc: 'Group Policy telemetry disable, Windows Defender PUA (Potentially Unwanted App) protection, installs PSWindowsUpdate.'
                  },
                  {
                    key: 'dev',
                    flag: '-Dev',
                    name: 'Developer Platform Features',
                    desc: 'Enables WSL (Windows Subsystem for Linux), Windows Sandbox, and native OpenSSH Client & Server.'
                  },
                  {
                    key: 'dualBoot',
                    flag: '-DualBoot',
                    name: 'Dual-Boot WSL Partition Mount',
                    desc: 'Auto-discovers Linux ext4/btrfs partitions, generates C:\\Scripts\\Mount-Linux.ps1, registers scheduled task to mount in Explorer.'
                  },
                  {
                    key: 'uninstall',
                    flag: '-Uninstall',
                    name: 'Reversal / Teardown Mode',
                    desc: 'Reverts previously applied changes and uninstalls applications matching selected deployment modules.',
                    badge: 'Rollback'
                  }
                ].map(opt => {
                  const isChecked = (winConfig as any)[opt.key];
                  return (
                    <label
                      key={opt.key}
                      className={`flex items-start space-x-3 p-3 rounded-lg border cursor-pointer transition-all ${
                        isChecked
                          ? opt.key === 'uninstall'
                            ? 'bg-rose-950/20 border-rose-700/60 text-rose-200'
                            : 'bg-blue-950/20 border-blue-600/50 text-slate-200'
                          : 'bg-slate-950/40 border-slate-800/80 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => {
                          setWinConfig(prev => ({
                            ...prev,
                            profile: 'Custom',
                            [opt.key]: e.target.checked
                          }));
                        }}
                        className="mt-1 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
                      />
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-xs font-semibold text-cyan-400">{opt.flag}</span>
                          <span className="text-xs font-medium text-slate-200">{opt.name}</span>
                          {opt.badge && (
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-900/60 text-rose-300 font-mono">
                              {opt.badge}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed">{opt.desc}</p>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Software Provisioning Stacks */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                <Monitor className="w-3.5 h-3.5 text-blue-400" />
                <span>Software Provisioning Stacks (Winget & Scrapers)</span>
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {[
                  {
                    key: 'apps',
                    flag: '-Apps',
                    name: 'General Software Suite',
                    apps: 'Brave, Chrome, Firefox, Opera, 7-Zip, VLC, Discord, Obsidian, Signal, WhatsApp, CrystalDiskInfo, PowerToys, Everything, Terminal, Rufus, TreeSize/WinDirStat'
                  },
                  {
                    key: 'devApps',
                    flag: '-DevApps',
                    name: 'Developer Toolchain',
                    apps: 'VS Code, Python 3.13, GitHub Desktop, Notepad++, PuTTY, PowerShell 7, OpenSSL (FireDaemon)'
                  },
                  {
                    key: 'creators',
                    flag: '-Creators',
                    name: 'Creative & Media Suite',
                    apps: 'darktable (Photo), Blender (3D), HandBrake (Video), Audacity (Audio), Inkscape (Vector)'
                  },
                  {
                    key: 'cyber',
                    flag: '-Cyber',
                    name: 'Cybersecurity & Packet Analysis',
                    apps: 'Wireshark, Nmap, Advanced IP Scanner'
                  },
                  {
                    key: 'maker',
                    flag: '-Maker',
                    name: '3D Printing & CAD Slicers',
                    apps: 'PrusaSlicer, OrcaSlicer, Bambu Studio, Autodesk Fusion 360'
                  },
                  {
                    key: 'gaming',
                    flag: '-Gaming',
                    name: 'Gaming Platforms',
                    apps: 'Steam, OBS Studio, Blizzard Battle.net (Silent Install Bypass)'
                  },
                  {
                    key: 'nvidia',
                    flag: '-Nvidia',
                    name: 'NVIDIA App (Dynamic Scraper)',
                    apps: 'Scrapes official NVIDIA site to download & silently install latest NVIDIA App directly'
                  },
                  {
                    key: 'autoUpdate',
                    flag: '-AutoUpdate',
                    name: 'Automated Update Task',
                    apps: 'Weekly SYSTEM-context task for silent Winget upgrades & Windows Update orchestration'
                  },
                  {
                    key: 'maintenance',
                    flag: '-Maintenance',
                    name: 'Automated Maintenance Task',
                    apps: 'Weekly task: TRIM, DNS flush, Chkdsk, SFC / DISM repair, and temporary-file purge'
                  }
                ].map(item => {
                  const isChecked = (winConfig as any)[item.key];
                  return (
                    <label
                      key={item.key}
                      className={`flex items-start space-x-3 p-3 rounded-lg border cursor-pointer transition-all ${
                        isChecked
                          ? 'bg-blue-950/20 border-blue-600/50 text-slate-200'
                          : 'bg-slate-950/40 border-slate-800/80 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => {
                          setWinConfig(prev => ({
                            ...prev,
                            profile: 'Custom',
                            [item.key]: e.target.checked
                          }));
                        }}
                        className="mt-1 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
                      />
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-xs font-semibold text-cyan-400">{item.flag}</span>
                          <span className="text-xs font-medium text-slate-200">{item.name}</span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-snug">{item.apps}</p>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Windows Side Panel (Command generator & Architecture details) */}
          <div className="space-y-6">
            {/* Generated Command Card */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <span>Execution Command</span>
                </span>
                <span className="text-[11px] text-slate-500 font-mono">Admin PowerShell</span>
              </div>

              <div className="relative group">
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 break-all leading-relaxed">
                  {currentCommand.cmd}
                </div>
              </div>

              <div className="flex flex-col gap-2 pt-2">
                <button
                  onClick={copyCommand}
                  className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md shadow-cyan-600/20 transition-all"
                >
                  {copiedCmd ? <Check className="w-4 h-4 text-white" /> : <Copy className="w-4 h-4" />}
                  <span>{copiedCmd ? 'Command Copied to Clipboard!' : 'Copy PowerShell Command'}</span>
                </button>

                <button
                  onClick={handleExecuteSimulation}
                  className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 border border-slate-700 font-medium text-xs transition-all"
                >
                  <Play className="w-4 h-4" />
                  <span>Test in Terminal Simulator</span>
                </button>
              </div>

              <div className="pt-3 border-t border-slate-800/80 space-y-2 text-xs text-slate-400">
                <div className="flex items-center space-x-2 text-amber-400">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <span className="font-semibold text-[11px]">Must execute in Administrator terminal</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Invokes with <code className="text-cyan-300 font-mono">-ExecutionPolicy Bypass</code>. Safe to run repeatedly due to Winget memory snapshotting and registry diffing.
                </p>
              </div>
            </div>

            {/* Quick Actions & Script Info */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Info className="w-3.5 h-3.5 text-blue-400" />
                <span>Script Architecture & Guardrails</span>
              </h4>

              <ul className="space-y-2 text-xs text-slate-400">
                <li className="flex items-start space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span><strong>Idempotent:</strong> Takes a Winget memory snapshot before applying any package commands.</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span><strong>Server OS Aware:</strong> Automatically swaps consumer utilities (TreeSize → WinDirStat) on Windows Server.</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span><strong>Log Rotation:</strong> Retains 10 most recent logs in <code className="text-cyan-300 font-mono">InstallerLogs/</code>.</span>
                </li>
              </ul>

              <div className="pt-3 border-t border-slate-800 flex justify-between items-center">
                <button
                  onClick={() => onViewScript('windows-deployment-tool')}
                  className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono"
                >
                  Inspect Full Source Code →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* LINUX CONFIGURATOR */}
      {selectedOS === 'linux' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Controls (2 cols) */}
          <div className="lg:col-span-2 space-y-6">
            {/* Distro, GPU & Desktop Environment Selector */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                <Server className="w-3.5 h-3.5 text-emerald-400" />
                <span>Environment Target & Hardware Auto-Selection</span>
              </span>

              <div className="space-y-3">
                {/* Distro Family */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-[11px] text-slate-400 font-medium">Distro Family Engine (Auto-Detected by Default)</label>
                    <span className="text-[10px] text-emerald-400 font-mono">v2.0 Multi-Distro Engine</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-1.5">
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, distro: 'rpm' }))}
                      className={`p-2 rounded-lg text-[11px] font-medium border text-center transition-all ${
                        linuxConfig.distro === 'rpm'
                          ? 'bg-blue-600/20 border-blue-500 text-blue-300 font-semibold'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      Fedora / RHEL
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, distro: 'nobara' }))}
                      className={`p-2 rounded-lg text-[11px] font-medium border text-center transition-all ${
                        linuxConfig.distro === 'nobara'
                          ? 'bg-purple-600/20 border-purple-500 text-purple-300 font-semibold ring-1 ring-purple-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      Nobara
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, distro: 'atomic' }))}
                      className={`p-2 rounded-lg text-[11px] font-medium border text-center transition-all ${
                        linuxConfig.distro === 'atomic'
                          ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300 font-semibold ring-1 ring-indigo-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      Atomic / Bazzite
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, distro: 'arch' }))}
                      className={`p-2 rounded-lg text-[11px] font-medium border text-center transition-all ${
                        linuxConfig.distro === 'arch'
                          ? 'bg-cyan-600/20 border-cyan-500 text-cyan-300 font-semibold ring-1 ring-cyan-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      Arch Linux
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, distro: 'steamos' }))}
                      className={`p-2 rounded-lg text-[11px] font-medium border text-center transition-all ${
                        linuxConfig.distro === 'steamos'
                          ? 'bg-amber-600/20 border-amber-500 text-amber-300 font-semibold ring-1 ring-amber-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      SteamOS
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, distro: 'opensuse' }))}
                      className={`p-2 rounded-lg text-[11px] font-medium border text-center transition-all ${
                        linuxConfig.distro === 'opensuse'
                          ? 'bg-emerald-600/20 border-emerald-500 text-emerald-300 font-semibold ring-1 ring-emerald-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      openSUSE
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, distro: 'deb' }))}
                      className={`p-2 rounded-lg text-[11px] font-medium border text-center transition-all ${
                        linuxConfig.distro === 'deb'
                          ? 'bg-rose-600/20 border-rose-500 text-rose-300 font-semibold'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      Debian / Ubuntu
                    </button>
                  </div>

                  {/* Contextual Distribution Safeguard Notices */}
                  {linuxConfig.distro === 'nobara' && (
                    <div className="text-[11px] text-purple-300 bg-purple-950/40 border border-purple-800/60 rounded px-2.5 py-1.5">
                      🎮 <strong>Nobara Safeguard Active:</strong> Uses pre-packaged <code>dkms-nvidia</code> from <code>nobara-nvidia-production</code>. Conflicting RPM Fusion <code>akmod-nvidia</code> is safely skipped.
                    </div>
                  )}
                  {linuxConfig.distro === 'atomic' && (
                    <div className="text-[11px] text-indigo-300 bg-indigo-950/40 border border-indigo-800/60 rounded px-2.5 py-1.5">
                      📦 <strong>Fedora Atomic / Bazzite Engine:</strong> Employs <code>rpm-ostree install --idempotent</code> with Flatpak-first containment and scheduled reboot notifications.
                    </div>
                  )}
                  {linuxConfig.distro === 'steamos' && (
                    <div className="text-[11px] text-amber-300 bg-amber-950/40 border border-amber-800/60 rounded px-2.5 py-1.5">
                      🕹️ <strong>SteamOS Lifecycle Engine:</strong> Unlocks root with <code>steamos-readonly disable</code>, initializes pacman keys, and guarantees re-locking via signal traps.
                    </div>
                  )}
                  {linuxConfig.distro === 'opensuse' && (
                    <div className="text-[11px] text-emerald-300 bg-emerald-950/40 border border-emerald-800/60 rounded px-2.5 py-1.5">
                      🦎 <strong>openSUSE Engine:</strong> Manages packages via <code>zypper</code>, wires Packman Essentials repository, and enforces AppArmor profile parity.
                    </div>
                  )}
                  {linuxConfig.distro === 'arch' && (
                    <div className="text-[11px] text-cyan-300 bg-cyan-950/40 border border-cyan-800/60 rounded px-2.5 py-1.5">
                      🏹 <strong>Arch Linux Engine:</strong> Utilizes <code>pacman -S --needed</code> with multilib repository verification for 32-bit gaming runtimes.
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">

                {/* GPU Stack */}
                <div className="space-y-1.5">
                  <label className="text-[11px] text-slate-400 font-medium">GPU Hardware Stack</label>
                  <div className="grid grid-cols-2 gap-1.5">
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, gpu: 'nvidia' }))}
                      className={`p-2 rounded-lg text-xs font-medium border text-center transition-all ${
                        linuxConfig.gpu === 'nvidia'
                          ? 'bg-emerald-600/20 border-emerald-500 text-emerald-300 font-semibold'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      NVIDIA (akmod)
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, gpu: 'amd' }))}
                      className={`p-2 rounded-lg text-xs font-medium border text-center transition-all ${
                        linuxConfig.gpu === 'amd'
                          ? 'bg-red-600/20 border-red-500 text-red-300 font-semibold'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      AMD (Mesa Vulkan)
                    </button>
                  </div>
                </div>

                {/* Desktop Environment */}
                <div className="space-y-1.5 sm:col-span-2">
                  <div className="flex items-center justify-between">
                    <label className="text-[11px] text-slate-400 font-medium">Desktop Environment Profile</label>
                    <span className="text-[10px] text-cyan-400 font-mono">QoL Tools & Tailored Config</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-1.5">
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, desktopEnv: 'kde' }))}
                      className={`p-2 rounded-lg text-xs font-medium border text-center transition-all ${
                        linuxConfig.desktopEnv === 'kde'
                          ? 'bg-cyan-600/20 border-cyan-500 text-cyan-300 font-semibold ring-1 ring-cyan-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      KDE Plasma
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, desktopEnv: 'gnome' }))}
                      className={`p-2 rounded-lg text-xs font-medium border text-center transition-all ${
                        linuxConfig.desktopEnv === 'gnome'
                          ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300 font-semibold ring-1 ring-indigo-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      GNOME
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, desktopEnv: 'cosmic' }))}
                      className={`p-2 rounded-lg text-xs font-medium border text-center transition-all ${
                        linuxConfig.desktopEnv === 'cosmic'
                          ? 'bg-purple-600/20 border-purple-500 text-purple-300 font-semibold ring-1 ring-purple-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      COSMIC (Rust)
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, desktopEnv: 'xfce' }))}
                      className={`p-2 rounded-lg text-xs font-medium border text-center transition-all ${
                        linuxConfig.desktopEnv === 'xfce'
                          ? 'bg-amber-600/20 border-amber-500 text-amber-300 font-semibold ring-1 ring-amber-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      XFCE
                    </button>
                    <button
                      onClick={() => setLinuxConfig(prev => ({ ...prev, desktopEnv: 'cinnamon' }))}
                      className={`p-2 rounded-lg text-xs font-medium border text-center transition-all ${
                        linuxConfig.desktopEnv === 'cinnamon'
                          ? 'bg-emerald-600/20 border-emerald-500 text-emerald-300 font-semibold ring-1 ring-emerald-500/50'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      Cinnamon
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

            {/* Presets */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                <span>Linux Deployment Presets</span>
              </span>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                {[
                  { id: 'baseline', label: '--all', desc: 'Universal Baseline (Safe Standard)', color: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' },
                  { id: 'strict', label: 'Strict Posture', desc: 'Auditd, ICMP Drop, 2FA, No SSH Passwords', color: 'border-rose-500/40 bg-rose-500/10 text-rose-300' },
                  { id: 'gaming', label: 'Gaming Rig', desc: 'GPU Drivers, Steam, Lutris, Bottles', color: 'border-purple-500/40 bg-purple-500/10 text-purple-300' },
                  { id: 'developer', label: 'Dev & Cyber', desc: 'VS Code, Wireshark, Nmap, Python', color: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300' },
                ].map(p => (
                  <button
                    key={p.id}
                    onClick={() => applyLinuxPreset(p.id as any)}
                    className={`p-3 rounded-lg text-left border transition-all ${
                      linuxConfig.preset === p.id
                        ? `${p.color} ring-1 ring-emerald-500`
                        : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="font-mono text-sm font-semibold">{p.label}</div>
                    <div className="text-[11px] text-slate-500 mt-1 leading-snug">{p.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Security & Hardening Tiers */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                  <Shield className="w-3.5 h-3.5 text-amber-400" />
                  <span>Tiered Security Hardening</span>
                </h3>
                <span className="text-[11px] text-amber-400 font-mono">Zero-Trust Postures</span>
              </div>

              {linuxConfig.hardenAdvanced && (
                <div className="p-3.5 rounded-lg bg-rose-950/30 border border-rose-800/80 text-xs text-rose-300 space-y-1">
                  <div className="font-semibold flex items-center space-x-1.5 text-rose-400">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                    <span>CRITICAL WARNING: --harden-advanced disables SSH Password Authentication!</span>
                  </div>
                  <p className="text-[11px] text-rose-300/90">
                    You <strong>MUST</strong> have an active SSH public key (<code className="font-mono bg-rose-900/60 px-1 py-0.5 rounded">id_rsa.pub</code> or <code className="font-mono bg-rose-900/60 px-1 py-0.5 rounded">id_ed25519.pub</code>) copied to <code className="font-mono bg-rose-900/60 px-1 py-0.5 rounded">~/.ssh/authorized_keys</code> before closing terminal, or you will be locked out!
                  </p>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <label className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  linuxConfig.harden && !linuxConfig.hardenAdvanced
                    ? 'bg-emerald-950/20 border-emerald-600/50 text-slate-200'
                    : 'bg-slate-950/40 border-slate-800 text-slate-400'
                }`}>
                  <input
                    type="checkbox"
                    checked={linuxConfig.harden && !linuxConfig.hardenAdvanced}
                    disabled={linuxConfig.hardenAdvanced}
                    onChange={(e) => {
                      setLinuxConfig(prev => ({
                        ...prev,
                        preset: 'custom',
                        harden: e.target.checked
                      }));
                    }}
                    className="mr-2 rounded bg-slate-900 border-slate-700 text-emerald-600"
                  />
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-emerald-400">--harden</span>
                    <span className="text-[10px] bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 px-1.5 py-0.5 rounded font-mono">CVE-2024-6387</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">Safe Baseline: SELinux/AppArmor verification, OpenSSH regreSSHion mitigation (LoginGraceTime 20s), and disables direct root SSH login.</p>
                </label>

                <label className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  linuxConfig.hardenAdvanced
                    ? 'bg-rose-950/30 border-rose-600/60 text-rose-200'
                    : 'bg-slate-950/40 border-slate-800 text-slate-400'
                }`}>
                  <input
                    type="checkbox"
                    checked={linuxConfig.hardenAdvanced}
                    onChange={(e) => {
                      setLinuxConfig(prev => ({
                        ...prev,
                        preset: 'custom',
                        hardenAdvanced: e.target.checked,
                        harden: !e.target.checked
                      }));
                    }}
                    className="mr-2 rounded bg-slate-900 border-slate-700 text-rose-600"
                  />
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-rose-400">--harden-advanced</span>
                    <span className="text-[10px] bg-rose-500/10 text-rose-300 border border-rose-500/20 px-1.5 py-0.5 rounded font-mono">CIS Level 2</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">Strict SecOps Posture: High-fidelity auditd rules, kernel sysctl drops (martians, redirects, suid_dumpable = 0), and disables SSH passwords.</p>
                </label>

                <label className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  linuxConfig.twoFactor
                    ? 'bg-cyan-950/20 border-cyan-600/50 text-slate-200'
                    : 'bg-slate-950/40 border-slate-800 text-slate-400'
                }`}>
                  <input
                    type="checkbox"
                    checked={linuxConfig.twoFactor}
                    onChange={(e) => {
                      setLinuxConfig(prev => ({
                        ...prev,
                        preset: 'custom',
                        twoFactor: e.target.checked,
                        ssh: true // 2fa requires ssh
                      }));
                    }}
                    className="mr-2 rounded bg-slate-900 border-slate-700 text-cyan-600"
                  />
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-cyan-400">--2fa</span>
                    <span className="text-[10px] bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 px-1.5 py-0.5 rounded font-mono">PAM MFA nullok</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">MFA SSH: Enforces Google Authenticator PAM with transitional safe-staging to prevent admin lockout prior to OTP token generation.</p>
                </label>
              </div>
            </div>

            {/* Application & Stack Modules */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Modules & Application Stacks</span>
                </h3>

                <label className="flex items-center space-x-2 text-xs text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={linuxConfig.all}
                    onChange={(e) => {
                      setLinuxConfig(prev => ({
                        ...prev,
                        all: e.target.checked,
                        preset: e.target.checked ? 'baseline' : 'custom'
                      }));
                    }}
                    className="rounded bg-slate-900 border-slate-700 text-emerald-600"
                  />
                  <span className="font-mono font-semibold text-emerald-400">--all (Run Standard Baseline)</span>
                </label>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {[
                  { key: 'update', flag: '--update', name: 'Sequential Package Update', desc: 'Updates DNF/APT, Flatpak runtimes, and Snap packages sequentially.' },
                  { key: 'apps', flag: '--apps', name: 'System Utilities & Browsers', desc: 'Brave, Chrome, Obsidian, Signal, Timeshift, btop, eza, plocate, VLC, 7zip.' },
                  { key: 'devapps', flag: '--devapps', name: 'Developer Toolchain', desc: 'Git, jq, fzf, tealdeer, rsync, Python 3, OpenSSL, VS Code, and PowerShell.' },
                  { key: 'cyber', flag: '--cyber', name: 'Cybersecurity & Packet Analysis', desc: 'Wireshark (adds user to wireshark group), Nmap, TCPDump, and Ncat.' },
                  { key: 'sysadmin', flag: '--sysadmin', name: 'System Administration', desc: 'Remmina, tmux, DNS/network diagnostics, disk observability, and process tracing.' },
                  { key: 'maker', flag: '--maker', name: '3D Printing & CAD Slicers', desc: 'PrusaSlicer, OrcaSlicer, and Bambu Studio.' },
                  { key: 'creators', flag: '--creators', name: 'Creative Production Stack', desc: 'GIMP, Krita, Blender, Audacity, Inkscape, and OBS Studio.' },
                  { key: 'gaming', flag: '--gaming', name: 'Gaming Runtimes & Drivers', desc: 'Steam, Lutris, GameMode, MangoHud, and auto-detected GPU drivers.' },
                  { key: 'ssh', flag: '--ssh', name: 'OpenSSH Daemon Provisioning', desc: 'Installs, starts, and validates the OpenSSH systemd service with socket tests.' },
                  { key: 'discord', flag: '--discord', name: 'Native Discord Transition', desc: 'Silently removes Flatpak Discord and installs native RPM / DEB package.' },
                ].map(item => {
                  const isChecked = linuxConfig.all || (linuxConfig as any)[item.key];
                  return (
                    <label
                      key={item.key}
                      className={`flex items-start space-x-3 p-3 rounded-lg border cursor-pointer transition-all ${
                        isChecked
                          ? 'bg-emerald-950/20 border-emerald-600/50 text-slate-200'
                          : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        disabled={linuxConfig.all}
                        onChange={(e) => {
                          setLinuxConfig(prev => ({
                            ...prev,
                            preset: 'custom',
                            [item.key]: e.target.checked
                          }));
                        }}
                        className="mt-1 rounded bg-slate-900 border-slate-700 text-emerald-600"
                      />
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-xs font-semibold text-emerald-400">{item.flag}</span>
                          <span className="text-xs font-medium text-slate-200">{item.name}</span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-snug">{item.desc}</p>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Global Modifiers */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center gap-4 text-xs">
              <span className="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">Modifiers:</span>
              
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={linuxConfig.autoYes}
                  onChange={(e) => setLinuxConfig(prev => ({ ...prev, autoYes: e.target.checked }))}
                  className="rounded bg-slate-900 border-slate-700 text-emerald-600"
                />
                <span className="font-mono text-slate-300">-y (Auto Yes)</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={linuxConfig.downloadOnly}
                  onChange={(e) => setLinuxConfig(prev => ({ ...prev, downloadOnly: e.target.checked }))}
                  className="rounded bg-slate-900 border-slate-700 text-cyan-600"
                />
                <span className="font-mono text-cyan-400">-d (Dry-Run / Download Only)</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={linuxConfig.unattended}
                  onChange={(e) => setLinuxConfig(prev => ({ ...prev, unattended: e.target.checked }))}
                  className="rounded bg-slate-900 border-slate-700 text-purple-600"
                />
                <span className="font-mono text-purple-400">--unattended (Bypass Prompts)</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={linuxConfig.debug}
                  onChange={(e) => setLinuxConfig(prev => ({ ...prev, debug: e.target.checked }))}
                  className="rounded bg-slate-900 border-slate-700 text-amber-600"
                />
                <span className="font-mono text-amber-400">--debug (Trace set -x)</span>
              </label>
            </div>
          </div>

          {/* Linux Side Panel */}
          <div className="space-y-6">
            {/* Generated Command Card */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <span>Linux Command Line</span>
                </span>
                <span className="text-[11px] text-slate-500 font-mono">root / sudo</span>
              </div>

              <div className="relative group">
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 break-all leading-relaxed">
                  {currentCommand.cmd}
                </div>
              </div>

              <div className="flex flex-col gap-2 pt-2">
                <button
                  onClick={copyCommand}
                  className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs shadow-md shadow-emerald-600/20 transition-all"
                >
                  {copiedCmd ? <Check className="w-4 h-4 text-white" /> : <Copy className="w-4 h-4" />}
                  <span>{copiedCmd ? 'Command Copied!' : 'Copy Bash Command'}</span>
                </button>

                <button
                  onClick={handleExecuteSimulation}
                  className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-emerald-400 hover:text-emerald-300 border border-slate-700 font-medium text-xs transition-all"
                >
                  <Play className="w-4 h-4" />
                  <span>Test in Terminal Simulator</span>
                </button>
              </div>

              <div className="pt-3 border-t border-slate-800/80 space-y-2 text-xs text-slate-400">
                <div className="flex items-center space-x-2 text-emerald-400">
                  <Shield className="w-4 h-4 flex-shrink-0" />
                  <span className="font-semibold text-[11px]">Strict Mode: set -euo pipefail</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Fails fast on any pipeline error to avoid leaving the system in an indeterminate state.
                </p>
              </div>
            </div>

            {/* Linux Architecture Specs */}
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Info className="w-3.5 h-3.5 text-emerald-400" />
                <span>Distro-Aware Capabilities</span>
              </h4>

              <ul className="space-y-2 text-xs text-slate-400">
                <li className="flex items-start space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span><strong>Cross-Distro Parity:</strong> Supports Fedora, RHEL, CentOS, Rocky, Alma, Debian, Ubuntu, Mint, and Pop!_OS.</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span><strong>Driver Auto-Detection:</strong> Auto-probes PCI vendor IDs for NVIDIA vs AMD and sets up RPM Fusion or official repos.</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span><strong>Dry-Run Mode (-d):</strong> Download-only parameter enables resolving dependencies without mutating system state.</span>
                </li>
              </ul>

              <div className="pt-3 border-t border-slate-800 flex justify-between items-center">
                <button
                  onClick={() => onViewScript('linux-deployment-tool')}
                  className="text-xs text-emerald-400 hover:text-emerald-300 underline font-mono"
                >
                  Inspect Full Source Code →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
