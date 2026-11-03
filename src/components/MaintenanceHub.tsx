import React, { useState } from 'react';
import { 
  RefreshCw, CheckCircle2, Terminal, Clock, HardDrive, ShieldCheck, 
  Cpu, Copy, Check, Play, AlertCircle, Wrench
} from 'lucide-react';

export const MaintenanceHub: React.FC = () => {
  const [selectedTask, setSelectedTask] = useState<string>('win-maintenance');
  const [copiedTask, setCopiedTask] = useState<boolean>(false);

  const tasks = [
    {
      id: 'win-maintenance',
      os: 'Windows',
      name: 'Deploy-OSMaintenanceTask.ps1',
      title: 'Weekly Automated Windows OS Servicing Task',
      cmd: 'powershell.exe -ExecutionPolicy Bypass -File .\\Windows\\Provisioning\\Deploy-OSMaintenanceTask.ps1',
      description: 'Registers a weekly scheduled task executing under NT AUTHORITY\\SYSTEM that performs TRIM, DNS cache flushing, chkdsk, SFC/DISM, and temp directory cleanup.',
      features: [
        'Storage TRIM: Invokes Optimize-Volume -Defrag -ReTrim on all fixed NTFS volumes',
        'Network Stack: Clears DNS resolver cache via Clear-DnsClientCache',
        'Filesystem Integrity: Runs read-only chkdsk volume health scan',
        'Component Store Repair: Executes sfc /scannow and DISM /Online /Cleanup-Image /RestoreHealth',
        'Disk Hygiene: Purges C:\\Windows\\Temp and User Temp folders',
        'Companion Registration: Optionally invokes Deploy-AutoUpdateTask.ps1'
      ]
    },
    {
      id: 'win-update',
      os: 'Windows',
      name: 'Deploy-AutoUpdateTask.ps1',
      title: 'Weekly Automated Winget & Windows Update Task',
      cmd: 'powershell.exe -ExecutionPolicy Bypass -File .\\Windows\\Provisioning\\Deploy-AutoUpdateTask.ps1',
      description: 'Registers an idempotent weekly SYSTEM task that updates all Winget packages and invokes PSWindowsUpdate.',
      features: [
        'Winget Silent Upgrade: winget upgrade --all --include-unknown --silent',
        'Bypasses License Prompts: --accept-source-agreements --accept-package-agreements',
        'Windows Update Integration: Bootstraps PSWindowsUpdate and schedules quiet patch cycle',
        'Rotated Transcripts: Captures execution stdout/stderr in InstallerLogs/'
      ]
    },
    {
      id: 'linux-updates-all',
      os: 'Linux',
      name: 'updatesAllMethods.sh',
      title: 'Universal Multi-Tier Package Update Alias',
      cmd: 'sudo ./Linux/Maintenance/updatesAllMethods.sh -y',
      description: 'Sequentially updates system RPM/DEB packages, Flatpak runtimes, and Snap packages in a single streamlined pass.',
      features: [
        'Sequential multi-tier upgrade (DNF/APT -> Flatpak -> Snap)',
        'Supports -y flag for non-interactive automated installs',
        'Supports -d flag for bandwidth pre-caching / download-only',
        'Clean ANSI colored output and failure rollbacks'
      ]
    },
    {
      id: 'linux-discord',
      os: 'Linux',
      name: 'FedoraDiscordUpdate.sh',
      title: 'Flatpak to Native RPM Discord Transition',
      cmd: 'sudo ./Linux/Maintenance/FedoraDiscordUpdate.sh',
      description: 'Detects and uninstalls Flatpak Discord, enables RPM Fusion non-free repos, and installs the native RPM package.',
      features: [
        'Fixes Wayland push-to-talk keybind limitations of sandbox',
        'Restores native system tray & audio share integrations',
        'Enables RPM Fusion non-free repository if not present',
        'Installs Discord via native DNF package manager'
      ]
    },
    {
      id: 'linux-ssh',
      os: 'Linux',
      name: 'FedoraEnableSSH.sh',
      title: 'OpenSSH Daemon Provisioning & 2FA Setup',
      cmd: 'sudo ./Linux/Networking/FedoraEnableSSH.sh',
      description: 'Provisions, starts, and verifies OpenSSH Server, opens firewalld ports, and optionally configures Google Authenticator MFA.',
      features: [
        'Verifies and installs openssh-server via DNF',
        'Optional Google Authenticator 2FA PAM integration',
        'Opens SSH in firewalld permanently: firewall-cmd --add-service=ssh',
        'Validates active socket listening via ss -tulpn'
      ]
    }
  ];

  const current = tasks.find(t => t.id === selectedTask) || tasks[0];

  const copyTaskCmd = () => {
    navigator.clipboard.writeText(current.cmd);
    setCopiedTask(true);
    setTimeout(() => setCopiedTask(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-md space-y-2">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <RefreshCw className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-100">OS Maintenance & Scheduled Automation Hub</h2>
            <p className="text-xs text-slate-400">
              Pre-configured maintenance scripts for volume health, TRIM, automatic updates, and service hardening.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Task List (1 col) */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 block pb-2 border-b border-slate-800">
            Select Automation Script
          </span>

          <div className="space-y-2">
            {tasks.map(t => {
              const isSelected = t.id === selectedTask;
              return (
                <button
                  key={t.id}
                  onClick={() => setSelectedTask(t.id)}
                  className={`w-full text-left p-3 rounded-lg border transition-all ${
                    isSelected
                      ? 'bg-cyan-500/10 border-cyan-500/40 text-slate-100 shadow-sm'
                      : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-cyan-400">{t.name}</span>
                    <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                      t.os === 'Windows' ? 'bg-blue-950 text-blue-300' : 'bg-emerald-950 text-emerald-300'
                    }`}>
                      {t.os}
                    </span>
                  </div>
                  <div className="text-xs text-slate-300 font-medium leading-snug">{t.title}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Task Details & Command (2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-cyan-400">{current.name}</span>
                <span className="text-xs text-slate-500 font-mono">• {current.os}</span>
              </div>
              <h3 className="text-base font-bold text-slate-100 mt-1">{current.title}</h3>
              <p className="text-xs text-slate-400 mt-2 leading-relaxed">{current.description}</p>
            </div>

            {/* Command Preview */}
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">Launch Command</span>
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 break-all">
                {current.cmd}
              </div>

              <button
                onClick={copyTaskCmd}
                className="w-full sm:w-auto flex items-center justify-center space-x-2 py-2 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md shadow-cyan-600/20 transition-all"
              >
                {copiedTask ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                <span>{copiedTask ? 'Command Copied!' : 'Copy Command'}</span>
              </button>
            </div>

            {/* Feature Checklist */}
            <div className="space-y-3 pt-3 border-t border-slate-800">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Automated Actions & Safeguards
              </span>
              <ul className="grid grid-cols-1 gap-2.5">
                {current.features.map((feat, idx) => (
                  <li key={idx} className="flex items-start space-x-2.5 text-xs text-slate-300 bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/80">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span>{feat}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
