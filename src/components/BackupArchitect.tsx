import React, { useState } from 'react';
import { 
  HardDrive, Shield, Cloud, Terminal, Copy, Check, Clock, Key, 
  Settings, CheckCircle2, Lock, AlertCircle, RefreshCw
} from 'lucide-react';

export const BackupArchitect: React.FC = () => {
  const [osTarget, setOsTarget] = useState<'linux' | 'windows'>('linux');
  const [remoteName, setRemoteName] = useState<string>('gdrive');
  const [repoDir, setRepoDir] = useState<string>('FedoraBackup');
  const [useVSS, setUseVSS] = useState<boolean>(true); // For Windows
  const [keepDaily, setKeepDaily] = useState<number>(7);
  const [keepWeekly, setKeepWeekly] = useState<number>(4);
  const [keepMonthly, setKeepMonthly] = useState<number>(12);
  const [keepYearly, setKeepYearly] = useState<number>(1);
  const [randomDelaySeconds, setRandomDelaySeconds] = useState<number>(300);
  const [copiedScript, setCopiedScript] = useState<boolean>(false);
  const [passwordGen, setPasswordGen] = useState<string>('s3cur3-r3st1c-k3y-99x2A');

  const generateNewPassword = () => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let res = '';
    for (let i = 0; i < 24; i++) {
      res += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setPasswordGen(res);
  };

  const generatedBackupCommand = osTarget === 'linux'
    ? `# Deploy Zero-Touch Restic Google Drive Backup on Linux
# 1. Ensure Rclone remote '${remoteName}' is configured:
rclone config

# 2. Run the automated deployment script:
chmod +x Linux/Backups/deploy-restic-gdrive.sh
./Linux/Backups/deploy-restic-gdrive.sh

# What it automatically provisions:
# - Systemd User Service: ~/.config/systemd/user/restic-gdrive-backup.service
# - Systemd User Timer:   ~/.config/systemd/user/restic-gdrive-backup.timer (Daily + ${randomDelaySeconds}s delay)
# - Secure Vault Key:     ~/.config/restic-passwd
# - Retention Pruning:    --keep-daily ${keepDaily} --keep-weekly ${keepWeekly} --keep-monthly ${keepMonthly} --keep-yearly ${keepYearly}`
    : `# Deploy Automated Restic Google Drive Backup on Windows 11 / Server
# Note: Executes in NT AUTHORITY\\SYSTEM context for complete VSS access.

# 1. Authorize Execution Policy & launch script in Administrator PowerShell:
powershell.exe -ExecutionPolicy Bypass -File .\\Windows\\Backups\\deploy-restic-gdrive.ps1

# Provisioned Infrastructure:
# - VSS Snapshot Mode:    ${useVSS ? '--use-fs-snapshot (Bypasses open file locks)' : 'Standard mode'}
# - Scheduled Task:       "Restic-GDrive-Backup" (Daily under SYSTEM)
# - Target Remote:        rclone:${remoteName}:${repoDir}
# - Jitter Delay:         0 to ${randomDelaySeconds}s (mitigates multi-host API throttling)`;

  const copyGenerated = () => {
    navigator.clipboard.writeText(generatedBackupCommand);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <HardDrive className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-100">Restic + Google Drive Cloud Backup Architect</h2>
            <p className="text-xs text-slate-400">Zero-knowledge encrypted backups with automated timers and locked-file VSS shadow copying.</p>
          </div>
        </div>

        {/* OS Selector */}
        <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => {
              setOsTarget('linux');
              setRepoDir('FedoraBackup');
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              osTarget === 'linux' ? 'bg-emerald-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
            }`}
          >
            Linux (Systemd Timer)
          </button>
          <button
            onClick={() => {
              setOsTarget('windows');
              setRepoDir('WindowsBackup');
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              osTarget === 'windows' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
            }`}
          >
            Windows 11 (VSS + Task Scheduler)
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Settings (2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Cloud Remote & Targets */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-1.5">
              <Cloud className="w-3.5 h-3.5 text-cyan-400" />
              <span>Storage Backend & Rclone Remote</span>
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs text-slate-400 font-medium">Rclone Remote Name</label>
                <input
                  type="text"
                  value={remoteName}
                  onChange={(e) => setRemoteName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <span className="text-[11px] text-slate-500">Configured in `rclone config` as Google Drive remote.</span>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-slate-400 font-medium">Remote Folder / Repository</label>
                <input
                  type="text"
                  value={repoDir}
                  onChange={(e) => setRepoDir(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <span className="text-[11px] text-slate-500">Subfolder path on your Google Drive.</span>
              </div>
            </div>

            {/* Default Backup Targets */}
            <div className="space-y-2 pt-2 border-t border-slate-800/80">
              <label className="text-xs text-slate-400 font-medium">Included Directories (Standard User Hierarchy)</label>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                {['Documents', 'Pictures', 'Videos', 'Music', 'Desktop'].map(folder => (
                  <div key={folder} className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-center">
                    <span className="text-xs font-mono text-slate-300 block">{folder}</span>
                    <span className="text-[10px] text-emerald-400 font-medium">Auto-Included</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Windows VSS Option */}
            {osTarget === 'windows' && (
              <div className="p-3.5 rounded-lg bg-blue-950/20 border border-blue-900/60 flex items-start space-x-3 text-xs">
                <input
                  type="checkbox"
                  id="vss-check"
                  checked={useVSS}
                  onChange={(e) => setUseVSS(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
                />
                <label htmlFor="vss-check" className="cursor-pointer space-y-0.5">
                  <span className="font-semibold text-blue-300 font-mono">--use-fs-snapshot (Volume Shadow Copy)</span>
                  <p className="text-[11px] text-slate-400">
                    Bypasses locked file exceptions (e.g. Outlook PSTs, active browser caches, SQLite DBs) using native Windows VSS snapshots under SYSTEM context.
                  </p>
                </label>
              </div>
            )}
          </div>

          {/* Retention Policies */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-1.5">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Retention & Auto-Pruning Architecture</span>
            </span>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="space-y-1">
                <label className="text-[11px] text-slate-400">Keep Daily</label>
                <input
                  type="number"
                  value={keepDaily}
                  min={1}
                  max={30}
                  onChange={(e) => setKeepDaily(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200"
                />
                <span className="text-[10px] text-slate-500">Last {keepDaily} days</span>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] text-slate-400">Keep Weekly</label>
                <input
                  type="number"
                  value={keepWeekly}
                  min={1}
                  max={12}
                  onChange={(e) => setKeepWeekly(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200"
                />
                <span className="text-[10px] text-slate-500">Last {keepWeekly} weeks</span>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] text-slate-400">Keep Monthly</label>
                <input
                  type="number"
                  value={keepMonthly}
                  min={1}
                  max={36}
                  onChange={(e) => setKeepMonthly(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200"
                />
                <span className="text-[10px] text-slate-500">Last {keepMonthly} months</span>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] text-slate-400">Keep Yearly</label>
                <input
                  type="number"
                  value={keepYearly}
                  min={1}
                  max={10}
                  onChange={(e) => setKeepYearly(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200"
                />
                <span className="text-[10px] text-slate-500">Last {keepYearly} years</span>
              </div>
            </div>

            {/* Random Offset Jitter */}
            <div className="space-y-2 pt-2 border-t border-slate-800/80">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Multi-Machine Randomized Offset Delay:</span>
                <span className="font-mono text-cyan-400 font-bold">{randomDelaySeconds}s ({Math.round(randomDelaySeconds / 60)} min)</span>
              </div>
              <input
                type="range"
                min="0"
                max="1800"
                step="60"
                value={randomDelaySeconds}
                onChange={(e) => setRandomDelaySeconds(Number(e.target.value))}
                className="w-full accent-cyan-500 bg-slate-800 h-1.5 rounded-lg"
              />
              <p className="text-[11px] text-slate-500">
                Randomizes scheduled execution time across laptops and desktops to avoid simultaneously exhausting Google Drive API requests or causing repository lock contention.
              </p>
            </div>
          </div>
        </div>

        {/* Generated Command & Deployment instructions */}
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Deployment Blueprint</span>
              </span>
              <span className="text-xs font-mono text-emerald-400">Zero-Touch</span>
            </div>

            <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 whitespace-pre-wrap leading-relaxed max-h-[380px] overflow-y-auto">
              {generatedBackupCommand}
            </pre>

            <button
              onClick={copyGenerated}
              className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md shadow-cyan-600/20 transition-all"
            >
              {copiedScript ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              <span>{copiedScript ? 'Blueprint Copied!' : 'Copy Deployment Steps'}</span>
            </button>
          </div>

          {/* Encryption Key Vault Helper */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Key className="w-3.5 h-3.5 text-amber-400" />
                <span>Client-Side Key Generator</span>
              </span>
              <button
                onClick={generateNewPassword}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Generate</span>
              </button>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-amber-300 break-all select-all">
              {passwordGen}
            </div>

            <p className="text-[11px] text-slate-500">
              Restic uses this password to encrypt chunk headers and file blobs client-side before uploading to Google Drive.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
