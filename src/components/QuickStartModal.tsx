import React from 'react';
import { X, Terminal, Shield, Monitor, Copy, Check, ExternalLink, AlertTriangle } from 'lucide-react';

interface QuickStartModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const QuickStartModal: React.FC<QuickStartModalProps> = ({ isOpen, onClose }) => {
  const [copiedIndex, setCopiedIndex] = React.useState<number | null>(null);

  if (!isOpen) return null;

  const copyText = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const quickSnippets = [
    {
      title: 'Clone Full Repository',
      desc: 'Clones the modular automation tools into your local terminal environment.',
      cmd: 'git clone https://github.com/ZacharySchmalzEng/Tools.git\ncd Tools',
      os: 'Cross-Platform'
    },
    {
      title: 'Windows: Universal Baseline Deployment',
      desc: 'Runs System, Debloat, Security, Apps, AutoUpdate, and Maintenance under ExecutionPolicy Bypass.',
      cmd: 'powershell.exe -ExecutionPolicy Bypass -File .\\Windows\\Provisioning\\Windows-Deployment-Tool\\Windows-Deployment-Tool.ps1 -Standard',
      os: 'Windows 11 / Server'
    },
    {
      title: 'Linux: Universal Baseline with 2FA SSH',
      desc: 'Deploys full package stack, desktop environment QoL tools, and Google Authenticator MFA.',
      cmd: 'sudo ./Linux/Provisioning/Linux-Deployment-Tool/Linux-Deployment-Tool.sh --all --2fa --unattended',
      os: 'Fedora / Nobara / Debian'
    },
    {
      title: 'Linux: Direct Script Download via curl',
      desc: 'Download the pristine raw script directly to your current directory without cloning git.',
      cmd: `curl -fsSL "${window.location.origin}/raw/Linux-Deployment-Tool.sh" -o Linux-Deployment-Tool.sh\nchmod +x Linux-Deployment-Tool.sh\nsudo ./Linux-Deployment-Tool.sh --all -d`,
      os: 'Linux'
    },
    {
      title: 'Linux: Safe Dry-Run Validation',
      desc: 'Resolves repositories and downloads packages without modifying kernel, PAM, or filesystem states.',
      cmd: 'sudo ./Linux/Provisioning/Linux-Deployment-Tool/Linux-Deployment-Tool.sh --all -d',
      os: 'Linux'
    }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6 space-y-5">
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">Quick Start & Execution Guide</h3>
              <p className="text-xs text-slate-400">Essential commands and safety prerequisites for deployment.</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Advisory */}
        <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-900/60 text-xs text-amber-300 flex items-start space-x-2.5">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-amber-400" />
          <div>
            <span className="font-semibold block">Elevated Permissions Required:</span>
            Windows tools require an Administrator PowerShell prompt; Linux tools require root/sudo privileges.
          </div>
        </div>

        {/* Snippets */}
        <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
          {quickSnippets.map((item, idx) => (
            <div key={item.title} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-slate-200">{item.title}</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                  {item.os}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">{item.desc}</p>
              <div className="relative group mt-1">
                <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 font-mono text-xs text-cyan-300 whitespace-pre-wrap break-all">
                  {item.cmd}
                </pre>
                <button
                  onClick={() => copyText(item.cmd, idx)}
                  className="absolute right-2 top-2 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono flex items-center space-x-1"
                >
                  {copiedIndex === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedIndex === idx ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
          <span>Author: Zachary Schmalz</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
