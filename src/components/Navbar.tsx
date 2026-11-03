import React from 'react';
import { Terminal, Shield, Wrench, HardDrive, Cpu, RefreshCw, Code, ExternalLink, Copy, Check, HelpCircle } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenQuickStart: () => void;
  onOpenSupport: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, onOpenQuickStart, onOpenSupport }) => {
  const [copiedClone, setCopiedClone] = React.useState(false);

  const copyCloneCommand = () => {
    navigator.clipboard.writeText('git clone https://github.com/ZacharySchmalzEng/Tools.git');
    setCopiedClone(true);
    setTimeout(() => setCopiedClone(false), 2000);
  };

  const navItems = [
    { id: 'configurator', label: 'Deployment Configurator', icon: Wrench },
    { id: 'simulator', label: 'Terminal Simulator', icon: Terminal },
    { id: 'inspector', label: 'Script Inspector', icon: Code },
    { id: 'backup', label: 'Restic Cloud Backup', icon: HardDrive },
    { id: 'profilemerge', label: 'Profile Deduplication', icon: Shield },
    { id: 'maintenance', label: 'OS Maintenance Hub', icon: RefreshCw },
  ];

  return (
    <header className="sticky top-0 z-40 bg-slate-900/90 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('configurator')}>
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white font-mono font-bold text-lg">
              <Cpu className="w-5 h-5 text-cyan-200" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-slate-100 tracking-tight text-base sm:text-lg">
                  ZacharySchmalz<span className="text-cyan-400">/Tools</span>
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 font-mono">
                  v2.0.1
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Modular OS Provisioning, Zero-Trust Hardening & Maintenance
              </p>
            </div>
          </div>

          {/* Quick Clone & Repo Info */}
          <div className="flex items-center space-x-2">
            <button
              onClick={copyCloneCommand}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/80 text-xs font-mono transition-colors"
              title="Copy Git clone command"
            >
              {copiedClone ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
              <span className="hidden md:inline">git clone ...</span>
              <span className="md:hidden">Clone</span>
            </button>

            <button
              onClick={onOpenQuickStart}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md shadow-cyan-600/30 transition-colors"
            >
              <span>Quick Start</span>
            </button>

            <button
              onClick={onOpenSupport}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/80 text-xs font-medium transition-colors"
              title="GitHub Support & Community Feedback"
            >
              <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">Support</span>
            </button>

            <a
              href="https://github.com/ZacharySchmalzEng/Tools"
              target="_blank"
              rel="noopener noreferrer"
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
              title="View on GitHub"
            >
              <ExternalLink className="w-4 h-4" />
            </a>
          </div>
        </div>

        {/* Tab Navigation */}
        <nav className="flex space-x-1 overflow-x-auto py-2 scrollbar-none border-t border-slate-800/60">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-all whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
