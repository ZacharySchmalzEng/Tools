import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { DeploymentConfigurator } from './components/DeploymentConfigurator';
import { TerminalSimulator } from './components/TerminalSimulator';
import { ScriptInspector } from './components/ScriptInspector';
import { BackupArchitect } from './components/BackupArchitect';
import { ProfileMergeTool } from './components/ProfileMergeTool';
import { MaintenanceHub } from './components/MaintenanceHub';
import { QuickStartModal } from './components/QuickStartModal';
import { SupportModal } from './components/SupportModal';
import { Bug, Lightbulb, ExternalLink, HelpCircle, ShieldAlert } from 'lucide-react';

const GithubIcon: React.FC<{ className?: string }> = ({ className = 'w-4 h-4' }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
    <path d="M9 18c-4.51 2-5-2-7-2" />
  </svg>
);

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('configurator');
  const [quickStartOpen, setQuickStartOpen] = useState<boolean>(false);
  const [supportOpen, setSupportOpen] = useState<boolean>(false);

  // States to pass between tabs
  const [simScriptId, setSimScriptId] = useState<string>('linux-deployment-tool');
  const [simCommand, setSimCommand] = useState<string>('sudo ./Linux-Deployment-Tool.sh --apps --gaming -d');
  const [simFlags, setSimFlags] = useState<string[]>(['--apps', '--gaming', '-d']);
  const [inspectScriptId, setInspectScriptId] = useState<string>('linux-deployment-tool');

  const handleRunSimulation = (scriptId: string, command: string, flags: string[]) => {
    setSimScriptId(scriptId);
    setSimCommand(command);
    setSimFlags(flags);
    setActiveTab('simulator');
  };

  const handleViewScript = (scriptId: string) => {
    setInspectScriptId(scriptId);
    setActiveTab('inspector');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenQuickStart={() => setQuickStartOpen(true)}
        onOpenSupport={() => setSupportOpen(true)}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'configurator' && (
          <DeploymentConfigurator
            onRunSimulation={handleRunSimulation}
            onViewScript={handleViewScript}
          />
        )}

        {activeTab === 'simulator' && (
          <TerminalSimulator
            initialScriptId={simScriptId}
            initialCommand={simCommand}
            initialFlags={simFlags}
          />
        )}

        {activeTab === 'inspector' && (
          <ScriptInspector
            selectedScriptId={inspectScriptId}
            onSelectScript={(id) => setInspectScriptId(id)}
            onRunSimulation={handleRunSimulation}
          />
        )}

        {activeTab === 'backup' && (
          <BackupArchitect />
        )}

        {activeTab === 'profilemerge' && (
          <ProfileMergeTool />
        )}

        {activeTab === 'maintenance' && (
          <MaintenanceHub />
        )}
      </main>

      {/* Dedicated GitHub Support & Footer Section */}
      <footer className="border-t border-slate-900 bg-slate-950 text-slate-400 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Column 1: Suite Overview */}
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <span className="font-bold text-slate-100 tracking-tight text-base">
                  ZacharySchmalz<span className="text-cyan-400">/Tools</span>
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 font-mono">
                  v2.0
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Modular OS provisioning, CIS Level 2 zero-trust hardening, automated Restic cloud backups, 
                and unified desktop maintenance for Linux (Fedora, Nobara, Atomic, Arch, SteamOS, openSUSE, Debian) 
                and Windows 11 Pro.
              </p>
              <div className="text-xs text-slate-500 font-mono">
                Licensed under the MIT License • Production Release v2.0
              </div>
            </div>

            {/* Column 2: Direct GitHub Actions & Support Modal Trigger */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                GitHub Support & Feedback
              </h4>
              <ul className="space-y-2 text-xs">
                <li>
                  <a
                    href="https://github.com/ZacharySchmalzEng/Tools/issues/new?labels=bug&template=bug_report.md&title=%5BBUG%5D+"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-2 text-slate-300 hover:text-rose-400 transition-colors group"
                  >
                    <Bug className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    <span>Submit a Bug Report</span>
                    <ExternalLink className="w-3 h-3 text-slate-500 group-hover:text-rose-400" />
                  </a>
                </li>
                <li>
                  <a
                    href="https://github.com/ZacharySchmalzEng/Tools/issues/new?labels=enhancement&template=feature_request.md&title=%5BFEATURE%5D+"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-2 text-slate-300 hover:text-cyan-400 transition-colors group"
                  >
                    <Lightbulb className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span>Request Feature Enhancement</span>
                    <ExternalLink className="w-3 h-3 text-slate-500 group-hover:text-cyan-400" />
                  </a>
                </li>
                <li>
                  <a
                    href="https://github.com/ZacharySchmalzEng/Tools/issues"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-2 text-slate-300 hover:text-slate-100 transition-colors group"
                  >
                    <GithubIcon className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    <span>Browse All GitHub Issues & Workarounds</span>
                    <ExternalLink className="w-3 h-3 text-slate-500 group-hover:text-slate-300" />
                  </a>
                </li>
                <li className="pt-1">
                  <button
                    onClick={() => setSupportOpen(true)}
                    className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 border border-slate-700/80 text-xs font-medium transition-colors"
                  >
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>Open Support Modal & Diagnostics</span>
                  </button>
                </li>
              </ul>
            </div>

            {/* Column 3: Explicit No-SLA / Best-Effort Advisory Policy */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Support Level & Commitments
              </h4>
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                <div className="flex items-center space-x-2 text-amber-400 text-xs font-medium">
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                  <span>No SLAs or Binding Commitments</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  This tool suite is provided on an <strong className="text-slate-300">as-is</strong> basis with 
                  community best-effort maintenance. There are no guaranteed response times (SLAs), uptime warranties, 
                  or binding engineering delivery commitments. Please verify scripts before running in mission-critical environments.
                </p>
              </div>
            </div>
          </div>

          {/* Bottom Hairline & Copyright */}
          <div className="mt-8 pt-6 border-t border-slate-900 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500">
            <div>
              © {new Date().getFullYear()} Zachary Schmalz Engineering • Production Release v2.0
            </div>
            <div className="flex items-center space-x-4">
              <a
                href="https://github.com/ZacharySchmalzEng/Tools"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-cyan-400 transition-colors"
              >
                GitHub Repository
              </a>
              <span>•</span>
              <button
                onClick={() => setQuickStartOpen(true)}
                className="hover:text-cyan-400 transition-colors"
              >
                Quick Reference
              </button>
              <span>•</span>
              <button
                onClick={() => setSupportOpen(true)}
                className="hover:text-cyan-400 transition-colors"
              >
                Support Hub
              </button>
            </div>
          </div>
        </div>
      </footer>

      {/* Quick Start Modal */}
      <QuickStartModal
        isOpen={quickStartOpen}
        onClose={() => setQuickStartOpen(false)}
      />

      {/* GitHub Support & Feedback Modal */}
      <SupportModal
        isOpen={supportOpen}
        onClose={() => setSupportOpen(false)}
        activeTab={activeTab}
        activeScriptId={inspectScriptId}
      />
    </div>
  );
};

export default App;
