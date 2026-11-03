import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { DeploymentConfigurator } from './components/DeploymentConfigurator';
import { TerminalSimulator } from './components/TerminalSimulator';
import { ScriptInspector } from './components/ScriptInspector';
import { BackupArchitect } from './components/BackupArchitect';
import { ProfileMergeTool } from './components/ProfileMergeTool';
import { MaintenanceHub } from './components/MaintenanceHub';
import { QuickStartModal } from './components/QuickStartModal';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('configurator');
  const [quickStartOpen, setQuickStartOpen] = useState<boolean>(false);

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

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div>
            Zachary Schmalz Provisioning & Automation Tool Suite • Windows 11 Pro & Linux (Fedora/Debian)
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
          </div>
        </div>
      </footer>

      {/* Quick Start Modal */}
      <QuickStartModal
        isOpen={quickStartOpen}
        onClose={() => setQuickStartOpen(false)}
      />
    </div>
  );
};

export default App;
