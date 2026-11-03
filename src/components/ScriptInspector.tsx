import React, { useState, useMemo } from 'react';
import { 
  Code, Copy, Check, Download, Search, Terminal, Monitor, HardDrive, 
  Shield, Wrench, RefreshCw, ChevronRight, FileText, ExternalLink, CheckCircle2, AlertTriangle
} from 'lucide-react';
import { SCRIPT_CATALOG, RAW_SCRIPTS } from '../data/scriptsData';

interface ScriptInspectorProps {
  selectedScriptId?: string;
  onSelectScript?: (scriptId: string) => void;
  onRunSimulation?: (scriptId: string, cmd: string, flags: string[]) => void;
}

export const ScriptInspector: React.FC<ScriptInspectorProps> = ({
  selectedScriptId = 'linux-deployment-tool',
  onSelectScript,
  onRunSimulation
}) => {
  const [currentId, setCurrentId] = useState<string>(selectedScriptId);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [activeSubTab, setActiveSubTab] = useState<'code' | 'docs' | 'flags'>('code');

  const selectedItem = useMemo(() => {
    return SCRIPT_CATALOG.find(s => s.id === currentId) || SCRIPT_CATALOG[0];
  }, [currentId]);

  const scriptFile = useMemo(() => {
    // Map catalog item name or path to RAW_SCRIPTS key
    if (RAW_SCRIPTS[selectedItem.name]) {
      return RAW_SCRIPTS[selectedItem.name];
    }
    // Search by ending
    const found = Object.entries(RAW_SCRIPTS).find(([k]) => k.toLowerCase() === selectedItem.name.toLowerCase());
    return found ? found[1] : { path: selectedItem.path, content: '# Script content preview not found in raw cache.' };
  }, [selectedItem]);

  const codeLines = useMemo(() => {
    return scriptFile.content.split('\n');
  }, [scriptFile.content]);

  const filteredLines = useMemo(() => {
    if (!searchQuery.trim()) return null;
    const q = searchQuery.toLowerCase();
    const matches: number[] = [];
    codeLines.forEach((line, idx) => {
      if (line.toLowerCase().includes(q)) {
        matches.push(idx);
      }
    });
    return matches;
  }, [codeLines, searchQuery]);

  const handleCopyCode = () => {
    navigator.clipboard.writeText(scriptFile.content);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([scriptFile.content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedItem.name;
    a.click;
    URL.revokeObjectURL(url);
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'Provisioning': return Wrench;
      case 'Gaming': return Terminal;
      case 'Maintenance': return RefreshCw;
      case 'Networking': return Terminal;
      case 'Backups': return HardDrive;
      case 'Data Management': return Shield;
      default: return FileText;
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      {/* Sidebar: Scripts Tree */}
      <div className="lg:col-span-1 p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-1.5">
            <Code className="w-3.5 h-3.5 text-cyan-400" />
            <span>Repository Scripts</span>
          </span>
          <span className="text-xs text-slate-500 font-mono">{SCRIPT_CATALOG.length} tools</span>
        </div>

        {/* Group by OS / Category */}
        <div className="space-y-4 max-h-[650px] overflow-y-auto pr-1">
          {/* Linux Section */}
          <div className="space-y-1.5">
            <div className="flex items-center space-x-1.5 text-xs font-semibold text-emerald-400 px-2 py-1 bg-emerald-950/30 rounded border border-emerald-900/40">
              <Terminal className="w-3.5 h-3.5" />
              <span>Linux Tools (Fedora / Debian)</span>
            </div>
            {SCRIPT_CATALOG.filter(s => s.os === 'linux').map(item => {
              const isSelected = item.id === currentId;
              const Icon = getCategoryIcon(item.category);
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setCurrentId(item.id);
                    if (onSelectScript) onSelectScript(item.id);
                  }}
                  className={`w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono flex items-center justify-between transition-all ${
                    isSelected
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center space-x-2 truncate">
                    <Icon className={`w-3.5 h-3.5 flex-shrink-0 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span className="truncate">{item.name}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 uppercase">{item.category}</span>
                </button>
              );
            })}
          </div>

          {/* Windows Section */}
          <div className="space-y-1.5 pt-2">
            <div className="flex items-center space-x-1.5 text-xs font-semibold text-blue-400 px-2 py-1 bg-blue-950/30 rounded border border-blue-950/40">
              <Monitor className="w-3.5 h-3.5" />
              <span>Windows 11 / Server Tools</span>
            </div>
            {SCRIPT_CATALOG.filter(s => s.os === 'windows').map(item => {
              const isSelected = item.id === currentId;
              const Icon = getCategoryIcon(item.category);
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setCurrentId(item.id);
                    if (onSelectScript) onSelectScript(item.id);
                  }}
                  className={`w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono flex items-center justify-between transition-all ${
                    isSelected
                      ? 'bg-blue-500/10 text-blue-300 border border-blue-500/30 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center space-x-2 truncate">
                    <Icon className={`w-3.5 h-3.5 flex-shrink-0 ${isSelected ? 'text-blue-400' : 'text-slate-500'}`} />
                    <span className="truncate">{item.name}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 uppercase">{item.category}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Main Code View (3 cols) */}
      <div className="lg:col-span-3 space-y-4">
        {/* Script Top Bar & Metadata */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center space-x-2.5">
                <h3 className="text-base font-bold text-slate-100 font-mono">{selectedItem.name}</h3>
                <span className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase ${
                  selectedItem.os === 'linux' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/60' : 'bg-blue-950 text-blue-300 border border-blue-800/60'
                }`}>
                  {selectedItem.language}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                  v{selectedItem.version}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">{selectedItem.description}</p>
            </div>

            {/* Actions */}
            <div className="flex items-center space-x-2">
              <button
                onClick={handleCopyCode}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors border border-slate-700"
              >
                {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedCode ? 'Copied' : 'Copy Code'}</span>
              </button>

              <button
                onClick={handleDownload}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download</span>
              </button>
            </div>
          </div>

          {/* Subtabs: Code vs Documentation vs Flags */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
            <div className="flex space-x-2">
              <button
                onClick={() => setActiveSubTab('code')}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                  activeSubTab === 'code' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Source Code ({codeLines.length} lines)
              </button>
              <button
                onClick={() => setActiveSubTab('docs')}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                  activeSubTab === 'docs' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Architecture & Safety Docs
              </button>
              {selectedItem.flags && (
                <button
                  onClick={() => setActiveSubTab('flags')}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    activeSubTab === 'flags' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Command Flags ({selectedItem.flags.length})
                </button>
              )}
            </div>

            {activeSubTab === 'code' && (
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                <input
                  type="text"
                  placeholder="Find in file..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-md pl-8 pr-3 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500 w-44 sm:w-56"
                />
              </div>
            )}
          </div>
        </div>

        {/* CODE VIEW */}
        {activeSubTab === 'code' && (
          <div className="rounded-xl bg-[#090d16] border border-slate-800 overflow-hidden shadow-2xl">
            <div className="flex items-center justify-between px-4 py-2 bg-slate-900/80 border-b border-slate-800 text-xs font-mono text-slate-400">
              <span className="truncate">{selectedItem.path}</span>
              <span>{codeLines.length} lines • {selectedItem.language}</span>
            </div>

            <div className="p-4 max-h-[560px] overflow-y-auto font-mono text-xs leading-relaxed select-text">
              {codeLines.map((line, idx) => {
                const isMatch = filteredLines ? filteredLines.includes(idx) : false;
                const isComment = line.trim().startsWith('#') || line.trim().startsWith('<#') || line.trim().startsWith('//');
                return (
                  <div
                    key={idx}
                    className={`flex items-start hover:bg-slate-800/40 rounded px-1 -mx-1 ${
                      isMatch ? 'bg-cyan-500/20 text-cyan-200' : ''
                    }`}
                  >
                    <span className="w-12 text-right pr-4 text-slate-600 select-none flex-shrink-0 text-[11px]">
                      {idx + 1}
                    </span>
                    <span className={`whitespace-pre-wrap break-all ${
                      isComment ? 'text-slate-500 italic' : line.includes('function') || line.includes('def') ? 'text-amber-300' : 'text-slate-200'
                    }`}>
                      {line}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* DOCS TAB */}
        {activeSubTab === 'docs' && (
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6 text-xs text-slate-300 leading-relaxed">
            <div>
              <h4 className="text-sm font-bold text-slate-100 uppercase tracking-wider mb-2">Technical Overview</h4>
              <p>{selectedItem.description}</p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
                <span className="font-semibold text-slate-200 block">Privilege Requirements</span>
                <div className="flex items-center space-x-2">
                  {selectedItem.requiresElevation ? (
                    <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-mono">
                      Elevated (sudo / Administrator required)
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono">
                      User Context (Non-Root)
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-500">
                  Required to register systemd daemons, modify registry policies, and manage low-level services.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
                <span className="font-semibold text-slate-200 block">Supported Environments</span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedItem.supportedDistrosOrEditions.map(env => (
                    <span key={env} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px] font-mono">
                      {env}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-100 uppercase tracking-wider">Key Engineering Features</h4>
              <ul className="space-y-2">
                {selectedItem.keyFeatures.map((feat, i) => (
                  <li key={i} className="flex items-start space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    <span>{feat}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* FLAGS TAB */}
        {activeSubTab === 'flags' && selectedItem.flags && (
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Command-Line Flags Reference</h4>
            <div className="space-y-3">
              {selectedItem.flags.map(f => (
                <div key={f.flag} className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">{f.flag}</span>
                    <span className="text-xs font-semibold text-slate-200">{f.name}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono uppercase">
                      {f.category}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{f.description}</p>
                  {f.warningNote && (
                    <div className="flex items-center space-x-1.5 text-xs text-rose-400 mt-1 font-semibold">
                      <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                      <span>{f.warningNote}</span>
                    </div>
                  )}
                  {f.associatedSoftware && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {f.associatedSoftware.map(app => (
                        <span key={app} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 font-mono">
                          {app}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
