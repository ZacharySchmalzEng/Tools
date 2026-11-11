import React, { useState, useMemo } from 'react';
import { 
  Code, Copy, Check, Download, Search, Terminal, Monitor, HardDrive, 
  Shield, Wrench, RefreshCw, ChevronRight, FileText, ExternalLink, 
  CheckCircle2, AlertTriangle, X, Play, SlidersHorizontal, Layers, Sparkles
} from 'lucide-react';
import { SCRIPT_CATALOG, RAW_SCRIPTS } from '../data/scriptsData';

interface ScriptInspectorProps {
  selectedScriptId?: string;
  onSelectScript?: (scriptId: string) => void;
  onRunSimulation?: (scriptId: string, cmd: string, flags: string[]) => void;
}

interface SearchIndexEntry {
  id: string;
  type: 'flag' | 'security' | 'feature' | 'overview';
  scriptId: string;
  scriptName: string;
  scriptCategory: string;
  title: string;
  description: string;
  category?: string;
  flagSyntax?: string;
  warningNote?: string;
  associatedSoftware?: string[];
  requiresElevation?: boolean;
}

const HighlightMatch: React.FC<{ text: string; query: string }> = ({ text, query }) => {
  if (!query || !query.trim()) return <>{text}</>;
  const trimmed = query.trim();
  const escaped = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`(${escaped})`, 'gi');
  const parts = text.split(regex);
  return (
    <>
      {parts.map((part, i) =>
        regex.test(part) ? (
          <mark key={i} className="bg-cyan-500/30 text-cyan-200 rounded px-0.5 font-semibold">
            {part}
          </mark>
        ) : (
          part
        )
      )}
    </>
  );
};

export const ScriptInspector: React.FC<ScriptInspectorProps> = ({
  selectedScriptId = 'linux-deployment-tool',
  onSelectScript,
  onRunSimulation
}) => {
  const [currentId, setCurrentId] = useState<string>(selectedScriptId);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [searchScope, setSearchScope] = useState<'active' | 'all'>('active');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [copiedCurl, setCopiedCurl] = useState<boolean>(false);
  const [copiedFlag, setCopiedFlag] = useState<string | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'code' | 'docs' | 'flags' | 'search'>('code');

  const selectedItem = useMemo(() => {
    return SCRIPT_CATALOG.find(s => s.id === currentId) || SCRIPT_CATALOG[0];
  }, [currentId]);

  const scriptFile = useMemo(() => {
    if (RAW_SCRIPTS[selectedItem.name]) {
      return RAW_SCRIPTS[selectedItem.name];
    }
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

  // Comprehensive Search Index
  const fullSearchIndex = useMemo<SearchIndexEntry[]>(() => {
    const scriptsToIndex = searchScope === 'all' 
      ? SCRIPT_CATALOG 
      : [selectedItem];

    const entries: SearchIndexEntry[] = [];

    scriptsToIndex.forEach(script => {
      // 1. Technical Overview Entry
      entries.push({
        id: `${script.id}-overview`,
        type: 'overview',
        scriptId: script.id,
        scriptName: script.name,
        scriptCategory: script.category,
        title: `${script.name} Overview`,
        description: script.description,
        requiresElevation: script.requiresElevation,
      });

      // 2. Key Engineering Features & Security Modules
      script.keyFeatures.forEach((feat, idx) => {
        const isSecurity = /secur|harden|ssh|cve|2fa|mfa|selinux|apparmor|auditd|sysctl|mask|umask|firewall/i.test(feat);
        entries.push({
          id: `${script.id}-feat-${idx}`,
          type: isSecurity ? 'security' : 'feature',
          scriptId: script.id,
          scriptName: script.name,
          scriptCategory: script.category,
          title: isSecurity ? 'Hardening & Security Control' : 'Engineering Feature',
          description: feat,
          category: isSecurity ? 'security' : 'core'
        });
      });

      // 3. Command Flags
      if (script.flags) {
        script.flags.forEach(f => {
          const isSecurity = f.category === 'security' || /harden|2fa|ssh|lock|cve|audit/i.test(f.flag + f.name + f.description);
          entries.push({
            id: `${script.id}-flag-${f.flag}`,
            type: isSecurity ? 'security' : 'flag',
            scriptId: script.id,
            scriptName: script.name,
            scriptCategory: script.category,
            title: f.name,
            flagSyntax: f.flag,
            description: f.description,
            category: f.category,
            warningNote: f.warningNote,
            associatedSoftware: f.associatedSoftware,
            requiresElevation: script.requiresElevation
          });
        });
      }
    });

    return entries;
  }, [searchScope, selectedItem]);

  // Filtered Search Results
  const searchResults = useMemo(() => {
    let items = fullSearchIndex;

    // Apply category filter if not 'all'
    if (categoryFilter !== 'all') {
      items = items.filter(item => {
        if (categoryFilter === 'security') {
          return item.type === 'security' || item.category === 'security';
        }
        return item.category?.toLowerCase() === categoryFilter.toLowerCase();
      });
    }

    if (!searchQuery.trim()) {
      return items;
    }

    const q = searchQuery.toLowerCase().trim();
    return items.filter(item => {
      const matchTitle = item.title.toLowerCase().includes(q);
      const matchDesc = item.description.toLowerCase().includes(q);
      const matchFlag = item.flagSyntax?.toLowerCase().includes(q);
      const matchWarning = item.warningNote?.toLowerCase().includes(q);
      const matchApps = item.associatedSoftware?.some(app => app.toLowerCase().includes(q));
      const matchScript = item.scriptName.toLowerCase().includes(q);
      return matchTitle || matchDesc || matchFlag || matchWarning || matchApps || matchScript;
    });
  }, [fullSearchIndex, searchQuery, categoryFilter]);

  const handleCopyCode = () => {
    navigator.clipboard.writeText(scriptFile.content);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleCopyCurl = () => {
    const rawUrl = `${window.location.origin}/raw/${selectedItem.name}`;
    const cmd = `curl -fsSL "${rawUrl}" -o ${selectedItem.name} && chmod +x ${selectedItem.name}`;
    navigator.clipboard.writeText(cmd);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  const handleCopyFlag = (flag: string) => {
    navigator.clipboard.writeText(flag);
    setCopiedFlag(flag);
    setTimeout(() => setCopiedFlag(null), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([scriptFile.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedItem.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleSelectScriptFromSearch = (scriptId: string) => {
    setCurrentId(scriptId);
    if (onSelectScript) onSelectScript(scriptId);
  };

  const handleRunFlagInSimulation = (entry: SearchIndexEntry) => {
    if (!onRunSimulation) return;
    const flag = entry.flagSyntax || '';
    const prefix = entry.requiresElevation ? 'sudo ' : '';
    const cmd = `${prefix}./${entry.scriptName} ${flag}`.trim();
    onRunSimulation(entry.scriptId, cmd, flag ? [flag] : []);
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
        </div>
      </div>

      {/* Main Content Area */}
      <div className="lg:col-span-3 space-y-4">
        {/* Top Header Card */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                <h3 className="text-lg font-bold text-slate-100 font-mono tracking-tight">{selectedItem.name}</h3>
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
                  v{selectedItem.version}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                  {selectedItem.language.toUpperCase()}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">{selectedItem.description}</p>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center flex-wrap gap-2 flex-shrink-0">
              {selectedItem.os === 'linux' && (
                <a
                  href="/raw/beta/Linux-Deployment-Tool-Beta.tar.gz"
                  download="Linux-Deployment-Tool-Beta.tar.gz"
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 text-xs font-mono transition-colors border border-amber-500/30"
                  title="Download complete ./Beta modular suite as a single tarball (Linux-Deployment-Tool.sh at top of ./Beta)"
                >
                  <Download className="w-3.5 h-3.5 text-amber-400" />
                  <span>./Beta Tarball (.tar.gz)</span>
                </a>
              )}

              <button
                onClick={handleCopyCurl}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors border border-slate-700"
                title="Copy curl one-liner to download and mark executable"
              >
                {copiedCurl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Terminal className="w-3.5 h-3.5" />}
                <span>{copiedCurl ? 'Copied curl' : 'Copy curl'}</span>
              </button>

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

          {/* Subtabs Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-slate-800/80">
            <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 sm:pb-0">
              <button
                onClick={() => setActiveSubTab('code')}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                  activeSubTab === 'code' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Source Code ({codeLines.length})
              </button>
              <button
                onClick={() => setActiveSubTab('docs')}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                  activeSubTab === 'docs' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Architecture & Safety Docs
              </button>
              {selectedItem.flags && (
                <button
                  onClick={() => setActiveSubTab('flags')}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                    activeSubTab === 'flags' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Command Flags ({selectedItem.flags.length})
                </button>
              )}
              <button
                onClick={() => setActiveSubTab('search')}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                  activeSubTab === 'search' || searchQuery.trim().length > 0
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-semibold' 
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Search className="w-3 h-3 text-cyan-400" />
                <span>Search Index ({searchResults.length})</span>
              </button>
            </div>

            {/* Live Search Input with Clear Button */}
            <div className="relative flex items-center">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5" />
              <input
                type="text"
                placeholder={searchScope === 'all' ? "Search across all scripts..." : "Search flags & modules..."}
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  if (activeSubTab === 'code' && e.target.value.trim().length > 0) {
                    // keep in code view if finding in file, or switch to search if clicking tab
                  }
                }}
                className="bg-slate-950 border border-slate-800 rounded-md pl-8 pr-7 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500 w-full sm:w-64"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2 text-slate-500 hover:text-slate-300"
                  title="Clear search"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>

        {/* SEARCH INDEX TOOLBAR (Shown when in search tab or when query is active) */}
        {(activeSubTab === 'search' || searchQuery.trim().length > 0) && (
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              {/* Scope Switch: Active vs All Scripts */}
              <div className="flex items-center space-x-1 p-1 bg-slate-950 rounded-lg border border-slate-800/80">
                <button
                  onClick={() => setSearchScope('active')}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    searchScope === 'active'
                      ? 'bg-slate-800 text-cyan-300 shadow-sm border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Active Script ({selectedItem.name})
                </button>
                <button
                  onClick={() => setSearchScope('all')}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                    searchScope === 'all'
                      ? 'bg-slate-800 text-cyan-300 shadow-sm border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  All Scripts ({SCRIPT_CATALOG.length} Tools)
                </button>
              </div>

              {/* Match Stats */}
              <div className="text-xs text-slate-400 flex items-center space-x-2">
                <span>
                  Showing <strong className="text-slate-200">{searchResults.length}</strong> matching modules
                </span>
                {searchQuery && (
                  <span className="text-slate-500">
                    for &ldquo;<strong className="text-cyan-400">{searchQuery}</strong>&rdquo;
                  </span>
                )}
              </div>
            </div>

            {/* Category Filter Pills */}
            <div className="flex items-center space-x-2 overflow-x-auto pt-1">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider shrink-0 flex items-center space-x-1">
                <SlidersHorizontal className="w-3 h-3 text-cyan-400" />
                <span>Filter:</span>
              </span>
              {[
                { id: 'all', label: 'All Items' },
                { id: 'security', label: 'Security & Hardening' },
                { id: 'core', label: 'Core / System' },
                { id: 'apps', label: 'Apps & Utilities' },
                { id: 'modifier', label: 'Flags & Modifiers' },
              ].map(cat => (
                <button
                  key={cat.id}
                  onClick={() => setCategoryFilter(cat.id)}
                  className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors shrink-0 ${
                    categoryFilter === cat.id
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                      : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800/80'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* SEARCH RESULTS VIEW (Rendered when Search tab is active or search query present) */}
        {(activeSubTab === 'search' || (searchQuery.trim().length > 0 && activeSubTab !== 'code')) ? (
          <div className="space-y-3">
            {searchResults.length === 0 ? (
              <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center space-y-3">
                <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto" />
                <h4 className="text-sm font-semibold text-slate-200">No matching flags or modules found</h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  No items matched &ldquo;{searchQuery}&rdquo; in {searchScope === 'active' ? selectedItem.name : 'any catalog script'}. 
                  Try searching for keywords like <code className="text-cyan-400">harden</code>, <code className="text-cyan-400">ssh</code>, <code className="text-cyan-400">cve</code>, <code className="text-cyan-400">cosmic</code>, or switch to &ldquo;All Scripts&rdquo;.
                </p>
                <button
                  onClick={() => {
                    setSearchQuery('');
                    setCategoryFilter('all');
                  }}
                  className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition-colors"
                >
                  Reset Search
                </button>
              </div>
            ) : (
              searchResults.map(entry => {
                const isSecurity = entry.type === 'security' || entry.category === 'security';
                const isCopied = copiedFlag === entry.flagSyntax;

                return (
                  <div
                    key={entry.id}
                    className={`p-4 rounded-xl border transition-all space-y-2.5 ${
                      isSecurity
                        ? 'bg-slate-900/90 border-slate-800 hover:border-rose-500/40'
                        : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {/* Header Row */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        {entry.flagSyntax ? (
                          <span className="font-mono text-xs font-bold text-cyan-400 px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                            <HighlightMatch text={entry.flagSyntax} query={searchQuery} />
                          </span>
                        ) : null}

                        <span className="text-xs font-semibold text-slate-200">
                          <HighlightMatch text={entry.title} query={searchQuery} />
                        </span>

                        {isSecurity ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800 font-mono uppercase flex items-center space-x-1">
                            <Shield className="w-3 h-3 text-rose-400" />
                            <span>Security Module</span>
                          </span>
                        ) : entry.category ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono uppercase">
                            {entry.category}
                          </span>
                        ) : null}

                        {searchScope === 'all' && (
                          <button
                            onClick={() => handleSelectScriptFromSearch(entry.scriptId)}
                            className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/40 font-mono hover:bg-cyan-900/40 transition-colors"
                            title="Jump to this script"
                          >
                            Script: {entry.scriptName}
                          </button>
                        )}
                      </div>

                      {/* Action buttons */}
                      <div className="flex items-center space-x-1.5 shrink-0">
                        {entry.flagSyntax && (
                          <button
                            onClick={() => handleCopyFlag(entry.flagSyntax!)}
                            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono border border-slate-700 transition-colors"
                            title="Copy flag syntax"
                          >
                            {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
                            <span>{isCopied ? 'Copied' : 'Copy'}</span>
                          </button>
                        )}

                        <button
                          onClick={() => handleRunFlagInSimulation(entry)}
                          className="flex items-center space-x-1 px-2.5 py-1 rounded bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 text-[11px] font-medium border border-cyan-500/30 transition-colors"
                          title="Simulate this module in Terminal"
                        >
                          <Play className="w-3 h-3 text-cyan-400" />
                          <span>Simulate</span>
                        </button>
                      </div>
                    </div>

                    {/* Description */}
                    <p className="text-xs text-slate-400 leading-relaxed">
                      <HighlightMatch text={entry.description} query={searchQuery} />
                    </p>

                    {/* Warning Note if present */}
                    {entry.warningNote && (
                      <div className="p-2 rounded-lg bg-rose-950/30 border border-rose-900/40 flex items-start space-x-2 text-xs text-rose-300">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                        <span>
                          <HighlightMatch text={entry.warningNote} query={searchQuery} />
                        </span>
                      </div>
                    )}

                    {/* Associated Software Chips */}
                    {entry.associatedSoftware && entry.associatedSoftware.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1 pt-1">
                        <span className="text-[10px] text-slate-500 font-mono">Packages:</span>
                        {entry.associatedSoftware.map(app => (
                          <span key={app} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 font-mono">
                            <HighlightMatch text={app} query={searchQuery} />
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        ) : (
          <>
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
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Command-Line Flags Reference</h4>
                  <span className="text-xs text-slate-500 font-mono">{selectedItem.flags.length} total flags</span>
                </div>
                <div className="space-y-3">
                  {selectedItem.flags.map(f => (
                    <div key={f.flag} className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                          <span className="font-mono text-xs font-bold text-cyan-400">{f.flag}</span>
                          <span className="text-xs font-semibold text-slate-200">{f.name}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono uppercase">
                            {f.category}
                          </span>
                        </div>
                        <button
                          onClick={() => handleCopyFlag(f.flag)}
                          className="flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono border border-slate-700 transition-colors"
                        >
                          {copiedFlag === f.flag ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
                          <span>{copiedFlag === f.flag ? 'Copied' : 'Copy'}</span>
                        </button>
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
          </>
        )}
      </div>
    </div>
  );
};
