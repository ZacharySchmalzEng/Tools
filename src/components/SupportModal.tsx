import React, { useState } from 'react';
import { 
  X, 
  ExternalLink, 
  Bug, 
  Lightbulb, 
  Copy, 
  Check, 
  ShieldAlert, 
  MessageSquare, 
  Terminal, 
  Info 
} from 'lucide-react';

const GithubIcon: React.FC<{ className?: string }> = ({ className = 'w-5 h-5' }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
    <path d="M9 18c-4.51 2-5-2-7-2" />
  </svg>
);

interface SupportModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeTab?: string;
  activeScriptId?: string;
}

export const SupportModal: React.FC<SupportModalProps> = ({
  isOpen,
  onClose,
  activeTab = 'configurator',
  activeScriptId = 'linux-deployment-tool',
}) => {
  const [copiedDiag, setCopiedDiag] = useState(false);

  if (!isOpen) return null;

  const repoBaseUrl = 'https://github.com/ZacharySchmalzEng/Tools';
  const bugReportUrl = `${repoBaseUrl}/issues/new?labels=bug&template=bug_report.md&title=%5BBUG%5D+`;
  const featureRequestUrl = `${repoBaseUrl}/issues/new?labels=enhancement&template=feature_request.md&title=%5BFEATURE%5D+`;
  const issuesUrl = `${repoBaseUrl}/issues`;

  const diagnosticsMarkdown = `### Environment Diagnostics
- **Repository**: ZacharySchmalzEng/Tools
- **Tool Suite Version**: 2.0 (Production Release)
- **Active Workspace Tab**: \`${activeTab}\`
- **Referenced Script**: \`${activeScriptId}\`
- **Client User Agent**: \`${typeof navigator !== 'undefined' ? navigator.userAgent : 'Unknown'}\`
- **Timestamp**: ${new Date().toISOString()}
- **Issue Category**: [Bug Report / Feature Request]`;

  const handleCopyDiagnostics = () => {
    navigator.clipboard.writeText(diagnosticsMarkdown);
    setCopiedDiag(true);
    setTimeout(() => setCopiedDiag(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 animate-fadeIn">
      <div 
        className="relative bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/50">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <GithubIcon className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                GitHub Support & Community Feedback
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 font-mono">
                  v2.0
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Direct issue submission, feature recommendations, and community triage
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            title="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="overflow-y-auto p-6 space-y-6">
          {/* Explicit SLA & Commitment Advisory Banner */}
          <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-200/90 text-xs leading-relaxed flex items-start space-x-3">
            <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-semibold text-amber-300 block">
                Open Source & Best-Effort Maintenance Policy (No SLAs or Binding Commitments)
              </span>
              <p className="text-slate-300">
                This repository is maintained as an open-source engineering toolkit under the MIT License. Contributions, 
                bug fixes, and feature discussions are handled by the maintainer on a voluntary, best-effort basis. 
                There are <strong>no formal service-level agreements (SLAs)</strong>, guaranteed resolution timelines, 
                or binding engineering roadmap delivery commitments.
              </p>
            </div>
          </div>

          {/* Action Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Bug Report Card */}
            <a
              href={bugReportUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="group p-4 rounded-xl bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/60 hover:border-rose-500/40 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
                    <Bug className="w-4 h-4" />
                  </div>
                  <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                </div>
                <h3 className="text-sm font-semibold text-slate-100 group-hover:text-rose-300 transition-colors">
                  Submit a Bug Report
                </h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  Encountered an execution error, missing package dependency, or permission collision? File a reproducible defect report on GitHub.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center text-xs text-rose-400 font-medium">
                <span>Open GitHub Bug Template</span>
                <span className="ml-1 group-hover:translate-x-0.5 transition-transform">→</span>
              </div>
            </a>

            {/* Feature Request Card */}
            <a
              href={featureRequestUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="group p-4 rounded-xl bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/60 hover:border-cyan-500/40 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                    <Lightbulb className="w-4 h-4" />
                  </div>
                  <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                </div>
                <h3 className="text-sm font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors">
                  Propose a Feature Enhancement
                </h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  Have an idea for a new Linux distribution engine, backup provider, security baseline, or profile migration recipe?
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center text-xs text-cyan-400 font-medium">
                <span>Open Enhancement Template</span>
                <span className="ml-1 group-hover:translate-x-0.5 transition-transform">→</span>
              </div>
            </a>

            {/* Browse All Issues Card */}
            <a
              href={issuesUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="group p-4 rounded-xl bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/60 hover:border-slate-600 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                    <MessageSquare className="w-4 h-4" />
                  </div>
                  <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                </div>
                <h3 className="text-sm font-semibold text-slate-100 group-hover:text-indigo-300 transition-colors">
                  Browse Active Issues & Fixes
                </h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  Search previously closed tickets, known workarounds, ongoing discussions, and verified CVE remediation notes.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center text-xs text-indigo-400 font-medium">
                <span>View Issue Tracker</span>
                <span className="ml-1 group-hover:translate-x-0.5 transition-transform">→</span>
              </div>
            </a>

            {/* Main Repository Card */}
            <a
              href={repoBaseUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="group p-4 rounded-xl bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/60 hover:border-slate-600 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="w-8 h-8 rounded-lg bg-slate-700/40 border border-slate-600/40 flex items-center justify-center text-slate-300">
                    <GithubIcon className="w-4 h-4" />
                  </div>
                  <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                </div>
                <h3 className="text-sm font-semibold text-slate-100 group-hover:text-slate-200 transition-colors">
                  ZacharySchmalzEng/Tools Home
                </h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  Inspect the source code, raw shell scripts, CI workflows, and documentation directly on GitHub.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center text-xs text-slate-300 font-medium">
                <span>Visit Main Repository</span>
                <span className="ml-1 group-hover:translate-x-0.5 transition-transform">→</span>
              </div>
            </a>
          </div>

          {/* Diagnostics Copy Helper */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-xs font-semibold text-slate-300">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Quick Diagnostic Context for Your Issue</span>
              </div>
              <button
                onClick={handleCopyDiagnostics}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 transition-colors"
                title="Copy formatted markdown to clipboard"
              >
                {copiedDiag ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-slate-400" />
                    <span>Copy Markdown</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400 overflow-x-auto whitespace-pre leading-relaxed">
              {diagnosticsMarkdown}
            </pre>
            <div className="flex items-center space-x-1.5 text-[11px] text-slate-500">
              <Info className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span>Paste this block directly into your GitHub issue description to assist triage.</span>
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <span className="text-xs text-slate-500">
            Licensed under the MIT License • Best-effort community triage
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
