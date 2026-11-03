import React, { useState } from 'react';
import { 
  Shield, FileCheck, Layers, AlertTriangle, ArrowRight, Copy, Check, 
  Terminal, Database, HardDrive, CheckCircle2, Lock, FileCode, Play
} from 'lucide-react';

interface PlanRow {
  sourceFile: string;
  targetFile: string;
  sizeBytes: number;
  sha256Source: string;
  sha256Target: string;
  status: 'TRUE_DUPLICATE_PRUNE' | 'COPY_UNIQUE' | 'CONTENT_COLLISION_RESOLVE' | 'REPARSE_POINT_SKIP';
}

const SAMPLE_CSV_PLAN: PlanRow[] = [
  {
    sourceFile: 'D:\\Backups_2023\\User\\Documents\\Tax2022.pdf',
    targetFile: 'C:\\Users\\ZSchmalz\\Documents\\Tax2022.pdf',
    sizeBytes: 1482012,
    sha256Source: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    sha256Target: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    status: 'TRUE_DUPLICATE_PRUNE'
  },
  {
    sourceFile: 'D:\\Backups_2023\\User\\Pictures\\Vacation2023_01.jpg',
    targetFile: 'C:\\Users\\ZSchmalz\\Pictures\\Vacation2023_01.jpg',
    sizeBytes: 5242880,
    sha256Source: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
    sha256Target: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
    status: 'TRUE_DUPLICATE_PRUNE'
  },
  {
    sourceFile: 'D:\\Backups_2023\\User\\Desktop\\Client_Proposal_v2.docx',
    targetFile: 'C:\\Users\\ZSchmalz\\Desktop\\Client_Proposal_v2.docx',
    sizeBytes: 842100,
    sha256Source: '7d793037a0760186574b0282f2f435e7090a6ff8bf5ecf81d113ae8a03290e50',
    sha256Target: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2',
    status: 'CONTENT_COLLISION_RESOLVE'
  },
  {
    sourceFile: 'D:\\Backups_2023\\User\\Projects\\HardwareConfig.json',
    targetFile: 'C:\\Users\\ZSchmalz\\Projects\\HardwareConfig.json',
    sizeBytes: 3120,
    sha256Source: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    sha256Target: 'NONE (Target does not exist)',
    status: 'COPY_UNIQUE'
  },
  {
    sourceFile: 'D:\\Backups_2023\\User\\OneDrive',
    targetFile: 'C:\\Users\\ZSchmalz\\OneDrive',
    sizeBytes: 0,
    sha256Source: 'REPARSE_POINT_JUNCTION',
    sha256Target: 'REPARSE_POINT_JUNCTION',
    status: 'REPARSE_POINT_SKIP'
  }
];

export const ProfileMergeTool: React.FC = () => {
  const [sourcePath, setSourcePath] = useState<string>('D:\\Old_Backups\\UserProfile_2023');
  const [destPath, setDestPath] = useState<string>('C:\\Users\\ZSchmalz');
  const [stateFilePath, setStateFilePath] = useState<string>('C:\\Scripts\\ProfileMerge_Plan.csv');
  const [autoPrune, setAutoPrune] = useState<boolean>(true);
  const [copiedPlanCmd, setCopiedPlanCmd] = useState<boolean>(false);
  const [copiedApplyCmd, setCopiedApplyCmd] = useState<boolean>(false);
  const [filterStatus, setFilterStatus] = useState<string>('all');

  const planCmd = `powershell.exe -ExecutionPolicy Bypass -File .\\Windows\\Data_Management\\ProfileMerge.ps1 -Plan -SourcePath "${sourcePath}" -DestinationPath "${destPath}" -StateFilePath "${stateFilePath}"`;
  
  const applyCmd = `powershell.exe -ExecutionPolicy Bypass -File .\\Windows\\Data_Management\\ProfileMerge.ps1 -Apply -StateFilePath "${stateFilePath}"${autoPrune ? ' -AutoPruneDuplicates' : ''}`;

  const copyPlan = () => {
    navigator.clipboard.writeText(planCmd);
    setCopiedPlanCmd(true);
    setTimeout(() => setCopiedPlanCmd(false), 2000);
  };

  const copyApply = () => {
    navigator.clipboard.writeText(applyCmd);
    setCopiedApplyCmd(true);
    setTimeout(() => setCopiedApplyCmd(false), 2000);
  };

  const filteredRows = SAMPLE_CSV_PLAN.filter(r => {
    if (filterStatus === 'all') return true;
    return r.status === filterStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-md space-y-2">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-100">Windows ProfileMerge & Cryptographic Deduplication</h2>
            <p className="text-xs text-slate-400">
              State-driven engine for cross-OS NTFS profile consolidation with Destination Memory Shield and SHA-256 validation.
            </p>
          </div>
        </div>
      </div>

      {/* Safety Architecture Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        {[
          {
            title: '1. Destination Memory Shield',
            desc: 'Locks target folder boundaries in RAM to prevent accidental self-overwrites or recursive loops.',
            icon: Shield,
            color: 'text-cyan-400'
          },
          {
            title: '2. Live Profile Protection',
            desc: 'Detects and denies mutations against actively mounted Windows session registry hives and NTUSER.dat.',
            icon: Lock,
            color: 'text-amber-400'
          },
          {
            title: '3. Reparse Point Detachment',
            desc: 'Leverages native .NET APIs to safely navigate OneDrive junctions without PS 5.1 recursion crashes.',
            icon: Layers,
            color: 'text-emerald-400'
          },
          {
            title: '4. SHA-256 Cryptography',
            desc: 'Files are only pruned if cryptographic hashes match 100%. Collision detection protects updated revisions.',
            icon: FileCheck,
            color: 'text-purple-400'
          }
        ].map(item => {
          const Icon = item.icon;
          return (
            <div key={item.title} className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
              <div className="flex items-center space-x-2">
                <Icon className={`w-4 h-4 ${item.color}`} />
                <h3 className="font-semibold text-xs text-slate-200">{item.title}</h3>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">{item.desc}</p>
            </div>
          );
        })}
      </div>

      {/* Two-Phase Configuration */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Phase 1: -Plan */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center space-x-1.5 font-mono">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>Phase 1: -Plan (Read-Only Analysis)</span>
            </span>
            <span className="text-[11px] text-slate-500 font-mono">Zero Disk Mutations</span>
          </div>

          <div className="space-y-3">
            <div className="space-y-1">
              <label className="text-[11px] text-slate-400">Scattered Backup Source Path</label>
              <input
                type="text"
                value={sourcePath}
                onChange={(e) => setSourcePath(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[11px] text-slate-400">Unified Target Profile Path</label>
              <input
                type="text"
                value={destPath}
                onChange={(e) => setDestPath(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[11px] text-slate-400">Output CSV Plan File Location</label>
              <input
                type="text"
                value={stateFilePath}
                onChange={(e) => setStateFilePath(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
              />
            </div>
          </div>

          <div className="pt-2">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 break-all">
              {planCmd}
            </div>
            <button
              onClick={copyPlan}
              className="mt-2 w-full flex items-center justify-center space-x-2 py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs transition-colors"
            >
              {copiedPlanCmd ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedPlanCmd ? 'Copied Plan Command!' : 'Copy Phase 1 Command'}</span>
            </button>
          </div>
        </div>

        {/* Phase 2: -Apply */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center space-x-1.5 font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>Phase 2: -Apply (Filesystem Mutations)</span>
            </span>
            <span className="text-[11px] text-slate-500 font-mono">State Ingestion</span>
          </div>

          <div className="space-y-3">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 space-y-2">
              <p>
                In Phase 2, the engine ingests the verified CSV state plan generated in Phase 1 and applies moves, deduplication, and file merges.
              </p>
              <label className="flex items-start space-x-2.5 pt-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoPrune}
                  onChange={(e) => setAutoPrune(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-900 border-slate-700 text-emerald-600 focus:ring-0"
                />
                <div className="space-y-0.5">
                  <span className="font-mono text-xs font-bold text-emerald-300">-AutoPruneDuplicates</span>
                  <p className="text-[11px] text-slate-500">
                    Authorizes the safe removal of true duplicate source files whose SHA-256 hashes match target files bit-for-bit.
                  </p>
                </div>
              </label>
            </div>
          </div>

          <div className="pt-2">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 break-all">
              {applyCmd}
            </div>
            <button
              onClick={copyApply}
              className="mt-2 w-full flex items-center justify-center space-x-2 py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors"
            >
              {copiedApplyCmd ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedApplyCmd ? 'Copied Apply Command!' : 'Copy Phase 2 Command'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* CSV State Plan Simulator Table */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Deterministic CSV State Plan Preview
            </h3>
          </div>

          <div className="flex items-center space-x-1.5 text-xs">
            <span className="text-slate-500">Filter Status:</span>
            {[
              { id: 'all', label: 'All' },
              { id: 'TRUE_DUPLICATE_PRUNE', label: 'Duplicates' },
              { id: 'COPY_UNIQUE', label: 'Unique' },
              { id: 'CONTENT_COLLISION_RESOLVE', label: 'Collisions' }
            ].map(f => (
              <button
                key={f.id}
                onClick={() => setFilterStatus(f.id)}
                className={`px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                  filterStatus === f.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-[#090d16]">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900 text-slate-400 text-[11px] uppercase border-b border-slate-800">
              <tr>
                <th className="p-3">Source File</th>
                <th className="p-3">Size</th>
                <th className="p-3">SHA-256 Hash Comparison</th>
                <th className="p-3">Plan Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredRows.map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30">
                  <td className="p-3 text-slate-300 max-w-xs truncate" title={row.sourceFile}>
                    {row.sourceFile}
                  </td>
                  <td className="p-3 text-slate-400 whitespace-nowrap">
                    {(row.sizeBytes / 1024 / 1024).toFixed(2)} MB
                  </td>
                  <td className="p-3 text-slate-400 text-[10px]">
                    <div className="truncate max-w-xs text-cyan-300" title={row.sha256Source}>
                      SRC: {row.sha256Source.slice(0, 16)}...
                    </div>
                    <div className="truncate max-w-xs text-slate-500" title={row.sha256Target}>
                      TGT: {row.sha256Target.slice(0, 16)}...
                    </div>
                  </td>
                  <td className="p-3 whitespace-nowrap">
                    {row.status === 'TRUE_DUPLICATE_PRUNE' && (
                      <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px]">
                        Safe Prune (Identical)
                      </span>
                    )}
                    {row.status === 'COPY_UNIQUE' && (
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px]">
                        Copy to Target
                      </span>
                    )}
                    {row.status === 'CONTENT_COLLISION_RESOLVE' && (
                      <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px]">
                        Collision (Requires Review)
                      </span>
                    )}
                    {row.status === 'REPARSE_POINT_SKIP' && (
                      <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px]">
                        Reparse Point Detached
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
