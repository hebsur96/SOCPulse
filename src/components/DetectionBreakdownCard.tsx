import React, { useState } from 'react';
import {
  Check,
  Copy,
  ShieldCheck,
  Zap,
  AlertTriangle,
  Sliders,
  Search,
  Database,
  Gauge,
  Code2,
  FileCheck,
  Download,
  Terminal,
  Info,
} from 'lucide-react';
import { DetectionBreakdown, SiemPlatformId } from '../types';
import { SIEM_PLATFORMS } from '../data/siemPlatforms';

interface DetectionBreakdownCardProps {
  detection: DetectionBreakdown;
  onExport: (detection: DetectionBreakdown) => void;
  onTranslateToPlatform: (platform: SiemPlatformId) => void;
}

export const DetectionBreakdownCard: React.FC<DetectionBreakdownCardProps> = ({
  detection,
  onExport,
  onTranslateToPlatform,
}) => {
  const [copiedQuery, setCopiedQuery] = useState(false);
  const [activeTab, setActiveTab] = useState<'query' | 'mitre' | 'tuning' | 'investigate' | 'performance' | 'matrix'>('query');

  const handleCopyQuery = (textToCopy: string) => {
    navigator.clipboard.writeText(textToCopy);
    setCopiedQuery(true);
    setTimeout(() => setCopiedQuery(false), 2000);
  };

  const platformMeta = SIEM_PLATFORMS[detection.targetPlatform] || SIEM_PLATFORMS.sentinel;

  return (
    <div className="bg-[#0B1726] border border-[#1B3047] rounded-2xl overflow-hidden shadow-2xl transition-all">
      {/* Header Banner */}
      <div className="bg-[#07111F] px-6 py-4 border-b border-[#1B3047] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className={`text-xs px-2.5 py-0.5 rounded-md font-mono font-medium border ${platformMeta.badgeColor}`}>
                {platformMeta.name}
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-[#101F32] border border-[#1B3047] text-cyan-300 font-mono">
                {detection.syntaxCompatibility.dialectVersion}
              </span>
            </div>
            <h2 className="text-base font-semibold text-white mt-1 font-mono">
              Detection Rule #{detection.id.slice(-6)}
            </h2>
          </div>
        </div>

        {/* Export & Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            id="btn-copy-main-query"
            onClick={() => handleCopyQuery(detection.query)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#101F32] hover:bg-[#15273e] border border-[#1B3047] text-xs text-slate-200 hover:text-cyan-300 font-mono transition-colors cursor-pointer"
          >
            {copiedQuery ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedQuery ? 'Copied!' : 'Copy Query'}
          </button>

          <button
            id="btn-export-rule"
            onClick={() => onExport(detection)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-semibold text-xs font-mono transition-colors shadow-lg shadow-cyan-500/10 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Rule
          </button>
        </div>
      </div>

      {/* 10-Point Analysis Navigation Tabs */}
      <div className="bg-[#07111F]/70 px-6 border-b border-[#1B3047] flex overflow-x-auto gap-1 text-xs font-mono no-scrollbar">
        <button
          onClick={() => setActiveTab('query')}
          className={`py-3 px-3 border-b-2 font-medium flex items-center gap-2 transition-all whitespace-nowrap cursor-pointer ${
            activeTab === 'query'
              ? 'border-cyan-400 text-cyan-300 bg-[#0B1726]'
              : 'border-transparent text-slate-400 hover:text-cyan-300'
          }`}
        >
          <Code2 className="w-4 h-4" />
          1. Production Query & Logic
        </button>
        <button
          onClick={() => setActiveTab('mitre')}
          className={`py-3 px-3 border-b-2 font-medium flex items-center gap-2 transition-all whitespace-nowrap cursor-pointer ${
            activeTab === 'mitre'
              ? 'border-cyan-400 text-cyan-300 bg-[#0B1726]'
              : 'border-transparent text-slate-400 hover:text-cyan-300'
          }`}
        >
          <Zap className="w-4 h-4 text-teal-400" />
          2. MITRE ATT&CK Mapping
        </button>
        <button
          onClick={() => setActiveTab('tuning')}
          className={`py-3 px-3 border-b-2 font-medium flex items-center gap-2 transition-all whitespace-nowrap cursor-pointer ${
            activeTab === 'tuning'
              ? 'border-cyan-400 text-cyan-300 bg-[#0B1726]'
              : 'border-transparent text-slate-400 hover:text-cyan-300'
          }`}
        >
          <Sliders className="w-4 h-4 text-cyan-400" />
          3. Tuning & Noise Reduction
        </button>
        <button
          onClick={() => setActiveTab('investigate')}
          className={`py-3 px-3 border-b-2 font-medium flex items-center gap-2 transition-all whitespace-nowrap cursor-pointer ${
            activeTab === 'investigate'
              ? 'border-cyan-400 text-cyan-300 bg-[#0B1726]'
              : 'border-transparent text-slate-400 hover:text-cyan-300'
          }`}
        >
          <Search className="w-4 h-4 text-cyan-400" />
          4. Investigation Pivots
        </button>
        <button
          onClick={() => setActiveTab('performance')}
          className={`py-3 px-3 border-b-2 font-medium flex items-center gap-2 transition-all whitespace-nowrap cursor-pointer ${
            activeTab === 'performance'
              ? 'border-cyan-400 text-cyan-300 bg-[#0B1726]'
              : 'border-transparent text-slate-400 hover:text-cyan-300'
          }`}
        >
          <Gauge className="w-4 h-4 text-teal-400" />
          5. Performance & Assumptions
        </button>
        <button
          onClick={() => setActiveTab('matrix')}
          className={`py-3 px-3 border-b-2 font-medium flex items-center gap-2 transition-all whitespace-nowrap cursor-pointer ${
            activeTab === 'matrix'
              ? 'border-cyan-400 text-cyan-300 bg-[#0B1726]'
              : 'border-transparent text-slate-400 hover:text-cyan-300'
          }`}
        >
          <Terminal className="w-4 h-4 text-cyan-400" />
          6. Multi-SIEM Matrix
        </button>
      </div>

      {/* Tab Contents */}
      <div className="p-6 font-mono text-xs">
        {/* TAB 1: Query & Detection Logic */}
        {activeTab === 'query' && (
          <div className="space-y-6">
            {/* Intent & Target */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047]">
                <div className="text-cyan-400 mb-1 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Point 1: User Detection Intent</span>
                </div>
                <p className="text-slate-200 font-sans leading-relaxed">{detection.userIntent}</p>
              </div>

              <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047]">
                <div className="text-cyan-400 mb-1 flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Point 2: Target SIEM Platform & Field Schema</span>
                </div>
                <div className="text-slate-200 space-y-1">
                  <div className="font-semibold text-cyan-300">{platformMeta.name} ({platformMeta.language})</div>
                  <div className="text-slate-400">Target Tables: {platformMeta.defaultTable}</div>
                </div>
              </div>
            </div>

            {/* Production Query Box */}
            <div className="bg-[#060D18] rounded-xl border border-[#1B3047] overflow-hidden">
              <div className="bg-[#101F32] px-4 py-2 border-b border-[#1B3047] flex items-center justify-between text-slate-400 text-[11px]">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
                  <span className="text-cyan-300 font-bold">Point 3: Production-Ready {platformMeta.language} Query</span>
                </div>
                <button
                  onClick={() => handleCopyQuery(detection.query)}
                  className="hover:text-cyan-300 flex items-center gap-1 text-[11px] text-slate-400 cursor-pointer"
                >
                  <Copy className="w-3 h-3 text-cyan-400" />
                  Copy Raw Code
                </button>
              </div>
              <pre className="p-4 text-cyan-200 bg-[#060D18] overflow-x-auto font-mono text-xs leading-relaxed whitespace-pre">
                <code>{detection.query}</code>
              </pre>
            </div>

            {/* Point 4: Detection Logic Explanation */}
            <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047]">
              <h3 className="text-sm font-bold text-white mb-2 flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-cyan-400" />
                Point 4: Step-by-Step Detection Logic Breakdown
              </h3>
              <p className="text-slate-300 font-sans leading-relaxed whitespace-pre-line">
                {detection.detectionLogic}
              </p>
            </div>
          </div>
        )}

        {/* TAB 2: MITRE ATT&CK */}
        {activeTab === 'mitre' && (
          <div className="space-y-6">
            <div className="bg-[#060D18] p-5 rounded-xl border border-[#1B3047]">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-cyan-400 font-semibold mb-1 flex items-center gap-2 text-sm">
                    <Zap className="w-4 h-4 text-teal-400" />
                    Point 5: MITRE ATT&CK Framework Mapping
                  </div>
                  <h3 className="text-base font-bold text-white font-sans">
                    {detection.mitreMapping.techniqueId}: {detection.mitreMapping.techniqueName}
                  </h3>
                  {detection.mitreMapping.subTechniqueId && (
                    <div className="text-xs text-teal-300 mt-0.5">
                      Sub-technique: {detection.mitreMapping.subTechniqueId} - {detection.mitreMapping.subTechniqueName}
                    </div>
                  )}
                </div>

                <span className="px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-xs font-semibold">
                  Tactic: {detection.mitreMapping.tactic}
                </span>
              </div>

              <p className="text-slate-300 font-sans mt-3 text-xs leading-relaxed">
                {detection.mitreMapping.description}
              </p>

              {detection.mitreMapping.threatActors && detection.mitreMapping.threatActors.length > 0 && (
                <div className="mt-4 pt-3 border-t border-[#1B3047] flex items-center gap-2 flex-wrap">
                  <span className="text-slate-400">Associated Threat Actors / Tooling:</span>
                  {detection.mitreMapping.threatActors.map((actor, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-[#101F32] border border-[#1B3047] text-teal-300 text-[11px]">
                      {actor}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: Tuning */}
        {activeTab === 'tuning' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047]">
                <h4 className="font-semibold text-amber-400 mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  False Positives & Triggers
                </h4>
                <ul className="list-disc list-inside space-y-1.5 text-slate-300 font-sans text-xs">
                  {detection.tuning.falsePositives.map((fp, i) => (
                    <li key={i}>{fp}</li>
                  ))}
                </ul>
              </div>

              <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047]">
                <h4 className="font-semibold text-cyan-400 mb-2 flex items-center gap-1.5">
                  <Sliders className="w-4 h-4" />
                  Recommended Whitelisting Filters
                </h4>
                <ul className="list-disc list-inside space-y-1.5 text-slate-300 font-sans text-xs">
                  {detection.tuning.whitelisting.map((wl, i) => (
                    <li key={i}>{wl}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047] flex items-center justify-between">
              <div>
                <span className="text-slate-400">Alert Threshold Guidance:</span>
                <p className="text-slate-200 font-sans mt-1">{detection.tuning.thresholding}</p>
              </div>
              <div className="text-right">
                <span className="text-slate-400">Noise Level</span>
                <div className="text-sm font-bold text-amber-400">
                  {detection.tuning.noiseRating}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: Investigation Queries */}
        {activeTab === 'investigate' && (
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Search className="w-4 h-4 text-cyan-400" />
              Point 7: Incident Response & Threat Hunting Pivot Queries
            </h3>

            {detection.investigationQueries.map((inv) => (
              <div key={inv.id} className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047] space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-cyan-300 font-mono text-xs">{inv.title}</h4>
                  <button
                    onClick={() => handleCopyQuery(inv.query)}
                    className="text-slate-400 hover:text-cyan-300 flex items-center gap-1 text-[11px] cursor-pointer"
                  >
                    <Copy className="w-3 h-3 text-cyan-400" />
                    Copy
                  </button>
                </div>
                <p className="text-slate-400 font-sans text-[11px]">{inv.purpose}</p>
                <pre className="p-3 bg-[#101F32] rounded-lg text-slate-200 font-mono text-[11px] overflow-x-auto whitespace-pre border border-[#1B3047]">
                  <code>{inv.query}</code>
                </pre>
              </div>
            ))}
          </div>
        )}

        {/* TAB 5: Performance & Assumptions */}
        {activeTab === 'performance' && (
          <div className="space-y-4">
            <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047] flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Gauge className="w-4 h-4 text-teal-400" />
                  Point 9: SIEM Performance & Execution Cost Score
                </h3>
                <p className="text-slate-400 font-sans text-xs mt-1">
                  Filtering Order: {detection.performance.filteringOrder}
                </p>
              </div>

              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="text-2xl font-extrabold text-cyan-400">{detection.performance.performanceScore}/100</div>
                  <div className="text-[10px] text-slate-400">Execution Score</div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047]">
                <h4 className="font-semibold text-white mb-2">Point 8: Underlying Schema Assumptions</h4>
                <ul className="list-disc list-inside space-y-1.5 text-slate-300 font-sans text-xs">
                  {detection.assumptions.map((asm, i) => (
                    <li key={i}>{asm}</li>
                  ))}
                </ul>
              </div>

              <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047]">
                <h4 className="font-semibold text-white mb-2">Point 10: Syntax Compatibility Check</h4>
                <div className="space-y-2 text-xs font-sans">
                  <div className="flex items-center gap-2 text-emerald-400">
                    <Check className="w-4 h-4" />
                    <span>{detection.syntaxCompatibility.dialectVersion} Compatible</span>
                  </div>
                  <p className="text-slate-400">{detection.syntaxCompatibility.compatibilityNotes}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 6: Multi-SIEM Matrix */}
        {activeTab === 'matrix' && (
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              Instant Translation to 11 Enterprise SIEM Dialects
            </h3>
            <p className="text-slate-400 font-sans text-xs">
              Click any SIEM platform below to load the translated query into the editor.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {detection.translatedQueries &&
                Object.entries(detection.translatedQueries).map(([platKey, transQuery]) => {
                  const platMeta = SIEM_PLATFORMS[platKey as SiemPlatformId];
                  if (!platMeta) return null;

                  return (
                    <div
                      key={platKey}
                      className="bg-[#060D18] p-3 rounded-xl border border-[#1B3047] hover:border-cyan-500/40 transition-all cursor-pointer"
                      onClick={() => onTranslateToPlatform(platKey as SiemPlatformId)}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-[11px] font-bold ${platMeta.badgeColor} px-2 py-0.5 rounded border`}>
                          {platMeta.name}
                        </span>
                        <span className="text-[10px] text-cyan-400 font-mono">Click to select</span>
                      </div>
                      <pre className="p-2 bg-[#101F32] rounded text-[11px] text-slate-300 font-mono overflow-x-auto truncate border border-[#1B3047]">
                        <code>{transQuery}</code>
                      </pre>
                    </div>
                  );
                })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
