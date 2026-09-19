import React, { useState } from 'react';
import { Terminal, Gauge, AlertTriangle, CheckCircle2, Zap, ArrowRight, Copy, Check } from 'lucide-react';
import { SiemPlatformId, QueryOptimizationResult, UserRole } from '../types';
import { SIEM_PLATFORMS, SIEM_PLATFORM_LIST } from '../data/siemPlatforms';

interface QueryOptimizerViewProps {
  initialQuery?: string;
  initialPlatform?: SiemPlatformId;
  userRole?: UserRole;
}

export const QueryOptimizerView: React.FC<QueryOptimizerViewProps> = ({
  initialQuery,
  initialPlatform,
  userRole = 'visitor',
}) => {
  const [platform, setPlatform] = useState<SiemPlatformId>(initialPlatform || 'sentinel');
  const [rawQuery, setRawQuery] = useState(
    initialQuery ||
      `SecurityEvent\n| where ProcessName contains "powershell"\n| where CommandLine contains "*encoded*"\n| summarize count() by Computer`
  );
  const [result, setResult] = useState<QueryOptimizationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleOptimize = async () => {
    if (!rawQuery.trim()) return;
    setLoading(true);

    try {
      const res = await fetch('/api/optimize-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: rawQuery,
          platform,
        }),
      });

      const data = await res.json();
      setResult(data);
    } catch (err) {
      console.error('Optimizer error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!result?.optimizedQuery) return;
    navigator.clipboard.writeText(result.optimizedQuery);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Intro Header */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
          <Gauge className="w-3.5 h-3.5 text-cyan-400" />
          <span>SIEM Query Performance Linter & Refactoring Engine</span>
        </div>
        <h2 className="text-xl font-bold text-white">
          Analyze Bottlenecks & Optimize Query CPU / Memory Cost
        </h2>
        <p className="text-slate-400 font-sans text-xs leading-relaxed">
          Paste slow or inefficient SIEM queries. Get immediate bottleneck detection for leading wildcards (*term), unindexed regex scans, missing time boundaries, and inefficient joins.
        </p>
      </div>

      {/* Editor & Platform Selector */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <label className="text-slate-300 font-semibold">Select Target Platform:</label>
            <select
              id="select-optimizer-platform"
              value={platform}
              onChange={(e) => setPlatform(e.target.value as SiemPlatformId)}
              className="bg-[#060D18] text-slate-100 font-mono text-xs border border-[#1B3047] rounded-lg p-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
            >
              {SIEM_PLATFORM_LIST.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.language})
                </option>
              ))}
            </select>
          </div>

          <button
            id="btn-run-query-optimizer"
            onClick={handleOptimize}
            disabled={loading}
            className="px-6 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-[#060D18] font-bold flex items-center gap-2 shadow-lg shadow-cyan-500/10 cursor-pointer transition-all"
          >
            {loading ? (
              <span>Analyzing CPU & Index Constraints...</span>
            ) : (
              <>
                <Zap className="w-4 h-4 text-[#060D18]" />
                <span>Analyze & Optimize Query</span>
              </>
            )}
          </button>
        </div>

        <div className="space-y-2">
          <label className="text-slate-400 text-[11px]">Raw / Inefficient Query Input:</label>
          <textarea
            id="input-raw-query-to-optimize"
            rows={5}
            value={rawQuery}
            onChange={(e) => setRawQuery(e.target.value)}
            placeholder="Paste your SIEM query here..."
            className="w-full bg-[#060D18] text-cyan-100 font-mono text-xs p-3.5 rounded-xl border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500 leading-relaxed"
          />
        </div>
      </div>

      {/* Results Display */}
      {result && (
        <div className="space-y-6">
          {/* Performance Comparison Score Card */}
          <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
            <div className="text-center p-4 rounded-xl bg-[#060D18] border border-[#1B3047]">
              <div className="text-xs text-slate-400">Original Speed Score</div>
              <div className="text-3xl font-extrabold text-[#EF4444] mt-1">{result.performanceScoreBefore}/100</div>
              <div className="text-[10px] text-[#EF4444]/80 mt-1">High CPU / Index Scan</div>
            </div>

            <div className="flex flex-col items-center text-cyan-400 font-semibold">
              <ArrowRight className="w-8 h-8 rotate-90 md:rotate-0 text-cyan-400 animate-pulse" />
              <span className="text-[11px] mt-1 text-teal-300">Refactored + Indexed</span>
            </div>

            <div className="text-center p-4 rounded-xl bg-[#060D18] border border-[#1B3047]">
              <div className="text-xs text-slate-400">Optimized Speed Score</div>
              <div className="text-3xl font-extrabold text-[#22C55E] mt-1">{result.performanceScoreAfter}/100</div>
              <div className="text-[10px] text-[#22C55E]/80 mt-1">Indexed & Bounded</div>
            </div>
          </div>

          {/* Bottlenecks Identified */}
          <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] space-y-3">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#F59E0B]" />
              Performance Bottlenecks Identified ({result.bottlenecksFound.length})
            </h3>

            <div className="space-y-2">
              {result.bottlenecksFound.map((item, idx) => (
                <div key={idx} className="bg-[#060D18] p-3.5 rounded-xl border border-[#1B3047] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white text-xs">{item.issue}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        item.severity === 'High' ? 'bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/30' : 'bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30'
                      }`}
                    >
                      Severity: {item.severity}
                    </span>
                  </div>
                  <p className="text-slate-400 font-sans text-xs">{item.fixExplanation}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Optimized Code Output */}
          <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden">
            <div className="bg-[#101F32] px-4 py-3 border-b border-[#1B3047] flex items-center justify-between">
              <span className="text-teal-300 font-semibold flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-teal-400" />
                Refactored & Production-Ready Code
              </span>

              <button
                id="btn-copy-optimized-code"
                onClick={handleCopy}
                className="text-slate-400 hover:text-cyan-300 flex items-center gap-1 text-[11px] cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied!' : 'Copy Code'}
              </button>
            </div>

            <pre className="p-4 bg-[#060D18] text-cyan-100 font-mono text-xs leading-relaxed overflow-x-auto whitespace-pre">
              <code>{result.optimizedQuery}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
