import React, { useState } from 'react';
import { RefreshCw, Copy, Check, ArrowRight, Code2, Sparkles, Terminal } from 'lucide-react';
import { SiemPlatformId, UserRole } from '../types';
import { SIEM_PLATFORMS, SIEM_PLATFORM_LIST } from '../data/siemPlatforms';

interface MultiPlatformTranslatorViewProps {
  initialQuery?: string;
  initialSourcePlatform?: SiemPlatformId;
  userRole?: UserRole;
}

export const MultiPlatformTranslatorView: React.FC<MultiPlatformTranslatorViewProps> = ({
  initialQuery,
  initialSourcePlatform,
  userRole = 'visitor',
}) => {
  const [sourcePlatform, setSourcePlatform] = useState<SiemPlatformId>(initialSourcePlatform || 'sentinel');
  const [targetPlatform, setTargetPlatform] = useState<SiemPlatformId>('splunk');
  const [sourceQuery, setSourceQuery] = useState(
    initialQuery ||
      `SecurityEvent\n| where EventID == 4688\n| where ProcessName endswith "powershell.exe"\n| where CommandLine has_any ("-enc", "-encodedcommand")\n| project TimeGenerated, Computer, Account, CommandLine`
  );
  const [translatedQuery, setTranslatedQuery] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleTranslate = async () => {
    if (!sourceQuery.trim()) return;
    setLoading(true);

    try {
      const res = await fetch('/api/translate-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sourceQuery,
          sourcePlatform,
          targetPlatform,
        }),
      });

      const data = await res.json();
      setTranslatedQuery(data.translatedQuery);
    } catch (err) {
      console.error('Translation error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!translatedQuery) return;
    navigator.clipboard.writeText(translatedQuery);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const sourceMeta = SIEM_PLATFORMS[sourcePlatform];
  const targetMeta = SIEM_PLATFORMS[targetPlatform];

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Title Header */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
          <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
          <span>Cross-SIEM Query Dialect Translator</span>
        </div>
        <h2 className="text-xl font-bold text-white">
          Translate Query Between Any 2 SIEM Engines
        </h2>
        <p className="text-slate-400 font-sans text-xs leading-relaxed">
          Instantly convert KQL, SPL, AQL, XQL, YARA-L, and EQL queries with exact field mappings, table schemas, and operator translations.
        </p>
      </div>

      {/* Platform Pickers Row */}
      <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] flex flex-wrap items-center justify-between gap-4">
        {/* Source Platform */}
        <div className="flex-1 min-w-[220px] space-y-1">
          <label className="text-[11px] text-slate-400">Source SIEM Dialect:</label>
          <select
            id="select-source-platform"
            value={sourcePlatform}
            onChange={(e) => setSourcePlatform(e.target.value as SiemPlatformId)}
            className="w-full bg-[#060D18] text-slate-100 font-mono text-xs border border-[#1B3047] rounded-lg p-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
          >
            {SIEM_PLATFORM_LIST.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.language})
              </option>
            ))}
          </select>
        </div>

        {/* Swap Arrow Icon */}
        <div className="hidden sm:flex items-center justify-center p-2 text-slate-500">
          <ArrowRight className="w-5 h-5 text-cyan-400" />
        </div>

        {/* Target Platform */}
        <div className="flex-1 min-w-[220px] space-y-1">
          <label className="text-[11px] text-slate-400">Target SIEM Dialect:</label>
          <select
            id="select-target-platform"
            value={targetPlatform}
            onChange={(e) => setTargetPlatform(e.target.value as SiemPlatformId)}
            className="w-full bg-[#060D18] text-slate-100 font-mono text-xs border border-[#1B3047] rounded-lg p-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
          >
            {SIEM_PLATFORM_LIST.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.language})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Side-by-side Editors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Source Query Box */}
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden flex flex-col">
          <div className="bg-[#101F32] px-4 py-2.5 border-b border-[#1B3047] flex items-center justify-between">
            <span className="text-slate-200 font-semibold flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              Source: {sourceMeta.name}
            </span>
            <span className="text-[10px] text-slate-400 font-mono">{sourceMeta.language}</span>
          </div>

          <div className="p-4 flex-1 flex flex-col space-y-3">
            <textarea
              id="input-source-query"
              rows={10}
              value={sourceQuery}
              onChange={(e) => setSourceQuery(e.target.value)}
              placeholder="Paste original SIEM query here..."
              className="w-full flex-1 bg-[#060D18] text-cyan-100 font-mono text-xs p-3 rounded-xl border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500 leading-relaxed resize-none"
            />

            <button
              id="btn-trigger-translation"
              onClick={handleTranslate}
              disabled={loading}
              className="w-full py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-[#060D18] font-bold flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/10 cursor-pointer transition-all"
            >
              {loading ? (
                <span>Translating Dialects...</span>
              ) : (
                <>
                  <RefreshCw className="w-4 h-4" />
                  <span>Translate to {targetMeta.name}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Target Query Box */}
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden flex flex-col">
          <div className="bg-[#101F32] px-4 py-2.5 border-b border-[#1B3047] flex items-center justify-between">
            <span className="text-slate-200 font-semibold flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              Target: {targetMeta.name}
            </span>
            {translatedQuery && (
              <button
                id="btn-copy-translated-query"
                onClick={handleCopy}
                className="text-slate-400 hover:text-cyan-300 flex items-center gap-1 text-[11px] cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied!' : 'Copy Translated Code'}
              </button>
            )}
          </div>

          <div className="p-4 flex-1 bg-[#060D18] flex flex-col">
            {translatedQuery ? (
              <pre className="p-4 bg-[#0B1726] text-slate-100 font-mono text-xs leading-relaxed overflow-x-auto whitespace-pre-wrap flex-1 rounded-xl border border-[#1B3047]">
                <code>{translatedQuery}</code>
              </pre>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-400 font-sans text-xs">
                <Sparkles className="w-8 h-8 text-slate-600 mb-2" />
                <p>Click "Translate" to transform your query into {targetMeta.name} syntax.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
