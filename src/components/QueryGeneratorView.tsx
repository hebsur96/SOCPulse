import React, { useState } from 'react';
import {
  Zap,
  Sparkles,
  AlertCircle,
  RotateCcw,
} from 'lucide-react';
import { DetectionBreakdown, SiemPlatformId, UserRole } from '../types';
import { SIEM_PLATFORMS, SIEM_PLATFORM_LIST } from '../data/siemPlatforms';
import { DetectionBreakdownCard } from './DetectionBreakdownCard';

interface QueryGeneratorViewProps {
  selectedPlatform: SiemPlatformId;
  onPlatformChange: (platform: SiemPlatformId) => void;
  onExport: (detection: DetectionBreakdown) => void;
  initialPrompt?: string;
  userRole?: UserRole;
}

const SAMPLE_PROMPTS = [
  'Detect LSASS memory dumping using Mimikatz or ProcDump',
  'Find ransomware volume shadow copy deletion via vssadmin',
  'Kerberoasting SPN ticket request with weak RC4 encryption',
  'Detect encoded PowerShell command execution using -enc',
  'Certutil downloading remote executable payloads from unknown IPs',
  'AWS unauthorized IAM Policy attachment to admin role',
  'Detect SSH brute force success after 10 failed logins',
];

export const QueryGeneratorView: React.FC<QueryGeneratorViewProps> = ({
  selectedPlatform,
  onPlatformChange,
  onExport,
  initialPrompt,
}) => {
  const [prompt, setPrompt] = useState(initialPrompt || 'Detect LSASS memory dumping using Mimikatz or ProcDump');
  const [timeFrame, setTimeFrame] = useState('24h');
  const [severity, setSeverity] = useState('High');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detectionResult, setDetectionResult] = useState<DetectionBreakdown | null>(null);

  const handleGenerate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!prompt.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/generate-detection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userPrompt: prompt,
          targetPlatform: selectedPlatform,
          timeFrame,
          severity,
        }),
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data = await res.json();
      setDetectionResult(data);
    } catch (err: any) {
      console.error('Generation error:', err);
      setError('Failed to generate detection query. Using local fallback.');
    } finally {
      setLoading(false);
    }
  };

  const currentPlatformMeta = SIEM_PLATFORMS[selectedPlatform] || SIEM_PLATFORMS.sentinel;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Intro Banner */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl relative overflow-hidden">
        <div className="max-w-3xl space-y-2 relative z-10">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>AI SIEM Detection Engineer</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-extrabold text-white tracking-tight font-mono">
            Natural Language to Production SIEM Queries
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed font-sans">
            Describe any threat scenario, behavior, or MITRE technique in plain English. Get production-ready, highly optimized queries for 11 SIEM platforms complete with 10-point SOC detection breakdown, tuning guides, and pivot queries.
          </p>
        </div>
      </div>

      {/* Input Generator Form */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-2xl">
        <form onSubmit={handleGenerate} className="space-y-4">
          <div className="space-y-2">
            <label className="text-xs font-mono text-cyan-300 font-semibold flex items-center justify-between">
              <span>Threat Scenario / Detection Objective:</span>
              <span className="text-slate-400 text-[11px]">Supports KQL, SPL, AQL, XQL, YARA-L & 6 more</span>
            </label>
            <textarea
              id="input-threat-prompt"
              rows={3}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="e.g. Detect LSASS memory dumping via comsvcs.dll or ProcDump, or PowerShell downloading remote payloads..."
              className="w-full bg-[#060D18] text-slate-100 font-mono text-xs rounded-xl border border-[#1B3047] p-3.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500 transition-all placeholder:text-slate-600"
            />
          </div>

          {/* Quick Sample Prompts */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-mono text-slate-400">Quick SOC Scenarios:</div>
            <div className="flex flex-wrap gap-1.5">
              {SAMPLE_PROMPTS.map((sp, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setPrompt(sp)}
                  className="px-2.5 py-1 rounded-lg bg-[#060D18] hover:bg-[#101F32] border border-[#1B3047] hover:border-cyan-500/40 text-[11px] text-slate-300 hover:text-cyan-300 font-mono transition-all text-left cursor-pointer"
                >
                  {sp}
                </button>
              ))}
            </div>
          </div>

          {/* Controls: SIEM Engine, Timeframe, Severity */}
          <div className="pt-2 grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] font-mono text-slate-400 mb-1 block">Target SIEM Engine:</label>
              <select
                id="select-target-siem-engine"
                value={selectedPlatform}
                onChange={(e) => onPlatformChange(e.target.value as SiemPlatformId)}
                className="w-full bg-[#060D18] text-slate-100 font-mono text-xs border border-[#1B3047] rounded-lg p-2 focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                {SIEM_PLATFORM_LIST.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.language.split(' ')[0]})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 mb-1 block">Search Timeframe:</label>
              <select
                id="select-search-timeframe"
                value={timeFrame}
                onChange={(e) => setTimeFrame(e.target.value)}
                className="w-full bg-[#060D18] text-slate-200 font-mono text-xs border border-[#1B3047] rounded-lg p-2 focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value="1h">Last 1 Hour (Real-time)</option>
                <option value="24h">Last 24 Hours (Standard)</option>
                <option value="7d">Last 7 Days (Threat Hunt)</option>
                <option value="30d">Last 30 Days (Historical)</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 mb-1 block">Target Severity:</label>
              <select
                id="select-target-severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="w-full bg-[#060D18] text-slate-200 font-mono text-xs border border-[#1B3047] rounded-lg p-2 focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value="Critical">Critical (P1)</option>
                <option value="High">High (P2)</option>
                <option value="Medium">Medium (P3)</option>
                <option value="Low">Low (P4)</option>
              </select>
            </div>
          </div>

          {/* Action Button */}
          <div className="pt-3 flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono hidden sm:inline">
              Engine: <strong className="text-cyan-300">{currentPlatformMeta.name}</strong> ({currentPlatformMeta.language})
            </span>

            <button
              id="btn-generate-detection"
              type="submit"
              disabled={loading}
              className="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-[#060D18] font-mono font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/10 transition-all cursor-pointer"
            >
              {loading ? (
                <>
                  <RotateCcw className="w-4 h-4 animate-spin text-[#060D18]" />
                  <span>Analyzing SOC Telemetry & Generating Query...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 text-[#060D18]" />
                  <span>Generate Production SIEM Query</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Error state */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 p-4 rounded-xl text-xs font-mono flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Detection Result Card with 10 Points */}
      {detectionResult && (
        <DetectionBreakdownCard
          detection={detectionResult}
          onExport={onExport}
          onTranslateToPlatform={(targetPlat) => {
            onPlatformChange(targetPlat);
            handleGenerate();
          }}
        />
      )}
    </div>
  );
};
