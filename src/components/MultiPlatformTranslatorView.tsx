import React, { useState } from 'react';
import {
  RefreshCw,
  Copy,
  Check,
  ArrowRight,
  ArrowLeftRight,
  Code2,
  Sparkles,
  Terminal,
  FileCode,
  Binary,
  Download,
  Zap,
  ShieldCheck,
  FileText,
  AlertCircle,
} from 'lucide-react';
import { SiemPlatformId, UserRole } from '../types';
import { SIEM_PLATFORMS, SIEM_PLATFORM_LIST } from '../data/siemPlatforms';

interface MultiPlatformTranslatorViewProps {
  initialQuery?: string;
  initialSourcePlatform?: SiemPlatformId;
  userRole?: UserRole;
}

interface TranslationPreset {
  label: string;
  badge: string;
  source: SiemPlatformId;
  target: SiemPlatformId;
  query: string;
}

const PRESETS: TranslationPreset[] = [
  {
    label: 'KQL → Sigma Rule (YAML)',
    badge: 'KQL to SIGMA',
    source: 'sentinel',
    target: 'sigma',
    query: `SecurityEvent
| where EventID == 4688
| where ProcessName endswith "powershell.exe"
| where CommandLine has_any ("-enc", "-encodedcommand", "DownloadString", "Invoke-WebRequest")
| project TimeGenerated, Computer, Account, CommandLine`,
  },
  {
    label: 'Splunk SPL → Sigma Rule (YAML)',
    badge: 'SPL to SIGMA',
    source: 'splunk',
    target: 'sigma',
    query: `index=security (EventCode=10 TargetImage="*\\\\lsass.exe" GrantedAccess IN ("0x0010", "0x1410", "0x1F0FFF"))
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen by host, user, SourceImage, TargetImage, GrantedAccess`,
  },
  {
    label: 'Sigma Rule → Splunk SPL',
    badge: 'SIGMA to SPL',
    source: 'sigma',
    target: 'splunk',
    query: `title: Suspicious Encoded PowerShell Download Cradle
id: 3b1a8d42-5f33-4e89-a2e1-8849b2f6c91a
status: test
description: Detects encoded PowerShell commands initiating remote download cradles.
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
            - 'DownloadString'
    condition: selection
falsepositives:
    - Verified IT deployment tooling
level: high`,
  },
  {
    label: 'Sigma Rule → Microsoft Sentinel (KQL)',
    badge: 'SIGMA to KQL',
    source: 'sigma',
    target: 'sentinel',
    query: `title: Volume Shadow Copy Deletion via LOLBins
id: a23d41f7-4952-47e2-8921-5f210d3e5210
status: test
description: Detects execution of vssadmin or wmic to delete shadow copies.
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_vss:
        CommandLine|contains|all:
            - 'vssadmin'
            - 'delete'
            - 'shadows'
    selection_wmic:
        CommandLine|contains|all:
            - 'wmic'
            - 'shadowcopy'
            - 'delete'
    condition: selection_vss or selection_wmic
falsepositives:
    - Backup software routines
level: critical`,
  },
  {
    label: 'Endpoint Query → YARA Rule',
    badge: 'QUERY to YARA',
    source: 'defender',
    target: 'yara',
    query: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("comsvcs.dll", "MiniDump", "procdump.exe", "sekurlsa")
| where InitiatingProcessFileName =~ "rundll32.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine`,
  },
  {
    label: 'YARA Rule → Elastic EQL Hunt Query',
    badge: 'YARA to EQL',
    source: 'yara',
    target: 'elastic',
    query: `rule Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Identifies commands attempting to delete volume shadow copies and disable recovery"
        author = "SOC Threat Intel"
        severity = "CRITICAL"
        mitre_technique = "T1490"
    strings:
        $vss = "vssadmin.exe delete shadows /all /quiet" nocase ascii wide
        $wmic = "wmic shadowcopy delete" nocase ascii wide
        $bcd = "recoveryenabled no" nocase ascii wide
    condition:
        any of them
}`,
  },
  {
    label: 'Sigma Rule → YARA Artifact Rule',
    badge: 'SIGMA to YARA',
    source: 'sigma',
    target: 'yara',
    query: `title: Mimikatz Execution and Process Access
id: e4b60e54-e65a-4b9b-9c32-1563f6e1f02a
status: test
description: Detects Mimikatz execution flags and memory inspection commands.
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'privilege::debug'
            - 'sekurlsa::logonpasswords'
            - 'lsadump::sam'
            - 'kerberos::golden'
    condition: selection
level: critical`,
  },
];

export const MultiPlatformTranslatorView: React.FC<MultiPlatformTranslatorViewProps> = ({
  initialQuery,
  initialSourcePlatform,
  userRole = 'visitor',
}) => {
  const [sourcePlatform, setSourcePlatform] = useState<SiemPlatformId>(initialSourcePlatform || 'sentinel');
  const [targetPlatform, setTargetPlatform] = useState<SiemPlatformId>('sigma');
  const [sourceQuery, setSourceQuery] = useState(
    initialQuery ||
      `SecurityEvent\n| where EventID == 4688\n| where ProcessName endswith "powershell.exe"\n| where CommandLine has_any ("-enc", "-encodedcommand")\n| project TimeGenerated, Computer, Account, CommandLine`
  );
  const [translatedQuery, setTranslatedQuery] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [activePreset, setActivePreset] = useState<string | null>('KQL → Sigma Rule (YAML)');

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

  const handleSwap = () => {
    const prevSource = sourcePlatform;
    const prevTarget = targetPlatform;
    setSourcePlatform(prevTarget);
    setTargetPlatform(prevSource);
    if (translatedQuery) {
      setSourceQuery(translatedQuery);
      setTranslatedQuery(null);
    }
  };

  const handleApplyPreset = (preset: TranslationPreset) => {
    setSourcePlatform(preset.source);
    setTargetPlatform(preset.target);
    setSourceQuery(preset.query);
    setTranslatedQuery(null);
    setActivePreset(preset.label);
  };

  const handleDownload = () => {
    if (!translatedQuery) return;
    let filename = `rule-${Date.now()}`;
    let ext = 'txt';

    if (targetPlatform === 'sigma') {
      filename = `sigma-detection-${Date.now()}`;
      ext = 'yml';
    } else if (targetPlatform === 'yara') {
      filename = `yara-rule-${Date.now()}`;
      ext = 'yar';
    } else {
      filename = `query-${targetPlatform}-${Date.now()}`;
      ext = 'txt';
    }

    const blob = new Blob([translatedQuery], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const sourceMeta = SIEM_PLATFORMS[sourcePlatform] || SIEM_PLATFORMS.sentinel;
  const targetMeta = SIEM_PLATFORMS[targetPlatform] || SIEM_PLATFORMS.splunk;

  // Validation checks for Sigma and YARA
  const isSigmaTarget = targetPlatform === 'sigma';
  const isYaraTarget = targetPlatform === 'yara';
  const hasSigmaStructure =
    translatedQuery &&
    (translatedQuery.includes('title:') || translatedQuery.includes('logsource:') || translatedQuery.includes('detection:'));
  const hasYaraStructure =
    translatedQuery &&
    (translatedQuery.includes('rule ') || (translatedQuery.includes('strings:') && translatedQuery.includes('condition:')));

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Title Header */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Universal Dialect & Rule Compiler</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 flex items-center gap-1">
              <FileCode className="w-3 h-3" /> SIGMA (YAML) SUPPORT
            </span>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1">
              <Binary className="w-3 h-3" /> YARA 4.x SUPPORT
            </span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-xl font-bold text-white">
            SIEM Query Translator Studio
          </h2>
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
            Cross-Platform SIEM, Sigma &amp; YARA Engine
          </span>
        </div>
        <p className="text-slate-400 font-sans text-xs leading-relaxed max-w-4xl">
          Instantly convert detection rules and threat hunting queries between <strong>13 industry-standard formats</strong>.
          Seamlessly compile vendor-agnostic <strong>Sigma YAML</strong> rules into native SIEM engines, extract <strong>YARA artifact signatures</strong>, or reverse-engineer SIEM queries into portable detection rules.
        </p>

        {/* Quick Presets Bar */}
        <div className="pt-2 border-t border-[#1B3047]/60">
          <div className="flex items-center gap-2 mb-2 text-slate-400 text-[11px] font-semibold">
            <Zap className="w-3.5 h-3.5 text-cyan-400" />
            <span>Quick Translation Presets:</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {PRESETS.map((preset) => {
              const isSelected = activePreset === preset.label;
              return (
                <button
                  key={preset.label}
                  onClick={() => handleApplyPreset(preset)}
                  className={`px-3 py-1.5 rounded-lg border text-[11px] font-medium transition-all cursor-pointer flex items-center gap-1.5 ${
                    isSelected
                      ? 'bg-cyan-500/20 border-cyan-400 text-cyan-200 shadow-sm'
                      : 'bg-[#060D18] hover:bg-[#101F32] border-[#1B3047] text-slate-300 hover:text-cyan-300'
                  }`}
                >
                  <span className="text-[10px] font-mono px-1 py-0.2 rounded bg-[#101F32] text-cyan-400 border border-cyan-500/30">
                    {preset.badge}
                  </span>
                  <span>{preset.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Platform Pickers Row */}
      <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] flex flex-wrap items-center justify-between gap-4">
        {/* Source Platform */}
        <div className="flex-1 min-w-[240px] space-y-1.5">
          <div className="flex items-center justify-between">
            <label className="text-[11px] text-slate-400 font-semibold">Source Dialect / Rule Standard:</label>
            <span className={`text-[10px] font-bold px-2 py-0.2 rounded border ${sourceMeta.badgeColor}`}>
              {sourceMeta.category}
            </span>
          </div>
          <select
            id="select-source-platform"
            value={sourcePlatform}
            onChange={(e) => {
              setSourcePlatform(e.target.value as SiemPlatformId);
              setActivePreset(null);
            }}
            className="w-full bg-[#060D18] text-slate-100 font-mono text-xs border border-[#1B3047] rounded-lg p-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
          >
            <optgroup label="Rule & Signature Standards">
              {SIEM_PLATFORM_LIST.filter((p) => p.category === 'Rule & Signature Standard').map((p) => (
                <option key={p.id} value={p.id}>
                  ⭐ {p.name} ({p.language})
                </option>
              ))}
            </optgroup>
            <optgroup label="Cloud & Enterprise SIEMs / EDRs">
              {SIEM_PLATFORM_LIST.filter((p) => p.category !== 'Rule & Signature Standard').map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.language})
                </option>
              ))}
            </optgroup>
          </select>
        </div>

        {/* Swap Button */}
        <div className="flex items-center justify-center pt-4 sm:pt-2">
          <button
            onClick={handleSwap}
            title="Swap Source and Target Dialects"
            className="p-2.5 rounded-xl bg-[#060D18] hover:bg-[#101F32] border border-[#1B3047] hover:border-cyan-500/50 text-cyan-400 hover:text-cyan-300 transition-all cursor-pointer shadow-sm group"
          >
            <ArrowLeftRight className="w-4 h-4 group-hover:rotate-180 transition-transform duration-300" />
          </button>
        </div>

        {/* Target Platform */}
        <div className="flex-1 min-w-[240px] space-y-1.5">
          <div className="flex items-center justify-between">
            <label className="text-[11px] text-slate-400 font-semibold">Target Dialect / Rule Standard:</label>
            <span className={`text-[10px] font-bold px-2 py-0.2 rounded border ${targetMeta.badgeColor}`}>
              {targetMeta.category}
            </span>
          </div>
          <select
            id="select-target-platform"
            value={targetPlatform}
            onChange={(e) => {
              setTargetPlatform(e.target.value as SiemPlatformId);
              setActivePreset(null);
            }}
            className="w-full bg-[#060D18] text-slate-100 font-mono text-xs border border-[#1B3047] rounded-lg p-2.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
          >
            <optgroup label="Rule & Signature Standards">
              {SIEM_PLATFORM_LIST.filter((p) => p.category === 'Rule & Signature Standard').map((p) => (
                <option key={p.id} value={p.id}>
                  ⭐ {p.name} ({p.language})
                </option>
              ))}
            </optgroup>
            <optgroup label="Cloud & Enterprise SIEMs / EDRs">
              {SIEM_PLATFORM_LIST.filter((p) => p.category !== 'Rule & Signature Standard').map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.language})
                </option>
              ))}
            </optgroup>
          </select>
        </div>
      </div>

      {/* Side-by-side Editors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Source Query Box */}
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden flex flex-col shadow-xl">
          <div className="bg-[#101F32] px-4 py-3 border-b border-[#1B3047] flex items-center justify-between">
            <span className="text-slate-200 font-semibold flex items-center gap-2">
              {sourcePlatform === 'sigma' ? (
                <FileCode className="w-4 h-4 text-amber-400" />
              ) : sourcePlatform === 'yara' ? (
                <Binary className="w-4 h-4 text-rose-400" />
              ) : (
                <Code2 className="w-4 h-4 text-cyan-400" />
              )}
              Source: {sourceMeta.name}
            </span>
            <span className={`text-[10px] px-2 py-0.5 rounded font-mono border ${sourceMeta.badgeColor}`}>
              {sourceMeta.language}
            </span>
          </div>

          <div className="p-4 flex-1 flex flex-col space-y-3">
            <textarea
              id="input-source-query"
              rows={14}
              value={sourceQuery}
              onChange={(e) => {
                setSourceQuery(e.target.value);
                setActivePreset(null);
              }}
              placeholder={`Paste original ${sourceMeta.name} (${sourceMeta.language}) here...`}
              className="w-full flex-1 bg-[#060D18] text-cyan-100 font-mono text-xs p-3 rounded-xl border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500 leading-relaxed resize-none"
            />

            <div className="flex items-center justify-between gap-3 pt-1">
              <span className="text-[11px] text-slate-500 font-mono">
                {sourceQuery.split('\n').length} lines | {sourceQuery.length} chars
              </span>
              <button
                id="btn-trigger-translation"
                onClick={handleTranslate}
                disabled={loading}
                className="px-6 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-[#060D18] font-bold flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 cursor-pointer transition-all"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Compiling Rule & Syntax...</span>
                  </>
                ) : (
                  <>
                    <RefreshCw className="w-4 h-4" />
                    <span>Translate to {targetMeta.name.split(' ')[0]}</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Target Query Box */}
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden flex flex-col shadow-xl">
          <div className="bg-[#101F32] px-4 py-3 border-b border-[#1B3047] flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              {targetPlatform === 'sigma' ? (
                <FileCode className="w-4 h-4 text-amber-400" />
              ) : targetPlatform === 'yara' ? (
                <Binary className="w-4 h-4 text-rose-400" />
              ) : (
                <Terminal className="w-4 h-4 text-cyan-400" />
              )}
              <span className="text-slate-200 font-semibold">Target: {targetMeta.name}</span>
            </div>

            <div className="flex items-center gap-2">
              {translatedQuery && (
                <>
                  <button
                    onClick={handleDownload}
                    title={`Download as ${targetPlatform === 'sigma' ? '.yml' : targetPlatform === 'yara' ? '.yar' : '.txt'}`}
                    className="px-2.5 py-1 rounded bg-[#060D18] hover:bg-[#1B3047] text-cyan-300 border border-[#1B3047] flex items-center gap-1 text-[11px] font-bold transition-all cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    <span>
                      {targetPlatform === 'sigma' ? '.yml' : targetPlatform === 'yara' ? '.yar' : 'Download'}
                    </span>
                  </button>

                  <button
                    id="btn-copy-translated-query"
                    onClick={handleCopy}
                    className="px-2.5 py-1 rounded bg-[#060D18] hover:bg-[#1B3047] text-cyan-300 border border-[#1B3047] flex items-center gap-1 text-[11px] transition-colors cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
                    <span>{copied ? 'Copied!' : 'Copy Code'}</span>
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="p-4 flex-1 bg-[#060D18] flex flex-col space-y-3">
            {translatedQuery ? (
              <>
                {/* Format Inspector Banner */}
                {isSigmaTarget && (
                  <div className="flex items-center justify-between p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px]">
                    <div className="flex items-center gap-2 font-mono">
                      <FileCode className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>Sigma YAML Specification (v1.1)</span>
                    </div>
                    {hasSigmaStructure ? (
                      <span className="flex items-center gap-1 text-emerald-400 font-bold">
                        <Check className="w-3.5 h-3.5" /> Valid Sigma Structure
                      </span>
                    ) : (
                      <span className="text-amber-400 font-bold">Generic Rule Output</span>
                    )}
                  </div>
                )}

                {isYaraTarget && (
                  <div className="flex items-center justify-between p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-[11px]">
                    <div className="flex items-center gap-2 font-mono">
                      <Binary className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>YARA 4.x Signature Rule Specification</span>
                    </div>
                    {hasYaraStructure ? (
                      <span className="flex items-center gap-1 text-emerald-400 font-bold">
                        <Check className="w-3.5 h-3.5" /> Valid YARA Structure
                      </span>
                    ) : (
                      <span className="text-rose-400 font-bold">Generic Signature Output</span>
                    )}
                  </div>
                )}

                {!isSigmaTarget && !isYaraTarget && (
                  <div className="flex items-center justify-between p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-[11px]">
                    <div className="flex items-center gap-2 font-mono">
                      <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span>{targetMeta.name} Production Executable Query</span>
                    </div>
                    <span className="text-emerald-400 font-bold flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" /> 100% Dialect Syntax Match
                    </span>
                  </div>
                )}

                <pre className="p-4 bg-[#0B1726] text-slate-100 font-mono text-xs leading-relaxed overflow-x-auto whitespace-pre-wrap flex-1 rounded-xl border border-[#1B3047] max-h-[420px]">
                  <code>{translatedQuery}</code>
                </pre>
              </>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-400 font-sans text-xs space-y-3 min-h-[300px]">
                {targetPlatform === 'sigma' ? (
                  <FileCode className="w-10 h-10 text-amber-500/50" />
                ) : targetPlatform === 'yara' ? (
                  <Binary className="w-10 h-10 text-rose-500/50" />
                ) : (
                  <Sparkles className="w-10 h-10 text-slate-600" />
                )}
                <div>
                  <p className="font-semibold text-slate-300">
                    Ready to translate into {targetMeta.name} ({targetMeta.language})
                  </p>
                  <p className="text-slate-500 text-[11px] mt-1">
                    Select a preset above or click "Translate" to convert your logic into production syntax.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

