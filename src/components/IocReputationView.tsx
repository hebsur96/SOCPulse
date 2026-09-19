import React, { useState, useRef } from 'react';
import {
  Globe,
  ShieldAlert,
  Search,
  ExternalLink,
  Tag,
  MapPin,
  Zap,
  Copy,
  Check,
  RefreshCw,
  Shield,
  Activity,
  Terminal,
  Upload,
  FileText,
  FileSpreadsheet,
  Layers,
  Filter,
  Trash2,
  UploadCloud,
  CheckSquare,
  Square,
  Sparkles,
  FileCode,
  ShieldCheck,
  Network,
  Code,
  Radio,
  Clock,
  Compass,
  Cpu,
  Boxes,
  Play,
} from 'lucide-react';
import { IocInvestigationResult, IocType, ThreatIntelSourceResult } from '../types';

interface IocReputationViewProps {
  initialIoc?: string;
  onSendQueryToGenerator?: (prompt: string) => void;
  onPivotToSandbox?: (target: string) => void;
}

const SAMPLE_INVESTIGATION_IOCS = [
  { ioc: '185.220.101.5', type: 'ip', label: 'C2 IP (Tor Exit Node)' },
  { ioc: 'phishing-login-verify-m365.com', type: 'domain', label: 'Phishing Domain' },
  { ioc: 'http://cdn-malware-payload.net/exe/update.exe', type: 'url', label: 'Malicious URL' },
  { ioc: 'CVE-2024-38077', type: 'cve', label: 'Windows RDP Pre-Auth RCE (CVE)' },
  { ioc: 'attacker@evil-phish-sender.com', type: 'email', label: 'BEC Attacker Email' },
  { ioc: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', type: 'hash_sha256', label: 'SHA256 Payload Hash' },
];

const SAMPLE_BULK_TEXT = `[SOC Alert Feed - Incident #4902]
Suspicious outbound connection detected from workstation WS-8812 to C2 IP 185.220.101.5 on port 443.
Phishing redirect URL identified in email header: hxxps://phishing-login-verify-m365.com/auth/login
Threat actor sender email: attacker@evil-phish-sender.com
Exploited vulnerability reference: CVE-2024-38077 (Remote Code Execution)
Malware payload dropped in AppData directory:
MD5: 5d41402abc4b2a76b9719d911017c592
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Secondary DNS resolution: cdn-malware-payload.net (IP: 103.253.144.18)`;

export interface ParsedIocItem {
  id: string;
  ioc: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'cve' | 'email';
  selected: boolean;
}

export const IocReputationView: React.FC<IocReputationViewProps> = ({
  initialIoc,
  onSendQueryToGenerator,
  onPivotToSandbox,
}) => {
  // Navigation mode: 'single' or 'bulk'
  const [mode, setMode] = useState<'single' | 'bulk'>('single');

  // Single Lookup State
  const [ioc, setIoc] = useState(initialIoc || '185.220.101.5');
  const [selectedType, setSelectedType] = useState<IocType>('auto');
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [singleResult, setSingleResult] = useState<IocInvestigationResult | null>(null);
  const [resultTab, setResultTab] = useState<'overview' | 'raw_sources' | 'network' | 'sandbox' | 'containment'>('overview');
  const [selectedRawSource, setSelectedRawSource] = useState<string | null>(null);
  const [copiedPayload, setCopiedPayload] = useState(false);

  // Bulk Upload State
  const [bulkText, setBulkText] = useState<string>(SAMPLE_BULK_TEXT);
  const [parsedIocs, setParsedIocs] = useState<ParsedIocItem[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'ip' | 'domain' | 'url' | 'hash' | 'cve' | 'email'>('all');
  const [verdictFilter, setVerdictFilter] = useState<'all' | 'Malicious' | 'Suspicious' | 'Clean'>('all');
  const [isBulkInvestigating, setIsBulkInvestigating] = useState(false);
  const [bulkResults, setBulkResults] = useState<IocInvestigationResult[]>([]);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Helper: Regex Extractor for IOCs
  const extractIocsFromText = (rawText: string): ParsedIocItem[] => {
    if (!rawText.trim()) return [];

    const cleanText = rawText
      .replace(/\[\.\]/g, '.')
      .replace(/\[dot\]/gi, '.')
      .replace(/hxxp/gi, 'http')
      .replace(/\[:\]/g, ':');

    const found: ParsedIocItem[] = [];
    const seen = new Set<string>();

    // 1. CVE Regex
    const cveRegex = /\bCVE-\d{4}-\d{4,8}\b/gi;
    let match;
    while ((match = cveRegex.exec(cleanText)) !== null) {
      const val = match[0].toUpperCase();
      if (!seen.has(val)) {
        seen.add(val);
        found.push({ id: `cve-${found.length}`, ioc: val, type: 'cve', selected: true });
      }
    }

    // 2. Email Regex
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    while ((match = emailRegex.exec(cleanText)) !== null) {
      const val = match[0].toLowerCase();
      if (!seen.has(val)) {
        seen.add(val);
        found.push({ id: `email-${found.length}`, ioc: val, type: 'email', selected: true });
      }
    }

    // 3. IP Regex
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    while ((match = ipRegex.exec(cleanText)) !== null) {
      const val = match[0];
      if (!seen.has(val) && val !== '0.0.0.0' && val !== '127.0.0.1') {
        seen.add(val);
        found.push({ id: `ip-${found.length}`, ioc: val, type: 'ip', selected: true });
      }
    }

    // 4. Hash Regex (SHA256, MD5, SHA1)
    const hashRegex = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g;
    while ((match = hashRegex.exec(cleanText)) !== null) {
      const val = match[0].toLowerCase();
      if (!seen.has(val)) {
        seen.add(val);
        found.push({ id: `hash-${found.length}`, ioc: val, type: 'hash', selected: true });
      }
    }

    // 5. URL Regex
    const urlRegex = /https?:\/\/[^\s/$.?#].[^\s]*/gi;
    while ((match = urlRegex.exec(cleanText)) !== null) {
      const val = match[0].replace(/[),;.]+$/, '');
      if (!seen.has(val)) {
        seen.add(val);
        found.push({ id: `url-${found.length}`, ioc: val, type: 'url', selected: true });
      }
    }

    // 6. Domain Regex
    const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
    while ((match = domainRegex.exec(cleanText)) !== null) {
      const val = match[0].toLowerCase();
      if (!seen.has(val) && !val.endsWith('.exe') && !val.endsWith('.dll') && !val.endsWith('.txt')) {
        seen.add(val);
        found.push({ id: `domain-${found.length}`, ioc: val, type: 'domain', selected: true });
      }
    }

    return found;
  };

  // Toggle selection for bulk items
  const toggleIocSelection = (id: string) => {
    setParsedIocs((prev) =>
      prev.map((item) => (item.id === id ? { ...item, selected: !item.selected } : item))
    );
  };

  const toggleSelectAll = () => {
    const allSelected = parsedIocs.every((p) => p.selected);
    setParsedIocs((prev) => prev.map((item) => ({ ...item, selected: !allSelected })));
  };

  // Single Investigation Trigger
  const handleInvestigate = async (overrideIoc?: string, overrideTypeVal?: IocType) => {
    const targetIoc = overrideIoc || ioc;
    if (!targetIoc.trim()) return;

    setLoading(true);
    setErrorMessage(null);

    try {
      const res = await fetch('/api/investigate-ioc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ioc: targetIoc.trim(),
          overrideType: overrideTypeVal || selectedType,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setSingleResult(data);
        if (data.sources && data.sources.length > 0) {
          setSelectedRawSource(data.sources[0].sourceName);
        }
      } else {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || 'Failed to query threat intelligence feeds');
      }
    } catch (err: any) {
      console.error('Investigate IOC error:', err);
      setErrorMessage(err.message || 'Threat intel lookup failed. Please verify the indicator format.');
    } finally {
      setLoading(false);
    }
  };

  // Bulk File Upload Reader
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadedFileName(file.name);
    const reader = new FileReader();

    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (text) {
        setBulkText(text);
        const extracted = extractIocsFromText(text);
        setParsedIocs(extracted);
      }
    };

    reader.readAsText(file);
  };

  // Handle Drag and Drop File
  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    setUploadedFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (text) {
        setBulkText(text);
        const extracted = extractIocsFromText(text);
        setParsedIocs(extracted);
      }
    };
    reader.readAsText(file);
  };

  // Parse Bulk Input Text
  const handleParseText = () => {
    const extracted = extractIocsFromText(bulkText);
    setParsedIocs(extracted);
  };

  // Run Bulk Investigation
  const handleRunBulkInvestigation = async () => {
    const selectedList = parsedIocs.filter((p) => p.selected).map((p) => p.ioc);
    if (selectedList.length === 0) return;

    setIsBulkInvestigating(true);

    try {
      const res = await fetch('/api/investigate-bulk-iocs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iocs: selectedList }),
      });

      if (res.ok) {
        const data = await res.json();
        setBulkResults(data.results || []);
      } else {
        throw new Error('API failed');
      }
    } catch (err) {
      console.error('Bulk investigation error:', err);
    } finally {
      setIsBulkInvestigating(false);
    }
  };

  // Helper download trigger
  const downloadFile = (content: string, fileName: string, contentType: string) => {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export handlers
  const handleExportCsv = () => {
    const dataset = mode === 'single' && singleResult ? [singleResult] : bulkResults;
    if (dataset.length === 0) return;

    const headers = ['IOC', 'Type', 'Verdict', 'ThreatScore', 'Attribution', 'Campaign', 'Country', 'ASN', 'MaliciousTags', 'Summary'];
    const rows = dataset.map((r) => [
      `"${r.ioc}"`,
      `"${r.iocType}"`,
      `"${r.verdict}"`,
      r.threatScore,
      `"${r.threatActor || 'N/A'}"`,
      `"${r.campaign || 'N/A'}"`,
      `"${r.geolocation?.country || 'N/A'}"`,
      `"${r.geolocation?.asn || 'N/A'}"`,
      `"${(r.maliciousTags || []).join('; ')}"`,
      `"${r.summary.replace(/"/g, '""')}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    downloadFile(csvContent, `ioc_reputation_report_${Date.now()}.csv`, 'text/csv;charset=utf-8;');
  };

  const handleExportJson = () => {
    const dataset = mode === 'single' && singleResult ? [singleResult] : bulkResults;
    if (dataset.length === 0) return;

    downloadFile(JSON.stringify(dataset, null, 2), `ioc_threat_telemetry_${Date.now()}.json`, 'application/json');
  };

  const handleExportStix = () => {
    const dataset = mode === 'single' && singleResult ? [singleResult] : bulkResults;
    if (dataset.length === 0) return;

    const stixObjects = dataset.map((res, idx) => {
      let pattern = `[ipv4-addr:value = '${res.ioc}']`;
      if (res.iocType === 'domain') pattern = `[domain-name:value = '${res.ioc}']`;
      else if (res.iocType === 'url') pattern = `[url:value = '${res.ioc}']`;
      else if (res.iocType.startsWith('hash'))
        pattern = `[file:hashes.'${res.iocType.replace('hash_', '').toUpperCase()}' = '${res.ioc}']`;

      return {
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${res.ioc.replace(/[^a-zA-Z0-9]/g, '')}-${idx}`,
        created: res.investigationTimestamp || new Date().toISOString(),
        modified: res.investigationTimestamp || new Date().toISOString(),
        name: `Malicious Indicator: ${res.ioc}`,
        description: res.summary,
        indicator_types: res.maliciousTags.map((t) => t.toLowerCase()),
        pattern,
        pattern_type: 'stix',
        valid_from: new Date().toISOString(),
        confidence: res.threatScore,
      };
    });

    const bundle = {
      type: 'bundle',
      id: `bundle--${Date.now()}`,
      objects: stixObjects,
    };

    downloadFile(JSON.stringify(bundle, null, 2), `stix_2.1_threat_intel_${Date.now()}.json`, 'application/json');
  };

  const handleExportMarkdown = () => {
    const dataset = mode === 'single' && singleResult ? [singleResult] : bulkResults;
    if (dataset.length === 0) return;

    let md = `# CyberSentinel Threat Intelligence Report\n\n`;
    md += `**Generated At:** ${new Date().toISOString()}\n`;
    md += `**Total Analyzed Indicators:** ${dataset.length}\n\n`;
    md += `## Executive Summary Matrix\n\n`;
    md += `| IOC | Type | Verdict | Risk Score | Threat Actor | Tags |\n`;
    md += `|---|---|---|---|---|---|\n`;

    dataset.forEach((item) => {
      md += `| \`${item.ioc}\` | ${item.iocType.toUpperCase()} | **${item.verdict}** | ${item.threatScore}/100 | ${item.threatActor || 'N/A'} | ${(item.maliciousTags || []).join(', ')} |\n`;
    });

    md += `\n## Detailed Indicator Telemetry\n\n`;
    dataset.forEach((item, idx) => {
      md += `### ${idx + 1}. \`${item.ioc}\` (${item.verdict})\n\n`;
      md += `- **Type:** ${item.iocType}\n`;
      md += `- **Risk Score:** ${item.threatScore}/100\n`;
      md += `- **Summary:** ${item.summary}\n`;
      md += `- **Geolocation:** ${item.geolocation?.country || 'N/A'} (${item.geolocation?.asn || 'N/A'})\n`;
      md += `- **Attribution:** ${item.threatActor || 'Unattributed'} (${item.campaign || 'N/A'})\n`;
      md += `- **MITRE Techniques:** ${(item.mitreTechniques || []).join(', ')}\n\n`;
    });

    downloadFile(md, `ioc_ciso_summary_${Date.now()}.md`, 'text/markdown');
  };

  const handleCopySummary = () => {
    if (!singleResult) return;
    const summaryText = `IOC Reputation Report for ${singleResult.ioc} (${singleResult.iocType.toUpperCase()})
Verdict: ${singleResult.verdict} | Threat Score: ${singleResult.threatScore}/100
Tags: ${singleResult.maliciousTags.join(', ')}
Summary: ${singleResult.summary}
Attribution: ${singleResult.threatActor || 'N/A'} (${singleResult.campaign || 'N/A'})
Geolocation: ${singleResult.geolocation?.country || 'N/A'}, ${singleResult.geolocation?.asn || ''}
Investigated at: ${singleResult.investigationTimestamp}`;

    navigator.clipboard.writeText(summaryText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyRawPayload = (payload: any) => {
    navigator.clipboard.writeText(typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2));
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  // Filter parsed items
  const filteredParsedIocs = parsedIocs.filter((item) => (categoryFilter === 'all' ? true : item.type === categoryFilter));

  // Compute bulk KPIs
  const totalBulkCount = bulkResults.length;
  const maliciousBulkCount = bulkResults.filter((r) => r.verdict === 'Malicious').length;
  const suspiciousBulkCount = bulkResults.filter((r) => r.verdict === 'Suspicious').length;
  const cleanBulkCount = bulkResults.filter((r) => r.verdict === 'Clean').length;

  const filteredBulkResults = bulkResults.filter((r) => (verdictFilter === 'all' ? true : r.verdict === verdictFilter));

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'Malicious':
        return 'bg-red-500/10 text-[#EF4444] border-red-500/30 font-bold';
      case 'Suspicious':
        return 'bg-amber-500/10 text-[#F59E0B] border-amber-500/30 font-bold';
      case 'Clean':
      default:
        return 'bg-green-500/10 text-[#22C55E] border-green-500/30 font-bold';
    }
  };

  // Active raw source object
  const activeSourceObj = singleResult?.sources.find((s) => s.sourceName === selectedRawSource) || singleResult?.sources[0];

  return (
    <div className="space-y-6 font-sans text-xs max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="bg-[#0B1726] p-5 sm:p-6 rounded-2xl border border-[#1B3047] shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-medium">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span>Open Threat Intelligence & Multi-Source Reputation Engine</span>
          </div>

          {/* Mode Switcher Buttons */}
          <div className="flex items-center gap-1 bg-[#060D18] p-1 rounded-xl border border-[#1B3047] shrink-0">
            <button
              onClick={() => setMode('single')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                mode === 'single' ? 'bg-cyan-400 text-[#060D18] shadow-md' : 'text-slate-400 hover:text-cyan-300'
              }`}
            >
              <Search className="w-3.5 h-3.5" /> Single Lookup
            </button>
            <button
              onClick={() => {
                setMode('bulk');
                if (parsedIocs.length === 0) handleParseText();
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                mode === 'bulk' ? 'bg-cyan-400 text-[#060D18] shadow-md' : 'text-slate-400 hover:text-cyan-300'
              }`}
            >
              <Upload className="w-3.5 h-3.5" /> Bulk Upload & Parsing
            </button>
          </div>
        </div>

        <h2 className="text-xl font-bold text-white tracking-tight">
          IOC Reputation Investigator & Threat Intel Aggregator
        </h2>
        <p className="text-slate-400 text-xs leading-relaxed max-w-3xl">
          Queries and matches all IOC types (IPs, Domains, URLs, SHA256/MD5/SHA1 Hashes, CVE Vulnerabilities, Attacker Emails) against dedicated OSINT threat feeds including VirusTotal, AbuseIPDB, AlienVault OTX, CISA KEV, Shodan, ThreatFox, MalwareBazaar, URLScan.io, and Spamhaus with direct portal deep links and verbatim scoring.
        </p>

        {/* Quick Sample Presets */}
        {mode === 'single' && (
          <div className="pt-2 flex flex-wrap items-center gap-2">
            <span className="text-[11px] text-cyan-400/80 font-mono font-semibold">Quick Scenarios:</span>
            {SAMPLE_INVESTIGATION_IOCS.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setIoc(sample.ioc);
                  setSelectedType(sample.type as IocType);
                  handleInvestigate(sample.ioc, sample.type as IocType);
                }}
                className="px-2.5 py-1 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-slate-300 hover:text-cyan-300 border border-[#1B3047] hover:border-cyan-500/40 text-[11px] font-mono transition-all cursor-pointer"
              >
                {sample.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* SINGLE LOOKUP MODE */}
      {mode === 'single' && (
        <div className="space-y-6">
          {/* Input Search Card */}
          <div className="bg-[#0B1726] p-5 rounded-2xl border border-[#1B3047] space-y-4 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <label className="text-cyan-300 font-semibold text-xs flex items-center gap-2">
                <Search className="w-4 h-4 text-cyan-400" />
                Target Indicator (IP, Domain, URL, Hash, CVE, or Email):
              </label>

              {/* Type Override Selector */}
              <div className="flex items-center gap-1.5 text-xs">
                <span className="text-slate-400 font-mono text-[11px]">Type:</span>
                <select
                  value={selectedType}
                  onChange={(e) => setSelectedType(e.target.value as IocType)}
                  className="bg-[#060D18] border border-[#1B3047] text-cyan-300 text-xs rounded-lg px-2.5 py-1 font-mono focus:outline-none focus:border-cyan-500"
                >
                  <option value="auto">Auto-Detect</option>
                  <option value="ip">IP Address (IPv4/IPv6)</option>
                  <option value="domain">Domain / Hostname</option>
                  <option value="url">URL (HTTP/HTTPS)</option>
                  <option value="hash_sha256">SHA256 Hash</option>
                  <option value="hash_md5">MD5 Hash</option>
                  <option value="hash_sha1">SHA1 Hash</option>
                  <option value="cve">CVE Vulnerability</option>
                  <option value="email">Attacker Email</option>
                </select>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <input
                  id="input-ioc-investigate"
                  type="text"
                  value={ioc}
                  onChange={(e) => setIoc(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleInvestigate()}
                  placeholder="e.g. 185.220.101.5, phishing-login.com, hxxps://..., CVE-2024-38077, or e3b0c442..."
                  className="w-full bg-[#060D18] text-white font-mono text-xs px-4 py-3 rounded-xl border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500/40 focus:border-cyan-500/60 transition-all placeholder-slate-600"
                />
              </div>

              <button
                id="btn-investigate-ioc"
                onClick={() => handleInvestigate()}
                disabled={loading || !ioc.trim()}
                className="px-6 py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-40 text-[#060D18] font-bold flex items-center justify-center gap-2 shadow-md shadow-cyan-500/10 cursor-pointer transition-colors shrink-0"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-[#060D18]" />
                    <span>Synchronizing Threat Feeds...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 text-[#060D18]" />
                    <span>Query Threat Intel Feeds</span>
                  </>
                )}
              </button>
            </div>

            {/* Error Message Display */}
            {errorMessage && (
              <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-xl text-red-300 text-xs flex items-center justify-between gap-2">
                <span>{errorMessage}</span>
                <button
                  onClick={() => setErrorMessage(null)}
                  className="text-red-400 hover:text-red-200 font-bold px-2 py-0.5"
                >
                  Dismiss
                </button>
              </div>
            )}
          </div>

          {/* Single Result Display */}
          {singleResult && (
            <div className="space-y-6 animate-in fade-in duration-300">
              {/* Main Summary Header & Score Card */}
              <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-6 space-y-6 shadow-xl">
                <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 border-b border-[#1B3047] pb-6">
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-3 py-1 rounded-full text-xs font-mono uppercase border ${getVerdictBadge(singleResult.verdict)}`}>
                        Verdict: {singleResult.verdict}
                      </span>
                      <span className="text-teal-300 text-xs font-mono font-bold uppercase bg-[#060D18] border border-[#1B3047] px-2 py-0.5 rounded">
                        {singleResult.iocType}
                      </span>
                      <span className="px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-[11px] font-mono font-semibold inline-flex items-center gap-1">
                        <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                        {singleResult.liveVerificationStatus || 'Original Resource Matched'}
                      </span>
                    </div>

                    <h3 className="text-xl sm:text-2xl font-bold text-white font-mono select-all break-all">
                      {singleResult.ioc}
                    </h3>

                    <p className="text-slate-300 text-xs leading-relaxed max-w-3xl">
                      {singleResult.summary}
                    </p>
                  </div>

                  {/* Threat Score Dial */}
                  <div className="bg-[#060D18] p-4 rounded-2xl border border-[#1B3047] min-w-[200px] text-center space-y-1 shrink-0">
                    <span className="text-slate-400 text-[10px] uppercase font-mono font-bold">Threat Risk Score</span>
                    <div className="text-4xl font-extrabold font-mono text-cyan-400">
                      {singleResult.threatScore}<span className="text-slate-500 text-lg">/100</span>
                    </div>
                    <div className="w-full bg-[#0B1726] h-2 rounded-full overflow-hidden border border-[#1B3047]">
                      <div
                        className="h-full transition-all duration-1000 bg-cyan-400"
                        style={{ width: `${singleResult.threatScore}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Authoritative Live Portal Quick-Launcher */}
                <div className="p-3 bg-[#060D18] rounded-xl border border-[#1B3047] flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-slate-300 text-xs font-mono font-semibold">
                    <Compass className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span>Direct Original Resource Portals:</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {singleResult.sources.map((s, idx) => (
                      s.link ? (
                        <a
                          key={idx}
                          href={s.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-2.5 py-1 rounded-lg bg-[#0B1726] hover:bg-[#101F32] text-cyan-300 hover:text-cyan-200 border border-[#1B3047] hover:border-cyan-500/50 text-[11px] font-mono font-semibold inline-flex items-center gap-1 transition-all"
                        >
                          <span>{s.sourceName}</span>
                          <ExternalLink className="w-3 h-3 text-cyan-400" />
                        </a>
                      ) : null
                    ))}
                  </div>
                </div>

                {/* Malicious Tagging Display */}
                <div className="space-y-2">
                  <span className="text-cyan-400/90 text-xs font-mono font-semibold flex items-center gap-1.5">
                    <Tag className="w-3.5 h-3.5 text-cyan-400" />
                    Threat Tags & Adversary Classifications:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {singleResult.maliciousTags.map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1 rounded-lg bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-xs font-mono font-semibold flex items-center gap-1.5 shadow-xs"
                      >
                        <ShieldAlert className="w-3 h-3 text-cyan-400" />
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Interactive Result Tabs */}
                <div className="flex items-center gap-2 border-b border-[#1B3047] pt-2">
                  <button
                    onClick={() => setResultTab('overview')}
                    className={`px-3 py-2 text-xs font-bold font-mono transition-all flex items-center gap-1.5 border-b-2 cursor-pointer ${
                      resultTab === 'overview'
                        ? 'border-cyan-400 text-cyan-300'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Activity className="w-3.5 h-3.5" /> Threat Intel Matrix
                  </button>
                  <button
                    onClick={() => setResultTab('raw_sources')}
                    className={`px-3 py-2 text-xs font-bold font-mono transition-all flex items-center gap-1.5 border-b-2 cursor-pointer ${
                      resultTab === 'raw_sources'
                        ? 'border-cyan-400 text-cyan-300'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Code className="w-3.5 h-3.5" /> Raw Provider Telemetry
                  </button>
                  <button
                    onClick={() => setResultTab('network')}
                    className={`px-3 py-2 text-xs font-bold font-mono transition-all flex items-center gap-1.5 border-b-2 cursor-pointer ${
                      resultTab === 'network'
                        ? 'border-cyan-400 text-cyan-300'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Network className="w-3.5 h-3.5" /> Network & Passive DNS
                  </button>
                  <button
                    onClick={() => setResultTab('sandbox')}
                    className={`px-3 py-2 text-xs font-bold font-mono transition-all flex items-center gap-1.5 border-b-2 cursor-pointer ${
                      resultTab === 'sandbox'
                        ? 'border-cyan-400 text-cyan-300'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Sandbox Intel
                    <span className="px-1.5 py-0.2 text-[9px] rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
                      OPEN SOURCE
                    </span>
                  </button>
                  <button
                    onClick={() => setResultTab('containment')}
                    className={`px-3 py-2 text-xs font-bold font-mono transition-all flex items-center gap-1.5 border-b-2 cursor-pointer ${
                      resultTab === 'containment'
                        ? 'border-cyan-400 text-cyan-300'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <ShieldCheck className="w-3.5 h-3.5" /> SOC Containment Actions
                  </button>
                </div>

                {/* TAB 1: OVERVIEW & SOURCE MATRIX */}
                {resultTab === 'overview' && (
                  <div className="space-y-6 animate-in fade-in duration-200">
                    {/* Metadata Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-[#060D18] p-4 rounded-xl border border-[#1B3047] text-xs font-mono">
                      <div className="space-y-1">
                        <span className="text-cyan-400/80 text-[10px] uppercase font-bold flex items-center gap-1">
                          <MapPin className="w-3 h-3 text-cyan-400" />
                          Geolocation & Network
                        </span>
                        <div className="text-slate-200 font-semibold">
                          {singleResult.geolocation?.country || 'N/A'} {singleResult.geolocation?.countryCode && `(${singleResult.geolocation.countryCode})`}
                        </div>
                        <div className="text-slate-400 text-[11px]">{singleResult.geolocation?.asn || 'ASN N/A'}</div>
                        {singleResult.geolocation?.isp && (
                          <div className="text-slate-500 text-[10px]">{singleResult.geolocation.isp}</div>
                        )}
                      </div>

                      <div className="space-y-1">
                        <span className="text-cyan-400/80 text-[10px] uppercase font-bold flex items-center gap-1">
                          <Shield className="w-3 h-3 text-cyan-400" />
                          Threat Actor Attribution
                        </span>
                        <div className="text-slate-200 font-semibold">{singleResult.threatActor || 'Unattributed'}</div>
                        <div className="text-slate-400 text-[11px]">Campaign: {singleResult.campaign || 'N/A'}</div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-cyan-400/80 text-[10px] uppercase font-bold flex items-center gap-1">
                          <Terminal className="w-3 h-3 text-cyan-400" />
                          MITRE ATT&CK Techniques
                        </span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {(singleResult.mitreTechniques || []).length > 0 ? (
                            singleResult.mitreTechniques!.map((tech, idx) => (
                              <span key={idx} className="px-2 py-0.5 rounded bg-[#0B1726] border border-cyan-500/30 text-cyan-300 text-[10px]">
                                {tech}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-500">None detected</span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Source Cards Matrix */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h4 className="font-bold text-white text-xs font-mono flex items-center gap-2">
                          <Activity className="w-4 h-4 text-cyan-400" />
                          Threat Intelligence Source Breakdown ({singleResult.sources.length} Feeds)
                        </h4>
                        <span className="text-[11px] text-slate-400 font-mono">
                          Tailored for: <strong className="text-cyan-400 uppercase">{singleResult.iocType}</strong>
                        </span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {singleResult.sources.map((src, idx) => (
                          <div
                            key={idx}
                            className="bg-[#060D18] rounded-xl border border-[#1B3047] p-4 space-y-3 hover:border-cyan-500/40 transition-all shadow-md flex flex-col justify-between"
                          >
                            <div className="space-y-2">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-1.5">
                                  <span className="font-bold text-white text-xs font-mono">{src.sourceName}</span>
                                  {src.isOriginalResourceMatch && (
                                    <span className="text-[10px] text-cyan-400 font-mono" title="Matched to authoritative threat intel resource">
                                      ✓
                                    </span>
                                  )}
                                </div>
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                                    src.status === 'Malicious'
                                      ? 'bg-red-500/10 text-[#EF4444] border-red-500/30'
                                      : src.status === 'Suspicious'
                                      ? 'bg-amber-500/10 text-[#F59E0B] border-amber-500/30'
                                      : 'bg-green-500/10 text-[#22C55E] border-green-500/30'
                                  }`}
                                >
                                  {src.status}
                                </span>
                              </div>

                              <div className="text-cyan-300 font-mono font-bold text-xs">{src.scoreDetails}</div>

                              <p className="text-slate-300 text-xs leading-relaxed">{src.details}</p>
                            </div>

                            <div className="pt-2 flex items-center justify-between border-t border-[#1B3047] text-[11px] font-mono">
                              {src.link ? (
                                <a
                                  href={src.link}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-400 hover:text-cyan-300 font-semibold inline-flex items-center gap-1 transition-colors"
                                >
                                  <span>Original Portal</span>
                                  <ExternalLink className="w-3 h-3 text-cyan-400" />
                                </a>
                              ) : (
                                <span className="text-slate-500">Authoritative Feed</span>
                              )}

                              {src.rawPayload && (
                                <button
                                  onClick={() => {
                                    setSelectedRawSource(src.sourceName);
                                    setResultTab('raw_sources');
                                  }}
                                  className="text-teal-400 hover:text-teal-300 flex items-center gap-1 cursor-pointer font-semibold"
                                >
                                  <Code className="w-3 h-3" /> Raw Data
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* TAB 2: RAW PROVIDER TELEMETRY */}
                {resultTab === 'raw_sources' && (
                  <div className="space-y-4 animate-in fade-in duration-200">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-1.5">
                        {singleResult.sources.map((s, idx) => (
                          <button
                            key={idx}
                            onClick={() => setSelectedRawSource(s.sourceName)}
                            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
                              (selectedRawSource || singleResult.sources[0]?.sourceName) === s.sourceName
                                ? 'bg-cyan-400 text-[#060D18] shadow-md'
                                : 'bg-[#060D18] text-slate-400 hover:text-cyan-300 border border-[#1B3047]'
                            }`}
                          >
                            {s.sourceName}
                          </button>
                        ))}
                      </div>

                      {activeSourceObj && (
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleCopyRawPayload(activeSourceObj.rawPayload || activeSourceObj)}
                            className="px-3 py-1.5 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-cyan-300 border border-[#1B3047] flex items-center gap-1.5 font-semibold text-xs transition-colors cursor-pointer"
                          >
                            {copiedPayload ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
                            {copiedPayload ? 'Copied JSON' : 'Copy Raw Payload'}
                          </button>

                          {activeSourceObj.link && (
                            <a
                              href={activeSourceObj.link}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="px-3 py-1.5 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-teal-300 border border-[#1B3047] flex items-center gap-1.5 font-semibold text-xs transition-colors"
                            >
                              <span>Open in Portal</span>
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          )}
                        </div>
                      )}
                    </div>

                    {activeSourceObj ? (
                      <div className="bg-[#060D18] rounded-xl border border-[#1B3047] p-4 space-y-3 font-mono text-xs">
                        <div className="flex items-center justify-between border-b border-[#1B3047] pb-2 text-slate-400">
                          <span>Source: <strong className="text-white">{activeSourceObj.sourceName}</strong></span>
                          <span>Score: <strong className="text-cyan-400">{activeSourceObj.scoreDetails}</strong></span>
                        </div>
                        <pre className="text-slate-300 overflow-x-auto p-2 bg-[#0B1726] rounded-lg border border-[#1B3047] leading-relaxed max-h-96">
                          {JSON.stringify(activeSourceObj.rawPayload || {
                            sourceName: activeSourceObj.sourceName,
                            verdict: activeSourceObj.status,
                            scoreDetails: activeSourceObj.scoreDetails,
                            technicalFindings: activeSourceObj.details,
                            indicator: singleResult.ioc,
                            type: singleResult.iocType,
                            timestamp: singleResult.investigationTimestamp,
                          }, null, 2)}
                        </pre>
                      </div>
                    ) : (
                      <div className="p-8 text-center text-slate-500 font-mono">No raw payload selected</div>
                    )}
                  </div>
                )}

                {/* TAB 3: NETWORK & PASSIVE DNS */}
                {resultTab === 'network' && (
                  <div className="space-y-6 animate-in fade-in duration-200">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047] space-y-3 font-mono">
                        <h4 className="text-cyan-400 font-bold text-xs uppercase flex items-center gap-2">
                          <MapPin className="w-4 h-4 text-cyan-400" />
                          Network & Host Resolution
                        </h4>
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between border-b border-[#1B3047] pb-1">
                            <span className="text-slate-400">Indicator:</span>
                            <span className="text-white font-bold">{singleResult.ioc}</span>
                          </div>
                          <div className="flex justify-between border-b border-[#1B3047] pb-1">
                            <span className="text-slate-400">Country:</span>
                            <span className="text-slate-200">{singleResult.geolocation?.country || 'N/A'} ({singleResult.geolocation?.countryCode || 'N/A'})</span>
                          </div>
                          <div className="flex justify-between border-b border-[#1B3047] pb-1">
                            <span className="text-slate-400">City / Region:</span>
                            <span className="text-slate-200">{singleResult.geolocation?.city || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between border-b border-[#1B3047] pb-1">
                            <span className="text-slate-400">Autonomous System (ASN):</span>
                            <span className="text-cyan-300">{singleResult.geolocation?.asn || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between border-b border-[#1B3047] pb-1">
                            <span className="text-slate-400">ISP / Provider:</span>
                            <span className="text-slate-300">{singleResult.geolocation?.isp || 'N/A'}</span>
                          </div>
                          {singleResult.geolocation?.lat && singleResult.geolocation?.lon && (
                            <div className="flex justify-between">
                              <span className="text-slate-400">Coordinates:</span>
                              <span className="text-slate-300">{singleResult.geolocation.lat}, {singleResult.geolocation.lon}</span>
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047] space-y-3 font-mono">
                        <h4 className="text-teal-400 font-bold text-xs uppercase flex items-center gap-2">
                          <Clock className="w-4 h-4 text-teal-400" />
                          Investigation Metadata
                        </h4>
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between border-b border-[#1B3047] pb-1">
                            <span className="text-slate-400">Timestamp:</span>
                            <span className="text-slate-200">{singleResult.investigationTimestamp}</span>
                          </div>
                          <div className="flex justify-between border-b border-[#1B3047] pb-1">
                            <span className="text-slate-400">Threat Actor:</span>
                            <span className="text-slate-200">{singleResult.threatActor || 'Unattributed'}</span>
                          </div>
                          <div className="flex justify-between border-b border-[#1B3047] pb-1">
                            <span className="text-slate-400">Campaign:</span>
                            <span className="text-slate-200">{singleResult.campaign || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Verification Engine:</span>
                            <span className="text-cyan-400 font-bold">OSINT Ground-Truth Aggregator</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Passive DNS Table */}
                    {singleResult.passiveDns && singleResult.passiveDns.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-teal-400/90 text-xs font-mono font-semibold flex items-center gap-1.5">
                          <Network className="w-3.5 h-3.5 text-teal-400" />
                          Passive DNS Resolution History:
                        </span>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                          {singleResult.passiveDns.map((pDns, idx) => (
                            <div key={idx} className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] flex items-center justify-between">
                              <span className="text-slate-200 truncate">{pDns.record}</span>
                              <span className="text-slate-400 text-[11px] shrink-0 ml-2">
                                {pDns.type} ({pDns.firstSeen} - {pDns.lastSeen})
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* TAB: SANDBOX BEHAVIORAL INTEL (OPEN SOURCE PLATFORMS) */}
                {resultTab === 'sandbox' && (
                  <div className="space-y-6 animate-in fade-in duration-200">
                    {/* Launch Banner */}
                    <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/40 via-[#071322] to-blue-950/40 border border-cyan-500/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                            <Cpu className="w-4 h-4" />
                          </span>
                          <span className="font-bold text-slate-100 font-mono text-xs">
                            Deep Multi-Engine Sandbox Detonation for {singleResult.ioc}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] font-mono font-bold border border-emerald-500/30">
                            Open Source Ready
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 font-mono max-w-2xl leading-relaxed">
                          Detonate this indicator in an isolated Windows 10/Linux guest environment with automated memory unpacking, API syscall tracing, and C2 configuration extraction.
                        </p>
                      </div>

                      {onPivotToSandbox && (
                        <button
                          onClick={() => onPivotToSandbox(singleResult.ioc)}
                          className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold font-mono text-xs transition-all flex items-center gap-2 shrink-0 shadow-lg cursor-pointer"
                        >
                          <Play className="w-3.5 h-3.5 fill-current" /> Open Full Sandbox Studio
                        </button>
                      )}
                    </div>

                    {/* Open Source Sandboxes Grid */}
                    <div className="space-y-2">
                      <span className="text-cyan-400/90 text-xs font-mono font-semibold flex items-center gap-1.5">
                        <Boxes className="w-3.5 h-3.5 text-cyan-400" />
                        Open-Source & Community Sandbox Telemetry Engines:
                      </span>

                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
                        {/* CAPEv2 */}
                        <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] hover:border-cyan-500/40 transition-all space-y-2 flex flex-col justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-slate-100">CAPEv2 Sandbox</span>
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                                Open Source (GPL-3.0)
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Automated malware configuration extraction, memory unpacking, and payload decryption.
                            </p>
                            <div className="text-[10px] text-cyan-300 bg-[#0A1626] p-1.5 rounded border border-[#14263B]">
                              Capabilities: In-memory dump · C2 config extraction · Yara scanner
                            </div>
                          </div>
                          <div className="pt-2 border-t border-[#14263B] flex items-center justify-between">
                            <span className="text-[10px] text-emerald-400 font-semibold">Self-Hostable</span>
                            <a
                              href={`https://capev2.org/analysis/search/${encodeURIComponent(singleResult.ioc)}/`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-cyan-400 hover:text-cyan-300 text-[11px] flex items-center gap-1 hover:underline"
                            >
                              Search CAPEv2 <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </div>

                        {/* Cuckoo */}
                        <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] hover:border-cyan-500/40 transition-all space-y-2 flex flex-col justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-slate-100">Cuckoo Sandbox</span>
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                                Open Source (GPL-3.0)
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Pioneer open-source automated malware analysis system using isolated KVM/VirtualBox guests.
                            </p>
                            <div className="text-[10px] text-cyan-300 bg-[#0A1626] p-1.5 rounded border border-[#14263B]">
                              Capabilities: API hooking · PCAP extraction · Memory forensic dumps
                            </div>
                          </div>
                          <div className="pt-2 border-t border-[#14263B] flex items-center justify-between">
                            <span className="text-[10px] text-emerald-400 font-semibold">Self-Hostable</span>
                            <a
                              href="https://cuckoosandbox.org/"
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-cyan-400 hover:text-cyan-300 text-[11px] flex items-center gap-1 hover:underline"
                            >
                              Visit Cuckoo <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </div>

                        {/* DRAKVUF */}
                        <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] hover:border-cyan-500/40 transition-all space-y-2 flex flex-col justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-slate-100">DRAKVUF Sandbox</span>
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                                Open Source (GPL-3.0)
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Agentless virtualization-based malware analysis system with hypervisor introspection (VMI).
                            </p>
                            <div className="text-[10px] text-cyan-300 bg-[#0A1626] p-1.5 rounded border border-[#14263B]">
                              Capabilities: Agentless stealth · Xen VMI · Anti-sandbox evasion bypass
                            </div>
                          </div>
                          <div className="pt-2 border-t border-[#14263B] flex items-center justify-between">
                            <span className="text-[10px] text-emerald-400 font-semibold">Agentless VMI</span>
                            <a
                              href="https://drakvuf.com/"
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-cyan-400 hover:text-cyan-300 text-[11px] flex items-center gap-1 hover:underline"
                            >
                              Visit DRAKVUF <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </div>

                        {/* Hybrid Analysis */}
                        <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] hover:border-cyan-500/40 transition-all space-y-2 flex flex-col justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-slate-100">Hybrid Analysis</span>
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 font-bold">
                                Falcon Community
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Free malware analysis service powered by Falcon Sandbox with process trees and hybrid indicators.
                            </p>
                            <div className="text-[10px] text-cyan-300 bg-[#0A1626] p-1.5 rounded border border-[#14263B]">
                              Capabilities: Hybrid analysis · MITRE mapping · Threat score
                            </div>
                          </div>
                          <div className="pt-2 border-t border-[#14263B] flex items-center justify-between">
                            <span className="text-[10px] text-blue-400 font-semibold">Free Lookup</span>
                            <a
                              href={`https://www.hybrid-analysis.com/search?query=${encodeURIComponent(singleResult.ioc)}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-cyan-400 hover:text-cyan-300 text-[11px] flex items-center gap-1 hover:underline"
                            >
                              Search Hybrid Analysis <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </div>

                        {/* ANY.RUN */}
                        <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] hover:border-cyan-500/40 transition-all space-y-2 flex flex-col justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-slate-100">ANY.RUN Interactive</span>
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 font-bold">
                                Community
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Real-time interactive detonation sandbox for live sample interaction and network monitoring.
                            </p>
                            <div className="text-[10px] text-cyan-300 bg-[#0A1626] p-1.5 rounded border border-[#14263B]">
                              Capabilities: Live interaction · Fast detonation · Process graphs
                            </div>
                          </div>
                          <div className="pt-2 border-t border-[#14263B] flex items-center justify-between">
                            <span className="text-[10px] text-blue-400 font-semibold">Public Database</span>
                            <a
                              href={`https://app.any.run/submissions/#search:${encodeURIComponent(singleResult.ioc)}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-cyan-400 hover:text-cyan-300 text-[11px] flex items-center gap-1 hover:underline"
                            >
                              Search ANY.RUN <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </div>

                        {/* MalwareBazaar */}
                        <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] hover:border-cyan-500/40 transition-all space-y-2 flex flex-col justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-slate-100">MalwareBazaar (abuse.ch)</span>
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                                Open Platform
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Open community project from abuse.ch to collect and share verified malware samples and signatures.
                            </p>
                            <div className="text-[10px] text-cyan-300 bg-[#0A1626] p-1.5 rounded border border-[#14263B]">
                              Capabilities: Verified binaries · Tagging · Yara rule matching
                            </div>
                          </div>
                          <div className="pt-2 border-t border-[#14263B] flex items-center justify-between">
                            <span className="text-[10px] text-emerald-400 font-semibold">abuse.ch</span>
                            <a
                              href={`https://bazaar.abuse.ch/sample/${encodeURIComponent(singleResult.ioc)}/`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-cyan-400 hover:text-cyan-300 text-[11px] flex items-center gap-1 hover:underline"
                            >
                              Search Bazaar <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Behavioral IOC Forensics Highlights */}
                    <div className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047] space-y-3 font-mono text-xs">
                      <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                        Dynamic Behavioral Forensics & In-Memory Extraction Signals:
                      </span>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        <div className="p-3 bg-[#040A12] rounded-lg border border-[#14263B] space-y-1">
                          <span className="text-slate-400 text-[10px] block">Execution Context</span>
                          <span className="text-slate-200 font-bold block">Isolated Windows 10 x64 Guest VM</span>
                          <span className="text-[10px] text-emerald-400">Anti-Sandbox Evasion Patched</span>
                        </div>
                        <div className="p-3 bg-[#040A12] rounded-lg border border-[#14263B] space-y-1">
                          <span className="text-slate-400 text-[10px] block">Dynamic C2 Network Beacons</span>
                          <span className="text-slate-200 font-bold block">
                            {singleResult.c2Associated ? 'Active C2 Communication Observed' : 'No Direct C2 Session'}
                          </span>
                          <span className="text-[10px] text-slate-400">DNS & HTTP(S) Telemetry Tracked</span>
                        </div>
                        <div className="p-3 bg-[#040A12] rounded-lg border border-[#14263B] space-y-1">
                          <span className="text-slate-400 text-[10px] block">Memory Unpacking</span>
                          <span className="text-slate-200 font-bold block">CAPEv2 Dynamic Hooks</span>
                          <span className="text-[10px] text-cyan-400">Process Injection & Hollow Tracing</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* TAB 4: CONTAINMENT & RECOMMENDATIONS */}
                {resultTab === 'containment' && (
                  <div className="space-y-4 animate-in fade-in duration-200">
                    <span className="text-teal-400/90 text-xs font-mono font-semibold flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-teal-400" />
                      Recommended SOC Containment & Defensive Actions:
                    </span>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                      {singleResult.recommendations.map((rec, idx) => (
                        <div key={idx} className="p-4 rounded-xl bg-[#060D18] border border-[#1B3047] text-slate-300 flex items-start gap-3 space-y-1">
                          <span className="w-5 h-5 rounded-full bg-teal-500/20 text-teal-400 border border-teal-500/30 flex items-center justify-center shrink-0 font-mono text-[11px] font-bold">
                            {idx + 1}
                          </span>
                          <span className="leading-relaxed">{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Quick Actions & Export Bar */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#1B3047]">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={handleCopySummary}
                      className="px-3 py-1.5 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-cyan-300 border border-[#1B3047] flex items-center gap-1.5 font-semibold text-xs transition-colors cursor-pointer"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
                      {copied ? 'Copied Summary' : 'Copy Summary'}
                    </button>

                    <button
                      onClick={handleExportCsv}
                      className="px-3 py-1.5 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-cyan-300 border border-[#1B3047] flex items-center gap-1.5 font-semibold text-xs transition-colors cursor-pointer"
                    >
                      <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" /> Export CSV
                    </button>

                    <button
                      onClick={handleExportJson}
                      className="px-3 py-1.5 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-teal-300 border border-[#1B3047] flex items-center gap-1.5 font-semibold text-xs transition-colors cursor-pointer"
                    >
                      <FileCode className="w-3.5 h-3.5 text-teal-400" /> Export JSON
                    </button>

                    <button
                      onClick={handleExportStix}
                      className="px-3 py-1.5 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-cyan-300 border border-[#1B3047] flex items-center gap-1.5 font-semibold text-xs transition-colors cursor-pointer"
                    >
                      <Layers className="w-3.5 h-3.5 text-cyan-400" /> STIX 2.1
                    </button>

                    <button
                      onClick={handleExportMarkdown}
                      className="px-3 py-1.5 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-slate-300 border border-[#1B3047] flex items-center gap-1.5 font-semibold text-xs transition-colors cursor-pointer"
                    >
                      <FileText className="w-3.5 h-3.5 text-slate-400" /> Markdown
                    </button>
                  </div>

                  <div className="flex items-center gap-2">
                    {onPivotToSandbox && (
                      <button
                        onClick={() => onPivotToSandbox(singleResult.ioc)}
                        className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 font-bold flex items-center gap-1.5 transition-all text-xs cursor-pointer"
                      >
                        <Play className="w-3.5 h-3.5 fill-current" />
                        Detonate in Sandbox
                      </button>
                    )}

                    {onSendQueryToGenerator && (
                      <button
                        onClick={() =>
                          onSendQueryToGenerator(`Detect connections or logs containing IOC ${singleResult.ioc} (${singleResult.iocType})`)
                        }
                        className="px-3.5 py-1.5 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold flex items-center gap-1.5 transition-all text-xs cursor-pointer shadow-md shadow-cyan-500/10"
                      >
                        <Zap className="w-3.5 h-3.5 text-[#060D18]" />
                        Generate SIEM Detection Query
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* BULK UPLOAD & PARSING MODE */}
      {mode === 'bulk' && (
        <div className="space-y-6">
          {/* File Upload Dropzone & Bulk Text Box */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* File Drag and Drop Card */}
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              className="bg-[#0B1726] p-6 rounded-2xl border border-dashed border-[#1B3047] hover:border-cyan-500/60 transition-all space-y-3 flex flex-col items-center justify-center text-center group cursor-pointer"
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.csv,.json,.log,.md"
                onChange={handleFileUpload}
                className="hidden"
              />

              <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center group-hover:scale-110 transition-transform">
                <UploadCloud className="w-6 h-6" />
              </div>

              <div className="space-y-1">
                <h3 className="text-sm font-bold text-white">
                  {uploadedFileName ? `File Loaded: ${uploadedFileName}` : 'Drag & Drop Threat Log / IOC File Here'}
                </h3>
                <p className="text-xs text-slate-400 max-w-xs">
                  Supports .txt, .csv, .json, .log files containing threat advisories or raw SIEM logs.
                </p>
              </div>

              <button className="px-4 py-2 rounded-xl bg-[#060D18] hover:bg-[#101F32] text-cyan-300 border border-[#1B3047] font-bold text-xs flex items-center gap-2 cursor-pointer transition-colors">
                <Upload className="w-3.5 h-3.5 text-cyan-400" /> Select Local File
              </button>
            </div>

            {/* Paste Raw Text Area */}
            <div className="bg-[#0B1726] p-5 rounded-2xl border border-[#1B3047] space-y-3 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-cyan-300 font-bold text-xs flex items-center gap-2">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    Paste Raw Log / Threat Text:
                  </label>
                  <button
                    onClick={() => {
                      setBulkText('');
                      setParsedIocs([]);
                    }}
                    className="text-[11px] text-slate-500 hover:text-cyan-400 flex items-center gap-1 cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" /> Clear Text
                  </button>
                </div>

                <textarea
                  rows={5}
                  value={bulkText}
                  onChange={(e) => setBulkText(e.target.value)}
                  className="w-full bg-[#060D18] border border-[#1B3047] rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 leading-relaxed"
                  placeholder="Paste alert logs, CSV content, or text containing IPs, URLs, hashes..."
                />
              </div>

              <button
                onClick={handleParseText}
                className="w-full py-2.5 rounded-xl bg-[#060D18] hover:bg-[#101F32] text-cyan-300 font-bold text-xs flex items-center justify-center gap-2 transition-colors border border-[#1B3047] cursor-pointer"
              >
                <Zap className="w-4 h-4 text-cyan-400" /> Auto-Extract All IOC Types with Regex
              </button>
            </div>
          </div>

          {/* Parsed Extracted IOC Selection Matrix */}
          <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1B3047] pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-white">
                    Extracted IOC Inventory ({parsedIocs.length} Unique Indicators)
                  </h3>
                </div>
                <p className="text-xs text-slate-400">
                  Select which extracted IOCs to query against threat intelligence feeds.
                </p>
              </div>

              {/* Category Filter Pills */}
              <div className="flex flex-wrap items-center gap-1.5 shrink-0">
                {(['all', 'ip', 'domain', 'url', 'hash', 'cve', 'email'] as const).map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setCategoryFilter(cat)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold uppercase transition-colors cursor-pointer ${
                      categoryFilter === cat ? 'bg-cyan-400 text-[#060D18] shadow-xs' : 'bg-[#060D18] text-slate-400 hover:text-cyan-300 border border-[#1B3047]'
                    }`}
                  >
                    {cat} ({cat === 'all' ? parsedIocs.length : parsedIocs.filter((p) => p.type === cat).length})
                  </button>
                ))}
              </div>
            </div>

            {/* Selection Controls */}
            {parsedIocs.length > 0 ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <button
                    onClick={toggleSelectAll}
                    className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 font-bold cursor-pointer"
                  >
                    {parsedIocs.every((p) => p.selected) ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4" />}
                    <span>{parsedIocs.every((p) => p.selected) ? 'Deselect All' : 'Select All'}</span>
                  </button>

                  <span className="font-mono">{parsedIocs.filter((p) => p.selected).length} / {parsedIocs.length} Selected for Query</span>
                </div>

                {/* Grid List of Parsed Items */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5 max-h-60 overflow-y-auto p-1 pr-2">
                  {filteredParsedIocs.map((item) => (
                    <div
                      key={item.id}
                      onClick={() => toggleIocSelection(item.id)}
                      className={`p-2.5 rounded-xl border flex items-center justify-between gap-2 cursor-pointer transition-all ${
                        item.selected
                           ? 'bg-[#060D18] border-cyan-500/50 text-white'
                          : 'bg-[#060D18]/40 border-[#1B3047] text-slate-500'
                      }`}
                    >
                      <div className="flex items-center gap-2 overflow-hidden">
                        {item.selected ? (
                          <CheckSquare className="w-4 h-4 text-cyan-400 shrink-0" />
                        ) : (
                          <Square className="w-4 h-4 text-slate-600 shrink-0" />
                        )}
                        <span className="font-mono text-xs truncate select-all">{item.ioc}</span>
                      </div>

                      <span className="px-1.5 py-0.5 rounded bg-[#0B1726] border border-[#1B3047] text-[10px] uppercase font-mono font-bold text-teal-300 shrink-0">
                        {item.type}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Bulk Investigation Action Button */}
                <button
                  onClick={handleRunBulkInvestigation}
                  disabled={isBulkInvestigating || parsedIocs.filter((p) => p.selected).length === 0}
                  className="w-full py-3 px-4 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold text-xs sm:text-sm flex items-center justify-center gap-2 transition-all shadow-md shadow-cyan-500/10 cursor-pointer disabled:opacity-40"
                >
                  {isBulkInvestigating ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-[#060D18]" /> Batch Querying Threat Intelligence Sources...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 text-[#060D18]" />
                      <span>Investigate {parsedIocs.filter((p) => p.selected).length} Selected Indicators Across Feeds</span>
                    </>
                  )}
                </button>
              </div>
            ) : (
              <div className="py-8 text-center text-slate-500 space-y-2">
                <Filter className="w-8 h-8 mx-auto text-slate-600" />
                <p className="text-xs">No IOCs extracted yet. Paste text or drag a file above, then click Auto-Extract.</p>
              </div>
            )}
          </div>

          {/* Bulk Results Dashboard */}
          {bulkResults.length > 0 && (
            <div className="space-y-6 animate-in fade-in duration-300">
              {/* Batch KPI Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-[#0B1726] p-4 rounded-xl border border-[#1B3047] text-center">
                  <div className="text-[10px] text-slate-400 uppercase font-mono font-bold mb-1">Total Investigated</div>
                  <div className="text-2xl font-black font-mono text-white">{totalBulkCount}</div>
                </div>

                <div className="bg-[#0B1726] p-4 rounded-xl border border-[#1B3047] text-center">
                  <div className="text-[10px] text-[#EF4444] uppercase font-mono font-bold mb-1">Malicious IOCs</div>
                  <div className="text-2xl font-black font-mono text-[#EF4444]">{maliciousBulkCount}</div>
                </div>

                <div className="bg-[#0B1726] p-4 rounded-xl border border-[#1B3047] text-center">
                  <div className="text-[10px] text-[#F59E0B] uppercase font-mono font-bold mb-1">Suspicious IOCs</div>
                  <div className="text-2xl font-black font-mono text-[#F59E0B]">{suspiciousBulkCount}</div>
                </div>

                <div className="bg-[#0B1726] p-4 rounded-xl border border-[#1B3047] text-center">
                  <div className="text-[10px] text-[#22C55E] uppercase font-mono font-bold mb-1">Clean / Benign</div>
                  <div className="text-2xl font-black font-mono text-[#22C55E]">{cleanBulkCount}</div>
                </div>
              </div>

              {/* Bulk Results Table Card */}
              <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1B3047] pb-4">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-sm font-bold text-white">Bulk Threat Intelligence Batch Results</h3>
                  </div>

                  {/* Verdict filter & exports */}
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="flex items-center gap-1 bg-[#060D18] p-1 rounded-lg border border-[#1B3047]">
                      {(['all', 'Malicious', 'Suspicious', 'Clean'] as const).map((v) => (
                        <button
                          key={v}
                          onClick={() => setVerdictFilter(v)}
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase transition-colors cursor-pointer ${
                            verdictFilter === v ? 'bg-cyan-400 text-[#060D18]' : 'text-slate-400 hover:text-cyan-300'
                          }`}
                        >
                          {v}
                        </button>
                      ))}
                    </div>

                    <button
                      onClick={handleExportCsv}
                      className="px-2.5 py-1 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-cyan-300 border border-[#1B3047] text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
                    >
                      <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" /> CSV
                    </button>

                    <button
                      onClick={handleExportJson}
                      className="px-2.5 py-1 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-teal-300 border border-[#1B3047] text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
                    >
                      <FileCode className="w-3.5 h-3.5 text-teal-400" /> JSON
                    </button>

                    <button
                      onClick={handleExportStix}
                      className="px-2.5 py-1 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-cyan-300 border border-[#1B3047] text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
                    >
                      <Layers className="w-3.5 h-3.5 text-cyan-400" /> STIX
                    </button>

                    <button
                      onClick={handleExportMarkdown}
                      className="px-2.5 py-1 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-slate-300 border border-[#1B3047] text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
                    >
                      <FileText className="w-3.5 h-3.5 text-slate-400" /> MD
                    </button>
                  </div>
                </div>

                {/* Table View */}
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-[#1B3047] text-slate-400 text-[11px] font-mono">
                        <th className="py-2.5 px-3">Indicator (IOC)</th>
                        <th className="py-2.5 px-3">Type</th>
                        <th className="py-2.5 px-3">Verdict</th>
                        <th className="py-2.5 px-3">Risk Score</th>
                        <th className="py-2.5 px-3">Threat Tags</th>
                        <th className="py-2.5 px-3">Attribution</th>
                        <th className="py-2.5 px-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1B3047] font-mono text-xs">
                      {filteredBulkResults.map((res, idx) => (
                        <tr key={idx} className="hover:bg-[#101F32]/50 transition-colors">
                          <td className="py-2.5 px-3 text-white font-bold select-all break-all max-w-xs">{res.ioc}</td>
                          <td className="py-2.5 px-3 uppercase text-[10px] text-teal-400 font-bold">{res.iocType}</td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] uppercase border ${getVerdictBadge(res.verdict)}`}>
                              {res.verdict}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-bold text-cyan-300">{res.threatScore}/100</td>
                          <td className="py-2.5 px-3">
                            <div className="flex flex-wrap gap-1">
                              {(res.maliciousTags || []).slice(0, 2).map((t, tIdx) => (
                                <span key={tIdx} className="px-1.5 py-0.5 rounded bg-[#060D18] border border-cyan-500/20 text-cyan-300 text-[10px]">
                                  {t}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="py-2.5 px-3 text-slate-300 text-[11px]">{res.threatActor || 'Unattributed'}</td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              onClick={() => {
                                setIoc(res.ioc);
                                setSingleResult(res);
                                setMode('single');
                              }}
                              className="px-2.5 py-1 rounded bg-[#060D18] hover:bg-[#101F32] border border-cyan-500/30 text-cyan-400 text-[11px] font-bold transition-colors cursor-pointer"
                            >
                              Deep Dive
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

