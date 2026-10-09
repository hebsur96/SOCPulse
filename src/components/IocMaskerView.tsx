import React, { useState, useRef } from 'react';
import {
  ShieldCheck,
  Upload,
  FileText,
  FileSpreadsheet,
  Image as ImageIcon,
  Copy,
  Check,
  Download,
  EyeOff,
  Search,
  Zap,
  ArrowRight,
  Layers,
  Hash,
  Sparkles,
} from 'lucide-react';
import * as XLSX from 'xlsx';
import { IocMaskMode, IocFileType, IocMaskResult, HashWrapStyle } from '../types';

// Client-side fallback engine for resilient offline/instant processing
function clientSideMaskTextIocs(
  text: string,
  mode: IocMaskMode,
  options: { hashWrapPound: boolean; hashWrapStyle: HashWrapStyle }
): IocMaskResult {
  let processed = text;
  const foundMap = new Map<string, { type: 'ip' | 'url' | 'domain' | 'email' | 'hash'; original: string; masked: string; count: number }>();
  const counts = { ip: 0, url: 0, domain: 0, email: 0, hash: 0, total: 0 };
  const wrapPound = options.hashWrapPound;
  const hashStyle = options.hashWrapStyle;

  // URLs
  const urlRegex = /\bhttps?:\/\/[^\s<>"'{}|\\^`]+[^\s<>"'{}|\\^`.,;:?]/gi;
  processed = processed.replace(urlRegex, (match) => {
    let masked = match;
    if (mode === 'defang') {
      masked = match.replace(/^http:\/\//i, 'http[:]//').replace(/^https:\/\//i, 'hxxps[:]//').replace(/\./g, '[.]');
    } else if (mode === 'redact') {
      masked = '[MASKED-URL]';
    } else {
      masked = `[URL-MASK-${match.length}]`;
    }
    if (!foundMap.has(match)) foundMap.set(match, { type: 'url', original: match, masked, count: 1 });
    else foundMap.get(match)!.count++;
    return masked;
  });

  // IPv4
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  processed = processed.replace(ipv4Regex, (match) => {
    let masked = match;
    if (mode === 'defang') masked = match.replace(/\./g, '[.]');
    else if (mode === 'redact') masked = '[MASKED-IP]';
    else masked = `[IP-MASK-${match.split('.').pop()}]`;
    if (!foundMap.has(match)) foundMap.set(match, { type: 'ip', original: match, masked, count: 1 });
    else foundMap.get(match)!.count++;
    return masked;
  });

  // Emails
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  processed = processed.replace(emailRegex, (match) => {
    let masked = match;
    if (mode === 'defang') masked = match.replace('@', '[@]').replace(/\./g, '[.]');
    else if (mode === 'redact') masked = '[MASKED-EMAIL]';
    else masked = `[EMAIL-MASK]`;
    if (!foundMap.has(match)) foundMap.set(match, { type: 'email', original: match, masked, count: 1 });
    else foundMap.get(match)!.count++;
    return masked;
  });

  // Domains
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|gov|edu|mil|ru|cn|xyz|top|info|co|biz|tk|online|site|tech|store|app|dev|cc|me)\b/gi;
  processed = processed.replace(domainRegex, (match) => {
    if (match.includes('[.]') || match.includes('[MASKED') || match.includes('[URL')) return match;
    let masked = match;
    if (mode === 'defang') masked = match.replace(/\./g, '[.]');
    else if (mode === 'redact') masked = '[MASKED-DOMAIN]';
    else masked = `[DOMAIN-MASK]`;
    if (!foundMap.has(match)) foundMap.set(match, { type: 'domain', original: match, masked, count: 1 });
    else foundMap.get(match)!.count++;
    return masked;
  });

  // SHA512 Hashes (128 hex chars)
  const sha512Regex = /(?<!#)\b[a-fA-F0-9]{128}\b(?!#)/g;
  processed = processed.replace(sha512Regex, (match) => {
    let masked = match;
    if (wrapPound) {
      if (hashStyle === 'defanged') masked = `#${match.slice(0, 8)}[...SHA512-DEFANGED...]${match.slice(-8)}#`;
      else if (hashStyle === 'token' || mode === 'redact' || mode === 'hash_mask') masked = `#[MASKED-SHA512]#`;
      else masked = `#${match}#`;
    } else {
      if (mode === 'defang') masked = `${match.slice(0, 8)}[...SHA512-DEFANGED...]${match.slice(-8)}`;
      else if (mode === 'redact') masked = '[MASKED-SHA512]';
      else masked = `[HASH-SHA512]`;
    }
    if (!foundMap.has(match)) foundMap.set(match, { type: 'hash', original: match, masked, count: 1 });
    else foundMap.get(match)!.count++;
    return masked;
  });

  // SHA256 Hashes (64 hex chars)
  const sha256Regex = /(?<!#)\b[a-fA-F0-9]{64}\b(?!#)/g;
  processed = processed.replace(sha256Regex, (match) => {
    let masked = match;
    if (wrapPound) {
      if (hashStyle === 'defanged') masked = `#${match.slice(0, 8)}[...SHA256-DEFANGED...]${match.slice(-8)}#`;
      else if (hashStyle === 'token' || mode === 'redact' || mode === 'hash_mask') masked = `#[MASKED-SHA256]#`;
      else masked = `#${match}#`;
    } else {
      if (mode === 'defang') masked = `${match.slice(0, 8)}[...SHA256-DEFANGED...]${match.slice(-8)}`;
      else if (mode === 'redact') masked = '[MASKED-SHA256]';
      else masked = `[HASH-SHA256]`;
    }
    if (!foundMap.has(match)) foundMap.set(match, { type: 'hash', original: match, masked, count: 1 });
    else foundMap.get(match)!.count++;
    return masked;
  });

  // MD5 / SHA1 Hashes (32 to 40 hex chars)
  const md5sha1Regex = /(?<!#)\b[a-fA-F0-9]{32,40}\b(?!#)/g;
  processed = processed.replace(md5sha1Regex, (match) => {
    if (match.includes('DEFANGED') || match.includes('MASKED') || match.includes('#')) return match;
    let masked = match;
    if (wrapPound) {
      if (hashStyle === 'defanged') masked = `#${match.slice(0, 6)}[...HASH-DEFANGED...]${match.slice(-6)}#`;
      else if (hashStyle === 'token' || mode === 'redact' || mode === 'hash_mask') masked = `#[MASKED-HASH]#`;
      else masked = `#${match}#`;
    } else {
      if (mode === 'defang') masked = `${match.slice(0, 6)}[...HASH-DEFANGED...]${match.slice(-6)}`;
      else if (mode === 'redact') masked = '[MASKED-HASH]';
      else masked = `[HASH-MASK]`;
    }
    if (!foundMap.has(match)) foundMap.set(match, { type: 'hash', original: match, masked, count: 1 });
    else foundMap.get(match)!.count++;
    return masked;
  });

  const extractedIocs = Array.from(foundMap.values());
  for (const val of extractedIocs) {
    counts[val.type] += val.count;
    counts.total += val.count;
  }

  return {
    maskedContent: processed,
    extractedIocs,
    counts,
    fileType: 'text',
    hashWrapPound: wrapPound,
    hashWrapStyle: hashStyle,
  };
}

interface IocMaskerViewProps {
  onInvestigateIoc?: (ioc: string) => void;
}

export const IocMaskerView: React.FC<IocMaskerViewProps> = ({ onInvestigateIoc }) => {
  const [inputText, setInputText] = useState(
    `Incident #8492 Log Details:
Suspect IP address 192.168.1.105 communicated with C2 server at 185.220.101.5 on port 443.
Phishing email received from attacker@malware-domain.org directing user to http://phishing-update.net/login.php.
Downloaded payload executable SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
MD5 hash: 5d41402abc4b2a76b9719d911017c592.`
  );
  const [maskMode, setMaskMode] = useState<IocMaskMode>('defang');
  const [hashWrapPound, setHashWrapPound] = useState<boolean>(true);
  const [hashWrapStyle, setHashWrapStyle] = useState<HashWrapStyle>('full');
  const [, setFileType] = useState<IocFileType>('text');
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [fileDataUri, setFileDataUri] = useState<string | null>(null);
  const [, setParsedGrid] = useState<string[][] | null>(null);

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [result, setResult] = useState<IocMaskResult | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const fileInputRef = useRef<HTMLInputElement>(null);

  // File Upload Handler for CSV, Excel, Text, Image
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setErrorMsg(null);
    setSelectedFileName(file.name);
    const ext = file.name.split('.').pop()?.toLowerCase();

    if (ext === 'csv' || ext === 'xlsx' || ext === 'xls') {
      setFileType(ext === 'csv' ? 'csv' : 'excel');
      const reader = new FileReader();
      reader.onload = (evt) => {
        const bstr = evt.target?.result;
        if (bstr) {
          const wb = XLSX.read(bstr, { type: 'binary' });
          const firstSheet = wb.SheetNames[0];
          const worksheet = wb.Sheets[firstSheet];
          const dataGrid = XLSX.utils.sheet_to_json<string[]>(worksheet, { header: 1 });
          setParsedGrid(dataGrid);
          // Plain text representation for preview
          const csvText = XLSX.utils.sheet_to_csv(worksheet);
          setInputText(csvText);
        }
      };
      reader.readAsBinaryString(file);
    } else if (ext === 'txt' || ext === 'log' || ext === 'json') {
      setFileType('text');
      const reader = new FileReader();
      reader.onload = (evt) => {
        const text = evt.target?.result as string;
        if (text) setInputText(text);
      };
      reader.readAsText(file);
    } else if (['png', 'jpg', 'jpeg', 'webp'].includes(ext || '')) {
      setFileType('image');
      const reader = new FileReader();
      reader.onload = (evt) => {
        const dataUrl = evt.target?.result as string;
        setFileDataUri(dataUrl);
        setInputText(`[Image file uploaded: ${file.name}. Click Submit to extract and mask IOCs via OCR analysis.]`);
      };
      reader.readAsDataURL(file);
    }
  };

  // Main Submit Action
  const handleMaskSubmit = async () => {
    if (!inputText.trim() && !fileDataUri) return;
    setLoading(true);
    setErrorMsg(null);

    try {
      const res = await fetch('/api/mask-iocs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          inputText,
          rawContent: inputText,
          maskMode,
          hashWrapPound,
          hashWrapStyle,
          imageDataUri: fileDataUri,
          fileDataUri,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setResult(data);
      } else {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || 'Failed to mask indicators');
      }
    } catch (err: any) {
      console.warn('Backend masking fallback to local engine:', err);
      try {
        const localResult = clientSideMaskTextIocs(inputText, maskMode, {
          hashWrapPound,
          hashWrapStyle,
        });
        setResult(localResult);
      } catch (localErr: any) {
        setErrorMsg(err.message || 'An error occurred while processing indicators.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!result?.maskedContent) return;
    navigator.clipboard.writeText(result.maskedContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportSameFormat = (targetFormat: 'csv' | 'xlsx' | 'txt') => {
    if (!result) return;

    if (targetFormat === 'csv' || targetFormat === 'xlsx') {
      const rows = result.maskedContent.split('\n').map((line) => line.split(','));
      const ws = XLSX.utils.aoa_to_sheet(rows);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'MaskedIOCs');

      if (targetFormat === 'xlsx') {
        XLSX.writeFile(wb, `Masked_IOC_Report_${Date.now()}.xlsx`);
      } else {
        XLSX.writeFile(wb, `Masked_IOC_Report_${Date.now()}.csv`, { bookType: 'csv' });
      }
    } else {
      const blob = new Blob([result.maskedContent], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `Masked_Logs_${Date.now()}.txt`;
      link.click();
      URL.revokeObjectURL(url);
    }
  };

  const filteredExtractedIocs = (result?.extractedIocs || []).filter(
    (ioc) =>
      ioc.original.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ioc.masked.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ioc.type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 font-mono text-xs max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono">
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          <span>Automated IOC Masker, Defanger & Multi-File Transformer</span>
        </div>
        <h2 className="text-xl font-bold text-white font-mono">
          Mask & Defang Threat Indicators in CSV, Excel, Text, or Screenshots
        </h2>
        <p className="text-slate-400 font-sans text-xs leading-relaxed max-w-3xl">
          Upload logs in CSV, Excel (.xlsx), text files, document screenshots, or paste raw text. Instantly defang or redact IPs, URLs, domains, email addresses, and hashes with format-preserving exports.
        </p>
      </div>

      {/* Main Input Card */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] space-y-6">
        {/* Upload Options and Masking Mode Selectors */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
          {/* File Upload Zone */}
          <div className="md:col-span-6 space-y-2">
            <label className="text-cyan-300 font-bold text-xs flex items-center gap-2">
              <Upload className="w-4 h-4 text-cyan-400" />
              Upload Input File (CSV, Excel, Text, Image):
            </label>

            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".csv,.xlsx,.xls,.txt,.log,.json,.png,.jpg,.jpeg,.webp"
              className="hidden"
            />

            <div
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-[#1B3047] hover:border-cyan-500/60 bg-[#060D18] p-4 rounded-xl text-center cursor-pointer transition-all space-y-1 hover:bg-[#101F32]"
            >
              <div className="flex items-center justify-center gap-2 text-slate-400 text-xs">
                <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
                <FileText className="w-4 h-4 text-teal-400" />
                <ImageIcon className="w-4 h-4 text-slate-400" />
                <span className="font-semibold text-slate-200">
                  {selectedFileName ? `Selected: ${selectedFileName}` : 'Click to Upload CSV, Excel, Text or Image'}
                </span>
              </div>
              <p className="text-[10px] text-slate-500 font-sans">
                Supports .csv, .xlsx, .txt, .log, and screenshots (.png/.jpg with OCR)
              </p>
            </div>
          </div>

          {/* Masking Mode Radios */}
          <div className="md:col-span-6 space-y-2">
            <label className="text-cyan-300 font-bold text-xs flex items-center gap-2">
              <EyeOff className="w-4 h-4 text-cyan-400" />
              Select Masking / Defanging Strategy:
            </label>

            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setMaskMode('defang')}
                className={`p-2.5 rounded-xl border text-left font-mono text-[11px] transition-all cursor-pointer ${
                  maskMode === 'defang'
                    ? 'bg-cyan-500/20 border-cyan-500 text-cyan-300 font-bold'
                    : 'bg-[#060D18] border-[#1B3047] text-slate-400 hover:text-cyan-300'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span>Defang</span>
                  <Check className={`w-3.5 h-3.5 ${maskMode === 'defang' ? 'opacity-100 text-cyan-400' : 'opacity-0'}`} />
                </div>
                <div className="text-[9px] text-slate-500 font-sans mt-1">192[.]168[.]1[.]1</div>
              </button>

              <button
                type="button"
                onClick={() => setMaskMode('redact')}
                className={`p-2.5 rounded-xl border text-left font-mono text-[11px] transition-all cursor-pointer ${
                  maskMode === 'redact'
                    ? 'bg-cyan-500/20 border-cyan-500 text-cyan-300 font-bold'
                    : 'bg-[#060D18] border-[#1B3047] text-slate-400 hover:text-cyan-300'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span>Full Redact</span>
                  <Check className={`w-3.5 h-3.5 ${maskMode === 'redact' ? 'opacity-100 text-cyan-400' : 'opacity-0'}`} />
                </div>
                <div className="text-[9px] text-slate-500 font-sans mt-1">[MASKED-IP]</div>
              </button>

              <button
                type="button"
                onClick={() => setMaskMode('hash_mask')}
                className={`p-2.5 rounded-xl border text-left font-mono text-[11px] transition-all cursor-pointer ${
                  maskMode === 'hash_mask'
                    ? 'bg-cyan-500/20 border-cyan-500 text-cyan-300 font-bold'
                    : 'bg-[#060D18] border-[#1B3047] text-slate-400 hover:text-cyan-300'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span>Token Mask</span>
                  <Check className={`w-3.5 h-3.5 ${maskMode === 'hash_mask' ? 'opacity-100 text-cyan-400' : 'opacity-0'}`} />
                </div>
                <div className="text-[9px] text-slate-500 font-sans mt-1">[IP-TOKEN-12]</div>
              </button>
            </div>
          </div>
        </div>

        {/* Hash Values Masking (# at Start & End) Feature Panel */}
        <div className="bg-[#060D18] p-4 rounded-xl border border-cyan-500/30 space-y-3 relative overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-start sm:items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-mono font-bold text-base shrink-0">
                <Hash className="w-4 h-4 text-cyan-400" />
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-white font-bold text-xs flex items-center gap-1.5">
                    Hash Masking: Add <span className="text-cyan-300 font-mono text-sm font-extrabold">#</span> at Start &amp; End
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-cyan-400" /> #HASH# DEFANGER
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                  Prepends and appends <span className="font-mono text-cyan-300 font-semibold">#</span> to SHA256, SHA512, SHA1, and MD5 hashes (e.g. <span className="font-mono text-cyan-300">#5d4140...c592#</span>) to defang execution in CLIs, tickets, and automated sandbox pipelines.
                </p>
              </div>
            </div>

            {/* Feature Toggle */}
            <button
              type="button"
              onClick={() => setHashWrapPound(!hashWrapPound)}
              className={`px-3.5 py-2 rounded-xl border text-xs font-mono font-bold flex items-center gap-2 transition-all cursor-pointer ${
                hashWrapPound
                  ? 'bg-cyan-500/20 border-cyan-400 text-cyan-300 shadow-md shadow-cyan-500/10'
                  : 'bg-[#0B1726] border-[#1B3047] text-slate-400 hover:text-slate-200'
              }`}
            >
              <div className={`w-2.5 h-2.5 rounded-full ${hashWrapPound ? 'bg-cyan-400 shadow-[0_0_8px_#22d3ee]' : 'bg-slate-600'}`} />
              <span>{hashWrapPound ? 'Enabled: # at Start & End' : 'Disabled (Standard)'}</span>
            </button>
          </div>

          {/* Format style options if hashWrapPound is active */}
          {hashWrapPound && (
            <div className="pt-2.5 border-t border-[#1B3047]/60 flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] text-slate-400 font-mono mr-1">Enclosed Format:</span>
                <button
                  type="button"
                  onClick={() => setHashWrapStyle('full')}
                  className={`px-3 py-1.5 rounded-lg border text-[11px] font-mono transition-all cursor-pointer flex items-center gap-1.5 ${
                    hashWrapStyle === 'full'
                      ? 'bg-cyan-500/25 border-cyan-400 text-cyan-200 font-bold'
                      : 'bg-[#0B1726] border-[#1B3047] text-slate-400 hover:text-cyan-300'
                  }`}
                >
                  <Hash className="w-3 h-3 text-cyan-400" />
                  <span>#&lt;full_hash&gt;#</span>
                  <span className="text-[10px] text-cyan-300/70 font-sans">(Preserve Hash)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setHashWrapStyle('defanged')}
                  className={`px-3 py-1.5 rounded-lg border text-[11px] font-mono transition-all cursor-pointer flex items-center gap-1.5 ${
                    hashWrapStyle === 'defanged'
                      ? 'bg-cyan-500/25 border-cyan-400 text-cyan-200 font-bold'
                      : 'bg-[#0B1726] border-[#1B3047] text-slate-400 hover:text-cyan-300'
                  }`}
                >
                  <Hash className="w-3 h-3 text-cyan-400" />
                  <span>#&lt;defanged&gt;#</span>
                  <span className="text-[10px] text-cyan-300/70 font-sans">(Truncated + #)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setHashWrapStyle('token')}
                  className={`px-3 py-1.5 rounded-lg border text-[11px] font-mono transition-all cursor-pointer flex items-center gap-1.5 ${
                    hashWrapStyle === 'token'
                      ? 'bg-cyan-500/25 border-cyan-400 text-cyan-200 font-bold'
                      : 'bg-[#0B1726] border-[#1B3047] text-slate-400 hover:text-cyan-300'
                  }`}
                >
                  <Hash className="w-3 h-3 text-cyan-400" />
                  <span>#[MASKED-HASH]#</span>
                  <span className="text-[10px] text-cyan-300/70 font-sans">(Token + #)</span>
                </button>
              </div>

              {/* Live Preview of Hash Format */}
              <div className="px-2.5 py-1 rounded bg-[#040A12] border border-cyan-500/30 text-[11px] font-mono text-cyan-300 flex items-center gap-1.5">
                <span className="text-slate-400 text-[10px]">Preview:</span>
                <span className="text-cyan-200 font-bold">
                  {hashWrapStyle === 'full'
                    ? '#5d41402abc4b2a76b9719d911017c592#'
                    : hashWrapStyle === 'defanged'
                    ? '#5d4140[...HASH-DEFANGED...]17c592#'
                    : '#[MASKED-HASH]#'}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Text Input Area */}
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <label className="text-slate-400 text-[11px]">Input Raw Text / Logs / CSV Data:</label>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] text-slate-500 font-mono">Sample Presets:</span>
              <button
                type="button"
                onClick={() => {
                  setInputText(
                    `Incident #9014 Threat Actor Payload Report:
Dropper SHA256: d3b07384d113edec49eaa6238ad5ff00f72f53d2bf26090e8a798544f9c5221b
Payload MD5: 5d41402abc4b2a76b9719d911017c592
Unpacked DLL SHA1: 3b18e5123b0a394ca5e66103b45e380437836b68
Staging C2 IP: 185.220.101.5:443
Beacon Domain: update-microsoft-azure.cc`
                  );
                }}
                className="text-[10px] text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 hover:bg-cyan-900/40 border border-cyan-500/30 px-2 py-0.5 rounded cursor-pointer transition-colors"
              >
                Hashes + C2 Sample
              </button>
              <button
                type="button"
                onClick={() => {
                  setInputText(
                    `Incident #8492 Log Details:
Suspect IP address 192.168.1.105 communicated with C2 server at 185.220.101.5 on port 443.
Phishing email received from attacker@malware-domain.org directing user to http://phishing-update.net/login.php.
Downloaded payload executable SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
MD5 hash: 5d41402abc4b2a76b9719d911017c592.`
                  );
                }}
                className="text-[10px] text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-slate-700 px-2 py-0.5 rounded cursor-pointer transition-colors"
              >
                Default Log
              </button>
              <button
                type="button"
                onClick={() => {
                  setInputText('');
                  setSelectedFileName(null);
                  setFileDataUri(null);
                  setParsedGrid(null);
                  setResult(null);
                }}
                className="text-slate-500 hover:text-cyan-300 text-[10px] cursor-pointer"
              >
                Clear Input
              </button>
            </div>
          </div>

          <textarea
            id="input-ioc-text-area"
            rows={6}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Paste raw log data, CSV, email headers, or IOC lists here..."
            className="w-full bg-[#060D18] text-slate-200 font-mono text-xs p-3.5 rounded-xl border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500/40 focus:border-cyan-500/60 leading-relaxed"
          />
        </div>

        {/* Error Alert Display */}
        {errorMsg && (
          <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-xl text-red-300 text-xs flex items-center justify-between gap-2">
            <span>{errorMsg}</span>
            <button
              onClick={() => setErrorMsg(null)}
              className="text-red-400 hover:text-red-200 font-bold px-2 py-0.5"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Submit Button */}
        <div className="flex justify-end">
          <button
            id="btn-submit-mask-iocs"
            onClick={handleMaskSubmit}
            disabled={loading || !inputText.trim()}
            className="px-8 py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-40 text-[#060D18] font-bold flex items-center gap-2 shadow-md shadow-cyan-500/10 cursor-pointer transition-colors"
          >
            {loading ? (
              <span>Processing & Defanging IOCs...</span>
            ) : (
              <>
                <Zap className="w-4 h-4 text-[#060D18]" />
                <span>Submit & Mask IOCs</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* IOC Count Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="bg-[#0B1726] p-3.5 rounded-xl border border-[#1B3047] text-center">
              <span className="text-slate-400 text-[10px] uppercase font-bold">Total IOCs</span>
              <div className="text-2xl font-extrabold text-cyan-400 mt-0.5">{result.counts.total}</div>
            </div>
            <div className="bg-[#0B1726] p-3.5 rounded-xl border border-[#1B3047] text-center">
              <span className="text-slate-400 text-[10px] uppercase font-bold">IP Addresses</span>
              <div className="text-2xl font-extrabold text-teal-400 mt-0.5">{result.counts.ip}</div>
            </div>
            <div className="bg-[#0B1726] p-3.5 rounded-xl border border-[#1B3047] text-center">
              <span className="text-slate-400 text-[10px] uppercase font-bold">URLs</span>
              <div className="text-2xl font-extrabold text-cyan-400 mt-0.5">{result.counts.url}</div>
            </div>
            <div className="bg-[#0B1726] p-3.5 rounded-xl border border-[#1B3047] text-center">
              <span className="text-slate-400 text-[10px] uppercase font-bold">Domains</span>
              <div className="text-2xl font-extrabold text-teal-400 mt-0.5">{result.counts.domain}</div>
            </div>
            <div className="bg-[#0B1726] p-3.5 rounded-xl border border-[#1B3047] text-center">
              <span className="text-slate-400 text-[10px] uppercase font-bold flex items-center justify-center gap-1">
                <Hash className="w-3 h-3 text-purple-400" />
                Hashes
              </span>
              <div className="text-2xl font-extrabold text-purple-400 mt-0.5">{result.counts.hash}</div>
              {hashWrapPound && (
                <span className="text-[9px] text-cyan-400 font-mono font-bold block mt-0.5"># wrapped</span>
              )}
            </div>
            <div className="bg-[#0B1726] p-3.5 rounded-xl border border-[#1B3047] text-center">
              <span className="text-slate-400 text-[10px] uppercase font-bold">Emails</span>
              <div className="text-2xl font-extrabold text-cyan-400 mt-0.5">{result.counts.email}</div>
            </div>
          </div>

          {/* Masked Output & Export Bar */}
          <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden shadow-xl">
            {/* Header Toolbar */}
            <div className="bg-[#060D18] px-6 py-4 border-b border-[#1B3047] flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2 text-cyan-300 font-bold flex-wrap">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <span>Masked / Defanged Output ({maskMode.toUpperCase()} MODE)</span>
                {hashWrapPound && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1">
                    <Hash className="w-3 h-3" /> #HASH# WRAPPED
                  </span>
                )}
              </div>

              {/* Export in Same Format Controls */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={handleCopy}
                  className="px-3 py-1.5 rounded-lg bg-[#101F32] hover:bg-[#1B3047] text-cyan-300 border border-[#1B3047] flex items-center gap-1.5 text-[11px] transition-colors cursor-pointer"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied' : 'Copy Text'}
                </button>

                <button
                  onClick={() => handleExportSameFormat('csv')}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 text-[11px] font-bold transition-all cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  Export CSV (.csv)
                </button>

                <button
                  onClick={() => handleExportSameFormat('xlsx')}
                  className="px-3 py-1.5 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 border border-teal-500/30 flex items-center gap-1.5 text-[11px] font-bold transition-all cursor-pointer"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5 text-teal-400" />
                  Export Excel (.xlsx)
                </button>

                <button
                  onClick={() => handleExportSameFormat('txt')}
                  className="px-3 py-1.5 rounded-lg bg-[#101F32] hover:bg-[#1B3047] text-slate-300 border border-[#1B3047] flex items-center gap-1.5 text-[11px] font-bold transition-all cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5 text-slate-400" />
                  Export Text (.txt)
                </button>
              </div>
            </div>

            {/* Masked Content View */}
            <pre className="p-6 bg-[#060D18] text-slate-200 font-mono text-xs leading-relaxed overflow-x-auto whitespace-pre border-b border-[#1B3047] max-h-80">
              <code>{result.maskedContent}</code>
            </pre>
          </div>

          {/* Extracted IOCs Table & Investigation Pivots */}
          <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <h3 className="font-bold text-white text-sm flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Extracted Indicators Table ({result.extractedIocs.length})
              </h3>

              {/* Filter Search */}
              <div className="relative min-w-[200px]">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400/60" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filter IOCs..."
                  className="w-full bg-[#060D18] text-slate-200 font-mono text-[11px] pl-8 pr-3 py-1.5 rounded-lg border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500/40 focus:border-cyan-500/60"
                />
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-[11px]">
                <thead>
                  <tr className="bg-[#060D18] text-slate-400 border-b border-[#1B3047]">
                    <th className="p-3 font-bold font-mono">Type</th>
                    <th className="p-3 font-bold font-mono">Original Indicator</th>
                    <th className="p-3 font-bold font-mono text-cyan-300">Masked / Defanged Output</th>
                    <th className="p-3 font-bold font-mono text-center">Occurrences</th>
                    <th className="p-3 font-bold font-mono text-right">Threat Intel Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1B3047] text-slate-300">
                  {filteredExtractedIocs.map((ioc, idx) => (
                    <tr key={idx} className="hover:bg-[#101F32]/50 transition-colors">
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border inline-flex items-center gap-1 ${
                          ioc.type === 'hash'
                            ? 'bg-purple-950/40 text-purple-300 border-purple-500/40'
                            : 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                        }`}>
                          {ioc.type === 'hash' && <Hash className="w-3 h-3 text-purple-400" />}
                          {ioc.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-slate-200 select-all">{ioc.original}</td>
                      <td className="p-3 font-mono text-cyan-300 font-semibold">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span>{ioc.masked}</span>
                          {ioc.type === 'hash' && ioc.masked.startsWith('#') && ioc.masked.endsWith('#') && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-950/70 border border-cyan-500/40 text-cyan-300">
                              #...# ENCLOSED
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-3 text-center text-slate-400">{ioc.count}</td>
                      <td className="p-3 text-right">
                        {onInvestigateIoc && (
                          <button
                            onClick={() => onInvestigateIoc(ioc.original)}
                            className="px-2.5 py-1 rounded bg-[#060D18] hover:bg-[#101F32] text-cyan-300 border border-cyan-500/30 font-bold inline-flex items-center gap-1 transition-all cursor-pointer"
                          >
                            <span>Investigate OSINT</span>
                            <ArrowRight className="w-3 h-3 text-cyan-400" />
                          </button>
                        )}
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
  );
};
