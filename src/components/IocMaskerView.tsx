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
} from 'lucide-react';
import * as XLSX from 'xlsx';
import { IocMaskMode, IocFileType, IocMaskResult } from '../types';

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
      console.error('Error masking IOCs:', err);
      setErrorMsg(err.message || 'An error occurred while processing indicators.');
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

        {/* Text Input Area */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-slate-400 text-[11px]">Input Raw Text / Logs / CSV Data:</label>
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
              <span className="text-slate-400 text-[10px] uppercase font-bold">Hashes</span>
              <div className="text-2xl font-extrabold text-slate-300 mt-0.5">{result.counts.hash}</div>
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
              <div className="flex items-center gap-2 text-cyan-300 font-bold">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <span>Masked / Defanged Output ({maskMode.toUpperCase()} MODE)</span>
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
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                          {ioc.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-slate-200 select-all">{ioc.original}</td>
                      <td className="p-3 font-mono text-cyan-300 font-semibold">{ioc.masked}</td>
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
