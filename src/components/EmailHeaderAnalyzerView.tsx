import React, { useState } from 'react';
import {
  Mail,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Clock,
  ArrowRight,
  Copy,
  Check,
  Search,
  Zap,
  Globe,
  Lock,
  Server,
  FileText,
  Upload,
  RefreshCw,
  Tag,
  Sparkles,
  Crosshair,
  Target,
} from 'lucide-react';
import { EmailHeaderAnalysisResult, UserRole } from '../types';

interface EmailHeaderAnalyzerViewProps {
  onInvestigateIoc?: (ioc: string) => void;
  onSendToCopilot?: (query: string) => void;
  userRole?: UserRole;
}

const SAMPLE_HEADERS = [
  {
    id: 'ceo_spoof',
    label: 'CEO Fraud / BEC (Executive Spoof & Wire Divergence)',
    description: 'Impersonates CEO display name with spoofed return-path and offshore reply-to divergence.',
    headers: `Delivered-To: victim-cfo@enterprise-corp.com
Received: by 2002:a05:620a:1189:0:0:0:0 with SMTP id af9csp1092837qkb;
        Thu, 20 Aug 2026 08:14:22 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IFnKk189dsjk2398jksdnfsdf
X-Received: by 2002:a2e:920c:0:b0:2e1:6554:78f1 with SMTP id n12-20020a2e920c000000b002e1655478f1mr2918413lje.56.1724166861912;
        Thu, 20 Aug 2026 08:14:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724166861; cv=none;
        d=google.com; s=arc-20240605;
        b=Nsd823...
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of evil-relay@spoof-sender-direct.xyz does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=evil-relay@spoof-sender-direct.xyz;
       dkim=fail header.i=@enterprise-corp.com;
       dmarc=fail (p=REJECT sp=REJECT dis=quarantine) header.from=enterprise-corp.com
Received: from mail-relay-out.bulletproof-host.ru (mail-relay-out.bulletproof-host.ru. [185.220.101.5])
        by mx.google.com with ESMTPS id o18-20020a170907291200b00a307e5b22b1si3401242ejc.829.2026.08.20.08.14.20
        for <victim-cfo@enterprise-corp.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Aug 2026 08:14:20 -0700 (PDT)
Received-SPF: fail (google.com: domain of evil-relay@spoof-sender-direct.xyz does not designate 185.220.101.5 as permitted sender) client-ip=185.220.101.5;
Message-ID: <20260820151419.89201.qmail@spoof-sender-direct.xyz>
Date: Thu, 20 Aug 2026 15:14:19 +0000
From: "Satya Nadella (CEO)" <ceo@enterprise-corp.com>
Reply-To: "Executive Office" <executive-secret-payments@offshore-banking-wire.cc>
Return-Path: <evil-relay@spoof-sender-direct.xyz>
To: <victim-cfo@enterprise-corp.com>
Subject: URGENT: Confidential Acquisition Wire Transfer - Immediate Execution Required
X-Originating-IP: [185.220.101.5]
X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8`,
  },
  {
    id: 'phish_m365',
    label: 'Credential Harvester (M365 EvilPhish Kit & DKIM Fail)',
    description: 'Phishing lure masquerading as IT Helpdesk with misaligned DKIM signing and fake password urgency.',
    headers: `Delivered-To: user.bob@company-domain.com
Received: by 2002:a05:6808:14d:0:0:0:0 with SMTP id j13csp849129oik;
        Wed, 19 Aug 2026 14:22:10 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=softfail (google.com: domain of transitioning helpdesk@it-support-update-service.tk does not designate 103.253.144.18 as permitted sender) smtp.mailfrom=helpdesk@it-support-update-service.tk;
       dkim=fail (bad signature) header.i=@it-support-update-service.tk;
       dmarc=fail (p=NONE dis=none) header.from=microsoft365-security-alert.com
Received: from vps-mailer.offshore-cloud.net (vps-mailer.offshore-cloud.net. [103.253.144.18])
        by mx.google.com with ESMTPS id p8-20020a170906324800b00a30b7e21245si1029481ejn.102.2026.08.19.14.22.09
        for <user.bob@company-domain.com>;
        Wed, 19 Aug 2026 14:22:09 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning helpdesk@it-support-update-service.tk) client-ip=103.253.144.18;
From: "Microsoft 365 Security Team" <no-reply@microsoft365-security-alert.com>
To: <user.bob@company-domain.com>
Reply-To: <credentials-harvest@it-support-update-service.tk>
Return-Path: <helpdesk@it-support-update-service.tk>
Subject: Action Required: Password Expiry Notification - 2 Hours Remaining
Date: Wed, 19 Aug 2026 21:22:00 +0000
Message-ID: <92837192.102938@it-support-update-service.tk>
X-Originating-IP: [103.253.144.18]
X-Mailer: EvilPhish Kit v4.2`,
  },
  {
    id: 'm365_legit',
    label: 'Legitimate Corporate Mail (Microsoft 365 Enterprise)',
    description: 'Fully authenticated email with passing SPF, DKIM, and DMARC alignment.',
    headers: `Delivered-To: analyst@security-ops.com
Received: by 2002:a05:6838:1a4:0:0:0:0 with SMTP id d4csp1298499nki;
        Thu, 20 Aug 2026 06:12:05 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of prvs=0849c7198=john.doe@partner-firm.com designates 40.107.93.82 as permitted sender) smtp.mailfrom=prvs=0849c7198=john.doe@partner-firm.com;
       dkim=pass header.i=@partner-firm.com header.s=selector1 header.b=X9bL4A;
       dmarc=pass (p=REJECT sp=REJECT dis=none) header.from=partner-firm.com
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (mail-bn8nam11on2082.outbound.protection.outlook.com. [40.107.93.82])
        by mx.google.com with ESMTPS id u12-20020a17090623cc00b00a35db4050a4si2910481ejk.492.2026.08.20.06.12.04
        for <analyst@security-ops.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Aug 2026 06:12:04 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=partner-firm.com;
 s=selector1;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=y8f/K92jKsj28jsdf...;
 b=X9bL4A...
Received: from DM6PR19MB3920.namprd19.prod.outlook.com (2603:10b6:5:273::14)
 by DM6PR19MB4201.namprd19.prod.outlook.com (2603:10b6:5:2d0::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7853.18; Thu, 20 Aug
 2026 13:12:01 +0000
Message-ID: <DM6PR19MB3920E783B38A234A51@namprd19.prod.outlook.com>
Date: Thu, 20 Aug 2026 13:12:01 +0000
From: "John Doe" <john.doe@partner-firm.com>
To: "Security Analyst" <analyst@security-ops.com>
Subject: Q3 Security Audit Schedule & Architecture Review
Content-Type: multipart/alternative; boundary="_000_DM6PR19MB3920_"
MIME-Version: 1.0`,
  },
];

export const EmailHeaderAnalyzerView: React.FC<EmailHeaderAnalyzerViewProps> = ({
  onInvestigateIoc,
  onSendToCopilot,
}) => {
  const [headersInput, setHeadersInput] = useState<string>(SAMPLE_HEADERS[0].headers);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<EmailHeaderAnalysisResult | null>(null);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const handleCopy = (text: string, section: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const handleAnalyze = async (customHeaders?: string) => {
    const textToAnalyze = customHeaders !== undefined ? customHeaders : headersInput;
    if (!textToAnalyze.trim()) return;

    setLoading(true);
    try {
      const res = await fetch('/api/analyze-email-header', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headersText: textToAnalyze }),
      });

      if (res.ok) {
        const data = await res.json();
        setResult(data);
      } else {
        throw new Error('Failed to analyze header');
      }
    } catch (err) {
      console.error('Email header analysis error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (text) {
        setHeadersInput(text);
        handleAnalyze(text);
      }
    };
    reader.readAsText(file);
  };

  const getVerdictStyle = (verdict: string) => {
    switch (verdict) {
      case 'Malicious / Phishing':
      case 'Spoofed':
        return {
          bg: 'bg-[#EF4444]/10 border-[#EF4444]/40 text-[#EF4444]',
          badge: 'bg-[#EF4444] text-white font-bold',
          icon: ShieldAlert,
          title: 'HIGH RISK THREAT / PHISHING',
        };
      case 'Suspicious':
        return {
          bg: 'bg-[#F59E0B]/10 border-[#F59E0B]/40 text-[#F59E0B]',
          badge: 'bg-[#F59E0B] text-slate-950 font-semibold',
          icon: AlertTriangle,
          title: 'SUSPICIOUS EMAIL / IRREGULARITIES',
        };
      case 'Legitimate':
      default:
        return {
          bg: 'bg-[#22C55E]/10 border-[#22C55E]/30 text-[#22C55E]',
          badge: 'bg-[#22C55E]/20 text-[#22C55E] border border-[#22C55E]/40 font-semibold',
          icon: ShieldCheck,
          title: 'AUTHENTICATED & LEGITIMATE',
        };
    }
  };

  const getAuthBadge = (status: string) => {
    const s = (status || '').toLowerCase();
    if (s.includes('pass')) {
      return 'bg-[#22C55E]/15 text-[#22C55E] border-[#22C55E]/40 font-semibold';
    }
    if (s.includes('fail')) {
      return 'bg-[#EF4444]/15 text-[#EF4444] border-[#EF4444]/50 font-bold';
    }
    if (s.includes('softfail') || s.includes('neutral')) {
      return 'bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/40';
    }
    return 'bg-[#060D18] text-slate-400 border-[#1B3047]';
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 font-sans text-xs">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-[#1B3047] pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <Mail className="w-5 h-5" />
            </span>
            <div>
              <h1 className="text-xl font-bold text-white font-sans tracking-tight">
                Email Header Analyzer & Threat Classifier
              </h1>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Full RFC 5322 header parser, SPF/DKIM/DMARC authentication triage, hop timeline reconstruction, and automated email type categorization (BEC, Credential Harvester, Malware Stager).
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <label className="cursor-pointer px-3 py-1.5 rounded-lg border border-[#1B3047] bg-[#0B1726] hover:bg-[#101F32] text-cyan-300 text-xs font-medium flex items-center gap-1.5 transition-colors shadow-xs">
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            Upload .eml / .txt
            <input type="file" accept=".eml,.msg,.txt" onChange={handleFileUpload} className="hidden" />
          </label>
        </div>
      </div>

      {/* Preset Quick Loader Buttons */}
      <div className="space-y-2">
        <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
          <Zap className="w-3 h-3 text-cyan-400" />
          Quick Test Scenario Presets
        </span>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          {SAMPLE_HEADERS.map((sample) => (
            <button
              key={sample.id}
              onClick={() => {
                setHeadersInput(sample.headers);
                handleAnalyze(sample.headers);
              }}
              className="text-left p-3 rounded-xl border border-[#1B3047] bg-[#0B1726] hover:bg-[#101F32] hover:border-cyan-500/40 transition-all group cursor-pointer"
            >
              <div className="text-xs font-semibold text-white group-hover:text-cyan-300 transition-colors">
                {sample.label}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                {sample.description}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Header Input Area */}
      <div className="rounded-xl border border-[#1B3047] bg-[#0B1726] p-4 shadow-xl space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-300 flex items-center gap-2">
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            Paste Raw RFC 5322 Email Headers
          </label>
          <span className="text-[11px] text-slate-400 font-mono">
            {headersInput.split('\n').length} lines ({headersInput.length} chars)
          </span>
        </div>

        <textarea
          value={headersInput}
          onChange={(e) => setHeadersInput(e.target.value)}
          placeholder="Paste full email headers starting with Received:, From:, To:, Subject:, Authentication-Results:..."
          rows={6}
          className="w-full font-mono text-xs p-3 rounded-lg bg-[#060D18] border border-[#1B3047] text-cyan-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 transition-all resize-y"
        />

        <div className="flex items-center justify-between pt-1">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Tag className="w-3 h-3 text-slate-500" />
            Supports Gmail, Outlook/M365, Exchange, Postfix, Sendmail, and generic MTA headers
          </div>

          <button
            onClick={() => handleAnalyze()}
            disabled={loading || !headersInput.trim()}
            className="px-5 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-[#060D18] text-xs font-bold flex items-center gap-2 transition-colors shadow-md shadow-cyan-500/10 cursor-pointer"
          >
            {loading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#060D18]" />
                Analyzing Headers & Authentication...
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5 text-[#060D18]" />
                Execute Deep Investigation & Categorization
              </>
            )}
          </button>
        </div>
      </div>

      {/* Investigation Results Display */}
      {result && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Forensic Email Conclusion & Type Classification Card */}
          <div className="rounded-2xl border border-[#1B3047] bg-[#0B1726] p-5 shadow-2xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-[#1B3047] pb-3">
              <div className="flex items-center gap-2.5">
                <span className="p-2 rounded-lg bg-teal-500/15 text-teal-300 border border-teal-500/30">
                  <Sparkles className="w-5 h-5 text-teal-400" />
                </span>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-bold uppercase tracking-wider text-white font-mono">
                      Forensic Email Type Conclusion
                    </h2>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold">
                      Automated Triage Tagging
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-0.5">
                    Conclusive classification derived from envelope authentication, header divergence, and MTA routing analysis.
                  </p>
                </div>
              </div>

              {/* Confidence Badge */}
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">Classification Confidence:</span>
                <span className="px-2.5 py-1 rounded-lg bg-teal-500/15 border border-teal-500/30 text-teal-300 font-mono font-bold text-xs flex items-center gap-1.5">
                  <Target className="w-3.5 h-3.5 text-teal-400" />
                  {result.confidenceLevel || 'High (95%)'}
                </span>
              </div>
            </div>

            {/* Email Category Spotlight */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
              <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Identified Email Category
                </span>
                <div className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
                  {result.emailCategory || 'Business Email Compromise (BEC)'}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  MITRE ATT&CK Technique
                </span>
                <div className="text-xs font-semibold text-cyan-300 font-mono flex items-center gap-1.5">
                  <Crosshair className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  {result.attackTechnique || 'T1566.002 - Spearphishing Link'}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Primary Threat Intent
                </span>
                <div className="text-xs font-semibold text-teal-300 font-sans truncate">
                  {result.threatIntent || 'Financial Wire Fraud / Credential Theft'}
                </div>
              </div>
            </div>

            {/* Classification Rationale */}
            {result.emailClassificationRationale && (
              <div className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-xs text-slate-200 leading-relaxed font-sans">
                <strong className="text-cyan-300 font-mono block mb-1">
                  Investigation Rationale & Forensic Proof:
                </strong>
                {result.emailClassificationRationale}
              </div>
            )}
          </div>

          {/* Top Threat Banner & Security Tags */}
          {(() => {
            const style = getVerdictStyle(result.verdict);
            const Icon = style.icon;
            return (
              <div className={`rounded-xl border p-5 ${style.bg} space-y-4 shadow-xl`}>
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="p-3 rounded-xl bg-[#060D18] border border-inherit">
                      <Icon className="w-6 h-6" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold font-mono uppercase ${style.badge}`}>
                          {result.verdict}
                        </span>
                        <span className="text-xs font-mono text-slate-300">
                          Risk Score: <strong className="text-white">{result.threatScore}/100</strong>
                        </span>
                      </div>
                      <h2 className="text-base font-bold text-white mt-1">
                        {result.subject}
                      </h2>
                    </div>
                  </div>

                  {/* Threat Meter Bar */}
                  <div className="w-full sm:w-48 bg-[#060D18] p-2.5 rounded-lg border border-[#1B3047]">
                    <div className="flex justify-between text-[10px] font-mono text-slate-400 mb-1">
                      <span>Threat Index</span>
                      <span className="font-bold text-white">{result.threatScore}%</span>
                    </div>
                    <div className="w-full bg-[#0B1726] h-2 rounded-full overflow-hidden border border-[#1B3047]">
                      <div
                        className="h-full rounded-full transition-all duration-500 bg-cyan-400"
                        style={{ width: `${result.threatScore}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Security Analyst Tags */}
                <div className="pt-2 border-t border-inherit/40">
                  <div className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-300 mb-2 flex items-center gap-1.5">
                    <Tag className="w-3 h-3 text-cyan-400" />
                    Assigned Investigation Tags ({result.securityTags.length})
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {result.securityTags.map((tag) => (
                      <div
                        key={tag.id}
                        className="px-2.5 py-1 rounded-md border text-xs font-mono flex items-center gap-1.5 bg-[#060D18] text-cyan-300 border-[#1B3047]"
                        title={tag.description}
                      >
                        <span>[{tag.name}]</span>
                        <span className="text-[10px] opacity-75 font-sans">({tag.severity})</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Executive Summary */}
                <div className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] text-xs text-slate-300 leading-relaxed">
                  <strong className="text-cyan-300 font-mono">SOC Briefing: </strong>
                  {result.executiveSummary}
                </div>
              </div>
            );
          })()}

          {/* Core Metadata & Identity Alignment */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Sender / Recipient Identity */}
            <div className="rounded-xl border border-[#1B3047] bg-[#0B1726] p-4 space-y-3">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-white flex items-center gap-2 border-b border-[#1B3047] pb-2">
                <Mail className="w-3.5 h-3.5 text-cyan-400" />
                Sender & Recipient Envelope Identity
              </h3>

              <div className="space-y-2.5 text-xs">
                <div>
                  <span className="text-slate-400 block text-[11px]">From (Header):</span>
                  <div className="font-mono text-white break-all bg-[#060D18] p-2 rounded border border-[#1B3047] mt-0.5">
                    {result.from.name && (
                      <span className="text-cyan-300 font-bold block">{result.from.name}</span>
                    )}
                    <span className="text-slate-300">&lt;{result.from.address}&gt;</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Reply-To:</span>
                    <div
                      className={`font-mono text-xs p-2 rounded border mt-0.5 break-all ${
                        result.replyTo?.isMismatched
                          ? 'bg-[#EF4444]/15 border-[#EF4444]/40 text-[#EF4444] font-semibold'
                          : 'bg-[#060D18] border-[#1B3047] text-slate-300'
                      }`}
                    >
                      {result.replyTo?.address || 'Same as From'}
                      {result.replyTo?.isMismatched && (
                        <span className="block text-[10px] text-[#EF4444] mt-0.5 font-sans">
                          Divergence from sender address!
                        </span>
                      )}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-400 block text-[11px]">Return-Path (Envelope):</span>
                    <div
                      className={`font-mono text-xs p-2 rounded border mt-0.5 break-all ${
                        result.returnPath?.isMismatched
                          ? 'bg-[#EF4444]/15 border-[#EF4444]/40 text-[#EF4444] font-semibold'
                          : 'bg-[#060D18] border-[#1B3047] text-slate-300'
                      }`}
                    >
                      {result.returnPath?.address || 'N/A'}
                      {result.returnPath?.isMismatched && (
                        <span className="block text-[10px] text-[#EF4444] mt-0.5 font-sans">
                          Envelope domain mismatch!
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="pt-1">
                  <span className="text-slate-400 block text-[11px]">Recipients (To):</span>
                  <div className="font-mono text-slate-300 bg-[#060D18] p-2 rounded border border-[#1B3047] mt-0.5">
                    {result.to.join(', ')}
                  </div>
                </div>
              </div>
            </div>

            {/* Email Authentication Grid (SPF, DKIM, DMARC, ARC, TLS) */}
            <div className="rounded-xl border border-[#1B3047] bg-[#0B1726] p-4 space-y-3">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-white flex items-center gap-2 border-b border-[#1B3047] pb-2">
                <Lock className="w-3.5 h-3.5 text-cyan-400" />
                Cryptographic Authentication & Policy Checks
              </h3>

              <div className="grid grid-cols-2 gap-2 text-xs">
                {/* SPF */}
                <div className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white font-mono">SPF (Sender Policy)</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] border font-mono ${getAuthBadge(result.authentication.spf.status)}`}>
                      {result.authentication.spf.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">
                    {result.authentication.spf.details}
                  </p>
                </div>

                {/* DKIM */}
                <div className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white font-mono">DKIM (Signature)</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] border font-mono ${getAuthBadge(result.authentication.dkim.status)}`}>
                      {result.authentication.dkim.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">
                    {result.authentication.dkim.details}
                  </p>
                </div>

                {/* DMARC */}
                <div className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white font-mono">DMARC Policy</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] border font-mono ${getAuthBadge(result.authentication.dmarc.status)}`}>
                      {result.authentication.dmarc.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">
                    {result.authentication.dmarc.details}
                  </p>
                </div>

                {/* TLS */}
                <div className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white font-mono">In-Transit TLS</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] border font-mono ${result.authentication.tls?.isEncrypted ? 'bg-[#22C55E]/15 text-[#22C55E] border-[#22C55E]/40' : 'bg-[#EF4444]/15 text-[#EF4444] border-[#EF4444]/50'}`}>
                      {result.authentication.tls?.isEncrypted ? 'ENCRYPTED' : 'UNENCRYPTED'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    {result.authentication.tls?.version || 'TLS 1.2+'} ({result.authentication.tls?.cipher || 'Encrypted'})
                  </p>
                </div>
              </div>

              <div className="p-2.5 rounded bg-[#060D18] border border-[#1B3047] text-[11px] text-slate-400 flex items-center justify-between">
                <span>Message-ID: <strong className="font-mono text-slate-300">{result.messageId}</strong></span>
                {result.mailerAgent && (
                  <span>Mailer: <strong className="text-cyan-400 font-mono">{result.mailerAgent}</strong></span>
                )}
              </div>
            </div>
          </div>

          {/* Delivery Transmission Path & MTA Hops Timeline */}
          <div className="rounded-xl border border-[#1B3047] bg-[#0B1726] p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-white flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                MTA Transmission Route & Latency Hop Timeline ({result.hops.length} Hops)
              </h3>
              <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                Total Transit Delay: <strong className="text-cyan-300">{result.totalTransitTime}</strong>
              </span>
            </div>

            <div className="space-y-3">
              {result.hops.map((hop) => (
                <div
                  key={hop.hopNumber}
                  className={`p-3.5 rounded-lg border text-xs transition-all ${
                    hop.isSuspicious
                      ? 'bg-[#EF4444]/10 border-[#EF4444]/40 text-slate-200'
                      : 'bg-[#060D18] border-[#1B3047] text-slate-300'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`w-6 h-6 rounded-full flex items-center justify-center font-mono font-bold text-xs ${
                        hop.isSuspicious ? 'bg-[#EF4444] text-white' : 'bg-[#0B1726] text-cyan-300 border border-[#1B3047]'
                      }`}>
                        {hop.hopNumber}
                      </span>
                      <div>
                        <span className="font-bold text-slate-300 font-mono">From: </span>
                        <span className="font-mono text-cyan-200">{hop.fromMta}</span>
                        <span className="text-slate-500 mx-1.5">→</span>
                        <span className="font-bold text-slate-300 font-mono">By: </span>
                        <span className="font-mono text-cyan-200">{hop.byMta}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {hop.ipAddress && (
                        <span className="font-mono px-2 py-0.5 rounded bg-[#0B1726] border border-[#1B3047] text-cyan-300 flex items-center gap-1">
                          <Globe className="w-3 h-3 text-cyan-400" />
                          {hop.ipAddress}
                        </span>
                      )}
                      <span className="font-mono px-2 py-0.5 rounded bg-[#0B1726] text-slate-400">
                        +{hop.delayFormatted}
                      </span>
                    </div>
                  </div>

                  <div className="mt-2 pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                    <div>
                      Protocol: <strong className="text-slate-300 font-mono">{hop.withProtocol || 'ESMTPS'}</strong>
                      {hop.country && (
                        <span className="ml-3">Location: <strong className="text-slate-300">{hop.country}</strong> {hop.asn && `(${hop.asn})`}</span>
                      )}
                    </div>

                    {hop.ipAddress && onInvestigateIoc && (
                      <button
                        onClick={() => onInvestigateIoc(hop.ipAddress!)}
                        className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition-colors cursor-pointer"
                      >
                        Investigate IP in Threat Intel <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Extracted IOCs & SIEM Threat Hunting Query */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Extracted IOCs Card */}
            <div className="rounded-xl border border-[#1B3047] bg-[#0B1726] p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-[#1B3047] pb-2">
                <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-white flex items-center gap-2">
                  <Globe className="w-3.5 h-3.5 text-cyan-400" />
                  Extracted Threat Indicators ({result.extractedIocs.length})
                </h3>
              </div>

              <div className="space-y-2">
                {result.extractedIocs.map((iocItem, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-[#060D18] border border-[#1B3047] flex items-center justify-between text-xs font-mono gap-2"
                  >
                    <div className="min-w-0">
                      <div className="text-[10px] text-slate-400 uppercase font-sans font-semibold">
                        {iocItem.role}
                      </div>
                      <div className="text-white truncate">{iocItem.value}</div>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      {onInvestigateIoc && (
                        <button
                          onClick={() => onInvestigateIoc(iocItem.value)}
                          className="p-1.5 rounded bg-[#0B1726] hover:bg-[#101F32] text-cyan-400 hover:text-cyan-300 transition-colors border border-[#1B3047] cursor-pointer"
                          title="Investigate in Threat Intel"
                        >
                          <Search className="w-3.5 h-3.5" />
                        </button>
                      )}
                      <button
                        onClick={() => handleCopy(iocItem.value, `ioc-${idx}`)}
                        className="p-1.5 rounded bg-[#0B1726] hover:bg-[#101F32] text-slate-300 transition-colors border border-[#1B3047] cursor-pointer"
                        title="Copy IOC"
                      >
                        {copiedSection === `ioc-${idx}` ? (
                          <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* SIEM Hunting Query */}
            <div className="rounded-xl border border-[#1B3047] bg-[#0B1726] p-4 space-y-3 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b border-[#1B3047] pb-2 mb-2">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-white flex items-center gap-2">
                    <Zap className="w-3.5 h-3.5 text-cyan-400" />
                    SIEM Telemetry Hunting Query
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-bold uppercase">
                    {result.siemHuntingQuery.platform}
                  </span>
                </div>

                <p className="text-xs text-slate-400 mb-2">
                  {result.siemHuntingQuery.description}
                </p>

                <div className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] font-mono text-xs text-cyan-100 overflow-x-auto whitespace-pre-wrap">
                  {result.siemHuntingQuery.query}
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2">
                <button
                  onClick={() => handleCopy(result.siemHuntingQuery.query, 'siem-query')}
                  className="flex-1 py-1.5 rounded-lg border border-[#1B3047] bg-[#060D18] hover:bg-[#101F32] text-cyan-300 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  {copiedSection === 'siem-query' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                      Copied Hunting Query
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      Copy Query
                    </>
                  )}
                </button>

                {onSendToCopilot && (
                  <button
                    onClick={() => onSendToCopilot(result.siemHuntingQuery.query)}
                    className="flex-1 py-1.5 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-[#060D18] text-xs font-bold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Zap className="w-3.5 h-3.5 text-[#060D18]" />
                    Open in SIEM Copilot
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Recommended SOC Response Actions */}
          <div className="rounded-xl border border-[#1B3047] bg-[#0B1726] p-4 space-y-3">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-white flex items-center gap-2 border-b border-[#1B3047] pb-2">
              <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
              Recommended SOC Containment & Remediation Actions
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              {result.recommendedActions.map((action, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] text-slate-300 flex items-start gap-2.5"
                >
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center shrink-0 font-mono font-bold text-[10px] border border-cyan-500/30">
                    {idx + 1}
                  </span>
                  <span className="leading-relaxed">{action}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
