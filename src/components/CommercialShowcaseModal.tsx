import React, { useState } from 'react';
import {
  Shield,
  Check,
  X,
  Sparkles,
  Server,
  KeyRound,
  FileCheck2,
  Award,
  Zap,
  Download,
  Building2,
  PhoneCall,
  CheckCircle2,
  ArrowRight,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { CommercialTier } from '../types/auth';
import { SocPulseLogo } from './SocPulseLogo';

interface CommercialShowcaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  onOpenMfaSetup?: () => void;
}

export const CommercialShowcaseModal: React.FC<CommercialShowcaseModalProps> = ({
  isOpen,
  onClose,
  onOpenMfaSetup,
}) => {
  const { license, activateCommercialLicense, user } = useAuth();
  const [selectedBilling, setSelectedBilling] = useState<'annual' | 'monthly'>('annual');
  const [licenseKeyInput, setLicenseKeyInput] = useState('');
  const [licenseActivationResult, setLicenseActivationResult] = useState<{
    success?: boolean;
    message?: string;
  } | null>(null);

  // Quote generator form state
  const [quoteOrgName, setQuoteOrgName] = useState(user?.organization || 'Enterprise Cyber Command');
  const [quoteSeats, setQuoteSeats] = useState(25);
  const [quoteTier, setQuoteTier] = useState<CommercialTier>('enterprise');
  const [quoteGenerated, setQuoteGenerated] = useState(false);

  if (!isOpen) return null;

  const handleActivateKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (!licenseKeyInput.trim()) return;
    const res = activateCommercialLicense(licenseKeyInput);
    setLicenseActivationResult(res);
    if (res.success) {
      setTimeout(() => {
        setLicenseActivationResult(null);
        setLicenseKeyInput('');
      }, 4000);
    }
  };

  const handleDownloadQuote = () => {
    const calculatedPrice =
      quoteTier === 'enterprise'
        ? selectedBilling === 'annual'
          ? 1499 * 12 * 0.8
          : 1499 * 12
        : selectedBilling === 'annual'
        ? 499 * 12 * 0.8
        : 499 * 12;

    const quoteText = `===========================================================
SOCPulse Enterprise Defense Platform - Official Commercial Quote
Reference ID: SOCP-QUOTE-${Date.now().toString(36).toUpperCase()}
Generated: ${new Date().toLocaleDateString()}
Issued For: ${quoteOrgName}
Authorized Contact: ${user?.email || 'sagarhebsur@gmail.com'} (${user?.name || 'Sagar Hebsur'})
===========================================================

TIER & LICENSING DETAILS:
Selected Commercial Tier: ${quoteTier.toUpperCase()} DEFENSE EDITION
Analyst Seats Included: ${quoteSeats} Named Users
Billing Cadence: ${selectedBilling === 'annual' ? 'Annual (20% Commercial Discount Applied)' : 'Monthly'}
Estimated Annual Subscription: $${calculatedPrice.toLocaleString()} USD

COMMERCIAL INCLUSIONS & GUARANTEES:
- Full Multi-Platform SIEM Query Translation Studio (11 Engines + Sigma + YARA)
- AI Detection Rule Quality & Performance Benchmarker
- Attack Path & Blast Radius Simulator with Active Directory & Cloud IAM Graphs
- Automated Incident Retrospectives & CISO Executive Briefings
- Open-Source Malware Sandbox Orchestrator (CAPE, Cuckoo, DRAKVUF)
- Email Header Forensics & Phishing Classification Engine
- Multi-Feed IOC Reputation Intel with High-Fidelity VirusTotal / AbuseIPDB / Shodan
- FIPS 140-2 Cryptographic Readiness & SOC 2 Type II Compliance Reports
- Air-Gapped On-Premises Kubernetes / Docker Container Deployment Option
- 99.99% Mission-Critical Uptime SLA & 24/7 Dedicated Support Engineering

TERMS:
Quote valid for 60 calendar days from issue date.
Master Services Agreement (MSA) and Enterprise Service Level Agreement (SLA) apply.
Enterprise Payment Terms: Net 30 upon invoice.
===========================================================`;

    const blob = new Blob([quoteText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `socpulse-commercial-quote-${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(url);
    setQuoteGenerated(true);
    setTimeout(() => setQuoteGenerated(false), 3000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-5xl max-h-[92vh] flex flex-col rounded-2xl border border-[#1B3047] bg-[#07111F] text-slate-100 shadow-2xl shadow-cyan-950/50 overflow-hidden">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#1B3047] bg-[#0B1726] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <SocPulseLogo size="md" glow={true} />
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold font-sans tracking-tight text-white">
                  SOCPulse Commercial Defense Edition
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                  Enterprise Ready
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Commercial packaging, feature tiers, compliance certifications & licensing harness
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Billing Toggle */}
            <div className="flex items-center p-0.5 rounded-lg border border-[#1B3047] bg-[#060D18] text-xs font-mono">
              <button
                onClick={() => setSelectedBilling('monthly')}
                className={`px-3 py-1 rounded transition-colors ${
                  selectedBilling === 'monthly'
                    ? 'bg-[#101F32] text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Monthly
              </button>
              <button
                onClick={() => setSelectedBilling('annual')}
                className={`px-3 py-1 rounded transition-colors flex items-center gap-1 ${
                  selectedBilling === 'annual'
                    ? 'bg-[#101F32] text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <span>Annual</span>
                <span className="text-[9px] px-1 py-0.2 rounded bg-emerald-500/20 text-emerald-300 font-bold">
                  -20%
                </span>
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg border border-transparent hover:border-[#1B3047] hover:bg-[#101F32] text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-8">
          
          {/* Active License Status Banner */}
          <div className="p-4 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/30 via-[#0B1E33] to-[#07111F] flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyan-500/20 border border-cyan-400/40 text-cyan-300">
                <Award className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono uppercase text-slate-400 font-semibold">Active License:</span>
                  <span className="text-sm font-sans font-bold text-white uppercase">
                    {license.tier} Commercial Defense
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-bold">
                    ACTIVE
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-mono mt-0.5">
                  Key: <span className="text-cyan-300">{license.key}</span> • Licensed to <span className="text-white font-medium">{license.licenseeEmail}</span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 text-xs font-mono">
              <div className="text-right">
                <span className="text-slate-400 block text-[10px] uppercase">Seats Allocated</span>
                <span className="text-cyan-300 font-bold">{license.seatsAllocated} / {license.seatsTotal} Analysts</span>
              </div>
              {onOpenMfaSetup && (
                <button
                  onClick={onOpenMfaSetup}
                  className="px-3 py-1.5 rounded-lg bg-[#101F32] hover:bg-[#182C44] border border-cyan-500/40 text-cyan-300 text-xs font-sans font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  MFA Harness Settings
                </button>
              )}
            </div>
          </div>

          {/* Pricing Tiers Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Tier 1: Free Community */}
            <div className="rounded-2xl border border-[#1B3047] bg-[#0B1726]/60 p-5 flex flex-col justify-between hover:border-slate-600 transition-all">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-sans font-bold text-base text-white">Community SOC</h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    Free Forever
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-sans mb-4">
                  For individual security analysts, researchers, and homelab threat hunters.
                </p>

                <div className="mb-5 pb-4 border-b border-[#1B3047]">
                  <span className="text-3xl font-bold font-sans text-white">$0</span>
                  <span className="text-xs text-slate-400 font-mono"> / month</span>
                </div>

                <ul className="space-y-2.5 text-xs text-slate-300 font-sans mb-6">
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Ask SOCPulse Generative AI Copilot (Standard quota)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>SIEM Query Generator across 11 Platforms</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>IOC Masker & Defanger (Pound wrap & token styles)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Email Header Forensics & Phishing Classifier</span>
                  </li>
                  <li className="flex items-start gap-2 text-slate-500">
                    <X className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>No Team Collaboration or Shared Playbooks</span>
                  </li>
                  <li className="flex items-start gap-2 text-slate-500">
                    <X className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>No Air-gapped On-Premises Appliance</span>
                  </li>
                </ul>
              </div>

              <button
                disabled
                className="w-full py-2.5 rounded-xl border border-[#1B3047] bg-[#060D18] text-slate-400 text-xs font-bold font-sans cursor-default"
              >
                Included by Default
              </button>
            </div>

            {/* Tier 2: SOC Pro Team */}
            <div className="rounded-2xl border-2 border-cyan-500/60 bg-[#0B1E33]/60 p-5 flex flex-col justify-between relative shadow-xl shadow-cyan-950/30">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-cyan-400 text-[#060D18] text-[10px] font-bold font-mono uppercase tracking-wider">
                Most Popular
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-sans font-bold text-base text-white">SOC Pro Team</h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold">
                    Up to 10 Seats
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-sans mb-4">
                  For mid-sized security operation centers, MSSPs, and incident response teams.
                </p>

                <div className="mb-5 pb-4 border-b border-[#1B3047]">
                  <span className="text-3xl font-bold font-sans text-white">
                    ${selectedBilling === 'annual' ? '399' : '499'}
                  </span>
                  <span className="text-xs text-slate-400 font-mono"> / month</span>
                  {selectedBilling === 'annual' && (
                    <span className="block text-[11px] text-emerald-400 font-mono mt-0.5">
                      Billed annually ($4,788/yr)
                    </span>
                  )}
                </div>

                <ul className="space-y-2.5 text-xs text-slate-200 font-sans mb-6">
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Everything in Community, plus:</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Attack Path & Blast Radius Simulator (Full graph access)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Rule Benchmark & Cloud Compute Cost Estimator</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Automated After-Action Incident Retrospectives (AAR)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Full Multi-Feed IOC Reputation Intel API quotas</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>99.9% Uptime SLA Guarantee</span>
                  </li>
                </ul>
              </div>

              <button
                onClick={() => {
                  activateCommercialLicense('SOCP-PRO-2026-TEAM-8821');
                  alert('Upgraded to SOC Pro Team License!');
                }}
                className="w-full py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#060D18] text-xs font-bold font-sans transition-all shadow-lg shadow-cyan-500/20 cursor-pointer"
              >
                Select SOC Pro Tier
              </button>
            </div>

            {/* Tier 3: Enterprise Sovereign Defense */}
            <div className="rounded-2xl border border-teal-500/40 bg-[#071926]/70 p-5 flex flex-col justify-between hover:border-teal-400 transition-all">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-sans font-bold text-base text-white">Enterprise Sovereign</h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-teal-500/20 text-teal-300 font-bold">
                    Air-Gapped & Custom
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-sans mb-4">
                  For regulated enterprises, banking, defense contractors & critical infrastructure.
                </p>

                <div className="mb-5 pb-4 border-b border-[#1B3047]">
                  <span className="text-3xl font-bold font-sans text-white">
                    ${selectedBilling === 'annual' ? '1,199' : '1,499'}
                  </span>
                  <span className="text-xs text-slate-400 font-mono"> / month (Base)</span>
                  <span className="block text-[11px] text-teal-300 font-mono mt-0.5">
                    Unlimited Analyst Seats Available
                  </span>
                </div>

                <ul className="space-y-2.5 text-xs text-slate-200 font-sans mb-6">
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                    <span>Everything in SOC Pro Team, plus:</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                    <span>Air-Gapped On-Premises Kubernetes / Docker Appliance</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                    <span>FIPS 140-2 Level 3 Ready Cryptographic Modules</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                    <span>SAML 2.0 / Okta / Azure AD SSO & Enforced MFA Harness</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                    <span>Custom SIEM Syntax Parsers & Private LLM Endpoints</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                    <span>99.99% Mission-Critical SLA + 24/7 Dedicated Architect</span>
                  </li>
                </ul>
              </div>

              <button
                onClick={() => {
                  activateCommercialLicense('SOCP-ENT-2026-SOVEREIGN-9912');
                  alert('Activated Enterprise Sovereign Defense License!');
                }}
                className="w-full py-2.5 rounded-xl bg-teal-500 hover:bg-teal-400 text-[#060D18] text-xs font-bold font-sans transition-all shadow-lg shadow-teal-500/20 cursor-pointer"
              >
                Deploy Enterprise Defense
              </button>
            </div>

          </div>

          {/* License Activation Box */}
          <div className="p-5 rounded-2xl border border-[#1B3047] bg-[#0B1726]/80 space-y-3">
            <h3 className="text-sm font-bold font-sans text-white flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-cyan-400" />
              Activate or Upgrade Commercial License Key
            </h3>
            <p className="text-xs text-slate-400 font-sans">
              Enter your enterprise license token provided by the SOCPulse commercial licensing portal to unlock enterprise features immediately.
            </p>

            <form onSubmit={handleActivateKey} className="flex flex-wrap items-center gap-2 pt-1">
              <input
                type="text"
                placeholder="e.g. SOCP-ENT-2026-COMMERCIAL-X992"
                value={licenseKeyInput}
                onChange={(e) => setLicenseKeyInput(e.target.value)}
                className="flex-1 min-w-[280px] px-3.5 py-2.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-cyan-300 font-mono text-xs uppercase focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
              />
              <button
                type="submit"
                disabled={licenseKeyInput.length < 8}
                className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-500/20"
              >
                <Zap className="w-4 h-4" />
                Activate License
              </button>
            </form>

            {licenseActivationResult && (
              <div
                className={`p-3 rounded-xl border text-xs flex items-center gap-2 animate-in fade-in ${
                  licenseActivationResult.success
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                }`}
              >
                {licenseActivationResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <X className="w-4 h-4 text-rose-400 shrink-0" />
                )}
                <span>{licenseActivationResult.message}</span>
              </div>
            )}
          </div>

          {/* Commercial Compliance & Enterprise Readiness Badges */}
          <div className="space-y-3">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider block">
              Enterprise Compliance & Cryptographic Attestations
            </span>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3.5 rounded-xl border border-[#1B3047] bg-[#060D18] flex items-center gap-2.5">
                <FileCheck2 className="w-5 h-5 text-emerald-400 shrink-0" />
                <div>
                  <span className="text-xs font-sans font-bold text-white block">SOC 2 Type II</span>
                  <span className="text-[10px] font-mono text-slate-400">Security & Privacy Audit</span>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[#1B3047] bg-[#060D18] flex items-center gap-2.5">
                <Award className="w-5 h-5 text-cyan-400 shrink-0" />
                <div>
                  <span className="text-xs font-sans font-bold text-white block">ISO/IEC 27001</span>
                  <span className="text-[10px] font-mono text-slate-400">ISMS Global Standard</span>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[#1B3047] bg-[#060D18] flex items-center gap-2.5">
                <Shield className="w-5 h-5 text-teal-400 shrink-0" />
                <div>
                  <span className="text-xs font-sans font-bold text-white block">FIPS 140-2 Level 3</span>
                  <span className="text-[10px] font-mono text-slate-400">Cryptographic Ready</span>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[#1B3047] bg-[#060D18] flex items-center gap-2.5">
                <Server className="w-5 h-5 text-purple-400 shrink-0" />
                <div>
                  <span className="text-xs font-sans font-bold text-white block">Air-Gapped Ready</span>
                  <span className="text-[10px] font-mono text-slate-400">No Outbound Telemetry</span>
                </div>
              </div>
            </div>
          </div>

          {/* Instant Commercial Quote Generator */}
          <div className="p-5 rounded-2xl border border-[#1B3047] bg-[#0B1726]/80 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold font-sans text-white flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-cyan-400" />
                  Request Official Procurement Quote (RFP / Purchase Order)
                </h3>
                <p className="text-xs text-slate-400 font-sans mt-0.5">
                  Generate an official Commercial Purchase Proposal for internal enterprise procurement approval.
                </p>
              </div>

              <button
                onClick={handleDownloadQuote}
                className="px-4 py-2 rounded-xl bg-[#101F32] hover:bg-[#182C44] border border-cyan-500/40 text-cyan-300 text-xs font-sans font-bold flex items-center gap-2 transition-colors cursor-pointer shadow-xs"
              >
                <Download className="w-4 h-4" />
                {quoteGenerated ? 'Quote Downloaded!' : 'Download Official Quote (.txt)'}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">Organization Name</label>
                <input
                  type="text"
                  value={quoteOrgName}
                  onChange={(e) => setQuoteOrgName(e.target.value)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-[#060D18] border border-[#1B3047] text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">Target Commercial Tier</label>
                <select
                  value={quoteTier}
                  onChange={(e) => setQuoteTier(e.target.value as CommercialTier)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-[#060D18] border border-[#1B3047] text-cyan-300 focus:outline-none focus:border-cyan-400 font-mono"
                >
                  <option value="pro">SOC Pro Team ($499/mo)</option>
                  <option value="enterprise">Enterprise Sovereign Defense ($1,499/mo)</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">Analyst Seats</label>
                <input
                  type="number"
                  min={5}
                  max={500}
                  value={quoteSeats}
                  onChange={(e) => setQuoteSeats(Number(e.target.value))}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-[#060D18] border border-[#1B3047] text-white focus:outline-none focus:border-cyan-400 font-mono"
                />
              </div>
            </div>
          </div>

        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-[#1B3047] bg-[#0B1726] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <PhoneCall className="w-3.5 h-3.5 text-cyan-400" />
            <span>Commercial Inquiries: sales@socpulse.security • SLA 99.99%</span>
          </div>

          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#060D18] font-bold text-xs font-sans transition-all cursor-pointer shadow-lg shadow-cyan-500/20"
          >
            Close Showcase
          </button>
        </div>

      </div>
    </div>
  );
};
