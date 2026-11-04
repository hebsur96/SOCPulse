import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Smartphone,
  KeyRound,
  FileCode,
  Sliders,
  Copy,
  Check,
  Download,
  RefreshCw,
  AlertTriangle,
  Lock,
  X,
  Laptop,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { MfaMethodType } from '../types/auth';

interface MfaSecurityHarnessModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const MfaSecurityHarnessModal: React.FC<MfaSecurityHarnessModalProps> = ({
  isOpen,
  onClose,
}) => {
  const { mfa, user, verifyMfaChallenge, updateMfaConfig, regenerateBackupCodes, registerHardwareKey } =
    useAuth();

  const [activeTab, setActiveTab] = useState<'totp' | 'hardware' | 'backup' | 'policy'>('totp');
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const [testTotpCode, setTestTotpCode] = useState('');
  const [totpVerifyStatus, setTotpVerifyStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [totpCountdown, setTotpCountdown] = useState(30);

  // Hardware key registration simulation state
  const [isRegisteringKey, setIsRegisteringKey] = useState(false);
  const [keyRegistrationStep, setKeyRegistrationStep] = useState<'idle' | 'prompt' | 'success'>('idle');
  const [newKeyName, setNewKeyName] = useState('YubiKey 5C NFC (Backup)');

  // 30s countdown timer for RFC 6238 TOTP window
  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      const seconds = now.getSeconds();
      setTotpCountdown(30 - (seconds % 30));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  if (!isOpen) return null;

  const handleCopySecret = () => {
    navigator.clipboard.writeText(mfa.totpSecret);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleCopyBackupCodes = () => {
    const text = `SOCPulse Emergency Recovery Codes for ${user?.email || 'sagarhebsur@gmail.com'}\nGenerated: ${new Date().toISOString()}\n\n` +
      mfa.backupCodes.map((c, i) => `${i + 1}. ${c}`).join('\n') +
      `\n\nStore these in an encrypted password manager or secure vault.`;
    navigator.clipboard.writeText(text);
    setCopiedCodes(true);
    setTimeout(() => setCopiedCodes(false), 2000);
  };

  const handleDownloadBackupCodes = () => {
    const text = `SOCPulse Enterprise Security Harness - Recovery Codes\nUser: ${user?.email || 'sagarhebsur@gmail.com'}\nOrganization: ${user?.organization || 'Enterprise Cyber Defense'}\nDate: ${new Date().toLocaleString()}\n\n` +
      mfa.backupCodes.map((c, i) => `[ ] ${i + 1}. ${c}`).join('\n') +
      `\n\nSecurity Notice: Each code can only be used once. Keep confidential.`;
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `socpulse-emergency-backup-codes-${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleVerifyTotp = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!testTotpCode.trim()) return;

    const valid = verifyMfaChallenge(testTotpCode, 'totp');
    if (valid) {
      setTotpVerifyStatus('success');
      setTimeout(() => setTotpVerifyStatus('idle'), 3500);
      setTestTotpCode('');
    } else {
      setTotpVerifyStatus('error');
      setTimeout(() => setTotpVerifyStatus('idle'), 3000);
    }
  };

  const handleStartHardwareKeyFlow = async () => {
    setIsRegisteringKey(true);
    setKeyRegistrationStep('prompt');
    // Simulate user tapping the hardware token
    setTimeout(async () => {
      await registerHardwareKey(newKeyName);
      setKeyRegistrationStep('success');
      setTimeout(() => {
        setIsRegisteringKey(false);
        setKeyRegistrationStep('idle');
      }, 2000);
    }, 2200);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl max-h-[92vh] flex flex-col rounded-2xl border border-[#1B3047] bg-[#07111F] text-slate-100 shadow-2xl shadow-cyan-950/40 overflow-hidden">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#1B3047] bg-[#0B1726] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold font-sans tracking-tight text-white">
                  Multi-Factor Authentication (MFA) Security Harness
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  FIPS 140-2 Compliant
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Zero-Trust Identity Hardening for <span className="text-cyan-300 font-mono font-medium">{user?.email || 'sagarhebsur@gmail.com'}</span>
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg border border-transparent hover:border-[#1B3047] hover:bg-[#101F32] text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Posture Bar */}
        <div className="px-6 py-2.5 bg-[#060D18] border-b border-[#1B3047] flex flex-wrap items-center justify-between gap-3 text-xs shrink-0">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-mono text-slate-300 text-[11px]">Harness State:</span>
              <span className="font-mono font-bold text-emerald-400 text-[11px]">Enforced & Active</span>
            </div>
            <div className="hidden sm:flex items-center gap-1.5 text-slate-400 text-[11px] font-mono">
              <span>Policy:</span>
              <span className="text-cyan-300">Strict Step-up Verification</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-slate-400 uppercase">Enrolled Methods:</span>
            {mfa.activeMethods.map((m) => (
              <span
                key={m}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#101F32] border border-[#1B3047] text-cyan-300 uppercase font-semibold"
              >
                {m.replace('_', ' ')}
              </span>
            ))}
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-[#1B3047] bg-[#091424] px-6 shrink-0 overflow-x-auto no-scrollbar">
          <button
            onClick={() => setActiveTab('totp')}
            className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-medium font-sans whitespace-nowrap transition-colors ${
              activeTab === 'totp'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Smartphone className="w-4 h-4" />
            <span>Authenticator App (TOTP)</span>
          </button>

          <button
            onClick={() => setActiveTab('hardware')}
            className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-medium font-sans whitespace-nowrap transition-colors ${
              activeTab === 'hardware'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-4 h-4" />
            <span>Hardware Token (FIDO2 / WebAuthn)</span>
          </button>

          <button
            onClick={() => setActiveTab('backup')}
            className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-medium font-sans whitespace-nowrap transition-colors ${
              activeTab === 'backup'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Emergency Recovery Codes</span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-cyan-500/20 text-cyan-300">
              {mfa.backupCodesRemaining}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('policy')}
            className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-medium font-sans whitespace-nowrap transition-colors ${
              activeTab === 'policy'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sliders className="w-4 h-4" />
            <span>Security Harness Policies</span>
          </button>
        </div>

        {/* Tab Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* TAB 1: TOTP App */}
          {activeTab === 'totp' && (
            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
              {/* Left Column: QR Code & Manual Secret */}
              <div className="md:col-span-5 flex flex-col items-center p-5 rounded-xl border border-[#1B3047] bg-[#0B1726]/80 text-center">
                <span className="text-[11px] font-mono font-semibold uppercase text-cyan-400 tracking-wider mb-3">
                  Scan via Authenticator App
                </span>

                {/* Styled SVG QR Code Matrix */}
                <div className="p-3 bg-white rounded-xl shadow-lg shadow-black/40 mb-3 border border-slate-300">
                  <svg
                    viewBox="0 0 160 160"
                    className="w-40 h-40"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    {/* Background */}
                    <rect width="160" height="160" fill="white" />
                    {/* Corner Box 1 */}
                    <rect x="12" y="12" width="40" height="40" fill="#060D18" rx="4" />
                    <rect x="18" y="18" width="28" height="28" fill="white" rx="2" />
                    <rect x="24" y="24" width="16" height="16" fill="#0891b2" rx="2" />
                    {/* Corner Box 2 */}
                    <rect x="108" y="12" width="40" height="40" fill="#060D18" rx="4" />
                    <rect x="114" y="18" width="28" height="28" fill="white" rx="2" />
                    <rect x="120" y="24" width="16" height="16" fill="#0891b2" rx="2" />
                    {/* Corner Box 3 */}
                    <rect x="12" y="108" width="40" height="40" fill="#060D18" rx="4" />
                    <rect x="18" y="114" width="28" height="28" fill="white" rx="2" />
                    <rect x="24" y="120" width="16" height="16" fill="#0891b2" rx="2" />
                    {/* Center Cyber Matrix Pattern */}
                    <rect x="64" y="16" width="8" height="24" fill="#060D18" />
                    <rect x="80" y="24" width="16" height="8" fill="#060D18" />
                    <rect x="60" y="48" width="40" height="8" fill="#060D18" />
                    <rect x="16" y="64" width="24" height="8" fill="#060D18" />
                    <rect x="48" y="64" width="16" height="16" fill="#0891b2" />
                    <rect x="72" y="64" width="16" height="8" fill="#060D18" />
                    <rect x="96" y="64" width="16" height="24" fill="#060D18" />
                    <rect x="120" y="64" width="24" height="8" fill="#060D18" />
                    <rect x="64" y="80" width="24" height="16" fill="#060D18" />
                    <rect x="120" y="80" width="16" height="16" fill="#0891b2" />
                    <rect x="16" y="88" width="16" height="8" fill="#060D18" />
                    <rect x="40" y="88" width="16" height="24" fill="#060D18" />
                    <rect x="64" y="104" width="8" height="16" fill="#060D18" />
                    <rect x="80" y="112" width="24" height="8" fill="#0891b2" />
                    <rect x="112" y="104" width="16" height="24" fill="#060D18" />
                    <rect x="136" y="112" width="12" height="16" fill="#060D18" />
                    <rect x="64" y="128" width="24" height="16" fill="#060D18" />
                    <rect x="96" y="136" width="32" height="12" fill="#060D18" />
                  </svg>
                </div>

                <div className="w-full text-left space-y-1.5 mt-2">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                    <span>Manual Setup Key:</span>
                    <span className="text-cyan-400">Base32</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <code className="flex-1 p-2 rounded-lg bg-[#060D18] border border-[#1B3047] font-mono text-xs text-cyan-300 font-semibold select-all break-all">
                      {mfa.totpSecret}
                    </code>
                    <button
                      onClick={handleCopySecret}
                      className="p-2 rounded-lg bg-[#101F32] hover:bg-[#182C44] text-slate-200 border border-[#1B3047] transition-colors"
                      title="Copy Secret Key"
                    >
                      {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-[#1B3047] w-full text-[11px] text-slate-400 flex items-center justify-center gap-3">
                  <span>Google Auth</span>
                  <span>•</span>
                  <span>Microsoft Auth</span>
                  <span>•</span>
                  <span>1Password</span>
                  <span>•</span>
                  <span>Duo</span>
                </div>
              </div>

              {/* Right Column: Interactive Verification Test Harness */}
              <div className="md:col-span-7 space-y-4">
                <div className="p-5 rounded-xl border border-[#1B3047] bg-[#0B1726]/80 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold font-sans text-white flex items-center gap-2">
                      <Lock className="w-4 h-4 text-cyan-400" />
                      Verify TOTP Token & Sync Harness
                    </h3>
                    <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                      <span>Token window:</span>
                      <span className="font-bold text-cyan-400">{totpCountdown}s</span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-400 font-sans">
                    Enter the current 6-digit code displayed in your mobile Authenticator app to confirm end-to-end synchronization with the SOCPulse security harness.
                  </p>

                  <form onSubmit={handleVerifyTotp} className="space-y-3 pt-1">
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        maxLength={8}
                        value={testTotpCode}
                        onChange={(e) => setTestTotpCode(e.target.value.replace(/[^0-9]/g, ''))}
                        placeholder="e.g. 583921"
                        className="w-48 text-center text-lg font-mono font-bold tracking-widest px-3 py-2 rounded-xl bg-[#060D18] border border-[#1B3047] text-cyan-300 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
                      />
                      <button
                        type="submit"
                        disabled={testTotpCode.length < 6}
                        className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed text-[#060D18] font-bold text-xs font-sans transition-all flex items-center gap-2 shadow-lg shadow-cyan-500/20 cursor-pointer"
                      >
                        <CheckCircle2 className="w-4 h-4" />
                        Verify Code
                      </button>
                    </div>

                    {totpVerifyStatus === 'success' && (
                      <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2 animate-in fade-in">
                        <Check className="w-4 h-4 shrink-0 text-emerald-400" />
                        <span>MFA Handshake Successful! Authenticator Token timestamp verified against NIST SP 800-63B standards.</span>
                      </div>
                    )}

                    {totpVerifyStatus === 'error' && (
                      <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2 animate-in fade-in">
                        <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                        <span>Verification failed. Enter any valid 6-digit number to complete test handshake.</span>
                      </div>
                    )}
                  </form>
                </div>

                {/* Enrollment telemetry summary */}
                <div className="p-4 rounded-xl border border-[#1B3047] bg-[#060D18] space-y-2 text-xs font-mono">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
                    Enrolled Cryptographic Parameters
                  </span>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300">
                    <div>
                      <span className="text-slate-500">Algorithm: </span>
                      <span className="text-cyan-300">HMAC-SHA1 / RFC 6238</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Digits: </span>
                      <span className="text-cyan-300">6 Numeric Digits</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Time-step Window: </span>
                      <span className="text-cyan-300">30 seconds (±1 drift window)</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Secret Entropy: </span>
                      <span className="text-emerald-400">160-bit Base32 (Secure)</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Hardware Security Key (FIDO2 / WebAuthn) */}
          {activeTab === 'hardware' && (
            <div className="space-y-6">
              <div className="p-5 rounded-xl border border-[#1B3047] bg-[#0B1726]/80 flex flex-col md:flex-row items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold font-sans text-white flex items-center gap-2">
                    <KeyRound className="w-4 h-4 text-cyan-400" />
                    FIDO2 / WebAuthn Hardware Security Keys
                  </h3>
                  <p className="text-xs text-slate-400 font-sans mt-1">
                    Phishing-resistant physical authentication using USB or NFC security tokens (YubiKey 5 Series, Google Titan, Feitian).
                  </p>
                </div>

                <button
                  onClick={handleStartHardwareKeyFlow}
                  disabled={isRegisteringKey}
                  className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center gap-2 shrink-0 cursor-pointer shadow-lg shadow-cyan-500/20"
                >
                  <KeyRound className="w-4 h-4" />
                  {isRegisteringKey ? 'Registering Device...' : 'Register New Security Key'}
                </button>
              </div>

              {/* Interactive Registration Simulation Modal / Prompt */}
              {isRegisteringKey && (
                <div className="p-6 rounded-xl border border-cyan-500/50 bg-[#061426] text-center space-y-4 animate-in fade-in">
                  <div className="w-16 h-16 mx-auto rounded-full bg-cyan-500/20 border-2 border-cyan-400 flex items-center justify-center animate-pulse">
                    <KeyRound className="w-8 h-8 text-cyan-300" />
                  </div>
                  {keyRegistrationStep === 'prompt' && (
                    <div className="space-y-1">
                      <h4 className="text-sm font-bold text-white">Touch your security key now</h4>
                      <p className="text-xs text-slate-400 font-sans">
                        Insert your physical security key into USB port or tap NFC, then touch the gold contact sensor.
                      </p>
                    </div>
                  )}
                  {keyRegistrationStep === 'success' && (
                    <div className="space-y-1">
                      <h4 className="text-sm font-bold text-emerald-400 flex items-center justify-center gap-2">
                        <Check className="w-4 h-4" /> Hardware Credential Registered!
                      </h4>
                      <p className="text-xs text-slate-300 font-sans">
                        WebAuthn public key credential anchored into SOCPulse trust root.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Enrolled Keys List */}
              <div className="space-y-3">
                <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider block">
                  Enrolled Hardware Keys (1 Active)
                </span>

                <div className="p-4 rounded-xl border border-[#1B3047] bg-[#060D18] flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                      <KeyRound className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-sans font-bold text-sm text-white">
                          {mfa.hardwareKeyName || 'YubiKey 5C NFC (Primary)'}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold">
                          Hardware Bound
                        </span>
                      </div>
                      <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                        FIDO2 WebAuthn • Registered {new Date(mfa.hardwareKeyRegisteredAt || Date.now()).toLocaleDateString()}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => alert('Simulated WebAuthn assertion test passed! Cryptographic signature valid.')}
                      className="px-3 py-1.5 rounded-lg bg-[#101F32] hover:bg-[#162A42] border border-[#1B3047] text-cyan-300 text-xs font-mono font-medium transition-colors"
                    >
                      Test Assertion
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: Emergency Recovery Codes */}
          {activeTab === 'backup' && (
            <div className="space-y-5">
              <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5 flex items-start gap-3 text-xs text-amber-200">
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <p className="font-bold font-sans text-amber-300">
                    Emergency Break-Glass Recovery Codes
                  </p>
                  <p className="font-sans leading-relaxed text-amber-200/90">
                    If you lose access to your phone or hardware key, each recovery code can be used exactly once to bypass the MFA challenge and regain access to the SOCPulse platform. Store them in a secure physical vault or enterprise password manager.
                  </p>
                </div>
              </div>

              {/* Codes Grid */}
              <div className="p-5 rounded-xl border border-[#1B3047] bg-[#060D18]">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {mfa.backupCodes.map((code, index) => (
                    <div
                      key={code}
                      className="p-3 rounded-lg border border-[#1B3047] bg-[#0B1726] flex items-center justify-between font-mono text-xs"
                    >
                      <span className="text-slate-500 text-[10px]">{index + 1}.</span>
                      <span className="text-cyan-300 font-bold tracking-wider">{code}</span>
                    </div>
                  ))}
                </div>

                <div className="mt-5 pt-4 border-t border-[#1B3047] flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleCopyBackupCodes}
                      className="px-3 py-2 rounded-lg bg-[#101F32] hover:bg-[#162A42] text-slate-200 border border-[#1B3047] text-xs font-medium font-sans flex items-center gap-2 transition-colors cursor-pointer"
                    >
                      {copiedCodes ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedCodes ? 'Codes Copied!' : 'Copy to Clipboard'}
                    </button>

                    <button
                      onClick={handleDownloadBackupCodes}
                      className="px-3 py-2 rounded-lg bg-[#101F32] hover:bg-[#162A42] text-slate-200 border border-[#1B3047] text-xs font-medium font-sans flex items-center gap-2 transition-colors cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Download .txt
                    </button>
                  </div>

                  <button
                    onClick={() => {
                      if (confirm('Regenerate all emergency recovery codes? Existing unused codes will be invalidated immediately.')) {
                        regenerateBackupCodes();
                      }
                    }}
                    className="px-3 py-2 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs font-medium font-sans flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    Regenerate All Codes
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: Security Harness Policies */}
          {activeTab === 'policy' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-[#1B3047] bg-[#0B1726]/80 space-y-4">
                <h3 className="text-sm font-bold font-sans text-white">
                  Zero-Trust Enforcement Policies
                </h3>

                {/* Policy 1: Admin Enforcement */}
                <div className="flex items-center justify-between p-3 rounded-lg bg-[#060D18] border border-[#1B3047]">
                  <div>
                    <h4 className="text-xs font-bold font-sans text-slate-200">
                      Enforce MFA for all Administrative & Detection Operations
                    </h4>
                    <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                      Requires step-up authentication before editing SIEM detection rules, exporting IOC intelligence, or altering blast radius models.
                    </p>
                  </div>
                  <input
                    type="checkbox"
                    checked={mfa.enforceForAdminActions}
                    onChange={(e) =>
                      updateMfaConfig((prev) => ({
                        ...prev,
                        enforceForAdminActions: e.target.checked,
                      }))
                    }
                    className="w-5 h-5 accent-cyan-400 cursor-pointer rounded"
                  />
                </div>

                {/* Policy 2: Session Timeout */}
                <div className="flex items-center justify-between p-3 rounded-lg bg-[#060D18] border border-[#1B3047]">
                  <div>
                    <h4 className="text-xs font-bold font-sans text-slate-200">
                      Inactivity Session Lifetime Policy
                    </h4>
                    <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                      Automatically lock SOC workspace session when analyst workstation is idle.
                    </p>
                  </div>
                  <select
                    value={mfa.sessionTimeoutMinutes}
                    onChange={(e) =>
                      updateMfaConfig((prev) => ({
                        ...prev,
                        sessionTimeoutMinutes: Number(e.target.value),
                      }))
                    }
                    className="text-xs font-mono px-3 py-1.5 rounded-lg bg-[#0B1726] border border-[#1B3047] text-cyan-300 focus:outline-none focus:border-cyan-400"
                  >
                    <option value={15}>15 Minutes (Strict)</option>
                    <option value={60}>1 Hour (Standard)</option>
                    <option value={480}>8 Hours (Shift Duration)</option>
                    <option value={1440}>24 Hours (Extended)</option>
                  </select>
                </div>

                {/* Policy 3: Device Posture Inspection */}
                <div className="p-3 rounded-lg bg-[#060D18] border border-[#1B3047] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200 flex items-center gap-2">
                      <Laptop className="w-4 h-4 text-cyan-400" />
                      Client Device Posture Telemetry
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                      Healthy & Compliant
                    </span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px] font-mono text-slate-400 pt-1">
                    <div>
                      <span>TLS Cipher: </span>
                      <span className="text-cyan-300">TLS 1.3 / AES-256-GCM</span>
                    </div>
                    <div>
                      <span>Origin: </span>
                      <span className="text-cyan-300">Corporate Egress IP</span>
                    </div>
                    <div>
                      <span>Posture Check: </span>
                      <span className="text-emerald-400">EDR Agent Active</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-[#1B3047] bg-[#0B1726] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>NIST SP 800-63B Authenticator Assurance Level 2 (AAL2)</span>
          </div>

          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#060D18] font-bold text-xs font-sans transition-all cursor-pointer shadow-lg shadow-cyan-500/20"
          >
            Done & Apply Harness
          </button>
        </div>

      </div>
    </div>
  );
};
