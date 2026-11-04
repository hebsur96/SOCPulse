import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Smartphone,
  KeyRound,
  Copy,
  Check,
  Lock,
  X,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
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
  const { mfa, user, verifyMfaChallenge } = useAuth();

  const [activeTab, setActiveTab] = useState<MfaMethodType>('totp');
  const [copiedKey, setCopiedKey] = useState(false);
  const [testCode, setTestCode] = useState('');
  const [verifyStatus, setVerifyStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [totpCountdown, setTotpCountdown] = useState(30);
  const [otpResent, setOtpResent] = useState(false);

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

  const handleVerify = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!testCode.trim()) return;

    const valid = verifyMfaChallenge(testCode, activeTab);
    if (valid) {
      setVerifyStatus('success');
      setTimeout(() => {
        setVerifyStatus('idle');
        setTestCode('');
      }, 3000);
    } else {
      setVerifyStatus('error');
      setTimeout(() => setVerifyStatus('idle'), 3000);
    }
  };

  const handleResendOtp = () => {
    setOtpResent(true);
    setTimeout(() => setOtpResent(false), 3000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl flex flex-col rounded-2xl border border-[#1B3047] bg-[#07111F] text-slate-100 shadow-2xl shadow-cyan-950/40 overflow-hidden">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#1B3047] bg-[#0B1726] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold font-sans tracking-tight text-white">
                  MFA Setup & Verification
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  Active
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Simple Multi-Factor Authentication for <span className="text-cyan-300 font-mono font-medium">{user?.email || user?.mobile || 'Active Account'}</span>
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

        {/* Tab Navigation: Authenticator vs OTP */}
        <div className="flex border-b border-[#1B3047] bg-[#091424] px-6 shrink-0">
          <button
            onClick={() => {
              setActiveTab('totp');
              setTestCode('');
              setVerifyStatus('idle');
            }}
            className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-semibold font-sans transition-colors ${
              activeTab === 'totp'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Smartphone className="w-4 h-4" />
            <span>Authenticator App (TOTP)</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('otp');
              setTestCode('');
              setVerifyStatus('idle');
            }}
            className={`flex items-center gap-2 py-3 px-4 border-b-2 text-xs font-semibold font-sans transition-colors ${
              activeTab === 'otp'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-4 h-4" />
            <span>OTP Code (One-Time Password)</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6">
          {activeTab === 'totp' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-[#1B3047] bg-[#060D18] flex flex-col sm:flex-row items-center gap-4">
                {/* SVG QR Code */}
                <div className="p-2.5 bg-white rounded-xl shadow-md shrink-0">
                  <svg viewBox="0 0 100 100" className="w-24 h-24" fill="none">
                    <rect width="100" height="100" fill="white" />
                    <rect x="8" y="8" width="28" height="28" fill="#060D18" rx="2" />
                    <rect x="12" y="12" width="20" height="20" fill="white" />
                    <rect x="16" y="16" width="12" height="12" fill="#0891b2" />
                    <rect x="64" y="8" width="28" height="28" fill="#060D18" rx="2" />
                    <rect x="68" y="12" width="20" height="20" fill="white" />
                    <rect x="72" y="16" width="12" height="12" fill="#0891b2" />
                    <rect x="8" y="64" width="28" height="28" fill="#060D18" rx="2" />
                    <rect x="12" y="68" width="20" height="20" fill="white" />
                    <rect x="16" y="72" width="12" height="12" fill="#0891b2" />
                    <rect x="42" y="12" width="16" height="8" fill="#060D18" />
                    <rect x="42" y="32" width="24" height="8" fill="#0891b2" />
                    <rect x="42" y="52" width="16" height="16" fill="#060D18" />
                    <rect x="64" y="52" width="24" height="8" fill="#0891b2" />
                    <rect x="42" y="80" width="20" height="12" fill="#060D18" />
                    <rect x="72" y="76" width="16" height="16" fill="#060D18" />
                  </svg>
                </div>

                <div className="space-y-2 text-left w-full">
                  <p className="text-xs text-slate-300 font-sans font-medium">
                    1. Scan QR code in Google Authenticator or Microsoft Authenticator.
                  </p>
                  <p className="text-[11px] text-slate-400 font-sans">
                    Or enter this manual secret key into your app:
                  </p>
                  <div className="flex items-center gap-1.5">
                    <code className="flex-1 p-2 rounded-lg bg-[#0B1726] border border-[#1B3047] font-mono text-xs text-cyan-300 font-bold select-all">
                      {mfa.totpSecret}
                    </code>
                    <button
                      onClick={handleCopySecret}
                      className="p-2 rounded-lg bg-[#101F32] hover:bg-[#182C44] text-slate-200 border border-[#1B3047] transition-colors"
                      title="Copy Key"
                    >
                      {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Verify Form */}
              <form onSubmit={handleVerify} className="p-4 rounded-xl border border-[#1B3047] bg-[#0B1726] space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-sans font-bold text-white flex items-center gap-2">
                    <Lock className="w-4 h-4 text-cyan-400" />
                    2. Test Authenticator Code
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    Window: <strong className="text-cyan-400">{totpCountdown}s</strong>
                  </span>
                </div>

                <div className="flex items-center gap-2 pt-1">
                  <input
                    type="text"
                    maxLength={6}
                    value={testCode}
                    onChange={(e) => setTestCode(e.target.value.replace(/[^0-9]/g, ''))}
                    placeholder="e.g. 582914"
                    className="w-44 text-center text-lg font-mono font-bold tracking-widest px-3 py-2 rounded-xl bg-[#060D18] border border-[#1B3047] text-cyan-300 focus:outline-none focus:border-cyan-400"
                  />
                  <button
                    type="submit"
                    disabled={testCode.length < 6}
                    className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    Verify Code
                  </button>
                  <button
                    type="button"
                    onClick={() => setTestCode('582914')}
                    className="text-[11px] font-mono text-cyan-400 underline hover:text-cyan-300 ml-1"
                  >
                    Fill 582914
                  </button>
                </div>

                {verifyStatus === 'success' && (
                  <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2 animate-in fade-in">
                    <Check className="w-4 h-4 shrink-0 text-emerald-400" />
                    <span>Authenticator code verified successfully!</span>
                  </div>
                )}
                {verifyStatus === 'error' && (
                  <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2 animate-in fade-in">
                    <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                    <span>Verification failed. Enter any 6-digit number.</span>
                  </div>
                )}
              </form>
            </div>
          )}

          {activeTab === 'otp' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-[#1B3047] bg-[#060D18] text-center space-y-1">
                <p className="text-xs text-slate-300 font-sans">
                  One-Time Password (OTP) verification for
                </p>
                <p className="text-xs font-mono font-bold text-cyan-300">
                  {user?.email || user?.mobile || 'User Account'}
                </p>
              </div>

              <form onSubmit={handleVerify} className="p-4 rounded-xl border border-[#1B3047] bg-[#0B1726] space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-sans font-bold text-white flex items-center gap-2">
                    <KeyRound className="w-4 h-4 text-cyan-400" />
                    Enter 6-digit OTP Code
                  </span>
                  <button
                    type="button"
                    onClick={handleResendOtp}
                    className="text-[11px] font-mono text-slate-400 hover:text-white flex items-center gap-1 cursor-pointer"
                  >
                    <RefreshCw className="w-3 h-3" />
                    Resend OTP
                  </button>
                </div>

                {otpResent && (
                  <p className="text-[11px] text-emerald-400 font-mono animate-in fade-in">
                    New OTP sent!
                  </p>
                )}

                <div className="flex items-center gap-2 pt-1">
                  <input
                    type="text"
                    maxLength={6}
                    value={testCode}
                    onChange={(e) => setTestCode(e.target.value.replace(/[^0-9]/g, ''))}
                    placeholder="492815"
                    className="w-44 text-center text-lg font-mono font-bold tracking-widest px-3 py-2 rounded-xl bg-[#060D18] border border-[#1B3047] text-cyan-300 focus:outline-none focus:border-cyan-400"
                  />
                  <button
                    type="submit"
                    disabled={testCode.length < 6}
                    className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    Verify OTP
                  </button>
                  <button
                    type="button"
                    onClick={() => setTestCode('492815')}
                    className="text-[11px] font-mono text-cyan-400 underline hover:text-cyan-300 ml-1"
                  >
                    Fill 492815
                  </button>
                </div>

                {verifyStatus === 'success' && (
                  <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2 animate-in fade-in">
                    <Check className="w-4 h-4 shrink-0 text-emerald-400" />
                    <span>OTP code verified successfully!</span>
                  </div>
                )}
                {verifyStatus === 'error' && (
                  <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2 animate-in fade-in">
                    <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                    <span>Verification failed. Enter any 6-digit number.</span>
                  </div>
                )}
              </form>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-[#1B3047] bg-[#0B1726] flex items-center justify-end shrink-0">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#060D18] font-bold text-xs font-sans transition-all cursor-pointer shadow-lg shadow-cyan-500/20"
          >
            Done
          </button>
        </div>

      </div>
    </div>
  );
};
