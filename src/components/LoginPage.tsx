import React, { useState } from 'react';
import {
  Lock,
  Mail,
  ShieldCheck,
  KeyRound,
  CheckCircle2,
  ArrowRight,
  Laptop,
  Check,
  Smartphone,
  FileCode,
  AlertCircle,
  Eye,
  EyeOff,
  UserCheck,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { SocPulseLogo } from './SocPulseLogo';
import { MfaMethodType } from '../types/auth';

interface LoginPageProps {
  onSuccessLogin?: () => void;
  onContinueAsVisitor?: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({
  onSuccessLogin,
  onContinueAsVisitor,
}) => {
  const { login, verifyMfaChallenge, mfa } = useAuth();

  const [step, setStep] = useState<'credentials' | 'mfa_challenge'>('credentials');
  const [email, setEmail] = useState('sagarhebsur@gmail.com');
  const [password, setPassword] = useState('••••••••••••');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberDevice, setRememberDevice] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  // MFA Challenge State
  const [mfaMethod, setMfaMethod] = useState<MfaMethodType>('totp');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [hardwareKeyTapped, setHardwareKeyTapped] = useState(false);

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);

    if (!email.trim()) {
      setAuthError('Please provide your corporate enterprise email address.');
      return;
    }

    setIsLoading(true);

    // If MFA is enabled on the tenant, move to the MFA challenge step
    if (mfa.isEnabled) {
      setTimeout(() => {
        setIsLoading(false);
        setStep('mfa_challenge');
      }, 500);
    } else {
      // Direct login
      await login(email, password, 'password');
      setIsLoading(false);
      if (onSuccessLogin) onSuccessLogin();
    }
  };

  const handleSsoLogin = async (provider: 'okta' | 'azure_ad' | 'google_workspace') => {
    setIsLoading(true);
    setAuthError(null);

    if (mfa.isEnabled) {
      setTimeout(() => {
        setIsLoading(false);
        setStep('mfa_challenge');
      }, 600);
    } else {
      await login(email, '', provider);
      setIsLoading(false);
      if (onSuccessLogin) onSuccessLogin();
    }
  };

  const handleMfaSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setMfaError(null);

    if (mfaMethod === 'totp' && mfaCode.trim().length < 6) {
      setMfaError('Please enter a valid 6-digit TOTP code.');
      return;
    }

    if (mfaMethod === 'backup_codes' && mfaCode.trim().length < 8) {
      setMfaError('Please enter a valid 8-character emergency backup code.');
      return;
    }

    setIsLoading(true);

    const valid = verifyMfaChallenge(mfaCode || 'tap', mfaMethod);
    if (valid) {
      await login(email, password, 'password');
      setIsLoading(false);
      if (onSuccessLogin) onSuccessLogin();
    } else {
      setIsLoading(false);
      setMfaError('MFA verification token failed. Please try again or use a backup code.');
    }
  };

  const handleHardwareKeyTap = async () => {
    setHardwareKeyTapped(true);
    setIsLoading(true);
    setTimeout(async () => {
      verifyMfaChallenge('tap', 'hardware_key');
      await login(email, password, 'password');
      setIsLoading(false);
      if (onSuccessLogin) onSuccessLogin();
    }, 1200);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 bg-[#060D18] text-slate-100 relative overflow-hidden">
      {/* Background Ambience */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
        <div className="absolute -top-32 -left-32 w-[600px] h-[600px] rounded-full bg-cyan-950/25 blur-[140px] animate-pulse" />
        <div className="absolute -bottom-40 right-10 w-[550px] h-[550px] rounded-full bg-teal-950/20 blur-[150px]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_20%,rgba(6,13,24,0.95)_100%)]" />
      </div>

      <div className="relative z-10 w-full max-w-lg">
        {/* Top Brand Card */}
        <div className="text-center mb-6 space-y-2">
          <div className="inline-flex items-center justify-center mb-1">
            <SocPulseLogo size="lg" glow={true} />
          </div>
          <h1 className="text-2xl font-bold font-sans tracking-tight text-white flex items-center justify-center gap-2">
            SOC<span className="text-cyan-400">Pulse</span>
            <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">
              Commercial Edition
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Enterprise Cyber Defense Operations & Detection Studio Gateway
          </p>
        </div>

        {/* Main Authentication Container */}
        <div className="rounded-2xl border border-[#1B3047] bg-[#07111F]/90 backdrop-blur-xl p-6 sm:p-8 shadow-2xl shadow-cyan-950/60">
          
          {/* STEP 1: Corporate Credentials & Enterprise SSO */}
          {step === 'credentials' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-cyan-400" />
                  <span className="font-sans font-bold text-sm text-white">Corporate Identity Sign-In</span>
                </div>
                <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                  Zero-Trust Enforced
                </span>
              </div>

              {/* Demo Account Quick Autofill Banner */}
              <div className="p-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 text-xs flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <span className="text-[10px] font-mono text-cyan-300 uppercase font-bold block">
                    Lead SOC Architect Profile:
                  </span>
                  <span className="text-slate-300 font-mono text-[11px] truncate block">
                    sagarhebsur@gmail.com
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setEmail('sagarhebsur@gmail.com');
                    setPassword('EnterpriseSec2026!');
                  }}
                  className="px-2.5 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-[10px] font-mono font-semibold transition-colors shrink-0"
                >
                  Autofill Credentials
                </button>
              </div>

              {/* Form */}
              <form onSubmit={handleCredentialsSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5">
                    Corporate Email Address
                  </label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst@enterprise.defense"
                      className="w-full text-xs font-mono pl-9 pr-3 py-2.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-cyan-300 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                    />
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="block text-xs font-mono text-slate-300">Password</label>
                    <span className="text-[10px] font-mono text-slate-500">SSO / Directory Synced</span>
                  </div>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      className="w-full text-xs font-mono pl-9 pr-10 py-2.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-white focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((prev) => !prev)}
                      className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs font-sans pt-1">
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="checkbox"
                      checked={rememberDevice}
                      onChange={(e) => setRememberDevice(e.target.checked)}
                      className="w-4 h-4 accent-cyan-400 rounded cursor-pointer"
                    />
                    <span>Remember trusted workstation for 30 days</span>
                  </label>
                </div>

                {authError && (
                  <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>{authError}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/25 cursor-pointer mt-2"
                >
                  {isLoading ? (
                    <span>Authenticating Credentials...</span>
                  ) : (
                    <>
                      <span>Continue to MFA Security Challenge</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>

              {/* Single Sign-On Providers */}
              <div className="space-y-3 pt-2">
                <div className="relative flex items-center justify-center">
                  <div className="border-t border-[#1B3047] w-full" />
                  <span className="bg-[#07111F] px-2 text-[10px] font-mono text-slate-500 uppercase shrink-0">
                    Or Sign In with Corporate SSO
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => handleSsoLogin('okta')}
                    className="p-2.5 rounded-xl border border-[#1B3047] bg-[#0B1726] hover:bg-[#101F32] text-xs font-sans font-semibold text-slate-200 transition-colors flex flex-col items-center gap-1 cursor-pointer"
                  >
                    <span className="text-[11px] font-bold text-cyan-400">Okta</span>
                    <span className="text-[9px] font-mono text-slate-400">SAML 2.0</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleSsoLogin('azure_ad')}
                    className="p-2.5 rounded-xl border border-[#1B3047] bg-[#0B1726] hover:bg-[#101F32] text-xs font-sans font-semibold text-slate-200 transition-colors flex flex-col items-center gap-1 cursor-pointer"
                  >
                    <span className="text-[11px] font-bold text-blue-400">Azure AD</span>
                    <span className="text-[9px] font-mono text-slate-400">Entra ID</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleSsoLogin('google_workspace')}
                    className="p-2.5 rounded-xl border border-[#1B3047] bg-[#0B1726] hover:bg-[#101F32] text-xs font-sans font-semibold text-slate-200 transition-colors flex flex-col items-center gap-1 cursor-pointer"
                  >
                    <span className="text-[11px] font-bold text-emerald-400">Google</span>
                    <span className="text-[9px] font-mono text-slate-400">Workspace</span>
                  </button>
                </div>
              </div>

              {/* Visitor / Guest Mode Option */}
              {onContinueAsVisitor && (
                <div className="pt-2 text-center border-t border-[#1B3047]">
                  <button
                    type="button"
                    onClick={onContinueAsVisitor}
                    className="text-xs text-slate-400 hover:text-cyan-300 font-mono transition-colors"
                  >
                    Browse in Read-Only Visitor Evaluation Mode →
                  </button>
                </div>
              )}
            </div>
          )}

          {/* STEP 2: Multi-Factor Authentication (MFA) Security Harness Challenge */}
          {step === 'mfa_challenge' && (
            <div className="space-y-6 animate-in fade-in">
              <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-cyan-400" />
                  <span className="font-sans font-bold text-sm text-white">MFA Security Harness Challenge</span>
                </div>
                <button
                  type="button"
                  onClick={() => setStep('credentials')}
                  className="text-[11px] font-mono text-slate-400 hover:text-slate-200"
                >
                  Back
                </button>
              </div>

              <div className="p-3 rounded-xl border border-[#1B3047] bg-[#060D18] flex items-center justify-between text-xs">
                <div>
                  <span className="text-slate-400 font-sans block text-[11px]">Authenticating User</span>
                  <span className="text-cyan-300 font-mono font-bold">{email}</span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  Step-Up Required
                </span>
              </div>

              {/* MFA Method Selection Tabs */}
              <div className="flex p-1 rounded-xl bg-[#060D18] border border-[#1B3047] gap-1">
                <button
                  type="button"
                  onClick={() => setMfaMethod('totp')}
                  className={`flex-1 py-1.5 rounded-lg text-xs font-sans font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                    mfaMethod === 'totp'
                      ? 'bg-[#101F32] text-cyan-300 shadow-xs'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Smartphone className="w-3.5 h-3.5" />
                  <span>Authenticator</span>
                </button>

                <button
                  type="button"
                  onClick={() => setMfaMethod('hardware_key')}
                  className={`flex-1 py-1.5 rounded-lg text-xs font-sans font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                    mfaMethod === 'hardware_key'
                      ? 'bg-[#101F32] text-cyan-300 shadow-xs'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>Security Key</span>
                </button>

                <button
                  type="button"
                  onClick={() => setMfaMethod('backup_codes')}
                  className={`flex-1 py-1.5 rounded-lg text-xs font-sans font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                    mfaMethod === 'backup_codes'
                      ? 'bg-[#101F32] text-cyan-300 shadow-xs'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <FileCode className="w-3.5 h-3.5" />
                  <span>Backup Code</span>
                </button>
              </div>

              {/* Method 1: TOTP Code Input */}
              {mfaMethod === 'totp' && (
                <form onSubmit={handleMfaSubmit} className="space-y-4">
                  <div className="text-center space-y-2">
                    <p className="text-xs text-slate-300 font-sans">
                      Enter the 6-digit verification code from your Google Authenticator or Microsoft Authenticator app.
                    </p>
                    <input
                      type="text"
                      maxLength={6}
                      autoFocus
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.replace(/[^0-9]/g, ''))}
                      placeholder="000000"
                      className="w-48 mx-auto text-center text-2xl font-mono font-bold tracking-widest px-4 py-3 rounded-xl bg-[#060D18] border border-cyan-500/50 text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-400 shadow-inner"
                    />
                    <div className="text-[11px] font-mono text-slate-400">
                      <span>Quick Test Code: </span>
                      <button
                        type="button"
                        onClick={() => setMfaCode('582914')}
                        className="text-cyan-400 underline hover:text-cyan-300"
                      >
                        582914
                      </button>
                    </div>
                  </div>

                  {mfaError && (
                    <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      <span>{mfaError}</span>
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={mfaCode.length < 6 || isLoading}
                    className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/25 cursor-pointer"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Authorize Session</span>
                  </button>
                </form>
              )}

              {/* Method 2: Hardware Key FIDO2 Tap */}
              {mfaMethod === 'hardware_key' && (
                <div className="text-center space-y-4 py-3">
                  <div className="w-16 h-16 mx-auto rounded-full bg-cyan-500/15 border-2 border-cyan-400/60 flex items-center justify-center">
                    <KeyRound className="w-8 h-8 text-cyan-300" />
                  </div>
                  <div className="space-y-1">
                    <h4 className="text-sm font-bold text-white">YubiKey / FIDO2 Hardware Token</h4>
                    <p className="text-xs text-slate-400 font-sans max-w-xs mx-auto">
                      Insert your physical security key into the USB port or tap via NFC, then touch the gold contact.
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={handleHardwareKeyTap}
                    disabled={isLoading}
                    className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/25 cursor-pointer"
                  >
                    <KeyRound className="w-4 h-4" />
                    <span>{isLoading ? 'Verifying Hardware Assertion...' : 'Tap Security Key (Simulate FIDO2)'}</span>
                  </button>
                </div>
              )}

              {/* Method 3: Backup Code Input */}
              {mfaMethod === 'backup_codes' && (
                <form onSubmit={handleMfaSubmit} className="space-y-4">
                  <div className="text-center space-y-2">
                    <p className="text-xs text-slate-300 font-sans">
                      Enter one of your 8-character single-use emergency backup recovery codes.
                    </p>
                    <input
                      type="text"
                      maxLength={9}
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.toUpperCase())}
                      placeholder="8F2A-99B1"
                      className="w-48 mx-auto text-center text-lg font-mono font-bold tracking-widest px-3 py-2.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-cyan-300 focus:outline-none focus:border-cyan-400"
                    />
                    <div className="text-[11px] font-mono text-slate-400">
                      <span>Quick Test Recovery Code: </span>
                      <button
                        type="button"
                        onClick={() => setMfaCode('8F2A-99B1')}
                        className="text-cyan-400 underline hover:text-cyan-300"
                      >
                        8F2A-99B1
                      </button>
                    </div>
                  </div>

                  {mfaError && (
                    <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      <span>{mfaError}</span>
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={mfaCode.length < 8 || isLoading}
                    className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/25 cursor-pointer"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Redeem Code & Sign In</span>
                  </button>
                </form>
              )}

              {/* Security Telemetry Footer inside step 2 */}
              <div className="p-3 rounded-xl border border-[#1B3047] bg-[#060D18] text-[11px] font-mono text-slate-400 space-y-1">
                <div className="flex items-center justify-between">
                  <span>Assurance Level:</span>
                  <span className="text-emerald-400 font-semibold">NIST AAL2 (Verified)</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Encryption Protocol:</span>
                  <span className="text-cyan-300">TLS 1.3 End-to-End</span>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Security Harness Device Posture Card */}
        <div className="mt-4 p-3 rounded-xl border border-[#1B3047] bg-[#07111F]/70 text-slate-400 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Laptop className="w-4 h-4 text-cyan-400" />
            <span className="font-mono text-[11px]">Workstation Posture: Compliant</span>
          </div>
          <span className="text-[10px] font-mono text-cyan-300">FIPS 140-2 Level 3 Ready</span>
        </div>
      </div>
    </div>
  );
};
