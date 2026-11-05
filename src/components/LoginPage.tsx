import React, { useState, useEffect } from 'react';
import {
  Lock,
  Mail,
  Phone,
  ShieldCheck,
  CheckCircle2,
  ArrowRight,
  Eye,
  EyeOff,
  User,
  Copy,
  Check,
  Smartphone,
  KeyRound,
  AlertCircle,
  RefreshCw,
  QrCode,
  ArrowLeft,
  Sparkles,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { SocPulseLogo } from './SocPulseLogo';
import { MfaMethodType } from '../types/auth';

interface LoginPageProps {
  onSuccessLogin?: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onSuccessLogin }) => {
  const { login, register, generateOtpCode, verifyMfaChallenge, mfa } = useAuth();

  // Mode: 'login' | 'register'
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');

  // Step: 'credentials' | 'mfa'
  const [step, setStep] = useState<'credentials' | 'mfa'>('credentials');

  // Registration type: 'email' | 'mobile'
  const [regType, setRegType] = useState<'email' | 'mobile'>('email');

  // Form Fields - Blank by default so users enter their own details
  const [fullName, setFullName] = useState('');
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Status & Errors
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  // MFA Setup & Verification State
  const [mfaMethod, setMfaMethod] = useState<MfaMethodType>('totp');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);

  // Dynamic OTP state
  const [dispatchedOtp, setDispatchedOtp] = useState<string | null>(null);
  const [otpSentNotice, setOtpSentNotice] = useState<string | null>(null);
  const [resendCooldown, setResendCooldown] = useState(0);

  // Countdown timer for resend OTP
  useEffect(() => {
    if (resendCooldown <= 0) return;
    const interval = setInterval(() => {
      setResendCooldown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(interval);
  }, [resendCooldown]);

  // Handle Login submission -> triggers MFA verification step
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const cleanId = identifier.trim();
    if (!cleanId) {
      setErrorMsg('Please enter your email address or mobile number.');
      return;
    }

    if (!password) {
      setErrorMsg('Please enter your password.');
      return;
    }

    await login(cleanId, password);
    setMfaCode('');
    setMfaError(null);
    setDispatchedOtp(null);
    setOtpSentNotice(null);
    setSuccessNotice(null);
    setStep('mfa');
  };

  // Handle Register submission -> registers account and directs to MFA setup step
  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const cleanId = identifier.trim();
    if (!cleanId) {
      setErrorMsg(`Please provide a valid ${regType === 'email' ? 'email address' : 'mobile number'}.`);
      return;
    }

    if (regType === 'email' && !cleanId.includes('@')) {
      setErrorMsg('Please enter a valid email address (e.g. analyst@enterprise.com).');
      return;
    }

    if (regType === 'mobile' && cleanId.replace(/\D/g, '').length < 8) {
      setErrorMsg('Please enter a valid mobile phone number with country code.');
      return;
    }

    if (password.length < 6) {
      setErrorMsg('Password must be at least 6 characters.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMsg('Passwords do not match.');
      return;
    }

    // Register account and advance to MFA Setup
    await register(cleanId, password, fullName || cleanId.split('@')[0], regType, mfaMethod);
    setMfaCode('');
    setMfaError(null);
    setDispatchedOtp(null);
    setOtpSentNotice(null);
    setSuccessNotice(`Account profile created for ${cleanId}! Please configure your MFA setup below to complete registration.`);
    setStep('mfa');
  };

  // Send a fresh dynamic OTP code to the registered email/mobile
  const handleDispatchOtp = () => {
    const freshCode = generateOtpCode(identifier);
    setDispatchedOtp(freshCode);
    setOtpSentNotice(`Security verification code sent to ${identifier}!`);
    setResendCooldown(30);
    setMfaError(null);
  };

  // Handle MFA verification / completion of setup
  const handleMfaSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setMfaError(null);

    const cleanCode = mfaCode.trim();
    if (cleanCode.length !== 6 || !/^\d{6}$/.test(cleanCode)) {
      setMfaError('Please enter the 6-digit verification code.');
      return;
    }

    // If using OTP, verify that user requested/dispatched a code
    if (mfaMethod === 'otp' && !dispatchedOtp && !mfa.otpCode) {
      setMfaError('Please click "Send Verification Code" first to receive your code.');
      return;
    }

    const success = verifyMfaChallenge(cleanCode, mfaMethod);
    if (success) {
      if (onSuccessLogin) onSuccessLogin();
    } else {
      if (mfaMethod === 'otp') {
        setMfaError('Invalid OTP code. Please enter the exact code dispatched to your email/mobile.');
      } else {
        setMfaError('Invalid code. Enter the 6-digit code shown in your authenticator app.');
      }
    }
  };

  const handleCopySecret = () => {
    navigator.clipboard.writeText(mfa.totpSecret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 bg-[#060D18] text-slate-100 relative overflow-hidden">
      {/* Subtle Deep Navy Ambient Background */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
        <div className="absolute -top-32 -left-32 w-[600px] h-[600px] rounded-full bg-cyan-950/25 blur-[140px]" />
        <div className="absolute -bottom-40 right-10 w-[550px] h-[550px] rounded-full bg-teal-950/20 blur-[150px]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_20%,rgba(6,13,24,0.96)_100%)]" />
      </div>

      <div className="relative z-10 w-full max-w-md">
        
        {/* Brand Header */}
        <div className="text-center mb-6 space-y-2">
          <div className="inline-flex items-center justify-center mb-1">
            <SocPulseLogo size="lg" glow={true} />
          </div>
          <h1 className="text-2xl font-bold font-sans tracking-tight text-white flex items-center justify-center gap-2">
            SOC<span className="text-cyan-400">Pulse</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
              MFA Protected
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Enterprise Cyber Defense & SIEM Query Studio
          </p>
        </div>

        {/* Card Container */}
        <div className="rounded-2xl border border-[#1B3047] bg-[#07111F]/95 backdrop-blur-xl p-6 sm:p-7 shadow-2xl shadow-cyan-950/60">
          
          {/* STEP 1: CREDENTIALS (LOGIN / REGISTER) */}
          {step === 'credentials' && (
            <div className="space-y-5">
              
              {/* Tab Switcher: Sign In vs Register */}
              <div className="flex p-1 rounded-xl bg-[#060D18] border border-[#1B3047]">
                <button
                  type="button"
                  onClick={() => {
                    setAuthMode('login');
                    setErrorMsg(null);
                  }}
                  className={`flex-1 py-2 text-xs font-sans font-semibold rounded-lg transition-all ${
                    authMode === 'login'
                      ? 'bg-[#101F32] text-cyan-300 shadow-xs'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setAuthMode('register');
                    setErrorMsg(null);
                  }}
                  className={`flex-1 py-2 text-xs font-sans font-semibold rounded-lg transition-all ${
                    authMode === 'register'
                      ? 'bg-[#101F32] text-cyan-300 shadow-xs'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Register Account
                </button>
              </div>

              {/* Progress Indicator for Registration */}
              {authMode === 'register' && (
                <div className="flex items-center justify-between px-1 text-xs">
                  <div className="flex items-center gap-1.5 text-cyan-300 font-mono font-medium">
                    <span className="w-5 h-5 rounded-full bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center text-[10px] font-bold">1</span>
                    <span>Account Details</span>
                  </div>
                  <div className="w-8 h-[1px] bg-slate-700" />
                  <div className="flex items-center gap-1.5 text-slate-500 font-mono">
                    <span className="w-5 h-5 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px]">2</span>
                    <span>MFA Setup</span>
                  </div>
                </div>
              )}

              {/* REGISTER SUB-OPTIONS: Email vs Mobile Number */}
              {authMode === 'register' && (
                <div className="space-y-2">
                  <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                    Register With:
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setRegType('email');
                        setIdentifier('');
                      }}
                      className={`p-2 rounded-lg border text-xs font-sans font-semibold flex items-center justify-center gap-2 transition-colors ${
                        regType === 'email'
                          ? 'border-cyan-400 bg-cyan-500/10 text-cyan-300'
                          : 'border-[#1B3047] bg-[#060D18] text-slate-400 hover:text-white'
                      }`}
                    >
                      <Mail className="w-3.5 h-3.5" />
                      <span>Email Address</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setRegType('mobile');
                        setIdentifier('');
                      }}
                      className={`p-2 rounded-lg border text-xs font-sans font-semibold flex items-center justify-center gap-2 transition-colors ${
                        regType === 'mobile'
                          ? 'border-cyan-400 bg-cyan-500/10 text-cyan-300'
                          : 'border-[#1B3047] bg-[#060D18] text-slate-400 hover:text-white'
                      }`}
                    >
                      <Phone className="w-3.5 h-3.5" />
                      <span>Mobile Number</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Form Body */}
              <form
                onSubmit={authMode === 'login' ? handleLoginSubmit : handleRegisterSubmit}
                className="space-y-3.5"
              >
                {/* Full Name for Registration */}
                {authMode === 'register' && (
                  <div>
                    <label className="block text-xs font-mono text-slate-300 mb-1">
                      Full Name
                    </label>
                    <div className="relative">
                      <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        placeholder="Enter your full name"
                        value={fullName}
                        onChange={(e) => setFullName(e.target.value)}
                        className="w-full text-xs font-sans pl-9 pr-3 py-2.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-white focus:outline-none focus:border-cyan-400"
                      />
                    </div>
                  </div>
                )}

                {/* Email Address or Mobile Number Input */}
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    {authMode === 'register'
                      ? regType === 'email'
                        ? 'Email Address'
                        : 'Mobile Phone Number'
                      : 'Email Address or Mobile Number'}
                  </label>
                  <div className="relative">
                    {authMode === 'register' && regType === 'mobile' ? (
                      <Phone className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    ) : (
                      <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    )}
                    <input
                      type={authMode === 'register' && regType === 'mobile' ? 'tel' : 'text'}
                      required
                      placeholder={
                        authMode === 'register' && regType === 'mobile'
                          ? '+1 (555) 000-0000'
                          : 'name@company.com'
                      }
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      className="w-full text-xs font-mono pl-9 pr-3 py-2.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-cyan-300 focus:outline-none focus:border-cyan-400"
                    />
                  </div>
                </div>

                {/* Password Input */}
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    Password
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      placeholder="••••••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full text-xs font-mono pl-9 pr-10 py-2.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-white focus:outline-none focus:border-cyan-400"
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

                {/* Confirm Password for Registration */}
                {authMode === 'register' && (
                  <div>
                    <label className="block text-xs font-mono text-slate-300 mb-1">
                      Confirm Password
                    </label>
                    <div className="relative">
                      <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        required
                        placeholder="••••••••••••"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className="w-full text-xs font-mono pl-9 pr-3 py-2.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-white focus:outline-none focus:border-cyan-400"
                      />
                    </div>
                  </div>
                )}

                {/* Error Banner */}
                {errorMsg && (
                  <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                    <span>{errorMsg}</span>
                  </div>
                )}

                {/* Submit Button */}
                <button
                  type="submit"
                  className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 cursor-pointer pt-3"
                >
                  <span>
                    {authMode === 'login'
                      ? 'Continue to MFA Verification'
                      : 'Continue to Step 2: MFA Setup'}
                  </span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </form>

              {/* Footer link to toggle */}
              <div className="text-center pt-2 border-t border-[#1B3047]/60">
                {authMode === 'login' ? (
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMode('register');
                      setErrorMsg(null);
                    }}
                    className="text-xs text-slate-400 hover:text-cyan-300 font-sans transition-colors"
                  >
                    Don't have an account yet? <span className="text-cyan-400 font-semibold underline">Register here</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMode('login');
                      setErrorMsg(null);
                    }}
                    className="text-xs text-slate-400 hover:text-cyan-300 font-sans transition-colors"
                  >
                    Already registered? <span className="text-cyan-400 font-semibold underline">Sign in with MFA</span>
                  </button>
                )}
              </div>

            </div>
          )}

          {/* STEP 2: MFA SETUP (DURING REGISTRATION) OR MFA VERIFICATION (DURING LOGIN) */}
          {step === 'mfa' && (
            <div className="space-y-4 animate-in fade-in">
              
              {/* Header with Back/Change Account option */}
              <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-cyan-400" />
                  <div>
                    <h2 className="font-sans font-bold text-sm text-white">
                      {authMode === 'register' ? 'Set Up MFA Security' : 'MFA Verification'}
                    </h2>
                    <p className="text-[11px] font-sans text-slate-400">
                      {authMode === 'register' ? 'Step 2 of 2: Configure Authenticator or OTP' : 'Two-Factor Authentication Required'}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setStep('credentials');
                    setMfaError(null);
                  }}
                  className="text-[11px] font-mono text-slate-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  <ArrowLeft className="w-3 h-3" />
                  <span>Back</span>
                </button>
              </div>

              {/* Success notice after registration step 1 */}
              {successNotice && authMode === 'register' && (
                <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs flex items-start gap-2">
                  <Sparkles className="w-4 h-4 shrink-0 text-cyan-400 mt-0.5" />
                  <div>
                    <span className="font-semibold block font-sans">Account Created Successfully!</span>
                    <span className="text-[11px] text-slate-300 font-sans">
                      Complete MFA setup below to activate two-factor protection and launch your session.
                    </span>
                  </div>
                </div>
              )}

              {/* Account Identifier Badge */}
              <div className="p-2.5 rounded-xl border border-[#1B3047] bg-[#060D18] flex items-center justify-between text-xs">
                <div>
                  <span className="text-slate-400 font-sans text-[11px] block">
                    {authMode === 'register' ? 'Enrolling Account:' : 'Verifying Account:'}
                  </span>
                  <span className="text-cyan-300 font-mono font-bold truncate block max-w-[240px]">
                    {identifier}
                  </span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold">
                  {authMode === 'register' ? 'Setup Mode' : 'Secured'}
                </span>
              </div>

              {/* Choice of MFA Setup Method: Authenticator App vs OTP */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400 block">
                  {authMode === 'register' ? 'Choose MFA Setup Method:' : 'Select Verification Method:'}
                </label>
                <div className="flex p-1 rounded-xl bg-[#060D18] border border-[#1B3047] gap-1">
                  <button
                    type="button"
                    onClick={() => {
                      setMfaMethod('totp');
                      setMfaError(null);
                      setMfaCode('');
                    }}
                    className={`flex-1 py-2 rounded-lg text-xs font-sans font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                      mfaMethod === 'totp'
                        ? 'bg-[#101F32] text-cyan-300 shadow-xs'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    <Smartphone className="w-3.5 h-3.5" />
                    <span>Authenticator App</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setMfaMethod('otp');
                      setMfaError(null);
                      setMfaCode('');
                    }}
                    className={`flex-1 py-2 rounded-lg text-xs font-sans font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                      mfaMethod === 'otp'
                        ? 'bg-[#101F32] text-cyan-300 shadow-xs'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    <KeyRound className="w-3.5 h-3.5" />
                    <span>OTP Code</span>
                  </button>
                </div>
              </div>

              {/* METHOD 1: AUTHENTICATOR APP (TOTP) SETUP / VERIFICATION */}
              {mfaMethod === 'totp' && (
                <div className="space-y-3.5">
                  <div className="p-3 rounded-xl border border-[#1B3047] bg-[#060D18] space-y-2.5">
                    <div className="flex items-center gap-3">
                      {/* Stylized QR Code Matrix */}
                      <div className="p-1.5 bg-white rounded-lg shrink-0">
                        <svg
                          viewBox="0 0 100 100"
                          className="w-16 h-16"
                          fill="none"
                          xmlns="http://www.w3.org/2000/svg"
                        >
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
                      <div className="min-w-0 flex-1 text-left">
                        <p className="text-[11px] font-sans text-slate-300 font-medium">
                          {authMode === 'register'
                            ? '1. Scan in Google Authenticator or Microsoft Authenticator'
                            : 'Open your Authenticator app (Google / Microsoft Authenticator)'}
                        </p>
                        <p className="text-[10px] text-slate-500 font-sans mt-0.5">
                          Or enter the secret setup key:
                        </p>
                        <div className="flex items-center gap-1.5 mt-1">
                          <code className="text-[10px] font-mono text-cyan-300 truncate font-bold">
                            {mfa.totpSecret}
                          </code>
                          <button
                            type="button"
                            onClick={handleCopySecret}
                            className="p-1 rounded bg-[#101F32] hover:bg-[#182C44] text-slate-200 shrink-0"
                            title="Copy Key"
                          >
                            {copiedSecret ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* 6-digit confirmation code input */}
                  <form onSubmit={handleMfaSubmit} className="space-y-3">
                    <div className="text-center">
                      <label className="block text-xs font-mono text-slate-300 mb-1.5">
                        {authMode === 'register'
                          ? '2. Enter 6-digit confirmation code from your app:'
                          : 'Enter 6-digit verification code:'}
                      </label>
                      <input
                        type="text"
                        maxLength={6}
                        autoFocus
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value.replace(/[^0-9]/g, ''))}
                        placeholder="000000"
                        className="w-48 mx-auto text-center text-2xl font-mono font-bold tracking-widest px-3 py-2 rounded-xl bg-[#060D18] border border-cyan-500/50 text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-400"
                      />
                    </div>

                    {mfaError && (
                      <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                        <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                        <span>{mfaError}</span>
                      </div>
                    )}

                    <button
                      type="submit"
                      disabled={mfaCode.length < 6}
                      className="w-full py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 cursor-pointer"
                    >
                      <CheckCircle2 className="w-4 h-4" />
                      <span>
                        {authMode === 'register'
                          ? 'Confirm Authenticator Setup & Login'
                          : 'Verify & Sign In'}
                      </span>
                    </button>
                  </form>
                </div>
              )}

              {/* METHOD 2: ONE-TIME PASSCODE (OTP) SETUP / VERIFICATION */}
              {mfaMethod === 'otp' && (
                <div className="space-y-3.5">
                  <div className="p-3.5 rounded-xl border border-[#1B3047] bg-[#060D18] text-center space-y-2">
                    <p className="text-xs text-slate-300 font-sans">
                      {authMode === 'register'
                        ? 'Set up One-Time Passcode (OTP) verification for:'
                        : 'Send verification code to:'}
                    </p>
                    <p className="text-xs font-mono font-bold text-cyan-300 truncate">
                      {identifier}
                    </p>

                    {/* Dispatch button */}
                    <button
                      type="button"
                      onClick={handleDispatchOtp}
                      disabled={resendCooldown > 0}
                      className="px-3.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 disabled:opacity-50 text-cyan-300 text-xs font-mono font-medium transition-colors inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      <RefreshCw className={`w-3 h-3 ${resendCooldown > 0 ? 'animate-spin' : ''}`} />
                      <span>
                        {resendCooldown > 0
                          ? `Resend in ${resendCooldown}s`
                          : dispatchedOtp
                          ? 'Resend Verification Code'
                          : 'Send Verification Code'}
                      </span>
                    </button>

                    {/* Security Dispatch Notice */}
                    {otpSentNotice && (
                      <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-[11px] font-sans">
                        <p>{otpSentNotice}</p>
                        {dispatchedOtp && (
                          <div className="mt-1 pt-1 border-t border-emerald-500/20 font-mono text-[11px]">
                            <span className="text-slate-400">Security Dispatch Code: </span>
                            <span className="text-emerald-300 font-bold tracking-wider">{dispatchedOtp}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* 6-digit OTP code input */}
                  <form onSubmit={handleMfaSubmit} className="space-y-3">
                    <div className="text-center">
                      <label className="block text-xs font-mono text-slate-300 mb-1.5">
                        Enter 6-digit OTP Code:
                      </label>
                      <input
                        type="text"
                        maxLength={6}
                        autoFocus
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value.replace(/[^0-9]/g, ''))}
                        placeholder="000000"
                        className="w-48 mx-auto text-center text-2xl font-mono font-bold tracking-widest px-3 py-2 rounded-xl bg-[#060D18] border border-cyan-500/50 text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-400"
                      />
                    </div>

                    {mfaError && (
                      <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                        <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                        <span>{mfaError}</span>
                      </div>
                    )}

                    <button
                      type="submit"
                      disabled={mfaCode.length < 6}
                      className="w-full py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-[#060D18] font-bold text-xs font-sans transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 cursor-pointer"
                    >
                      <CheckCircle2 className="w-4 h-4" />
                      <span>
                        {authMode === 'register'
                          ? 'Verify OTP & Complete Setup'
                          : 'Verify OTP & Sign In'}
                      </span>
                    </button>
                  </form>
                </div>
              )}

            </div>
          )}

        </div>

        {/* Security Footer Note */}
        <div className="mt-4 text-center text-[11px] font-mono text-slate-500">
          SOCPulse Enterprise Defense • FIPS 140-2 Level 3 Aligned MFA
        </div>

      </div>
    </div>
  );
};
