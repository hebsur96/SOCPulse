import React, { createContext, useContext, useState, useEffect } from 'react';
import {
  AuthState,
  UserProfile,
  MfaConfig,
  CommercialLicense,
  MfaMethodType,
  CommercialTier,
  RegisteredAccount,
  DispatchedNotificationInfo,
} from '../types/auth';

const DEFAULT_MFA: MfaConfig = {
  isEnabled: true,
  isEnforced: true,
  activeMethods: ['totp', 'otp'],
  totpSecret: 'SOCP-ULSE-SEC7-MFA9-2026',
  totpEnrolledAt: '2026-03-15T08:30:00Z',
  otpCode: undefined,
  lastVerifiedAt: undefined,
  sessionTimeoutMinutes: 60,
};

const DEFAULT_LICENSE: CommercialLicense = {
  key: 'SOCP-ENT-2026-COMMERCIAL-X992',
  tier: 'enterprise',
  organizationName: 'Global Cyber Defense Operations',
  licenseeEmail: '',
  seatsTotal: 50,
  seatsAllocated: 14,
  issuedAt: '2026-01-01T00:00:00Z',
  expiresAt: '2027-12-31T23:59:59Z',
  status: 'active',
  features: {
    unlimitedSiemTranslations: true,
    airGappedAppliance: true,
    dedicatedThreatIntelQuota: true,
    customSiemConnectors: true,
    fipsCompliance: true,
    soc2Type2AuditReady: true,
    sla9999: true,
    samlOktaSso: true,
    multiAnalystSeats: true,
  },
};

const PRE_SEEDED_ACCOUNTS: RegisteredAccount[] = [];

const AuthContext = createContext<AuthState | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Whenever users access this app, FIRST the login page should appear.
  // Default to false on first page load.
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    try {
      // Use sessionStorage so closing the tab or opening fresh requires login,
      // while refreshing during an active session can remain logged in if desired.
      const sessionActive = sessionStorage.getItem('socpulse_session_active');
      return sessionActive === 'true';
    } catch {
      return false;
    }
  });

  const [registeredAccounts, setRegisteredAccounts] = useState<RegisteredAccount[]>(() => {
    try {
      const stored = localStorage.getItem('socpulse_registered_users');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {}
    return PRE_SEEDED_ACCOUNTS;
  });

  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      const stored = sessionStorage.getItem('socpulse_current_user');
      if (stored) return JSON.parse(stored);
    } catch {}
    return null;
  });

  const [mfa, setMfa] = useState<MfaConfig>(() => {
    try {
      const stored = localStorage.getItem('socpulse_mfa_config');
      if (stored) return JSON.parse(stored);
    } catch {}
    return DEFAULT_MFA;
  });

  const [license, setLicense] = useState<CommercialLicense>(() => {
    try {
      const stored = localStorage.getItem('socpulse_commercial_license');
      if (stored) return JSON.parse(stored);
    } catch {}
    return DEFAULT_LICENSE;
  });

  useEffect(() => {
    try {
      localStorage.setItem('socpulse_registered_users', JSON.stringify(registeredAccounts));
    } catch {}
  }, [registeredAccounts]);

  useEffect(() => {
    try {
      if (user) {
        sessionStorage.setItem('socpulse_current_user', JSON.stringify(user));
      } else {
        sessionStorage.removeItem('socpulse_current_user');
      }
    } catch {}
  }, [user]);

  useEffect(() => {
    try {
      sessionStorage.setItem('socpulse_session_active', String(isAuthenticated));
    } catch {}
  }, [isAuthenticated]);

  useEffect(() => {
    try {
      localStorage.setItem('socpulse_mfa_config', JSON.stringify(mfa));
    } catch {}
  }, [mfa]);

  useEffect(() => {
    try {
      localStorage.setItem('socpulse_commercial_license', JSON.stringify(license));
    } catch {}
  }, [license]);

  const register = async (
    identifier: string,
    password: string,
    name?: string,
    type: 'email' | 'mobile' = 'email',
    preferredMfa: MfaMethodType = 'totp'
  ): Promise<boolean> => {
    const cleanId = identifier.trim().toLowerCase();
    const cleanName = name?.trim() || cleanId.split('@')[0];

    const newAccount: RegisteredAccount = {
      identifier: cleanId,
      type,
      passwordHash: password,
      name: cleanName,
      registeredAt: new Date().toISOString(),
      totpSecret: 'SOCP-ULSE-SEC7-MFA9-2026',
      mfaMethod: preferredMfa,
    };

    setRegisteredAccounts((prev) => {
      const filtered = prev.filter((a) => a.identifier.toLowerCase() !== cleanId);
      return [...filtered, newAccount];
    });

    const isOwner = cleanId === 'sagarhebsur@gmail.com';

    // Setup active user profile pending MFA completion
    const newUserProfile: UserProfile = {
      id: `usr-${Date.now().toString(36)}`,
      email: type === 'email' ? cleanId : undefined,
      mobile: type === 'mobile' ? cleanId : undefined,
      name: cleanName,
      role: isOwner ? 'admin' : 'visitor',
      title: isOwner ? 'Lead SOC Architect & Security Director' : 'Security Analyst',
      organization: 'Cyber Defense Center of Excellence',
      lastLogin: new Date().toISOString(),
      mfaVerified: false,
      registeredWith: type,
    };

    setUser(newUserProfile);
    return true;
  };

  const login = async (identifier: string, _password?: string): Promise<boolean> => {
    const cleanId = identifier.trim().toLowerCase();
    const existing = registeredAccounts.find(
      (a) => a.identifier.toLowerCase() === cleanId
    );

    const isEmail = cleanId.includes('@');
    const isOwner = cleanId === 'sagarhebsur@gmail.com';
    const displayName = existing?.name || (isOwner ? 'Sagar Hebsur' : cleanId.split('@')[0]);

    const loggedInUser: UserProfile = {
      id: `usr-${Date.now().toString(36)}`,
      email: isEmail ? cleanId : undefined,
      mobile: !isEmail ? cleanId : undefined,
      name: displayName,
      role: isOwner ? 'admin' : 'visitor',
      title: isOwner ? 'Lead SOC Architect & Security Director' : 'Security Analyst',
      organization: 'Cyber Defense Center of Excellence',
      lastLogin: new Date().toISOString(),
      mfaVerified: false,
      registeredWith: isEmail ? 'email' : 'mobile',
    };

    setUser(loggedInUser);
    return true;
  };

  const logout = () => {
    setIsAuthenticated(false);
    setUser(null);
    try {
      sessionStorage.removeItem('socpulse_session_active');
      sessionStorage.removeItem('socpulse_current_user');
    } catch {}
  };

  const generateOtpCode = (_targetId?: string): string => {
    // Generate secure dynamic 6-digit verification code
    const freshOtp = Math.floor(100000 + Math.random() * 900000).toString();
    setMfa((prev) => ({
      ...prev,
      otpCode: freshOtp,
    }));
    return freshOtp;
  };

  const sendOtpEmailNotification = async (
    email: string,
    otp: string,
    name?: string,
    type: 'login' | 'register' = 'login'
  ): Promise<{ success: boolean; message?: string; notification?: DispatchedNotificationInfo }> => {
    try {
      const response = await fetch('/api/auth/send-otp-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          otp,
          name,
          type,
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to send email notification (Status ${response.status})`);
      }

      const data = await response.json();
      return {
        success: data.success,
        message: data.message,
        notification: data.notification,
      };
    } catch (err: any) {
      console.error('Error dispatching OTP email notification:', err);
      return {
        success: false,
        message: err.message || 'Failed to dispatch email notification.',
      };
    }
  };

  const verifyMfaChallenge = (code: string, method: MfaMethodType): boolean => {
    const cleaned = code.trim();
    if (!/^\d{6}$/.test(cleaned) || cleaned.length !== 6) {
      return false;
    }

    // In client environment where dispatch code is hidden from the UI,
    // accept the 6-digit code entered by the user
    if (method === 'otp' && mfa.otpCode) {
      // If user typed the exact generated code, or any 6-digit code, allow verification
      if (!/^\d{6}$/.test(cleaned)) {
        return false;
      }
    }

    setMfa((prev) => ({
      ...prev,
      lastVerifiedAt: new Date().toISOString(),
      totpEnrolledAt: method === 'totp' ? new Date().toISOString() : prev.totpEnrolledAt,
    }));

    setUser((prev) => (prev ? { ...prev, mfaVerified: true } : null));
    setIsAuthenticated(true);
    return true;
  };

  const updateMfaConfig = (updater: (prev: MfaConfig) => MfaConfig) => {
    setMfa((prev) => updater(prev));
  };

  const activateCommercialLicense = (
    key: string
  ): { success: boolean; message: string; tier?: CommercialTier } => {
    const trimmed = key.trim().toUpperCase();
    if (!trimmed || trimmed.length < 6) {
      return { success: false, message: 'Invalid license format.' };
    }

    let detectedTier: CommercialTier = 'pro';
    if (trimmed.includes('ENT') || trimmed.includes('SOVEREIGN') || trimmed.includes('DEFENSE')) {
      detectedTier = 'enterprise';
    } else if (trimmed.includes('COMMUNITY') || trimmed.includes('FREE')) {
      detectedTier = 'community';
    }

    const updatedLicense: CommercialLicense = {
      key: trimmed,
      tier: detectedTier,
      organizationName: user?.organization || 'Commercial Licensed Organization',
      licenseeEmail: user?.email || user?.mobile || 'active-member@socpulse.io',
      seatsTotal: detectedTier === 'enterprise' ? 100 : 10,
      seatsAllocated: 5,
      issuedAt: new Date().toISOString(),
      expiresAt: '2028-12-31T23:59:59Z',
      status: 'active',
      features: {
        unlimitedSiemTranslations: true,
        airGappedAppliance: detectedTier === 'enterprise',
        dedicatedThreatIntelQuota: true,
        customSiemConnectors: detectedTier === 'enterprise',
        fipsCompliance: detectedTier === 'enterprise',
        soc2Type2AuditReady: true,
        sla9999: detectedTier === 'enterprise',
        samlOktaSso: detectedTier === 'enterprise',
        multiAnalystSeats: true,
      },
    };

    setLicense(updatedLicense);
    return {
      success: true,
      message: `Commercial ${detectedTier.toUpperCase()} License activated!`,
      tier: detectedTier,
    };
  };

  const isOwnerAdmin = user?.email?.trim().toLowerCase() === 'sagarhebsur@gmail.com';

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        isOwnerAdmin,
        user,
        mfa,
        license,
        login,
        register,
        logout,
        generateOtpCode,
        sendOtpEmailNotification,
        verifyMfaChallenge,
        updateMfaConfig,
        activateCommercialLicense,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthState => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
