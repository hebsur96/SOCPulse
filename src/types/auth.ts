export type MfaMethodType = 'totp' | 'otp';

export interface MfaConfig {
  isEnabled: boolean;
  isEnforced: boolean;
  activeMethods: MfaMethodType[];
  totpSecret: string;
  totpEnrolledAt?: string;
  otpCode?: string;
  lastVerifiedAt?: string;
  sessionTimeoutMinutes: number;
}

export type CommercialTier = 'community' | 'pro' | 'enterprise';

export interface CommercialLicense {
  key: string;
  tier: CommercialTier;
  organizationName: string;
  licenseeEmail: string;
  seatsTotal: number;
  seatsAllocated: number;
  issuedAt: string;
  expiresAt: string;
  status: 'active' | 'expiring_soon' | 'expired' | 'trial';
  features: {
    unlimitedSiemTranslations: boolean;
    airGappedAppliance: boolean;
    dedicatedThreatIntelQuota: boolean;
    customSiemConnectors: boolean;
    fipsCompliance: boolean;
    soc2Type2AuditReady: boolean;
    sla9999: boolean;
    samlOktaSso: boolean;
    multiAnalystSeats: boolean;
  };
}

export interface UserProfile {
  id: string;
  email?: string;
  mobile?: string;
  name: string;
  role: 'admin' | 'visitor';
  title: string;
  organization: string;
  avatarUrl?: string;
  lastLogin: string;
  mfaVerified: boolean;
  registeredWith: 'email' | 'mobile';
}

export interface RegisteredAccount {
  identifier: string; // email or mobile
  type: 'email' | 'mobile';
  passwordHash: string;
  name: string;
  registeredAt: string;
  totpSecret: string;
  mfaMethod?: MfaMethodType;
}

export interface DispatchedNotificationInfo {
  id: string;
  recipient: string;
  recipientName: string;
  subject: string;
  otpCode?: string;
  purpose: 'login' | 'register';
  timestamp: string;
  status: 'sent' | 'simulated';
  previewHtml?: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  isOwnerAdmin: boolean;
  user: UserProfile | null;
  mfa: MfaConfig;
  license: CommercialLicense;
  login: (identifier: string, password?: string) => Promise<boolean>;
  register: (
    identifier: string,
    password: string,
    name?: string,
    type?: 'email' | 'mobile',
    preferredMfa?: MfaMethodType
  ) => Promise<boolean>;
  logout: () => void;
  generateOtpCode: (identifier?: string) => string;
  sendOtpEmailNotification: (
    email: string,
    otp: string,
    name?: string,
    type?: 'login' | 'register'
  ) => Promise<{ success: boolean; message?: string; notification?: DispatchedNotificationInfo }>;
  verifyMfaChallenge: (code: string, method: MfaMethodType) => boolean;
  updateMfaConfig: (updater: (prev: MfaConfig) => MfaConfig) => void;
  activateCommercialLicense: (key: string) => { success: boolean; message: string; tier?: CommercialTier };
}
