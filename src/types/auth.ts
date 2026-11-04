export type MfaMethodType = 'totp' | 'hardware_key' | 'backup_codes';

export interface MfaConfig {
  isEnabled: boolean;
  isEnforced: boolean;
  activeMethods: MfaMethodType[];
  totpSecret: string;
  totpEnrolledAt?: string;
  hardwareKeyName?: string;
  hardwareKeyRegisteredAt?: string;
  backupCodes: string[];
  backupCodesRemaining: number;
  lastVerifiedAt?: string;
  enforceForAdminActions: boolean;
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
  email: string;
  name: string;
  role: 'admin' | 'visitor';
  title: string;
  organization: string;
  avatarUrl?: string;
  lastLogin: string;
  mfaVerified: boolean;
  authProvider: 'password' | 'okta' | 'azure_ad' | 'google_workspace';
}

export interface AuthState {
  isAuthenticated: boolean;
  user: UserProfile | null;
  mfa: MfaConfig;
  license: CommercialLicense;
  login: (email: string, password?: string, provider?: UserProfile['authProvider']) => Promise<boolean>;
  logout: () => void;
  verifyMfaChallenge: (codeOrKey: string, method: MfaMethodType) => boolean;
  updateMfaConfig: (updater: (prev: MfaConfig) => MfaConfig) => void;
  activateCommercialLicense: (key: string) => { success: boolean; message: string; tier?: CommercialTier };
  regenerateBackupCodes: () => string[];
  enrollTotp: (secret: string) => void;
  registerHardwareKey: (keyName: string) => Promise<boolean>;
}
