import { UserRole, UserRoleMeta } from '../types';

export const USER_ROLES: Record<UserRole, UserRoleMeta> = {
  visitor: {
    role: 'visitor',
    label: 'Visitor',
    badge: 'Visitor',
    description: 'Safe interactive sandbox. Access to Email Header Forensics, AI SIEM Copilot, Query Generator, IOC Defanger, and Threat Intel investigations.',
    permissions: {
      canExecuteAiCopilot: true,
      canGenerateQueries: true,
      canTranslateSiem: true,
      canDefangIocs: true,
      canInvestigateThreatIntel: true,
      canAnalyzeEmailHeaders: true,
      canAnalyzeSandbox: true,
      canSimulateAttackPaths: false,
      canBenchmarkRules: false,
      canExportReports: true,
      canEditCoreRepositories: false,
      canDeleteTemplates: false,
      canModifyAdminConfigs: false,
    },
  },
  admin: {
    role: 'admin',
    label: 'Admin',
    badge: 'Administrator',
    description: 'Full administrative rights with core SIEM detection rule commits, template authoring, email rules, attack path simulation, and platform configuration.',
    permissions: {
      canExecuteAiCopilot: true,
      canGenerateQueries: true,
      canTranslateSiem: true,
      canDefangIocs: true,
      canInvestigateThreatIntel: true,
      canAnalyzeEmailHeaders: true,
      canAnalyzeSandbox: true,
      canSimulateAttackPaths: true,
      canBenchmarkRules: true,
      canExportReports: true,
      canEditCoreRepositories: true,
      canDeleteTemplates: true,
      canModifyAdminConfigs: true,
    },
  },
};


