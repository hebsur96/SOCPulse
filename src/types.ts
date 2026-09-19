export type UserRole = 'visitor' | 'admin';

export interface UserRoleMeta {
  role: UserRole;
  label: string;
  badge: string;
  description: string;
  permissions: {
    canExecuteAiCopilot: boolean;
    canGenerateQueries: boolean;
    canTranslateSiem: boolean;
    canDefangIocs: boolean;
    canInvestigateThreatIntel: boolean;
    canAnalyzeEmailHeaders: boolean;
    canAnalyzeSandbox: boolean;
    canSimulateAttackPaths: boolean;
    canBenchmarkRules: boolean;
    canExportReports: boolean;
    canEditCoreRepositories: boolean;
    canDeleteTemplates: boolean;
    canModifyAdminConfigs: boolean;
  };
}

export type SiemPlatformId =
  | 'sentinel'
  | 'defender'
  | 'splunk'
  | 'qradar'
  | 'elastic'
  | 'google_secops'
  | 'cortex'
  | 'securonix'
  | 'logrhythm'
  | 'arcsight'
  | 'gurucul';

export interface SiemPlatformMeta {
  id: SiemPlatformId;
  name: string;
  language: string;
  category: 'Cloud SIEM' | 'EDR / XDR' | 'Enterprise SIEM' | 'Legacy / Specialized';
  icon: string;
  badgeColor: string;
  description: string;
  defaultTable: string;
}

export interface MitreMapping {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  subTechniqueId?: string;
  subTechniqueName?: string;
  description: string;
  threatActors?: string[];
}

export interface InvestigationQuery {
  id: string;
  title: string;
  platform: SiemPlatformId;
  platformName: string;
  query: string;
  purpose: string;
}

export interface TuningRecommendation {
  falsePositives: string[];
  whitelisting: string[];
  thresholding: string;
  noiseRating: 'Low' | 'Medium' | 'High';
}

export interface PerformanceOptimization {
  indexStrategy: string;
  filteringOrder: string;
  timeWindow: string;
  estimatedCostImpact: 'Very Low' | 'Low' | 'Medium' | 'High';
  performanceScore: number; // 0 - 100
  recommendations: string[];
}

export interface DetectionBreakdown {
  id: string;
  timestamp: string;
  userIntent: string;
  targetPlatform: SiemPlatformId;
  targetPlatformName: string;
  query: string;
  detectionLogic: string;
  mitreMapping: MitreMapping;
  tuning: TuningRecommendation;
  investigationQueries: InvestigationQuery[];
  assumptions: string[];
  performance: PerformanceOptimization;
  syntaxCompatibility: {
    dialectVersion: string;
    isLatestSyntax: boolean;
    compatibilityNotes: string;
  };
  translatedQueries?: Record<SiemPlatformId, string>;
}

export interface QueryOptimizationResult {
  originalQuery: string;
  platform: SiemPlatformId;
  optimizedQuery: string;
  performanceScoreBefore: number;
  performanceScoreAfter: number;
  bottlenecksFound: {
    issue: string;
    severity: 'High' | 'Medium' | 'Low';
    fixExplanation: string;
  }[];
  explanation: string;
}

export interface ThreatPlaybookItem {
  id: string;
  title: string;
  description: string;
  category: string;
  mitreTactic: string;
  mitreTechniqueId: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  platforms: Partial<Record<SiemPlatformId, string>>;
  tags: string[];
  sampleLog: string;
}

export interface CopilotChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  generatedQuery?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  threatActor?: string;
  cveReferences?: string[];
  researchInsights?: string[];
  sources?: Array<{ title: string; url?: string }>;
  modelUsed?: string;
  followUpSuggestions?: string[];
}

export type IocMaskMode = 'defang' | 'redact' | 'hash_mask';
export type IocFileType = 'text' | 'csv' | 'excel' | 'xlsx' | 'txt' | 'image';

export interface ExtractedIoc {
  type: 'ip' | 'url' | 'domain' | 'email' | 'hash';
  original: string;
  masked: string;
  count: number;
}

export interface IocMaskResult {
  maskedContent: string;
  extractedIocs: ExtractedIoc[];
  counts: {
    ip: number;
    url: number;
    domain: number;
    email: number;
    hash: number;
    total: number;
  };
  fileType: IocFileType;
  fileName?: string;
  rawCsvRows?: string[][];
  maskedCsvRows?: string[][];
}

export type IocType = 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha256' | 'hash_sha1' | 'cve' | 'email' | 'auto';

export interface ThreatIntelSourceResult {
  sourceName: string;
  status: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
  scoreDetails: string;
  details: string;
  lastReported?: string;
  link?: string;
  isOriginalResourceMatch?: boolean;
  category?: string;
  rawPayload?: Record<string, any>;
  engineDetections?: { engine: string; category: string; result: string }[];
}

export interface IocInvestigationResult {
  ioc: string;
  iocType: 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha256' | 'hash_sha1' | 'cve' | 'email';
  verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
  threatScore: number;
  maliciousTags: string[];
  summary: string;
  geolocation?: {
    country: string;
    countryCode?: string;
    city?: string;
    asn?: string;
    isp?: string;
    lat?: number;
    lon?: number;
    timezone?: string;
  };
  threatActor?: string;
  campaign?: string;
  mitreTechniques?: string[];
  sources: ThreatIntelSourceResult[];
  passiveDns?: { record: string; type: string; firstSeen: string; lastSeen: string }[];
  recommendations: string[];
  investigationTimestamp: string;
  liveVerificationStatus?: 'Verified Live Match' | 'Enriched Telemetry' | 'OSINT Feeds Synchronized';
  authoritativeOriginUrl?: string;
  rawProviderFeeds?: Record<string, any>;
}

export type ViewMode =
  | 'copilot'
  | 'iocs_reputation'
  | 'sandbox'
  | 'email_header'
  | 'iocs_masker'
  | 'generator'
  | 'translator'
  | 'optimizer'
  | 'incident_retro'
  | 'playbooks'
  | 'cheat_sheet'
  | 'attack_path'
  | 'rule_benchmarker';

// --- Email Header Analyzer Types ---
export interface EmailHeaderHop {
  hopNumber: number;
  fromMta: string;
  byMta: string;
  withProtocol?: string;
  timestamp: string;
  delaySeconds: number;
  delayFormatted: string;
  ipAddress?: string;
  country?: string;
  asn?: string;
  isSuspicious?: boolean;
}

export interface EmailSecurityTag {
  id: string;
  name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info' | 'Clean';
  description: string;
}

export interface EmailAuthResult {
  spf: {
    status: 'Pass' | 'Fail' | 'SoftFail' | 'Neutral' | 'None' | 'TempError' | 'PermError';
    ip?: string;
    domain?: string;
    details: string;
  };
  dkim: {
    status: 'Pass' | 'Fail' | 'None';
    domain?: string;
    selector?: string;
    alignment: 'Aligned' | 'Misaligned' | 'None';
    details: string;
  };
  dmarc: {
    status: 'Pass' | 'Fail' | 'None';
    policy: 'Reject' | 'Quarantine' | 'None';
    disposition?: string;
    alignment: 'Pass' | 'Fail' | 'None';
    details: string;
  };
  arc?: {
    status: 'Pass' | 'Fail' | 'None';
    details: string;
  };
  tls?: {
    version?: string;
    cipher?: string;
    isEncrypted: boolean;
  };
}

export interface EmailHeaderAnalysisResult {
  id: string;
  subject: string;
  from: {
    name: string;
    address: string;
    domain: string;
  };
  to: string[];
  cc?: string[];
  replyTo?: {
    name?: string;
    address: string;
    domain: string;
    isMismatched: boolean;
  };
  returnPath?: {
    address: string;
    domain: string;
    isMismatched: boolean;
  };
  date: string;
  messageId: string;
  originatingIp?: string;
  mailerAgent?: string;
  verdict: 'Malicious / Phishing' | 'Suspicious' | 'Spoofed' | 'Legitimate';
  emailCategory: string; // e.g. 'CEO Fraud / Business Email Compromise (BEC)', 'Credential Harvester Phishing', 'Malware Dropper / Payload Delivery', 'Spoofed Vendor Invoice & Wire Fraud', 'Extortion / Blackmail Scam', 'Legitimate Corporate Communication', 'Legitimate Transactional Alert'
  emailClassificationRationale: string;
  confidenceLevel: 'High' | 'Medium' | 'Low';
  attackTechnique?: string;
  threatIntent?: string;
  threatScore: number; // 0 - 100
  securityTags: EmailSecurityTag[];
  authentication: EmailAuthResult;
  hops: EmailHeaderHop[];
  totalTransitTime: string;
  extractedIocs: {
    type: 'ip' | 'domain' | 'email' | 'url';
    value: string;
    role: string;
  }[];
  executiveSummary: string;
  investigationDetails: string[];
  recommendedActions: string[];
  siemHuntingQuery: {
    platform: SiemPlatformId;
    query: string;
    description: string;
  };
}

export type DeviceFrameMode = 'desktop' | 'ios' | 'android';
export type ThemeMode = 'light' | 'dark' | 'terminal' | 'cyberpunk' | 'nordic' | 'solarized';

export interface ThemeMeta {
  id: ThemeMode;
  name: string;
  subtitle: string;
  previewBg: string;
  previewAccent: string;
  previewCard: string;
  accentClass: string;
  icon: string;
}

// --- Module 1: Interactive Attack Path & Blast Radius Simulator Types ---
export interface AttackGraphNode {
  id: string;
  name: string;
  type: 'workstation' | 'server' | 'user' | 'domain_admin' | 'cloud_iam' | 'database' | 'ip' | 'firewall';
  criticalAsset: boolean;
  status: 'compromised' | 'at_risk' | 'safe';
  riskScore: number; // 0 - 100
  osOrType?: string;
  ipAddress?: string;
  departmentOrRegion?: string;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  techniqueId: string;
  techniqueName: string;
  protocolOrVector: string;
  siemQuery?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  timestamp?: string;
}

export interface BlastRadiusReport {
  totalNodes: number;
  compromisedNodes: number;
  atRiskNodes: number;
  blastRadiusPercentage: number;
  criticalAssetsAtRisk: number;
  initialAccessNode: string;
  targetAssetNode: string;
  pathHopCount: number;
  containmentSteps: {
    stepNumber: number;
    title: string;
    action: string;
    platformCommand?: string;
    impact: string;
  }[];
}

export interface AttackScenario {
  id: string;
  title: string;
  description: string;
  threatActor: string;
  initialAccess: string;
  targetAsset: string;
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  report: BlastRadiusReport;
}

// --- Module 2: AI Detection Rule Quality & Performance Benchmarker Types ---
export interface RuleBenchmarkIssue {
  line?: number;
  code: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  recommendation: string;
  costImpact: string;
}

export interface RuleBenchmarkResult {
  ruleTitle: string;
  platform: SiemPlatformId;
  overallGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  performanceScore: number; // 0 - 100
  costImpactScore: number; // 0 - 100
  fidelityScore: number; // 0 - 100
  portabilityScore: number; // 0 - 100
  estimatedComputeUnits: string;
  estimatedMonthlyCloudCost: string;
  issuesFound: RuleBenchmarkIssue[];
  optimizedRuleContent: string;
  optimizedDiffExplanation: string;
  portabilityBreakdown: {
    platform: SiemPlatformId;
    platformName: string;
    compatibility: 'Native' | 'Easy Translation' | 'Requires Rewrite' | 'Unsupported';
    notes: string;
  }[];
  mitreCoverage: {
    tactic: string;
    techniqueId: string;
    techniqueName: string;
    confidence: number;
  }[];
}

// --- Module 3: Automated Incident Retrospective & Alert Triage Report Generator Types ---
export interface IncidentRetroInput {
  incidentTitle: string;
  dataSource: string; // e.g., Windows Event Log, AWS CloudTrail, CrowdStrike EDR, Okta Logs
  iocsInvolved?: string;
}

export interface CyberKillChainStage {
  stage: 'Reconnaissance' | 'Weaponization' | 'Delivery' | 'Exploitation' | 'Installation' | 'Command & Control' | 'Actions on Objectives';
  description: string;
  detectedArtifacts?: string;
}

export interface InvestigationStep {
  stepNumber: number;
  phase: string;
  action: string;
  details: string;
  expectedOutcome: string;
}

export interface AlertAnalysisOverview {
  alertTriggerMechanism: string;
  technicalDeepDive: string;
  truePositiveIndicators: string[];
  falsePositiveIndicators: string[];
  investigationScope: string;
}

export interface ThreatIntelEnrichment {
  ipAddress: string;
  reportsCount: number;
  abuseConfidence: number;
  isp: string;
  usageType: string;
  asn: string;
  domainName: string;
  country: string;
  city: string;
}

export interface IncidentRetroReport {
  id: string;
  incidentId: string;
  alertId: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  clientName: string;
  incidentTitle: string;
  dataSource: string;
  generatedAt: string;
  timestamp: string;
  sourceIpAddress: string;
  username: string;
  mitreSummary: string;
  observedFacts: string[];
  threatIntelEnrichment?: ThreatIntelEnrichment[];
  recommendedActions: string[];
  alertAnalysis?: AlertAnalysisOverview;
  executiveSummary: {
    cisoBriefing: string;
    businessImpact: string;
    keyTakeaway: string;
  };
  investigationSteps: InvestigationStep[];
  recommendations: string[];
  attackVector: {
    summary: string;
    technicalDetails: string;
  };
  mitreAttackMapping: {
    tactic: string;
    techniqueId: string;
    techniqueName: string;
    description: string;
  }[];
  cyberKillChain: CyberKillChainStage[];
  postIncidentPlan?: {
    immediateActionItems: {
      priority: 'P0' | 'P1' | 'P2';
      task: string;
      owner: string;
      status: 'Open' | 'In Progress' | 'Completed';
    }[];
  };
  siemQueriesForTriage: {
    title: string;
    platform: SiemPlatformId;
    query: string;
    purpose: string;
  }[];
}

// --- Open-Source Malware Sandbox Analysis Types ---
export type SandboxPlatformId =
  | 'capev2'
  | 'cuckoo'
  | 'drakvuf'
  | 'anyrun'
  | 'hybrid'
  | 'triage'
  | 'malwarebazaar'
  | 'intezer';

export interface SandboxPlatformMeta {
  id: SandboxPlatformId;
  name: string;
  shortName: string;
  isOpenSource: boolean;
  license: string;
  category: 'Automated Extraction' | 'VMI Agentless' | 'Interactive Sandbox' | 'Hybrid Dynamic' | 'Community Repository';
  description: string;
  githubUrl?: string;
  publicUrl: string;
  badgeColor: string;
  supportedFormats: string[];
  capabilities: string[];
}

export interface ProcessTreeNode {
  pid: number;
  ppid: number;
  name: string;
  commandLine: string;
  integrityLevel: 'System' | 'High' | 'Medium' | 'Low';
  isMalicious: boolean;
  lolbas: boolean;
  signatures: string[];
  children?: ProcessTreeNode[];
}

export interface NetworkConnection {
  protocol: 'DNS' | 'HTTP' | 'HTTPS' | 'TCP' | 'UDP' | 'IRC';
  destination: string;
  port: number;
  process: string;
  bytesTransferred?: string;
  country?: string;
  verdict: 'Malicious C2' | 'Suspicious' | 'Benign' | 'CDN / Legitimate';
  details: string;
}

export interface ExtractedConfig {
  family: string;
  c2Servers: string[];
  ports: number[];
  mutexes: string[];
  encryptionKey?: string;
  campaignId?: string;
  version?: string;
  injectedProcess?: string;
  rawDumpSample?: string;
}

export interface DroppedFile {
  path: string;
  fileName: string;
  sha256: string;
  size: string;
  fileType: string;
  entropy: number;
  verdict: 'Malicious' | 'Suspicious' | 'Clean';
}

export interface RegistryChange {
  action: 'Created' | 'Modified' | 'Deleted';
  key: string;
  value: string;
  purpose: 'Persistence (Run Key)' | 'Defense Evasion (Disable Defender/UAC)' | 'Configuration' | 'System Setting';
}

export interface SandboxEngineResult {
  platformId: SandboxPlatformId;
  platformName: string;
  verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Undetected';
  score: number; // 0 - 100
  analysisTime: string;
  environment: string;
  detectionRatio?: string;
  signaturesTriggered: number;
  liveUrl: string;
  isOpenSource: boolean;
}

export interface SandboxAnalysisResult {
  id: string;
  sampleTarget: string;
  targetType: 'file_hash' | 'url' | 'uploaded_sample' | 'ip' | 'domain';
  fileMeta: {
    name: string;
    size: string;
    type: string;
    md5: string;
    sha1?: string;
    sha256: string;
    ssdeep?: string;
    entropy: number;
  };
  verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
  threatScore: number;
  malwareFamily: string;
  threatActor: string;
  summary: string;
  engineResults: SandboxEngineResult[];
  processTree: ProcessTreeNode[];
  extractedConfig?: ExtractedConfig;
  networkTraffic: NetworkConnection[];
  droppedFiles: DroppedFile[];
  registryActivity: RegistryChange[];
  mitreTechniques: {
    tactic: string;
    techniqueId: string;
    techniqueName: string;
    details: string;
  }[];
  yaraMatches: {
    ruleName: string;
    author?: string;
    description: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Info';
  }[];
  suricataAlerts?: {
    signature: string;
    category: string;
    severity: number;
  }[];
  recommendedDetectionQueries: {
    platform: SiemPlatformId;
    platformName: string;
    query: string;
    title: string;
  }[];
  analysisTimestamp: string;
  pcapAvailable: boolean;
  memoryDumpAvailable: boolean;
}


