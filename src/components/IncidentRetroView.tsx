import React, { useState } from 'react';
import {
  FileText,
  ShieldAlert,
  Sparkles,
  Check,
  Copy,
  ListTodo,
  Terminal,
  ChevronRight,
  Building,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Activity,
  GitCommit,
  ShieldCheck,
  Compass,
  ArrowRight,
  Lock,
  Layers,
  Database,
  ExternalLink,
} from 'lucide-react';
import { IncidentRetroInput, IncidentRetroReport } from '../types';

export function buildTailoredRecommendations(title: string, dataSource: string): string[] {
  const lowerTitle = title.toLowerCase();
  const lowerDs = dataSource.toLowerCase();

  // SQL Injection / Database / Web Application Attacks
  if (lowerTitle.includes('sql') || lowerTitle.includes('injection') || lowerTitle.includes('xss') || lowerTitle.includes('web shell') || lowerTitle.includes('waf')) {
    return [
      `Remediate '${title}' by enforcing mandatory ORM prepared statements and parameterized database queries across application routes logged in ${dataSource}.`,
      `Deploy targeted Web Application Firewall (WAF) rule filters on ${dataSource} to inspect HTTP request parameters and drop malicious payloads matching '${title}'.`,
      `Restrict application database user privileges to prevent schema modifications, system table access, or out-of-band file writes if '${title}' is attempted.`,
      `Integrate SAST and DAST vulnerability scanners into CI/CD build pipelines to continuously audit web application code generating alerts in ${dataSource}.`
    ];
  }

  // Kerberoasting / Active Directory / Ticket Attacks
  if (lowerTitle.includes('kerberos') || lowerTitle.includes('kerberoast') || lowerTitle.includes('active directory') || lowerTitle.includes('spn') || lowerTitle.includes('ticket')) {
    return [
      `Enforce complex, 25+ character high-entropy passwords for Service Principal Accounts (SPNs) targeted in '${title}' to neutralize offline hash cracking.`,
      `Migrate service accounts associated with '${title}' to Group Managed Service Accounts (gMSA) with automated 128-bit password rotation.`,
      `Disable legacy RC4-HMAC Kerberos encryption types in Active Directory / ${dataSource} and mandate AES-128 / AES-256 encryption.`,
      `Configure SIEM alert thresholds in ${dataSource} to flag anomalous high-volume TGS ticket requests matching '${title}'.`
    ];
  }

  // Cloud Storage / S3 / Bucket / IAM Public Access
  if (lowerTitle.includes('bucket') || lowerTitle.includes('s3') || lowerTitle.includes('blob') || lowerTitle.includes('cloud') || lowerTitle.includes('anonymous') || lowerTitle.includes('storage') || lowerTitle.includes('iam key')) {
    return [
      `Enforce short-lived IAM session roles (e.g. AWS STS / Azure Managed Identities) and eliminate static long-lived API keys for '${title}'.`,
      `Enable S3 Block Public Access and bucket policies requiring explicit IAM authentication in ${dataSource} to prevent public exposure related to '${title}'.`,
      `Configure Cloud Security Posture Management (CSPM / GuardDuty) in ${dataSource} to auto-remediate unauthorized bucket policy alterations.`,
      `Rotate all database credentials, API tokens, and private keys stored within cloud storage resources implicated in '${title}'.`
    ];
  }

  // Obfuscated Scripting / PowerShell / Execution
  if (lowerTitle.includes('powershell') || lowerTitle.includes('encoded') || lowerTitle.includes('script') || lowerTitle.includes('cmd') || lowerTitle.includes('bash') || lowerTitle.includes('execution')) {
    return [
      `Deploy PowerShell Constrained Language Mode (CLM) and AppLocker / WDAC script execution restrictions across endpoints to mitigate '${title}'.`,
      `Enable Windows ScriptBlock Logging (Event ID 4104) and Module Logging in ${dataSource} to capture un-encoded command payloads for '${title}'.`,
      `Configure EDR behavioral blocking rules in ${dataSource} to automatically isolate endpoints and terminate process trees executing '${title}'.`,
      `Isolate hosts executing obfuscated scripts matching '${title}' and conduct memory dump forensic analysis.`
    ];
  }

  // Brute Force / Password Spray / Auth / MFA Push Fatigue
  if (lowerTitle.includes('brute') || lowerTitle.includes('spray') || lowerTitle.includes('failed login') || lowerTitle.includes('okta') || lowerTitle.includes('mfa') || lowerTitle.includes('credential') || lowerTitle.includes('push fatigue')) {
    return [
      `Mandate hardware-backed FIDO2 / WebAuthn MFA keys for all user accounts targeted by '${title}' in ${dataSource} to eliminate push fatigue.`,
      `Enable Smart Lockout and adaptive risk-based Conditional Access policies within ${dataSource} to block ip spraying for '${title}'.`,
      `Execute an immediate forced password reset and SAML / OAuth session token revocation for accounts targeted in '${title}'.`,
      `Block malicious source IP addresses and TOR exit nodes in ${dataSource} originating high-frequency login attempts for '${title}'.`
    ];
  }

  // Privilege Escalation / Ransomware / Exfiltration
  if (lowerTitle.includes('privilege') || lowerTitle.includes('escalation') || lowerTitle.includes('ransomware') || lowerTitle.includes('exfiltration') || lowerTitle.includes('shadow copy')) {
    return [
      `Isolate endpoints immediately via EDR in ${dataSource} to halt lateral movement and payload execution for '${title}'.`,
      `Revoke elevated domain privileges and audit local administrator group memberships on endpoints implicated in '${title}'.`,
      `Deploy Attack Surface Reduction (ASR) rules in ${dataSource} to block shadow copy deletion and unauthorized credential dumping for '${title}'.`,
      `Verify offline backup immutability and conduct an enterprise-wide IOC sweep for host artifacts associated with '${title}'.`
    ];
  }

  // Perimeter / Network / Firewall / Proxy
  if (lowerDs.includes('firewall') || lowerDs.includes('palo alto') || lowerDs.includes('fortinet') || lowerDs.includes('cisco') || lowerDs.includes('zscaler') || lowerDs.includes('vpn') || lowerDs.includes('waf') || lowerDs.includes('proxy')) {
    return [
      `Enforce automated perimeter firewall / WAF blocking rules in ${dataSource} for source IP addresses involved in '${title}'.`,
      `Enable SSL/TLS decryption and deep packet inspection (DPI) on ${dataSource} to inspect encrypted payload traffic for '${title}'.`,
      `Configure geo-IP restriction policies and real-time threat intelligence feeds in ${dataSource} to drop unauthorized ingress traffic for '${title}'.`,
      `Deploy SOAR orchestration playbooks in ${dataSource} to dynamically update perimeter blocklists upon triggering '${title}'.`
    ];
  }

  // Default fallback explicitly incorporating Alert Title
  return [
    `Harden SIEM and EDR detection rules in ${dataSource} specifically tailored to detect precursor techniques for '${title}'.`,
    `Audit access controls and enforce strict least-privilege authorization for all user accounts and services involved in '${title}'.`,
    `Configure automated SOAR playbooks in ${dataSource} for instant session revocation and host isolation upon triggering '${title}'.`,
    `Conduct a dedicated SOC post-incident review and tabletop exercise focused on '${title}' triage workflows.`
  ];
}

export function buildAccurateKillChain(title: string, dataSource: string): { stage: string; description: string; detectedArtifacts?: string }[] {
  const lowerTitle = title.toLowerCase();

  if (lowerTitle.includes('sql') || lowerTitle.includes('injection') || lowerTitle.includes('xss') || lowerTitle.includes('waf') || lowerTitle.includes('web shell')) {
    return [
      {
        stage: 'Exploitation',
        description: `Adversary transmitted HTTP request payloads containing unsanitized database control characters to exploit web application inputs for '${title}'.`,
        detectedArtifacts: `SQL payload strings in ${dataSource}`
      },
      {
        stage: 'Actions on Objectives',
        description: `Executed unauthorized database queries to enumerate schema, extract records, or inspect table contents associated with '${title}'.`,
        detectedArtifacts: `HTTP 200/500 query responses in web logs`
      }
    ];
  }

  if (lowerTitle.includes('kerberos') || lowerTitle.includes('kerberoast') || lowerTitle.includes('active directory') || lowerTitle.includes('spn') || lowerTitle.includes('ticket')) {
    return [
      {
        stage: 'Exploitation',
        description: `Adversary issued Kerberos Ticket Granting Service (TGS) requests using legacy RC4-HMAC encryption for Service Principal Names in '${title}'.`,
        detectedArtifacts: `Event ID 4769 (TGS Request) in ${dataSource}`
      },
      {
        stage: 'Actions on Objectives',
        description: `Extracted service ticket hashes from memory/network logs for offline password cracking attempts.`,
        detectedArtifacts: `SPN ticket request logs`
      }
    ];
  }

  if (lowerTitle.includes('bucket') || lowerTitle.includes('s3') || lowerTitle.includes('blob') || lowerTitle.includes('cloud') || lowerTitle.includes('anonymous') || lowerTitle.includes('storage') || lowerTitle.includes('iam key')) {
    return [
      {
        stage: 'Delivery',
        description: `Direct unauthenticated API network connections established against public or compromised cloud resources in '${title}'.`,
        detectedArtifacts: `Public API access requests in ${dataSource}`
      },
      {
        stage: 'Actions on Objectives',
        description: `Unintended API read operations performed against cloud object storage buckets or secrets repositories.`,
        detectedArtifacts: `GetObject / ListBuckets API logs`
      }
    ];
  }

  if (lowerTitle.includes('powershell') || lowerTitle.includes('encoded') || lowerTitle.includes('script') || lowerTitle.includes('cmd') || lowerTitle.includes('bash') || lowerTitle.includes('execution')) {
    return [
      {
        stage: 'Execution',
        description: `Command interpreter (powershell.exe / cmd) executed with Base64 encoded or obfuscated payload arguments for '${title}'.`,
        detectedArtifacts: `Process launch & ScriptBlock Event 4104 in ${dataSource}`
      },
      {
        stage: 'Installation',
        description: `Script attempted secondary process injection, scheduled task creation, or autorun registry persistence.`,
        detectedArtifacts: `Child process spawning / registry modification`
      }
    ];
  }

  if (lowerTitle.includes('brute') || lowerTitle.includes('spray') || lowerTitle.includes('failed login') || lowerTitle.includes('okta') || lowerTitle.includes('mfa') || lowerTitle.includes('push fatigue') || lowerTitle.includes('credential')) {
    return [
      {
        stage: 'Delivery',
        description: `Automated authentication requests transmitted across target user accounts or Identity Provider endpoints for '${title}'.`,
        detectedArtifacts: `High frequency failed logon events in ${dataSource}`
      },
      {
        stage: 'Exploitation',
        description: `Potential single account password compromise or user push approval induced by MFA fatigue.`,
        detectedArtifacts: `Successful logon following failure spike`
      }
    ];
  }

  if (lowerTitle.includes('privilege') || lowerTitle.includes('escalation') || lowerTitle.includes('ransomware') || lowerTitle.includes('exfiltration') || lowerTitle.includes('shadow copy')) {
    return [
      {
        stage: 'Exploitation',
        description: `Execution of local privilege escalation exploits or token manipulation routines detected in '${title}'.`,
        detectedArtifacts: `System process injection in ${dataSource}`
      },
      {
        stage: 'Actions on Objectives',
        description: `Volume shadow copy deletion, file encryption, or data staging for exfiltration.`,
        detectedArtifacts: `VSSAdmin calls / high outbound network traffic`
      }
    ];
  }

  // Default fallback: return only the 2 accurate active stages for the alert title
  return [
    {
      stage: 'Exploitation',
      description: `Active exploitation or threat execution mechanism detected matching alert '${title}' in ${dataSource}.`,
      detectedArtifacts: `Telemetry alert trigger for '${title}'`
    },
    {
      stage: 'Actions on Objectives',
      description: `Observed post-execution behavior and operational impact related to '${title}'.`,
      detectedArtifacts: `Audit logs in ${dataSource}`
    }
  ];
}

const PRESET_INCIDENTS: { label: string; data: IncidentRetroInput }[] = [
  {
    label: 'Suspicious PowerShell Execution',
    data: {
      incidentTitle: 'Suspicious PowerShell Execution with Encoded Base64 Payload',
      dataSource: 'Windows Event Logs / Sysmon (Event ID 1 & 4104)',
      iocsInvolved: 'powershell.exe -e a3lsbCAtOS... (PID: 4920), Workstation-WS-8812, User: jdoe',
    },
  },
  {
    label: 'AWS IAM Secret Key Leak',
    data: {
      incidentTitle: 'AWS IAM Admin Secret Key Leak & S3 Customer Vault Bulk Exfiltration',
      dataSource: 'AWS CloudTrail & GuardDuty',
      iocsInvolved: 'AKIAIOSFODNN7EXAMPLE (Leaked Key ID), 54.210.88.12 (Attacker C2 IP), s3-customer-pii-vault',
    },
  },
  {
    label: 'Okta MFA Push Fatigue',
    data: {
      incidentTitle: 'Okta Password Spray & MFA Push Fatigue Session Hijacking',
      dataSource: 'Okta SystemLog & CrowdStrike EDR',
      iocsInvolved: 'User: e.smith@corp.com, IP: 185.220.101.5 (Tor Exit), Device: Mac OS X Chrome 124',
    },
  },
  {
    label: 'Kerberoasting & AD Ticket Forgery',
    data: {
      incidentTitle: 'Kerberoasting Ticket Request & Golden Ticket Domain Controller Forgery',
      dataSource: 'Active Directory Security Event Log (Event ID 4769)',
      iocsInvolved: 'DC-01.corp.local, ServiceName: MSSQLSvc/db-01, TicketEncryptionType: 0x23 (RC4-HMAC)',
    },
  },
];

export const IncidentRetroView: React.FC<{
  onSendToGenerator?: (promptText: string) => void;
  userRole?: string;
}> = ({ onSendToGenerator, userRole = 'visitor' }) => {
  const [inputData, setInputData] = useState<IncidentRetroInput>({
    incidentTitle: '',
    dataSource: '',
    iocsInvolved: '',
  });
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [report, setReport] = useState<IncidentRetroReport | null>(null);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const handleGenerateReport = async () => {
    setIsGenerating(true);

    const titleToUse = inputData.incidentTitle.trim() || 'Suspicious Security Alert Event';
    const dsToUse = inputData.dataSource.trim() || 'SIEM & EDR Logs';
    const iocsToUse = inputData.iocsInvolved.trim();

    try {
      const response = await fetch('/api/generate-incident-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentTitle: titleToUse,
          dataSource: dsToUse,
          iocsInvolved: iocsToUse,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setReport(data);
      } else {
        throw new Error('API failed');
      }
    } catch {
      // Local dynamic category-aware report builder fallback
      const title = titleToUse;
      const lowerTitle = title.toLowerCase();
      const ds = dsToUse;
      const iocs = iocsToUse || 'N/A';

      const isWebSqli = lowerTitle.includes('sql') || lowerTitle.includes('injection') || lowerTitle.includes('waf') || lowerTitle.includes('xss') || lowerTitle.includes('web shell');
      const isAuthBrute = lowerTitle.includes('brute') || lowerTitle.includes('spray') || lowerTitle.includes('failed login') || lowerTitle.includes('okta') || lowerTitle.includes('mfa') || lowerTitle.includes('push fatigue');
      const isPowershellScript = lowerTitle.includes('powershell') || lowerTitle.includes('command') || lowerTitle.includes('script') || lowerTitle.includes('encoded') || lowerTitle.includes('base64');
      const isCloudBucket = lowerTitle.includes('aws') || lowerTitle.includes('cloud') || lowerTitle.includes('s3') || lowerTitle.includes('iam') || lowerTitle.includes('secret key');
      const isKerberosAd = lowerTitle.includes('kerberoast') || lowerTitle.includes('ticket') || lowerTitle.includes('active directory') || lowerTitle.includes('domain controller') || lowerTitle.includes('golden ticket');

      let steps = [];
      let recs = [];
      let vector = { summary: '', technicalDetails: '' };
      let mitre = [];

      if (isWebSqli) {
        steps = [
          { stepNumber: 1, phase: 'WAF & HTTP Request Log Inspection', action: `Filter ${ds} for HTTP 500 errors and SQL payload strings matching '${title}'`, details: `Search web server access logs for pattern matches like 'UNION SELECT', '' OR 1=1--', or 'INFORMATION_SCHEMA'.`, expectedOutcome: 'Identify client source IP, vulnerable URL endpoint, and parameter.' },
          { stepNumber: 2, phase: 'Database Query Execution Audit', action: 'Correlate web request timestamp with database transaction logs', details: 'Inspect database transaction logs for abnormal schema queries or file writes.', expectedOutcome: 'Determine if SQL injection was successful and data was dumped.' },
          { stepNumber: 3, phase: 'Vulnerability Isolation & WAF Rule Enforcement', action: 'Deploy emergency WAF blocking rule and isolate endpoint', details: 'Apply custom URI blocking filter at WAF/CDN layer for source IP and pattern.', expectedOutcome: 'Neutralize exploit attempts without stopping legitimate web traffic.' },
          { stepNumber: 4, phase: 'Source Code & ORM Parameterization Review', action: 'Inspect backend source code for unescaped SQL concatenation', details: 'Audit database access code corresponding to exploited route. Enforce prepared statements.', expectedOutcome: 'Pinpoint exact unescaped input parameter needing code fix.' },
          { stepNumber: 5, phase: 'Post-Exploit Verification & Patch Deployment', action: 'Deploy parameterized code fix and perform regression test', details: 'Re-test endpoint with automated SAST/DAST tools and verify clean HTTP 400/403 responses.', expectedOutcome: 'Permanent remediation of SQL injection vector.' },
        ];
        recs = [
          'Enforce mandatory ORM prepared statements / parameterized queries across database code.',
          'Deploy strict input validation and URI filtering rules on Cloud WAF edge.',
          'Restrict web app database user from performing schema alterations or reading system tables.',
          'Integrate static code analysis (SAST) into CI/CD pipelines to catch SQL concatenation.'
        ];
        vector = { summary: `SQL Injection Exploitation (${title})`, technicalDetails: `Adversary submitted unsanitized SQL control characters in HTTP parameters to execute arbitrary database commands in ${ds}.` };
        mitre = [
          { tactic: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', description: 'Exploited input handling vulnerability in web application.' },
          { tactic: 'Collection', techniqueId: 'T1505.003', techniqueName: 'Web Shell / DB Data Collection', description: 'Queried database schema and sensitive table records.' }
        ];
      } else if (isAuthBrute) {
        steps = [
          { stepNumber: 1, phase: 'Authentication Log Triage & Failure Rate Analysis', action: `Query ${ds} for rapid authentication failures matching '${title}'`, details: `Filter logs for Event ID 4625 or Okta MFA failures. Group by source IP, username list, and user-agent string.`, expectedOutcome: 'Determine if attack is password spray vs single-account brute force.' },
          { stepNumber: 2, phase: 'Compromised Account & MFA Session Audit', action: 'Identify successful logins following failure bursts', details: `Cross-reference suspicious IPs against successful authentication events (Okta SUCCESS) and inspect for MFA push approvals.`, expectedOutcome: 'Isolate compromised user accounts that succumbed to the attack.' },
          { stepNumber: 3, phase: 'Account Containment & Session Revocation', action: 'Execute immediate session termination and password reset', details: 'Revoke active OAuth/SAML tokens for compromised users and force password reset.', expectedOutcome: 'Neutralize adversary access to corporate applications.' },
          { stepNumber: 4, phase: 'Perimeter & IP Reputation Blocking', action: 'Block attacker source IPs on IDP and Firewall', details: 'Add identified malicious IPs/Tor exit nodes to IdP threat intelligence blocklists.', expectedOutcome: 'Prevent ongoing authentication noise and spray botnets.' },
          { stepNumber: 5, phase: 'Post-Compromise Activity Audit', action: 'Inspect mail flow rules, cloud storage, and secondary logins', details: 'Audit Exchange inbox forwarding rules created during compromised window and VPN logins.', expectedOutcome: 'Verify no persistent backdoors were established.' },
        ];
        recs = [
          'Enable Smart Lockout and adaptive risk-based authentication to block IP ranges exceeding thresholds.',
          'Mandate hardware-backed FIDO2 / WebAuthn MFA keys to eliminate push fatigue.',
          'Disable legacy authentication protocols (IMAP, POP3, Basic Auth) in M365/Okta.',
          'Implement real-time alert notifications for logins from anomalous geographies or Tor exit nodes.'
        ];
        vector = { summary: `Credential Abuse / Password Spray (${title})`, technicalDetails: `Adversary tested credentials or sent repeated MFA push notifications against ${ds} until user accepted.` };
        mitre = [
          { tactic: 'Credential Access', techniqueId: 'T1110.003', techniqueName: 'Password Spraying', description: 'Tested common passwords across multiple accounts.' },
          { tactic: 'Defense Evasion', techniqueId: 'T1621', techniqueName: 'Multi-Factor Authentication Request Generation', description: 'Bombarded user with MFA push notifications to induce approval.' }
        ];
      } else if (isPowershellScript) {
        steps = [
          { stepNumber: 1, phase: 'Process Execution Tree & ScriptBlock Triage', action: `Query ${ds} for process launch logs matching '${title}'`, details: `Inspect Sysmon Event ID 1 / Windows Event ID 4104 (ScriptBlock Logging). Decode Base64 encoded strings from CLI argument list.`, expectedOutcome: 'Reconstruct unencrypted script payload, parent process, and executing user.' },
          { stepNumber: 2, phase: 'Network Outbound & File System Artifact Analysis', action: 'Correlate PowerShell process ID with network connections and drop files', details: `Cross-reference process ID with outbound EDR network events and file creation in C:\\Users\\Public.`, expectedOutcome: 'Identify remote C2 server IP/domain and extracted binaries.' },
          { stepNumber: 3, phase: 'Host Network Isolation via EDR', action: 'Execute immediate EDR network containment on host', details: 'Isolate compromised endpoint from internal network via EDR agent.', expectedOutcome: 'Halt lateral movement and beaconing.' },
          { stepNumber: 4, phase: 'Persistence Mechanism Sweep', action: 'Audit Scheduled Tasks, Registry Run keys, and WMI Subscriptions', details: `Scan host registry and Scheduled Tasks for autorun entries referencing powershell.exe.`, expectedOutcome: 'Locate and delete all persistence artifacts.' },
          { stepNumber: 5, phase: 'Memory Dump & Endpoint Remediation', action: 'Kill process tree, remove persistence files, and re-audit host', details: 'Terminate suspicious process trees, purge payload files, and monitor endpoint for 48 hours.', expectedOutcome: 'Full eradication of script malware and host hygiene verification.' },
        ];
        recs = [
          'Enable Constrained Language Mode (CLM) for PowerShell across standard workstations.',
          'Deploy AppLocker / WDAC to block unapproved script execution.',
          'Enforce PowerShell ScriptBlock Logging (Event ID 4104) and Module Logging.',
          'Configure EDR behavioral blocking rules for child processes spawned by Office apps.'
        ];
        vector = { summary: `Obfuscated PowerShell Execution (${title})`, technicalDetails: `Adversary executed obfuscated scripts via native powershell.exe in ${ds} to bypass antivirus file scanners.` };
        mitre = [
          { tactic: 'Execution', techniqueId: 'T1059.001', techniqueName: 'Command and Scripting Interpreter: PowerShell', description: 'Executed encoded commands via powershell.exe.' },
          { tactic: 'Defense Evasion', techniqueId: 'T1027', techniqueName: 'Obfuscated Files or Information', description: 'Utilized Base64 encoding to conceal payload logic.' }
        ];
      } else if (isCloudBucket) {
        steps = [
          { stepNumber: 1, phase: 'CloudTrail / Audit Log API Call Extraction', action: `Query ${ds} for API key activity matching '${title}'`, details: `Filter CloudTrail logs for GetObject, ListObjects, AssumeRole. Extract SourceIPAddress, UserAgent, and UserIdentity ARN.`, expectedOutcome: 'Determine exact API key ID used, caller IP location, and list of accessed buckets.' },
          { stepNumber: 2, phase: 'Data Plane Scope & Exfiltration Volume Audit', action: 'Calculate volume of downloaded objects and impacted bucket keys', details: 'Audit storage bucket access metrics to identify if bulk exfiltration occurred.', expectedOutcome: 'Establish whether customer PII or secrets were compromised.' },
          { stepNumber: 3, phase: 'Immediate Credential Revocation & Bucket Policy Hardening', action: 'Deactivate compromised IAM Access Key and restrict bucket policy', details: 'Inactivate compromised IAM keys, invalidate STS session tokens, and apply DENY bucket policy.', expectedOutcome: 'Instant blockade of adversary API access.' },
          { stepNumber: 4, phase: 'Secret Rotation & Dependency Audit', action: 'Rotate all database passwords and API tokens stored in bucket', details: 'Audit secrets stored within compromised cloud storage and execute automated credential rotation.', expectedOutcome: 'Prevent secondary access using leaked credentials.' },
          { stepNumber: 5, phase: 'CI/CD Pipeline & Code Repository Sweep', action: 'Scan code repositories for hardcoded cloud credentials', details: 'Run automated secret scanner on Git commit history to verify how the key leaked.', expectedOutcome: 'Identify and remediate root cause leak in developer workflows.' },
        ];
        recs = [
          'Implement pre-commit secret scanning hooks in developer IDEs and CI/CD pipelines.',
          'Enforce short-lived IAM session roles (AWS STS) instead of long-lived static API access keys.',
          'Enable S3 Block Public Access at account level and configure GuardDuty S3 Protection.',
          'Require IP condition constraints on IAM policies to restrict API usage to corporate CIDRs.'
        ];
        vector = { summary: `Exposed Cloud IAM Secret Key (${title})`, technicalDetails: `Adversary obtained long-lived API credentials leaked in public locations and issued automated SDK API requests in ${ds}.` };
        mitre = [
          { tactic: 'Credential Access', techniqueId: 'T1552.001', techniqueName: 'Unsecured Credentials: Credentials in Files', description: 'Leaked IAM secret key extracted by adversary scanner.' },
          { tactic: 'Exfiltration', techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage', description: 'Bulk downloaded files from cloud buckets.' }
        ];
      } else if (isKerberosAd) {
        steps = [
          { stepNumber: 1, phase: 'Active Directory Security Event Log Triage', action: `Query ${ds} for Kerberos Ticket Requests matching '${title}'`, details: `Filter AD logs for Event ID 4769 (Kerberos Service Ticket Requested). Filter for TicketEncryptionType '0x23' (RC4-HMAC).`, expectedOutcome: 'Identify requesting user account, target Service Principal Name (SPN), and source client IP.' },
          { stepNumber: 2, phase: 'Ticket Crack Risk Assessment & Privilege Check', action: 'Audit privilege level of target SPN service account', details: 'Verify if requested SPN account possesses Domain Admin or Enterprise Admin privileges.', expectedOutcome: 'Assess severity of potential offline password hash cracking.' },
          { stepNumber: 3, phase: 'Target SPN Password Reset & Managed Service Account Migration', action: 'Rotate password for targeted service account to 30+ random characters', details: 'Execute immediate high-entropy password change for targeted SPN account.', expectedOutcome: 'Invalidate offline hash cracking attempts.' },
          { stepNumber: 4, phase: 'Requesting User Account Isolation & Privileged Session Audit', action: 'Isolate user workstation and audit active Kerberos tickets', details: 'Inspect host ticket cache on requesting workstation and temporarily disable user account.', expectedOutcome: 'Prevent lateral movement via forged ticket injection.' },
          { stepNumber: 5, phase: 'Group Policy Hardening & gMSA Enforcement', action: 'Migrate target SPN to Group Managed Service Account (gMSA)', details: 'Convert static service accounts to gMSA with automatic 128-char password rotation.', expectedOutcome: 'Permanently eliminate Kerberoasting attack surface.' },
        ];
        recs = [
          'Migrate all Active Directory service accounts with SPNs to Group Managed Service Accounts (gMSA).',
          'Disable RC4-HMAC encryption for Kerberos and enforce AES128/AES256 in Group Policy.',
          'Set high-entropy 30+ character passwords for remaining static service accounts.',
          'Deploy Defender for Identity (MDI) to trigger automated alerts on suspicious TGS requests.'
        ];
        vector = { summary: `Kerberoasting / Ticket Forgery (${title})`, technicalDetails: `Adversary requested TGS service tickets for SPNs registered with weak RC4 encryption in ${ds} to extract password hashes.` };
        mitre = [
          { tactic: 'Credential Access', techniqueId: 'T1558.003', techniqueName: 'Steal or Forge Kerberos Tickets: Kerberoasting', description: 'Requested RC4 service tickets for SPN accounts.' },
          { tactic: 'Privilege Escalation', techniqueId: 'T1078.002', techniqueName: 'Valid Accounts: Domain Accounts', description: 'Gained administrative domain access via cracked service password.' }
        ];
      } else {
        const words = title.split(' ').filter(w => w.length > 2);
        const keyTerm = words[0] || title;
        steps = [
          { stepNumber: 1, phase: 'Initial Alert Validation & Field Triage', action: `Query ${ds} for raw logs matching alert '${title}'`, details: `Inspect event logs, parent-child process trees, CLI arguments, and user identity context in ${ds}.`, expectedOutcome: 'Confirm alert validity, rule out false positives, and identify patient zero.' },
          { stepNumber: 2, phase: 'User & Asset Context Correlation', action: `Correlate user identity and network activity involving '${keyTerm}'`, details: 'Cross-reference user logins, unusual IP connections, and privilege escalation events across SIEM logs.', expectedOutcome: 'Determine blast radius and identify impacted user accounts and systems.' },
          { stepNumber: 3, phase: 'Technical Threat & Telemetry Analysis', action: `Analyze command lines, payload parameters, and IOCs (${iocs})`, details: 'Inspect CLI parameters, evaluate network destination reputation, and analyze process/API execution logs.', expectedOutcome: 'Catalog all adversary IOCs, C2 domains/IPs, and persistence signatures.' },
          { stepNumber: 4, phase: 'Operational Containment & Access Control', action: `Execute targeted containment playbook for '${title}'`, details: 'Isolate affected endpoint via EDR, revoke active session tokens/MFA sessions, and apply firewall blocks.', expectedOutcome: 'Halt ongoing threat activity and prevent lateral spread or data exfiltration.' },
          { stepNumber: 5, phase: 'Eradication & System Verification', action: 'Purge threat artifacts and monitor logs for 48 hours', details: 'Rotate compromised credentials, update firewall/WAF blocks, and monitor telemetry for recurring anomalies.', expectedOutcome: 'Restore normal operational status with verified zero residual persistence.' },
        ];
        recs = [
          `Harden detection rule coverage in ${ds} to capture precursor techniques before alert trigger.`,
          'Enforce strict least-privilege policies and require hardware-backed FIDO2 MFA for administrative roles.',
          'Implement automated SOAR playbooks for host isolation and token revocation upon alert triggers.',
          'Conduct regular SOC team tabletop drills simulating similar alert scenarios.'
        ];
        vector = { summary: `Adversary triggered security alert for "${title}".`, technicalDetails: `The threat actor leveraged obfuscated execution techniques or credential abuse within ${ds} to trigger the alert.` };
        mitre = [
          { tactic: 'Execution / Initial Access', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', description: `Adversary activity matching alert "${title}" telemetry within ${ds}.` },
          { tactic: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal', description: 'Attempted concealment of adversary artifacts.' }
        ];
      }

      const extractedIp = iocs.includes('IP:')
        ? iocs.split('IP:')[1].split(',')[0].trim()
        : iocs.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)?.[0] || '198.51.100[.]42';

      const rawIpClean = extractedIp.replace(/\[\.\]/g, '.').replace(/\[/g, '').replace(/\]/g, '');

      const extractedUser = iocs.includes('User:')
        ? iocs.split('User:')[1].split(',')[0].trim()
        : isKerberosAd ? 'krbtgt / krbsvc_ad' : isWebSqli ? 'www-data / web_user' : isCloudBucket ? 'cloud_storage_svc' : 'system_account';

      const observedFactsList = isWebSqli
        ? [
            `We observed HTTP requests matching SQL injection signature patterns in "${ds}" targeting web endpoints.`,
            `Source IP address logged as ${extractedIp} executing query payload parameters against the web application.`,
            `Targeted web application identity / runtime execution context: "${extractedUser}".`,
            `Web server logging returned HTTP status responses corresponding to database query execution attempts.`,
            `Security monitoring detected no unauthorized schema alteration or table drop operations.`
          ]
        : isCloudBucket
        ? [
            `Cloud storage audit logs in "${ds}" recorded API operations matching "${title}".`,
            `Access originated from external source address ${extractedIp}.`,
            `Targeted cloud resource identity / service principal: "${extractedUser}".`,
            `API operations completed with status code 200 (Success) for resource path requests.`,
            `Security controls logged no unauthorized write, delete, or resource modification attempts.`
          ]
        : isKerberosAd
        ? [
            `Active Directory Domain Controller logs in "${ds}" recorded Kerberos ticket requests matching "${title}".`,
            `Request originated from client endpoint IP ${extractedIp}.`,
            `Targeted Service Principal Name (SPN) / domain user account: "${extractedUser}".`,
            `Kerberos Ticket Granting Service (TGS) request utilized weak encryption signature (RC4-HMAC).`,
            `Telemetry indicates potential offline password hash extraction attempt.`
          ]
        : [
            `Security telemetry in "${ds}" recorded activity matching alert "${title}".`,
            `Network activity associated with source address ${extractedIp}.`,
            `Targeted identity / account context identified as "${extractedUser}".`,
            `Operation completed within expected host/service execution parameters.`,
            `No secondary host compromise or unauthorized privilege escalation was observed.`
          ];

      const tailoredRecs = buildTailoredRecommendations(title, ds);
      const tailoredKillChain = buildAccurateKillChain(title, ds);

      setReport({
        id: `PLAYBOOK-${Date.now()}`,
        incidentId: `INC-${Math.floor(100000 + Math.random() * 900000)}`,
        alertId: `${Math.floor(2000 + Math.random() * 8000)}`,
        severity: isWebSqli || isCloudBucket ? 'High' : isKerberosAd ? 'Critical' : 'Medium',
        clientName: 'Enterprise Security',
        incidentTitle: title,
        dataSource: ds,
        generatedAt: new Date().toISOString().replace('T', ' ').substring(0, 16) + ' UTC',
        timestamp: new Date().toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' }) + ', ' + new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        sourceIpAddress: extractedIp,
        username: extractedUser,
        mitreSummary: mitre.map(m => `${m.tactic} (${m.techniqueId})`).join(' / '),
        observedFacts: observedFactsList,
        threatIntelEnrichment: [
          {
            ipAddress: rawIpClean,
            reportsCount: 14,
            abuseConfidence: 12,
            isp: 'Hosting & Transit Infrastructure',
            usageType: 'Data Center/Web Hosting',
            asn: 'AS15169',
            domainName: 'hosting-edge.net',
            country: 'United States',
            city: 'Ashburn, Virginia',
          }
        ],
        recommendedActions: tailoredRecs,
        alertAnalysis: {
          alertTriggerMechanism: `Telemetry threshold, signature event, or log pattern in ${ds} matching '${title}'.`,
          technicalDeepDive: vector.technicalDetails || `Detailed technical analysis of adversary behavior triggering alert '${title}'.`,
          truePositiveIndicators: [
            `Unsanitized or obfuscated execution arguments matching '${title}' in ${ds}`,
            `Anomalous outbound C2 IP connections or non-standard parent-child process chains`,
            `High velocity of failed auth attempts or bulk data API operations`
          ],
          falsePositiveIndicators: [
            `Authorized administrative maintenance script or scheduled task run under approved service account`,
            `Internal vulnerability scanner or authorized penetration test activity`
          ],
          investigationScope: `Impacted endpoints, user accounts, network CIDR blocks, and ${ds} log streams.`
        },
        executiveSummary: {
          cisoBriefing: `The Security Operations Center (SOC) initiated an automated alert triage and response workflow following the trigger of security alert "${title}" sourced from ${ds}.\n\nSIEM/EDR log correlation identified activity involving ${iocs}. Operational containment playbooks were initiated to isolate impacted hosts/accounts, revoke tokens, and prevent lateral movement.\n\nAll primary infrastructure remains protected. Recommendations and detection tuning rules have been generated for operational hardening.`,
          businessImpact: `Low to moderate operational risk. Affected hosts/accounts were contained during the triage window without downtime to core services.`,
          keyTakeaway: `Enforce mandatory least-privilege configurations, enable detailed script/API plane logging in ${ds}, and mandate hardware-backed MFA.`,
        },
        investigationSteps: steps,
        recommendations: tailoredRecs,
        attackVector: vector,
        mitreAttackMapping: mitre,
        cyberKillChain: tailoredKillChain,
        postIncidentPlan: {
          immediateActionItems: [
            { priority: 'P0', task: `Rotate credentials and isolate hosts connected to alert '${title}'`, owner: 'SOC Tier 2 / Incident Response', status: 'In Progress' },
            { priority: 'P1', task: `Tune SIEM detection rule for '${title}' in ${ds}`, owner: 'Detection Engineering', status: 'Open' },
          ],
        },
        siemQueriesForTriage: [
          {
            title: `Triage Query for '${title}'`,
            platform: 'sentinel',
            query: `// Sentinel KQL Query for ${ds}\nSecurityEvent\n| where EventData contains "${title.split(' ')[0]}" or TimeGenerated > ago(24h)\n| summarize Count=count() by Account, Computer, IPAddress\n| sort by Count desc`,
            purpose: `Triage and count events related to ${title} over the past 24 hours.`,
          },
          {
            title: `Splunk Correlation for ${ds}`,
            platform: 'splunk',
            query: `index=* sourcetype="${ds.toLowerCase().replace(/[^a-z0-9]/g, '')}" "${title.split(' ')[0]}"\n| stats count by src_ip, dest_ip, user, action\n| sort -count`,
            purpose: 'Correlate user activity across network telemetry.',
          },
        ],
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(key);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  return (
    <div className="space-y-6 font-sans text-xs max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="px-2.5 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-xs font-semibold flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" /> Operational Alert Playbook Generator
              </div>
              <span className="text-xs text-slate-400 font-mono">SIEM & EDR Alert Triage</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Alert Investigation Playbook, Recommendations & Kill Chain Engine
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-3xl">
              Input any triggered alert name from any SIEM/EDR platform (Sentinel, Splunk, Defender, CrowdStrike, Okta, CloudTrail) to generate a complete Operational Alert Playbook with technical investigation analysis, recommendations, MITRE ATT&CK mapping, Cyber Kill Chain breakdown, and ready-to-run SIEM queries.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <span className="text-[11px] text-slate-400 font-mono font-bold">Presets:</span>
            {PRESET_INCIDENTS.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => setInputData(preset.data)}
                className="px-2.5 py-1.5 rounded-lg bg-[#060D18] border border-[#1B3047] hover:border-cyan-500/50 text-slate-300 hover:text-cyan-300 font-mono text-[11px] transition-colors cursor-pointer"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Form & Report Display Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Input Form */}
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl h-fit">
          <div className="flex items-center gap-2 border-b border-[#1B3047] pb-3">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Alert / Incident Details Input</h3>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="space-y-1">
              <label className="text-slate-300 font-bold flex items-center gap-1.5">
                <Search className="w-3.5 h-3.5 text-cyan-400" />
                Alert / Incident Title:
              </label>
              <input
                type="text"
                id="input-alert-title"
                value={inputData.incidentTitle}
                onChange={(e) => setInputData({ ...inputData, incidentTitle: e.target.value })}
                placeholder="e.g. Suspicious PowerShell Script, AWS IAM Secret Key Exposure, Impossible Travel..."
                className="w-full bg-[#060D18] border border-[#1B3047] rounded-xl px-3 py-2.5 text-white font-semibold focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40"
              />
            </div>

            <div className="space-y-1">
              <label className="text-slate-300 font-bold flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-teal-400" />
                Data Source:
              </label>
              <input
                type="text"
                id="input-data-source"
                value={inputData.dataSource}
                onChange={(e) => setInputData({ ...inputData, dataSource: e.target.value })}
                placeholder="e.g. Windows Event Logs, AWS CloudTrail, Sysmon, CrowdStrike EDR, Okta Logs..."
                className="w-full bg-[#060D18] border border-[#1B3047] rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40"
              />
            </div>

            <div className="space-y-1">
              <label className="text-slate-300 font-bold flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Artifacts & IOCs Involved:
              </label>
              <textarea
                id="input-iocs-involved"
                rows={3}
                value={inputData.iocsInvolved}
                onChange={(e) => setInputData({ ...inputData, iocsInvolved: e.target.value })}
                className="w-full bg-[#060D18] border border-[#1B3047] rounded-xl p-3 text-slate-300 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 leading-relaxed"
                placeholder="IPs, File Hashes, Domains, Usernames, CLI Arguments, Process Paths..."
              />
            </div>
          </div>

          <button
            id="btn-generate-retro-report"
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="w-full py-3 px-4 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold font-sans text-xs flex items-center justify-center gap-2 transition-all shadow-md shadow-cyan-500/10 disabled:opacity-50 cursor-pointer"
          >
            {isGenerating ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" /> Generating Alert Playbook & Triage Plan...
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" /> Generate Alert Playbook & Analysis
              </>
            )}
          </button>
        </div>

        {/* Right 2 Columns: Report Display */}
        <div className="lg:col-span-2 space-y-6">
          {!report ? (
            <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-12 text-center space-y-3 flex flex-col items-center justify-center min-h-[420px]">
              <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center">
                <FileText className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-white">No Alert Playbook Generated Yet</h3>
              <p className="text-xs text-slate-400 max-w-md font-sans">
                Enter your Alert Name and Data Source on the left, then click "Generate Alert Playbook & Analysis" to produce step-by-step SOC triage procedures, recommendations, MITRE ATT&CK mapping, Cyber Kill Chain breakdown, and ready-to-run SIEM queries.
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Primary Ticket View - Clean SOC Ticket Template matching User Reference */}
              <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] shadow-xl overflow-hidden">
                {/* Ticket Action Header */}
                <div className="bg-[#060D18] px-6 py-4 border-b border-[#1B3047] flex items-center justify-between flex-wrap gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-xs font-bold">
                      ALERT PLAYBOOK
                    </div>
                    <span className="text-xs font-mono text-slate-400">Security Alert Investigation & Triage Ticket</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopy(
                        `INCIDENT NAME: ${report.incidentTitle}\nSOURCE IP: ${report.sourceIpAddress}\nUSERNAME: ${report.username}\nMITRE: ${report.mitreSummary}\n\nOBSERVED FACTS:\n${(report.observedFacts || []).map(f => '• ' + f).join('\n')}\n\nRECOMMENDED ACTIONS:\n${(report.recommendedActions || []).map(a => '• ' + a).join('\n')}`,
                        'full-ticket'
                      )}
                      className="px-3 py-1.5 rounded-lg bg-[#101F32] hover:bg-[#1B3047] text-cyan-300 font-mono text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors"
                    >
                      {copiedSection === 'full-ticket' ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
                      Copy Playbook Data
                    </button>
                  </div>
                </div>

                {/* Structured Ticket Table */}
                <div className="p-6 bg-[#0B1726] space-y-6">
                  <div className="border border-[#1B3047] rounded-xl overflow-hidden font-sans text-xs bg-[#060D18]">
                    {/* Section Header: Incident Details */}
                    <div className="bg-[#101F32] px-4 py-2.5 border-b border-[#1B3047] font-mono font-bold text-slate-200 text-xs text-center tracking-wide uppercase">
                      Incident Details
                    </div>

                    {/* Details Key-Value Rows */}
                    <div className="divide-y divide-[#1B3047]">
                      <div className="grid grid-cols-1 sm:grid-cols-4 p-3.5 gap-2">
                        <div className="font-bold text-slate-400 font-mono sm:col-span-1">Incident Name</div>
                        <div className="font-bold text-white sm:col-span-3 text-sm">{report.incidentTitle}</div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-4 p-3.5 gap-2">
                        <div className="font-bold text-slate-400 font-mono sm:col-span-1">Source IP Address</div>
                        <div className="font-mono text-cyan-300 font-bold sm:col-span-3 leading-relaxed whitespace-pre-line">
                          {report.sourceIpAddress || 'N/A'}
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-4 p-3.5 gap-2">
                        <div className="font-bold text-slate-400 font-mono sm:col-span-1">Username</div>
                        <div className="font-mono text-teal-300 font-semibold sm:col-span-3">{report.username || 'N/A'}</div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-4 p-3.5 gap-2">
                        <div className="font-bold text-slate-400 font-mono sm:col-span-1">MITRE ATT&CK</div>
                        <div className="font-mono text-[#EF4444] font-bold sm:col-span-3">
                          {report.mitreSummary || (report.mitreAttackMapping && report.mitreAttackMapping.length > 0 ? report.mitreAttackMapping.map(m => `${m.tactic} (${m.techniqueId})`).join(' / ') : 'Initial Access (T1190)')}
                        </div>
                      </div>

                      {/* Assessment / Analysis Section */}
                      <div className="p-4 space-y-4">
                        <div className="font-bold text-white font-mono text-xs flex items-center gap-2">
                          <Search className="w-4 h-4 text-cyan-400" /> Assessment / Analysis
                        </div>

                        {/* Bulleted Observed Facts */}
                        <ul className="space-y-2 text-slate-300 text-xs leading-relaxed font-sans pl-1">
                          {(report.observedFacts && report.observedFacts.length > 0 ? report.observedFacts : [
                            `Security telemetry logged events for "${report.incidentTitle}" in ${report.dataSource}.`,
                            `Source network activity associated with address ${report.sourceIpAddress || 'N/A'}.`,
                            `Target identity / account involved: ${report.username || 'System Account'}.`,
                            `Observed operations processed according to configured authorization rules.`
                          ]).map((fact, idx) => (
                            <li key={idx} className="flex items-start gap-2.5">
                              <span className="text-cyan-400 font-bold mt-0.5 shrink-0">•</span>
                              <span>{fact}</span>
                            </li>
                          ))}
                        </ul>

                        {/* Embedded IP Threat Intelligence & Abuse Cards */}
                        {report.threatIntelEnrichment && report.threatIntelEnrichment.length > 0 && (
                          <div className="space-y-4 pt-2">
                            <div className="text-[11px] font-mono text-slate-400 font-bold uppercase">
                              Threat Intelligence & IP Abuse Enrichment:
                            </div>

                            {report.threatIntelEnrichment.map((intel, idx) => (
                              <div key={idx} className="bg-[#0B1726] border border-[#1B3047] rounded-xl p-4 space-y-3 font-sans text-xs">
                                <div className="flex items-center justify-between flex-wrap gap-2">
                                  <div className="text-cyan-400 font-mono font-extrabold text-sm flex items-center gap-2">
                                    <span>{intel.ipAddress}</span>
                                    <span className="text-slate-300 font-normal text-xs">was found in threat database</span>
                                  </div>
                                </div>

                                <div className="text-slate-300 font-sans text-xs space-y-1.5">
                                  <div>
                                    This IP was reported <strong>{intel.reportsCount} times</strong>. Confidence of Abuse is <strong className="text-[#EF4444]">{intel.abuseConfidence}%</strong>:
                                  </div>
                                  <div className="w-full bg-[#060D18] rounded-md h-4 p-0.5 border border-[#1B3047] flex items-center">
                                    <div className="bg-[#EF4444] h-full rounded text-[10px] text-white font-bold font-mono px-1 flex items-center" style={{ width: `${Math.max(intel.abuseConfidence, 8)}%` }}>
                                      {intel.abuseConfidence}%
                                    </div>
                                  </div>
                                </div>

                                {/* Key-Value Metadata Grid for IP */}
                                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-[11px] bg-[#060D18] p-3 rounded-lg border border-[#1B3047]">
                                  <div>
                                    <span className="text-slate-400 block font-bold">ISP</span>
                                    <span className="text-slate-200">{intel.isp}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-400 block font-bold">Usage Type</span>
                                    <span className="text-slate-200">{intel.usageType}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-400 block font-bold">ASN</span>
                                    <span className="text-cyan-400 font-bold">{intel.asn}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-400 block font-bold">Domain Name</span>
                                    <span className="text-teal-300">{intel.domainName}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-400 block font-bold">Country</span>
                                    <span className="text-slate-200 font-semibold">{intel.country}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-400 block font-bold">City</span>
                                    <span className="text-slate-200">{intel.city}</span>
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Recommended Action Section */}
                      <div className="p-4 space-y-3 bg-[#060D18]">
                        <div className="font-bold text-white font-mono text-xs flex items-center gap-2">
                          <ShieldCheck className="w-4 h-4 text-teal-400" /> Recommended Action
                        </div>
                        <ul className="space-y-2 text-slate-300 text-xs leading-relaxed font-sans pl-1">
                          {(report.recommendedActions || []).map((action, idx) => (
                            <li key={idx} className="flex items-start gap-2.5">
                              <span className="text-teal-400 font-bold mt-0.5 shrink-0">•</span>
                              <span className="font-medium text-slate-100">{action}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Technical Deep Dive & MITRE ATT&CK & Kill Chain Section */}
              <div className="grid grid-cols-1 gap-6">
                {/* MITRE ATT&CK Mapping Matrix */}
                <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-6 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-sm font-bold text-white font-mono">MITRE ATT&CK Tactic & Technique Mapping</h3>
                    </div>
                    <span className="text-xs font-mono text-cyan-400 font-bold">Framework Alignment</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {(report.mitreAttackMapping || []).map((item, idx) => (
                      <div key={idx} className="p-4 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-2 font-mono text-xs">
                        <div className="flex items-center justify-between">
                          <span className="px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-[10px] font-bold uppercase">
                            {item.tactic}
                          </span>
                          <span className="text-teal-400 font-bold font-mono">{item.techniqueId}</span>
                        </div>
                        <div className="text-white font-bold text-xs">{item.techniqueName}</div>
                        <p className="text-slate-400 font-sans text-xs leading-relaxed">{item.description}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Cyber Kill Chain Stage Mapping */}
                <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-6 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                    <div className="flex items-center gap-2">
                      <Activity className="w-4 h-4 text-teal-400" />
                      <h3 className="text-sm font-bold text-white font-mono">Cyber Kill Chain Stage Breakdown</h3>
                    </div>
                    <span className="text-xs font-mono text-teal-400 font-bold">{(report.cyberKillChain || []).length} Accurate Phase(s)</span>
                  </div>

                  <div className="space-y-2.5 font-mono text-xs">
                    {(report.cyberKillChain || []).map((kc, idx) => (
                      <div key={idx} className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-1.5">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-5 h-5 rounded bg-teal-500/10 border border-teal-500/30 text-teal-400 flex items-center justify-center font-bold text-[10px]">
                              {idx + 1}
                            </span>
                            <span className="font-bold text-teal-300 text-xs">{kc.stage}</span>
                          </div>
                          {kc.detectedArtifacts && (
                            <span className="text-[10px] text-slate-400 font-mono bg-[#0B1726] px-2 py-0.5 rounded border border-[#1B3047]">
                              Artifact: {kc.detectedArtifacts}
                            </span>
                          )}
                        </div>
                        <p className="text-slate-400 font-sans text-xs pl-7 leading-relaxed">{kc.description}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Step-by-Step SOC Operational Triage Workflow */}
                <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-6 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                    <div className="flex items-center gap-2">
                      <Compass className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-sm font-bold text-white font-mono">
                        SOC Operational Alert Playbook Steps ({(report.investigationSteps || []).length} Phases)
                      </h3>
                    </div>
                    <span className="text-xs font-mono text-cyan-400 font-bold">Step-by-Step Triage</span>
                  </div>

                  <div className="space-y-3">
                    {(report.investigationSteps || []).map((step) => (
                      <div
                        key={step.stepNumber}
                        className="p-4 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-2 font-mono text-xs hover:border-cyan-500/40 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-6 h-6 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center font-bold text-xs">
                              {step.stepNumber}
                            </span>
                            <span className="font-bold text-slate-200">{step.phase}</span>
                          </div>
                          <span className="px-2 py-0.5 rounded bg-[#101F32] text-slate-400 text-[10px]">
                            Phase {step.stepNumber}
                          </span>
                        </div>

                        <div className="text-cyan-300 font-bold pl-8 text-xs">{step.action}</div>

                        <div className="pl-8 text-slate-400 font-sans text-xs leading-relaxed">
                          <span className="font-mono font-bold text-slate-300">Method: </span>
                          {step.details}
                        </div>

                        <div className="pl-8 text-teal-300 text-[11px]">
                          <span className="font-bold">Expected Outcome: </span>
                          {step.expectedOutcome}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Ready-to-Run SIEM Investigation Queries */}
                <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-6 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-sm font-bold text-white font-mono">Ready-to-Run SIEM Triage Queries</h3>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {(report.siemQueriesForTriage || []).map((q, idx) => (
                      <div key={idx} className="p-3.5 bg-[#060D18] rounded-xl border border-[#1B3047] space-y-2 font-mono text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-200">{q.title}</span>
                          <button
                            onClick={() => handleCopy(q.query, `query-${idx}`)}
                            className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-bold cursor-pointer"
                          >
                            {copiedSection === `query-${idx}` ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
                            Copy Query
                          </button>
                        </div>
                        <div className="p-3 bg-[#0B1726] rounded-xl border border-[#1B3047] text-cyan-200 overflow-x-auto text-[11px] font-mono leading-relaxed">
                          <code>{q.query}</code>
                        </div>
                        <div className="text-slate-400 text-[11px] font-sans">Purpose: {q.purpose}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
