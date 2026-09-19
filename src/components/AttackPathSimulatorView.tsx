import React, { useState } from 'react';
import {
  GitBranch,
  ShieldAlert,
  Server,
  UserCheck,
  Database,
  Cloud,
  Terminal,
  Play,
  Zap,
  Activity,
  AlertTriangle,
  Lock,
  Copy,
  Check,
  ChevronRight,
  RefreshCw,
  Sliders,
  Share2,
  FileText,
  Key,
  Shield,
  ShieldCheck,
  Layers,
} from 'lucide-react';
import { AttackScenario, AttackGraphNode, AttackGraphEdge, SiemPlatformId } from '../types';

const PRESET_SCENARIOS: AttackScenario[] = [
  {
    id: 'lsass_to_cloud',
    title: 'LSASS Credential Dump → Domain Admin → Azure AD Global Admin',
    description: 'Spearphishing on HR workstation leads to local admin token extraction, lateral movement via WinRM to Domain Controller, and compromise of Azure AD Sync account credentials.',
    threatActor: 'APT29 (Cozy Bear)',
    initialAccess: 'HR-Workstation-01 (10.0.4.12)',
    targetAsset: 'Azure-EntraID-GlobalAdmin (Cloud Tenant)',
    nodes: [
      { id: 'n1', name: 'HR-Workstation-01', type: 'workstation', criticalAsset: false, status: 'compromised', riskScore: 95, osOrType: 'Windows 11 Enterprise', ipAddress: '10.0.4.12', departmentOrRegion: 'HR / East US' },
      { id: 'n2', name: 'Finance-Server-02', type: 'server', criticalAsset: false, status: 'compromised', riskScore: 88, osOrType: 'Windows Server 2022', ipAddress: '10.0.2.45', departmentOrRegion: 'Finance Subnet' },
      { id: 'n3', name: 'Domain Controller (DC-01)', type: 'domain_admin', criticalAsset: true, status: 'compromised', riskScore: 100, osOrType: 'Active Directory Domain Controller', ipAddress: '10.0.0.4', departmentOrRegion: 'Core Infrastructure' },
      { id: 'n4', name: 'Azure AD Connect Agent', type: 'cloud_iam', criticalAsset: true, status: 'compromised', riskScore: 92, osOrType: 'Hybrid Cloud Sync Service', ipAddress: '10.0.0.88', departmentOrRegion: 'Cloud Bridge' },
      { id: 'n5', name: 'Prod Database Server', type: 'database', criticalAsset: true, status: 'at_risk', riskScore: 75, osOrType: 'MS SQL Enterprise Server', ipAddress: '10.0.10.15', departmentOrRegion: 'Database Cluster' },
      { id: 'n6', name: 'Azure Cloud Production Tenant', type: 'cloud_iam', criticalAsset: true, status: 'at_risk', riskScore: 80, osOrType: 'Azure Resource Manager', ipAddress: 'portal.azure.com', departmentOrRegion: 'Cloud Production' },
      { id: 'n7', name: 'Engineering Workstation 09', type: 'workstation', criticalAsset: false, status: 'safe', riskScore: 10, osOrType: 'Windows 11 Enterprise', ipAddress: '10.0.4.89', departmentOrRegion: 'Dev Subnet' },
    ],
    edges: [
      {
        id: 'e1',
        source: 'n1',
        target: 'n2',
        techniqueId: 'T1003.001',
        techniqueName: 'OS Credential Dumping: LSASS',
        protocolOrVector: 'WinRM / PowerShell Remoting (Port 5985)',
        severity: 'Critical',
        timestamp: '14:22:04 UTC',
        siemQuery: 'SecurityEvent | where EventID == 4688 and ProcessNameHasAny ("mimikatz.exe", "procdump.exe") or (CommandLine contains "lsass")',
      },
      {
        id: 'e2',
        source: 'n2',
        target: 'n3',
        techniqueId: 'T1558.003',
        techniqueName: 'Kerberoasting & DCSync',
        protocolOrVector: 'Kerberos TGS Request / LDAP Sync',
        severity: 'Critical',
        timestamp: '14:35:12 UTC',
        siemQuery: 'SecurityEvent | where EventID == 4769 and TicketEncryptionType == "0x17" and ServiceName !contains "$"',
      },
      {
        id: 'e3',
        source: 'n3',
        target: 'n4',
        techniqueId: 'T1078.002',
        techniqueName: 'Valid Accounts: Domain Accounts',
        protocolOrVector: 'RPC / WMI (Port 135/445)',
        severity: 'High',
        timestamp: '14:48:30 UTC',
        siemQuery: 'DeviceProcessEvents | where ProcessCommandLine contains "AdSync" or AccountName contains "MSOL_"',
      },
      {
        id: 'e4',
        source: 'n4',
        target: 'n6',
        techniqueId: 'T1098.001',
        techniqueName: 'Account Manipulation: Cloud Credentials',
        protocolOrVector: 'HTTPS REST API / OAuth Token',
        severity: 'Critical',
        timestamp: '15:02:11 UTC',
        siemQuery: 'SigninLogs | where UserPrincipalName contains "sync" or AppDisplayName == "Azure Active Directory Connect"',
      },
      {
        id: 'e5',
        source: 'n3',
        target: 'n5',
        techniqueId: 'T1021.002',
        techniqueName: 'SMB/Windows Admin Shares',
        protocolOrVector: 'TDS / MSSQL Port 1433',
        severity: 'High',
        timestamp: '15:15:00 UTC',
        siemQuery: 'SecurityEvent | where EventID == 4624 and LogonType == 3 and TargetServerName contains "SQL"',
      },
    ],
    report: {
      totalNodes: 7,
      compromisedNodes: 4,
      atRiskNodes: 2,
      blastRadiusPercentage: 85.7,
      criticalAssetsAtRisk: 4,
      initialAccessNode: 'HR-Workstation-01',
      targetAssetNode: 'Azure Cloud Production Tenant',
      pathHopCount: 4,
      containmentSteps: [
        {
          stepNumber: 1,
          title: 'Isolate Host HR-Workstation-01',
          action: 'Issue EDR Network Containment command to disconnect host 10.0.4.12 from internal VLANs.',
          platformCommand: 'Invoke-MdeHostContainment -DeviceId "HR-Workstation-01" -ContainmentType Full',
          impact: 'Stops outbound credential harvesting and C2 callbacks.',
        },
        {
          stepNumber: 2,
          title: 'Reset Azure AD Sync Account & KRBTGT Passwords',
          action: 'Perform double KRBTGT password reset in Active Directory and rotate MSOL_ service account keys.',
          platformCommand: 'Reset-KrbTgtPassword -Force -Verbose; Revoke-AzureADUserAllRefreshToken -ObjectId "msol-service-id"',
          impact: 'Invalidates forged Golden Tickets and compromised Azure AD sync tokens.',
        },
        {
          stepNumber: 3,
          title: 'Block WinRM / SMB Inbound to DC-01',
          action: 'Apply emergency firewall rule blocking WinRM (5985/5986) and SMB (445) from workstation subnets.',
          platformCommand: 'New-NetFirewallRule -Name "SOC-Emergency-Block-WinRM" -Direction Inbound -Action Block -Protocol TCP -LocalPort 5985,5986,445 -RemoteAddress 10.0.4.0/24',
          impact: 'Prevents further lateral movement across workstation subnets.',
        },
      ],
    },
  },
  {
    id: 'ransomware_smb',
    title: 'Ransomware Propagation via SMB Exec & Shadow Copy Destruction',
    description: 'Malicious macro on Exec-Laptop executes PsExec across internal subnets, enumerating network shares, purging Volume Shadow Copies, and staging exfiltration.',
    threatActor: 'LockBit 3.0 / BlackCat',
    initialAccess: 'Exec-Laptop-04 (10.0.8.99)',
    targetAsset: 'Backup-SAN-Storage & Corp File Shares',
    nodes: [
      { id: 'n1', name: 'Exec-Laptop-04', type: 'workstation', criticalAsset: false, status: 'compromised', riskScore: 98, osOrType: 'Windows 11 Pro', ipAddress: '10.0.8.99', departmentOrRegion: 'Executive' },
      { id: 'n2', name: 'File-Server-01', type: 'server', criticalAsset: true, status: 'compromised', riskScore: 92, osOrType: 'Windows Server 2019', ipAddress: '10.0.1.10', departmentOrRegion: 'Corporate Storage' },
      { id: 'n3', name: 'Backup SAN Array', type: 'database', criticalAsset: true, status: 'at_risk', riskScore: 85, osOrType: 'iSCSI Storage Appliance', ipAddress: '10.0.99.5', departmentOrRegion: 'Backup Datacenter' },
      { id: 'n4', name: 'Dev-Build-Server', type: 'server', criticalAsset: false, status: 'compromised', riskScore: 80, osOrType: 'Ubuntu Linux 22.04', ipAddress: '10.0.3.18', departmentOrRegion: 'Engineering' },
      { id: 'n5', name: 'Domain Controller (DC-02)', type: 'domain_admin', criticalAsset: true, status: 'at_risk', riskScore: 70, osOrType: 'Windows Server 2022 AD', ipAddress: '10.0.0.5', departmentOrRegion: 'Core Infra' },
    ],
    edges: [
      {
        id: 'e1',
        source: 'n1',
        target: 'n2',
        techniqueId: 'T1021.002',
        techniqueName: 'Remote Services: SMB/Windows Admin Shares',
        protocolOrVector: 'PsExec / C$ Admin Share',
        severity: 'Critical',
        timestamp: '02:10:00 UTC',
        siemQuery: 'DeviceProcessEvents | where ProcessCommandLine contains "psexec" or ProcessCommandLine contains "vssadmin delete shadows"',
      },
      {
        id: 'e2',
        source: 'n2',
        target: 'n3',
        techniqueId: 'T1490',
        techniqueName: 'Inhibit System Recovery & Data Destruction',
        protocolOrVector: 'iSCSI Target Command / Shadow Copy Purge',
        severity: 'Critical',
        timestamp: '02:18:45 UTC',
        siemQuery: 'SecurityEvent | where EventID == 4688 and CommandLine contains "wbadmin" or CommandLine contains "bcdedit /set"',
      },
      {
        id: 'e3',
        source: 'n1',
        target: 'n4',
        techniqueId: 'T1021.004',
        techniqueName: 'Remote Services: SSH',
        protocolOrVector: 'SSH Port 22 (Stolen Key)',
        severity: 'High',
        timestamp: '02:22:10 UTC',
        siemQuery: 'Syslog | where ProcessName == "sshd" and SyslogMessage contains "Accepted publickey"',
      },
    ],
    report: {
      totalNodes: 5,
      compromisedNodes: 3,
      atRiskNodes: 2,
      blastRadiusPercentage: 100.0,
      criticalAssetsAtRisk: 3,
      initialAccessNode: 'Exec-Laptop-04',
      targetAssetNode: 'Backup SAN Array',
      pathHopCount: 3,
      containmentSteps: [
        {
          stepNumber: 1,
          title: 'Trigger Emergency Immutable Backup Isolation',
          action: 'Immediately severed SAN network interface and enable write-once-read-many (WORM) vault locks.',
          platformCommand: 'Disable-NetAdapter -Name "SAN-iSCSI-Interface" -Confirm:$false',
          impact: 'Protects offline backups from ransomware encryption or shadow copy deletion.',
        },
        {
          stepNumber: 2,
          title: 'Block Admin Shares (C$, ADMIN$) Globally',
          action: 'Push GPO registry change disabling default administrative share creation.',
          platformCommand: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "AutoShareWks" -Value 0',
          impact: 'Blocks automated PsExec lateral spread across workstations.',
        },
      ],
    },
  },
  {
    id: 'waf_sqli_db',
    title: 'Public WAF Bypass → SQL Injection → DB Exfiltration & AWS IAM Role Impersonation',
    description: 'Threat actor exploits unpatched HTTP endpoint on public web app, injects UNION-based SQLi, dumps customer database hashes, and queries EC2 Metadata endpoint (IMDSv1) to steal AWS IAM role keys.',
    threatActor: 'Lapsus$ / FIN7',
    initialAccess: 'Public Web App (WAF Front Door)',
    targetAsset: 'AWS S3 Customer Vault & RDS Cluster',
    nodes: [
      { id: 'n1', name: 'Public Web Frontend (WAF)', type: 'firewall', criticalAsset: false, status: 'compromised', riskScore: 85, osOrType: 'NGINX + AWS WAF', ipAddress: '52.14.88.102', departmentOrRegion: 'DMZ Environment' },
      { id: 'n2', name: 'Backend App Container', type: 'server', criticalAsset: false, status: 'compromised', riskScore: 90, osOrType: 'Docker Container / Node.js', ipAddress: '172.18.0.12', departmentOrRegion: 'ECS Cluster' },
      { id: 'n3', name: 'AWS IMDSv1 Metadata API', type: 'cloud_iam', criticalAsset: true, status: 'compromised', riskScore: 98, osOrType: 'EC2 Metadata Service', ipAddress: '169.254.169.254', departmentOrRegion: 'AWS Infra' },
      { id: 'n4', name: 'Prod Aurora PostgreSQL DB', type: 'database', criticalAsset: true, status: 'compromised', riskScore: 95, osOrType: 'AWS Aurora DB', ipAddress: 'db-prod.internal', departmentOrRegion: 'Database Subnet' },
      { id: 'n5', name: 'AWS S3 Data Lake (Customer PII)', type: 'cloud_iam', criticalAsset: true, status: 'at_risk', riskScore: 88, osOrType: 'AWS S3 Bucket', ipAddress: 's3://corp-pii-vault', departmentOrRegion: 'Cloud Storage' },
    ],
    edges: [
      {
        id: 'e1',
        source: 'n1',
        target: 'n2',
        techniqueId: 'T1190',
        techniqueName: 'Exploit Public-Facing Application',
        protocolOrVector: 'HTTP POST / SQL Injection (WAF Evasion)',
        severity: 'Critical',
        timestamp: '19:04:12 UTC',
        siemQuery: 'CommonSecurityLog | where DeviceVendor == "AWS" and RequestURL contains "UNION" or RequestURL contains "SELECT"',
      },
      {
        id: 'e2',
        source: 'n2',
        target: 'n3',
        techniqueId: 'T1552.005',
        techniqueName: 'Unsecured Credentials: Cloud Instance Metadata',
        protocolOrVector: 'HTTP GET /latest/meta-data/iam/security-credentials/',
        severity: 'Critical',
        timestamp: '19:11:30 UTC',
        siemQuery: 'AWSCloudTrail | where EventName == "AssumeRole" or UserAgent contains "curl" or UserAgent contains "python"',
      },
      {
        id: 'e3',
        source: 'n2',
        target: 'n4',
        techniqueId: 'T1005',
        techniqueName: 'Data from Local System / Database',
        protocolOrVector: 'PostgreSQL Protocol Port 5432',
        severity: 'High',
        timestamp: '19:15:02 UTC',
        siemQuery: 'AzureDiagnostics | where Category == "PostgreSQLEventLogs" and Message contains "pg_dump" or Message contains "COPY"',
      },
      {
        id: 'e4',
        source: 'n3',
        target: 'n5',
        techniqueId: 'T1530',
        techniqueName: 'Data from Cloud Storage Object',
        protocolOrVector: 'AWS S3 API GetObject / Sync',
        severity: 'Critical',
        timestamp: '19:22:45 UTC',
        siemQuery: 'AWSCloudTrail | where EventName in ("GetObject", "ListObjects") and EventSource == "s3.amazonaws.com"',
      },
    ],
    report: {
      totalNodes: 5,
      compromisedNodes: 4,
      atRiskNodes: 1,
      blastRadiusPercentage: 100.0,
      criticalAssetsAtRisk: 3,
      initialAccessNode: 'Public Web Frontend (WAF)',
      targetAssetNode: 'AWS S3 Data Lake (Customer PII)',
      pathHopCount: 4,
      containmentSteps: [
        {
          stepNumber: 1,
          title: 'Enforce IMDSv2 (Session Token Required)',
          action: 'Enforce IMDSv2 across all EC2/ECS instances to block SSRF and unauthorized metadata reads.',
          platformCommand: 'aws ec2 modify-instance-metadata-options --instance-id i-0123456789 --http-tokens required --http-endpoint enabled',
          impact: 'Completely neutralizes IMDS credential extraction via SSRF/SQLi.',
        },
        {
          stepNumber: 2,
          title: 'Revoke AWS IAM Temporary Credentials',
          action: 'Attach inline deny policy to the compromised ECS Task Execution Role.',
          platformCommand: 'aws iam put-role-policy --role-name ECSTaskRole --policy-name DenyAllEmergency --policy-document file://deny-policy.json',
          impact: 'Immediately invalidates attacker stolen AWS access keys.',
        },
      ],
    },
  },
];

export const AttackPathSimulatorView: React.FC<{
  onSendToGenerator?: (promptText: string) => void;
}> = ({ onSendToGenerator }) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('lsass_to_cloud');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>('n3');
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>('e1');
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [targetSiem, setTargetSiem] = useState<SiemPlatformId>('sentinel');

  const scenario = PRESET_SCENARIOS.find((s) => s.id === selectedScenarioId) || PRESET_SCENARIOS[0];
  const selectedNode = scenario.nodes.find((n) => n.id === selectedNodeId) || scenario.nodes[0];
  const selectedEdge = scenario.edges.find((e) => e.id === selectedEdgeId) || scenario.edges[0];

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const getNodeIcon = (type: AttackGraphNode['type']) => {
    switch (type) {
      case 'workstation':
        return <Terminal className="w-4 h-4 text-cyan-400" />;
      case 'server':
        return <Server className="w-4 h-4 text-cyan-300" />;
      case 'domain_admin':
        return <ShieldAlert className="w-4 h-4 text-[#EF4444] animate-pulse" />;
      case 'cloud_iam':
        return <Cloud className="w-4 h-4 text-teal-400" />;
      case 'database':
        return <Database className="w-4 h-4 text-[#F59E0B]" />;
      case 'user':
        return <UserCheck className="w-4 h-4 text-cyan-400" />;
      case 'firewall':
        return <Lock className="w-4 h-4 text-[#F59E0B]" />;
      default:
        return <Layers className="w-4 h-4 text-slate-400" />;
    }
  };

  const getNodeBorder = (status: AttackGraphNode['status']) => {
    switch (status) {
      case 'compromised':
        return 'border-[#EF4444]/60 bg-[#EF4444]/10 text-white shadow-sm';
      case 'at_risk':
        return 'border-[#F59E0B]/60 bg-[#F59E0B]/10 text-white shadow-sm';
      case 'safe':
        return 'border-[#1B3047] bg-[#060D18] text-slate-300';
    }
  };

  return (
    <div className="space-y-6 font-sans max-w-7xl mx-auto pb-12 text-xs">
      {/* Header Banner */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="px-2.5 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-xs font-semibold flex items-center gap-1.5">
                <GitBranch className="w-3.5 h-3.5" /> SOC Attack Path Simulator
              </div>
              <span className="text-xs text-slate-400 font-mono">Graph Topology & Blast Radius Modeling</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Interactive Attack Path & Blast Radius Simulator
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-3xl">
              Visualize multi-hop lateral movement vectors across Endpoints, Active Directory, Cloud IAM, and Databases. Calculate impact blast radius and execute 1-click containment playbooks.
            </p>
          </div>

          {/* Scenario Selector */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 shrink-0">
            <label className="text-xs font-mono text-slate-400">Threat Scenario:</label>
            <select
              id="scenario-select"
              value={selectedScenarioId}
              onChange={(e) => {
                setSelectedScenarioId(e.target.value);
                const s = PRESET_SCENARIOS.find((sc) => sc.id === e.target.value);
                if (s) {
                  setSelectedNodeId(s.nodes[0]?.id || null);
                  setSelectedEdgeId(s.edges[0]?.id || null);
                }
              }}
              className="bg-[#060D18] text-slate-200 border border-[#1B3047] rounded-xl px-3 py-2 text-xs font-mono focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 cursor-pointer hover:border-slate-600 transition-colors"
            >
              {PRESET_SCENARIOS.map((sc) => (
                <option key={sc.id} value={sc.id}>
                  {sc.title}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Scenario Overview Card */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#0B1726] p-4 rounded-xl border border-[#1B3047] flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/30 text-[#EF4444]">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">Threat Actor</div>
            <div className="text-sm font-bold text-white">{scenario.threatActor}</div>
          </div>
        </div>

        <div className="bg-[#0B1726] p-4 rounded-xl border border-[#1B3047] flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">Initial Entry Point</div>
            <div className="text-xs font-bold text-cyan-300 font-mono truncate max-w-[180px]">{scenario.initialAccess}</div>
          </div>
        </div>

        <div className="bg-[#0B1726] p-4 rounded-xl border border-[#1B3047] flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#F59E0B]/10 border border-[#F59E0B]/30 text-[#F59E0B]">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">Target Objective</div>
            <div className="text-xs font-bold text-[#F59E0B] font-mono truncate max-w-[180px]">{scenario.targetAsset}</div>
          </div>
        </div>

        <div className="bg-[#0B1726] p-4 rounded-xl border border-[#EF4444]/30 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#EF4444]/15 border border-[#EF4444]/30 text-[#EF4444]">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">Impact Blast Radius</div>
            <div className="text-lg font-black text-[#EF4444] font-mono">{scenario.report.blastRadiusPercentage}%</div>
          </div>
        </div>
      </div>

      {/* Main Graph & Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Attack Topology Graph Canvas */}
        <div className="lg:col-span-2 bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
            <div className="flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">Attack Graph Topology</h3>
              <span className="text-[11px] text-slate-400 font-mono">({scenario.nodes.length} Nodes, {scenario.edges.length} Lateral Hops)</span>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1 text-[#EF4444]"><span className="w-2 h-2 rounded-full bg-[#EF4444] animate-ping" /> Compromised</span>
              <span className="flex items-center gap-1 text-[#F59E0B]"><span className="w-2 h-2 rounded-full bg-[#F59E0B]" /> At Risk</span>
              <span className="flex items-center gap-1 text-slate-400"><span className="w-2 h-2 rounded-full bg-slate-600" /> Safe</span>
            </div>
          </div>

          {/* Graph Nodes Grid Display */}
          <div className="py-6 px-3 space-y-8 bg-[#060D18] rounded-xl border border-[#1B3047] relative">
            <div className="text-xs text-slate-500 font-mono text-center mb-2">
              ← Direction of Attack Propagation & Lateral Escalation →
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
              {scenario.nodes.map((node) => {
                const isSelected = selectedNodeId === node.id;
                return (
                  <div
                    key={node.id}
                    id={`node-${node.id}`}
                    onClick={() => setSelectedNodeId(node.id)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer relative group ${getNodeBorder(
                      node.status
                    )} ${isSelected ? 'ring-2 ring-cyan-400 ring-offset-2 ring-offset-[#060D18] scale-102 z-10' : 'hover:border-cyan-500/40'}`}
                  >
                    {node.criticalAsset && (
                      <span className="absolute -top-2 -right-2 px-1.5 py-0.5 rounded bg-[#EF4444] text-white font-bold text-[9px] uppercase tracking-wider font-mono shadow">
                        Critical
                      </span>
                    )}
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <div className="p-1.5 rounded-md bg-[#0B1726] border border-[#1B3047]">
                          {getNodeIcon(node.type)}
                        </div>
                        <div>
                          <h4 className="text-xs font-bold font-mono text-white">{node.name}</h4>
                          <span className="text-[10px] text-slate-400 font-mono block">{node.ipAddress}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1B3047] mt-2">
                      <span className="text-slate-400">{node.osOrType}</span>
                      <span
                        className={`font-bold ${
                          node.riskScore > 80 ? 'text-[#EF4444]' : node.riskScore > 50 ? 'text-[#F59E0B]' : 'text-slate-400'
                        }`}
                      >
                        Risk: {node.riskScore}/100
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Lateral Hops / Edges Table */}
            <div className="mt-6 pt-4 border-t border-[#1B3047] space-y-2">
              <div className="text-xs font-bold text-slate-300 font-mono flex items-center justify-between">
                <span>Lateral Movement Vector Edges:</span>
                <span className="text-[11px] text-slate-500">Click edge to inspect SIEM Query</span>
              </div>
              <div className="space-y-2">
                {scenario.edges.map((edge) => {
                  const srcNode = scenario.nodes.find((n) => n.id === edge.source);
                  const tgtNode = scenario.nodes.find((n) => n.id === edge.target);
                  const isEdgeSelected = selectedEdgeId === edge.id;
                  return (
                    <div
                      key={edge.id}
                      id={`edge-${edge.id}`}
                      onClick={() => setSelectedEdgeId(edge.id)}
                      className={`p-2.5 rounded-lg border text-xs font-mono transition-all cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                        isEdgeSelected
                          ? 'border-cyan-400 bg-cyan-500/10 text-white ring-1 ring-cyan-400'
                          : 'border-[#1B3047] bg-[#0B1726] text-slate-300 hover:border-cyan-500/40'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/30 text-[10px] font-bold">
                          {edge.techniqueId}
                        </span>
                        <span className="font-bold text-slate-200">{edge.techniqueName}</span>
                      </div>

                      <div className="flex items-center gap-2 text-[11px] text-slate-400">
                        <span className="text-cyan-400 font-semibold">{srcNode?.name}</span>
                        <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                        <span className="text-teal-400 font-semibold">{tgtNode?.name}</span>
                        <span className="text-[10px] text-slate-400 bg-[#060D18] px-1.5 py-0.5 rounded border border-[#1B3047]">
                          {edge.protocolOrVector}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Containment Action Playbook */}
          <div className="p-4 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-3 mt-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-teal-400 font-mono">
                <ShieldCheck className="w-4 h-4 text-teal-400" /> 1-Click Automated Containment Playbook
              </div>
              <span className="text-[10px] text-slate-400 font-mono">Step-by-Step Response Actions</span>
            </div>

            <div className="space-y-2">
              {scenario.report.containmentSteps.map((step) => (
                <div key={step.stepNumber} className="p-3 rounded-lg bg-[#0B1726] border border-[#1B3047] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200 font-mono">
                      Step {step.stepNumber}: {step.title}
                    </span>
                    <span className="text-[10px] text-teal-300 font-mono bg-teal-500/10 px-2 py-0.5 rounded border border-teal-500/20">
                      Impact: {step.impact}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{step.action}</p>
                  {step.platformCommand && (
                    <div className="relative bg-[#060D18] rounded border border-[#1B3047] p-2 font-mono text-[11px] text-teal-300 overflow-x-auto flex items-center justify-between">
                      <code>{step.platformCommand}</code>
                      <button
                        onClick={() => handleCopy(step.platformCommand!, `step-${step.stepNumber}`)}
                        className="ml-2 p-1 rounded hover:bg-[#101F32] text-slate-400 hover:text-slate-200 cursor-pointer"
                        title="Copy containment command"
                      >
                        {copiedCode === `step-${step.stepNumber}` ? (
                          <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Col: Detailed Node & Edge Inspection Panel */}
        <div className="space-y-6">
          {/* Node Inspector */}
          <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Asset Node Inspector</h3>
              </div>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                  selectedNode.status === 'compromised'
                    ? 'bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/40'
                    : selectedNode.status === 'at_risk'
                    ? 'bg-[#F59E0B]/20 text-[#F59E0B] border border-[#F59E0B]/40'
                    : 'bg-[#101F32] text-slate-400 border border-[#1B3047]'
                }`}
              >
                {selectedNode.status}
              </span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="flex justify-between py-1.5 border-b border-[#1B3047]">
                <span className="text-slate-400">Node ID / Name:</span>
                <span className="font-bold text-white">{selectedNode.name}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[#1B3047]">
                <span className="text-slate-400">Asset Category:</span>
                <span className="text-cyan-300 font-semibold">{selectedNode.type}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[#1B3047]">
                <span className="text-slate-400">IP / Network Address:</span>
                <span className="text-slate-200">{selectedNode.ipAddress}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[#1B3047]">
                <span className="text-slate-400">OS / Environment:</span>
                <span className="text-slate-300">{selectedNode.osOrType}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[#1B3047]">
                <span className="text-slate-400">Department / Region:</span>
                <span className="text-slate-300">{selectedNode.departmentOrRegion}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[#1B3047]">
                <span className="text-slate-400">Calculated Risk Score:</span>
                <span className="font-bold text-[#EF4444]">{selectedNode.riskScore} / 100</span>
              </div>
            </div>

            {onSendToGenerator && (
              <button
                onClick={() =>
                  onSendToGenerator(
                    `Investigate all security events and authentication attempts targeting asset ${selectedNode.name} (${selectedNode.ipAddress})`
                  )
                }
                className="w-full py-2.5 px-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold font-sans text-xs flex items-center justify-center gap-2 transition-all shadow-md shadow-cyan-500/10 cursor-pointer"
              >
                <Zap className="w-4 h-4 text-[#060D18]" /> Generate Triage SIEM Query for Node
              </button>
            )}
          </div>

          {/* Edge Vector Inspector & SIEM Query */}
          <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Lateral Movement Telemetry Query</h3>
              </div>
              <span className="text-[10px] font-mono text-[#EF4444] font-bold bg-[#EF4444]/10 px-2 py-0.5 rounded border border-[#EF4444]/30">
                {selectedEdge.techniqueId}
              </span>
            </div>

            <div className="space-y-2 text-xs">
              <div className="font-bold text-slate-200">{selectedEdge.techniqueName}</div>
              <div className="text-slate-400 text-[11px] font-mono">
                Vector: <span className="text-cyan-300">{selectedEdge.protocolOrVector}</span>
              </div>
            </div>

            {selectedEdge.siemQuery && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400">Detection Logic Query:</span>
                  <button
                    onClick={() => handleCopy(selectedEdge.siemQuery!, 'edge-query')}
                    className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                  >
                    {copiedCode === 'edge-query' ? <Check className="w-3 h-3 text-[#22C55E]" /> : <Copy className="w-3 h-3" />}
                    Copy Query
                  </button>
                </div>

                <div className="p-3 bg-[#060D18] rounded-xl border border-[#1B3047] text-cyan-200 font-mono text-[11px] overflow-x-auto leading-relaxed whitespace-pre-wrap">
                  <code>{selectedEdge.siemQuery}</code>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
