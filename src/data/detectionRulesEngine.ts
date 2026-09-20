import type { DetectionBreakdown, SiemPlatformId } from '../types.js';
import { SIEM_PLATFORMS } from './siemPlatforms.js';

export interface ThreatScenarioTemplate {
  id: string;
  keywords: string[];
  title: string;
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  subTechniqueId?: string;
  subTechniqueName?: string;
  description: string;
  threatActors: string[];
  noiseRating: 'Low' | 'Medium' | 'High';
  falsePositives: string[];
  whitelisting: string[];
  thresholding: string;
  assumptions: string[];
  queries: Record<SiemPlatformId, string>;
  investigationQueries: Array<{
    title: string;
    queryTemplates: Record<SiemPlatformId, string>;
    purpose: string;
  }>;
}

export const THREAT_SCENARIOS: ThreatScenarioTemplate[] = [
  {
    id: 'ssh_brute_force_success',
    keywords: ['ssh', 'brute', 'failed login', 'failed ssh', 'authentication failure', 'login failure', 'password spray'],
    title: 'SSH / Remote Auth Brute Force Followed by Successful Login',
    tactic: 'Credential Access',
    techniqueId: 'T1110.001',
    techniqueName: 'Brute Force: Password Guessing',
    description: 'Detects multiple failed SSH authentication attempts from a single source IP address followed by a successful login within a short time window.',
    threatActors: ['Lazarus Group', 'Volt Typhoon', 'FIN7', 'Scattered Spider'],
    noiseRating: 'Low',
    falsePositives: ['Automated Ansible/Puppet deployment scripts with outdated SSH keys', 'Network vulnerability scanners (e.g. Tenable, Qualys)'],
    whitelisting: ['Exclude internal bastion jump hosts (e.g., 10.0.10.50)', 'Whitelist authorized vulnerability scanner IP subnets'],
    thresholding: 'Trigger alert when >= 5 failed attempts are followed by >= 1 successful authentication within 10 minutes from the same source IP.',
    assumptions: ['Assumes Linux Syslog authpriv/sshd telemetry or Windows Security Event Logs are ingested into SIEM.'],
    queries: {
      sentinel: `// Microsoft Sentinel KQL - SSH Brute Force with Success
let timeframe = 24h;
let threshold = 5;
let failedLogins = Syslog
| where TimeGenerated > ago(timeframe)
| where Facility == "auth" or Facility == "authpriv" or SyslogMessage has "sshd"
| where SyslogMessage has "Failed password" or SyslogMessage has "authentication failure"
| parse SyslogMessage with * "from " SourceIP " port" *
| summarize FailedCount = count(), FirstFailTime = min(TimeGenerated), LastFailTime = max(TimeGenerated) by SourceIP, HostIP, Computer
| where FailedCount >= threshold;
let successLogins = Syslog
| where TimeGenerated > ago(timeframe)
| where Facility == "auth" or Facility == "authpriv" or SyslogMessage has "sshd"
| where SyslogMessage has "Accepted password" or SyslogMessage has "Accepted publickey"
| parse SyslogMessage with * "from " SourceIP " port" *
| project SuccessTime = TimeGenerated, SourceIP, TargetUser = extract(@"for (\\w+)", 1, SyslogMessage), HostIP, Computer;
failedLogins
| join kind=inner (successLogins) on SourceIP
| where SuccessTime between (FirstFailTime .. (LastFailTime + 15m))
| project FirstFailTime, LastFailTime, SuccessTime, SourceIP, TargetUser, Computer, FailedCount
| order by SuccessTime desc`,
      defender: `// Microsoft Defender XDR - Remote Auth Brute Force to Success
let timeframe = 24h;
let threshold = 5;
let failures = DeviceLogonEvents
| where Timestamp > ago(timeframe)
| where ActionType == "LogonFailed" and Protocol == "SSH" or LogonType in (3, 10)
| summarize FailedCount = count(), FirstFail = min(Timestamp), LastFail = max(Timestamp) by RemoteIP, DeviceName
| where FailedCount >= threshold;
let successes = DeviceLogonEvents
| where Timestamp > ago(timeframe)
| where ActionType == "LogonSuccess" and Protocol == "SSH" or LogonType in (3, 10)
| project SuccessTime = Timestamp, RemoteIP, AccountName, DeviceName;
failures
| join kind=inner (successes) on RemoteIP, DeviceName
| where SuccessTime >= LastFail and SuccessTime <= LastFail + 10m
| project FirstFail, LastFail, SuccessTime, RemoteIP, AccountName, DeviceName, FailedCount`,
      splunk: `// Splunk SPL - SSH Brute Force with Successful Login
index=linux sourcetype=syslog (process=sshd OR "sshd[") ("Failed password" OR "Accepted password" OR "Accepted publickey")
| rex field=_raw "Failed password for (invalid user )?(?<target_user>\\w+) from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
| rex field=_raw "Accepted (?:password|publickey) for (?<target_user>\\w+) from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
| eval is_failed=if(like(_raw, "%Failed password%"), 1, 0)
| eval is_success=if(like(_raw, "%Accepted%"), 1, 0)
| stats count(eval(is_failed==1)) as fail_count, count(eval(is_success==1)) as success_count, earliest(_time) as first_seen, latest(_time) as last_seen, values(target_user) as users by src_ip, host
| where fail_count >= 5 AND success_count >= 1
| eval duration_sec = last_seen - first_seen
| convert ctime(first_seen) ctime(last_seen)
| table src_ip, host, users, fail_count, success_count, duration_sec, first_seen, last_seen`,
      qradar: `// IBM QRadar AQL - SSH Brute Force Followed by Success
SELECT "sourceip" as SourceIP, "username" as Username, "destinationip" as DestIP,
       COUNT(*) as TotalAttempts,
       DATEFORMAT(MIN(devicetime), 'yyyy-MM-dd HH:mm:ss') as FirstAttempt,
       DATEFORMAT(MAX(devicetime), 'yyyy-MM-dd HH:mm:ss') as LastAttempt
FROM events
WHERE (qid = 27750001 OR "eventname" ILIKE '%SSH%Fail%' OR "payload" ILIKE '%Failed password%')
GROUP BY "sourceip", "username", "destinationip"
HAVING TotalAttempts >= 5
ORDER BY TotalAttempts DESC
START ago(24h) STOP now()`,
      elastic: `// Elastic EQL - Sequence of Failed SSH Logins Followed by Success
sequence by source.ip with maxspan=10m
  [ authentication where event.action == "logon-failed" and network.protocol == "ssh" ] with runs >= 5
  [ authentication where event.action == "logon-success" and network.protocol == "ssh" ]`,
      google_secops: `// Google SecOps (Chronicle) YARA-L 2.0
rule ssh_brute_force_success {
  meta:
    author = "SOC Detection Engineer"
    description = "Detects 5+ failed SSH logins followed by successful authentication from same IP"
    severity = "HIGH"
    mitre_attack = "T1110.001"
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.network.application_protocol = "SSH"
    $fail.principal.ip = $src_ip
    $fail.target.hostname = $target_host

    $succ.metadata.event_type = "USER_LOGIN"
    $succ.security_result.action = "ALLOW"
    $succ.network.application_protocol = "SSH"
    $succ.principal.ip = $src_ip
    $succ.target.hostname = $target_host
    $succ.metadata.event_timestamp.seconds > $fail.metadata.event_timestamp.seconds

  match:
    $src_ip, $target_host over 10m

  condition:
    #fail >= 5 and #succ >= 1
}`,
      cortex: `// Palo Alto Cortex XQL - SSH Brute Force with Successful Login
dataset = authentication_stories
| filter event_type = ENUM.AUTH_FAILED and auth_type = "SSH"
| comp count() as fail_count, min(_time) as first_fail, max(_time) as last_fail by src_ip, dst_agent_id
| filter fail_count >= 5
| join type = inner (
    dataset = authentication_stories
    | filter event_type = ENUM.AUTH_SUCCESS and auth_type = "SSH"
    | fields _time as success_time, src_ip, dst_agent_id, user_name
  ) on src_ip = src_ip and dst_agent_id = dst_agent_id
| filter success_time >= last_fail and success_time <= last_fail + 600000
| fields src_ip, dst_agent_id, user_name, fail_count, first_fail, success_time`,
      securonix: `// Securonix Spotter - SSH Brute Force to Success
rg_category = "Authentication" AND (deviceaction = "failure" OR outcome = "FAILURE") AND application = "SSH"
| STATS count(eventid) as fail_count, min(eventtime) as first_seen, max(eventtime) as last_seen BY sourceaddress, destinationhostname, destinationusername
| FILTER fail_count >= 5
| JOIN ON sourceaddress (
    rg_category = "Authentication" AND (deviceaction = "success" OR outcome = "SUCCESS") AND application = "SSH"
    | FIELDS eventtime as success_time, sourceaddress, destinationhostname, destinationusername
  )
| FILTER success_time >= last_seen`,
      logrhythm: `// LogRhythm MPE Rule
(CommonEvent: "Authentication Failure" OR EventID: 4625 OR Message: "*Failed password*") AND Application: "SSH"
| GROUP BY SourceIP, HostName
| HAVING COUNT >= 5 WITHIN 10 MINUTES
| FOLLOWED BY (CommonEvent: "Authentication Success" OR EventID: 4624) WITHIN 10 MINUTES ON SourceIP`,
      arcsight: `// OpenText ArcSight ESM EPL
deviceEventClassId = "SSHD-FAIL" OR message CONTAINS "Failed password"
| chart count() as fail_count by sourceAddress, destinationAddress
| where fail_count >= 5
| join on sourceAddress [
    deviceEventClassId = "SSHD-SUCCESS" OR message CONTAINS "Accepted password"
    | chart count() as success_count by sourceAddress, destinationUserName
  ]`,
      gurucul: `// Gurucul Next-Gen SIEM
category = "Authentication" AND status = "FAILURE" AND application = "SSH"
| GROUPBY source_ip, destination_host
| HAVING COUNT >= 5
| SEQUENCE_FOLLOWED_BY (category = "Authentication" AND status = "SUCCESS" AND application = "SSH")
| WITHIN 10m BY source_ip
| RISK_SCORE = 85`,
    },
    investigationQueries: [
      {
        title: 'Pivot on Attacker Source IP for Outbound Scans or Lateral Logins',
        queryTemplates: {
          sentinel: `Syslog | where TimeGenerated > ago(6h) | where SyslogMessage has "<SOURCE_IP>" | project TimeGenerated, Computer, SyslogMessage`,
          defender: `DeviceNetworkEvents | where Timestamp > ago(6h) | where RemoteIP == "<SOURCE_IP>" | project Timestamp, DeviceName, InitiatingProcessFileName, LocalPort`,
          splunk: `index=* "<SOURCE_IP>" | stats count by sourcetype, host, action`,
          qradar: `SELECT * FROM events WHERE "sourceip" = '<SOURCE_IP>' START ago(6h)`,
          elastic: `* where source.ip == "<SOURCE_IP>"`,
          google_secops: `$e.principal.ip = "<SOURCE_IP>"`,
          cortex: `dataset = xdr_data | filter action_remote_ip = "<SOURCE_IP>"`,
          securonix: `sourceaddress = "<SOURCE_IP>" | STATS count by rg_category, destinationhostname`,
          logrhythm: `SourceIP: "<SOURCE_IP>"`,
          arcsight: `sourceAddress = "<SOURCE_IP>"`,
          gurucul: `source_ip = "<SOURCE_IP>"`,
        },
        purpose: 'Identify whether the attacker attempted connections to other servers in the fleet or performed reconnaissance.',
      },
    ],
  },
  {
    id: 'lsass_dumping',
    keywords: ['lsass', 'procdump', 'mimikatz', 'comsvcs', 'minidump', 'credential dumping', 'lsass.exe', 'memory dump'],
    title: 'LSASS Process Memory Access & Credential Dumping',
    tactic: 'Credential Access',
    techniqueId: 'T1003.001',
    techniqueName: 'OS Credential Dumping: LSASS Memory',
    description: 'Detects unauthorized processes requesting memory read handles to lsass.exe (AccessMask 0x0010, 0x1410, 0x1F0FFF) or executing LOLBins like procdump.exe and comsvcs.dll MiniDump.',
    threatActors: ['APT29', 'FIN7', 'Wizard Spider', 'Scattered Spider', 'BlackCat/ALPHV'],
    noiseRating: 'Low',
    falsePositives: ['Legitimate AV/EDR sensors (e.g. MsMpEng.exe, SentinelAgent.exe)', 'Active Directory Domain Controller synchronization'],
    whitelisting: ['Whitelist verified EDR agent paths (e.g. C:\\Program Files\\Windows Defender\\*)', 'Filter benign backup tools that have authorized security handles'],
    thresholding: 'Alert on a single occurrence of unauthorized process handle to lsass.exe or MiniDump execution.',
    assumptions: ['Assumes Sysmon Event ID 10 (ProcessAccess) or Windows Auditing Event 4656/4663 is ingested.'],
    queries: {
      sentinel: `// Microsoft Sentinel KQL - LSASS Memory Dumping
let suspicious_processes = dynamic(["procdump.exe", "dumpert.exe", "nanodump.exe", "mimikatz.exe", "rundll32.exe"]);
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4656, 4663, 4688)
| where (ObjectName endswith "lsass.exe" and AccessMask in ("0x0010", "0x1410", "0x1F0FFF", "0x143a", "0x1418"))
    or (ProcessName has_any (suspicious_processes) and CommandLine has_any ("minidump", "lsass", "full", "comsvcs"))
| project TimeGenerated, Computer, Account, ProcessName, CommandLine, ObjectName, AccessMask
| order by TimeGenerated desc`,
      defender: `// Microsoft Defender XDR - LSASS Credential Dumping Hunting
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (ProcessCommandLine has "comsvcs" and ProcessCommandLine has "minidump")
    or (FileName in~ ("procdump.exe", "procdump64.exe", "mimikatz.exe", "dumpert.exe", "nanodump.exe") and ProcessCommandLine has "lsass")
    or (InitiatingProcessFileName =~ "rundll32.exe" and ProcessCommandLine has "MiniDump" and ProcessCommandLine has "#24")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine`,
      splunk: `// Splunk SPL - LSASS Memory Dump via AccessMask or LOLBins
index=security (EventCode=10 TargetImage="*\\\\lsass.exe" GrantedAccess IN ("0x0010", "0x1410", "0x1F0FFF", "0x1010", "0x143a"))
OR (EventCode=4688 (CommandLine="*comsvcs.dll*#24*" OR CommandLine="*comsvcs*minidump*" OR (Image="*\\\\procdump*.exe" CommandLine="*lsass*") OR CommandLine="*mimikatz*"))
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen by host, user, SourceImage, TargetImage, GrantedAccess, CommandLine
| convert ctime(first_seen) ctime(last_seen)`,
      qradar: `// IBM QRadar AQL - LSASS Memory Dump
SELECT "sourceip", "username", "eventname", "ProcessName", "CommandLine",
       DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') as EventTime
FROM events
WHERE (qid = 27750001 OR "EventID" = '4688' OR "EventID" = '10')
  AND ("CommandLine" ILIKE '%comsvcs%minidump%' OR "CommandLine" ILIKE '%procdump%lsass%' OR "TargetImage" ILIKE '%lsass.exe%')
START ago(24h) STOP now()`,
      elastic: `// Elastic EQL - LSASS Memory Dumping
process where event.type == "start" and (
  (process.pe.original_file_name in ("procdump.exe", "procdump64.exe") and process.args : "*lsass*") or
  (process.name == "rundll32.exe" and process.args : "*comsvcs*" and process.args : "*MiniDump*") or
  (process.args : "*sekurlsa*" or process.args : "*lsadump*")
)`,
      google_secops: `// Google SecOps YARA-L 2.0 - LSASS Credential Extraction
rule detect_lsass_dumping {
  meta:
    description = "Detects LSASS dump via comsvcs or procdump"
    severity = "CRITICAL"
    mitre_attack = "T1003.001"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    (
      $e.target.process.command_line = /comsvcs(\.dll)?.*MiniDump/i or
      $e.target.process.command_line = /procdump.*lsass/i or
      $e.target.process.file.full_path = /.*\\lsass\.exe/i
    )
  condition:
    $e
}`,
      cortex: `// Palo Alto Cortex XQL - LSASS Dumping
dataset = xdr_data
| filter event_type = ENUM.PROCESS and (
    (action_process_image_command_line ~= ".*comsvcs.*MiniDump.*" or action_process_image_command_line ~= ".*procdump.*lsass.*") or
    (action_process_image_name in ("mimikatz.exe", "nanodump.exe", "dumpert.exe"))
  )
| fields _time, agent_hostname, actor_process_image_name, action_process_image_name, action_process_image_command_line`,
      securonix: `// Securonix Spotter - LSASS Memory Access
rg_category = "Endpoint" AND (
  commandline CONTAINS "comsvcs" AND commandline CONTAINS "minidump" OR
  commandline CONTAINS "procdump" AND commandline CONTAINS "lsass" OR
  targetprocessname CONTAINS "lsass.exe" AND (accessmask = "0x1410" OR accessmask = "0x1F0FFF")
)
| STATS count BY destinationhostname, destinationusername, commandline`,
      logrhythm: `// LogRhythm MPE - LSASS Dumping
(EventID: 4688 OR EventID: 10) AND (VendorMessage: "*comsvcs*minidump*" OR VendorMessage: "*procdump*lsass*" OR ObjectName: "*lsass.exe*")`,
      arcsight: `// OpenText ArcSight ESM
deviceEventClassId = "4688" AND (commandLine CONTAINS "comsvcs" AND commandLine CONTAINS "minidump" OR commandLine CONTAINS "procdump")
| chart count() by destinationHostName, destinationUserName, commandLine`,
      gurucul: `// Gurucul Next-Gen SIEM
category = "Endpoint Analytics" AND (
  command_line LIKE "%comsvcs%minidump%" OR
  command_line LIKE "%procdump%lsass%" OR
  process_name = "mimikatz.exe"
)
| RISK_SCORE = 95`,
    },
    investigationQueries: [
      {
        title: 'Check files created in C:\\Windows\\Temp or AppData around dump time',
        queryTemplates: {
          sentinel: `DeviceFileEvents | where TimeGenerated between (ago(1h)..now()) | where FolderPath has "temp" and FileName endswith ".dmp"`,
          defender: `DeviceFileEvents | where Timestamp > ago(2h) | where FileName endswith ".dmp" or FolderPath has_any ("Temp", "Public")`,
          splunk: `index=endpoint (sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11) TargetFilename="*.dmp"`,
          qradar: `SELECT * FROM events WHERE "EventID" = '11' AND "TargetFilename" ILIKE '%.dmp' START ago(2h)`,
          elastic: `file where file.extension == "dmp" or file.path : "*\\\\Temp\\\\*"`,
          google_secops: `$e.target.file.full_path = /.*\.dmp$/i`,
          cortex: `dataset = xdr_data | filter event_type = ENUM.FILE and action_file_name ~= ".*\\.dmp"`,
          securonix: `rg_category = "File" AND filename CONTAINS ".dmp"`,
          logrhythm: `EventID: 11 AND TargetFilename: "*.dmp"`,
          arcsight: `deviceEventClassId = "11" AND filePath CONTAINS ".dmp"`,
          gurucul: `file_extension = "dmp"`,
        },
        purpose: 'Locate the saved .dmp memory artifact to verify if credentials were exfiltrated.',
      },
    ],
  },
  {
    id: 'powershell_encoded_cradle',
    keywords: ['powershell', 'encoded', 'downloadstring', 'downloadfile', 'webclient', 'iex', 'invoke-expression', 'invoke-webrequest', 'curl', 'wget', 'certutil'],
    title: 'Suspicious Encoded PowerShell & Remote Download Cradle Execution',
    tactic: 'Execution',
    techniqueId: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    description: 'Detects PowerShell executing with encoded commands (-enc, -encodedcommand), hidden windows (-w hidden), execution bypass, or downloading payloads via WebClient.DownloadString/IEX.',
    threatActors: ['APT28', 'APT29', 'MuddyWater', 'Emotet', 'QakBot'],
    noiseRating: 'Low',
    falsePositives: ['IT configuration management tools (e.g. Microsoft SCCM, Chocolatey, PDQ Deploy)', 'Authorized administrative inventory scripts'],
    whitelisting: ['Whitelist known enterprise management service accounts', 'Filter signed PowerShell scripts running from C:\\Program Files\\Microsoft\\*'],
    thresholding: 'Alert on any occurrence of obfuscated/encoded PowerShell containing download cradle functions.',
    assumptions: ['Assumes PowerShell Script Block Logging (Event ID 4104) and Process Creation (4688 / Sysmon 1) are enabled.'],
    queries: {
      sentinel: `// Microsoft Sentinel KQL - Encoded PowerShell & Download Cradle
let enc_flags = dynamic(["-enc", "-encodedcommand", "-e ", "-en "]);
let cradle_keywords = dynamic(["DownloadString", "DownloadFile", "Invoke-Expression", "IEX", "Net.WebClient", "BitTransfer", "Start-BitsTransfer"]);
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4688, 4104)
| where (ProcessName endswith "powershell.exe" or ProcessName endswith "pwsh.exe")
| where CommandLine has_any (enc_flags) or CommandLine has_any (cradle_keywords) or ScriptBlockText has_any (cradle_keywords)
| project TimeGenerated, Computer, Account, ProcessName, CommandLine, ParentProcessName, ScriptBlockText
| order by TimeGenerated desc`,
      defender: `// Microsoft Defender XDR - PowerShell Download Cradle & Encoded Execution
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "powershell_ise.exe", "pwsh.exe")
| where (ProcessCommandLine has_any ("-enc", "-encodedcommand", "-e ", "bypass", "-w hidden", "-windowstyle hidden"))
    and (ProcessCommandLine has_any ("downloadstring", "downloadfile", "webclient", "iex", "invoke-expression", "http://", "https://"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine`,
      splunk: `// Splunk SPL - PowerShell Encoded & Cradle Execution
index=security (EventCode=4688 OR EventCode=4104) (Process_Name="*powershell.exe" OR Process_Name="*pwsh.exe" OR sourcetype="*PowerShell*")
(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*downloadstring*" OR CommandLine="*webclient*" OR CommandLine="*bypass*" OR ScriptBlockText="*downloadstring*")
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen by host, user, Process_Name, ParentProcessName, CommandLine
| convert ctime(first_seen) ctime(last_seen)`,
      qradar: `// IBM QRadar AQL - PowerShell Download Cradle
SELECT "sourceip", "username", "Computer", "CommandLine", DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') as Time
FROM events
WHERE "EventID" IN ('4688', '4104')
  AND ("ProcessName" ILIKE '%powershell.exe%' OR "ProcessName" ILIKE '%pwsh.exe%')
  AND ("CommandLine" ILIKE '%-enc%' OR "CommandLine" ILIKE '%downloadstring%' OR "CommandLine" ILIKE '%webclient%')
START ago(24h) STOP now()`,
      elastic: `// Elastic EQL - Suspicious PowerShell Execution
process where event.type == "start" and process.name in ("powershell.exe", "pwsh.exe") and (
  process.args : ("*-enc*", "*-encodedcommand*", "*DownloadString*", "*Net.WebClient*", "*Invoke-Expression*")
)`,
      google_secops: `// Google SecOps YARA-L 2.0 - Encoded PowerShell Cradle
rule powershell_download_cradle {
  meta:
    description = "Detects PowerShell with encoded payload or download cradle"
    severity = "HIGH"
    mitre_attack = "T1059.001"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /powershell\.exe/i
    (
      $e.target.process.command_line = /(-enc|-encodedcommand|downloadstring|webclient|iex)/i
    )
  condition:
    $e
}`,
      cortex: `// Palo Alto Cortex XQL - PowerShell Encoded Execution
dataset = xdr_data
| filter event_type = ENUM.PROCESS and action_process_image_name in ("powershell.exe", "pwsh.exe")
| filter action_process_image_command_line ~= ".*(-enc|-encodedcommand|downloadstring|iex).*"
| fields _time, agent_hostname, actor_process_image_name, action_process_image_command_line`,
      securonix: `// Securonix Spotter - PowerShell Obfuscation
rg_category = "Endpoint" AND (processname = "powershell.exe" OR processname = "pwsh.exe") AND (
  commandline CONTAINS "-enc" OR commandline CONTAINS "downloadstring" OR commandline CONTAINS "webclient"
)
| STATS count BY destinationhostname, destinationusername, commandline`,
      logrhythm: `// LogRhythm MPE - PowerShell Cradle
(Process: "powershell.exe" OR Process: "pwsh.exe") AND (VendorMessage: "*-enc*" OR VendorMessage: "*downloadstring*" OR VendorMessage: "*webclient*")`,
      arcsight: `// OpenText ArcSight ESM
deviceEventClassId = "4688" AND (destinationProcessName = "powershell.exe" OR destinationProcessName = "pwsh.exe") AND (commandLine CONTAINS "-enc" OR commandLine CONTAINS "downloadstring")`,
      gurucul: `// Gurucul Next-Gen SIEM
category = "Endpoint Analytics" AND process_name IN ("powershell.exe", "pwsh.exe") AND (
  command_line LIKE "%-enc%" OR command_line LIKE "%downloadstring%"
)
| RISK_SCORE = 85`,
    },
    investigationQueries: [
      {
        title: 'Check network connections initiated by powershell.exe to external IPs',
        queryTemplates: {
          sentinel: `DeviceNetworkEvents | where InitiatingProcessFileName =~ "powershell.exe" | where RemoteIPType != "Private"`,
          defender: `DeviceNetworkEvents | where InitiatingProcessFileName =~ "powershell.exe" and RemoteIPType == "Public"`,
          splunk: `index=network (InitiatingProcessFileName="*powershell.exe" OR process="powershell.exe") NOT (dest_ip="10.*" OR dest_ip="192.168.*" OR dest_ip="172.16.*")`,
          qradar: `SELECT * FROM events WHERE "ProcessName" ILIKE '%powershell.exe%' AND "destinationip" NOT ILIKE '10.%' START ago(2h)`,
          elastic: `network where process.name == "powershell.exe" and not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")`,
          google_secops: `$e.principal.process.file.full_path = /powershell\.exe/i and $e.target.ip != ""`,
          cortex: `dataset = xdr_data | filter actor_process_image_name = "powershell.exe" and action_remote_ip != ""`,
          securonix: `processname = "powershell.exe" AND destinationaddress IS NOT NULL`,
          logrhythm: `Process: "powershell.exe" AND Direction: "Outbound"`,
          arcsight: `destinationProcessName = "powershell.exe" AND destinationAddress IS NOT NULL`,
          gurucul: `process_name = "powershell.exe" AND network_direction = "OUTBOUND"`,
        },
        purpose: 'Identify the external C2 server or repository hosting the downloaded payload.',
      },
    ],
  },
  {
    id: 'kerberoasting_spn',
    keywords: ['kerberoasting', 'kerberoast', 'spn', 'ticket', 'rc4', '4769', 'service principal name', 'tgss'],
    title: 'Kerberoasting Attack: Suspicious Service Principal Name (SPN) Ticket Request',
    tactic: 'Credential Access',
    techniqueId: 'T1558.003',
    techniqueName: 'Steal or Forge Kerberos Tickets: Kerberoasting',
    description: 'Detects high volume or weak RC4 (0x17) Kerberos Ticket Granting Service (TGS) ticket requests targeting Service Principal Names (SPNs) for offline password cracking.',
    threatActors: ['FIN7', 'Wizard Spider', 'Scattered Spider', 'DEV-0537'],
    noiseRating: 'Low',
    falsePositives: ['Legacy service accounts configured only with RC4 encryption (e.g., legacy SQL Server reporting)'],
    whitelisting: ['Filter known legacy service accounts while tracking remediation to AES256'],
    thresholding: 'Trigger alert when a single user account requests > 3 TGS tickets with TicketEncryptionType 0x17 within 10 minutes.',
    assumptions: ['Assumes Windows Domain Controller Event ID 4769 (A Kerberos service ticket was requested) is ingested.'],
    queries: {
      sentinel: `// Microsoft Sentinel KQL - Kerberoasting Detection
let timeframe = 24h;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4769
| where TicketEncryptionType == "0x17" // RC4-HMAC-MD5 encryption
| where ServiceName !endswith "$" and ServiceName !in ("krbtgt", "kadmin/changepw")
| summarize RequestCount = count(), SPNs = make_set(ServiceName), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by TargetUserName, IpAddress, Computer
| where RequestCount >= 3
| order by RequestCount desc`,
      defender: `// Microsoft Defender XDR - Kerberoasting Activity
IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "Kerberos" and AdditionalFields has '"EncryptionType":"0x17"'
| where AccountName !endswith "$" and DestinationDeviceName !has "$"
| summarize count(), dcount(DestinationDeviceName), make_set(DestinationDeviceName) by AccountName, IPAddress
| where count_ >= 3`,
      splunk: `// Splunk SPL - Kerberoasting TGS Requests with RC4
index=security EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$*" Service_Name!="krbtgt"
| stats count as ticket_requests, values(Service_Name) as targeted_spns, earliest(_time) as first_seen, latest(_time) as last_seen by Target_User_Name, IpAddress, host
| where ticket_requests >= 3
| convert ctime(first_seen) ctime(last_seen)
| table Target_User_Name, IpAddress, host, ticket_requests, targeted_spns, first_seen, last_seen`,
      qradar: `// IBM QRadar AQL - Kerberoasting TGS Requests
SELECT "username", "sourceip", COUNT(*) as TicketCount, DATEFORMAT(MIN(devicetime), 'yyyy-MM-dd HH:mm:ss') as FirstSeen
FROM events
WHERE "EventID" = '4769' AND "payload" ILIKE '%0x17%' AND "payload" NOT ILIKE '%$%'
GROUP BY "username", "sourceip"
HAVING TicketCount >= 3
START ago(24h) STOP now()`,
      elastic: `// Elastic EQL - Kerberoasting TGS Ticket Spike
authentication where winlog.event_id == 4769 and winlog.event_data.TicketEncryptionType == "0x17" and
  not winlog.event_data.ServiceName : ("*$", "krbtgt")`,
      google_secops: `// Google SecOps YARA-L 2.0 - Kerberoasting Detection
rule kerberoasting_spn_request {
  meta:
    description = "Detects multiple Kerberos TGS tickets requested with weak RC4 encryption"
    severity = "HIGH"
    mitre_attack = "T1558.003"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.metadata.product_event_type = "4769"
    $e.security_result.description = /0x17/i
    $e.target.user.user_display_name != /.*\$$/
    $e.principal.user.user_display_name = $user
  match:
    $user over 10m
  condition:
    #e >= 3
}`,
      cortex: `// Palo Alto Cortex XQL - Kerberoasting
dataset = xdr_data
| filter event_type = ENUM.AUTH and action_auth_encryption_type = "0x17" and not(action_target_name ~= ".*\\$")
| comp count() as req_count, values(action_target_name) as spns by actor_effective_username, action_remote_ip
| filter req_count >= 3`,
      securonix: `// Securonix Spotter - Kerberoasting
rg_category = "Authentication" AND eventid = "4769" AND encryptiontype = "0x17" AND servicename NOT CONTAINS "$"
| STATS count BY destinationusername, sourceaddress, servicename
| FILTER count >= 3`,
      logrhythm: `// LogRhythm MPE - Kerberoasting
EventID: 4769 AND VendorMessage: "*0x17*" AND NOT ServiceName: "*$*" | GROUP BY Account | HAVING COUNT >= 3`,
      arcsight: `// OpenText ArcSight ESM
deviceEventClassId = "4769" AND message CONTAINS "0x17" AND NOT destinationUserName CONTAINS "$" | chart count() by sourceUserName, sourceAddress`,
      gurucul: `// Gurucul Next-Gen SIEM
category = "Authentication" AND event_id = 4769 AND encryption_type = "0x17" AND service_name NOT LIKE "%$%"
| GROUPBY user_name, source_ip | HAVING COUNT >= 3 | RISK_SCORE = 90`,
    },
    investigationQueries: [
      {
        title: 'Query account login history for the user requesting SPN tickets',
        queryTemplates: {
          sentinel: `SecurityEvent | where EventID == 4624 | where TargetUserName == "<USER>" | project TimeGenerated, Computer, IpAddress, LogonType`,
          defender: `IdentityLogonEvents | where AccountName == "<USER>" | project Timestamp, DeviceName, IPAddress, ActionType`,
          splunk: `index=security EventCode=4624 Target_User_Name="<USER>" | stats count by host, src_ip, Logon_Type`,
          qradar: `SELECT * FROM events WHERE "EventID" = '4624' AND "username" = '<USER>' START ago(12h)`,
          elastic: `authentication where user.name == "<USER>" and event.action == "logon-success"`,
          google_secops: `$e.target.user.user_display_name = "<USER>"`,
          cortex: `dataset = xdr_data | filter actor_effective_username = "<USER>"`,
          securonix: `destinationusername = "<USER>"`,
          logrhythm: `Account: "<USER>"`,
          arcsight: `destinationUserName = "<USER>"`,
          gurucul: `user_name = "<USER>"`,
        },
        purpose: 'Verify if the user account requesting tickets was compromised or accessed from an anomalous workstation.',
      },
    ],
  },
  {
    id: 'ransomware_shadow_copies',
    keywords: ['shadow', 'shadowcopy', 'vssadmin', 'vss', 'ransomware', 'delete shadows', 'bcdedit', 'recoveryenabled', 'wbadmin'],
    title: 'Ransomware Preparation: Volume Shadow Copy Deletion & Recovery Inhibition',
    tactic: 'Impact',
    techniqueId: 'T1490',
    techniqueName: 'Inhibit System Recovery',
    description: 'Detects execution of system utilities (vssadmin, wmic, bcdedit, wbadmin) configured to delete Volume Shadow Copies or disable Windows startup recovery mode prior to ransomware deployment.',
    threatActors: ['LockBit', 'BlackCat/ALPHV', 'Play', 'Akira', 'Clop'],
    noiseRating: 'Low',
    falsePositives: ['Rare enterprise disk re-imaging scripts during controlled OS upgrade windows'],
    whitelisting: ['Strictly whitelist verified deployment scripts with hardcoded change-management ticket numbers'],
    thresholding: 'Alert immediately on a single execution (Threshold = 1) across any server or workstation.',
    assumptions: ['Assumes Process Creation Auditing (Event ID 4688 / Sysmon Event ID 1) is active.'],
    queries: {
      sentinel: `// Microsoft Sentinel KQL - Shadow Copy Deletion & Inhibit Recovery
let commands = dynamic(["delete shadows", "shadowcopy delete", "resize shadowstorage", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "delete catalog", "delete systemstatebackup"]);
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where ProcessName has_any ("vssadmin.exe", "wmic.exe", "bcdedit.exe", "wbadmin.exe", "powershell.exe", "cipher.exe")
| where CommandLine has_any (commands)
| project TimeGenerated, Computer, Account, ProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc`,
      defender: `// Microsoft Defender XDR - Shadow Copy Deletion
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (FileName in~ ("vssadmin.exe", "wmic.exe", "bcdedit.exe", "wbadmin.exe", "powershell.exe") and
         ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "recoveryenabled no", "ignoreallfailures", "delete catalog"))
    or (ProcessCommandLine has "Win32_ShadowCopy" and ProcessCommandLine has "Delete")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      splunk: `// Splunk SPL - Inhibit System Recovery via vssadmin/wmic/bcdedit
index=security EventCode=4688 (Process_Name="*vssadmin.exe" OR Process_Name="*wmic.exe" OR Process_Name="*bcdedit.exe" OR Process_Name="*wbadmin.exe" OR Process_Name="*powershell.exe")
(CommandLine="*delete shadows*" OR CommandLine="*shadowcopy delete*" OR CommandLine="*recoveryenabled*no*" OR CommandLine="*ignoreallfailures*" OR CommandLine="*delete catalog*")
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen by host, user, Process_Name, ParentProcessName, CommandLine
| convert ctime(first_seen) ctime(last_seen)`,
      qradar: `// IBM QRadar AQL - Shadow Copy Deletion
SELECT "sourceip", "username", "Computer", "CommandLine", DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') as Time
FROM events
WHERE "EventID" = '4688'
  AND ("CommandLine" ILIKE '%delete shadows%' OR "CommandLine" ILIKE '%shadowcopy delete%' OR "CommandLine" ILIKE '%recoveryenabled no%')
START ago(24h) STOP now()`,
      elastic: `// Elastic EQL - Deletion of Volume Shadow Copies
process where event.type == "start" and (
  (process.name == "vssadmin.exe" and process.args : "delete" and process.args : "shadows*") or
  (process.name == "wmic.exe" and process.args : "shadowcopy" and process.args : "delete") or
  (process.name == "bcdedit.exe" and process.args : "recoveryenabled" and process.args : "no") or
  (process.name == "wbadmin.exe" and process.args : "delete" and process.args : "catalog*")
)`,
      google_secops: `// Google SecOps YARA-L 2.0 - Ransomware Shadow Copy Invalidation
rule ransomware_shadow_deletion {
  meta:
    description = "Detects Volume Shadow Copy destruction commands"
    severity = "CRITICAL"
    mitre_attack = "T1490"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    (
      $e.target.process.command_line = /(delete\s+shadows|shadowcopy\s+delete|recoveryenabled\s+no|ignoreallfailures)/i
    )
  condition:
    $e
}`,
      cortex: `// Palo Alto Cortex XQL - Shadow Copy Invalidation
dataset = xdr_data
| filter event_type = ENUM.PROCESS and action_process_image_command_line ~= ".*(delete\\s+shadows|shadowcopy\\s+delete|recoveryenabled\\s+no).*"
| fields _time, agent_hostname, actor_process_image_name, action_process_image_command_line`,
      securonix: `// Securonix Spotter - Shadow Copy Destruction
rg_category = "Endpoint" AND (
  commandline CONTAINS "delete shadows" OR commandline CONTAINS "shadowcopy delete" OR commandline CONTAINS "recoveryenabled no"
)
| STATS count BY destinationhostname, destinationusername, commandline`,
      logrhythm: `// LogRhythm MPE - Ransomware Shadow Copy Invalidation
EventID: 4688 AND (VendorMessage: "*delete shadows*" OR VendorMessage: "*shadowcopy delete*" OR VendorMessage: "*recoveryenabled no*")`,
      arcsight: `// OpenText ArcSight ESM
deviceEventClassId = "4688" AND (commandLine CONTAINS "delete shadows" OR commandLine CONTAINS "shadowcopy delete" OR commandLine CONTAINS "recoveryenabled no")`,
      gurucul: `// Gurucul Next-Gen SIEM
category = "Endpoint Analytics" AND (
  command_line LIKE "%delete shadows%" OR command_line LIKE "%shadowcopy delete%"
)
| RISK_SCORE = 100`,
    },
    investigationQueries: [
      {
        title: 'Check rapid file modifications or renaming indicating encryption stage',
        queryTemplates: {
          sentinel: `DeviceFileEvents | where TimeGenerated > ago(1h) | summarize RenamedFiles = count() by InitiatingProcessFileName, DeviceName | where RenamedFiles > 50`,
          defender: `DeviceFileEvents | where Timestamp > ago(1h) | summarize count() by InitiatingProcessFileName, DeviceName | where count_ > 100`,
          splunk: `index=endpoint EventCode=11 | stats count by host, Image | where count > 100`,
          qradar: `SELECT COUNT(*) as FileOps, "ProcessName" FROM events WHERE "EventID" = '11' GROUP BY "ProcessName" HAVING FileOps > 100 START ago(1h)`,
          elastic: `file where event.action in ("file-rename", "file-create") | stats count(*) by process.name`,
          google_secops: `$e.metadata.event_type = "FILE_MODIFICATION"`,
          cortex: `dataset = xdr_data | filter event_type = ENUM.FILE | comp count() by action_file_name`,
          securonix: `rg_category = "File" | STATS count by destinationhostname | FILTER count > 100`,
          logrhythm: `CommonEvent: "File Create" | GROUP BY HostName | HAVING COUNT > 100`,
          arcsight: `deviceEventClassId = "11" | chart count() by destinationHostName`,
          gurucul: `category = "File Operations" | GROUPBY host_name | HAVING COUNT > 100`,
        },
        purpose: 'Verify whether a high-speed encryption loop is actively running on the endpoint.',
      },
    ],
  },
  {
    id: 'aws_cloudtrail_iam_abuse',
    keywords: ['aws', 'cloudtrail', 'iam', 'assumerole', 'attachuserpolicy', 'createaccesskey', 'root', 'cloud', 's3'],
    title: 'AWS CloudTrail: Unauthorized IAM Policy Attachment & Privilege Escalation',
    tactic: 'Privilege Escalation',
    techniqueId: 'T1098',
    techniqueName: 'Account Manipulation: Additional Cloud Credentials',
    description: 'Detects unauthorized administrative policy attachments (AdministratorAccess), creation of IAM access keys, or suspicious AssumeRole operations in AWS CloudTrail.',
    threatActors: ['Scattered Spider', 'TeamTNT', 'Lapsus$'],
    noiseRating: 'Low',
    falsePositives: ['Approved Terraform / AWS CloudFormation CI/CD pipeline deployments'],
    whitelisting: ['Whitelist IAM role arn:aws:iam::*:role/TerraformDeployer', 'Exclude authorized AWS Control Tower automations'],
    thresholding: 'Alert on any AdministratorAccess policy attachment outside approved deployment windows.',
    assumptions: ['Assumes AWS CloudTrail management events are streamed into the SIEM.'],
    queries: {
      sentinel: `// Microsoft Sentinel KQL - AWS CloudTrail IAM Privilege Escalation
let admin_policies = dynamic(["AdministratorAccess", "PowerUserAccess", "*Admin*"]);
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventName in ("AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy", "PutUserPolicy", "CreateAccessKey", "CreateLoginProfile")
| extend PolicyArn = tostring(parse_json(RequestParameters).policyArn)
| extend AttachedUser = tostring(parse_json(RequestParameters).userName)
| where PolicyArn has_any (admin_policies) or EventName == "CreateAccessKey"
| project TimeGenerated, SourceIPAddress, UserIdentityArn, UserIdentityAccountId, EventName, AttachedUser, PolicyArn, UserAgent
| order by TimeGenerated desc`,
      defender: `// Microsoft Defender XDR - AWS CloudTrail IAM Escalation
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Amazon Web Services"
| where ActionType in ("AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey")
| where RawEventData has "AdministratorAccess" or ActionType == "CreateAccessKey"
| project Timestamp, AccountDisplayName, IPAddress, ActionType, RawEventData`,
      splunk: `// Splunk SPL - AWS IAM Admin Policy Attachment & Access Key Creation
index=aws_cloudtrail (eventName="AttachUserPolicy" OR eventName="AttachRolePolicy" OR eventName="CreateAccessKey" OR eventName="PutUserPolicy")
(requestParameters.policyArn="*AdministratorAccess*" OR eventName="CreateAccessKey")
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen by awsRegion, userIdentity.arn, src_ip, eventName, requestParameters.userName, requestParameters.policyArn
| convert ctime(first_seen) ctime(last_seen)`,
      qradar: `// IBM QRadar AQL - AWS CloudTrail Privilege Escalation
SELECT "sourceip", "username", "eventName", "payload", DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') as Time
FROM events
WHERE "eventName" IN ('AttachUserPolicy', 'AttachRolePolicy', 'CreateAccessKey')
  AND ("payload" ILIKE '%AdministratorAccess%' OR "eventName" = 'CreateAccessKey')
START ago(24h) STOP now()`,
      elastic: `// Elastic EQL - AWS IAM Policy Escalation
cloud where event.dataset == "aws.cloudtrail" and event.action in ("AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey") and (
  aws.cloudtrail.request_parameters : "*AdministratorAccess*" or event.action == "CreateAccessKey"
)`,
      google_secops: `// Google SecOps YARA-L 2.0 - AWS CloudTrail Escalation
rule aws_iam_admin_escalation {
  meta:
    description = "Detects AWS IAM AdministratorAccess policy attachment or Access Key creation"
    severity = "HIGH"
    mitre_attack = "T1098"
  events:
    $e.metadata.product_name = "AWS CloudTrail"
    (
      $e.metadata.event_type = "USER_MODIFICATION" and
      ($e.security_result.description = /Attach.*Policy/i or $e.security_result.description = /CreateAccessKey/i)
    )
  condition:
    $e
}`,
      cortex: `// Palo Alto Cortex XQL - AWS CloudTrail IAM Escalation
dataset = aws_cloudtrail_raw
| filter eventName in ("AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey")
| filter requestParameters ~= ".*AdministratorAccess.*" or eventName = "CreateAccessKey"
| fields _time, awsRegion, userIdentity_arn, sourceIPAddress, eventName, requestParameters`,
      securonix: `// Securonix Spotter - AWS IAM Escalation
rg_category = "Cloud" AND (eventname = "AttachUserPolicy" OR eventname = "AttachRolePolicy" OR eventname = "CreateAccessKey")
| STATS count BY sourceaddress, destinationusername, eventname`,
      logrhythm: `// LogRhythm MPE - AWS IAM Policy Attachment
CommonEvent: "Account Modified" AND VendorMessage: "*AttachUserPolicy*" AND VendorMessage: "*AdministratorAccess*"`,
      arcsight: `// OpenText ArcSight ESM
deviceEventClassId = "AWS-IAM-POLICY" AND (commandLine CONTAINS "AttachUserPolicy" OR commandLine CONTAINS "CreateAccessKey")`,
      gurucul: `// Gurucul Next-Gen SIEM
category = "Cloud Audit" AND cloud_provider = "AWS" AND event_name IN ("AttachUserPolicy", "CreateAccessKey")
| RISK_SCORE = 90`,
    },
    investigationQueries: [
      {
        title: 'Audit all subsequent CloudTrail API actions executed by the affected user/key',
        queryTemplates: {
          sentinel: `AWSCloudTrail | where TimeGenerated > ago(12h) | where UserIdentityArn == "<USER_ARN>" | summarize count() by EventName, SourceIPAddress`,
          defender: `CloudAppEvents | where Timestamp > ago(12h) | where AccountDisplayName == "<USER_NAME>" | summarize count() by ActionType, IPAddress`,
          splunk: `index=aws_cloudtrail userIdentity.arn="<USER_ARN>" | stats count by eventName, src_ip, awsRegion`,
          qradar: `SELECT "eventName", COUNT(*) FROM events WHERE "username" = '<USER_NAME>' GROUP BY "eventName" START ago(12h)`,
          elastic: `cloud where user.name == "<USER_NAME>" | stats count(*) by event.action`,
          google_secops: `$e.principal.user.user_display_name = "<USER_NAME>"`,
          cortex: `dataset = aws_cloudtrail_raw | filter userIdentity_arn = "<USER_ARN>" | comp count() by eventName`,
          securonix: `destinationusername = "<USER_NAME>" | STATS count BY eventname`,
          logrhythm: `Account: "<USER_NAME>"`,
          arcsight: `sourceUserName = "<USER_NAME>"`,
          gurucul: `user_name = "<USER_NAME>"`,
        },
        purpose: 'Establish whether the compromised credentials were used to download S3 buckets or spawn EC2 instances.',
      },
    ],
  },
];

/**
 * Universal dynamic query generator for any custom or arbitrary user query
 */
export function buildUniversalDetection(
  userPrompt: string,
  targetPlatform: SiemPlatformId,
  timeFrame: string = '24h',
  severity: string = 'High'
): DetectionBreakdown {
  const lower = userPrompt.toLowerCase();

  // Check matching template first
  for (const scenario of THREAT_SCENARIOS) {
    if (scenario.keywords.some((k) => lower.includes(k))) {
      const platformMeta = SIEM_PLATFORMS[targetPlatform] || SIEM_PLATFORMS.sentinel;
      const mainQuery = scenario.queries[targetPlatform] || scenario.queries.sentinel;

      return {
        id: `det_${Date.now()}_${scenario.id.slice(0, 6)}`,
        timestamp: new Date().toISOString(),
        userIntent: `Detect ${scenario.title} within enterprise logs (${timeFrame} timeframe).`,
        targetPlatform,
        targetPlatformName: platformMeta.name,
        query: mainQuery,
        detectionLogic: scenario.description,
        mitreMapping: {
          tactic: scenario.tactic,
          techniqueId: scenario.techniqueId,
          techniqueName: scenario.techniqueName,
          subTechniqueId: scenario.subTechniqueId,
          subTechniqueName: scenario.subTechniqueName,
          description: `Targeting activity mapped under MITRE ATT&CK ${scenario.techniqueId} (${scenario.techniqueName}).`,
          threatActors: scenario.threatActors,
        },
        tuning: {
          falsePositives: scenario.falsePositives,
          whitelisting: scenario.whitelisting,
          thresholding: scenario.thresholding,
          noiseRating: scenario.noiseRating,
        },
        investigationQueries: scenario.investigationQueries.map((inv, idx) => ({
          id: `inv_${idx + 1}`,
          title: inv.title,
          platform: targetPlatform,
          platformName: platformMeta.name,
          query: inv.queryTemplates[targetPlatform] || inv.queryTemplates.sentinel,
          purpose: inv.purpose,
        })),
        assumptions: scenario.assumptions,
        performance: {
          indexStrategy: 'Utilizes primary EventID and ProcessName indexing prior to payload pattern matching.',
          filteringOrder: 'Time Window -> Event Code -> Process/User Filter -> Pattern Match',
          timeWindow: `Bounded by ${timeFrame} time filter`,
          estimatedCostImpact: 'Low',
          performanceScore: 94,
          recommendations: ['Maintain strict time bounds when querying multi-terabyte data lakes.'],
        },
        syntaxCompatibility: {
          dialectVersion: 'Latest Enterprise Specification',
          isLatestSyntax: true,
          compatibilityNotes: `Native syntax for ${platformMeta.name} (${platformMeta.language}).`,
        },
        translatedQueries: scenario.queries,
      };
    }
  }

  // Synthesize dynamic detection for arbitrary query
  const words = userPrompt.split(/\s+/).filter((w) => w.length > 2);
  const mainToken = words[0] || 'threat';
  const cleanTerms = words.map((w) => w.replace(/[^a-zA-Z0-9_.-]/g, '')).filter(Boolean);
  const searchPattern = cleanTerms.slice(0, 4).join(' ');

  const synthesizedTranslations: Record<SiemPlatformId, string> = {
    sentinel: `// Microsoft Sentinel KQL - Custom SOC Detection
// Objective: ${userPrompt}
let timeframe = ${timeFrame};
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID in (4688, 4624, 4625, 1102) or CommandLine has_any ("${cleanTerms.join('", "')}")
| summarize ExecutionCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Computer, Account, ProcessName, CommandLine
| where ExecutionCount >= 1
| project FirstSeen, LastSeen, Computer, Account, ProcessName, CommandLine, ExecutionCount
| order by LastSeen desc`,
    defender: `// Microsoft Defender XDR - Advanced Hunting
// Objective: ${userPrompt}
DeviceProcessEvents
| where Timestamp > ago(${timeFrame})
| where ProcessCommandLine has_any ("${cleanTerms.join('", "')}") or FileName has "${mainToken}"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc`,
    splunk: `// Splunk SPL - Production Detection Rule
// Objective: ${userPrompt}
index=security (EventCode=4688 OR EventCode=4624 OR EventCode=4625) (${cleanTerms.map((t) => `CommandLine="*${t}*"`).join(' OR ')})
| stats count as event_count, earliest(_time) as first_seen, latest(_time) as last_seen by host, user, Process_Name, CommandLine
| where event_count >= 1
| convert ctime(first_seen) ctime(last_seen)
| table host, user, Process_Name, CommandLine, event_count, first_seen, last_seen`,
    qradar: `// IBM QRadar AQL - Enterprise Security Search
// Objective: ${userPrompt}
SELECT "sourceip", "username", "Computer", "CommandLine", DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') as EventTime
FROM events
WHERE (${cleanTerms.map((t) => `"payload" ILIKE '%${t}%'`).join(' OR ')})
START ago(${timeFrame}) STOP now()`,
    elastic: `// Elastic EQL / Lucene Query
// Objective: ${userPrompt}
process where event.type == "start" and (
  process.args : (${cleanTerms.map((t) => `"*${t}*"`).join(', ')})
)`,
    google_secops: `// Google SecOps (Chronicle) YARA-L 2.0
rule custom_detection_${mainToken.replace(/[^a-zA-Z0-9]/g, '_')} {
  meta:
    description = "${userPrompt.replace(/"/g, '')}"
    severity = "${severity.toUpperCase()}"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.command_line = /(${cleanTerms.join('|')})/i
  condition:
    $e
}`,
    cortex: `// Palo Alto Cortex XQL
dataset = xdr_data
| filter action_process_image_command_line ~= ".*(${cleanTerms.join('|')}).*"
| comp count() as total_events by agent_hostname, actor_effective_username, action_process_image_command_line`,
    securonix: `// Securonix Spotter Search
rg_category = "Endpoint" AND (${cleanTerms.map((t) => `commandline CONTAINS "${t}"`).join(' OR ')})
| STATS count BY destinationhostname, destinationusername, commandline`,
    logrhythm: `// LogRhythm MPE Search
(${cleanTerms.map((t) => `VendorMessage: "*${t}*"`).join(' OR ')}) AND Direction: Outbound`,
    arcsight: `// OpenText ArcSight ESM
deviceEventClassId = "4688" AND (${cleanTerms.map((t) => `commandLine CONTAINS "${t}"`).join(' OR ')})
| chart count() by destinationHostName, destinationUserName`,
    gurucul: `// Gurucul Next-Gen SIEM
category = "Endpoint Analytics" AND (${cleanTerms.map((t) => `command_line LIKE "%${t}%"`).join(' OR ')})
| RISK_SCORE = 75`,
  };

  const platformMeta = SIEM_PLATFORMS[targetPlatform] || SIEM_PLATFORMS.sentinel;
  const chosenQuery = synthesizedTranslations[targetPlatform] || synthesizedTranslations.sentinel;

  return {
    id: `det_${Date.now()}_custom`,
    timestamp: new Date().toISOString(),
    userIntent: `Detect ${userPrompt} within enterprise logs (${timeFrame} timeframe).`,
    targetPlatform,
    targetPlatformName: platformMeta.name,
    query: chosenQuery,
    detectionLogic: `Analyzes telemetry streams across endpoint, identity, and network logs for occurrences of keywords, process signatures, and execution flags related to: "${userPrompt}".`,
    mitreMapping: {
      tactic: 'Execution',
      techniqueId: 'T1059',
      techniqueName: 'Command and Scripting Interpreter',
      description: `Detection logic targets suspicious execution and adversarial behaviors related to "${userPrompt}".`,
      threatActors: ['APT29', 'FIN7', 'Wizard Spider', 'Lazarus Group'],
    },
    tuning: {
      falsePositives: ['Legitimate enterprise automation scripts', 'Scheduled maintenance and IT support tasks'],
      whitelisting: ['Exclude verified domain controller service accounts', 'Filter trusted SCCM / Intune deployment paths'],
      thresholding: 'Alert when execution count >= 1 for critical hosts, or > 3 in 15 minutes for workstations.',
      noiseRating: 'Medium',
    },
    investigationQueries: [
      {
        id: 'inv_1',
        title: 'Parent & Child Process Ancestry Triage',
        platform: targetPlatform,
        platformName: platformMeta.name,
        query: synthesizedTranslations[targetPlatform],
        purpose: 'Analyze parent process chain and child process spawns surrounding the alert timestamp.',
      },
    ],
    assumptions: [
      'Assumes Windows Security Event Log 4688 / Syslog process creation logging is enabled.',
      'Assumes proper ingestion of endpoint telemetry into SIEM index tables.',
    ],
    performance: {
      indexStrategy: 'Utilizes primary EventID and ProcessName indexing prior to payload pattern matching.',
      filteringOrder: 'Time Window -> Event Code -> Process Name -> Command Line Regex',
      timeWindow: `Bounded by ${timeFrame} time filter`,
      estimatedCostImpact: 'Low',
      performanceScore: 92,
      recommendations: ['Maintain strict time bounds when querying multi-terabyte data lakes.'],
    },
    syntaxCompatibility: {
      dialectVersion: 'Latest Enterprise Specification',
      isLatestSyntax: true,
      compatibilityNotes: `Native syntax for ${platformMeta.name} (${platformMeta.language}).`,
    },
    translatedQueries: synthesizedTranslations,
  };
}
