import React, { useState } from 'react';
import { Table, Database, Layers, Search, Code, Shield, Check, Copy } from 'lucide-react';

interface CheatSheetViewProps {
  onSelectPrompt?: (promptText: string) => void;
}

export const CheatSheetView: React.FC<CheatSheetViewProps> = () => {
  const [activeTab, setActiveTab] = useState<'tables' | 'fields' | 'operators'>('tables');
  const [searchFilter, setSearchFilter] = useState('');

  // 1. GENERIC LOG SOURCES & TABLES COMPARISON (9 SIEM PLATFORMS)
  const TABLE_MAPPINGS = [
    {
      telemetryType: 'Windows Event Logs (System/Security/App)',
      sentinel: 'SecurityEvent / Event / Syslog',
      defender: 'DeviceEvents / DeviceProcessEvents',
      splunk: 'sourcetype=WinEventLog:*',
      qradar: 'FROM events WHERE devicetype = Windows',
      logrhythm: 'Log Source Type = "Windows Event Log"',
      securonix: 'rg_category="Windows Security"',
      gurucul: 'category="Windows Event Log"',
      rapid7: 'where(asset_type = windows)',
      elastic: 'logs-windows.sysmon_operational-*',
    },
    {
      telemetryType: 'Process Creation (Sysmon / Windows 4688)',
      sentinel: 'SecurityEvent (4688) / DeviceProcessEvents',
      defender: 'DeviceProcessEvents',
      splunk: 'sourcetype=WinEventLog:Security (4688) / XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (1)',
      qradar: 'FROM events WHERE EventID=4688 OR EventID=1',
      logrhythm: 'MsgID=4688 OR CommonEvent="Process Created"',
      securonix: 'rg_category="Endpoint" AND eventtype="4688"',
      gurucul: 'category="Endpoint" AND event_id="4688"',
      rapid7: 'where(process_launched)',
      elastic: 'logs-endpoint.events.process-*',
    },
    {
      telemetryType: 'Firewall (Palo Alto, Fortinet, Cisco ASA, CheckPoint)',
      sentinel: 'CommonSecurityLog / PaloAltoNetworks / Fortinet',
      defender: 'DeviceNetworkEvents',
      splunk: 'sourcetype=pan:traffic / fortinet:traffic / cisco:asa',
      qradar: 'FROM events WHERE devicetype IN (PaloAlto, Fortigate, CiscoASA)',
      logrhythm: 'CommonEvent="Network Traffic" / Firewall',
      securonix: 'rg_category="Firewall"',
      gurucul: 'category="Network Firewall"',
      rapid7: 'where(ingress_traffic OR egress_traffic)',
      elastic: 'event.category: "network" AND event.kind: "event"',
    },
    {
      telemetryType: 'Web Proxy & SWG (Zscaler, BlueCoat, Netskope, Squid)',
      sentinel: 'CommonSecurityLog (Zscaler/BlueCoat)',
      defender: 'DeviceNetworkEvents (Http)',
      splunk: 'sourcetype=zscaler:proxy / bluecoat:proxysg / squid:access',
      qradar: 'FROM events WHERE devicetype = Proxy',
      logrhythm: 'CommonEvent="Web Traffic / Web Proxy"',
      securonix: 'rg_category="Web Proxy"',
      gurucul: 'category="Web Proxy"',
      rapid7: 'where(web_proxy_activity)',
      elastic: 'event.category: "web" AND event.dataset: "proxy"',
    },
    {
      telemetryType: 'WAF / Web App Firewall (Cloudflare, AWS WAF, F5, Imperva)',
      sentinel: 'W3CIISLog / AzureDiagnostics (WAF) / AWSWAFLogs',
      defender: 'CloudAppEvents (WAF)',
      splunk: 'sourcetype=cloudflare:json / aws:waf / f5:bigip:asm',
      qradar: 'FROM events WHERE devicetype = Web Application Firewall',
      logrhythm: 'CommonEvent="Web Application Security"',
      securonix: 'rg_category="Web Application Firewall"',
      gurucul: 'category="WAF Security"',
      rapid7: 'where(waf_rule_action)',
      elastic: 'event.category: "web" AND event.type: "access"',
    },
    {
      telemetryType: 'Web Servers (IIS, Nginx, Apache HTTPD)',
      sentinel: 'W3CIISLog / ApacheAccess / NginxAccess',
      defender: 'DeviceNetworkEvents (Web)',
      splunk: 'sourcetype=ms:iis:auto / apache:access / nginx:plus:access',
      qradar: 'FROM events WHERE devicetype IN (IIS, Apache, Nginx)',
      logrhythm: 'CommonEvent="Web Server Log"',
      securonix: 'rg_category="Web Server"',
      gurucul: 'category="Web Servers"',
      rapid7: 'where(http_request)',
      elastic: 'event.dataset: ("iis.access" or "nginx.access" or "apache.access")',
    },
    {
      telemetryType: 'Linux / Unix (Syslog, Auth.log, Auditd, Secure, Journald)',
      sentinel: 'Syslog / LinuxAuditLog / Auditd',
      defender: 'DeviceEvents (Linux)',
      splunk: 'sourcetype=syslog / linux_secure / auditd',
      qradar: 'FROM events WHERE devicetype = Linux / OS',
      logrhythm: 'Log Source Type = "Unix / Linux Syslog"',
      securonix: 'rg_category="Linux OS Security"',
      gurucul: 'category="Linux System"',
      rapid7: 'where(os_type = linux)',
      elastic: 'event.dataset: "system.auth" or "auditd"',
    },
    {
      telemetryType: 'PAM / Privileged Access (CyberArk, BeyondTrust, Delinea)',
      sentinel: 'CommonSecurityLog (CyberArk/BeyondTrust)',
      defender: 'IdentityDirectoryEvents (PAM)',
      splunk: 'sourcetype=cyberark:epv / beyondtrust:sra',
      qradar: 'FROM events WHERE devicetype = CyberArk Vault',
      logrhythm: 'CommonEvent="Privileged Access Management"',
      securonix: 'rg_category="PAM Security"',
      gurucul: 'category="Privileged Management"',
      rapid7: 'where(pam_session_started)',
      elastic: 'event.category: "iam" AND event.type: "access"',
    },
    {
      telemetryType: 'Switches & Routers (Cisco IOS, Juniper, Arista, HP)',
      sentinel: 'Syslog (CiscoIOS / JuniperJunOS)',
      defender: 'DeviceNetworkEvents (Infrastructure)',
      splunk: 'sourcetype=cisco:ios / juniper:junos / arista:syslog',
      qradar: 'FROM events WHERE devicetype IN (CiscoIOS, Juniper)',
      logrhythm: 'CommonEvent="Network Device Management"',
      securonix: 'rg_category="Router / Switch"',
      gurucul: 'category="Network Infrastructure"',
      rapid7: 'where(network_device_activity)',
      elastic: 'event.dataset: "cisco.ios" or "juniper.junos"',
    },
    {
      telemetryType: 'Wireless Controllers & APs (Cisco Meraki, Aruba, Ruckus)',
      sentinel: 'Syslog (Meraki / Aruba)',
      defender: 'DeviceNetworkEvents (Wireless)',
      splunk: 'sourcetype=meraki / aruba:syslog / ruckus:wireless',
      qradar: 'FROM events WHERE devicetype = Wireless Controller',
      logrhythm: 'CommonEvent="Wireless Access Point Log"',
      securonix: 'rg_category="Wireless Network"',
      gurucul: 'category="Wireless Controller"',
      rapid7: 'where(wireless_client_connect)',
      elastic: 'event.dataset: "aruba.wireless" or "meraki"',
    },
    {
      telemetryType: 'VPN & Zero Trust (Pulse Secure, GlobalProtect, ZPA, AnyConnect)',
      sentinel: 'CommonSecurityLog (Pulse/GlobalProtect/ZPA)',
      defender: 'DeviceNetworkEvents (VPN)',
      splunk: 'sourcetype=cisco:anyconnect / pan:vpn / pulse:secure',
      qradar: 'FROM events WHERE devicetype = VPN Gateway',
      logrhythm: 'CommonEvent="VPN Session Log"',
      securonix: 'rg_category="VPN Connection"',
      gurucul: 'category="VPN Gateway"',
      rapid7: 'where(vpn_connection)',
      elastic: 'event.category: "network" AND event.type: "connection"',
    },
    {
      telemetryType: 'Database Audit Logs (MSSQL, Oracle, PostgreSQL, MySQL)',
      sentinel: 'AzureDiagnostics (SQL) / Syslog (PostgreSQL)',
      defender: 'CloudAppEvents (Database)',
      splunk: 'sourcetype=mssql:audit / oracle:audit / postgresql',
      qradar: 'FROM events WHERE devicetype IN (Database, Oracle, MSSQL)',
      logrhythm: 'CommonEvent="Database Access / Query"',
      securonix: 'rg_category="Database Security"',
      gurucul: 'category="Database Audit"',
      rapid7: 'where(database_query_executed)',
      elastic: 'event.category: "database"',
    },
    {
      telemetryType: 'User Authentication / Sign-ins (Entra ID, Okta, Duo)',
      sentinel: 'SigninLogs / SecurityEvent (4624)',
      defender: 'DeviceLogonEvents / AADSignInEventsBeta',
      splunk: 'sourcetype=WinEventLog:Security (4624) / okta:im',
      qradar: 'FROM events WHERE category=1001',
      logrhythm: 'MsgID=4624 (User Logon)',
      securonix: 'rg_category="Authentication"',
      gurucul: 'category="Authentication"',
      rapid7: 'where(source_user AND authentication)',
      elastic: 'event.category: "authentication"',
    },
    {
      telemetryType: 'EDR Alerts & Antivirus (CrowdStrike, Defender, SentinelOne)',
      sentinel: 'SecurityAlert / ProtectionStatus',
      defender: 'AlertInfo / AlertEvidence',
      splunk: 'index=alerts sourcetype=crowdstrike:stream / defender:alert',
      qradar: 'FROM offenses / events (Alert)',
      logrhythm: 'CommonEvent="Malware / Threat Alert"',
      securonix: 'rg_category="Antivirus" OR "EDR Alert"',
      gurucul: 'category="Threat Alerts"',
      rapid7: 'where(alert_name)',
      elastic: 'event.kind: "alert"',
    },
    {
      telemetryType: 'Cloud Infrastructure Audit (AWS CloudTrail, Azure, GCP)',
      sentinel: 'AzureActivity / AWSCloudTrail / GCP_Audit',
      defender: 'CloudAppEvents',
      splunk: 'sourcetype=aws:cloudtrail / azure:activity',
      qradar: 'FROM events WHERE devicetype IN (AWS,Azure,GCP)',
      logrhythm: 'CommonEvent="Cloud Activity"',
      securonix: 'rg_category="Cloud Infrastructure"',
      gurucul: 'category="Cloud Audit"',
      rapid7: 'where(cloud_service_activity)',
      elastic: 'event.dataset: "aws.cloudtrail"',
    },
    {
      telemetryType: 'Email Gateway & Phishing (Proofpoint, Mimecast, O365)',
      sentinel: 'EmailEvents / EmailAttachmentInfo',
      defender: 'EmailEvents / EmailUrlInfo',
      splunk: 'sourcetype=proofpoint:pps / mimecast:audit',
      qradar: 'FROM events WHERE devicetype = Email Gateway',
      logrhythm: 'CommonEvent="Email Message"',
      securonix: 'rg_category="Email Security"',
      gurucul: 'category="Email Gateway"',
      rapid7: 'where(email_received OR phishing)',
      elastic: 'event.category: "email"',
    },
  ];

  // 2. GENERIC FIELDS COMPARISON (9 SIEM PLATFORMS)
  const FIELD_MAPPINGS = [
    {
      fieldConcept: 'Event Timestamp',
      sentinel: 'TimeGenerated',
      defender: 'Timestamp',
      splunk: '_time',
      qradar: 'starttime / devicetime',
      logrhythm: 'LogDate / NormalDate',
      securonix: 'eventtime',
      gurucul: 'event_timestamp',
      rapid7: 'timestamp',
      elastic: '@timestamp',
    },
    {
      fieldConcept: 'Host / Computer Name',
      sentinel: 'Computer / DeviceName',
      defender: 'DeviceName',
      splunk: 'host / dest',
      qradar: 'hostname',
      logrhythm: 'HostName',
      securonix: 'host',
      gurucul: 'device_host',
      rapid7: 'destination_address / hostname',
      elastic: 'host.name',
    },
    {
      fieldConcept: 'User / Account Name',
      sentinel: 'Account / TargetUserName',
      defender: 'AccountName',
      splunk: 'user / Account_Name',
      qradar: 'username',
      logrhythm: 'User',
      securonix: 'customstring1 / username',
      gurucul: 'user_id',
      rapid7: 'source_user',
      elastic: 'user.name',
    },
    {
      fieldConcept: 'Process Name / Image',
      sentinel: 'Process / NewProcessName',
      defender: 'FileName / ProcessCommandLine',
      splunk: 'process_name / New_Process_Name',
      qradar: 'processname',
      logrhythm: 'ProcessName',
      securonix: 'processname',
      gurucul: 'process_name',
      rapid7: 'process.name',
      elastic: 'process.name',
    },
    {
      fieldConcept: 'Parent Process Name',
      sentinel: 'ParentProcessName',
      defender: 'InitiatingProcessFileName',
      splunk: 'parent_process_name',
      qradar: 'parentprocessname',
      logrhythm: 'ParentProcessName',
      securonix: 'parentprocessname',
      gurucul: 'parent_process_name',
      rapid7: 'parent_process.name',
      elastic: 'process.parent.name',
    },
    {
      fieldConcept: 'Process Command Line',
      sentinel: 'CommandLine',
      defender: 'ProcessCommandLine',
      splunk: 'command_line / process',
      qradar: 'cmdline',
      logrhythm: 'Command',
      securonix: 'commandline',
      gurucul: 'cmd_line',
      rapid7: 'process.cmd',
      elastic: 'process.command_line',
    },
    {
      fieldConcept: 'Source IP Address',
      sentinel: 'IpAddress / SourceIP',
      defender: 'RemoteIP / LocalIP',
      splunk: 'src_ip / src',
      qradar: 'sourceip',
      logrhythm: 'SIP',
      securonix: 'ipaddress',
      gurucul: 'src_ip',
      rapid7: 'source_address',
      elastic: 'source.ip',
    },
    {
      fieldConcept: 'Destination IP Address',
      sentinel: 'DestinationIP',
      defender: 'RemoteIP',
      splunk: 'dest_ip / dest',
      qradar: 'destinationip',
      logrhythm: 'DIP',
      securonix: 'destinationip',
      gurucul: 'dest_ip',
      rapid7: 'destination_address',
      elastic: 'destination.ip',
    },
    {
      fieldConcept: 'Source Port',
      sentinel: 'SourcePort',
      defender: 'LocalPort',
      splunk: 'src_port',
      qradar: 'sourceport',
      logrhythm: 'SPort',
      securonix: 'sourceport',
      gurucul: 'src_port',
      rapid7: 'source_port',
      elastic: 'source.port',
    },
    {
      fieldConcept: 'Destination Port',
      sentinel: 'DestinationPort',
      defender: 'RemotePort',
      splunk: 'dest_port',
      qradar: 'destinationport',
      logrhythm: 'DPort',
      securonix: 'destinationport',
      gurucul: 'dest_port',
      rapid7: 'destination_port',
      elastic: 'destination.port',
    },
    {
      fieldConcept: 'File Hash (SHA256)',
      sentinel: 'SHA256 / FileHash',
      defender: 'SHA256',
      splunk: 'sha256 / file_hash',
      qradar: 'hash',
      logrhythm: 'Hash',
      securonix: 'filehash',
      gurucul: 'sha256_hash',
      rapid7: 'hash.sha256',
      elastic: 'file.hash.sha256',
    },
    {
      fieldConcept: 'File Path / Directory',
      sentinel: 'FilePath',
      defender: 'FolderPath',
      splunk: 'file_path',
      qradar: 'filename',
      logrhythm: 'FilePath',
      securonix: 'filepath',
      gurucul: 'file_path',
      rapid7: 'file_path',
      elastic: 'file.path',
    },
    {
      fieldConcept: 'HTTP URL / Request Path',
      sentinel: 'Url / CsUriStem',
      defender: 'RemoteUrl',
      splunk: 'url / uri_path',
      qradar: 'url',
      logrhythm: 'URL',
      securonix: 'requesturl',
      gurucul: 'url_path',
      rapid7: 'url',
      elastic: 'url.full / url.path',
    },
    {
      fieldConcept: 'HTTP Status Code',
      sentinel: 'HttpStatusCode / ScStatus',
      defender: 'AdditionalFields.StatusCode',
      splunk: 'status / http_status',
      qradar: 'statuscode',
      logrhythm: 'ResponseCode',
      securonix: 'statuscode',
      gurucul: 'http_status',
      rapid7: 'status_code',
      elastic: 'http.response.status_code',
    },
    {
      fieldConcept: 'HTTP Method (GET/POST)',
      sentinel: 'CsMethod',
      defender: 'AdditionalFields.Method',
      splunk: 'http_method / method',
      qradar: 'requestmethod',
      logrhythm: 'Method',
      securonix: 'httpmethod',
      gurucul: 'http_method',
      rapid7: 'method',
      elastic: 'http.request.method',
    },
    {
      fieldConcept: 'WAF Rule / Policy Action',
      sentinel: 'Action / ActionTaken',
      defender: 'ActionType',
      splunk: 'action / waf_action',
      qradar: 'action',
      logrhythm: 'Action',
      securonix: 'policyaction',
      gurucul: 'waf_action',
      rapid7: 'waf_rule_action',
      elastic: 'event.outcome',
    },
    {
      fieldConcept: 'MAC Address / Hardware ID',
      sentinel: 'MacAddress',
      defender: 'MacAddress',
      splunk: 'mac / src_mac',
      qradar: 'macaddress',
      logrhythm: 'MACAddress',
      securonix: 'macaddress',
      gurucul: 'mac_id',
      rapid7: 'source_mac',
      elastic: 'source.mac',
    },
    {
      fieldConcept: 'Wireless SSID / Network',
      sentinel: 'SSID',
      defender: 'AdditionalFields.SSID',
      splunk: 'ssid / wifi_network',
      qradar: 'ssid',
      logrhythm: 'SSID',
      securonix: 'ssid',
      gurucul: 'wifi_ssid',
      rapid7: 'wireless_network_name',
      elastic: 'wireless.ssid',
    },
    {
      fieldConcept: 'PAM Session ID / Ticket',
      sentinel: 'SessionId',
      defender: 'AdditionalFields.SessionId',
      splunk: 'session_id / ticket_id',
      qradar: 'sessionid',
      logrhythm: 'SessionID',
      securonix: 'sessionid',
      gurucul: 'pam_session_id',
      rapid7: 'session_id',
      elastic: 'service.id',
    },
    {
      fieldConcept: 'Database Query / SQL Statement',
      sentinel: 'Statement / QueryText',
      defender: 'AdditionalFields.Query',
      splunk: 'query / sql_statement',
      qradar: 'sqlstatement',
      logrhythm: 'Object',
      securonix: 'sqlquery',
      gurucul: 'sql_text',
      rapid7: 'database_query',
      elastic: 'db.statement',
    },
  ];

  // 3. GENERIC SYNTAX OPERATORS COMPARISON (9 SIEM PLATFORMS)
  const OPERATOR_MAPPINGS = [
    {
      concept: 'Table / Index Selection',
      sentinel: 'SecurityEvent',
      defender: 'DeviceProcessEvents',
      splunk: 'index=security sourcetype=WinEventLog',
      qradar: 'FROM events',
      logrhythm: 'LogRhythm Search Engine',
      securonix: 'rg_category="Endpoint"',
      gurucul: 'category="Endpoint"',
      rapid7: 'where(process_launched)',
      elastic: 'logs-endpoint.events.process-*',
    },
    {
      concept: 'Filtering Rows (Where)',
      sentinel: '| where EventID == 4688',
      defender: '| where ActionType == "ProcessCreated"',
      splunk: 'EventCode=4688',
      qradar: 'WHERE EventID=4688',
      logrhythm: 'MsgID=4688',
      securonix: 'AND eventtype="4688"',
      gurucul: 'AND event_id="4688"',
      rapid7: 'where(event_id = 4688)',
      elastic: 'event.code: "4688"',
    },
    {
      concept: 'String Contains (Insensitive)',
      sentinel: '| where CommandLine has "powershell"',
      defender: '| where ProcessCommandLine has "powershell"',
      splunk: 'CommandLine="*powershell*"',
      qradar: 'payload ILIKE "%powershell%"',
      logrhythm: 'Command CONTAINS "powershell"',
      securonix: 'commandline CONTAINS "powershell"',
      gurucul: 'cmd_line LIKE "%powershell%"',
      rapid7: 'where(process.cmd = /powershell/i)',
      elastic: 'process.args: "*powershell*"',
    },
    {
      concept: 'Regex Matching',
      sentinel: '| where CommandLine matches regex @"vssadmin.*delete"',
      defender: '| where ProcessCommandLine matches regex @"..."',
      splunk: '| regex CommandLine="vssadmin.*delete"',
      qradar: 'payload MATCHES "vssadmin.*delete"',
      logrhythm: 'Command REGEX "vssadmin.*delete"',
      securonix: 'commandline REGEX "vssadmin.*delete"',
      gurucul: 'cmd_line REGEX "vssadmin.*delete"',
      rapid7: 'where(process.cmd = /vssadmin.*delete/i)',
      elastic: 'process.command_line matches "vssadmin.*delete"',
    },
    {
      concept: 'Aggregation & Grouping',
      sentinel: '| summarize count() by Account, Computer',
      defender: '| summarize EventCount = count() by AccountName',
      splunk: '| stats count by host, Account_Name',
      qradar: 'GROUP BY username, sourceip',
      logrhythm: 'GROUP BY User, HostName',
      securonix: '| STATS count BY username, host',
      gurucul: 'GROUP BY user_id, device_host',
      rapid7: 'groupby(source_user, hostname) calculate(count)',
      elastic: '| stats count() by user.name, host.name',
    },
    {
      concept: 'Time Range Limit',
      sentinel: '| where TimeGenerated > ago(24h)',
      defender: '| where Timestamp > ago(24h)',
      splunk: 'earliest=-24h latest=now',
      qradar: 'START ago(24h)',
      logrhythm: 'Date Range = Last 24 Hours',
      securonix: 'TIMEDELTA > 24h',
      gurucul: 'time_range="24h"',
      rapid7: 'time(24h)',
      elastic: '@timestamp >= now-24h',
    },
    {
      concept: 'Select Specific Fields',
      sentinel: '| project TimeGenerated, Computer, Account',
      defender: '| project Timestamp, DeviceName, AccountName',
      splunk: '| table _time, host, user',
      qradar: 'SELECT starttime, hostname, username',
      logrhythm: 'SELECT LogDate, HostName, User',
      securonix: '| FIELDS eventtime, host, customstring1',
      gurucul: 'SELECT event_timestamp, device_host, user_id',
      rapid7: 'select(timestamp, hostname, source_user)',
      elastic: '| keep @timestamp, host.name, user.name',
    },
    {
      concept: 'Sorting & Ordering',
      sentinel: '| sort by TimeGenerated desc',
      defender: '| sort by Timestamp desc',
      splunk: '| sort - _time',
      qradar: 'ORDER BY starttime DESC',
      logrhythm: 'ORDER BY LogDate DESC',
      securonix: '| SORT BY eventtime DESC',
      gurucul: 'ORDER BY event_timestamp DESC',
      rapid7: 'sort(timestamp, desc)',
      elastic: '| sort @timestamp desc',
    },
  ];

  // Helper filter function
  const filterList = (items: any[], key: string) => {
    if (!searchFilter.trim()) return items;
    return items.filter((item) =>
      Object.values(item).some((val) =>
        String(val).toLowerCase().includes(searchFilter.toLowerCase())
      )
    );
  };

  return (
    <div className="space-y-6 font-sans text-xs max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl relative overflow-hidden">
        <div className="relative z-10 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-medium">
              <Table className="w-3.5 h-3.5" />
              <span>Multi-Platform SIEM Log Source & Field Matrix</span>
            </div>

            {/* Category Tabs */}
            <div className="flex items-center gap-1 bg-[#060D18] p-1 rounded-xl border border-[#1B3047] text-xs font-medium">
              <button
                onClick={() => setActiveTab('tables')}
                className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                  activeTab === 'tables'
                    ? 'bg-cyan-400 text-[#060D18] font-bold shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Database className="w-3.5 h-3.5" />
                <span>Log Sources & Tables</span>
              </button>
              <button
                onClick={() => setActiveTab('fields')}
                className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                  activeTab === 'fields'
                    ? 'bg-cyan-400 text-[#060D18] font-bold shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Field Identifiers</span>
              </button>
              <button
                onClick={() => setActiveTab('operators')}
                className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                  activeTab === 'operators'
                    ? 'bg-cyan-400 text-[#060D18] font-bold shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Code className="w-3.5 h-3.5" />
                <span>Query Operators</span>
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between flex-wrap gap-4 pt-1">
            <div>
              <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Unified SIEM Field & Log Source Syntax Reference
              </h2>
              <p className="text-slate-400 text-xs max-w-3xl leading-relaxed mt-0.5">
                Comprehensive mapping comparing table schemas, event field identifiers, and query operators across <strong>9 major enterprise SIEM platforms</strong>: Microsoft Sentinel, Defender XDR, Splunk, IBM QRadar, LogRhythm, Securonix, Gurucul, Rapid7, and Elasticsearch.
              </p>
            </div>

            {/* Quick Filter Search Input */}
            <div className="relative min-w-[240px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Search fields or log sources..."
                className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-[#060D18] border border-[#1B3047] text-slate-200 text-xs placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40"
              />
            </div>
          </div>
        </div>
      </div>

      {/* 1. LOG SOURCES & TABLES COMPARISON TABLE */}
      {(activeTab === 'tables' || searchFilter) && (
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden shadow-xl">
          <div className="px-6 py-4 bg-[#060D18] border-b border-[#1B3047] font-bold text-white text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <span>Generic Log Source & Table Names Across 9 SIEM Platforms</span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">13 Telemetry Categories</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[1200px]">
              <thead>
                <tr className="bg-[#060D18] text-slate-400 border-b border-[#1B3047] text-[11px]">
                  <th className="p-3.5 font-bold font-mono min-w-[180px] text-white">Log Source / Telemetry</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-400">Microsoft Sentinel</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-300">Defender XDR</th>
                  <th className="p-3.5 font-bold font-mono text-teal-400">Splunk</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-300">IBM QRadar</th>
                  <th className="p-3.5 font-bold font-mono text-slate-300">LogRhythm</th>
                  <th className="p-3.5 font-bold font-mono text-teal-300">Securonix</th>
                  <th className="p-3.5 font-bold font-mono text-slate-400">Gurucul</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-400">Rapid7</th>
                  <th className="p-3.5 font-bold font-mono text-teal-400">Elasticsearch</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1B3047] text-[11px] text-slate-300 font-mono">
                {filterList(TABLE_MAPPINGS, 'telemetryType').map((row, idx) => (
                  <tr key={idx} className="hover:bg-[#101F32]/50 transition-colors">
                    <td className="p-3.5 font-bold text-white bg-[#060D18] font-sans sticky left-0 z-10 border-r border-[#1B3047]">
                      {row.telemetryType}
                    </td>
                    <td className="p-3.5 text-cyan-200 bg-[#0B1726]/40">{row.sentinel}</td>
                    <td className="p-3.5 text-slate-200">{row.defender}</td>
                    <td className="p-3.5 text-teal-200 bg-[#0B1726]/40">{row.splunk}</td>
                    <td className="p-3.5 text-slate-200">{row.qradar}</td>
                    <td className="p-3.5 text-slate-300 bg-[#0B1726]/40">{row.logrhythm}</td>
                    <td className="p-3.5 text-slate-200">{row.securonix}</td>
                    <td className="p-3.5 text-slate-300 bg-[#0B1726]/40">{row.gurucul}</td>
                    <td className="p-3.5 text-slate-200">{row.rapid7}</td>
                    <td className="p-3.5 text-teal-200 bg-[#0B1726]/40">{row.elastic}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 2. FIELD NAMES COMPARISON TABLE */}
      {(activeTab === 'fields' || searchFilter) && (
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden shadow-xl">
          <div className="px-6 py-4 bg-[#060D18] border-b border-[#1B3047] font-bold text-white text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Generic Field Identifiers Across 9 SIEM Platforms</span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">15 Core Event Attributes</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[1200px]">
              <thead>
                <tr className="bg-[#060D18] text-slate-400 border-b border-[#1B3047] text-[11px]">
                  <th className="p-3.5 font-bold font-mono min-w-[180px] text-white">Field Concept</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-400">Microsoft Sentinel</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-300">Defender XDR</th>
                  <th className="p-3.5 font-bold font-mono text-teal-400">Splunk</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-300">IBM QRadar</th>
                  <th className="p-3.5 font-bold font-mono text-slate-300">LogRhythm</th>
                  <th className="p-3.5 font-bold font-mono text-teal-300">Securonix</th>
                  <th className="p-3.5 font-bold font-mono text-slate-400">Gurucul</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-400">Rapid7</th>
                  <th className="p-3.5 font-bold font-mono text-teal-400">Elasticsearch</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1B3047] text-[11px] text-slate-300 font-mono">
                {filterList(FIELD_MAPPINGS, 'fieldConcept').map((row, idx) => (
                  <tr key={idx} className="hover:bg-[#101F32]/50 transition-colors">
                    <td className="p-3.5 font-bold text-white bg-[#060D18] font-sans sticky left-0 z-10 border-r border-[#1B3047]">
                      {row.fieldConcept}
                    </td>
                    <td className="p-3.5 text-cyan-200 bg-[#0B1726]/40">{row.sentinel}</td>
                    <td className="p-3.5 text-slate-200">{row.defender}</td>
                    <td className="p-3.5 text-teal-200 bg-[#0B1726]/40">{row.splunk}</td>
                    <td className="p-3.5 text-slate-200">{row.qradar}</td>
                    <td className="p-3.5 text-slate-300 bg-[#0B1726]/40">{row.logrhythm}</td>
                    <td className="p-3.5 text-slate-200">{row.securonix}</td>
                    <td className="p-3.5 text-slate-300 bg-[#0B1726]/40">{row.gurucul}</td>
                    <td className="p-3.5 text-slate-200">{row.rapid7}</td>
                    <td className="p-3.5 text-teal-200 bg-[#0B1726]/40">{row.elastic}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 3. SYNTAX OPERATORS COMPARISON TABLE */}
      {(activeTab === 'operators' || searchFilter) && (
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden shadow-xl">
          <div className="px-6 py-4 bg-[#060D18] border-b border-[#1B3047] font-bold text-white text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              <span>Generic Query Operators Across 9 SIEM Platforms</span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">8 Core Operations</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[1200px]">
              <thead>
                <tr className="bg-[#060D18] text-slate-400 border-b border-[#1B3047] text-[11px]">
                  <th className="p-3.5 font-bold font-mono min-w-[180px] text-white">Operator Concept</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-400">Microsoft Sentinel</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-300">Defender XDR</th>
                  <th className="p-3.5 font-bold font-mono text-teal-400">Splunk</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-300">IBM QRadar</th>
                  <th className="p-3.5 font-bold font-mono text-slate-300">LogRhythm</th>
                  <th className="p-3.5 font-bold font-mono text-teal-300">Securonix</th>
                  <th className="p-3.5 font-bold font-mono text-slate-400">Gurucul</th>
                  <th className="p-3.5 font-bold font-mono text-cyan-400">Rapid7</th>
                  <th className="p-3.5 font-bold font-mono text-teal-400">Elasticsearch</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1B3047] text-[11px] text-slate-300 font-mono">
                {filterList(OPERATOR_MAPPINGS, 'concept').map((row, idx) => (
                  <tr key={idx} className="hover:bg-[#101F32]/50 transition-colors">
                    <td className="p-3.5 font-bold text-white bg-[#060D18] font-sans sticky left-0 z-10 border-r border-[#1B3047]">
                      {row.concept}
                    </td>
                    <td className="p-3.5 text-cyan-200 bg-[#0B1726]/40 whitespace-pre">{row.sentinel}</td>
                    <td className="p-3.5 text-slate-200 whitespace-pre">{row.defender}</td>
                    <td className="p-3.5 text-teal-200 bg-[#0B1726]/40 whitespace-pre">{row.splunk}</td>
                    <td className="p-3.5 text-slate-200 whitespace-pre">{row.qradar}</td>
                    <td className="p-3.5 text-slate-300 bg-[#0B1726]/40 whitespace-pre">{row.logrhythm}</td>
                    <td className="p-3.5 text-slate-200 whitespace-pre">{row.securonix}</td>
                    <td className="p-3.5 text-slate-300 bg-[#0B1726]/40 whitespace-pre">{row.gurucul}</td>
                    <td className="p-3.5 text-slate-200 whitespace-pre">{row.rapid7}</td>
                    <td className="p-3.5 text-teal-200 bg-[#0B1726]/40 whitespace-pre">{row.elastic}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};




