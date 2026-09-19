import React, { useState } from 'react';
import { X, Download, Copy, Check, FileJson, FileText, Layers } from 'lucide-react';
import { DetectionBreakdown } from '../types';

interface ExportModalProps {
  detection: DetectionBreakdown;
  onClose: () => void;
}

export const ExportModal: React.FC<ExportModalProps> = ({ detection, onClose }) => {
  const [exportFormat, setExportFormat] = useState<'sentinel_json' | 'splunk_conf' | 'sigma_yaml' | 'markdown'>('sentinel_json');
  const [copied, setCopied] = useState(false);

  const generateExportContent = () => {
    switch (exportFormat) {
      case 'sentinel_json':
        return JSON.stringify(
          {
            $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
            contentVersion: '1.0.0.0',
            resources: [
              {
                type: 'Microsoft.SecurityInsights/alertRules',
                apiVersion: '2022-11-01-preview',
                name: `[SOC] ${detection.mitreMapping.techniqueId} - ${detection.mitreMapping.techniqueName}`,
                properties: {
                  displayName: `[SOC Rule] ${detection.userIntent}`,
                  description: detection.detectionLogic,
                  severity: 'High',
                  enabled: true,
                  query: detection.query,
                  queryFrequency: 'PT1H',
                  queryPeriod: 'PT1H',
                  triggerOperator: 'GreaterThan',
                  triggerThreshold: 0,
                  tactics: [detection.mitreMapping.tactic],
                  techniques: [detection.mitreMapping.techniqueId],
                },
              },
            ],
          },
          null,
          2
        );

      case 'splunk_conf':
        return `[savedsearch: SOC Detection - ${detection.mitreMapping.techniqueId}]
action.email = 1
action.email.to = soc-alerts@company.com
alert.severity = 4
alert.suppress = 0
alert.track = 1
cron_schedule = */15 * * * *
description = ${detection.userIntent} (MITRE ${detection.mitreMapping.techniqueId})
dispatch.earliest_time = -1h
dispatch.latest_time = now
search = ${detection.query}`;

      case 'sigma_yaml':
        return `title: ${detection.mitreMapping.techniqueName} Detection
id: ${detection.id}
status: experimental
description: ${detection.userIntent}
author: CyberSentinel SOC Detection Engineer
references:
    - https://attack.mitre.org/techniques/${detection.mitreMapping.techniqueId.replace('.', '/')}/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
falsepositives:
${detection.tuning.falsePositives.map((fp) => `    - ${fp}`).join('\n')}
level: high
tags:
    - attack.${detection.mitreMapping.tactic.toLowerCase().replace(/\s+/g, '_')}
    - attack.${detection.mitreMapping.techniqueId.toLowerCase()}`;

      case 'markdown':
        return `# SOC Incident Response Detection Specification

## Rule Overview
- **Title**: ${detection.userIntent}
- **Target SIEM**: ${detection.targetPlatformName}
- **MITRE Tactic**: ${detection.mitreMapping.tactic}
- **MITRE Technique**: ${detection.mitreMapping.techniqueId} - ${detection.mitreMapping.techniqueName}

## Detection Query (${detection.targetPlatformName})
\`\`\`
${detection.query}
\`\`\`

## Step-by-Step Logic
${detection.detectionLogic}

## Tuning & Whitelisting
### Recommended Whitelist Filters:
${detection.tuning.whitelisting.map((w) => `- ${w}`).join('\n')}

### False Positive Considerations:
${detection.tuning.falsePositives.map((fp) => `- ${fp}`).join('\n')}

## Triage & Investigation Pivot Queries
${detection.investigationQueries.map((iq) => `### ${iq.title}\n\`\`\`\n${iq.query}\n\`\`\`\n*Purpose*: ${iq.purpose}\n`).join('\n')}
`;
    }
  };

  const exportText = generateExportContent();

  const handleCopy = () => {
    navigator.clipboard.writeText(exportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadFile = () => {
    const ext = exportFormat === 'sentinel_json' ? 'json' : exportFormat === 'sigma_yaml' ? 'yml' : exportFormat === 'splunk_conf' ? 'conf' : 'md';
    const blob = new Blob([exportText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `soc-rule-${detection.id.slice(-6)}.${ext}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="fixed inset-0 z-50 bg-[#060D18]/85 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0B1726] border border-[#1B3047] rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl font-mono text-xs space-y-4 p-6">
        <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Download className="w-5 h-5 text-cyan-400" />
            Export Detection Rule Specification
          </h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white cursor-pointer transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Export Format Selectors */}
        <div className="flex flex-wrap gap-2 text-[11px]">
          <button
            onClick={() => setExportFormat('sentinel_json')}
            className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
              exportFormat === 'sentinel_json' ? 'bg-cyan-400 text-[#060D18] font-bold border-cyan-400 shadow-xs' : 'bg-[#060D18] text-slate-400 hover:text-cyan-300 border-[#1B3047]'
            }`}
          >
            Microsoft Sentinel ARM JSON
          </button>
          <button
            onClick={() => setExportFormat('splunk_conf')}
            className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
              exportFormat === 'splunk_conf' ? 'bg-cyan-400 text-[#060D18] font-bold border-cyan-400 shadow-xs' : 'bg-[#060D18] text-slate-400 hover:text-cyan-300 border-[#1B3047]'
            }`}
          >
            Splunk savedsearches.conf
          </button>
          <button
            onClick={() => setExportFormat('sigma_yaml')}
            className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
              exportFormat === 'sigma_yaml' ? 'bg-cyan-400 text-[#060D18] font-bold border-cyan-400 shadow-xs' : 'bg-[#060D18] text-slate-400 hover:text-cyan-300 border-[#1B3047]'
            }`}
          >
            Sigma Generic Rule YAML
          </button>
          <button
            onClick={() => setExportFormat('markdown')}
            className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
              exportFormat === 'markdown' ? 'bg-cyan-400 text-[#060D18] font-bold border-cyan-400 shadow-xs' : 'bg-[#060D18] text-slate-400 hover:text-cyan-300 border-[#1B3047]'
            }`}
          >
            SOC IR Documentation (.md)
          </button>
        </div>

        {/* Output Code Box */}
        <pre className="p-4 bg-[#060D18] text-teal-300 rounded-xl border border-[#1B3047] h-64 overflow-y-auto font-mono text-[11px] leading-relaxed whitespace-pre">
          <code>{exportText}</code>
        </pre>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[#101F32] hover:bg-[#1B3047] text-slate-200 border border-[#1B3047] cursor-pointer transition-colors"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-cyan-400" />}
            {copied ? 'Copied to Clipboard' : 'Copy Content'}
          </button>

          <button
            onClick={handleDownloadFile}
            className="flex items-center gap-1.5 px-5 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold shadow-md cursor-pointer transition-colors"
          >
            <Download className="w-4 h-4" />
            Download File
          </button>
        </div>
      </div>
    </div>
  );
};
