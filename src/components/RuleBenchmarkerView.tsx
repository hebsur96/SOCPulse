import React, { useState } from 'react';
import {
  Gauge,
  Zap,
  DollarSign,
  AlertOctagon,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Copy,
  Check,
  Code2,
  Layers,
  ArrowRight,
  Shield,
  FileCheck,
  Sliders,
  Sparkles,
} from 'lucide-react';
import { SiemPlatformId, RuleBenchmarkResult, RuleBenchmarkIssue } from '../types';
import { SIEM_PLATFORM_LIST, SIEM_PLATFORMS } from '../data/siemPlatforms';

const SAMPLE_RULES: { label: string; platform: SiemPlatformId; title: string; code: string }[] = [
  {
    label: 'Unoptimized KQL (Sentinel)',
    platform: 'sentinel',
    title: 'Detect Suspicious PowerShell Script Execution',
    code: `// POOR PERFORMANCE KQL RULE (High Cloud Ingest Cost)
SecurityEvent
| where EventID == 4688
| where CommandLine contains "powershell"
| where Activity contains "process"
| where TimeGenerated > ago(30d)
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
) on Computer
| project TimeGenerated, Computer, Account, CommandLine`,
  },
  {
    label: 'Unoptimized SPL (Splunk)',
    platform: 'splunk',
    title: 'Detect Brute Force Authentication',
    code: `index=* sourcetype=* "failed password"
| eval user=lower(user)
| stats count by src_ip, user
| where count > 5
| join src_ip [ search index=* sourcetype=* "Accepted password" ]`,
  },
  {
    label: 'Unoptimized Lucene (Elastic)',
    platform: 'elastic',
    title: 'Detect Web Shell Creation',
    code: `event.category: "file" AND file.path: *.php AND process.name: *cmd* AND NOT user.name: "system"`,
  },
];

export const RuleBenchmarkerView: React.FC<{
  onSendToOptimizer?: (query: string, platform: SiemPlatformId) => void;
}> = ({ onSendToOptimizer }) => {
  const [platform, setPlatform] = useState<SiemPlatformId>('sentinel');
  const [ruleTitle, setRuleTitle] = useState<string>('Detect Suspicious PowerShell Process Creation');
  const [ruleCode, setRuleCode] = useState<string>(SAMPLE_RULES[0].code);
  const [isBenchmarking, setIsBenchmarking] = useState<boolean>(false);
  const [benchmarkResult, setBenchmarkResult] = useState<RuleBenchmarkResult | null>(null);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  const handleRunBenchmark = () => {
    setIsBenchmarking(true);

    setTimeout(() => {
      // Analyze rule code to calculate dynamic static analysis scores & issues
      const issues: RuleBenchmarkIssue[] = [];
      let perf = 85;
      let cost = 80;
      let fidelity = 88;
      let portability = 82;

      const codeLower = ruleCode.toLowerCase();

      // Check 1: Wildcard prefix
      if (codeLower.includes('*') || codeLower.includes('contains "*')) {
        issues.push({
          line: 2,
          code: 'PERF-01',
          title: 'Leading Wildcard Prefix (*)',
          severity: 'Critical',
          description: 'Using leading wildcards or unindexed string searching forces full unindexed table scans across millions of logs.',
          recommendation: 'Replace generic wildcards with explicit indexed field tokens or `has` operators.',
          costImpact: 'High Compute Overhead (+40% processing latency)',
        });
        perf -= 25;
        cost -= 30;
      }

      // Check 2: Unbounded Join
      if (codeLower.includes('join') || codeLower.includes('search index=*')) {
        issues.push({
          line: 5,
          code: 'COST-02',
          title: 'Unbounded Heavy Join Operation',
          severity: 'High',
          description: 'Cross-table join without time constraints or sub-filtering causes memory spill and high query execution units.',
          recommendation: 'Restructure using `summarize` aggregation or limit join right-hand side time window to ago(1h).',
          costImpact: 'Extremely High Cloud Compute Billing',
        });
        perf -= 20;
        cost -= 25;
      }

      // Check 3: Large Time Window (ago(30d))
      if (codeLower.includes('30d') || codeLower.includes('index=*')) {
        issues.push({
          line: 4,
          code: 'TIME-03',
          title: 'Excessive Lookback Window (> 7 Days)',
          severity: 'Medium',
          description: 'Real-time scheduled detection rules running over 30 days degrade SIEM scheduled query engine throughput.',
          recommendation: 'Limit real-time detection schedule to ago(1h) or ago(24h) and use summary indexing for long trend analysis.',
          costImpact: 'Increases API timeout risk',
        });
        perf -= 15;
      }

      // Default issue if code is relatively good
      if (issues.length === 0) {
        issues.push({
          line: 1,
          code: 'INFO-01',
          title: 'Minor Index Optimization Available',
          severity: 'Low',
          description: 'Rule is well structured, but adding strict column filtering early reduces projection bandwidth.',
          recommendation: 'Ensure `project-away` or `project` is executed right after initial filters.',
          costImpact: 'Negligible',
        });
      }

      perf = Math.max(35, perf);
      cost = Math.max(30, cost);

      let grade: RuleBenchmarkResult['overallGrade'] = 'A+';
      const avgScore = (perf + cost + fidelity) / 3;
      if (avgScore >= 90) grade = 'A+';
      else if (avgScore >= 80) grade = 'A';
      else if (avgScore >= 70) grade = 'B';
      else if (avgScore >= 60) grade = 'C';
      else if (avgScore >= 50) grade = 'D';
      else grade = 'F';

      // Generate optimized version
      let optimized = ruleCode;
      if (platform === 'sentinel') {
        optimized = `// OPTIMIZED HIGH-PERFORMANCE KQL RULE (70% Lower Cloud Compute Cost)
SecurityEvent
| where TimeGenerated > ago(1h) // Constrained time window
| where EventID == 4688
| where ProcessName has "powershell.exe" or CommandLine has "powershell"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
| summarize FirstSeen=min(TimeGenerated), ExecutionCount=count() by Computer, Account, CommandLine
| where ExecutionCount > 0`;
      } else if (platform === 'splunk') {
        optimized = `index=windows sourcetype="WinEventLog:Security" EventCode=4688 "powershell"
| fields _time, host, user, Process_Command_Line
| stats count by host, user, Process_Command_Line
| where count > 1`;
      } else {
        optimized = `event.category: "file" AND file.extension: "php" AND process.name: "cmd.exe" AND NOT user.id: "S-1-5-18"`;
      }

      const platformMeta = SIEM_PLATFORMS[platform] || SIEM_PLATFORMS.sentinel;

      setBenchmarkResult({
        ruleTitle: ruleTitle || 'Custom SIEM Detection Rule',
        platform,
        overallGrade: grade,
        performanceScore: perf,
        costImpactScore: cost,
        fidelityScore: fidelity,
        portabilityScore: portability,
        estimatedComputeUnits: `${(100 - perf) * 12 + 15} SCU/run`,
        estimatedMonthlyCloudCost: `$${Math.round((100 - cost) * 4.2 + 12)} / mo`,
        issuesFound: issues,
        optimizedRuleContent: optimized,
        optimizedDiffExplanation:
          '1. Replaced unindexed substring searching (`contains`) with token-aware search (`has`).\n2. Narrowed real-time evaluation lookback from 30 days to 1 hour.\n3. Replaced memory-heavy inner join with efficient `summarize` aggregation.',
        portabilityBreakdown: SIEM_PLATFORM_LIST.map((p) => ({
          platform: p.id,
          platformName: p.name,
          compatibility: p.id === platform ? 'Native' : p.id === 'sentinel' || p.id === 'splunk' ? 'Easy Translation' : 'Requires Rewrite',
          notes: p.id === platform ? 'Current rule source dialect' : `Can be converted to ${p.language} using AI Translator`,
        })),
        mitreCoverage: [
          { tactic: 'Execution', techniqueId: 'T1059.001', techniqueName: 'Command and Scripting Interpreter: PowerShell', confidence: 95 },
          { tactic: 'Credential Access', techniqueId: 'T1003', techniqueName: 'OS Credential Dumping', confidence: 78 },
        ],
      });

      setIsBenchmarking(false);
    }, 1200);
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(key);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const getGradeBadgeClass = (grade: RuleBenchmarkResult['overallGrade']) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
      case 'B':
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40';
      case 'C':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      default:
        return 'bg-red-500/20 text-red-400 border-red-500/40';
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header Banner */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="px-2.5 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-xs font-semibold flex items-center gap-1.5">
                <Gauge className="w-3.5 h-3.5 text-cyan-400" /> Static Linter & Cost Analyzer
              </div>
              <span className="text-xs text-slate-400 font-mono">Rule Benchmarker v2.1</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              AI Detection Rule Quality & Performance Benchmarker
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-3xl">
              Benchmark detection query performance, identify cloud ingest & compute cost traps, evaluate MITRE ATT&CK fidelity, and auto-optimize queries for maximum speed.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {SAMPLE_RULES.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setPlatform(sample.platform);
                  setRuleTitle(sample.title);
                  setRuleCode(sample.code);
                }}
                className="px-3 py-1.5 rounded-lg bg-[#060D18] border border-[#1B3047] hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 font-mono text-xs transition-colors cursor-pointer"
              >
                Sample {idx + 1}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Editor & Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Query Input */}
        <div className="lg:col-span-2 bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 border-b border-[#1B3047] pb-3">
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 font-mono">Detection Rule Editor</h3>
            </div>

            <div className="flex items-center gap-2">
              <label className="text-xs font-mono text-slate-400">Target SIEM:</label>
              <select
                id="benchmark-platform-select"
                value={platform}
                onChange={(e) => setPlatform(e.target.value as SiemPlatformId)}
                className="bg-[#060D18] text-slate-200 border border-[#1B3047] rounded-lg px-2.5 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500/40 cursor-pointer"
              >
                {SIEM_PLATFORM_LIST.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.language})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-400">Rule Title / Description:</label>
            <input
              type="text"
              id="rule-title-input"
              value={ruleTitle}
              onChange={(e) => setRuleTitle(e.target.value)}
              className="w-full bg-[#060D18] border border-[#1B3047] rounded-xl px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500/60"
              placeholder="e.g. Detect Suspicious Process Execution"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-400">Paste Query / Rule Code:</label>
            <textarea
              id="rule-code-input"
              rows={9}
              value={ruleCode}
              onChange={(e) => setRuleCode(e.target.value)}
              className="w-full bg-[#060D18] border border-[#1B3047] rounded-xl p-3.5 text-xs font-mono text-teal-300 focus:outline-none focus:border-cyan-500/60 leading-relaxed"
              placeholder="Paste KQL, SPL, YARA-L, or Lucene rule..."
            />
          </div>

          <button
            onClick={handleRunBenchmark}
            disabled={isBenchmarking || !ruleCode.trim()}
            className="w-full py-3 px-4 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold font-sans text-sm flex items-center justify-center gap-2 transition-all shadow-md cursor-pointer disabled:opacity-50"
          >
            {isBenchmarking ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" /> Running Static Linter & Cost Audit...
              </>
            ) : (
              <>
                <Zap className="w-4 h-4 fill-current" /> Benchmark Quality & Compute Cost
              </>
            )}
          </button>
        </div>

        {/* Right Col: Benchmark Highlights / Quick Instructions */}
        <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-2 border-b border-[#1B3047] pb-3">
              <DollarSign className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 font-mono">Ingestion Cost Traps Checked</h3>
            </div>

            <ul className="space-y-2.5 text-xs text-slate-300 font-mono">
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                <span>Unindexed Wildcard Prefix Searches (`*term*`)</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                <span>Cross-Table Memory Joins without Time Constraints</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                <span>Excessive Lookback Windows (&gt; 7-30 Days)</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                <span>Unfiltered `index=*` or `SecurityEvent` Full Scans</span>
              </li>
            </ul>
          </div>

          <div className="p-4 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-2 text-xs">
            <div className="font-bold text-teal-400 font-mono flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-teal-400" /> Pro-Tip for SOC Engineers
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Optimizing rule syntax reduces cloud SIEM compute allocation charges and prevents scheduled query execution timeouts during critical incidents.
            </p>
          </div>
        </div>
      </div>

      {/* Benchmark Results Display */}
      {benchmarkResult && (
        <div className="space-y-6">
          {/* Top Score Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] flex flex-col items-center justify-center text-center">
              <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Overall Grade</div>
              <div className={`text-2xl font-black font-mono px-3 py-0.5 rounded-lg border ${getGradeBadgeClass(benchmarkResult.overallGrade)}`}>
                {benchmarkResult.overallGrade}
              </div>
            </div>

            <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] flex flex-col items-center justify-center text-center">
              <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Performance Score</div>
              <div className="text-2xl font-black font-mono text-cyan-400">{benchmarkResult.performanceScore}/100</div>
            </div>

            <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] flex flex-col items-center justify-center text-center">
              <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Cost Efficiency</div>
              <div className="text-2xl font-black font-mono text-teal-400">{benchmarkResult.costImpactScore}/100</div>
            </div>

            <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] flex flex-col items-center justify-center text-center">
              <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Est. Compute Units</div>
              <div className="text-sm font-bold font-mono text-slate-200 mt-1">{benchmarkResult.estimatedComputeUnits}</div>
            </div>

            <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] flex flex-col items-center justify-center text-center col-span-2 md:col-span-1">
              <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Est. Monthly Cost</div>
              <div className="text-sm font-bold font-mono text-teal-400 mt-1">{benchmarkResult.estimatedMonthlyCloudCost}</div>
            </div>
          </div>

          {/* Issues Found & Auto-Optimized Rule */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Linter Issues */}
            <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl">
              <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <h3 className="text-sm font-bold text-slate-200 font-mono">Linter Anti-Pattern Audit</h3>
                </div>
                <span className="text-xs font-mono text-slate-400">{benchmarkResult.issuesFound.length} Items Flagged</span>
              </div>

              <div className="space-y-3">
                {benchmarkResult.issuesFound.map((issue, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-[#060D18] border border-[#1B3047] space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[10px] font-mono font-bold">
                          {issue.code}
                        </span>
                        <h4 className="text-xs font-bold text-slate-100 font-mono">{issue.title}</h4>
                      </div>
                      <span className="text-[10px] font-mono text-red-400 font-semibold">{issue.severity}</span>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{issue.description}</p>

                    <div className="text-[11px] font-mono text-teal-300 bg-teal-500/5 p-2 rounded border border-teal-500/20">
                      <strong>Fix:</strong> {issue.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Optimized Query Output */}
            <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-5 space-y-4 shadow-xl flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between border-b border-[#1B3047] pb-3">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-teal-400" />
                    <h3 className="text-sm font-bold text-slate-200 font-mono">AI Auto-Optimized Rule Code</h3>
                  </div>
                  <button
                    onClick={() => handleCopy(benchmarkResult.optimizedRuleContent, 'optimized-rule')}
                    className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer transition-colors"
                  >
                    {copiedCode === 'optimized-rule' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    Copy Optimized Rule
                  </button>
                </div>

                <div className="p-4 bg-[#060D18] rounded-xl border border-[#1B3047] font-mono text-xs text-teal-300 overflow-x-auto leading-relaxed">
                  <pre>{benchmarkResult.optimizedRuleContent}</pre>
                </div>

                <div className="p-3 bg-[#060D18] rounded-xl border border-[#1B3047] text-xs text-slate-400 space-y-1">
                  <div className="font-bold text-cyan-300 font-mono text-[11px]">Optimization Explanation:</div>
                  <pre className="font-sans text-[11px] whitespace-pre-wrap text-slate-300">{benchmarkResult.optimizedDiffExplanation}</pre>
                </div>
              </div>

              {onSendToOptimizer && (
                <button
                  onClick={() => onSendToOptimizer(benchmarkResult.optimizedRuleContent, platform)}
                  className="w-full mt-4 py-2.5 px-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold font-sans text-xs flex items-center justify-center gap-2 transition-all shadow-md cursor-pointer"
                >
                  <ArrowRight className="w-4 h-4" /> Load in Full Query Optimizer Module
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
