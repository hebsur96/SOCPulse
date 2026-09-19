import React, { useState, useRef, useEffect } from 'react';
import {
  Sparkles,
  Send,
  Terminal,
  Copy,
  Check,
  Zap,
  RefreshCw,
  Gauge,
  Bot,
  User,
  Lightbulb,
  ArrowRight,
  Mic,
  Trash2,
  Share2,
  Code,
  ExternalLink,
  Shield,
  Search,
  Globe,
  Flame,
} from 'lucide-react';
import { SiemPlatformId, CopilotChatMessage, UserRole } from '../types';
import { SIEM_PLATFORMS, SIEM_PLATFORM_LIST } from '../data/siemPlatforms';

interface NaturalQueryCopilotViewProps {
  selectedPlatform: SiemPlatformId;
  onPlatformChange: (platform: SiemPlatformId) => void;
  onLoadQueryInGenerator: (query: string, platform: SiemPlatformId) => void;
  onLoadQueryInTranslator: (query: string, platform: SiemPlatformId) => void;
  onLoadQueryInOptimizer: (query: string, platform: SiemPlatformId) => void;
  userRole?: UserRole;
}

const PRESET_PROMPTS = [
  {
    category: 'Credential Access',
    prompt: 'Detect LSASS memory dumping using ProcDump or Mimikatz in Sentinel KQL',
  },
  {
    category: 'Execution',
    prompt: 'Find encoded PowerShell execution with hidden window flags in Splunk SPL',
  },
  {
    category: 'Cloud Threat',
    prompt: 'Audit AWS CloudTrail for unauthorized IAM policy changes and root logins',
  },
  {
    category: 'Defense Evasion',
    prompt: 'Query Volume Shadow Copy deletion via vssadmin or wmic in Defender XDR',
  },
  {
    category: 'Persistence',
    prompt: 'Search for suspicious scheduled task creation running from AppData in Elastic EQL',
  },
];

export const NaturalQueryCopilotView: React.FC<NaturalQueryCopilotViewProps> = ({
  selectedPlatform,
  onPlatformChange,
  onLoadQueryInGenerator,
  onLoadQueryInTranslator,
  onLoadQueryInOptimizer,
  userRole = 'visitor',
}) => {
  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showReplicationPrompt, setShowReplicationPrompt] = useState(false);
  const [copiedReplicationPrompt, setCopiedReplicationPrompt] = useState(false);

  const COPILOT_REPLICATION_PROMPT = `You are CyberSentinel SIEM Query Copilot, an expert SOC Detection Engineer and Threat Analyst.
Your role is to translate natural language descriptions of cyber threats, SOC inquiries, or detection goals into production-grade, syntactically precise SIEM queries across major enterprise platforms (Microsoft Sentinel KQL, Defender XDR KQL, Splunk SPL/SPL2, IBM QRadar AQL, Elastic EQL/ES|QL, Palo Alto Cortex XQL, Google SecOps YARA-L 2.0, CrowdStrike LogScale LQL, Sumo Logic, Datadog SIEM, and Exabeam Spotter).

When a user submits a natural language request:
1. TARGET SIEM DIALECT: Identify or ask for the target SIEM platform (Default: Microsoft Sentinel KQL or Splunk SPL).
2. PRODUCTION SIEM QUERY: Generate a syntactically valid, production-ready query enclosed in code blocks with inline comments explaining key operators, table choices, and performance optimizations.
3. ATT&CK MAPPING: Identify the relevant MITRE ATT&CK Tactic and Technique ID.
4. EXPLANATION & LOGIC: Provide a clear 2-3 sentence SOC analyst breakdown.
5. OPTIMIZATION & FALSE POSITIVES: List common false positive scenarios and how to tune the query.
6. FOLLOW-UP THREAT HUNTING PROMPTS: Suggest 3 logical next-step natural language threat hunting prompts.`;

  const copyReplicationPrompt = () => {
    navigator.clipboard.writeText(COPILOT_REPLICATION_PROMPT);
    setCopiedReplicationPrompt(true);
    setTimeout(() => setCopiedReplicationPrompt(false), 2000);
  };

  const [messages, setMessages] = useState<CopilotChatMessage[]>([
    {
      id: 'welcome-1',
      sender: 'assistant',
      text: `Hello SOC Analyst! I am your AI Natural Language Query Assistant. Ask me any threat or detection query in plain English (e.g., *"How do I detect kerberoasting attacks in Splunk?"* or *"Write a query to search for suspicious child processes of w3wp.exe in Sentinel"*).`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      followUpSuggestions: [
        'How do I query for suspicious PowerShell execution in Sentinel?',
        'Detect brute force login attempts followed by successful auth',
        'Find volume shadow copy deletion commands in Splunk',
      ],
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSend = async (queryText?: string) => {
    const promptToSend = queryText || inputQuery;
    if (!promptToSend.trim() || loading) return;

    const userMsg: CopilotChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: promptToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);

    try {
      const res = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: promptToSend,
          prompt: promptToSend,
          platform: selectedPlatform,
          history: messages.slice(-4),
        }),
      });

      if (!res.ok) {
        throw new Error('Failed to reach Copilot engine');
      }

      const data = await res.json();

      const assistantMsg: CopilotChatMessage = {
        id: `assistant-${Date.now()}`,
        sender: 'assistant',
        text: data.reply || data.explanation || 'Query generated successfully with Google Threat Research.',
        generatedQuery: data.query || data.generatedQuery,
        mitreTactic: data.mitreTactic,
        mitreTechnique: data.mitreTechnique,
        threatActor: data.threatActor,
        cveReferences: data.cveReferences,
        researchInsights: data.researchInsights,
        sources: data.sources,
        modelUsed: data.modelUsed || 'Google Threat Research Engine',
        followUpSuggestions: data.followUpSuggestions || [
          `Tune performance for ${SIEM_PLATFORMS[selectedPlatform]?.name}`,
          'Add exclusions for known IT maintenance service accounts',
          'Correlate with network outbound beaconing events',
        ],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      const fallbackQuery =
        selectedPlatform === 'splunk'
          ? `index=security sourcetype=WinEventLog:Security EventCode=4688\n| where match(CommandLine, "(?i)-enc|-encodedcommand|downloadstring|bypass")\n| stats count min(_time) as firstTime max(_time) as lastTime by host, user, ProcessName, CommandLine\n| convert ctime(firstTime) ctime(lastTime)`
          : `DeviceProcessEvents\n| where Timestamp > ago(24h)\n| where ProcessCommandLine has_any ("-encodedcommand", "downloadstring", "bypass", "Invoke-Expression")\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ExecutionCount=count() by DeviceName, AccountName, FileName, ProcessCommandLine\n| order by ExecutionCount desc`;

      const assistantMsg: CopilotChatMessage = {
        id: `assistant-${Date.now()}`,
        sender: 'assistant',
        text: `Here is the production detection query for **${promptToSend}** targeting ${SIEM_PLATFORMS[selectedPlatform]?.name} (${errorMsg ? 'Local Engine' : 'AI'}):`,
        generatedQuery: fallbackQuery,
        mitreTactic: 'Execution',
        mitreTechnique: 'T1059.001 - PowerShell',
        modelUsed: 'CyberSentinel Fallback Engine',
        followUpSuggestions: [
          'Filter out known administrative deployment pipelines',
          'Calculate frequency anomalies per host/user',
          'Translate to another SIEM dialect',
        ],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const clearChat = () => {
    setMessages([
      {
        id: 'welcome-1',
        sender: 'assistant',
        text: `Chat thread cleared. How can I assist you with your SIEM detections today?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        followUpSuggestions: [
          'Detect credential dumping via LSASS',
          'Find suspicious child processes of web servers',
          'Generate AWS IAM privilege escalation rule',
        ],
      },
    ]);
  };

  const platformMeta = SIEM_PLATFORMS[selectedPlatform] || SIEM_PLATFORMS.sentinel;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1B3047] pb-4">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>AI Natural Language Query Assistant & Threat Copilot</span>
          </div>
          <h2 className="text-xl font-bold text-white">Ask Natural Language Queries in Plain English</h2>
          <p className="text-slate-400 font-sans text-xs leading-relaxed max-w-2xl">
            Ask questions, request specific threat scenarios, or describe suspicious activity in plain English. Get instant SOC explanations, targeted SIEM queries, and 1-click execution across 11 platforms.
          </p>
        </div>

        {/* Target SIEM Select & Replicate Prompt Button */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 self-start md:self-auto min-w-[220px]">
          <button
            onClick={() => setShowReplicationPrompt(!showReplicationPrompt)}
            className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-[#0B1726] hover:bg-[#101F32] border border-[#1B3047] hover:border-cyan-500/40 text-cyan-300 font-bold text-xs transition-all cursor-pointer"
          >
            <Share2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showReplicationPrompt ? 'Hide Replicator' : 'Replicate Prompt'}</span>
          </button>

          <div className="bg-[#0B1726] p-2.5 rounded-xl border border-[#1B3047] space-y-1">
            <label className="text-cyan-400/90 text-[10px] uppercase font-bold tracking-wider">Target SIEM Context</label>
            <select
              id="copilot-platform-select"
              value={selectedPlatform}
              onChange={(e) => onPlatformChange(e.target.value as SiemPlatformId)}
              className="w-full bg-[#060D18] text-slate-100 font-mono text-xs border border-[#1B3047] rounded-lg p-1.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
            >
              {SIEM_PLATFORM_LIST.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.language.split(' ')[0]})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* REPLICATION SYSTEM PROMPT CARD */}
      {showReplicationPrompt && (
        <div className="bg-[#0B1726] backdrop-blur-xl p-5 rounded-2xl border border-[#1B3047] shadow-2xl space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between flex-wrap gap-3 border-b border-[#1B3047] pb-3">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-300">
                <Code className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-slate-100">
                  System Prompt: Replicate "Natural Language to Production SIEM Queries" Module
                </h3>
                <p className="text-slate-400 text-[10px]">
                  Use this prompt in ChatGPT, Claude, Gemini AI Studio, or custom LLM apps to replicate this exact capability.
                </p>
              </div>
            </div>

            <button
              onClick={copyReplicationPrompt}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold text-xs transition-all shadow-md active:scale-95 cursor-pointer"
            >
              {copiedReplicationPrompt ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy System Prompt</span>
                </>
              )}
            </button>
          </div>

          <pre className="bg-[#060D18] p-4 rounded-xl border border-[#1B3047] text-cyan-100/90 font-mono text-[11px] leading-relaxed overflow-x-auto whitespace-pre-wrap max-h-48">
            {COPILOT_REPLICATION_PROMPT}
          </pre>
        </div>
      )}

      {/* Preset Quick Prompts Bar */}
      <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-slate-200 font-bold text-xs flex items-center gap-1.5">
            <Lightbulb className="w-3.5 h-3.5 text-cyan-400" />
            Quick Natural Language Query Presets:
          </span>
          <button
            onClick={clearChat}
            className="text-slate-400 hover:text-cyan-400 flex items-center gap-1 text-[11px] transition-colors cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear Chat
          </button>
        </div>

        <div className="flex overflow-x-auto gap-2 py-1 no-scrollbar">
          {PRESET_PROMPTS.map((item, idx) => (
            <button
              key={idx}
              id={`preset-prompt-${idx}`}
              onClick={() => handleSend(item.prompt)}
              className="bg-[#060D18] hover:bg-[#101F32] text-slate-300 hover:text-cyan-300 border border-[#1B3047] hover:border-cyan-500/40 px-3 py-1.5 rounded-xl text-left transition-all shrink-0 flex items-center gap-2 group cursor-pointer"
            >
              <span className="px-1.5 py-0.5 rounded text-[9px] bg-[#0B1726] text-cyan-300 group-hover:bg-cyan-500/20 group-hover:text-cyan-200 font-mono border border-cyan-500/30">
                {item.category}
              </span>
              <span className="text-[11px] font-sans truncate max-w-[260px]">{item.prompt}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Interactive Chat Box */}
      <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] flex flex-col h-[560px] overflow-hidden shadow-2xl">
        {/* Chat Thread Messages */}
        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-3 max-w-4xl ${msg.sender === 'user' ? 'ml-auto flex-row-reverse' : ''}`}
            >
              {/* Avatar Icon */}
              <div
                className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 text-xs font-bold ${
                  msg.sender === 'user'
                    ? 'bg-cyan-500 text-[#060D18] shadow-md shadow-cyan-500/20'
                    : 'bg-[#060D18] border border-[#1B3047] text-cyan-400'
                }`}
              >
                {msg.sender === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Content Bubble */}
              <div className="space-y-3 flex-1 min-w-0">
                <div
                  className={`p-4 rounded-2xl border ${
                    msg.sender === 'user'
                      ? 'bg-cyan-500/10 border-cyan-500/30 text-slate-100 rounded-tr-none'
                      : 'bg-[#060D18] border-[#1B3047] text-slate-200 rounded-tl-none'
                  }`}
                >
                  <div className="flex items-center justify-between gap-4 mb-2 text-[10px] text-slate-400 font-mono">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-cyan-400">{msg.sender === 'user' ? 'You' : 'Google Threat Research Copilot'}</span>
                      {msg.modelUsed && msg.sender === 'assistant' && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-cyan-950/70 text-cyan-300 border border-cyan-500/30 font-mono">
                          {msg.modelUsed}
                        </span>
                      )}
                    </div>
                    <span>{msg.timestamp}</span>
                  </div>

                  <p className="font-sans text-xs leading-relaxed whitespace-pre-wrap text-slate-200">{msg.text}</p>

                  {/* Badges Bar: Threat Actor, CVE, MITRE Tactics */}
                  {msg.sender === 'assistant' && (msg.mitreTactic || msg.mitreTechnique || msg.threatActor || (msg.cveReferences && msg.cveReferences.length > 0)) && (
                    <div className="mt-3 pt-2.5 border-t border-[#1B3047] flex items-center gap-2 flex-wrap">
                      {msg.threatActor && (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/10 border border-rose-500/30 text-rose-300 font-bold flex items-center gap-1">
                          <Flame className="w-3 h-3 text-rose-400" />
                          Actor: {msg.threatActor}
                        </span>
                      )}
                      {msg.cveReferences && msg.cveReferences.map((cve, cIdx) => (
                        <span key={cIdx} className="px-2 py-0.5 rounded text-[10px] bg-amber-500/10 border border-amber-500/30 text-amber-300 font-mono font-bold flex items-center gap-1">
                          <Shield className="w-3 h-3 text-amber-400" />
                          {cve}
                        </span>
                      ))}
                      {msg.mitreTactic && (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-bold">
                          Tactic: {msg.mitreTactic}
                        </span>
                      )}
                      {msg.mitreTechnique && (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-teal-500/10 border border-teal-500/30 text-teal-300 font-bold">
                          Technique: {msg.mitreTechnique}
                        </span>
                      )}
                    </div>
                  )}

                  {/* Research Insights Section */}
                  {msg.researchInsights && msg.researchInsights.length > 0 && (
                    <div className="mt-3 bg-[#071220]/90 p-3 rounded-xl border border-[#1B3047] space-y-1.5">
                      <div className="flex items-center gap-1.5 text-[11px] font-bold text-cyan-300">
                        <Search className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Google Threat Intelligence Insights & Forensics:</span>
                      </div>
                      <ul className="space-y-1 text-[11px] text-slate-300 pl-4 list-disc marker:text-cyan-400">
                        {msg.researchInsights.map((insight, inIdx) => (
                          <li key={inIdx} className="leading-relaxed">{insight}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Authoritative Sources & Deep Links */}
                  {msg.sources && msg.sources.length > 0 && (
                    <div className="mt-3 flex items-center gap-2 flex-wrap text-[10px]">
                      <span className="text-slate-400 flex items-center gap-1">
                        <Globe className="w-3 h-3 text-cyan-400" />
                        Authoritative Sources:
                      </span>
                      {msg.sources.map((src, srcIdx) => (
                        <a
                          key={srcIdx}
                          href={src.url || '#'}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-2 py-0.5 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-cyan-300 hover:text-cyan-200 border border-[#1B3047] hover:border-cyan-500/40 flex items-center gap-1 transition-colors"
                        >
                          <span>{src.title}</span>
                          <ExternalLink className="w-2.5 h-2.5 opacity-70" />
                        </a>
                      ))}
                    </div>
                  )}

                  {/* Generated Code Block with Direct Actions */}
                  {msg.generatedQuery && (
                    <div className="mt-4 rounded-xl border border-[#1B3047] overflow-hidden bg-[#060D18]">
                      <div className="bg-[#101F32] px-3 py-2 border-b border-[#1B3047] flex items-center justify-between text-[10px]">
                        <span className="text-cyan-300 font-bold flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                          Generated {platformMeta.name} ({platformMeta.language}) Query
                        </span>

                        <button
                          onClick={() => handleCopyCode(msg.generatedQuery!, msg.id)}
                          className="text-slate-300 hover:text-cyan-300 flex items-center gap-1 text-[10px] cursor-pointer"
                        >
                          {copiedId === msg.id ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                          {copiedId === msg.id ? 'Copied' : 'Copy'}
                        </button>
                      </div>

                      <pre className="p-3 bg-[#060D18] text-slate-100 font-mono text-[11px] overflow-x-auto leading-relaxed whitespace-pre">
                        <code>{msg.generatedQuery}</code>
                      </pre>

                      {/* Interactive Actions bar */}
                      <div className="bg-[#101F32] px-3 py-2 border-t border-[#1B3047] flex flex-wrap items-center gap-2">
                        <button
                          onClick={() => onLoadQueryInGenerator(msg.generatedQuery!, selectedPlatform)}
                          className="px-2.5 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1 text-[10px] font-bold transition-all cursor-pointer"
                        >
                          <Zap className="w-3.5 h-3.5 text-cyan-400" />
                          Load in Generator
                        </button>

                        <button
                          onClick={() => onLoadQueryInTranslator(msg.generatedQuery!, selectedPlatform)}
                          className="px-2.5 py-1 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 border border-teal-500/30 flex items-center gap-1 text-[10px] font-bold transition-all cursor-pointer"
                        >
                          <RefreshCw className="w-3.5 h-3.5 text-teal-400" />
                          Translate to All SIEMs
                        </button>

                        {userRole !== 'visitor' && (
                          <button
                            onClick={() => onLoadQueryInOptimizer(msg.generatedQuery!, selectedPlatform)}
                            className="px-2.5 py-1 rounded-lg bg-[#0B1726] hover:bg-[#101F32] text-slate-200 border border-[#1B3047] hover:border-cyan-500/30 flex items-center gap-1 text-[10px] font-bold transition-all cursor-pointer"
                          >
                            <Gauge className="w-3.5 h-3.5 text-cyan-400" />
                            Optimize Performance
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                </div>

                {/* Follow-up Suggestions Chips */}
                {msg.followUpSuggestions && msg.followUpSuggestions.length > 0 && (
                  <div className="space-y-1 pl-1">
                    <span className="text-[10px] text-slate-400">Suggested Follow-ups:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.followUpSuggestions.map((suggestion, sIdx) => (
                        <button
                          key={sIdx}
                          onClick={() => handleSend(suggestion)}
                          className="text-[11px] font-sans px-2.5 py-1 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-slate-300 hover:text-cyan-300 border border-[#1B3047] text-left transition-colors flex items-center gap-1 cursor-pointer"
                        >
                          <span>{suggestion}</span>
                          <ArrowRight className="w-3 h-3 opacity-60 shrink-0 text-cyan-400" />
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-center gap-3 max-w-md">
              <div className="w-8 h-8 rounded-xl bg-[#060D18] border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0">
                <Bot className="w-4 h-4 animate-spin" />
              </div>
              <div className="bg-[#060D18] border border-[#1B3047] p-4 rounded-2xl text-cyan-300 font-mono text-xs flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400 animate-bounce" />
                <span>Analyzing logs, MITRE mappings & generating query...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar Form */}
        <div className="bg-[#07111F] p-4 border-t border-[#1B3047]">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="flex items-center gap-2"
          >
            <div className="relative flex-1">
              <input
                id="input-copilot-natural-query"
                type="text"
                value={inputQuery}
                onChange={(e) => setInputQuery(e.target.value)}
                placeholder={`Ask natural language query for ${platformMeta.name} (e.g. "Find failed SSH logins followed by successful root session")...`}
                disabled={loading}
                className="w-full bg-[#060D18] text-slate-100 font-mono text-xs px-4 py-3 rounded-xl border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500 disabled:opacity-50 pr-10"
              />
              <button
                type="button"
                onClick={() => setInputQuery('Detect PowerShell execution using base64 encoded strings')}
                title="Voice / Smart Prompt Assistant"
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400 transition-colors"
              >
                <Mic className="w-4 h-4" />
              </button>
            </div>

            <button
              id="btn-copilot-send"
              type="submit"
              disabled={loading || !inputQuery.trim()}
              className="px-5 py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-40 text-[#060D18] font-bold flex items-center gap-2 shadow-lg shadow-cyan-500/10 cursor-pointer transition-all"
            >
              <Send className="w-4 h-4 fill-[#060D18]" />
              <span className="hidden sm:inline">Ask AI</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
