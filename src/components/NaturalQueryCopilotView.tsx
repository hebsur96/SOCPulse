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
  Trash2,
  Share2,
  Code,
  CornerDownLeft,
  MessageSquare,
  Cpu,
  Layers,
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

interface StarterPrompt {
  category: string;
  badgeColor: string;
  prompt: string;
}

const STARTER_PROMPTS: StarterPrompt[] = [
  {
    category: 'Security Threat',
    badgeColor: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
    prompt: 'Explain Kerberoasting attack mechanics and how defenders can detect it',
  },
  {
    category: 'SIEM Query',
    badgeColor: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
    prompt: 'Detect LSASS memory dumping using ProcDump or Mimikatz in Sentinel KQL',
  },
  {
    category: 'Python Script',
    badgeColor: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
    prompt: 'Write a Python script to parse auth logs and report top 5 brute-forcing IP addresses',
  },
  {
    category: 'Networking',
    badgeColor: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30',
    prompt: 'What is the difference between TCP three-way handshake and UDP stateful inspection?',
  },
  {
    category: 'Cloud Audit',
    badgeColor: 'bg-teal-500/10 text-teal-300 border-teal-500/30',
    prompt: 'Audit AWS CloudTrail for unauthorized IAM policy alterations and root logins',
  },
  {
    category: 'General Concept',
    badgeColor: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
    prompt: 'Explain asymmetric public-key cryptography vs symmetric AES encryption in simple terms',
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

  const REPLICATION_PROMPT = `You are "Ask SOCPulse", an intelligent, versatile generative AI chatbot.
You function as a full-featured conversational assistant (similar to ChatGPT or Gemini) capable of answering ANY question — irrespective of topic:
- Cybersecurity, SOC operations, SIEM detection engineering (KQL, SPL, EQL, AQL, YARA-L), forensics, and threat hunting.
- Software engineering, scripting (Python, Bash, PowerShell, TypeScript, Go), system architecture, and debugging.
- General science, mathematics, technology, networking, cloud infrastructure, or everyday reasoning and explanations.
Always structure responses cleanly in Markdown with headers, bold highlights, bullet points, and syntax-tagged code blocks.`;

  const copyReplicationPrompt = () => {
    navigator.clipboard.writeText(REPLICATION_PROMPT);
    setCopiedReplicationPrompt(true);
    setTimeout(() => setCopiedReplicationPrompt(false), 2000);
  };

  const [messages, setMessages] = useState<CopilotChatMessage[]>([
    {
      id: 'welcome-1',
      sender: 'assistant',
      text: `### Welcome to Ask SOCPulse! 👋

I am your **intelligent generative AI assistant**. You can ask me **anything** — from cybersecurity, incident investigations, and SIEM detection engineering to programming scripts, system design, or open general knowledge questions.

#### What would you like to explore today?
- **Cybersecurity & Detection:** Request production queries for Microsoft Sentinel, Splunk, Elastic, Defender, or AWS.
- **Code & Scripting:** Ask me to write or debug Python, Bash, PowerShell, SQL, or regex scripts.
- **Deep Explanations:** Learn how malware, encryption, networking protocols, or authentication systems work.
- **General AI:** Ask any question just like a typical generative AI chatbot!`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      modelUsed: 'Ask SOCPulse Generative AI',
      followUpSuggestions: [
        'Explain Kerberoasting attack mechanics and how to detect it',
        'Write a Python script to parse security logs and extract IP counts',
        'Detect LSASS memory dumping in Microsoft Sentinel KQL',
      ],
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSend = async (queryText?: string) => {
    const promptToSend = (queryText !== undefined ? queryText : inputQuery).trim();
    if (!promptToSend || loading) return;

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
          history: messages.slice(-6).map((m) => ({
            role: m.sender === 'user' ? 'user' : 'model',
            sender: m.sender,
            text: m.text,
          })),
        }),
      });

      if (!res.ok) {
        throw new Error('Failed to reach Ask SOCPulse AI service');
      }

      const data = await res.json();

      const assistantMsg: CopilotChatMessage = {
        id: `assistant-${Date.now()}`,
        sender: 'assistant',
        text: data.reply || 'Response received from Ask SOCPulse.',
        generatedQuery: data.query || data.generatedQuery,
        mitreTactic: data.mitreTactic,
        mitreTechnique: data.mitreTechnique,
        threatActor: data.threatActor,
        cveReferences: data.cveReferences,
        researchInsights: data.researchInsights,
        sources: data.sources,
        modelUsed: data.modelUsed || 'Ask SOCPulse Generative AI',
        followUpSuggestions: data.followUpSuggestions || [
          'Can you explain this in greater detail?',
          'What are alternative approaches or mitigations?',
          'How can I test or automate this?',
        ],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      const assistantMsg: CopilotChatMessage = {
        id: `assistant-${Date.now()}`,
        sender: 'assistant',
        text: `### Response from Ask SOCPulse\n\nI processed your request: **"${promptToSend}"**.\n\n*(Note: Service response fallback — ${errorMsg})*\n\nIf you have questions about cybersecurity detection, scripting, or general technology, please feel free to ask again or rephrase!`,
        modelUsed: 'Ask SOCPulse Offline Assistant',
        followUpSuggestions: [
          'Explain how this concept works',
          'Provide a concrete code example',
          'What are common security risks associated with this?',
        ],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } finally {
      setLoading(false);
      // Auto-focus input
      setTimeout(() => textareaRef.current?.focus(), 100);
    }
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const clearChat = () => {
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        sender: 'assistant',
        text: `### Conversation Cleared 🧹\n\nI am ready for your next question! Ask me anything — whether about threat hunting, writing code, debugging issues, or general topics.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        modelUsed: 'Ask SOCPulse Generative AI',
        followUpSuggestions: [
          'Explain Kerberoasting attack mechanics and how defenders detect it',
          'Write a Python script to parse security logs',
          'What is the difference between TCP and UDP?',
        ],
      },
    ]);
  };

  const platformMeta = SIEM_PLATFORMS[selectedPlatform] || SIEM_PLATFORMS.sentinel;

  // Render markdown-like text with headers, lists, code blocks, bold text
  const renderFormattedMessage = (content: string, msgId: string) => {
    // Split into code blocks and normal text blocks
    const parts = content.split(/(```[\s\S]*?```)/g);

    return (
      <div className="space-y-3 text-xs leading-relaxed text-slate-200">
        {parts.map((part, partIdx) => {
          if (part.startsWith('```') && part.endsWith('```')) {
            // Code block
            const lines = part.slice(3, -3).trim().split('\n');
            let lang = 'code';
            let codeContent = lines.join('\n');

            // If first line is a language identifier
            if (lines.length > 0 && /^[a-zA-Z0-9_-]+$/.test(lines[0].trim())) {
              lang = lines[0].trim();
              codeContent = lines.slice(1).join('\n');
            }

            const codeId = `${msgId}-code-${partIdx}`;

            return (
              <div key={partIdx} className="rounded-xl border border-[#1B3047] overflow-hidden bg-[#060D18] my-3">
                <div className="bg-[#101F32] px-3 py-1.5 border-b border-[#1B3047] flex items-center justify-between text-[11px] font-mono">
                  <span className="text-cyan-300 font-bold flex items-center gap-1.5 uppercase">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    {lang}
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopyText(codeContent, codeId)}
                      className="text-slate-300 hover:text-cyan-300 flex items-center gap-1 text-[11px] px-2 py-0.5 rounded hover:bg-white/5 transition-colors cursor-pointer"
                    >
                      {copiedId === codeId ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                      <span>{copiedId === codeId ? 'Copied!' : 'Copy Code'}</span>
                    </button>
                  </div>
                </div>

                <pre className="p-3.5 bg-[#040A12] text-slate-100 font-mono text-[11px] overflow-x-auto leading-relaxed whitespace-pre">
                  <code>{codeContent}</code>
                </pre>

                {/* If the code snippet looks like a query or detection, provide direct SOC actions */}
                {(lang.includes('kql') ||
                  lang.includes('spl') ||
                  lang.includes('eql') ||
                  lang.includes('sql') ||
                  lang.includes('aql') ||
                  lang.includes('sigma') ||
                  lang.includes('yara') ||
                  codeContent.toLowerCase().includes('| where') ||
                  codeContent.toLowerCase().includes('index=') ||
                  codeContent.toLowerCase().includes('select ')) && (
                  <div className="bg-[#0D1929] px-3 py-2 border-t border-[#1B3047] flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => onLoadQueryInGenerator(codeContent, selectedPlatform)}
                      className="px-2.5 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1 text-[10px] font-bold transition-all cursor-pointer"
                    >
                      <Zap className="w-3 h-3 text-cyan-400" />
                      Load in Generator
                    </button>

                    <button
                      onClick={() => onLoadQueryInTranslator(codeContent, selectedPlatform)}
                      className="px-2.5 py-1 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 border border-teal-500/30 flex items-center gap-1 text-[10px] font-bold transition-all cursor-pointer"
                    >
                      <RefreshCw className="w-3 h-3 text-teal-400" />
                      Translate in Studio
                    </button>

                    {userRole !== 'visitor' && (
                      <button
                        onClick={() => onLoadQueryInOptimizer(codeContent, selectedPlatform)}
                        className="px-2.5 py-1 rounded-lg bg-[#0B1726] hover:bg-[#101F32] text-slate-200 border border-[#1B3047] hover:border-cyan-500/30 flex items-center gap-1 text-[10px] font-bold transition-all cursor-pointer"
                      >
                        <Gauge className="w-3 h-3 text-cyan-400" />
                        Optimize Query
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          }

          // Format paragraphs, headers, and bullet lists
          const paragraphs = part.split(/\n\n+/);
          return (
            <div key={partIdx} className="space-y-2">
              {paragraphs.map((para, pIdx) => {
                const trimmed = para.trim();
                if (!trimmed) return null;

                // Headers
                if (trimmed.startsWith('### ')) {
                  return (
                    <h3 key={pIdx} className="text-sm font-bold text-cyan-300 pt-1 pb-0.5 border-b border-[#1B3047]/60">
                      {trimmed.slice(4)}
                    </h3>
                  );
                }
                if (trimmed.startsWith('## ')) {
                  return (
                    <h2 key={pIdx} className="text-base font-bold text-white pt-1.5 pb-0.5">
                      {trimmed.slice(3)}
                    </h2>
                  );
                }
                if (trimmed.startsWith('# ')) {
                  return (
                    <h1 key={pIdx} className="text-lg font-bold text-white pt-2 pb-1">
                      {trimmed.slice(2)}
                    </h1>
                  );
                }

                // Bullet Lists
                if (trimmed.startsWith('- ') || trimmed.startsWith('* ') || trimmed.startsWith('• ')) {
                  const items = trimmed.split('\n').filter((l) => l.trim().length > 0);
                  return (
                    <ul key={pIdx} className="space-y-1 pl-4 list-disc marker:text-cyan-400 text-slate-300">
                      {items.map((item, itemIdx) => {
                        const cleanItem = item.replace(/^[-*•]\s*/, '');
                        return <li key={itemIdx}>{renderInlineMarkdown(cleanItem)}</li>;
                      })}
                    </ul>
                  );
                }

                // Numbered Lists
                if (/^\d+\.\s/.test(trimmed)) {
                  const items = trimmed.split('\n').filter((l) => l.trim().length > 0);
                  return (
                    <ol key={pIdx} className="space-y-1 pl-4 list-decimal marker:text-cyan-400 text-slate-300">
                      {items.map((item, itemIdx) => {
                        const cleanItem = item.replace(/^\d+\.\s*/, '');
                        return <li key={itemIdx}>{renderInlineMarkdown(cleanItem)}</li>;
                      })}
                    </ol>
                  );
                }

                // Standard paragraph
                return (
                  <p key={pIdx} className="leading-relaxed text-slate-200">
                    {renderInlineMarkdown(trimmed)}
                  </p>
                );
              })}
            </div>
          );
        })}
      </div>
    );
  };

  // Helper for inline markdown: bold, inline code, italics
  const renderInlineMarkdown = (text: string) => {
    // Split by inline code `...`
    const codeSegments = text.split(/(`[^`]+`)/g);

    return codeSegments.map((segment, segIdx) => {
      if (segment.startsWith('`') && segment.endsWith('`') && segment.length >= 2) {
        return (
          <code key={segIdx} className="px-1.5 py-0.5 rounded bg-[#101F32] text-cyan-300 font-mono text-[11px] border border-cyan-500/20">
            {segment.slice(1, -1)}
          </code>
        );
      }

      // Format bold text within segment
      const boldSegments = segment.split(/(\*\*[^*]+\*\*)/g);
      return (
        <React.Fragment key={segIdx}>
          {boldSegments.map((bSeg, bIdx) => {
            if (bSeg.startsWith('**') && bSeg.endsWith('**') && bSeg.length >= 4) {
              return (
                <strong key={bIdx} className="font-bold text-white">
                  {bSeg.slice(2, -2)}
                </strong>
              );
            }
            return bSeg;
          })}
        </React.Fragment>
      );
    });
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header Banner - Ask SOCPulse */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono font-semibold">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>Ask SOCPulse</span>
              </div>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-teal-500/15 text-teal-300 border border-teal-500/30 flex items-center gap-1">
                <Cpu className="w-3 h-3" /> GENERATIVE AI CHATBOT
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono text-slate-400 bg-[#060D18] border border-[#1B3047]">
                Multi-Turn • Irrespective of Topic
              </span>
            </div>

            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <span>Ask SOCPulse — Conversational AI Assistant</span>
            </h2>
            <p className="text-slate-400 font-sans text-xs leading-relaxed max-w-3xl">
              Ask anything — from SOC detection engineering, threat hunting, and log queries to programming, script automation, system architectures, or open general knowledge questions typical of a generative AI.
            </p>
          </div>

          {/* Controls: Target SIEM Context & Replicate System Prompt */}
          <div className="flex flex-wrap sm:flex-nowrap items-center gap-3 shrink-0">
            <button
              onClick={() => setShowReplicationPrompt(!showReplicationPrompt)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-[#060D18] hover:bg-[#101F32] border border-[#1B3047] hover:border-cyan-500/40 text-cyan-300 font-medium text-xs transition-all cursor-pointer"
              title="View and copy the system prompt to replicate in other AI platforms"
            >
              <Share2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>{showReplicationPrompt ? 'Hide Prompt' : 'Replicate Prompt'}</span>
            </button>

            {/* Target Dialect context (optional helper for SIEM queries) */}
            <div className="bg-[#060D18] p-2 rounded-xl border border-[#1B3047] flex items-center gap-2">
              <label htmlFor="copilot-platform-select" className="text-slate-400 text-[10px] font-semibold whitespace-nowrap pl-1">
                Query Context:
              </label>
              <select
                id="copilot-platform-select"
                value={selectedPlatform}
                onChange={(e) => onPlatformChange(e.target.value as SiemPlatformId)}
                className="bg-[#0B1726] text-slate-100 font-mono text-xs border border-[#1B3047] rounded-lg px-2.5 py-1 focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer"
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

        {/* REPLICATION SYSTEM PROMPT MODAL / CARD */}
        {showReplicationPrompt && (
          <div className="bg-[#060D18] p-4 rounded-xl border border-cyan-500/30 shadow-lg space-y-2 animate-in fade-in duration-200">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <Code className="w-4 h-4 text-cyan-400" />
                <span>System Prompt: Replicate "Ask SOCPulse" Generative AI</span>
              </div>
              <button
                onClick={copyReplicationPrompt}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-bold text-xs transition-all cursor-pointer"
              >
                {copiedReplicationPrompt ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedReplicationPrompt ? 'Copied!' : 'Copy System Prompt'}</span>
              </button>
            </div>
            <pre className="bg-[#03070E] p-3 rounded-lg border border-[#1B3047] text-cyan-200/90 font-mono text-[11px] leading-relaxed whitespace-pre-wrap overflow-x-auto max-h-36">
              {REPLICATION_PROMPT}
            </pre>
          </div>
        )}

        {/* Starter Prompts Bar */}
        <div className="pt-2 border-t border-[#1B3047]/60">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-300 font-bold text-xs flex items-center gap-1.5">
              <Lightbulb className="w-3.5 h-3.5 text-cyan-400" />
              Suggested Starter Prompts:
            </span>
            <button
              onClick={clearChat}
              className="text-slate-400 hover:text-cyan-400 flex items-center gap-1 text-[11px] transition-colors cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Chat</span>
            </button>
          </div>

          <div className="flex overflow-x-auto gap-2 py-1 no-scrollbar">
            {STARTER_PROMPTS.map((item, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(item.prompt)}
                className="bg-[#060D18] hover:bg-[#101F32] text-slate-300 hover:text-cyan-300 border border-[#1B3047] hover:border-cyan-500/40 px-3 py-1.5 rounded-xl text-left transition-all shrink-0 flex items-center gap-2 group cursor-pointer"
              >
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono border ${item.badgeColor}`}>
                  {item.category}
                </span>
                <span className="text-[11px] font-sans truncate max-w-[280px]">{item.prompt}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Interactive Chat Area */}
      <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] flex flex-col h-[600px] overflow-hidden shadow-2xl">
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
                    : 'bg-cyan-500/10 border border-cyan-500/40 text-cyan-400'
                }`}
              >
                {msg.sender === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Content Bubble */}
              <div className="space-y-2.5 flex-1 min-w-0">
                <div
                  className={`p-4 rounded-2xl border ${
                    msg.sender === 'user'
                      ? 'bg-cyan-500/10 border-cyan-500/30 text-slate-100 rounded-tr-none'
                      : 'bg-[#060D18] border-[#1B3047] text-slate-200 rounded-tl-none shadow-md'
                  }`}
                >
                  <div className="flex items-center justify-between gap-4 mb-2.5 text-[10px] text-slate-400 font-mono">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-cyan-400">
                        {msg.sender === 'user' ? 'You' : 'Ask SOCPulse'}
                      </span>
                      {msg.modelUsed && msg.sender === 'assistant' && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-cyan-950/70 text-cyan-300 border border-cyan-500/30 font-mono">
                          {msg.modelUsed}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleCopyText(msg.text, msg.id)}
                        className="text-slate-400 hover:text-cyan-300 flex items-center gap-1 text-[10px] cursor-pointer"
                        title="Copy message text"
                      >
                        {copiedId === msg.id ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                        <span>{copiedId === msg.id ? 'Copied' : 'Copy'}</span>
                      </button>
                      <span>{msg.timestamp}</span>
                    </div>
                  </div>

                  {/* Render content */}
                  {msg.sender === 'assistant' ? (
                    renderFormattedMessage(msg.text, msg.id)
                  ) : (
                    <p className="font-sans text-xs leading-relaxed whitespace-pre-wrap text-slate-100">
                      {msg.text}
                    </p>
                  )}

                  {/* Badges Bar if MITRE or Threat Actor was tagged */}
                  {msg.sender === 'assistant' && (msg.mitreTactic || msg.mitreTechnique) && (
                    <div className="mt-3 pt-2 border-t border-[#1B3047] flex items-center gap-2 flex-wrap">
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
                </div>

                {/* Follow-up Suggestions Chips */}
                {msg.followUpSuggestions && msg.followUpSuggestions.length > 0 && (
                  <div className="space-y-1 pl-1">
                    <span className="text-[10px] text-slate-400 flex items-center gap-1">
                      <MessageSquare className="w-3 h-3 text-cyan-400" />
                      Suggested Follow-Ups:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.followUpSuggestions.map((suggestion, sIdx) => (
                        <button
                          key={sIdx}
                          onClick={() => handleSend(suggestion)}
                          className="text-[11px] font-sans px-2.5 py-1 rounded-lg bg-[#060D18] hover:bg-[#101F32] text-slate-300 hover:text-cyan-300 border border-[#1B3047] hover:border-cyan-500/40 text-left transition-colors flex items-center gap-1.5 cursor-pointer"
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
              <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/40 text-cyan-400 flex items-center justify-center shrink-0">
                <Bot className="w-4 h-4 animate-spin" />
              </div>
              <div className="bg-[#060D18] border border-[#1B3047] p-3.5 rounded-2xl text-cyan-300 font-mono text-xs flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400 animate-pulse" />
                <span>Ask SOCPulse is thinking & generating answer...</span>
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
            className="flex items-end gap-2"
          >
            <div className="relative flex-1">
              <textarea
                ref={textareaRef}
                id="input-copilot-natural-query"
                rows={2}
                value={inputQuery}
                onChange={(e) => setInputQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSend();
                  }
                }}
                placeholder={`Ask SOCPulse anything (e.g. "Explain Kerberoasting", "Write a python script to parse logs", "Detect brute force in ${platformMeta.name}")...`}
                disabled={loading}
                className="w-full bg-[#060D18] text-slate-100 font-mono text-xs px-4 py-2.5 rounded-xl border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500 disabled:opacity-50 resize-none pr-10"
              />
              <div className="absolute right-3 bottom-3 text-slate-500 text-[10px] hidden sm:flex items-center gap-1 font-mono">
                <CornerDownLeft className="w-3 h-3" /> Enter to send
              </div>
            </div>

            <button
              id="btn-copilot-send"
              type="submit"
              disabled={loading || !inputQuery.trim()}
              className="px-5 py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-40 text-[#060D18] font-bold flex items-center gap-2 shadow-lg shadow-cyan-500/10 cursor-pointer transition-all shrink-0"
            >
              <Send className="w-4 h-4 fill-[#060D18]" />
              <span className="hidden sm:inline">Ask SOCPulse</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
