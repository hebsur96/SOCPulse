import React, { useState } from 'react';
import { BookOpen, Search, ShieldAlert, ArrowRight, Tag, Terminal, ExternalLink } from 'lucide-react';
import { ThreatPlaybookItem, SiemPlatformId } from '../types';
import { THREAT_PLAYBOOKS } from '../data/threatPlaybooks';
import { SIEM_PLATFORMS } from '../data/siemPlatforms';

interface ThreatLibraryViewProps {
  onSelectPlaybookQuery: (query: string, platform: SiemPlatformId) => void;
}

export const ThreatLibraryView: React.FC<ThreatLibraryViewProps> = ({ onSelectPlaybookQuery }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedPlaybook, setSelectedPlaybook] = useState<ThreatPlaybookItem | null>(THREAT_PLAYBOOKS[0]);
  const [activePlatformTab, setActivePlatformTab] = useState<SiemPlatformId>('sentinel');

  const categories = ['All', ...new Set(THREAT_PLAYBOOKS.map((p) => p.category))];

  const filteredPlaybooks = THREAT_PLAYBOOKS.filter((p) => {
    const matchesCategory = selectedCategory === 'All' || p.category === selectedCategory;
    const matchesSearch =
      p.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.mitreTechniqueId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.tags.some((t) => t.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Banner */}
      <div className="bg-[#0B1726] p-6 rounded-2xl border border-[#1B3047] shadow-xl space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono">
          <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
          <span>SOC Threat Detection Playbooks Library</span>
        </div>
        <h2 className="text-xl font-bold text-white font-mono">
          Pre-built Production Detection Playbooks
        </h2>
        <p className="text-slate-400 font-sans text-xs leading-relaxed">
          Curated threat detection logic covering high-impact attack techniques across MITRE ATT&CK tactics. Click any playbook to inspect queries in KQL, SPL, AQL, XQL, YARA-L, and EQL.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0B1726] p-4 rounded-2xl border border-[#1B3047] flex flex-wrap items-center justify-between gap-4">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400/60" />
          <input
            id="input-threat-library-search"
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search Mimikatz, Kerberoasting, VSS, Certutil, MITRE ID..."
            className="w-full bg-[#060D18] text-slate-100 font-mono text-xs pl-9 pr-3 py-2 rounded-xl border border-[#1B3047] focus:outline-none focus:ring-1 focus:ring-cyan-500/40 focus:border-cyan-500/60"
          />
        </div>

        {/* Category Filter Pills */}
        <div className="flex overflow-x-auto gap-1 text-[11px] no-scrollbar">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg whitespace-nowrap transition-all cursor-pointer ${
                selectedCategory === cat
                  ? 'bg-cyan-400 text-[#060D18] font-bold shadow-xs'
                  : 'bg-[#060D18] text-slate-400 hover:text-cyan-300 border border-[#1B3047]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Grid: Playbook List & Detail View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Playbook Cards List */}
        <div className="lg:col-span-5 space-y-3">
          {filteredPlaybooks.map((pb) => {
            const isSelected = selectedPlaybook?.id === pb.id;

            return (
              <div
                key={pb.id}
                onClick={() => setSelectedPlaybook(pb)}
                className={`p-4 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-[#101F32] border-cyan-500/60 shadow-md shadow-cyan-500/5'
                    : 'bg-[#0B1726] border-[#1B3047] hover:border-cyan-500/30 hover:bg-[#0e1d30]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-bold">
                    {pb.mitreTechniqueId}
                  </span>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      pb.severity === 'Critical'
                        ? 'bg-red-500/10 text-[#EF4444] border border-red-500/30'
                        : 'bg-amber-500/10 text-[#F59E0B] border border-amber-500/30'
                    }`}
                  >
                    {pb.severity}
                  </span>
                </div>

                <h3 className="font-bold text-slate-200 text-xs mb-1 font-mono">{pb.title}</h3>
                <p className="text-slate-400 font-sans text-[11px] line-clamp-2">{pb.description}</p>

                <div className="mt-3 flex items-center gap-1.5 flex-wrap">
                  {pb.tags.map((t, idx) => (
                    <span key={idx} className="text-[10px] px-2 py-0.5 bg-[#060D18] text-slate-400 border border-[#1B3047] rounded">
                      #{t}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Playbook Code Inspector */}
        <div className="lg:col-span-7">
          {selectedPlaybook ? (
            <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] overflow-hidden space-y-4 p-6 sticky top-20 shadow-xl">
              <div className="space-y-2 border-b border-[#1B3047] pb-4">
                <div className="flex items-center justify-between">
                  <span className="text-cyan-300 font-bold">
                    {selectedPlaybook.mitreTactic} ({selectedPlaybook.mitreTechniqueId})
                  </span>
                  <span className="text-slate-400 text-[11px]">{selectedPlaybook.category}</span>
                </div>
                <h2 className="text-base font-bold text-white font-mono">{selectedPlaybook.title}</h2>
                <p className="text-slate-300 font-sans text-xs leading-relaxed">{selectedPlaybook.description}</p>
              </div>

              {/* Sample Log Telemetry snippet */}
              <div className="bg-[#060D18] p-3 rounded-xl border border-[#1B3047] space-y-1">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Target Log Telemetry Example:</span>
                <pre className="text-[11px] text-slate-300 font-mono overflow-x-auto whitespace-pre">
                  <code>{selectedPlaybook.sampleLog}</code>
                </pre>
              </div>

              {/* SIEM Language Tabs */}
              <div className="space-y-3">
                <div className="flex overflow-x-auto gap-1 border-b border-[#1B3047] pb-2 no-scrollbar">
                  {Object.keys(selectedPlaybook.platforms).map((platKey) => {
                    const pMeta = SIEM_PLATFORMS[platKey as SiemPlatformId];
                    if (!pMeta) return null;
                    const isActive = activePlatformTab === platKey;

                    return (
                      <button
                        key={platKey}
                        onClick={() => setActivePlatformTab(platKey as SiemPlatformId)}
                        className={`px-3 py-1 rounded-lg whitespace-nowrap text-[11px] font-medium transition-all cursor-pointer ${
                          isActive
                            ? 'bg-cyan-400 text-[#060D18] font-bold shadow-xs'
                            : 'text-slate-400 hover:text-cyan-300 bg-[#060D18] border border-[#1B3047]'
                        }`}
                      >
                        {pMeta.name.split(' ')[0]}
                      </button>
                    );
                  })}
                </div>

                {/* Selected SIEM Query Code Block */}
                <div className="bg-[#060D18] rounded-xl border border-[#1B3047] overflow-hidden">
                  <div className="bg-[#101F32] px-4 py-2 border-b border-[#1B3047] flex items-center justify-between">
                    <span className="text-slate-300 text-[11px] font-bold">
                      {SIEM_PLATFORMS[activePlatformTab]?.name} Query
                    </span>
                    <button
                      onClick={() =>
                        onSelectPlaybookQuery(
                          selectedPlaybook.platforms[activePlatformTab] || '',
                          activePlatformTab
                        )
                      }
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px] font-bold cursor-pointer transition-colors"
                    >
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      Load in Generator
                    </button>
                  </div>

                  <pre className="p-4 bg-[#060D18] text-teal-300 font-mono text-xs overflow-x-auto leading-relaxed whitespace-pre">
                    <code>
                      {selectedPlaybook.platforms[activePlatformTab] || '// No pre-built query for this dialect'}
                    </code>
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-[#0B1726] rounded-2xl border border-[#1B3047] p-12 text-center text-slate-500">
              Select a playbook on the left to inspect multi-platform queries.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
