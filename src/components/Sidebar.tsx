import React, { useState } from 'react';
import {
  Sparkles,
  GitBranch,
  Gauge,
  FileText,
  ShieldCheck,
  Globe,
  Zap,
  RefreshCw,
  Terminal as TerminalIcon,
  BookOpen,
  FileCode,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Layers,
  Activity,
  Code2,
  Bookmark,
  Server,
  Cloud,
  Database,
  ShieldAlert,
  Cpu,
  Search,
  Key,
  Check,
  Mail,
} from 'lucide-react';
import { ViewMode, ThemeMode, SiemPlatformId, UserRole } from '../types';
import { SIEM_PLATFORMS, SIEM_PLATFORM_LIST } from '../data/siemPlatforms';

interface SidebarProps {
  currentView: ViewMode;
  onViewChange: (view: ViewMode) => void;
  theme: ThemeMode;
  selectedPlatform: SiemPlatformId;
  onPlatformChange: (platform: SiemPlatformId) => void;
  userRole?: UserRole;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
}

interface NavItem {
  id: ViewMode;
  label: string;
  icon: React.ElementType;
  badge?: string;
}

interface NavGroup {
  title: string;
  groupIcon: React.ElementType;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onViewChange,
  theme,
  selectedPlatform,
  onPlatformChange,
  userRole = 'visitor',
  isCollapsed = false,
  onToggleCollapse,
}) => {
  const [isSiemExpanded, setIsSiemExpanded] = useState(true);
  const [siemSearch, setSiemSearch] = useState('');

  const isLight = theme === 'light';

  const getSiemIcon = (iconName: string) => {
    switch (iconName) {
      case 'ShieldCheck':
        return ShieldCheck;
      case 'ShieldAlert':
        return ShieldAlert;
      case 'Terminal':
        return TerminalIcon;
      case 'Cloud':
        return Cloud;
      case 'Database':
        return Database;
      case 'Activity':
        return Activity;
      case 'Cpu':
        return Cpu;
      case 'Search':
        return Search;
      case 'Layers':
        return Layers;
      case 'Key':
        return Key;
      case 'Zap':
      default:
        return Zap;
    }
  };

  const allNavGroups: NavGroup[] = [
    {
      title: 'Operations & AI',
      groupIcon: Activity,
      items: [
        {
          id: 'copilot',
          label: 'Ask Copilot',
          icon: Sparkles,
          badge: 'AI',
        },
        {
          id: 'attack_path',
          label: 'Attack Path Simulator',
          icon: GitBranch,
          badge: 'Blast',
        },
        {
          id: 'rule_benchmarker',
          label: 'Rule Benchmark & Cost',
          icon: Gauge,
          badge: 'SIEM',
        },
        {
          id: 'incident_retro',
          label: 'Alert Playbook (AAR)',
          icon: FileText,
          badge: 'AAR',
        },
      ],
    },
    {
      title: 'Data & Threat Intel',
      groupIcon: Layers,
      items: [
        {
          id: 'iocs_masker',
          label: 'IOC Masker & Defanger',
          icon: ShieldCheck,
        },
        {
          id: 'iocs_reputation',
          label: 'IOC Reputation Intel',
          icon: Globe,
        },
        {
          id: 'sandbox',
          label: 'Sandbox Intel',
          icon: Cpu,
          badge: 'OPEN SOURCE',
        },
        {
          id: 'email_header',
          label: 'Email Header Forensics',
          icon: Mail,
          badge: 'NEW',
        },
      ],
    },
    {
      title: 'Detection Studio',
      groupIcon: Code2,
      items: [
        {
          id: 'generator',
          label: 'Query Generator',
          icon: Zap,
        },
        {
          id: 'translator',
          label: 'SIEM Query Translator Studio',
          icon: RefreshCw,
        },
        {
          id: 'optimizer',
          label: 'Query Optimizer',
          icon: TerminalIcon,
        },
      ],
    },
    {
      title: 'Knowledge Base',
      groupIcon: Bookmark,
      items: [
        {
          id: 'playbooks',
          label: 'Threat Playbooks',
          icon: BookOpen,
        },
        {
          id: 'cheat_sheet',
          label: 'SIEM Syntax Guide',
          icon: FileCode,
        },
      ],
    },
  ];

  // For visitors: hide attack_path, rule_benchmarker, and playbooks
  const navGroups: NavGroup[] = allNavGroups
    .map((group) => {
      const filteredItems = group.items.filter((item) => {
        if (userRole === 'visitor') {
          if (
            item.id === 'attack_path' ||
            item.id === 'rule_benchmarker' ||
            item.id === 'playbooks'
          ) {
            return false;
          }
        }
        return true;
      });
      return { ...group, items: filteredItems };
    })
    .filter((group) => group.items.length > 0);

  const filteredSiemPlatforms = SIEM_PLATFORM_LIST.filter(
    (p) =>
      p.name.toLowerCase().includes(siemSearch.toLowerCase()) ||
      p.language.toLowerCase().includes(siemSearch.toLowerCase()) ||
      p.category.toLowerCase().includes(siemSearch.toLowerCase())
  );

  const getSidebarClasses = () => {
    if (isLight) {
      return 'bg-white/95 backdrop-blur-xl border-slate-200 text-slate-800 shadow-sm';
    }
    return 'bg-[#07111F] backdrop-blur-xl border-[#1B3047] text-slate-200 shadow-2xl';
  };

  const getActiveItemClass = () => {
    if (isLight) {
      return 'bg-cyan-50 text-cyan-950 border-l-2 border-cyan-500 shadow-xs font-semibold';
    }
    return 'bg-[#0B1726] text-cyan-300 border-l-2 border-cyan-400 border-y-transparent border-r-transparent shadow-xs font-semibold';
  };

  const getInactiveItemClass = () => {
    if (isLight) {
      return 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 border-transparent';
    }
    return 'text-slate-400 hover:bg-[#0B1726] hover:text-slate-200 border-transparent';
  };

  return (
    <aside
      className={`transition-all duration-300 ease-in-out shrink-0 border-r flex flex-col z-30 ${
        isCollapsed ? 'w-16' : 'w-72'
      } ${getSidebarClasses()}`}
    >
      {/* Top Header Controls in Sidebar */}
      <div className="p-3 border-b border-inherit flex items-center justify-between">
        {!isCollapsed && (
          <div className="flex items-center gap-2">
            <span
              className={`text-xs font-mono font-semibold uppercase tracking-wider ${
                isLight ? 'text-slate-600' : 'text-slate-400'
              }`}
            >
              MODULE NAVIGATION
            </span>
          </div>
        )}
        {onToggleCollapse && (
          <button
            id="sidebar-toggle-btn"
            onClick={onToggleCollapse}
            title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
            className={`p-1.5 rounded-lg border transition-all ${
              isLight
                ? 'bg-white border-slate-200 hover:bg-slate-100 text-slate-600'
                : 'bg-[#0B1726] border-[#1B3047] hover:bg-[#101F32] text-slate-300 hover:text-cyan-400'
            }`}
          >
            {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        )}
      </div>

      {/* Vertical Navigation Group List */}
      <div className="flex-1 overflow-y-auto p-2.5 space-y-4 no-scrollbar">
        {/* Module Groups */}
        {navGroups.map((group, groupIdx) => (
          <div key={groupIdx} className="space-y-1">
            {!isCollapsed && (
              <div className="px-2.5 py-0.5 flex items-center justify-between">
                <span
                  className={`text-[10px] font-mono font-bold tracking-wider uppercase flex items-center gap-1.5 ${
                    isLight ? 'text-slate-400' : 'text-slate-500'
                  }`}
                >
                  <group.groupIcon className="w-3 h-3 text-cyan-400/80" />
                  {group.title}
                </span>
              </div>
            )}

            <div className="space-y-0.5">
              {group.items.map((item) => {
                const isActive = currentView === item.id;
                const Icon = item.icon;
                const activeClass = isActive ? getActiveItemClass() : getInactiveItemClass();

                return (
                  <button
                    key={item.id}
                    id={`sidebar-nav-${item.id}`}
                    onClick={() => onViewChange(item.id)}
                    title={isCollapsed ? item.label : undefined}
                    className={`w-full flex items-center justify-between gap-2 px-2.5 py-2 rounded-lg border text-xs font-medium transition-all ${activeClass}`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'scale-105 text-cyan-400' : 'opacity-80'}`} />
                      {!isCollapsed && (
                        <span className="truncate text-left font-sans text-xs">{item.label}</span>
                      )}
                    </div>

                    {!isCollapsed && item.badge && (
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-semibold shrink-0 ${
                          isActive
                            ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                            : isLight
                            ? 'bg-slate-200 text-slate-600'
                            : 'bg-[#0B1726] text-slate-400 border border-[#1B3047]'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}

        {/* Dedicated SIEM Tools Navigation Section */}
        <div className="pt-2 border-t border-inherit space-y-1">
          {!isCollapsed && (
            <button
              onClick={() => setIsSiemExpanded((prev) => !prev)}
              className="w-full px-2.5 py-1 flex items-center justify-between text-left hover:opacity-80 transition-opacity"
            >
              <span
                className={`text-[10px] font-mono font-bold tracking-wider uppercase flex items-center gap-1.5 ${
                  isLight ? 'text-slate-600' : 'text-slate-400'
                }`}
              >
                <Server className="w-3 h-3 text-cyan-400" />
                Target SIEM Engines ({SIEM_PLATFORM_LIST.length})
              </span>
              <ChevronDown
                className={`w-3 h-3 transition-transform ${isSiemExpanded ? 'rotate-180' : ''} opacity-60`}
              />
            </button>
          )}

          {(!isCollapsed ? isSiemExpanded : true) && (
            <div className="space-y-1">
              {!isCollapsed && (
                <div className="px-1 pb-1">
                  <input
                    type="text"
                    placeholder="Filter SIEM tools..."
                    value={siemSearch}
                    onChange={(e) => setSiemSearch(e.target.value)}
                    className={`w-full text-[11px] px-2 py-1 rounded border font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
                      isLight
                        ? 'bg-slate-50 border-slate-200 text-slate-800 placeholder-slate-400'
                        : 'bg-[#060D18] border-[#1B3047] text-slate-200 placeholder-slate-600'
                    }`}
                  />
                </div>
              )}

              <div className="space-y-0.5 max-h-52 overflow-y-auto pr-1 no-scrollbar">
                {filteredSiemPlatforms.map((platform) => {
                  const isSelected = selectedPlatform === platform.id;
                  const Icon = getSiemIcon(platform.icon);

                  let activeSiemClass = '';
                  if (isSelected) {
                    activeSiemClass = isLight
                      ? 'bg-cyan-50 border-cyan-300 text-cyan-950 font-semibold shadow-xs'
                      : 'bg-[#0B1726] text-cyan-300 border-cyan-500/50 font-semibold shadow-xs';
                  } else {
                    activeSiemClass = isLight
                      ? 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 border-transparent'
                      : 'text-slate-400 hover:bg-[#0B1726] hover:text-slate-200 border-transparent';
                  }

                  return (
                    <button
                      key={platform.id}
                      id={`sidebar-siem-tool-${platform.id}`}
                      onClick={() => onPlatformChange(platform.id)}
                      title={`${platform.name} (${platform.language})`}
                      className={`w-full flex items-center justify-between gap-1.5 px-2 py-1.5 rounded-lg border text-xs transition-all ${activeSiemClass}`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <Icon className={`w-3.5 h-3.5 shrink-0 ${isSelected ? 'scale-110 text-cyan-400' : 'opacity-70'}`} />
                        {!isCollapsed && (
                          <div className="truncate text-left">
                            <span className="truncate block font-sans text-[11px] leading-tight">
                              {platform.name}
                            </span>
                            <span className="text-[9px] font-mono opacity-60 leading-none">
                              {platform.language.split(' ')[0]}
                            </span>
                          </div>
                        )}
                      </div>

                      {!isCollapsed && isSelected && (
                        <Check className="w-3.5 h-3.5 shrink-0 text-cyan-400" />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Bottom SIEM Platform Indicator */}
      {!isCollapsed && (
        <div className="p-3 border-t border-inherit">
          <div
            className={`p-2.5 rounded-xl border flex items-center justify-between text-xs transition-all ${
              isLight
                ? 'bg-slate-50 border-slate-200 text-slate-800'
                : 'bg-[#0B1726] border-[#1B3047] text-slate-300'
            }`}
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center font-bold border shrink-0 ${
                  isLight
                    ? 'bg-white border-cyan-300 text-cyan-600 shadow-xs'
                    : 'bg-[#060D18] border-cyan-500/30 text-cyan-400'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
              </div>
              <div className="truncate">
                <p className="text-[9px] font-mono uppercase tracking-wider text-slate-400">Active Engine</p>
                <p className="font-semibold font-sans text-xs truncate leading-tight text-white">
                  {SIEM_PLATFORMS[selectedPlatform]?.name || selectedPlatform}
                </p>
                <p className="text-[10px] font-mono opacity-70 truncate leading-none mt-0.5 text-cyan-300/90">
                  {SIEM_PLATFORMS[selectedPlatform]?.language}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};
