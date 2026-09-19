import React, { useState, useRef, useEffect } from 'react';
import {
  Smartphone,
  Tablet,
  Monitor,
  Sun,
  Moon,
  Check,
  ChevronDown,
  Menu,
  ShieldCheck,
  UserCheck,
  Activity,
} from 'lucide-react';
import { DeviceFrameMode, SiemPlatformId, ThemeMode, UserRole } from '../types';
import { SIEM_PLATFORMS, SIEM_PLATFORM_LIST } from '../data/siemPlatforms';
import { USER_ROLES } from '../data/userRoles';

interface HeaderProps {
  deviceFrame: DeviceFrameMode;
  onDeviceFrameChange: (mode: DeviceFrameMode) => void;
  selectedPlatform: SiemPlatformId;
  onPlatformChange: (platform: SiemPlatformId) => void;
  theme: ThemeMode;
  onThemeChange: (theme: ThemeMode) => void;
  onToggleSidebar?: () => void;
  isSidebarCollapsed?: boolean;
  userRole?: UserRole;
  onUserRoleChange?: (role: UserRole) => void;
}

export const Header: React.FC<HeaderProps> = ({
  deviceFrame,
  onDeviceFrameChange,
  selectedPlatform,
  onPlatformChange,
  theme,
  onThemeChange,
  onToggleSidebar,
  isSidebarCollapsed = false,
  userRole = 'visitor',
  onUserRoleChange,
}) => {
  const [showPlatformPicker, setShowPlatformPicker] = useState(false);
  const [showRolePicker, setShowRolePicker] = useState(false);
  const [platformSearch, setPlatformSearch] = useState('');
  const platformPickerRef = useRef<HTMLDivElement>(null);
  const rolePickerRef = useRef<HTMLDivElement>(null);

  const isLight = theme === 'light';

  const currentRoleMeta = USER_ROLES[userRole] || USER_ROLES.visitor;

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (platformPickerRef.current && !platformPickerRef.current.contains(event.target as Node)) {
        setShowPlatformPicker(false);
      }
      if (rolePickerRef.current && !rolePickerRef.current.contains(event.target as Node)) {
        setShowRolePicker(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const getHeaderThemeClasses = () => {
    if (isLight) {
      return 'bg-white/95 text-slate-900 border-slate-200 shadow-xs';
    }
    return 'bg-[#07111F]/95 text-slate-100 border-[#1B3047] shadow-lg';
  };

  const activeSiemMeta = SIEM_PLATFORMS[selectedPlatform] || SIEM_PLATFORMS.sentinel;

  const filteredPlatforms = SIEM_PLATFORM_LIST.filter(
    (p) =>
      p.name.toLowerCase().includes(platformSearch.toLowerCase()) ||
      p.language.toLowerCase().includes(platformSearch.toLowerCase()) ||
      p.category.toLowerCase().includes(platformSearch.toLowerCase())
  );

  return (
    <header className={`sticky top-0 z-40 border-b transition-colors backdrop-blur-xl ${getHeaderThemeClasses()}`}>
      <div className="w-full mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-3">
          {/* Left: Brand & Mobile Sidebar Trigger */}
          <div className="flex items-center gap-3 shrink-0">
            {onToggleSidebar && (
              <button
                id="header-sidebar-toggle-btn"
                onClick={onToggleSidebar}
                title={isSidebarCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
                className={`p-2 rounded-lg border flex items-center justify-center transition-all ${
                  isLight
                    ? 'bg-slate-100 border-slate-200 hover:bg-slate-200 text-slate-700'
                    : 'bg-[#0B1726] border-[#1B3047] hover:bg-[#101F32] text-slate-200'
                }`}
              >
                <Menu className="w-4 h-4" />
              </button>
            )}

            <div className="flex items-center gap-2.5">
              <div
                className={`w-9 h-9 rounded-lg border flex items-center justify-center font-bold transition-all shadow-sm ${
                  isLight
                    ? 'bg-cyan-500 text-white border-cyan-600'
                    : 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30'
                }`}
              >
                <Activity className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-base font-bold tracking-tight font-sans text-white">
                    SOC<span className="text-cyan-400">Pulse</span>
                  </h1>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold ${
                      isLight
                        ? 'bg-cyan-50 text-cyan-800 border border-cyan-200'
                        : 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                    }`}
                  >
                    Enterprise
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Controls: Role Badge, SIEM Selector, Theme Palette Selector, Device Simulator */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* User Role & Permission Mode Selector - Hidden for Visitors */}
            {userRole !== 'visitor' && (
              <div className="relative" ref={rolePickerRef}>
                <button
                  id="header-role-selector-btn"
                  onClick={() => setShowRolePicker((prev) => !prev)}
                  title="Visitor & Admin Access Switcher"
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-mono transition-all shadow-xs ${
                    userRole === 'visitor'
                      ? isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-800 hover:bg-slate-100'
                        : 'bg-[#0B1726] border-[#1B3047] text-slate-200 hover:bg-[#101F32]'
                      : isLight
                      ? 'bg-cyan-50 border-cyan-300 text-cyan-900'
                      : 'bg-[#0B1726] border-cyan-500/40 text-cyan-300'
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    {userRole === 'visitor' ? (
                      <ShieldCheck className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    ) : (
                      <UserCheck className="w-3.5 h-3.5 text-teal-400 shrink-0" />
                    )}
                    <span className="font-sans font-semibold text-xs hidden sm:inline-block">
                      {currentRoleMeta.label}
                    </span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
                        userRole === 'visitor'
                          ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20'
                          : 'bg-teal-500/15 text-teal-300 border border-teal-500/30'
                      }`}
                    >
                      {userRole === 'visitor' ? 'Visitor' : 'Admin'}
                    </span>
                  </div>
                  <ChevronDown className="w-3 h-3 opacity-60 shrink-0" />
                </button>

                {/* Role Permissions Dropdown / Modal */}
                {showRolePicker && (
                  <div
                    className={`absolute right-0 mt-2 w-88 rounded-2xl border p-3 shadow-2xl z-50 animate-in fade-in slide-in-from-top-2 duration-150 ${
                      isLight
                        ? 'bg-white/95 backdrop-blur-xl border-slate-200 text-slate-900'
                        : 'bg-[#0B1726]/98 backdrop-blur-xl border-[#1B3047] text-slate-100'
                    }`}
                  >
                    <div className="px-1 py-1 mb-2 border-b border-inherit/40 flex items-center justify-between">
                      <span className="text-[10px] font-mono uppercase font-bold tracking-wider opacity-60">
                        Access Role & Security Policy
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        Role Switcher
                      </span>
                    </div>

                    <p className="text-[11px] font-sans opacity-75 px-1 mb-3">
                      Visitor and Admin roles both have access to the Email Header Forensics & Analysis engine, IOC investigations, and Copilot.
                    </p>

                    <div className="space-y-1.5 mb-3">
                      {Object.values(USER_ROLES).map((r) => {
                        const isSelected = userRole === r.role;
                        return (
                          <button
                            key={r.role}
                            onClick={() => {
                              if (onUserRoleChange) onUserRoleChange(r.role);
                              setShowRolePicker(false);
                            }}
                            className={`w-full flex items-center justify-between p-2 rounded-xl text-left text-xs transition-all ${
                              isSelected
                                ? isLight
                                  ? 'bg-cyan-50 font-semibold text-cyan-950 border border-cyan-200'
                                  : 'bg-[#101F32] font-semibold text-cyan-300 border border-cyan-500/40'
                                : isLight
                                ? 'hover:bg-slate-100 text-slate-700'
                                : 'hover:bg-white/5 text-slate-300'
                            }`}
                          >
                            <div className="min-w-0 pr-2">
                              <div className="flex items-center gap-1.5">
                                <span className="font-sans font-medium text-xs">
                                  {r.label}
                                </span>
                                <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-cyan-500/15 text-cyan-300">
                                  {r.badge}
                                </span>
                              </div>
                              <p className="text-[10px] font-mono opacity-60 leading-tight mt-0.5 truncate">
                                {r.description}
                              </p>
                            </div>
                            {isSelected && <Check className="w-4 h-4 shrink-0 text-cyan-400" />}
                          </button>
                        );
                      })}
                    </div>

                    {/* Active Permission Checklist */}
                    <div
                      className={`p-2.5 rounded-xl border text-[11px] font-mono space-y-1.5 ${
                        isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#060D18] border-[#1B3047]'
                      }`}
                    >
                      <p className="font-sans font-semibold text-xs opacity-90 mb-1 text-cyan-300">
                        {currentRoleMeta.label} Access Permissions:
                      </p>
                      <div className="flex items-center gap-1.5 text-slate-300">
                        <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span>Email Header Forensics & Phishing Classifier (Granted)</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-slate-300">
                        <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span>Natural Language SOC Copilot & Analysis</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-slate-300">
                        <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span>Query Generator across 11 SIEM Engines</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-slate-300">
                        <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span>IOC Defanger & Reputation Intelligence</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Active SIEM Platform Selector Dropdown */}
            <div className="relative" ref={platformPickerRef}>
              <button
                id="header-platform-selector-btn"
                onClick={() => setShowPlatformPicker((prev) => !prev)}
                title="Select Active Target SIEM Engine"
                className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-xs font-mono transition-all shadow-xs ${
                  isLight
                    ? 'bg-white hover:bg-slate-50 border-slate-300 text-slate-800'
                    : 'bg-[#0B1726] hover:bg-[#101F32] border-[#1B3047] text-slate-200'
                }`}
              >
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shrink-0" />
                  <span className="font-sans font-semibold text-xs truncate max-w-[120px] sm:max-w-[150px]">
                    {activeSiemMeta.name}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-1 py-0.2 rounded font-semibold hidden md:inline-block ${
                      isLight
                        ? 'bg-cyan-50 text-cyan-900 border border-cyan-200'
                        : 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                    }`}
                  >
                    {activeSiemMeta.language.split(' ')[0]}
                  </span>
                </div>
                <ChevronDown className="w-3 h-3 opacity-60 shrink-0" />
              </button>

              {/* SIEM Platforms Dropdown Menu */}
              {showPlatformPicker && (
                <div
                  className={`absolute right-0 mt-2 w-80 rounded-2xl border p-2 shadow-2xl z-50 animate-in fade-in slide-in-from-top-2 duration-150 ${
                    isLight
                      ? 'bg-white/95 backdrop-blur-xl border-slate-200 text-slate-900'
                      : 'bg-[#0B1726]/98 backdrop-blur-xl border-[#1B3047] text-slate-100'
                  }`}
                >
                  <div className="px-2.5 py-1.5 mb-1.5 border-b border-inherit/40 flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase font-bold tracking-wider opacity-60">
                      Target SIEM Engines
                    </span>
                    <span className="text-[10px] font-mono opacity-50">
                      {SIEM_PLATFORM_LIST.length} Platforms
                    </span>
                  </div>

                  <div className="px-1 pb-2">
                    <input
                      type="text"
                      placeholder="Search SIEM tools..."
                      value={platformSearch}
                      onChange={(e) => setPlatformSearch(e.target.value)}
                      className={`w-full text-xs px-2.5 py-1.5 rounded-lg border font-sans focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
                        isLight
                          ? 'bg-slate-50 border-slate-200 text-slate-800 placeholder-slate-400'
                          : 'bg-[#060D18] border-[#1B3047] text-slate-200 placeholder-slate-500'
                      }`}
                    />
                  </div>

                  <div className="space-y-1 max-h-72 overflow-y-auto no-scrollbar pr-1">
                    {filteredPlatforms.map((platform) => {
                      const isSelected = selectedPlatform === platform.id;
                      return (
                        <button
                          key={platform.id}
                          id={`header-siem-option-${platform.id}`}
                          onClick={() => {
                            onPlatformChange(platform.id);
                            setShowPlatformPicker(false);
                          }}
                          className={`w-full flex items-center justify-between p-2 rounded-xl text-left text-xs transition-all ${
                            isSelected
                              ? isLight
                                ? 'bg-cyan-50 font-semibold text-cyan-950 border border-cyan-200'
                                : 'bg-[#101F32] font-semibold text-cyan-300 border border-cyan-500/40'
                              : isLight
                              ? 'hover:bg-slate-100 text-slate-700'
                              : 'hover:bg-white/5 text-slate-300'
                          }`}
                        >
                          <div className="min-w-0 pr-2">
                            <div className="flex items-center gap-2">
                              <p className="font-sans font-medium text-xs truncate">
                                {platform.name}
                              </p>
                              <span
                                className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-semibold ${
                                  isLight ? 'bg-slate-200 text-slate-700' : 'bg-[#060D18] text-cyan-300 border border-[#1B3047]'
                                }`}
                              >
                                {platform.category}
                              </span>
                            </div>
                            <p className="text-[10px] font-mono opacity-60 leading-tight mt-0.5 truncate">
                              Syntax: {platform.language}
                            </p>
                          </div>

                          {isSelected && (
                            <Check className="w-4 h-4 shrink-0 text-cyan-400" />
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Quick Dark / Light Switcher Buttons */}
            <div
              className={`flex items-center p-0.5 rounded-lg border text-xs font-mono ${
                isLight
                  ? 'bg-slate-100 border-slate-300 text-slate-700'
                  : 'bg-[#0B1726] border-[#1B3047] text-slate-300'
              }`}
            >
              <button
                id="theme-btn-light"
                title="Light Theme"
                onClick={() => onThemeChange('light')}
                className={`p-1.5 rounded transition-colors ${
                  theme === 'light'
                    ? 'bg-white text-cyan-600 font-bold shadow-xs'
                    : 'hover:text-white opacity-70'
                }`}
              >
                <Sun className="w-3.5 h-3.5" />
              </button>
              <button
                id="theme-btn-dark"
                title="Deep Navy & Cyan Dark Theme"
                onClick={() => onThemeChange('dark')}
                className={`p-1.5 rounded transition-colors ${
                  theme === 'dark'
                    ? 'bg-[#101F32] text-cyan-400 font-bold'
                    : 'hover:text-white opacity-70'
                }`}
              >
                <Moon className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Device Mode Switcher */}
            <div
              className={`hidden sm:flex items-center border rounded-lg p-0.5 text-xs font-mono ${
                isLight
                  ? 'bg-slate-100 border-slate-300 text-slate-600'
                  : 'bg-[#0B1726] border-[#1B3047] text-slate-400'
              }`}
            >
              <button
                id="device-frame-desktop"
                title="Desktop Layout"
                onClick={() => onDeviceFrameChange('desktop')}
                className={`p-1.5 rounded transition-colors ${
                  deviceFrame === 'desktop'
                    ? isLight
                      ? 'bg-white text-slate-900 shadow-xs font-semibold'
                      : 'bg-[#101F32] text-cyan-400 font-semibold'
                    : 'hover:text-slate-200'
                }`}
              >
                <Monitor className="w-3.5 h-3.5" />
              </button>
              <button
                id="device-frame-ios"
                title="iOS App Frame"
                onClick={() => onDeviceFrameChange('ios')}
                className={`p-1.5 rounded transition-colors ${
                  deviceFrame === 'ios'
                    ? isLight
                      ? 'bg-white text-slate-900 shadow-xs font-semibold'
                      : 'bg-[#101F32] text-cyan-400 font-semibold'
                    : 'hover:text-slate-200'
                }`}
              >
                <Smartphone className="w-3.5 h-3.5" />
              </button>
              <button
                id="device-frame-android"
                title="Android App Frame"
                onClick={() => onDeviceFrameChange('android')}
                className={`p-1.5 rounded transition-colors ${
                  deviceFrame === 'android'
                    ? isLight
                      ? 'bg-white text-slate-900 shadow-xs font-semibold'
                      : 'bg-[#101F32] text-cyan-400 font-semibold'
                    : 'hover:text-slate-200'
                }`}
              >
                <Tablet className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

