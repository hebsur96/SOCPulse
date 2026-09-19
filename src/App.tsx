import React, { useState, useEffect } from 'react';
import { ViewMode, DeviceFrameMode, SiemPlatformId, DetectionBreakdown, ThemeMode, UserRole } from './types';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { DeviceFrame } from './components/DeviceFrame';
import { QueryGeneratorView } from './components/QueryGeneratorView';
import { MultiPlatformTranslatorView } from './components/MultiPlatformTranslatorView';
import { QueryOptimizerView } from './components/QueryOptimizerView';
import { ThreatLibraryView } from './components/ThreatLibraryView';
import { CheatSheetView } from './components/CheatSheetView';
import { ExportModal } from './components/ExportModal';
import { NaturalQueryCopilotView } from './components/NaturalQueryCopilotView';
import { IocMaskerView } from './components/IocMaskerView';
import { IocReputationView } from './components/IocReputationView';
import { AttackPathSimulatorView } from './components/AttackPathSimulatorView';
import { RuleBenchmarkerView } from './components/RuleBenchmarkerView';
import { IncidentRetroView } from './components/IncidentRetroView';
import { EmailHeaderAnalyzerView } from './components/EmailHeaderAnalyzerView';
import { SandboxAnalysisView } from './components/SandboxAnalysisView';
import { ShieldCheck, Lock, X, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [currentView, setCurrentView] = useState<ViewMode>('copilot');
  const [deviceFrame, setDeviceFrame] = useState<DeviceFrameMode>('desktop');
  const [selectedPlatform, setSelectedPlatform] = useState<SiemPlatformId>('sentinel');
  const [theme, setTheme] = useState<ThemeMode>('dark');
  // Determine default user role:
  // If ?admin=true or ?role=admin is in URL, or stored in localStorage, set admin.
  // Otherwise, default to 'visitor' (clean experience for shared URL visitors).
  const [userRole, setUserRole] = useState<UserRole>(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const roleParam = urlParams.get('role');
      const adminParam = urlParams.get('admin');
      if (roleParam === 'admin' || adminParam === 'true' || adminParam === '1') {
        localStorage.setItem('socpulse_role', 'admin');
        return 'admin';
      }
      if (roleParam === 'visitor') {
        localStorage.setItem('socpulse_role', 'visitor');
        return 'visitor';
      }
      const savedRole = localStorage.getItem('socpulse_role') as UserRole | null;
      if (savedRole === 'admin' || savedRole === 'visitor') {
        return savedRole;
      }
    } catch {
      // ignore in SSR / restricted iframe
    }
    return 'visitor';
  });

  const handleRoleChange = (role: UserRole) => {
    setUserRole(role);
    try {
      localStorage.setItem('socpulse_role', role);
    } catch {}
  };
  const [showPermissionModal, setShowPermissionModal] = useState<boolean>(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);
  const [exportDetection, setExportDetection] = useState<DetectionBreakdown | null>(null);

  const [transferredQuery, setTransferredQuery] = useState<string | undefined>(undefined);
  const [transferredPrompt, setTransferredPrompt] = useState<string | undefined>(undefined);
  const [investigateIoc, setInvestigateIoc] = useState<string | undefined>(undefined);
  const [sandboxTarget, setSandboxTarget] = useState<string | undefined>(undefined);

  // If visitor is active and on a restricted tab, switch to copilot
  useEffect(() => {
    if (
      userRole === 'visitor' &&
      (currentView === 'attack_path' || currentView === 'rule_benchmarker' || currentView === 'playbooks')
    ) {
      setCurrentView('copilot');
    }
  }, [userRole, currentView]);

  const getThemeClasses = (t: ThemeMode) => {
    if (t === 'light') {
      return 'bg-[#F8FAFC] text-slate-900 selection:bg-cyan-500 selection:text-slate-950 bg-grid-light relative';
    }
    return 'bg-[#060D18] text-slate-100 selection:bg-cyan-400 selection:text-slate-950 bg-grid-dark relative';
  };

  const isLight = theme === 'light';

  return (
    <DeviceFrame mode={deviceFrame}>
      <div className={`min-h-screen flex flex-col font-sans transition-colors duration-300 ${getThemeClasses(theme)}`}>
        {/* Atmospheric Ambient Glow Backdrop - Enterprise Deep Navy & Cyan */}
        {!isLight ? (
          <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
            {/* Top Left Deep Navy Blue Aura */}
            <div className="absolute -top-32 -left-32 w-[550px] h-[550px] rounded-full bg-cyan-950/25 blur-[140px] animate-glow-1" />
            {/* Top Right Subtle Teal Glow */}
            <div className="absolute top-10 -right-32 w-[500px] h-[500px] rounded-full bg-teal-500/5 blur-[150px] animate-glow-2" />
            {/* Center Bottom Deep Slate Aura */}
            <div className="absolute -bottom-40 left-1/3 w-[650px] h-[650px] rounded-full bg-[#07111F]/80 blur-[160px]" />
            {/* Subtle radial vignette */}
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_25%,rgba(6,13,24,0.92)_100%)]" />
          </div>
        ) : (
          <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
            <div className="absolute -top-40 -left-40 w-[700px] h-[700px] rounded-full bg-gradient-to-br from-slate-200/40 via-sky-100/20 to-transparent blur-[130px] animate-glow-1" />
            <div className="absolute top-1/4 -right-40 w-[650px] h-[650px] rounded-full bg-gradient-to-bl from-sky-100/25 via-slate-200/20 to-transparent blur-[140px] animate-glow-2" />
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,transparent_30%,rgba(248,250,252,0.9)_100%)]" />
          </div>
        )}

        <div className="relative z-10 flex flex-col min-h-screen">
          <Header
            deviceFrame={deviceFrame}
            onDeviceFrameChange={setDeviceFrame}
            selectedPlatform={selectedPlatform}
            onPlatformChange={setSelectedPlatform}
            theme={theme}
            onThemeChange={setTheme}
            onToggleSidebar={() => setIsSidebarCollapsed((prev) => !prev)}
            isSidebarCollapsed={isSidebarCollapsed}
            userRole={userRole}
            onUserRoleChange={handleRoleChange}
          />

          {/* Main Content Area with Vertical Sidebar */}
          <div className="flex flex-col lg:flex-row flex-1 w-full min-h-0">
            <Sidebar
              currentView={currentView}
              onViewChange={setCurrentView}
              theme={theme}
              selectedPlatform={selectedPlatform}
              onPlatformChange={setSelectedPlatform}
              userRole={userRole}
              isCollapsed={isSidebarCollapsed}
              onToggleCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
            />

            <main className="flex-1 p-4 sm:p-6 min-w-0 max-w-7xl mx-auto w-full">
              {currentView === 'copilot' && (
                <NaturalQueryCopilotView
                  selectedPlatform={selectedPlatform}
                  onPlatformChange={setSelectedPlatform}
                  userRole={userRole}
                  onLoadQueryInGenerator={(query, platform) => {
                    setSelectedPlatform(platform);
                    setTransferredPrompt(query);
                    setCurrentView('generator');
                  }}
                  onLoadQueryInTranslator={(query, platform) => {
                    setSelectedPlatform(platform);
                    setTransferredQuery(query);
                    setCurrentView('translator');
                  }}
                  onLoadQueryInOptimizer={(query, platform) => {
                    setSelectedPlatform(platform);
                    setTransferredQuery(query);
                    setCurrentView('optimizer');
                  }}
                />
              )}

              {/* Only non-visitors can view these restricted views */}
              {userRole !== 'visitor' && currentView === 'attack_path' && (
                <AttackPathSimulatorView
                  onSendToGenerator={(promptText) => {
                    setTransferredPrompt(promptText);
                    setCurrentView('generator');
                  }}
                />
              )}

              {userRole !== 'visitor' && currentView === 'rule_benchmarker' && (
                <RuleBenchmarkerView
                  onSendToOptimizer={(query, platform) => {
                    setSelectedPlatform(platform);
                    setTransferredQuery(query);
                    setCurrentView('optimizer');
                  }}
                />
              )}

              {currentView === 'incident_retro' && (
                <IncidentRetroView
                  onSendToGenerator={(promptText) => {
                    setTransferredPrompt(promptText);
                    setCurrentView('generator');
                  }}
                  userRole={userRole}
                />
              )}

              {currentView === 'iocs_masker' && (
                <IocMaskerView
                  onInvestigateIoc={(iocTarget) => {
                    setInvestigateIoc(iocTarget);
                    setCurrentView('iocs_reputation');
                  }}
                />
              )}

              {currentView === 'iocs_reputation' && (
                <IocReputationView
                  initialIoc={investigateIoc}
                  onSendQueryToGenerator={(promptText) => {
                    setTransferredPrompt(promptText);
                    setCurrentView('generator');
                  }}
                  onPivotToSandbox={(target) => {
                    setSandboxTarget(target);
                    setCurrentView('sandbox');
                  }}
                />
              )}

              {currentView === 'sandbox' && (
                <SandboxAnalysisView
                  initialTarget={sandboxTarget || investigateIoc}
                  onSendQueryToGenerator={(promptText) => {
                    setTransferredPrompt(promptText);
                    setCurrentView('generator');
                  }}
                  onPivotToIocIntel={(iocTarget) => {
                    setInvestigateIoc(iocTarget);
                    setCurrentView('iocs_reputation');
                  }}
                  onPivotToMasker={() => {
                    setCurrentView('iocs_masker');
                  }}
                />
              )}

              {currentView === 'email_header' && (
                <EmailHeaderAnalyzerView
                  onInvestigateIoc={(iocTarget) => {
                    setInvestigateIoc(iocTarget);
                    setCurrentView('iocs_reputation');
                  }}
                  onSendToCopilot={(query) => {
                    setTransferredPrompt(`Hunt for emails using this query:\n${query}`);
                    setCurrentView('copilot');
                  }}
                  userRole={userRole}
                />
              )}

              {currentView === 'generator' && (
                <QueryGeneratorView
                  selectedPlatform={selectedPlatform}
                  onPlatformChange={setSelectedPlatform}
                  onExport={setExportDetection}
                  initialPrompt={transferredPrompt}
                  userRole={userRole}
                />
              )}

              {currentView === 'translator' && (
                <MultiPlatformTranslatorView
                  initialQuery={transferredQuery}
                  initialSourcePlatform={selectedPlatform}
                  userRole={userRole}
                />
              )}

              {currentView === 'optimizer' && (
                <QueryOptimizerView
                  initialQuery={transferredQuery}
                  initialPlatform={selectedPlatform}
                  userRole={userRole}
                />
              )}

              {userRole !== 'visitor' && currentView === 'playbooks' && (
                <ThreatLibraryView
                  onSelectPlaybookQuery={(query, platform) => {
                    setSelectedPlatform(platform);
                    setTransferredPrompt(query);
                    setCurrentView('generator');
                  }}
                />
              )}

              {currentView === 'cheat_sheet' && (
                <CheatSheetView
                  onSelectPrompt={(promptText) => {
                    setTransferredPrompt(promptText);
                    setCurrentView('copilot');
                  }}
                />
              )}
            </main>
          </div>

          {/* Footer */}
          <footer
            className={`border-t py-4 text-center text-[11px] font-mono transition-colors ${
              isLight
                ? 'border-slate-200 bg-slate-100/90 text-slate-500'
                : 'border-[#1B3047] bg-[#07111F]/90 text-slate-400'
            }`}
          >
            <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-white font-semibold flex items-center gap-1.5">
                  SOC<span className="text-cyan-400">Pulse</span>
                </span>
                <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-[10px]">
                  {userRole === 'visitor' ? 'Visitor Mode' : 'Admin Mode'}
                </span>
              </div>
              <span className="text-slate-400">Deep Navy & Cyan • 11 SIEM Engines Supported</span>
            </div>
          </footer>

          {/* Permission Matrix Dialog */}
          {showPermissionModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
              <div
                className={`w-full max-w-lg rounded-2xl border p-6 shadow-2xl space-y-4 ${
                  isLight ? 'bg-white text-slate-900 border-slate-200' : 'bg-[#0B1726] text-slate-100 border-[#1B3047]'
                }`}
              >
                <div className="flex items-center justify-between border-b pb-3 border-inherit/40">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-cyan-400" />
                    <h3 className="font-sans font-bold text-base text-white">Visitor Role & Access Policy</h3>
                  </div>
                  <button
                    onClick={() => setShowPermissionModal(false)}
                    className="p-1 rounded hover:bg-slate-200 dark:hover:bg-[#101F32] text-slate-400 hover:text-white"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <p className="font-sans text-xs text-slate-400 leading-relaxed">
                  Visitors have safe interactive access across Email Header Forensics, phishing investigation, SIEM query tools, AI copilot, and threat intel analyzers.
                </p>

                <div className="space-y-2 text-xs font-mono">
                  <div className="p-3 rounded-xl border bg-[#101F32] border-[#1B3047] space-y-1.5">
                    <span className="font-bold text-cyan-400 uppercase tracking-wider text-[10px] block">
                      Granted Interactive Permissions
                    </span>
                    <div className="flex items-center gap-2 text-slate-200">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>Email Header Forensics & Threat Classifier</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-200">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>Natural Language SOC Copilot & Threat Investigations</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-200">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>SIEM Query Generation across all 11 Engines</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-200">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>Cross-Platform Query Translation & Syntax Optimization</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-200">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>IOC Defanger, Masker & Multi-Feed Threat Intel</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-200">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>SIEM Syntax Guide & Cheat Sheet Access</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-xl border bg-[#060D18] border-[#1B3047] space-y-1.5">
                    <span className="font-bold text-slate-400 uppercase tracking-wider text-[10px] block">
                      Protected / Restricted from Visitors
                    </span>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Lock className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      <span>Attack Path Simulator Tab (Hidden for Visitors)</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Lock className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      <span>Rule Benchmark & Costs Tab (Hidden for Visitors)</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Lock className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      <span>Threat Playbooks Tab (Hidden for Visitors)</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Lock className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      <span>Overwriting Master Detection Database & Modifying Rules</span>
                    </div>
                  </div>
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    onClick={() => setShowPermissionModal(false)}
                    className="px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-[#060D18] font-sans text-xs font-bold transition-colors cursor-pointer"
                  >
                    Close Policy Matrix
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Modal for Exporting Detection Rule */}
          {exportDetection && (
            <ExportModal
              detection={exportDetection}
              onClose={() => setExportDetection(null)}
            />
          )}
        </div>
      </div>
    </DeviceFrame>
  );
}
