import React from 'react';
import { DeviceFrameMode } from '../types';
import { Battery, Wifi, Signal } from 'lucide-react';

interface DeviceFrameProps {
  mode: DeviceFrameMode;
  children: React.ReactNode;
}

export const DeviceFrame: React.FC<DeviceFrameProps> = ({ mode, children }) => {
  if (mode === 'desktop') {
    return <div className="min-h-screen bg-[#060D18] text-[#F1F5F9]">{children}</div>;
  }

  const isIos = mode === 'ios';

  return (
    <div className="min-h-screen bg-[#060D18] py-6 sm:py-10 flex flex-col items-center justify-start overflow-x-hidden">
      <div className="text-center mb-4">
        <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#0B1726] border border-[#1B3047] text-xs text-cyan-300 font-mono">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          {isIos ? '📱 iOS App View Simulator (iPhone 16 Pro)' : '🤖 Android App View Simulator (Pixel 9)'}
        </span>
      </div>

      {/* Device Physical Mockup Shell */}
      <div
        className={`relative w-[395px] max-w-[95vw] h-[830px] bg-[#060D18] rounded-[48px] border-[10px] ${
          isIos ? 'border-[#1B3047] shadow-[0_0_50px_rgba(34,211,238,0.1)]' : 'border-[#1B3047] shadow-[0_0_50px_rgba(45,212,191,0.1)]'
        } overflow-hidden flex flex-col`}
      >
        {/* iOS Notch / Dynamic Island or Android Hole-Punch */}
        {isIos ? (
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-28 h-7 bg-black rounded-b-2xl z-50 flex items-center justify-center gap-2">
            <div className="w-3 h-3 rounded-full bg-[#07111F] border border-[#1B3047]" />
            <div className="w-2 h-2 rounded-full bg-cyan-900/50" />
          </div>
        ) : (
          <div className="absolute top-2 left-1/2 -translate-x-1/2 w-4 h-4 bg-black rounded-full z-50 border border-[#1B3047]" />
        )}

        {/* Mobile Status Bar */}
        <div className="w-full bg-[#060D18] text-slate-400 text-[11px] font-mono px-6 pt-3 pb-1 flex items-center justify-between shrink-0 z-40 select-none">
          <span>09:41</span>
          <div className="flex items-center gap-1.5 text-slate-400">
            <Signal className="w-3 h-3" />
            <Wifi className="w-3 h-3" />
            <Battery className="w-4 h-4 text-cyan-400" />
          </div>
        </div>

        {/* Inner Scrollable Mobile App Body */}
        <div className="flex-1 overflow-y-auto bg-[#060D18] text-[#F1F5F9] flex flex-col no-scrollbar">
          {children}
        </div>

        {/* Mobile Home Bar / Nav Indicator */}
        <div className="w-full bg-[#060D18] pt-2 pb-3 flex justify-center items-center shrink-0 z-40 select-none">
          <div className="w-32 h-1 bg-[#1B3047] rounded-full" />
        </div>
      </div>
    </div>
  );
};
