import React from 'react';

interface SocPulseLogoProps {
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | number;
  showText?: boolean;
  className?: string;
  glow?: boolean;
}

export const SocPulseLogo: React.FC<SocPulseLogoProps> = ({
  size = 'md',
  showText = false,
  className = '',
  glow = true,
}) => {
  const getDimension = () => {
    if (typeof size === 'number') return size;
    switch (size) {
      case 'xs':
        return 18;
      case 'sm':
        return 24;
      case 'md':
        return 34;
      case 'lg':
        return 44;
      case 'xl':
        return 56;
      default:
        return 34;
    }
  };

  const dim = getDimension();

  return (
    <div className={`inline-flex items-center gap-2.5 select-none ${className}`}>
      {/* Unique Cybersecurity Emblem: Faceted Cyber Shield + Telemetry Pulse Wave + Diamond Core */}
      <div className="relative flex items-center justify-center shrink-0">
        {glow && (
          <div
            className="absolute inset-0 rounded-full blur-md opacity-40 bg-gradient-to-r from-cyan-500 to-teal-400 pointer-events-none"
            style={{ width: dim, height: dim }}
          />
        )}
        <svg
          width={dim}
          height={dim}
          viewBox="0 0 100 100"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="relative shrink-0 transition-transform hover:scale-105 duration-200"
        >
          <defs>
            {/* Outer Armor Gradient */}
            <linearGradient id="socpulse-shield-border" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#00F0FF" />
              <stop offset="50%" stopColor="#0284C7" />
              <stop offset="100%" stopColor="#0D9488" />
            </linearGradient>

            {/* Inner Shield Fill */}
            <linearGradient id="socpulse-shield-fill" x1="50%" y1="0%" x2="50%" y2="100%">
              <stop offset="0%" stopColor="#0B1726" />
              <stop offset="50%" stopColor="#07111F" />
              <stop offset="100%" stopColor="#030811" />
            </linearGradient>

            {/* Pulse Wave Neon Gradient */}
            <linearGradient id="socpulse-pulse-gradient" x1="0%" y1="50%" x2="100%" y2="50%">
              <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.4" />
              <stop offset="35%" stopColor="#00F0FF" />
              <stop offset="50%" stopColor="#22D3EE" />
              <stop offset="65%" stopColor="#10B981" />
              <stop offset="100%" stopColor="#34D399" stopOpacity="0.4" />
            </linearGradient>

            {/* Core Diamond Radial Glow */}
            <radialGradient id="socpulse-core-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00F0FF" />
              <stop offset="60%" stopColor="#0EA5E9" />
              <stop offset="100%" stopColor="#0284C7" stopOpacity="0" />
            </radialGradient>

            {/* Subtle Drop Shadow */}
            <filter id="socpulse-shadow" x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="#00F0FF" floodOpacity="0.45" />
            </filter>
          </defs>

          {/* 1. Outer Faceted Cyber Armor Shield */}
          <path
            d="M 50 6 L 86 20 L 86 52 C 86 73 70 89 50 95 C 30 89 14 73 14 52 L 14 20 Z"
            fill="url(#socpulse-shield-fill)"
            stroke="url(#socpulse-shield-border)"
            strokeWidth="3.5"
            strokeLinejoin="round"
          />

          {/* 2. Inner Chamfer Inset Line */}
          <path
            d="M 50 14 L 78 25 L 78 50 C 78 67 65 80 50 86 C 35 80 22 67 22 50 L 22 25 Z"
            fill="none"
            stroke="#1E3A5F"
            strokeWidth="1.2"
            strokeDasharray="4 2"
            opacity="0.7"
          />

          {/* 3. Concentric Cyber Radar Arc */}
          <circle cx="50" cy="50" r="22" stroke="#0284C7" strokeWidth="1" strokeOpacity="0.35" />
          <circle cx="50" cy="50" r="14" stroke="#00F0FF" strokeWidth="1" strokeOpacity="0.25" strokeDasharray="2 3" />

          {/* 4. Crosshair Coordinate Micro-Ticks */}
          <line x1="50" y1="20" x2="50" y2="28" stroke="#00F0FF" strokeWidth="1.5" strokeOpacity="0.6" />
          <line x1="50" y1="72" x2="50" y2="80" stroke="#00F0FF" strokeWidth="1.5" strokeOpacity="0.6" />
          <line x1="20" y1="50" x2="28" y2="50" stroke="#00F0FF" strokeWidth="1.5" strokeOpacity="0.6" />
          <line x1="72" y1="50" x2="80" y2="50" stroke="#00F0FF" strokeWidth="1.5" strokeOpacity="0.6" />

          {/* 5. The Signature "SOC Pulse" Telemetry Waveform */}
          <path
            d="M 16 50 L 32 50 L 38 41 L 44 60 L 50 30 L 56 65 L 62 44 L 68 50 L 84 50"
            fill="none"
            stroke="url(#socpulse-pulse-gradient)"
            strokeWidth="3.2"
            strokeLinecap="round"
            strokeLinejoin="round"
            filter="url(#socpulse-shadow)"
          />

          {/* 6. Central Focus Diamond Core (Eye of SOCPulse) */}
          <polygon
            points="50,44 55,50 50,56 45,50"
            fill="#FFFFFF"
            stroke="#00F0FF"
            strokeWidth="1.5"
          />
          <circle cx="50" cy="50" r="1.8" fill="#00F0FF" />

          {/* 7. North Cardinal Satellite Sensor Node */}
          <circle cx="50" cy="10" r="2" fill="#00F0FF" />
        </svg>
      </div>

      {/* Optional Wordmark */}
      {showText && (
        <div className="flex flex-col">
          <div className="flex items-center text-white font-bold tracking-tight text-base font-sans leading-none">
            <span>SOC</span>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-teal-300 font-extrabold ml-0.5">
              Pulse
            </span>
          </div>
          <span className="text-[9px] font-mono uppercase tracking-widest text-cyan-400/70 leading-none mt-1">
            Cyber Threat Ops
          </span>
        </div>
      )}
    </div>
  );
};
