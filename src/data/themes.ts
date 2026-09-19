import { ThemeMeta } from '../types';

export const THEME_PRESETS: ThemeMeta[] = [
  {
    id: 'dark',
    name: 'Enterprise Deep Navy & Cyan',
    subtitle: 'High-contrast Deep Navy with Cyan & Teal Accents',
    previewBg: '#060D18',
    previewAccent: '#22D3EE',
    previewCard: '#0B1726',
    accentClass: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    icon: 'Moon',
  },
  {
    id: 'nordic',
    name: 'Obsidian Teal & Cyan',
    subtitle: 'Dark Slate Navy with Restrained Luminescence',
    previewBg: '#07111F',
    previewAccent: '#2DD4BF',
    previewCard: '#101F32',
    accentClass: 'text-teal-400 bg-teal-500/10 border-teal-500/30',
    icon: 'Sparkles',
  },
  {
    id: 'light',
    name: 'Daylight High-Contrast',
    subtitle: 'Refined Slate Canvas with Cyan Accents',
    previewBg: '#F8FAFC',
    previewAccent: '#0284C7',
    previewCard: '#FFFFFF',
    accentClass: 'text-sky-700 bg-sky-50 border-sky-300',
    icon: 'Sun',
  },
];

