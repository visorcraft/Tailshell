import type { ITheme } from '@xterm/xterm';

export type LayoutMode = 'standard';

export type DesignId = 'obsidian' | 'aurora' | 'clinical' | 'minimal' | 'synthwave';

export type Design = {
  id: DesignId;
  name: string;
  description: string;
  layout: LayoutMode;
  xtermTheme: ITheme;
};

export const DEFAULT_DESIGN_ID: DesignId = 'obsidian';

export const DESIGNS: readonly Design[] = [
  {
    id: 'obsidian',
    name: 'Midnight Blue',
    description: 'Midnight glass with cool blue accents.',
    layout: 'standard',
    xtermTheme: {
      foreground: '#d8def0',
      background: '#0b1020',
      cursor: '#d8def0',
      selectionBackground: 'rgba(124, 58, 237, 0.35)',
      selectionInactiveBackground: 'rgba(124, 58, 237, 0.22)'
    }
  },
  {
    id: 'aurora',
    name: 'Aurora Glass',
    description: 'Emerald glow with a glassy shell.',
    layout: 'standard',
    xtermTheme: {
      foreground: '#e6f1ff',
      background: '#071018',
      cursor: '#e6f1ff',
      selectionBackground: 'rgba(34, 197, 94, 0.28)',
      selectionInactiveBackground: 'rgba(34, 197, 94, 0.18)'
    }
  },
  {
    id: 'clinical',
    name: 'Clinical',
    description: 'Clean, high-contrast panels with crisp blues.',
    layout: 'standard',
    xtermTheme: {
      foreground: '#e8eef6',
      background: '#0a0f16',
      cursor: '#e8eef6',
      selectionBackground: 'rgba(14, 165, 233, 0.26)',
      selectionInactiveBackground: 'rgba(14, 165, 233, 0.18)'
    }
  },
  {
    id: 'minimal',
    name: 'Minimal Terminal',
    description: 'Amber focus with a muted, low-noise palette.',
    layout: 'standard',
    xtermTheme: {
      foreground: '#e6e6e6',
      background: '#0b0b0b',
      cursor: '#e6e6e6',
      selectionBackground: 'rgba(245, 158, 11, 0.24)',
      selectionInactiveBackground: 'rgba(245, 158, 11, 0.16)'
    }
  },
  {
    id: 'synthwave',
    name: 'Synthwave',
    description: 'Neon accents for late-night sessions.',
    layout: 'standard',
    xtermTheme: {
      foreground: '#f3e9ff',
      background: '#0d0821',
      cursor: '#f3e9ff',
      selectionBackground: 'rgba(236, 72, 153, 0.26)',
      selectionInactiveBackground: 'rgba(236, 72, 153, 0.16)'
    }
  }
] as const;

export function getDesign(id: string | undefined): Design {
  const found = DESIGNS.find((d) => d.id === id);
  return found ?? DESIGNS.find((d) => d.id === DEFAULT_DESIGN_ID)!;
}
