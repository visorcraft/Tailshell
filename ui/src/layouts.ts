export type LayoutId = 'future';

export type Layout = {
  id: LayoutId;
  name: string;
  description: string;
};

export const DEFAULT_LAYOUT_ID: LayoutId = 'future';

export const LAYOUTS: readonly Layout[] = [
  {
    id: 'future',
    name: 'Future',
    description: 'Minimal chrome, maximum terminal.'
  }
] as const;

export function getLayout(id: string | undefined): Layout {
  const found = LAYOUTS.find((layout) => layout.id === id);
  return found ?? LAYOUTS.find((layout) => layout.id === DEFAULT_LAYOUT_ID)!;
}
