import type { JSX } from 'preact';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';

type Key = string | number;

type Props<T> = {
  items: T[];
  itemHeight: number;
  itemGap?: number;
  overscan?: number;
  class?: string;
  style?: JSX.CSSProperties;
  getKey?: (item: T, index: number) => Key;
  renderItem: (item: T, index: number) => JSX.Element;
};

export function VirtualList<T>({
  items,
  itemHeight,
  itemGap = 0,
  overscan = 6,
  class: className,
  style,
  getKey,
  renderItem
}: Props<T>) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [viewportHeight, setViewportHeight] = useState(0);
  const [scrollTop, setScrollTop] = useState(0);

  const rafRef = useRef<number | null>(null);
  const pendingScrollTopRef = useRef(0);

  const stride = Math.max(1, itemHeight + itemGap);
  const totalHeight = Math.max(0, items.length * stride - itemGap);

  useLayoutEffect(() => {
    const node = containerRef.current;
    if (!node) return;

    const measure = () => setViewportHeight(node.clientHeight);
    measure();

    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', measure);
      return () => window.removeEventListener('resize', measure);
    }

    const ro = new ResizeObserver(() => measure());
    ro.observe(node);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const node = containerRef.current;
    if (!node) return;

    const next = Math.min(node.scrollTop, Math.max(0, totalHeight - viewportHeight));
    if (next !== node.scrollTop) node.scrollTop = next;
    setScrollTop(next);
  }, [totalHeight, viewportHeight]);

  const { startIndex, endIndex } = useMemo(() => {
    const start = Math.max(0, Math.floor(scrollTop / stride) - overscan);
    const end = Math.min(items.length, Math.ceil((scrollTop + viewportHeight) / stride) + overscan);
    return { startIndex: start, endIndex: end };
  }, [items.length, overscan, scrollTop, stride, viewportHeight]);

  const visibleItems = useMemo(() => items.slice(startIndex, endIndex), [endIndex, items, startIndex]);

  const onScroll: JSX.EventHandler<JSX.TargetedUIEvent<HTMLDivElement>> = (event) => {
    pendingScrollTopRef.current = (event.currentTarget as HTMLDivElement).scrollTop;
    if (rafRef.current !== null) return;
    rafRef.current = window.requestAnimationFrame(() => {
      rafRef.current = null;
      setScrollTop(pendingScrollTopRef.current);
    });
  };

  useEffect(() => {
    return () => {
      if (rafRef.current !== null) window.cancelAnimationFrame(rafRef.current);
    };
  }, []);

  return (
    <div
      ref={(node) => {
        containerRef.current = node;
      }}
      class={className}
      style={{ overflow: 'auto', ...style }}
      onScroll={onScroll}
    >
      <div style={{ height: `${totalHeight}px`, position: 'relative', minHeight: '100%' }}>
        {visibleItems.map((item, i) => {
          const index = startIndex + i;
          const key = getKey ? getKey(item, index) : index;
          return (
            <div
              key={key}
              style={{
                position: 'absolute',
                left: 0,
                right: 0,
                top: `${index * stride}px`,
                height: `${itemHeight}px`
              }}
            >
              {renderItem(item, index)}
            </div>
          );
        })}
      </div>
    </div>
  );
}

