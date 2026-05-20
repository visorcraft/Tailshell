import type { ComponentChildren } from 'preact';
import { useEffect, useRef } from 'preact/hooks';

type Props = {
  show: boolean;
  children: ComponentChildren;
  onDismiss?: () => void;
  ariaLabel?: string;
  ariaLabelledBy?: string;
  contentClassName?: string;
};

function getFocusableElements(root: HTMLElement) {
  const selectors = [
    'a[href]',
    'area[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])'
  ];
  return Array.from(root.querySelectorAll<HTMLElement>(selectors.join(','))).filter((el) => {
    const style = window.getComputedStyle(el);
    return style.visibility !== 'hidden' && style.display !== 'none';
  });
}

export function Modal({ show, children, onDismiss, ariaLabel, ariaLabelledBy, contentClassName }: Props) {
  const contentRef = useRef<HTMLDivElement | null>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);
  const bodyOverflowRef = useRef<string>('');

  useEffect(() => {
    if (!show) return;
    bodyOverflowRef.current = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    document.documentElement.style.overflow = 'hidden';
    restoreFocusRef.current = document.activeElement as HTMLElement | null;

    const focusInitial = () => {
      const node = contentRef.current;
      if (!node) return;
      const focusables = getFocusableElements(node);
      (focusables[0] ?? node).focus?.();
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onDismiss?.();
        return;
      }
      if (event.key !== 'Tab') return;
      const node = contentRef.current;
      if (!node) return;
      const focusables = getFocusableElements(node);
      if (focusables.length === 0) {
        event.preventDefault();
        return;
      }

      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement as HTMLElement | null;

      if (event.shiftKey) {
        if (active === first || !node.contains(active)) {
          event.preventDefault();
          last.focus();
        }
      } else if (active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    window.setTimeout(focusInitial, 0);
    document.addEventListener('keydown', onKeyDown);

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = bodyOverflowRef.current;
      document.documentElement.style.overflow = '';
      window.setTimeout(() => restoreFocusRef.current?.focus?.(), 0);
    };
  }, [show, onDismiss]);

  if (!show) return null;

  return (
    <div class="modal" role="dialog" aria-modal="true" aria-label={ariaLabel} aria-labelledby={ariaLabelledBy}>
      <button class="modal-backdrop" type="button" aria-label="Close" onClick={() => onDismiss?.()} />
      <div
        class={`modal-content${contentClassName ? ` ${contentClassName}` : ''}`}
        ref={(node) => {
          contentRef.current = node;
        }}
      >
        {children}
      </div>
    </div>
  );
}
