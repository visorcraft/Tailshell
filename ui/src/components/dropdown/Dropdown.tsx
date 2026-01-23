import type { JSX } from 'preact';
import { useState, useRef, useEffect, useLayoutEffect } from 'preact/hooks';
import { createPortal } from 'preact/compat';
import './Dropdown.css';

export type DropdownOption = {
  value: string;
  label: string;
};

type DropdownProps = {
  value: string;
  options: DropdownOption[];
  onChange: (value: string) => void;
  onClick?: (event: JSX.TargetedMouseEvent<HTMLElement>) => void;
  class?: string;
  disabled?: boolean;
};

type MenuPosition = {
  top: number;
  left: number;
  width: number;
};

export function Dropdown({ value, options, onChange, onClick, class: className, disabled }: DropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [menuPosition, setMenuPosition] = useState<MenuPosition | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const selectedOption = options.find((opt) => opt.value === value);
  const displayLabel = selectedOption?.label ?? '';

  // Calculate menu position when opening
  useLayoutEffect(() => {
    if (isOpen && triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      setMenuPosition({
        top: rect.bottom + 4,
        left: rect.left,
        width: rect.width
      });
    }
  }, [isOpen]);

  // Close on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      const clickedContainer = containerRef.current?.contains(target);
      const clickedMenu = menuRef.current?.contains(target);
      if (!clickedContainer && !clickedMenu) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Close on scroll or resize
  useEffect(() => {
    if (!isOpen) return;

    const handleClose = () => setIsOpen(false);

    window.addEventListener('scroll', handleClose, true);
    window.addEventListener('resize', handleClose);

    return () => {
      window.removeEventListener('scroll', handleClose, true);
      window.removeEventListener('resize', handleClose);
    };
  }, [isOpen]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!isOpen) return;

      if (event.key === 'Escape') {
        setIsOpen(false);
        return;
      }

      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        const currentIndex = options.findIndex((opt) => opt.value === value);
        let nextIndex: number;

        if (event.key === 'ArrowDown') {
          nextIndex = currentIndex < options.length - 1 ? currentIndex + 1 : 0;
        } else {
          nextIndex = currentIndex > 0 ? currentIndex - 1 : options.length - 1;
        }

        onChange(options[nextIndex].value);
      }

      if (event.key === 'Enter') {
        setIsOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, value, options, onChange]);

  const handleToggle = (event: JSX.TargetedMouseEvent<HTMLButtonElement>) => {
    if (disabled) return;
    if (onClick) {
      onClick(event);
    }
    setIsOpen((prev) => !prev);
  };

  const handleSelect = (optionValue: string) => {
    onChange(optionValue);
    setIsOpen(false);
  };

  const themeVars: Record<string, string> = {};
  if (isOpen && triggerRef.current) {
    const computed = window.getComputedStyle(triggerRef.current);
    const keys = [
      '--page-bg',
      '--panel-bg',
      '--panel-border',
      '--text-primary',
      '--text-muted',
      '--control-bg',
      '--accent',
      '--accent-rgb',
      '--accent-2',
      '--shadow-md',
      '--radius-xs'
    ];
    for (const key of keys) {
      const value = computed.getPropertyValue(key).trim();
      if (value) themeVars[key] = value;
    }
  }

  const menu = isOpen && menuPosition ? createPortal(
    <div
      ref={menuRef}
      class="dropdown-menu"
      role="listbox"
      style={{
        position: 'fixed',
        top: `${menuPosition.top}px`,
        left: `${menuPosition.left}px`,
        width: `${menuPosition.width}px`,
        ...themeVars
      } as unknown as JSX.CSSProperties}
    >
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          class={`dropdown-option ${option.value === value ? 'is-selected' : ''}`}
          role="option"
          aria-selected={option.value === value}
          onClick={() => handleSelect(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>,
    document.body
  ) : null;

  return (
    <div class={`dropdown ${className ?? ''} ${disabled ? 'is-disabled' : ''}`} ref={containerRef}>
      <button
        ref={triggerRef}
        type="button"
        class={`dropdown-trigger ${isOpen ? 'is-open' : ''}`}
        onClick={handleToggle}
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        disabled={disabled}
      >
        <span class="dropdown-value">{displayLabel}</span>
        <span class="dropdown-arrow" aria-hidden="true" />
      </button>
      {menu}
    </div>
  );
}
