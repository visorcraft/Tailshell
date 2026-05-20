import type { IDisposable, ITerminalOptions, ITheme } from '@xterm/xterm';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { Unicode11Addon } from '@xterm/addon-unicode11';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { WebglAddon } from '@xterm/addon-webgl';

import '@xterm/xterm/css/xterm.css';

import { OverlayAddon } from './addons/overlay';
import { AI_PAYLOAD_PREFIX } from '../../../constants';

interface TtydTerminal extends Terminal {
  fit(): void;
}

declare global {
  interface Window {
    term?: TtydTerminal;
  }
}

enum ServerCommand {
  OUTPUT = '0',
  SET_WINDOW_TITLE = '1',
  SET_PREFERENCES = '2'
}

enum ClientCommand {
  INPUT = '0',
  RESIZE_TERMINAL = '1',
  PAUSE = '2',
  RESUME = '3'
}

const AUTOCOMPLETE_BEGIN = '__AI_COMPLETE_BEGIN__';
const AUTOCOMPLETE_END = '__AI_COMPLETE_END__';

function sanitizeCompletionOutput(value: string) {
  if (!value) return '';
  /* eslint-disable no-control-regex */
  const withoutOsc = value.replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '');
  const withoutCsi = withoutOsc.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '');
  const withoutDcs = withoutCsi.replace(/\x1b[PX^_][\s\S]*?\x1b\\/g, '');
  const withoutControlChars = withoutDcs.replace(/[\r\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  /* eslint-enable no-control-regex */
  return withoutControlChars;
}

type Preferences = ITerminalOptions & ClientOptions;

export type RendererType = 'dom' | 'webgl';

export type ClientOptions = {
  rendererType: RendererType;
  disableLeaveAlert: boolean;
  disableResizeOverlay: boolean;
  enableSixel: boolean;
  titleFixed?: string;
  isWindows: boolean;
  unicodeVersion: string;
};

export type FlowControl = {
  limit: number;
  highWater: number;
  lowWater: number;
};

export type XtermOptions = {
  wsUrl: string;
  tokenUrl: string;
  flowControl: FlowControl;
  clientOptions: ClientOptions;
  termOptions: ITerminalOptions;
  tmuxPrefix?: string;
};

export type ConnectionState = 'connecting' | 'open' | 'closed';

export type TmuxScrollState = {
  historySize: number;
  historyLimit: number;
  paneHeight: number;
  inMode: boolean;
  scrollPosition: number;
};

function toDisposable(dispose: () => void): IDisposable {
  return { dispose };
}

function addEventListener(
  target: EventTarget,
  type: string,
  listener: EventListenerOrEventListenerObject,
  options?: AddEventListenerOptions | boolean
): IDisposable {
  target.addEventListener(type, listener, options);
  return toDisposable(() => target.removeEventListener(type, listener, options));
}

export class Xterm {
  private disposables: IDisposable[] = [];
  private textEncoder = new TextEncoder();
  private textDecoder = new TextDecoder();
  private written = 0;
  private pending = 0;
  private autocompleteBuffer = '';
  private autocompleteCaptureId = '';
  private autocompleteCapture = '';
  private wheelRemainder = 0;
  private tmuxScrollRemainder = 0;
  private tmuxScrollbarOverlay?: HTMLDivElement;
  private tmuxScrollbarThumb?: HTMLDivElement;
  private tmuxScrollbarPointerId: number | null = null;
  private tmuxScrollbarLastY: number | null = null;
  private tmuxScrollbarGrabOffset = 0;
  private tmuxDragStartScroll = 0;
  private tmuxDragTargetScroll = 0;
  private tmuxDragLastSentScroll = 0;
  private tmuxDragLastSendAt = 0;
  private tmuxDragFlushTimer: number | null = null;
  private tmuxScrollState: TmuxScrollState | null = null;
  private tmuxCopyModeActive = false;
  private tmuxMaxScroll = 0;
  private tmuxCommandQueue: string[] = [];
  private tmuxCommandInFlight = false;
  private lastScrollAt = 0;
  private cancelCopyModeOnNextInput = false;

  private terminal?: Terminal;
  private fitAddon = new FitAddon();
  private overlayAddon = new OverlayAddon();
  private webglAddon?: WebglAddon;

  private socket?: WebSocket;
  private token = '';
  private lastSelection = '';
  private opened = false;
  private wheelHandlerInstalled = false;
  private title?: string;
  private titleFixed?: string;
  private resizeOverlay = true;
  private reconnect = true;
  private doReconnect = true;

  constructor(
    private options: XtermOptions,
    private onConnectionStateChange?: (state: ConnectionState) => void,
    private onCopySelection?: (selection: string) => void,
    private onTitlePayload?: (payload: string) => void
  ) {}

  dispose() {
    for (const d of this.disposables) d.dispose();
    this.disposables.length = 0;

    this.tmuxScrollbarPointerId = null;
    this.tmuxScrollbarLastY = null;
    this.tmuxScrollbarGrabOffset = 0;
    this.tmuxDragStartScroll = 0;
    this.tmuxDragTargetScroll = 0;
    this.tmuxDragLastSentScroll = 0;
    this.tmuxDragLastSendAt = 0;
    if (this.tmuxDragFlushTimer) {
      window.clearTimeout(this.tmuxDragFlushTimer);
      this.tmuxDragFlushTimer = null;
    }
    this.tmuxScrollRemainder = 0;
    this.tmuxScrollState = null;
    this.tmuxCopyModeActive = false;
    this.tmuxScrollbarThumb?.remove();
    this.tmuxScrollbarThumb = undefined;
    this.tmuxScrollbarOverlay?.remove();
    this.tmuxScrollbarOverlay = undefined;
    this.tmuxMaxScroll = 0;
    this.tmuxCommandQueue.length = 0;
    this.tmuxCommandInFlight = false;
    this.lastScrollAt = 0;
    this.cancelCopyModeOnNextInput = false;
  }

  private register<T extends IDisposable>(d: T): T {
    this.disposables.push(d);
    return d;
  }

  focus() {
    try {
      window.term?.focus();
    } catch {
      // ignore
    }
  }

  async refreshToken() {
    try {
      const resp = await fetch(this.options.tokenUrl);
      if (resp.ok) {
        const json = (await resp.json()) as { token?: string };
        this.token = json.token ?? '';
      }
    } catch (e) {
      console.error(`[ai-webterm] fetch ${this.options.tokenUrl}:`, e);
    }
  }

  private onWindowUnload = (event: BeforeUnloadEvent) => {
    event.preventDefault();
    if (this.socket?.readyState === WebSocket.OPEN) {
      const message = 'Close terminal? this will also terminate the command.';
      event.returnValue = message;
      return message;
    }
    return undefined;
  };

  open(parent: HTMLElement) {
    this.terminal = new Terminal(this.options.termOptions);
    const terminal = this.terminal;

    window.term = terminal as TtydTerminal;
    window.term.fit = () => this.fitAddon.fit();

    terminal.loadAddon(this.fitAddon);
    terminal.loadAddon(this.overlayAddon);
    terminal.loadAddon(new WebLinksAddon());

    terminal.open(parent);
    if (terminal.element) {
      // No additional listeners needed when tmux mouse mode is off.
    }
    this.fitAddon.fit();
  }

  fit() {
    this.fitAddon.fit();
  }

  setTmuxScrollState(state: TmuxScrollState | null) {
    this.tmuxScrollState = state;
    this.tmuxCopyModeActive = !!state?.inMode;
    this.updateTmuxScrollbar();
  }

  private initListeners() {
    const terminal = this.terminal;
    if (!terminal) return;

    terminal.attachCustomKeyEventHandler((event) => {
      // Ctrl+C with selection: copy to clipboard instead of sending SIGINT
      if (
        event.type === 'keydown' &&
        event.ctrlKey &&
        !event.shiftKey &&
        !event.altKey &&
        !event.metaKey &&
        event.key.toLowerCase() === 'c'
      ) {
        const selection = terminal.getSelection();
        if (selection) {
          this.onCopySelection?.(selection);
          navigator.clipboard.writeText(selection).catch(() => {
            // ignore clipboard errors
          });
          return false;
        }
      }

      // If we just scrolled, tmux is likely in copy-mode; send cancel before the key is handled.
      if (event.type === 'keydown' && (this.tmuxCopyModeActive || Date.now() - this.lastScrollAt < 1200)) {
        this.cancelCopyModeOnNextInput = true;
      }

      // Shift+Enter: send backslash + carriage return for line continuation
      // Block all event types (keydown, keypress, keyup) but only send data on keydown
      if (event.key === 'Enter' && event.shiftKey && !event.ctrlKey && !event.altKey && !event.metaKey) {
        if (event.type === 'keydown') {
          this.sendData('\\\r');
        }
        return false;
      }

      return true;
    });

    this.register(
      terminal.onTitleChange((data) => {
        if (data?.startsWith(AI_PAYLOAD_PREFIX)) {
          this.onTitlePayload?.(data);
          return;
        }
        if (data && data !== '' && !this.titleFixed) {
          document.title = `${data} | ${this.title ?? ''}`.trim();
        }
      })
    );

    this.register(
      terminal.onData((data) => {
        if (this.cancelCopyModeOnNextInput || this.tmuxCopyModeActive) {
          this.cancelCopyModeOnNextInput = false;
          this.tmuxCopyModeActive = false;
          if (data === '\x1b') {
            this.sendData(data);
            return;
          }
          // Cancel copy-mode before forwarding the user's input.
          this.sendData('\x1d'); // C-] (bound to cancel copy-mode)
          window.setTimeout(() => this.sendData(data), 120);
          return;
        }
        this.sendData(data);
      })
    );
    this.register(terminal.onBinary((data) => this.sendData(Uint8Array.from(data, (v) => v.charCodeAt(0)))));

    this.register(
      terminal.onResize(({ cols, rows }) => {
        const msg = JSON.stringify({ columns: cols, rows: rows });
        this.socket?.send(this.textEncoder.encode(ClientCommand.RESIZE_TERMINAL + msg));
        if (this.resizeOverlay) this.overlayAddon.showOverlay(`${cols}x${rows}`, 320);
        this.updateTmuxScrollbar();
      })
    );

    this.register(
      terminal.onRender(() => {
        // Keep the custom scrollbar synced as scrollback grows.
        this.updateTmuxScrollbar();
      })
    );

    this.register(
      terminal.onSelectionChange(() => {
        const selection = terminal.getSelection();
        if (selection === '') return;
        this.lastSelection = selection;
      })
    );

    this.register(
      addEventListener(window, 'resize', () => {
        this.fitAddon.fit();
        this.updateTmuxScrollbar();
      })
    );
    this.register(addEventListener(window, 'beforeunload', this.onWindowUnload as unknown as EventListener));

    this.installScrollHandlers();
  }

  private dispatchTmuxScroll(deltaPixels: number) {
    const stepPixels = 12;
    this.tmuxScrollRemainder += deltaPixels;

    const steps =
      this.tmuxScrollRemainder < 0
        ? Math.ceil(this.tmuxScrollRemainder / stepPixels)
        : Math.floor(this.tmuxScrollRemainder / stepPixels);
    if (steps === 0) return;

    this.tmuxScrollRemainder -= steps * stepPixels;
    const direction = steps > 0 ? 'down' : 'up';
    if (direction === 'up') {
      // Scrolling up enters tmux copy-mode; assume active until state refresh arrives.
      this.tmuxCopyModeActive = true;
    }
    this.lastScrollAt = Date.now();
    this.updateLocalTmuxScrollPosition(direction, Math.abs(steps));
    this.sendTmuxScrollSteps(direction, Math.abs(steps));
    this.updateTmuxScrollbar();
  }

  private sendTmuxScrollSteps(direction: 'up' | 'down', count: number) {
    if (count <= 0) return;
    const maxBurst = 40;
    const clamped = Math.min(count, maxBurst);
    const sequence = direction === 'up' ? '\x1b[5~' : '\x1b[6~';
    this.sendData(sequence.repeat(clamped));
    if (count > maxBurst) {
      window.setTimeout(() => this.sendTmuxScrollSteps(direction, count - maxBurst), 16);
    }
  }

  private sendTmuxCommand(command: string) {
    if (!command) return;
    this.tmuxCommandQueue.push(command);
    if (!this.tmuxCommandInFlight) {
      this.processNextTmuxCommand();
    }
  }

  private processNextTmuxCommand() {
    if (this.tmuxCommandInFlight || this.tmuxCommandQueue.length === 0) return;
    const terminal = this.terminal;
    if (!terminal) return;

    this.tmuxCommandInFlight = true;
    const command = this.tmuxCommandQueue.shift()!;
    const prefix = this.options.tmuxPrefix ?? '\x02';
    const prefixByte = prefix.charCodeAt(0);

    this.sendData(new Uint8Array([prefixByte]));
    window.setTimeout(() => {
      this.sendData(':');
      window.setTimeout(() => {
        this.sendData(`${command}\r`);
        window.setTimeout(() => {
          this.tmuxCommandInFlight = false;
          this.processNextTmuxCommand();
        }, 120);
      }, 120);
    }, 120);
  }

  private sendTmuxScrollLines(direction: 'up' | 'down', lines: number, inMode: boolean) {
    if (lines <= 0) return;
    const maxLines = 2000;
    const clamped = Math.min(lines, maxLines);
    const action = direction === 'up' ? 'scroll-up' : 'scroll-down';
    const command = inMode
      ? `send-keys -X -N ${clamped} ${action}`
      : `copy-mode ; send-keys -X -N ${clamped} ${action}`;
    this.sendTmuxCommand(command);
    if (lines > maxLines) {
      this.sendTmuxScrollLines(direction, lines - maxLines, true);
    }
  }

  private updateLocalTmuxScrollPosition(direction: 'up' | 'down', steps: number) {
    const tmuxState = this.tmuxScrollState;
    if (!tmuxState || steps <= 0) return;
    const stepLines = 5;
    const deltaLines = (direction === 'up' ? 1 : -1) * steps * stepLines;
    const maxScroll = Math.max(0, tmuxState.historySize);
    const current = Math.max(0, tmuxState.scrollPosition);
    const next = Math.max(0, Math.min(maxScroll, current + deltaLines));
    tmuxState.scrollPosition = next;
    tmuxState.inMode = next > 0;
    this.tmuxCopyModeActive = tmuxState.inMode;
  }

  private updateTmuxScrollbar() {
    const overlay = this.tmuxScrollbarOverlay;
    const thumb = this.tmuxScrollbarThumb;
    if (!overlay || !thumb) return;

    const terminal = this.terminal;
    if (!terminal) {
      overlay.classList.add('is-disabled');
      return;
    }

    const trackHeight = overlay.clientHeight;
    if (trackHeight <= 0) return;

    const padding = 2;
    const usableHeight = Math.max(0, trackHeight - padding * 2);

    const tmuxState = this.tmuxScrollState;
    let paneHeight = Math.max(0, terminal.rows);
    let maxScroll = 0;
    let scrollOffset = 0;

    if (tmuxState) {
      paneHeight = Math.max(0, tmuxState.paneHeight || paneHeight);
      maxScroll = Math.max(0, tmuxState.historySize);
      scrollOffset = Math.max(0, tmuxState.scrollPosition); // 0 at bottom
    } else {
      const buffer = terminal.buffer.active;
      maxScroll = Math.max(0, buffer.baseY);
      scrollOffset = Math.max(0, buffer.baseY - buffer.viewportY); // 0 at bottom
    }

    if (terminal) {
      const bufferMax = Math.max(0, terminal.buffer.active.baseY);
      if (bufferMax > maxScroll) {
        maxScroll = bufferMax;
        if (tmuxState) {
          tmuxState.historySize = bufferMax;
        }
      }
    }

    const totalLines = maxScroll + paneHeight;

    const minThumbHeight = 28;
    const rawThumbHeight = totalLines > 0 ? (paneHeight / totalLines) * usableHeight : usableHeight;
    const thumbHeight = Math.max(minThumbHeight, Math.min(usableHeight, rawThumbHeight));

    const clampedScroll = Math.max(0, Math.min(maxScroll, scrollOffset));
    const maxTravel = Math.max(0, usableHeight - thumbHeight);
    const ratio = maxScroll > 0 ? (maxScroll - clampedScroll) / maxScroll : 1;
    const thumbTop = padding + maxTravel * ratio;

    thumb.style.height = `${thumbHeight}px`;
    thumb.style.transform = `translateY(${thumbTop}px)`;

    const canScroll = maxScroll > 0 && usableHeight > minThumbHeight;
    overlay.classList.toggle('is-disabled', !canScroll);
  }

  private installTmuxScrollbarOverlay(_viewport: HTMLElement) {
    const terminal = this.terminal;
    if (!terminal?.element) return;
    if (this.tmuxScrollbarOverlay) return;

    const overlay = document.createElement('div');
    overlay.className = 'xterm-tmux-scrollbar';
    const thumb = document.createElement('div');
    thumb.className = 'xterm-tmux-scrollbar-thumb';
    overlay.appendChild(thumb);
    terminal.element.appendChild(overlay);
    this.tmuxScrollbarOverlay = overlay;
    this.tmuxScrollbarThumb = thumb;
    this.updateTmuxScrollbar();

    this.register(
      addEventListener(
        overlay,
        'wheel',
        (event) => {
          const e = event as WheelEvent;
          // Use tmux-driven scroll for the custom bar.
          this.dispatchTmuxScroll(e.deltaY);
          e.preventDefault();
        },
        { passive: false }
      )
    );

    // Track if actual drag movement occurred (for conditional preventDefault)
    let didDrag = false;

    this.register(
      addEventListener(
        thumb, // Moved from overlay to thumb (Option 3)
        'pointerdown',
        (event) => {
          const e = event as PointerEvent;
          if (e.button !== 0) return;
          this.tmuxScrollbarPointerId = e.pointerId;
          this.tmuxScrollbarLastY = e.clientY;
          this.tmuxScrollRemainder = 0;
          didDrag = false; // Reset drag tracking
          overlay.classList.add('is-dragging');
          const thumbRect = thumb.getBoundingClientRect();
          this.tmuxScrollbarGrabOffset = e.clientY - thumbRect.top;
          const tmuxState = this.tmuxScrollState;
          this.tmuxDragStartScroll = tmuxState ? Math.max(0, tmuxState.scrollPosition) : 0;
          this.tmuxDragTargetScroll = this.tmuxDragStartScroll;
          this.tmuxDragLastSentScroll = this.tmuxDragStartScroll;
          this.tmuxDragLastSendAt = 0;
          if (this.tmuxDragFlushTimer) {
            window.clearTimeout(this.tmuxDragFlushTimer);
            this.tmuxDragFlushTimer = null;
          }
          // Capture pointer so the thumb can be dragged smoothly even if the cursor leaves it.
          try {
            (e.currentTarget as HTMLElement | null)?.setPointerCapture?.(e.pointerId);
          } catch {
            // ignore
          }
          terminal.focus();
          e.preventDefault();
        },
        { passive: false }
      )
    );

    this.register(
      addEventListener(
        thumb, // Moved from overlay to thumb (Option 3)
        'pointermove',
        (event) => {
          const e = event as PointerEvent;
          if (this.tmuxScrollbarPointerId !== e.pointerId) return;
          if (this.tmuxScrollbarLastY === null) return;
          const delta = e.clientY - this.tmuxScrollbarLastY;
          this.tmuxScrollbarLastY = e.clientY;
          didDrag = true; // Mark that actual drag movement occurred
          const tmuxState = this.tmuxScrollState;
          if (tmuxState) {
            const trackHeight = overlay.clientHeight;
            const padding = 2;
            const usableHeight = Math.max(0, trackHeight - padding * 2);
            const paneHeight = Math.max(0, tmuxState.paneHeight || 0);
            let maxScroll = Math.max(0, tmuxState.historySize);
            const bufferMax = Math.max(0, terminal.buffer.active.baseY);
            if (bufferMax > maxScroll) {
              maxScroll = bufferMax;
              tmuxState.historySize = bufferMax;
            }
            const totalLines = maxScroll + paneHeight;
            const minThumbHeight = 28;
            const rawThumbHeight = totalLines > 0 ? (paneHeight / totalLines) * usableHeight : usableHeight;
            const thumbHeight = Math.max(minThumbHeight, Math.min(usableHeight, rawThumbHeight));
            const maxTravel = Math.max(0, usableHeight - thumbHeight);
            if (maxTravel > 0 && maxScroll > 0) {
              const trackRect = overlay.getBoundingClientRect();
              const desiredTop = e.clientY - trackRect.top - this.tmuxScrollbarGrabOffset;
              const nextThumbTop = Math.max(padding, Math.min(padding + maxTravel, desiredTop));
              const nextRatio = (nextThumbTop - padding) / maxTravel; // 0 top -> 1 bottom
              const nextScroll = Math.round(maxScroll * (1 - nextRatio));
              this.tmuxDragTargetScroll = nextScroll;
              if (this.tmuxDragFlushTimer) {
                window.clearTimeout(this.tmuxDragFlushTimer);
              }
              this.tmuxDragFlushTimer = window.setTimeout(() => {
                const pendingTarget = this.tmuxDragTargetScroll;
                const pendingDelta = pendingTarget - this.tmuxDragLastSentScroll;
                if (pendingDelta !== 0 && this.tmuxScrollState) {
                  const direction = pendingDelta > 0 ? 'up' : 'down';
                  const lines = Math.abs(pendingDelta);
                  this.sendTmuxScrollLines(direction, lines, this.tmuxScrollState.inMode);
                  this.tmuxDragLastSentScroll = pendingTarget;
                  this.tmuxCopyModeActive = true;
                  this.lastScrollAt = Date.now();
                }
                this.tmuxDragFlushTimer = null;
              }, 200);
              if (this.tmuxScrollState) {
                this.tmuxScrollState.scrollPosition = nextScroll;
                this.tmuxScrollState.inMode = nextScroll > 0;
                this.tmuxCopyModeActive = this.tmuxScrollState.inMode;
              }
              this.updateTmuxScrollbar();
              e.preventDefault();
              return;
            }
          }
          this.dispatchTmuxScroll(delta);
          this.updateTmuxScrollbar();
          e.preventDefault();
        },
        { passive: false }
      )
    );

    const endDrag = (event: Event) => {
      const e = event as PointerEvent;
      if (this.tmuxScrollbarPointerId !== e.pointerId) return;

      const wasDragging = didDrag; // Capture before resetting

      const dragStart = this.tmuxDragStartScroll;
      const dragTarget = this.tmuxDragTargetScroll;
      this.tmuxScrollbarPointerId = null;
      this.tmuxScrollbarLastY = null;
      this.tmuxScrollbarGrabOffset = 0;
      this.tmuxDragStartScroll = 0;
      const dragLastSent = this.tmuxDragLastSentScroll;
      this.tmuxDragTargetScroll = 0;
      this.tmuxDragLastSentScroll = 0;
      this.tmuxDragLastSendAt = 0;
      if (this.tmuxDragFlushTimer) {
        window.clearTimeout(this.tmuxDragFlushTimer);
        this.tmuxDragFlushTimer = null;
      }
      this.tmuxScrollRemainder = 0;
      didDrag = false;
      overlay.classList.remove('is-dragging');
      this.updateTmuxScrollbar();

      if (dragTarget !== dragStart && this.tmuxScrollState) {
        const bufferMax = Math.max(0, terminal.buffer.active.baseY);
        const maxScroll = Math.max(0, Math.max(this.tmuxScrollState.historySize, bufferMax));
        const atTop = dragTarget >= Math.max(0, maxScroll - 1);
        const atBottom = dragTarget <= 1;

        if (atTop) {
          this.sendTmuxCommand('copy-mode ; send-keys -X history-top');
          this.tmuxScrollState.scrollPosition = maxScroll;
          this.tmuxScrollState.inMode = true;
          this.tmuxCopyModeActive = true;
          this.lastScrollAt = Date.now();
          return;
        }

        if (atBottom) {
          this.sendTmuxCommand('copy-mode ; send-keys -X history-bottom ; send-keys -X cancel');
          this.tmuxScrollState.scrollPosition = 0;
          this.tmuxScrollState.inMode = false;
          this.tmuxCopyModeActive = false;
          this.lastScrollAt = Date.now();
          return;
        }

        const deltaLines = dragTarget - dragLastSent;
        const direction = deltaLines > 0 ? 'up' : 'down';
        const lines = Math.abs(deltaLines);
        if (lines > 0) {
          this.sendTmuxScrollLines(direction, lines, this.tmuxScrollState.inMode);
          this.tmuxCopyModeActive = true;
          this.lastScrollAt = Date.now();
        }
      }

      try {
        (e.currentTarget as HTMLElement | null)?.releasePointerCapture?.(e.pointerId);
      } catch {
        // ignore
      }

      // Only prevent default if actual drag occurred (Option 1)
      if (wasDragging) {
        e.preventDefault();
      }
    };

    this.register(addEventListener(thumb, 'pointerup', endDrag as unknown as EventListener, { passive: false }));
    this.register(addEventListener(thumb, 'pointercancel', endDrag as unknown as EventListener, { passive: false }));
  }

  private installScrollHandlers() {
    const terminal = this.terminal;
    if (!terminal?.element) return;

    const viewport = terminal.element.querySelector('.xterm-viewport') as HTMLElement | null;
    if (!viewport) return;

    this.installTmuxScrollbarOverlay(viewport);

    if (!this.wheelHandlerInstalled) {
      this.wheelHandlerInstalled = true;
    }

    // Keep the custom scrollbar in sync with xterm's scrollback.
    this.register(terminal.onScroll(() => this.updateTmuxScrollbar()));

    const handleWheel = (event: Event) => {
      const e = event as WheelEvent;
      if (e.ctrlKey) return;
      this.dispatchTmuxScroll(e.deltaY);
      e.preventDefault();
    };

    this.register(addEventListener(viewport, 'wheel', handleWheel as EventListener, { passive: false }));
    this.register(
      addEventListener(terminal.element, 'wheel', handleWheel as EventListener, { passive: false, capture: true })
    );

    let lastTouchY: number | null = null;
    this.register(
      addEventListener(
        viewport,
        'touchstart',
        (event) => {
          const e = event as TouchEvent;
          if (e.touches.length !== 1) return;
          lastTouchY = e.touches[0]?.clientY ?? null;
        },
        { passive: true }
      )
    );

    this.register(
      addEventListener(
        viewport,
        'touchmove',
        (event) => {
          const e = event as TouchEvent;
          if (lastTouchY === null) return;
          if (e.touches.length !== 1) return;
          const y = e.touches[0]?.clientY;
          if (y === undefined) return;
          const delta = lastTouchY - y;
          lastTouchY = y;
          this.dispatchTmuxScroll(delta);
          e.preventDefault();
        },
        { passive: false }
      )
    );

    this.register(
      addEventListener(
        viewport,
        'touchend',
        () => {
          lastTouchY = null;
        },
        { passive: true }
      )
    );

    this.register(
      addEventListener(
        viewport,
        'touchcancel',
        () => {
          lastTouchY = null;
        },
        { passive: true }
      )
    );
  }

  private writeData = (data: string | Uint8Array) => {
    const terminal = this.terminal;
    if (!terminal) return;

    const { limit, highWater, lowWater } = this.options.flowControl;
    this.written += data.length;

    if (this.written > limit) {
      terminal.write(data, () => {
        this.pending = Math.max(this.pending - 1, 0);
        if (this.pending < lowWater) {
          this.socket?.send(this.textEncoder.encode(ClientCommand.RESUME));
        }
      });
      this.pending++;
      this.written = 0;
      if (this.pending > highWater) {
        this.socket?.send(this.textEncoder.encode(ClientCommand.PAUSE));
      }
    } else {
      terminal.write(data);
    }
  };

  sendData(data: string | Uint8Array) {
    const socket = this.socket;
    if (socket?.readyState !== WebSocket.OPEN) return;

    if (typeof data === 'string') {
      const payload = new Uint8Array(data.length * 3 + 1);
      payload[0] = ClientCommand.INPUT.charCodeAt(0);
      const stats = this.textEncoder.encodeInto(data, payload.subarray(1));
      socket.send(payload.subarray(0, (stats.written ?? 0) + 1));
      return;
    }

    const payload = new Uint8Array(data.length + 1);
    payload[0] = ClientCommand.INPUT.charCodeAt(0);
    payload.set(data, 1);
    socket.send(payload);
  }

  getSelection() {
    return this.terminal?.getSelection?.() ?? '';
  }

  getLastSelection() {
    return this.lastSelection;
  }

  getBufferText(lines = 200) {
    const terminal = this.terminal as unknown as {
      buffer?: {
        active?: {
          length: number;
          viewportY?: number;
          getLine: (idx: number) => { translateToString: (trimRight?: boolean) => string } | undefined;
        };
      };
    };

    const active = terminal?.buffer?.active;
    if (!active) return '';

    const end = active.length;
    const start = Math.max(0, end - lines);
    const out: string[] = [];
    for (let i = start; i < end; i++) {
      const line = active.getLine(i);
      if (!line) continue;
      out.push(line.translateToString(true));
    }
    return out.join('\n');
  }

  getViewportText() {
    const term = this.terminal as unknown as {
      rows?: number;
      buffer?: {
        active?: {
          length: number;
          viewportY?: number;
          getLine: (idx: number) => { translateToString: (trimRight?: boolean) => string } | undefined;
        };
      };
    };

    const active = term?.buffer?.active;
    const rows = term?.rows ?? 0;
    if (!active || rows <= 0) return '';

    const viewportY = active.viewportY ?? 0;
    const start = Math.max(0, viewportY);
    const end = Math.min(active.length, viewportY + rows);
    const out: string[] = [];

    for (let i = start; i < end; i += 1) {
      const line = active.getLine(i);
      if (!line) continue;
      out.push(line.translateToString(true));
    }

    return out.join('\n');
  }

  setUserInputEnabled(enabled: boolean) {
    if (!this.terminal) return;
    this.terminal.options.disableStdin = !enabled;
  }

  setTheme(theme: ITheme) {
    if (!this.terminal) return;
    this.terminal.options.theme = { ...(this.terminal.options.theme ?? {}), ...theme };
  }

  setTmuxPrefix(prefix: string) {
    this.options.tmuxPrefix = prefix;
  }

  connect() {
    this.onConnectionStateChange?.('connecting');
    this.socket = new WebSocket(this.options.wsUrl, ['tty']);
    const socket = this.socket;

    socket.binaryType = 'arraybuffer';
    this.register(addEventListener(socket, 'open', this.onSocketOpen as unknown as EventListener));
    this.register(addEventListener(socket, 'message', this.onSocketData as unknown as EventListener));
    this.register(addEventListener(socket, 'close', this.onSocketClose as unknown as EventListener));
    this.register(addEventListener(socket, 'error', () => (this.doReconnect = false)));
  }

  private onSocketOpen = () => {
    console.log('[ai-webterm] websocket open');
    this.onConnectionStateChange?.('open');

    const terminal = this.terminal;
    if (!terminal) return;

    const msg = JSON.stringify({ AuthToken: this.token, columns: terminal.cols, rows: terminal.rows });
    this.socket?.send(this.textEncoder.encode(msg));

    if (this.opened) {
      terminal.reset();
      terminal.options.disableStdin = false;
      this.overlayAddon.showOverlay('Reconnected', 320);
    } else {
      this.opened = true;
    }

    this.doReconnect = this.reconnect;
    this.initListeners();
    terminal.focus();
  };

  private onSocketClose = (event: CloseEvent) => {
    console.log(`[ai-webterm] websocket closed (${event.code})`);
    this.onConnectionStateChange?.('closed');

    this.overlayAddon.showOverlay('Connection Closed');
    this.dispose();

    // 1000: CLOSE_NORMAL
    if (event.code !== 1000 && this.doReconnect) {
      this.overlayAddon.showOverlay('Reconnecting...');
      this.refreshToken().then(() => this.connect());
      return;
    }

    const terminal = this.terminal;
    if (!terminal) return;

    const keyDispose = terminal.onKey((e) => {
      const domEvent = e.domEvent;
      if (domEvent.key === 'Enter') {
        keyDispose.dispose();
        this.overlayAddon.showOverlay('Reconnecting...');
        this.refreshToken().then(() => this.connect());
      }
    });
    this.overlayAddon.showOverlay('Press ⏎ to Reconnect');
  };

  private parseOptsFromUrlQuery(query: string): Preferences {
    const terminal = this.terminal;
    if (!terminal) return {} as Preferences;

    const { clientOptions } = this.options;
    const prefs: Record<string, unknown> = {};
    const queryObj = Array.from(new URLSearchParams(query) as unknown as Iterable<[string, string]>);

    for (const [key, queryVal] of queryObj) {
      let v: unknown = (clientOptions as Record<string, unknown>)[key];
      if (v === undefined) v = (terminal.options as Record<string, unknown>)[key];

      switch (typeof v) {
        case 'boolean':
          prefs[key] = queryVal === 'true' || queryVal === '1';
          break;
        case 'number':
        case 'bigint':
          prefs[key] = Number.parseInt(queryVal, 10);
          break;
        case 'string':
          prefs[key] = queryVal;
          break;
        case 'object':
          prefs[key] = JSON.parse(queryVal);
          break;
        default:
          prefs[key] = queryVal;
          break;
      }
    }

    return prefs as unknown as Preferences;
  }

  private onSocketData = (event: MessageEvent) => {
    const rawData = event.data as ArrayBuffer;
    const cmd = String.fromCharCode(new Uint8Array(rawData)[0] ?? 0);
    const data = rawData.slice(1);

    switch (cmd) {
      case ServerCommand.OUTPUT:
        this.writeData(this.filterAutocompleteOutput(new Uint8Array(data)));
        break;
      case ServerCommand.SET_WINDOW_TITLE:
        {
          const title = this.textDecoder.decode(data);
          if (title.startsWith(AI_PAYLOAD_PREFIX)) {
            this.onTitlePayload?.(title);
            break;
          }
          this.title = title;
          document.title = this.title;
        }
        break;
      case ServerCommand.SET_PREFERENCES:
        this.applyPreferences({
          ...this.options.clientOptions,
          ...JSON.parse(this.textDecoder.decode(data)),
          ...this.parseOptsFromUrlQuery(window.location.search)
        } as Preferences);
        break;
      default:
        console.warn(`[ai-webterm] unknown command: ${cmd}`);
        break;
    }
  };

  private filterAutocompleteOutput(data: Uint8Array) {
    const chunk = this.textDecoder.decode(data);
    if (!chunk) return data;

    this.autocompleteBuffer += chunk;
    let output = '';
    const findMarkerTail = (buffer: string, marker: string) => {
      const max = Math.min(buffer.length, marker.length - 1);
      for (let i = max; i > 0; i -= 1) {
        if (buffer.endsWith(marker.slice(0, i))) {
          return buffer.slice(buffer.length - i);
        }
      }
      return '';
    };

    while (this.autocompleteBuffer.length) {
      if (!this.autocompleteCaptureId) {
        const startIndex = this.autocompleteBuffer.indexOf(AUTOCOMPLETE_BEGIN);
        if (startIndex === -1) {
          const tail = findMarkerTail(this.autocompleteBuffer, AUTOCOMPLETE_BEGIN);
          if (tail) {
            output += this.autocompleteBuffer.slice(0, -tail.length);
            this.autocompleteBuffer = tail;
          } else {
            output += this.autocompleteBuffer;
            this.autocompleteBuffer = '';
          }
          break;
        }
        output += this.autocompleteBuffer.slice(0, startIndex);
        const afterStart = this.autocompleteBuffer.slice(startIndex + AUTOCOMPLETE_BEGIN.length);
        const newlineIndex = afterStart.indexOf('\n');
        if (newlineIndex === -1) {
          this.autocompleteBuffer = this.autocompleteBuffer.slice(startIndex);
          break;
        }
        const captureId = afterStart.slice(0, newlineIndex).replace(/\r/g, '').trim();
        if (!captureId) {
          this.autocompleteBuffer = afterStart.slice(newlineIndex + 1);
          continue;
        }
        this.autocompleteCaptureId = captureId;
        this.autocompleteCapture = '';
        this.autocompleteBuffer = afterStart.slice(newlineIndex + 1);
        continue;
      }

      const endMarker = `${AUTOCOMPLETE_END}${this.autocompleteCaptureId}`;
      const endIndex = this.autocompleteBuffer.indexOf(endMarker);
      if (endIndex === -1) {
        const tail = findMarkerTail(this.autocompleteBuffer, endMarker);
        if (tail) {
          this.autocompleteCapture += this.autocompleteBuffer.slice(0, -tail.length);
          this.autocompleteBuffer = tail;
        } else if (this.autocompleteBuffer) {
          this.autocompleteCapture += this.autocompleteBuffer;
          this.autocompleteBuffer = '';
        }
        break;
      }
      this.autocompleteCapture += this.autocompleteBuffer.slice(0, endIndex);
      const cleaned = sanitizeCompletionOutput(this.autocompleteCapture);
      const payload = window.btoa(cleaned);
      this.onTitlePayload?.(`${AI_PAYLOAD_PREFIX}complete::${this.autocompleteCaptureId}::${payload}`);
      this.autocompleteCaptureId = '';
      this.autocompleteCapture = '';
      let remainder = this.autocompleteBuffer.slice(endIndex + endMarker.length);
      if (remainder.startsWith('\r')) remainder = remainder.slice(1);
      if (remainder.startsWith('\n')) remainder = remainder.slice(1);
      this.autocompleteBuffer = remainder;
    }

    if (!output) return new Uint8Array();
    return this.textEncoder.encode(output);
  }

  private applyPreferences(prefs: Preferences) {
    const terminal = this.terminal;
    if (!terminal) return;

    for (const [key, value] of Object.entries(prefs)) {
      switch (key) {
        case 'rendererType':
          this.setRendererType(value as RendererType);
          break;
        case 'disableLeaveAlert':
          if (value) window.removeEventListener('beforeunload', this.onWindowUnload);
          break;
        case 'disableResizeOverlay':
          if (value) this.resizeOverlay = false;
          break;
        case 'disableReconnect':
          if (value) {
            this.reconnect = false;
            this.doReconnect = false;
          }
          break;
        case 'titleFixed':
          if (!value || value === '') break;
          this.titleFixed = String(value);
          document.title = this.titleFixed;
          break;
        case 'unicodeVersion':
          if (value === 6 || value === '6') {
            terminal.unicode.activeVersion = '6';
          } else {
            terminal.loadAddon(new Unicode11Addon());
            terminal.unicode.activeVersion = '11';
          }
          break;
        default:
          {
            const opts = terminal.options as Record<string, unknown>;
            if (opts[key] instanceof Object) {
              opts[key] = Object.assign({}, opts[key] as object, value);
            } else {
              opts[key] = value;
            }
            if (key.startsWith('font')) this.fitAddon.fit();
          }
          break;
      }
    }
  }

  private setRendererType(value: RendererType) {
    const terminal = this.terminal;
    if (!terminal) return;

    const disposeWebglRenderer = () => {
      try {
        this.webglAddon?.dispose();
      } catch {
        // ignore
      }
      this.webglAddon = undefined;
    };

    const enableWebglRenderer = () => {
      if (this.webglAddon) return;
      this.webglAddon = new WebglAddon();
      try {
        this.webglAddon.onContextLoss(() => this.webglAddon?.dispose());
        terminal.loadAddon(this.webglAddon);
      } catch {
        // Fall back to DOM renderer if WebGL fails
        disposeWebglRenderer();
      }
    };

    switch (value) {
      case 'webgl':
        enableWebglRenderer();
        break;
      case 'dom':
        disposeWebglRenderer();
        break;
      default:
        break;
    }
  }
}
