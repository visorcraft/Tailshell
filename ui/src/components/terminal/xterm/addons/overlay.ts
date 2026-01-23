import type { ITerminalAddon, Terminal } from '@xterm/xterm';

export class OverlayAddon implements ITerminalAddon {
  private terminal?: Terminal;
  private overlayNode: HTMLElement;
  private overlayTimeout?: number;

  constructor() {
    this.overlayNode = document.createElement('div');
    this.overlayNode.className = 'xterm-overlay';
  }

  activate(terminal: Terminal): void {
    this.terminal = terminal;
  }

  dispose(): void {
    if (this.overlayTimeout) window.clearTimeout(this.overlayTimeout);
    this.overlayNode.remove();
  }

  showOverlay = (msg: string, timeout?: number): void => {
    const terminal = this.terminal;
    if (!terminal?.element) return;

    const overlayNode = this.overlayNode;
    overlayNode.textContent = msg;
    overlayNode.style.opacity = '0.85';

    if (!overlayNode.parentNode) terminal.element.appendChild(overlayNode);

    const divSize = terminal.element.getBoundingClientRect();
    const overlaySize = overlayNode.getBoundingClientRect();
    overlayNode.style.top = `${(divSize.height - overlaySize.height) / 2}px`;
    overlayNode.style.left = `${(divSize.width - overlaySize.width) / 2}px`;

    if (this.overlayTimeout) window.clearTimeout(this.overlayTimeout);
    if (!timeout) return;

    this.overlayTimeout = window.setTimeout(() => {
      overlayNode.style.opacity = '0';
      this.overlayTimeout = window.setTimeout(() => {
        overlayNode.remove();
        this.overlayTimeout = undefined;
        overlayNode.style.opacity = '0.85';
      }, 220);
    }, timeout);
  };
}

