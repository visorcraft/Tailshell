import type { ITerminalOptions, ITheme } from '@xterm/xterm';
import { Component } from 'preact';

import { Xterm, type ConnectionState, type ClientOptions, type FlowControl, type TmuxScrollState } from './xterm';

export type TerminalProps = {
  id: string;
  wsUrl: string;
  tokenUrl: string;
  tmuxPrefix: string;
  clientOptions: ClientOptions;
  termOptions: ITerminalOptions;
  flowControl: FlowControl;
  onConnectionStateChange?: (state: ConnectionState) => void;
  onCopySelection?: (selection: string) => void;
  onTitlePayload?: (payload: string) => void;
};

export class Terminal extends Component<TerminalProps> {
  private container?: HTMLElement;
  private xterm: Xterm;
  private resizeObserver?: ResizeObserver;
  private tmuxCommandQueue: Array<{ command: string; prefix: string }> = [];
  private tmuxCommandInProgress = false;

  constructor(props: TerminalProps) {
    super(props);
    this.xterm = new Xterm(props, props.onConnectionStateChange, props.onCopySelection, props.onTitlePayload);
  }

  async componentDidMount() {
    await this.xterm.refreshToken();
    if (this.container) {
      this.xterm.open(this.container);
      this.resizeObserver = new ResizeObserver(() => this.xterm.fit());
      this.resizeObserver.observe(this.container);
    }
    this.xterm.connect();
  }

  componentWillUnmount() {
    this.resizeObserver?.disconnect();
    this.xterm.dispose();
  }

  focus() {
    this.xterm.focus();
  }

  send(data: string | Uint8Array) {
    this.xterm.sendData(data);
  }

  getSelection() {
    return this.xterm.getSelection();
  }

  getLastSelection() {
    return this.xterm.getLastSelection();
  }

  getBufferText(lines = 200) {
    return this.xterm.getBufferText(lines);
  }

  getViewportText() {
    return this.xterm.getViewportText();
  }

  setUserInputEnabled(enabled: boolean) {
    this.xterm.setUserInputEnabled(enabled);
  }

  setTheme(theme: ITheme) {
    this.xterm.setTheme(theme);
  }

  componentDidUpdate(prevProps: TerminalProps) {
    if (prevProps.tmuxPrefix !== this.props.tmuxPrefix) {
      this.xterm.setTmuxPrefix(this.props.tmuxPrefix);
    }
  }

  setTmuxScrollState(state: TmuxScrollState | null) {
    this.xterm.setTmuxScrollState(state);
  }

  fit() {
    this.xterm.fit();
  }

  sendTmuxCommand(command: string, prefix = '\x02') {
    // Queue commands to prevent interleaving when multiple are sent in quick succession
    this.tmuxCommandQueue.push({ command, prefix });
    this.processNextTmuxCommand();
  }

  private processNextTmuxCommand() {
    if (this.tmuxCommandInProgress || this.tmuxCommandQueue.length === 0) return;

    this.tmuxCommandInProgress = true;
    const { command, prefix } = this.tmuxCommandQueue.shift()!;

    // tmux: Prefix (Ctrl+B) + ":" opens the command prompt.
    // Send prefix as binary to avoid filtering, then colon and command.
    const prefixByte = prefix.charCodeAt(0);
    this.send(new Uint8Array([prefixByte]));
    window.setTimeout(() => {
      this.send(':');
      window.setTimeout(() => {
        this.send(`${command}\r`);
        // Mark complete and process next command after a small delay
        window.setTimeout(() => {
          this.tmuxCommandInProgress = false;
          this.processNextTmuxCommand();
        }, 100);
      }, 200);
    }, 200);
  }

  sendTmuxKeys(keys: string, prefix = '\x02') {
    this.send(`${prefix}${keys}`);
  }

  render({ id }: TerminalProps) {
    return (
      <div
        id={id}
        ref={(node) => {
          this.container = node ?? undefined;
        }}
      />
    );
  }
}
