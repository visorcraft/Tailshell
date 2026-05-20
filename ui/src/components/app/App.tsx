import type { JSX } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Suspense, lazy } from 'preact/compat';
import type { ITerminalOptions } from '@xterm/xterm';

import { Terminal } from '../terminal/Terminal';
import type { ClientOptions, ConnectionState, FlowControl } from '../terminal/xterm';
import { Modal } from '../modal/Modal';
import { DESIGNS as THEMES, DEFAULT_DESIGN_ID as DEFAULT_THEME_ID, getDesign as getTheme } from '../../designs';
import { DEFAULT_LAYOUT_ID, getLayout, LAYOUTS } from '../../layouts';
import { AI_PAYLOAD_PREFIX } from '../../constants';
import type { CurrentUser, Prompt, PromptFilter, PromptFolder, Tag, Workspace } from '../../types';
import { Dropdown } from '../dropdown/Dropdown';
import { withCsrfHeaders } from '../../utils/csrf';

const PromptLibraryModal = lazy(() =>
  import('../prompts/PromptLibraryModal').then((mod) => ({ default: mod.PromptLibraryModal }))
);
const AdminModal = lazy(() => import('../admin/AdminModal').then((mod) => ({ default: mod.AdminModal })));

const LEGACY_THEME_STORAGE_KEY = 'ai-webterm.design';
const THEME_STORAGE_KEY = 'ai-webterm.theme';
const LAYOUT_STORAGE_KEY = 'ai-webterm.layout';
const PREFIX_STORAGE_KEY = 'ai-webterm.tmuxPrefix';
const COMPOSE_STORAGE_KEY = 'ai-webterm.composeOpen';
const COMPOSE_DRAFTS_STORAGE_KEY = 'ai-webterm.composeDrafts';
const CLOSE_IDLE_STORAGE_KEY = 'ai-webterm.closeIdleSkipConfirm';
const FOCUS_COMPOSE_POSITION_STORAGE_KEY = 'ai-webterm.focusComposePosition';
const FOCUS_OVERVIEW_STORAGE_KEY = 'ai-webterm.focusOverviewEnabled';
const COMPOSE_OPACITY_STORAGE_KEY = 'ai-webterm.composeOpacity';
const PROMPT_CONFIRM_STORAGE_KEY = 'ai-webterm.promptConfirm';

type FocusComposePosition = 'left' | 'center' | 'right';

const PREFIX_CHOICES = [
  { value: '\x02', label: 'Ctrl+B (default)' },
  { value: '\x01', label: 'Ctrl+A' }
] as const;

type WindowOption = {
  id: string;
  index: number;
  label: string;
  name: string;
  active: boolean;
};

function parseTmuxPrefix(value: string | null) {
  if (!value) return null;
  const normalized = value.trim();
  if (!normalized) return null;
  if (normalized === 'C-b' || normalized === '^B') return '\x02';
  if (normalized === 'C-a' || normalized === '^A') return '\x01';
  return null;
}

function tmuxWindowTarget(id: string) {
  return id.startsWith('@') ? id : `:${id}`;
}

function sanitizeTmuxSession(value: string) {
  const cleaned = value.replace(/[^A-Za-z0-9_-]/g, '');
  return cleaned || 'ai';
}

function readStorage(key: string, fallback: string) {
  try {
    return window.localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function writeStorage(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // ignore
  }
}

function getQueryTheme() {
  try {
    const params = new URLSearchParams(window.location.search);
    const queryTheme = params.get('theme') ?? params.get('design');
    if (!queryTheme) return undefined;
    return THEMES.some((theme) => theme.id === queryTheme) ? queryTheme : undefined;
  } catch {
    return undefined;
  }
}

function getQueryLayout() {
  try {
    const queryLayout = new URLSearchParams(window.location.search).get('layout');
    if (!queryLayout) return undefined;
    return LAYOUTS.some((layout) => layout.id === queryLayout) ? queryLayout : undefined;
  } catch {
    return undefined;
  }
}

function readThemeStorage(fallback: string) {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored) return stored;
    const legacy = window.localStorage.getItem(LEGACY_THEME_STORAGE_KEY);
    if (legacy) {
      window.localStorage.setItem(THEME_STORAGE_KEY, legacy);
      return legacy;
    }
    return fallback;
  } catch {
    return fallback;
  }
}

function getWsUrl() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/ws`;
}

function getCommonPrefix(values: string[]) {
  if (values.length === 0) return '';
  let prefix = values[0];
  for (const value of values.slice(1)) {
    while (!value.startsWith(prefix) && prefix) {
      prefix = prefix.slice(0, -1);
    }
    if (!prefix) break;
  }
  return prefix;
}

function parseWindowsPayload(payload: string): WindowOption[] {
  const options = new Map<string, WindowOption>();
  const lines = payload
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  for (const line of lines) {
    const parts = line.split('::');
    const rawId = (parts[0] ?? '').trim();
    if (!rawId) continue;

    let indexPart = '';
    let nameParts: string[] = [];
    let activePart = '0';

    if (parts.length >= 4) {
      indexPart = parts[1] ?? '';
      nameParts = parts.slice(2, -1);
      activePart = parts[parts.length - 1] ?? '0';
    } else {
      indexPart = parts[0] ?? '';
      nameParts = parts.slice(1, -1);
      activePart = parts[parts.length - 1] ?? '0';
    }

    const parsedIndex = parseInt(indexPart, 10);
    const index = Number.isFinite(parsedIndex) ? parsedIndex : 0;
    const name = nameParts.join('::').trim();
    const label = name ? `${index + 1} · ${name}` : `Tab ${index + 1}`;
    const active = activePart.trim() === '1';
    options.set(rawId, { id: rawId, index, name, label, active });
  }
  return Array.from(options.values()).sort((a, b) => a.index - b.index);
}

function parseCompletionPayload(payload: string) {
  return payload
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

export function App() {
  const [layoutId, _setLayoutId] = useState(
    () => getQueryLayout() ?? readStorage(LAYOUT_STORAGE_KEY, DEFAULT_LAYOUT_ID)
  );
  const layout = useMemo(() => getLayout(layoutId), [layoutId]);

  const [themeId, setThemeId] = useState(() => getQueryTheme() ?? readThemeStorage(DEFAULT_THEME_ID));
  const theme = useMemo(() => getTheme(themeId), [themeId]);

  const [connectionState, setConnectionState] = useState<ConnectionState>('connecting');
  const [composeOpen, setComposeOpen] = useState(() => readStorage(COMPOSE_STORAGE_KEY, 'true') === 'true');
  const [composeText, setComposeText] = useState('');
  const [showToolsModal, setShowToolsModal] = useState(false);
  const [toolsTab, setToolsTab] = useState<'settings' | 'activity' | 'account'>('settings');
  const [activityPage, setActivityPage] = useState(0);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwordForm, setPasswordForm] = useState({ current: '', new: '', confirm: '' });
  const [passwordError, setPasswordError] = useState('');
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [prefix, setPrefix] = useState(() => readStorage(PREFIX_STORAGE_KEY, '\x02'));
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState<number | null>(null);
  const [activeTmuxSession, setActiveTmuxSession] = useState<string | null>(null);
  const [tabs, setTabs] = useState<WindowOption[]>([]);
  const [editingTabId, setEditingTabId] = useState<string | null>(null);
  const [editingTabName, setEditingTabName] = useState('');
  const isCommittingRenameRef = useRef(false);
  const [tabOverviewOpen, setTabOverviewOpen] = useState(false);
  const [notice, setNotice] = useState('');
  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [folders, setFolders] = useState<PromptFolder[]>([]);
  const [filters, setFilters] = useState<PromptFilter[]>([]);
  const [recentActivity, setRecentActivity] = useState<
    Array<{ id: number; action: string; details: unknown; created_at: string }>
  >([]);
  const [apiHealthy, setApiHealthy] = useState(true);
  const [showPromptLibraryModal, setShowPromptLibraryModal] = useState(false);
  const [showWorkspacesModal, setShowWorkspacesModal] = useState(false);
  const [showAdminModal, setShowAdminModal] = useState(false);
  const [composeDrafts, setComposeDrafts] = useState<Record<string, string>>(() => {
    try {
      const raw = window.localStorage.getItem(COMPOSE_DRAFTS_STORAGE_KEY);
      return raw ? (JSON.parse(raw) as Record<string, string>) : {};
    } catch {
      return {};
    }
  });
  const [closeIdleSkipConfirm, setCloseIdleSkipConfirm] = useState(
    () => readStorage(CLOSE_IDLE_STORAGE_KEY, 'true') === 'true'
  );
  const [focusComposePosition, setFocusComposePosition] = useState<FocusComposePosition>(() => {
    const stored = readStorage(FOCUS_COMPOSE_POSITION_STORAGE_KEY, 'center');
    return stored === 'left' || stored === 'right' || stored === 'center' ? stored : 'center';
  });
  const [focusOverviewEnabled, setFocusOverviewEnabled] = useState(
    () => readStorage(FOCUS_OVERVIEW_STORAGE_KEY, 'false') === 'true'
  );
  const [composeOpacity, setComposeOpacity] = useState(() => {
    const stored = readStorage(COMPOSE_OPACITY_STORAGE_KEY, '50');
    const parsed = parseInt(stored, 10);
    return Number.isFinite(parsed) ? Math.max(0, Math.min(100, parsed)) : 50;
  });
  const [promptConfirmMode, setPromptConfirmMode] = useState(() =>
    readStorage(PROMPT_CONFIRM_STORAGE_KEY, 'dangerous')
  );

  const refreshAbortRef = useRef<AbortController | null>(null);

  const terminalRef = useRef<Terminal | null>(null);
  const composeTextRef = useRef('');
  const _defaultWorkspaceAppliedRef = useRef(false);
  const dragTabIdRef = useRef<string | null>(null);
  const dragWorkspaceIdRef = useRef<number | null>(null);
  const pendingStateRequestId = useRef<string | null>(null);
  const pendingWindowStatusRequestId = useRef<string | null>(null);
  const pendingWindowStatusTabId = useRef<string | null>(null);
  const pendingWindowStatusTabName = useRef<string | null>(null);
  const pendingCompletionRequestId = useRef<string | null>(null);
  const autocompleteInFlight = useRef(false);
  const autocompleteTimeoutRef = useRef<number | null>(null);

  const clearAutocompleteTimeout = () => {
    if (autocompleteTimeoutRef.current) {
      window.clearTimeout(autocompleteTimeoutRef.current);
      autocompleteTimeoutRef.current = null;
    }
  };

  useEffect(() => {
    writeStorage(LAYOUT_STORAGE_KEY, layout.id);
  }, [layout.id]);

  useEffect(() => {
    writeStorage(THEME_STORAGE_KEY, theme.id);
  }, [theme.id]);

  useEffect(() => {
    writeStorage(PREFIX_STORAGE_KEY, prefix);
  }, [prefix]);

  useEffect(() => {
    writeStorage(COMPOSE_STORAGE_KEY, String(composeOpen));
  }, [composeOpen]);

  useEffect(() => {
    writeStorage(CLOSE_IDLE_STORAGE_KEY, String(closeIdleSkipConfirm));
  }, [closeIdleSkipConfirm]);

  useEffect(() => {
    writeStorage(FOCUS_COMPOSE_POSITION_STORAGE_KEY, focusComposePosition);
  }, [focusComposePosition]);

  useEffect(() => {
    writeStorage(FOCUS_OVERVIEW_STORAGE_KEY, String(focusOverviewEnabled));
  }, [focusOverviewEnabled]);

  useEffect(() => {
    writeStorage(COMPOSE_OPACITY_STORAGE_KEY, String(composeOpacity));
  }, [composeOpacity]);

  useEffect(() => {
    const mode =
      promptConfirmMode === 'never' || promptConfirmMode === 'always' || promptConfirmMode === 'dangerous'
        ? promptConfirmMode
        : 'dangerous';
    writeStorage(PROMPT_CONFIRM_STORAGE_KEY, mode);
    if (mode !== promptConfirmMode) setPromptConfirmMode(mode);
  }, [promptConfirmMode]);

  useEffect(() => {
    try {
      window.localStorage.setItem(COMPOSE_DRAFTS_STORAGE_KEY, JSON.stringify(composeDrafts));
    } catch {
      // ignore
    }
  }, [composeDrafts]);

  useEffect(() => {
    composeTextRef.current = composeText;
  }, [composeText]);

  useEffect(() => {
    document.title = 'AI Web Terminal';
  }, []);

  useEffect(() => {
    if (!terminalRef.current) return;
    terminalRef.current.setTheme(theme.xtermTheme);
    window.setTimeout(() => terminalRef.current?.fit(), 50);
  }, [theme.id]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(''), 2000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    if (connectionState !== 'open') return;
    // Longer delay on first load to ensure tmux is fully ready
    const timer = window.setTimeout(() => refreshTmuxState(), 3500);
    return () => window.clearTimeout(timer);
  }, [connectionState]);

  useEffect(() => {
    if (!activeTmuxSession) return;
    const match = workspaces.find((ws) => ws.tmux_session === activeTmuxSession);
    if (!match) return;
    setActiveWorkspaceId(match.id);
  }, [activeTmuxSession, workspaces]);

  // Disabled: sendTmuxCommand doesn't work reliably over ttyd.
  // ai-session already attaches to the user's default tmux session.
  // useEffect(() => {
  //   if (connectionState !== 'open') return;
  //   if (workspaces.length === 0) return;
  //   if (defaultWorkspaceAppliedRef.current) return;
  //   const target = workspaces.find((ws) => ws.is_default) ?? workspaces[0];
  //   if (!target) return;
  //   defaultWorkspaceAppliedRef.current = true;
  //   const timer = window.setTimeout(() => refreshTmuxState(), 1500);
  //   return () => window.clearTimeout(timer);
  // }, [connectionState, workspaces, prefix]);

  useEffect(() => {
    window.setTimeout(() => terminalRef.current?.fit(), 50);
  }, [composeOpen, layout.id]);

  const termOptions = useMemo<ITerminalOptions>(
    () => ({
      cursorBlink: true,
      fontFamily: 'DM Mono, JetBrains Mono, Fira Code, Menlo, Consolas, monospace',
      fontSize: 14,
      fontWeight: 400,
      fontWeightBold: 600,
      lineHeight: 1.2,
      scrollback: 10000,
      scrollSensitivity: 5,
      fastScrollSensitivity: 15,
      smoothScrollDuration: 0,
      allowProposedApi: true,
      theme: theme.xtermTheme
    }),
    []
  );

  const clientOptions = useMemo<ClientOptions>(
    () => ({
      // Canvas renderer is significantly more stable than WebGL across browsers/drivers.
      rendererType: 'dom',
      disableLeaveAlert: false,
      disableResizeOverlay: false,
      enableSixel: false,
      titleFixed: 'AI Web Terminal',
      isWindows: window.navigator.userAgent.toLowerCase().includes('windows'),
      unicodeVersion: '11'
    }),
    []
  );

  const flowControl = useMemo<FlowControl>(
    () => ({
      limit: 100000,
      highWater: 10,
      lowWater: 3
    }),
    []
  );

  const handleTitlePayload = (payload: string) => {
    if (!payload.startsWith(AI_PAYLOAD_PREFIX)) return;
    const raw = payload.slice(AI_PAYLOAD_PREFIX.length);
    const parts = raw.split('::');
    const type = parts[0];
    if (!type) return;

    if (type === 'windows') {
      // Backwards compatible payload (no session info).
      const requestId = parts.length >= 3 ? parts[1] : '';
      const encoded = parts.length >= 3 ? parts.slice(2).join('::') : (parts[1] ?? '');
      if (!encoded) return;
      if (requestId && pendingStateRequestId.current && requestId !== pendingStateRequestId.current) return;
      const decoded = window.atob(encoded);
      const windows = parseWindowsPayload(decoded);
      setTabs(windows);
      return;
    }

    if (type === 'state') {
      const requestId = parts.length >= 3 ? parts[1] : '';
      const encoded = parts.length >= 3 ? parts.slice(2).join('::') : (parts[1] ?? '');
      if (!encoded) return;
      if (requestId && pendingStateRequestId.current && requestId !== pendingStateRequestId.current) return;

      const decoded = window.atob(encoded);
      const lines = decoded
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
      let session: string | null = null;
      let tmuxPrefix: string | null = null;
      const windowLines: string[] = [];
      for (const line of lines) {
        if (line.startsWith('session::')) {
          session = line.slice('session::'.length).trim() || null;
          continue;
        }
        if (line.startsWith('prefix::')) {
          tmuxPrefix = line.slice('prefix::'.length).trim() || null;
          continue;
        }
        windowLines.push(line);
      }

      const windows = parseWindowsPayload(windowLines.join('\n'));
      setActiveTmuxSession(session);
      const parsedPrefix = parseTmuxPrefix(tmuxPrefix);
      if (parsedPrefix && parsedPrefix !== prefix) {
        setPrefix(parsedPrefix);
      }
      setTabs(windows);
      return;
    }

    if (type === 'windowStatus') {
      const requestId = parts[1] ?? '';
      const encoded = parts.slice(2).join('::');
      if (!requestId || !encoded) return;
      if (pendingWindowStatusRequestId.current && requestId !== pendingWindowStatusRequestId.current) return;

      const decoded = window.atob(encoded);
      const status = new Map<string, string>();
      for (const line of decoded
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)) {
        const [key, ...rest] = line.split('::');
        if (!key) continue;
        status.set(key, rest.join('::'));
      }

      const command = (status.get('command') ?? '').trim().toLowerCase();
      const inMode = (status.get('in_mode') ?? '').trim() === '1';
      const dead = (status.get('dead') ?? '').trim() === '1';

      const tabId = pendingWindowStatusTabId.current;
      const tabName = pendingWindowStatusTabName.current;
      pendingWindowStatusRequestId.current = null;
      pendingWindowStatusTabId.current = null;
      pendingWindowStatusTabName.current = null;

      if (!tabId) return;

      const idleShells = new Set(['bash', 'zsh', 'fish', 'sh', 'dash', 'pwsh', 'powershell', 'cmd.exe']);
      const safeToClose = dead || (!inMode && idleShells.has(command));
      if (safeToClose) {
        killTab(tabId);
        return;
      }

      const ok = window.confirm(`Close tab${tabName ? ` "${tabName}"` : ''}? This may terminate a running task.`);
      if (ok) killTab(tabId);
      return;
    }

    if (type === 'scroll') {
      const requestId = parts[1] ?? '';
      const encoded = parts.slice(2).join('::');
      if (!requestId || !encoded) return;

      const decoded = window.atob(encoded);
      const values = new Map<string, string>();
      for (const line of decoded
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)) {
        const [key, ...rest] = line.split('::');
        if (!key) continue;
        values.set(key, rest.join('::'));
      }

      const historySize = Math.max(0, parseInt(values.get('history_size') ?? '0', 10) || 0);
      const historyLimit = Math.max(0, parseInt(values.get('history_limit') ?? '0', 10) || 0);
      const paneHeight = Math.max(0, parseInt(values.get('pane_height') ?? '0', 10) || 0);
      const inMode = (values.get('in_mode') ?? '').trim() === '1';
      const scrollPosition = Math.max(0, parseInt(values.get('scroll_position') ?? '0', 10) || 0);

      terminalRef.current?.setTmuxScrollState({
        historySize,
        historyLimit,
        paneHeight,
        inMode,
        scrollPosition
      });
      return;
    }

    if (type === 'complete') {
      const requestId = parts[1] ?? '';
      const encoded = parts.slice(2).join('::');
      if (!requestId) return;
      if (pendingCompletionRequestId.current && requestId !== pendingCompletionRequestId.current) return;
      pendingCompletionRequestId.current = null;
      clearAutocompleteTimeout();
      const decoded = encoded ? window.atob(encoded) : '';
      const matches = parseCompletionPayload(decoded);
      if (matches.length === 0) {
        setNotice('No completions');
        autocompleteInFlight.current = false;
        return;
      }
      const currentComposeText = composeTextRef.current;
      const lines = currentComposeText.split('\n');
      const lastLine = lines[lines.length - 1] ?? '';
      const match = lastLine.match(/(\S+)$/);
      if (!match) {
        autocompleteInFlight.current = false;
        return;
      }
      const token = match[1];
      const common = getCommonPrefix(matches);
      if (common && common !== token) {
        lines[lines.length - 1] = lastLine.replace(/(\S+)$/, common);
        setComposeText(lines.join('\n'));
        setNotice(`Autocomplete: ${common}`);
      } else if (matches.length === 1) {
        lines[lines.length - 1] = lastLine.replace(/(\S+)$/, matches[0]);
        setComposeText(lines.join('\n'));
        setNotice(`Autocomplete: ${matches[0]}`);
      }
      if (matches.length > 1) {
        const sample = matches.slice(0, 4).join(', ');
        setNotice(matches.length > 4 ? `Matches: ${sample}…` : `Matches: ${sample}`);
      }
      autocompleteInFlight.current = false;
    }
  };

  const refreshTmuxState = () => {
    if (connectionState !== 'open') return;
    pendingStateRequestId.current = Date.now().toString();
    setNotice('Syncing tabs…');
    terminalRef.current?.sendTmuxCommand(
      `run-shell -b "$HOME/.local/bin/ai-tmux-state ${pendingStateRequestId.current}"`,
      prefix
    );
  };

  const requestAutocomplete = () => {
    if (connectionState !== 'open') return;
    const snapshot = composeText;
    if (!snapshot.trim()) return;
    const lines = snapshot.split('\n');
    const lastLine = lines[lines.length - 1] ?? '';
    const match = lastLine.match(/(\S+)$/);
    if (!match) return;
    if (autocompleteInFlight.current) {
      setNotice('Autocomplete busy');
      return;
    }
    const token = match[1];
    const requestId = Date.now().toString();
    pendingCompletionRequestId.current = requestId;
    autocompleteInFlight.current = true;
    const tokenEncoded = window.btoa(token);
    const helperCmd = `run-shell -b "$HOME/.local/bin/ai-tmux-complete ${requestId} ${tokenEncoded}"`;
    setNotice('Fetching completions...');
    clearAutocompleteTimeout();
    terminalRef.current?.sendTmuxCommand(helperCmd, prefix);
    autocompleteTimeoutRef.current = window.setTimeout(() => {
      autocompleteInFlight.current = false;
      pendingCompletionRequestId.current = null;
      setNotice('Autocomplete timed out');
    }, 4500);
  };

  const tabOverviewEnabled = focusOverviewEnabled;

  useEffect(() => {
    if (!tabOverviewEnabled) {
      setTabOverviewOpen(false);
    }
  }, [tabOverviewEnabled]);

  const activeWorkspace = useMemo(() => {
    if (activeWorkspaceId !== null) {
      return workspaces.find((ws) => ws.id === activeWorkspaceId) ?? null;
    }
    if (activeTmuxSession) {
      return workspaces.find((ws) => ws.tmux_session === activeTmuxSession) ?? null;
    }
    return workspaces.find((ws) => ws.is_default) ?? workspaces[0] ?? null;
  }, [activeWorkspaceId, activeTmuxSession, workspaces]);
  const activeTab = useMemo(() => tabs.find((tab) => tab.active) ?? tabs[0] ?? null, [tabs]);

  const composeDraftKey = useMemo(
    () => (activeWorkspaceId !== null && activeTab ? `${activeWorkspaceId}:${activeTab.id}` : null),
    [activeWorkspaceId, activeTab?.id]
  );
  const visiblePrompts = useMemo(() => {
    const workspaceId = activeWorkspaceId;
    return prompts.filter((prompt) => {
      if (prompt.status !== 'published') return false;
      if (prompt.is_global) return true;
      if (!workspaceId) return false;
      return (prompt.workspace_ids ?? []).includes(workspaceId);
    });
  }, [prompts, activeWorkspaceId]);

  useEffect(() => {
    if (!composeDraftKey) return;
    setComposeText(composeDrafts[composeDraftKey] ?? '');
  }, [composeDraftKey]);

  useEffect(() => {
    if (!composeDraftKey) return;
    setComposeDrafts((prev) => {
      if (prev[composeDraftKey] === composeText) return prev;
      return { ...prev, [composeDraftKey]: composeText };
    });
  }, [composeText, composeDraftKey]);

  const focusTerminal = () => {
    const selection = terminalRef.current?.getSelection();
    if (selection) return;
    terminalRef.current?.focus();
  };

  const sendText = (text: string) => {
    if (!terminalRef.current) return;
    const normalized = text.replace(/\r?\n/g, '\r');
    if (!normalized) return;
    terminalRef.current.send(normalized);
  };

  const sendComposer = () => {
    const trimmed = composeText.trim();
    if (!trimmed) {
      setNotice('Composer is empty');
      return;
    }
    const normalized = composeText.replace(/\r?\n/g, '\r');
    const needsReturn = !normalized.endsWith('\r');
    terminalRef.current?.send(`${normalized}${needsReturn ? '\r' : ''}`);
    setComposeText('');
    focusTerminal();
  };

  const handleComposerKey = (event: JSX.TargetedKeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Tab') {
      event.preventDefault();
      requestAutocomplete();
      return;
    }
    if (event.key !== 'Enter') return;
    if (event.shiftKey) return;
    event.preventDefault();
    sendComposer();
  };

  const createTab = () => {
    terminalRef.current?.sendTmuxKeys('c', prefix);
    window.setTimeout(() => refreshTmuxState(), 240);
  };

  const killTab = (tabId: string) => {
    const target = tmuxWindowTarget(tabId);
    terminalRef.current?.sendTmuxCommand(`kill-window -t ${target}`, prefix);
    window.setTimeout(() => refreshTmuxState(), 600);
  };

  const requestCloseTab = (tab: WindowOption) => {
    if (!closeIdleSkipConfirm) {
      const ok = window.confirm(`Close tab${tab.name ? ` "${tab.name}"` : ''}? This will terminate any running task.`);
      if (ok) killTab(tab.id);
      return;
    }

    const requestId = Date.now().toString();
    pendingWindowStatusRequestId.current = requestId;
    pendingWindowStatusTabId.current = tab.id;
    pendingWindowStatusTabName.current = tab.name;
    setNotice('Checking tab status…');
    terminalRef.current?.sendTmuxCommand(
      `run-shell -b "$HOME/.local/bin/ai-tmux-window-status ${requestId} ${tab.id}"`,
      prefix
    );

    window.setTimeout(() => {
      if (pendingWindowStatusRequestId.current !== requestId) return;
      pendingWindowStatusRequestId.current = null;
      pendingWindowStatusTabId.current = null;
      pendingWindowStatusTabName.current = null;
      const ok = window.confirm(`Close tab${tab.name ? ` "${tab.name}"` : ''}? This may terminate a running task.`);
      if (ok) killTab(tab.id);
    }, 900);
  };

  const copyTranscript = async () => {
    const full = terminalRef.current?.getBufferText(Number.POSITIVE_INFINITY) ?? '';
    const viewport = terminalRef.current?.getViewportText() ?? '';
    const last = terminalRef.current?.getBufferText(200) ?? '';
    const text = full.trim() ? full : viewport.trim() ? viewport : last;
    if (!text.trim()) {
      setNotice('Nothing to copy');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      setNotice('Copied');
    } catch {
      setNotice('Clipboard blocked');
    }
  };

  const pasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text) {
        setNotice('Clipboard empty');
        return;
      }
      sendText(text);
      setNotice('Pasted to terminal');
    } catch {
      setNotice('Clipboard blocked');
    }
  };

  const ensureTmuxSession = (session: string) => {
    const safeSession = sanitizeTmuxSession(session);
    terminalRef.current?.sendTmuxCommand(
      `run-shell -b "tmux has-session -t '${safeSession}' 2>/dev/null || tmux new-session -d -s '${safeSession}' -n shell"`,
      prefix
    );
  };

  const switchTmuxSession = (session: string) => {
    const safeSession = sanitizeTmuxSession(session);
    ensureTmuxSession(safeSession);
    terminalRef.current?.sendTmuxCommand(`switch-client -t '${safeSession}'`, prefix);
    window.setTimeout(() => refreshTmuxState(), 600);
  };

  const switchWorkspace = (workspaceId: number) => {
    const workspace = workspaces.find((ws) => ws.id === workspaceId);
    if (!workspace) return;
    setActiveWorkspaceId(workspace.id);
    switchTmuxSession(workspace.tmux_session);
    fetch(`/api/workspaces/${workspace.id}/activate`, { method: 'POST', headers: withCsrfHeaders() }).catch(() => {
      // ignore
    });
  };

  const createWorkspace = async () => {
    const raw = window.prompt('Workspace name (max 64 characters)');
    if (!raw) return;
    const name = raw.trim().slice(0, 64);
    if (!name) return;

    try {
      const response = await fetch('/api/workspaces', {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ name })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        setNotice(data.error || 'Failed to create workspace');
        return;
      }

      const created = data as Workspace;
      await fetchWorkspaces();
      setActiveWorkspaceId(created.id);
      switchTmuxSession(created.tmux_session);
      setNotice('Workspace created');
    } catch {
      setNotice('Network error');
    }
  };

  const updateWorkspace = async (
    workspaceId: number,
    patch: Partial<Pick<Workspace, 'name' | 'pinned' | 'is_default' | 'sort_order'>>
  ) => {
    try {
      const response = await fetch(`/api/workspaces/${workspaceId}`, {
        method: 'PUT',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(patch)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        setNotice(data.error || 'Failed to update workspace');
        return false;
      }
      await fetchWorkspaces();
      return true;
    } catch {
      setNotice('Network error');
      return false;
    }
  };

  const reorderWorkspaces = async (ids: number[]) => {
    try {
      const response = await fetch('/api/workspaces/reorder', {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ ids })
      });
      if (!response.ok) return;
      await fetchWorkspaces();
    } catch {
      // ignore
    }
  };

  const deleteWorkspace = async (workspace: Workspace) => {
    const isLast = workspaces.length <= 1;
    if (isLast) {
      setNotice('Cannot delete your last workspace');
      return;
    }

    const ok = window.confirm(
      workspace.prompt_count > 0
        ? `Delete workspace "${workspace.name}"?\n\nThis will remove it from ${workspace.prompt_count} prompt(s) and delete any prompt(s) that were scoped only to this workspace.`
        : `Delete workspace "${workspace.name}"?`
    );
    if (!ok) return;

    // If deleting the active workspace, switch away first.
    if (activeWorkspaceId === workspace.id) {
      const fallback = workspaces.find((ws) => ws.id !== workspace.id) ?? null;
      if (fallback) {
        switchWorkspace(fallback.id);
      }
    }

    const confirmParam = workspace.prompt_count > 0 ? '?confirm=true' : '';
    try {
      const response = await fetch(`/api/workspaces/${workspace.id}${confirmParam}`, {
        method: 'DELETE',
        headers: withCsrfHeaders()
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        setNotice(data.error || 'Failed to delete workspace');
        return;
      }

      const safeSession = sanitizeTmuxSession(workspace.tmux_session);
      terminalRef.current?.sendTmuxCommand(`kill-session -t '${safeSession}'`, prefix);
      await fetchWorkspaces();
      await fetchPrompts();
      setNotice('Workspace deleted');
    } catch {
      setNotice('Network error');
    }
  };

  const selectTab = (tabId: string) => {
    const target = tmuxWindowTarget(tabId);
    terminalRef.current?.sendTmuxCommand(`select-window -t ${target}`, prefix);
    focusTerminal();
    // sendTmuxCommand takes ~400ms (200ms + 200ms delays), plus tmux processing time.
    // Wait long enough to avoid interleaving with refreshTmuxState's command.
    window.setTimeout(() => refreshTmuxState(), 600);
  };

  const beginRenameTab = (tab: WindowOption) => {
    isCommittingRenameRef.current = false;
    setEditingTabId(tab.id);
    setEditingTabName(tab.name || `Tab ${tab.index + 1}`);
  };

  const cancelRenameTab = () => {
    setEditingTabId(null);
    setEditingTabName('');
    // Don't reset isCommittingRenameRef here - it prevents the blur handler from re-executing
  };

  const commitRenameTab = (tabId: string) => {
    // Prevent double-execution (Enter key triggers commit, then unmounting input triggers blur)
    if (isCommittingRenameRef.current) return;
    isCommittingRenameRef.current = true;

    const name = editingTabName
      .replace(/[\r\n]+/g, ' ')
      .replace(/::/g, ':')
      .trim()
      .slice(0, 64);
    if (!name) {
      cancelRenameTab();
      return;
    }

    // Skip if name hasn't changed
    const tab = tabs.find((t) => t.id === tabId);
    const currentName = tab?.name || `Tab ${(tab?.index ?? 0) + 1}`;
    if (name === currentName) {
      cancelRenameTab();
      return;
    }

    const escaped = name.replace(/"/g, '\\"');
    const target = tmuxWindowTarget(tabId);
    terminalRef.current?.sendTmuxCommand(`rename-window -t ${target} "${escaped}"`, prefix);
    cancelRenameTab();
    window.setTimeout(() => refreshTmuxState(), 600);
  };

  const moveTab = (sourceId: string, targetId: string) => {
    if (sourceId === targetId) return;
    const sourceTarget = tmuxWindowTarget(sourceId);
    const targetTarget = tmuxWindowTarget(targetId);
    // Swap windows, then re-select the source (dragged) tab to keep focus on it
    terminalRef.current?.sendTmuxCommand(`swap-window -s ${sourceTarget} -t ${targetTarget}`, prefix);
    terminalRef.current?.sendTmuxCommand(`select-window -t ${sourceTarget}`, prefix);
    window.setTimeout(() => refreshTmuxState(), 600);
  };

  const openPasswordModal = () => {
    setPasswordForm({ current: '', new: '', confirm: '' });
    setPasswordError('');
    setShowToolsModal(false);
    setShowPasswordModal(true);
  };

  const performLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST', headers: withCsrfHeaders() });
    } catch {
      // ignore
    } finally {
      window.location.href = '/logout';
    }
  };

  const handleChangePassword = async () => {
    setPasswordError('');

    if (!passwordForm.current || !passwordForm.new || !passwordForm.confirm) {
      setPasswordError('All fields are required');
      return;
    }

    if (passwordForm.new.length < 12) {
      setPasswordError('New password must be at least 12 characters');
      return;
    }

    if (passwordForm.new !== passwordForm.confirm) {
      setPasswordError('New passwords do not match');
      return;
    }

    setPasswordLoading(true);

    try {
      const response = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          currentPassword: passwordForm.current,
          newPassword: passwordForm.new
        })
      });

      const data = await response.json();

      if (!response.ok) {
        setPasswordError(data.error || 'Failed to change password');
        setPasswordLoading(false);
        return;
      }

      // Success - logout and redirect to login
      setShowPasswordModal(false);
      await performLogout();
    } catch {
      setPasswordError('Network error. Please try again.');
      setPasswordLoading(false);
    }
  };

  const fetchPrompts = async (signal?: AbortSignal) => {
    try {
      const response = await fetch('/api/prompts', { signal });
      if (response.ok) {
        const data = (await response.json()) as Prompt[];
        setPrompts(data);
      }
    } catch {
      // Silently fail - prompts are optional
    }
  };

  const fetchMe = async (signal?: AbortSignal) => {
    try {
      const response = await fetch('/api/auth/me', { signal });
      if (!response.ok) return;
      const data = (await response.json()) as CurrentUser;
      setCurrentUser(data);
    } catch {
      // ignore
    }
  };

  const fetchTags = async (signal?: AbortSignal) => {
    try {
      const response = await fetch('/api/tags', { signal });
      if (!response.ok) return;
      const data = (await response.json()) as Tag[];
      setTags(data);
    } catch {
      // ignore
    }
  };

  const fetchFolders = async (signal?: AbortSignal) => {
    try {
      const response = await fetch('/api/prompt-folders', { signal });
      if (!response.ok) return;
      const data = (await response.json()) as PromptFolder[];
      setFolders(data);
    } catch {
      // ignore
    }
  };

  const fetchFilters = async (signal?: AbortSignal) => {
    try {
      const response = await fetch('/api/prompt-filters', { signal });
      if (!response.ok) return;
      const data = (await response.json()) as PromptFilter[];
      setFilters(data);
    } catch {
      // ignore
    }
  };

  const fetchRecentActivity = async (signal?: AbortSignal) => {
    try {
      const response = await fetch('/api/activity/recent?limit=200', { signal });
      if (!response.ok) return;
      const data = (await response.json()) as Array<{
        id: number;
        action: string;
        details: unknown;
        created_at: string;
      }>;
      setRecentActivity(data);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    if (!showToolsModal) return;
    setToolsTab('settings');
    setActivityPage(0);
  }, [showToolsModal]);

  useEffect(() => {
    const pageSize = 10;
    const totalPages = Math.max(1, Math.ceil(recentActivity.length / pageSize));
    setActivityPage((prev) => Math.max(0, Math.min(prev, totalPages - 1)));
  }, [recentActivity.length]);

  const refreshAll = async () => {
    refreshAbortRef.current?.abort();
    const controller = new AbortController();
    refreshAbortRef.current = controller;
    const signal = controller.signal;

    await Promise.all([
      fetchMe(signal),
      fetchWorkspaces(signal),
      fetchPrompts(signal),
      fetchTags(signal),
      fetchFolders(signal),
      fetchFilters(signal),
      fetchRecentActivity(signal)
    ]);
  };

  const fetchWorkspaces = async (signal?: AbortSignal) => {
    try {
      const response = await fetch('/api/workspaces', { signal });
      if (!response.ok) return;
      const data = (await response.json()) as Workspace[];
      setWorkspaces(data);
      if (activeWorkspaceId === null && data.length > 0) {
        const fallback = data.find((ws) => ws.is_default) ?? data[0];
        setActiveWorkspaceId(fallback?.id ?? null);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    refreshAll();
  }, []);

  useEffect(() => {
    return () => refreshAbortRef.current?.abort();
  }, []);

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        const controller = new AbortController();
        const timer = window.setTimeout(() => controller.abort(), 2500);
        const response = await fetch('/api/health', { signal: controller.signal });
        window.clearTimeout(timer);
        if (!cancelled) setApiHealthy(response.ok);
      } catch {
        if (!cancelled) setApiHealthy(false);
      }
    };
    check();
    const interval = window.setInterval(check, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const openPromptLibrary = () => {
    setShowToolsModal(false);
    setShowPromptLibraryModal(true);
  };

  const insertToCompose = (text: string) => {
    const next = String(text || '');
    if (!next) return;
    setComposeText((prev) => {
      if (!prev) return next;
      const spacer = prev.endsWith('\n') ? '' : '\n';
      return `${prev}${spacer}${next}`;
    });
  };

  const isDangerousCommand = (command: string) => {
    const value = command.toLowerCase();
    return (
      value.includes('rm -rf') ||
      value.includes('mkfs') ||
      value.includes('dd if=') ||
      value.includes(':(){:|:&};:') ||
      value.includes('shutdown') ||
      value.includes('reboot')
    );
  };

  const runCommand = (command: string, label: string, promptId: number | null) => {
    if (!terminalRef.current) return;
    const trimmed = String(command || '').trim();
    if (!trimmed) {
      setNotice('Prompt command is empty');
      return;
    }

    const mode = promptConfirmMode;
    const needsConfirm = mode === 'always' || (mode === 'dangerous' && isDangerousCommand(trimmed));
    if (needsConfirm) {
      const ok = window.confirm(`Run prompt "${label}"?\n\n${trimmed}`);
      if (!ok) return;
    }

    const normalized = trimmed.replace(/\r?\n/g, '\r');
    terminalRef.current.send(`${normalized}\r`);
    focusTerminal();
    setNotice(`Sent: ${label}`);

    if (promptId !== null) {
      fetch('/api/activity/prompt', {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ prompt_id: promptId })
      })
        .then(() => fetchRecentActivity())
        .catch(() => {
          // ignore
        });
    }
  };

  const executePrompt = (prompt: Prompt) => {
    if (!terminalRef.current) return;
    runCommand(prompt.command, prompt.label, prompt.id);
  };

  const focusComposeDocked = focusComposePosition !== 'center';
  const composer = composeOpen ? (
    <div class={`composer is-open composer-opacity-${composeOpacity}`}>
      <div class="composer-header">
        <div class="composer-title">Compose</div>
        <div class="composer-actions">
          <button class="btn btn--ghost btn--small" type="button" onClick={() => setComposeText('')}>
            Clear
          </button>
          <button class="btn btn--ghost btn--small" type="button" onClick={pasteClipboard}>
            Paste
          </button>
        </div>
      </div>
      <textarea
        class="composer-input"
        rows={4}
        placeholder="Type here. Enter to send, Shift+Enter for newline."
        value={composeText}
        onInput={(event) => setComposeText((event.target as HTMLTextAreaElement).value)}
        onKeyDown={handleComposerKey}
      />
      <div class="composer-footer">
        <span class="composer-hint">Shift+Enter for newline</span>
        <div class="composer-dock" role="group" aria-label="Compose position">
          <button
            class={`btn btn--ghost btn--small ${focusComposePosition === 'left' ? 'is-active' : ''}`}
            type="button"
            aria-label="Dock compose left"
            title="Dock compose left"
            onClick={() => setFocusComposePosition('left')}
          >
            ←
          </button>
          <button
            class={`btn btn--ghost btn--small ${focusComposePosition === 'center' ? 'is-active' : ''}`}
            type="button"
            aria-label="Dock compose center"
            title="Dock compose center"
            onClick={() => setFocusComposePosition('center')}
          >
            ↔
          </button>
          <button
            class={`btn btn--ghost btn--small ${focusComposePosition === 'right' ? 'is-active' : ''}`}
            type="button"
            aria-label="Dock compose right"
            title="Dock compose right"
            onClick={() => setFocusComposePosition('right')}
          >
            →
          </button>
        </div>
        <button class="btn btn--solid composer-send" type="button" onClick={sendComposer}>
          Send
        </button>
      </div>
    </div>
  ) : null;

  const terminalAllowed = currentUser?.terminalAllowed ?? true;
  const terminalStatus = terminalAllowed ? connectionState : 'disabled';
  const terminalNode = currentUser ? (
    terminalAllowed ? (
      <Terminal
        id="terminal"
        ref={(node) => {
          terminalRef.current = node ?? null;
        }}
        key={`terminal-${currentUser.id}`}
        wsUrl={getWsUrl()}
        tokenUrl={`${window.location.origin}/token`}
        tmuxPrefix={prefix}
        clientOptions={clientOptions}
        termOptions={termOptions}
        flowControl={flowControl}
        onConnectionStateChange={setConnectionState}
        onCopySelection={() => setNotice('Selection copied')}
        onTitlePayload={handleTitlePayload}
      />
    ) : (
      <div id="terminal" class="terminal-loading terminal-blocked">
        <div class="terminal-blocked-message">Terminal access is disabled for your role.</div>
      </div>
    )
  ) : (
    <div id="terminal" class="terminal-loading" />
  );

  return (
    <div
      class={`app design-${theme.id} layout-future future-compose-${focusComposePosition} ${focusOverviewEnabled ? 'future-overview-on' : 'future-overview-off'}`}
    >
      <div class="main-grid">
        {focusComposePosition === 'left' && composer ? <aside class="compose-panel">{composer}</aside> : null}
        <section class="workspace">
          <div class="terminal-card">
            <div class="terminal-header">
              <div class="terminal-title">
                <div class="terminal-name">Workspace: {activeWorkspace?.name ?? '—'}</div>
                {tabOverviewEnabled ? (
                  <div class="terminal-hint">Tip: Drag tabs to reorder or open the overview grid to switch/close.</div>
                ) : null}
                <div class="terminal-meta">
                  tmux session: {activeTmuxSession ?? '—'} · terminal: {terminalStatus} · api:{' '}
                  {apiHealthy ? 'ok' : 'offline'}
                </div>
              </div>
              <div class="terminal-actions">
                <Dropdown
                  value={String(activeWorkspace?.id ?? '')}
                  onClick={(event) => event.stopPropagation()}
                  onChange={(value) => {
                    const id = parseInt(value, 10);
                    if (Number.isFinite(id)) switchWorkspace(id);
                  }}
                  options={workspaces.map((ws) => ({
                    value: String(ws.id),
                    label: `${ws.pinned ? '★ ' : ''}${ws.name}${ws.is_default ? ' (default)' : ''}`
                  }))}
                />
                <button
                  class="btn btn--ghost"
                  type="button"
                  onClick={() => {
                    setShowToolsModal(false);
                    setShowWorkspacesModal(true);
                  }}
                >
                  Workspaces
                </button>
                {tabOverviewEnabled ? (
                  <button class="btn btn--ghost" type="button" onClick={() => setTabOverviewOpen((prev) => !prev)}>
                    Manage
                  </button>
                ) : null}
                <button class="btn btn--ghost" type="button" onClick={copyTranscript}>
                  Copy
                </button>
                <button class="btn btn--ghost" type="button" onClick={() => setShowToolsModal(true)}>
                  Tools
                </button>
              </div>
            </div>
            <div class="tab-strip">
              {tabs.map((tab) => {
                const isEditing = editingTabId === tab.id;
                const label = tab.name ? tab.name : `Tab ${tab.index + 1}`;
                const draftKey = activeWorkspaceId !== null ? `${activeWorkspaceId}:${tab.id}` : null;
                const hasDraft = draftKey ? Boolean((composeDrafts[draftKey] ?? '').trim()) : false;
                return (
                  <div
                    key={tab.id}
                    class={`tab ${tab.active ? 'is-active' : ''} ${isEditing ? 'is-editing' : ''}`}
                    draggable={!isEditing}
                    onDragStart={(event) => {
                      const dt = event.dataTransfer;
                      if (!dt) return;
                      dragTabIdRef.current = tab.id;
                      dt.effectAllowed = 'move';
                      dt.setData('text/plain', tab.id);
                    }}
                    onDragOver={(event) => event.preventDefault()}
                    onDrop={(event) => {
                      event.preventDefault();
                      const dt = event.dataTransfer;
                      const sourceId = dragTabIdRef.current || (dt ? dt.getData('text/plain') : '');
                      dragTabIdRef.current = null;
                      if (!sourceId) return;
                      moveTab(sourceId, tab.id);
                    }}
                  >
                    {isEditing ? (
                      <input
                        class="tab-rename"
                        value={editingTabName}
                        onInput={(event) => setEditingTabName((event.target as HTMLInputElement).value)}
                        onKeyDown={(event) => {
                          if (event.key === 'Escape') {
                            event.preventDefault();
                            cancelRenameTab();
                            return;
                          }
                          if (event.key === 'Enter') {
                            event.preventDefault();
                            commitRenameTab(tab.id);
                          }
                        }}
                        onBlur={() => commitRenameTab(tab.id)}
                        onClick={(event) => event.stopPropagation()}
                        onMouseDown={(event) => event.stopPropagation()}
                        autoFocus
                      />
                    ) : (
                      <button
                        type="button"
                        class="tab-button"
                        onClick={() => selectTab(tab.id)}
                        onDblClick={() => beginRenameTab(tab)}
                        onContextMenu={(event) => {
                          event.preventDefault();
                          beginRenameTab(tab);
                        }}
                      >
                        {hasDraft ? <span class="tab-draft" title="Unsent draft" aria-hidden="true" /> : null}
                        <span class="tab-label">{label}</span>
                      </button>
                    )}
                    <button
                      type="button"
                      class="tab-close"
                      aria-label={`Close ${label}`}
                      onClick={() => requestCloseTab(tab)}
                    >
                      ×
                    </button>
                  </div>
                );
              })}
              <button type="button" class="tab-add" aria-label="New tab" onClick={createTab}>
                +
              </button>
            </div>
            <div class="terminal-split">
              <aside class="prompt-rail">
                <div class="prompt-rail-header">
                  <div class="prompt-rail-title">Quick prompts</div>
                </div>
                {visiblePrompts.length > 0 ? (
                  <div class="prompt-rail-list">
                    {visiblePrompts.map((prompt) => (
                      <button
                        key={prompt.id}
                        type="button"
                        class="prompt-rail-item"
                        onClick={() => executePrompt(prompt)}
                      >
                        {prompt.label}
                      </button>
                    ))}
                  </div>
                ) : (
                  <div class="prompt-rail-empty">No prompts.</div>
                )}
                <button class="btn btn--ghost btn--small prompt-rail-manage" type="button" onClick={openPromptLibrary}>
                  Manage
                </button>
              </aside>
              <div class="terminal-body">{terminalNode}</div>
            </div>
          </div>
          {!focusComposeDocked ? composer : null}
        </section>
        {focusComposePosition === 'right' && composer ? <aside class="compose-panel">{composer}</aside> : null}
      </div>

      {notice ? (
        <div class="toast" role="status">
          {notice}
        </div>
      ) : null}

      <Modal show={showToolsModal} onDismiss={() => setShowToolsModal(false)}>
        <div class="design-modal tools-modal">
          <div class="design-header">
            <div>
              <div class="design-title">Tools</div>
              <div class="design-subtitle">Clipboard, settings, and account actions.</div>
            </div>
            <div class="button-row">
              <button class="btn btn--ghost" type="button" onClick={refreshTmuxState}>
                Sync tabs
              </button>
              <button class="btn btn--ghost" type="button" onClick={() => setShowToolsModal(false)}>
                Close
              </button>
            </div>
          </div>

          <div class="tools-modal-tabs">
            <div class="button-row" style={{ flexWrap: 'wrap' }}>
              <button
                class={`btn btn--ghost btn--small ${toolsTab === 'settings' ? 'is-active' : ''}`}
                type="button"
                onClick={() => setToolsTab('settings')}
              >
                Settings
              </button>
              <button
                class={`btn btn--ghost btn--small ${toolsTab === 'activity' ? 'is-active' : ''}`}
                type="button"
                onClick={() => setToolsTab('activity')}
              >
                Activity
              </button>
              <button
                class={`btn btn--ghost btn--small ${toolsTab === 'account' ? 'is-active' : ''}`}
                type="button"
                onClick={() => setToolsTab('account')}
              >
                Account
              </button>
            </div>
          </div>

          <div class="tools-modal-content">
            {toolsTab === 'settings' ? (
              <>
                <div class="panel-section">
                  <div class="panel-title">Settings</div>
                  <label class="field field-toggle" style={{ padding: '5px 0' }}>
                    <span>Enable Overview</span>
                    <input
                      type="checkbox"
                      checked={focusOverviewEnabled}
                      onChange={(event) => setFocusOverviewEnabled((event.target as HTMLInputElement).checked)}
                    />
                  </label>
                  <label class="field field-toggle" style={{ padding: '5px 0' }}>
                    <span>Skip confirm when idle</span>
                    <input
                      type="checkbox"
                      checked={closeIdleSkipConfirm}
                      onChange={(event) => setCloseIdleSkipConfirm((event.target as HTMLInputElement).checked)}
                    />
                  </label>
                  <label class="field field-toggle" style={{ padding: '5px 0' }}>
                    <span>Compose</span>
                    <input
                      type="checkbox"
                      checked={composeOpen}
                      onChange={(event) => setComposeOpen((event.target as HTMLInputElement).checked)}
                    />
                  </label>
                  <label class="field">
                    <span>Compose opacity: {composeOpacity}%</span>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      step="5"
                      value={composeOpacity}
                      onChange={(event) => setComposeOpacity(parseInt((event.target as HTMLInputElement).value, 10))}
                    />
                  </label>
                  <label class="field">
                    <span>Theme</span>
                    <Dropdown
                      value={theme.id}
                      onChange={setThemeId}
                      options={THEMES.map((choice) => ({ value: choice.id, label: choice.name }))}
                    />
                  </label>
                  <label class="field">
                    <span>Prefix</span>
                    <Dropdown
                      value={prefix}
                      onChange={setPrefix}
                      options={PREFIX_CHOICES.map((choice) => ({ value: choice.value, label: choice.label }))}
                    />
                  </label>
                  <label class="field">
                    <span>Prompt confirm</span>
                    <Dropdown
                      value={promptConfirmMode}
                      onChange={setPromptConfirmMode}
                      options={[
                        { value: 'dangerous', label: 'Dangerous only' },
                        { value: 'always', label: 'Always' },
                        { value: 'never', label: 'Never' }
                      ]}
                    />
                  </label>
                </div>

                <div class="panel-section">
                  <div class="panel-title">Clipboard</div>
                  <div class="button-row">
                    <button class="btn btn--ghost" type="button" onClick={copyTranscript}>
                      Copy transcript
                    </button>
                    <button class="btn btn--ghost" type="button" onClick={pasteClipboard}>
                      Paste to terminal
                    </button>
                  </div>
                </div>
              </>
            ) : null}

            {toolsTab === 'activity' ? (
              <div class="panel-section">
                <div class="panel-title-row">
                  <div class="panel-title">Activity</div>
                  <button
                    class="btn btn--ghost btn--small"
                    type="button"
                    onClick={() => {
                      setActivityPage(0);
                      fetchRecentActivity();
                    }}
                  >
                    Refresh
                  </button>
                </div>
                <div class="terminal-hint">
                  API: {apiHealthy ? 'ok' : 'offline'} · Terminal: {connectionState}
                </div>
                {(() => {
                  const pageSize = 10;
                  const totalPages = Math.max(1, Math.ceil(recentActivity.length / pageSize));
                  const safePage = Math.max(0, Math.min(activityPage, totalPages - 1));
                  const start = safePage * pageSize;
                  const end = Math.min(recentActivity.length, start + pageSize);
                  const pageItems = recentActivity.slice(start, end);

                  if (recentActivity.length === 0) return <div class="prompt-empty">No recent activity.</div>;

                  return (
                    <>
                      <div class="button-row" style={{ alignItems: 'center', justifyContent: 'space-between' }}>
                        <button
                          class="btn btn--ghost btn--small"
                          type="button"
                          disabled={safePage === 0}
                          onClick={() => setActivityPage((p) => Math.max(0, p - 1))}
                        >
                          Prev
                        </button>
                        <div class="terminal-hint">
                          Showing {start + 1}–{end} of {recentActivity.length} · Page {safePage + 1} of {totalPages}
                        </div>
                        <button
                          class="btn btn--ghost btn--small"
                          type="button"
                          disabled={safePage >= totalPages - 1}
                          onClick={() => setActivityPage((p) => Math.min(totalPages - 1, p + 1))}
                        >
                          Next
                        </button>
                      </div>

                      <div class="tools-activity-table-wrap">
                        <table class="tools-activity-table">
                          <thead>
                            <tr>
                              <th>When</th>
                              <th>Action</th>
                              <th>Item</th>
                              <th aria-label="Actions" />
                            </tr>
                          </thead>
                          <tbody>
                            {pageItems.map((entry) => {
                              const details = entry.details as unknown as { prompt_id?: number } | null;
                              const promptId =
                                details && typeof details === 'object' ? (details.prompt_id ?? null) : null;
                              const prompt = promptId ? (prompts.find((p) => p.id === promptId) ?? null) : null;
                              const itemLabel = prompt ? prompt.label : promptId ? `Prompt #${promptId}` : '—';
                              return (
                                <tr key={entry.id}>
                                  <td class="tools-activity-time">
                                    {new Date(entry.created_at).toLocaleString(undefined, {
                                      dateStyle: 'short',
                                      timeStyle: 'short'
                                    })}
                                  </td>
                                  <td class="tools-activity-action">{entry.action}</td>
                                  <td class="tools-activity-item">
                                    <span class="tools-activity-item-text">{itemLabel}</span>
                                  </td>
                                  <td class="tools-activity-cta">
                                    {prompt ? (
                                      <button
                                        class="btn btn--ghost btn--small"
                                        type="button"
                                        onClick={() => executePrompt(prompt)}
                                      >
                                        Run
                                      </button>
                                    ) : null}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </>
                  );
                })()}

                {workspaces.length > 0 ? (
                  <>
                    <div class="panel-title-row" style={{ marginTop: '10px' }}>
                      <div class="panel-title">Recent workspaces</div>
                    </div>
                    <div class="prompt-list">
                      {[...workspaces]
                        .sort((a, b) => (b.last_used_at ?? '').localeCompare(a.last_used_at ?? ''))
                        .slice(0, 5)
                        .map((ws) => (
                          <button
                            key={ws.id}
                            class="btn btn--ghost btn--small"
                            type="button"
                            onClick={() => switchWorkspace(ws.id)}
                          >
                            {ws.name}
                          </button>
                        ))}
                    </div>
                  </>
                ) : null}
              </div>
            ) : null}

            {toolsTab === 'account' ? (
              <div class="panel-section">
                <div class="panel-title">Account</div>
                <div class="terminal-hint">
                  Signed in as {currentUser?.username ?? '—'} · role {currentUser?.role ?? '—'}
                </div>
                <div class="button-row">
                  <button class="btn btn--ghost" type="button" onClick={openPasswordModal}>
                    Change password
                  </button>
                  <button class="btn btn--ghost btn--danger" type="button" onClick={performLogout}>
                    Logout
                  </button>
                </div>
                {currentUser?.role === 'admin' ? (
                  <div class="button-row" style={{ marginTop: '10px' }}>
                    <button
                      class="btn btn--ghost"
                      type="button"
                      onClick={() => {
                        setShowToolsModal(false);
                        setShowAdminModal(true);
                      }}
                    >
                      Open admin console
                    </button>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </div>
      </Modal>

      <Modal show={tabOverviewEnabled && tabOverviewOpen} onDismiss={() => setTabOverviewOpen(false)}>
        <div class="design-modal overview-modal">
          <div class="design-header">
            <div>
              <div class="design-title">Tab Overview</div>
              <div class="design-subtitle">Switch, close, or drag to reorder tabs.</div>
            </div>
            <button class="btn btn--ghost" type="button" onClick={() => setTabOverviewOpen(false)}>
              Close
            </button>
          </div>
          <div class="overview-grid">
            {tabs.map((tab) => {
              const label = tab.name ? tab.name : `Tab ${tab.index + 1}`;
              return (
                <div
                  key={tab.id}
                  class={`overview-card ${tab.active ? 'is-active' : ''}`}
                  draggable
                  onDragStart={(event) => {
                    const dt = event.dataTransfer;
                    if (!dt) return;
                    dragTabIdRef.current = tab.id;
                    dt.effectAllowed = 'move';
                    dt.setData('text/plain', tab.id);
                  }}
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={(event) => {
                    event.preventDefault();
                    const dt = event.dataTransfer;
                    const sourceId = dragTabIdRef.current || (dt ? dt.getData('text/plain') : '');
                    dragTabIdRef.current = null;
                    if (!sourceId) return;
                    moveTab(sourceId, tab.id);
                  }}
                >
                  <button
                    type="button"
                    class="overview-card-main"
                    onClick={() => {
                      selectTab(tab.id);
                      setTabOverviewOpen(false);
                    }}
                  >
                    <div class="overview-card-title">{label}</div>
                    <div class="overview-card-meta">{activeWorkspace?.name ?? ''}</div>
                  </button>
                  <button
                    type="button"
                    class="overview-card-close"
                    aria-label={`Close ${label}`}
                    onClick={() => requestCloseTab(tab)}
                  >
                    ×
                  </button>
                </div>
              );
            })}
            <button
              type="button"
              class="overview-add"
              onClick={() => {
                createTab();
              }}
            >
              + New tab
            </button>
          </div>
        </div>
      </Modal>

      <Modal show={showWorkspacesModal} onDismiss={() => setShowWorkspacesModal(false)}>
        <div class="design-modal">
          <div class="design-header">
            <div>
              <div class="design-title">Manage Workspaces</div>
              <div class="design-subtitle">Reorder, pin, set default, rename, and delete workspaces.</div>
            </div>
            <button class="btn btn--ghost" type="button" onClick={() => setShowWorkspacesModal(false)}>
              Close
            </button>
          </div>

          <div class="workspaces-panel">
            <div class="button-row">
              <button class="btn btn--solid" type="button" onClick={createWorkspace}>
                + New workspace
              </button>
            </div>
            <div class="workspaces-list">
              {workspaces.map((ws) => (
                <div
                  key={ws.id}
                  class={`workspaces-row ${ws.id === activeWorkspaceId ? 'is-active' : ''}`}
                  draggable
                  onDragStart={(event) => {
                    const dt = event.dataTransfer;
                    if (!dt) return;
                    dragWorkspaceIdRef.current = ws.id;
                    dt.effectAllowed = 'move';
                    dt.setData('text/plain', String(ws.id));
                  }}
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={(event) => {
                    event.preventDefault();
                    const dt = event.dataTransfer;
                    const sourceIdRaw = dragWorkspaceIdRef.current ?? parseInt(dt ? dt.getData('text/plain') : '', 10);
                    dragWorkspaceIdRef.current = null;
                    if (!Number.isFinite(sourceIdRaw) || sourceIdRaw === ws.id) return;
                    const currentIds = workspaces.map((w) => w.id);
                    const nextIds = currentIds.filter((id) => id !== sourceIdRaw);
                    const targetIndex = nextIds.indexOf(ws.id);
                    nextIds.splice(Math.max(0, targetIndex), 0, sourceIdRaw);
                    reorderWorkspaces(nextIds);
                  }}
                >
                  <button class="btn btn--ghost btn--small" type="button" onClick={() => switchWorkspace(ws.id)}>
                    Open
                  </button>
                  <div class="workspaces-name">{ws.name}</div>
                  <div class="workspaces-meta">{ws.prompt_count} prompt(s)</div>
                  <button
                    class={`btn btn--ghost btn--small ${ws.pinned ? 'is-active' : ''}`}
                    type="button"
                    onClick={() => updateWorkspace(ws.id, { pinned: !ws.pinned })}
                  >
                    {ws.pinned ? '★' : '☆'}
                  </button>
                  <button
                    class={`btn btn--ghost btn--small ${ws.is_default ? 'is-active' : ''}`}
                    type="button"
                    onClick={() => updateWorkspace(ws.id, { is_default: true })}
                  >
                    Default
                  </button>
                  <button
                    class="btn btn--ghost btn--small"
                    type="button"
                    onClick={async () => {
                      const next = window.prompt('New workspace name (max 64 characters)', ws.name);
                      if (!next) return;
                      const name = next.trim().slice(0, 64);
                      if (!name || name === ws.name) return;
                      await updateWorkspace(ws.id, { name });
                    }}
                  >
                    Rename
                  </button>
                  <button
                    class="btn btn--ghost btn--small btn--danger"
                    type="button"
                    onClick={() => deleteWorkspace(ws)}
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Modal>

      <Modal show={showPasswordModal} onDismiss={() => setShowPasswordModal(false)}>
        <div class="design-modal">
          <div class="design-header">
            <div>
              <div class="design-title">Change Password</div>
              <div class="design-subtitle">Enter your current password and choose a new one.</div>
            </div>
            <button class="btn btn--ghost" type="button" onClick={() => setShowPasswordModal(false)}>
              Close
            </button>
          </div>
          <div class="password-form">
            {passwordError && <div class="password-error">{passwordError}</div>}
            <label class="field">
              <span>Current Password</span>
              <input
                type="password"
                value={passwordForm.current}
                onInput={(e) => setPasswordForm({ ...passwordForm, current: (e.target as HTMLInputElement).value })}
                autoComplete="current-password"
              />
            </label>
            <label class="field">
              <span>New Password</span>
              <input
                type="password"
                value={passwordForm.new}
                onInput={(e) => setPasswordForm({ ...passwordForm, new: (e.target as HTMLInputElement).value })}
                autoComplete="new-password"
              />
            </label>
            <label class="field">
              <span>Confirm New Password</span>
              <input
                type="password"
                value={passwordForm.confirm}
                onInput={(e) => setPasswordForm({ ...passwordForm, confirm: (e.target as HTMLInputElement).value })}
                autoComplete="new-password"
              />
            </label>
            <div class="button-row button-row--spaced">
              <button class="btn btn--ghost" type="button" onClick={() => setShowPasswordModal(false)}>
                Cancel
              </button>
              <button class="btn btn--solid" type="button" onClick={handleChangePassword} disabled={passwordLoading}>
                {passwordLoading ? 'Changing...' : 'Change Password'}
              </button>
            </div>
          </div>
        </div>
      </Modal>

      {showPromptLibraryModal ? (
        <Suspense
          fallback={
            <Modal
              show
              onDismiss={() => setShowPromptLibraryModal(false)}
              ariaLabel="Prompt Library loading"
              contentClassName="prompt-library-modal-content"
            >
              <div class="design-modal tools-modal">
                <div class="design-header">
                  <div>
                    <div class="design-title">Prompt Library</div>
                    <div class="design-subtitle">Loading…</div>
                  </div>
                  <button class="btn btn--ghost" type="button" onClick={() => setShowPromptLibraryModal(false)}>
                    Close
                  </button>
                </div>
                <div class="prompt-empty">Loading…</div>
              </div>
            </Modal>
          }
        >
          <PromptLibraryModal
            show={showPromptLibraryModal}
            onDismiss={() => setShowPromptLibraryModal(false)}
            currentUser={currentUser}
            prompts={prompts}
            workspaces={workspaces}
            tags={tags}
            folders={folders}
            filters={filters}
            activeWorkspaceId={activeWorkspaceId}
            activeWorkspaceName={activeWorkspace?.name ?? null}
            activeTabName={activeTab?.name ?? null}
            getTerminalSelection={() => terminalRef.current?.getSelection() ?? ''}
            getTerminalLastSelection={() => terminalRef.current?.getLastSelection() ?? ''}
            onRunCommand={(command, label) => runCommand(command, label, null)}
            onInsertToCompose={insertToCompose}
            notify={setNotice}
            refreshAll={refreshAll}
          />
        </Suspense>
      ) : null}

      {showAdminModal ? (
        <Suspense
          fallback={
            <Modal show onDismiss={() => setShowAdminModal(false)} ariaLabel="Admin loading">
              <div class="design-modal tools-modal">
                <div class="design-header">
                  <div>
                    <div class="design-title">Admin</div>
                    <div class="design-subtitle">Loading…</div>
                  </div>
                  <button class="btn btn--ghost" type="button" onClick={() => setShowAdminModal(false)}>
                    Close
                  </button>
                </div>
                <div class="prompt-empty">Loading…</div>
              </div>
            </Modal>
          }
        >
          <AdminModal
            show={showAdminModal}
            onDismiss={() => setShowAdminModal(false)}
            currentUser={currentUser}
            notify={setNotice}
          />
        </Suspense>
      ) : null}
    </div>
  );
}
