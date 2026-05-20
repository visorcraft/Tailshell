import type { JSX } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';

import type {
  CurrentUser,
  Prompt,
  PromptAccess,
  PromptFilter,
  PromptFolder,
  PromptSharePermission,
  PromptStatus,
  PromptVisibility,
  Tag,
  Workspace
} from '../../types';
import { Modal } from '../modal/Modal';
import { Dropdown } from '../dropdown/Dropdown';
import { VirtualList } from '../virtual/VirtualList';
import { withCsrfHeaders } from '../../utils/csrf';

type PromptVersion = {
  id: number;
  version_num: number;
  created_at: string;
  created_by_username: string;
  label: string;
  command: string;
  description: string | null;
  status: PromptStatus;
  visibility: PromptVisibility;
  metadata: Record<string, unknown> | null;
};

type PromptShare = {
  user_id: number;
  username: string;
  permission: PromptSharePermission;
  created_at: string;
  updated_at: string;
};

type PromptQuery = {
  q: string;
  workspace_id: number | 'all' | 'any';
  folder_id: number | 'all' | 'none';
  tag_ids: number[];
  favorite_only: boolean;
  status: PromptStatus | 'all';
  visibility: PromptVisibility | 'all';
  access: PromptAccess | 'all';
  sort: 'label' | 'sort_order' | 'owner' | 'status';
};

type Props = {
  show: boolean;
  onDismiss: () => void;
  currentUser: CurrentUser | null;
  prompts: Prompt[];
  workspaces: Workspace[];
  tags: Tag[];
  folders: PromptFolder[];
  filters: PromptFilter[];
  activeWorkspaceId: number | null;
  activeWorkspaceName: string | null;
  activeTabName: string | null;
  getTerminalSelection: () => string;
  getTerminalLastSelection: () => string;
  onRunCommand: (command: string, label: string) => void;
  onInsertToCompose: (text: string) => void;
  notify: (message: string) => void;
  refreshAll: () => Promise<void>;
};

function normalizeName(value: string, maxLen: number) {
  return String(value || '')
    .trim()
    .replace(/\s+/g, ' ')
    .slice(0, maxLen);
}

function extractPlaceholders(command: string) {
  const out = new Set<string>();
  const re = /{{\s*([a-zA-Z0-9_:-]+)\s*}}/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(command)) !== null) {
    const key = match[1]?.trim();
    if (key) out.add(key);
  }
  return Array.from(out.values()).sort((a, b) => a.localeCompare(b));
}

function getMetadataVariables(metadata: Record<string, unknown> | null) {
  const vars = (
    metadata && typeof metadata === 'object' ? (metadata as Record<string, unknown>).variables : null
  ) as unknown;
  if (!vars || typeof vars !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(vars as Record<string, unknown>)) {
    if (!key) continue;
    out[key] = value === null || value === undefined ? '' : String(value);
  }
  return out;
}

function setMetadataVariables(metadata: Record<string, unknown> | null, variables: Record<string, string>) {
  const next = { ...(metadata ?? {}) } as Record<string, unknown>;
  next.variables = { ...variables };
  return next;
}

function substitutePlaceholders(command: string, variables: Record<string, string>) {
  return command.replace(/{{\s*([a-zA-Z0-9_:-]+)\s*}}/g, (_m, keyRaw) => {
    const key = String(keyRaw || '').trim();
    return Object.prototype.hasOwnProperty.call(variables, key) ? variables[key] : `{{${key}}}`;
  });
}

function isOwned(prompt: Prompt) {
  return prompt.access === 'owned';
}

function canCopy(prompt: Prompt) {
  if (prompt.access === 'public') return true;
  if (prompt.access === 'shared') return prompt.share_permission === 'copy';
  return false;
}

export function PromptLibraryModal({
  show,
  onDismiss,
  currentUser: _currentUser,
  prompts,
  workspaces,
  tags,
  folders,
  filters: _filters,
  activeWorkspaceId,
  activeWorkspaceName,
  activeTabName,
  getTerminalSelection,
  getTerminalLastSelection,
  onRunCommand,
  onInsertToCompose,
  notify,
  refreshAll
}: Props) {
  const LIST_ROW_HEIGHT = 96;
  const LIST_ROW_GAP = 14;

  const [view, setView] = useState<'list' | 'edit'>('list');
  const [listTab, setListTab] = useState<'prompts' | 'folders' | 'tags' | 'backups'>('prompts');
  const [editingId, setEditingId] = useState<number | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(() => new Set());

  const [query, setQuery] = useState<PromptQuery>({
    q: '',
    workspace_id: activeWorkspaceId ?? 'all',
    folder_id: 'all',
    tag_ids: [],
    favorite_only: false,
    status: 'all',
    visibility: 'all',
    access: 'all',
    sort: 'label'
  });

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [debouncedSearch, setDebouncedSearch] = useState(query.q);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(query.q), 180);
    return () => window.clearTimeout(timer);
  }, [query.q]);

  const filtered = useMemo(() => {
    const q = debouncedSearch.trim().toLowerCase();
    const tagIdSet = new Set(query.tag_ids);
    const out = prompts.filter((p) => {
      if (query.access !== 'all' && p.access !== query.access) return false;
      if (query.status !== 'all' && p.status !== query.status) return false;
      if (query.visibility !== 'all' && p.visibility !== query.visibility) return false;
      if (query.favorite_only && !p.is_favorite) return false;
      if (query.folder_id !== 'all') {
        if (query.folder_id === 'none') {
          if (p.folder_id !== null) return false;
        } else if (p.folder_id !== query.folder_id) {
          return false;
        }
      }
      if (query.workspace_id !== 'all') {
        if (query.workspace_id === 'any') {
          if (!p.is_global) return false;
        } else {
          const wsId = query.workspace_id;
          if (!p.is_global && !(p.workspace_ids ?? []).includes(wsId)) return false;
        }
      }
      if (tagIdSet.size > 0) {
        const promptTagIds = new Set((p.tags ?? []).map((t) => t.id));
        for (const id of tagIdSet) {
          if (!promptTagIds.has(id)) return false;
        }
      }
      if (q) {
        const hay =
          `${p.label} ${p.description ?? ''} ${p.command} ${(p.tags ?? []).map((t) => t.name).join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const by = query.sort;
    out.sort((a, b) => {
      if (by === 'sort_order') return (a.sort_order ?? 0) - (b.sort_order ?? 0);
      if (by === 'owner') return a.owner_username.localeCompare(b.owner_username, undefined, { sensitivity: 'base' });
      if (by === 'status') return a.status.localeCompare(b.status);
      return a.label.localeCompare(b.label, undefined, { sensitivity: 'base' });
    });
    return out;
  }, [
    debouncedSearch,
    prompts,
    query.access,
    query.favorite_only,
    query.folder_id,
    query.workspace_id,
    query.sort,
    query.status,
    query.tag_ids,
    query.visibility
  ]);

  const editingPrompt = useMemo(
    () => (editingId === null ? null : (prompts.find((p) => p.id === editingId) ?? null)),
    [editingId, prompts]
  );

  const [editor, setEditor] = useState<{
    name: string;
    label: string;
    description: string;
    command: string;
    is_global: boolean;
    workspace_ids: number[];
    folder_id: number | null;
    is_favorite: boolean;
    status: PromptStatus;
    visibility: PromptVisibility;
    tags: string;
    variables: Record<string, string>;
  }>({
    name: '',
    label: '',
    description: '',
    command: '',
    is_global: true,
    workspace_ids: [],
    folder_id: null,
    is_favorite: false,
    status: 'published',
    visibility: 'private',
    tags: '',
    variables: {}
  });

  const [editorError, setEditorError] = useState('');
  const [editorBusy, setEditorBusy] = useState(false);

  const [versions, setVersions] = useState<PromptVersion[]>([]);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [selectedVersion, setSelectedVersion] = useState<PromptVersion | null>(null);

  const [shares, setShares] = useState<PromptShare[]>([]);
  const [sharesLoading, setSharesLoading] = useState(false);
  const [shareForm, setShareForm] = useState<{ username: string; permission: PromptSharePermission }>({
    username: '',
    permission: 'view'
  });

  useEffect(() => {
    if (!show) return;
    setView('list');
    setListTab('prompts');
    setEditingId(null);
    setSelectedIds(new Set());
    setSelectedVersion(null);
    setVersions([]);
    setShares([]);
    setEditorError('');
    setQuery((prev) => ({ ...prev }));
  }, [show]);

  const startCreate = () => {
    const scopedDefault = activeWorkspaceId ? [activeWorkspaceId] : [];
    setEditor({
      name: '',
      label: '',
      description: '',
      command: '',
      is_global: scopedDefault.length === 0,
      workspace_ids: scopedDefault,
      folder_id: null,
      is_favorite: false,
      status: 'published',
      visibility: 'private',
      tags: '',
      variables: {}
    });
    setEditingId(null);
    setSelectedVersion(null);
    setVersions([]);
    setShares([]);
    setEditorError('');
    setView('edit');
  };

  const startEdit = async (prompt: Prompt) => {
    if (!isOwned(prompt)) return;
    setEditor({
      name: prompt.name ?? '',
      label: prompt.label ?? '',
      description: (prompt.description ?? '') as string,
      command: prompt.command ?? '',
      is_global: Boolean(prompt.is_global),
      workspace_ids: prompt.workspace_ids ?? [],
      folder_id: prompt.folder_id ?? null,
      is_favorite: Boolean(prompt.is_favorite),
      status: prompt.status ?? 'published',
      visibility: prompt.visibility ?? 'private',
      tags: (prompt.tags ?? []).map((t) => t.name).join(', '),
      variables: getMetadataVariables(prompt.metadata ?? null)
    });
    setEditingId(prompt.id);
    setSelectedVersion(null);
    setEditorError('');
    setView('edit');
    await Promise.all([loadVersions(prompt.id), loadShares(prompt.id)]);
  };

  const loadVersions = async (promptId: number) => {
    setVersionsLoading(true);
    try {
      const resp = await fetch(`/api/prompts/${promptId}/versions`);
      if (!resp.ok) return;
      const data = (await resp.json()) as PromptVersion[];
      setVersions(data);
    } finally {
      setVersionsLoading(false);
    }
  };

  const loadShares = async (promptId: number) => {
    setSharesLoading(true);
    try {
      const resp = await fetch(`/api/prompts/${promptId}/shares`);
      if (!resp.ok) return;
      const data = (await resp.json()) as PromptShare[];
      setShares(data);
    } finally {
      setSharesLoading(false);
    }
  };

  const previewCommand = useMemo(() => {
    const runtime: Record<string, string> = {
      clipboard: '{{clipboard}}',
      selection: getTerminalSelection() || getTerminalLastSelection() || '{{selection}}',
      workspace: activeWorkspaceName ?? '{{workspace}}',
      tab: activeTabName ?? '{{tab}}'
    };
    const merged = { ...runtime, ...editor.variables };
    return substitutePlaceholders(editor.command, merged);
  }, [editor.command, editor.variables, activeWorkspaceName, activeTabName]);

  const placeholders = useMemo(() => extractPlaceholders(editor.command), [editor.command]);

  const ensureEditorVariables = () => {
    if (placeholders.length === 0) return;
    setEditor((prev) => {
      const next = { ...prev, variables: { ...prev.variables } };
      for (const key of placeholders) {
        if (Object.prototype.hasOwnProperty.call(next.variables, key)) continue;
        next.variables[key] = '';
      }
      return next;
    });
  };

  useEffect(() => {
    if (view !== 'edit') return;
    ensureEditorVariables();
  }, [view, placeholders.join('|')]);

  const saveEditor = async () => {
    setEditorError('');
    const label = normalizeName(editor.label, 100);
    const name = normalizeName(editor.name || label.toLowerCase().replace(/\s+/g, '-'), 50);
    const command = editor.command.trim();
    if (!label || !name || !command) {
      setEditorError('Label and command are required');
      return;
    }
    if (!editor.is_global && (editor.workspace_ids ?? []).length === 0) {
      setEditorError('Select at least one workspace or choose Any workspace');
      return;
    }

    const metadata = setMetadataVariables(null, editor.variables);
    const tags = editor.tags
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    const payload = {
      name,
      label,
      command,
      description: editor.description.trim() ? editor.description.trim() : null,
      is_favorite: editor.is_favorite,
      folder_id: editor.folder_id,
      status: editor.status,
      visibility: editor.status === 'published' ? editor.visibility : 'private',
      metadata,
      tags,
      workspace_ids: editor.is_global ? [] : editor.workspace_ids
    };

    setEditorBusy(true);
    try {
      const isEditing = editingId !== null;
      const url = isEditing ? `/api/prompts/${editingId}` : '/api/prompts';
      const method = isEditing ? 'PUT' : 'POST';
      const resp = await fetch(url, {
        method,
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        setEditorError(data.error || 'Failed to save prompt');
        return;
      }
      await refreshAll();
      notify(isEditing ? 'Prompt updated' : 'Prompt created');
      setView('list');
      setEditingId(null);
    } finally {
      setEditorBusy(false);
    }
  };

  const deletePrompt = async (promptId: number) => {
    const ok = window.confirm('Delete this prompt?');
    if (!ok) return;
    const resp = await fetch(`/api/prompts/${promptId}`, { method: 'DELETE', headers: withCsrfHeaders() });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      notify(data.error || 'Failed to delete prompt');
      return;
    }
    await refreshAll();
    notify('Prompt deleted');
  };

  const runPreview = () => {
    const label = editor.label.trim() || 'Prompt';
    onRunCommand(previewCommand, label);
  };

  const insertPreview = () => {
    onInsertToCompose(previewCommand);
    notify('Inserted into compose');
  };

  const rollbackTo = async (promptId: number, versionNum: number) => {
    const ok = window.confirm(`Rollback to version ${versionNum}?`);
    if (!ok) return;
    const resp = await fetch(`/api/prompts/${promptId}/rollback`, {
      method: 'POST',
      headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ version_num: versionNum })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      notify(data.error || 'Rollback failed');
      return;
    }
    await refreshAll();
    await loadVersions(promptId);
    notify('Rolled back');
  };

  const addShare = async () => {
    if (editingId === null) return;
    const username = normalizeName(shareForm.username, 50);
    if (!username) return;
    const resp = await fetch(`/api/prompts/${editingId}/shares`, {
      method: 'POST',
      headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ username, permission: shareForm.permission })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      notify(data.error || 'Failed to add share');
      return;
    }
    setShareForm({ username: '', permission: 'view' });
    await loadShares(editingId);
    await refreshAll();
    notify('Share updated');
  };

  const removeShare = async (promptId: number, userId: number) => {
    const resp = await fetch(`/api/prompts/${promptId}/shares/${userId}`, {
      method: 'DELETE',
      headers: withCsrfHeaders()
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      notify(data.error || 'Failed to remove share');
      return;
    }
    await loadShares(promptId);
    await refreshAll();
    notify('Share removed');
  };

  const copyPrompt = async (promptId: number) => {
    const resp = await fetch(`/api/prompts/${promptId}/copy`, { method: 'POST', headers: withCsrfHeaders() });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      notify(data.error || 'Copy failed');
      return;
    }
    await refreshAll();
    notify('Copied to your prompts');
  };

  const exportPrompts = (format: 'json' | 'yaml') => {
    window.open(`/api/prompts/export?format=${format}`, '_blank', 'noopener,noreferrer');
  };

  const triggerImport = () => fileInputRef.current?.click();

  const handleImportFile = async (event: JSX.TargetedEvent<HTMLInputElement>) => {
    const file = (event.currentTarget.files ?? [])[0];
    if (!file) return;
    event.currentTarget.value = '';
    const text = await file.text();
    const format =
      file.name.toLowerCase().endsWith('.yml') || file.name.toLowerCase().endsWith('.yaml') ? 'yaml' : 'json';
    const resp = await fetch('/api/prompts/import', {
      method: 'POST',
      headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ format, data: text })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      notify(data.error || 'Import failed');
      return;
    }
    await refreshAll();
    notify(`Imported ${data.created ?? 0} prompt(s)`);
  };

  const toggleSelected = (promptId: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(promptId)) next.delete(promptId);
      else next.add(promptId);
      return next;
    });
  };

  const clearSelection = () => setSelectedIds(new Set());

  const [bulkAction, setBulkAction] = useState('');
  const [bulkInput, setBulkInput] = useState('');
  const [bulkBusy, setBulkBusy] = useState(false);

  const applyBulk = async () => {
    if (selectedIds.size === 0) return;
    const ids = Array.from(selectedIds.values());
    if (!bulkAction) return;

    const payload: Record<string, unknown> = { action: bulkAction, prompt_ids: ids };
    if (bulkAction === 'set_folder') {
      if (bulkInput.trim().toLowerCase() === 'none') payload.folder_id = null;
      else payload.folder_id = parseInt(bulkInput, 10);
    }
    if (bulkAction === 'set_favorite') {
      payload.is_favorite =
        bulkInput.trim().toLowerCase() === 'true' || bulkInput.trim() === '1' || bulkInput.trim() === 'yes';
    }
    if (bulkAction === 'set_status') {
      payload.status = bulkInput.trim().toLowerCase();
    }
    if (bulkAction === 'set_visibility') {
      payload.visibility = bulkInput.trim().toLowerCase();
    }
    if (bulkAction === 'add_tags') {
      payload.tags = bulkInput
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
    }
    if (bulkAction === 'remove_tags') {
      payload.tag_ids = bulkInput
        .split(',')
        .map((t) => parseInt(t.trim(), 10))
        .filter(Number.isFinite);
    }

    if (bulkAction === 'delete') {
      const ok = window.confirm(`Delete ${ids.length} prompt(s)?`);
      if (!ok) return;
    }

    setBulkBusy(true);
    try {
      const resp = await fetch('/api/prompts/bulk', {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'Bulk action failed');
        return;
      }
      await refreshAll();
      notify('Bulk action applied');
      clearSelection();
    } finally {
      setBulkBusy(false);
    }
  };

  const newFolder = async () => {
    const name = window.prompt('Folder name');
    if (!name) return;
    const resp = await fetch('/api/prompt-folders', {
      method: 'POST',
      headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ name })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      notify(data.error || 'Failed to create folder');
      return;
    }
    await refreshAll();
    notify('Folder created');
  };

  const newTag = async () => {
    const name = window.prompt('Tag name');
    if (!name) return;
    const resp = await fetch('/api/tags', {
      method: 'POST',
      headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ name })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      notify(data.error || 'Failed to create tag');
      return;
    }
    await refreshAll();
    notify('Tag created');
  };

  const listTabLabels = {
    prompts: 'Prompts',
    folders: 'Folders',
    tags: 'Tags',
    backups: 'Backups'
  } as const;

  const listView = (
    <div class="design-modal tools-modal prompt-library-modal">
      <div class="design-header prompt-library-header">
        <div>
          <div class="design-title" id="prompt-library-title">
            Prompt Library
          </div>
          <div class="design-subtitle">Search, tag, version, share, and bulk-manage prompts.</div>
        </div>
        <div class="button-row prompt-library-actions">
          <button class="btn btn--solid" type="button" onClick={startCreate}>
            New prompt
          </button>
          <button class="btn btn--ghost" type="button" onClick={onDismiss}>
            Close
          </button>
        </div>
      </div>

      <input
        ref={fileInputRef}
        type="file"
        accept=".json,.yml,.yaml"
        style={{ display: 'none' }}
        onChange={handleImportFile}
      />

      <div class="prompt-library-tabs">
        <div class="button-row" style={{ flexWrap: 'wrap' }}>
          {(Object.keys(listTabLabels) as Array<keyof typeof listTabLabels>).map((entry) => (
            <button
              key={entry}
              class={`btn btn--ghost btn--small ${listTab === entry ? 'is-active' : ''}`}
              type="button"
              onClick={() => setListTab(entry)}
            >
              {listTabLabels[entry]}
            </button>
          ))}
        </div>
      </div>

      <div class="prompt-library-tab-content">
        {listTab === 'prompts' ? (
          <>
            <div class="prompt-library-toolbar">
              <label class="prompt-library-search">
                <span>Search prompts</span>
                <input
                  value={query.q}
                  onInput={(e) => setQuery((p) => ({ ...p, q: (e.target as HTMLInputElement).value }))}
                  placeholder="Search prompts, tags, or commands"
                />
              </label>
              <div class="prompt-library-toolbar-meta">
                <div class="terminal-hint">
                  {filtered.length} shown · {prompts.length} total
                </div>
              </div>
            </div>

            <div class="panel-section prompt-library-filters" style={{ minWidth: 0 }}>
              <div class="panel-title-row">
                <div class="panel-title">Filters</div>
              </div>
              <div class="tools-grid prompt-library-filters-grid">
                <label class="field">
                  <span>Workspace</span>
                  <Dropdown
                    value={
                      query.workspace_id === 'all' || query.workspace_id === 'any'
                        ? query.workspace_id
                        : String(query.workspace_id)
                    }
                    onChange={(value) =>
                      setQuery((p) => ({
                        ...p,
                        workspace_id:
                          value === 'all'
                            ? 'all'
                            : value === 'any'
                              ? 'any'
                              : Number.isFinite(parseInt(value, 10))
                                ? parseInt(value, 10)
                                : 'all'
                      }))
                    }
                    options={[
                      { value: 'all', label: 'All workspaces' },
                      { value: 'any', label: 'Any workspace (global)' },
                      ...workspaces.map((ws) => ({ value: String(ws.id), label: ws.name }))
                    ]}
                  />
                </label>

                <label class="field">
                  <span>Folder</span>
                  <Dropdown
                    value={
                      query.folder_id === 'all' ? 'all' : query.folder_id === 'none' ? 'none' : String(query.folder_id)
                    }
                    onChange={(value) =>
                      setQuery((p) => ({
                        ...p,
                        folder_id:
                          value === 'all'
                            ? 'all'
                            : value === 'none'
                              ? 'none'
                              : Number.isFinite(parseInt(value, 10))
                                ? parseInt(value, 10)
                                : 'all'
                      }))
                    }
                    options={[
                      { value: 'all', label: 'All folders' },
                      { value: 'none', label: 'No folder' },
                      ...folders.map((f) => ({ value: String(f.id), label: f.name }))
                    ]}
                  />
                </label>

                <label class="field field-toggle">
                  <span>Favorites only</span>
                  <input
                    type="checkbox"
                    checked={query.favorite_only}
                    onChange={(e) => setQuery((p) => ({ ...p, favorite_only: (e.target as HTMLInputElement).checked }))}
                  />
                </label>

                <label class="field">
                  <span>Status</span>
                  <Dropdown
                    value={query.status}
                    onChange={(value) => setQuery((p) => ({ ...p, status: value as PromptQuery['status'] }))}
                    options={[
                      { value: 'all', label: 'All' },
                      { value: 'published', label: 'Published' },
                      { value: 'draft', label: 'Draft' }
                    ]}
                  />
                </label>

                <label class="field">
                  <span>Access</span>
                  <Dropdown
                    value={query.access}
                    onChange={(value) => setQuery((p) => ({ ...p, access: value as PromptQuery['access'] }))}
                    options={[
                      { value: 'all', label: 'All' },
                      { value: 'owned', label: 'Owned' },
                      { value: 'shared', label: 'Shared' },
                      { value: 'public', label: 'Public' }
                    ]}
                  />
                </label>

                <label class="field">
                  <span>Visibility</span>
                  <Dropdown
                    value={query.visibility}
                    onChange={(value) => setQuery((p) => ({ ...p, visibility: value as PromptQuery['visibility'] }))}
                    options={[
                      { value: 'all', label: 'All' },
                      { value: 'private', label: 'Private' },
                      { value: 'shared', label: 'Shared' },
                      { value: 'public', label: 'Public' }
                    ]}
                  />
                </label>

                <label class="field">
                  <span>Sort</span>
                  <Dropdown
                    value={query.sort}
                    onChange={(value) => setQuery((p) => ({ ...p, sort: value as PromptQuery['sort'] }))}
                    options={[
                      { value: 'label', label: 'Label' },
                      { value: 'sort_order', label: 'Sort order' },
                      { value: 'owner', label: 'Owner' },
                      { value: 'status', label: 'Status' }
                    ]}
                  />
                </label>
              </div>
            </div>

            <div class="panel-section prompt-library-panel" style={{ minWidth: 0, flex: '1 1 auto' }}>
              <div class="panel-title-row">
                <div class="panel-title">Prompts</div>
              </div>

              {selectedIds.size > 0 ? (
                <div class="button-row" style={{ flexWrap: 'wrap' }}>
                  <Dropdown
                    value={bulkAction}
                    onChange={setBulkAction}
                    options={[
                      { value: '', label: 'Bulk action…' },
                      { value: 'set_folder', label: 'Set folder (input id or "none")' },
                      { value: 'set_favorite', label: 'Set favorite (input true/false)' },
                      { value: 'set_status', label: 'Set status (draft/published)' },
                      { value: 'set_visibility', label: 'Set visibility (private/shared/public)' },
                      { value: 'add_tags', label: 'Add tags (input comma names)' },
                      { value: 'remove_tags', label: 'Remove tags (input comma tag ids)' },
                      { value: 'delete', label: 'Delete' }
                    ]}
                  />
                  <input
                    placeholder="Bulk input"
                    value={bulkInput}
                    onInput={(e) => setBulkInput((e.target as HTMLInputElement).value)}
                  />
                  <button class="btn btn--solid" type="button" disabled={bulkBusy} onClick={applyBulk}>
                    {bulkBusy ? 'Applying…' : `Apply (${selectedIds.size})`}
                  </button>
                  <button class="btn btn--ghost" type="button" onClick={clearSelection}>
                    Clear
                  </button>
                </div>
              ) : null}

              <div class="prompt-library-list">
                {filtered.length === 0 ? (
                  <div class="prompts-empty">No prompts match your filters.</div>
                ) : (
                  <VirtualList
                    class="prompts-virtual-list"
                    items={filtered}
                    itemHeight={LIST_ROW_HEIGHT}
                    itemGap={LIST_ROW_GAP}
                    overscan={8}
                    style={{ paddingRight: '8px' }}
                    getKey={(p) => p.id}
                    renderItem={(p) => {
                      const owned = isOwned(p);
                      const selected = selectedIds.has(p.id);
                      const tagText = (p.tags ?? []).map((t) => t.name).join(', ');
                      return (
                        <div class="prompts-list-item list-item--fixed" style={{ height: '100%' }}>
                          <div class="prompts-item-info" style={{ minWidth: 0 }}>
                            <div class="prompts-item-name">
                              {owned ? (
                                <input
                                  type="checkbox"
                                  checked={selected}
                                  onChange={() => toggleSelected(p.id)}
                                  style={{ marginRight: '8px' }}
                                  aria-label={`Select ${p.label}`}
                                />
                              ) : (
                                <span style={{ display: 'inline-block', width: '24px' }} aria-hidden="true" />
                              )}
                              {p.label}
                              <span class="terminal-meta" style={{ marginLeft: '10px' }}>
                                {p.status} · {p.visibility} · {p.access}
                                {p.access !== 'owned' ? ` · by ${p.owner_username}` : ''}
                              </span>
                            </div>
                            <div class="prompts-item-command">{p.command}</div>
                            {tagText ? <div class="prompts-item-scope">Tags: {tagText}</div> : null}
                          </div>
                          <div class="prompts-item-actions">
                            <button
                              class="btn btn--ghost btn--small"
                              type="button"
                              onClick={() => onRunCommand(p.command, p.label)}
                            >
                              Run
                            </button>
                            {owned ? (
                              <button class="btn btn--ghost btn--small" type="button" onClick={() => startEdit(p)}>
                                Edit
                              </button>
                            ) : (
                              <button
                                class="btn btn--ghost btn--small"
                                type="button"
                                disabled={!canCopy(p)}
                                onClick={() => copyPrompt(p.id)}
                              >
                                Copy
                              </button>
                            )}
                            {owned ? (
                              <button
                                class="btn btn--ghost btn--small btn--danger"
                                type="button"
                                onClick={() => deletePrompt(p.id)}
                              >
                                Delete
                              </button>
                            ) : null}
                          </div>
                        </div>
                      );
                    }}
                  />
                )}
              </div>
            </div>
          </>
        ) : null}

        {listTab === 'folders' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">Folders</div>
              <button class="btn btn--ghost btn--small" type="button" onClick={newFolder}>
                +
              </button>
            </div>
            {folders.length === 0 ? (
              <div class="prompt-empty">No folders.</div>
            ) : (
              <div class="prompt-list">
                {folders.map((f) => (
                  <div key={f.id} class="prompt-chip">
                    {f.name}
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : null}

        {listTab === 'tags' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">Tags</div>
              <div class="button-row" style={{ justifyContent: 'flex-end' }}>
                {query.tag_ids.length > 0 ? (
                  <button
                    class="btn btn--ghost btn--small"
                    type="button"
                    onClick={() => setQuery((p) => ({ ...p, tag_ids: [] }))}
                  >
                    Clear
                  </button>
                ) : null}
                <button class="btn btn--ghost btn--small" type="button" onClick={newTag}>
                  +
                </button>
              </div>
            </div>
            {tags.length === 0 ? (
              <div class="prompt-empty">No tags.</div>
            ) : (
              <div class="prompt-list">
                {tags.map((t) => {
                  const selected = query.tag_ids.includes(t.id);
                  return (
                    <button
                      key={t.id}
                      class={`btn btn--ghost btn--small ${selected ? 'is-active' : ''}`}
                      type="button"
                      onClick={() =>
                        setQuery((p) => ({
                          ...p,
                          tag_ids: selected ? p.tag_ids.filter((id) => id !== t.id) : [...p.tag_ids, t.id]
                        }))
                      }
                    >
                      {t.name}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        ) : null}

        {listTab === 'backups' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">Backups</div>
            </div>
            <div class="button-row" style={{ flexWrap: 'wrap' }}>
              <button class="btn btn--ghost" type="button" onClick={() => exportPrompts('json')}>
                Export JSON
              </button>
              <button class="btn btn--ghost" type="button" onClick={() => exportPrompts('yaml')}>
                Export YAML
              </button>
              <button class="btn btn--ghost" type="button" onClick={triggerImport}>
                Import
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );

  const editView = (
    <div class="design-modal tools-modal prompt-library-modal">
      <div class="design-header prompt-library-header">
        <div>
          <div class="design-title" id="prompt-library-title">
            Edit Prompt
          </div>
          <div class="design-subtitle">
            {editingPrompt ? `Editing "${editingPrompt.label}"` : 'Create a new prompt.'}
          </div>
        </div>
        <div class="button-row prompt-library-actions">
          <button class="btn btn--ghost" type="button" onClick={() => setView('list')}>
            Back
          </button>
          <button class="btn btn--solid" type="button" disabled={editorBusy} onClick={saveEditor}>
            {editorBusy ? 'Saving…' : 'Save'}
          </button>
          <button class="btn btn--ghost" type="button" onClick={onDismiss}>
            Close
          </button>
        </div>
      </div>

      {editorError ? <div class="password-error">{editorError}</div> : null}

      <div class="tools-grid">
        <div class="panel-section">
          <div class="panel-title-row">
            <div class="panel-title">Definition</div>
          </div>
          <label class="field">
            <span>Label</span>
            <input
              value={editor.label}
              onInput={(e) => setEditor((p) => ({ ...p, label: (e.target as HTMLInputElement).value }))}
            />
          </label>
          <label class="field">
            <span>Name (slug)</span>
            <input
              value={editor.name}
              onInput={(e) => setEditor((p) => ({ ...p, name: (e.target as HTMLInputElement).value }))}
              placeholder="auto from label"
            />
          </label>
          <label class="field">
            <span>Description</span>
            <textarea
              rows={3}
              value={editor.description}
              onInput={(e) => setEditor((p) => ({ ...p, description: (e.target as HTMLTextAreaElement).value }))}
            />
          </label>
          <label class="field">
            <span>Command</span>
            <textarea
              class="prompts-command-input"
              rows={5}
              value={editor.command}
              onInput={(e) => setEditor((p) => ({ ...p, command: (e.target as HTMLTextAreaElement).value }))}
            />
          </label>

          <div class="button-row" style={{ flexWrap: 'wrap' }}>
            <button
              class="btn btn--ghost btn--small"
              type="button"
              onClick={() =>
                setEditor((p) => ({
                  ...p,
                  command: `${p.command}${p.command.endsWith(' ') || !p.command ? '' : ' '}{{clipboard}}`
                }))
              }
            >
              {'+ {{clipboard}}'}
            </button>
            <button
              class="btn btn--ghost btn--small"
              type="button"
              onClick={() =>
                setEditor((p) => ({
                  ...p,
                  command: `${p.command}${p.command.endsWith(' ') || !p.command ? '' : ' '}{{selection}}`
                }))
              }
            >
              {'+ {{selection}}'}
            </button>
            <button
              class="btn btn--ghost btn--small"
              type="button"
              onClick={() =>
                setEditor((p) => ({
                  ...p,
                  command: `${p.command}${p.command.endsWith(' ') || !p.command ? '' : ' '}{{workspace}}`
                }))
              }
            >
              {'+ {{workspace}}'}
            </button>
            <button
              class="btn btn--ghost btn--small"
              type="button"
              onClick={() =>
                setEditor((p) => ({
                  ...p,
                  command: `${p.command}${p.command.endsWith(' ') || !p.command ? '' : ' '}{{tab}}`
                }))
              }
            >
              {'+ {{tab}}'}
            </button>
          </div>

          <label class="field">
            <span>Tags (comma separated)</span>
            <input
              value={editor.tags}
              onInput={(e) => setEditor((p) => ({ ...p, tags: (e.target as HTMLInputElement).value }))}
            />
          </label>
          <label class="field">
            <span>Folder</span>
            <Dropdown
              value={editor.folder_id === null ? '' : String(editor.folder_id)}
              onChange={(value) => setEditor((p) => ({ ...p, folder_id: value ? parseInt(value, 10) : null }))}
              options={[
                { value: '', label: 'No folder' },
                ...folders.map((f) => ({ value: String(f.id), label: f.name }))
              ]}
            />
          </label>
          <label class="field field-toggle">
            <span>Favorite</span>
            <input
              type="checkbox"
              checked={editor.is_favorite}
              onChange={(e) => setEditor((p) => ({ ...p, is_favorite: (e.target as HTMLInputElement).checked }))}
            />
          </label>
          <label class="field">
            <span>Status</span>
            <Dropdown
              value={editor.status}
              onChange={(value) => setEditor((p) => ({ ...p, status: value as PromptStatus }))}
              options={[
                { value: 'published', label: 'Published' },
                { value: 'draft', label: 'Draft' }
              ]}
            />
          </label>
          <label class="field">
            <span>Visibility</span>
            <Dropdown
              value={editor.visibility}
              disabled={editor.status !== 'published'}
              onChange={(value) => setEditor((p) => ({ ...p, visibility: value as PromptVisibility }))}
              options={[
                { value: 'private', label: 'Private' },
                { value: 'shared', label: 'Shared' },
                { value: 'public', label: 'Public' }
              ]}
            />
          </label>

          <label class="field field-toggle">
            <span>Any workspace</span>
            <input
              type="checkbox"
              checked={editor.is_global}
              onChange={(e) => {
                const nextGlobal = (e.target as HTMLInputElement).checked;
                setEditor((p) => ({
                  ...p,
                  is_global: nextGlobal,
                  workspace_ids: nextGlobal ? [] : p.workspace_ids
                }));
              }}
            />
          </label>

          {!editor.is_global ? (
            <div class="workspace-scope">
              <div class="workspace-scope-title">Workspaces</div>
              <div class="workspace-scope-grid">
                {workspaces.map((ws) => (
                  <label key={ws.id} class="workspace-scope-item">
                    <input
                      type="checkbox"
                      checked={editor.workspace_ids.includes(ws.id)}
                      onChange={(e) => {
                        const checked = (e.target as HTMLInputElement).checked;
                        setEditor((p) => ({
                          ...p,
                          workspace_ids: checked
                            ? Array.from(new Set([...p.workspace_ids, ws.id]))
                            : p.workspace_ids.filter((id) => id !== ws.id)
                        }));
                      }}
                    />
                    {ws.name}
                  </label>
                ))}
              </div>
            </div>
          ) : null}

          <div class="panel-title-row" style={{ marginTop: '10px' }}>
            <div class="panel-title">Preview</div>
          </div>
          <div class="prompts-item-command" style={{ whiteSpace: 'pre-wrap' }}>
            {previewCommand}
          </div>
          <div class="button-row">
            <button class="btn btn--ghost" type="button" onClick={insertPreview}>
              Insert to compose
            </button>
            <button class="btn btn--solid" type="button" onClick={runPreview}>
              Test run
            </button>
          </div>
        </div>

        <div class="panel-section" style={{ minWidth: 0 }}>
          <div class="panel-title-row">
            <div class="panel-title">Variables</div>
            <div class="terminal-hint">
              {placeholders.length ? `${placeholders.length} placeholder(s)` : 'No placeholders found.'}
            </div>
          </div>
          {placeholders.length === 0 ? (
            <div class="prompt-empty">
              Use placeholders like <code>{'{{path}}'}</code> in your command.
            </div>
          ) : (
            <div class="workspace-scope-grid">
              {placeholders.map((key) => (
                <label key={key} class="field">
                  <span>{key}</span>
                  <input
                    value={editor.variables[key] ?? ''}
                    onInput={(e) => {
                      const value = (e.target as HTMLInputElement).value;
                      setEditor((p) => ({ ...p, variables: { ...p.variables, [key]: value } }));
                    }}
                  />
                </label>
              ))}
            </div>
          )}

          {editingId !== null ? (
            <>
              <div class="panel-title-row" style={{ marginTop: '12px' }}>
                <div class="panel-title">Versions</div>
              </div>
              {versionsLoading ? (
                <div class="prompt-empty">Loading versions…</div>
              ) : versions.length === 0 ? (
                <div class="prompt-empty">No versions yet.</div>
              ) : (
                <div class="prompts-list-items">
                  {versions.slice(0, 10).map((v) => (
                    <div key={v.id} class={`prompts-list-item ${selectedVersion?.id === v.id ? 'is-editing' : ''}`}>
                      <div class="prompts-item-info">
                        <div class="prompts-item-name">
                          v{v.version_num} · {v.status} · {v.visibility}
                        </div>
                        <div class="prompts-item-scope">
                          {v.created_by_username} · {new Date(v.created_at).toLocaleString()}
                        </div>
                      </div>
                      <div class="prompts-item-actions">
                        <button class="btn btn--ghost btn--small" type="button" onClick={() => setSelectedVersion(v)}>
                          View
                        </button>
                        <button
                          class="btn btn--ghost btn--small"
                          type="button"
                          onClick={() => rollbackTo(editingId, v.version_num)}
                        >
                          Rollback
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {selectedVersion ? (
                <div style={{ marginTop: '10px' }}>
                  <div class="panel-title-row">
                    <div class="panel-title">Diff (manual)</div>
                  </div>
                  <div class="workspace-scope-grid">
                    <label class="field">
                      <span>Current</span>
                      <textarea value={editor.command} rows={6} readOnly />
                    </label>
                    <label class="field">
                      <span>v{selectedVersion.version_num}</span>
                      <textarea value={selectedVersion.command} rows={6} readOnly />
                    </label>
                  </div>
                </div>
              ) : null}

              <div class="panel-title-row" style={{ marginTop: '12px' }}>
                <div class="panel-title">Sharing</div>
              </div>
              {sharesLoading ? (
                <div class="prompt-empty">Loading shares…</div>
              ) : (
                <>
                  <div class="button-row" style={{ flexWrap: 'wrap' }}>
                    <input
                      placeholder="username"
                      value={shareForm.username}
                      onInput={(e) => setShareForm((p) => ({ ...p, username: (e.target as HTMLInputElement).value }))}
                    />
                    <Dropdown
                      value={shareForm.permission}
                      onChange={(value) => setShareForm((p) => ({ ...p, permission: value as PromptSharePermission }))}
                      options={[
                        { value: 'view', label: 'view' },
                        { value: 'copy', label: 'copy' }
                      ]}
                    />
                    <button class="btn btn--ghost" type="button" onClick={addShare}>
                      Add
                    </button>
                  </div>
                  {shares.length === 0 ? (
                    <div class="prompt-empty">Not shared with anyone yet.</div>
                  ) : (
                    <div class="prompts-list-items">
                      {shares.map((s) => (
                        <div key={s.user_id} class="prompts-list-item">
                          <div class="prompts-item-info">
                            <div class="prompts-item-name">{s.username}</div>
                            <div class="prompts-item-scope">{s.permission}</div>
                          </div>
                          <div class="prompts-item-actions">
                            <button
                              class="btn btn--ghost btn--small btn--danger"
                              type="button"
                              onClick={() => removeShare(editingId, s.user_id)}
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </>
          ) : null}
        </div>
      </div>
    </div>
  );

  return (
    <Modal
      show={show}
      onDismiss={onDismiss}
      ariaLabelledBy="prompt-library-title"
      contentClassName="prompt-library-modal-content"
    >
      {view === 'list' ? listView : editView}
    </Modal>
  );
}
