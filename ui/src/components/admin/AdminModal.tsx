import { useEffect, useMemo, useState } from 'preact/hooks';

import type { CurrentUser, UserRole } from '../../types';
import { Modal } from '../modal/Modal';
import { Dropdown } from '../dropdown/Dropdown';
import { VirtualList } from '../virtual/VirtualList';
import { withCsrfHeaders } from '../../utils/csrf';

type AdminUserRow = {
  id: number;
  username: string;
  role: UserRole;
  active: boolean;
  must_change_password: boolean;
  failed_login_attempts: number;
  last_failed_login_at: string | null;
  locked_until: string | null;
  created_at?: string;
  updated_at?: string;
};

type InviteRow = {
  id: number;
  token: string;
  role: UserRole;
  expires_at: string;
  redeemed_at: string | null;
  redeemed_by_user_id: number | null;
  created_at: string;
};

type SessionRow = {
  id: string;
  user_id: number;
  username: string;
  role: UserRole;
  active: boolean;
  created_at: string;
  last_seen_at: string | null;
  expires_at: string;
  revoked: boolean;
  ip_address: string | null;
  user_agent: string | null;
};

type AuditRow = {
  id: number;
  user_id: number | null;
  username: string | null;
  action: string;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
};

type SystemInfo = {
  ok: boolean;
  release: string | null;
  counts: { users: number; prompts: number; active_sessions: number };
  now: string;
  db?: {
    circuit?: {
      state: string;
      failureCount: number;
      threshold: number;
      openedAt: string | null;
      lastFailureAt: string | null;
      lastErrorCode: string | null;
    };
  };
};

type RateLimitInfo = {
  auth: { windowMs: number; max: number };
  stats: {
    auth: {
      blocked: number;
      lastBlockedAt: string | null;
      lastBlockedIp: string | null;
      lastBlockedUserAgent: string | null;
    };
  };
};

type Props = {
  show: boolean;
  onDismiss: () => void;
  currentUser: CurrentUser | null;
  notify: (message: string) => void;
};

const ROLE_OPTIONS: Array<{ value: UserRole; label: string }> = [
  { value: 'admin', label: 'admin' },
  { value: 'user', label: 'user' },
  { value: 'editor', label: 'editor' },
  { value: 'readonly', label: 'readonly' },
  { value: 'auditor', label: 'auditor' }
];

export function AdminModal({ show, onDismiss, currentUser, notify }: Props) {
  const USER_ROW_HEIGHT = 132;
  const USER_ROW_GAP = 14;

  const isAdmin = currentUser?.role === 'admin';
  const isAuditor = currentUser?.role === 'auditor';
  const canViewAdmin = isAdmin || isAuditor;
  const availableTabs = isAdmin
    ? (['users', 'invites', 'sessions', 'audit', 'system', 'rate'] as const)
    : (['audit', 'system', 'rate'] as const);
  const [tab, setTab] = useState<'users' | 'invites' | 'sessions' | 'audit' | 'system' | 'rate'>('users');

  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [invites, setInvites] = useState<InviteRow[]>([]);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [rateLimit, setRateLimit] = useState<RateLimitInfo | null>(null);
  const [mfaStatus, setMfaStatus] = useState<{ enabled: boolean; confirmedAt: string | null } | null>(null);
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; otpauthUrl: string } | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [mfaDisableCode, setMfaDisableCode] = useState('');
  const [mfaDisablePassword, setMfaDisablePassword] = useState('');

  const [busy, setBusy] = useState(false);
  const [sessionsPage, setSessionsPage] = useState(0);
  const [auditPage, setAuditPage] = useState(0);

  const origin = useMemo(() => window.location.origin, []);
  const circuit = system?.db?.circuit ?? null;
  const circuitState = circuit?.state ?? 'unknown';
  const circuitBadgeClass =
    circuitState === 'closed'
      ? 'status-pill status-pill--ok'
      : circuitState === 'half_open'
        ? 'status-pill status-pill--warn'
        : circuitState === 'open'
          ? 'status-pill status-pill--error'
          : 'status-pill status-pill--neutral';

  const loadUsers = async () => {
    const resp = await fetch('/api/users');
    if (!resp.ok) return;
    const data = (await resp.json()) as AdminUserRow[];
    setUsers(data);
  };

  const loadInvites = async () => {
    const resp = await fetch('/api/admin/invites');
    if (!resp.ok) return;
    const data = (await resp.json()) as InviteRow[];
    setInvites(data);
  };

  const loadSessions = async () => {
    const resp = await fetch('/api/admin/sessions');
    if (!resp.ok) return;
    const data = (await resp.json()) as SessionRow[];
    setSessions(data);
  };

  const loadAudit = async () => {
    const resp = await fetch('/api/admin/audit?limit=200');
    if (!resp.ok) return;
    const data = (await resp.json()) as AuditRow[];
    setAudit(data);
  };

  const loadSystem = async () => {
    const resp = await fetch('/api/admin/system');
    if (!resp.ok) return;
    const data = (await resp.json()) as SystemInfo;
    setSystem(data);
  };

  const loadRate = async () => {
    const resp = await fetch('/api/admin/rate-limit');
    if (!resp.ok) return;
    const data = (await resp.json()) as RateLimitInfo;
    setRateLimit(data);
  };

  const loadMfaStatus = async () => {
    if (!isAdmin) return;
    const resp = await fetch('/api/auth/mfa');
    if (!resp.ok) return;
    const data = (await resp.json()) as { enabled: boolean; confirmedAt: string | null };
    setMfaStatus(data);
  };

  const startMfaSetup = async () => {
    setBusy(true);
    try {
      const resp = await fetch('/api/auth/mfa/setup', { method: 'POST', headers: withCsrfHeaders() });
      const data = (await resp.json()) as { secret?: string; otpauthUrl?: string; error?: string };
      if (!resp.ok) {
        notify(data.error || 'MFA setup failed');
        return;
      }
      if (!data.secret || !data.otpauthUrl) {
        notify('MFA setup failed');
        return;
      }
      setMfaSetup({ secret: data.secret, otpauthUrl: data.otpauthUrl });
      setMfaCode('');
      await loadMfaStatus();
    } finally {
      setBusy(false);
    }
  };

  const confirmMfaSetup = async () => {
    if (!mfaCode.trim()) {
      notify('Enter the MFA code from your authenticator app');
      return;
    }
    setBusy(true);
    try {
      const resp = await fetch('/api/auth/mfa/confirm', {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ token: mfaCode.trim() })
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'MFA confirmation failed');
        return;
      }
      setMfaSetup(null);
      setMfaCode('');
      await loadMfaStatus();
      notify('MFA enabled');
    } finally {
      setBusy(false);
    }
  };

  const disableMfa = async () => {
    if (!mfaDisablePassword.trim() || !mfaDisableCode.trim()) {
      notify('Enter password and MFA code');
      return;
    }
    setBusy(true);
    try {
      const resp = await fetch('/api/auth/mfa/disable', {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ password: mfaDisablePassword, token: mfaDisableCode.trim() })
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'MFA disable failed');
        return;
      }
      setMfaDisablePassword('');
      setMfaDisableCode('');
      setMfaSetup(null);
      await loadMfaStatus();
      notify('MFA disabled');
    } finally {
      setBusy(false);
    }
  };

  const refreshTab = async () => {
    if (!canViewAdmin) return;
    if (tab === 'users' && isAdmin) return loadUsers();
    if (tab === 'invites' && isAdmin) return loadInvites();
    if (tab === 'sessions' && isAdmin) return loadSessions();
    if (tab === 'audit') return loadAudit();
    if (tab === 'system') {
      await loadSystem();
      await loadMfaStatus();
      return;
    }
    if (tab === 'rate') return loadRate();
  };

  useEffect(() => {
    if (!show) return;
    const nextTab = isAdmin ? 'users' : 'audit';
    setTab(nextTab);
    setBusy(false);
    setMfaSetup(null);
    setMfaStatus(null);
    setMfaCode('');
    setMfaDisableCode('');
    setMfaDisablePassword('');
  }, [show, isAdmin]);

  useEffect(() => {
    if (!show) return;
    refreshTab();
  }, [show, tab]);

  if (!canViewAdmin) {
    return (
      <Modal show={show} onDismiss={onDismiss} ariaLabel="Admin">
        <div class="design-modal tools-modal">
          <div class="design-header">
            <div>
              <div class="design-title">Admin</div>
              <div class="design-subtitle">Admin access required.</div>
            </div>
            <button class="btn btn--ghost" type="button" onClick={onDismiss}>
              Close
            </button>
          </div>
          <div class="prompt-empty">You are not an admin.</div>
        </div>
      </Modal>
    );
  }

  const updateUser = async (
    userId: number,
    patch: Partial<Pick<AdminUserRow, 'role' | 'active' | 'must_change_password'>>
  ) => {
    setBusy(true);
    try {
      const resp = await fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(patch)
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'Update failed');
        return;
      }
      await loadUsers();
      notify('User updated');
    } finally {
      setBusy(false);
    }
  };

  const deleteUser = async (userId: number) => {
    const ok = window.confirm('Delete this user?');
    if (!ok) return;
    setBusy(true);
    try {
      const resp = await fetch(`/api/users/${userId}`, { method: 'DELETE', headers: withCsrfHeaders() });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'Delete failed');
        return;
      }
      await loadUsers();
      notify('User deleted');
    } finally {
      setBusy(false);
    }
  };

  const unlockUser = async (userId: number) => {
    const ok = window.confirm('Unlock this user (clear failed login attempts)?');
    if (!ok) return;
    setBusy(true);
    try {
      const resp = await fetch(`/api/admin/users/${userId}/unlock`, { method: 'POST', headers: withCsrfHeaders() });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'Unlock failed');
        return;
      }
      await loadUsers();
      notify('User unlocked');
    } finally {
      setBusy(false);
    }
  };

  const createInvite = async () => {
    const role = (window.prompt('Invite role (admin/user/editor/readonly/auditor)', 'user') || 'user')
      .trim()
      .toLowerCase();
    const expires = window.prompt('Expires in hours', '72');
    setBusy(true);
    try {
      const resp = await fetch('/api/admin/invites', {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ role, expires_in_hours: expires })
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'Invite create failed');
        return;
      }
      await loadInvites();
      const link = `${origin}/invite?token=${data.token}`;
      await navigator.clipboard.writeText(link).catch(() => {});
      notify('Invite created (link copied)');
    } finally {
      setBusy(false);
    }
  };

  const revokeInvite = async (inviteId: number) => {
    const ok = window.confirm('Revoke this invite?');
    if (!ok) return;
    setBusy(true);
    try {
      const resp = await fetch(`/api/admin/invites/${inviteId}`, { method: 'DELETE', headers: withCsrfHeaders() });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'Revoke failed');
        return;
      }
      await loadInvites();
      notify('Invite revoked');
    } finally {
      setBusy(false);
    }
  };

  const createPasswordReset = async (userId: number) => {
    const expires = window.prompt('Reset link expires in hours', '2');
    setBusy(true);
    try {
      const resp = await fetch(`/api/admin/users/${userId}/password-reset`, {
        method: 'POST',
        headers: withCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ expires_in_hours: expires })
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'Reset link failed');
        return;
      }
      const link = `${origin}/reset-password?token=${data.token}`;
      await navigator.clipboard.writeText(link).catch(() => {});
      notify('Reset link created (copied)');
    } finally {
      setBusy(false);
    }
  };

  const revokeSession = async (sessionId: string) => {
    const ok = window.confirm('Revoke this session?');
    if (!ok) return;
    setBusy(true);
    try {
      const resp = await fetch(`/api/admin/sessions/${sessionId}/revoke`, {
        method: 'POST',
        headers: withCsrfHeaders()
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        notify(data.error || 'Revoke failed');
        return;
      }
      await loadSessions();
      notify('Session revoked');
    } finally {
      setBusy(false);
    }
  };

  const tabLabels = {
    users: 'Users',
    invites: 'Invites',
    sessions: 'Sessions',
    audit: 'Audit',
    system: 'System',
    rate: 'Rate limit'
  } as const;

  const tabs = (
    <div class="button-row" style={{ flexWrap: 'wrap' }}>
      {availableTabs.map((entry) => (
        <button
          key={entry}
          class={`btn btn--ghost btn--small ${tab === entry ? 'is-active' : ''}`}
          type="button"
          onClick={() => setTab(entry)}
        >
          {tabLabels[entry]}
        </button>
      ))}
    </div>
  );

  return (
    <Modal show={show} onDismiss={onDismiss} ariaLabel="Admin console">
      <div class="design-modal tools-modal">
        <div class="design-header">
          <div>
            <div class="design-title">Admin</div>
            <div class="design-subtitle">Users, invites, sessions, audit, and health.</div>
          </div>
          <div class="button-row">
            <button class="btn btn--ghost" type="button" disabled={busy} onClick={refreshTab}>
              Refresh
            </button>
            <button class="btn btn--ghost" type="button" onClick={onDismiss}>
              Close
            </button>
          </div>
        </div>

        {tabs}

        {tab === 'users' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">Users</div>
              <div class="terminal-hint">{users.length} total</div>
            </div>
            {users.length === 0 ? (
              <div class="prompt-empty">No users.</div>
            ) : (
              <VirtualList
                items={users}
                itemHeight={USER_ROW_HEIGHT}
                itemGap={USER_ROW_GAP}
                overscan={8}
                style={{ maxHeight: '60vh', paddingRight: '6px' }}
                getKey={(u) => u.id}
                renderItem={(u) => (
                  <div class="prompts-list-item list-item--fixed" style={{ height: '100%' }}>
                    <div class="prompts-item-info">
                      <div class="prompts-item-name">{u.username}</div>
                      <div class="prompts-item-scope">
                        {u.role} · {u.active ? 'active' : 'disabled'} ·{' '}
                        {u.must_change_password ? 'must change password' : 'ok'}
                        {u.locked_until && new Date(u.locked_until).getTime() > Date.now()
                          ? ` · locked until ${new Date(u.locked_until).toLocaleString()}`
                          : u.failed_login_attempts > 0
                            ? ` · ${u.failed_login_attempts} failed login${u.failed_login_attempts === 1 ? '' : 's'}`
                            : ''}
                      </div>
                    </div>
                    <div class="prompts-item-actions" style={{ flexWrap: 'wrap' }}>
                      <Dropdown
                        value={u.role}
                        onChange={(value) => updateUser(u.id, { role: value as UserRole })}
                        disabled={busy}
                        options={ROLE_OPTIONS}
                      />
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        disabled={busy}
                        onClick={() => updateUser(u.id, { active: !u.active })}
                      >
                        {u.active ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        disabled={
                          busy || u.id === currentUser?.id || (u.failed_login_attempts === 0 && !u.locked_until)
                        }
                        onClick={() => unlockUser(u.id)}
                      >
                        Unlock
                      </button>
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        disabled={busy}
                        onClick={() => updateUser(u.id, { must_change_password: !u.must_change_password })}
                      >
                        {u.must_change_password ? 'Clear forced change' : 'Force change'}
                      </button>
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        disabled={busy}
                        onClick={() => createPasswordReset(u.id)}
                      >
                        Reset link
                      </button>
                      <button
                        class="btn btn--ghost btn--small btn--danger"
                        type="button"
                        disabled={busy}
                        onClick={() => deleteUser(u.id)}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                )}
              />
            )}
          </div>
        ) : null}

        {tab === 'invites' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">Invites</div>
              <button class="btn btn--ghost btn--small" type="button" disabled={busy} onClick={createInvite}>
                Create invite (copy link)
              </button>
            </div>
            {invites.length === 0 ? (
              <div class="prompt-empty">No invites.</div>
            ) : (
              <div class="prompts-list-items">
                {invites.map((i) => (
                  <div key={i.id} class="prompts-list-item">
                    <div class="prompts-item-info">
                      <div class="prompts-item-name">
                        {i.role} · {i.redeemed_at ? 'used' : 'unused'}
                      </div>
                      <div class="prompts-item-scope">expires {new Date(i.expires_at).toLocaleString()}</div>
                      <div class="prompts-item-command">{`${origin}/invite?token=${i.token}`}</div>
                    </div>
                    <div class="prompts-item-actions" style={{ flexWrap: 'wrap' }}>
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        onClick={() =>
                          navigator.clipboard
                            .writeText(`${origin}/invite?token=${i.token}`)
                            .then(() => notify('Invite link copied'))
                            .catch(() => notify('Clipboard blocked'))
                        }
                      >
                        Copy
                      </button>
                      <button
                        class="btn btn--ghost btn--small btn--danger"
                        type="button"
                        disabled={busy}
                        onClick={() => revokeInvite(i.id)}
                      >
                        Revoke
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : null}

        {tab === 'sessions' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">Sessions</div>
            </div>
            {sessions.length === 0 ? (
              <div class="prompt-empty">No sessions.</div>
            ) : (
              (() => {
                const pageSize = 10;
                const totalPages = Math.max(1, Math.ceil(sessions.length / pageSize));
                const safePage = Math.max(0, Math.min(sessionsPage, totalPages - 1));
                const start = safePage * pageSize;
                const end = Math.min(sessions.length, start + pageSize);
                const pageItems = sessions.slice(start, end);

                return (
                  <>
                    <div class="button-row" style={{ alignItems: 'center', justifyContent: 'space-between' }}>
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        disabled={safePage === 0}
                        onClick={() => setSessionsPage((p) => Math.max(0, p - 1))}
                      >
                        Prev
                      </button>
                      <div class="terminal-hint">
                        Showing {start + 1}–{end} of {sessions.length} · Page {safePage + 1} of {totalPages}
                      </div>
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        disabled={safePage >= totalPages - 1}
                        onClick={() => setSessionsPage((p) => Math.min(totalPages - 1, p + 1))}
                      >
                        Next
                      </button>
                    </div>

                    <div class="tools-activity-table-wrap">
                      <table class="tools-activity-table">
                        <thead>
                          <tr>
                            <th>User</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Seen</th>
                            <th>Expires</th>
                            <th aria-label="Actions" />
                          </tr>
                        </thead>
                        <tbody>
                          {pageItems.map((s) => (
                            <tr key={s.id}>
                              <td class="tools-activity-item">
                                <span class="tools-activity-item-text">{s.username}</span>
                              </td>
                              <td class="tools-activity-action">{s.role}</td>
                              <td class="tools-activity-action">{s.revoked ? 'revoked' : 'active'}</td>
                              <td class="tools-activity-time">
                                {s.last_seen_at
                                  ? new Date(s.last_seen_at).toLocaleString(undefined, {
                                      dateStyle: 'short',
                                      timeStyle: 'short'
                                    })
                                  : '—'}
                              </td>
                              <td class="tools-activity-time">
                                {new Date(s.expires_at).toLocaleString(undefined, {
                                  dateStyle: 'short',
                                  timeStyle: 'short'
                                })}
                              </td>
                              <td class="tools-activity-cta">
                                <button
                                  class="btn btn--ghost btn--small"
                                  type="button"
                                  disabled={busy || s.revoked}
                                  onClick={() => revokeSession(s.id)}
                                >
                                  Revoke
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                );
              })()
            )}
          </div>
        ) : null}

        {tab === 'audit' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">Audit log</div>
            </div>
            {audit.length === 0 ? (
              <div class="prompt-empty">No audit entries.</div>
            ) : (
              (() => {
                const pageSize = 10;
                const totalPages = Math.max(1, Math.ceil(audit.length / pageSize));
                const safePage = Math.max(0, Math.min(auditPage, totalPages - 1));
                const start = safePage * pageSize;
                const end = Math.min(audit.length, start + pageSize);
                const pageItems = audit.slice(start, end);

                return (
                  <>
                    <div class="button-row" style={{ alignItems: 'center', justifyContent: 'space-between' }}>
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        disabled={safePage === 0}
                        onClick={() => setAuditPage((p) => Math.max(0, p - 1))}
                      >
                        Prev
                      </button>
                      <div class="terminal-hint">
                        Showing {start + 1}–{end} of {audit.length} · Page {safePage + 1} of {totalPages}
                      </div>
                      <button
                        class="btn btn--ghost btn--small"
                        type="button"
                        disabled={safePage >= totalPages - 1}
                        onClick={() => setAuditPage((p) => Math.min(totalPages - 1, p + 1))}
                      >
                        Next
                      </button>
                    </div>

                    <div class="tools-activity-table-wrap">
                      <table class="tools-activity-table">
                        <thead>
                          <tr>
                            <th>When</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Details</th>
                          </tr>
                        </thead>
                        <tbody>
                          {pageItems.map((a) => (
                            <tr key={a.id}>
                              <td class="tools-activity-time">
                                {new Date(a.created_at).toLocaleString(undefined, {
                                  dateStyle: 'short',
                                  timeStyle: 'short'
                                })}
                              </td>
                              <td class="tools-activity-action">{a.username ?? '—'}</td>
                              <td class="tools-activity-action">{a.action}</td>
                              <td class="tools-activity-item">
                                <span class="tools-activity-item-text">
                                  {a.details ? JSON.stringify(a.details) : '—'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                );
              })()
            )}
          </div>
        ) : null}

        {tab === 'system' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">System</div>
            </div>
            {system ? (
              <div class="prompt-empty system-status">
                <div class="system-status-row">
                  <span>Release: {system.release ?? '—'}</span>
                  <span>DB ok: {String(system.ok)}</span>
                  <span>users: {system.counts.users}</span>
                  <span>prompts: {system.counts.prompts}</span>
                  <span>active sessions: {system.counts.active_sessions}</span>
                </div>
                {circuit ? (
                  <div class="system-status-row">
                    <span>
                      DB circuit: <span class={circuitBadgeClass}>{circuitState.replace('_', ' ')}</span>
                    </span>
                    <span>
                      failures: {circuit.failureCount}/{circuit.threshold}
                    </span>
                    {circuit.openedAt ? <span>opened: {new Date(circuit.openedAt).toLocaleString()}</span> : null}
                    {circuit.lastErrorCode ? <span>last error: {circuit.lastErrorCode}</span> : null}
                  </div>
                ) : null}
                <div class="system-status-row">now: {new Date(system.now).toLocaleString()}</div>
              </div>
            ) : (
              <div class="prompt-empty">Loading…</div>
            )}
            {isAdmin ? (
              <div class="prompt-empty system-status mfa-card">
                <div class="system-status-row">
                  <span>MFA: {mfaStatus?.enabled ? 'enabled' : 'disabled'}</span>
                  {mfaStatus?.confirmedAt ? (
                    <span>confirmed: {new Date(mfaStatus.confirmedAt).toLocaleString()}</span>
                  ) : null}
                </div>
                {mfaStatus?.enabled ? (
                  <div class="system-status-row mfa-actions">
                    <input
                      class="mfa-input"
                      type="password"
                      placeholder="Password"
                      value={mfaDisablePassword}
                      onInput={(event) => setMfaDisablePassword((event.target as HTMLInputElement).value)}
                    />
                    <input
                      class="mfa-input"
                      type="text"
                      placeholder="6-digit code"
                      value={mfaDisableCode}
                      onInput={(event) => setMfaDisableCode((event.target as HTMLInputElement).value)}
                    />
                    <button class="btn btn--ghost btn--small" type="button" disabled={busy} onClick={disableMfa}>
                      Disable MFA
                    </button>
                  </div>
                ) : (
                  <>
                    <div class="system-status-row">
                      <button class="btn btn--ghost btn--small" type="button" disabled={busy} onClick={startMfaSetup}>
                        Enable MFA
                      </button>
                    </div>
                    {mfaSetup ? (
                      <>
                        <div class="system-status-row">
                          <span class="mfa-secret">Secret: {mfaSetup.secret}</span>
                        </div>
                        <div class="system-status-row">
                          <span class="mfa-secret">otpauth: {mfaSetup.otpauthUrl}</span>
                        </div>
                        <div class="system-status-row mfa-actions">
                          <input
                            class="mfa-input"
                            type="text"
                            placeholder="6-digit code"
                            value={mfaCode}
                            onInput={(event) => setMfaCode((event.target as HTMLInputElement).value)}
                          />
                          <button
                            class="btn btn--ghost btn--small"
                            type="button"
                            disabled={busy}
                            onClick={confirmMfaSetup}
                          >
                            Confirm MFA
                          </button>
                        </div>
                      </>
                    ) : null}
                  </>
                )}
              </div>
            ) : null}
          </div>
        ) : null}

        {tab === 'rate' ? (
          <div class="panel-section">
            <div class="panel-title-row">
              <div class="panel-title">Rate limit</div>
            </div>
            {rateLimit ? (
              <div class="prompt-empty">
                login max {rateLimit.auth.max} per {Math.round(rateLimit.auth.windowMs / 60000)}m · blocked:{' '}
                {rateLimit.stats.auth.blocked}
              </div>
            ) : (
              <div class="prompt-empty">Loading…</div>
            )}
          </div>
        ) : null}
      </div>
    </Modal>
  );
}
