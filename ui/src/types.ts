export type PromptAccess = 'owned' | 'shared' | 'public';

export type PromptVisibility = 'private' | 'shared' | 'public';

export type PromptStatus = 'draft' | 'published';

export type PromptSharePermission = 'view' | 'copy';

export type PromptTag = {
  id: number;
  name: string;
};

export type Prompt = {
  id: number;
  owner_user_id: number;
  owner_username: string;
  access: PromptAccess;
  share_permission: PromptSharePermission | null;

  name: string;
  label: string;
  command: string;
  description?: string | null;

  is_global: boolean;
  sort_order: number;
  workspace_ids: number[];

  folder_id: number | null;
  is_favorite: boolean;
  status: PromptStatus;
  visibility: PromptVisibility;
  metadata: Record<string, unknown> | null;

  tags: PromptTag[];
};

export type Workspace = {
  id: number;
  name: string;
  tmux_session: string;
  sort_order: number;
  pinned: boolean;
  is_default: boolean;
  prompt_count: number;
  last_used_at?: string | null;
};

export type Tag = {
  id: number;
  name: string;
  created_at?: string;
};

export type PromptFolder = {
  id: number;
  name: string;
  sort_order: number;
  created_at?: string;
  updated_at?: string;
};

export type PromptFilter = {
  id: number;
  name: string;
  filter_json: Record<string, unknown> | null;
  created_at?: string;
  updated_at?: string;
};

export type UserRole = 'admin' | 'user' | 'editor' | 'readonly' | 'auditor';

export type CurrentUser = {
  id: number;
  username: string;
  role: UserRole;
  mustChangePassword: boolean;
  active: boolean;
  mfaEnabled: boolean;
  terminalAllowed: boolean;
};
