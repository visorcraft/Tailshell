-- Performance indexes migration
-- Run with: docker compose exec -T mysql mysql -uTailshell -p"$MYSQL_PASSWORD" Tailshell < db/migrations/001_add_performance_indexes.sql

-- Compound index for audit_log queries (user_id + created_at DESC is common)
CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_log (user_id, created_at DESC);

-- Compound index for prompts visibility queries
CREATE INDEX IF NOT EXISTS idx_prompts_visibility_status ON prompts (visibility, status);

-- Compound index for prompt sorting (user_id + sort_order + name)
CREATE INDEX IF NOT EXISTS idx_prompts_user_sort_name ON prompts (user_id, sort_order, name);

-- Compound index for sessions cleanup queries
CREATE INDEX IF NOT EXISTS idx_sessions_expires_revoked ON sessions (expires_at, revoked);

-- Compound index for workspaces user queries
CREATE INDEX IF NOT EXISTS idx_workspaces_user_sort ON workspaces (user_id, sort_order, id);

-- Index for prompt_versions lookup by prompt
CREATE INDEX IF NOT EXISTS idx_prompt_versions_prompt_num ON prompt_versions (prompt_id, version_num DESC);

-- Index for user_invites cleanup
CREATE INDEX IF NOT EXISTS idx_invites_expires_redeemed ON user_invites (expires_at, redeemed_at);

-- Index for password_reset_tokens cleanup
CREATE INDEX IF NOT EXISTS idx_reset_expires_used ON password_reset_tokens (expires_at, used_at);
