async function tryRaw(knex, sql, ignoreCodes) {
  try {
    await knex.raw(sql);
    return;
  } catch (error) {
    const code = error?.code;
    if (code && Array.isArray(ignoreCodes) && ignoreCodes.includes(code)) return;
    throw error;
  }
}

exports.up = async function up(knex) {
  await knex.raw(`
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        role ENUM('admin', 'user', 'readonly') DEFAULT 'user',
        failed_login_attempts INT NOT NULL DEFAULT 0,
        last_failed_login_at TIMESTAMP NULL,
        locked_until TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_username (username),
        INDEX idx_active (active),
        INDEX idx_role (role)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS prompt_folders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(80) NOT NULL,
        sort_order INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uniq_user_folder_name (user_id, name),
        INDEX idx_user_folder_sort (user_id, sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS tags (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uniq_user_tag_name (user_id, name),
        INDEX idx_user_tag_name (user_id, name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS prompts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(50) NOT NULL,
        label VARCHAR(100) NOT NULL,
        command TEXT NOT NULL,
        description TEXT NULL,
        is_global BOOLEAN NOT NULL DEFAULT TRUE,
        sort_order INT NOT NULL DEFAULT 0,
        folder_id INT NULL,
        is_favorite BOOLEAN NOT NULL DEFAULT FALSE,
        status ENUM('draft', 'published') NOT NULL DEFAULT 'published',
        visibility ENUM('private', 'shared', 'public') NOT NULL DEFAULT 'private',
        metadata JSON NULL,
        source_prompt_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (folder_id) REFERENCES prompt_folders(id) ON DELETE SET NULL,
        FOREIGN KEY (source_prompt_id) REFERENCES prompts(id) ON DELETE SET NULL,
        INDEX idx_user_id (user_id),
        INDEX idx_is_global (is_global),
        INDEX idx_user_folder (user_id, folder_id),
        INDEX idx_user_favorite (user_id, is_favorite),
        INDEX idx_user_status (user_id, status),
        INDEX idx_visibility (visibility),
        INDEX idx_prompts_visibility_status (visibility, status),
        INDEX idx_prompts_user_sort_name (user_id, sort_order, name),
        INDEX idx_user_created_at (user_id, created_at),
        INDEX idx_user_updated_at (user_id, updated_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS prompt_tags (
        prompt_id INT NOT NULL,
        tag_id INT NOT NULL,
        PRIMARY KEY (prompt_id, tag_id),
        FOREIGN KEY (prompt_id) REFERENCES prompts(id) ON DELETE CASCADE,
        FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE,
        INDEX idx_tag_prompt (tag_id, prompt_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS prompt_versions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        prompt_id INT NOT NULL,
        version_num INT NOT NULL,
        created_by INT NOT NULL,
        label VARCHAR(100) NOT NULL,
        command TEXT NOT NULL,
        description TEXT NULL,
        status ENUM('draft', 'published') NOT NULL,
        visibility ENUM('private', 'shared', 'public') NOT NULL,
        metadata JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (prompt_id) REFERENCES prompts(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,
        UNIQUE KEY uniq_prompt_version (prompt_id, version_num),
        INDEX idx_prompt_versions_prompt_created (prompt_id, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS prompt_shares (
        prompt_id INT NOT NULL,
        shared_with_user_id INT NOT NULL,
        permission ENUM('view', 'copy') NOT NULL DEFAULT 'view',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (prompt_id, shared_with_user_id),
        FOREIGN KEY (prompt_id) REFERENCES prompts(id) ON DELETE CASCADE,
        FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_shared_with_prompt (shared_with_user_id, prompt_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS prompt_filters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(80) NOT NULL,
        filter_json JSON NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uniq_user_filter_name (user_id, name),
        INDEX idx_user_filter_name (user_id, name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS workspaces (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(64) NOT NULL,
        tmux_session VARCHAR(128) NOT NULL,
        sort_order INT NOT NULL DEFAULT 0,
        pinned BOOLEAN NOT NULL DEFAULT FALSE,
        is_default BOOLEAN NOT NULL DEFAULT FALSE,
        last_used_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uniq_user_workspace_name (user_id, name),
        UNIQUE KEY uniq_user_tmux_session (user_id, tmux_session),
        INDEX idx_user_sort (user_id, sort_order),
        INDEX idx_user_pinned (user_id, pinned),
        INDEX idx_user_default (user_id, is_default),
        INDEX idx_user_last_used (user_id, last_used_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS prompt_workspaces (
        prompt_id INT NOT NULL,
        workspace_id INT NOT NULL,
        PRIMARY KEY (prompt_id, workspace_id),
        FOREIGN KEY (prompt_id) REFERENCES prompts(id) ON DELETE CASCADE,
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
        INDEX idx_workspace_prompt (workspace_id, prompt_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS sessions (
        id VARCHAR(64) PRIMARY KEY,
        user_id INT NOT NULL,
        terminal_token VARCHAR(80) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP NULL,
        expires_at TIMESTAMP NOT NULL,
        revoked BOOLEAN DEFAULT FALSE,
        ip_address VARCHAR(45) NULL,
        user_agent VARCHAR(255) NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY idx_terminal_token (terminal_token),
        INDEX idx_user_id (user_id),
        INDEX idx_expires_at (expires_at),
        INDEX idx_revoked (revoked),
        INDEX idx_sessions_expires_revoked (expires_at, revoked)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        action VARCHAR(50) NOT NULL,
        details JSON NULL,
        ip_address VARCHAR(45) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_user_id (user_id),
        INDEX idx_created_at (created_at),
        INDEX idx_audit_user_created (user_id, created_at DESC)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS events (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        type VARCHAR(80) NOT NULL,
        payload JSON NULL,
        ip_address VARCHAR(45) NULL,
        request_id VARCHAR(128) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_events_user_created (user_id, created_at),
        INDEX idx_events_type_created (type, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS user_invites (
        id INT AUTO_INCREMENT PRIMARY KEY,
        token VARCHAR(64) NOT NULL,
        created_by INT NOT NULL,
        role ENUM('admin', 'user', 'readonly') NOT NULL DEFAULT 'user',
        expires_at TIMESTAMP NOT NULL,
        redeemed_at TIMESTAMP NULL,
        redeemed_by_user_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,
        FOREIGN KEY (redeemed_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
        UNIQUE KEY uniq_invite_token (token),
        INDEX idx_invite_expires (expires_at),
        INDEX idx_invite_redeemed (redeemed_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await knex.raw(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        token VARCHAR(64) NOT NULL,
        user_id INT NOT NULL,
        created_by INT NULL,
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
        UNIQUE KEY uniq_reset_token (token),
        INDEX idx_reset_user (user_id),
        INDEX idx_reset_expires (expires_at),
        INDEX idx_reset_used (used_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await tryRaw(knex, 'DELETE FROM prompts WHERE user_id IS NULL', []);

  const maybeAddColumn = async (table, column, addFn) => {
    const exists = await knex.schema.hasColumn(table, column);
    if (!exists) {
      await knex.schema.alterTable(table, addFn);
    }
  };

  await maybeAddColumn('sessions', 'terminal_token', (t) => t.string('terminal_token', 80).nullable());
  try {
    await knex.schema.alterTable('sessions', (t) => t.unique(['terminal_token'], { indexName: 'idx_terminal_token' }));
  } catch (error) {
    const code = error?.code;
    if (code && code !== 'ER_DUP_KEYNAME') throw error;
  }

  await maybeAddColumn('sessions', 'last_seen_at', (t) => t.timestamp('last_seen_at').nullable());
  await maybeAddColumn('sessions', 'ip_address', (t) => t.string('ip_address', 45).nullable());
  await maybeAddColumn('sessions', 'user_agent', (t) => t.string('user_agent', 255).nullable());

  await maybeAddColumn('users', 'active', (t) => t.boolean('active').notNullable().defaultTo(true));
  await maybeAddColumn('users', 'failed_login_attempts', (t) => t.integer('failed_login_attempts').notNullable().defaultTo(0));
  await maybeAddColumn('users', 'last_failed_login_at', (t) => t.timestamp('last_failed_login_at').nullable());
  await maybeAddColumn('users', 'locked_until', (t) => t.timestamp('locked_until').nullable());

  await maybeAddColumn('workspaces', 'last_used_at', (t) => t.timestamp('last_used_at').nullable());

  await maybeAddColumn('prompts', 'folder_id', (t) => t.integer('folder_id').nullable());
  await maybeAddColumn('prompts', 'is_favorite', (t) => t.boolean('is_favorite').notNullable().defaultTo(false));
  await maybeAddColumn('prompts', 'status', (t) => t.enu('status', ['draft', 'published']).notNullable().defaultTo('published'));
  await maybeAddColumn('prompts', 'visibility', (t) => t.enu('visibility', ['private', 'shared', 'public']).notNullable().defaultTo('private'));
  await maybeAddColumn('prompts', 'metadata', (t) => t.json('metadata').nullable());
  await maybeAddColumn('prompts', 'source_prompt_id', (t) => t.integer('source_prompt_id').nullable());

  await tryRaw(knex, 'CREATE INDEX idx_user_folder ON prompts (user_id, folder_id)', ['ER_DUP_KEYNAME']);
  await tryRaw(knex, 'CREATE INDEX idx_user_favorite ON prompts (user_id, is_favorite)', ['ER_DUP_KEYNAME']);
  await tryRaw(knex, 'CREATE INDEX idx_user_status ON prompts (user_id, status)', ['ER_DUP_KEYNAME']);
  await tryRaw(knex, 'CREATE INDEX idx_visibility ON prompts (visibility)', ['ER_DUP_KEYNAME']);
  await tryRaw(knex, 'CREATE INDEX idx_user_created_at ON prompts (user_id, created_at)', ['ER_DUP_KEYNAME']);
  await tryRaw(knex, 'CREATE INDEX idx_user_updated_at ON prompts (user_id, updated_at)', ['ER_DUP_KEYNAME']);

  await tryRaw(
    knex,
    'ALTER TABLE prompts ADD CONSTRAINT fk_prompts_folder FOREIGN KEY (folder_id) REFERENCES prompt_folders(id) ON DELETE SET NULL',
    ['ER_FK_DUP_NAME', 'ER_DUP_KEYNAME']
  );
  await tryRaw(
    knex,
    'ALTER TABLE prompts ADD CONSTRAINT fk_prompts_source FOREIGN KEY (source_prompt_id) REFERENCES prompts(id) ON DELETE SET NULL',
    ['ER_FK_DUP_NAME', 'ER_DUP_KEYNAME']
  );
};

exports.down = async function down(_knex) {};

