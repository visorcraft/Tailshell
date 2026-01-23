async function tryRaw(knex, sql, ignoreCodes = []) {
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
  await knex.raw(`ALTER TABLE users MODIFY role ENUM('admin', 'user', 'editor', 'readonly', 'auditor') DEFAULT 'user'`);
  await knex.raw(
    `ALTER TABLE user_invites MODIFY role ENUM('admin', 'user', 'editor', 'readonly', 'auditor') NOT NULL DEFAULT 'user'`
  );

  await tryRaw(knex, 'ALTER TABLE users ADD COLUMN mfa_totp_secret VARCHAR(64) NULL', ['ER_DUP_FIELDNAME']);
  await tryRaw(knex, 'ALTER TABLE users ADD COLUMN mfa_totp_enabled BOOLEAN NOT NULL DEFAULT FALSE', [
    'ER_DUP_FIELDNAME'
  ]);
  await tryRaw(knex, 'ALTER TABLE users ADD COLUMN mfa_totp_confirmed_at TIMESTAMP NULL', ['ER_DUP_FIELDNAME']);

  await tryRaw(knex, 'ALTER TABLE sessions ADD COLUMN refresh_token_hash VARCHAR(128) NULL', ['ER_DUP_FIELDNAME']);
  await tryRaw(knex, 'ALTER TABLE sessions ADD COLUMN refresh_expires_at TIMESTAMP NULL', ['ER_DUP_FIELDNAME']);
  await tryRaw(knex, 'ALTER TABLE sessions ADD COLUMN refresh_last_used_at TIMESTAMP NULL', ['ER_DUP_FIELDNAME']);
  await tryRaw(knex, 'ALTER TABLE sessions ADD COLUMN csrf_token VARCHAR(64) NULL', ['ER_DUP_FIELDNAME']);
  await tryRaw(knex, 'ALTER TABLE sessions ADD INDEX idx_refresh_expires (refresh_expires_at)', ['ER_DUP_KEYNAME']);

  await knex.raw('UPDATE sessions SET refresh_expires_at = expires_at WHERE refresh_expires_at IS NULL');
};

exports.down = async function down(knex) {
  await tryRaw(knex, 'ALTER TABLE sessions DROP COLUMN csrf_token', ['ER_CANT_DROP_FIELD_OR_KEY']);
  await tryRaw(knex, 'ALTER TABLE sessions DROP COLUMN refresh_last_used_at', ['ER_CANT_DROP_FIELD_OR_KEY']);
  await tryRaw(knex, 'ALTER TABLE sessions DROP COLUMN refresh_expires_at', ['ER_CANT_DROP_FIELD_OR_KEY']);
  await tryRaw(knex, 'ALTER TABLE sessions DROP COLUMN refresh_token_hash', ['ER_CANT_DROP_FIELD_OR_KEY']);
  await tryRaw(knex, 'ALTER TABLE sessions DROP INDEX idx_refresh_expires', ['ER_CANT_DROP_FIELD_OR_KEY']);

  await tryRaw(knex, 'ALTER TABLE users DROP COLUMN mfa_totp_confirmed_at', ['ER_CANT_DROP_FIELD_OR_KEY']);
  await tryRaw(knex, 'ALTER TABLE users DROP COLUMN mfa_totp_enabled', ['ER_CANT_DROP_FIELD_OR_KEY']);
  await tryRaw(knex, 'ALTER TABLE users DROP COLUMN mfa_totp_secret', ['ER_CANT_DROP_FIELD_OR_KEY']);
  await knex.raw(`ALTER TABLE user_invites MODIFY role ENUM('admin', 'user', 'readonly') NOT NULL DEFAULT 'user'`);
  await knex.raw(`ALTER TABLE users MODIFY role ENUM('admin', 'user', 'readonly') DEFAULT 'user'`);
};
