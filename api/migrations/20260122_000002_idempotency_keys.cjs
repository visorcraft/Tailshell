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
    CREATE TABLE IF NOT EXISTS idempotency_keys (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        endpoint VARCHAR(100) NOT NULL,
        idempotency_key VARCHAR(128) NOT NULL,
        request_hash CHAR(64) NOT NULL,
        status_code INT NOT NULL,
        response_body JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uniq_idempotency (user_id, endpoint, idempotency_key),
        INDEX idx_idempotency_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);
};

exports.down = async function down(knex) {
  await tryRaw(knex, 'DROP TABLE IF EXISTS idempotency_keys', ['ER_BAD_TABLE_ERROR', 'ER_UNKNOWN_TABLE']);
};
