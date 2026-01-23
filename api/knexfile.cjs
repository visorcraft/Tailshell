module.exports = {
  client: 'mysql2',
  connection: {
    host: process.env.DATABASE_HOST,
    port: parseInt(process.env.DATABASE_PORT || '3306', 10),
    database: process.env.DATABASE_NAME,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD
  },
  migrations: {
    directory: './migrations',
    tableName: 'knex_migrations'
  }
};

