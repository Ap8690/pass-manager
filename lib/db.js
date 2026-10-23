'use strict';

const { Pool } = require('pg');

const DEFAULT_URL = 'postgres://postgres:postgres@localhost:5432/pass_manager';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || DEFAULT_URL,
  // Serverless instances each hold their own pool — keep it small there.
  max: process.env.VERCEL ? 3 : 10,
});

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username   text NOT NULL UNIQUE,
    salt       text NOT NULL,
    auth_hash  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash text PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
  CREATE TABLE IF NOT EXISTS passwords (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id         text NOT NULL,
    data       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
  );
  CREATE TABLE IF NOT EXISTS login_attempts (
    key          text PRIMARY KEY,
    failures     integer NOT NULL DEFAULT 0,
    window_start timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS app_meta (
    key   text PRIMARY KEY,
    value text NOT NULL
  );
`;

let schemaReady = null;

// Runs once per process. The advisory lock stops concurrent cold starts
// from racing each other on CREATE TABLE IF NOT EXISTS.
function ensureSchema() {
  if (!schemaReady) {
    schemaReady = transaction(async client => {
      await client.query('SELECT pg_advisory_xact_lock(727274)');
      await client.query(SCHEMA);
    }).catch(err => { schemaReady = null; throw err; });
  }
  return schemaReady;
}

async function transaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

function query(text, params) {
  return pool.query(text, params);
}

// For logs: the connection target with any password masked.
function describeTarget() {
  try {
    const u = new URL(process.env.DATABASE_URL || DEFAULT_URL);
    if (u.password) u.password = '****';
    return u.toString();
  } catch {
    return '(unparseable DATABASE_URL)';
  }
}

module.exports = { pool, query, transaction, ensureSchema, describeTarget };
