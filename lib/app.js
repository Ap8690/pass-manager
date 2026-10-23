'use strict';

// API for the password manager. Exported as a plain Express app so it can be
// mounted by the local server (server.js) or run as a Vercel function (api/index.js).
//
// Zero-knowledge model: the browser derives an AES key from the master password
// and never sends it. It sends only an "auth key" (an HMAC of that AES key), which
// the server hashes again with scrypt before storing. Vault entries arrive already
// encrypted and are stored as opaque blobs.

const express = require('express');
const crypto  = require('crypto');
const { promisify } = require('util');
const db = require('./db');

const scrypt = promisify(crypto.scrypt);

const SESSION_TTL_MS     = 24 * 60 * 60 * 1000;
const LOGIN_WINDOW_MIN   = 15;
const LOGIN_MAX_FAILURES = 10;
const USERNAME_RE        = /^[a-z0-9._@+-]{3,64}$/;

const app = express();

// Vercel sets X-Forwarded-For itself; locally there is no proxy to trust.
app.set('trust proxy', process.env.VERCEL ? 1 : false);
app.disable('x-powered-by');
app.use(express.json({ limit: '4mb' }));

app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// Express 4 doesn't catch rejected promises from async handlers.
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

app.use('/api', wrap(async (_req, _res, next) => {
  await db.ensureSchema();
  next();
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function normalizeUsername(raw) {
  const u = String(raw || '').trim().toLowerCase();
  if (!USERNAME_RE.test(u)) {
    throw new HttpError(400, 'Username must be 3–64 characters: letters, numbers, . _ @ + -');
  }
  return u;
}

function decodeB64(value, bytes, field) {
  const buf = Buffer.from(String(value || ''), 'base64');
  if (buf.length !== bytes) throw new HttpError(400, `${field} is malformed`);
  return buf;
}

async function hashAuthKey(authKeyBuf) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(authKeyBuf, salt, 32);
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}

async function verifyAuthKey(authKeyBuf, stored) {
  const [scheme, saltB64, hashB64] = String(stored).split('$');
  if (scheme !== 'scrypt') return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual   = await scrypt(authKeyBuf, Buffer.from(saltB64, 'base64'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  await db.query(
    'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)',
    [sha256(token), userId, new Date(Date.now() + SESSION_TTL_MS)]
  );
  // Opportunistic cleanup; cheap with the primary key + small table.
  await db.query('DELETE FROM sessions WHERE expires_at < now()');
  return token;
}

// Per-deployment secret, generated on first use, used to derive stable decoy
// salts so /prelogin doesn't reveal which usernames exist.
let decoySecret = null;
async function getDecoySecret() {
  if (decoySecret) return decoySecret;
  await db.query(
    "INSERT INTO app_meta (key, value) VALUES ('decoy_salt_secret', $1) ON CONFLICT (key) DO NOTHING",
    [crypto.randomBytes(32).toString('hex')]
  );
  const { rows } = await db.query("SELECT value FROM app_meta WHERE key = 'decoy_salt_secret'");
  decoySecret = rows[0].value;
  return decoySecret;
}

async function decoySalt(username) {
  const secret = await getDecoySecret();
  return crypto.createHmac('sha256', secret).update(username).digest().subarray(0, 16).toString('base64');
}

function attemptKey(req, username) {
  return `${req.ip || 'unknown'}|${username}`;
}

async function assertNotRateLimited(key) {
  const { rows } = await db.query(
    `SELECT failures FROM login_attempts
      WHERE key = $1 AND window_start > now() - make_interval(mins => $2)`,
    [key, LOGIN_WINDOW_MIN]
  );
  if (rows[0] && rows[0].failures >= LOGIN_MAX_FAILURES) {
    throw new HttpError(429, `Too many failed attempts. Try again in ${LOGIN_WINDOW_MIN} minutes.`);
  }
}

async function recordFailure(key) {
  await db.query(
    `INSERT INTO login_attempts (key, failures, window_start) VALUES ($1, 1, now())
     ON CONFLICT (key) DO UPDATE SET
       failures     = CASE WHEN login_attempts.window_start > now() - make_interval(mins => $2)
                           THEN login_attempts.failures + 1 ELSE 1 END,
       window_start = CASE WHEN login_attempts.window_start > now() - make_interval(mins => $2)
                           THEN login_attempts.window_start ELSE now() END`,
    [key, LOGIN_WINDOW_MIN]
  );
}

function toTimestamp(value) {
  const t = Date.parse(value);
  return Number.isNaN(t) ? new Date() : new Date(t);
}

function publicUser(row) {
  return { id: row.id, username: row.username };
}

// ── Auth middleware ───────────────────────────────────────────────────────────

const requireAuth = wrap(async (req, _res, next) => {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) throw new HttpError(401, 'Unauthorized');
  const { rows } = await db.query(
    `SELECT u.id, u.username, u.salt, u.auth_hash FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [sha256(m[1])]
  );
  if (!rows[0]) throw new HttpError(401, 'Unauthorized');
  req.user = rows[0];
  req.tokenHash = sha256(m[1]);
  next();
});

async function assertAuthKey(user, authKeyB64) {
  const ok = await verifyAuthKey(decodeB64(authKeyB64, 32, 'authKey'), user.auth_hash);
  if (!ok) throw new HttpError(403, 'Master password is incorrect');
}

// ── Public routes ─────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', name: 'pass-manager', signupCodeRequired: !!process.env.SIGNUP_CODE });
});

app.post('/api/auth/prelogin', wrap(async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const { rows } = await db.query('SELECT salt FROM users WHERE username = $1', [username]);
  res.json({ salt: rows[0] ? rows[0].salt : await decoySalt(username) });
}));

app.post('/api/auth/register', wrap(async (req, res) => {
  const { salt, authKey, signupCode } = req.body;
  const username = normalizeUsername(req.body.username);

  const required = process.env.SIGNUP_CODE;
  if (required) {
    const given = Buffer.from(String(signupCode || ''));
    const want  = Buffer.from(required);
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
      throw new HttpError(403, 'Invalid signup code');
    }
  }

  decodeB64(salt, 16, 'salt');
  const authHash = await hashAuthKey(decodeB64(authKey, 32, 'authKey'));

  const { rows } = await db.query(
    `INSERT INTO users (username, salt, auth_hash) VALUES ($1, $2, $3)
     ON CONFLICT (username) DO NOTHING RETURNING id, username`,
    [username, salt, authHash]
  );
  if (!rows[0]) throw new HttpError(409, 'That username is taken');

  const token = await createSession(rows[0].id);
  res.status(201).json({ token, user: publicUser(rows[0]), salt });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const authKey  = decodeB64(req.body.authKey, 32, 'authKey');
  const key      = attemptKey(req, username);

  await assertNotRateLimited(key);

  const { rows } = await db.query('SELECT id, username, salt, auth_hash FROM users WHERE username = $1', [username]);
  const user = rows[0];
  if (!user || !(await verifyAuthKey(authKey, user.auth_hash))) {
    await recordFailure(key);
    throw new HttpError(401, 'Incorrect username or master password');
  }

  await db.query('DELETE FROM login_attempts WHERE key = $1', [key]);
  const token = await createSession(user.id);
  res.json({ token, user: publicUser(user), salt: user.salt });
}));

// ── Account routes ────────────────────────────────────────────────────────────

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user), salt: req.user.salt });
});

app.post('/api/auth/logout', requireAuth, wrap(async (req, res) => {
  await db.query('DELETE FROM sessions WHERE token_hash = $1', [req.tokenHash]);
  res.json({ ok: true });
}));

// Re-key the vault: new salt + auth key, and every entry re-encrypted client-side.
// The submitted entry ids must match the server exactly, so a stale client can't
// silently drop entries that were added from another device.
app.post('/api/auth/change-password', requireAuth, wrap(async (req, res) => {
  const { currentAuthKey, salt, authKey, passwords } = req.body;
  await assertAuthKey(req.user, currentAuthKey);
  decodeB64(salt, 16, 'salt');
  const authHash = await hashAuthKey(decodeB64(authKey, 32, 'authKey'));
  if (!Array.isArray(passwords) || passwords.some(p => !p || !p.id || !p.data)) {
    throw new HttpError(400, 'passwords array required');
  }

  await db.transaction(async client => {
    const { rows } = await client.query(
      'SELECT id FROM passwords WHERE user_id = $1 FOR UPDATE', [req.user.id]
    );
    const serverIds = new Set(rows.map(r => r.id));
    const sentIds   = new Set(passwords.map(p => p.id));
    if (serverIds.size !== sentIds.size || [...serverIds].some(id => !sentIds.has(id))) {
      throw new HttpError(409, 'Your vault changed on another device. Reload and try again.');
    }

    await client.query(
      'UPDATE users SET salt = $1, auth_hash = $2, updated_at = now() WHERE id = $3',
      [salt, authHash, req.user.id]
    );
    for (const p of passwords) {
      await client.query(
        'UPDATE passwords SET data = $1, updated_at = now() WHERE user_id = $2 AND id = $3',
        [p.data, req.user.id, p.id]
      );
    }
    // Other devices must sign in again with the new password.
    await client.query(
      'DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2', [req.user.id, req.tokenHash]
    );
  });

  res.json({ ok: true });
}));

app.delete('/api/auth/account', requireAuth, wrap(async (req, res) => {
  await assertAuthKey(req.user, req.body.authKey);
  await db.query('DELETE FROM users WHERE id = $1', [req.user.id]);
  res.json({ ok: true });
}));

// ── Vault routes (always scoped to the signed-in user) ────────────────────────

const ROW_COLS = 'id, data, created_at, updated_at';

app.get('/api/passwords', requireAuth, wrap(async (req, res) => {
  const { rows } = await db.query(
    `SELECT ${ROW_COLS} FROM passwords WHERE user_id = $1 ORDER BY updated_at DESC`, [req.user.id]
  );
  res.json(rows);
}));

app.post('/api/passwords', requireAuth, wrap(async (req, res) => {
  const { id, data } = req.body;
  if (!id || !data) throw new HttpError(400, 'id and data required');
  const { rows } = await db.query(
    `INSERT INTO passwords (user_id, id, data) VALUES ($1, $2, $3)
     ON CONFLICT (user_id, id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()
     RETURNING ${ROW_COLS}`,
    [req.user.id, String(id), data]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/passwords/:id', requireAuth, wrap(async (req, res) => {
  const { data } = req.body;
  if (!data) throw new HttpError(400, 'data required');
  const { rows } = await db.query(
    `UPDATE passwords SET data = $1, updated_at = now() WHERE user_id = $2 AND id = $3
     RETURNING ${ROW_COLS}`,
    [data, req.user.id, req.params.id]
  );
  if (!rows[0]) throw new HttpError(404, 'Not found');
  res.json(rows[0]);
}));

app.delete('/api/passwords/:id', requireAuth, wrap(async (req, res) => {
  const { rowCount } = await db.query(
    'DELETE FROM passwords WHERE user_id = $1 AND id = $2', [req.user.id, req.params.id]
  );
  if (rowCount === 0) throw new HttpError(404, 'Not found');
  res.json({ success: true });
}));

app.get('/api/export', requireAuth, wrap(async (req, res) => {
  const { rows } = await db.query(
    `SELECT ${ROW_COLS} FROM passwords WHERE user_id = $1 ORDER BY updated_at DESC`, [req.user.id]
  );
  res.json({
    passwords: rows,
    salt: req.user.salt,
    username: req.user.username,
    exportedAt: new Date().toISOString(),
  });
}));

app.post('/api/import', requireAuth, wrap(async (req, res) => {
  const { passwords, merge } = req.body;
  if (!Array.isArray(passwords)) throw new HttpError(400, 'passwords array required');

  const count = await db.transaction(async client => {
    if (!merge) await client.query('DELETE FROM passwords WHERE user_id = $1', [req.user.id]);
    for (const p of passwords) {
      if (!p || !p.id || !p.data) continue;
      await client.query(
        `INSERT INTO passwords (user_id, id, data, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id, id) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at`,
        [req.user.id, String(p.id), p.data, toTimestamp(p.created_at), toTimestamp(p.updated_at)]
      );
    }
    const { rows } = await client.query(
      'SELECT COUNT(*)::int AS c FROM passwords WHERE user_id = $1', [req.user.id]
    );
    return rows[0].c;
  });

  res.json({ success: true, count });
}));

app.use('/api', (_req, _res, next) => next(new HttpError(404, 'Not found')));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;
