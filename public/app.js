'use strict';

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ CRYPTO MODULE ═══
// ═══════════════════════════════════════════════════════════════════════════════

const toB64   = bytes => btoa(String.fromCharCode(...bytes));
const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

const Crypto = {
  // Derive AES-GCM key from master password using PBKDF2
  async deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // Encrypt object → base64 string (iv prepended, 12 bytes)
  async encrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return btoa(String.fromCharCode(...combined));
  },

  // Decrypt base64 string → object
  async decrypt(key, encryptedData) {
    const combined = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(decrypted));
  },

  // Generate random salt (16 bytes)
  generateSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
  },

  // Hash master password for verification (export key material, SHA-256 it)
  async hashForVerification(key) {
    const exported = await crypto.subtle.exportKey('raw', key);
    const hash = await crypto.subtle.digest('SHA-256', exported);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  },

  // Auth key sent to the server at sign-in: a domain-separated HMAC of the AES key,
  // so the server can check the master password without ever learning the key.
  async deriveAuthKey(key) {
    const raw     = await crypto.subtle.exportKey('raw', key);
    const hmacKey = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig     = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode('pass-manager:auth:v1'));
    return toB64(new Uint8Array(sig));
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ PASSKEY UNLOCK ═══
// ═══════════════════════════════════════════════════════════════════════════════

// A passkey can stand in for the master password on this device. The WebAuthn
// PRF extension yields a secret only the authenticator can reproduce (after
// Face ID / Touch ID / PIN); it encrypts a copy of the vault key kept in
// localStorage. The server never sees any of it: unlocking still proves the key
// with the usual auth key, so the zero-knowledge model is unchanged.

const Passkey = {
  STORAGE_KEY: 'pm_passkey',   // { credId, salt, wrapped }

  supported() { return !!(window.PublicKeyCredential && navigator.credentials); },
  enrolled()  { return !!localStorage.getItem(this.STORAGE_KEY); },
  remove()    { localStorage.removeItem(this.STORAGE_KEY); },

  // AES key derived from the PRF output, used only to wrap the vault key.
  async wrappingKey(prfOutput) {
    const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('pass-manager:passkey-wrap:v1') },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  // Ask the authenticator for the PRF output of an existing credential.
  async evaluate(credId, salt) {
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: fromB64(credId) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: fromB64(salt) } } }
    }});
    const out = cred.getClientExtensionResults().prf?.results?.first;
    if (!out) throw new Error('this passkey does not support unlocking (PRF)');
    return new Uint8Array(out);
  },

  async store(credId, salt, prfOutput, masterKey) {
    const raw     = new Uint8Array(await crypto.subtle.exportKey('raw', masterKey));
    const wrapped = await Crypto.encrypt(await this.wrappingKey(prfOutput), toB64(raw));
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify({ credId, salt, wrapped }));
  },

  async enroll(masterKey, userId, username) {
    const salt = toB64(crypto.getRandomValues(new Uint8Array(32)));
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { name: 'Pass Manager' },
      user: { id: new TextEncoder().encode(userId), name: username, displayName: username },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      extensions: { prf: { eval: { first: fromB64(salt) } } }
    }});
    const prf    = cred.getClientExtensionResults().prf;
    const credId = toB64(new Uint8Array(cred.rawId));
    if (!prf?.results?.first && !prf?.enabled) {
      throw new Error('this browser or authenticator does not support passkey unlock (PRF). You can delete the passkey it just saved.');
    }
    // Some authenticators only evaluate PRF on sign-in, which costs a second prompt.
    const out = prf.results?.first ? new Uint8Array(prf.results.first) : await this.evaluate(credId, salt);
    await this.store(credId, salt, out, masterKey);
  },

  // Re-encrypt the stored copy after the master password changes.
  async rewrap(masterKey) {
    const { credId, salt } = JSON.parse(localStorage.getItem(this.STORAGE_KEY));
    await this.store(credId, salt, await this.evaluate(credId, salt), masterKey);
  },

  async unlock() {
    const { credId, salt, wrapped } = JSON.parse(localStorage.getItem(this.STORAGE_KEY));
    const out = await this.evaluate(credId, salt);
    const raw = await Crypto.decrypt(await this.wrappingKey(out), wrapped);
    return crypto.subtle.importKey('raw', fromB64(raw), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  }
};

// The user dismissed the OS passkey sheet (or the browser refused without a tap).
const isPasskeyCancel = err => err && (err.name === 'NotAllowedError' || err.name === 'AbortError');

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ LOCAL STORAGE (IndexedDB) ═══
// ═══════════════════════════════════════════════════════════════════════════════

const LocalDB = {
  db: null,

  async open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('pass-manager', 1);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('passwords')) {
          db.createObjectStore('passwords', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('meta')) {
          db.createObjectStore('meta', { keyPath: 'key' });
        }
      };
      req.onsuccess = e => { this.db = e.target.result; resolve(); };
      req.onerror   = e => reject(e.target.error);
    });
  },

  async getAll() {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('passwords', 'readonly');
      const req = tx.objectStore('passwords').getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror   = () => reject(req.error);
    });
  },

  async put(record) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('passwords', 'readwrite');
      const req = tx.objectStore('passwords').put(record);
      req.onsuccess = () => resolve();
      req.onerror   = () => reject(req.error);
    });
  },

  async delete(id) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('passwords', 'readwrite');
      const req = tx.objectStore('passwords').delete(id);
      req.onsuccess = () => resolve();
      req.onerror   = () => reject(req.error);
    });
  },

  async clear() {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('passwords', 'readwrite');
      const req = tx.objectStore('passwords').clear();
      req.onsuccess = () => resolve();
      req.onerror   = () => reject(req.error);
    });
  },

  async getMeta(key) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('meta', 'readonly');
      const req = tx.objectStore('meta').get(key);
      req.onsuccess = () => resolve(req.result ? req.result.value : null);
      req.onerror   = () => reject(req.error);
    });
  },

  async setMeta(key, value) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('meta', 'readwrite');
      const req = tx.objectStore('meta').put({ key, value });
      req.onsuccess = () => resolve();
      req.onerror   = () => reject(req.error);
    });
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ API CLIENT ═══
// ═══════════════════════════════════════════════════════════════════════════════

const API = {
  token: '',   // session token; held in memory only, issued on each unlock

  async request(method, path, body, { timeoutMs = 15000 } = {}) {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const headers = { 'Content-Type': 'application/json' };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    try {
      const res = await fetch(path, {
        method, headers, signal: ctrl.signal,
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        const err = new Error(json.error || `API error ${res.status}`);
        err.status = res.status;
        throw err;
      }
      return json;
    } finally {
      clearTimeout(timer);
    }
  },

  async health() {
    try {
      return await this.request('GET', '/api/health', undefined, { timeoutMs: 3000 });
    } catch {
      return null;
    }
  },

  prelogin(username)          { return this.request('POST',   '/api/auth/prelogin', { username }); },
  register(fields)            { return this.request('POST',   '/api/auth/register', fields); },
  login(username, authKey)    { return this.request('POST',   '/api/auth/login', { username, authKey }); },
  logout()                    { return this.request('POST',   '/api/auth/logout'); },
  changePassword(fields)      { return this.request('POST',   '/api/auth/change-password', fields); },
  deleteAccount(authKey)      { return this.request('DELETE', '/api/auth/account', { authKey }); },
  getAll()                    { return this.request('GET',    '/api/passwords'); },
  create(record)              { return this.request('POST',   '/api/passwords', { id: record.id, data: record.data }); },
  update(id, data)            { return this.request('PUT',    `/api/passwords/${encodeURIComponent(id)}`, { data }); },
  delete(id)                  { return this.request('DELETE', `/api/passwords/${encodeURIComponent(id)}`); },
  exportAll()                 { return this.request('GET',    '/api/export'); },
  importAll(passwords, merge) { return this.request('POST',   '/api/import', { passwords, merge }); }
};

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ APP STATE ═══
// ═══════════════════════════════════════════════════════════════════════════════

const state = {
  masterKey: null,         // CryptoKey object
  masterKeyHash: null,     // for re-verification
  passwords: [],           // decrypted password objects: { id, title, url, username, password, notes, created_at, updated_at }
  serverOnline: false,
  username: null,
  currentScreen: 'unlock',
  editingId: null,
  searchQuery: '',
  inactivityTimer: null,
  INACTIVITY_MS: 10 * 60 * 1000,  // 10 minutes
  passkeyPrompting: false,
  passkeyAutoTried: false   // auto-prompt at most once per lock, so a cancel doesn't loop
};

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ UI HELPERS ═══
// ═══════════════════════════════════════════════════════════════════════════════

function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3100);
}

function showScreen(name) {
  // Handle special case: add screen uses slide animation, not display toggling
  if (name === 'add') { openAddSlide(); return; }

  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));

  const target = document.getElementById(`screen-${name}`);
  if (target) {
    target.classList.add('active');
    state.currentScreen = name;
  }

  // Load settings fields when showing settings
  if (name === 'settings') loadSettingsFields();
  if (name === 'unlock') {
    document.getElementById('unlock-username').textContent = localStorage.getItem('pm_username') || '';
    document.getElementById('btn-passkey-unlock').style.display = Passkey.enrolled() ? '' : 'none';
  }
  if (name === 'setup') loadSignupOptions();
}

function openAddSlide() {
  document.getElementById('screen-add').classList.add('slide-in');
  state.currentScreen = 'add';
}

function closeAdd() {
  document.getElementById('screen-add').classList.remove('slide-in');
  state.currentScreen = 'main';
}

function togglePw(id, btn) {
  const input = document.getElementById(id);
  if (!input) return;
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  btn.textContent = showing ? '👁' : '🙈';
}

function toggleChangePwForm() {
  const f = document.getElementById('change-pw-form');
  f.classList.toggle('open');
}

function toggleGenPanel() {
  const p = document.getElementById('gen-panel');
  p.classList.toggle('open');
  if (p.classList.contains('open')) regenerate();
}

function toggleChip(id) {
  document.getElementById(id).classList.toggle('on');
}

// Confirm dialog
function confirmDialog(msg) {
  return new Promise(resolve => {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.innerHTML = `
      <div class="modal">
        <h3>Confirm</h3>
        <p>${msg}</p>
        <div class="modal-btns">
          <button class="btn btn-secondary" id="conf-no">Cancel</button>
          <button class="btn btn-danger" id="conf-yes">Confirm</button>
        </div>
      </div>`;
    document.body.appendChild(backdrop);
    backdrop.querySelector('#conf-yes').onclick = () => { backdrop.remove(); resolve(true); };
    backdrop.querySelector('#conf-no').onclick  = () => { backdrop.remove(); resolve(false); };
  });
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied to clipboard', 'success');
  } catch {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    showToast('Copied to clipboard', 'success');
  }
}

// Password strength
function calcStrength(pw) {
  if (!pw) return { score: 0, label: '' };
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const levels = [
    { label: '', color: 'transparent', pct: '0%' },
    { label: 'Very Weak', color: '#e74c3c', pct: '15%' },
    { label: 'Weak',      color: '#e67e22', pct: '30%' },
    { label: 'Fair',      color: '#f39c12', pct: '50%' },
    { label: 'Good',      color: '#2980b9', pct: '70%' },
    { label: 'Strong',    color: '#27ae60', pct: '85%' },
    { label: 'Very Strong', color: '#2ecc71', pct: '100%' },
    { label: 'Excellent', color: '#1abc9c', pct: '100%' },
  ];
  return levels[Math.min(score, levels.length - 1)];
}

function updateStrength(val, fillId = 'add-strength-fill', labelId = 'add-strength-label') {
  const s = calcStrength(val);
  const fill  = document.getElementById(fillId);
  const label = document.getElementById(labelId);
  if (fill)  { fill.style.width = s.pct; fill.style.background = s.color; }
  if (label) label.textContent = s.label;
}

// Favicon helpers
function faviconUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    return `https://www.google.com/s2/favicons?domain=${u.hostname}&sz=32`;
  } catch { return null; }
}

function faviconHtml(url, title) {
  const src = faviconUrl(url);
  if (src) {
    return `<img src="${src}" alt="${escHtml(title)}" onerror="this.parentElement.innerHTML='<span class=pw-favicon-fallback>🔑</span>'" loading="lazy">`;
  }
  return `<span class="pw-favicon-fallback">🔑</span>`;
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Inactivity timer
function resetInactivityTimer() {
  clearTimeout(state.inactivityTimer);
  if (!state.masterKey) return;
  state.inactivityTimer = setTimeout(() => {
    if (state.masterKey) {
      lockApp();
      showToast('Locked due to inactivity', 'info');
    }
  }, state.INACTIVITY_MS);
}

function lockApp() {
  if (API.token) API.logout().catch(() => {});
  API.token = '';
  state.masterKey = null;
  state.masterKeyHash = null;
  state.passwords = [];
  state.editingId = null;
  state.passkeyAutoTried = false;
  clearTimeout(state.inactivityTimer);
  closeAdd();
  showScreen('unlock');
  checkServerStatus();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ PASSWORD GENERATOR ═══
// ═══════════════════════════════════════════════════════════════════════════════

function generatePassword(length, opts) {
  const upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower   = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';

  let chars = '';
  if (opts.upper)   chars += upper;
  if (opts.lower)   chars += lower;
  if (opts.numbers) chars += numbers;
  if (opts.symbols) chars += symbols;

  if (!chars) chars = lower + numbers;

  let result = '';
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  for (let i = 0; i < length; i++) {
    result += chars[arr[i] % chars.length];
  }

  // Guarantee at least one of each selected type
  const required = [];
  if (opts.upper   && chars.includes(upper[0]))   required.push(upper[Math.floor(Math.random()*upper.length)]);
  if (opts.lower   && chars.includes(lower[0]))   required.push(lower[Math.floor(Math.random()*lower.length)]);
  if (opts.numbers && chars.includes(numbers[0])) required.push(numbers[Math.floor(Math.random()*numbers.length)]);
  if (opts.symbols && chars.includes(symbols[0])) required.push(symbols[Math.floor(Math.random()*symbols.length)]);

  // Splice required chars into random positions
  const arr2 = new Uint32Array(required.length);
  crypto.getRandomValues(arr2);
  let resultArr = result.split('');
  required.forEach((ch, i) => {
    const pos = arr2[i] % resultArr.length;
    resultArr[pos] = ch;
  });

  return resultArr.join('');
}

function regenerate() {
  const length = parseInt(document.getElementById('gen-length').value);
  const opts = {
    upper:   document.getElementById('chip-upper').classList.contains('on'),
    lower:   document.getElementById('chip-lower').classList.contains('on'),
    numbers: document.getElementById('chip-num').classList.contains('on'),
    symbols: document.getElementById('chip-sym').classList.contains('on')
  };
  const pw = generatePassword(length, opts);
  const input = document.getElementById('add-password');
  input.value = pw;
  input.type = 'text';
  updateStrength(pw);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ SCREEN RENDERERS ═══
// ═══════════════════════════════════════════════════════════════════════════════

function renderPasswordList() {
  const list = document.getElementById('pw-list');
  let items = state.passwords;

  if (state.searchQuery) {
    const q = state.searchQuery.toLowerCase();
    items = items.filter(p =>
      (p.title || '').toLowerCase().includes(q) ||
      (p.username || '').toLowerCase().includes(q) ||
      (p.url || '').toLowerCase().includes(q)
    );
  }

  // Sort: updated_at desc
  items = [...items].sort((a, b) => {
    const ta = a.updated_at ? new Date(a.updated_at).getTime() : 0;
    const tb = b.updated_at ? new Date(b.updated_at).getTime() : 0;
    return tb - ta;
  });

  if (items.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔐</div>
        <h3>${state.searchQuery ? 'No results' : 'No passwords yet'}</h3>
        <p>${state.searchQuery ? 'Try a different search' : 'Tap + to add your first password'}</p>
      </div>`;
    return;
  }

  list.innerHTML = items.map(p => `
    <div class="pw-card" onclick="openEdit('${escHtml(p.id)}')">
      <div class="pw-card-top">
        <div class="pw-favicon">${faviconHtml(p.url, p.title)}</div>
        <div class="pw-info">
          <div class="pw-title">${escHtml(p.title || 'Untitled')}</div>
          <div class="pw-username">${escHtml(p.username || '—')}</div>
        </div>
        <div class="pw-actions" onclick="event.stopPropagation()">
          <button class="btn btn-icon" title="Copy username"
                  onclick="copyToClipboard('${escHtml(p.username || '')}')">👤</button>
          <button class="btn btn-icon" title="Copy password"
                  onclick="copyPasswordById('${escHtml(p.id)}')">🔑</button>
        </div>
      </div>
    </div>`
  ).join('');
}

function copyPasswordById(id) {
  const p = state.passwords.find(x => x.id === id);
  if (p) copyToClipboard(p.password || '');
}

function updateServerBadge(online) {
  const badges = [
    document.getElementById('main-server-badge'),
    document.getElementById('unlock-server-badge')
  ];
  badges.forEach(b => {
    if (!b) return;
    if (online) {
      b.className = 'server-badge online';
      b.textContent = 'Server: Connected';
    } else {
      b.className = 'server-badge offline';
      b.textContent = 'Server: Offline (local mode)';
    }
  });
}

function loadSettingsFields() {
  document.getElementById('settings-username').textContent = state.username || '—';
  document.getElementById('passkey-group').style.display = Passkey.supported() ? '' : 'none';
  document.getElementById('btn-passkey').textContent = Passkey.enrolled()
    ? '🪪 Turn Off Passkey Unlock' : '🪪 Enable Passkey Unlock';
}

// Show the signup-code field only when the server asks for one.
async function loadSignupOptions() {
  const h = await API.health();
  document.getElementById('signup-code-group').style.display = h && h.signupCodeRequired ? '' : 'none';
}

function showSettings() {
  loadSettingsFields();
  showScreen('settings');
}

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ EVENT HANDLERS ═══
// ═══════════════════════════════════════════════════════════════════════════════

// ── Sign in / Create account ─────────────────────────────────────────────────

function switchSetupMode(mode) {
  document.getElementById('setup-mode-signin').style.display = mode === 'signin' ? '' : 'none';
  document.getElementById('setup-mode-create').style.display = mode === 'create' ? '' : 'none';
  document.getElementById('tab-signin').classList.toggle('active', mode === 'signin');
  document.getElementById('tab-create').classList.toggle('active', mode === 'create');
}

// Fetch the account's salt, derive keys and sign in. Returns null on bad credentials.
async function serverLogin(username, pw) {
  const { salt } = await API.prelogin(username);
  const key      = await Crypto.deriveKey(pw, fromB64(salt));
  const authKey  = await Crypto.deriveAuthKey(key);
  try {
    return { session: await API.login(username, authKey), key };
  } catch (err) {
    if (err.status === 401) return null;
    throw err;
  }
}

// After a successful sign-in or registration: remember the account on this device
// and load its vault. Signing in as a different account discards the old local cache.
async function startSession({ token, user, salt }, key) {
  if (localStorage.getItem('pm_user_id') !== user.id) await clearLocalData();

  const hash = await Crypto.hashForVerification(key);
  localStorage.setItem('pm_user_id',  user.id);
  localStorage.setItem('pm_username', user.username);
  localStorage.setItem('pm_salt',     salt);
  localStorage.setItem('pm_key_hash', hash);

  API.token           = token;
  state.username      = user.username;
  state.masterKey     = key;
  state.masterKeyHash = hash;
  state.serverOnline  = true;

  await loadPasswords();
  showScreen('main');
  renderPasswordList();
  resetInactivityTimer();
}

async function handleSignIn() {
  const username = document.getElementById('signin-username').value.trim().toLowerCase();
  const pw       = document.getElementById('signin-password').value;
  if (!username) return showToast('Username is required', 'error');
  if (!pw)       return showToast('Master password is required', 'error');

  showLoading('Signing in…');
  try {
    const h = await API.health();
    if (!h || h.status !== 'ok') {
      hideLoading();
      return showToast('Cannot reach the server', 'error');
    }

    const result = await serverLogin(username, pw);
    if (!result) {
      hideLoading();
      return showToast('Incorrect username or master password', 'error');
    }

    document.getElementById('signin-password').value = '';
    await startSession(result.session, result.key);
    hideLoading();
    showToast(`Signed in as ${result.session.user.username}`, 'success');
  } catch (err) {
    hideLoading();
    showToast('Sign in failed: ' + err.message, 'error');
    console.error(err);
  }
}

async function handleRegister() {
  const username = document.getElementById('create-username').value.trim().toLowerCase();
  const pw       = document.getElementById('setup-password').value;
  const confirm  = document.getElementById('setup-confirm').value;
  const code     = document.getElementById('create-signup-code').value.trim();

  if (!username) return showToast('Username is required', 'error');
  if (!pw) return showToast('Please enter a master password', 'error');
  if (pw.length < 8) return showToast('Password must be at least 8 characters', 'error');
  if (pw !== confirm) return showToast('Passwords do not match', 'error');

  showLoading('Creating your vault…');
  try {
    const h = await API.health();
    if (!h || h.status !== 'ok') {
      hideLoading();
      return showToast('Cannot reach the server', 'error');
    }

    const salt    = toB64(Crypto.generateSalt());
    const key     = await Crypto.deriveKey(pw, fromB64(salt));
    const authKey = await Crypto.deriveAuthKey(key);
    const session = await API.register({ username, salt, authKey, signupCode: code });

    document.getElementById('setup-password').value = '';
    document.getElementById('setup-confirm').value  = '';
    await startSession(session, key);
    hideLoading();
    showToast('Vault created! Welcome 🎉', 'success');
  } catch (err) {
    hideLoading();
    showToast('Could not create account: ' + err.message, 'error');
    console.error(err);
  }
}

// ── Unlock ───────────────────────────────────────────────────────────────────

// Online, the server verifies the password (so a password changed on another
// device takes effect here). Offline, the cached key hash is checked instead.
async function handleUnlock() {
  const pw       = document.getElementById('unlock-password').value;
  const username = localStorage.getItem('pm_username');
  if (!pw) return showToast('Please enter your master password', 'error');
  if (!username) return showScreen('setup');

  showLoading('Unlocking…');
  try {
    const h = await API.health();
    if (h && h.status === 'ok') {
      const result = await serverLogin(username, pw);
      if (!result) {
        hideLoading();
        return rejectUnlock();
      }
      document.getElementById('unlock-password').value = '';
      await startSession(result.session, result.key);
      hideLoading();
      return;
    }

    const key = await Crypto.deriveKey(pw, fromB64(localStorage.getItem('pm_salt')));
    if (!(await unlockOffline(key))) {
      hideLoading();
      return rejectUnlock();
    }
    document.getElementById('unlock-password').value = '';
    hideLoading();
  } catch (err) {
    hideLoading();
    showToast('Unlock failed: ' + err.message, 'error');
    console.error(err);
  }
}

// Open the vault from the local cache. Returns false if the key doesn't match it.
async function unlockOffline(key) {
  const hash = await Crypto.hashForVerification(key);
  if (hash !== localStorage.getItem('pm_key_hash')) return false;

  state.username      = localStorage.getItem('pm_username');
  state.masterKey     = key;
  state.masterKeyHash = hash;
  state.serverOnline  = false;
  await loadPasswords();
  showScreen('main');
  renderPasswordList();
  resetInactivityTimer();
  showToast('Server unreachable — using this device’s offline copy', 'info');
  return true;
}

// Unlock with the passkey enrolled on this device. `auto` is the prompt shown on
// its own when the unlock screen appears; cancelling that one stays quiet.
async function handlePasskeyUnlock({ auto = false } = {}) {
  if (state.passkeyPrompting || state.masterKey || !Passkey.enrolled()) return;
  state.passkeyPrompting = true;
  let key;
  try {
    key = await Passkey.unlock();
  } catch (err) {
    if (!isPasskeyCancel(err)) {
      showToast('Passkey unlock failed: ' + err.message, 'error');
      console.error(err);
    } else if (!auto) {
      showToast('Passkey unlock cancelled', 'info');
    }
    return;
  } finally {
    state.passkeyPrompting = false;
  }

  showLoading('Unlocking…');
  try {
    const username = localStorage.getItem('pm_username');
    const h = await API.health();
    let ok;
    if (h && h.status === 'ok') {
      try {
        await startSession(await API.login(username, await Crypto.deriveAuthKey(key)), key);
        ok = true;
      } catch (err) {
        if (err.status !== 401) throw err;
        ok = false;
      }
    } else {
      ok = await unlockOffline(key);
    }
    hideLoading();

    // The stored key is stale: the master password was changed on another device.
    if (!ok) {
      Passkey.remove();
      showScreen('unlock');
      showToast('Your master password changed — enter it, then re-enable passkey unlock in Settings', 'error');
    }
  } catch (err) {
    hideLoading();
    showToast('Unlock failed: ' + err.message, 'error');
    console.error(err);
  }
}

function autoPasskeyUnlock() {
  if (state.passkeyAutoTried || state.currentScreen !== 'unlock' || !Passkey.enrolled()) return;
  state.passkeyAutoTried = true;
  handlePasskeyUnlock({ auto: true });
}

async function handlePasskeyToggle() {
  if (Passkey.enrolled()) {
    const ok = await confirmDialog('Turn off passkey unlock on this device? You will need your master password to unlock.');
    if (!ok) return;
    Passkey.remove();
    loadSettingsFields();
    return showToast('Passkey unlock turned off', 'info');
  }

  try {
    await Passkey.enroll(state.masterKey, localStorage.getItem('pm_user_id'), state.username);
    loadSettingsFields();
    showToast('Passkey unlock enabled on this device', 'success');
  } catch (err) {
    if (isPasskeyCancel(err)) return showToast('Passkey setup cancelled', 'info');
    showToast('Could not enable passkey: ' + err.message, 'error');
    console.error(err);
  }
}

function rejectUnlock() {
  const wrap = document.getElementById('unlock-pw-wrap');
  wrap.classList.add('shake');
  setTimeout(() => wrap.classList.remove('shake'), 500);
  showToast('Incorrect master password', 'error');
}

async function handleSignOut() {
  const unsynced = pendingList('pm_pending_writes').length + pendingList('pm_pending_deletes').length;
  const ok = await confirmDialog(unsynced
    ? `Sign out? ${unsynced} change(s) on this device haven't synced to the server and will be lost.`
    : 'Sign out of this device? Your vault stays on the server.');
  if (!ok) return;

  if (API.token) await API.logout().catch(() => {});
  API.token = '';
  await clearLocalData();
  resetState();
  showScreen('setup');
  switchSetupMode('signin');
}

// ── Load passwords ───────────────────────────────────────────────────────────

async function loadPasswords() {
  updateServerBadge(state.serverOnline);
  if (!state.serverOnline) return loadFromLocal();

  try {
    // Push offline changes first; only then is the server copy authoritative.
    const unsynced = await syncPending();
    if (unsynced) throw new Error(`${unsynced} offline change(s) could not sync`);

    const rows = await API.getAll();
    await LocalDB.clear();
    state.passwords = [];
    for (const row of rows) {
      await LocalDB.put({ id: row.id, data: row.data, created_at: row.created_at, updated_at: row.updated_at });
      try {
        const decrypted = await Crypto.decrypt(state.masterKey, row.data);
        state.passwords.push({ id: row.id, ...decrypted, created_at: row.created_at, updated_at: row.updated_at });
      } catch (e) {
        console.warn('Failed to decrypt entry', row.id, e);
      }
    }
    const lbl = document.getElementById('last-synced-label');
    if (lbl) lbl.textContent = `Synced ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    console.error('Server load failed, falling back to local', err);
    state.serverOnline = false;
    updateServerBadge(false);
    showToast('Sync failed — showing this device’s offline copy', 'info');
    await loadFromLocal();
  }
}

async function loadFromLocal() {
  const rows = await LocalDB.getAll();
  state.passwords = [];
  for (const row of rows) {
    try {
      const decrypted = await Crypto.decrypt(state.masterKey, row.data);
      state.passwords.push({ id: row.id, ...decrypted, created_at: row.created_at, updated_at: row.updated_at });
    } catch (e) {
      console.warn('Failed to decrypt local entry', row.id, e);
    }
  }
}

// Push offline changes to the server. Anything that fails stays queued.
// Returns how many changes are still unsynced.
async function syncPending() {
  const failedDeletes = [];
  for (const id of pendingList('pm_pending_deletes')) {
    try {
      await API.delete(id);
    } catch (e) {
      if (e.status !== 404) failedDeletes.push(id);
    }
  }
  setPendingList('pm_pending_deletes', failedDeletes);

  const localRows = await LocalDB.getAll();
  const failedWrites = [];
  for (const id of pendingList('pm_pending_writes')) {
    const row = localRows.find(r => r.id === id);
    if (!row) continue;
    try {
      await API.create(row); // server-side upsert
    } catch (e) {
      console.warn('Pending write failed', id, e);
      failedWrites.push(id);
    }
  }
  setPendingList('pm_pending_writes', failedWrites);

  return failedDeletes.length + failedWrites.length;
}

// ── Add / Edit / Delete ──────────────────────────────────────────────────────

function showAdd() {
  state.editingId = null;
  document.getElementById('add-screen-title').textContent = 'Add Password';
  document.getElementById('add-title').value    = '';
  document.getElementById('add-url').value      = '';
  document.getElementById('add-username').value = '';
  document.getElementById('add-password').value = '';
  document.getElementById('add-password').type  = 'password';
  document.getElementById('add-notes').value    = '';
  document.getElementById('btn-delete').style.display = 'none';
  document.getElementById('gen-panel').classList.remove('open');
  updateStrength('');
  showScreen('add');
}

function openEdit(id) {
  const p = state.passwords.find(x => x.id === id);
  if (!p) return;
  state.editingId = id;

  document.getElementById('add-screen-title').textContent = 'Edit Password';
  document.getElementById('add-title').value    = p.title    || '';
  document.getElementById('add-url').value      = p.url      || '';
  document.getElementById('add-username').value = p.username || '';
  document.getElementById('add-password').value = p.password || '';
  document.getElementById('add-password').type  = 'password';
  document.getElementById('add-notes').value    = p.notes    || '';
  document.getElementById('btn-delete').style.display = 'block';
  document.getElementById('gen-panel').classList.remove('open');
  updateStrength(p.password || '');
  showScreen('add');
}

async function handleSave() {
  const title    = document.getElementById('add-title').value.trim();
  const url      = document.getElementById('add-url').value.trim();
  const username = document.getElementById('add-username').value.trim();
  const password = document.getElementById('add-password').value;
  const notes    = document.getElementById('add-notes').value.trim();

  if (!title) return showToast('Title is required', 'error');
  if (!password) return showToast('Password is required', 'error');

  const payload = { title, url, username, password, notes };

  try {
    const encryptedData = await Crypto.encrypt(state.masterKey, payload);
    const now = new Date().toISOString();

    if (state.editingId) {
      // Update
      const record = {
        id: state.editingId,
        data: encryptedData,
        created_at: state.passwords.find(p => p.id === state.editingId)?.created_at || now,
        updated_at: now
      };

      await LocalDB.put(record);

      if (state.serverOnline) {
        try {
          await API.update(state.editingId, encryptedData);
        } catch (e) {
          addPendingWrite(state.editingId);
          showToast('Saved locally (server sync failed)', 'info');
        }
      } else {
        addPendingWrite(state.editingId);
      }

      // Update in state
      const idx = state.passwords.findIndex(p => p.id === state.editingId);
      if (idx !== -1) {
        state.passwords[idx] = { id: state.editingId, ...payload, created_at: record.created_at, updated_at: now };
      }
    } else {
      // Create
      const id = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const record = { id, data: encryptedData, created_at: now, updated_at: now };

      await LocalDB.put(record);

      if (state.serverOnline) {
        try {
          await API.create(record);
        } catch (e) {
          addPendingWrite(id);
          showToast('Saved locally (server sync failed)', 'info');
        }
      } else {
        addPendingWrite(id);
      }

      state.passwords.unshift({ id, ...payload, created_at: now, updated_at: now });
    }

    closeAdd();
    renderPasswordList();
    showToast(state.editingId ? 'Password updated' : 'Password saved', 'success');
    state.editingId = null;
  } catch (err) {
    showToast('Save failed: ' + err.message, 'error');
    console.error(err);
  }
}

async function handleDelete() {
  const ok = await confirmDialog('Delete this password? This cannot be undone.');
  if (!ok) return;

  const id = state.editingId;
  if (!id) return;

  try {
    await LocalDB.delete(id);

    if (state.serverOnline) {
      try {
        await API.delete(id);
      } catch (e) {
        addPendingDelete(id);
      }
    } else {
      addPendingDelete(id);
    }

    state.passwords = state.passwords.filter(p => p.id !== id);
    state.editingId = null;
    closeAdd();
    renderPasswordList();
    showToast('Password deleted', 'info');
  } catch (err) {
    showToast('Delete failed: ' + err.message, 'error');
    console.error(err);
  }
}

function pendingList(key) {
  return JSON.parse(localStorage.getItem(key) || '[]');
}

function setPendingList(key, ids) {
  if (ids.length) localStorage.setItem(key, JSON.stringify(ids));
  else localStorage.removeItem(key);
}

function addPendingWrite(id) {
  const writes = pendingList('pm_pending_writes');
  if (!writes.includes(id)) writes.push(id);
  setPendingList('pm_pending_writes', writes);
}

function addPendingDelete(id) {
  const dels = pendingList('pm_pending_deletes');
  if (!dels.includes(id)) dels.push(id);
  setPendingList('pm_pending_deletes', dels);
  // A queued delete supersedes any queued write for the same entry.
  setPendingList('pm_pending_writes', pendingList('pm_pending_writes').filter(x => x !== id));
}

// ── Search ───────────────────────────────────────────────────────────────────

function handleSearch(q) {
  state.searchQuery = q;
  renderPasswordList();
}

// ── Export / Import ──────────────────────────────────────────────────────────

async function handleExport() {
  try {
    let exportData;
    if (state.serverOnline) {
      exportData = await API.exportAll();
    } else {
      const rows = await LocalDB.getAll();
      exportData = { passwords: rows, exportedAt: new Date().toISOString() };
    }

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `pass-manager-backup-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Backup downloaded', 'success');
  } catch (err) {
    showToast('Export failed: ' + err.message, 'error');
    console.error(err);
  }
}

async function handleImport(input) {
  const file = input.files[0];
  if (!file) return;
  const mode = document.querySelector('input[name="import-mode"]:checked')?.value || 'merge';
  const merge = mode === 'merge';

  try {
    const text = await file.text();
    const json = JSON.parse(text);
    const passwords = json.passwords || (Array.isArray(json) ? json : null);
    if (!passwords) return showToast('Invalid backup file', 'error');

    // Validate decryptability
    let validCount = 0;
    for (const row of passwords) {
      try {
        await Crypto.decrypt(state.masterKey, row.data);
        validCount++;
      } catch {
        // Skip invalid entries
      }
    }

    if (validCount === 0) return showToast('No valid entries found (wrong master password?)', 'error');

    const ok = await confirmDialog(
      `Import ${validCount} entries? Mode: ${merge ? 'Merge' : 'Replace all'}`
    );
    if (!ok) { input.value = ''; return; }

    const validRows = [];
    for (const row of passwords) {
      try {
        await Crypto.decrypt(state.masterKey, row.data);
        validRows.push(row);
      } catch { /* skip */ }
    }

    if (!merge) await LocalDB.clear();
    for (const row of validRows) {
      await LocalDB.put(row);
    }

    if (state.serverOnline) {
      await API.importAll(validRows, merge);
    }

    // Reload
    await loadFromLocal();
    renderPasswordList();
    input.value = '';
    showToast(`Imported ${validCount} entries`, 'success');
  } catch (err) {
    showToast('Import failed: ' + err.message, 'error');
    console.error(err);
    input.value = '';
  }
}

// ── Change master password ───────────────────────────────────────────────────

async function handleChangePw() {
  const current = document.getElementById('cpw-current').value;
  const newPw   = document.getElementById('cpw-new').value;
  const confirm = document.getElementById('cpw-confirm').value;

  if (!current || !newPw || !confirm) return showToast('Fill all fields', 'error');
  if (newPw !== confirm) return showToast('New passwords do not match', 'error');
  if (newPw.length < 8) return showToast('New password must be at least 8 characters', 'error');
  if (!state.serverOnline) return showToast('Connect to the server to change your master password', 'error');

  showLoading('Re-encrypting vault…');
  try {
    const currentKey  = await Crypto.deriveKey(current, fromB64(localStorage.getItem('pm_salt')));
    const currentHash = await Crypto.hashForVerification(currentKey);
    if (currentHash !== state.masterKeyHash) {
      hideLoading();
      return showToast('Current password is incorrect', 'error');
    }

    // Re-encrypt the server's copy, so entries added on other devices are included.
    if (await syncPending()) throw new Error('some offline changes could not sync — try again');
    const rows = await API.getAll();

    const newSalt = toB64(Crypto.generateSalt());
    const newKey  = await Crypto.deriveKey(newPw, fromB64(newSalt));
    const reencrypted = [];
    for (const row of rows) {
      let decrypted;
      try {
        decrypted = await Crypto.decrypt(currentKey, row.data);
      } catch {
        throw new Error('an entry could not be decrypted, so nothing was changed');
      }
      reencrypted.push({ ...row, data: await Crypto.encrypt(newKey, decrypted) });
    }

    await API.changePassword({
      currentAuthKey: await Crypto.deriveAuthKey(currentKey),
      salt:           newSalt,
      authKey:        await Crypto.deriveAuthKey(newKey),
      passwords:      reencrypted.map(r => ({ id: r.id, data: r.data }))
    });

    const newHash = await Crypto.hashForVerification(newKey);
    localStorage.setItem('pm_salt',     newSalt);
    localStorage.setItem('pm_key_hash', newHash);
    state.masterKey     = newKey;
    state.masterKeyHash = newHash;

    await LocalDB.clear();
    state.passwords = [];
    for (const row of reencrypted) {
      await LocalDB.put(row);
      const decrypted = await Crypto.decrypt(newKey, row.data);
      state.passwords.push({ id: row.id, ...decrypted, created_at: row.created_at, updated_at: row.updated_at });
    }

    hideLoading();
    document.getElementById('cpw-current').value = '';
    document.getElementById('cpw-new').value     = '';
    document.getElementById('cpw-confirm').value = '';
    document.getElementById('change-pw-form').classList.remove('open');
    renderPasswordList();
    showToast('Master password updated — other devices must sign in again', 'success');

    // The passkey's copy of the key is now stale; re-encrypt it (one more prompt).
    if (Passkey.enrolled()) {
      try {
        await Passkey.rewrap(newKey);
      } catch (err) {
        Passkey.remove();
        loadSettingsFields();
        showToast('Passkey unlock was turned off — enable it again below', 'info');
        if (!isPasskeyCancel(err)) console.error(err);
      }
    }
  } catch (err) {
    hideLoading();
    showToast('Failed: ' + err.message, 'error');
    console.error(err);
  }
}

// ── Delete account / local cleanup ───────────────────────────────────────────

async function handleDeleteAccount() {
  if (!state.serverOnline) return showToast('Connect to the server to delete your account', 'error');
  const ok = await confirmDialog(
    `Permanently delete the account "${state.username}" and every password in it? This CANNOT be undone.`
  );
  if (!ok) return;

  showLoading('Deleting account…');
  try {
    await API.deleteAccount(await Crypto.deriveAuthKey(state.masterKey));
    API.token = '';
    await clearLocalData();
    resetState();
    hideLoading();
    showScreen('setup');
    switchSetupMode('create');
    showToast('Account deleted', 'info');
  } catch (err) {
    hideLoading();
    showToast('Delete failed: ' + err.message, 'error');
    console.error(err);
  }
}

// Forget the account on this device (the server copy is untouched).
async function clearLocalData() {
  ['pm_user_id', 'pm_username', 'pm_salt', 'pm_key_hash', 'pm_pending_deletes', 'pm_pending_writes',
   Passkey.STORAGE_KEY, 'pm_server_url', 'pm_server_key'] // last two: left over from the single-vault version
    .forEach(k => localStorage.removeItem(k));
  await LocalDB.clear().catch(() => {});
}

function resetState() {
  state.masterKey     = null;
  state.masterKeyHash = null;
  state.passwords     = [];
  state.editingId     = null;
  state.serverOnline  = false;
  state.username      = null;
  clearTimeout(state.inactivityTimer);
  closeAdd();
}

// ── Server status check (for unlock screen) ───────────────────────────────────

async function checkServerStatus() {
  const badge = document.getElementById('unlock-server-badge');
  if (badge) { badge.className = 'server-badge offline'; badge.textContent = 'Checking server…'; }

  const h = await API.health();
  const online = !!(h && h.status === 'ok');

  if (badge) {
    badge.className = online ? 'server-badge online' : 'server-badge offline';
    badge.textContent = online ? 'Server: Connected' : 'Server: Offline (local mode)';
  }
}

// ── Loading overlay ──────────────────────────────────────────────────────────

function showLoading(msg = 'Loading…') {
  const overlay = document.getElementById('loading-overlay');
  overlay.querySelector('p').textContent = msg;
  overlay.style.display = 'flex';
}

function hideLoading() {
  document.getElementById('loading-overlay').style.display = 'none';
}

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ INITIALIZATION ═══
// ═══════════════════════════════════════════════════════════════════════════════

async function init() {
  // Web Crypto needs a secure context: HTTPS, or http://localhost in development.
  if (!window.isSecureContext) {
    hideLoading();
    document.body.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;
                  min-height:100vh;padding:2rem;background:#0f0f23;color:#e8e8f0;text-align:center;font-family:sans-serif;">
        <div style="font-size:3rem;margin-bottom:1rem;">🔒</div>
        <h2 style="color:#6c63ff;margin-bottom:1rem">HTTPS Required</h2>
        <p style="color:#a0a0c0;max-width:360px;line-height:1.6">
          This app encrypts your passwords in the browser, which only works over HTTPS.
          Open it from its https:// address.
        </p>
      </div>`;
    return;
  }

  showLoading('Starting…');

  try {
    // Open IndexedDB
    await LocalDB.open();

    // Register service worker
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/sw.js').catch(e => console.warn('SW reg failed', e));
    }

    // A remembered account goes to unlock; otherwise sign in / create account.
    hideLoading();
    if (localStorage.getItem('pm_username')) {
      showScreen('unlock');
      checkServerStatus();
      autoPasskeyUnlock();
    } else {
      showScreen('setup');
    }

    // Inactivity listeners
    ['click','keypress','touchstart','mousemove'].forEach(ev => {
      document.addEventListener(ev, resetInactivityTimer, { passive: true });
    });

    // Lock when tab hidden
    document.addEventListener('visibilitychange', () => {
      if (document.hidden && state.masterKey) {
        lockApp();
      } else if (!document.hidden) {
        autoPasskeyUnlock();
      }
    });

    // Password strength on setup screen
    document.getElementById('setup-password').addEventListener('input', function() {
      updateStrength(this.value, 'setup-strength-fill', 'setup-strength-label');
    });

  } catch (err) {
    hideLoading();
    showToast('Startup error: ' + err.message, 'error');
    console.error(err);
  }
}

// Start
init();
