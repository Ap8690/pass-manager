'use strict';

// Local dev server. In production, Vercel serves public/ and runs api/index.js instead.
// http://localhost counts as a secure context, so Web Crypto works here without HTTPS.

const express = require('express');
const path    = require('path');
const api     = require('./lib/app');
const db      = require('./lib/db');

const PORT = parseInt(process.env.PORT || '3000');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(api);

async function main() {
  try {
    await db.ensureSchema();
  } catch (err) {
    console.error(`Cannot connect to Postgres at ${db.describeTarget()}`);
    console.error(`  ${err.message}`);
    console.error('Set DATABASE_URL (e.g. in .env) to a reachable database.');
    process.exit(1);
  }

  app.listen(PORT, 'localhost', () => {
    console.log(`Pass Manager running at http://localhost:${PORT}`);
    console.log(`Database: ${db.describeTarget()}`);
  });
}

main().catch(err => { console.error('Startup error:', err); process.exit(1); });
