'use strict';

// Vercel serverless entry. Static files in public/ are served by Vercel's CDN;
// every /api/* request is rewritten here (see vercel.json).
module.exports = require('../lib/app');
