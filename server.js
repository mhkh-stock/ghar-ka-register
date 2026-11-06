// Personal Card Vault — local-first private card/account wallet (Pakistan).
// Node.js 24+, native node:http only. No external dependencies.
// Port 3036. The server serves the app shell ONLY and stores NOTHING:
// all vault data lives in the user's browser (localStorage), encrypted with
// the user's PIN (+ optional passphrase) via PBKDF2 + AES-256-GCM.
// There is no database, no account on the server, no sync, no tracking.
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 3036);
const PUBLIC_DIR = path.join(__dirname, 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml', '.txt': 'text/plain; charset=utf-8',
};
function send(res, status, type, body) {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(body);
}
function serveFile(res, file) {
  const full = path.join(PUBLIC_DIR, file);
  if (!full.startsWith(PUBLIC_DIR) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
    return send(res, 404, 'text/plain; charset=utf-8', 'Not found');
  }
  send(res, 200, MIME[path.extname(full)] || 'application/octet-stream', fs.readFileSync(full));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const p = url.pathname;
  if (req.method === 'GET' && p === '/health') {
    return send(res, 200, 'application/json; charset=utf-8', JSON.stringify({ ok: true }));
  }
  if (req.method === 'GET' && (p === '/' || p === '/index.html')) return serveFile(res, 'index.html');
  if (req.method === 'GET' && (p === '/styles.css' || p === '/vault.js' || p === '/model.js' || p === '/sms.js' || p === '/csv.js' || p === '/cards.js' || p === '/intel.js' || p === '/proof.js' || p === '/totp.js' || p === '/nav.js' || p === '/app.js' || p === '/bg.jpg' || p === '/favicon.ico')) {
    return serveFile(res, p.slice(1));
  }
  return send(res, 404, 'text/plain; charset=utf-8', 'Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('Personal Card Vault listening on :' + PORT);
});
