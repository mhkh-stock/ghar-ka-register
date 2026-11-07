// Ghar ka Register — local-first household book (Pakistan).
// Node.js 24+, native node:http only. No external dependencies.
// Port 3036. The server serves the app shell ONLY and stores NOTHING
// except the P12 portal's recovery file (see below):
// all vault data lives in the user's browser (localStorage), encrypted with
// the user's PIN (+ optional passphrase) via PBKDF2 + AES-256-GCM.
// There is no database, no account on the server, no sync, no tracking.
//
// P12 login portal (server part): the server also answers the OTP +
// recovery endpoints. OTPs live in memory only (die on restart) and
// are stored hashed, never plaintext. The spare key for forgot-code
// recovery lives in ONE file on this PC only (data/recovery.key,
// mode 0600, outside public/, never served over HTTP, never in a
// backup, never committed). The spare key is never sent to the
// browser; the server creates the spare envelope from the unlocked
// vault and returns only the envelope. Mail goes out through the
// user's own Gmail (GMAIL_USER + GMAIL_APP_PASSWORD env vars,
// app password — never the Gmail password — never logged, never
// sent to the browser). If mail is not set up, the OTP endpoints
// answer 503 and the book otherwise works exactly as today
// (PIN-only, as before the portal).
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Mail = require('./server/mail.js');
const Otp = require('./server/otp.js');
const VaultCrypto = require('./public/vault.js');
const GharModel = require('./public/model.js');

const PORT = Number(process.env.PORT || 3036);
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const RECOVERY_KEY_FILE = path.join(DATA_DIR, 'recovery.key');
const ACCOUNT_FILE = path.join(DATA_DIR, 'account.json');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml', '.txt': 'text/plain; charset=utf-8',
  // OCR (Phase 3.6): the vendored Tesseract engine lives in
  // public/vendor/tesseract/ and is loaded on demand only, from this
  // same origin — never from a CDN.
  '.wasm': 'application/wasm',
};
function send(res, status, type, body) {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(body);
}
function sendJson(res, status, obj) {
  send(res, status, 'application/json; charset=utf-8', JSON.stringify(obj));
}
function serveFile(res, file) {
  const full = path.join(PUBLIC_DIR, file);
  if (!full.startsWith(PUBLIC_DIR) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
    return send(res, 404, 'text/plain; charset=utf-8', 'Not found');
  }
  send(res, 200, MIME[path.extname(full)] || 'application/octet-stream', fs.readFileSync(full));
}

// ---- P12 portal helpers ----
const otpStore = Otp.createOtpStore();
// Per-IP reset attempts (defence in depth): 10 reset calls per hour.
const resetAttempts = new Map();
const RESET_MAX_PER_HOUR = 10;
const BODY_LIMIT_BYTES = 256 * 1024;

// Same-origin only for the API (the pattern the sibling projects use):
// no Origin header (curl, tests, same-origin fetch) is fine; a foreign
// Origin is refused. The app is served from this same origin only.
function originAllowed(req) {
  const o = req.headers.origin;
  if (!o) return true;
  try {
    const u = new URL(o);
    return u.hostname === '127.0.0.1' || u.hostname === 'localhost';
  } catch (_e) { return false; }
}
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    let done = false;
    function fail(status, error) {
      if (done) return;
      done = true;
      try { req.destroy(); } catch (_e) { /* already gone */ }
      const e = new Error(error);
      e.status = status;
      reject(e);
    }
    req.on('data', (c) => {
      size += c.length;
      if (size > BODY_LIMIT_BYTES) return fail(413, 'BODY_TOO_LARGE');
      chunks.push(c);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      try {
        const obj = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
          const e = new Error('BAD_JSON');
          e.status = 400;
          return reject(e);
        }
        resolve(obj);
      } catch (_e) {
        const e = new Error('BAD_JSON');
        e.status = 400;
        reject(e);
      }
    });
    req.on('error', () => fail(400, 'BAD_BODY'));
  });
}
// The server-side Gmail binding for reset (written by /api/recover/setup
// when a book is linked). The browser keeps its own copy in
// localStorage; this copy is what the reset OTP is sent to — the reset
// request body Gmail is ignored, so an OTP can never be pointed at a
// freely typed address.
function readAccountGmail() {
  try {
    const obj = JSON.parse(fs.readFileSync(ACCOUNT_FILE, 'utf8'));
    const g = obj && typeof obj.gmail === 'string' ? Otp.normalizeGmail(obj.gmail) : '';
    return g && !GharModel.validateEmail(g) ? g : null;
  } catch (_e) { return null; }
}
function writeAccountGmail(gmail) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(ACCOUNT_FILE, JSON.stringify({ gmail }), { mode: 0o600 });
  try { fs.chmodSync(ACCOUNT_FILE, 0o600); } catch (_e) { /* best effort on Windows */ }
}
function readSpareKeyBytes() {
  try {
    const b = fs.readFileSync(RECOVERY_KEY_FILE);
    return b.length === VaultCrypto.SPARE_KEY_BYTES ? b : null;
  } catch (_e) { return null; }
}
function writeSpareKeyBytes(bytes) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(RECOVERY_KEY_FILE, Buffer.from(bytes), { mode: 0o600 });
  try { fs.chmodSync(RECOVERY_KEY_FILE, 0o600); } catch (_e) { /* best effort on Windows */ }
}
function otpEmailText(code) {
  return 'Your Ghar ka Register code is ' + code + '.\n'
    + '\n'
    + 'It works for 10 minutes and one time only.\n'
    + '\n'
    + 'If you did not ask for this, ignore this email.';
}
const OTP_PURPOSES = ['register', 'link', 'reset', 'change-gmail'];

async function handleMailStatus(req, res) {
  return sendJson(res, 200, { configured: Mail.isMailConfigured() });
}

async function handleOtpRequest(req, res) {
  let body;
  try { body = await readJsonBody(req); }
  catch (e) { return sendJson(res, e.status || 400, { ok: false, error: e.message || 'BAD_JSON' }); }
  const purpose = body.purpose;
  if (OTP_PURPOSES.indexOf(purpose) < 0) {
    return sendJson(res, 400, { ok: false, error: 'BAD_PURPOSE' });
  }
  if (!Mail.isMailConfigured()) {
    return sendJson(res, 503, { ok: false, error: 'MAIL_NOT_CONFIGURED' });
  }
  let gmail;
  if (purpose === 'reset') {
    // Reset ignores the request-body Gmail: the OTP goes only to the
    // server-side bound Gmail. No binding (or no spare key) means
    // recovery is off for this book.
    gmail = readAccountGmail();
    if (!gmail || !readSpareKeyBytes()) {
      return sendJson(res, 200, { ok: false, error: 'RECOVERY_OFF' });
    }
  } else {
    gmail = Otp.normalizeGmail(body.gmail);
    if (!gmail || GharModel.validateEmail(gmail)) {
      return sendJson(res, 400, { ok: false, error: 'BAD_GMAIL' });
    }
  }
  const issued = Otp.issueOtp(otpStore, purpose, gmail, Date.now());
  if (!issued.ok) return sendJson(res, 200, { ok: false, error: issued.error });
  try {
    await Mail.sendMail(gmail, 'Ghar ka Register code', otpEmailText(issued.code));
  } catch (_e) {
    // Mail failed: drop the OTP so the user can retry without burning
    // the rate limit, and say so plainly (never a fake "sent").
    Otp.revokeOtp(otpStore, purpose, gmail);
    return sendJson(res, 503, { ok: false, error: 'MAIL_FAILED' });
  }
  Otp.noteOtpSent(otpStore, gmail, Date.now());
  return sendJson(res, 200, { ok: true });
}

async function handleOtpVerify(req, res) {
  let body;
  try { body = await readJsonBody(req); }
  catch (e) { return sendJson(res, e.status || 400, { ok: false, error: e.message || 'BAD_JSON' }); }
  const purpose = body.purpose;
  if (OTP_PURPOSES.indexOf(purpose) < 0) {
    return sendJson(res, 400, { ok: false, error: 'BAD_PURPOSE' });
  }
  let gmail;
  if (purpose === 'reset') {
    gmail = readAccountGmail();
    if (!gmail || !readSpareKeyBytes()) {
      return sendJson(res, 200, { ok: false, error: 'RECOVERY_OFF' });
    }
  } else {
    gmail = Otp.normalizeGmail(body.gmail);
    if (!gmail || GharModel.validateEmail(gmail)) {
      return sendJson(res, 400, { ok: false, error: 'BAD_GMAIL' });
    }
  }
  const v = Otp.verifyOtp(otpStore, purpose, gmail, body.code, Date.now());
  if (!v.ok) {
    const out = { ok: false, error: v.error };
    if (typeof v.triesLeft === 'number') out.triesLeft = v.triesLeft;
    return sendJson(res, 200, out);
  }
  return sendJson(res, 200, { ok: true, token: v.token });
}

// Create the spare key + spare envelope for a book (registration and
// linking). The browser sends the main envelope + the code so the
// server can decrypt the vault and re-lock it under the spare key —
// localhost only, never logged, never stored. (Plan note: the plan's
// "{ rkEnvelope }" cannot work as written, because the browser never
// sees the spare key — the server must create the spare envelope, so
// it needs the unlocked vault. This mirrors the plan-approved reset
// pattern, where the new code travels to the local server.)
// Refuses (409) if a spare key already exists AND the caller cannot
// prove the same book — a second book cannot silently overwrite the
// first book's spare key. The one allowed call while a key exists is
// a Gmail change (Phase 4): current spare envelope + a token from an
// OTP sent to the NEW Gmail. The spare key and spare envelope are
// NOT affected by a Gmail change; the old Gmail gets a plain notice.
async function handleRecoverSetup(req, res) {
  let body;
  try { body = await readJsonBody(req); }
  catch (e) { return sendJson(res, e.status || 400, { ok: false, error: e.message || 'BAD_JSON' }); }
  const gmail = Otp.normalizeGmail(body.gmail);
  if (!gmail || GharModel.validateEmail(gmail)) {
    return sendJson(res, 400, { ok: false, error: 'BAD_GMAIL' });
  }
  const existingSpare = readSpareKeyBytes();
  if (existingSpare) {
    // Gmail change for the same book: prove the book with the current
    // spare envelope (it opens under the existing spare key).
    if (!body.rkEnvelope || typeof body.rkEnvelope !== 'object') {
      return sendJson(res, 409, { ok: false, error: 'ALREADY_SET' });
    }
    let spareVault;
    try {
      const spareKey = await VaultCrypto.importSpareKey(existingSpare);
      spareVault = await VaultCrypto.openSpareEnvelope(spareKey, body.rkEnvelope);
    } catch (_e) {
      return sendJson(res, 409, { ok: false, error: 'ALREADY_SET' });
    }
    if (!GharModel.isGharVault(spareVault)) {
      return sendJson(res, 409, { ok: false, error: 'ALREADY_SET' });
    }
    // The spare-envelope proof runs BEFORE the token is consumed, so a
    // change that fails closed does not burn a valid token.
    const t = Otp.consumeToken(otpStore, body.token, 'change-gmail', Date.now());
    if (!t.ok) return sendJson(res, 200, { ok: false, error: t.error });
    if (t.gmail !== gmail) return sendJson(res, 200, { ok: false, error: 'BAD_TOKEN' });
    const oldGmail = readAccountGmail();
    writeAccountGmail(gmail);
    // Plain notice to the OLD Gmail (no code in it). Best effort: the
    // change itself already happened; a failed notice never blocks it.
    let notifiedOld = false;
    if (oldGmail && oldGmail !== gmail) {
      try {
        await Mail.sendMail(oldGmail, 'Ghar ka Register — login Gmail changed',
          'Your Ghar ka Register login Gmail was changed to ' + gmail + '.\n'
          + '\n'
          + 'If this was not you, open the book and change it back in Security.');
        notifiedOld = true;
      } catch (_e) { notifiedOld = false; }
    }
    return sendJson(res, 200, { ok: true, rkEnvelope: body.rkEnvelope, notifiedOld });
  }
  if (!VaultCrypto.validPin(body.pin) || !VaultCrypto.validPassphrase(body.passphrase || '')) {
    return sendJson(res, 400, { ok: false, error: 'BAD_CREDENTIALS' });
  }
  if (!body.envelope || typeof body.envelope !== 'object') {
    return sendJson(res, 400, { ok: false, error: 'BAD_ENVELOPE' });
  }
  let vaultObj;
  try {
    const res2 = await VaultCrypto.unlockVault(body.pin, body.passphrase || '', body.envelope);
    vaultObj = res2.vault;
  } catch (_e) {
    return sendJson(res, 400, { ok: false, error: 'BAD_CREDENTIALS' });
  }
  if (!GharModel.isGharVault(vaultObj)) {
    return sendJson(res, 400, { ok: false, error: 'BAD_ENVELOPE' });
  }
  const spareBytes = VaultCrypto.randomSpareKey();
  try {
    writeSpareKeyBytes(spareBytes);
    writeAccountGmail(gmail);
    const spareKey = await VaultCrypto.importSpareKey(spareBytes);
    const rkEnvelope = await VaultCrypto.createSpareEnvelope(spareKey, vaultObj);
    return sendJson(res, 200, { ok: true, rkEnvelope });
  } catch (_e) {
    return sendJson(res, 500, { ok: false, error: 'SETUP_FAILED' });
  }
}

// Reset the book under a new code, OTP-gated. Token only — a raw OTP is
// never accepted here. On success: new main envelope (new code, EMPTY
// passphrase), fresh spare key + fresh spare envelope (rotation).
// Fails closed without the spare key file or a valid spare envelope.
async function handleRecoverReset(req, res) {
  const ip = (req.socket && req.socket.remoteAddress) || 'unknown';
  const now = Date.now();
  const list = (resetAttempts.get(ip) || []).filter((t) => now - t < 60 * 60 * 1000);
  if (list.length >= RESET_MAX_PER_HOUR) {
    return sendJson(res, 429, { ok: false, error: 'TRY_LATER' });
  }
  list.push(now);
  resetAttempts.set(ip, list);
  let body;
  try { body = await readJsonBody(req); }
  catch (e) { return sendJson(res, e.status || 400, { ok: false, error: e.message || 'BAD_JSON' }); }
  if (!VaultCrypto.validPin(body.newPin)) {
    return sendJson(res, 400, { ok: false, error: 'BAD_PIN' });
  }
  // The spare key file is checked BEFORE the token is consumed, so a
  // reset that fails closed (recovery off) does not burn a valid token.
  const spareBytes = readSpareKeyBytes();
  if (!spareBytes) {
    return sendJson(res, 200, { ok: false, error: 'RECOVERY_OFF' });
  }
  const t = Otp.consumeToken(otpStore, body.token, 'reset', now);
  if (!t.ok) return sendJson(res, 200, { ok: false, error: t.error });
  if (!body.rkEnvelope || typeof body.rkEnvelope !== 'object') {
    return sendJson(res, 400, { ok: false, error: 'BAD_ENVELOPE' });
  }
  let vaultObj;
  try {
    const spareKey = await VaultCrypto.importSpareKey(spareBytes);
    vaultObj = await VaultCrypto.openSpareEnvelope(spareKey, body.rkEnvelope);
  } catch (_e) {
    return sendJson(res, 200, { ok: false, error: 'RECOVERY_OFF' });
  }
  if (!GharModel.isGharVault(vaultObj)) {
    return sendJson(res, 200, { ok: false, error: 'RECOVERY_OFF' });
  }
  try {
    const made = await VaultCrypto.createVault(body.newPin, '', vaultObj);
    const freshBytes = VaultCrypto.randomSpareKey();
    writeSpareKeyBytes(freshBytes);
    const freshKey = await VaultCrypto.importSpareKey(freshBytes);
    const freshRk = await VaultCrypto.createSpareEnvelope(freshKey, vaultObj);
    return sendJson(res, 200, { ok: true, envelope: made.envelope, rkEnvelope: freshRk });
  } catch (_e) {
    return sendJson(res, 500, { ok: false, error: 'RESET_FAILED' });
  }
}

// Turn forgot-code recovery OFF: delete the spare key file. The browser
// deletes the spare envelope. The account binding stays (turning
// recovery back on re-creates the key via /api/recover/setup).
// Requires the current code, verified against the book's envelope
// (the same check as unlock) — an unauthenticated caller can no longer
// switch recovery off. Refuses when recovery was never set up.
async function handleRecoverOff(req, res) {
  let body;
  try { body = await readJsonBody(req); }
  catch (e) { return sendJson(res, e.status || 400, { ok: false, error: e.message || 'BAD_JSON' }); }
  if (!readSpareKeyBytes()) {
    return sendJson(res, 200, { ok: false, error: 'RECOVERY_OFF' });
  }
  if (!VaultCrypto.validPin(body.pin) || !VaultCrypto.validPassphrase(body.passphrase || '')) {
    return sendJson(res, 400, { ok: false, error: 'BAD_CREDENTIALS' });
  }
  if (!body.envelope || typeof body.envelope !== 'object') {
    return sendJson(res, 400, { ok: false, error: 'BAD_ENVELOPE' });
  }
  let vaultObj;
  try {
    const res2 = await VaultCrypto.unlockVault(body.pin, body.passphrase || '', body.envelope);
    vaultObj = res2.vault;
  } catch (_e) {
    return sendJson(res, 400, { ok: false, error: 'BAD_CREDENTIALS' });
  }
  if (!GharModel.isGharVault(vaultObj)) {
    return sendJson(res, 400, { ok: false, error: 'BAD_ENVELOPE' });
  }
  try { fs.unlinkSync(RECOVERY_KEY_FILE); } catch (_e) { /* already gone */ }
  return sendJson(res, 200, { ok: true });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const p = url.pathname;
  if (req.method === 'GET' && p === '/health') {
    return send(res, 200, 'application/json; charset=utf-8', JSON.stringify({ ok: true }));
  }
  if (req.method === 'GET' && (p === '/' || p === '/index.html')) return serveFile(res, 'index.html');
  if (req.method === 'GET' && (p === '/styles.css' || p === '/vault.js' || p === '/model.js' || p === '/csv.js' || p === '/proof.js' || p === '/nav.js' || p === '/ocr.js' || p === '/app.js' || p === '/bg.jpg' || p === '/favicon.ico')) {
    return serveFile(res, p.slice(1));
  }
  // The old vault modules (sms.js, intel.js, totp.js, cards.js) were
  // deleted in Phase 1 and are no longer listed here — they 404 by the
  // fall-through below, like any unknown path.
  // OCR engine (Phase 3.6): vendored Tesseract files, served from this
  // same origin only. The language data is a plain .traineddata file
  // (no .gz) — Tesseract is told gzip: false.
  if (req.method === 'GET' && p.startsWith('/vendor/tesseract/')
    && ['/vendor/tesseract/tesseract.min.js', '/vendor/tesseract/worker.min.js',
      '/vendor/tesseract/tesseract-core.wasm.js', '/vendor/tesseract/tesseract-core.wasm',
      '/vendor/tesseract/eng.traineddata'].includes(p)) {
    return serveFile(res, p.slice(1));
  }
  // ---- P12 portal API (POST, JSON only, same-origin) ----
  if (req.method === 'POST' && (p === '/api/mail/status' || p === '/api/otp/request' || p === '/api/otp/verify'
    || p === '/api/recover/setup' || p === '/api/recover/reset' || p === '/api/recover/off')) {
    if (!originAllowed(req)) {
      return sendJson(res, 403, { ok: false, error: 'FORBIDDEN' });
    }
    if (p === '/api/mail/status') return handleMailStatus(req, res);
    if (p === '/api/otp/request') return handleOtpRequest(req, res);
    if (p === '/api/otp/verify') return handleOtpVerify(req, res);
    if (p === '/api/recover/setup') return handleRecoverSetup(req, res);
    if (p === '/api/recover/reset') return handleRecoverReset(req, res);
    if (p === '/api/recover/off') return handleRecoverOff(req, res);
  }
  // data/ is never served: /data/recovery.key, /data/account.json and
  // anything else under data/ falls through to 404 here.
  return send(res, 404, 'text/plain; charset=utf-8', 'Not found');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('Ghar ka Register listening on 127.0.0.1:' + PORT);
});
