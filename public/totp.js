// Personal Card Vault — two-factor authentication (browser + Node tests).
// TOTP per RFC 6238: HMAC-SHA1, 30-second step, 6 digits, ±1 step window
// for clock drift. Fully offline/local: no server, no SMS, no email.
// ONE implementation, used in both places: globalThis.crypto.subtle
// (WebCrypto), which exists in the browser and in Node 24 — same as vault.js.
// The TOTP secret lives INSIDE the vault (encrypted under the PIN).
// Backup codes: 10 one-time codes; only their SHA-256 hashes are stored,
// OUTSIDE the vault (localStorage), so they can be checked while the vault
// is still locked. A used code's hash is deleted (burned).
// No real secrets in tests — RFC 6238 vectors and synthetic secrets only.
'use strict';

const TOTP_STEP_MS = 30 * 1000;
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1;
const BACKUP_CODE_COUNT = 10;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

function base32Encode(bytes) {
  let out = '';
  let bits = 0, value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) { out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  const clean = String(str || '').replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
  if (!clean || /[^A-Z2-7]/.test(clean)) throw fail('BAD_SECRET', 'Not a valid base32 secret.');
  const out = [];
  let bits = 0, value = 0;
  for (let i = 0; i < clean.length; i++) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(clean[i]);
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
function generateSecret() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(20)); // 160-bit, RFC 4226
  return base32Encode(bytes);
}

async function hmacSha1(keyBytes, msgBytes) {
  const key = await globalThis.crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, msgBytes));
}
function counterBytes(counter) {
  const b = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) { b[i] = Number(c & 0xffn); c >>= 8n; }
  return b;
}
function truncate(hmacBytes, digits) {
  const o = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const code = ((hmacBytes[o] & 0x7f) << 24) | (hmacBytes[o + 1] << 16)
    | (hmacBytes[o + 2] << 8) | hmacBytes[o + 3];
  return String(code % (10 ** digits)).padStart(digits, '0');
}

// The TOTP code for `secret` at `timeMs` (defaults to now).
async function totpCode(secret, timeMs, digits, stepMs) {
  const key = base32Decode(secret);
  const step = stepMs || TOTP_STEP_MS;
  const counter = Math.floor((timeMs == null ? Date.now() : timeMs) / step);
  const hmac = await hmacSha1(key, counterBytes(counter));
  return truncate(hmac, digits || TOTP_DIGITS);
}
function validTotpCode(code) {
  return typeof code === 'string' && /^\d{6}$/.test(code.replace(/[\s-]/g, ''));
}
function timingEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
// Verify a 6-digit code against `secret` at `timeMs`, accepting the
// current step and ±`window` steps (clock drift). Returns true/false.
async function verifyTotp(secret, code, timeMs, window) {
  if (!validTotpCode(code)) return false;
  const clean = code.replace(/[\s-]/g, '');
  const w = window == null ? TOTP_WINDOW : window;
  const now = timeMs == null ? Date.now() : timeMs;
  for (let d = -w; d <= w; d++) {
    const expect = await totpCode(secret, now + d * TOTP_STEP_MS);
    if (timingEqual(clean, expect)) return true;
  }
  return false;
}

function otpauthUrl(secret, account, issuer) {
  const iss = issuer || 'Card Vault';
  const acc = account || 'Personal Card Vault';
  return 'otpauth://totp/' + encodeURIComponent(iss) + ':' + encodeURIComponent(acc)
    + '?secret=' + secret + '&issuer=' + encodeURIComponent(iss)
    + '&algorithm=SHA1&digits=6&period=30';
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hash = await globalThis.crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function normalizeBackupCode(code) {
  return String(code || '').replace(/[\s-]/g, '');
}
function randomBackupCode() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(4));
  const n = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return String(n % 100000000).padStart(8, '0');
}
// Generate 10 one-time backup codes + their SHA-256 hashes (digits only,
// no dashes). Show the codes ONCE; store only the hashes.
async function generateBackupCodes(count) {
  const n = count || BACKUP_CODE_COUNT;
  const codes = [];
  const seen = new Set();
  while (codes.length < n) {
    const raw = randomBackupCode();
    if (seen.has(raw)) continue;
    seen.add(raw);
    codes.push(raw.slice(0, 4) + '-' + raw.slice(4));
  }
  const hashes = [];
  for (const c of codes) hashes.push(await sha256Hex(normalizeBackupCode(c)));
  return { codes: codes, hashes: hashes };
}
// Check a backup code against stored hashes. Returns { ok, remaining } —
// `remaining` is the hash list with the used code burned (deleted).
async function checkBackupCode(code, hashes) {
  const norm = normalizeBackupCode(code);
  if (!/^\d{8}$/.test(norm)) return { ok: false, remaining: hashes };
  const h = await sha256Hex(norm);
  const i = (hashes || []).indexOf(h);
  if (i < 0) return { ok: false, remaining: hashes };
  const remaining = hashes.slice();
  remaining.splice(i, 1);
  return { ok: true, remaining: remaining };
}

// The gate for disabling 2FA: a valid current code is required. The UI
// calls this before touching the vault; the PIN is checked separately by
// decrypting the envelope (same check as unlock).
async function canDisableTwoFactor(secret, code, timeMs) {
  if (typeof secret !== 'string' || !secret) return false;
  return verifyTotp(secret, code, timeMs);
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    TOTP_STEP_MS, TOTP_DIGITS, TOTP_WINDOW, BACKUP_CODE_COUNT,
    base32Encode, base32Decode, generateSecret, totpCode, validTotpCode,
    verifyTotp, otpauthUrl, sha256Hex, generateBackupCodes, checkBackupCode,
    canDisableTwoFactor,
  };
}
if (typeof window !== 'undefined') {
  window.Totp = {
    TOTP_STEP_MS, TOTP_DIGITS, TOTP_WINDOW, BACKUP_CODE_COUNT,
    base32Encode, base32Decode, generateSecret, totpCode, validTotpCode,
    verifyTotp, otpauthUrl, sha256Hex, generateBackupCodes, checkBackupCode,
    canDisableTwoFactor,
  };
}
