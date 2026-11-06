// Personal Card Vault — vault crypto (browser + Node tests).
// ONE implementation, used in both places: it uses globalThis.crypto.subtle
// (WebCrypto), which exists in the browser and in Node 24. Same KDF params,
// same AES-GCM layout, so the Node tests prove the real browser format.
//
// Vault format v1:
//   envelope = { v: 1, kdf: 'pbkdf2-sha256', iter: 600000,
//                data: base64( salt(16) || iv(12) || ciphertext || tag(16) ) }
//   key material = PIN + '\n' + passphrase   (passphrase optional, may be '')
//   KDF  = PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023), 32-byte key
//   cipher = AES-256-GCM, fresh 12-byte IV per encryption, 128-bit tag.
//   The salt is not secret (it is inside the blob); the PIN + passphrase are
//   the only secret. Wrong PIN and tampered ciphertext both fail the GCM
//   authentication check — the vault cannot be opened, and no partial
//   plaintext is ever returned.
// Lockout: 5 wrong PINs -> growing lockout delay (30s, doubling, cap 15 min).
//   The failure count lives OUTSIDE the vault (localStorage), because a
//   locked vault cannot be read to count its own failures.
// No "forgot PIN", by design: there is no recovery key and no server copy.
// A forgotten PIN means the vault is unrecoverable — the app says so on setup.
'use strict';

const VAULT_VERSION = 1;
const KDF_NAME = 'pbkdf2-sha256';
const KDF_ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_BYTES = 32;
const PIN_RE = /^\d{6}$/;
const LOCKOUT_BASE_MS = 30 * 1000;      // first lockout after 5 failures
const LOCKOUT_MAX_MS = 15 * 60 * 1000;  // cap
const LOCKOUT_FREE_FAILURES = 4;        // failures 1-4: no delay yet
const AUTO_LOCK_MS = 5 * 60 * 1000;     // 5 minutes of inactivity

function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}
function validPin(pin) { return typeof pin === 'string' && PIN_RE.test(pin); }
function validPassphrase(p) { return typeof p === 'string' && (p === '' || p.length >= 4); }

function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
function bytesToB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64ToBytes(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw fail('CORRUPT_VAULT', 'Vault data is not valid base64.');
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function keyMaterial(pin, passphrase) {
  return new TextEncoder().encode(pin + '\n' + (passphrase || ''));
}

async function deriveKey(pin, passphrase, salt) {
  if (!validPin(pin)) throw fail('BAD_PIN', 'PIN must be exactly 6 digits.');
  if (!validPassphrase(passphrase)) throw fail('BAD_PASSPHRASE', 'Passphrase must be empty or at least 4 characters.');
  const base = await globalThis.crypto.subtle.importKey(
    'raw', keyMaterial(pin, passphrase), 'PBKDF2', false, ['deriveKey']);
  return globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: KDF_ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: KEY_BYTES * 8 }, false, ['encrypt', 'decrypt']);
}

// Encrypt a vault object. Returns the envelope (JSON-able).
async function encryptVault(key, salt, vaultObj) {
  const iv = randomBytes(IV_BYTES);
  const plain = new TextEncoder().encode(JSON.stringify(vaultObj));
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, plain));
  const blob = new Uint8Array(SALT_BYTES + IV_BYTES + ct.length);
  blob.set(salt, 0);
  blob.set(iv, SALT_BYTES);
  blob.set(ct, SALT_BYTES + IV_BYTES);
  return { v: VAULT_VERSION, kdf: KDF_NAME, iter: KDF_ITERATIONS, data: bytesToB64(blob) };
}

// Decrypt an envelope. Throws DECRYPT_FAILED (wrong PIN / tampered data)
// or CORRUPT_VAULT (structurally invalid envelope).
async function decryptVault(key, envelope) {
  if (!envelope || typeof envelope !== 'object' || envelope.v !== VAULT_VERSION
    || envelope.kdf !== KDF_NAME || envelope.iter !== KDF_ITERATIONS
    || typeof envelope.data !== 'string') {
    throw fail('CORRUPT_VAULT', 'Vault envelope is missing or has an unknown format.');
  }
  const blob = b64ToBytes(envelope.data);
  if (blob.length < SALT_BYTES + IV_BYTES + 16 + 1) {
    throw fail('CORRUPT_VAULT', 'Vault data is too short to be a vault.');
  }
  const iv = blob.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const ct = blob.slice(SALT_BYTES + IV_BYTES);
  let plain;
  try {
    plain = await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  } catch (_e) {
    throw fail('DECRYPT_FAILED', 'Wrong PIN or damaged vault data.');
  }
  let obj;
  try {
    obj = JSON.parse(new TextDecoder().decode(plain));
  } catch (_e) {
    throw fail('CORRUPT_VAULT', 'Vault decrypted but is not valid vault data.');
  }
  return obj;
}

function saltFromEnvelope(envelope) {
  if (!envelope || typeof envelope.data !== 'string') {
    throw fail('CORRUPT_VAULT', 'Vault envelope is missing or has an unknown format.');
  }
  const blob = b64ToBytes(envelope.data);
  if (blob.length < SALT_BYTES + IV_BYTES + 16 + 1) {
    throw fail('CORRUPT_VAULT', 'Vault data is too short to be a vault.');
  }
  return blob.slice(0, SALT_BYTES);
}

// First run: create a vault holding `vaultObj`, encrypted under the PIN.
// Returns { envelope, key } — the caller stores the envelope and keeps the
// key in memory only (never in storage).
async function createVault(pin, passphrase, vaultObj) {
  const salt = randomBytes(SALT_BYTES);
  const key = await deriveKey(pin, passphrase, salt);
  const envelope = await encryptVault(key, salt, vaultObj);
  return { envelope, key };
}

// Unlock: derive the key from the PIN and decrypt the stored envelope.
// Returns { key, vault } or throws BAD_PIN / DECRYPT_FAILED / CORRUPT_VAULT.
async function unlockVault(pin, passphrase, envelope) {
  const salt = saltFromEnvelope(envelope);
  const key = await deriveKey(pin, passphrase, salt);
  const vault = await decryptVault(key, envelope);
  return { key, vault };
}

// Re-encrypt the (possibly changed) vault object under the already-unlocked key.
async function saveVault(key, envelope, vaultObj) {
  const salt = saltFromEnvelope(envelope);
  return encryptVault(key, salt, vaultObj);
}

// ---- Lockout (pure, time-injected so tests never wait real seconds) ----
// Delay after `failures` consecutive wrong PINs: 0 for the first 4, then
// 30s, doubling each further failure, capped at 15 minutes.
function lockoutDelayMs(failures) {
  const f = Math.max(0, Math.floor(Number(failures) || 0));
  if (f <= LOCKOUT_FREE_FAILURES) return 0;
  return Math.min(LOCKOUT_BASE_MS * Math.pow(2, f - LOCKOUT_FREE_FAILURES - 1), LOCKOUT_MAX_MS);
}
function createLockoutState() { return { failures: 0, lockoutUntil: 0 }; }
function isLocked(state, nowMs) {
  return !!state && Number(state.lockoutUntil || 0) > Number(nowMs);
}
function lockoutRemainingMs(state, nowMs) {
  return Math.max(0, Number(state.lockoutUntil || 0) - Number(nowMs));
}
// Record a wrong PIN at `nowMs`. Returns the updated state.
function recordFailure(state, nowMs) {
  const s = { failures: (state ? Number(state.failures) || 0 : 0) + 1, lockoutUntil: state ? Number(state.lockoutUntil) || 0 : 0 };
  const delay = lockoutDelayMs(s.failures);
  if (delay > 0) s.lockoutUntil = Number(nowMs) + delay;
  return s;
}
function recordSuccess() { return createLockoutState(); }

// Auto-lock: true when the last activity was at least AUTO_LOCK_MS ago.
function isIdleLocked(lastActiveMs, nowMs) {
  return Number(nowMs) - Number(lastActiveMs) >= AUTO_LOCK_MS;
}

// ---- Encrypted backup ----
// A backup file is the encrypted envelope plus metadata — it is already
// encrypted under the PIN (+ passphrase), so exporting needs no
// re-encryption and restoring needs the backup's own PIN. The file never
// contains plaintext and never leaves the device unless the user moves it.
function createBackup(envelope) {
  if (!envelope || typeof envelope !== 'object' || typeof envelope.data !== 'string') {
    throw fail('CORRUPT_VAULT', 'Nothing to back up.');
  }
  return {
    app: 'personal-card-vault',
    backupVersion: 1,
    exportedAt: new Date().toISOString(),
    envelope,
  };
}
function parseBackup(text) {
  let obj;
  try {
    obj = JSON.parse(String(text));
  } catch (_e) {
    throw fail('BAD_BACKUP', 'That file is not a vault backup.');
  }
  if (!obj || obj.app !== 'personal-card-vault' || obj.backupVersion !== 1 || !obj.envelope) {
    throw fail('BAD_BACKUP', 'That file is not a vault backup.');
  }
  const env = obj.envelope;
  if (env.v !== VAULT_VERSION || env.kdf !== KDF_NAME || env.iter !== KDF_ITERATIONS || typeof env.data !== 'string') {
    throw fail('CORRUPT_VAULT', 'The backup envelope is damaged or from another app version.');
  }
  return env;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    VAULT_VERSION, KDF_NAME, KDF_ITERATIONS, SALT_BYTES, IV_BYTES, KEY_BYTES,
    LOCKOUT_BASE_MS, LOCKOUT_MAX_MS, LOCKOUT_FREE_FAILURES, AUTO_LOCK_MS,
    validPin, validPassphrase, randomBytes, bytesToB64, b64ToBytes,
    deriveKey, encryptVault, decryptVault, saltFromEnvelope,
    createVault, unlockVault, saveVault,
    createBackup, parseBackup,
    lockoutDelayMs, createLockoutState, isLocked, lockoutRemainingMs,
    recordFailure, recordSuccess, isIdleLocked,
  };
}
if (typeof window !== 'undefined') {
  window.VaultCrypto = {
    VAULT_VERSION, KDF_NAME, KDF_ITERATIONS, SALT_BYTES, IV_BYTES, KEY_BYTES,
    LOCKOUT_BASE_MS, LOCKOUT_MAX_MS, LOCKOUT_FREE_FAILURES, AUTO_LOCK_MS,
    validPin, validPassphrase, randomBytes, bytesToB64, b64ToBytes,
    deriveKey, encryptVault, decryptVault, saltFromEnvelope,
    createVault, unlockVault, saveVault,
    createBackup, parseBackup,
    lockoutDelayMs, createLockoutState, isLocked, lockoutRemainingMs,
    recordFailure, recordSuccess, isIdleLocked,
  };
}
