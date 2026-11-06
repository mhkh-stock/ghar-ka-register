// Personal Card Vault — data model + balance engine (browser + Node tests).
// Pure functions over the vault object. No DOM, no storage, no crypto.
// The vault object: { v, createdAt, accounts, transactions, notifications,
//   settings: { lowBalanceThreshold } }
//
// Money rule (one rule for every account type): `balance` is the money in
// the account. Positive = you have it; negative = you owe it (a credit card
// with Rs 5,000 owed has balance -5000). A debit subtracts, a credit adds —
// for a credit card that means a purchase makes the balance more negative
// (you owe more) and a payment brings it back toward zero. Totals across
// accounts are therefore the user's net position.
// Every account also keeps `startingBalance` (set at creation, never
// changed) so `reconcile()` can rebuild every balance from the approved
// transactions and prove the books add up.
//
// NEVER stored, enforced by validation: full card numbers (13–19 digits),
// CVV/CVC, card PIN, expiry, bank passwords. Only the last 4 digits.
'use strict';

const PROVIDERS = ['HBL', 'Meezan', 'UBL', 'MCB', 'Allied', 'Bank Alfalah',
  'Askari', 'Faysal', 'JS', 'Standard Chartered', 'NBP', 'BOP',
  'SadaPay', 'NayaPay', 'Zindigi', 'Easypaisa', 'JazzCash', 'Payoneer', 'Custom'];
const ACCOUNT_TYPES = ['bank', 'debit', 'credit', 'wallet'];
const CATEGORIES = ['food', 'transport', 'shopping', 'bills', 'transfer',
  'cash', 'health', 'entertainment', 'other'];
const TX_SOURCES = ['manual', 'sms', 'csv'];
const MAX_MONEY = 1000000000000; // Rs 1 trillion sanity cap per value
const SENSITIVE_KEY_RE = /(card.?number|card.?num|cvv|cvc|expir|card.?pin|bank.?pass|password|otp)/i;
const LONG_DIGITS_RE = /\d{13,19}/;

function fail(code, message, errors) {
  const e = new Error(message);
  e.code = code;
  if (errors) e.errors = errors;
  return e;
}
function newId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}
function roundRs(x) { return Math.round(x); }
function isDateStr(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}
function todayStr() { return new Date().toISOString().slice(0, 10); }

// True when a value looks like forbidden card data: a sensitive key name,
// or a 13–19 digit run (a full card number) anywhere in a string.
function containsSensitiveValue(value) {
  if (typeof value === 'string') return LONG_DIGITS_RE.test(value.replace(/[\s-]/g, ''));
  return false;
}
function scanSensitive(obj) {
  const hits = [];
  if (!obj || typeof obj !== 'object') return hits;
  for (const k of Object.keys(obj)) {
    if (SENSITIVE_KEY_RE.test(k)) { hits.push(k); continue; }
    if (containsSensitiveValue(obj[k])) hits.push(k);
  }
  return hits;
}

function emptyVault() {
  return {
    v: 1, createdAt: new Date().toISOString(),
    accounts: [], transactions: [], notifications: [],
    // profile: display name + optional contact + DP photo (data URL JPEG).
    // The profile lives INSIDE the vault, so it is encrypted with everything
    // else. Old vaults (Phase 1/2) have no profile key — migrateVault()
    // fills an empty one so they load fine.
    profile: { displayName: '', phone: '', email: '', dp: null },
    // twoFactor: null | { enabled: true, secret: base32 } — the TOTP secret
    // lives INSIDE the vault, so it is protected by the PIN. Backup-code
    // hashes live OUTSIDE the vault (localStorage) by design (see totp.js).
    settings: { lowBalanceThreshold: 5000, twoFactor: null, autoLockMinutes: 5 },
  };
}

// ---- Profile (Phase 3) ----
const MAX_DP_BYTES = 100 * 1024; // ~100 KB for the stored DP photo
function emptyProfile() {
  return { displayName: '', phone: '', email: '', dp: null };
}
function validateProfile(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['profile is required'];
  const name = String(input.displayName || '').trim();
  if (name.length > 60) errors.push('display name must be 60 characters or fewer');
  const phone = String(input.phone || '').trim();
  if (phone.length > 20) errors.push('phone must be 20 characters or fewer');
  const email = String(input.email || '').trim();
  if (email.length > 100) errors.push('email must be 100 characters or fewer');
  else if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('email does not look like an email address');
  if (input.dp !== undefined && input.dp !== null && input.dp !== '') {
    if (typeof input.dp !== 'string' || input.dp.indexOf('data:image/jpeg;base64,') !== 0) {
      errors.push('profile photo must be a JPEG data URL');
    } else if (dpByteLength(input.dp) > MAX_DP_BYTES) {
      errors.push('profile photo must be 100 KB or smaller');
    }
  }
  // The DP data URL itself is never scanned: base64 can hold digit runs
  // that look like card numbers but are not. Only the text fields are scanned.
  const hits = scanSensitive({ displayName: name, phone: phone, email: email });
  if (hits.length) errors.push('profile details must not contain card or password data');
  return errors;
}
function setProfile(vault, input) {
  const errors = validateProfile(input);
  if (errors.length) throw fail('VALIDATION', 'Profile is not valid.', errors);
  const prev = (vault.profile && typeof vault.profile === 'object') ? vault.profile : emptyProfile();
  vault.profile = {
    displayName: String(input.displayName || '').trim(),
    phone: String(input.phone || '').trim(),
    email: String(input.email || '').trim(),
    dp: input.dp !== undefined ? (input.dp || null) : (prev.dp || null),
  };
  return vault.profile;
}
// Fill in everything a Phase 1/2 vault is missing, so old saves load fine.
function migrateVault(vault) {
  if (!vault || typeof vault !== 'object') throw fail('VALIDATION', 'Vault is required.');
  if (!vault.profile || typeof vault.profile !== 'object') vault.profile = emptyProfile();
  else {
    vault.profile.displayName = String(vault.profile.displayName || '');
    vault.profile.phone = String(vault.profile.phone || '');
    vault.profile.email = String(vault.profile.email || '');
    if (vault.profile.dp === undefined) vault.profile.dp = null;
  }
  if (!vault.settings || typeof vault.settings !== 'object') vault.settings = {};
  if (vault.settings.twoFactor === undefined) vault.settings.twoFactor = null;
  if (vault.settings.autoLockMinutes === undefined) vault.settings.autoLockMinutes = 5;
  if (vault.settings.lowBalanceThreshold === undefined) vault.settings.lowBalanceThreshold = 5000;
  if (!Array.isArray(vault.accounts)) vault.accounts = [];
  if (!Array.isArray(vault.transactions)) vault.transactions = [];
  if (!Array.isArray(vault.notifications)) vault.notifications = [];
  return vault;
}
// Notification read-state (Phase 3 bell). A notification without a `read`
// key (a Phase 1/2 save) counts as unread.
function unreadNotificationCount(vault) {
  if (!vault || !Array.isArray(vault.notifications)) return 0;
  return vault.notifications.filter(function (n) { return !n.read; }).length;
}
function markAllNotificationsRead(vault) {
  if (!vault || !Array.isArray(vault.notifications)) return 0;
  let marked = 0;
  vault.notifications.forEach(function (n) { if (!n.read) { n.read = true; marked++; } });
  return marked;
}
// DP downscale math (pure, so Node can test it): shrink so the longest side
// is 256px, never upscale.
function dpTargetSize(w, h) {
  const MAX = 256;
  const ww = Math.max(1, Math.floor(Number(w) || 0));
  const hh = Math.max(1, Math.floor(Number(h) || 0));
  if (ww <= MAX && hh <= MAX) return { width: ww, height: hh };
  const s = Math.min(MAX / ww, MAX / hh);
  return { width: Math.max(1, Math.round(ww * s)), height: Math.max(1, Math.round(hh * s)) };
}
function dpByteLength(dataUrl) {
  const b64 = String(dataUrl || '').split(',')[1] || '';
  return Math.floor(b64.length * 3 / 4);
}

// Two-factor (TOTP) state. The secret is validated as base32 here; the
// code itself is verified by totp.js, never by the model.
function enableTwoFactor(vault, secret) {
  if (typeof secret !== 'string' || !/^[A-Z2-7]{16,64}$/.test(secret.replace(/[\s=]/g, ''))) {
    throw fail('VALIDATION', 'Two-factor secret must be a base32 string.');
  }
  vault.settings.twoFactor = { enabled: true, secret: secret.replace(/[\s=]/g, '') };
  return vault.settings.twoFactor;
}
function disableTwoFactor(vault) {
  vault.settings.twoFactor = null;
  return null;
}
function setAutoLockMinutes(vault, n) {
  if (![1, 5, 15].includes(Number(n))) {
    throw fail('VALIDATION', 'Auto-lock must be 1, 5 or 15 minutes.');
  }
  vault.settings.autoLockMinutes = Number(n);
  return vault.settings.autoLockMinutes;
}

function validateAccount(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['account is required'];
  if (!PROVIDERS.includes(input.provider)) errors.push('provider must be one of: ' + PROVIDERS.join(', '));
  if (!ACCOUNT_TYPES.includes(input.type)) errors.push('type must be bank, debit, credit or wallet');
  const nick = String(input.nickname || '').trim();
  if (!nick) errors.push('nickname is required');
  if (nick.length > 40) errors.push('nickname must be 40 characters or fewer');
  if (!/^\d{4}$/.test(String(input.last4 || ''))) errors.push('last 4 digits must be exactly 4 digits');
  const bal = Number(input.balance);
  if (!Number.isFinite(bal)) errors.push('balance must be a number');
  else if (Math.abs(bal) > MAX_MONEY) errors.push('balance is unreasonably large');
  const hits = scanSensitive(input);
  if (hits.length) errors.push('never store full card numbers, CVV, PIN, expiry or passwords (found in: ' + hits.join(', ') + ')');
  return errors;
}

function createAccount(vault, input) {
  const errors = validateAccount(input);
  if (errors.length) throw fail('VALIDATION', 'Account is not valid.', errors);
  const balance = roundRs(Number(input.balance));
  const account = {
    id: newId(),
    provider: input.provider,
    type: input.type,
    nickname: String(input.nickname).trim(),
    last4: String(input.last4),
    balance,
    startingBalance: balance,
    createdAt: new Date().toISOString(),
  };
  vault.accounts.push(account);
  return account;
}

function findAccount(vault, accountId) {
  return vault.accounts.find((a) => a.id === accountId) || null;
}

function validateTransaction(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['transaction is required'];
  const amt = Number(input.amount);
  if (!Number.isFinite(amt) || amt <= 0) errors.push('amount must be a number greater than 0');
  else if (amt > MAX_MONEY) errors.push('amount is unreasonably large');
  if (input.direction !== 'debit' && input.direction !== 'credit') errors.push('direction must be debit or credit');
  if (input.merchant != null && String(input.merchant).length > 100) errors.push('merchant must be 100 characters or fewer');
  if (input.category != null && input.category !== '' && !CATEGORIES.includes(input.category)) {
    errors.push('category must be one of: ' + CATEGORIES.join(', '));
  }
  if (!isDateStr(input.date)) errors.push('date must be YYYY-MM-DD');
  if (!TX_SOURCES.includes(input.source)) errors.push('source must be manual, sms or csv');
  if (input.status != null && input.status !== 'pending' && input.status !== 'approved') {
    errors.push('status must be pending or approved');
  }
  const hits = scanSensitive(input);
  if (hits.length) errors.push('never store full card numbers, CVV, PIN, expiry or passwords (found in: ' + hits.join(', ') + ')');
  return errors;
}

// Add a transaction WITHOUT touching any balance (it starts pending unless
// the caller passes status 'approved' — only the UI's manual entry does
// that, after the user has typed it themselves).
function addTransaction(vault, input) {
  const errors = validateTransaction(input);
  if (errors.length) throw fail('VALIDATION', 'Transaction is not valid.', errors);
  if (!findAccount(vault, input.accountId)) throw fail('NOT_FOUND', 'Account does not exist.');
  const txn = {
    id: newId(),
    accountId: input.accountId,
    amount: roundRs(Number(input.amount)),
    direction: input.direction,
    merchant: String(input.merchant || '').trim(),
    category: input.category && CATEGORIES.includes(input.category) ? input.category : 'other',
    date: input.date,
    source: input.source,
    status: input.status === 'approved' ? 'approved' : 'pending',
    createdAt: new Date().toISOString(),
  };
  vault.transactions.push(txn);
  return txn;
}

function addNotification(vault, kind, text) {
  const n = { id: newId(), kind, text: String(text), at: new Date().toISOString(), read: false };
  vault.notifications.push(n);
  return n;
}

// Apply a transaction's balance effect to its account.
function applyEffect(account, txn) {
  if (txn.direction === 'debit') account.balance = roundRs(account.balance - txn.amount);
  else account.balance = roundRs(account.balance + txn.amount);
}
function reverseEffect(account, txn) {
  if (txn.direction === 'debit') account.balance = roundRs(account.balance + txn.amount);
  else account.balance = roundRs(account.balance - txn.amount);
}

// Approve a pending transaction: balance updates, notification added, and
// a low-balance alert fires when the balance CROSSES below the threshold
// (not on every transaction while already below it). Idempotent: approving
// an already-approved transaction changes nothing and returns false.
function approveTransaction(vault, txId) {
  const txn = vault.transactions.find((t) => t.id === txId);
  if (!txn) throw fail('NOT_FOUND', 'Transaction does not exist.');
  if (txn.status === 'approved') return false;
  const account = findAccount(vault, txn.accountId);
  if (!account) throw fail('NOT_FOUND', 'Account does not exist.');
  const before = account.balance;
  txn.status = 'approved';
  applyEffect(account, txn);
  const sign = txn.direction === 'debit' ? '−' : '+';
  addNotification(vault, 'transaction',
    sign + ' Rs ' + txn.amount.toLocaleString('en-PK') + (txn.merchant ? ' at ' + txn.merchant : '')
    + ' — ' + account.nickname + ' (•••• ' + account.last4 + ')');
  const threshold = Number((vault.settings && vault.settings.lowBalanceThreshold) || 0);
  if (before >= threshold && account.balance < threshold) {
    addNotification(vault, 'low-balance',
      account.nickname + ' (•••• ' + account.last4 + ') is below Rs '
      + threshold.toLocaleString('en-PK') + ' — balance ' + fmtBalance(account.balance) + '.');
  }
  return true;
}

function fmtBalance(n) {
  return 'Rs ' + Number(n || 0).toLocaleString('en-PK');
}

// Delete a transaction. An approved one is reversed first (the balance
// goes back to what it was); a pending one is just removed.
function deleteTransaction(vault, txId) {
  const i = vault.transactions.findIndex((t) => t.id === txId);
  if (i < 0) throw fail('NOT_FOUND', 'Transaction does not exist.');
  const txn = vault.transactions[i];
  if (txn.status === 'approved') {
    const account = findAccount(vault, txn.accountId);
    if (account) reverseEffect(account, txn);
  }
  vault.transactions.splice(i, 1);
  return txn;
}

function setLowBalanceThreshold(vault, n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0 || v > MAX_MONEY) {
    throw fail('VALIDATION', 'Low-balance threshold must be a number from 0 up.');
  }
  vault.settings.lowBalanceThreshold = roundRs(v);
  return vault.settings.lowBalanceThreshold;
}

function totals(vault) {
  let total = 0;
  const byProvider = {};
  for (const a of vault.accounts) {
    total = roundRs(total + (Number(a.balance) || 0));
    byProvider[a.provider] = roundRs((byProvider[a.provider] || 0) + (Number(a.balance) || 0));
  }
  return { total, byProvider, count: vault.accounts.length };
}

// Rebuild every balance from starting balances + approved transactions.
// Returns { ok, mismatches: [{accountId, stored, computed}] }.
function reconcile(vault) {
  const computed = {};
  for (const a of vault.accounts) computed[a.id] = Number(a.startingBalance) || 0;
  for (const t of vault.transactions) {
    if (t.status !== 'approved') continue;
    if (computed[t.accountId] === undefined) continue;
    computed[t.accountId] = roundRs(computed[t.accountId] + (t.direction === 'credit' ? t.amount : -t.amount));
  }
  const mismatches = [];
  for (const a of vault.accounts) {
    if (roundRs(Number(a.balance) || 0) !== computed[a.id]) {
      mismatches.push({ accountId: a.id, stored: a.balance, computed: computed[a.id] });
    }
  }
  return { ok: mismatches.length === 0, mismatches };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    PROVIDERS, ACCOUNT_TYPES, CATEGORIES, TX_SOURCES, MAX_MONEY,
    newId, roundRs, isDateStr, todayStr, containsSensitiveValue, scanSensitive,
    emptyVault, validateAccount, createAccount, findAccount,
    validateTransaction, addTransaction, addNotification,
    approveTransaction, deleteTransaction, setLowBalanceThreshold,
    enableTwoFactor, disableTwoFactor, setAutoLockMinutes,
    emptyProfile, validateProfile, setProfile, migrateVault,
    unreadNotificationCount, markAllNotificationsRead,
    dpTargetSize, dpByteLength, MAX_DP_BYTES,
    totals, reconcile, fmtBalance,
  };
}
if (typeof window !== 'undefined') {
  window.VaultModel = {
    PROVIDERS, ACCOUNT_TYPES, CATEGORIES, TX_SOURCES, MAX_MONEY,
    newId, roundRs, isDateStr, todayStr, containsSensitiveValue, scanSensitive,
    emptyVault, validateAccount, createAccount, findAccount,
    validateTransaction, addTransaction, addNotification,
    approveTransaction, deleteTransaction, setLowBalanceThreshold,
    enableTwoFactor, disableTwoFactor, setAutoLockMinutes,
    emptyProfile, validateProfile, setProfile, migrateVault,
    unreadNotificationCount, markAllNotificationsRead,
    dpTargetSize, dpByteLength, MAX_DP_BYTES,
    totals, reconcile, fmtBalance,
  };
}
