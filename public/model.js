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
// A balance is NEVER typed — not even at creation (Phase 3.5, Hashir's
// rule 2026-11-06: a typed balance is how a made-up card fools people).
// New accounts start with balance `null` (unknown) and startingBalance
// `null`. A balance is set ONLY by a bank source — setBaselineFromBank()
// from a bank SMS (Intelligence) or a statement — which also sets
// startingBalance so reconcile() can rebuild every balance from the
// approved transactions and prove the books add up. An account whose
// baseline was never set stays unknown: totals skip it (never silently
// as 0), reconcile cannot prove it, and the monthly check treats it as
// not ready. Old vaults keep their numeric balances (their own history).
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
    // Monthly check (Phase 4): the date (YYYY-MM-DD) the last monthly
    // check was marked done, and how many accounts were skipped then.
    // Old vaults have neither — migrateVault() fills null / 0.
    lastReconcileAt: null,
    lastReconcileSkipped: 0,
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
  // Verified (Phase 3.6): old accounts have no confirmedBy — they were
  // never verified by a screenshot or a statement, so they load as
  // "Not confirmed".
  vault.accounts.forEach(function (a) { if (a && a.confirmedBy === undefined) a.confirmedBy = null; });
  // No typed balances (Phase 3.5): an old account without a balance field
  // loads as unknown (null). Existing numeric balances stay exactly as
  // they are — they are the user's own history.
  vault.accounts.forEach(function (a) {
    if (!a) return;
    if (a.balance === undefined) a.balance = null;
    if (a.startingBalance === undefined) a.startingBalance = null;
  });
  // Statement proof (Phase 3.3): old accounts have no proof field.
  vault.accounts.forEach(function (a) { if (a && a.proof === undefined) a.proof = null; });
  // STRIP old badges (Hashir, 2026-11-06): a "Bank-confirmed" earned by
  // an SMS under the old Phase 3.1 rule is no longer valid — an SMS never
  // verifies a card. The badge is cleared to null; the card must be
  // re-verified by a total-amount screenshot or a statement PDF. The
  // balance is NOT touched — only the verification badge is stripped.
  // Accounts verified by a statement keep their badge untouched.
  vault.accounts.forEach(function (a) {
    if (a && a.confirmedBy && a.confirmedBy.source === 'bank-sms') a.confirmedBy = null;
  });
  // Monthly check (Phase 4): old vaults were never reconciled.
  if (vault.lastReconcileAt === undefined) vault.lastReconcileAt = null;
  if (vault.lastReconcileSkipped === undefined) vault.lastReconcileSkipped = 0;
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
  // No typed balances (Phase 3.5): a balance is set ONLY by a bank source
  // (setBaselineFromBank), never typed — not even at creation. Supplying
  // one is a caller mistake, so it is rejected, never silently ignored.
  if (input.balance !== undefined && input.balance !== null) {
    errors.push('balance is set by your bank, not typed — leave it blank');
  }
  const hits = scanSensitive(input);
  if (hits.length) errors.push('never store full card numbers, CVV, PIN, expiry or passwords (found in: ' + hits.join(', ') + ')');
  return errors;
}

function createAccount(vault, input) {
  const errors = validateAccount(input);
  if (errors.length) throw fail('VALIDATION', 'Account is not valid.', errors);
  // Duplicate guard (Phase 3.1): the same provider + last-4 is one card —
  // adding it twice is how a made-up card gets saved. A different provider
  // may share the same last-4 (different banks can), and the same provider
  // may hold a different last-4.
  const dup = (vault.accounts || []).find(function (a) {
    return a.provider === input.provider && String(a.last4) === String(input.last4);
  });
  if (dup) throw fail('VALIDATION', 'You already have a ' + input.provider + ' card ending ' + String(input.last4) + '.');
  // No typed balance (Phase 3.5): a new account starts unknown (null).
  // Only a bank source sets it — see setBaselineFromBank().
  const account = {
    id: newId(),
    provider: input.provider,
    type: input.type,
    nickname: String(input.nickname).trim(),
    last4: String(input.last4),
    balance: null,
    startingBalance: null,
    // Bank-confirmed: null until the card is verified — ONLY by a
    // total-amount screenshot or a statement PDF (Hashir's rule,
    // 2026-11-06). An SMS never sets this. Manual add/edit and CSV import
    // never set it either.
    confirmedBy: null,
    // Statement proof (Phase 3.3): a record built by the UI from a validated
    // upload (see proof.js isValidProofRecord) — or null. The shape is
    // checked here so a bad record can never be stored.
    proof: validProofRecord(input.proof) ? input.proof : null,
    createdAt: new Date().toISOString(),
  };
  vault.accounts.push(account);
  return account;
}

function findAccount(vault, accountId) {
  return vault.accounts.find((a) => a.id === accountId) || null;
}

// Is this account's balance known? `null` means unknown — never treat it
// as 0. A wallet CAN hold a real Rs 0; null and 0 are different things.
function isBalanceKnown(account) {
  return !!account && typeof account.balance === 'number' && Number.isFinite(account.balance);
}

// Set an account's balance from a BANK source only (Phase 3.5): a bank SMS
// (Intelligence), a statement, or a total-amount screenshot read by
// on-device OCR (Phase 3.6). `source` must be 'sms', 'statement' or
// 'screenshot' — anything else is rejected. The bank's number is the
// CURRENT balance, so startingBalance is back-computed from it:
// startingBalance = balance − (net effect of the already-approved
// transactions), which keeps reconcile() true. The bank's number is
// trusted as stated — even a negative one (an overdrawn account) —
// because it came from the bank.
function setBaselineFromBank(vault, accountId, balance, source) {
  const account = findAccount(vault, accountId);
  if (!account) throw fail('NOT_FOUND', 'Account does not exist.');
  if (source !== 'sms' && source !== 'statement' && source !== 'screenshot') {
    throw fail('VALIDATION', 'A baseline can only come from a bank SMS, a statement, or a total-amount screenshot.');
  }
  const b = Number(balance);
  if (!Number.isFinite(b)) throw fail('VALIDATION', 'Baseline balance must be a number.');
  if (Math.abs(b) > MAX_MONEY) throw fail('VALIDATION', 'Baseline balance is unreasonably large.');
  let net = 0;
  for (const t of (vault.transactions || [])) {
    if (t.accountId !== accountId || t.status !== 'approved') continue;
    net = roundRs(net + (t.direction === 'credit' ? t.amount : -t.amount));
  }
  account.startingBalance = roundRs(b - net);
  account.balance = roundRs(b);
  return account;
}

// Rename a card (Phase 3.2, revised by Hashir's rule 2026-11-06): the
// nickname is the user's own label — the ONLY thing a hand may change on a
// saved card. Balance and type are bank data: after creation they can only
// change through a bank SMS (Intelligence), a CSV statement import, or a
// matching statement — never by typing. There is deliberately NO function
// in this file that lets a hand edit change a balance or a type; the old
// balance-edit path (updateAccount + "Balance correction") was removed.
function renameAccount(vault, accountId, nickname) {
  const account = findAccount(vault, accountId);
  if (!account) throw fail('NOT_FOUND', 'Account does not exist.');
  const nick = String(nickname || '').trim();
  if (!nick) throw fail('VALIDATION', 'nickname is required');
  if (nick.length > 40) throw fail('VALIDATION', 'nickname must be 40 characters or fewer');
  const hits = scanSensitive({ nickname: nick });
  if (hits.length) throw fail('VALIDATION', 'never store full card numbers, CVV, PIN, expiry or passwords');
  account.nickname = nick;
  return account;
}

// Reorder (Phase 3.2): move one card one step up or down. The stored array
// order IS the display order (carousel + Summary read the same array), so
// it survives lock/unlock and reload. At the ends it is a no-op (false).
function moveAccount(vault, accountId, direction) {
  if (direction !== 'up' && direction !== 'down') {
    throw fail('VALIDATION', 'Direction must be up or down.');
  }
  const idx = vault.accounts.findIndex((a) => a.id === accountId);
  if (idx < 0) throw fail('NOT_FOUND', 'Account does not exist.');
  const to = direction === 'up' ? idx - 1 : idx + 1;
  if (to < 0 || to >= vault.accounts.length) return false;
  const tmp = vault.accounts[idx];
  vault.accounts[idx] = vault.accounts[to];
  vault.accounts[to] = tmp;
  return true;
}

// Delete a card (Phase 3.2): removes the account AND its transactions, so
// reconcile() still passes afterwards. The UI confirms in two taps first.
function deleteAccount(vault, accountId) {
  const idx = vault.accounts.findIndex((a) => a.id === accountId);
  if (idx < 0) throw fail('NOT_FOUND', 'Account does not exist.');
  const account = vault.accounts[idx];
  vault.accounts.splice(idx, 1);
  vault.transactions = vault.transactions.filter((t) => t.accountId !== accountId);
  return account;
}

// Remove the statement proof from a card (Phase 3.3). The card itself is
// untouched — only its proof record is cleared, so its status falls back
// to "Not confirmed yet" — unless the card was verified by a total-amount
// screenshot: that verification IS the screenshot proof, so removing the
// proof removes the verification too (confirmedBy is cleared as well).
// A statement-matched card keeps its own rule: removing its statement
// proof also drops it back to unconfirmed (the proof was the match).
function removeProof(vault, accountId) {
  const account = findAccount(vault, accountId);
  if (!account) throw fail('NOT_FOUND', 'Account does not exist.');
  account.proof = null;
  if (account.confirmedBy && account.confirmedBy.source === 'total-amount-screenshot') {
    account.confirmedBy = null;
  }
  return account;
}

// A proof record is only what the UI built from a validated upload.
// Statuses: 'match' (statement PDF matched), 'screenshot-verified'
// (total-amount screenshot read by on-device OCR, Phase 3.6),
// 'self-checked' (user checked a screenshot by eye), 'attached' (kept as
// a record), 'mismatch' (readable PDF that does not mention this card).
function validProofRecord(proof) {
  if (!proof || typeof proof !== 'object') return false;
  if (proof.kind !== 'pdf' && proof.kind !== 'image') return false;
  if (!['match', 'screenshot-verified', 'self-checked', 'attached', 'mismatch'].includes(proof.status)) return false;
  if (typeof proof.dataUrl !== 'string' || proof.dataUrl.indexOf('data:') !== 0) return false;
  if (typeof proof.name !== 'string' || !proof.name) return false;
  return true;
}
// Attach (or replace) a statement proof on a saved card (Phase 4
// re-check). The record is validated the same way as at creation.
function attachProof(vault, accountId, proof) {
  const account = findAccount(vault, accountId);
  if (!account) throw fail('NOT_FOUND', 'Account does not exist.');
  if (!validProofRecord(proof)) throw fail('VALIDATION', 'Proof is not valid.');
  account.proof = proof;
  return account;
}

// ---- Monthly check (Phase 4) ----
// An account is "ready" for the monthly check when it was verified (a
// total-amount screenshot or a statement matched it) AND its balance is
// known. A verified card whose balance was never set is not ready: the
// check cannot verify a number that does not exist yet. An SMS alone
// never makes an account ready: it confirms nothing (Hashir's rule,
// 2026-11-06).
function accountCheckReady(account) {
  return isBalanceKnown(account)
    && (isBankConfirmed(account) || !!(account && account.proof && account.proof.status === 'match'));
}
// The last date this account was confirmed (confirmation record date,
// else the statement's upload date), or null when never confirmed. An SMS
// alone never sets a date — it confirms nothing.
function lastConfirmedAt(account) {
  if (account && account.confirmedBy && account.confirmedBy.at) return String(account.confirmedBy.at).slice(0, 10);
  if (account && account.proof && account.proof.at) return String(account.proof.at).slice(0, 10);
  return null;
}
function daysBetween(fromDateStr, toDateStr) {
  const from = new Date(fromDateStr + 'T00:00:00Z');
  const to = new Date(toDateStr + 'T00:00:00Z');
  if (isNaN(from.getTime()) || isNaN(to.getTime())) return Infinity;
  return Math.floor((to - from) / 86400000);
}
// The monthly check is due when it was never done, or 30+ days have passed.
function monthlyCheckDue(vault, today) {
  const last = vault && vault.lastReconcileAt;
  if (!last) return true;
  return daysBetween(last, today || todayStr()) >= 30;
}
// Which accounts still need a re-check or an explicit skip. skippedIds is
// a map of account id -> true, kept in memory for this month's check.
function monthlyCheckStatus(vault, skippedIds) {
  const skipped = skippedIds || {};
  const pending = [];
  let skippedCount = 0;
  for (const a of (vault && vault.accounts) || []) {
    if (accountCheckReady(a)) continue;
    if (skipped[a.id]) { skippedCount++; continue; }
    pending.push(a);
  }
  return { ready: pending.length === 0, pending, skippedCount };
}
function markMonthlyCheckDone(vault, skippedCount) {
  vault.lastReconcileAt = todayStr();
  vault.lastReconcileSkipped = Number(skippedCount) || 0;
  return vault.lastReconcileAt;
}

// Verified status. RULE (Hashir, 2026-11-06): a card is VERIFIED only by
// a total-amount screenshot or a bank statement PDF — NEVER by an SMS. An
// SMS can set the balance (it is bank data), but it never verifies the
// card. markAccountBankConfirmed is called ONLY by the total-amount
// screenshot path (Add page, Phase 3.6, on-device OCR) and stamps source
// 'total-amount-screenshot'. Old 'bank-sms' records (Phase 3.1, before
// the rule change) are STRIPPED by migrateVault() — they load as
// unconfirmed and must be re-verified.
function isBankConfirmed(account) {
  return !!(account && account.confirmedBy && account.confirmedBy.source === 'total-amount-screenshot'
    && typeof account.confirmedBy.at === 'string');
}
function markAccountBankConfirmed(vault, accountId) {
  const account = findAccount(vault, accountId);
  if (!account) throw fail('NOT_FOUND', 'Account does not exist.');
  if (!isBankConfirmed(account)) {
    account.confirmedBy = { source: 'total-amount-screenshot', at: new Date().toISOString() };
  }
  return account.confirmedBy;
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

// Apply a transaction's balance effect to its account. A null (unknown)
// balance is left alone — a transaction cannot move a number that was
// never set. The transaction is still recorded; the baseline, when a bank
// source later sets it, accounts for it (see setBaselineFromBank).
function applyEffect(account, txn) {
  if (account.balance === null || account.balance === undefined) return;
  if (txn.direction === 'debit') account.balance = roundRs(account.balance - txn.amount);
  else account.balance = roundRs(account.balance + txn.amount);
}
function reverseEffect(account, txn) {
  if (account.balance === null || account.balance === undefined) return;
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
  // No low-balance alert while the balance is unknown — there is no number
  // to compare against the threshold.
  if (isBalanceKnown(account) && before !== null && before >= threshold && account.balance < threshold) {
    addNotification(vault, 'low-balance',
      account.nickname + ' (•••• ' + account.last4 + ') is below Rs '
      + threshold.toLocaleString('en-PK') + ' — balance ' + fmtBalance(account.balance) + '.');
  }
  return true;
}

function fmtBalance(n) {
  if (n === null || n === undefined) return 'Balance not set yet';
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
  let unknownCount = 0;
  const byProvider = {};
  for (const a of vault.accounts) {
    if (!isBalanceKnown(a)) { unknownCount++; continue; }
    total = roundRs(total + a.balance);
    byProvider[a.provider] = roundRs((byProvider[a.provider] || 0) + a.balance);
  }
  return { total, byProvider, count: vault.accounts.length, unknownCount };
}

// Rebuild every balance from starting balances + approved transactions.
// Returns { ok, mismatches: [{accountId, stored, computed}], unknown: [ids] }.
// Accounts whose baseline was never set (startingBalance null) cannot be
// proved — they are listed under `unknown`, never counted as mismatches
// and never silently treated as 0.
function reconcile(vault) {
  const computed = {};
  const unknown = [];
  for (const a of vault.accounts) {
    if (a.startingBalance === null || a.startingBalance === undefined) { unknown.push(a.id); continue; }
    computed[a.id] = Number(a.startingBalance) || 0;
  }
  for (const t of vault.transactions) {
    if (t.status !== 'approved') continue;
    if (computed[t.accountId] === undefined) continue;
    computed[t.accountId] = roundRs(computed[t.accountId] + (t.direction === 'credit' ? t.amount : -t.amount));
  }
  const mismatches = [];
  for (const a of vault.accounts) {
    if (computed[a.id] === undefined) continue;
    if (roundRs(Number(a.balance) || 0) !== computed[a.id]) {
      mismatches.push({ accountId: a.id, stored: a.balance, computed: computed[a.id] });
    }
  }
  return { ok: mismatches.length === 0, mismatches, unknown };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    PROVIDERS, ACCOUNT_TYPES, CATEGORIES, TX_SOURCES, MAX_MONEY,
    newId, roundRs, isDateStr, todayStr, containsSensitiveValue, scanSensitive,
    emptyVault, validateAccount, createAccount, findAccount,
    setBaselineFromBank, isBalanceKnown,
    renameAccount, moveAccount, deleteAccount, removeProof,
    validProofRecord, attachProof,
    isBankConfirmed, markAccountBankConfirmed,
    accountCheckReady, lastConfirmedAt, monthlyCheckDue,
    monthlyCheckStatus, markMonthlyCheckDone,
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
    setBaselineFromBank, isBalanceKnown,
    renameAccount, moveAccount, deleteAccount, removeProof,
    validProofRecord, attachProof,
    isBankConfirmed, markAccountBankConfirmed,
    accountCheckReady, lastConfirmedAt, monthlyCheckDue,
    monthlyCheckStatus, markMonthlyCheckDone,
    validateTransaction, addTransaction, addNotification,
    approveTransaction, deleteTransaction, setLowBalanceThreshold,
    enableTwoFactor, disableTwoFactor, setAutoLockMinutes,
    emptyProfile, validateProfile, setProfile, migrateVault,
    unreadNotificationCount, markAllNotificationsRead,
    dpTargetSize, dpByteLength, MAX_DP_BYTES,
    totals, reconcile, fmtBalance,
  };
}
