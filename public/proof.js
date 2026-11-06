// Personal Card Vault — statement proof (browser + Node tests).
// Proof-keeping, NOT proof: a statement upload is the user's own record.
// A forged statement PDF is as easy to make as a fake card number, so a
// statement can never prove a card is real — and a forged screenshot can
// lie the same way. Only a bank SMS arriving from the bank is hard to
// fake — but an SMS never VERIFIES a card (Hashir's rule, 2026-11-06):
// verification comes only from a total-amount screenshot (read on-device
// by OCR, Phase 3.6) or a statement PDF whose text matches the provider,
// last-4 and profile name. Images other than a total-amount screenshot
// carry no readable text for the statement check: the user checks those
// by eye instead — "self-checked".
// Pure functions. No DOM, no storage, no crypto.
'use strict';

const MAX_PROOF_BYTES = 500 * 1024; // 500 KB file cap

function bytesFromBase64(b64) {
  if (typeof Buffer !== 'undefined') return Buffer.from(b64, 'base64');
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
// The raw bytes behind a data: URL (or null when it is not one).
function dataUrlToBytes(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  const m = dataUrl.match(/^data:([^;,]+);base64,(.*)$/);
  if (!m) return null;
  try { return bytesFromBase64(m[2]); } catch (_e) { return null; }
}
function latin1(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('latin1');
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] & 0xFF);
  return s;
}

// File type by magic bytes — never by the file name or the claimed MIME.
// PDF: %PDF. JPEG: FF D8 FF. PNG: 89 50 4E 47 0D 0A 1A 0A.
function detectProofKind(bytes) {
  if (!bytes || bytes.length < 3) return null;
  if (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'pdf';
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'image';
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47
    && bytes[4] === 0x0D && bytes[5] === 0x0A && bytes[6] === 0x1A && bytes[7] === 0x0A) return 'image';
  return null;
}

// Validate an uploaded proof file (data URL + the file's real byte size).
function validateProofData(dataUrl, sizeBytes) {
  const errors = [];
  if (typeof sizeBytes !== 'number' || !Number.isFinite(sizeBytes)) {
    errors.push('Statement file size is unknown.');
  } else if (sizeBytes > MAX_PROOF_BYTES) {
    errors.push('Statement is too large — upload a file under 500 KB.');
  }
  let kind = null;
  if (typeof dataUrl !== 'string' || dataUrl.indexOf('data:') !== 0) {
    errors.push('Statement must be a PDF or a photo file.');
  } else {
    const m = dataUrl.match(/^data:([^;,]+);base64,(.*)$/);
    if (!m) {
      errors.push('Statement must be a PDF or a photo file.');
    } else {
      kind = detectProofKind(bytesFromBase64(m[2]));
      if (!kind) errors.push('Only a PDF or a photo (JPEG/PNG) can be used as proof.');
    }
  }
  return { ok: errors.length === 0, errors, kind };
}

// Best-effort text out of a PDF: literal (...) and hex <...> strings from
// the raw bytes, plus the same from any FlateDecode stream we can inflate
// (DecompressionStream in the browser, zlib under Node). A scanned-image
// PDF has no text to find — that returns null, honestly, and the app says
// so instead of guessing.
function collectPdfStrings(src, out) {
  const lit = src.match(/\((?:\\.|[^\\()])*\)/g) || [];
  for (const s of lit) {
    out.push(s.slice(1, -1).replace(/\\([()\\])/g, '$1').replace(/\\[nr]/g, ' '));
  }
  const hex = src.match(/<([0-9a-fA-F\s]+)>/g) || [];
  for (const h of hex) {
    const clean = h.slice(1, -1).replace(/\s+/g, '');
    if (clean.length % 2 !== 0 || clean.length < 4) continue;
    let decoded = '';
    let ok = true;
    for (let i = 0; i < clean.length; i += 2) {
      const code = parseInt(clean.slice(i, i + 2), 16);
      if (code < 32 || code > 126) { ok = false; break; }
      decoded += String.fromCharCode(code);
    }
    if (ok && decoded.trim()) out.push(decoded);
  }
}
async function inflateLatin1(s) {
  try {
    if (typeof DecompressionStream !== 'undefined') {
      const bytes = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i) & 0xFF;
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
      const buf = await new Response(stream).arrayBuffer();
      return latin1(new Uint8Array(buf));
    }
  } catch (_e) { /* not flate — ignore */ }
  try {
    if (typeof require === 'function') {
      const zlib = require('node:zlib');
      return zlib.inflateRawSync(Buffer.from(s, 'latin1')).toString('latin1');
    }
  } catch (_e) { /* not flate — ignore */ }
  return null;
}
async function extractPdfText(bytes) {
  const raw = latin1(bytes);
  const parts = [];
  collectPdfStrings(raw, parts);
  const streams = [...raw.matchAll(/stream\r?\n([\s\S]*?)\r?\nendstream/g)].map((m) => m[1]);
  for (const s of streams) {
    const inflated = await inflateLatin1(s);
    if (inflated) collectPdfStrings(inflated, parts);
  }
  const text = parts.join(' ').replace(/\s+/g, ' ').trim();
  return text || null;
}

function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
// Word-boundary, case-insensitive search: "JS" must not match "adjust",
// "1234" must not match "12345", "Muhammad Hashir" may span a line break.
function containsTerm(text, term) {
  const t = String(term || '').trim();
  if (!t) return false;
  const pattern = '\\b' + escapeRegExp(t).replace(/\s+/g, '\\s+') + '\\b';
  return new RegExp(pattern, 'i').test(String(text || ''));
}

// Which of the typed facts are missing from the document text. The name to
// match is the PROFILE display name (the name the bank statement shows as
// the account holder) — the card nickname is just a label the user picks.
// If no profile name is set, the name check is skipped.
function missingProofTerms(kind, text, account, profileName) {
  if (kind !== 'pdf' || !text) return [];
  const missing = [];
  if (!containsTerm(text, account.provider)) missing.push(account.provider);
  if (!containsTerm(text, String(account.last4))) missing.push('••••' + account.last4);
  const name = String(profileName || '').trim();
  if (name && !containsTerm(text, name)) missing.push(name);
  return missing;
}

// 'match' — PDF text holds provider + last-4 (+ profile name when set).
// 'mismatch' — readable PDF text, but something is missing.
// 'unreadable' — PDF with no readable text (scanned-image PDF).
// 'image' — a screenshot/photo: the app cannot read it, the user checks it.
function checkProofMatch(kind, text, account, profileName) {
  if (kind === 'image') return 'image';
  if (kind !== 'pdf') return 'unreadable';
  if (!text) return 'unreadable';
  return missingProofTerms(kind, text, account, profileName).length === 0 ? 'match' : 'mismatch';
}

// Best-effort balance out of a statement's readable text (Phase 3.5).
// Looks for "available balance" / "closing balance" / "balance" with an
// amount next to it. A strong match carries a currency marker (Rs/PKR);
// without one, a bare number only counts when it looks like money (a
// thousands comma, a decimal, or at least Rs 100) — "Balance as on
// 06-Nov-2026" must never be read as a balance of Rs 6. "Opening" and
// "minimum" balances are never counted — they are not the balance now.
// Returns { status: 'one', amount, label, match } when exactly ONE
// distinct amount is found (match = the line it was read from, so the user
// can see what the app read), { status: 'none' } when nothing clear is
// found, and { status: 'ambiguous', amounts } when several different
// amounts are found. Never guesses: 'none' / 'ambiguous' set no balance.
// Images carry no readable text (no OCR) — they never reach this function.
function parseBalanceAmount(s) {
  const n = parseFloat(String(s).replace(/,/g, ''));
  if (!Number.isFinite(n)) return null;
  if (Math.abs(n) > 1e12) return null;
  return Math.round(n);
}
function collectBalanceMatches(text, requireCurrency) {
  const found = [];
  const amt = requireCurrency
    ? '(?:rs\\.?|pkr)\\s*(-?[\\d,]+(?:\\.\\d{1,2})?)'
    : '(-?[\\d,]+(?:\\.\\d{1,2})?)';
  const patterns = [
    { re: new RegExp('(available|closing)\\s+balance.{0,60}?' + amt, 'gi'), labelFor: (m) => m[1][0].toUpperCase() + m[1].slice(1).toLowerCase() + ' Balance' },
    { re: new RegExp('(?<!available\\s)(?<!closing\\s)(?<!opening\\s)(?<!minimum\\s)\\bbalance\\b.{0,60}?' + amt, 'gi'), labelFor: () => 'Balance' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(text)) !== null) {
      const amount = parseBalanceAmount(m[m.length - 1]);
      if (amount === null) continue;
      if (!requireCurrency) {
        const raw = m[m.length - 1];
        const looksLikeMoney = raw.indexOf(',') >= 0 || raw.indexOf('.') >= 0 || Math.abs(amount) >= 100;
        if (!looksLikeMoney) continue;
      }
      found.push({ label: p.labelFor(m), amount: amount, match: m[0].replace(/\s+/g, ' ').trim() });
    }
  }
  return found;
}
function extractStatementBalance(text) {
  const t = String(text || '');
  if (!t.trim()) return { status: 'none' };
  let found = collectBalanceMatches(t, true);
  if (found.length === 0) found = collectBalanceMatches(t, false);
  const distinct = [];
  for (const f of found) {
    if (!distinct.some((d) => d.amount === f.amount)) distinct.push(f);
  }
  if (distinct.length === 0) return { status: 'none' };
  if (distinct.length === 1) {
    return { status: 'one', amount: distinct[0].amount, label: distinct[0].label, match: distinct[0].match };
  }
  return { status: 'ambiguous', amounts: distinct.slice(0, 3).map((d) => d.amount) };
}

// A proof record is only what the UI built from a validated upload.
function isValidProofRecord(proof) {
  if (!proof || typeof proof !== 'object') return false;
  if (proof.kind !== 'pdf' && proof.kind !== 'image') return false;
  if (!['match', 'screenshot-verified', 'self-checked', 'attached', 'mismatch'].includes(proof.status)) return false;
  if (typeof proof.dataUrl !== 'string' || proof.dataUrl.indexOf('data:') !== 0) return false;
  if (typeof proof.name !== 'string' || !proof.name) return false;
  return true;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    MAX_PROOF_BYTES, detectProofKind, validateProofData, extractPdfText,
    containsTerm, missingProofTerms, checkProofMatch, isValidProofRecord,
    extractStatementBalance,
    dataUrlToBytes,
  };
}
if (typeof window !== 'undefined') {
  window.Proof = {
    MAX_PROOF_BYTES, detectProofKind, validateProofData, extractPdfText,
    containsTerm, missingProofTerms, checkProofMatch, isValidProofRecord,
    extractStatementBalance,
    dataUrlToBytes,
  };
}
