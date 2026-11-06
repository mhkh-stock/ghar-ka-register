// Personal Card Vault — statement proof (browser + Node tests).
// Proof-keeping, NOT proof: a statement upload is the user's own record.
// A forged statement PDF is as easy to make as a fake card number, so a
// statement can never prove a card is real — only a real bank SMS does
// (Phase 3.1). What the app CAN do: check the document's readable text
// against the provider name, the last-4 and the profile display name the
// user typed, and keep the file encrypted in the vault.
// Images (screenshots/photos) carry no readable text for this zero-dep app
// (no OCR): the user checks those by eye instead — "self-checked".
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

// A proof record is only what the UI built from a validated upload.
function isValidProofRecord(proof) {
  if (!proof || typeof proof !== 'object') return false;
  if (proof.kind !== 'pdf' && proof.kind !== 'image') return false;
  if (!['match', 'self-checked', 'attached', 'mismatch'].includes(proof.status)) return false;
  if (typeof proof.dataUrl !== 'string' || proof.dataUrl.indexOf('data:') !== 0) return false;
  if (typeof proof.name !== 'string' || !proof.name) return false;
  return true;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    MAX_PROOF_BYTES, detectProofKind, validateProofData, extractPdfText,
    containsTerm, missingProofTerms, checkProofMatch, isValidProofRecord,
    dataUrlToBytes,
  };
}
if (typeof window !== 'undefined') {
  window.Proof = {
    MAX_PROOF_BYTES, detectProofKind, validateProofData, extractPdfText,
    containsTerm, missingProofTerms, checkProofMatch, isValidProofRecord,
    dataUrlToBytes,
  };
}
