// Personal Card Vault — bank SMS parser (browser + Node tests).
// Pure functions. Paste a bank/wallet SMS -> extract amount, direction,
// merchant, date, available balance and last 4 digits. NOTHING is saved
// until the user approves the review card (see app.js).
// OTPs are NEVER parsed: any text containing "OTP" returns null.
// Amounts are whole rupees. Dates normalise to YYYY-MM-DD; when no date is
// in the text, today's date is used and flagged (dateGuessed).
// The formats below are the representative Pakistani SMS patterns for each
// provider; the parser is keyword/regex based with a generic fallback, so
// small wording differences still parse.
'use strict';

const PROVIDER_KEYWORDS = [
  ['HBL', ['hbl']],
  ['Meezan', ['meezan']],
  ['UBL', ['ubl']],
  ['MCB', ['mcb']],
  ['Allied', ['allied', 'abl']],
  ['Bank Alfalah', ['alfalah']],
  ['Askari', ['askari']],
  ['JazzCash', ['jazzcash', 'jazz cash']],
  ['Easypaisa', ['easypaisa', 'easy paisa']],
  ['SadaPay', ['sadapay', 'sada pay']],
  ['NayaPay', ['nayapay', 'naya pay']],
];
const DEBIT_RES = [/\bdebited\b/, /\bspent\b/, /\bpaid\b/, /\bsent\b/, /\bwithdrawn\b/,
  /\bdeducted\b/, /\bcharged\b/, /\bused\b/, /\bpayment of\b/, /\bpurchase\b/];
const CREDIT_RES = [/\bcredited\b/, /\breceived\b/, /\bdeposited\b/, /\brefund\b/, /\bcashback\b/];
const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const AMOUNT_RE = /(?:Rs\.?|PKR)\s*([\d,]+\.\d{2})/gi;
const BALANCE_RE = /(?:available balance|avail(?:able)?\s*bal(?:ance)?|new balance|balance is|balance)\s*(?:is|:)?\s*(?:Rs\.?|PKR)?\s*([\d,]+\.\d{2})/i;

function detectProvider(text) {
  const low = String(text || '').toLowerCase();
  for (const [name, keys] of PROVIDER_KEYWORDS) {
    for (const k of keys) {
      // Short codes (HBL, UBL, MCB, ABL) must match as whole words — 'abl'
      // is inside "available", so a plain substring test misfires.
      if (k.length <= 3) {
        if (new RegExp('\\b' + k + '\\b').test(low)) return name;
      } else if (low.includes(k)) {
        return name;
      }
    }
  }
  return 'Unknown';
}
function parseAmount(s) {
  const n = Number(String(s).replace(/,/g, ''));
  return Number.isFinite(n) && n > 0 ? Math.round(n) : null;
}
function earliest(reList, low) {
  let best = -1;
  for (const re of reList) {
    const m = re.exec(low);
    if (m && (best < 0 || m.index < best)) best = m.index;
  }
  return best;
}
function detectDirection(low) {
  const d = earliest(DEBIT_RES, low);
  const c = earliest(CREDIT_RES, low);
  if (d < 0 && c < 0) return null;
  if (c < 0) return 'debit';
  if (d < 0) return 'credit';
  return d < c ? 'debit' : 'credit';
}
function parseDateStr(text) {
  const m1 = /(\d{1,2})[-\s/](Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[-\s/](\d{2,4})/i.exec(text);
  if (m1) {
    const y = m1[3].length === 2 ? 2000 + Number(m1[3]) : Number(m1[3]);
    const mo = MONTHS[m1[2].toLowerCase().slice(0, 3)];
    const d = String(Number(m1[1])).padStart(2, '0');
    return y + '-' + String(mo).padStart(2, '0') + '-' + d;
  }
  const m2 = /(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})/.exec(text);
  if (m2) {
    const y = m2[3].length === 2 ? 2000 + Number(m2[3]) : Number(m2[3]);
    return y + '-' + String(Number(m2[2])).padStart(2, '0') + '-' + String(Number(m2[1])).padStart(2, '0');
  }
  return null;
}
// A merchant candidate that is really an account reference ("your account
// ending 1234", "account 9753", "A/C 2468") is not a merchant at all.
function isAccountReference(candidate) {
  const c = String(candidate || '').trim();
  return /^(your\s+)?account\b/i.test(c) || /^a\/c\b/i.test(c) || /ending\s+\d{4}/i.test(c);
}
function extractMerchant(text) {
  const pats = [
    /\bat\s+([A-Z][A-Za-z0-9 .&'\-]{2,40}?)\s+on\b/gi,
    /\bto\s+([A-Z][A-Za-z0-9 .&'\-]{2,40}?)\s+on\b/gi,
    /\bfrom\s+([A-Z][A-Za-z0-9 .&'\-]{2,40}?)\s+on\b/gi,
    /\bfrom\s+([A-Z][A-Za-z0-9 .&'\-]{2,40}?)\./gi,
    /\bat\s+([A-Z][A-Za-z0-9 .&'\-]{2,40}?)(?:\.| Available)/gi,
  ];
  for (const re of pats) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const cand = m[1].replace(/[\s.]+$/, '').trim();
      if (cand && !isAccountReference(cand)) return cand;
    }
  }
  return '';
}
function extractLast4(text) {
  const pats = [/ending\s+(\d{4})/i, /A\/C\s+\w*?(\d{4})/i, /\bAC\s+(\d{4})/i,
    /[•·*]{2,4}\s*(\d{4})/, /account\s+(?:ending\s+)?(\d{4})/i];
  for (const re of pats) {
    const m = re.exec(text);
    if (m) return m[1];
  }
  return null;
}

// Parse one pasted SMS. Returns a draft object or null when nothing
// transaction-like can be read (garbage input, OTP, no amount, no direction).
function parseSms(text) {
  const raw = String(text || '').trim();
  if (!raw) return null;
  if (/otp/i.test(raw)) return null; // OTPs are never parsed
  const low = raw.toLowerCase();
  const amounts = [];
  let m;
  AMOUNT_RE.lastIndex = 0;
  while ((m = AMOUNT_RE.exec(raw)) !== null) amounts.push({ value: parseAmount(m[1]), index: m.index });
  const first = amounts.find((a) => a.value != null);
  if (!first) return null;
  const direction = detectDirection(low);
  if (!direction) return null;
  const bal = BALANCE_RE.exec(raw);
  const availableBalance = bal ? parseAmount(bal[1]) : null;
  const date = parseDateStr(raw);
  const today = new Date().toISOString().slice(0, 10);
  return {
    provider: detectProvider(raw),
    amount: first.value,
    direction,
    merchant: extractMerchant(raw),
    date: date || today,
    dateGuessed: !date,
    availableBalance,
    last4: extractLast4(raw),
    raw,
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PROVIDER_KEYWORDS, detectProvider, parseSms, parseDateStr, extractMerchant, extractLast4 };
}
if (typeof window !== 'undefined') {
  window.SmsParser = { PROVIDER_KEYWORDS, detectProvider, parseSms, parseDateStr, extractMerchant, extractLast4 };
}
