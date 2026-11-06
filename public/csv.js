// Personal Card Vault — statement CSV import (browser + Node tests).
// Pure functions. Upload a statement CSV -> map columns -> review every
// row -> approve. Duplicates (same amount + date + merchant, already in the
// vault or twice in the file) are flagged, never silently saved.
// Amounts are whole rupees. Dates normalise to YYYY-MM-DD.
'use strict';

const DIRECTION_WORDS = {
  debit: ['debit', 'dr', 'withdrawal', 'withdraw', 'debited', 'spent', 'payment', 'purchase'],
  credit: ['credit', 'cr', 'deposit', 'deposited', 'credited', 'received', 'refund', 'salary'],
};

// Minimal CSV parser: handles quoted fields, commas inside quotes, escaped
// double-quotes (""), CRLF and LF line endings.
function parseCsv(text) {
  const src = String(text || '').replace(/^\uFEFF/, '');
  const rows = [];
  let row = [], field = '', inQuotes = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inQuotes) {
      if (c === '"') {
        if (src[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      row.push(field); field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && src[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  if (!rows.length) return { headers: [], rows: [] };
  const headers = rows[0].map((h) => String(h).trim());
  const out = [];
  for (let r = 1; r < rows.length; r++) {
    const obj = {};
    headers.forEach((h, i) => { obj[h] = rows[r][i] == null ? '' : String(rows[r][i]).trim(); });
    if (Object.values(obj).some((v) => v !== '')) out.push(obj);
  }
  return { headers, rows: out };
}

// Guess a mapping from header names: date / amount / merchant / direction.
function guessMapping(headers) {
  const find = (words) => headers.find((h) => words.some((w) => h.toLowerCase().includes(w))) || '';
  return {
    date: find(['date']),
    amount: find(['amount', 'value']),
    merchant: find(['merchant', 'description', 'narration', 'details', 'payee']),
    direction: find(['type', 'direction', 'dr/cr', 'debit/credit', 'debit or credit']),
  };
}

function parseAmountCell(s) {
  if (s == null) return null;
  let t = String(s).trim().replace(/(Rs\.?|PKR)/gi, '').replace(/,/g, '').trim();
  let neg = false;
  if (/^\(.*\)$/.test(t)) { neg = true; t = t.slice(1, -1); }
  if (t.startsWith('-')) { neg = true; t = t.slice(1); }
  if (t.startsWith('+')) t = t.slice(1);
  const n = Number(t);
  if (!Number.isFinite(n) || n === 0) return null;
  return Math.round(Math.abs(n)) * (neg ? -1 : 1);
}

function parseDateCell(s) {
  if (s == null) return null;
  const t = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(t)) return t;
  const months = { jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06', jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12' };
  let m = /^(\d{1,2})[-\s/](Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[-\s/](\d{2,4})$/i.exec(t);
  if (m) {
    const y = m[3].length === 2 ? 2000 + Number(m[3]) : Number(m[3]);
    return y + '-' + months[m[2].toLowerCase().slice(0, 3)] + '-' + String(Number(m[1])).padStart(2, '0');
  }
  m = /^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})$/.exec(t); // DD/MM/YYYY (Pakistani)
  if (m) {
    const y = m[3].length === 2 ? 2000 + Number(m[3]) : Number(m[3]);
    return y + '-' + String(Number(m[2])).padStart(2, '0') + '-' + String(Number(m[1])).padStart(2, '0');
  }
  return null;
}

function directionFromCell(s) {
  const t = String(s || '').trim().toLowerCase();
  if (!t) return null;
  if (DIRECTION_WORDS.debit.includes(t)) return 'debit';
  if (DIRECTION_WORDS.credit.includes(t)) return 'credit';
  return null;
}

// Convert parsed rows into transaction drafts.
// mapping: { date, amount, merchant, direction } — header names; direction
// may be '' meaning "use the amount sign" (negative = debit).
// Returns { drafts, errors } — drafts are { amount, direction, merchant,
// date, source: 'csv', _row }.
function rowsToTransactions(parsed, mapping, accountId) {
  const drafts = [], errors = [];
  if (!mapping.date || !mapping.amount) {
    errors.push('Date and amount columns are required.');
    return { drafts, errors };
  }
  parsed.rows.forEach((row, i) => {
    const line = i + 2; // header is line 1
    const date = parseDateCell(row[mapping.date]);
    if (!date) { errors.push('Row ' + line + ': date not understood (' + (row[mapping.date] || '') + ').'); return; }
    const signed = parseAmountCell(row[mapping.amount]);
    if (signed == null) { errors.push('Row ' + line + ': amount not understood (' + (row[mapping.amount] || '') + ').'); return; }
    let direction = null;
    if (mapping.direction) direction = directionFromCell(row[mapping.direction]);
    if (!direction) direction = signed < 0 ? 'debit' : 'credit';
    drafts.push({
      accountId,
      amount: Math.abs(signed),
      direction,
      merchant: mapping.merchant ? String(row[mapping.merchant] || '').trim() : '',
      category: 'other',
      date,
      source: 'csv',
      status: 'pending',
      _row: line,
    });
  });
  return { drafts, errors };
}

function dupKey(amount, date, merchant) {
  return Math.abs(Number(amount)) + '|' + String(date) + '|' + String(merchant || '').trim().toLowerCase();
}

// Flag duplicates: same amount + date + merchant already in the vault
// (approved or pending) or twice in this import. Returns the drafts with
// `duplicate: true/false` added.
function markDuplicates(vault, drafts) {
  const seen = new Set();
  for (const t of vault.transactions) seen.add(dupKey(t.amount, t.date, t.merchant));
  return drafts.map((d) => {
    const k = dupKey(d.amount, d.date, d.merchant);
    const dup = seen.has(k);
    seen.add(k);
    return { ...d, duplicate: dup };
  });
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { parseCsv, guessMapping, parseAmountCell, parseDateCell, directionFromCell, rowsToTransactions, markDuplicates, dupKey };
}
if (typeof window !== 'undefined') {
  window.CsvImport = { parseCsv, guessMapping, parseAmountCell, parseDateCell, directionFromCell, rowsToTransactions, markDuplicates, dupKey };
}
