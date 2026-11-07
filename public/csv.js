// Ghar ka Register — CSV export (Phase 5) + a small CSV parser for
// reading exported files back in the tests.
// Pure functions. The export half writes the book out: one CSV per
// section, or one combined file. Money is plain integers (no "Rs", no
// thousands commas) so the file opens as readable CSV in a spreadsheet.
// A field with a comma, a quote or a line break is quoted; a quote
// inside a field is doubled. Nothing is fetched or looked up — the rows
// come from the vault, as entered.
// (The old statement-import half was dead code from the Card Vault:
// nothing called it, and its duplicate-flagging crashed on a v2 vault.
// It was removed, not repaired; the parser stays because the tests
// round-trip exports through it.)
'use strict';

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

// ---- CSV export (Phase 5: Summary + export) ----
function csvEscape(value) {
  const s = value == null ? '' : String(value);
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function rowsToCsv(headers, rows) {
  const lines = [];
  lines.push(headers.map(csvEscape).join(','));
  for (const row of (rows || [])) lines.push(row.map(csvEscape).join(','));
  return lines.join('\r\n') + '\r\n';
}
// One combined file: each section under its own heading line, so the
// sections stay readable in one download.
function buildCombinedCsv(sections) {
  const order = ['staff', 'deliveries', 'udhaar', 'bills', 'documents', 'medicines'];
  const titles = {
    staff: 'Staff', deliveries: 'Deliveries', udhaar: 'Udhaar',
    bills: 'Bills', documents: 'Documents', medicines: 'Medicines',
  };
  const parts = [];
  for (const key of order) {
    const sec = sections[key];
    if (!sec) continue;
    parts.push(titles[key]);
    parts.push(rowsToCsv(sec.headers, sec.rows).replace(/\r\n$/, ''));
    parts.push('');
  }
  return parts.join('\r\n');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { parseCsv, csvEscape, rowsToCsv, buildCombinedCsv };
}
if (typeof window !== 'undefined') {
  window.CsvExport = { csvEscape, rowsToCsv, buildCombinedCsv };
}
