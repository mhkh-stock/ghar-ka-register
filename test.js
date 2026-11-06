// Ghar ka Register tests. Run: node test.js  (exit 0 = all pass)
// Tests the shared logic in public/*.js (browser + Node), the app shell
// in a minimal fake DOM (vm), and the real server on a throwaway port.
// Phases 1–5: shell + staff/deliveries + udhaar/bills + documents/medicine
// + summary/export/final review. No old vault/card tests survive.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const V = require('./public/vault.js');
const M = require('./public/model.js');
const N = require('./public/nav.js');
const C = require('./public/csv.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' — ' + JSON.stringify(extra) : '')); }
}
function throwsCode(fn, code) {
  try { fn(); } catch (e) { return e && e.code === code; }
  return false;
}
async function throwsCodeAsync(fn, code) {
  try { await fn(); } catch (e) { return e && e.code === code; }
  return false;
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
async function waitFor(fn, timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 10000);
  for (;;) {
    let ok = false;
    try { ok = !!fn(); } catch (_e) { ok = false; }
    if (ok) return true;
    if (Date.now() > deadline) return false;
    await sleep(100);
  }
}

// A v2 vault with one row in most collections, for crypto round-trips.
function sampleVault() {
  const v = M.emptyVault();
  v.householdName = 'Hashir Home';
  v.monthStartDay = 5;
  M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2, phone: '03001234567' });
  M.addDelivery(v, { name: 'Doodhwala', kind: 'Doodhwala', unit: 'litre', ratePkr: 220, usualQty: 1 });
  const p = M.addUdhaarPerson(v, { person: 'Ahmed' });
  M.addUdhaarEntry(v, p.id, { direction: 'lent', amountPkr: 20000, date: '2026-11-01', reason: 'shop rent', dueDate: '2026-11-20' });
  M.addBill(v, { type: 'electricity', provider: 'IESCO', accountNo: '1234567890', amountPkr: 8500, dueDate: '2026-11-10', surchargeNote: 'Rs 500 after due date' });
  M.addDocument(v, { type: 'passport', owner: 'Abu', issueDate: '2021-01-01', expiryDate: '2026-11-26' });
  M.addMedicine(v, { name: 'Panadol', qtyLeft: 10, unit: 'tablets', expiryDate: '2027-06-01', place: 'cupboard', person: 'Ami', dosesPerDay: 3, lowStockAt: 5 });
  return v;
}

async function main() {
  const SAMPLE = sampleVault();

  // ---- §1. Vault crypto (unchanged vault.js, now holding a v2 vault) ----
  check('PIN: 6 digits accepted', V.validPin('123456') === true);
  check('PIN: 5 digits rejected', V.validPin('12345') === false);
  check('PIN: 7 digits rejected', V.validPin('1234567') === false);
  check('PIN: letters rejected', V.validPin('12345a') === false);
  check('PIN: empty rejected', V.validPin('') === false);
  check('PIN: non-string rejected', V.validPin(123456) === false);
  check('Passphrase: empty ok', V.validPassphrase('') === true);
  check('Passphrase: 3 chars rejected', V.validPassphrase('abc') === false);
  check('Passphrase: 4 chars ok', V.validPassphrase('abcd') === true);

  const c1 = await V.createVault('123456', 'my secret', SAMPLE);
  check('Envelope: version/kdf/iter recorded', c1.envelope.v === 1 && c1.envelope.kdf === 'pbkdf2-sha256' && c1.envelope.iter === 600000, c1.envelope);
  const u1 = await V.unlockVault('123456', 'my secret', c1.envelope);
  check('Round-trip with passphrase: v2 vault identical', JSON.stringify(u1.vault) === JSON.stringify(SAMPLE));
  check('Round-trip: vault is a Ghar vault', M.isGharVault(u1.vault) === true);
  const c2 = await V.createVault('654321', '', SAMPLE);
  const u2 = await V.unlockVault('654321', '', c2.envelope);
  check('Round-trip PIN only: v2 vault identical', JSON.stringify(u2.vault) === JSON.stringify(SAMPLE));
  check('Wrong PIN fails (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('123457', 'my secret', c1.envelope), 'DECRYPT_FAILED'));
  check('Wrong passphrase fails (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secreT', c1.envelope), 'DECRYPT_FAILED'));
  check('Unlock with bad PIN format fails (BAD_PIN)',
    await throwsCodeAsync(() => V.unlockVault('12345', '', c1.envelope), 'BAD_PIN'));
  const tampered = JSON.parse(JSON.stringify(c1.envelope));
  const blob = V.b64ToBytes(tampered.data);
  blob[blob.length - 5] ^= 0x01;
  tampered.data = V.bytesToB64(blob);
  check('Tampered ciphertext rejected (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', tampered), 'DECRYPT_FAILED'));
  const tampered2 = JSON.parse(JSON.stringify(c1.envelope));
  const blob2 = V.b64ToBytes(tampered2.data);
  blob2[blob2.length - 1] ^= 0x01;
  tampered2.data = V.bytesToB64(blob2);
  check('Tampered auth tag rejected (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', tampered2), 'DECRYPT_FAILED'));
  check('Envelope with wrong version rejected (CORRUPT_VAULT)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', { ...c1.envelope, v: 99 }), 'CORRUPT_VAULT'));
  check('Envelope with bad base64 rejected (CORRUPT_VAULT)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', { ...c1.envelope, data: '!!!not-base64!!!' }), 'CORRUPT_VAULT'));
  check('Null envelope rejected (CORRUPT_VAULT)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', null), 'CORRUPT_VAULT'));
  const salt = V.saltFromEnvelope(c1.envelope);
  const key = await V.deriveKey('123456', 'my secret', salt);
  const eA = await V.encryptVault(key, salt, SAMPLE);
  const eB = await V.encryptVault(key, salt, SAMPLE);
  check('Fresh IV: two encryptions differ', eA.data !== eB.data);
  check('Both fresh encryptions decrypt', JSON.stringify((await V.decryptVault(key, eA))) === JSON.stringify(SAMPLE)
    && JSON.stringify((await V.decryptVault(key, eB))) === JSON.stringify(SAMPLE));
  const c3 = await V.createVault('123456', 'my secret', SAMPLE);
  check('Fresh salt per vault', c3.envelope.data !== c1.envelope.data
    && V.saltFromEnvelope(c3.envelope).join(',') !== V.saltFromEnvelope(c1.envelope).join(','));
  const key3 = await V.deriveKey('123456', 'my secret', V.saltFromEnvelope(c3.envelope));
  check('Key from another salt cannot open this vault',
    await throwsCodeAsync(() => V.decryptVault(key3, c1.envelope), 'DECRYPT_FAILED'));
  const saved = await V.saveVault(u1.key, c1.envelope, { ...SAMPLE, householdName: 'Renamed Home' });
  const u3 = await V.unlockVault('123456', 'my secret', saved);
  check('saveVault round-trip: changed vault decrypts', u3.vault.householdName === 'Renamed Home');

  // ---- §2. Lockout + auto-lock ----
  check('Lockout delay: 0 failures -> 0ms', V.lockoutDelayMs(0) === 0);
  check('Lockout delay: 4 failures -> 0ms', V.lockoutDelayMs(4) === 0);
  check('Lockout delay: 5 failures -> 30s', V.lockoutDelayMs(5) === 30000);
  check('Lockout delay: 6 failures -> 60s', V.lockoutDelayMs(6) === 60000);
  check('Lockout delay: 7 failures -> 120s', V.lockoutDelayMs(7) === 120000);
  check('Lockout delay: 8 failures -> 240s', V.lockoutDelayMs(8) === 240000);
  check('Lockout delay: capped at 15 min', V.lockoutDelayMs(50) === 900000);
  let st = V.createLockoutState();
  check('Lockout: fresh state not locked', V.isLocked(st, 1000) === false);
  for (let i = 0; i < 4; i++) st = V.recordFailure(st, 1000 + i);
  check('Lockout: 4 failures not locked', V.isLocked(st, 2000) === false && st.failures === 4);
  st = V.recordFailure(st, 2000);
  check('Lockout: 5th failure locks for 30s', V.isLocked(st, 2000) === true && V.lockoutRemainingMs(st, 2000) === 30000, st);
  check('Lockout: still locked at +29s', V.isLocked(st, 2000 + 29000) === true);
  check('Lockout: free at +30s', V.isLocked(st, 2000 + 30000) === false);
  st = V.recordSuccess();
  check('Lockout: success resets failures', st.failures === 0 && st.lockoutUntil === 0);
  check('Auto-lock: 4m59s idle -> not locked', V.isIdleLocked(0, 4 * 60 * 1000 + 59000) === false);
  check('Auto-lock: 5m idle -> locked', V.isIdleLocked(0, 5 * 60 * 1000) === true);
  check('Auto-lock: 6m idle -> locked', V.isIdleLocked(0, 6 * 60 * 1000) === true);

  // ---- §3. Encrypted backup (v2 vault round-trip; v1 vault refused by the model) ----
  const made = await V.createVault('112233', 'backup-pass', SAMPLE);
  const backup = V.createBackup(made.envelope);
  const backupText = JSON.stringify(backup);
  const parsedEnv = V.parseBackup(backupText);
  check('Backup: envelope parses back', parsedEnv.v === 1 && parsedEnv.data === made.envelope.data);
  const restored = await V.unlockVault('112233', 'backup-pass', parsedEnv);
  check('Backup: round-trip restores the v2 vault',
    JSON.stringify(restored.vault) === JSON.stringify(SAMPLE) && M.isGharVault(restored.vault) === true);
  check('Backup: wrong PIN on import fails (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('112234', 'backup-pass', parsedEnv), 'DECRYPT_FAILED'));
  check('Backup: wrong passphrase on import fails (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('112233', 'wrong-pass', parsedEnv), 'DECRYPT_FAILED'));
  check('Backup: garbage file rejected (BAD_BACKUP)',
    throwsCode(() => V.parseBackup('not json at all'), 'BAD_BACKUP'));
  check('Backup: wrong app rejected (BAD_BACKUP)',
    throwsCode(() => V.parseBackup(JSON.stringify({ app: 'other-app', backupVersion: 1, envelope: made.envelope })), 'BAD_BACKUP'));
  check('Backup: missing envelope rejected (BAD_BACKUP)',
    throwsCode(() => V.parseBackup(JSON.stringify({ app: 'personal-card-vault', backupVersion: 1 })), 'BAD_BACKUP'));
  check('Backup: damaged envelope rejected (CORRUPT_VAULT)',
    throwsCode(() => V.parseBackup(JSON.stringify({ app: 'personal-card-vault', backupVersion: 1, envelope: { ...made.envelope, v: 99 } })), 'CORRUPT_VAULT'));
  check('Backup: createBackup with no envelope throws',
    throwsCode(() => V.createBackup(null), 'CORRUPT_VAULT'));
  // No migration: an old v1 vault object decrypts fine as bytes, but the
  // model refuses it — the app must say so instead of opening it.
  const v1Vault = { v: 1, createdAt: '2026-11-06T00:00:00.000Z', accounts: [{ id: 'a1', provider: 'HBL', last4: '1234', balance: 150000 }], transactions: [] };
  const v1Made = await V.createVault('123456', '', v1Vault);
  const v1Backup = JSON.stringify(V.createBackup(v1Made.envelope));
  const v1Env = V.parseBackup(v1Backup);
  const v1Opened = await V.unlockVault('123456', '', v1Env);
  check('No migration: v1 vault object decrypts but is NOT a Ghar vault',
    M.isGharVault(v1Opened.vault) === false && v1Opened.vault.v === 1);

  // ---- §4. Navigation (nav.js + the sidebar in index.html) ----
  const htmlSrc = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const EXPECTED_PAGES = ['home', 'staff', 'deliveries', 'udhaar', 'bills', 'documents',
    'medicine', 'summary', 'security', 'backup', 'profile'];
  check('Nav: PAGES order matches the plan sidebar order',
    JSON.stringify(N.PAGES) === JSON.stringify(EXPECTED_PAGES), N.PAGES);
  check('Nav: NAV_ORDER ids match PAGES in order',
    JSON.stringify(N.NAV_ORDER.map((n) => n.id)) === JSON.stringify(EXPECTED_PAGES));
  check('Nav: NAV_ORDER labels are the plan labels',
    JSON.stringify(N.NAV_ORDER.map((n) => n.label)) === JSON.stringify(
      ['Today', 'Staff', 'Deliveries', 'Udhaar', 'Bills', 'Documents', 'Medicine',
        'Summary', 'Security', 'Backup & Import', 'Profile']));
  check('Nav: NAV_ORDER hashes are #/id',
    N.NAV_ORDER.every((n) => n.hash === '#/' + n.id));
  check('Nav: routeForHash maps every page', EXPECTED_PAGES.every((p) => N.routeForHash('#/' + p) === p));
  check('Nav: unknown hash -> home', N.routeForHash('#/reconcile') === 'home' && N.routeForHash('#/nope') === 'home');
  check('Nav: empty / bare / non-string hash -> home',
    N.routeForHash('') === 'home' && N.routeForHash('#/') === 'home' && N.routeForHash(null) === 'home' && N.routeForHash(42) === 'home');
  check('Nav: uppercase hash -> home (routes are lowercase)',
    N.routeForHash('#/STAFF') === 'home');
  check('Nav: hash with a query still routes', N.routeForHash('#/bills?x=1') === 'bills');
  // The sidebar buttons in index.html, in order, match NAV_ORDER.
  const sidebarIds = [...htmlSrc.matchAll(/<button class="nav-btn" id="nav-([a-z]+)" data-page="([a-z]+)">/g)]
    .map((m) => ({ id: m[1], page: m[2] }));
  check('Nav: sidebar buttons exist for all 11 pages', sidebarIds.length === 11, sidebarIds.length);
  check('Nav: sidebar button order matches NAV_ORDER',
    JSON.stringify(sidebarIds.map((b) => b.id)) === JSON.stringify(EXPECTED_PAGES), sidebarIds);
  check('Nav: sidebar button labels match NAV_ORDER',
    N.NAV_ORDER.every((n) => htmlSrc.replace(/&amp;/g, '&').includes('>' + n.label + '</span>') || htmlSrc.includes('>' + n.label + '<')));
  check('Nav: no vault-era routes survive (#/reconcile, #/wallet, #/add, #/intelligence)',
    !/#\/(reconcile|wallet|add|intelligence)/.test(htmlSrc));

  // ---- §5. Model: vault shape, household, every collection, Today ----
  const v0 = M.emptyVault();
  check('Model: emptyVault is version 2 with all six collections empty',
    v0.version === 2 && v0.householdName === '' && v0.monthStartDay === 1
    && v0.staff.length === 0 && v0.deliveries.length === 0 && v0.udhaar.length === 0
    && v0.bills.length === 0 && v0.documents.length === 0 && v0.medicines.length === 0
    && Array.isArray(v0.settings.reminders.docDays) && Array.isArray(v0.settings.reminders.medDays));
  check('Model: isGharVault accepts an empty v2 vault', M.isGharVault(v0) === true);
  check('Model: isGharVault rejects a v1 vault object',
    M.isGharVault({ v: 1, accounts: [] }) === false);
  check('Model: isGharVault rejects null / missing collections',
    M.isGharVault(null) === false && M.isGharVault({ version: 2, staff: [] }) === false
    && M.isGharVault({ version: 2, staff: [], deliveries: [], udhaar: [], bills: [], documents: [] }) === false);
  check('Model: fmtRs formats integer rupees', M.fmtRs(15000) === 'Rs 15,000' && M.fmtRs(0) === 'Rs 0' && M.fmtRs(1000000) === 'Rs 1,000,000', M.fmtRs(15000));
  check('Model: isDateStr accepts a real date, rejects junk',
    M.isDateStr('2026-11-06') === true && M.isDateStr('2026-02-30') === false
    && M.isDateStr('06-11-2026') === false && M.isDateStr('') === false);
  check('Model: daysBetween counts whole days', M.daysBetween('2026-11-06', '2026-11-10') === 4 && M.daysBetween('2026-11-10', '2026-11-06') === -4 && M.daysBetween('2026-11-06', '2026-11-06') === 0);

  // Household (Profile page).
  const vH = M.emptyVault();
  const hh = M.setHousehold(vH, { householdName: '  Hashir Home ', monthStartDay: 5 });
  check('Model: setHousehold trims the name and stores the day',
    hh.householdName === 'Hashir Home' && hh.monthStartDay === 5 && vH.householdName === 'Hashir Home');
  check('Model: setHousehold allows an empty name', M.setHousehold(vH, { householdName: '', monthStartDay: 1 }).householdName === '');
  check('Model: setHousehold trims a >60-char name to 60',
    M.setHousehold(vH, { householdName: 'x'.repeat(80), monthStartDay: 1 }).householdName.length === 60);
  for (const bad of [0, 29, 1.5, 'x', null, undefined]) {
    check('Model: setHousehold rejects month start day ' + JSON.stringify(bad),
      throwsCode(() => M.setHousehold(M.emptyVault(), { householdName: 'H', monthStartDay: bad }), 'VALIDATION'));
  }

  // Staff.
  const vS = M.emptyVault();
  const staff = M.addStaff(vS, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2, phone: '0300-1234567' });
  check('Model: addStaff stores a helper with empty attendance/advances',
    staff.name === 'Ayesha' && staff.role === 'maid' && staff.salaryPkr === 15000
    && staff.phone === '0300-1234567' && Array.isArray(staff.advances) && Array.isArray(staff.paidMonths)
    && typeof staff.id === 'string' && staff.id.length > 0);
  check('Model: findStaff finds by id', M.findStaff(vS, staff.id) === staff && M.findStaff(vS, 'nope') === null);
  const staffBad = [
    [{ role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 }, 'missing name'],
    [{ name: 'A', role: 'king', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 }, 'bad role'],
    [{ name: 'A', role: 'maid', salaryPkr: 0, joinedDate: '2026-11-01', leavePerMonth: 2 }, 'salary 0'],
    [{ name: 'A', role: 'maid', salaryPkr: 15000.5, joinedDate: '2026-11-01', leavePerMonth: 2 }, 'salary not whole rupees'],
    [{ name: 'A', role: 'maid', salaryPkr: 15000, joinedDate: '2026-13-01', leavePerMonth: 2 }, 'bad joined date'],
    [{ name: 'A', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 32 }, 'leave 32'],
    [{ name: 'A', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2, phone: '12345' }, 'bad phone'],
  ];
  for (const [input, why] of staffBad) {
    check('Model: addStaff rejects ' + why,
      throwsCode(() => M.addStaff(M.emptyVault(), input), 'VALIDATION'));
  }
  check('Model: addStaff allows an empty phone', (() => {
    const v = M.emptyVault();
    return M.addStaff(v, { name: 'A', role: 'cook', salaryPkr: 20000, joinedDate: '2026-11-01', leavePerMonth: 0, phone: '' }).phone === '';
  })());

  // Deliveries.
  const vD = M.emptyVault();
  const del = M.addDelivery(vD, { name: 'Doodhwala', kind: 'Doodhwala', unit: 'litre', ratePkr: 220, usualQty: 1 });
  check('Model: addDelivery stores a delivery with an empty log',
    del.name === 'Doodhwala' && del.ratePkr === 220 && del.usualQty === 1 && typeof del.log === 'object');
  for (const [input, why] of [
    [{ name: 'X', kind: 'Milkman', unit: 'litre', ratePkr: 220, usualQty: 1 }, 'bad kind'],
    [{ name: 'X', kind: 'Doodhwala', unit: 'kg', ratePkr: 220, usualQty: 1 }, 'bad unit'],
    [{ name: 'X', kind: 'Doodhwala', unit: 'litre', ratePkr: 0, usualQty: 1 }, 'rate 0'],
    [{ name: '', kind: 'Doodhwala', unit: 'litre', ratePkr: 220, usualQty: 1 }, 'missing name'],
    [{ name: 'X', kind: 'Doodhwala', unit: 'litre', ratePkr: 220, usualQty: -1 }, 'negative qty'],
  ]) {
    check('Model: addDelivery rejects ' + why,
      throwsCode(() => M.addDelivery(M.emptyVault(), input), 'VALIDATION'));
  }

  // Udhaar: people, entries, balances (recomputed, never stored).
  const vU = M.emptyVault();
  check('Model: addUdhaarPerson rejects an empty name',
    throwsCode(() => M.addUdhaarPerson(vU, { person: '  ' }), 'VALIDATION'));
  const person = M.addUdhaarPerson(vU, { person: 'Ahmed' });
  check('Model: addUdhaarPerson stores a person with no entries',
    person.person === 'Ahmed' && person.entries.length === 0);
  check('Model: findUdhaarPerson finds by id', M.findUdhaarPerson(vU, person.id) === person);
  const entry = M.addUdhaarEntry(vU, person.id, { direction: 'lent', amountPkr: 20000, date: '2026-11-01', reason: 'shop rent', dueDate: '2026-11-20' });
  check('Model: addUdhaarEntry stores a lent entry, unsettled, nothing forgiven',
    entry.direction === 'lent' && entry.amountPkr === 20000 && entry.settled === false && entry.forgivenPkr === 0);
  check('Model: udhaarEntryBalance starts at the full amount', M.udhaarEntryBalance(entry) === 20000);
  entry.repayments.push({ amountPkr: 5000, date: '2026-11-05' });
  check('Model: lent 20,000, repaid 5,000 -> balance 15,000', M.udhaarEntryBalance(entry) === 15000);
  entry.forgivenPkr = 2000;
  check('Model: forgiven 2,000 reduces the balance and is not a payment',
    M.udhaarEntryBalance(entry) === 13000 && entry.repayments.length === 1);
  const entry2 = M.addUdhaarEntry(vU, person.id, { direction: 'borrowed', amountPkr: 3000, date: '2026-11-02', reason: '', dueDate: null });
  const pb = M.udhaarPersonBalance(person);
  check('Model: person balance splits lent / borrowed',
    pb.lent === 13000 && pb.borrowed === 3000, pb);
  for (const [input, why] of [
    [{ direction: 'given', amountPkr: 1000, date: '2026-11-01' }, 'bad direction'],
    [{ direction: 'lent', amountPkr: 0, date: '2026-11-01' }, 'amount 0'],
    [{ direction: 'lent', amountPkr: 1000, date: 'tomorrow' }, 'bad date'],
    [{ direction: 'lent', amountPkr: 1000, date: '2026-11-01', reason: 'x'.repeat(121) }, 'reason > 120 chars'],
    [{ direction: 'lent', amountPkr: 1000, date: '2026-11-01', dueDate: 'next week' }, 'bad due date'],
  ]) {
    check('Model: addUdhaarEntry rejects ' + why,
      throwsCode(() => M.addUdhaarEntry(vU, person.id, input), 'VALIDATION'));
  }
  check('Model: addUdhaarEntry to an unknown person fails (NOT_FOUND)',
    throwsCode(() => M.addUdhaarEntry(vU, 'nope', { direction: 'lent', amountPkr: 1000, date: '2026-11-01' }), 'NOT_FOUND'));

  // Bills (typed only — never fetched).
  const vB = M.emptyVault();
  const bill = M.addBill(vB, { type: 'electricity', provider: 'IESCO', accountNo: '1234567890', amountPkr: 8500, dueDate: '2026-11-10', surchargeNote: 'Rs 500 after due date' });
  check('Model: addBill stores a due bill',
    bill.type === 'electricity' && bill.provider === 'IESCO' && bill.amountPkr === 8500
    && bill.status === 'due' && bill.paidDate === null);
  check('Model: findBill finds by id', M.findBill(vB, bill.id) === bill);
  for (const [input, why] of [
    [{ type: 'tax', provider: 'FBR', amountPkr: 100, dueDate: '2026-11-10' }, 'bad type'],
    [{ type: 'gas', provider: '', amountPkr: 100, dueDate: '2026-11-10' }, 'missing provider'],
    [{ type: 'gas', provider: 'SNGPL', amountPkr: 0, dueDate: '2026-11-10' }, 'amount 0'],
    [{ type: 'gas', provider: 'SNGPL', amountPkr: 100, dueDate: '2026-11-32' }, 'bad due date'],
    [{ type: 'gas', provider: 'SNGPL', amountPkr: 100, dueDate: '2026-11-10', accountNo: 'x'.repeat(41) }, 'account number > 40 chars'],
    [{ type: 'gas', provider: 'SNGPL', amountPkr: 100, dueDate: '2026-11-10', surchargeNote: 'x'.repeat(121) }, 'surcharge note > 120 chars'],
  ]) {
    check('Model: addBill rejects ' + why,
      throwsCode(() => M.addBill(M.emptyVault(), input), 'VALIDATION'));
  }

  // Documents.
  const vDoc = M.emptyVault();
  const doc = M.addDocument(vDoc, { type: 'passport', owner: 'Abu', issueDate: '2021-01-01', expiryDate: '2027-01-01' });
  check('Model: addDocument stores a passport with its checklist key',
    doc.type === 'passport' && doc.owner === 'Abu' && doc.checklistKey === 'passport' && doc.photo === null);
  const doc2 = M.addDocument(vDoc, { type: 'warranty', owner: 'Ami', expiryDate: '2027-01-01' });
  check('Model: a type without a v1 checklist gets checklistKey null',
    doc2.checklistKey === null && doc2.issueDate === null);
  check('Model: addDocument accepts a JPEG data-URL photo', (() => {
    const v = M.emptyVault();
    return M.addDocument(v, { type: 'CNIC', owner: 'Me', expiryDate: '2030-01-01', photo: { dataUrl: 'data:image/jpeg;base64,/9j/xxx', mime: 'image/jpeg' } }).photo !== null;
  })());
  for (const [input, why] of [
    [{ type: 'visa', owner: 'Abu', expiryDate: '2027-01-01' }, 'bad type'],
    [{ type: 'CNIC', owner: '', expiryDate: '2027-01-01' }, 'missing owner'],
    [{ type: 'CNIC', owner: 'Me', expiryDate: 'not-a-date' }, 'bad expiry date'],
    [{ type: 'CNIC', owner: 'Me', issueDate: '32-01-2021', expiryDate: '2027-01-01' }, 'bad issue date'],
    [{ type: 'CNIC', owner: 'Me', expiryDate: '2027-01-01', photo: { dataUrl: 'http://x/y.jpg', mime: 'image/jpeg' } }, 'photo not a data URL'],
  ]) {
    check('Model: addDocument rejects ' + why,
      throwsCode(() => M.addDocument(M.emptyVault(), input), 'VALIDATION'));
  }

  // Medicines.
  const vMed = M.emptyVault();
  const med = M.addMedicine(vMed, { name: 'Panadol', qtyLeft: 10, unit: 'tablets', expiryDate: '2027-06-01', place: 'cupboard', person: 'Ami', dosesPerDay: 3, lowStockAt: 5 });
  check('Model: addMedicine stores a medicine with an empty dose log',
    med.name === 'Panadol' && med.qtyLeft === 10 && med.dosesPerDay === 3 && med.lowStockAt === 5 && med.dosesTaken.length === 0);
  for (const [input, why] of [
    [{ name: '', qtyLeft: 10, expiryDate: '2027-06-01' }, 'missing name'],
    [{ name: 'X', qtyLeft: -1, expiryDate: '2027-06-01' }, 'negative quantity'],
    [{ name: 'X', qtyLeft: 10, expiryDate: '2027-13-01' }, 'bad expiry date'],
    [{ name: 'X', qtyLeft: 10, expiryDate: '2027-06-01', place: 'drawer' }, 'bad place'],
    [{ name: 'X', qtyLeft: 10, expiryDate: '2027-06-01', dosesPerDay: 25 }, 'doses per day 25'],
    [{ name: 'X', qtyLeft: 10, expiryDate: '2027-06-01', lowStockAt: -1 }, 'negative low-stock number'],
  ]) {
    check('Model: addMedicine rejects ' + why,
      throwsCode(() => M.addMedicine(M.emptyVault(), input), 'VALIDATION'));
  }

  // Today (Home page) — fixed "today" so the tests never depend on the clock.
  const TODAY = '2026-11-06';
  check('Model: todayItems on an empty vault is []', M.todayItems(M.emptyVault(), TODAY).length === 0);
  const vT = M.emptyVault();
  M.addBill(vT, { type: 'electricity', provider: 'IESCO', amountPkr: 8500, dueDate: '2026-11-10' });
  M.addBill(vT, { type: 'gas', provider: 'SNGPL', amountPkr: 3000, dueDate: '2026-11-14' });
  M.addBill(vT, { type: 'water', provider: 'WASA', amountPkr: 1200, dueDate: '2026-11-04' });
  const paidBill = M.addBill(vT, { type: 'internet', provider: 'PTCL', amountPkr: 4000, dueDate: '2026-11-07' });
  paidBill.status = 'paid'; paidBill.paidDate = '2026-11-05';
  M.addDocument(vT, { type: 'passport', owner: 'Abu', expiryDate: '2026-12-12' });
  M.addDocument(vT, { type: 'CNIC', owner: 'Me', expiryDate: '2026-11-26' });
  M.addDocument(vT, { type: 'driving licence', owner: 'Abu', expiryDate: '2026-10-20' });
  M.addMedicine(vT, { name: 'Panadol', qtyLeft: 10, unit: 'tablets', expiryDate: '2027-06-01', place: 'cupboard', person: 'Ami' });
  M.addMedicine(vT, { name: 'Insulin', qtyLeft: 3, unit: 'bottles', expiryDate: '2027-06-01', place: 'fridge', person: 'Abu', lowStockAt: 5 });
  const up = M.addUdhaarPerson(vT, { person: 'Ahmed' });
  const ue = M.addUdhaarEntry(vT, up.id, { direction: 'lent', amountPkr: 20000, date: '2026-11-01', dueDate: '2026-11-05' });
  ue.repayments.push({ amountPkr: 5000, date: '2026-11-05' });
  const ueSettled = M.addUdhaarEntry(vT, up.id, { direction: 'lent', amountPkr: 1000, date: '2026-11-01', dueDate: '2026-11-01' });
  ueSettled.settled = true;
  M.addUdhaarEntry(vT, up.id, { direction: 'borrowed', amountPkr: 7000, date: '2026-11-01' });
  M.addStaff(vT, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 });
  const items = M.todayItems(vT, TODAY);
  const kinds = items.map((i) => i.kind + ':' + i.title.split(' — ')[0]);
  check('Model: Today shows the bill due in 4 days', items.some((i) => i.kind === 'bill' && i.daysUntil === 4 && i.detail.includes('Rs 8,500')), kinds);
  check('Model: Today hides the bill due in 8 days', !items.some((i) => i.kind === 'bill' && i.title.includes('SNGPL')));
  check('Model: Today shows the overdue water bill', items.some((i) => i.kind === 'bill' && i.overdue === true && i.daysUntil === -2));
  check('Model: Today hides a paid bill', !items.some((i) => i.kind === 'bill' && i.title.includes('PTCL')));
  check('Model: Today hides a document expiring in 36 days (30-day window)', !items.some((i) => i.kind === 'document' && i.title.includes('passport')));
  check('Model: Today shows a document expiring in 20 days', items.some((i) => i.kind === 'document' && i.daysUntil === 20));
  check('Model: Today shows an expired document, overdue', items.some((i) => i.kind === 'document' && i.overdue === true && i.daysUntil === -17));
  check('Model: Today hides a medicine expiring far away with stock', !items.some((i) => i.kind === 'medicine' && i.title.startsWith('Panadol')));
  check('Model: Today shows a low-stock medicine even with a far expiry', items.some((i) => i.kind === 'medicine' && i.title.startsWith('Insulin') && i.detail.includes('low stock')));
  check('Model: Today shows overdue udhaar with the running balance',
    items.some((i) => i.kind === 'udhaar' && i.daysUntil === -1 && i.detail.includes('Rs 15,000') && i.detail.includes('Rs 20,000')), kinds);
  check('Model: Today hides a settled udhaar entry', !items.some((i) => i.kind === 'udhaar' && i.detail.includes('Rs 1,000')));
  check('Model: Today hides udhaar with no due date', !items.some((i) => i.kind === 'udhaar' && i.detail.includes('Rs 7,000')));
  check('Model: Today hides staff pay far from month end (Nov 6, pay due Nov 30)',
    !items.some((i) => i.kind === 'staff'));
  const nearEnd = M.todayItems(vT, '2026-11-25');
  check('Model: Today shows staff pay within 7 days of month end',
    nearEnd.some((i) => i.kind === 'staff' && i.title.includes('Ayesha') && i.date === '2026-11-30'));
  const paidMonthVault = M.emptyVault();
  const pmStaff = M.addStaff(paidMonthVault, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 });
  pmStaff.paidMonths.push({ month: '2026-11', working: {}, netPkr: 15000, paidDate: '2026-11-25' });
  check('Model: Today hides staff pay for a month already marked paid',
    !M.todayItems(paidMonthVault, '2026-11-25').some((i) => i.kind === 'staff'));
  check('Model: Today is sorted soonest-first',
    items.every((it, idx) => idx === 0 || items[idx - 1].date <= it.date), items.map((i) => i.date));
  check('Model: every Today item carries a page link',
    items.every((i) => typeof i.link === 'string' && i.link.startsWith('#/')));
  check('Model: dueLabel overdue singular', M.dueLabel({ daysUntil: -1 }) === 'OVERDUE by 1 day');
  check('Model: dueLabel overdue plural', M.dueLabel({ daysUntil: -2 }) === 'OVERDUE by 2 days');
  check('Model: dueLabel today', M.dueLabel({ daysUntil: 0 }) === 'due today');
  check('Model: dueLabel in 1 day', M.dueLabel({ daysUntil: 1 }) === 'due in 1 day');
  check('Model: dueLabel in 4 days', M.dueLabel({ daysUntil: 4 }) === 'due in 4 days');
  check('Model: dueLabel empty item', M.dueLabel(null) === '');

  // ---- §6. Design tokens: WCAG AA contrast + tap targets, from real CSS ----
  const cssSrc = fs.readFileSync(path.join(__dirname, 'public', 'styles.css'), 'utf8');
  function hexRgb(h) {
    const n = parseInt(h.slice(1), 16);
    return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
  }
  function blendOver(fg, a, bg) {
    return fg.map((c, i) => c * a + bg[i] * (1 - a));
  }
  function relLum(rgb) {
    const f = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
    const [r, g, b] = rgb.map(f);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }
  function ratio(a, b) {
    const l1 = relLum(a), l2 = relLum(b);
    const hi = Math.max(l1, l2), lo = Math.min(l1, l2);
    return (hi + 0.05) / (lo + 0.05);
  }
  const glassMatch = cssSrc.match(/\.glass[^{]*\{[^}]*linear-gradient\(135deg,\s*rgba\(([^)]+)\),\s*rgba\(([^)]+)\)\)/);
  check('Contrast: glass rgba tokens parse from styles.css', !!glassMatch);
  const darkBg = hexRgb('#5a432a');
  const glassStops = glassMatch ? [glassMatch[1], glassMatch[2]].map((s) => {
    const parts = s.split(',').map((x) => parseFloat(x));
    return blendOver([parts[0] / 255, parts[1] / 255, parts[2] / 255], parts[3], darkBg);
  }) : [];
  const effGlass = glassStops.length ? glassStops.reduce((a, b) => (relLum(a) < relLum(b) ? a : b)) : [1, 1, 1];
  check('Contrast: darkest effective glass over #5a432a is ~#d1c5b7',
    Math.abs(effGlass[0] * 255 - 209) < 4 && Math.abs(effGlass[1] * 255 - 197) < 4 && Math.abs(effGlass[2] * 255 - 183) < 4,
    'rgb(' + effGlass.map((c) => Math.round(c * 255)).join(',') + ')');
  function cssColor(re) {
    const m = cssSrc.match(re);
    return m ? m[1] : null;
  }
  const contrastTexts = [
    ['body text', cssColor(/body\s*\{[^}]*color:\s*(#[0-9a-f]{6})/)],
    ['muted text', cssColor(/\.muted\s*\{[^}]*color:\s*(#[0-9a-f]{6})/)],
    ['success text', cssColor(/\.ok\s*\{[^}]*color:\s*(#[0-9a-f]{6})/)],
    ['error text', cssColor(/\.error\s*\{[^}]*color:\s*(#[0-9a-f]{6})/)],
  ];
  for (const [label, hex] of contrastTexts) {
    check('Contrast: ' + label + ' (' + hex + ') on glass >= 4.5:1',
      !!hex && ratio(hexRgb(hex), effGlass) >= 4.5,
      hex ? ratio(hexRgb(hex), effGlass).toFixed(2) + ':1' : 'token missing');
  }
  const pillBg = cssColor(/^button\s*\{[^}]*background:\s*(#[0-9a-f]{6})/m);
  const greenBg = cssColor(/\.ok\s*\{[^}]*color:\s*(#[0-9a-f]{6})/);
  const amberBg = '#7c2d12';
  const whiteOn = [
    ['white on black pill button', pillBg],
    ['white on success green', greenBg],
    ['white on amber (locked pill)', amberBg],
  ];
  for (const [label, hex] of whiteOn) {
    check('Contrast: ' + label + ' (' + hex + ') >= 4.5:1',
      !!hex && ratio([1, 1, 1], hexRgb(hex)) >= 4.5,
      hex ? ratio([1, 1, 1], hexRgb(hex)).toFixed(2) + ':1' : 'token missing');
  }
  // Tap targets 44px+: nav buttons (11px padding + 15px text at 1.5 line-height)
  // and base buttons (12px padding + 15px text) both clear 44px tall.
  const navPad = cssSrc.match(/\.nav-btn\s*\{[^}]*padding:\s*(\d+)px\s+(\d+)px/);
  const navFont = cssSrc.match(/\.nav-btn\s*\{[^}]*font-size:\s*(\d+)px/);
  check('Tap target: sidebar nav buttons are >= 44px tall',
    !!navPad && !!navFont && (2 * Number(navPad[1]) + 1.5 * Number(navFont[1])) >= 44,
    navPad ? navPad[0] : 'nav-btn padding missing');
  const btnPad = cssSrc.match(/^button\s*\{[^}]*padding:\s*(\d+)px\s+(\d+)px/m);
  const btnFont = cssSrc.match(/^button\s*\{[^}]*font-size:\s*(\d+)px/m);
  check('Tap target: base buttons are >= 44px tall',
    !!btnPad && !!btnFont && (2 * Number(btnPad[1]) + 1.5 * Number(btnFont[1])) >= 44);
  check('Mobile: 375px layout has an icon-rail sidebar + narrow-screen rules',
    cssSrc.includes('@media (max-width: 960px)') && cssSrc.includes('@media (max-width: 560px)')
    && cssSrc.includes('#sidebar .nav-label'));

  // ---- §7. Review pass: wiring, removed modules, honesty rules, server ----
  const appSrc = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
  const usedIds = [...new Set([...appSrc.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]))];
  const definedIds = new Set([
    ...[...htmlSrc.matchAll(/id="([^"]+)"/g)].map((m) => m[1]),
    ...[...appSrc.matchAll(/id="([^"]+)"/g)].map((m) => m[1]),
  ]);
  // An id ending in '-' is a prefix (e.g. 'nav-' + page, 'page-' + page):
  // it counts as covered when real ids with that prefix exist.
  const missingIds = usedIds.filter((id) => !definedIds.has(id)
    && ![...definedIds].some((d) => id.endsWith('-') && d.startsWith(id)));
  check('Review: every ID touched by app.js exists in the page', missingIds.length === 0, missingIds);
  check('Review: app.js touches a real set of IDs', usedIds.length > 25, usedIds.length);
  const mods = { VaultCrypto: V, GharModel: M, Nav: N };
  let apiOk = true; const apiMissing = [];
  for (const [name, mod] of Object.entries(mods)) {
    const used = [...new Set([...appSrc.matchAll(new RegExp(name + '\\.(\\w+)', 'g'))].map((m) => m[1]))];
    for (const fn of used) {
      if (typeof mod[fn] === 'undefined') { apiOk = false; apiMissing.push(name + '.' + fn); }
    }
  }
  check('Review: every shared-module call in app.js exists', apiOk, apiMissing);
  check('Review: app.js never reaches a page while locked (route guard)',
    appSrc.includes('if (!state.key) { showScreen(') && appSrc.includes("showScreen(state.envelope ? 'unlock' : 'setup')"));
  check('Review: app.js rejects a v1 vault on unlock and on import',
    (appSrc.match(/!GharModel\.isGharVault/g) || []).length >= 2);
  check('Review: app.js auto-locks after 5 idle minutes',
    appSrc.includes('isIdleLocked') && appSrc.includes('setInterval(autoLockCheck, 15000)'));
  // Removed modules: gone from disk and unreferenced by the app code.
  // (server.js still lists them in its static allowlist — rename-only per
  // the plan — but the files do not exist, so they serve 404; checked in §9.)
  for (const f of ['sms.js', 'intel.js', 'totp.js', 'cards.js']) {
    check('Review: removed module ' + f + ' is deleted from public/',
      !fs.existsSync(path.join(__dirname, 'public', f)));
  }
  const appCode = [htmlSrc, appSrc,
    fs.readFileSync(path.join(__dirname, 'public', 'model.js'), 'utf8'),
    fs.readFileSync(path.join(__dirname, 'public', 'nav.js'), 'utf8')].join('\n');
  check('Review: no removed-module file or API is referenced by the app code',
    !/(sms|intel|totp|cards)\.js|SmsParser|Intel\.|Totp\.|Cards\./.test(appCode));
  check('Review: ocr.js + vendor stay on disk but are NOT loaded by any page',
    fs.existsSync(path.join(__dirname, 'public', 'ocr.js'))
    && fs.existsSync(path.join(__dirname, 'public', 'vendor', 'tesseract'))
    && !/ocr\.js|vendor\//.test(htmlSrc) && !/ocr\.js|vendor\//.test(appSrc));
  // R1: the app never claims anything is confirmed / verified / real.
  const visibleHtml = htmlSrc.replace(/<[^>]*>/g, ' ');
  check('R1: index.html never says "confirmed", "verified" or "real"',
    !/\b(confirmed|verified|real)\b/i.test(visibleHtml));
  check('R1: app.js user-facing strings never say "confirmed", "verified" or "real"',
    !/\b(confirmed|verified|real)\b/i.test(appSrc));
  check('R1: the page states the no-migration rule on first run',
    htmlSrc.includes('An old Card Vault backup does not open here'));
  check('R1: the page labels every record "as you entered it"',
    htmlSrc.includes('as you entered it') && appSrc.includes('as you entered it'));
  check('R1: the page states the honest limits (nothing fetched, no reminders closed, no recovery)',
    htmlSrc.includes('Nothing is fetched, checked or looked up')
    && htmlSrc.includes('There are no reminders when the app is closed')
    && htmlSrc.includes('No recovery, by design'));
  // R2: no live data — no network calls from the app.
  check('R2: app.js makes no network calls (no fetch / XHR / WebSocket)',
    !/fetch\s*\(|XMLHttpRequest|WebSocket/.test(appSrc));
  check('R2: app.js never reads SMS', !/sms/i.test(appSrc) && !/sms/i.test(htmlSrc));
  // The server stores nothing: no POST/PUT/DELETE routes, no database.
  const serverSrc = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  check('Review: server has no write routes (GET only)', !/req\.method === '(POST|PUT|DELETE|PATCH)'/.test(serverSrc));
  check('Review: server has no database', !/sqlite|DatabaseSync|fs\.writeFile/.test(serverSrc));
  check('Review: server log line + title name the new app',
    serverSrc.includes('Ghar ka Register listening') && serverSrc.startsWith('// Ghar ka Register'));
  check('Review: server.js keeps the old app name out',
    !serverSrc.includes('Personal Card Vault'));
  // The six scripts the shell needs are loaded, in order, and nothing else.
  const scriptOrder = [...htmlSrc.matchAll(/<script src="\/([a-z]+\.js)"><\/script>/g)].map((m) => m[1]);
  check('Review: index.html loads exactly the six Phase-1 scripts in order',
    JSON.stringify(scriptOrder) === JSON.stringify(['vault.js', 'model.js', 'csv.js', 'proof.js', 'nav.js', 'app.js']), scriptOrder);
  check('Review: homepage names the app + the empty-Today state',
    htmlSrc.includes('Ghar ka Register') && htmlSrc.includes('Nothing due — add your first helper, bill or document.'));
  check('Review: homepage has all 11 page sections',
    EXPECTED_PAGES.every((p) => htmlSrc.includes('id="page-' + p + '"')));

  // ---- §7b. Phase 2 model: Staff attendance / advances / month-end pay ----
  check('Phase 2: model exports the new Staff + Deliveries functions',
    ['markAttendance', 'attendanceCounts', 'addAdvance', 'advanceRemaining',
      'staffRemainingAdvance', 'advanceMonthRecovery', 'payWorkingForHelper',
      'computeMonthPay', 'markMonthPaid', 'staffPayStatement',
      'findPaidStaffMonth', 'isStaffMonthPaid', 'findDelivery',
      'logDelivery', 'addGasRefill', 'lastGasRefill', 'gasDaysSinceLastRefill',
      'deliveryMonthTotal', 'markDeliveryMonthPaid',
      'findPaidDeliveryMonth', 'isDeliveryMonthPaid', 'isMonthKey',
      'daysInMonth', 'monthKeyOf'].every((f) => typeof M[f] === 'function'));
  check('Phase 2: isMonthKey / daysInMonth (incl. leap February)',
    M.isMonthKey('2026-11') === true && M.isMonthKey('2026-13') === false
    && M.isMonthKey('2026-1') === false && M.isMonthKey('Nov 2026') === false
    && M.daysInMonth('2026-11') === 30 && M.daysInMonth('2026-02') === 28
    && M.daysInMonth('2024-02') === 29 && M.monthKeyOf('2026-11-06') === '2026-11');

  function payVault() {
    const v = M.emptyVault();
    const s = M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2, phone: '03001234567' });
    return { v, s };
  }
  // Attendance: only exceptions are stored; present deletes the mark.
  {
    const { v, s } = payVault();
    check('Phase 2: markAttendance stores an absent exception',
      M.markAttendance(v, s.id, '2026-11-03', 'absent').mark === 'absent' && s.attendance['2026-11-03'] === 'absent');
    check('Phase 2: markAttendance defaults to present when no mark is given',
      M.markAttendance(v, s.id, '2026-11-04').mark === 'present');
    M.markAttendance(v, s.id, '2026-11-05', 'half');
    check('Phase 2: marking a day present again deletes the stored exception',
      M.markAttendance(v, s.id, '2026-11-05', 'present').mark === 'present' && !('2026-11-05' in s.attendance));
    check('Phase 2: attendanceCounts counts only that month',
      M.attendanceCounts(s, '2026-11').absentDays === 1 && M.attendanceCounts(s, '2026-11').halfDays === 0
      && M.attendanceCounts(s, '2026-12').absentDays === 0);
    check('Phase 2: markAttendance for an unknown helper fails (NOT_FOUND)',
      throwsCode(() => M.markAttendance(v, 'nope', '2026-11-03', 'absent'), 'NOT_FOUND'));
    check('Phase 2: markAttendance rejects a bad date',
      throwsCode(() => M.markAttendance(v, s.id, '2026-11-32', 'absent'), 'VALIDATION'));
    check('Phase 2: markAttendance rejects a bad mark',
      throwsCode(() => M.markAttendance(v, s.id, '2026-11-03', 'sick'), 'VALIDATION'));
  }
  // Advances: validation + remaining.
  {
    const { v, s } = payVault();
    const a = M.addAdvance(v, s.id, { amount: 2000, date: '2026-11-05', note: 'for medicine', recovery: 'full' });
    check('Phase 2: addAdvance stores a full-recovery advance, nothing recovered yet',
      a.amount === 2000 && a.recovery === 'full' && a.recoveredPkr === 0 && M.advanceRemaining(a) === 2000);
    const b = M.addAdvance(v, s.id, { amount: 1500, date: '2026-11-06', recovery: 'instalments', instalmentPkr: 500 });
    check('Phase 2: addAdvance stores an instalment advance with its instalment',
      b.recovery === 'instalments' && b.instalmentPkr === 500 && M.staffRemainingAdvance(s) === 3500);
    check('Phase 2: addAdvance defaults recovery to full when omitted',
      M.addAdvance(v, s.id, { amount: 100, date: '2026-11-07' }).recovery === 'full');
    for (const [input, why] of [
      [{ amount: 0, date: '2026-11-05', recovery: 'full' }, 'amount 0'],
      [{ amount: -500, date: '2026-11-05', recovery: 'full' }, 'negative amount'],
      [{ amount: 100.5, date: '2026-11-05', recovery: 'full' }, 'amount not whole rupees'],
      [{ amount: 500, date: 'not-a-date', recovery: 'full' }, 'bad date'],
      [{ amount: 500, date: '2026-11-05', recovery: 'instalments' }, 'instalments with no instalment'],
      [{ amount: 500, date: '2026-11-05', recovery: 'instalments', instalmentPkr: 0 }, 'instalment 0'],
      [{ amount: 500, date: '2026-11-05', recovery: 'whenever' }, 'bad recovery mode'],
      [{ amount: 500, date: '2026-11-05', recovery: 'full', note: 'x'.repeat(121) }, 'note > 120 chars'],
    ]) {
      check('Phase 2: addAdvance rejects ' + why,
        throwsCode(() => M.addAdvance(v, s.id, input), 'VALIDATION'));
    }
    check('Phase 2: addAdvance for an unknown helper fails (NOT_FOUND)',
      throwsCode(() => M.addAdvance(v, 'nope', { amount: 500, date: '2026-11-05', recovery: 'full' }), 'NOT_FOUND'));
  }
  // Acceptance: Rs 15,000 salary, 3 absent days, Rs 2,000 advance (full
  // recovery) pays Rs 15,000 − 1,500 − 2,000 = Rs 11,500, every line shown.
  {
    const { v, s } = payVault();
    M.markAttendance(v, s.id, '2026-11-01', 'absent');
    M.markAttendance(v, s.id, '2026-11-02', 'absent');
    M.markAttendance(v, s.id, '2026-11-03', 'absent');
    M.addAdvance(v, s.id, { amount: 2000, date: '2026-11-05', recovery: 'full' });
    const w = M.computeMonthPay(v, s.id, '2026-11');
    check('Phase 2 acceptance: 15,000 − 3 absent − 2,000 advance = 11,500 net',
      w.salaryPkr === 15000 && w.absentDays === 3 && w.halfDays === 0
      && w.absentDeduction === 1500 && w.halfDeduction === 0
      && w.advanceRecovery === 2000 && w.netPkr === 11500 && w.daysInMonth === 30, w);
    const stmt = M.staffPayStatement(s, '2026-11');
    check('Phase 2: WhatsApp statement contains every working line',
      stmt.includes('Ayesha') && stmt.includes('2026-11')
      && stmt.includes('Monthly salary: Rs 15,000')
      && stmt.includes('Absent days: 3 x Rs 500 = Rs 1,500')
      && stmt.includes('Half days: 0 x Rs 250 = Rs 0')
      && stmt.includes('Advance recovery: Rs 2,000')
      && stmt.includes('Net payable: Rs 15,000 - Rs 1,500 - Rs 0 - Rs 2,000 = Rs 11,500')
      && stmt.includes('as you entered it'), stmt);
    check('Phase 2: computeMonthPay rejects a bad month key',
      throwsCode(() => M.computeMonthPay(v, s.id, '2026-13'), 'VALIDATION'));
    check('Phase 2: computeMonthPay for an unknown helper fails (NOT_FOUND)',
      throwsCode(() => M.computeMonthPay(v, 'nope', '2026-11'), 'NOT_FOUND'));
    // Half days + rounding: salary ÷ 60 rounds to the rupee, halves up.
    const vH = M.emptyVault();
    const h = M.addStaff(vH, { name: 'Bilal', role: 'driver', salaryPkr: 10000, joinedDate: '2026-11-01', leavePerMonth: 2 });
    M.markAttendance(vH, h.id, '2026-11-02', 'half');
    M.markAttendance(vH, h.id, '2026-11-03', 'absent');
    const wH = M.computeMonthPay(vH, h.id, '2026-11');
    check('Phase 2: half-day deduction is salary ÷ 60, rounded (10,000 ÷ 60 = 167)',
      wH.halfDays === 1 && wH.halfDeduction === 167, wH);
    check('Phase 2: absent deduction is salary ÷ 30, rounded (10,000 ÷ 30 = 333)',
      wH.absentDays === 1 && wH.absentDeduction === 333 && wH.netPkr === 10000 - 333 - 167, wH);
  }
  // Instalments: exactly one instalment per month; the last month takes
  // only what is left.
  {
    const { v, s } = payVault();
    M.addAdvance(v, s.id, { amount: 2000, date: '2026-11-05', recovery: 'instalments', instalmentPkr: 500 });
    check('Phase 2: instalment advance recovers exactly 500 in month 1',
      M.computeMonthPay(v, s.id, '2026-11').advanceRecovery === 500
      && M.computeMonthPay(v, s.id, '2026-11').netPkr === 14500);
    const paid1 = M.markMonthPaid(v, s.id, '2026-11', '2026-11-30');
    check('Phase 2: marking month 1 paid stores the working + net + paid date',
      paid1.month === '2026-11' && paid1.netPkr === 14500 && paid1.paidDate === '2026-11-30'
      && paid1.working.advanceRecovery === 500 && M.staffRemainingAdvance(s) === 1500);
    check('Phase 2: instalment advance recovers exactly 500 again in month 2',
      M.computeMonthPay(v, s.id, '2026-12').advanceRecovery === 500
      && M.computeMonthPay(v, s.id, '2026-12').netPkr === 14500);
    M.markMonthPaid(v, s.id, '2026-12', '2026-12-31');
    M.markMonthPaid(v, s.id, '2027-01', '2027-01-31');
    M.markMonthPaid(v, s.id, '2027-02', '2027-02-28');
    check('Phase 2: after 4 instalments the advance is cleared (500 x 4 = 2,000)',
      M.staffRemainingAdvance(s) === 0
      && M.computeMonthPay(v, s.id, '2027-03').advanceRecovery === 0);
    const { v: v2, s: s2 } = payVault();
    M.addAdvance(v2, s2.id, { amount: 700, date: '2026-11-05', recovery: 'instalments', instalmentPkr: 500 });
    M.markMonthPaid(v2, s2.id, '2026-11', '2026-11-30');
    check('Phase 2: the last instalment takes only the remainder (700 − 500 = 200)',
      M.computeMonthPay(v2, s2.id, '2026-12').advanceRecovery === 200
      && M.computeMonthPay(v2, s2.id, '2026-12').netPkr === 14800);
  }
  // Locked month: attendance / advance / compute / pay all refuse, and a
  // later month still works.
  {
    const { v, s } = payVault();
    M.markAttendance(v, s.id, '2026-11-01', 'absent');
    M.addAdvance(v, s.id, { amount: 2000, date: '2026-11-05', recovery: 'full' });
    M.markMonthPaid(v, s.id, '2026-11', '2026-11-30');
    check('Phase 2: a paid month is locked — attendance refuses',
      throwsCode(() => M.markAttendance(v, s.id, '2026-11-10', 'absent'), 'LOCKED'));
    check('Phase 2: a paid month is locked — advance refuses',
      throwsCode(() => M.addAdvance(v, s.id, { amount: 100, date: '2026-11-15', recovery: 'full' }), 'LOCKED'));
    check('Phase 2: a paid month is locked — compute refuses',
      throwsCode(() => M.computeMonthPay(v, s.id, '2026-11'), 'LOCKED'));
    check('Phase 2: a paid month is locked — marking paid again refuses',
      throwsCode(() => M.markMonthPaid(v, s.id, '2026-11', '2026-11-30'), 'LOCKED'));
    check('Phase 2: the stored paid working survives the lock',
      M.findPaidStaffMonth(s, '2026-11').netPkr === 12500
      && M.isStaffMonthPaid(s, '2026-11') === true && M.isStaffMonthPaid(s, '2026-12') === false);
    check('Phase 2: a paid statement shows the stored working + paid date',
      M.staffPayStatement(s, '2026-11').includes('Net payable: Rs 15,000 - Rs 500 - Rs 0 - Rs 2,000 = Rs 12,500')
      && M.staffPayStatement(s, '2026-11').includes('Paid on 2026-11-30')
      && M.staffPayStatement(s, '2026-11').includes('Absent days: 1 x Rs 500 = Rs 500'));
    check('Phase 2: the next month is still open after a lock',
      M.computeMonthPay(v, s.id, '2026-12').netPkr === 15000
      && M.markAttendance(v, s.id, '2026-12-01', 'absent').mark === 'absent');
    check('Phase 2: markMonthPaid rejects a bad paid date',
      throwsCode(() => M.markMonthPaid(v, s.id, '2026-12', 'tomorrow'), 'VALIDATION'));
  }

  // ---- §7c. Phase 2 model: Deliveries daily log / monthly sum / gas ----
  function delVault() {
    const v = M.emptyVault();
    const d = M.addDelivery(v, { name: 'Doodhwala', kind: 'Doodhwala', unit: 'litre', ratePkr: 220, usualQty: 1 });
    return { v, d };
  }
  check('Phase 2: findDelivery finds by id', (() => {
    const { v, d } = delVault();
    return M.findDelivery(v, d.id) === d && M.findDelivery(v, 'nope') === null;
  })());
  check('Phase 2: a new delivery starts with an empty log and no refills', (() => {
    const { d } = delVault();
    return Object.keys(d.log).length === 0 && Array.isArray(d.refills) && d.refills.length === 0;
  })());
  {
    const { v, d } = delVault();
    check('Phase 2: logDelivery stores a day (qty 0 = skipped)',
      M.logDelivery(v, d.id, '2026-11-01', 0).qty === 0 && d.log['2026-11-01'] === 0);
    check('Phase 2: logDelivery rejects a negative quantity',
      throwsCode(() => M.logDelivery(v, d.id, '2026-11-02', -1), 'VALIDATION'));
    check('Phase 2: logDelivery rejects a quantity above 10000',
      throwsCode(() => M.logDelivery(v, d.id, '2026-11-02', 10001), 'VALIDATION'));
    check('Phase 2: logDelivery rejects a bad date',
      throwsCode(() => M.logDelivery(v, d.id, 'Nov 2', 1), 'VALIDATION'));
    check('Phase 2: logDelivery for an unknown delivery fails (NOT_FOUND)',
      throwsCode(() => M.logDelivery(v, 'nope', '2026-11-02', 1), 'NOT_FOUND'));
  }
  // Acceptance: 1 litre/day x Rs 220 x 30 days with 2 skipped days =
  // Rs 6,160, shown as 28 x 220.
  {
    const { v, d } = delVault();
    for (let day = 1; day <= 30; day++) {
      M.logDelivery(v, d.id, '2026-11-' + String(day).padStart(2, '0'), day <= 2 ? 0 : 1);
    }
    const t = M.deliveryMonthTotal(v, d.id, '2026-11');
    check('Phase 2 acceptance: 28 days x Rs 220 = Rs 6,160 (2 skipped)',
      t.totalPkr === 6160 && t.days === 30 && t.skippedDays === 2, t);
    check('Phase 2: the month total shows its working as 28 x 220',
      t.lines.length === 2 && t.lines[0].qty === 1 && t.lines[0].days === 28
      && t.lines[0].text === '28 x 1 litre x Rs 220 = Rs 6,160', t.lines);
    check('Phase 2: the skipped-days line shows 2 x 0 = Rs 0',
      t.lines[1].qty === 0 && t.lines[1].days === 2 && t.lines[1].amountPkr === 0);
    check('Phase 2: a skipped day removes exactly one day\u2019s charge',
      (() => {
        const { v: v2, d: d2 } = delVault();
        for (let day = 1; day <= 28; day++) M.logDelivery(v2, d2.id, '2026-11-' + String(day).padStart(2, '0'), 1);
        const before = M.deliveryMonthTotal(v2, d2.id, '2026-11').totalPkr;
        M.logDelivery(v2, d2.id, '2026-11-29', 0);
        const after = M.deliveryMonthTotal(v2, d2.id, '2026-11');
        return before === 6160 && after.totalPkr === 6160 && after.skippedDays === 1;
      })());
    check('Phase 2: changing a skipped day to 1 litre adds exactly Rs 220',
      (() => {
        M.logDelivery(v, d.id, '2026-11-01', 1);
        const t2 = M.deliveryMonthTotal(v, d.id, '2026-11');
        return t2.totalPkr === 6380 && t2.skippedDays === 1;
      })());
    check('Phase 2: totals recompute from the rows (no stored total)',
      (() => {
        d.log['2026-11-03'] = 2;
        return M.deliveryMonthTotal(v, d.id, '2026-11').totalPkr === 6600;
      })());
    check('Phase 2: the total counts only its own month',
      M.deliveryMonthTotal(v, d.id, '2026-12').totalPkr === 0
      && M.deliveryMonthTotal(v, d.id, '2026-12').days === 0);
    check('Phase 2: deliveryMonthTotal rejects a bad month key',
      throwsCode(() => M.deliveryMonthTotal(v, d.id, '2026-13'), 'VALIDATION'));
    check('Phase 2: deliveryMonthTotal for an unknown delivery fails (NOT_FOUND)',
      throwsCode(() => M.deliveryMonthTotal(v, 'nope', '2026-11'), 'NOT_FOUND'));
  }
  // Delivery paid month: stored total + lock.
  {
    const { v, d } = delVault();
    for (let day = 1; day <= 30; day++) {
      M.logDelivery(v, d.id, '2026-11-' + String(day).padStart(2, '0'), day <= 2 ? 0 : 1);
    }
    const rec = M.markDeliveryMonthPaid(v, d.id, '2026-11', '2026-11-30');
    check('Phase 2: marking a delivery month paid stores month + total + paid date',
      rec.month === '2026-11' && rec.totalPkr === 6160 && rec.paidDate === '2026-11-30'
      && M.isDeliveryMonthPaid(d, '2026-11') === true);
    check('Phase 2: a paid delivery month locks the log',
      throwsCode(() => M.logDelivery(v, d.id, '2026-11-15', 1), 'LOCKED'));
    check('Phase 2: marking a paid delivery month again refuses',
      throwsCode(() => M.markDeliveryMonthPaid(v, d.id, '2026-11', '2026-11-30'), 'LOCKED'));
    check('Phase 2: the next delivery month is still open',
      M.logDelivery(v, d.id, '2026-12-01', 1).qty === 1);
    check('Phase 2: markDeliveryMonthPaid rejects a bad paid date',
      throwsCode(() => M.markDeliveryMonthPaid(v, d.id, '2026-12', 'tomorrow'), 'VALIDATION'));
  }
  // Gas refills.
  {
    const v = M.emptyVault();
    const g = M.addDelivery(v, { name: 'Gas', kind: 'Gas cylinder', unit: 'cylinder', ratePkr: 3000, usualQty: 1 });
    check('Phase 2: no refills yet -> no last refill, days since is null',
      M.lastGasRefill(g) === null && M.gasDaysSinceLastRefill(g, '2026-11-06') === null);
    const r = M.addGasRefill(v, g.id, { date: '2026-10-15', pricePkr: 3000 });
    check('Phase 2: addGasRefill stores a refill record {date, pricePkr}',
      r.date === '2026-10-15' && r.pricePkr === 3000 && g.refills.length === 1);
    check('Phase 2: days since the last refill is worked out from the date',
      M.gasDaysSinceLastRefill(g, '2026-11-06') === 22);
    M.addGasRefill(v, g.id, { date: '2026-10-01', pricePkr: 2900 });
    check('Phase 2: refills stay sorted by date, latest last',
      g.refills[0].date === '2026-10-01' && M.lastGasRefill(g).date === '2026-10-15');
    for (const [input, why] of [
      [{ date: 'not-a-date', pricePkr: 3000 }, 'bad date'],
      [{ date: '2026-10-15', pricePkr: 0 }, 'price 0'],
      [{ date: '2026-10-15', pricePkr: -100 }, 'negative price'],
      [{ date: '2026-10-15', pricePkr: 100.5 }, 'price not whole rupees'],
    ]) {
      check('Phase 2: addGasRefill rejects ' + why,
        throwsCode(() => M.addGasRefill(v, g.id, input), 'VALIDATION'));
    }
    check('Phase 2: addGasRefill for an unknown delivery fails (NOT_FOUND)',
      throwsCode(() => M.addGasRefill(v, 'nope', { date: '2026-10-15', pricePkr: 3000 }), 'NOT_FOUND'));
  }

  // ---- §7d. Phase 3 model: Udhaar repayments / forgive / reminder + Bills ----
  check('Phase 3: model exports the new Udhaar + Bills functions',
    ['findUdhaarEntry', 'recordRepayment', 'forgiveUdhaar', 'udhaarReminderText',
      'markBillPaid', 'markBillUnpaid', 'deleteBill'].every((f) => typeof M[f] === 'function'));
  function udhaarVault() {
    const v = M.emptyVault();
    const p = M.addUdhaarPerson(v, { person: 'Ahmed' });
    return { v, p };
  }
  // Acceptance: lent 20,000, repaid 5,000 -> balance 15,000, on the
  // person and on Today when past the due date.
  {
    const { v, p } = udhaarVault();
    const e = M.addUdhaarEntry(v, p.id, { direction: 'lent', amountPkr: 20000, date: '2026-11-01', reason: 'shop rent', dueDate: '2026-11-05' });
    check('Phase 3: findUdhaarEntry finds an entry by id',
      M.findUdhaarEntry(p, e.id) === e && M.findUdhaarEntry(p, 'nope') === null && M.findUdhaarEntry(null, e.id) === null);
    const r = M.recordRepayment(v, p.id, e.id, { amountPkr: 5000, date: '2026-11-05' });
    check('Phase 3 acceptance: lent 20,000, repaid 5,000 -> balance 15,000',
      r.amountPkr === 5000 && r.date === '2026-11-05' && M.udhaarEntryBalance(e) === 15000
      && M.udhaarPersonBalance(p).lent === 15000 && e.settled === false);
    const items = M.todayItems(v, '2026-11-06');
    check('Phase 3 acceptance: the 15,000 balance shows on Today past the due date',
      items.some((i) => i.kind === 'udhaar' && i.overdue === true && i.detail.includes('Rs 15,000')));
    // Forgive: 2,000 lowers the balance and is labelled forgiven, not paid.
    const f = M.forgiveUdhaar(v, p.id, e.id, 2000);
    check('Phase 3 acceptance: forgiven 2,000 reduces the balance and is labelled forgiven, not paid',
      f.forgivenPkr === 2000 && f.balance === 13000 && f.settled === false
      && M.udhaarEntryBalance(e) === 13000 && e.repayments.length === 1, f);
    // Reminder text names the person and the outstanding balance.
    const text = M.udhaarReminderText(p, e);
    check('Phase 3: reminder text names the person, the balance and the working',
      text.includes('Ahmed') && text.includes('Rs 13,000') && text.includes('Assalam-o-Alaikum')
      && text.includes('Rs 20,000') && text.includes('Rs 5,000') && text.includes('Rs 2,000')
      && text.includes('forgiven') && text.includes('asani ho'), text);
    // Settled: repaying the last 13,000 stamps the entry settled.
    M.recordRepayment(v, p.id, e.id, { amountPkr: 13000, date: '2026-11-10' });
    check('Phase 3: balance zero stamps the entry settled',
      M.udhaarEntryBalance(e) === 0 && e.settled === true && M.udhaarPersonBalance(p).lent === 0);
    check('Phase 3: a settled entry no longer shows on Today',
      !M.todayItems(v, '2026-11-06').some((i) => i.kind === 'udhaar'));
    check('Phase 3: the reminder for a settled entry says settled, not a payment request',
      M.udhaarReminderText(p, e).includes('settled') && M.udhaarReminderText(p, e).includes('nothing is outstanding'));
    // Repayment after settle is refused (SETTLED), not reopened.
    check('Phase 3: repayment after settle is refused (SETTLED)',
      throwsCode(() => M.recordRepayment(v, p.id, e.id, { amountPkr: 100, date: '2026-11-11' }), 'SETTLED'));
    check('Phase 3: forgive after settle is refused (SETTLED)',
      throwsCode(() => M.forgiveUdhaar(v, p.id, e.id, 100), 'SETTLED'));
  }
  // Overpayment + validation.
  {
    const { v, p } = udhaarVault();
    const e = M.addUdhaarEntry(v, p.id, { direction: 'lent', amountPkr: 5000, date: '2026-11-01', dueDate: '2026-11-20' });
    check('Phase 3: overpayment is refused and the balance is unchanged',
      throwsCode(() => M.recordRepayment(v, p.id, e.id, { amountPkr: 5001, date: '2026-11-02' }), 'VALIDATION')
      && M.udhaarEntryBalance(e) === 5000 && e.repayments.length === 0);
    check('Phase 3: forgiving more than the outstanding balance is refused',
      throwsCode(() => M.forgiveUdhaar(v, p.id, e.id, 5001), 'VALIDATION') && e.forgivenPkr === 0);
    for (const [input, why] of [
      [{ amountPkr: 0, date: '2026-11-02' }, 'repayment 0'],
      [{ amountPkr: -100, date: '2026-11-02' }, 'negative repayment'],
      [{ amountPkr: 100.5, date: '2026-11-02' }, 'repayment not whole rupees'],
      [{ amountPkr: 100, date: 'next week' }, 'bad repayment date'],
      [null, 'no repayment at all'],
    ]) {
      check('Phase 3: recordRepayment rejects ' + why,
        throwsCode(() => M.recordRepayment(v, p.id, e.id, input), 'VALIDATION'));
    }
    for (const bad of [0, -100, 100.5, 'x', null]) {
      check('Phase 3: forgiveUdhaar rejects amount ' + JSON.stringify(bad),
        throwsCode(() => M.forgiveUdhaar(v, p.id, e.id, bad), 'VALIDATION'));
    }
    check('Phase 3: recordRepayment for an unknown person fails (NOT_FOUND)',
      throwsCode(() => M.recordRepayment(v, 'nope', e.id, { amountPkr: 100, date: '2026-11-02' }), 'NOT_FOUND'));
    check('Phase 3: recordRepayment for an unknown entry fails (NOT_FOUND)',
      throwsCode(() => M.recordRepayment(v, p.id, 'nope', { amountPkr: 100, date: '2026-11-02' }), 'NOT_FOUND'));
    check('Phase 3: forgiveUdhaar for an unknown entry fails (NOT_FOUND)',
      throwsCode(() => M.forgiveUdhaar(v, p.id, 'nope', 100), 'NOT_FOUND'));
    check('Phase 3: udhaarReminderText for a missing entry fails (NOT_FOUND)',
      throwsCode(() => M.udhaarReminderText(p, null), 'NOT_FOUND'));
    // Repaying exactly the outstanding amount settles; a partial one does not.
    const e2 = M.addUdhaarEntry(v, p.id, { direction: 'borrowed', amountPkr: 3000, date: '2026-11-01' });
    M.recordRepayment(v, p.id, e2.id, { amountPkr: 1000, date: '2026-11-02' });
    check('Phase 3: a partial repayment does not settle the entry',
      M.udhaarEntryBalance(e2) === 2000 && e2.settled === false);
    M.recordRepayment(v, p.id, e2.id, { amountPkr: 2000, date: '2026-11-03' });
    check('Phase 3: repaying exactly the outstanding amount settles the entry',
      M.udhaarEntryBalance(e2) === 0 && e2.settled === true);
    // Forgiving the whole balance settles too.
    const e3 = M.addUdhaarEntry(v, p.id, { direction: 'lent', amountPkr: 4000, date: '2026-11-01' });
    M.forgiveUdhaar(v, p.id, e3.id, 4000);
    check('Phase 3: forgiving the whole balance settles the entry',
      M.udhaarEntryBalance(e3) === 0 && e3.settled === true && e3.repayments.length === 0);
  }
  // Bills: paid / unpaid / delete + Today.
  {
    const v = M.emptyVault();
    const b = M.addBill(v, { type: 'electricity', provider: 'IESCO', accountNo: '1234567890', amountPkr: 8500, dueDate: '2026-11-10', surchargeNote: 'Rs 500 after due date' });
    check('Phase 3 acceptance: a bill due in 4 days shows on Today',
      M.todayItems(v, '2026-11-06').some((i) => i.kind === 'bill' && i.daysUntil === 4 && i.detail.includes('Rs 8,500')));
    const paid = M.markBillPaid(v, b.id, '2026-11-08');
    check('Phase 3 acceptance: marking paid records the paid date and keeps the bill',
      paid.status === 'paid' && paid.paidDate === '2026-11-08' && v.bills.length === 1
      && paid.amountPkr === 8500 && paid.provider === 'IESCO');
    check('Phase 3 acceptance: a paid bill never shows on Today again',
      !M.todayItems(v, '2026-11-06').some((i) => i.kind === 'bill'));
    check('Phase 3: marking an already-paid bill refuses',
      throwsCode(() => M.markBillPaid(v, b.id, '2026-11-09'), 'VALIDATION'));
    const unpaid = M.markBillUnpaid(v, b.id);
    check('Phase 3 acceptance: mark unpaid restores the bill to due with no paid date',
      unpaid.status === 'due' && unpaid.paidDate === null);
    check('Phase 3: marking unpaid restores the bill on Today',
      M.todayItems(v, '2026-11-06').some((i) => i.kind === 'bill' && i.daysUntil === 4));
    check('Phase 3: marking a due bill unpaid refuses',
      throwsCode(() => M.markBillUnpaid(v, b.id), 'VALIDATION'));
    // Default paid date is today.
    const paid2 = M.markBillPaid(v, b.id);
    check('Phase 3: marking paid with no date records today',
      paid2.paidDate === M.todayStr());
    check('Phase 3: markBillPaid rejects a bad paid date',
      throwsCode(() => M.markBillPaid(v, b.id, 'tomorrow'), 'VALIDATION'));
    M.markBillUnpaid(v, b.id);
    const gone = M.deleteBill(v, b.id);
    check('Phase 3 acceptance: delete removes the bill and returns it',
      gone.id === b.id && v.bills.length === 0
      && !M.todayItems(v, '2026-11-06').some((i) => i.kind === 'bill'));
    check('Phase 3: delete for an unknown bill fails (NOT_FOUND)',
      throwsCode(() => M.deleteBill(v, 'nope'), 'NOT_FOUND'));
    check('Phase 3: markBillPaid for an unknown bill fails (NOT_FOUND)',
      throwsCode(() => M.markBillPaid(v, 'nope'), 'NOT_FOUND'));
    check('Phase 3: markBillUnpaid for an unknown bill fails (NOT_FOUND)',
      throwsCode(() => M.markBillUnpaid(v, 'nope'), 'NOT_FOUND'));
  }
  // No string in the app claims to fetch, check or verify anything with
  // any provider. The only occurrences of those words are the honest
  // denials ("nothing is fetched...", "never fetched"), which are
  // stripped before the scan. nav.js is out of scope here: it carries a
  // pre-existing "checked in test.js" comment about route order, which
  // is not a provider claim.
  {
    const modelSrc = fs.readFileSync(path.join(__dirname, 'public', 'model.js'), 'utf8');
    const DENIALS = [
      'Nothing here is fetched or checked anywhere.',
      'Nothing is fetched, checked or looked up — every record is as you entered it. A wrong date is a wrong date; the book shows it, it does not bless it.',
      'Nothing here is fetched, checked or looked up anywhere:',
      'Nothing is fetched from any provider.',
      '(typed only — never fetched)',
      // Phase 4 honest phrases: the renewal checklists carry the dated
      // note "check with the office", and an expired medicine tells the
      // user to check with a pharmacist. Neither claims the app checked
      // anything — both send the user to a human.
      'Check with the office; rules change.',
      'do not use — check with a pharmacist',
    ];
    let scanned = [htmlSrc, appSrc, modelSrc].join('\n');
    for (const d of DENIALS) scanned = scanned.split(d).join('');
    check('Phase 3: no app string claims to fetch, check or verify anything',
      !/\b(fetch|fetched|fetching|check|checked|checking|verify|verified|verifying|looks?\s+up|looked\s+up)\b/i.test(scanned),
      (scanned.match(/\b(fetch|fetched|fetching|check|checked|checking|verify|verified|verifying|looks?\s+up|looked\s+up)\b/gi) || []).slice(0, 5));
    check('Phase 3: no provider-claim phrasing in app code or page text',
      !/\b(provider|bill)\b[^<]{0,60}\b(fetch|check|verify)\b/i.test(scanned)
      && !/\b(fetch|check|verify)\b[^<]{0,60}\b(provider|bill)\b/i.test(scanned));
    check('Phase 3: the Bills page still states nothing is fetched from any provider',
      htmlSrc.includes('Nothing is fetched from any provider.'));
  }

  // ---- §7e. Phase 4 model: Documents countdowns / reminders / checklists / photos + Medicine doses ----
  check('Phase 4: model exports the new Documents + Medicine functions',
    ['findDocument', 'documentDaysUntil', 'documentReminder', 'deleteDocument',
      'getChecklist', 'validatePhotoDataUrl', 'photoFitsCap',
      'findMedicine', 'recordDose', 'medicineWarnings', 'deleteMedicine',
      'isTimeStr'].every((f) => typeof M[f] === 'function')
    && typeof M.CHECKLISTS === 'object' && typeof M.CHECKLIST_UPDATED === 'string'
    && typeof M.MAX_PHOTO_INPUT_BYTES === 'number');
  // Document countdowns + reminders (fixed "today" so no test depends on the clock).
  {
    const v = M.emptyVault();
    const pass = M.addDocument(v, { type: 'passport', owner: 'Abu', issueDate: '2021-01-01', expiryDate: '2026-12-12' });
    check('Phase 4: documentDaysUntil counts days to expiry (36 days)',
      M.documentDaysUntil(pass, '2026-11-06') === 36);
    check('Phase 4: documentDaysUntil is negative once expired',
      M.documentDaysUntil(pass, '2026-12-13') === -1 && M.documentDaysUntil(pass, '2026-12-24') === -12);
    check('Phase 4: documentDaysUntil is 0 on the expiry day',
      M.documentDaysUntil(pass, '2026-12-12') === 0);
    check('Phase 4: documentReminder is null beyond the 30-day window',
      M.documentReminder(pass, '2026-11-06') === null);
    check('Phase 4: documentReminder is due-30 at the 30-day mark',
      M.documentReminder(pass, '2026-11-12') === 'due-30');
    check('Phase 4: documentReminder steps down the windows (20 -> due-30, 14 -> due-14, 7 -> due-7, 1 -> due-1)',
      M.documentReminder(pass, '2026-11-22') === 'due-30'
      && M.documentReminder(pass, '2026-11-28') === 'due-14'
      && M.documentReminder(pass, '2026-12-05') === 'due-7'
      && M.documentReminder(pass, '2026-12-11') === 'due-1');
    check('Phase 4: documentReminder is expired past the expiry date',
      M.documentReminder(pass, '2026-12-13') === 'expired');
    check('Phase 4: documentReminder honours a custom window',
      M.documentReminder(pass, '2026-11-06', [7, 1]) === null
      && M.documentReminder(pass, '2026-12-05', [7, 1]) === 'due-7');
    check('Phase 4: documentReminder returns null for a document with no expiry date',
      M.documentReminder({ expiryDate: null }, '2026-11-06') === null);
    // Acceptance: a passport expiring in 36 days shows on Home at the 30-day mark.
    check('Phase 4 acceptance: passport expiring in 36 days is hidden on Today, shown at the 30-day mark',
      !M.todayItems(v, '2026-11-06').some((i) => i.kind === 'document' && i.title.includes('passport'))
      && M.todayItems(v, '2026-11-12').some((i) => i.kind === 'document' && i.title.includes('passport') && i.daysUntil === 30));
    // Expired document: red on Today (reminder 'expired', negative daysUntil).
    const exp = M.addDocument(v, { type: 'CNIC', owner: 'Me', expiryDate: '2026-10-25' });
    check('Phase 4 acceptance: an expired document shows on Today, overdue, daysUntil negative',
      M.todayItems(v, '2026-11-06').some((i) => i.kind === 'document' && i.title.includes('CNIC') && i.overdue === true && i.daysUntil === -12)
      && M.documentReminder(exp, '2026-11-06') === 'expired');
    // Delete removes the document (and its photo with it).
    const gone = M.deleteDocument(v, pass.id);
    check('Phase 4: deleteDocument removes the document and returns it',
      gone.id === pass.id && v.documents.length === 1 && M.findDocument(v, pass.id) === null
      && !M.todayItems(v, '2026-11-12').some((i) => i.kind === 'document' && i.title.includes('passport')));
    check('Phase 4: deleteDocument for an unknown id fails (NOT_FOUND)',
      throwsCode(() => M.deleteDocument(v, 'nope'), 'NOT_FOUND'));
    check('Phase 4: findDocument finds by id', M.findDocument(v, exp.id) === exp && M.findDocument(v, 'nope') === null);
  }
  // Renewal checklists: the 4 v1 types, dated, with the office note; null
  // for every other type ("no checklist yet").
  {
    const titles = { 'CNIC': 'CNIC', 'passport': 'Passport', 'driving licence': 'Driving licence', 'vehicle token': 'Vehicle token' };
    for (const t of Object.keys(titles)) {
      const c = M.getChecklist(t);
      check('Phase 4: a renewal checklist exists for ' + t + ' (dated, with the office note)',
        !!c && c.title.includes(titles[t])
        && c.updated === '2026-11-06' && Array.isArray(c.items) && c.items.length >= 3
        && c.note === 'Check with the office; rules change.'
        && c.items.join(' ').includes('Where:') && c.items.join(' ').includes('Fee'));
    }
    check('Phase 4: CHECKLISTS holds exactly the 4 v1 types',
      JSON.stringify(Object.keys(M.CHECKLISTS).sort()) === JSON.stringify(['CNIC', 'driving licence', 'passport', 'vehicle token']));
    for (const t of ['vehicle registration', 'domicile', 'birth certificate', 'insurance', 'warranty', 'other', 'visa']) {
      check('Phase 4: no checklist yet for ' + t, M.getChecklist(t) === null);
    }
    // The fee lines name the fee as printed on the official site, dated —
    // never claimed as current.
    check('Phase 4: CNIC checklist names the NADRA fee as printed (Rs 750 / 1,500 / 2,500)',
      M.getChecklist('CNIC').items.join(' ').includes('Rs 750')
      && M.getChecklist('CNIC').items.join(' ').includes('Rs 1,500')
      && M.getChecklist('CNIC').items.join(' ').includes('Rs 2,500'));
    check('Phase 4: passport checklist names the DGIP e-passport fee (Rs 9,000 / 15,000)',
      M.getChecklist('passport').items.join(' ').includes('Rs 9,000')
      && M.getChecklist('passport').items.join(' ').includes('Rs 15,000'));
    check('Phase 4: driving licence checklist names the DLIMS fee (Rs 450 / 1,350 + Rs 480 courier)',
      M.getChecklist('driving licence').items.join(' ').includes('Rs 450')
      && M.getChecklist('driving licence').items.join(' ').includes('Rs 1,350')
      && M.getChecklist('driving licence').items.join(' ').includes('Rs 480'));
    check('Phase 4: vehicle token checklist names the Excise token tax (Rs 20,000 once; 0.3% / 0.4%)',
      M.getChecklist('vehicle token').items.join(' ').includes('Rs 20,000')
      && M.getChecklist('vehicle token').items.join(' ').includes('0.3%')
      && M.getChecklist('vehicle token').items.join(' ').includes('0.4%'));
  }
  // Photos: magic bytes decide the type; the 5 MB input cap and the
  // 500 KB vault cap are both enforced by the model (the app shrinks in
  // the browser before saving — never silently).
  {
    // Small JPEG (FF D8 FF) and PNG (89 50 4E 47...) data URLs, built from
    // real magic bytes so the test does not depend on a fixture file.
    const jpegBytes = Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), Buffer.alloc(100, 0x00)]);
    const pngBytes = Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), Buffer.alloc(100, 0x00)]);
    const jpegUrl = 'data:image/jpeg;base64,' + jpegBytes.toString('base64');
    const pngUrl = 'data:image/png;base64,' + pngBytes.toString('base64');
    const gifUrl = 'data:image/gif;base64,' + Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0, 0, 0]).toString('base64');
    const bigJpegUrl = 'data:image/jpeg;base64,' + Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF]), Buffer.alloc(600 * 1024, 0)]).toString('base64');
    check('Phase 4: validatePhotoDataUrl accepts a small JPEG (magic bytes)',
      M.validatePhotoDataUrl(jpegUrl).ok === true && M.validatePhotoDataUrl(jpegUrl).mime === 'image/jpeg');
    check('Phase 4: validatePhotoDataUrl accepts a small PNG (magic bytes)',
      M.validatePhotoDataUrl(pngUrl).ok === true && M.validatePhotoDataUrl(pngUrl).mime === 'image/png');
    check('Phase 4: validatePhotoDataUrl rejects a GIF (not JPEG/PNG)',
      M.validatePhotoDataUrl(gifUrl).ok === false);
    check('Phase 4: validatePhotoDataUrl rejects a non-image data URL',
      M.validatePhotoDataUrl('data:text/plain;base64,aGVsbG8=').ok === false);
    check('Phase 4: validatePhotoDataUrl rejects a non-data URL',
      M.validatePhotoDataUrl('http://x/y.jpg').ok === false);
    check('Phase 4: validatePhotoDataUrl rejects a file over the 5 MB input cap',
      (() => {
        const big = 'data:image/jpeg;base64,' + Buffer.alloc(5 * 1024 * 1024 + 10, 0xFF).toString('base64');
        const r = M.validatePhotoDataUrl(big);
        return r.ok === false && r.errors.join(' ').includes('5 MB');
      })());
    check('Phase 4: photoFitsCap accepts a small photo, rejects a 600 KB one, accepts exactly 500 KB',
      M.photoFitsCap(jpegUrl) === true
      && M.photoFitsCap(bigJpegUrl) === false
      && M.photoFitsCap('data:image/jpeg;base64,' + Buffer.alloc(500 * 1024, 0xFF).toString('base64')) === true);
    check('Phase 4: photoFitsCap rejects a non-data URL', M.photoFitsCap('http://x/y.jpg') === false);
    check('Phase 4: addDocument refuses a photo over the 500 KB cap (VALIDATION, 500 KB)',
      (() => {
        try {
          M.addDocument(M.emptyVault(), {
            type: 'CNIC', owner: 'Me', expiryDate: '2030-01-01',
            photo: { dataUrl: bigJpegUrl, mime: 'image/jpeg' },
          });
          return false;
        } catch (e) {
          return e.code === 'VALIDATION' && (e.errors || []).join(' ').includes('500 KB');
        }
      })());
    check('Phase 4: addDocument refuses a GIF photo',
      throwsCode(() => M.addDocument(M.emptyVault(), {
        type: 'CNIC', owner: 'Me', expiryDate: '2030-01-01',
        photo: { dataUrl: gifUrl, mime: 'image/gif' },
      }), 'VALIDATION'));
    // A stored photo keeps its magic-byte mime, not the claimed one.
    check('Phase 4: a stored photo keeps the mime read from its magic bytes',
      (() => {
        const v = M.emptyVault();
        const d = M.addDocument(v, { type: 'CNIC', owner: 'Me', expiryDate: '2030-01-01', photo: { dataUrl: pngUrl, mime: 'image/jpeg' } });
        return d.photo.mime === 'image/png' && d.photo.dataUrl === pngUrl;
      })());
  }
  // Medicines: warnings, dose ticks, delete.
  {
    const v = M.emptyVault();
    const med = M.addMedicine(v, { name: 'Panadol', qtyLeft: 10, unit: 'tablets', expiryDate: '2026-11-26', place: 'cupboard', person: 'Ami', dosesPerDay: 3, lowStockAt: 5 });
    check('Phase 4: findMedicine finds by id', M.findMedicine(v, med.id) === med && M.findMedicine(v, 'nope') === null);
    // Acceptance: a medicine expiring in 20 days warns at 30 days.
    const w = M.medicineWarnings(med, '2026-11-06');
    check('Phase 4 acceptance: a medicine expiring in 20 days warns at 30 days',
      w.expired === false && w.daysUntil === 20 && w.lowStock === false && w.warning === true, w);
    const far = M.addMedicine(v, { name: 'Vitamin D', qtyLeft: 20, unit: 'tablets', expiryDate: '2027-06-01', place: 'cupboard', person: 'Ami', lowStockAt: 5 });
    check('Phase 4: a medicine expiring far away with stock does not warn',
      M.medicineWarnings(far, '2026-11-06').warning === false
      && M.medicineWarnings(far, '2026-11-06').daysUntil > 30);
    check('Phase 4: low stock warns even with a far expiry',
      (() => {
        const low = M.addMedicine(v, { name: 'Insulin', qtyLeft: 3, unit: 'bottles', expiryDate: '2027-06-01', place: 'fridge', person: 'Abu', lowStockAt: 5 });
        const lw = M.medicineWarnings(low, '2026-11-06');
        return lw.lowStock === true && lw.warning === true && lw.expired === false;
      })());
    check('Phase 4: no low-stock number set means no low-stock warning',
      M.medicineWarnings(M.addMedicine(v, { name: 'X', qtyLeft: 1, unit: 'tablets', expiryDate: '2027-06-01' }), '2026-11-06').lowStock === false);
    // Dose ticks: exactly one off the quantity, one record appended.
    const dose = M.recordDose(v, med.id, { date: '2026-11-06', time: '09:30' });
    check('Phase 4 acceptance: a dose tick reduces the quantity by exactly one and appends the dose record',
      dose.date === '2026-11-06' && dose.time === '09:30' && med.qtyLeft === 9
      && med.dosesTaken.length === 1 && med.dosesTaken[0].date === '2026-11-06' && med.dosesTaken[0].time === '09:30');
    M.recordDose(v, med.id, { date: '2026-11-06', time: '21:30' });
    check('Phase 4: a second dose tick takes the quantity to 8, two records',
      med.qtyLeft === 8 && med.dosesTaken.length === 2);
    // Dose tick at qty 0 is refused.
    const zero = M.addMedicine(v, { name: 'Empty', qtyLeft: 0, unit: 'tablets', expiryDate: '2027-06-01' });
    check('Phase 4 acceptance: a dose tick at quantity 0 is refused (VALIDATION, none left)',
      throwsCode(() => M.recordDose(v, zero.id, { date: '2026-11-06', time: '09:30' }), 'VALIDATION')
      && zero.qtyLeft === 0 && zero.dosesTaken.length === 0);
    // Dose validation.
    for (const [input, why] of [
      [{ date: 'not-a-date', time: '09:30' }, 'bad dose date'],
      [{ date: '2026-11-06', time: '9:30' }, 'time not HH:MM'],
      [{ date: '2026-11-06', time: '24:00' }, 'hour 24'],
      [{ date: '2026-11-06', time: '09:60' }, 'minute 60'],
      [null, 'no dose at all'],
    ]) {
      check('Phase 4: recordDose rejects ' + why,
        throwsCode(() => M.recordDose(v, med.id, input), 'VALIDATION'));
    }
    check('Phase 4: recordDose for an unknown medicine fails (NOT_FOUND)',
      throwsCode(() => M.recordDose(v, 'nope', { date: '2026-11-06', time: '09:30' }), 'NOT_FOUND'));
    // Expired medicine stays listed — never disappears.
    const old = M.addMedicine(v, { name: 'Old Syrup', qtyLeft: 2, unit: 'bottles', expiryDate: '2026-10-20', place: 'cupboard', person: 'Abu' });
    const ow = M.medicineWarnings(old, '2026-11-06');
    check('Phase 4 acceptance: an expired medicine stays listed (never disappears), red',
      ow.expired === true && ow.daysUntil === -17 && ow.warning === true
      && M.todayItems(v, '2026-11-06').some((i) => i.kind === 'medicine' && i.title.startsWith('Old Syrup') && i.overdue === true));
    // Delete removes the medicine.
    const goneMed = M.deleteMedicine(v, med.id);
    check('Phase 4: deleteMedicine removes the medicine and returns it',
      goneMed.id === med.id && v.medicines.length === 5 && M.findMedicine(v, med.id) === null);
    check('Phase 4: deleteMedicine for an unknown id fails (NOT_FOUND)',
      throwsCode(() => M.deleteMedicine(v, 'nope'), 'NOT_FOUND'));
    // Time format helper.
    check('Phase 4: isTimeStr accepts HH:MM, rejects junk',
      M.isTimeStr('09:30') === true && M.isTimeStr('23:59') === true && M.isTimeStr('00:00') === true
      && M.isTimeStr('9:30') === false && M.isTimeStr('24:00') === false && M.isTimeStr('09:60') === false
      && M.isTimeStr('') === false && M.isTimeStr(null) === false);
  }

  // ---- §8. The app shell in a minimal fake DOM (vm) ----
  // Proves the real flow end to end: setup -> empty Today -> lock ->
  // wrong PINs -> lockout -> unlock -> profile save -> change PIN ->
  // export -> auto-lock -> no page reachable while locked.
  const RealDate = Date;
  class El {
    constructor(id) {
      this.id = id || '';
      this._cls = new Set();
      this.classList = {
        add: (...c) => c.forEach((x) => this._cls.add(x)),
        remove: (...c) => c.forEach((x) => this._cls.delete(x)),
        toggle: (c, f) => { if (f === undefined) f = !this._cls.has(c); if (f) this._cls.add(c); else this._cls.delete(c); },
        contains: (c) => this._cls.has(c),
      };
      this.style = {};
      this.textContent = '';
      this._html = '';
      this.value = '';
      this.files = null;
      this.href = '';
      this.download = '';
      this._listeners = {};
    }
    get innerHTML() { return this._html; }
    set innerHTML(v) { this._html = String(v); }
    addEventListener(t, f) { (this._listeners[t] = this._listeners[t] || []).push(f); }
    dispatch(t, ev) { (this._listeners[t] || []).forEach((f) => f(ev || { target: this, key: '', preventDefault() {} })); }
    click() { this.dispatch('click'); }
    setAttribute() {}
    appendChild() { return this; }
    removeChild() { return this; }
    remove() {}
  }
  function buildVmContext() {
    const els = {};
    for (const id of [...htmlSrc.matchAll(/id="([^"]+)"/g)].map((m) => m[1])) els[id] = new El(id);
    const store = new Map();
    const intervals = [];
    const winListeners = {};
    const blobs = [];
    let fakeNow = 1780000000000; // fixed clock the test controls
    class FakeDate extends RealDate {
      constructor(...a) { super(...(a.length ? a : [fakeNow])); }
      static now() { return fakeNow; }
    }
    const sandbox = {
      console,
      crypto: globalThis.crypto,
      TextEncoder, TextDecoder, atob, btoa,
      setTimeout, clearTimeout,
      setInterval: (fn) => { intervals.push(fn); return intervals.length; },
      clearInterval: () => {},
      Date: FakeDate,
      Blob: class { constructor(parts) { this.parts = parts; blobs.push(this); } },
      URL: { createObjectURL: () => 'blob:test', revokeObjectURL: () => {} },
      FileReader: class { readAsText() {} },
      location: { hash: '' },
      localStorage: {
        getItem: (k) => (store.has(k) ? store.get(k) : null),
        setItem: (k, v) => store.set(k, String(v)),
        removeItem: (k) => store.delete(k),
      },
      document: {
        readyState: 'complete',
        getElementById: (id) => els[id] || null,
        createElement: () => new El(''),
        body: new El('body'),
        addEventListener: (t, f) => { (winListeners['doc:' + t] = winListeners['doc:' + t] || []).push(f); },
        _dispatch: (t, ev) => { (winListeners['doc:' + t] || []).forEach((f) => f(ev || {})); },
      },
      addEventListener: (t, f) => { (winListeners[t] = winListeners[t] || []).push(f); },
      _dispatchWin: (t, ev) => { (winListeners[t] || []).forEach((f) => f(ev || {})); },
      _els: els, _store: store, _intervals: intervals, _blobs: blobs,
      _advanceMs: (ms) => { fakeNow += ms; },
      _now: () => fakeNow,
    };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    for (const f of ['vault.js', 'model.js', 'csv.js', 'nav.js', 'app.js']) {
      vm.runInContext(fs.readFileSync(path.join(__dirname, 'public', f), 'utf8'), sandbox, { filename: f });
    }
    return sandbox;
  }
  const ctx = buildVmContext();
  const el = (id) => ctx._els[id];
  const isHidden = (id) => el(id).classList.contains('hidden');
  const isVisible = (id) => !isHidden(id);

  check('Shell: first run shows the setup screen, vault hidden',
    isVisible('setup-screen') && isHidden('unlock-screen') && isHidden('vault-screen')
    && el('lock-pill').textContent === 'Locked');
  // Setup with mismatched PINs is refused.
  el('setup-pin').value = '123456'; el('setup-pin2').value = '123457'; el('setup-pass').value = '';
  el('setup-btn').click();
  await sleep(50);
  check('Shell: mismatched PINs are refused on setup',
    el('setup-error').textContent.includes('do not match') && isVisible('setup-screen'));
  el('setup-pin').value = '123456'; el('setup-pin2').value = '123456';
  el('setup-btn').click();
  check('Shell: setup creates the book and lands on an empty Today page',
    await waitFor(() => isVisible('vault-screen') && isVisible('today-empty') && el('today-list').innerHTML === ''
      && el('lock-pill').textContent === 'Unlocked'),
    'vault-screen visible=' + isVisible('vault-screen') + ' today-empty visible=' + isVisible('today-empty'));
  check('Shell: the envelope is stored (new localStorage key, not the old vault key)',
    ctx._store.get('ghar-register-vault') !== undefined && ctx._store.get('ghar-register-vault') !== null
    && ctx._store.get('pcv.vault') === undefined);
  check('Shell: section pages render their empty states',
    ['staff', 'deliveries', 'udhaar', 'bills', 'documents', 'medicine', 'summary']
      .every((p) => isVisible(p + '-empty')));
  // Routing: bills page.
  ctx.location.hash = '#/bills';
  ctx._dispatchWin('hashchange');
  check('Shell: hash #/bills shows the Bills page and marks its nav button',
    isVisible('page-bills') && isHidden('page-home') && el('nav-bills').classList.contains('active'));
  // Profile save.
  ctx.location.hash = '#/profile';
  ctx._dispatchWin('hashchange');
  el('profile-household').value = 'Hashir Home';
  el('profile-monthstart').value = '5';
  el('profile-save-btn').click();
  check('Shell: profile save stores the household and renames the sidebar',
    await waitFor(() => el('profile-ok').textContent.includes('Saved') && el('sidebar-name').textContent === 'Hashir Home'));
  check('Shell: profile rejects a month start day of 29',
    await (async () => {
      el('profile-monthstart').value = '29';
      el('profile-save-btn').click();
      await sleep(50);
      return el('profile-error').textContent.includes('1 to 28');
    })());
  // Change PIN (old 123456 -> new 654321).
  ctx.location.hash = '#/security';
  ctx._dispatchWin('hashchange');
  el('change-pin-old').value = '123456'; el('change-pin-pass').value = '';
  el('change-pin-new').value = '654321'; el('change-pin-new2').value = '654321';
  el('change-pin-btn').click();
  check('Shell: change PIN works',
    await waitFor(() => el('change-pin-ok').textContent.includes('PIN changed')));
  // Lock, then unlock with the NEW pin.
  el('lock-btn').click();
  check('Shell: lock shows the unlock screen and hides the book',
    isVisible('unlock-screen') && isHidden('vault-screen'));
  el('unlock-pin').value = '654321';
  el('unlock-btn').click();
  check('Shell: unlock with the new PIN reopens the book',
    await waitFor(() => isVisible('vault-screen')));
  // Wrong PINs: 4 tries warn, the 5th locks for 30s.
  el('lock-btn').click();
  for (let i = 0; i < 4; i++) {
    el('unlock-pin').value = '000000';
    el('unlock-btn').click();
    await waitFor(() => el('unlock-error').textContent.includes('Wrong PIN'));
    el('unlock-error').textContent = '';
  }
  check('Shell: 4 wrong PINs warn but do not lock yet', isHidden('lockout-note'));
  el('unlock-pin').value = '000000';
  el('unlock-btn').click();
  check('Shell: the 5th wrong PIN locks the book (30s note shows)',
    await waitFor(() => !isHidden('lockout-note') && el('lockout-note').textContent.includes('30 seconds')));
  el('unlock-pin').value = '654321';
  el('unlock-btn').click();
  await sleep(100);
  check('Shell: the right PIN is refused while the lockout runs',
    isVisible('unlock-screen') && isHidden('vault-screen'));
  ctx._advanceMs(31000);
  el('unlock-pin').value = '654321';
  el('unlock-btn').click();
  check('Shell: after the 30s wait the right PIN opens the book again',
    await waitFor(() => isVisible('vault-screen')));
  // Backup export (Blob captured by the stub).
  ctx.location.hash = '#/backup';
  ctx._dispatchWin('hashchange');
  const blobsBefore = ctx._blobs.length;
  el('export-btn').click();
  check('Shell: export produces an encrypted backup file',
    ctx._blobs.length === blobsBefore + 1
    && JSON.parse(String(ctx._blobs[ctx._blobs.length - 1].parts[0])).envelope.data.length > 50
    && el('backup-ok').textContent.includes('Backup exported'));
  // Auto-lock: 6 idle minutes -> locked.
  ctx._advanceMs(6 * 60 * 1000);
  ctx._intervals.forEach((fn) => fn());
  check('Shell: 6 idle minutes auto-locks the book',
    isVisible('unlock-screen') && isHidden('vault-screen'));
  // No page reachable while locked, even by hash.
  ctx.location.hash = '#/staff';
  ctx._dispatchWin('hashchange');
  check('Shell: no page is reachable while locked (hash #/staff still shows unlock)',
    isHidden('vault-screen') && isVisible('unlock-screen') && isHidden('page-staff'));
  // Unlock again to leave the shell open.
  el('unlock-pin').value = '654321';
  el('unlock-btn').click();
  check('Shell: unlock after auto-lock reopens the book',
    await waitFor(() => isVisible('vault-screen')));

  // ---- §8b. Phase 2 UI wiring (Staff + Deliveries) in the fake DOM ----
  // The static form ids exist in index.html, and the handlers are bound:
  // add a helper through the real form, tap attendance days, record an
  // advance, copy the statement, mark the month paid (locked), then do
  // the same for a delivery + a gas refill.
  const phase2Ids = ['staff-name', 'staff-role', 'staff-salary', 'staff-joined',
    'staff-leave', 'staff-phone', 'staff-add-btn', 'staff-add-error', 'staff-add-ok',
    'staff-month', 'staff-list', 'staff-empty', 'staff-statement',
    'adv-helper', 'adv-amount', 'adv-date', 'adv-note', 'adv-recovery',
    'adv-instalment', 'adv-add-btn', 'adv-error', 'adv-ok',
    'del-name', 'del-kind', 'del-unit', 'del-rate', 'del-qty', 'del-add-btn',
    'del-add-error', 'del-add-ok', 'del-month', 'deliveries-list', 'deliveries-empty',
    'log-delivery', 'log-date', 'log-qty', 'log-btn', 'log-error', 'log-ok',
    'refill-delivery', 'refill-date', 'refill-price', 'refill-btn', 'refill-error', 'refill-ok'];
  check('Phase 2 UI: every Staff + Deliveries form id exists in index.html',
    phase2Ids.every((id) => htmlSrc.includes('id="' + id + '"')),
    phase2Ids.filter((id) => !htmlSrc.includes('id="' + id + '"')));
  check('Phase 2 UI: the Staff/Deliveries pages no longer say "next build phase"',
    !htmlSrc.includes('Adding helpers arrives in the next build phase')
    && !htmlSrc.includes('Adding deliveries arrives in the next build phase'));
  const staffHtml = () => el('staff-list').innerHTML;
  const firstId = (html, attr) => {
    const m = html.match(new RegExp(attr + '="([^"]+)"'));
    return m ? m[1] : null;
  };
  // Staff: open the page, set the month, add a helper through the form.
  ctx.location.hash = '#/staff';
  ctx._dispatchWin('hashchange');
  el('staff-month').value = '2026-11';
  el('staff-month').dispatch('change');
  el('staff-name').value = 'Ayesha';
  el('staff-role').value = 'maid';
  el('staff-salary').value = '15000';
  el('staff-joined').value = '2026-11-01';
  el('staff-leave').value = '2';
  el('staff-phone').value = '03001234567';
  el('staff-add-btn').click();
  check('Phase 2 UI: adding a helper through the form renders the helper card',
    await waitFor(() => el('staff-add-ok').textContent.includes('Helper added')
      && staffHtml().includes('Ayesha') && staffHtml().includes('Rs 15,000')
      && staffHtml().includes('as you entered it')),
    staffHtml().slice(0, 200));
  const helperId = firstId(staffHtml(), 'data-helper');
  check('Phase 2 UI: the helper card carries a helper id for its buttons', !!helperId);
  // Attendance: tap days 1, 2, 3 -> absent; tap day 3 again -> half, again -> present.
  const tapAtt = (date) => el('staff-list').dispatch('click',
    { target: { dataset: { action: 'att', helper: helperId, date }, parentElement: null } });
  tapAtt('2026-11-01'); tapAtt('2026-11-02'); tapAtt('2026-11-03');
  await sleep(50);
  check('Phase 2 UI: tapping attendance days marks them absent (working updates)',
    staffHtml().includes('1 · A') && staffHtml().includes('2 · A') && staffHtml().includes('3 · A')
    && staffHtml().includes('Absent: 3'));
  tapAtt('2026-11-03');
  await sleep(50);
  check('Phase 2 UI: tapping an absent day again cycles it to half day',
    staffHtml().includes('3 · H') && staffHtml().includes('Half: 1'));
  tapAtt('2026-11-03');
  await sleep(50);
  check('Phase 2 UI: tapping a half day again cycles it back to present',
    staffHtml().includes('3 · P') && staffHtml().includes('Half: 0'));
  tapAtt('2026-11-03');
  await sleep(50);
  check('Phase 2 UI: tapping a present day again cycles it back to absent',
    staffHtml().includes('3 · A') && staffHtml().includes('Absent: 3'));
  // Advance: Rs 2,000 full recovery through the advance form.
  el('adv-helper').value = helperId;
  el('adv-amount').value = '2000';
  el('adv-date').value = '2026-11-05';
  el('adv-note').value = 'for medicine';
  el('adv-recovery').value = 'full';
  el('adv-add-btn').click();
  check('Phase 2 UI: recording an advance shows its remaining amount',
    await waitFor(() => el('adv-ok').textContent.includes('Advance recorded')
      && staffHtml().includes('Remaining advance: Rs 2,000')),
    staffHtml().slice(0, 300));
  check('Phase 2 UI: the pay panel shows the acceptance working (net Rs 11,500)',
    staffHtml().includes('Net payable') && staffHtml().includes('Rs 11,500')
    && staffHtml().includes('Absent: 3 × Rs 500'));
  // Copy statement: the statement box shows the full working.
  el('staff-list').dispatch('click',
    { target: { dataset: { action: 'copy', helper: helperId }, parentElement: null } });
  await sleep(50);
  check('Phase 2 UI: Copy statement shows the WhatsApp text with the working lines',
    el('staff-statement').textContent.includes('Net payable: Rs 15,000 - Rs 1,500 - Rs 0 - Rs 2,000 = Rs 11,500')
    && el('staff-statement').textContent.includes('Absent days: 3 x Rs 500 = Rs 1,500'));
  // Mark paid -> locked: the panel shows the stored working, taps refuse.
  el('staff-list').dispatch('click',
    { target: { dataset: { action: 'pay', helper: helperId }, parentElement: null } });
  check('Phase 2 UI: Mark paid locks the month and shows the stored working',
    await waitFor(() => staffHtml().includes('Paid on') && staffHtml().includes('locked and cannot be edited')
      && staffHtml().includes('Rs 11,500')));
  tapAtt('2026-11-10');
  await sleep(50);
  check('Phase 2 UI: tapping attendance on a locked month is refused with an error',
    el('staff-add-error').textContent.includes('already marked paid'));
  // Deliveries: add the doodhwala through the form, log days, mark paid.
  ctx.location.hash = '#/deliveries';
  ctx._dispatchWin('hashchange');
  el('del-month').value = '2026-11';
  el('del-month').dispatch('change');
  el('del-name').value = 'Doodhwala';
  el('del-kind').value = 'Doodhwala';
  el('del-unit').value = 'litre';
  el('del-rate').value = '220';
  el('del-qty').value = '1';
  el('del-add-btn').click();
  check('Phase 2 UI: adding a delivery through the form renders its card',
    await waitFor(() => el('del-add-ok').textContent.includes('Delivery added')
      && el('deliveries-list').innerHTML.includes('Doodhwala')
      && el('deliveries-list').innerHTML.includes('Rs 220 per litre')));
  const delHtml = () => el('deliveries-list').innerHTML;
  const delId = firstId(el('log-delivery').innerHTML, 'value');
  check('Phase 2 UI: the log form lists the new delivery', !!delId);
  const logDay = async (date, qty) => {
    el('log-delivery').value = delId;
    el('log-date').value = date;
    el('log-qty').value = String(qty);
    el('log-btn').click();
    await sleep(50);
  };
  await logDay('2026-11-01', 0);
  await logDay('2026-11-02', 0);
  await logDay('2026-11-03', 1);
  check('Phase 2 UI: logging a skipped day says so, and the bill shows the working',
    el('log-ok').textContent.includes('Logged 1 on 2026-11-03')
    && delHtml().includes('2 skipped days') && delHtml().includes('Rs 220'));
  // Gas: add a cylinder delivery, record a refill, days-since shows.
  el('del-name').value = 'Gas';
  el('del-kind').value = 'Gas cylinder';
  el('del-unit').value = 'cylinder';
  el('del-rate').value = '3000';
  el('del-qty').value = '1';
  el('del-add-btn').click();
  await waitFor(() => delHtml().includes('Gas cylinder'));
  const gasId = (() => {
    const opts = [...el('refill-delivery').innerHTML.matchAll(/value="([^"]+)"/g)].map((m) => m[1]);
    return opts[opts.length - 1];
  })();
  el('refill-delivery').value = gasId;
  el('refill-date').value = '2026-05-01';
  el('refill-price').value = '3000';
  el('refill-btn').click();
  check('Phase 2 UI: recording a gas refill shows the last refill + days since',
    await waitFor(() => el('refill-ok').textContent.includes('Refill recorded')
      && delHtml().includes('Last refill: 2026-05-01') && delHtml().includes('days ago')));
  // Mark the doodhwala month paid -> locked; a further log refuses.
  el('deliveries-list').dispatch('click',
    { target: { dataset: { action: 'delpay', delivery: delId }, parentElement: null } });
  check('Phase 2 UI: Mark paid locks the delivery month',
    await waitFor(() => delHtml().includes('Paid on') && delHtml().includes('locked and cannot be edited')));
  await logDay('2026-11-04', 1);
  check('Phase 2 UI: logging into a locked delivery month is refused with an error',
    el('log-error').textContent.includes('already marked paid'));

  // ---- §8c. Phase 3 UI wiring (Udhaar + Bills) in the fake DOM ----
  // Fake today is 2026-05-28 (fixed clock): the bill due 2026-06-01 is
  // "due in 4 days", the udhaar entry due 2026-05-20 is overdue.
  const phase3Ids = ['udh-person-name', 'udh-person-add-btn', 'udh-person-error', 'udh-person-ok',
    'udh-entry-person', 'udh-entry-direction', 'udh-entry-amount', 'udh-entry-date',
    'udh-entry-reason', 'udh-entry-due', 'udh-entry-add-btn', 'udh-entry-error', 'udh-entry-ok',
    'udh-reminder', 'repay-person', 'repay-entry', 'repay-amount', 'repay-date',
    'repay-add-btn', 'repay-error', 'repay-ok',
    'forgive-person', 'forgive-entry', 'forgive-amount', 'forgive-add-btn', 'forgive-error', 'forgive-ok',
    'bill-type', 'bill-provider', 'bill-account', 'bill-amount', 'bill-due', 'bill-surcharge',
    'bill-add-btn', 'bill-add-error', 'bill-add-ok'];
  check('Phase 3 UI: every Udhaar + Bills form id exists in index.html',
    phase3Ids.every((id) => htmlSrc.includes('id="' + id + '"')),
    phase3Ids.filter((id) => !htmlSrc.includes('id="' + id + '"')));
  check('Phase 3 UI: the Udhaar/Bills pages no longer say "next build phase"',
    !htmlSrc.includes('Adding people and entries arrives in the next build phase')
    && !htmlSrc.includes('Adding bills arrives in the next build phase'));
  const udhaarHtml = () => el('udhaar-list').innerHTML;
  const billsHtml = () => el('bills-list').innerHTML;
  const optValueFor = (selectHtml, labelRe) => {
    const m = selectHtml.match(new RegExp('<option value="([^"]+)">' + labelRe));
    return m ? m[1] : null;
  };
  // Udhaar: add a person through the form.
  ctx.location.hash = '#/udhaar';
  ctx._dispatchWin('hashchange');
  el('udh-person-name').value = 'Ahmed';
  el('udh-person-add-btn').click();
  check('Phase 3 UI: adding a person through the form renders the person card',
    await waitFor(() => el('udh-person-ok').textContent.includes('Person added')
      && udhaarHtml().includes('Ahmed') && udhaarHtml().includes('as you entered it')));
  const personId = optValueFor(el('udh-entry-person').innerHTML, 'Ahmed');
  check('Phase 3 UI: the entry form lists the new person', !!personId);
  // Entry: lent Rs 20,000 on 2026-05-01, due 2026-05-20 (overdue on fake today).
  el('udh-entry-person').value = personId;
  el('udh-entry-direction').value = 'lent';
  el('udh-entry-amount').value = '20000';
  el('udh-entry-date').value = '2026-05-01';
  el('udh-entry-reason').value = 'shop rent';
  el('udh-entry-due').value = '2026-05-20';
  el('udh-entry-add-btn').click();
  check('Phase 3 UI: adding an entry shows the balance + working (20,000 outstanding)',
    await waitFor(() => el('udh-entry-ok').textContent.includes('Entry added')
      && udhaarHtml().includes('Rs 20,000') && udhaarHtml().includes('Rs 20,000 left')
      && udhaarHtml().includes('Rs 20,000 − Rs 0 repaid − Rs 0 forgiven = Rs 20,000 outstanding')));
  const entryId = optValueFor(el('repay-entry').innerHTML, 'lent Rs 20,000');
  check('Phase 3 UI: the repayment form lists the new entry', !!entryId);
  const setRepayTarget = async () => {
    el('repay-person').value = personId;
    el('repay-person').dispatch('change');
    await sleep(10);
    el('repay-entry').value = entryId;
  };
  const setForgiveTarget = async () => {
    el('forgive-person').value = personId;
    el('forgive-person').dispatch('change');
    await sleep(10);
    el('forgive-entry').value = entryId;
  };
  // Repay Rs 5,000 -> balance Rs 15,000.
  await setRepayTarget();
  el('repay-amount').value = '5000';
  el('repay-date').value = '2026-05-05';
  el('repay-add-btn').click();
  check('Phase 3 UI: repaying 5,000 updates the balance to 15,000 + shows the repayment',
    await waitFor(() => el('repay-ok').textContent.includes('Balance now Rs 15,000')
      && udhaarHtml().includes('Rs 15,000 left')
      && udhaarHtml().includes('Repayment 2026-05-05')));
  // Forgive Rs 2,000 -> balance Rs 13,000, labelled forgiven not paid.
  await setForgiveTarget();
  el('forgive-amount').value = '2000';
  el('forgive-add-btn').click();
  check('Phase 3 UI: forgiving 2,000 updates the balance to 13,000, labelled forgiven',
    await waitFor(() => el('forgive-ok').textContent.includes('Balance now Rs 13,000')
      && udhaarHtml().includes('Rs 13,000 left')
      && udhaarHtml().includes('Rs 2,000 forgiven — recorded as forgiven, not as a payment')));
  // Reminder: the box shows the text with the person + outstanding balance.
  el('udhaar-list').dispatch('click',
    { target: { dataset: { action: 'reminder', person: personId, entry: entryId }, parentElement: null } });
  await sleep(50);
  check('Phase 3 UI: Copy reminder shows the WhatsApp text with the balance',
    el('udh-reminder').textContent.includes('Ahmed')
    && el('udh-reminder').textContent.includes('Rs 13,000')
    && el('udh-reminder').textContent.includes('Assalam-o-Alaikum'));
  // Overpayment is refused from the form too.
  await setRepayTarget();
  el('repay-amount').value = '20000';
  el('repay-date').value = '2026-05-06';
  el('repay-add-btn').click();
  check('Phase 3 UI: an overpayment is refused with an error, balance unchanged',
    await waitFor(() => el('repay-error').textContent.includes('more than the outstanding balance'))
    && udhaarHtml().includes('Rs 13,000 left'));
  // Repay the last Rs 13,000 -> settled stamp.
  await setRepayTarget();
  el('repay-amount').value = '13000';
  el('repay-date').value = '2026-05-10';
  el('repay-add-btn').click();
  check('Phase 3 UI: repaying the last of the balance stamps the entry settled',
    await waitFor(() => el('repay-ok').textContent.includes('settled, nothing outstanding')
      && udhaarHtml().includes('Settled — nothing outstanding')
      && udhaarHtml().includes('Rs 0 left')));
  // Repaying a settled entry is refused.
  await setRepayTarget();
  el('repay-amount').value = '100';
  el('repay-date').value = '2026-05-11';
  el('repay-add-btn').click();
  check('Phase 3 UI: repaying a settled entry is refused with an error',
    await waitFor(() => el('repay-error').textContent.includes('already settled')));
  // Bills: add a bill due 2026-06-01 (fake today 2026-05-28 -> due in 4 days).
  ctx.location.hash = '#/bills';
  ctx._dispatchWin('hashchange');
  el('bill-type').value = 'electricity';
  el('bill-provider').value = 'IESCO';
  el('bill-account').value = '1234567890';
  el('bill-amount').value = '8500';
  el('bill-due').value = '2026-06-01';
  el('bill-surcharge').value = 'Rs 500 after due date';
  el('bill-add-btn').click();
  check('Phase 3 UI: adding a bill shows it with a due-in-4-days countdown',
    await waitFor(() => el('bill-add-ok').textContent.includes('Bill added')
      && billsHtml().includes('IESCO') && billsHtml().includes('Rs 8,500')
      && billsHtml().includes('due in 4 days') && billsHtml().includes('Rs 500 after due date')));
  const billId = (() => {
    const m = billsHtml().match(/data-bill="([^"]+)"/);
    return m ? m[1] : null;
  })();
  check('Phase 3 UI: the bill row carries a bill id for its buttons', !!billId);
  ctx.location.hash = '#/home';
  ctx._dispatchWin('hashchange');
  check('Phase 3 UI: the new bill shows on Today (due in 4 days)',
    el('today-list').innerHTML.includes('IESCO') && el('today-list').innerHTML.includes('due in 4 days'));
  // Mark paid -> history, off Today.
  ctx.location.hash = '#/bills';
  ctx._dispatchWin('hashchange');
  el('bills-list').dispatch('click',
    { target: { dataset: { action: 'billpay', bill: billId }, parentElement: null } });
  check('Phase 3 UI: Mark paid moves the bill to history with the paid date',
    await waitFor(() => billsHtml().includes('Paid — history') && billsHtml().includes('Paid on 2026-05-28')));
  ctx.location.hash = '#/home';
  ctx._dispatchWin('hashchange');
  check('Phase 3 UI: a paid bill no longer shows on Today',
    !el('today-list').innerHTML.includes('IESCO'));
  // Mark unpaid -> back on Today.
  ctx.location.hash = '#/bills';
  ctx._dispatchWin('hashchange');
  el('bills-list').dispatch('click',
    { target: { dataset: { action: 'billunpay', bill: billId }, parentElement: null } });
  check('Phase 3 UI: Mark unpaid restores the bill to due',
    await waitFor(() => billsHtml().includes('due in 4 days') && !billsHtml().includes('Paid — history')));
  // Delete: first tap arms, second tap deletes.
  el('bills-list').dispatch('click',
    { target: { dataset: { action: 'billdel', bill: billId }, parentElement: null } });
  await sleep(50);
  check('Phase 3 UI: first delete tap only arms ("Tap again to delete"), bill stays',
    billsHtml().includes('Tap again to delete') && billsHtml().includes('IESCO'));
  el('bills-list').dispatch('click',
    { target: { dataset: { action: 'billdel', bill: billId }, parentElement: null } });
  check('Phase 3 UI: second delete tap removes the bill',
    await waitFor(() => isVisible('bills-empty') && !billsHtml().includes('IESCO')));
  // Bill validation from the form.
  el('bill-type').value = 'gas';
  el('bill-provider').value = 'SNGPL';
  el('bill-amount').value = '0';
  el('bill-due').value = '2026-06-05';
  el('bill-add-btn').click();
  check('Phase 3 UI: a bill with amount 0 is refused with an error',
    await waitFor(() => el('bill-add-error').textContent.includes('above 0')));

  // ---- §8d. Phase 4 UI wiring (Documents + Medicine) in the fake DOM ----
  // Fake today is 2026-05-28 (fixed clock). The passport expiring
  // 2026-06-03 is "expires in 6 days"; the medicine expiring 2026-06-17
  // warns at 30 days; the expired CNIC shows red.
  const phase4Ids = ['doc-type', 'doc-owner', 'doc-issue', 'doc-expiry', 'doc-photo',
    'doc-photo-note', 'doc-add-btn', 'doc-add-error', 'doc-add-ok',
    'med-name', 'med-qty', 'med-unit', 'med-expiry', 'med-place', 'med-person',
    'med-doses', 'med-low', 'med-add-btn', 'med-add-error', 'med-add-ok'];
  check('Phase 4 UI: every Documents + Medicine form id exists in index.html',
    phase4Ids.every((id) => htmlSrc.includes('id="' + id + '"')),
    phase4Ids.filter((id) => !htmlSrc.includes('id="' + id + '"')));
  check('Phase 4 UI: the Documents/Medicine pages no longer say "next build phase"',
    !htmlSrc.includes('Adding documents arrives in the next build phase')
    && !htmlSrc.includes('Adding medicines arrives in the next build phase'));
  // The canvas downscale cannot run in the fake DOM (no canvas/Image),
  // so the wiring test covers the form flow without a photo, and this
  // source check covers the downscale path itself: quality steps down to
  // the 0.5 floor, then the picture shrinks, and a photo that still does
  // not fit is refused with a plain message — never silently dropped.
  check('Phase 4: app.js downscales oversize photos in the browser (canvas, quality steps to 0.5, plain refusal)',
    appSrc.includes('downscalePhoto') && appSrc.includes("toDataURL('image/jpeg'")
    && appSrc.includes('quality = 0.9') && appSrc.includes('0.5')
    && appSrc.includes('still over 500 KB after shrinking'));
  const docsHtml = () => el('documents-list').innerHTML;
  const medsHtml = () => el('medicine-list').innerHTML;
  // Documents: add a passport through the form.
  ctx.location.hash = '#/documents';
  ctx._dispatchWin('hashchange');
  el('doc-type').value = 'passport';
  el('doc-owner').value = 'Abu';
  el('doc-issue').value = '2021-06-03';
  el('doc-expiry').value = '2026-06-03';
  el('doc-add-btn').click();
  check('Phase 4 UI: adding a document shows the countdown (expires in 6 days)',
    await waitFor(() => el('doc-add-ok').textContent.includes('Document added')
      && docsHtml().includes('passport — Abu') && docsHtml().includes('expires in 6 days')
      && docsHtml().includes('as you entered it')));
  check('Phase 4 UI: the passport shows its renewal checklist, dated, with the office note',
    docsHtml().includes('Passport renewal checklist') && docsHtml().includes('updated 2026-11-06')
    && docsHtml().includes('Check with the office; rules change.')
    && docsHtml().includes('Rs 9,000'));
  check('Phase 4 UI: the document row carries a doc id for its buttons',
    !!docsHtml().match(/data-doc="([^"]+)"/));
  const docId = docsHtml().match(/data-doc="([^"]+)"/)[1];
  // A type without a checklist says so.
  el('doc-type').value = 'warranty';
  el('doc-owner').value = 'Ami';
  el('doc-issue').value = '';
  el('doc-expiry').value = '2027-01-01';
  el('doc-add-btn').click();
  check('Phase 4 UI: a type without a checklist says "no checklist yet"',
    await waitFor(() => docsHtml().includes('warranty — Ami') && docsHtml().includes('No checklist yet')));
  // An expired document shows red (amber pill).
  el('doc-type').value = 'CNIC';
  el('doc-owner').value = 'Me';
  el('doc-expiry').value = '2026-05-16';
  el('doc-add-btn').click();
  check('Phase 4 UI: an expired document shows EXPIRED 12 days ago, red',
    await waitFor(() => docsHtml().includes('CNIC — Me') && docsHtml().includes('EXPIRED 12 days ago')
      && docsHtml().includes('pill amber')));
  // Document validation from the form.
  el('doc-type').value = 'passport';
  el('doc-owner').value = '';
  el('doc-expiry').value = '2027-01-01';
  el('doc-add-btn').click();
  check('Phase 4 UI: a document with no owner is refused with an error',
    await waitFor(() => el('doc-add-error').textContent.includes('owner is required')));
  // Delete: first tap arms, second tap deletes.
  el('documents-list').dispatch('click',
    { target: { dataset: { action: 'docdel', doc: docId }, parentElement: null } });
  await sleep(50);
  check('Phase 4 UI: first delete tap only arms ("Tap again to delete"), document stays',
    docsHtml().includes('Tap again to delete') && docsHtml().includes('passport — Abu'));
  el('documents-list').dispatch('click',
    { target: { dataset: { action: 'docdel', doc: docId }, parentElement: null } });
  check('Phase 4 UI: second delete tap removes the document',
    await waitFor(() => !docsHtml().includes('passport — Abu') && docsHtml().includes('warranty — Ami')));
  // Medicine: add Panadol through the form, then mark doses taken.
  ctx.location.hash = '#/medicine';
  ctx._dispatchWin('hashchange');
  el('med-name').value = 'Panadol';
  el('med-qty').value = '10';
  el('med-unit').value = 'tablets';
  el('med-expiry').value = '2026-06-17';
  el('med-place').value = 'cupboard';
  el('med-person').value = 'Ami';
  el('med-doses').value = '3';
  el('med-low').value = '5';
  el('med-add-btn').click();
  check('Phase 4 UI: adding a medicine shows it with stock + expiry',
    await waitFor(() => el('med-add-ok').textContent.includes('Medicine added')
      && medsHtml().includes('Panadol — Ami') && medsHtml().includes('10 tablets left')
      && medsHtml().includes('expires in 20 days') && medsHtml().includes('as you entered it')));
  const medId = medsHtml().match(/data-med="([^"]+)"/)[1];
  check('Phase 4 UI: the medicine row carries a med id for its buttons', !!medId);
  // Mark dose taken: quantity drops by exactly one, dose recorded.
  el('medicine-list').dispatch('click',
    { target: { dataset: { action: 'dose', med: medId }, parentElement: null } });
  check('Phase 4 UI: a dose tick drops the quantity by one (10 -> 9) and records the dose',
    await waitFor(() => medsHtml().includes('9 tablets left')
      && medsHtml().includes('Doses taken: 1') && medsHtml().includes('2026-05-28')));
  el('medicine-list').dispatch('click',
    { target: { dataset: { action: 'dose', med: medId }, parentElement: null } });
  check('Phase 4 UI: a second dose tick drops the quantity to 8',
    await waitFor(() => medsHtml().includes('8 tablets left') && medsHtml().includes('Doses taken: 2')));
  // Today: the medicine expiring in 20 days warns at 30 days.
  ctx.location.hash = '#/home';
  ctx._dispatchWin('hashchange');
  check('Phase 4 UI: the medicine shows on Today (expires in 20 days, 30-day warning)',
    el('today-list').innerHTML.includes('Panadol') && el('today-list').innerHTML.includes('expires in 20 days'));
  // An expired medicine shows red with "do not use — check with a pharmacist".
  ctx.location.hash = '#/medicine';
  ctx._dispatchWin('hashchange');
  el('med-name').value = 'Old Syrup';
  el('med-qty').value = '2';
  el('med-unit').value = 'bottles';
  el('med-expiry').value = '2026-05-10';
  el('med-place').value = 'cupboard';
  el('med-person').value = 'Abu';
  el('med-doses').value = '';
  el('med-low').value = '';
  el('med-add-btn').click();
  check('Phase 4 UI: an expired medicine stays listed, red, "do not use — check with a pharmacist"',
    await waitFor(() => medsHtml().includes('Old Syrup — Abu') && medsHtml().includes('EXPIRED 18 days ago')
      && medsHtml().includes('do not use — check with a pharmacist') && medsHtml().includes('pill amber')));
  // A dose tick at quantity 0 is refused from the page too.
  el('med-name').value = 'Empty Bottle';
  el('med-qty').value = '0';
  el('med-unit').value = 'bottles';
  el('med-expiry').value = '2027-01-01';
  el('med-place').value = 'cupboard';
  el('med-person').value = '';
  el('med-doses').value = '';
  el('med-low').value = '';
  el('med-add-btn').click();
  check('Phase 4 UI: adding a zero-quantity medicine works (it is a cabinet list, not a suggestion)',
    await waitFor(() => medsHtml().includes('Empty Bottle') && medsHtml().includes('0 bottles left')));
  const medIds = [...medsHtml().matchAll(/data-med="([^"]+)"/g)].map((m) => m[1]);
  const emptyId = medIds[medIds.length - 1];
  el('medicine-list').dispatch('click',
    { target: { dataset: { action: 'dose', med: emptyId }, parentElement: null } });
  check('Phase 4 UI: a dose tick at quantity 0 is refused with an error, quantity stays 0',
    await waitFor(() => el('med-add-error').textContent.includes('None left'))
    && medsHtml().includes('0 bottles left'));
  // Medicine validation from the form.
  el('med-name').value = '';
  el('med-qty').value = '10';
  el('med-expiry').value = '2027-01-01';
  el('med-add-btn').click();
  check('Phase 4 UI: a medicine with no name is refused with an error',
    await waitFor(() => el('med-add-error').textContent.includes('name is required')));

  // ---- §10. Phase 5: Summary + CSV export + final review ----
  // A vault with known rows in every section, November 2026 vs October:
  // staff A Rs 15,000, 3 absent Nov, Rs 2,000 advance (full) -> paid Nov
  // net Rs 11,500 (the acceptance example); staff A was also paid Oct
  // (Rs 15,000, no deductions). Staff B Rs 20,000 unpaid; staff C
  // Rs 10,000 with a Rs 3,000 instalment advance (Rs 1,000/month).
  // Doodhwala Nov: 28 days x 1 litre x Rs 220 = Rs 6,160, marked paid;
  // Oct: 10 days = Rs 2,200. Newspaper Nov: 5 days x Rs 100 = Rs 500.
  {
    const v = M.emptyVault();
    const a = M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-10-01', leavePerMonth: 2, phone: '03001234567' });
    M.markMonthPaid(v, a.id, '2026-10', '2026-10-31');
    M.addAdvance(v, a.id, { amount: 2000, date: '2026-11-01', note: '', recovery: 'full' });
    M.markAttendance(v, a.id, '2026-11-01', 'absent');
    M.markAttendance(v, a.id, '2026-11-02', 'absent');
    M.markAttendance(v, a.id, '2026-11-03', 'absent');
    M.markMonthPaid(v, a.id, '2026-11', '2026-11-30');
    const b = M.addStaff(v, { name: 'Bilal', role: 'driver', salaryPkr: 20000, joinedDate: '2026-10-01', leavePerMonth: 2 });
    const c = M.addStaff(v, { name: 'Chanda', role: 'cook', salaryPkr: 10000, joinedDate: '2026-10-01', leavePerMonth: 2 });
    M.addAdvance(v, c.id, { amount: 3000, date: '2026-11-01', note: '', recovery: 'instalments', instalmentPkr: 1000 });
    const milk = M.addDelivery(v, { name: 'Doodhwala', kind: 'Doodhwala', unit: 'litre', ratePkr: 220, usualQty: 1 });
    for (let d = 1; d <= 28; d++) M.logDelivery(v, milk.id, '2026-11-' + String(d).padStart(2, '0'), 1);
    M.logDelivery(v, milk.id, '2026-11-29', 0);
    M.logDelivery(v, milk.id, '2026-11-30', 0);
    for (let d = 1; d <= 10; d++) M.logDelivery(v, milk.id, '2026-10-' + String(d).padStart(2, '0'), 1);
    M.markDeliveryMonthPaid(v, milk.id, '2026-11', '2026-11-30');
    const paper = M.addDelivery(v, { name: 'Newspaper', kind: 'Newspaper', unit: 'day', ratePkr: 100, usualQty: 1 });
    for (let d = 1; d <= 5; d++) M.logDelivery(v, paper.id, '2026-11-' + String(d).padStart(2, '0'), 1);
    const p = M.addUdhaarPerson(v, { person: 'Ahmed' });
    const lent = M.addUdhaarEntry(v, p.id, { direction: 'lent', amountPkr: 20000, date: '2026-11-01', reason: 'shop rent', dueDate: '2026-11-20' });
    M.recordRepayment(v, p.id, lent.id, { amountPkr: 5000, date: '2026-11-05' });
    M.addUdhaarEntry(v, p.id, { direction: 'borrowed', amountPkr: 3000, date: '2026-11-02' });
    M.addUdhaarEntry(v, p.id, { direction: 'lent', amountPkr: 4000, date: '2026-10-15' });
    const settledEntry = M.addUdhaarEntry(v, p.id, { direction: 'lent', amountPkr: 1000, date: '2026-11-03' });
    M.recordRepayment(v, p.id, settledEntry.id, { amountPkr: 1000, date: '2026-11-04' });
    M.addBill(v, { type: 'electricity', provider: 'IESCO', accountNo: '1', amountPkr: 8500, dueDate: '2026-11-10' });
    M.markBillPaid(v, v.bills[0].id, '2026-11-09');
    M.addBill(v, { type: 'gas', provider: 'SNGPL', accountNo: '2', amountPkr: 3000, dueDate: '2026-11-15' });
    M.addBill(v, { type: 'internet', provider: 'PTCL', accountNo: '3', amountPkr: 2000, dueDate: '2026-10-20' });
    M.addBill(v, { type: 'water', provider: 'WASA', accountNo: '4', amountPkr: 1500, dueDate: '2026-10-05' });
    M.markBillPaid(v, v.bills[3].id, '2026-10-05');
    M.addDocument(v, { type: 'passport', owner: 'Abu', issueDate: '2021-01-01', expiryDate: '2026-11-26' });
    M.addDocument(v, { type: 'CNIC', owner: 'Ami', expiryDate: '2026-10-20' });
    M.addDocument(v, { type: 'domicile', owner: 'Abu', expiryDate: '2026-12-15' });
    M.addMedicine(v, { name: 'Panadol', qtyLeft: 10, unit: 'tablets', expiryDate: '2026-11-20', place: 'cupboard', person: 'Ami', dosesPerDay: 3, lowStockAt: 5 });
    M.addMedicine(v, { name: 'Old Syrup', qtyLeft: 2, unit: 'bottles', expiryDate: '2026-10-20', place: 'cupboard', person: 'Abu' });
    M.addMedicine(v, { name: 'Insulin', qtyLeft: 3, unit: 'bottles', expiryDate: '2027-06-01', place: 'fridge', person: 'Abu', lowStockAt: 5 });

    check('Phase 5: prevMonthKey rolls back a year boundary',
      M.prevMonthKey('2026-01') === '2025-12' && M.prevMonthKey('2026-11') === '2026-10');
    check('Phase 5: summaryForMonth rejects a bad month key',
      throwsCode(() => M.summaryForMonth(v, '2026-13'), 'VALIDATION'));
    const s = M.summaryForMonth(v, '2026-11', '2026-11-06');
    check('Phase 5: summary staff paid = Rs 11,500 (1 helper), unpaid working Rs 29,000 (2 helpers)',
      s.staff.paidPkr === 11500 && s.staff.paidCount === 1
      && s.staff.unpaidWorkingPkr === 29000 && s.staff.unpaidCount === 2, s.staff);
    check('Phase 5: summary advances outstanding = Rs 3,000 (instalment advance, nothing recovered yet)',
      s.staff.advancesOutstandingPkr === 3000, s.staff);
    check('Phase 5: summary deliveries total Rs 6,660, paid Rs 6,160, unpaid Rs 500',
      s.deliveries.totalPkr === 6660 && s.deliveries.paidPkr === 6160 && s.deliveries.unpaidPkr === 500, s.deliveries);
    check('Phase 5: summary udhaar lent outstanding Rs 19,000, borrowed Rs 3,000, lent this month Rs 21,000, settled 1',
      s.udhaar.lentOutstandingPkr === 19000 && s.udhaar.borrowedOutstandingPkr === 3000
      && s.udhaar.lentThisMonthPkr === 21000 && s.udhaar.borrowedThisMonthPkr === 3000
      && s.udhaar.settledCount === 1, s.udhaar);
    check('Phase 5: summary bills paid this month Rs 8,500, due this month Rs 3,000, all unpaid Rs 5,000, overdue Rs 2,000',
      s.bills.paidPkr === 8500 && s.bills.paidCount === 1 && s.bills.dueThisMonthPkr === 3000
      && s.bills.dueAllPkr === 5000 && s.bills.overduePkr === 2000, s.bills);
    check('Phase 5: summary documents expiring this month 1, already expired 1',
      s.documents.expiringCount === 1 && s.documents.expiredCount === 1
      && s.documents.expiringThisMonth[0].type === 'passport', s.documents);
    check('Phase 5: summary medicines expiring this month 1, expired 1, low stock 1',
      s.medicines.expiringCount === 1 && s.medicines.expiredCount === 1 && s.medicines.lowStockCount === 1, s.medicines);
    check('Phase 5: compare staff paid delta Rs -3,500 vs Oct (Rs 15,000)',
      s.compare.staffPaidDeltaPkr === -3500 && s.compare.staffPaidPrevPkr === 15000, s.compare);
    check('Phase 5: compare deliveries delta Rs 4,460 vs Oct (Rs 2,200)',
      s.compare.deliveriesDeltaPkr === 4460 && s.compare.deliveriesPrevPkr === 2200, s.compare);
    check('Phase 5: compare bills paid delta Rs 7,000 vs Oct (Rs 1,500)',
      s.compare.billsPaidDeltaPkr === 7000 && s.compare.billsPaidPrevPkr === 1500, s.compare);
    check('Phase 5: empty vault summary is all zeros',
      (() => {
        const e = M.summaryForMonth(M.emptyVault(), '2026-11', '2026-11-06');
        return e.staff.paidPkr === 0 && e.deliveries.totalPkr === 0
          && e.udhaar.lentOutstandingPkr === 0 && e.bills.dueAllPkr === 0
          && e.documents.expiringCount === 0 && e.medicines.lowStockCount === 0;
      })());
    // CSV: the export rows reconcile with the summary to the rupee.
    const rows = M.sectionCsvRows(v, '2026-11', '2026-11-06');
    const staffCsv = C.rowsToCsv(rows.staff.headers, rows.staff.rows);
    const staffParsed = C.parseCsv(staffCsv);
    check('Phase 5: staff CSV parses as readable CSV with the right rows + TOTAL',
      staffParsed.headers.includes('Net payable (Rs)') && staffParsed.rows.length === 4
      && staffParsed.rows[3]['Helper'] === 'TOTAL'
      && Number(staffParsed.rows[3]['Net payable (Rs)']) === 40500, staffParsed.rows);
    check('Phase 5: staff CSV TOTAL (Rs 40,500) = summary paid + unpaid working (11,500 + 29,000)',
      Number(staffParsed.rows[3]['Net payable (Rs)']) === s.staff.paidPkr + s.staff.unpaidWorkingPkr);
    const delCsv = C.rowsToCsv(rows.deliveries.headers, rows.deliveries.rows);
    const delParsed = C.parseCsv(delCsv);
    check('Phase 5: deliveries CSV TOTAL (Rs 6,660) = summary deliveries total',
      Number(delParsed.rows[delParsed.rows.length - 1]['Total (Rs)']) === s.deliveries.totalPkr, delParsed.rows);
    const udhCsv = C.rowsToCsv(rows.udhaar.headers, rows.udhaar.rows);
    const udhParsed = C.parseCsv(udhCsv);
    check('Phase 5: udhaar CSV outstanding totals (lent 19,000 / borrowed 3,000) = summary',
      Number(udhParsed.rows.find((r) => r['Direction'] === 'lent' && r['Person'] === 'TOTAL outstanding')['Outstanding (Rs)']) === s.udhaar.lentOutstandingPkr
      && Number(udhParsed.rows.find((r) => r['Direction'] === 'borrowed' && r['Person'] === 'TOTAL outstanding')['Outstanding (Rs)']) === s.udhaar.borrowedOutstandingPkr, udhParsed.rows);
    const billCsv = C.rowsToCsv(rows.bills.headers, rows.bills.rows);
    const billParsed = C.parseCsv(billCsv);
    check('Phase 5: bills CSV due TOTAL (Rs 5,000) = summary all-unpaid',
      Number(billParsed.rows.find((r) => r['Status'] === 'due (all unpaid)')['Amount (Rs)']) === s.bills.dueAllPkr, billParsed.rows);
    check('Phase 5: bills CSV paid TOTAL (Rs 10,000) = both paid bills ever',
      Number(billParsed.rows.find((r) => r['Status'] === 'paid (all)')['Amount (Rs)']) === 10000, billParsed.rows);
    check('Phase 5: documents CSV carries days-until-expiry (passport 20 days on 2026-11-06) and no photo bytes',
      (() => {
        const docCsv = C.rowsToCsv(rows.documents.headers, rows.documents.rows);
        const parsed = C.parseCsv(docCsv);
        const pass = parsed.rows.find((r) => r['Type'] === 'passport');
        return pass && Number(pass['Days until expiry']) === 20 && !docCsv.includes('data:image');
      })());
    check('Phase 5: CSV money is plain integers — no "Rs" and no thousands commas in amounts',
      !staffCsv.includes('Rs ') && !staffCsv.includes('15,000') && !staffCsv.includes('11,500')
      && staffParsed.rows.every((r) => /^\d+$/.test(String(r['Net payable (Rs)']).trim())));
    check('Phase 5: csvEscape quotes commas and doubles quotes',
      C.csvEscape('a,b') === '"a,b"' && C.csvEscape('say "hi"') === '"say ""hi"""' && C.csvEscape('plain') === 'plain');
    check('Phase 5: combined CSV holds all six sections',
      (() => {
        const all = C.buildCombinedCsv(rows);
        return ['Staff', 'Deliveries', 'Udhaar', 'Bills', 'Documents', 'Medicines'].every((t) => all.includes(t))
          && all.includes('TOTAL');
      })());
    // Second pass (a): borrowed reminder promises to pay back — it never
    // asks the lender to pay us.
    const borrowedEntry = v.udhaar[0].entries.find((e) => e.direction === 'borrowed');
    const borrowedText = M.udhaarReminderText(v.udhaar[0], borrowedEntry);
    check('Phase 5 second pass: borrowed reminder promises to pay back, never asks the lender to pay',
      borrowedText.includes('I will pay') && !borrowedText.includes('ada kar dein'), borrowedText);
    check('Phase 5 second pass: lent reminder still asks the borrower to pay when they can',
      M.udhaarReminderText(v.udhaar[0], lent).includes('Jab asani ho to ada kar dein'));
    // Second pass (b): checklist figures that were NOT verified are
    // softened to "ask the office" — no invented processing times.
    check('Phase 5 second pass: passport checklist no longer prints an unverified processing time',
      !M.getChecklist('passport').items.join(' ').includes('21 working days')
      && M.getChecklist('passport').items.join(' ').includes('Rs 9,000')
      && M.getChecklist('passport').items.join(' ').includes('Ask the office how long it takes'));
    check('Phase 5 second pass: licence checklist no longer prints an unverified renewal window',
      !M.getChecklist('driving licence').items.join(' ').includes('6 months before expiry')
      && M.getChecklist('driving licence').items.join(' ').includes('Rs 450')
      && M.getChecklist('driving licence').items.join(' ').includes('Ask the office how early'));
    check('Phase 5 second pass: verified fee figures stay (CNIC 750/1,500/2,500, token 20,000 / 0.3% / 0.4%)',
      M.getChecklist('CNIC').items.join(' ').includes('Rs 750')
      && M.getChecklist('vehicle token').items.join(' ').includes('Rs 20,000')
      && M.getChecklist('vehicle token').items.join(' ').includes('0.3%'));
  }
  // Backup label (carry-over b): new label created, old label still restores.
  {
    const made = await V.createVault('112233', '', SAMPLE);
    const backup = V.createBackup(made.envelope);
    check('Phase 5: new backups carry the ghar-ka-register label',
      backup.app === 'ghar-ka-register' && V.parseBackup(JSON.stringify(backup)).data === made.envelope.data);
    check('Phase 5: an old-label backup (personal-card-vault, Phase 1–4 builds) still restores',
      V.parseBackup(JSON.stringify({ ...backup, app: 'personal-card-vault' })).data === made.envelope.data
      && (await V.unlockVault('112233', '', V.parseBackup(JSON.stringify({ ...backup, app: 'personal-card-vault' })))).vault.householdName === 'Hashir Home');
    check('Phase 5: both backup labels are listed as accepted',
      V.BACKUP_APP_LABELS.includes('ghar-ka-register') && V.BACKUP_APP_LABELS.includes('personal-card-vault'));
  }
  // ---- §10b. Phase 5 UI wiring (Summary + CSV) in the fake DOM ----
  // The shell vault already holds Ayesha (paid Nov, net Rs 11,500), the
  // doodhwala (Nov total Rs 220, paid) and a gas delivery with a refill.
  const phase5Ids = ['summary-month', 'summary-list', 'summary-empty',
    'csv-staff-btn', 'csv-deliveries-btn', 'csv-udhaar-btn', 'csv-bills-btn',
    'csv-documents-btn', 'csv-medicines-btn', 'csv-all-btn',
    'summary-error', 'summary-ok', 'doc-photo-clear-btn'];
  check('Phase 5 UI: every Summary + export form id exists in index.html',
    phase5Ids.every((id) => htmlSrc.includes('id="' + id + '"')),
    phase5Ids.filter((id) => !htmlSrc.includes('id="' + id + '"')));
  check('Phase 5 UI: the Summary page no longer says "next build phase"',
    !htmlSrc.includes('next build phase'));
  ctx.location.hash = '#/summary';
  ctx._dispatchWin('hashchange');
  el('summary-month').value = '2026-11';
  el('summary-month').dispatch('change');
  check('Phase 5 UI: the Summary page shows the paid staff total (Rs 11,500) + deliveries (Rs 220) + last-month comparison',
    el('summary-list').innerHTML.includes('Rs 11,500')
    && el('summary-list').innerHTML.includes('Rs 220')
    && el('summary-list').innerHTML.includes('last month')
    && isHidden('summary-empty'), el('summary-list').innerHTML.slice(0, 300));
  const blobsBefore5 = ctx._blobs.length;
  el('csv-staff-btn').click();
  check('Phase 5 UI: Staff CSV export downloads a readable CSV with the helper + TOTAL',
    ctx._blobs.length === blobsBefore5 + 1
    && String(ctx._blobs[ctx._blobs.length - 1].parts[0]).includes('Ayesha')
    && String(ctx._blobs[ctx._blobs.length - 1].parts[0]).includes('Net payable (Rs)')
    && el('summary-ok').textContent.includes('Exported the staff CSV'),
    String(ctx._blobs[ctx._blobs.length - 1].parts[0]).slice(0, 200));
  el('csv-all-btn').click();
  check('Phase 5 UI: combined CSV export holds all six sections',
    ctx._blobs.length === blobsBefore5 + 2
    && ['Staff', 'Deliveries', 'Udhaar', 'Bills', 'Documents', 'Medicines']
      .every((t) => String(ctx._blobs[ctx._blobs.length - 1].parts[0]).includes(t)));
  // Second pass (c): the refill list offers gas cylinders only.
  ctx.location.hash = '#/deliveries';
  ctx._dispatchWin('hashchange');
  check('Phase 5 second pass UI: the gas-refill list offers gas cylinders only (no doodhwala)',
    el('refill-delivery').innerHTML.includes('Gas cylinder')
    && !el('refill-delivery').innerHTML.includes('Doodhwala'));
  // Second pass (d): the photo-clear button exists and clears the note.
  el('doc-photo-clear-btn').click();
  check('Phase 5 second pass UI: Remove photo clears the photo note',
    el('doc-photo-note').textContent === '');

  // ---- §9. Live smoke on a throwaway port (the real port 3036 is checked by hand) ----
  const { spawn } = require('node:child_process');
  const TEST_PORT = 3037;
  const BASE = 'http://127.0.0.1:' + TEST_PORT;
  function req(method, p) {
    return new Promise((resolve, reject) => {
      const r = require('node:http').request(BASE + p, { method }, (res) => {
        let raw = '';
        res.on('data', (c) => { raw += c; });
        res.on('end', () => resolve({ status: res.statusCode, raw }));
      });
      r.on('error', reject);
      r.end();
    });
  }
  const server = spawn('node', ['server.js'], {
    cwd: __dirname, env: { ...process.env, PORT: String(TEST_PORT) },
  });
  let serverOut = '';
  server.stdout.on('data', (d) => { serverOut += d; });
  server.stderr.on('data', (d) => { serverOut += d; });
  try {
    let up = false;
    for (let i = 0; i < 20 && !up; i++) {
      try { await req('GET', '/health'); up = true; } catch (_e) { await sleep(200); }
    }
    check('Smoke: server comes up on a fresh port', up);
    check('Smoke: /health ok', (await req('GET', '/health')).status === 200);
    check('Smoke: /health body is {"ok":true}',
      (await req('GET', '/health')).raw === JSON.stringify({ ok: true }));
    for (const p of ['/', '/index.html', '/styles.css', '/vault.js', '/model.js', '/nav.js', '/app.js', '/csv.js', '/proof.js', '/bg.jpg', '/favicon.ico']) {
      check('Smoke: GET ' + p + ' -> 200', (await req('GET', p)).status === 200);
    }
    // Removed modules: no longer in the server allowlist (Phase 5
    // cleanup), so they 404 like any unknown path.
    for (const p of ['/sms.js', '/intel.js', '/totp.js', '/cards.js']) {
      check('Smoke: GET ' + p + ' -> 404 (module removed)', (await req('GET', p)).status === 404);
    }
    // ocr.js stays on disk (dormant, Phase 2) and is still served; it is
    // simply never loaded by any page.
    check('Smoke: GET /ocr.js -> 200 (dormant, on disk, not loaded)', (await req('GET', '/ocr.js')).status === 200);
    // OCR engine (vendored Tesseract) is still served from this same origin.
    for (const p of ['/vendor/tesseract/tesseract.min.js', '/vendor/tesseract/worker.min.js',
      '/vendor/tesseract/tesseract-core.wasm.js', '/vendor/tesseract/tesseract-core.wasm',
      '/vendor/tesseract/eng.traineddata']) {
      check('Smoke: GET ' + p + ' -> 200', (await req('GET', p)).status === 200);
    }
    check('Smoke: vendor paths outside the OCR engine are not served', (await req('GET', '/vendor/tesseract/other.js')).status === 404);
    const home = await req('GET', '/');
    check('Smoke: homepage names Ghar ka Register + no-recovery warning',
      home.raw.includes('Ghar ka Register') && home.raw.includes('No recovery, by design'));
    check('Smoke: homepage shows the empty-Today state',
      home.raw.includes('Nothing due — add your first helper, bill or document.'));
    check('Smoke: homepage loads the six Phase-1 scripts and no removed ones',
      home.raw.includes('/vault.js') && home.raw.includes('/model.js')
      && home.raw.includes('/csv.js') && home.raw.includes('/proof.js')
      && home.raw.includes('/nav.js') && home.raw.includes('/app.js')
      && !home.raw.includes('/sms.js') && !home.raw.includes('/intel.js')
      && !home.raw.includes('/totp.js') && !home.raw.includes('/cards.js')
      && !home.raw.includes('/ocr.js'));
    check('Smoke: homepage has all 11 page sections',
      EXPECTED_PAGES.every((p) => home.raw.includes('id="page-' + p + '"')));
    check('Smoke: unknown page -> 404', (await req('GET', '/nope.html')).status === 404);
    check('Smoke: server log names Ghar ka Register',
      serverOut.includes('Ghar ka Register listening on :' + TEST_PORT), serverOut.trim());
  } finally {
    server.kill();
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  if (failed > 0) { console.log('TESTS FAILED'); process.exit(1); }
  console.log('ALL TESTS PASSED');
}

main().catch((e) => { console.error('TEST RUNNER ERROR', e); process.exit(1); });
