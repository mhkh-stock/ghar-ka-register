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

  // ---- §4b. One layout sequence on every page (Task 4) ----
  // One h2 per screen/page (the title only); back-link first where one
  // exists; sections as h3 in the fixed order form -> list -> actions
  // -> notes; page sections in the file in sidebar order.
  function sectionBody(id) {
    const start = htmlSrc.indexOf('id="' + id + '"');
    if (start < 0) return null;
    return htmlSrc.slice(htmlSrc.lastIndexOf('<section', start), htmlSrc.indexOf('</section>', start));
  }
  const seqPages = ['setup-screen', 'unlock-screen', 'page-home', 'page-staff', 'page-deliveries',
    'page-udhaar', 'page-bills', 'page-documents', 'page-medicine', 'page-summary',
    'page-security', 'page-backup', 'page-profile'];
  check('Layout: every screen/page has exactly one h2 (the title only)',
    seqPages.every((id) => {
      const b = sectionBody(id);
      return b && (b.match(/<h2[\s>]/g) || []).length === 1;
    }));
  check('Layout: the back-link is first on every page that has one (not Today)',
    ['page-staff', 'page-deliveries', 'page-udhaar', 'page-bills', 'page-documents',
      'page-medicine', 'page-summary', 'page-security', 'page-backup', 'page-profile']
      .every((id) => {
        const b = sectionBody(id);
        return b && b.slice(b.indexOf('>') + 1).trim().startsWith('<a class="back-link"');
      }));
  check('Layout: page sections in index.html follow the sidebar order',
    seqPages.every((id, i) => i === 0 || htmlSrc.indexOf('id="' + seqPages[i - 1] + '"') < htmlSrc.indexOf('id="' + id + '"')));
  function h3s(id) {
    const b = sectionBody(id) || '';
    return [...b.matchAll(/<h3[^>]*>([^<]*)<\/h3>/g)].map((m) => m[1].trim());
  }
  // D15: every page runs form(s) -> list -> actions, so the record
  // forms sit before their lists (not after, reading as actions).
  check('Layout: Staff sections run form -> form -> form -> list',
    JSON.stringify(h3s('page-staff')) === JSON.stringify(['Add a helper', 'Record an advance', "Change a helper's salary", 'Helpers']), h3s('page-staff'));
  check('Layout: Deliveries sections run form -> form -> form -> list',
    JSON.stringify(h3s('page-deliveries')) === JSON.stringify(['Add a delivery', 'Log a day', 'Gas refill', 'Deliveries']), h3s('page-deliveries'));
  check('Layout: Udhaar sections run form -> form -> form -> form -> list',
    JSON.stringify(h3s('page-udhaar')) === JSON.stringify(['Add a person', 'Add an udhaar entry', 'Record a repayment', 'Forgive an amount', 'People &amp; entries']), h3s('page-udhaar'));
  check('Layout: Security sections run credentials -> change PIN -> change passphrase -> change Gmail -> recovery -> notes',
    JSON.stringify(h3s('page-security')) === JSON.stringify(['Your current PIN and passphrase', 'Change PIN', 'Change passphrase', 'Change login Gmail', 'Forgot-code recovery', 'How your book is protected']), h3s('page-security'));
  check('Layout: Summary sections run figures -> export',
    JSON.stringify(h3s('page-summary')) === JSON.stringify(["This month's figures", 'Export — CSV']), h3s('page-summary'));
  check('Layout: no duplicate current-PIN/passphrase fields survive on Security',
    !htmlSrc.includes('id="change-pin-old"') && !htmlSrc.includes('id="change-pin-pass"')
    && !htmlSrc.includes('id="change-pass-old"') && !htmlSrc.includes('id="change-pass-pass"')
    && htmlSrc.includes('id="security-pin"') && htmlSrc.includes('id="security-pass"'));
  check('Layout: the sidebar Lock book button does not share the Security lock icon',
    htmlSrc.includes('id="lock-btn"') && !/>🔒 <span class="nav-label">Lock book<\/span>/.test(htmlSrc)
    && />🚪 <span class="nav-label">Lock book<\/span>/.test(htmlSrc));

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

  // Profile contact details + picture (phone/email optional, photo in the vault).
  const vP = M.emptyVault();
  check('Model: emptyVault carries empty phone/email and no photo',
    vP.phone === '' && vP.email === '' && vP.photo === null);
  for (const good of ['0300 1234567', '+92 300 1234567', '0300-1234567', '03001234567']) {
    check('Model: setHousehold accepts phone ' + JSON.stringify(good),
      M.setHousehold(M.emptyVault(), { householdName: 'H', monthStartDay: 1, phone: good }).phone === good);
  }
  for (const bad of ['abc', '0300', '0300#123', 'x'.repeat(21), '++92 300 1234567']) {
    check('Model: setHousehold rejects phone ' + JSON.stringify(bad),
      throwsCode(() => M.setHousehold(M.emptyVault(), { householdName: 'H', monthStartDay: 1, phone: bad }), 'VALIDATION'));
  }
  for (const good of ['a@b.com', 'hashir.name@example.pk']) {
    check('Model: setHousehold accepts email ' + good,
      M.setHousehold(M.emptyVault(), { householdName: 'H', monthStartDay: 1, email: good }).email === good);
  }
  for (const bad of ['no-at', 'a@b', 'a b@c.com', 'a@@b.com', '@b.com']) {
    check('Model: setHousehold rejects email ' + JSON.stringify(bad),
      throwsCode(() => M.setHousehold(M.emptyVault(), { householdName: 'H', monthStartDay: 1, email: bad }), 'VALIDATION'));
  }
  check('Model: setHousehold allows empty phone and email',
    (() => { const r = M.setHousehold(M.emptyVault(), { householdName: 'H', monthStartDay: 1, phone: '', email: '' }); return r.phone === '' && r.email === ''; })());
  check('Model: a bad phone or email saves nothing (vault unchanged)',
    (() => {
      const v = M.emptyVault();
      M.setHousehold(v, { householdName: 'Before', monthStartDay: 3, phone: '03001234567', email: 'a@b.com' });
      try { M.setHousehold(v, { householdName: 'After', monthStartDay: 4, phone: 'abc', email: 'bad' }); } catch (_e) { /* expected */ }
      return v.householdName === 'Before' && v.monthStartDay === 3 && v.phone === '03001234567' && v.email === 'a@b.com';
    })());
  // Profile picture: JPEG/PNG by magic bytes, 500 KB cap, remove = null.
  const tinyJpeg = 'data:image/jpeg;base64,' + Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]).toString('base64');
  const tinyPng = 'data:image/png;base64,' + Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).toString('base64');
  const tinyGif = 'data:image/gif;base64,' + Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]).toString('base64');
  const bigJpeg = 'data:image/jpeg;base64,' + Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF]), Buffer.alloc(600 * 1024, 0)]).toString('base64');
  check('Model: setHouseholdPhoto stores a JPEG and reads its true mime',
    (() => { const v = M.emptyVault(); const p = M.setHouseholdPhoto(v, { dataUrl: tinyJpeg, mime: 'image/png' }); return p && p.mime === 'image/jpeg' && v.photo === p; })());
  check('Model: setHouseholdPhoto stores a PNG',
    (() => { const v = M.emptyVault(); return M.setHouseholdPhoto(v, { dataUrl: tinyPng, mime: 'image/png' }).mime === 'image/png'; })());
  check('Model: setHouseholdPhoto rejects a GIF (not JPEG/PNG)',
    throwsCode(() => M.setHouseholdPhoto(M.emptyVault(), { dataUrl: tinyGif, mime: 'image/gif' }), 'VALIDATION'));
  check('Model: setHouseholdPhoto rejects a text file',
    throwsCode(() => M.setHouseholdPhoto(M.emptyVault(), { dataUrl: 'data:text/plain;base64,aGVsbG8=', mime: 'text/plain' }), 'VALIDATION'));
  check('Model: setHouseholdPhoto refuses a photo over 500 KB (the app shrinks it first)',
    throwsCode(() => M.setHouseholdPhoto(M.emptyVault(), { dataUrl: bigJpeg, mime: 'image/jpeg' }), 'VALIDATION'));
  check('Model: setHouseholdPhoto(null) removes the picture',
    (() => { const v = M.emptyVault(); M.setHouseholdPhoto(v, { dataUrl: tinyJpeg, mime: 'image/jpeg' }); return M.setHouseholdPhoto(v, null) === null && v.photo === null; })());
  check('Model: normalizeHousehold fills missing phone/email/photo on an old vault',
    (() => {
      const v = M.emptyVault();
      delete v.phone; delete v.email; delete v.photo;
      const hh = M.normalizeHousehold(v);
      return hh.phone === '' && hh.email === '' && hh.photo === null
        && v.phone === '' && v.email === '' && v.photo === null;
    })());
  check('Model: normalizeHousehold keeps phone/email/photo that are already there',
    (() => {
      const v = M.emptyVault();
      M.setHousehold(v, { householdName: 'H', monthStartDay: 2, phone: '03001234567', email: 'a@b.com' });
      M.setHouseholdPhoto(v, { dataUrl: tinyJpeg, mime: 'image/jpeg' });
      const hh = M.normalizeHousehold(v);
      return hh.phone === '03001234567' && hh.email === 'a@b.com' && hh.photo !== null && hh.photo.dataUrl === tinyJpeg;
    })());
  check('Model: profile round-trip — phone/email/photo survive a save + reload',
    (() => {
      const v = M.emptyVault();
      M.setHousehold(v, { householdName: 'H', monthStartDay: 2, phone: '+92 300 1234567', email: 'a@b.com' });
      M.setHouseholdPhoto(v, { dataUrl: tinyPng, mime: 'image/png' });
      const reloaded = JSON.parse(JSON.stringify(v));
      const hh = M.normalizeHousehold(reloaded);
      return hh.phone === '+92 300 1234567' && hh.email === 'a@b.com' && hh.photo && hh.photo.dataUrl === tinyPng;
    })());

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
  check('Model: Today shows udhaar with no due date, one row per person, sorted last',
    items.some((i) => i.kind === 'udhaar' && i.noDueDate === true && i.detail.includes('Rs 7,000')
      && i.title.includes('Ahmed') && M.dueLabel(i) === 'no due date')
    && items[items.length - 1].noDueDate === true, kinds);
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
  check('Model: Today is sorted soonest-first, undated udhaar last',
    items.slice(0, -1).every((it, idx) => idx === 0 || items[idx - 1].date <= it.date)
    && items[items.length - 1].noDueDate === true, items.map((i) => i.date));
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
  for (const f of ['sms.js', 'intel.js', 'totp.js', 'cards.js', 'proof.js', 'ocr.js']) {
    check('Review: removed module ' + f + ' is deleted from public/',
      !fs.existsSync(path.join(__dirname, 'public', f)));
  }
  const appCode = [htmlSrc, appSrc,
    fs.readFileSync(path.join(__dirname, 'public', 'model.js'), 'utf8'),
    fs.readFileSync(path.join(__dirname, 'public', 'nav.js'), 'utf8')].join('\n');
  check('Review: no removed-module file or API is referenced by the app code',
    !/(sms|intel|totp|cards|proof|ocr)\.js|vendor\/|SmsParser|Intel\.|Totp\.|Cards\.|Proof\./.test(appCode));
  // D9/D11 cleanup: the dead proof/OCR files are deleted from disk —
  // proof.js was loaded but never called by the live app, ocr.js was
  // never loaded by any page and could not even be required (it
  // depended on the deleted sms.js), and the ~12 MB vendor engine
  // was served but never fetched.
  check('Review: proof.js, ocr.js and public/vendor are deleted (D9/D11)',
    !fs.existsSync(path.join(__dirname, 'public', 'proof.js'))
    && !fs.existsSync(path.join(__dirname, 'public', 'ocr.js'))
    && !fs.existsSync(path.join(__dirname, 'public', 'vendor'))
    && !/proof\.js|ocr\.js|vendor\//.test(htmlSrc) && !/proof\.js|ocr\.js|vendor\//.test(appSrc));
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
  check('R1: the page states the honest limits (nothing fetched, no reminders closed, spare-key limit)',
    htmlSrc.includes('Nothing is fetched, checked or looked up')
    && htmlSrc.includes('There are no reminders when the app is closed')
    && htmlSrc.includes('If the spare key file is deleted, forgot-code recovery stops working — the book still opens with your code'));
  // R2: no live data — the app calls ONLY its own server (same-origin
  // POSTs to /api/* for the login portal). No outside URL, no XHR,
  // no WebSocket, no live data of any kind.
  check('R2: app.js only calls its own server (same-origin /api/, no XHR/WebSocket, no outside URL)',
    !/XMLHttpRequest|WebSocket/.test(appSrc)
    && !/fetch\s*\(\s*['"`]https?:/.test(appSrc)
    && !/['"`]https?:\/\/[^'"` ]+['"`]/.test(appSrc)
    && appSrc.includes('fetch(path,'));
  check('R2: app.js never reads SMS', !/sms/i.test(appSrc) && !/sms/i.test(htmlSrc));
  // P12 portal: the server gained POST routes, but ONLY the portal API
  // (mail status, OTP, recovery) — no PUT/DELETE/PATCH routes, and every
  // POST route is behind the same-origin check.
  const serverSrc = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  check('Review: server write routes are only the P12 portal API (POST, same-origin)',
    !/req\.method === '(PUT|DELETE|PATCH)'/.test(serverSrc)
    && ['/api/mail/status', '/api/otp/request', '/api/otp/verify',
      '/api/recover/setup', '/api/recover/reset', '/api/recover/off'].every((p) => serverSrc.includes("'" + p + "'"))
    && serverSrc.includes('originAllowed(req)'));
  check('Review: server binds localhost only, never 0.0.0.0 (D5)',
    serverSrc.includes("server.listen(PORT, '127.0.0.1'") && !serverSrc.includes('0.0.0.0'));
  check('Review: server has no database (only the two P12 files, never served)',
    !/sqlite|DatabaseSync/.test(serverSrc)
    && serverSrc.includes('RECOVERY_KEY_FILE') && serverSrc.includes('ACCOUNT_FILE')
    && serverSrc.includes('data/ is never served'));
  check('Review: server log line + title name the new app',
    serverSrc.includes('Ghar ka Register listening') && serverSrc.startsWith('// Ghar ka Register'));
  check('Review: server.js keeps the old app name out',
    !serverSrc.includes('Personal Card Vault'));
  // The five scripts the shell needs are loaded, in order, and nothing else.
  const scriptOrder = [...htmlSrc.matchAll(/<script src="\/([a-z]+\.js)"><\/script>/g)].map((m) => m[1]);
  check('Review: index.html loads exactly the five scripts in order',
    JSON.stringify(scriptOrder) === JSON.stringify(['vault.js', 'model.js', 'csv.js', 'nav.js', 'app.js']), scriptOrder);
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
  // Acceptance (paid leave, Hashir 2026-11-06): Rs 15,000 salary,
  // 3 absent days, Rs 2,000 advance (full recovery), 2 days paid leave
  // -> the first 2 absent days are free, so it pays
  // Rs 15,000 − 500 − 2,000 = Rs 12,500, every line shown.
  {
    const { v, s } = payVault();
    M.markAttendance(v, s.id, '2026-11-01', 'absent');
    M.markAttendance(v, s.id, '2026-11-02', 'absent');
    M.markAttendance(v, s.id, '2026-11-03', 'absent');
    M.addAdvance(v, s.id, { amount: 2000, date: '2026-11-05', recovery: 'full' });
    const w = M.computeMonthPay(v, s.id, '2026-11');
    check('Phase 2 acceptance (paid leave): 15,000 − 3 absent (2 free) − 2,000 advance = 12,500 net',
      w.salaryPkr === 15000 && w.absentDays === 3 && w.halfDays === 0
      && w.freeDaysUsed === 2 && w.freeDaysLeft === 0
      && w.chargedAbsentDays === 1 && w.chargedHalfDays === 0
      && w.absentDeduction === 500 && w.halfDeduction === 0
      && w.advanceRecovery === 2000 && w.netPkr === 12500 && w.daysInMonth === 30, w);
    const stmt = M.staffPayStatement(s, '2026-11');
    check('Phase 2: WhatsApp statement contains every working line (paid leave shown)',
      stmt.includes('Ayesha') && stmt.includes('2026-11')
      && stmt.includes('Monthly salary: Rs 15,000')
      && stmt.includes('Paid leave used: 2 days — Rs 0')
      && stmt.includes('Absent days: 1 x Rs 500 = Rs 500')
      && stmt.includes('Half days: 0 x Rs 250 = Rs 0')
      && stmt.includes('Advance recovery: Rs 2,000')
      && stmt.includes('Net payable: Rs 15,000 - Rs 500 - Rs 0 - Rs 2,000 = Rs 12,500')
      && stmt.includes('as you entered it'), stmt);
    // Same rows with NO paid leave left: the old number stands.
    const v0 = M.emptyVault();
    const s0 = M.addStaff(v0, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 0 });
    M.markAttendance(v0, s0.id, '2026-11-01', 'absent');
    M.markAttendance(v0, s0.id, '2026-11-02', 'absent');
    M.markAttendance(v0, s0.id, '2026-11-03', 'absent');
    M.addAdvance(v0, s0.id, { amount: 2000, date: '2026-11-05', recovery: 'full' });
    const w0 = M.computeMonthPay(v0, s0.id, '2026-11');
    check('Phase 2 acceptance (no paid leave): 15,000 − 3 absent − 2,000 advance = 11,500 net',
      w0.freeDaysUsed === 0 && w0.chargedAbsentDays === 3 && w0.absentDeduction === 1500
      && w0.netPkr === 11500, w0);
    // Same rows, no advance: 15,000 − 500 = 14,500.
    const vN = M.emptyVault();
    const sN = M.addStaff(vN, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 });
    M.markAttendance(vN, sN.id, '2026-11-01', 'absent');
    M.markAttendance(vN, sN.id, '2026-11-02', 'absent');
    M.markAttendance(vN, sN.id, '2026-11-03', 'absent');
    check('Phase 2 acceptance (paid leave, no advance): 15,000 − 3 absent (2 free) = 14,500 net',
      M.computeMonthPay(vN, sN.id, '2026-11').netPkr === 14500);
    check('Phase 2: computeMonthPay rejects a bad month key',
      throwsCode(() => M.computeMonthPay(v, s.id, '2026-13'), 'VALIDATION'));
    check('Phase 2: computeMonthPay for an unknown helper fails (NOT_FOUND)',
      throwsCode(() => M.computeMonthPay(v, 'nope', '2026-11'), 'NOT_FOUND'));
    // Half days + paid leave: 1 half (0.5 free days) + 1 absent (1 free
    // day) use 1.5 of the 2 free days, so nothing deducts and 0.5 free
    // days are left. The rounding itself is covered by the leave-0 twin.
    const vH = M.emptyVault();
    const h = M.addStaff(vH, { name: 'Bilal', role: 'driver', salaryPkr: 10000, joinedDate: '2026-11-01', leavePerMonth: 2 });
    M.markAttendance(vH, h.id, '2026-11-02', 'half');
    M.markAttendance(vH, h.id, '2026-11-03', 'absent');
    const wH = M.computeMonthPay(vH, h.id, '2026-11');
    check('Phase 2 (paid leave): 1 half day with leave 2 costs nothing — 1.5 free days left',
      wH.halfDays === 1 && wH.absentDays === 1 && wH.freeDaysUsed === 1.5 && wH.freeDaysLeft === 0.5
      && wH.halfDeduction === 0 && wH.absentDeduction === 0 && wH.netPkr === 10000, wH);
    const vH0 = M.emptyVault();
    const h0 = M.addStaff(vH0, { name: 'Bilal', role: 'driver', salaryPkr: 10000, joinedDate: '2026-11-01', leavePerMonth: 0 });
    M.markAttendance(vH0, h0.id, '2026-11-02', 'half');
    M.markAttendance(vH0, h0.id, '2026-11-03', 'absent');
    const wH0 = M.computeMonthPay(vH0, h0.id, '2026-11');
    check('Phase 2: half-day deduction is salary ÷ 60, rounded (10,000 ÷ 60 = 167)',
      wH0.halfDays === 1 && wH0.halfDeduction === 167, wH0);
    check('Phase 2: absent deduction is salary ÷ 30, rounded (10,000 ÷ 30 = 333)',
      wH0.absentDays === 1 && wH0.absentDeduction === 333 && wH0.netPkr === 10000 - 333 - 167, wH0);
  }
  // Paid leave edges + mid-month proration (Hashir 2026-11-06):
  // leave excuses the first N absent days; joiners are paid only from
  // the join date. Each case is hand-computed below.
  {
    const mk = (salary, leave, joined) => {
      const v = M.emptyVault();
      const s = M.addStaff(v, { name: 'T', role: 'maid', salaryPkr: salary, joinedDate: joined, leavePerMonth: leave });
      return { v, s };
    };
    const mark = (v, s, dates, what) => dates.forEach((d) => M.markAttendance(v, s.id, d, what));
    // 1 absent day, leave 2: full salary, 1 free day left.
    {
      const { v, s } = mk(15000, 2, '2026-11-01');
      mark(v, s, ['2026-11-05'], 'absent');
      const w = M.computeMonthPay(v, s.id, '2026-11');
      check('Phase 2 (paid leave): 1 absent day with leave 2 is free — full salary, 1 free day left',
        w.netPkr === 15000 && w.freeDaysUsed === 1 && w.freeDaysLeft === 1
        && w.chargedAbsentDays === 0 && w.absentDeduction === 0, w);
    }
    // 4 absent days, leave 2: 2 deduct.
    {
      const { v, s } = mk(15000, 2, '2026-11-01');
      mark(v, s, ['2026-11-01', '2026-11-02', '2026-11-03', '2026-11-04'], 'absent');
      const w = M.computeMonthPay(v, s.id, '2026-11');
      check('Phase 2 (paid leave): 4 absent days with leave 2 deduct 2 days — net 14,000',
        w.freeDaysUsed === 2 && w.freeDaysLeft === 0 && w.chargedAbsentDays === 2
        && w.absentDeduction === 1000 && w.netPkr === 14000, w);
    }
    // Consumption order: absent days use the free days first.
    // Leave 1, 1 absent + 1 half: the absent day is free, the half day
    // is charged (250). Leave 2, 2 absent + 2 half: both absent days
    // are free, both half days are charged (500).
    {
      const { v, s } = mk(15000, 1, '2026-11-01');
      mark(v, s, ['2026-11-01'], 'absent');
      mark(v, s, ['2026-11-02'], 'half');
      const w = M.computeMonthPay(v, s.id, '2026-11');
      check('Phase 2 (paid leave): leave 1, 1 absent + 1 half — absent free, half charged Rs 250',
        w.freeDaysUsed === 1 && w.chargedAbsentDays === 0 && w.chargedHalfDays === 1
        && w.halfDeduction === 250 && w.netPkr === 14750, w);
    }
    {
      const { v, s } = mk(15000, 2, '2026-11-01');
      mark(v, s, ['2026-11-01', '2026-11-02'], 'absent');
      mark(v, s, ['2026-11-03', '2026-11-04'], 'half');
      const w = M.computeMonthPay(v, s.id, '2026-11');
      check('Phase 2 (paid leave): leave 2, 2 absent + 2 half — absents free, halves charged Rs 500',
        w.freeDaysUsed === 2 && w.chargedAbsentDays === 0 && w.chargedHalfDays === 2
        && w.halfDeduction === 500 && w.netPkr === 14500, w);
    }
    // Proration: joined 16 Nov (30-day month) -> 15 days x 500 = 7,500.
    {
      const { v, s } = mk(15000, 2, '2026-11-16');
      const w = M.computeMonthPay(v, s.id, '2026-11');
      check('Phase 2 (proration): joined 16 Nov, Rs 15,000 — 15 days = Rs 7,500',
        w.isProrated === true && w.proratedDays === 15 && w.salaryPkr === 7500 && w.netPkr === 7500, w);
      const stmt = M.staffPayStatement(s, '2026-11');
      check('Phase 2 (proration): statement shows the prorated salary line',
        stmt.includes('Salary (joined 2026-11-16, 15 days): Rs 7,500')
        && stmt.includes('Net payable: Rs 7,500 - Rs 0 - Rs 0 - Rs 0 = Rs 7,500'), stmt);
    }
    // Joined on the 1st: the full salary, not prorated.
    {
      const { v, s } = mk(15000, 2, '2026-11-01');
      const w = M.computeMonthPay(v, s.id, '2026-11');
      check('Phase 2 (proration): joined 1 Nov — full salary, not prorated',
        w.isProrated === false && w.proratedDays === 30 && w.salaryPkr === 15000 && w.netPkr === 15000, w);
    }
    // Joined on the last day: one day's pay.
    {
      const { v, s } = mk(15000, 2, '2026-11-30');
      const w = M.computeMonthPay(v, s.id, '2026-11');
      check('Phase 2 (proration): joined 30 Nov — one day = Rs 500',
        w.isProrated === true && w.proratedDays === 1 && w.salaryPkr === 500 && w.netPkr === 500, w);
    }
    // A 31-day month counts to the 31st; joining on the 1st still pays
    // the full salary (never more than the monthly salary).
    {
      const { v, s } = mk(15000, 2, '2026-10-16');
      const w = M.computeMonthPay(v, s.id, '2026-10');
      check('Phase 2 (proration): joined 16 Oct (31-day month) — 16 days = Rs 8,000',
        w.proratedDays === 16 && w.salaryPkr === 8000 && w.netPkr === 8000, w);
    }
    {
      const { v, s } = mk(15000, 2, '2026-10-01');
      const w = M.computeMonthPay(v, s.id, '2026-10');
      check('Phase 2 (proration): joined 1 Oct (31-day month) — full salary, capped at 30 days',
        w.isProrated === false && w.proratedDays === 30 && w.salaryPkr === 15000, w);
    }
    {
      const { v, s } = mk(15000, 2, '2026-10-31');
      const w = M.computeMonthPay(v, s.id, '2026-10');
      check('Phase 2 (proration): joined 31 Oct — one day = Rs 500',
        w.proratedDays === 1 && w.salaryPkr === 500, w);
    }
    // A joiner with absences deducts from the prorated salary.
    // (October dates: the D4 rule refuses attendance in the future,
    // so these cases use a month that is fully past.)
    {
      const { v, s } = mk(15000, 2, '2026-10-16');
      mark(v, s, ['2026-10-20', '2026-10-21'], 'absent');
      const w = M.computeMonthPay(v, s.id, '2026-10');
      check('Phase 2 (proration + leave): joined 16 Oct, 2 absent, leave 2 — both free, net Rs 8,000',
        w.salaryPkr === 8000 && w.freeDaysUsed === 2 && w.netPkr === 8000, w);
    }
    {
      const { v, s } = mk(15000, 2, '2026-10-16');
      mark(v, s, ['2026-10-20', '2026-10-21', '2026-10-22'], 'absent');
      const w = M.computeMonthPay(v, s.id, '2026-10');
      check('Phase 2 (proration + leave): joined 16 Oct, 3 absent, leave 2 — 1 charged, net Rs 7,500',
        w.salaryPkr === 8000 && w.chargedAbsentDays === 1 && w.absentDeduction === 500 && w.netPkr === 7500, w);
    }
    // A month before the join date pays nothing — the helper was not here.
    {
      const { v, s } = mk(15000, 2, '2026-12-01');
      const w = M.computeMonthPay(v, s.id, '2026-11');
      check('Phase 2 (proration): a month before the join date pays Rs 0',
        w.proratedDays === 0 && w.salaryPkr === 0 && w.netPkr === 0, w);
    }
    // A working stored before these rules (no new fields) still reads:
    // every absent day charged, no proration, no "undefined" anywhere.
    check('Phase 2: a working stored under the old rules renders without undefined',
      (() => {
        const v = M.emptyVault();
        const s = M.addStaff(v, { name: 'Old', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 });
        const oldWorking = { salaryPkr: 15000, absentDays: 2, halfDays: 0, absentDeduction: 1000, halfDeduction: 0, advanceRecovery: 0, netPkr: 14000, daysInMonth: 30 };
        s.paidMonths.push({ month: '2026-11', working: oldWorking, netPkr: 14000, paidDate: '2026-11-30' });
        const stmt = M.staffPayStatement(s, '2026-11');
        return stmt.includes('Monthly salary: Rs 15,000')
          && stmt.includes('Absent days: 2 x Rs 500 = Rs 1,000')
          && stmt.includes('Net payable: Rs 15,000 - Rs 1,000 - Rs 0 - Rs 0 = Rs 14,000')
          && !stmt.includes('undefined');
      })());
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
    check('Phase 2: the stored paid working survives the lock (paid leave: 1 absent free, net 13,000)',
      M.findPaidStaffMonth(s, '2026-11').netPkr === 13000
      && M.isStaffMonthPaid(s, '2026-11') === true && M.isStaffMonthPaid(s, '2026-12') === false);
    check('Phase 2: a paid statement shows the stored working + paid date',
      M.staffPayStatement(s, '2026-11').includes('Net payable: Rs 15,000 - Rs 0 - Rs 0 - Rs 2,000 = Rs 13,000')
      && M.staffPayStatement(s, '2026-11').includes('Paid on 2026-11-30')
      && M.staffPayStatement(s, '2026-11').includes('Paid leave used: 1 day — Rs 0')
      && M.staffPayStatement(s, '2026-11').includes('Absent days: 0 x Rs 500 = Rs 0'));
    check('Phase 2: the next month is still open after a lock (pay maths only — marking a December day refuses while today is in November, see D4)',
      M.computeMonthPay(v, s.id, '2026-12').netPkr === 15000);
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
      // P12 portal: "verify"/"check"/"fetch" here are about the OTP code
      // and the app's own server — never about a household record. The
      // OTP is verified, the Gmail is checked, the code is fetched from
      // the user's own inbox via the app's own /api/* endpoints.
      'We will send a 6-digit code to your Gmail to check it is yours.',
      'Verify code',
      'Could not check the code — try again.',
      '/api/otp/verify',
      'fetch(path, {',
      'setup-verify-btn',
      'mig-verify-btn',
      'reset-verify-btn',
      'change-gmail-verify-btn',
      'recovery-verify-btn',
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
  // Proves the real flow end to end: register (Gmail + OTP) -> empty
  // Today -> lock -> wrong codes -> lockout -> unlock -> profile save ->
  // change PIN -> export -> auto-lock -> no page reachable while locked.
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
    const fetchCalls = [];
    let mailConfigured = true;
    let portalPin = '123456';
    let setupCount = 0;
    let setupConflict = false; // D12: the server already has recovery for a different book
    let fakeNow = 1779969600000; // 2026-05-28T12:00:00Z: MIDDAY UTC so the fake local date is May 28 in every timezone (the old 20:26Z instant was May 29 in PKT and broke 13 date-relative UI checks under TZ=Asia/Karachi)
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
      // Mocked portal API (fetch boundary): the suite never needs a real
      // server. Mail is "configured" by default; the OTP code the fake
      // "sends" is always '123456'. The fake reset does REAL crypto: it
      // decrypts the stored envelope with the known current code
      // (portalPin, set by the test) and re-encrypts under the new code,
      // so the data survives the reset. Passphrase is '' in the fake.
      fetch: async (url, opts) => {
        const u = String(url);
        const body = opts && opts.body ? JSON.parse(opts.body) : {};
        fetchCalls.push({ url: u, body });
        const ok = (status, json) => ({ ok: status >= 200 && status < 300, status, json: async () => json });
        if (u.endsWith('/api/mail/status')) return ok(200, { configured: mailConfigured });
        if (u.endsWith('/api/otp/request')) {
          if (!mailConfigured) return ok(503, { ok: false, error: 'MAIL_NOT_CONFIGURED' });
          if (body.purpose === 'reset' && !store.has(V.ACCOUNT_KEY)) return ok(200, { ok: false, error: 'RECOVERY_OFF' });
          return ok(200, { ok: true });
        }
        if (u.endsWith('/api/otp/verify')) {
          if (body.code === '123456') return ok(200, { ok: true, token: 'tok-' + (body.purpose || 'x') });
          return ok(200, { ok: false, error: 'WRONG', triesLeft: 4 });
        }
        if (u.endsWith('/api/recover/setup')) {
          // Gmail change (Phase 4): the caller sends the current spare
          // envelope + a token; the server returns the SAME envelope
          // and records whether the old Gmail was notified.
          if (body.rkEnvelope) {
            return ok(200, { ok: true, rkEnvelope: body.rkEnvelope, notifiedOld: true });
          }
          // D12: the server already has recovery for a different book —
          // setup answers ALREADY_SET_OTHER_BOOK until the caller
          // re-binds on purpose (rebind:true).
          if (setupConflict && !body.rebind) {
            return ok(409, { ok: false, error: 'ALREADY_SET_OTHER_BOOK' });
          }
          if (body.rebind) setupConflict = false;
          setupCount += 1;
          const tag = setupCount === 1 ? 'fake-rk-envelope' : 'fake-rk-envelope-' + setupCount;
          return ok(200, { ok: true, rkEnvelope: { v: 1, kdf: 'pbkdf2-sha256', iter: 600000, data: tag }, rebound: body.rebind === true });
        }
        if (u.endsWith('/api/recover/reset')) {
          const raw = store.get('ghar-register-vault');
          const env = JSON.parse(raw);
          const res = await V.unlockVault(portalPin, '', env);
          const made = await V.createVault(body.newPin, '', res.vault);
          return ok(200, { ok: true, envelope: made.envelope, rkEnvelope: { v: 1, kdf: 'pbkdf2-sha256', iter: 600000, data: 'fake-rk-new' } });
        }
        if (u.endsWith('/api/recover/off')) return ok(200, { ok: true });
        return ok(404, { ok: false, error: 'NOT_FOUND' });
      },
      _fetchCalls: fetchCalls,
      _setMailConfigured: (b) => { mailConfigured = b; },
      _setPortalPin: (p) => { portalPin = p; },
      _setSetupConflict: (b) => { setupConflict = b; },
      FileReader: class {
        readAsText(file) {
          this.result = (file && file._text) || '';
          if (typeof this.onload === 'function') this.onload();
        }
        readAsDataURL(file) {
          this.result = (file && file._dataUrl) || '';
          if (typeof this.onload === 'function') this.onload();
        }
      },
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
  // Setup with mismatched codes is refused (Gmail filled, so the check
  // reaches the code match, not the Gmail check).
  el('setup-gmail').value = 'test@example.com';
  el('setup-pin').value = '123456'; el('setup-pin2').value = '123457'; el('setup-pass').value = '';
  el('setup-btn').click();
  await sleep(50);
  check('Shell: mismatched codes are refused on setup',
    el('setup-error').textContent.includes('do not match') && isVisible('setup-screen'));
  el('setup-pin').value = '123456'; el('setup-pin2').value = '123456';
  el('setup-btn').click();
  check('Shell: Create my book sends a code and shows the OTP step',
    await waitFor(() => isVisible('setup-otp-section') && el('setup-otp-note').textContent.includes('test@example.com')));
  el('setup-otp').value = '123456';
  el('setup-verify-btn').click();
  check('Shell: setup creates the book and lands on an empty Today page',
    await waitFor(() => isVisible('vault-screen') && isVisible('today-empty') && el('today-list').innerHTML === ''
      && el('lock-pill').textContent === 'Unlocked'),
    'vault-screen visible=' + isVisible('vault-screen') + ' today-empty visible=' + isVisible('today-empty'));
  check('Shell: the envelope is stored (new localStorage key, not the old vault key)',
    ctx._store.get('ghar-register-vault') !== undefined && ctx._store.get('ghar-register-vault') !== null
    && ctx._store.get('pcv.vault') === undefined);
  check('Shell: the account is saved after registration (Gmail + recovery on)',
    await (async () => {
      const raw = ctx._store.get('ghar-register-account');
      if (!raw) return false;
      const acct = JSON.parse(raw);
      return acct.gmail === 'test@example.com' && acct.recoveryOn === true
        && acct.rkEnvelope && acct.rkEnvelope.data === 'fake-rk-envelope'
        && typeof acct.verifiedAt === 'number';
    })());
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
  // Profile: phone + email save and survive leaving the page and coming back.
  ctx.location.hash = '#/profile';
  ctx._dispatchWin('hashchange');
  el('profile-household').value = 'Hashir Home';
  el('profile-monthstart').value = '5';
  el('profile-phone').value = '0300 1234567';
  el('profile-email').value = 'hashir@example.com';
  el('profile-save-btn').click();
  check('Shell: profile save stores phone and email',
    await waitFor(() => el('profile-ok').textContent.includes('Saved')));
  ctx.location.hash = '#/home';
  ctx._dispatchWin('hashchange');
  ctx.location.hash = '#/profile';
  ctx._dispatchWin('hashchange');
  check('Shell: phone and email are still there after leaving and returning to Profile',
    el('profile-phone').value === '0300 1234567' && el('profile-email').value === 'hashir@example.com');
  check('Shell: profile rejects a bad phone and saves nothing',
    await (async () => {
      el('profile-phone').value = 'abc';
      el('profile-save-btn').click();
      await sleep(50);
      ctx.location.hash = '#/home';
      ctx._dispatchWin('hashchange');
      ctx.location.hash = '#/profile';
      ctx._dispatchWin('hashchange');
      return el('profile-error').textContent.includes('Phone') && el('profile-phone').value === '0300 1234567';
    })());
  check('Shell: profile rejects a bad email',
    await (async () => {
      el('profile-email').value = 'not-an-email';
      el('profile-save-btn').click();
      await sleep(50);
      return el('profile-error').textContent.includes('Email');
    })());
  el('profile-email').value = 'hashir@example.com';
  el('profile-save-btn').click();
  await waitFor(() => el('profile-ok').textContent.includes('Saved'));
  // Profile picture: pick a small JPEG, save, sidebar shows it; remove it, save, sidebar hides it.
  const shellJpeg = 'data:image/jpeg;base64,' + Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]).toString('base64');
  el('profile-photo').files = [{ _dataUrl: shellJpeg }];
  el('profile-photo').dispatch('change');
  check('Shell: picking a small JPEG photo shows it in the preview',
    await waitFor(() => !isHidden('profile-photo-preview') && isHidden('profile-photo-initials')));
  el('profile-save-btn').click();
  check('Shell: saving the profile puts the photo in the sidebar (no reload)',
    await waitFor(() => el('profile-ok').textContent.includes('Saved') && !isHidden('sidebar-photo') && el('sidebar-photo').src === shellJpeg));
  el('profile-photo-remove-btn').click();
  el('profile-save-btn').click();
  check('Shell: removing the photo and saving hides the sidebar photo again',
    await waitFor(() => el('profile-ok').textContent.includes('Saved') && isHidden('sidebar-photo') && !isHidden('sidebar-initials')));
  // A photo over 500 KB reaches the shrinker; this test shell has no
  // canvas, so it refuses cleanly instead of storing a huge photo.
  const shellBig = 'data:image/jpeg;base64,' + Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF]), Buffer.alloc(600 * 1024, 0)]).toString('base64');
  el('profile-photo').files = [{ _dataUrl: shellBig }];
  el('profile-photo').dispatch('change');
  check('Shell: a photo over 500 KB is refused, never stored half-shrunk',
    await waitFor(() => el('profile-error').textContent.includes('cannot shrink')));
  // Change PIN (old 123456 -> new 654321), using the single shared credentials.
  ctx.location.hash = '#/security';
  ctx._dispatchWin('hashchange');
  el('security-pin').value = '123456'; el('security-pass').value = '';
  el('change-pin-new').value = '654321'; el('change-pin-new2').value = '654321';
  el('change-pin-btn').click();
  check('Shell: change PIN works off the single shared credentials',
    await waitFor(() => el('change-pin-ok').textContent.includes('PIN changed')));
  // Change passphrase off the SAME single credentials (new PIN 654321).
  el('security-pin').value = '654321'; el('security-pass').value = '';
  el('change-pass-new').value = 'house-pass';
  el('change-pass-btn').click();
  check('Shell: change passphrase works off the same single credentials',
    await waitFor(() => el('change-pass-ok').textContent.includes('Passphrase changed')));
  // Remove the passphrase again (credentials: new PIN + the passphrase just set).
  el('security-pin').value = '654321'; el('security-pass').value = 'house-pass';
  el('change-pass-new').value = '';
  el('change-pass-btn').click();
  check('Shell: removing the passphrase works off the same single credentials',
    await waitFor(() => el('change-pass-ok').textContent.includes('Passphrase removed')));
  // Wrong credentials fail once, in one place, and change nothing.
  el('security-pin').value = '999999'; el('security-pass').value = '';
  el('change-pin-new').value = '111111'; el('change-pin-new2').value = '111111';
  el('change-pin-btn').click();
  check('Shell: wrong current PIN fails once with one error and changes nothing',
    await waitFor(() => el('security-error').textContent.includes('Current PIN (or passphrase) is wrong'))
    && el('change-pin-ok').textContent === '');
  // Lock, then unlock with the NEW pin.
  el('lock-btn').click();
  check('Shell: lock shows the unlock screen and hides the book',
    isVisible('unlock-screen') && isHidden('vault-screen'));
  el('unlock-pin').value = '654321';
  el('unlock-btn').click();
  check('Shell: unlock with the new code reopens the book',
    await waitFor(() => isVisible('vault-screen')));
  // Wrong codes: 4 tries warn, the 5th locks for 30s.
  el('lock-btn').click();
  for (let i = 0; i < 4; i++) {
    el('unlock-pin').value = '999999';
    el('unlock-btn').click();
    await waitFor(() => el('unlock-error').textContent.includes('Wrong code'));
    el('unlock-error').textContent = '';
  }
  check('Shell: 4 wrong codes warn but do not lock yet', isHidden('lockout-note'));
  el('unlock-pin').value = '999999';
  el('unlock-btn').click();
  check('Shell: the 5th wrong code locks the book (30s note shows)',
    await waitFor(() => !isHidden('lockout-note') && el('lockout-note').textContent.includes('30 seconds')));
  el('unlock-pin').value = '654321';
  el('unlock-btn').click();
  await sleep(100);
  check('Shell: the right code is refused while the lockout runs',
    isVisible('unlock-screen') && isHidden('vault-screen'));
  ctx._advanceMs(31000);
  el('unlock-pin').value = '654321';
  el('unlock-btn').click();
  check('Shell: after the 30s wait the right code opens the book again',
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
  el('staff-month').value = '2026-05';
  el('staff-month').dispatch('change');
  el('staff-name').value = 'Ayesha';
  el('staff-role').value = 'maid';
  el('staff-salary').value = '15000';
  el('staff-joined').value = '2026-05-01';
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
  tapAtt('2026-05-01'); tapAtt('2026-05-02'); tapAtt('2026-05-03');
  await sleep(50);
  check('Phase 2 UI: tapping attendance days marks them absent (working updates)',
    staffHtml().includes('1 · A') && staffHtml().includes('2 · A') && staffHtml().includes('3 · A')
    && staffHtml().includes('Absent: 3'));
  tapAtt('2026-05-03');
  check('Phase 2 UI: tapping an absent day again cycles it to half day',
    await waitFor(() => staffHtml().includes('3 · H') && staffHtml().includes('Half: 1')));
  tapAtt('2026-05-03');
  await sleep(50);
  check('Phase 2 UI: tapping a half day again cycles it back to present',
    staffHtml().includes('3 · P') && staffHtml().includes('Half: 0'));
  tapAtt('2026-05-03');
  await sleep(50);
  check('Phase 2 UI: tapping a present day again cycles it back to absent',
    staffHtml().includes('3 · A') && staffHtml().includes('Absent: 3'));
  // Advance: Rs 2,000 full recovery through the advance form.
  el('adv-helper').value = helperId;
  el('adv-amount').value = '2000';
  el('adv-date').value = '2026-05-05';
  el('adv-note').value = 'for medicine';
  el('adv-recovery').value = 'full';
  el('adv-add-btn').click();
  check('Phase 2 UI: recording an advance shows its remaining amount',
    await waitFor(() => el('adv-ok').textContent.includes('Advance recorded')
      && staffHtml().includes('Remaining advance: Rs 2,000')),
    staffHtml().slice(0, 300));
  check('Phase 2 UI: the pay panel shows the acceptance working (net Rs 12,500, paid leave)',
    staffHtml().includes('Net payable') && staffHtml().includes('Rs 12,500')
    && staffHtml().includes('Absent: 1 × Rs 500') && staffHtml().includes('Paid leave used: 2 days'));
  // Copy statement: the statement box shows the full working.
  el('staff-list').dispatch('click',
    { target: { dataset: { action: 'copy', helper: helperId }, parentElement: null } });
  await sleep(50);
  check('Phase 2 UI: Copy statement shows the WhatsApp text with the working lines',
    el('staff-statement').textContent.includes('Net payable: Rs 15,000 - Rs 500 - Rs 0 - Rs 2,000 = Rs 12,500')
    && el('staff-statement').textContent.includes('Absent days: 1 x Rs 500 = Rs 500'));
  // Mark paid -> locked: the panel shows the stored working, taps refuse.
  el('staff-list').dispatch('click',
    { target: { dataset: { action: 'pay', helper: helperId }, parentElement: null } });
  check('Phase 2 UI: Mark paid locks the month and shows the stored working',
    await waitFor(() => staffHtml().includes('Paid on') && staffHtml().includes('locked and cannot be edited')
      && staffHtml().includes('Rs 12,500')));
  tapAtt('2026-05-10');
  await sleep(50);
  check('Phase 2 UI: tapping attendance on a locked month is refused with an error',
    el('staff-add-error').textContent.includes('already marked paid'));
  // Deliveries: add the doodhwala through the form, log days, mark paid.
  ctx.location.hash = '#/deliveries';
  ctx._dispatchWin('hashchange');
  el('del-month').value = '2026-05';
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
  await logDay('2026-05-01', 0);
  await logDay('2026-05-02', 0);
  await logDay('2026-05-03', 1);
  check('Phase 2 UI: logging a skipped day says so, and the bill shows the working',
    el('log-ok').textContent.includes('Logged 1 on 2026-05-03')
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
  await logDay('2026-05-04', 1);
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
  // net Rs 12,500 (the acceptance example with paid leave); staff A was
  // also paid Oct (Rs 15,000, no deductions). Staff B Rs 20,000 unpaid;
  // staff C Rs 10,000 with a Rs 3,000 instalment advance (Rs 1,000/month).
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
    check('Phase 5: summary staff paid = Rs 12,500 (1 helper), unpaid working Rs 29,000 (2 helpers)',
      s.staff.paidPkr === 12500 && s.staff.paidCount === 1
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
    check('Phase 5: compare staff paid delta Rs -2,500 vs Oct (Rs 15,000)',
      s.compare.staffPaidDeltaPkr === -2500 && s.compare.staffPaidPrevPkr === 15000, s.compare);
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
      && Number(staffParsed.rows[3]['Net payable (Rs)']) === 41500, staffParsed.rows);
    check('Phase 5: staff CSV TOTAL (Rs 41,500) = summary paid + unpaid working (12,500 + 29,000)',
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
      !staffCsv.includes('Rs ') && !staffCsv.includes('15,000') && !staffCsv.includes('12,500')
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
  // The shell vault already holds Ayesha (paid May, net Rs 12,500), the
  // doodhwala (May total Rs 220, paid) and a gas delivery with a refill.
  // (May, not November: the fake clock is 2026-05-28, and the D4 rule
  // refuses attendance in the future, so the Phase 2 UI flow logs May.)
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
  el('summary-month').value = '2026-05';
  el('summary-month').dispatch('change');
  check('Phase 5 UI: the Summary page shows the paid staff total (Rs 12,500) + deliveries (Rs 220) + last-month comparison',
    el('summary-list').innerHTML.includes('Rs 12,500')
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
    for (const p of ['/', '/index.html', '/styles.css', '/vault.js', '/model.js', '/nav.js', '/app.js', '/csv.js', '/bg.jpg', '/favicon.ico']) {
      check('Smoke: GET ' + p + ' -> 200', (await req('GET', p)).status === 200);
    }
    // Removed modules: no longer in the server allowlist (Phase 5
    // cleanup), so they 404 like any unknown path.
    for (const p of ['/sms.js', '/intel.js', '/totp.js', '/cards.js', '/proof.js', '/ocr.js']) {
      check('Smoke: GET ' + p + ' -> 404 (module removed)', (await req('GET', p)).status === 404);
    }
    // D9/D11 cleanup: the dead proof/OCR files and the vendored
    // Tesseract engine are deleted, so none of them is served.
    for (const p of ['/vendor/tesseract/tesseract.min.js', '/vendor/tesseract/worker.min.js',
      '/vendor/tesseract/tesseract-core.wasm.js', '/vendor/tesseract/tesseract-core.wasm',
      '/vendor/tesseract/eng.traineddata', '/vendor/tesseract/other.js']) {
      check('Smoke: GET ' + p + ' -> 404 (deleted in D9/D11 cleanup)', (await req('GET', p)).status === 404);
    }
    const home = await req('GET', '/');
    check('Smoke: homepage names Ghar ka Register + spare-key trade-off',
      home.raw.includes('Ghar ka Register') && home.raw.includes('If someone can open the files on your PC, they can find the spare key'));
    check('Smoke: homepage shows the empty-Today state',
      home.raw.includes('Nothing due — add your first helper, bill or document.'));
    check('Smoke: homepage loads the five scripts and no removed ones',
      home.raw.includes('/vault.js') && home.raw.includes('/model.js')
      && home.raw.includes('/csv.js')
      && home.raw.includes('/nav.js') && home.raw.includes('/app.js')
      && !home.raw.includes('/sms.js') && !home.raw.includes('/intel.js')
      && !home.raw.includes('/totp.js') && !home.raw.includes('/cards.js')
      && !home.raw.includes('/proof.js') && !home.raw.includes('/ocr.js')
      && !home.raw.includes('/vendor/'));
    check('Smoke: homepage has all 11 page sections',
      EXPECTED_PAGES.every((p) => home.raw.includes('id="page-' + p + '"')));
    check('Smoke: unknown page -> 404', (await req('GET', '/nope.html')).status === 404);
    check('Smoke: server log names Ghar ka Register',
      serverOut.includes('Ghar ka Register listening on 127.0.0.1:' + TEST_PORT), serverOut.trim());
  } finally {
    server.kill();
  }

  // ---- §10. P12 Phase 1 — mail + OTP + recovery endpoints (server only) ----
  // Fixtures use obviously fake addresses (test@example.com etc.) and
  // never a real Gmail. No test ever sends real mail.
  const Otp = require('./server/otp.js');
  const Mail = require('./server/mail.js');
  const netMod = require('node:net');
  const spawn2 = require('node:child_process').spawn;
  const outboxFile = '/tmp/p12-test-outbox-' + process.pid + '.jsonl';
  try { fs.unlinkSync(outboxFile); } catch (_e) { /* fresh */ }
  const PORTAL_PORT = 3039;
  const PORTAL_BASE = 'http://127.0.0.1:' + PORTAL_PORT;
  const UNCONF_PORT = 3041;
  const UNCONF_BASE = 'http://127.0.0.1:' + UNCONF_PORT;
  function postJson(base, p, body, extraHeaders) {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? '' : JSON.stringify(body);
      const r = require('node:http').request(base + p, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }, extraHeaders || {}),
      }, (res) => {
        let raw = '';
        res.on('data', (c) => { raw += c; });
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(raw); } catch (_e) { /* not JSON */ }
          resolve({ status: res.statusCode, raw, json });
        });
      });
      r.on('error', reject);
      r.end(data);
    });
  }
  function getRaw(base, p) {
    return new Promise((resolve, reject) => {
      const r = require('node:http').request(base + p, { method: 'GET' }, (res) => {
        let raw = '';
        res.on('data', (c) => { raw += c; });
        res.on('end', () => resolve({ status: res.statusCode, raw }));
      });
      r.on('error', reject);
      r.end();
    });
  }
  function outboxMails() {
    try {
      return fs.readFileSync(outboxFile, 'utf8').trim().split('\n')
        .filter(Boolean).map((l) => JSON.parse(l));
    } catch (_e) { return []; }
  }
  function outboxCodeFor(gmail) {
    const mails = outboxMails().filter((m) => m.to === gmail);
    if (!mails.length) return null;
    const m = /(\d{6})/.exec(mails[mails.length - 1].text || '');
    return m ? m[1] : null;
  }
  // Fake SMTP server (plain, no TLS): records the transcript and answers
  // the protocol. `advertiseStartTls` / `authFail` switch its behaviour.
  function startFakeSmtp(opts) {
    const o = opts || {};
    const transcript = [];
    const server = netMod.createServer((sock) => {
      sock.write('220 fake.test ESMTP\r\n');
      let buf = '';
      let inData = false;
      sock.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        let idx;
        while ((idx = buf.indexOf('\r\n')) >= 0) {
          const line = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          transcript.push(line);
          if (inData) {
            if (line === '.') { inData = false; sock.write('250 OK queued\r\n'); }
            continue;
          }
          const up = line.toUpperCase();
          if (up.startsWith('EHLO')) {
            sock.write(o.advertiseStartTls ? '250-localhost\r\n250 STARTTLS\r\n' : '250 Hello\r\n');
          } else if (up === 'STARTTLS') {
            sock.write('220 Go ahead\r\n');
          } else if (up === 'AUTH LOGIN') {
            sock.write('334 VXNlcm5hbWU6\r\n');
          } else if (line === Buffer.from('test@example.com').toString('base64')) {
            sock.write('334 UGFzc3dvcmQ6\r\n');
          } else if (line === Buffer.from('fake-pass').toString('base64')) {
            sock.write(o.authFail ? '535 Bad credentials\r\n' : '235 OK\r\n');
          } else if (up.startsWith('MAIL FROM')) sock.write('250 OK\r\n');
          else if (up.startsWith('RCPT TO')) sock.write('250 OK\r\n');
          else if (up === 'DATA') { inData = true; sock.write('354 End data\r\n'); }
          else if (up === 'QUIT') sock.write('221 Bye\r\n');
          else sock.write('250 OK\r\n');
        }
      });
    });
    return new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, transcript }));
    });
  }
  function startBadGreetingSmtp() {
    const server = netMod.createServer((sock) => {
      sock.write('500 Nope\r\n');
      sock.end();
    });
    return new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
    });
  }

  // ---- §10a. OTP store (pure functions) ----
  {
    const t0 = 1779969600000; // same midday-UTC instant as the fake clock above
    const store = Otp.createOtpStore();
    check('P12 OTP: normalizeGmail trims + lower-cases',
      Otp.normalizeGmail('  Test@Example.COM ') === 'test@example.com');
    const issued = Otp.issueOtp(store, 'register', 'test@example.com', t0);
    check('P12 OTP: issue returns a 6-digit code', issued.ok === true && /^\d{6}$/.test(issued.code));
    // No plaintext code anywhere in the store (scan every string field).
    const seen = [];
    (function scan(v) {
      if (typeof v === 'string') seen.push(v);
      else if (v && typeof v === 'object') {
        if (v instanceof Map) { v.forEach((x) => scan(x)); }
        else Object.values(v).forEach(scan);
      }
    })(store);
    check('P12 OTP: the plaintext code is stored nowhere (hash only)',
      seen.indexOf(issued.code) < 0);
    const bad = Otp.verifyOtp(store, 'register', 'test@example.com', '12345', t0 + 1000);
    check('P12 OTP: malformed code is refused without burning a try',
      bad.ok === false && bad.error === 'BAD_CODE'
      && Otp.verifyOtp(store, 'register', 'test@example.com', issued.code, t0 + 2000).ok === true);
    const store2 = Otp.createOtpStore();
    const i2 = Otp.issueOtp(store2, 'register', 'test@example.com', t0);
    const vWrong = Otp.verifyOtp(store2, 'register', 'test@example.com', i2.code === '123456' ? '123457' : '123456', t0 + 1000);
    check('P12 OTP: one wrong try leaves 4 tries',
      vWrong.ok === false && vWrong.error === 'WRONG' && vWrong.triesLeft === 4);
    const vOk = Otp.verifyOtp(store2, 'register', 'test@example.com', i2.code, t0 + 2000);
    check('P12 OTP: the right code verifies and returns a token',
      vOk.ok === true && typeof vOk.token === 'string' && /^[0-9a-f]{64}$/.test(vOk.token));
    check('P12 OTP: a consumed OTP cannot verify again',
      Otp.verifyOtp(store2, 'register', 'test@example.com', i2.code, t0 + 3000).error === 'NONE');
    check('P12 OTP: token consumes once and returns the Gmail',
      Otp.consumeToken(store2, vOk.token, 'register', t0 + 4000).gmail === 'test@example.com'
      && Otp.consumeToken(store2, vOk.token, 'register', t0 + 5000).error === 'BAD_TOKEN');
    const store3 = Otp.createOtpStore();
    const i3 = Otp.issueOtp(store3, 'reset', 'test@example.com', t0);
    check('P12 OTP: token is purpose-bound (reset token refuses register)',
      await (async () => {
        const v3 = Otp.verifyOtp(store3, 'reset', 'test@example.com', i3.code, t0 + 1000);
        return v3.ok === true
          && Otp.consumeToken(store3, v3.token, 'register', t0 + 2000).error === 'WRONG_PURPOSE';
      })());
    const store4 = Otp.createOtpStore();
    const i4 = Otp.issueOtp(store4, 'register', 'test@example.com', t0);
    check('P12 OTP: expired OTP is refused',
      Otp.verifyOtp(store4, 'register', 'test@example.com', i4.code, t0 + 11 * 60 * 1000).error === 'EXPIRED');
    const store5 = Otp.createOtpStore();
    const i5 = Otp.issueOtp(store5, 'register', 'test@example.com', t0);
    const wrong = i5.code === '123456' ? '123457' : '123456';
    for (let k = 0; k < 4; k++) Otp.verifyOtp(store5, 'register', 'test@example.com', wrong, t0 + 1000 + k);
    check('P12 OTP: 5th wrong try kills the OTP',
      Otp.verifyOtp(store5, 'register', 'test@example.com', wrong, t0 + 2000).error === 'DEAD');
    check('P12 OTP: after death, new requests are in cooldown',
      Otp.issueOtp(store5, 'register', 'test@example.com', t0 + 3000).error === 'COOLDOWN');
    check('P12 OTP: after the cooldown, a new OTP can be requested',
      Otp.issueOtp(store5, 'register', 'test@example.com', t0 + 16 * 60 * 1000).ok === true);
    const store6 = Otp.createOtpStore();
    const g6 = 'limit@example.com';
    Otp.issueOtp(store6, 'register', g6, t0);
    Otp.noteOtpSent(store6, g6, t0);
    check('P12 OTP: a second request within 60s is refused',
      Otp.issueOtp(store6, 'register', g6, t0 + 30000).error === 'TRY_LATER');
    Otp.issueOtp(store6, 'register', g6, t0 + 61000);
    Otp.noteOtpSent(store6, g6, t0 + 61000);
    Otp.issueOtp(store6, 'register', g6, t0 + 122000);
    Otp.noteOtpSent(store6, g6, t0 + 122000);
    check('P12 OTP: a 4th OTP in one hour is refused',
      Otp.issueOtp(store6, 'register', g6, t0 + 183000).error === 'TRY_LATER');
    const store7 = Otp.createOtpStore();
    const i7 = Otp.issueOtp(store7, 'register', 'test@example.com', t0);
    Otp.revokeOtp(store7, 'register', 'test@example.com');
    check('P12 OTP: revoking after a mail failure leaves no OTP',
      Otp.verifyOtp(store7, 'register', 'test@example.com', i7.code, t0 + 1000).error === 'NONE');
    const store8 = Otp.createOtpStore();
    const i8 = Otp.issueOtp(store8, 'register', 'test@example.com', t0);
    const v8 = Otp.verifyOtp(store8, 'register', 'test@example.com', i8.code, t0 + 1000);
    check('P12 OTP: token expires after 5 minutes',
      Otp.consumeToken(store8, v8.token, 'register', t0 + 6 * 60 * 1000).error === 'EXPIRED');
  }

  // ---- §10b. SMTP client against a local fake server ----
  {
    const fake = await startFakeSmtp({ advertiseStartTls: false });
    try {
      const sent = await Mail.smtpSend({
        host: '127.0.0.1', port: fake.port, user: 'test@example.com', pass: 'fake-pass',
        to: 'test@example.com', subject: 'Hi', text: 'Hello there', requireStartTls: false,
      });
      check('P12 SMTP: full conversation succeeds against the fake server', sent.ok === true);
      check('P12 SMTP: transcript has AUTH + MAIL FROM + RCPT TO + DATA + subject',
        fake.transcript.some((l) => l === 'AUTH LOGIN')
        && fake.transcript.some((l) => l.startsWith('MAIL FROM:<test@example.com>'))
        && fake.transcript.some((l) => l.startsWith('RCPT TO:<test@example.com>'))
        && fake.transcript.some((l) => l === 'Subject: Hi'));
    } finally { fake.server.close(); }
    const fakeTls = await startFakeSmtp({ advertiseStartTls: false });
    try {
      check('P12 SMTP: a server without STARTTLS is refused when it is required',
        await (async () => {
          try {
            await Mail.smtpSend({
              host: '127.0.0.1', port: fakeTls.port, user: 'test@example.com', pass: 'fake-pass',
              to: 'test@example.com', subject: 'Hi', text: 'Hello', requireStartTls: true,
            });
            return false;
          } catch (e) { return e && e.code === 'NO_STARTTLS'; }
        })());
    } finally { fakeTls.server.close(); }
    const fakeAuth = await startFakeSmtp({ advertiseStartTls: false, authFail: true });
    try {
      check('P12 SMTP: a refused app password fails with AUTH_FAILED',
        await (async () => {
          try {
            await Mail.smtpSend({
              host: '127.0.0.1', port: fakeAuth.port, user: 'test@example.com', pass: 'fake-pass',
              to: 'test@example.com', subject: 'Hi', text: 'Hello', requireStartTls: false,
            });
            return false;
          } catch (e) { return e && e.code === 'AUTH_FAILED'; }
        })());
    } finally { fakeAuth.server.close(); }
    const badGreet = await startBadGreetingSmtp();
    try {
      check('P12 SMTP: a bad greeting fails closed',
        await (async () => {
          try {
            await Mail.smtpSend({
              host: '127.0.0.1', port: badGreet.port, user: 'test@example.com', pass: 'fake-pass',
              to: 'test@example.com', subject: 'Hi', text: 'Hello', requireStartTls: false,
            });
            return false;
          } catch (e) { return !!e && e.code === 'SMTP_PROTOCOL'; }
        })());
    } finally { badGreet.server.close(); }
    check('P12 SMTP: missing credentials fail closed (MAIL_NOT_CONFIGURED)',
      await (async () => {
        const u = process.env.GMAIL_USER;
        const p = process.env.GMAIL_APP_PASSWORD;
        delete process.env.GMAIL_USER;
        delete process.env.GMAIL_APP_PASSWORD;
        try {
          await Mail.smtpSend({ to: 'test@example.com', subject: 'Hi', text: 'Hello' });
          return false;
        } catch (e) { return e && e.code === 'MAIL_NOT_CONFIGURED'; }
        finally {
          if (u !== undefined) process.env.GMAIL_USER = u;
          if (p !== undefined) process.env.GMAIL_APP_PASSWORD = p;
        }
      })());
    const seen = [];
    const rec = { send: async (m) => { seen.push(m); return { ok: true }; } };
    await Mail.sendMail('test@example.com', 'Subj', 'Body', rec);
    check('P12 SMTP: injected transport replaces SMTP (no socket)',
      seen.length === 1 && seen[0].to === 'test@example.com' && seen[0].subject === 'Subj');
    check('P12 mail: isMailConfigured is false without env vars',
      await (async () => {
        const u = process.env.GMAIL_USER;
        const p = process.env.GMAIL_APP_PASSWORD;
        delete process.env.GMAIL_USER;
        delete process.env.GMAIL_APP_PASSWORD;
        const r = Mail.isMailConfigured() === false;
        if (u !== undefined) process.env.GMAIL_USER = u;
        if (p !== undefined) process.env.GMAIL_APP_PASSWORD = p;
        return r;
      })());
  }

  // ---- §10c. Spare-envelope helpers (vault.js) ----
  {
    const k1 = V.randomSpareKey();
    const k2 = V.randomSpareKey();
    check('P12 spare: a spare key is 32 random bytes',
      k1 instanceof Uint8Array && k1.length === 32
      && Buffer.from(k1).toString('hex') !== Buffer.from(k2).toString('hex'));
    const sk = await V.importSpareKey(k1);
    const rkEnv = await V.createSpareEnvelope(sk, SAMPLE);
    check('P12 spare: spare envelope round-trips the vault object',
      JSON.stringify(await V.openSpareEnvelope(sk, rkEnv)) === JSON.stringify(SAMPLE));
    const sk2 = await V.importSpareKey(k2);
    check('P12 spare: a different spare key cannot open the envelope',
      await throwsCodeAsync(() => V.openSpareEnvelope(sk2, rkEnv), 'DECRYPT_FAILED'));
    check('P12 spare: importing a short key is refused',
      await throwsCodeAsync(() => V.importSpareKey(new Uint8Array(16)), 'BAD_SPARE_KEY'));
    check('P12 spare: importing a non-bytes key is refused',
      await throwsCodeAsync(() => V.importSpareKey('not-bytes'), 'BAD_SPARE_KEY'));
  }

  // ---- §10d. Server endpoints (spawned servers) ----
  const portalServer = spawn2('node', ['server.js'], {
    cwd: __dirname,
    env: {
      ...process.env, PORT: String(PORTAL_PORT),
      GMAIL_USER: 'test@example.com', GMAIL_APP_PASSWORD: 'fake-pass',
      GMAIL_FAKE_OUTBOX: outboxFile,
    },
  });
  let portalOut = '';
  portalServer.stdout.on('data', (d) => { portalOut += d; });
  portalServer.stderr.on('data', (d) => { portalOut += d; });
  const unconfServer = spawn2('node', ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(UNCONF_PORT), GMAIL_USER: '', GMAIL_APP_PASSWORD: '' },
  });
  let unconfOut = '';
  unconfServer.stdout.on('data', (d) => { unconfOut += d; });
  unconfServer.stderr.on('data', (d) => { unconfOut += d; });
  try {
    let up1 = false;
    for (let i = 0; i < 20 && !up1; i++) {
      try { await getRaw(PORTAL_BASE, '/health'); up1 = true; } catch (_e) { await sleep(200); }
    }
    let up2 = false;
    for (let i = 0; i < 20 && !up2; i++) {
      try { await getRaw(UNCONF_BASE, '/health'); up2 = true; } catch (_e) { await sleep(200); }
    }
    check('P12 server: portal server comes up', up1);
    check('P12 server: unconfigured server comes up', up2);
    check('P12 server: /api/mail/status says configured with env vars',
      (await postJson(PORTAL_BASE, '/api/mail/status', {})).json.configured === true);
    check('P12 server: /api/mail/status says not configured without env vars',
      (await postJson(UNCONF_BASE, '/api/mail/status', {})).json.configured === false);
    check('P12 server: OTP request without mail configured is 503',
      (await postJson(UNCONF_BASE, '/api/otp/request', { purpose: 'register', gmail: 'test@example.com' })).status === 503);
    check('P12 server: book routes still work without mail configured',
      (await getRaw(UNCONF_BASE, '/health')).status === 200
      && (await getRaw(UNCONF_BASE, '/')).status === 200);
    check('P12 server: foreign Origin is refused on the API',
      (await postJson(PORTAL_BASE, '/api/mail/status', {}, { Origin: 'https://evil.example' })).status === 403);
    check('P12 server: bad purpose is refused (400)',
      (await postJson(PORTAL_BASE, '/api/otp/request', { purpose: 'nope', gmail: 'test@example.com' })).status === 400);
    check('P12 server: bad Gmail is refused (400)',
      (await postJson(PORTAL_BASE, '/api/otp/request', { purpose: 'register', gmail: 'not-an-email' })).status === 400);
    check('P12 server: bad JSON body is refused (400)',
      await (async () => {
        const r = await new Promise((resolve, reject) => {
          const req2 = require('node:http').request(PORTAL_BASE + '/api/otp/request', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
          }, (res) => {
            let raw = '';
            res.on('data', (c) => { raw += c; });
            res.on('end', () => resolve({ status: res.statusCode }));
          });
          req2.on('error', reject);
          req2.end('{not json');
        });
        return r.status === 400;
      })());
    // OTP request + verify through HTTP, mail captured in the outbox file.
    const gA = 'otp-a@example.com';
    const rqA = await postJson(PORTAL_BASE, '/api/otp/request', { purpose: 'register', gmail: gA });
    check('P12 server: OTP request answers ok and a mail is captured',
      rqA.json && rqA.json.ok === true && outboxCodeFor(gA) !== null);
    const codeA = outboxCodeFor(gA);
    check('P12 server: the captured mail goes to the right Gmail, no code in the subject',
      outboxMails().some((m) => m.to === gA && !/^\d{6}$/.test(m.subject) && !m.subject.includes(codeA)));
    const vWrong = await postJson(PORTAL_BASE, '/api/otp/verify', { purpose: 'register', gmail: gA, code: codeA === '123456' ? '123457' : '123456' });
    check('P12 server: a wrong OTP is refused with tries left',
      vWrong.json && vWrong.json.ok === false && vWrong.json.error === 'WRONG' && vWrong.json.triesLeft === 4);
    const vOk = await postJson(PORTAL_BASE, '/api/otp/verify', { purpose: 'register', gmail: gA, code: codeA });
    check('P12 server: the right OTP verifies and returns a token',
      vOk.json && vOk.json.ok === true && typeof vOk.json.token === 'string');
    check('P12 server: the same OTP cannot verify twice',
      (await postJson(PORTAL_BASE, '/api/otp/verify', { purpose: 'register', gmail: gA, code: codeA })).json.error === 'NONE');
    // Recovery setup + reset end to end through HTTP.
    const made = await V.createVault('123456', '', SAMPLE);
    const setup = await postJson(PORTAL_BASE, '/api/recover/setup', {
      gmail: 'otp-setup@example.com', envelope: made.envelope, pin: '123456', passphrase: '',
    });
    check('P12 server: recovery setup returns a spare envelope',
      setup.json && setup.json.ok === true && setup.json.rkEnvelope && typeof setup.json.rkEnvelope.data === 'string');
    const keyFile = path.join(__dirname, 'data', 'recovery.key');
    const acctFile = path.join(__dirname, 'data', 'account.json');
    check('P12 server: setup writes a 32-byte spare key file',
      fs.existsSync(keyFile) && fs.readFileSync(keyFile).length === 32);
    check('P12 server: setup writes the account binding',
      JSON.parse(fs.readFileSync(acctFile, 'utf8')).gmail === 'otp-setup@example.com');
    const oldKeyBytes = fs.readFileSync(keyFile);
    check('P12 server: a second setup without a spare-envelope proof is refused (409 ALREADY_SET_OTHER_BOOK)',
      await (async () => {
        const r = await postJson(PORTAL_BASE, '/api/recover/setup', {
          gmail: 'otp-setup@example.com', envelope: made.envelope, pin: '123456', passphrase: '',
        });
        return r.status === 409 && r.json && r.json.error === 'ALREADY_SET_OTHER_BOOK';
      })());
    check('P12 server: setup with a wrong PIN is refused',
      await (async () => {
        // Temporarily remove the key file so the ALREADY_SET guard does
        // not mask the credentials check, then put it back.
        fs.unlinkSync(keyFile);
        const r = await postJson(PORTAL_BASE, '/api/recover/setup', {
          gmail: 'otp-setup@example.com', envelope: made.envelope, pin: '123457', passphrase: '',
        });
        fs.writeFileSync(keyFile, oldKeyBytes, { mode: 0o600 });
        return r.status === 400 && r.json.error === 'BAD_CREDENTIALS';
      })());
    // D5: recovery off needs the current code, verified against the
    // book's envelope. No credentials, a wrong code, or another book's
    // envelope all refuse — and the key file stays in every case.
    check('P12 server: recovery off without credentials is refused and the key file stays',
      await (async () => {
        const r = await postJson(PORTAL_BASE, '/api/recover/off', {});
        return r.status === 400 && r.json.error === 'BAD_CREDENTIALS' && fs.existsSync(keyFile);
      })());
    check('P12 server: recovery off with a wrong PIN is refused and the key file stays',
      await (async () => {
        const r = await postJson(PORTAL_BASE, '/api/recover/off', {
          pin: '123457', passphrase: '', envelope: made.envelope,
        });
        return r.status === 400 && r.json.error === 'BAD_CREDENTIALS' && fs.existsSync(keyFile);
      })());
    check('P12 server: recovery off with another book\u2019s envelope is refused and the key file stays',
      await (async () => {
        const other = await V.createVault('654321', '', SAMPLE);
        const r = await postJson(PORTAL_BASE, '/api/recover/off', {
          pin: '123456', passphrase: '', envelope: other.envelope,
        });
        return r.status === 400 && r.json.error === 'BAD_CREDENTIALS' && fs.existsSync(keyFile);
      })());
    // Reset: OTP to the BOUND Gmail — a freely typed address is ignored.
    const rqR = await postJson(PORTAL_BASE, '/api/otp/request', { purpose: 'reset', gmail: 'attacker@example.com' });
    check('P12 server: reset OTP request answers ok (body Gmail ignored)',
      rqR.json && rqR.json.ok === true);
    check('P12 server: the reset mail went to the BOUND Gmail only',
      outboxCodeFor('otp-setup@example.com') !== null
      && outboxMails().filter((m) => m.to === 'attacker@example.com').length === 0);
    const codeR = outboxCodeFor('otp-setup@example.com');
    const vR = await postJson(PORTAL_BASE, '/api/otp/verify', { purpose: 'reset', code: codeR });
    check('P12 server: reset OTP verifies to a token',
      vR.json && vR.json.ok === true && typeof vR.json.token === 'string');
    check('P12 server: reset with a bad new code is refused and the token stays valid',
      await (async () => {
        // validPin is checked BEFORE the token is consumed, so a bad
        // code leaves the token usable for the real reset below.
        const r = await postJson(PORTAL_BASE, '/api/recover/reset', {
          token: vR.json.token, newPin: '12345', rkEnvelope: setup.json.rkEnvelope,
        });
        return r.status === 400 && r.json.error === 'BAD_PIN';
      })());
    // Reset fails closed when the spare key file is gone — and the token
    // survives the failure (the key-file check runs before consuming it).
    check('P12 server: reset fails closed without the spare key file',
      await (async () => {
        const off = await postJson(PORTAL_BASE, '/api/recover/off', {
          pin: '123456', passphrase: '', envelope: made.envelope,
        });
        if (!off.json || !off.json.ok) return false;
        const r = await postJson(PORTAL_BASE, '/api/recover/reset', {
          token: vR.json.token, newPin: '654321', rkEnvelope: setup.json.rkEnvelope,
        });
        return r.json && r.json.error === 'RECOVERY_OFF';
      })());
    // Set recovery up again (same book, same code) and reset with the
    // SAME token — it was not consumed by the failed reset.
    const setup2 = await postJson(PORTAL_BASE, '/api/recover/setup', {
      gmail: 'otp-setup@example.com', envelope: made.envelope, pin: '123456', passphrase: '',
    });
    check('P12 server: recovery can be set up again after being turned off',
      setup2.json && setup2.json.ok === true && setup2.json.rkEnvelope);
    const reset = await postJson(PORTAL_BASE, '/api/recover/reset', {
      token: vR.json.token, newPin: '654321', rkEnvelope: setup2.json.rkEnvelope,
    });
    check('P12 server: reset returns a new envelope + fresh spare envelope',
      reset.json && reset.json.ok === true && reset.json.envelope && reset.json.rkEnvelope
      && reset.json.envelope.data !== made.envelope.data
      && reset.json.rkEnvelope.data !== setup2.json.rkEnvelope.data);
    check('P12 server: the new envelope opens with the new code, empty passphrase',
      await (async () => {
        const u = await V.unlockVault('654321', '', reset.json.envelope);
        return JSON.stringify(u.vault) === JSON.stringify(SAMPLE);
      })());
    check('P12 server: the old code no longer opens the new envelope',
      await throwsCodeAsync(() => V.unlockVault('123456', '', reset.json.envelope), 'DECRYPT_FAILED'));
    const newKeyBytes = fs.readFileSync(keyFile);
    check('P12 server: the spare key rotated on reset',
      Buffer.from(newKeyBytes).toString('hex') !== Buffer.from(oldKeyBytes).toString('hex'));
    check('P12 server: the OLD spare envelope does not open the new vault',
      await (async () => {
        const oldSk = await V.importSpareKey(oldKeyBytes);
        try { await V.openSpareEnvelope(oldSk, reset.json.rkEnvelope); return false; }
        catch (e) { return e && e.code === 'DECRYPT_FAILED'; }
      })());
    check('P12 server: the NEW spare envelope opens the vault with the new key',
      await (async () => {
        const newSk = await V.importSpareKey(newKeyBytes);
        const v = await V.openSpareEnvelope(newSk, reset.json.rkEnvelope);
        return JSON.stringify(v) === JSON.stringify(SAMPLE);
      })());
    check('P12 server: the same reset token cannot be used twice',
      (await postJson(PORTAL_BASE, '/api/recover/reset', {
        token: vR.json.token, newPin: '111222', rkEnvelope: reset.json.rkEnvelope,
      })).json.error === 'BAD_TOKEN');
    check('P12 server: a raw OTP is never accepted as a reset token',
      (await postJson(PORTAL_BASE, '/api/recover/reset', {
        token: codeR, newPin: '111222', rkEnvelope: reset.json.rkEnvelope,
      })).json.error === 'BAD_TOKEN');
    check('P12 server: a token for the WRONG purpose cannot reset',
      await (async () => {
        const rq3 = await postJson(PORTAL_BASE, '/api/otp/request', { purpose: 'register', gmail: 'otp-z@example.com' });
        if (!rq3.json || !rq3.json.ok) return false;
        const c3 = outboxCodeFor('otp-z@example.com');
        const v3 = await postJson(PORTAL_BASE, '/api/otp/verify', { purpose: 'register', gmail: 'otp-z@example.com', code: c3 });
        const r = await postJson(PORTAL_BASE, '/api/recover/reset', {
          token: v3.json.token, newPin: '654321', rkEnvelope: reset.json.rkEnvelope,
        });
        return r.json && r.json.error === 'WRONG_PURPOSE';
      })());
    // Gmail change (Phase 4): same book, new Gmail — the spare key and
    // spare envelope are NOT affected; the old Gmail gets a plain note.
    const gNew = 'otp-changed@example.com';
    const rqC = await postJson(PORTAL_BASE, '/api/otp/request', { purpose: 'change-gmail', gmail: gNew });
    check('P12 server: change-Gmail OTP request answers ok and a mail is captured',
      rqC.json && rqC.json.ok === true && outboxCodeFor(gNew) !== null);
    const codeC = outboxCodeFor(gNew);
    const vC = await postJson(PORTAL_BASE, '/api/otp/verify', { purpose: 'change-gmail', gmail: gNew, code: codeC });
    check('P12 server: change-Gmail OTP verifies to a token',
      vC.json && vC.json.ok === true && typeof vC.json.token === 'string');
    const change = await postJson(PORTAL_BASE, '/api/recover/setup', {
      gmail: gNew, rkEnvelope: reset.json.rkEnvelope, token: vC.json.token,
    });
    check('P12 server: Gmail change returns the SAME spare envelope + notifiedOld',
      change.json && change.json.ok === true
      && JSON.stringify(change.json.rkEnvelope) === JSON.stringify(reset.json.rkEnvelope)
      && change.json.notifiedOld === true);
    check('P12 server: Gmail change updates the account binding',
      JSON.parse(fs.readFileSync(acctFile, 'utf8')).gmail === gNew);
    check('P12 server: Gmail change notifies the OLD Gmail with a plain note, no code in it',
      await (async () => {
        const notes = outboxMails().filter((m) => m.to === 'otp-setup@example.com'
          && (m.subject || '').includes('login Gmail changed'));
        if (!notes.length) return false;
        const n = notes[notes.length - 1];
        return (n.text || '').includes(gNew) && !/\b\d{6}\b/.test(n.text || '') && !/\b\d{6}\b/.test(n.subject || '');
      })());
    check('P12 server: Gmail change does NOT rotate the spare key file',
      Buffer.from(fs.readFileSync(keyFile)).toString('hex') === Buffer.from(newKeyBytes).toString('hex'));
    check('P12 server: a second book cannot change the Gmail (fabricated spare envelope → 409)',
      (await postJson(PORTAL_BASE, '/api/recover/setup', {
        gmail: 'otp-attacker@example.com',
        rkEnvelope: { v: 1, kdf: 'pbkdf2-sha256', iter: 600000, data: 'fabricated' },
        token: vC.json.token,
      })).status === 409);
    check('P12 server: Gmail change with a bad token is refused and the binding stays',
      await (async () => {
        const r = await postJson(PORTAL_BASE, '/api/recover/setup', {
          gmail: 'otp-attacker@example.com', rkEnvelope: reset.json.rkEnvelope,
          token: '0'.repeat(64),
        });
        return r.json && r.json.ok === false && r.json.error === 'BAD_TOKEN'
          && JSON.parse(fs.readFileSync(acctFile, 'utf8')).gmail === gNew;
      })());
    check('P12 server: Gmail change with a token for the WRONG Gmail is refused',
      await (async () => {
        const rqW = await postJson(PORTAL_BASE, '/api/otp/request', { purpose: 'change-gmail', gmail: 'otp-other@example.com' });
        if (!rqW.json || !rqW.json.ok) return false;
        const cW = outboxCodeFor('otp-other@example.com');
        const vW = await postJson(PORTAL_BASE, '/api/otp/verify', { purpose: 'change-gmail', gmail: 'otp-other@example.com', code: cW });
        if (!vW.json || !vW.json.ok) return false;
        const r = await postJson(PORTAL_BASE, '/api/recover/setup', {
          gmail: 'otp-mismatch@example.com', rkEnvelope: reset.json.rkEnvelope, token: vW.json.token,
        });
        return r.json && r.json.ok === false && r.json.error === 'BAD_TOKEN';
      })());
    // Recovery off: key file deleted, reset OTP refused, data/ never served.
    // (The code changed with the reset above, so the current code is
    // 654321 and the current envelope is the reset one.)
    check('P12 server: recovery off deletes the spare key file',
      (await postJson(PORTAL_BASE, '/api/recover/off', {
        pin: '654321', passphrase: '', envelope: reset.json.envelope,
      })).json.ok === true
      && !fs.existsSync(keyFile));
    check('P12 server: reset OTP is refused once recovery is off',
      (await postJson(PORTAL_BASE, '/api/otp/request', { purpose: 'reset' })).json.error === 'RECOVERY_OFF');
    check('P12 server: /data/recovery.key is never served (404)',
      (await getRaw(PORTAL_BASE, '/data/recovery.key')).status === 404);
    check('P12 server: /data/account.json is never served (404)',
      (await getRaw(PORTAL_BASE, '/data/account.json')).status === 404);
    // D12 wrinkle: restoring a different book's backup leaves the OLD
    // book's recovery.key + account.json on this PC, and re-linking the
    // restored book used to hit ALREADY_SET with no way forward. Setup
    // now answers ALREADY_SET_OTHER_BOOK for a valid different book,
    // and rebind:true (a deliberate second step) moves recovery to it.
    const bookA = await V.createVault('111111', '', SAMPLE);
    const setupA = await postJson(PORTAL_BASE, '/api/recover/setup', {
      gmail: 'd12-a@example.com', envelope: bookA.envelope, pin: '111111', passphrase: '',
    });
    check('D12 server: setup for book A works after recovery was turned off',
      setupA.json && setupA.json.ok === true && setupA.json.rkEnvelope);
    const keyABytes = fs.readFileSync(keyFile);
    const bookB = await V.createVault('222222', '', SAMPLE);
    const conflict = await postJson(PORTAL_BASE, '/api/recover/setup', {
      gmail: 'd12-b@example.com', envelope: bookB.envelope, pin: '222222', passphrase: '',
    });
    check('D12 server: a different book setup is refused with ALREADY_SET_OTHER_BOOK (409)',
      conflict.status === 409 && conflict.json && conflict.json.error === 'ALREADY_SET_OTHER_BOOK');
    check('D12 server: the refused setup leaves the spare key + binding untouched',
      Buffer.from(fs.readFileSync(keyFile)).toString('hex') === Buffer.from(keyABytes).toString('hex')
      && JSON.parse(fs.readFileSync(acctFile, 'utf8')).gmail === 'd12-a@example.com');
    check('D12 server: rebind with a wrong PIN is refused and the key stays',
      await (async () => {
        const r = await postJson(PORTAL_BASE, '/api/recover/setup', {
          gmail: 'd12-b@example.com', envelope: bookB.envelope, pin: '222223', passphrase: '', rebind: true,
        });
        return r.status === 400 && r.json.error === 'BAD_CREDENTIALS'
          && Buffer.from(fs.readFileSync(keyFile)).toString('hex') === Buffer.from(keyABytes).toString('hex');
      })());
    check('D12 server: rebind with no envelope is refused and the key stays',
      await (async () => {
        const r = await postJson(PORTAL_BASE, '/api/recover/setup', {
          gmail: 'd12-b@example.com', pin: '222222', passphrase: '', rebind: true,
        });
        return r.status === 400 && r.json.error === 'BAD_ENVELOPE'
          && Buffer.from(fs.readFileSync(keyFile)).toString('hex') === Buffer.from(keyABytes).toString('hex');
      })());
    const reb = await postJson(PORTAL_BASE, '/api/recover/setup', {
      gmail: 'd12-b@example.com', envelope: bookB.envelope, pin: '222222', passphrase: '', rebind: true,
    });
    check('D12 server: rebind:true moves recovery to the new book',
      reb.json && reb.json.ok === true && reb.json.rebound === true && reb.json.rkEnvelope);
    const keyBBytes = fs.readFileSync(keyFile);
    check('D12 server: rebind rotates the spare key + updates the binding',
      Buffer.from(keyBBytes).toString('hex') !== Buffer.from(keyABytes).toString('hex')
      && JSON.parse(fs.readFileSync(acctFile, 'utf8')).gmail === 'd12-b@example.com');
    check('D12 server: the new spare envelope opens the new book under the new key',
      await (async () => {
        const sk = await V.importSpareKey(keyBBytes);
        const v = await V.openSpareEnvelope(sk, reb.json.rkEnvelope);
        return JSON.stringify(v) === JSON.stringify(SAMPLE);
      })());
    check('D12 server: the OLD spare envelope does not open under the new key',
      await (async () => {
        const sk = await V.importSpareKey(keyBBytes);
        try { await V.openSpareEnvelope(sk, setupA.json.rkEnvelope); return false; }
        catch (e) { return e && e.code === 'DECRYPT_FAILED'; }
      })());
    check('D12 server: the old book cannot re-bind with a fabricated spare envelope (409)',
      (await postJson(PORTAL_BASE, '/api/recover/setup', {
        gmail: 'd12-a@example.com',
        rkEnvelope: { v: 1, kdf: 'pbkdf2-sha256', iter: 600000, data: 'fabricated' },
      })).status === 409);
  } finally {
    portalServer.kill();
    unconfServer.kill();
    try { fs.unlinkSync(path.join(__dirname, 'data', 'recovery.key')); } catch (_e) { /* already gone */ }
    try { fs.unlinkSync(path.join(__dirname, 'data', 'account.json')); } catch (_e) { /* already gone */ }
    try { fs.unlinkSync(outboxFile); } catch (_e) { /* already gone */ }
  }

  // ---- §11. P12 Phase 2 — account binding + session (vault.js, model.js) ----
  // The browser's localStorage does not exist in Node: install a fake on
  // globalThis for this section, then remove it again.
  function fakeStorage() {
    const m = new Map();
    return {
      getItem: (k) => (m.has(k) ? m.get(k) : null),
      setItem: (k, v) => { m.set(k, String(v)); },
      removeItem: (k) => { m.delete(k); },
      _map: m,
    };
  }
  const savedLocalStorage = globalThis.localStorage;
  globalThis.localStorage = fakeStorage();
  try {
    check('P12 portal: VaultState has REGISTER / MIGRATION / READY',
      V.VaultState.REGISTER === 'register' && V.VaultState.MIGRATION === 'migration' && V.VaultState.READY === 'ready');
    check('P12 portal: saveAccount returns true and loadAccount reads it back',
      V.saveAccount({ gmail: 'test@example.com' }) === true
      && JSON.stringify(V.loadAccount()) === JSON.stringify({ gmail: 'test@example.com' }));
    check('P12 portal: loadAccount is null when nothing is saved',
      (V.clearAccount(), V.loadAccount() === null));
    check('P12 portal: a corrupt account value loads as null (never crashes)',
      (globalThis.localStorage.setItem(V.ACCOUNT_KEY, 'not json'), V.loadAccount() === null));
    check('P12 portal: saveAccount throws STORAGE_QUOTA when storage is full',
      await (async () => {
        const prev = globalThis.localStorage;
        globalThis.localStorage = fakeStorage();
        globalThis.localStorage.setItem = () => { throw new Error('QuotaExceededError'); };
        let code = null;
        try { V.saveAccount({ gmail: 'test@example.com' }); } catch (e) { code = e && e.code; }
        globalThis.localStorage = prev;
        return code === 'STORAGE_QUOTA';
      })());
    check('P12 portal: clearAccount removes the binding',
      (V.saveAccount({ gmail: 'test@example.com' }), V.clearAccount(), V.loadAccount() === null));
    const sess = V.saveSession('test@example.com');
    check('P12 portal: saveSession stores the Gmail with a ~12h expiry',
      sess.gmail === 'test@example.com'
      && sess.expiresAt > Date.now() && sess.expiresAt <= Date.now() + 12 * 3600 * 1000 + 1000);
    check('P12 portal: loadSession reads the session back',
      JSON.stringify(V.loadSession()) === JSON.stringify(sess));
    check('P12 portal: loadSession is null when nothing is saved',
      (V.clearSession(), V.loadSession() === null));
    check('P12 portal: an expired session loads as null and is removed',
      (V.saveSession('test@example.com', -1),
        V.loadSession() === null && globalThis.localStorage.getItem(V.SESSION_KEY) === null));
    check('P12 portal: a corrupt session loads as null',
      (globalThis.localStorage.setItem(V.SESSION_KEY, 'not json'), V.loadSession() === null));
    check('P12 portal: isSessionValid is true before expiry, false at/after it',
      V.isSessionValid({ gmail: 'test@example.com', expiresAt: 1000 }, 999) === true
      && V.isSessionValid({ gmail: 'test@example.com', expiresAt: 1000 }, 1000) === false
      && V.isSessionValid({ gmail: 'test@example.com', expiresAt: 1000 }, 1001) === false);
    check('P12 portal: isSessionValid refuses an empty Gmail or no session',
      V.isSessionValid({ gmail: '', expiresAt: 9999999999999 }, 0) === false
      && V.isSessionValid(null, 0) === false);
    check('P12 portal: clearSession removes the session',
      (V.saveSession('test@example.com'), V.clearSession(), V.loadSession() === null));
    check('P12 portal: confirmGmailChange needs no confirmation for the same address',
      V.confirmGmailChange('test@example.com', 'test@example.com') === true);
    check('P12 portal: confirmGmailChange needs no confirmation with no saved address',
      V.confirmGmailChange('test@example.com', null) === true);
    const facts = V.confirmGmailChange('new@example.com', 'old@example.com');
    check('P12 portal: changing Gmail returns exactly 3 facts, naming the old address',
      Array.isArray(facts) && facts.length === 3 && facts[1].includes('old@example.com'));
    check('P12 portal: there is no rememberPin — the code is never saved',
      V.rememberPin === undefined);
    check('P12 portal: localStorage holds only the account + session keys (no PIN key)',
      await (async () => {
        const src = fs.readFileSync(path.join(__dirname, 'public', 'vault.js'), 'utf8');
        const setItems = [...src.matchAll(/\.setItem\(([^,]+),/g)].map((m) => m[1].trim());
        return JSON.stringify(setItems) === JSON.stringify(['ACCOUNT_KEY', 'SESSION_KEY'])
          && !src.includes('rememberPin');
      })());
    check('P12 portal: the saved account/session JSON never contains a code or PIN field',
      await (async () => {
        V.saveAccount({ gmail: 'test@example.com' });
        V.saveSession('test@example.com');
        const a = globalThis.localStorage.getItem(V.ACCOUNT_KEY);
        const s = globalThis.localStorage.getItem(V.SESSION_KEY);
        V.clearAccount(); V.clearSession();
        return !/pin|code/i.test(a) && !/pin|code/i.test(s);
      })());
    // model.js: migration status + Gmail change validation.
    check('P12 portal: migration is linked when an account binding exists',
      M.migrationStatusFromVault({}, { gmail: 'test@example.com' }) === 'linked');
    check('P12 portal: migration is dismissed when the vault says so',
      M.migrationStatusFromVault({ migrationDismissed: true }, null) === 'dismissed');
    check('P12 portal: migration is pending otherwise',
      M.migrationStatusFromVault({}, null) === 'pending'
      && M.migrationStatusFromVault({ migrationDismissed: false }, {}) === 'pending');
    const origVault = { householdName: 'Home' };
    const dismissedVault = M.markMigrationDismissed(origVault);
    check('P12 portal: marking dismissed returns a NEW vault, original untouched',
      dismissedVault.migrationDismissed === true && origVault.migrationDismissed === undefined
      && dismissedVault.householdName === 'Home');
    check('P12 portal: migration options are link / skip / dont-ask-again',
      M.MIGRATION_OPTIONS.LINK_GMAIL === 'link_gmail'
      && M.MIGRATION_OPTIONS.SKIP_FOR_NOW === 'skip_for_now'
      && M.MIGRATION_OPTIONS.DONT_ASK_AGAIN === 'dont_ask_again');
    check('P12 portal: empty new Gmail is NO_GMAIL',
      M.isValidGmailChange('', null) === 'NO_GMAIL'
      && M.isValidGmailChange('   ', null) === 'NO_GMAIL');
    check('P12 portal: a bad new Gmail is INVALID_GMAIL',
      M.isValidGmailChange('not-an-email', null) === 'INVALID_GMAIL'
      && M.isValidGmailChange('a@b', null) === 'INVALID_GMAIL');
    check('P12 portal: the same Gmail (any case) is SAME_GMAIL',
      M.isValidGmailChange('Test@Example.com', { gmail: 'test@example.com' }) === 'SAME_GMAIL');
    check('P12 portal: a different valid Gmail is allowed',
      M.isValidGmailChange('new@example.com', { gmail: 'test@example.com' }) === true
      && M.isValidGmailChange('new@example.com', null) === true);
  } finally {
    if (savedLocalStorage === undefined) delete globalThis.localStorage;
    else globalThis.localStorage = savedLocalStorage;
  }

  // ---- §12. P12 Phase 2 — register / login / migration in jsdom ----
  // Fresh vm contexts per scenario (buildVmContext = §8 harness, with the
  // mocked fetch portal API). The OTP code the fake "sends" is '123456'.
  function portalCtx() {
    const c = buildVmContext();
    return {
      ctx: c,
      el: (id) => c._els[id],
      hidden: (id) => c._els[id].classList.contains('hidden'),
      visible: (id) => !c._els[id].classList.contains('hidden'),
      store: c._store,
    };
  }
  async function registerIn(p, gmail, pin) {
    p.el('setup-gmail').value = gmail;
    p.el('setup-pin').value = pin;
    p.el('setup-pin2').value = pin;
    p.el('setup-pass').value = '';
    p.el('setup-btn').click();
    // Harness note: an El starts with NO classes, so visible('setup-otp-section')
    // is true before onSetup even runs — a plain visibility wait returns at
    // once and the verify click races onSetup's async mail/OTP chain (the
    // verify then sees pendingRegister still null). Wait for the OTP note
    // text instead: onSetup sets it only after pendingRegister is stored and
    // the OTP request succeeded.
    await waitFor(() => p.el('setup-otp-note').textContent.includes(gmail)
      && p.el('setup-otp-note').textContent.includes('10 minutes'));
    p.el('setup-otp').value = '123456';
    p.el('setup-verify-btn').click();
    await waitFor(() => p.visible('vault-screen') && !!p.store.get(V.ACCOUNT_KEY));
  }
  // Exact wording (plan, "Exact wording" section) is on the screens.
  check('P12 portal: register screen uses the plan wording',
    htmlSrc.includes('Create your account')
    && htmlSrc.includes('One Gmail, one code. This book is yours alone')
    && htmlSrc.includes('We will send a 6-digit code to your Gmail to check it is yours.')
    && htmlSrc.includes('If someone can open the files on your PC, they can find the spare key')
    && htmlSrc.includes('You can turn this recovery off later in Security.')
    && htmlSrc.includes('Create without Gmail — no forgot-code later'));
  check('P12 portal: login + migration screens use the plan wording',
    htmlSrc.includes('Open your book')
    && htmlSrc.includes('Secure code (6 digits)')
    && htmlSrc.includes('Forgot your code?')
    && htmlSrc.includes('Not your Gmail?')
    && htmlSrc.includes('One more step: add your Gmail')
    && htmlSrc.includes('Skip for now — you can add it later in Security. Forgot-code will not work until then.')
    && htmlSrc.includes('Mail is not set up on this PC yet, so no code can be sent.'));
  {
    // Registration happy path (mail configured).
    const p = portalCtx();
    check('P12 portal: first run shows the register screen',
      p.visible('setup-screen') && p.hidden('unlock-screen') && p.hidden('vault-screen'));
    p.el('setup-gmail').value = '';
    p.el('setup-pin').value = '123456'; p.el('setup-pin2').value = '123456';
    p.el('setup-btn').click();
    await sleep(50);
    check('P12 portal: an empty Gmail is refused on register',
      p.el('setup-error').textContent.includes('Type your Gmail'));
    p.el('setup-gmail').value = 'not-an-email';
    p.el('setup-btn').click();
    await sleep(50);
    check('P12 portal: a bad Gmail is refused on register',
      p.el('setup-error').textContent.includes('Type your Gmail'));
    p.el('setup-gmail').value = 'test@example.com';
    p.el('setup-btn').click();
    check('P12 portal: Create my book sends a code and shows the OTP step',
      await waitFor(() => p.visible('setup-otp-section')
        && p.el('setup-otp-note').textContent.includes('test@example.com')
        && p.el('setup-otp-note').textContent.includes('10 minutes')));
    check('P12 portal: the OTP request went to the typed Gmail (fetch log)',
      p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/otp/request') && c.body.gmail === 'test@example.com'));
    p.el('setup-otp').value = '111111';
    p.el('setup-verify-btn').click();
    await sleep(50);
    check('P12 portal: a wrong OTP is refused, the book stays closed',
      p.el('setup-otp-error').textContent.includes('Wrong code') && p.hidden('vault-screen'));
    p.el('setup-otp').value = '123456';
    p.el('setup-verify-btn').click();
    check('P12 portal: the right OTP opens the book',
      await waitFor(() => p.visible('vault-screen')));
    check('P12 portal: registration saves the account (Gmail + recovery on + spare envelope)',
      await (async () => {
        const raw = p.store.get(V.ACCOUNT_KEY);
        if (!raw) return false;
        const acct = JSON.parse(raw);
        return acct.gmail === 'test@example.com' && acct.recoveryOn === true
          && acct.rkEnvelope && typeof acct.verifiedAt === 'number';
      })());
    check('P12 portal: registration saves a 12h session for the Gmail',
      await (async () => {
        const raw = p.store.get(V.SESSION_KEY);
        if (!raw) return false;
        const sess = JSON.parse(raw);
        return sess.gmail === 'test@example.com' && sess.expiresAt > p.ctx._now()
          && sess.expiresAt <= p.ctx._now() + 12 * 3600 * 1000 + 1000;
      })());
    // Code-alone login with the saved Gmail.
    p.el('lock-btn').click();
    check('P12 portal: lock shows the login screen with the saved Gmail',
      p.visible('unlock-screen') && p.el('unlock-gmail-addr').textContent === 'test@example.com'
      && p.hidden('unlock-gmail-input-wrap'));
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    check('P12 portal: code-alone login reopens the book',
      await waitFor(() => p.visible('vault-screen')));
    // "Not your Gmail?" — a different Gmail is refused, the right one works.
    p.el('lock-btn').click();
    p.el('not-gmail-link').click();
    check('P12 portal: Not your Gmail shows the Gmail field',
      p.visible('unlock-gmail-input-wrap') && p.hidden('unlock-gmail-line'));
    p.el('unlock-gmail').value = 'other@example.com';
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    await sleep(50);
    check('P12 portal: a Gmail that does not match the book is refused',
      p.el('unlock-error').textContent.includes('That Gmail does not match this book')
      && p.hidden('vault-screen'));
    p.el('unlock-gmail').value = 'test@example.com';
    p.el('unlock-btn').click();
    check('P12 portal: the matching Gmail + code opens the book',
      await waitFor(() => p.visible('vault-screen')));
  }
  {
    // Mail unconfigured: fallback creates a PIN-only book; migration
    // asks after the next unlock and offers only Skip.
    const p = portalCtx();
    p.ctx._setMailConfigured(false);
    p.el('setup-gmail').value = 'test@example.com';
    p.el('setup-pin').value = '123456'; p.el('setup-pin2').value = '123456';
    p.el('setup-btn').click();
    check('P12 portal: mail not set up shows the note + fallback, no code sent',
      await waitFor(() => p.visible('setup-mail-note') && p.visible('setup-fallback-btn')
        && p.el('setup-mail-error').textContent.includes('Mail is not set up')));
    check('P12 portal: no OTP was requested when mail is not set up',
      !p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/otp/request')));
    p.el('setup-fallback-btn').click();
    check('P12 portal: Create without Gmail opens a PIN-only book',
      await waitFor(() => p.visible('vault-screen')));
    check('P12 portal: the PIN-only book has no account saved',
      !p.store.has(V.ACCOUNT_KEY));
    p.el('lock-btn').click();
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    check('P12 portal: a PIN-only vault shows the migration screen after unlock',
      await waitFor(() => p.visible('migration-screen') && p.hidden('vault-screen')));
    check('P12 portal: migration with mail off shows the note and only Skip',
      await waitFor(() => p.visible('mig-mail-note') && p.hidden('mig-send-btn')));
    p.el('mig-skip-link').click();
    check('P12 portal: Skip for now opens the book',
      await waitFor(() => p.visible('vault-screen')));
    p.el('lock-btn').click();
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    check('P12 portal: Skip asks again on the next login (not dismissed)',
      await waitFor(() => p.visible('migration-screen')));
    p.el('mig-skip-link').click();
    await waitFor(() => p.visible('vault-screen'));
  }
  {
    // Migration link: Gmail → OTP → linked, account saved, no more asks.
    const p = portalCtx();
    p.ctx._setMailConfigured(false);
    p.el('setup-gmail').value = 'test@example.com';
    p.el('setup-pin').value = '123456'; p.el('setup-pin2').value = '123456';
    p.el('setup-btn').click();
    await waitFor(() => p.visible('setup-fallback-btn'));
    p.el('setup-fallback-btn').click();
    await waitFor(() => p.visible('vault-screen'));
    p.el('lock-btn').click();
    p.ctx._setMailConfigured(true);
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    check('P12 portal: migration screen offers Send code when mail is set up',
      await waitFor(() => p.visible('migration-screen') && p.visible('mig-send-btn')));
    p.el('mig-gmail').value = 'test@example.com';
    p.el('mig-send-btn').click();
    check('P12 portal: migration sends a link code and shows the OTP step',
      await waitFor(() => p.visible('mig-otp-section')
        && p.el('mig-otp-note').textContent.includes('test@example.com')));
    check('P12 portal: the link OTP request used purpose link',
      p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/otp/request') && c.body.purpose === 'link'));
    p.el('mig-otp').value = '111111';
    p.el('mig-verify-btn').click();
    await sleep(50);
    check('P12 portal: a wrong migration OTP is refused',
      p.el('mig-error').textContent.includes('Wrong code') && p.visible('migration-screen'));
    p.el('mig-otp').value = '123456';
    p.el('mig-verify-btn').click();
    check('P12 portal: the right migration OTP links the Gmail and opens the book',
      await waitFor(() => p.visible('vault-screen')));
    check('P12 portal: the linked account is saved (Gmail + recovery on)',
      await (async () => {
        const raw = p.store.get(V.ACCOUNT_KEY);
        if (!raw) return false;
        const acct = JSON.parse(raw);
        return acct.gmail === 'test@example.com' && acct.recoveryOn === true;
      })());
    p.el('lock-btn').click();
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    check('P12 portal: a linked vault never shows migration again',
      await waitFor(() => p.visible('vault-screen') && p.hidden('migration-screen')));
  }
  {
    // "Don't ask again": the flag is stored in the vault and migration
    // never asks again, even after lock + unlock.
    const p = portalCtx();
    p.ctx._setMailConfigured(false);
    p.el('setup-gmail').value = 'test@example.com';
    p.el('setup-pin').value = '123456'; p.el('setup-pin2').value = '123456';
    p.el('setup-btn').click();
    await waitFor(() => p.visible('setup-fallback-btn'));
    p.el('setup-fallback-btn').click();
    await waitFor(() => p.visible('vault-screen'));
    p.el('lock-btn').click();
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    await waitFor(() => p.visible('migration-screen'));
    p.el('mig-dont-ask-link').click();
    check('P12 portal: Don\'t ask again opens the book',
      await waitFor(() => p.visible('vault-screen')));
    check('P12 portal: the vault now carries migrationDismissed',
      await (async () => {
        const raw = p.store.get('ghar-register-vault');
        const env = JSON.parse(raw);
        const res = await V.unlockVault('123456', '', env);
        return res.vault.migrationDismissed === true;
      })());
    p.el('lock-btn').click();
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    check('P12 portal: a dismissed vault never shows migration again',
      await waitFor(() => p.visible('vault-screen') && p.hidden('migration-screen')));
  }

  // ---- §13. P12 Phase 3 — forgot-code reset in jsdom ----
  check('P12 reset: reset screen uses the plan wording',
    htmlSrc.includes('Reset your code')
    && htmlSrc.includes('We will send a 6-digit code to')
    && appSrc.includes('We sent a 6-digit code to')
    && appSrc.includes('It works for 10 minutes and one time only.')
    && htmlSrc.includes('New secure code (6 digits)')
    && htmlSrc.includes('Type the new code again')
    && htmlSrc.includes('Set new code and open my book')
    && appSrc.includes('Your book is open. Your old code no longer works. Your extra passphrase was removed — you can set a new one in Security.')
    && htmlSrc.includes('Forgot-code is off for this book — your code cannot be reset. Restore from a backup instead.'));
  {
    // Full round-trip: register → lockout (5 wrong codes) → forgot →
    // OTP → new code → locked → login with the new code. Data survives
    // (household name set before the reset is still there).
    const p = portalCtx();
    await registerIn(p, 'test@example.com', '123456');
    p.ctx.location.hash = '#/profile';
    p.ctx._dispatchWin('hashchange');
    p.el('profile-household').value = 'Hashir Home';
    p.el('profile-monthstart').value = '5';
    p.el('profile-save-btn').click();
    await waitFor(() => p.el('profile-ok').textContent.includes('Saved'));
    check('P12 reset: household name saved before the reset',
      p.el('sidebar-name').textContent === 'Hashir Home');
    p.el('lock-btn').click();
    for (let i = 0; i < 5; i++) {
      p.el('unlock-pin').value = '999999';
      p.el('unlock-btn').click();
      // Serialise: wait for THIS attempt to finish (and record its failure)
      // before the next click, as in the §8 lockout test.
      await waitFor(() => p.el('unlock-error').textContent.includes('Wrong code'));
      p.el('unlock-error').textContent = '';
    }
    check('P12 reset: 5 wrong codes lock the book before the reset',
      await waitFor(() => p.el('lockout-note').textContent.includes('Too many wrong codes')));
    p.el('forgot-link').click();
    check('P12 reset: Forgot your code shows the saved Gmail',
      await waitFor(() => p.visible('reset-screen')
        && p.el('reset-gmail-addr').textContent === 'test@example.com'
        && p.visible('reset-send-btn') && p.hidden('reset-off-note')));
    p.el('reset-send-btn').click();
    check('P12 reset: Send shows the OTP step with the 10-minute note',
      await waitFor(() => p.visible('reset-otp-section')
        && p.el('reset-otp-note').textContent.includes('We sent a 6-digit code to test@example.com')
        && p.el('reset-otp-note').textContent.includes('10 minutes')));
    check('P12 reset: the new-code step stays hidden until the OTP verifies',
      p.hidden('reset-new-section'));
    p.el('reset-otp').value = '111111';
    p.el('reset-verify-btn').click();
    await sleep(50);
    check('P12 reset: a wrong OTP is refused, the new-code step stays hidden',
      p.el('reset-otp-error').textContent.includes('Wrong code') && p.hidden('reset-new-section'));
    p.el('reset-otp').value = '123456';
    p.el('reset-verify-btn').click();
    check('P12 reset: the right OTP opens the new-code step',
      await waitFor(() => p.visible('reset-new-section')));
    p.el('reset-new-pin').value = '654321';
    p.el('reset-new-pin2').value = '654322';
    p.el('reset-btn').click();
    await sleep(50);
    check('P12 reset: mismatched new codes are refused',
      p.el('reset-new-error').textContent.includes('do not match') && p.visible('reset-screen'));
    p.el('reset-new-pin').value = '654321';
    p.el('reset-new-pin2').value = '654321';
    p.el('reset-btn').click();
    check('P12 reset: setting the new code locks the book (login with the new code)',
      await waitFor(() => p.visible('unlock-screen') && p.hidden('vault-screen')));
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    check('P12 reset: the old code no longer opens the book',
      await waitFor(() => p.el('unlock-error').textContent.includes('Wrong code')) && p.hidden('vault-screen'));
    p.el('unlock-pin').value = '654321';
    p.el('unlock-btn').click();
    check('P12 reset: the new code opens the book right away (lockout cleared by the reset)',
      await waitFor(() => p.visible('vault-screen')));
    check('P12 reset: the exact success message shows once on Today',
      !p.hidden('today-notice')
      && p.el('today-notice').textContent.includes('Your book is open. Your old code no longer works.'));
    check('P12 reset: the book data survived the reset (household name still there)',
      p.el('sidebar-name').textContent === 'Hashir Home');
    check('P12 reset: the stored envelope now opens with the new code only',
      await (async () => {
        const env = JSON.parse(p.store.get('ghar-register-vault'));
        try { await V.unlockVault('123456', '', env); return false; }
        catch (e) { if (!e || e.code !== 'DECRYPT_FAILED') return false; }
        const res = await V.unlockVault('654321', '', env);
        return JSON.stringify(res.vault.householdName) === '"Hashir Home"';
      })());
  }
  {
    // Recovery off: a PIN-only book gets the plain off message, no Send,
    // and the envelope is left untouched.
    const p = portalCtx();
    p.ctx._setMailConfigured(false);
    p.el('setup-gmail').value = 'test@example.com';
    p.el('setup-pin').value = '123456'; p.el('setup-pin2').value = '123456';
    p.el('setup-btn').click();
    await waitFor(() => p.visible('setup-fallback-btn'));
    p.el('setup-fallback-btn').click();
    await waitFor(() => p.visible('vault-screen'));
    const envBefore = p.store.get('ghar-register-vault');
    p.el('lock-btn').click();
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    await waitFor(() => p.visible('migration-screen'));
    p.el('mig-skip-link').click();
    await waitFor(() => p.visible('vault-screen'));
    p.el('lock-btn').click();
    p.el('forgot-link').click();
    // fillReset's off branch hides the Send button and the Gmail line; the
    // off-note text itself is static HTML (asserted by the wording check
    // above) — the harness El never sees static text, so the runtime signal
    // here is the hidden Send button + hidden Gmail line.
    check('P12 reset: recovery off shows the plain off message, no Send button',
      await waitFor(() => p.hidden('reset-send-btn') && p.hidden('reset-gmail-line')));
    check('P12 reset: recovery off leaves the envelope untouched',
      p.store.get('ghar-register-vault') === envBefore);
  }
  {
    // Other-tab lock: the envelope changing under another tab locks
    // this tab at once; any other key does nothing.
    const p = portalCtx();
    await registerIn(p, 'test@example.com', '123456');
    p.ctx._dispatchWin('storage', { key: 'something-else' });
    check('P12 reset: an unrelated storage change does not lock the book',
      p.visible('vault-screen'));
    p.ctx._dispatchWin('storage', { key: 'ghar-register-vault' });
    check('P12 reset: the envelope changing in another tab locks this tab',
      await waitFor(() => p.visible('unlock-screen') && p.hidden('vault-screen')));
  }

  // ---- §14. P12 Phase 4 — Security: Gmail change + recovery on/off ----
  check('P12 security: Security page uses the plan wording',
    htmlSrc.includes('Change login Gmail')
    && htmlSrc.includes('Forgot-code recovery')
    && htmlSrc.includes('Login Gmail:')
    && appSrc.includes('Forgot-code is now off. If you forget your code, the book cannot be opened.')
    && appSrc.includes('Login Gmail changed to'));
  {
    // Gmail change happy path: wrong OTP refused, right OTP changes the
    // Gmail, the spare envelope is NOT affected, the old Gmail is
    // notified (mock records the setup call), Profile line updates.
    const p = portalCtx();
    await registerIn(p, 'test@example.com', '123456');
    const acctBefore = JSON.parse(p.store.get(V.ACCOUNT_KEY));
    p.ctx.location.hash = '#/security';
    p.ctx._dispatchWin('hashchange');
    check('P12 security: Security shows the current login Gmail + recovery on',
      await waitFor(() => p.el('change-gmail-current').textContent === 'test@example.com'
        && p.el('recovery-status').textContent.includes('recovery: on')));
    p.el('change-gmail-new').value = 'test@example.com';
    p.el('change-gmail-send-btn').click();
    await sleep(50);
    check('P12 security: changing to the same Gmail is refused',
      p.el('change-gmail-error').textContent.includes('already your login Gmail'));
    p.el('change-gmail-new').value = 'not-an-email';
    p.el('change-gmail-send-btn').click();
    await sleep(50);
    check('P12 security: a bad new Gmail is refused',
      p.el('change-gmail-error').textContent.includes('looks right'));
    p.el('change-gmail-new').value = 'new@example.com';
    p.el('change-gmail-send-btn').click();
    check('P12 security: Send shows the OTP step for the NEW Gmail',
      await waitFor(() => p.el('change-gmail-otp-note').textContent.includes('new@example.com')
        && p.el('change-gmail-otp-note').textContent.includes('10 minutes')));
    p.el('change-gmail-otp').value = '111111';
    p.el('change-gmail-verify-btn').click();
    await sleep(50);
    check('P12 security: a wrong change OTP is refused',
      p.el('change-gmail-otp-error').textContent.includes('Wrong code'));
    p.el('change-gmail-otp').value = '123456';
    p.el('change-gmail-verify-btn').click();
    check('P12 security: the right OTP changes the login Gmail',
      await waitFor(() => p.el('change-gmail-ok').textContent.includes('Login Gmail changed to new@example.com')));
    check('P12 security: the old Gmail got the note (success line says so)',
      p.el('change-gmail-ok').textContent.includes('old Gmail got a note'));
    const acctAfter = JSON.parse(p.store.get(V.ACCOUNT_KEY));
    check('P12 security: the account keeps recovery on with the SAME spare envelope',
      acctAfter.gmail === 'new@example.com' && acctAfter.recoveryOn === true
      && JSON.stringify(acctAfter.rkEnvelope) === JSON.stringify(acctBefore.rkEnvelope));
    check('P12 security: the change call sent the spare envelope + token (mock log)',
      p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/recover/setup')
        && c.body.gmail === 'new@example.com' && c.body.rkEnvelope
        && c.body.token === 'tok-change-gmail'));
    check('P12 security: the session moves to the new Gmail',
      JSON.parse(p.store.get(V.SESSION_KEY)).gmail === 'new@example.com');
    p.ctx.location.hash = '#/profile';
    p.ctx._dispatchWin('hashchange');
    check('P12 security: the Profile page shows the new login Gmail',
      await waitFor(() => p.el('profile-login-gmail').textContent === 'new@example.com'));
  }
  {
    // Recovery off → forgot shows the off message; back on (with the
    // current code) → reset works again.
    const p = portalCtx();
    await registerIn(p, 'test@example.com', '123456');
    const rkBefore = JSON.parse(p.store.get(V.ACCOUNT_KEY)).rkEnvelope;
    p.ctx.location.hash = '#/security';
    p.ctx._dispatchWin('hashchange');
    // D5: turning recovery off needs the current code, typed at the top
    // of the Security page — without it the button refuses.
    p.el('recovery-off-btn').click();
    check('P12 security: turning recovery off without the current code is refused',
      await waitFor(() => p.el('recovery-error').textContent.includes('Current PIN must be exactly 6 digits'))
      && !p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/recover/off')));
    p.el('security-pin').value = '123456';
    p.el('recovery-off-btn').click();
    check('P12 security: turning recovery off shows the plan message',
      await waitFor(() => p.el('recovery-ok').textContent.includes('Forgot-code is now off. If you forget your code, the book cannot be opened.')));
    const acctOff = JSON.parse(p.store.get(V.ACCOUNT_KEY));
    check('P12 security: turning off drops the spare envelope, keeps the Gmail',
      acctOff.gmail === 'test@example.com' && acctOff.recoveryOn === false && !acctOff.rkEnvelope);
    check('P12 security: turning off called /api/recover/off with the current code + envelope',
      p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/recover/off')
        && c.body.pin === '123456' && c.body.envelope && typeof c.body.envelope.data === 'string'));
    check('P12 security: with recovery off, the change-Gmail section hides',
      p.hidden('change-gmail-section') && !p.hidden('change-gmail-unavailable'));
    p.el('lock-btn').click();
    p.el('forgot-link').click();
    check('P12 security: with recovery off, forgot shows the off message, no Send',
      await waitFor(() => p.hidden('reset-send-btn') && p.hidden('reset-gmail-line')));
    // Back on: the current code is typed at the top, as the page asks.
    p.el('reset-back-link').click();
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    await waitFor(() => p.visible('vault-screen'));
    p.ctx.location.hash = '#/security';
    p.ctx._dispatchWin('hashchange');
    p.el('security-pin').value = '123456';
    p.el('recovery-on-btn').click();
    check('P12 security: turning recovery back on works with the current code',
      await waitFor(() => p.el('recovery-ok').textContent.includes('Forgot-code recovery is on again.')));
    const acctOn = JSON.parse(p.store.get(V.ACCOUNT_KEY));
    check('P12 security: turning back on makes a NEW spare envelope',
      acctOn.recoveryOn === true && acctOn.rkEnvelope
      && JSON.stringify(acctOn.rkEnvelope) !== JSON.stringify(rkBefore));
    // Reset works again after turning back on.
    p.el('lock-btn').click();
    p.el('forgot-link').click();
    p.el('reset-send-btn').click();
    check('P12 security: reset Send works again after turning back on',
      await waitFor(() => p.el('reset-otp-note').textContent.includes('10 minutes')));
    p.el('reset-otp').value = '123456';
    p.el('reset-verify-btn').click();
    await waitFor(() => p.visible('reset-new-section'));
    p.el('reset-new-pin').value = '654321';
    p.el('reset-new-pin2').value = '654321';
    p.el('reset-btn').click();
    check('P12 security: reset works again after turning recovery back on',
      await waitFor(() => p.visible('unlock-screen') && p.hidden('vault-screen')));
    p.el('unlock-pin').value = '654321';
    p.el('unlock-btn').click();
    check('P12 security: the new code opens the book after the re-on reset',
      await waitFor(() => p.visible('vault-screen')));
  }
  {
    // Never linked: Security offers the link (Gmail + code), OTP first,
    // then the book links. With mail off, Send says so plainly.
    const p = portalCtx();
    p.ctx._setMailConfigured(false);
    p.el('setup-gmail').value = 'test@example.com';
    p.el('setup-pin').value = '123456'; p.el('setup-pin2').value = '123456';
    p.el('setup-btn').click();
    await waitFor(() => p.el('setup-mail-error').textContent.includes('Mail is not set up'));
    p.el('setup-fallback-btn').click();
    await waitFor(() => p.visible('vault-screen'));
    p.el('lock-btn').click();
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    await waitFor(() => p.visible('migration-screen'));
    p.el('mig-skip-link').click();
    await waitFor(() => p.visible('vault-screen'));
    p.ctx.location.hash = '#/security';
    p.ctx._dispatchWin('hashchange');
    check('P12 security: a never-linked book is offered the link in Security',
      await waitFor(() => p.el('recovery-status').textContent.includes('no Gmail linked yet')
        && !p.hidden('recovery-gmail-wrap')));
    check('P12 security: a never-linked book has no change-Gmail section',
      p.hidden('change-gmail-section') && !p.hidden('change-gmail-unavailable'));
    p.ctx.location.hash = '#/profile';
    p.ctx._dispatchWin('hashchange');
    check('P12 security: the Profile page shows no login Gmail yet',
      await waitFor(() => !p.hidden('profile-login-gmail-none') && p.hidden('profile-login-gmail-line')));
    p.ctx.location.hash = '#/security';
    p.ctx._dispatchWin('hashchange');
    p.el('recovery-gmail').value = 'test@example.com';
    p.el('security-pin').value = '123456';
    p.el('recovery-send-btn').click();
    check('P12 security: link Send with mail off says so plainly',
      await waitFor(() => p.el('recovery-error').textContent.includes('Mail is not set up')));
    p.ctx._setMailConfigured(true);
    p.el('recovery-send-btn').click();
    check('P12 security: link Send shows the OTP step',
      await waitFor(() => p.el('recovery-otp-note').textContent.includes('test@example.com')));
    p.el('recovery-otp').value = '111111';
    p.el('recovery-verify-btn').click();
    await sleep(50);
    check('P12 security: a wrong link OTP is refused',
      p.el('recovery-otp-error').textContent.includes('Wrong code'));
    p.el('recovery-otp').value = '123456';
    p.el('recovery-verify-btn').click();
    check('P12 security: the right OTP links the Gmail from Security',
      await waitFor(() => p.el('recovery-ok').textContent.includes('Gmail linked. Forgot-code recovery is on.')));
    const acct = JSON.parse(p.store.get(V.ACCOUNT_KEY));
    check('P12 security: the linked account has recovery on + a spare envelope',
      acct.gmail === 'test@example.com' && acct.recoveryOn === true && !!acct.rkEnvelope);
    p.ctx.location.hash = '#/profile';
    p.ctx._dispatchWin('hashchange');
    check('P12 security: the Profile page shows the linked Gmail',
      await waitFor(() => p.el('profile-login-gmail').textContent === 'test@example.com'));
  }

  // ---- §15. Review fixes (2026-11-07): D1–D6, D12–D14 + improvements ----
  // D1: "today" is the local calendar date, not UTC.
  check('D1: localDateStr builds from local parts, not UTC',
    M.localDateStr(new Date(2026, 10, 7, 2, 56)) === '2026-11-07'
    && M.localDateStr(new Date(2026, 0, 5, 23, 59)) === '2026-01-05');
  check('D1: the Pakistan date for a fixed 02:56 PKT instant is Nov 7, not Nov 6 (TZ child process)',
    await (async () => {
      try {
        const out = require('node:child_process').execFileSync('node', ['-e',
          "const M=require(require('node:path').join(process.argv[1],'public','model.js'));"
          + "const now=new Date();"
          + "console.log(M.localDateStr(new Date('2026-11-07T02:56:00+05:00')));"
          + "console.log(M.todayStr());"
          + "console.log(new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Karachi',year:'numeric',month:'2-digit',day:'2-digit'}).format(now));",
          __dirname],
        { env: { ...process.env, TZ: 'Asia/Karachi' }, encoding: 'utf8' }).trim().split('\n');
        return out.length === 3 && out[0] === '2026-11-07' && out[1] === out[2];
      } catch (_e) { return false; }
    })());
  // D2: a big advance never makes the net negative — the shortfall carries.
  {
    const v = M.emptyVault();
    const s = M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 });
    M.addAdvance(v, s.id, { amount: 20000, date: '2026-11-01', recovery: 'full' });
    const w = M.payWorkingForHelper(s, '2026-11');
    check('D2: Rs 15,000 salary + Rs 20,000 advance shows net Rs 0, Rs 5,000 carries',
      w.netPkr === 0 && w.advanceRecovery === 15000 && w.advanceCarriedPkr === 5000, w);
    const rec = M.markMonthPaid(v, s.id, '2026-11', '2026-11-30');
    check('D2: marking paid recovers only Rs 15,000 — recoveredPkr never grows past the salary',
      rec.netPkr === 0 && s.advances[0].recoveredPkr === 15000 && M.advanceRemaining(s.advances[0]) === 5000);
    check('D2: the carried Rs 5,000 is recovered from the next month (net Rs 10,000)',
      M.computeMonthPay(v, s.id, '2026-12').advanceRecovery === 5000
      && M.computeMonthPay(v, s.id, '2026-12').netPkr === 10000);
    check('D2: the pay statement names the carry-forward',
      M.staffPayStatement(s, '2026-11').includes('Rs 5,000 of this advance carries to next month'));
    const v2 = M.emptyVault();
    const s2 = M.addStaff(v2, { name: 'Bilal', role: 'maid', salaryPkr: 15000, joinedDate: '2026-10-01', leavePerMonth: 0 });
    for (let d = 1; d <= 31; d++) M.markAttendance(v2, s2.id, '2026-10-' + String(d).padStart(2, '0'), 'absent');
    check('D2: absence deductions alone never push the net below Rs 0 either',
      M.computeMonthPay(v2, s2.id, '2026-10').netPkr === 0);
  }
  // D3: an advance is recovered only from its own month onward.
  {
    const v = M.emptyVault();
    const s = M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-10-01', leavePerMonth: 2 });
    M.addAdvance(v, s.id, { amount: 3000, date: '2026-11-20', recovery: 'full' });
    check('D3: an advance dated Nov 20 is not recovered from October pay',
      M.computeMonthPay(v, s.id, '2026-10').advanceRecovery === 0
      && M.computeMonthPay(v, s.id, '2026-10').netPkr === 15000);
    const rec = M.markMonthPaid(v, s.id, '2026-10', '2026-10-31');
    check('D3: marking October paid leaves the November advance untouched',
      rec.netPkr === 15000 && s.advances[0].recoveredPkr === 0);
    check('D3: the advance is recovered in full from November pay',
      M.computeMonthPay(v, s.id, '2026-11').advanceRecovery === 3000);
  }
  // D4: no attendance before the join date, none in the future; old
  // pre-join marks never deduct (the review's own example).
  {
    const v = M.emptyVault();
    const s = M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-16', leavePerMonth: 2 });
    s.attendance['2026-11-02'] = 'absent';
    s.attendance['2026-11-03'] = 'absent';
    s.attendance['2026-11-04'] = 'absent';
    const w = M.computeMonthPay(v, s.id, '2026-11');
    check('D4: absents marked before the join date never deduct (net Rs 7,500, not Rs 7,000)',
      w.absentDays === 0 && w.salaryPkr === 7500 && w.netPkr === 7500, w);
  }
  {
    const v = M.emptyVault();
    const s = M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-06', leavePerMonth: 2 });
    check('D4: attendance before the join date is refused',
      throwsCode(() => M.markAttendance(v, s.id, '2026-11-05', 'absent'), 'VALIDATION'));
    const tomorrow = (() => {
      const d = new Date(Date.now() + 86400000);
      return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0')
        + '-' + String(d.getDate()).padStart(2, '0');
    })();
    check('D4: attendance in the future is refused',
      throwsCode(() => M.markAttendance(v, s.id, tomorrow, 'absent'), 'VALIDATION'));
    check('D4: attendance on the join date itself works',
      M.markAttendance(v, s.id, '2026-11-06', 'absent').mark === 'absent');
  }
  // D6: delete + salary edit, refusing locked months (date-relative, so
  // the suite stays green whatever day it runs).
  {
    const curMonth = M.todayStr().slice(0, 7);
    const curDate = M.todayStr();
    const v = M.emptyVault();
    const s = M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 });
    const adv = M.addAdvance(v, s.id, { amount: 2000, date: curDate, recovery: 'full' });
    check('D6: deleteAdvance removes the advance while its month is unpaid',
      M.deleteAdvance(v, s.id, adv.id).id === adv.id && s.advances.length === 0);
    check('D6: deleteAdvance of a missing advance fails (NOT_FOUND)',
      throwsCode(() => M.deleteAdvance(v, s.id, 'nope'), 'NOT_FOUND'));
    const adv2 = M.addAdvance(v, s.id, { amount: 2000, date: curDate, recovery: 'full' });
    M.markMonthPaid(v, s.id, curMonth, curDate);
    check('D6: deleteAdvance refuses once its month is marked paid',
      throwsCode(() => M.deleteAdvance(v, s.id, adv2.id), 'LOCKED'));
    check('D6: deleteStaff refuses a helper with a paid month',
      throwsCode(() => M.deleteStaff(v, s.id), 'LOCKED'));
    check('D6: updateStaffSalary refuses while the current month is paid',
      throwsCode(() => M.updateStaffSalary(v, s.id, 16000), 'LOCKED'));
    const v2 = M.emptyVault();
    const s2 = M.addStaff(v2, { name: 'Bilal', role: 'driver', salaryPkr: 10000, joinedDate: '2026-11-01', leavePerMonth: 2 });
    check('D6: updateStaffSalary changes the salary on an open month',
      M.updateStaffSalary(v2, s2.id, 12000).salaryPkr === 12000
      && M.computeMonthPay(v2, s2.id, curMonth).salaryPkr === 12000);
    check('D6: updateStaffSalary refuses a bad salary',
      throwsCode(() => M.updateStaffSalary(v2, s2.id, 0), 'VALIDATION'));
    check('D6: deleteStaff removes a helper with no paid months',
      M.deleteStaff(v2, s2.id).id === s2.id && v2.staff.length === 0);
    const d = M.addDelivery(v, { name: 'Doodhwala', kind: 'Doodhwala', unit: 'litre', ratePkr: 220, usualQty: 1 });
    check('D6: deleteDelivery removes a delivery with no paid months',
      M.deleteDelivery(v, d.id).id === d.id && v.deliveries.length === 0);
    const d2 = M.addDelivery(v, { name: 'Gas', kind: 'Gas cylinder', unit: 'cylinder', ratePkr: 3000, usualQty: 1 });
    M.markDeliveryMonthPaid(v, d2.id, curMonth, curDate);
    check('D6: deleteDelivery refuses a delivery with a paid month',
      throwsCode(() => M.deleteDelivery(v, d2.id), 'LOCKED'));
    const p = M.addUdhaarPerson(v, { person: 'Ahmed' });
    const e = M.addUdhaarEntry(v, p.id, { direction: 'lent', amountPkr: 5000, date: '2026-11-01' });
    check('D6: deleteUdhaarEntry removes the entry',
      M.deleteUdhaarEntry(v, p.id, e.id).id === e.id && p.entries.length === 0);
    check('D6: deleteUdhaarPerson removes the person',
      M.deleteUdhaarPerson(v, p.id).id === p.id && v.udhaar.length === 0);
    check('D6: deleteUdhaarPerson of a missing person fails (NOT_FOUND)',
      throwsCode(() => M.deleteUdhaarPerson(v, 'nope'), 'NOT_FOUND'));
  }
  // D14: gas "days since refill" never goes negative.
  {
    const v = M.emptyVault();
    const d = M.addDelivery(v, { name: 'Gas', kind: 'Gas cylinder', unit: 'cylinder', ratePkr: 3000, usualQty: 1 });
    M.addGasRefill(v, d.id, { date: '2026-11-20', pricePkr: 3000 });
    check('D14: gas days since a future refill clamps at 0, never negative',
      M.gasDaysSinceLastRefill(d, '2026-11-07') === 0);
    check('D14: gas days since a past refill still counts',
      M.gasDaysSinceLastRefill(d, '2026-11-25') === 5);
  }
  // Improvement 9: Today shows the worked net on the staff row.
  {
    const v = M.emptyVault();
    const s = M.addStaff(v, { name: 'Ayesha', role: 'maid', salaryPkr: 15000, joinedDate: '2026-11-01', leavePerMonth: 2 });
    M.addAdvance(v, s.id, { amount: 2000, date: '2026-11-01', recovery: 'full' });
    const row = M.todayItems(v, '2026-11-25').find((i) => i.kind === 'staff');
    check('Imp9: the Today staff row shows the worked net, not just the salary',
      !!row && row.detail.includes('Rs 13,000 net payable') && row.detail.includes('Rs 15,000 salary'), row && row.detail);
  }
  // Improvement 10: an undated udhaar row carries the "no due date" label.
  check('Imp10: dueLabel says "no due date" for an undated row',
    M.dueLabel({ noDueDate: true }) === 'no due date');
  // Improvement 12: medicine quantities in 0.5 steps; a dose is still 1.
  {
    const v = M.emptyVault();
    check('Imp12: a medicine with 10.5 tablets is accepted (0.5 steps)',
      M.addMedicine(v, { name: 'Panadol', qtyLeft: 10.5, unit: 'tablets', expiryDate: '2027-06-01' }).qtyLeft === 10.5);
    check('Imp12: a medicine with 10.25 tablets is refused',
      throwsCode(() => M.addMedicine(v, { name: 'X', qtyLeft: 10.25, expiryDate: '2027-06-01' }), 'VALIDATION'));
    const med = M.addMedicine(v, { name: 'Half', qtyLeft: 0.5, unit: 'tablets', expiryDate: '2027-06-01' });
    check('Imp12: a dose tick from 0.5 left is refused (a dose is a whole tablet)',
      throwsCode(() => M.recordDose(v, med.id, { date: '2026-11-07', time: '08:00' }), 'VALIDATION'));
    check('Imp12: a dose tick from 1.5 leaves 0.5',
      (() => {
        const m2 = M.addMedicine(v, { name: 'OneHalf', qtyLeft: 1.5, unit: 'tablets', expiryDate: '2027-06-01' });
        M.recordDose(v, m2.id, { date: '2026-11-07', time: '08:00' });
        return m2.qtyLeft === 0.5;
      })());
  }
  // D10: the dead CSV import half is gone; the export half still works.
  check('D10: csv.js has no dead import half left (CsvImport, guessMapping, markDuplicates)',
    !/CsvImport|guessMapping|markDuplicates|rowsToTransactions|parseAmountCell|parseDateCell/.test(
      fs.readFileSync(path.join(__dirname, 'public', 'csv.js'), 'utf8'))
    && typeof C.parseCsv === 'function' && typeof C.rowsToCsv === 'function'
    && typeof C.buildCombinedCsv === 'function' && C.CsvImport === undefined);
  // D7 + D8: the fixed copy is on the page.
  check('D7: the Home page says deleting the spare key stops recovery, not the book',
    htmlSrc.includes('If the spare key file is deleted, forgot-code recovery stops working — the book still opens with your code'));
  check('D8: the Security page says PIN (and passphrase, if you set one)',
    htmlSrc.includes('The book opens with your PIN (and passphrase, if you set one)'));
  // D4 / D6 / Imp7 / Imp8 / Imp11 / D13 in the fake DOM.
  {
    const p = portalCtx();
    await registerIn(p, 'test@example.com', '123456');
    p.ctx.location.hash = '#/staff';
    p.ctx._dispatchWin('hashchange');
    p.el('staff-month').value = '2026-05';
    p.el('staff-month').dispatch('change');
    p.el('staff-name').value = 'Ayesha';
    p.el('staff-role').value = 'maid';
    p.el('staff-salary').value = '15000';
    p.el('staff-joined').value = '2026-05-01';
    p.el('staff-leave').value = '2';
    p.el('staff-add-btn').click();
    await waitFor(() => p.el('staff-add-ok').textContent.includes('Helper added'));
    // D4 UI: future-day buttons are disabled (fake today is May 28).
    const staffHtml = () => p.el('staff-list').innerHTML;
    check('D4 UI: future-day attendance buttons are disabled, today is not',
      staffHtml().includes('data-date="2026-05-29" disabled')
      && staffHtml().includes('data-date="2026-05-31" disabled')
      && !staffHtml().includes('data-date="2026-05-28" disabled'));
    const helperId = (() => {
      const m = staffHtml().match(/data-helper="([^"]+)"/);
      return m ? m[1] : null;
    })();
    check('D4 UI: the helper card carries a helper id', !!helperId);
    // D6 UI: advance delete (two-tap), salary change, helper delete (two-tap).
    p.el('adv-helper').value = helperId;
    p.el('adv-amount').value = '2000';
    p.el('adv-date').value = '2026-05-05';
    p.el('adv-add-btn').click();
    await waitFor(() => p.el('adv-ok').textContent.includes('Advance recorded')
      && staffHtml().includes('Remaining advance: Rs 2,000'));
    const advId = (() => {
      const m = staffHtml().match(/data-advance="([^"]+)"/);
      return m ? m[1] : null;
    })();
    p.el('staff-list').dispatch('click',
      { target: { dataset: { action: 'advdel', helper: helperId, advance: advId }, parentElement: null } });
    await sleep(50);
    check('D6 UI: first delete tap on an advance only arms it',
      staffHtml().includes('Tap again to delete') && staffHtml().includes('Remaining advance: Rs 2,000'));
    p.el('staff-list').dispatch('click',
      { target: { dataset: { action: 'advdel', helper: helperId, advance: advId }, parentElement: null } });
    check('D6 UI: second delete tap removes the advance',
      await waitFor(() => p.el('staff-add-ok').textContent.includes('Advance deleted')
        && staffHtml().includes('No advances')));
    p.el('salary-helper').value = helperId;
    p.el('salary-new').value = '16000';
    p.el('salary-save-btn').click();
    check('D6 UI: changing the salary updates the helper card',
      await waitFor(() => p.el('salary-ok').textContent.includes('Salary changed')
        && staffHtml().includes('Rs 16,000')));
    p.el('staff-list').dispatch('click',
      { target: { dataset: { action: 'staffdel', helper: helperId }, parentElement: null } });
    await sleep(50);
    check('D6 UI: first delete tap on a helper only arms it',
      staffHtml().includes('Tap again to delete') && staffHtml().includes('Ayesha'));
    p.el('staff-list').dispatch('click',
      { target: { dataset: { action: 'staffdel', helper: helperId }, parentElement: null } });
    check('D6 UI: second delete tap removes the helper',
      await waitFor(() => p.el('staff-add-ok').textContent.includes('Helper deleted')
        && p.visible('staff-empty')));
    // Imp7 + Imp8: log the whole week, then the whole month (fake today
    // is Thursday May 28: the week is Mon May 25 – Thu May 28, 4 days).
    p.ctx.location.hash = '#/deliveries';
    p.ctx._dispatchWin('hashchange');
    p.el('del-month').value = '2026-05';
    p.el('del-month').dispatch('change');
    p.el('del-name').value = 'Doodhwala';
    p.el('del-kind').value = 'Doodhwala';
    p.el('del-unit').value = 'litre';
    p.el('del-rate').value = '220';
    p.el('del-qty').value = '1';
    p.el('del-add-btn').click();
    await waitFor(() => p.el('del-add-ok').textContent.includes('Delivery added'));
    const delId = (() => {
      const m = p.el('log-delivery').innerHTML.match(/value="([^"]+)"/);
      return m ? m[1] : null;
    })();
    p.el('log-delivery').value = delId;
    p.el('log-week-btn').click();
    check('Imp7 UI: Log this whole week fills the unlogged days of the current week at the usual quantity',
      await waitFor(() => p.el('log-ok').textContent.includes('Logged 4 days')));
    p.el('log-month-btn').click();
    check('Imp7 UI: Log this whole month fills the rest of the month',
      await waitFor(() => p.el('log-ok').textContent.includes('Logged 24 days')));
    const delHtml = () => p.el('deliveries-list').innerHTML;
    check('Imp8 UI: the delivery bill shows the days not logged yet (31 − 28 = 3)',
      delHtml().includes('28 days logged') && delHtml().includes('3 days not logged yet')
      && delHtml().includes('Rs 6,160'));
    // D6 UI: delivery delete (two-tap).
    p.el('deliveries-list').dispatch('click',
      { target: { dataset: { action: 'deldel', delivery: delId }, parentElement: null } });
    await sleep(50);
    check('D6 UI: first delete tap on a delivery only arms it',
      delHtml().includes('Tap again to delete') && delHtml().includes('Doodhwala'));
    p.el('deliveries-list').dispatch('click',
      { target: { dataset: { action: 'deldel', delivery: delId }, parentElement: null } });
    check('D6 UI: second delete tap removes the delivery',
      await waitFor(() => p.el('del-add-ok').textContent.includes('Delivery deleted')
        && p.visible('deliveries-empty')));
    // D6 UI: udhaar entry + person delete (two-tap each).
    p.ctx.location.hash = '#/udhaar';
    p.ctx._dispatchWin('hashchange');
    p.el('udh-person-name').value = 'Ahmed';
    p.el('udh-person-add-btn').click();
    await waitFor(() => p.el('udh-person-ok').textContent.includes('Person added'));
    const udhHtml = () => p.el('udhaar-list').innerHTML;
    const personId = (() => {
      const m = p.el('udh-entry-person').innerHTML.match(/value="([^"]+)"/);
      return m ? m[1] : null;
    })();
    p.el('udh-entry-person').value = personId;
    p.el('udh-entry-direction').value = 'lent';
    p.el('udh-entry-amount').value = '5000';
    p.el('udh-entry-date').value = '2026-05-01';
    p.el('udh-entry-add-btn').click();
    await waitFor(() => p.el('udh-entry-ok').textContent.includes('Entry added'));
    const entryId = (() => {
      const m = udhHtml().match(/data-entry="([^"]+)"/);
      return m ? m[1] : null;
    })();
    p.el('udhaar-list').dispatch('click',
      { target: { dataset: { action: 'udhentrydel', person: personId, entry: entryId }, parentElement: null } });
    await sleep(50);
    check('D6 UI: first delete tap on an udhaar entry only arms it',
      udhHtml().includes('Tap again to delete') && udhHtml().includes('Rs 5,000 left'));
    p.el('udhaar-list').dispatch('click',
      { target: { dataset: { action: 'udhentrydel', person: personId, entry: entryId }, parentElement: null } });
    check('D6 UI: second delete tap removes the udhaar entry',
      await waitFor(() => p.el('udh-entry-ok').textContent.includes('Entry deleted')
        && udhHtml().includes('No entries for this person yet')));
    p.el('udhaar-list').dispatch('click',
      { target: { dataset: { action: 'udhpersondel', person: personId }, parentElement: null } });
    await sleep(50);
    check('D6 UI: first delete tap on an udhaar person only arms it',
      udhHtml().includes('Tap again to delete') && udhHtml().includes('Ahmed'));
    p.el('udhaar-list').dispatch('click',
      { target: { dataset: { action: 'udhpersondel', person: personId }, parentElement: null } });
    check('D6 UI: second delete tap removes the udhaar person',
      await waitFor(() => p.el('udh-person-ok').textContent.includes('Person deleted')
        && p.visible('udhaar-empty')));
    // Imp11: sidebar initials follow the household name (fallback "V").
    check('Imp11 UI: sidebar initials fall back to "V" with no household name',
      p.el('sidebar-initials').textContent === 'V');
    p.ctx.location.hash = '#/profile';
    p.ctx._dispatchWin('hashchange');
    p.el('profile-household').value = 'Hashir Home';
    p.el('profile-save-btn').click();
    check('Imp11 UI: sidebar initials use the household name\u2019s first letter',
      await waitFor(() => p.el('profile-ok').textContent.includes('Saved')
        && p.el('sidebar-initials').textContent === 'H'));
    // D13: the Add button is disabled while a big photo is shrinking.
    p.ctx.location.hash = '#/documents';
    p.ctx._dispatchWin('hashchange');
    p.el('doc-photo').files = [{ _dataUrl: bigJpeg }];
    p.el('doc-photo').dispatch('change');
    check('D13 UI: the Add button is disabled while a photo is shrinking',
      p.el('doc-add-btn').disabled === true);
    await sleep(50);
    check('D13 UI: the Add button is back on after the shrink fails, with a plain error',
      p.el('doc-add-btn').disabled === false && p.el('doc-add-error').textContent !== '');
  }
  // D12: restoring a different book's backup clears the portal account.
  {
    const p = portalCtx();
    await registerIn(p, 'test@example.com', '123456');
    const other = await V.createVault('654321', '', SAMPLE);
    const backup = V.createBackup(other.envelope);
    p.ctx.location.hash = '#/backup';
    p.ctx._dispatchWin('hashchange');
    p.el('import-file').files = [{ _text: JSON.stringify(backup) }];
    p.el('import-file').dispatch('change');
    check('D12 UI: the backup file reads and asks for its PIN',
      await waitFor(() => p.el('backup-ok').textContent.includes('Backup file read')));
    p.el('import-pin').value = '654321';
    p.el('import-btn').click();
    check('D12 UI: restoring a different book clears the old login Gmail',
      await waitFor(() => p.el('backup-ok').textContent.includes('Backup restored')
        && p.store.get(V.ACCOUNT_KEY) == null));
    p.ctx.location.hash = '#/profile';
    p.ctx._dispatchWin('hashchange');
    check('D12 UI: the Profile page shows no login Gmail after the restore',
      await waitFor(() => p.visible('profile-login-gmail-none')));
  }
  // D12 wrinkle: the restore clears the browser account, but the server
  // still holds the OLD book's recovery.key + account.json — re-linking
  // the restored book used to hit ALREADY_SET with no way forward.
  // First tap prompts (nothing overwritten), second tap re-binds.
  {
    const p = portalCtx();
    await registerIn(p, 'test@example.com', '123456');
    const other = await V.createVault('654321', '', SAMPLE);
    const backup = V.createBackup(other.envelope);
    p.ctx.location.hash = '#/backup';
    p.ctx._dispatchWin('hashchange');
    p.el('import-file').files = [{ _text: JSON.stringify(backup) }];
    p.el('import-file').dispatch('change');
    await waitFor(() => p.el('backup-ok').textContent.includes('Backup file read'));
    p.el('import-pin').value = '654321';
    p.el('import-btn').click();
    await waitFor(() => p.el('backup-ok').textContent.includes('Backup restored'));
    // The server still has the OLD book's recovery binding.
    p.ctx._setSetupConflict(true);
    p.ctx.location.hash = '#/security';
    p.ctx._dispatchWin('hashchange');
    check('D12 UI: after a restore, Security offers to link a Gmail',
      await waitFor(() => p.el('recovery-status').textContent.includes('no Gmail linked yet')));
    p.el('security-pin').value = '654321';
    p.el('recovery-gmail').value = 'test@example.com';
    p.el('recovery-send-btn').click();
    await waitFor(() => p.el('recovery-otp-note').textContent.includes('test@example.com'));
    p.el('recovery-otp').value = '123456';
    p.el('recovery-verify-btn').click();
    check('D12 UI: re-linking after a restore prompts instead of failing silently',
      await waitFor(() => p.el('recovery-error').textContent.includes('already has forgot-code recovery for a different book')));
    check('D12 UI: the first tap does NOT re-bind (no account saved, no rebind call)',
      p.store.get(V.ACCOUNT_KEY) == null
      && !p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/recover/setup') && c.body.rebind === true));
    p.el('recovery-verify-btn').click();
    check('D12 UI: the second tap re-binds recovery to the restored book',
      await waitFor(() => p.el('recovery-ok').textContent.includes('recovery moved to this book')));
    check('D12 UI: the re-bound account is saved (Gmail + recovery on + spare envelope)',
      await (async () => {
        const raw = p.store.get(V.ACCOUNT_KEY);
        if (!raw) return false;
        const acct = JSON.parse(raw);
        return acct.gmail === 'test@example.com' && acct.recoveryOn === true && !!acct.rkEnvelope;
      })());
    check('D12 UI: the re-bind call sent rebind:true and skipped the used OTP (fetch log)',
      p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/recover/setup') && c.body.rebind === true)
      && p.ctx._fetchCalls.filter((c) => c.url.endsWith('/api/otp/verify') && c.body.purpose === 'link').length === 1);
  }
  {
    // Same re-bind through the migration screen (PIN-only book, asked
    // to link a Gmail after unlock).
    const p = portalCtx();
    p.ctx._setMailConfigured(false);
    p.el('setup-gmail').value = 'test@example.com';
    p.el('setup-pin').value = '123456'; p.el('setup-pin2').value = '123456';
    p.el('setup-btn').click();
    await waitFor(() => p.visible('setup-fallback-btn'));
    p.el('setup-fallback-btn').click();
    await waitFor(() => p.visible('vault-screen'));
    p.ctx._setSetupConflict(true);
    p.el('lock-btn').click();
    p.ctx._setMailConfigured(true);
    p.el('unlock-pin').value = '123456';
    p.el('unlock-btn').click();
    check('D12 UI: migration screen offers Send code after a lock + unlock',
      await waitFor(() => p.visible('migration-screen') && p.visible('mig-send-btn')));
    p.el('mig-gmail').value = 'test@example.com';
    p.el('mig-send-btn').click();
    await waitFor(() => p.visible('mig-otp-section')
      && p.el('mig-otp-note').textContent.includes('test@example.com'));
    p.el('mig-otp').value = '123456';
    p.el('mig-verify-btn').click();
    check('D12 UI: migration link prompts to re-bind when the server has another book',
      await waitFor(() => p.el('mig-error').textContent.includes('already has forgot-code recovery for a different book')));
    check('D12 UI: the first migration tap does not re-bind (still on migration, no rebind call)',
      p.visible('migration-screen')
      && !p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/recover/setup') && c.body.rebind === true));
    p.el('mig-verify-btn').click();
    check('D12 UI: the second migration tap re-binds and opens the book',
      await waitFor(() => p.visible('vault-screen')));
    check('D12 UI: the migration re-bind saved the account (fetch log + store)',
      p.ctx._fetchCalls.some((c) => c.url.endsWith('/api/recover/setup') && c.body.rebind === true)
      && JSON.parse(p.store.get(V.ACCOUNT_KEY)).recoveryOn === true);
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  if (failed > 0) { console.log('TESTS FAILED'); process.exit(1); }
  console.log('ALL TESTS PASSED');
}

main().catch((e) => { console.error('TEST RUNNER ERROR', e); process.exit(1); });
