// Personal Card Vault tests. Run: node test.js  (exit 0 = all pass)
// Tests the shared logic in public/*.js (browser + Node) and, from Step 5,
// the real server on a throwaway port.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const V = require('./public/vault.js');
const M = require('./public/model.js');
const S = require('./public/sms.js');
const C = require('./public/csv.js');
const K = require('./public/cards.js');
const I = require('./public/intel.js');
const P = require('./public/proof.js');
const T = require('./public/totp.js');
const N = require('./public/nav.js');

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
const SAMPLE = {
  v: 1, createdAt: '2026-11-06T00:00:00.000Z',
  accounts: [{ id: 'a1', provider: 'HBL', type: 'debit', nickname: 'HBL Salary', last4: '1234', balance: 150000 }],
  transactions: [], notifications: [], settings: { lowBalanceThreshold: 5000 },
};

async function main() {
  // ---- §1. Vault crypto ----
  check('PIN: 6 digits accepted', V.validPin('123456') === true);
  check('PIN: 5 digits rejected', V.validPin('12345') === false);
  check('PIN: 7 digits rejected', V.validPin('1234567') === false);
  check('PIN: letters rejected', V.validPin('12345a') === false);
  check('PIN: empty rejected', V.validPin('') === false);
  check('PIN: non-string rejected', V.validPin(123456) === false);
  check('Passphrase: empty ok', V.validPassphrase('') === true);
  check('Passphrase: 3 chars rejected', V.validPassphrase('abc') === false);
  check('Passphrase: 4 chars ok', V.validPassphrase('abcd') === true);

  // Round-trip with PIN + passphrase.
  const c1 = await V.createVault('123456', 'my secret', SAMPLE);
  check('Envelope: version/kdf/iter recorded', c1.envelope.v === 1 && c1.envelope.kdf === 'pbkdf2-sha256' && c1.envelope.iter === 600000, c1.envelope);
  const u1 = await V.unlockVault('123456', 'my secret', c1.envelope);
  check('Round-trip with passphrase: vault identical', JSON.stringify(u1.vault) === JSON.stringify(SAMPLE));
  // Round-trip with PIN only.
  const c2 = await V.createVault('654321', '', SAMPLE);
  const u2 = await V.unlockVault('654321', '', c2.envelope);
  check('Round-trip PIN only: vault identical', JSON.stringify(u2.vault) === JSON.stringify(SAMPLE));
  // Wrong PIN fails cleanly.
  check('Wrong PIN fails (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('123457', 'my secret', c1.envelope), 'DECRYPT_FAILED'));
  // Wrong passphrase fails.
  check('Wrong passphrase fails (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secreT', c1.envelope), 'DECRYPT_FAILED'));
  // Bad PIN format fails before any crypto.
  check('Unlock with bad PIN format fails (BAD_PIN)',
    await throwsCodeAsync(() => V.unlockVault('12345', '', c1.envelope), 'BAD_PIN'));
  // Tampered ciphertext is rejected.
  const tampered = JSON.parse(JSON.stringify(c1.envelope));
  const blob = V.b64ToBytes(tampered.data);
  blob[blob.length - 5] ^= 0x01; // flip one ciphertext byte
  tampered.data = V.bytesToB64(blob);
  check('Tampered ciphertext rejected (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', tampered), 'DECRYPT_FAILED'));
  // Tampered tag byte rejected.
  const tampered2 = JSON.parse(JSON.stringify(c1.envelope));
  const blob2 = V.b64ToBytes(tampered2.data);
  blob2[blob2.length - 1] ^= 0x01; // flip one tag byte
  tampered2.data = V.bytesToB64(blob2);
  check('Tampered auth tag rejected (DECRYPT_FAILED)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', tampered2), 'DECRYPT_FAILED'));
  // Corrupt envelopes rejected.
  check('Envelope with wrong version rejected (CORRUPT_VAULT)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', { ...c1.envelope, v: 99 }), 'CORRUPT_VAULT'));
  check('Envelope with bad base64 rejected (CORRUPT_VAULT)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', { ...c1.envelope, data: '!!!not-base64!!!' }), 'CORRUPT_VAULT'));
  check('Null envelope rejected (CORRUPT_VAULT)',
    await throwsCodeAsync(() => V.unlockVault('123456', 'my secret', null), 'CORRUPT_VAULT'));
  // Fresh IV per encryption: same vault + same key -> different ciphertext.
  const salt = V.saltFromEnvelope(c1.envelope);
  const key = await V.deriveKey('123456', 'my secret', salt);
  const eA = await V.encryptVault(key, salt, SAMPLE);
  const eB = await V.encryptVault(key, salt, SAMPLE);
  check('Fresh IV: two encryptions differ', eA.data !== eB.data);
  check('Both fresh encryptions decrypt', JSON.stringify((await V.decryptVault(key, eA))) === JSON.stringify(SAMPLE)
    && JSON.stringify((await V.decryptVault(key, eB))) === JSON.stringify(SAMPLE));
  // Different vaults get different salts.
  const c3 = await V.createVault('123456', 'my secret', SAMPLE);
  check('Fresh salt per vault', c3.envelope.data !== c1.envelope.data
    && V.saltFromEnvelope(c3.envelope).join(',') !== V.saltFromEnvelope(c1.envelope).join(','));
  // Same PIN, different salt -> key cannot open the other vault.
  const key3 = await V.deriveKey('123456', 'my secret', V.saltFromEnvelope(c3.envelope));
  check('Key from another salt cannot open this vault',
    await throwsCodeAsync(() => V.decryptVault(key3, c1.envelope), 'DECRYPT_FAILED'));
  // saveVault round-trip: re-encrypt under the unlocked key, unlock again.
  const saved = await V.saveVault(u1.key, c1.envelope, { ...SAMPLE, accounts: [] });
  const u3 = await V.unlockVault('123456', 'my secret', saved);
  check('saveVault round-trip: changed vault decrypts', u3.vault.accounts.length === 0);

  // ---- Lockout ----
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
  st = V.recordFailure(st, 5000); // 5th failure -> 30s lockout from now=5000
  check('Lockout: 5th failure locks for 30s', V.isLocked(st, 5000) === true && V.lockoutRemainingMs(st, 5000) === 30000, st);
  check('Lockout: still locked at 34s', V.isLocked(st, 34000) === true);
  check('Lockout: free again at 35s', V.isLocked(st, 35000) === false);
  st = V.recordFailure(st, 35000); // 6th failure -> 60s
  check('Lockout: 6th failure locks for 60s', V.lockoutRemainingMs(st, 35000) === 60000, st);
  st = V.recordSuccess();
  check('Lockout: success resets failures', st.failures === 0 && V.isLocked(st, 999999) === false);

  // ---- Auto-lock ----
  check('Auto-lock: 4m59s idle -> not locked', V.isIdleLocked(0, 4 * 60 * 1000 + 59000) === false);
  check('Auto-lock: 5m idle -> locked', V.isIdleLocked(0, 5 * 60 * 1000) === true);
  check('Auto-lock: constant is 5 minutes', V.AUTO_LOCK_MS === 300000);

  // ---- §2. Data model + balance engine ----
  const vault = M.emptyVault();
  check('Model: empty vault shape', vault.v === 1 && Array.isArray(vault.accounts)
    && Array.isArray(vault.transactions) && Array.isArray(vault.notifications)
    && vault.settings.lowBalanceThreshold === 5000, vault);
  const hbl = M.createAccount(vault, { provider: 'HBL', type: 'debit', nickname: 'HBL Salary', last4: '1234', balance: 150000 });
  check('Model: account created with id + starting balance', !!hbl.id && hbl.balance === 150000 && hbl.startingBalance === 150000, hbl);
  check('Model: bad provider rejected', M.validateAccount({ provider: 'FakeBank', type: 'debit', nickname: 'X', last4: '1234', balance: 0 }).length > 0);
  check('Model: bad type rejected', M.validateAccount({ provider: 'HBL', type: 'gold', nickname: 'X', last4: '1234', balance: 0 }).length > 0);
  check('Model: empty nickname rejected', M.validateAccount({ provider: 'HBL', type: 'debit', nickname: '  ', last4: '1234', balance: 0 }).length > 0);
  check('Model: 3-digit last4 rejected', M.validateAccount({ provider: 'HBL', type: 'debit', nickname: 'X', last4: '123', balance: 0 }).length > 0);
  check('Model: 5-digit last4 rejected', M.validateAccount({ provider: 'HBL', type: 'debit', nickname: 'X', last4: '12345', balance: 0 }).length > 0);
  check('Model: letters in last4 rejected', M.validateAccount({ provider: 'HBL', type: 'debit', nickname: 'X', last4: '12a4', balance: 0 }).length > 0);
  check('Model: full 16-digit number in last4 rejected',
    M.validateAccount({ provider: 'HBL', type: 'debit', nickname: 'X', last4: '0000000000000000', balance: 0 }).length > 0);
  check('Model: full 16-digit number in nickname rejected',
    M.validateAccount({ provider: 'HBL', type: 'debit', nickname: 'card 0000000000000000', last4: '4454', balance: 0 }).length > 0);
  check('Model: CVV key rejected',
    M.validateAccount({ provider: 'HBL', type: 'debit', nickname: 'X', last4: '1234', balance: 0, cvv: '123' }).length > 0);
  check('Model: NaN balance rejected', M.validateAccount({ provider: 'HBL', type: 'debit', nickname: 'X', last4: '1234', balance: NaN }).length > 0);
  check('Model: sensitive scan flags 16 digits, not 4', M.containsSensitiveValue('0000000000000000') === true && M.containsSensitiveValue('1234') === false);
  // Balance engine — hand-computed cases.
  const t1 = M.addTransaction(vault, { accountId: hbl.id, amount: 2500, direction: 'debit', merchant: 'Imtiaz Super Market', category: 'food', date: '2026-11-06', source: 'manual' });
  check('Model: new transaction starts pending', t1.status === 'pending');
  check('Model: pending transaction does not change balance', hbl.balance === 150000);
  M.approveTransaction(vault, t1.id);
  check('Model: debit 2500 from 150000 -> 147500', hbl.balance === 147500, hbl.balance);
  const t2 = M.addTransaction(vault, { accountId: hbl.id, amount: 10000, direction: 'credit', merchant: 'Salary', category: 'transfer', date: '2026-11-06', source: 'manual' });
  M.approveTransaction(vault, t2.id);
  check('Model: credit 10000 -> 157500', hbl.balance === 157500, hbl.balance);
  check('Model: approve is idempotent (no double apply)', M.approveTransaction(vault, t2.id) === false && hbl.balance === 157500);
  M.deleteTransaction(vault, t2.id);
  check('Model: deleting approved credit reverses it -> 147500', hbl.balance === 147500, hbl.balance);
  const t3 = M.addTransaction(vault, { accountId: hbl.id, amount: 999, direction: 'debit', merchant: 'Test', date: '2026-11-06', source: 'manual' });
  M.deleteTransaction(vault, t3.id);
  check('Model: deleting pending changes nothing', hbl.balance === 147500 && vault.transactions.length === 1);
  check('Model: approve unknown transaction throws',
    throwsCode(() => M.approveTransaction(vault, 'nope'), 'NOT_FOUND'));
  check('Model: transaction on unknown account throws',
    throwsCode(() => M.addTransaction(vault, { accountId: 'nope', amount: 1, direction: 'debit', date: '2026-11-06', source: 'manual' }), 'NOT_FOUND'));
  check('Model: zero amount rejected', M.validateTransaction({ accountId: hbl.id, amount: 0, direction: 'debit', date: '2026-11-06', source: 'manual' }).length > 0);
  check('Model: bad date rejected', M.validateTransaction({ accountId: hbl.id, amount: 5, direction: 'debit', date: '06/11/2026', source: 'manual' }).length > 0);
  check('Model: bad direction rejected', M.validateTransaction({ accountId: hbl.id, amount: 5, direction: 'spent', date: '2026-11-06', source: 'manual' }).length > 0);
  // Notifications + low-balance crossing.
  const ez = M.createAccount(vault, { provider: 'Easypaisa', type: 'wallet', nickname: 'Easypaisa daily', last4: '9876', balance: 6000 });
  check('Model: notifications recorded for approvals', vault.notifications.some((n) => n.kind === 'transaction' && n.text.includes('Imtiaz')));
  const t4 = M.addTransaction(vault, { accountId: ez.id, amount: 2000, direction: 'debit', merchant: 'Utility bill', date: '2026-11-06', source: 'manual' });
  M.approveTransaction(vault, t4.id);
  check('Model: low-balance alert fires on crossing below 5000',
    vault.notifications.some((n) => n.kind === 'low-balance' && n.text.includes('Easypaisa daily')), vault.notifications);
  const t5 = M.addTransaction(vault, { accountId: ez.id, amount: 500, direction: 'debit', merchant: 'Chai', date: '2026-11-06', source: 'manual' });
  M.approveTransaction(vault, t5.id);
  check('Model: no duplicate low-balance alert while already below',
    vault.notifications.filter((n) => n.kind === 'low-balance').length === 1);
  // Totals + reconcile.
  const tot = M.totals(vault);
  check('Model: totals reconcile (147500 + 3500 = 151000)', tot.total === 151000 && tot.byProvider.HBL === 147500 && tot.byProvider.Easypaisa === 3500, tot);
  check('Model: reconcile clean after real operations', M.reconcile(vault).ok === true);
  hbl.balance = 999999; // corrupt one balance by hand
  const rec = M.reconcile(vault);
  check('Model: reconcile catches a corrupted balance', rec.ok === false && rec.mismatches.length === 1 && rec.mismatches[0].computed === 147500, rec);
  hbl.balance = 147500; // repair
  check('Model: reconcile clean again after repair', M.reconcile(vault).ok === true);
  check('Model: threshold validation rejects negative', throwsCode(() => M.setLowBalanceThreshold(vault, -1), 'VALIDATION'));
  check('Model: threshold set + read back', M.setLowBalanceThreshold(vault, 10000) === 10000);

  // ---- §3. SMS parser + CSV import ----
  const SMS_CASES = [
    ['HBL', 'Dear Customer, your HBL Debit Card ending 1234 was used for Rs. 2,500.00 at IMTIAZ SUPER MARKET on 06-Nov-2026. Available balance: Rs. 147,500.00. For queries call 111-111-425.',
      { amount: 2500, direction: 'debit', merchant: 'IMTIAZ SUPER MARKET', date: '2026-11-06', availableBalance: 147500, last4: '1234' }],
    ['Meezan', 'Meezan Bank: Rs. 15,000.00 debited from your account ending 5678 on 06-Nov-2026 at AL-FATAH STORE. Available balance Rs. 82,340.00',
      { amount: 15000, direction: 'debit', merchant: 'AL-FATAH STORE', date: '2026-11-06', availableBalance: 82340, last4: '5678' }],
    ['UBL', 'UBL: PKR 3,200.00 has been debited from your account ending 4321 on 06-Nov-26 at PIZZA HUT. Available balance PKR 45,120.50',
      { amount: 3200, direction: 'debit', merchant: 'PIZZA HUT', date: '2026-11-06', availableBalance: 45121, last4: '4321' }],
    ['MCB', 'MCB: Your account 8765 debited PKR 7,800.00 on 06-NOV-2026 at SHELL PETROL PUMP. Available balance: PKR 210,000.00',
      { amount: 7800, direction: 'debit', merchant: 'SHELL PETROL PUMP', date: '2026-11-06', availableBalance: 210000, last4: '8765' }],
    ['Allied', 'ABL: Rs. 1,200.00 debited from A/C 2468 on 06-Nov-2026. Avail Bal: Rs. 33,400.00',
      { amount: 1200, direction: 'debit', merchant: '', date: '2026-11-06', availableBalance: 33400, last4: '2468' }],
    ['Bank Alfalah', 'Bank Alfalah: PKR 9,999.00 debited from your account 1357 on 06-Nov-2026 at CARREFOUR. Available balance PKR 120,500.00',
      { amount: 9999, direction: 'debit', merchant: 'CARREFOUR', date: '2026-11-06', availableBalance: 120500, last4: '1357' }],
    ['Askari', 'Askari Bank: Rs. 4,450.00 debited from account 9753 on 06-Nov-2026. Avail Bal Rs. 67,890.00',
      { amount: 4450, direction: 'debit', merchant: '', date: '2026-11-06', availableBalance: 67890, last4: '9753' }],
    ['JazzCash', 'JazzCash: You have sent Rs. 5,000.00 to ALI RAZA on 06-Nov-2026. Your new balance is Rs. 12,300.00',
      { amount: 5000, direction: 'debit', merchant: 'ALI RAZA', date: '2026-11-06', availableBalance: 12300, last4: null }],
    ['Easypaisa', 'Easypaisa: Rs. 2,000.00 paid to KE ELECTRIC on 06-Nov-2026. Your balance is Rs. 8,750.00',
      { amount: 2000, direction: 'debit', merchant: 'KE ELECTRIC', date: '2026-11-06', availableBalance: 8750, last4: null }],
    ['SadaPay', 'SadaPay: Rs. 1,850.00 spent at FOODPANDA on 06-Nov-2026. Balance: Rs. 22,400.00',
      { amount: 1850, direction: 'debit', merchant: 'FOODPANDA', date: '2026-11-06', availableBalance: 22400, last4: null }],
    ['NayaPay', 'NayaPay: Payment of Rs. 3,300.00 to DARAZ on 06-Nov-2026. New balance Rs. 15,600.00',
      { amount: 3300, direction: 'debit', merchant: 'DARAZ', date: '2026-11-06', availableBalance: 15600, last4: null }],
  ];
  for (const [provider, text, exp] of SMS_CASES) {
    const p = S.parseSms(text);
    check('SMS ' + provider + ': parses amount/direction/merchant/date/balance/last4',
      !!p && p.provider === provider && p.amount === exp.amount && p.direction === exp.direction
      && p.merchant === exp.merchant && p.date === exp.date
      && p.availableBalance === exp.availableBalance && p.last4 === exp.last4, p);
  }
  const credit = S.parseSms('UBL: PKR 50,000.00 has been credited to your account ending 4321 on 06-Nov-26 from SALARY - ABC COMPANY. Available balance PKR 95,120.50');
  check('SMS credit: direction credit, merchant from sender',
    !!credit && credit.direction === 'credit' && credit.amount === 50000 && credit.merchant === 'SALARY - ABC COMPANY', credit);
  check('SMS garbage parses nothing', S.parseSms('hello, how are you today?') === null);
  check('SMS with no amount parses nothing', S.parseSms('HBL: your account was debited yesterday at the store.') === null);
  check('SMS OTP is never parsed', S.parseSms('Your HBL OTP is 482917. Do not share it with anyone.') === null);
  check('SMS empty parses nothing', S.parseSms('   ') === null);
  check('SMS date: DD/MM/YYYY understood', S.parseDateStr('spent on 06/11/2026 at store') === '2026-11-06');
  check('SMS date: 2-digit year understood', S.parseDateStr('on 06-Nov-26') === '2026-11-06');
  // SMS draft flows through the model: approve updates the balance.
  const smsVault = M.emptyVault();
  const smsAcct = M.createAccount(smsVault, { provider: 'HBL', type: 'debit', nickname: 'HBL Salary', last4: '1234', balance: 150000 });
  const draft = S.parseSms(SMS_CASES[0][1]);
  const smsTxn = M.addTransaction(smsVault, { accountId: smsAcct.id, amount: draft.amount, direction: draft.direction, merchant: draft.merchant, date: draft.date, source: 'sms' });
  check('SMS flow: draft starts pending, balance untouched', smsTxn.status === 'pending' && smsAcct.balance === 150000);
  M.approveTransaction(smsVault, smsTxn.id);
  check('SMS flow: approve updates balance 150000 -> 147500', smsAcct.balance === 147500, smsAcct.balance);
  check('SMS flow: reconcile clean', M.reconcile(smsVault).ok === true);

  // CSV import.
  const csvText = 'Date,Description,Amount,Type\r\n'
    + '06/11/2026,"IMTIAZ SUPER MARKET, GULBERG",-2500,Debit\r\n'
    + '06-Nov-2026,Salary ABC Company,50000,Credit\r\n'
    + '2026-11-05,FOODPANDA,-1850,Debit\r\n';
  const parsed = C.parseCsv(csvText);
  check('CSV: headers + 3 rows parsed', parsed.headers.join(',') === 'Date,Description,Amount,Type' && parsed.rows.length === 3, parsed);
  check('CSV: quoted comma inside merchant kept', parsed.rows[0].Description === 'IMTIAZ SUPER MARKET, GULBERG', parsed.rows[0]);
  const mapping = C.guessMapping(parsed.headers);
  check('CSV: mapping guessed from headers', mapping.date === 'Date' && mapping.amount === 'Amount' && mapping.merchant === 'Description' && mapping.direction === 'Type', mapping);
  const conv = C.rowsToTransactions(parsed, mapping, 'acct1');
  check('CSV: all rows convert, no errors', conv.drafts.length === 3 && conv.errors.length === 0, conv);
  check('CSV: DD/MM/YYYY date normalised', conv.drafts[0].date === '2026-11-06' && conv.drafts[0].amount === 2500 && conv.drafts[0].direction === 'debit', conv.drafts[0]);
  check('CSV: DD-Mon-YYYY date normalised, credit kept', conv.drafts[1].date === '2026-11-06' && conv.drafts[1].amount === 50000 && conv.drafts[1].direction === 'credit', conv.drafts[1]);
  check('CSV: ISO date kept, negative amount = debit', conv.drafts[2].date === '2026-11-05' && conv.drafts[2].direction === 'debit', conv.drafts[2]);
  const signConv = C.rowsToTransactions(
    C.parseCsv('Date,Amount,Merchant\n06/11/2026,-1200,TEST SHOP\n06/11/2026,5000,REFUND X\n'),
    { date: 'Date', amount: 'Amount', merchant: 'Merchant', direction: '' }, 'acct1');
  check('CSV: no direction column -> amount sign decides', signConv.drafts.length === 2
    && signConv.drafts[0].direction === 'debit' && signConv.drafts[1].direction === 'credit', signConv.drafts);
  const badCsv = C.rowsToTransactions(
    C.parseCsv('Date,Amount,Merchant\nnot-a-date,100,X\n06/11/2026,abc,Y\n'),
    { date: 'Date', amount: 'Amount', merchant: 'Merchant', direction: '' }, 'acct1');
  check('CSV: bad rows reported as errors, not drafts', badCsv.drafts.length === 0 && badCsv.errors.length === 2, badCsv.errors);
  check('CSV: missing date/amount mapping rejected', C.rowsToTransactions(parsed, { date: '', amount: 'Amount', merchant: '', direction: '' }, 'acct1').errors.length === 1);
  // Dedupe.
  const dupVault = M.emptyVault();
  const dupAcct = M.createAccount(dupVault, { provider: 'HBL', type: 'debit', nickname: 'HBL', last4: '1234', balance: 150000 });
  const existing = M.addTransaction(dupVault, { accountId: dupAcct.id, amount: 2500, direction: 'debit', merchant: 'IMTIAZ SUPER MARKET', date: '2026-11-06', source: 'manual' });
  M.approveTransaction(dupVault, existing.id);
  const marked = C.markDuplicates(dupVault, [
    { accountId: dupAcct.id, amount: 2500, direction: 'debit', merchant: 'IMTIAZ SUPER MARKET', date: '2026-11-06', source: 'csv' },
    { accountId: dupAcct.id, amount: 2500, direction: 'debit', merchant: 'imtiaz super market', date: '2026-11-06', source: 'csv' },
    { accountId: dupAcct.id, amount: 999, direction: 'debit', merchant: 'OTHER SHOP', date: '2026-11-06', source: 'csv' },
  ]);
  check('CSV dedupe: exact duplicate flagged', marked[0].duplicate === true);
  check('CSV dedupe: case-insensitive merchant still a duplicate', marked[1].duplicate === true);
  check('CSV dedupe: different amount not a duplicate', marked[2].duplicate === false);

  // ---- §4. Encrypted backup ----
  const backupVault = M.emptyVault();
  M.createAccount(backupVault, { provider: 'JazzCash', type: 'wallet', nickname: 'JazzCash daily', last4: '5555', balance: 12500 });
  const made = await V.createVault('112233', 'backup-pass', backupVault);
  const backup = V.createBackup(made.envelope);
  check('Backup: file shape (app/version/date/envelope)', backup.app === 'personal-card-vault'
    && backup.backupVersion === 1 && typeof backup.exportedAt === 'string' && backup.envelope === made.envelope, backup);
  const parsedEnv = V.parseBackup(JSON.stringify(backup));
  check('Backup: parse returns the same envelope', JSON.stringify(parsedEnv) === JSON.stringify(made.envelope));
  const restored = await V.unlockVault('112233', 'backup-pass', parsedEnv);
  check('Backup: export -> import round-trip restores the vault',
    JSON.stringify(restored.vault) === JSON.stringify(backupVault));
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

  // ---- §5. Review pass + server smoke ----
  // 5a. Every element ID the app JS touches exists — either in index.html
  // or created by the JS itself (innerHTML review cards).
  const appSrc = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
  const htmlSrc = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const usedIds = [...new Set([...appSrc.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]))];
  const definedIds = new Set([
    ...[...htmlSrc.matchAll(/id="([^"]+)"/g)].map((m) => m[1]),
    ...[...appSrc.matchAll(/id="([^"]+)"/g)].map((m) => m[1]),
  ]);
  const missingIds = usedIds.filter((id) => !definedIds.has(id));
  check('Review: every ID touched by app.js exists in the page', missingIds.length === 0, missingIds);
  check('Review: app.js touches a real set of IDs', usedIds.length > 40, usedIds.length);
  // 5b. Every shared-module member the app calls actually exists.
  const mods = { VaultCrypto: V, VaultModel: M, SmsParser: S, CsvImport: C, Cards: K, Intel: I, Totp: T };
  let apiOk = true; const apiMissing = [];
  for (const [name, mod] of Object.entries(mods)) {
    const used = [...new Set([...appSrc.matchAll(new RegExp(name + '\\.(\\w+)', 'g'))].map((m) => m[1]))];
    for (const fn of used) {
      if (typeof mod[fn] === 'undefined') { apiOk = false; apiMissing.push(name + '.' + fn); }
    }
  }
  check('Review: every shared-module call in app.js exists', apiOk, apiMissing);
  // 5c. No secrets, no real card data anywhere in the project sources.
  const srcFiles = [];
  (function walk(dir) {
    for (const f of fs.readdirSync(dir)) {
      const full = path.join(dir, f);
      if (fs.statSync(full).isDirectory()) { if (f !== 'data') walk(full); }
      else if (/\.(js|html|css|md|json)$/.test(f)) srcFiles.push(full);
    }
  })(__dirname);
  let secretHits = [];
  for (const f of srcFiles) {
    const src = fs.readFileSync(f, 'utf8');
    // Digit runs of 13-19 inside a single-line string literal (a full card number).
    const strRuns = [...src.matchAll(/['"][^'"\n]*?(\d{13,})[^'"\n]*?['"]/g)].map((m) => m[1]);
    // The RFC 6238 TOTP test secret ("12345678901234567890") is a published
    // test vector, not a real secret — it is allow-listed here by design.
    for (const r of strRuns) if (r !== '0000000000000000' && r !== '12345678901234567890') secretHits.push(path.basename(f) + ': ' + r);
    // Hardcoded credential-looking assignments.
    if (/['"]\s*(api[_-]?key|secret|token|password)\s*['"]\s*:\s*['"][^'"]{4,}['"]/i.test(src)) {
      secretHits.push(path.basename(f) + ': hardcoded credential');
    }
    if (/AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{16,}/.test(src)) secretHits.push(path.basename(f) + ': api key pattern');
  }
  check('Review: no full card numbers or secrets in project sources', secretHits.length === 0, secretHits);
  // 5d. The server stores nothing: no POST/PUT/DELETE routes, no database.
  const serverSrc = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  check('Review: server has no write routes (GET only)', !/req\.method === '(POST|PUT|DELETE|PATCH)'/.test(serverSrc));
  check('Review: server has no database', !/sqlite|DatabaseSync|fs\.writeFile/.test(serverSrc));

  // ---- §6. Phase 2 reel theme (glass tokens + structure) ----
  // 6a. The reel tokens are actually served in styles.css.
  const cssSrc = fs.readFileSync(path.join(__dirname, 'public', 'styles.css'), 'utf8');
  const cssTokens = [
    ['warm photo background', cssSrc.includes('url("/bg.jpg")')],
    ['frosted glass gradient', cssSrc.includes('linear-gradient(135deg, rgba(255,252,246,.88), rgba(255,248,238,.72))')],
    ['heavy backdrop blur', cssSrc.includes('blur(18px)')],
    ['20px glass radius', cssSrc.includes('border-radius: 20px')],
    ['black pill button', cssSrc.includes('background: #111827')],
    ['green success token', cssSrc.includes('#14532d')],
    ['card visual class', cssSrc.includes('.card-visual')],
    ['per-provider gradients', cssSrc.includes('.card-easypaisa') && cssSrc.includes('.card-jazzcash') && cssSrc.includes('.card-hbl') && cssSrc.includes('.card-payoneer')],
    ['stepper styles', cssSrc.includes('.stepper')],
    ['securing overlay + shimmer', cssSrc.includes('.securing-overlay') && cssSrc.includes('@keyframes shimmer')],
    ['green success card', cssSrc.includes('.card-visual.success')],
    ['no leftover Phase 1 plain account rows', !cssSrc.includes('.acct')],
    ['trust badges under the carousel', cssSrc.includes('.badges') && htmlSrc.includes('PBKDF2 · AES-256-GCM')],
    ['no dark-navy Ciral theme left', !cssSrc.includes('#0b1220') && !cssSrc.includes('#60a5fa')],
  ];
  for (const [name, ok] of cssTokens) check('Theme: ' + name, ok);
  check('Theme: bg photo exists on disk', fs.existsSync(path.join(__dirname, 'public', 'bg.jpg')));

  // ---- §6b. Card visuals (cards.js) ----
  check('Cards: every provider maps to a gradient class',
    M.PROVIDERS.every((p) => typeof K.providerClass(p) === 'string' && K.providerClass(p).startsWith('card-')));
  check('Cards: unknown provider falls back to the reel red-orange card',
    K.providerClass('NoSuchBank') === 'card-default');
  check('Cards: visual shows provider, •••• last-4, nickname and balance',
    (() => {
      const html = K.buildCardVisual({ id: 'x1', provider: 'JazzCash', type: 'wallet', nickname: 'Daily', last4: '1234', balance: 47500 }, {});
      return html.includes('card-jazzcash') && html.includes('•••• 1234') && html.includes('Daily')
        && html.includes('Rs 47,500') && html.includes('Tap to pay') && html.includes('cv-chip');
    })());
  check('Cards: hide-balances masks the amount on the card',
    K.buildCardVisual({ id: 'x1', provider: 'HBL', type: 'debit', nickname: 'Salary', last4: '9999', balance: 150000 }, { hideBalances: true }).includes('Rs ••••'));
  check('Cards: nickname is escaped (no HTML injection)',
    !K.buildCardVisual({ id: 'x1', provider: 'HBL', type: 'debit', nickname: '<script>alert(1)</script>', last4: '1111', balance: 0 }, {}).includes('<script>'));
  check('Cards: selected card carries the selected class',
    K.buildCardVisual({ id: 'x1', provider: 'UBL', type: 'bank', nickname: 'Main', last4: '2222', balance: 1 }, { selected: true }).includes('selected'));

  // ---- §6c. WCAG AA contrast for the warm glass theme ----
  // Method (same as the Loan Calculator §19): blend each glass rgba over
  // the darkest decile of the background photo (#5a432a) to get the darkest
  // effective glass, then require ≥4.5:1 for text on it. Tokens are parsed
  // from styles.css itself, so the check tests the real CSS, not copies.
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
  const cardStops = [];
  for (const line of cssSrc.split('\n')) {
    if (/^\.card-[a-z-]+\s*\{/.test(line) && line.includes('linear-gradient')) {
      const stops = [...line.matchAll(/#[0-9a-f]{6}/g)].map((m) => m[0]);
      cardStops.push(...stops);
    }
  }
  const successLine = cssSrc.split('\n').find((l) => l.includes('.card-visual.success'));
  const successStops = successLine ? [...successLine.matchAll(/#[0-9a-f]{6}/g)].map((m) => m[0]) : [];
  const allStops = [...new Set([...cardStops, ...successStops])];
  check('Contrast: card gradient stops parsed (' + allStops.length + ' unique stops)',
    allStops.length >= 20, allStops.join(' '));
  const worstStop = allStops.length ? allStops.reduce((a, b) =>
    (ratio([1, 1, 1], hexRgb(a)) < ratio([1, 1, 1], hexRgb(b)) ? a : b)) : null;
  check('Contrast: white card text on EVERY gradient stop >= 4.5:1',
    allStops.length > 0 && allStops.every((s) => ratio([1, 1, 1], hexRgb(s)) >= 4.5),
    'worst stop ' + worstStop + ' = ' + (worstStop ? ratio([1, 1, 1], hexRgb(worstStop)).toFixed(2) + ':1' : 'n/a'));
  // The logo "V" is a brand mark (WCAG exempts logos from the 4.5:1 rule);
  // it must still clear the 3:1 large-text/graphical threshold.
  const logoGreen = '#16a34a';
  check('Contrast: logo mark white on ' + logoGreen + ' >= 3:1 (logo, WCAG-exempt from 4.5:1)',
    ratio([1, 1, 1], hexRgb(logoGreen)) >= 3,
    ratio([1, 1, 1], hexRgb(logoGreen)).toFixed(2) + ':1');

  // ---- §7. Intelligence — paste an SMS, the wallet updates itself ----
  check('Intel: extractLast4 reads ••••1234', S.extractLast4('Rs 2,500 debited ••••1234') === '1234');
  check('Intel: extractLast4 reads AC 1234', S.extractLast4('from AC 1234 on 06-Nov') === '1234');
  check('Intel: extractLast4 reads ending 1234', S.extractLast4('your account ending 1234') === '1234');
  const intelVault = M.emptyVault();
  M.createAccount(intelVault, { provider: 'JazzCash', type: 'wallet', nickname: 'JC daily', last4: '1234', balance: 50000 });
  M.createAccount(intelVault, { provider: 'HBL', type: 'debit', nickname: 'HBL main', last4: '1234', balance: 150000 });
  M.createAccount(intelVault, { provider: 'Easypaisa', type: 'wallet', nickname: 'EP', last4: '5678', balance: 20000 });
  const jcDraft = S.parseSms('Rs 2,500.00 debited from your JazzCash account ••••1234 at Daraz on 06-Nov-2026. Available balance Rs 47,500.00');
  check('Intel: SMS parses provider + last-4 + amount + balance',
    !!jcDraft && jcDraft.provider === 'JazzCash' && jcDraft.last4 === '1234'
    && jcDraft.amount === 2500 && jcDraft.direction === 'debit' && jcDraft.availableBalance === 47500);
  check('Intel: provider disambiguates two accounts with the same last-4',
    I.findIntelMatch(intelVault.accounts, 'JazzCash', '1234').status === 'match'
    && I.findIntelMatch(intelVault.accounts, 'JazzCash', '1234').account.provider === 'JazzCash'
    && I.findIntelMatch(intelVault.accounts, 'HBL', '1234').account.provider === 'HBL');
  check('Intel: no match for an unknown last-4', I.findIntelMatch(intelVault.accounts, 'JazzCash', '9999').status === 'none');
  check('Intel: unknown provider / no last-4 -> no match',
    I.findIntelMatch(intelVault.accounts, 'Unknown', '1234').status === 'none'
    && I.findIntelMatch(intelVault.accounts, 'JazzCash', null).status === 'none');
  check('Intel: two accounts, same provider + last-4 -> ambiguous',
    (() => {
      // Built by hand, not createAccount: creation now forbids a duplicate
      // provider + last-4, but an old vault can still hold one — and the
      // matcher must still refuse to guess which one an SMS belongs to.
      const v = M.emptyVault();
      v.accounts.push(
        { id: 'dup1', provider: 'UBL', type: 'debit', nickname: 'A', last4: '7777', balance: 1000, startingBalance: 1000, confirmedBy: null, createdAt: '2026-11-06T00:00:00.000Z' },
        { id: 'dup2', provider: 'UBL', type: 'credit', nickname: 'B', last4: '7777', balance: 2000, startingBalance: 2000, confirmedBy: null, createdAt: '2026-11-06T00:00:00.000Z' });
      return I.findIntelMatch(v.accounts, 'UBL', '7777').status === 'ambiguous';
    })());
  const jcAccount = I.findIntelMatch(intelVault.accounts, 'JazzCash', '1234').account;
  const applied = I.applyIntelUpdate(intelVault, jcDraft, jcAccount);
  check('Intel: debit SMS with a matching last-4 updates that account directly',
    applied.newBalance === 47500 && applied.prevBalance === 50000
    && intelVault.transactions.length === 1 && intelVault.transactions[0].status === 'approved');
  check('Intel: the update adds a transaction row + a notification',
    intelVault.notifications.length === 1 && intelVault.notifications[0].kind === 'transaction');
  const resText = I.intelResultText(jcAccount, jcDraft, applied.prevBalance, applied.newBalance);
  check('Intel: result line reads like the spec',
    resText.line === 'JazzCash ••1234 updated: −Rs 2,500 → new balance Rs 47,500');
  check('Intel: available-balance cross-check is shown (matches)',
    resText.cross === 'Bank says available balance Rs 47,500 — matches the vault.');
  const undone = I.undoIntelUpdate(intelVault, applied.txn.id, applied.notifId);
  check('Intel: Undo reverses the update and the balance',
    undone.balance === 50000 && intelVault.transactions.length === 0
    && intelVault.notifications.length === 0 && M.reconcile(intelVault).ok);
  const creditDraft = S.parseSms('Rs 10,000.00 credited to your Easypaisa account ending 5678 on 06-Nov-2026.');
  const epAccount = I.findIntelMatch(intelVault.accounts, 'Easypaisa', '5678').account;
  const appliedCr = I.applyIntelUpdate(intelVault, creditDraft, epAccount);
  check('Intel: credit SMS adds to the balance', appliedCr.newBalance === 30000);
  const crossDiff = I.intelResultText(epAccount, { ...creditDraft, availableBalance: 30500 }, 20000, 30000);
  check('Intel: cross-check flags a bank balance that differs',
    crossDiff.cross.includes('Rs 500 more than the vault shows'));
  check('Intel: garbage / OTP / no-amount parses nothing',
    S.parseSms('hello world') === null && S.parseSms('Your OTP is 123456. Never share it.') === null
    && S.parseSms('Rs debited from JazzCash') === null);

  // ---- §8. Two-factor authentication (TOTP RFC 6238 + backup codes) ----
  // RFC 6238 vectors, secret "12345678901234567890" (base32 below), 6-digit
  // truncation of the published 8-digit codes — cross-checked against an
  // independent Python HMAC implementation before hardcoding.
  const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const RFC_VECTORS = [
    [59, '287082'], [1111111109, '081804'], [1111111111, '050471'],
    [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130'],
  ];
  for (const [t, expect] of RFC_VECTORS) {
    check('TOTP: RFC 6238 vector t=' + t + ' -> ' + expect,
      (await T.totpCode(RFC_SECRET, t * 1000)) === expect);
  }
  check('TOTP: code from the wrong secret fails',
    (await T.verifyTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJR', await T.totpCode(RFC_SECRET, 1234567890 * 1000), 1234567890 * 1000)) === false);
  check('TOTP: code one step ahead (+30s) verifies (clock drift)',
    (await T.verifyTotp(RFC_SECRET, await T.totpCode(RFC_SECRET, 1234567890 * 1000 + 30000), 1234567890 * 1000)) === true);
  check('TOTP: code two steps ahead (+60s) fails — outside the ±1 window',
    (await T.verifyTotp(RFC_SECRET, await T.totpCode(RFC_SECRET, 1234567890 * 1000 + 60000), 1234567890 * 1000)) === false);
  check('TOTP: garbage code fails', (await T.verifyTotp(RFC_SECRET, '000000', 1234567890 * 1000)) === false
    && (await T.verifyTotp(RFC_SECRET, 'abc', 1234567890 * 1000)) === false);
  check('TOTP: base32 round-trip', (() => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    const enc = T.base32Encode(bytes);
    const dec = T.base32Decode(enc);
    return enc.length === 32 && dec.length === 20 && dec.every((b, i) => b === bytes[i]);
  })());
  check('TOTP: generated secret is 32 base32 chars -> 20 bytes',
    (() => { const s = T.generateSecret(); return s.length === 32 && T.base32Decode(s).length === 20; })());
  check('TOTP: otpauth URL shape',
    T.otpauthUrl(RFC_SECRET).startsWith('otpauth://totp/Card%20Vault:')
    && T.otpauthUrl(RFC_SECRET).includes('secret=' + RFC_SECRET)
    && T.otpauthUrl(RFC_SECRET).includes('algorithm=SHA1&digits=6&period=30'));
  const backupSet = await T.generateBackupCodes(10);
  check('Backup: 10 unique codes, 10 hashes',
    backupSet.codes.length === 10 && new Set(backupSet.codes).size === 10 && backupSet.hashes.length === 10
    && backupSet.codes.every((c) => /^\d{4}-\d{4}$/.test(c)));
  const firstUse = await T.checkBackupCode(backupSet.codes[0], backupSet.hashes);
  check('Backup: a code works once', firstUse.ok === true && firstUse.remaining.length === 9);
  const secondUse = await T.checkBackupCode(backupSet.codes[0], firstUse.remaining);
  check('Backup: the same code is burned after one use', secondUse.ok === false && secondUse.remaining.length === 9);
  check('Backup: a wrong code fails',
    (await T.checkBackupCode('0000-0000', backupSet.hashes)).ok === false);
  check('Backup: codes are stored as hashes only (no plaintext code in the hash list)',
    !backupSet.hashes.some((h) => backupSet.codes.some((c) => h.includes(c.replace('-', '')))));
  // 2FA state lives in the vault settings (secret encrypted under the PIN).
  const v2fa = M.emptyVault();
  check('2FA: new vault has 2FA off + 5-min auto-lock',
    v2fa.settings.twoFactor === null && v2fa.settings.autoLockMinutes === 5);
  check('2FA: enabling with a bad secret fails',
    (() => { try { M.enableTwoFactor(v2fa, 'not base32!!'); return false; } catch (e) { return e.code === 'VALIDATION'; } })());
  M.enableTwoFactor(v2fa, RFC_SECRET);
  check('2FA: enabling stores the secret inside the vault',
    v2fa.settings.twoFactor && v2fa.settings.twoFactor.enabled === true
    && v2fa.settings.twoFactor.secret === RFC_SECRET);
  M.disableTwoFactor(v2fa);
  check('2FA: disabling clears the secret', v2fa.settings.twoFactor === null);
  check('2FA: auto-lock accepts 1/5/15 only',
    M.setAutoLockMinutes(v2fa, 1) === 1 && M.setAutoLockMinutes(v2fa, 15) === 15
    && (() => { try { M.setAutoLockMinutes(v2fa, 7); return false; } catch (e) { return e.code === 'VALIDATION'; } })());
  check('2FA: disabling without a valid code fails (the gate)',
    (await T.canDisableTwoFactor(RFC_SECRET, '000000', 1234567890 * 1000)) === false
    && (await T.canDisableTwoFactor(RFC_SECRET, await T.totpCode(RFC_SECRET, 1234567890 * 1000), 1234567890 * 1000)) === true
    && (await T.canDisableTwoFactor(null, '005924', 1234567890 * 1000)) === false);
  check('2FA: a vault with 2FA off still unlocks with the PIN alone',
    await (async () => {
      const made = await V.createVault('482917', '', M.emptyVault());
      const out = await V.unlockVault('482917', '', made.envelope);
      return out.vault.settings.twoFactor === null && Array.isArray(out.vault.accounts);
    })());

  // ---- §9a. Phase 3: hash routing (nav.js, pure) + profile + bell read-state ----
  check('Nav: routeForHash maps every page hash',
    N.routeForHash('#/wallet') === 'wallet' && N.routeForHash('#/add') === 'add'
    && N.routeForHash('#/intelligence') === 'intelligence' && N.routeForHash('#/security') === 'security'
    && N.routeForHash('#/backup') === 'backup' && N.routeForHash('#/profile') === 'profile');
  check('Nav: unknown/empty/missing hash falls back to the Wallet page',
    N.routeForHash('') === 'wallet' && N.routeForHash('#/nope') === 'wallet'
    && N.routeForHash('#wallet') === 'wallet' && N.routeForHash(null) === 'wallet'
    && N.routeForHash('#/wallet?x=1') === 'wallet');
  check('Nav: the sidebar order is exactly Wallet, Add Card, Intelligence, Security, Backup & Import, Profile',
    N.NAV_ORDER.map((o) => o.label).join('|') === 'Wallet|Add Card|Intelligence|Security|Backup & Import|Profile'
    && N.NAV_ORDER.map((o) => o.id).join('|') === 'wallet|add|intelligence|security|backup|profile');
  const SMALL_DP = 'data:image/jpeg;base64,/9j/AAAA';
  const vprof = M.emptyVault();
  check('Profile: a new vault starts with an empty profile',
    vprof.profile && vprof.profile.displayName === '' && vprof.profile.phone === ''
    && vprof.profile.email === '' && vprof.profile.dp === null);
  M.setProfile(vprof, { displayName: 'Muhammad Hashir', phone: '0300 1234567', email: 'h@example.com', dp: SMALL_DP });
  check('Profile: save/load round-trip keeps name, phone, email and DP',
    vprof.profile.displayName === 'Muhammad Hashir' && vprof.profile.phone === '0300 1234567'
    && vprof.profile.email === 'h@example.com' && vprof.profile.dp === SMALL_DP);
  check('Profile: saving without a DP keeps the old DP',
    (() => { M.setProfile(vprof, { displayName: 'Hashir', phone: '', email: '' }); return vprof.profile.dp === SMALL_DP && vprof.profile.displayName === 'Hashir'; })());
  check('Profile: saving with dp=null clears the DP',
    (() => { M.setProfile(vprof, { displayName: 'Hashir', phone: '', email: '', dp: null }); return vprof.profile.dp === null; })());
  check('Profile: a bad email, a too-long name and a too-long phone are rejected',
    M.validateProfile({ displayName: 'x', email: 'not-an-email' }).length === 1
    && M.validateProfile({ displayName: 'x'.repeat(61) }).length === 1
    && M.validateProfile({ displayName: 'x', phone: 'a'.repeat(21) }).length === 1);
  check('Profile: setProfile throws VALIDATION on a bad profile',
    (() => { try { M.setProfile(vprof, { displayName: 'x', email: 'nope' }); return false; } catch (e) { return e.code === 'VALIDATION'; } })());
  check('Profile: a profile must not contain a full card number or a long digit run',
    M.validateProfile({ displayName: 'card ' + '4534'.repeat(4) }).length > 0
    && M.validateProfile({ displayName: 'account ' + '1'.repeat(13) }).length > 0);
  check('Profile: DP size cap — a data URL over 100 KB is rejected, a small one is accepted',
    (() => {
      const bigDp = 'data:image/jpeg;base64,' + 'A'.repeat(Math.ceil((M.MAX_DP_BYTES + 1) * 4 / 3));
      return M.MAX_DP_BYTES === 100 * 1024
        && M.validateProfile({ displayName: 'x', dp: bigDp }).some((e) => e.indexOf('100 KB') >= 0)
        && M.validateProfile({ displayName: 'x', dp: SMALL_DP }).length === 0
        && M.validateProfile({ displayName: 'x', dp: 'data:image/png;base64,AAAA' }).length === 1;
    })());
  check('Profile: DP downscale — long side becomes 256px, small photos are never upscaled',
    (() => {
      const a = M.dpTargetSize(1024, 768), b = M.dpTargetSize(100, 50), c = M.dpTargetSize(200, 400), d = M.dpTargetSize(256, 256);
      return a.width === 256 && a.height === 192 && b.width === 100 && b.height === 50
        && c.width === 128 && c.height === 256 && d.width === 256 && d.height === 256;
    })());
  check('Profile: an old vault without a profile loads with an empty profile (migration default)',
    (() => {
      const old = { v: 1, createdAt: '2026-11-06T00:00:00.000Z', accounts: [], transactions: [], notifications: [], settings: { lowBalanceThreshold: 5000 } };
      const mig = M.migrateVault(old);
      return mig.profile.displayName === '' && mig.profile.phone === '' && mig.profile.email === '' && mig.profile.dp === null
        && mig.settings.twoFactor === null && mig.settings.autoLockMinutes === 5 && mig.settings.lowBalanceThreshold === 5000;
    })());
  check('Profile: a migrated old vault survives an encrypt/decrypt round-trip',
    await (async () => {
      const old = { v: 1, createdAt: '2026-11-06T00:00:00.000Z', accounts: [], transactions: [], notifications: [], settings: { lowBalanceThreshold: 5000 } };
      const made = await V.createVault('482917', '', M.migrateVault(old));
      const out = await V.unlockVault('482917', '', made.envelope);
      return out.vault.profile && out.vault.profile.displayName === '' && out.vault.profile.dp === null;
    })());
  const vbell = M.emptyVault();
  M.addNotification(vbell, 'transaction', 'test one');
  M.addNotification(vbell, 'low-balance', 'test two');
  check('Bell: new notifications start unread, and the badge count equals the unread count',
    M.unreadNotificationCount(vbell) === 2 && vbell.notifications.every((n) => n.read === false));
  check('Bell: opening the bell marks all read (badge clears)',
    M.markAllNotificationsRead(vbell) === 2 && M.unreadNotificationCount(vbell) === 0
    && vbell.notifications.every((n) => n.read === true));
  check('Bell: a notification from an old save (no read key) counts as unread',
    (() => {
      const old = M.emptyVault();
      old.notifications.push({ id: 'x1', kind: 'transaction', text: 'old', at: new Date().toISOString() });
      return M.unreadNotificationCount(old) === 1 && M.markAllNotificationsRead(old) === 1;
    })());

  // ---- §9b. Phase 3: page structure (parsed from index.html / styles.css / app.js) ----
  // Pages never nest <section>, so a page is the text from its opening tag
  // to the first </section> after it.
  const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, 'public', 'styles.css'), 'utf8');
  const appJs = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
  function pageHtml(page) {
    const start = html.indexOf('id="page-' + page + '"');
    if (start < 0) return '';
    const end = html.indexOf('</section>', start);
    return html.slice(start, end);
  }
  const navStart = html.indexOf('<nav id="sidebar-nav"');
  const navBlock = html.slice(navStart, html.indexOf('</nav>', navStart));
  const navLabels = [...navBlock.matchAll(/<span class="nav-label">([^<]+)<\/span>/g)].map((m) => m[1].replace(/&amp;/g, '&'));
  check('Structure: the sidebar buttons run in Hashir\'s exact order',
    navLabels.join('|') === 'Wallet|Add Card|Intelligence|Security|Backup & Import|Profile');
  check('Structure: all seven pages exist',
    ['wallet', 'add', 'intelligence', 'security', 'backup', 'profile', 'reconcile'].every((p) => html.includes('id="page-' + p + '"')));
  const wallet = pageHtml('wallet');
  check('Structure: the Wallet page holds ONLY cards + summary + the Add button',
    wallet.includes('id="accounts-card"') && wallet.includes('id="summary-card"')
    && wallet.includes('id="txns-card"') && wallet.includes('id="wallet-add-btn"')
    && wallet.includes('id="vault-stepper"')
    && !wallet.includes('id="add-account-card"') && !wallet.includes('id="sms-card"')
    && !wallet.includes('id="csv-card"') && !wallet.includes('id="backup-card"')
    && !wallet.includes('id="security-settings-card"') && !wallet.includes('id="security-card"')
    && !wallet.includes('id="connect-card"') && !wallet.includes('notifs'));
  check('Structure: the stepper lives on the Wallet page only',
    wallet.includes('id="vault-stepper"')
    && !pageHtml('add').includes('vault-stepper') && !pageHtml('intelligence').includes('vault-stepper')
    && !pageHtml('security').includes('vault-stepper') && !pageHtml('backup').includes('vault-stepper')
    && !pageHtml('profile').includes('vault-stepper'));
  check('Structure: Add holds the form + Connect a bank; Intelligence holds the SMS panel',
    pageHtml('add').includes('id="add-account-card"') && pageHtml('add').includes('id="connect-card"')
    && pageHtml('intelligence').includes('id="sms-card"'));
  check('Structure: Security holds 2FA/settings + the protection note; Backup holds backup + CSV',
    pageHtml('security').includes('id="security-settings-card"') && pageHtml('security').includes('id="security-card"')
    && pageHtml('backup').includes('id="backup-card"') && pageHtml('backup').includes('id="csv-card"'));
  check('Structure: Profile holds the DP upload + name/phone/email + Save',
    pageHtml('profile').includes('id="profile-card"') && pageHtml('profile').includes('id="profile-dp-input"')
    && pageHtml('profile').includes('id="profile-name"') && pageHtml('profile').includes('id="profile-phone"')
    && pageHtml('profile').includes('id="profile-email"') && pageHtml('profile').includes('id="profile-save-btn"'));
  check('Structure: every non-Wallet page has a "← Back to Wallet" link',
    ['add', 'intelligence', 'security', 'backup', 'profile', 'reconcile'].every((p) =>
      pageHtml(p).includes('<a class="back-link" href="#/wallet">← Back to Wallet</a>')));
  check('Structure: the bell (button + badge + dropdown) is in the sidebar, not on a page',
    html.includes('id="bell-btn"') && html.includes('id="bell-badge"') && html.includes('id="notif-panel"')
    && html.includes('id="bell-list"') && html.includes('id="bell-empty"') && html.includes('id="bell-mark-read"')
    && html.indexOf('id="sidebar"') > html.indexOf('id="vault-screen"'));
  check('Structure: the sidebar header and the top bar both show the DP + name',
    html.includes('id="sidebar-dp"') && html.includes('id="sidebar-dp-initials"') && html.includes('id="sidebar-name"')
    && html.includes('id="topbar-dp"') && html.includes('id="topbar-dp-initials"') && html.includes('id="topbar-name"'));
  check('Structure: no leftover single-page sections (no vault-grid, no notifs card)',
    !html.includes('vault-grid') && !html.includes('vault-col') && !html.includes('notifs-card')
    && !html.includes('notifs-list') && !html.includes('notifs-empty')
    && !appJs.includes('notifs-list') && !appJs.includes('STEP_CARDS') && !appJs.includes('STEP_DONE'));
  check('Fix: content can never hide under the sticky top bar (top padding + scroll margins)',
    css.includes('scroll-margin-top: 96px') && css.includes('scroll-padding-top: 96px')
    && /main \{[^}]*padding: 24px 16px 16px;/.test(css));
  check('Fix: the stepper is in the normal flow, never sticky (it cannot overlap a form)',
    (() => {
      const m = css.match(/\.stepper \{[^}]*\}/);
      return m && !m[0].includes('sticky') && !m[0].includes('position:');
    })());
  check('Wiring: app.js routes hashes, toggles the bell, marks read, and migrates old vaults',
    appJs.includes('Nav.routeForHash') && appJs.includes('function showPage') && appJs.includes('toggleBell')
    && appJs.includes('markAllNotificationsRead') && appJs.includes('unreadNotificationCount')
    && appJs.includes('migrateVault(out.vault)') && appJs.includes("hide($('totp-screen'))"));

  // ---- §9c. Clickable profile headers (Hashir's call 2026-11-06: the DP + name
  // on top — sidebar header and top-bar chip — open the Profile page) ----
  check('Profile: the sidebar header is a link to the Profile page (DP + name kept)',
    html.includes('<a class="sidebar-profile" href="#/profile"')
    && html.includes('id="sidebar-dp"') && html.includes('id="sidebar-name"'));
  check('Profile: the top-bar chip is a link to the Profile page (DP + name kept)',
    html.includes('<a class="profile-chip" href="#/profile"')
    && html.includes('id="topbar-dp"') && html.includes('id="topbar-name"'));
  check('Profile: both profile links route through the hash router to the Profile page',
    N.routeForHash('#/profile') === 'profile'
    && [...html.matchAll(/<a class="(?:sidebar-profile|profile-chip)" href="([^"]+)"/g)]
      .every((m) => m[1] === '#/profile'));
  check('Profile: the clickable headers have a hover + keyboard-focus style',
    css.includes('.sidebar-profile:hover') && css.includes('.sidebar-profile:focus-visible')
    && css.includes('.topbar .profile-chip:hover') && css.includes('.topbar .profile-chip:focus-visible'));

  // ---- §9d. Phase 3.1, Step 1: tighter add-account validation ----
  check('Verify: same provider + last-4 cannot be added twice (error names the card)',
    (() => {
      const v = M.emptyVault();
      M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL main', last4: '1234', balance: 1000 });
      try {
        M.createAccount(v, { provider: 'UBL', type: 'credit', nickname: 'UBL other', last4: '1234', balance: 0 });
        return false;
      } catch (e) {
        return e.code === 'VALIDATION' && e.message.includes('UBL') && e.message.includes('1234');
      }
    })());
  check('Verify: same last-4 under a different provider is allowed (different banks can share it)',
    (() => {
      const v = M.emptyVault();
      M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 1000 });
      const second = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'HBL', last4: '1234', balance: 500 });
      return !!second && v.accounts.length === 2;
    })());
  check('Verify: same provider + a different last-4 is allowed',
    (() => {
      const v = M.emptyVault();
      M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL 1', last4: '1234', balance: 1000 });
      const second = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL 2', last4: '5678', balance: 500 });
      return !!second && v.accounts.length === 2;
    })());
  check('Verify: negative balance rejected for debit / wallet / bank',
    M.validateAccount({ provider: 'HBL', type: 'debit', nickname: 'X', last4: '1234', balance: -100 }).length > 0
    && M.validateAccount({ provider: 'JazzCash', type: 'wallet', nickname: 'X', last4: '1234', balance: -100 }).length > 0
    && M.validateAccount({ provider: 'HBL', type: 'bank', nickname: 'X', last4: '1234', balance: -100 }).length > 0);
  check('Verify: negative balance allowed for a credit card (money owed)',
    M.validateAccount({ provider: 'HBL', type: 'credit', nickname: 'X', last4: '1234', balance: -5000 }).length === 0);
  check('Verify: a new account starts unconfirmed (confirmedBy null)',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 0 });
      return a.confirmedBy === null && M.isBankConfirmed(a) === false;
    })());

  // ---- §9d (cont). Phase 3.1, Step 2: bank-confirmed status ----
  const intelJs = fs.readFileSync(path.join(__dirname, 'public', 'intel.js'), 'utf8');
  const confVault = M.emptyVault();
  M.createAccount(confVault, { provider: 'JazzCash', type: 'wallet', nickname: 'JC daily', last4: '1234', balance: 50000 });
  const confDraft = S.parseSms('Rs 2,500.00 debited from your JazzCash account ••••1234 at Daraz on 06-Nov-2026. Available balance Rs 47,500.00');
  const confAcct = I.findIntelMatch(confVault.accounts, 'JazzCash', '1234').account;
  check('Verify: a real bank-SMS direct match marks the account bank-confirmed with a date',
    (() => {
      const out = I.applyIntelUpdate(confVault, confDraft, confAcct);
      return out.confirmed === true && confAcct.confirmedBy && confAcct.confirmedBy.source === 'bank-sms'
        && typeof confAcct.confirmedBy.at === 'string' && !isNaN(Date.parse(confAcct.confirmedBy.at))
        && M.isBankConfirmed(confAcct) === true && out.newBalance === 47500;
    })());
  check('Verify: Undo reverses the balance only — the confirmation stays (the SMS was real)',
    (() => {
      const out = I.undoIntelUpdate(confVault, confVault.transactions[0].id, confVault.notifications[0] ? confVault.notifications[0].id : null);
      return out.balance === 50000 && confVault.transactions.length === 0
        && M.isBankConfirmed(confAcct) === true && confAcct.confirmedBy.source === 'bank-sms';
    })());
  check('Verify: a second SMS does not re-stamp the confirmation (first date kept)',
    (() => {
      const v = M.emptyVault();
      M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'HBL', last4: '4321', balance: 10000 });
      const a = v.accounts[0];
      const d1 = S.parseSms('Rs 500.00 debited from your HBL account ••••4321 on 06-Nov-2026.');
      const d2 = S.parseSms('Rs 200.00 debited from your HBL account ••••4321 on 06-Nov-2026.');
      const o1 = I.applyIntelUpdate(v, d1, a);
      const firstAt = a.confirmedBy.at;
      const o2 = I.applyIntelUpdate(v, d2, a);
      return o1.confirmed === true && o2.confirmed === false && a.confirmedBy.at === firstAt;
    })());
  check('Verify: manual add and manual/CSV transactions never confirm an account',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'HBL', last4: '9999', balance: 10000 });
      const t1 = M.addTransaction(v, { accountId: a.id, amount: 500, direction: 'debit', merchant: 'Shop', date: '2026-11-06', source: 'manual' });
      M.approveTransaction(v, t1.id);
      const t2 = M.addTransaction(v, { accountId: a.id, amount: 1000, direction: 'credit', merchant: 'Salary', date: '2026-11-06', source: 'csv' });
      M.approveTransaction(v, t2.id);
      return M.isBankConfirmed(a) === false && a.confirmedBy === null;
    })());
  check('Verify: an old vault without confirmedBy loads as unconfirmed',
    (() => {
      const v = M.emptyVault();
      v.accounts.push({ id: 'old1', provider: 'UBL', type: 'debit', nickname: 'Old', last4: '1111', balance: 100, startingBalance: 100, createdAt: '2026-11-06T00:00:00.000Z' });
      M.migrateVault(v);
      return v.accounts[0].confirmedBy === null && M.isBankConfirmed(v.accounts[0]) === false;
    })());
  check('Verify: only the Intelligence direct-match path can confirm (review/CSV/manual never call it)',
    intelJs.includes('markAccountBankConfirmed') && !appJs.includes('markAccountBankConfirmed'));
  check('Verify: cards show the bank-confirmed badge, unconfirmed cards the muted badge',
    K.buildCardVisual({ id: 'c1', provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 0, confirmedBy: { source: 'bank-sms', at: '2026-11-06T00:00:00.000Z' } }, {}).includes('✓ Bank-confirmed')
    && K.buildCardVisual({ id: 'c2', provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 0, confirmedBy: null }, {}).includes('Not confirmed yet')
    && K.confirmationBadge({ confirmedBy: { source: 'bank-sms', at: 'x' } }).includes('Bank-confirmed')
    && appJs.includes('Cards.confirmationBadge(a)'));
  check('Verify: the Add page carries the honest note',
    html.includes('id="add-honest-note"') && html.includes('We save only what you type — no app can check a card with the bank until open banking goes live in Pakistan.'));
  check('Verify: the badge styles exist',
    css.includes('.cv-confirmed') && css.includes('.sum-row .pill'));

  // ---- §9e. Phase 3.2 (REVISED by Hashir's rule 2026-11-06): rename,
  // reorder, delete. A saved card's data can only be changed by a bank SMS
  // — never by the user's hand. The only hand-change is the nickname.
  check('Rename: unknown account id rejected',
    throwsCode(function () {
      M.renameAccount(M.emptyVault(), 'nope', 'X');
    }, 'NOT_FOUND'));
  check('Rename: empty, over-long or sensitive nicknames rejected',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 1000 });
      return throwsCode(function () { M.renameAccount(v, a.id, '  '); }, 'VALIDATION')
        && throwsCode(function () { M.renameAccount(v, a.id, 'x'.repeat(41)); }, 'VALIDATION')
        && throwsCode(function () { M.renameAccount(v, a.id, 'card 0000000000000000'); }, 'VALIDATION');
    })());
  check('Rename: only the nickname changes — balance, type, proof and confirmation untouched, reconcile clean',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 1000 });
      M.renameAccount(v, a.id, 'UBL Salary');
      return a.nickname === 'UBL Salary' && a.balance === 1000 && a.type === 'debit'
        && a.startingBalance === 1000 && a.provider === 'UBL' && a.last4 === '1234'
        && v.transactions.length === 0 && M.reconcile(v).ok;
    })());
  check('Rename: a bank-confirmed card keeps its badge after a rename',
    (() => {
      const v = M.emptyVault();
      M.createAccount(v, { provider: 'JazzCash', type: 'wallet', nickname: 'JC', last4: '1234', balance: 50000 });
      const a = v.accounts[0];
      const d = S.parseSms('Rs 2,500.00 debited from your JazzCash account ••••1234 on 06-Nov-2026.');
      I.applyIntelUpdate(v, d, a);
      M.renameAccount(v, a.id, 'JC daily');
      return M.isBankConfirmed(a) === true && a.nickname === 'JC daily' && a.balance === 47500;
    })());
  check('Audit: NO model function lets a hand edit change a balance or a type (updateAccount is gone)',
    typeof M.updateAccount === 'undefined'
    && !Object.keys(M).some((k) => /updateAccount|setBalance|setType|editAccount/i.test(k)));
  check('Audit: no balance/type edit control exists in the UI (rename form has nickname only)',
    !html.includes('id="edit-balance"') && !html.includes('id="edit-type"')
    && !appJs.includes('edit-balance') && !appJs.includes('edit-type')
    && !appJs.includes('updateAccount') && appJs.includes('VaultModel.renameAccount'));
  check('Reorder: up/down swap neighbours; ends are a no-op; unknown id rejected',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'A', last4: '1111', balance: 1 });
      const b = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'B', last4: '2222', balance: 2 });
      const c = M.createAccount(v, { provider: 'MCB', type: 'debit', nickname: 'C', last4: '3333', balance: 3 });
      const topNoop = M.moveAccount(v, a.id, 'up') === false;
      const bottomNoop = M.moveAccount(v, c.id, 'down') === false;
      const moved = M.moveAccount(v, c.id, 'up') === true;
      const order = v.accounts.map((x) => x.nickname).join('|');
      const movedBack = M.moveAccount(v, c.id, 'down') === true;
      const orderBack = v.accounts.map((x) => x.nickname).join('|');
      return topNoop && bottomNoop && moved && order === 'A|C|B' && movedBack && orderBack === 'A|B|C'
        && throwsCode(function () { M.moveAccount(v, 'nope', 'up'); }, 'NOT_FOUND')
        && throwsCode(function () { M.moveAccount(v, a.id, 'left'); }, 'VALIDATION');
    })());
  check('Delete: removes the account AND its transactions; reconcile stays clean; unknown id rejected',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'A', last4: '1111', balance: 10000 });
      const b = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'B', last4: '2222', balance: 5000 });
      const t = M.addTransaction(v, { accountId: a.id, amount: 500, direction: 'debit', merchant: 'Shop', date: '2026-11-06', source: 'manual' });
      M.approveTransaction(v, t.id);
      M.addTransaction(v, { accountId: b.id, amount: 100, direction: 'debit', merchant: 'Shop', date: '2026-11-06', source: 'manual' });
      const removed = M.deleteAccount(v, a.id);
      return removed.nickname === 'A' && v.accounts.length === 1 && v.accounts[0].id === b.id
        && v.transactions.every((x) => x.accountId === b.id) && v.transactions.length === 1
        && M.reconcile(v).ok
        && throwsCode(function () { M.deleteAccount(v, 'nope'); }, 'NOT_FOUND');
    })());
  check('Delete: removing the last card leaves an empty vault',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'A', last4: '1111', balance: 100 });
      M.deleteAccount(v, a.id);
      return v.accounts.length === 0 && M.totals(v).count === 0 && M.reconcile(v).ok;
    })());

  // ---- §9e (cont). Phase 3.2: card management UI structure ----
  check('Manage: the Wallet page has a rename panel with provider + last-4 read-only and nickname only',
    pageHtml('wallet').includes('id="edit-account-card"')
    && pageHtml('wallet').includes('id="edit-provider"') && pageHtml('wallet').includes('id="edit-last4"')
    && pageHtml('wallet').includes('id="edit-nick"') && pageHtml('wallet').includes('id="edit-save-btn"')
    && pageHtml('wallet').includes('id="edit-cancel-btn"')
    && !pageHtml('wallet').includes('id="edit-type"') && !pageHtml('wallet').includes('id="edit-balance"')
    && /id="edit-provider"[^>]*readonly/.test(html) && /id="edit-last4"[^>]*readonly/.test(html));
  check('Manage: every card and every Summary row gets Edit / ↑ / ↓ / Remove buttons',
    appJs.includes('cardActionsHtml') && appJs.includes('sumActionsHtml')
    && appJs.includes('data-action="edit"') && appJs.includes('data-action="move-up"')
    && appJs.includes('data-action="move-down"') && appJs.includes('data-action="remove"')
    && appJs.includes("data-action=\"confirm-remove\"") && appJs.includes("data-action=\"cancel-remove\""));
  check('Manage: reorder buttons are disabled at the ends (first ↑, last ↓)',
    appJs.includes("(i === 0 ? ' disabled' : '')") && appJs.includes("(i === n - 1 ? ' disabled' : '')"));
  check('Manage: delete is two-tap — the first tap only arms, the confirm says the transactions go too',
    appJs.includes('pendingDeleteId') && appJs.includes('requestDelete') && appJs.includes('confirmDelete')
    && appJs.includes('This also removes its transactions.')
    && appJs.includes('if (state.pendingDeleteId !== accountId) return;'));
  check('Manage: rename/reorder/delete go through persist + render',
    appJs.includes('VaultModel.renameAccount') && appJs.includes('VaultModel.moveAccount')
    && appJs.includes('VaultModel.deleteAccount') && appJs.includes('showSecuring(updated,')
    && appJs.includes('cardActionsHtml(a, i, v.accounts.length)'));

  // ---- §9f. Phase 3.3: statement proof (module) ----
  // Minimal readable-text PDFs, built in-test (latin1 -> base64 data URL).
  function pdfDataUrl(body) {
    const bytes = Buffer.from('%PDF-1.4\n' + body, 'latin1');
    return { dataUrl: 'data:application/pdf;base64,' + bytes.toString('base64'), size: bytes.length };
  }
  const stmtFull = pdfDataUrl('1 0 obj << /Type /Page /Contents 2 0 R >> endobj\n'
    + '2 0 obj << /Length 200 >> stream\n'
    + 'BT (UBL Bank Statement) Tj ET\nBT (Account holder: Muhammad Hashir) Tj ET\nBT (Account ending 1234) Tj ET\n'
    + 'endstream endobj\n');
  const stmtNoName = pdfDataUrl('1 0 obj << /Type /Page /Contents 2 0 R >> endobj\n'
    + '2 0 obj << /Length 200 >> stream\n'
    + 'BT (UBL Bank Statement) Tj ET\nBT (Account ending 1234) Tj ET\n'
    + 'endstream endobj\n');
  const stmtBlank = pdfDataUrl('% just a header, no text\n');
  const pngFile = { dataUrl: 'data:image/png;base64,' + Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0]).toString('base64'), size: 12 };
  const jpgFile = { dataUrl: 'data:image/jpeg;base64,' + Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0]).toString('base64'), size: 8 };
  const txtFile = { dataUrl: 'data:text/plain;base64,' + Buffer.from('hello world').toString('base64'), size: 11 };
  const ublCard = { provider: 'UBL', last4: '1234' };
  check('Proof: magic bytes detect PDF / JPEG / PNG, and reject a text file',
    P.detectProofKind(Buffer.from([0x25, 0x50, 0x44, 0x46])) === 'pdf'
    && P.detectProofKind(Buffer.from([0xFF, 0xD8, 0xFF])) === 'image'
    && P.detectProofKind(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) === 'image'
    && P.detectProofKind(Buffer.from('hello')) === null);
  check('Proof: over 500 KB rejected with the exact message; a valid PDF under the cap passes',
    P.validateProofData(stmtFull.dataUrl, P.MAX_PROOF_BYTES + 1).errors.includes('Statement is too large — upload a file under 500 KB.')
    && P.validateProofData(stmtFull.dataUrl, stmtFull.size).ok === true
    && P.validateProofData(txtFile.dataUrl, txtFile.size).errors.includes('Only a PDF or a photo (JPEG/PNG) can be used as proof.'));
  check('Proof: a text PDF holding provider + last-4 + profile name is a match',
    (await P.extractPdfText(Buffer.from(stmtFull.dataUrl.split(',')[1], 'base64'))) !== null
    && P.checkProofMatch('pdf', await P.extractPdfText(Buffer.from(stmtFull.dataUrl.split(',')[1], 'base64')), ublCard, 'Muhammad Hashir') === 'match');
  check('Proof: the same PDF without the profile name is NOT a match (name is missing)',
    P.checkProofMatch('pdf', await P.extractPdfText(Buffer.from(stmtNoName.dataUrl.split(',')[1], 'base64')), ublCard, 'Muhammad Hashir') === 'mismatch'
    && P.missingProofTerms('pdf', await P.extractPdfText(Buffer.from(stmtNoName.dataUrl.split(',')[1], 'base64')), ublCard, 'Muhammad Hashir').includes('Muhammad Hashir'));
  check('Proof: no profile name set — the name check is skipped, provider + last-4 decide',
    P.checkProofMatch('pdf', await P.extractPdfText(Buffer.from(stmtNoName.dataUrl.split(',')[1], 'base64')), ublCard, '') === 'match'
    && P.checkProofMatch('pdf', await P.extractPdfText(Buffer.from(stmtNoName.dataUrl.split(',')[1], 'base64')), ublCard, null) === 'match');
  check('Proof: a PDF with no readable text is unreadable (kept as a record, never a match)',
    (await P.extractPdfText(Buffer.from(stmtBlank.dataUrl.split(',')[1], 'base64'))) === null
    && P.checkProofMatch('pdf', null, ublCard, 'Muhammad Hashir') === 'unreadable');
  check('Proof: an image claims no automatic match — the user checks it by eye',
    P.validateProofData(pngFile.dataUrl, pngFile.size).kind === 'image'
    && P.validateProofData(jpgFile.dataUrl, jpgFile.size).kind === 'image'
    && P.checkProofMatch('image', null, ublCard, 'Muhammad Hashir') === 'image');
  check('Proof: word boundaries — "JS" does not match "adjust", "1234" does not match "12345"',
    P.containsTerm('adjust your settings', 'JS') === false
    && P.containsTerm('account 12345', '1234') === false
    && P.containsTerm('JS Bank account 1234', 'JS') === true
    && P.containsTerm('Account ending 1234', '1234') === true);
  check('Proof: dataUrlToBytes returns the raw bytes behind a data URL',
    (() => {
      const b = P.dataUrlToBytes(stmtFull.dataUrl);
      return b && b.length === stmtFull.size && b[0] === 0x25 && P.dataUrlToBytes('not-a-data-url') === null;
    })());
  check('Proof: a Flate-compressed stream is inflated and read (bank PDFs are usually compressed)',
    (await (async () => {
      const zlib = require('node:zlib');
      const body = 'BT (UBL Bank Statement) Tj ET\nBT (Muhammad Hashir) Tj ET\nBT (ending 1234) Tj ET';
      const deflated = zlib.deflateRawSync(Buffer.from(body, 'latin1'));
      const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n1 0 obj << /Length ' + deflated.length + ' /Filter /FlateDecode >> stream\n', 'latin1'), deflated, Buffer.from('\nendstream endobj\n', 'latin1')]);
      const text = await P.extractPdfText(pdf);
      return text && P.checkProofMatch('pdf', text, ublCard, 'Muhammad Hashir') === 'match';
    })()) === true);

  // ---- §9f (cont). Phase 3.3: proof on the account (model + ladder) ----
  function proofRecord(status) {
    return { kind: 'pdf', name: 'statement.pdf', mime: 'application/pdf', dataUrl: 'data:application/pdf;base64,JVBERi0xLjQK', status, at: '2026-11-06T00:00:00.000Z' };
  }
  check('Proof: the status ladder runs Bank-confirmed > match > self-checked > attached > mismatch > unconfirmed',
    K.confirmationBadge({ confirmedBy: { source: 'bank-sms', at: 'x' }, proof: proofRecord('match') }).includes('✓ Bank-confirmed')
    && K.confirmationBadge({ confirmedBy: null, proof: proofRecord('match') }).includes('Statement matches')
    && K.confirmationBadge({ confirmedBy: null, proof: proofRecord('self-checked') }).includes('self-checked')
    && K.confirmationBadge({ confirmedBy: null, proof: proofRecord('attached') }).includes('Statement attached</span>')
    && K.confirmationBadge({ confirmedBy: null, proof: proofRecord('mismatch') }).includes("doesn't match this card")
    && K.confirmationBadge({ confirmedBy: null, proof: null }).includes('Not confirmed yet')
    && !K.confirmationBadge({ confirmedBy: null, proof: proofRecord('match') }).includes('verified'));
  check('Proof: a new card with no proof is "Not confirmed yet"; a proof record is stored on the card',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 0, proof: proofRecord('match') });
      const b = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'HBL', last4: '5678', balance: 0 });
      return a.proof && a.proof.status === 'match' && b.proof === null
        && K.confirmationBadge(b).includes('Not confirmed yet');
    })());
  check('Proof: a bad proof record is never stored (wrong kind / status / data URL)',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 0, proof: { kind: 'txt', name: 'x', dataUrl: 'data:text/plain;base64,aGVsbG8=', status: 'match' } });
      const b = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'HBL', last4: '5678', balance: 0, proof: { kind: 'pdf', name: 'x', dataUrl: 'data:application/pdf;base64,JVBERi0xLjQK', status: 'verified' } });
      return a.proof === null && b.proof === null;
    })());
  check('Proof: removing proof clears the status back to unconfirmed — unless the card is bank-confirmed',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 0, proof: proofRecord('match') });
      M.removeProof(v, a.id);
      const backToUnconfirmed = a.proof === null && K.confirmationBadge(a).includes('Not confirmed yet');
      const b = M.createAccount(v, { provider: 'JazzCash', type: 'wallet', nickname: 'JC', last4: '9999', balance: 50000, proof: proofRecord('match') });
      const d = S.parseSms('Rs 2,500.00 debited from your JazzCash account ••••9999 on 06-Nov-2026.');
      I.applyIntelUpdate(v, d, b);
      M.removeProof(v, b.id);
      return backToUnconfirmed && b.proof === null && K.confirmationBadge(b).includes('✓ Bank-confirmed');
    })());
  check('Proof: renaming a card keeps its proof (provider/last-4 cannot change, so proof stays attached)',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 1000, proof: proofRecord('match') });
      M.renameAccount(v, a.id, 'UBL Salary');
      return a.proof && a.proof.status === 'match' && a.nickname === 'UBL Salary' && M.reconcile(v).ok;
    })());
  check('Proof: an old vault without proof fields loads as unconfirmed, and the proof survives an encrypted round-trip',
    (await (async () => {
      const v = M.emptyVault();
      v.accounts.push({ id: 'old1', provider: 'UBL', type: 'debit', nickname: 'Old', last4: '1111', balance: 100, startingBalance: 100, createdAt: '2026-11-06T00:00:00.000Z' });
      M.migrateVault(v);
      if (v.accounts[0].proof !== null || !K.confirmationBadge(v.accounts[0]).includes('Not confirmed yet')) return false;
      const w = M.emptyVault();
      M.createAccount(w, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 1000, proof: proofRecord('self-checked') });
      const made = await V.createVault('123456', 'my secret', w);
      const back = await V.decryptVault(made.key, made.envelope);
      return back.accounts[0].proof && back.accounts[0].proof.status === 'self-checked'
        && K.confirmationBadge(back.accounts[0]).includes('self-checked');
    })()) === true);

  // ---- §9f (cont). Phase 3.3: proof UI structure ----
  check('Proof UI: the Add page has the proof upload field, preview and self-check button',
    pageHtml('add').includes('id="add-proof"') && pageHtml('add').includes('id="add-proof-status"')
    && pageHtml('add').includes('id="add-proof-preview"') && pageHtml('add').includes('id="add-proof-img"')
    && pageHtml('add').includes('id="add-proof-typed"') && pageHtml('add').includes('id="add-proof-selfcheck-btn"')
    && pageHtml('add').includes('id="add-proof-error"')
    && pageHtml('add').includes('I checked — this matches'));
  check('Proof UI: the Add page note says a statement cannot prove a card, and screenshots are self-checked',
    pageHtml('add').includes('id="add-honest-note"')
    && pageHtml('add').includes('A statement is your own record of proof.')
    && pageHtml('add').includes('it cannot prove a card is real')
    && pageHtml('add').includes("A screenshot's text can't be read by the app — for screenshots, you check the match yourself."));
  check('Proof UI: the card shows View proof + a two-tap Remove proof; the proof rides along on add',
    appJs.includes('proofActionsHtml') && appJs.includes('class="proof-link"')
    && appJs.includes('data-action="remove-proof"') && appJs.includes('data-action="confirm-remove-proof"')
    && appJs.includes('pendingProofRemoveId') && appJs.includes('VaultModel.removeProof')
    && appJs.includes('proof: state.addProof || null') && appJs.includes('onProofFile')
    && appJs.includes('onProofSelfCheck'));
  check('Proof UI: the self-check only happens on a deliberate tap — images never match automatically',
    P.checkProofMatch('image', 'UBL 1234 Muhammad Hashir', ublCard, 'Muhammad Hashir') === 'image'
    && appJs.includes("state.addProof.status = 'self-checked'")
    && !appJs.includes("checkProofMatch('image'"));

  // ---- §9g. Phase 4: monthly check (model) ----
  check('Monthly: a vault that was never reconciled is due',
    M.monthlyCheckDue(M.emptyVault(), '2026-11-06') === true);
  check('Monthly: done within 30 days is not due; 30 days is due again; 31 days is due',
    (() => {
      const v = M.emptyVault();
      v.lastReconcileAt = '2026-10-20';
      const fresh = M.monthlyCheckDue(v, '2026-11-06') === false;
      const thirty = M.monthlyCheckDue(v, '2026-11-19') === true;
      const thirtyOne = M.monthlyCheckDue(v, '2026-11-20') === true;
      return fresh && thirty && thirtyOne;
    })());
  check('Monthly: marking done sets today + the skipped count',
    (() => {
      const v = M.emptyVault();
      const done = M.markMonthlyCheckDone(v, 2);
      return done === M.todayStr() && v.lastReconcileAt === M.todayStr() && v.lastReconcileSkipped === 2
        && M.monthlyCheckDue(v) === false;
    })());
  check('Monthly: only bank-confirmed or statement-matched accounts are ready; the rest are pending or skipped',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'A', last4: '1111', balance: 1000 });
      const b = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'B', last4: '2222', balance: 2000, proof: proofRecord('match') });
      const c = M.createAccount(v, { provider: 'MCB', type: 'debit', nickname: 'C', last4: '3333', balance: 3000, proof: proofRecord('self-checked') });
      const d = S.parseSms('Rs 100.00 debited from your HBL account ••••1111 on 06-Nov-2026.');
      I.applyIntelUpdate(v, d, a);
      const none = M.monthlyCheckStatus(v, {});
      const skipped = M.monthlyCheckStatus(v, { [c.id]: true });
      return M.accountCheckReady(a) === true && M.accountCheckReady(b) === true
        && M.accountCheckReady(c) === false && none.ready === false && none.pending.length === 1
        && none.pending[0].id === c.id && skipped.ready === true && skipped.skippedCount === 1;
    })());
  check('Monthly: last confirmed date comes from the bank SMS first, else the statement, else null',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'HBL', type: 'debit', nickname: 'A', last4: '1111', balance: 1000 });
      const b = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'B', last4: '2222', balance: 2000, proof: proofRecord('match') });
      const c = M.createAccount(v, { provider: 'MCB', type: 'debit', nickname: 'C', last4: '3333', balance: 3000 });
      const d = S.parseSms('Rs 100.00 debited from your HBL account ••••1111 on 06-Nov-2026.');
      I.applyIntelUpdate(v, d, a);
      return M.lastConfirmedAt(a) === M.todayStr() && M.lastConfirmedAt(b) === '2026-11-06'
        && M.lastConfirmedAt(c) === null;
    })());
  check('Monthly: attachProof stores a valid record, rejects a bad one and an unknown account',
    (() => {
      const v = M.emptyVault();
      const a = M.createAccount(v, { provider: 'UBL', type: 'debit', nickname: 'UBL', last4: '1234', balance: 1000 });
      M.attachProof(v, a.id, proofRecord('match'));
      const attached = a.proof && a.proof.status === 'match';
      return attached
        && throwsCode(function () { M.attachProof(v, a.id, { kind: 'txt', name: 'x', dataUrl: 'data:text/plain;base64,aGVsbG8=', status: 'match' }); }, 'VALIDATION')
        && throwsCode(function () { M.attachProof(v, 'nope', proofRecord('match')); }, 'NOT_FOUND');
    })());
  check('Monthly: an old vault loads with lastReconcileAt null (check due)',
    (() => {
      const v = M.emptyVault();
      delete v.lastReconcileAt;
      delete v.lastReconcileSkipped;
      M.migrateVault(v);
      return v.lastReconcileAt === null && v.lastReconcileSkipped === 0 && M.monthlyCheckDue(v) === true;
    })());

  // ---- §9g (cont). Phase 4: monthly check UI structure ----
  check('Monthly UI: the Wallet page has the due banner + the done line',
    pageHtml('wallet').includes('id="monthly-banner"') && pageHtml('wallet').includes('id="monthly-banner-btn"')
    && pageHtml('wallet').includes('Monthly check due')
    && pageHtml('wallet').includes('id="monthly-done-line"') && pageHtml('wallet').includes('id="monthly-done-date"')
    && pageHtml('wallet').includes('Monthly check done on'));
  check('Monthly UI: the reconcile view lists accounts with badges, re-check actions, export + done buttons',
    pageHtml('reconcile').includes('id="reconcile-card"') && pageHtml('reconcile').includes('id="reconcile-list"')
    && pageHtml('reconcile').includes('id="reconcile-summary"') && pageHtml('reconcile').includes('id="reconcile-export-btn"')
    && pageHtml('reconcile').includes('id="reconcile-done-btn"') && pageHtml('reconcile').includes('id="reconcile-error"')
    && pageHtml('reconcile').includes('id="reconcile-ok"')
    && pageHtml('reconcile').includes('Mark monthly check done'));
  check('Monthly UI: the reconcile view is reached from the banner and the Backup page — NOT a sidebar button',
    N.PAGES.includes('reconcile') && N.routeForHash('#/reconcile') === 'reconcile'
    && !N.NAV_ORDER.some((n) => n.id === 'reconcile')
    && pageHtml('backup').includes('href="#/reconcile"') && pageHtml('backup').includes('Monthly check'));
  check('Monthly UI: the view reuses the SMS + statement flows and gates Mark-done on ready-or-skipped',
    appJs.includes('renderReconcile') && appJs.includes('VaultModel.monthlyCheckDue')
    && appJs.includes('VaultModel.monthlyCheckStatus') && appJs.includes('markMonthlyCheckDoneClick')
    && appJs.includes('toggleReconcileSkip') && appJs.includes('onReconcileProof')
    && appJs.includes("href=\"#/intelligence\"") && appJs.includes('Proof.checkProofMatch')
    && appJs.includes('VaultModel.attachProof') && appJs.includes("reconcile-done-btn').disabled = !st.ready")
    && appJs.includes('data-rec-skip'));
  check('Monthly UI: the banner hides once the check is marked done (render toggles on monthlyCheckDue)',
    appJs.includes("monthly-banner').classList.toggle('hidden', !due")
    && appJs.includes("monthly-done-line').classList.toggle('hidden', due"));

  // 5e. Live smoke on a throwaway port (the real port 3036 is checked by hand below).
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
      try { await req('GET', '/health'); up = true; } catch (_e) { await new Promise((r) => setTimeout(r, 200)); }
    }
    check('Smoke: server comes up on a fresh port', up);
    check('Smoke: /health ok', (await req('GET', '/health')).status === 200);
    for (const p of ['/', '/index.html', '/styles.css', '/vault.js', '/model.js', '/sms.js', '/csv.js', '/cards.js', '/intel.js', '/proof.js', '/totp.js', '/nav.js', '/app.js', '/bg.jpg']) {
      check('Smoke: GET ' + p + ' -> 200', (await req('GET', p)).status === 200);
    }
    const home = await req('GET', '/');
    check('Smoke: homepage mentions the vault + no-recovery warning',
      home.raw.includes('Personal Card Vault') && home.raw.includes('No recovery, by design'));
    check('Smoke: the monthly-check page is in the served HTML (hash route #/reconcile)',
      home.raw.includes('id="page-reconcile"') && home.raw.includes('id="monthly-banner"'));
    check('Smoke: homepage loads all nine shared scripts',
      home.raw.includes('/vault.js') && home.raw.includes('/model.js')
      && home.raw.includes('/sms.js') && home.raw.includes('/csv.js')
      && home.raw.includes('/cards.js') && home.raw.includes('/intel.js')
      && home.raw.includes('/proof.js') && home.raw.includes('/totp.js') && home.raw.includes('/nav.js'));
    check('Smoke: unknown page -> 404', (await req('GET', '/nope.html')).status === 404);
  } finally {
    server.kill();
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  if (failed > 0) { console.log('TESTS FAILED'); process.exit(1); }
  console.log('ALL TESTS PASSED');
}

main().catch((e) => { console.error('TEST RUNNER ERROR', e); process.exit(1); });
