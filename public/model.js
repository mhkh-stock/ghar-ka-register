// Ghar ka Register — data model (browser + Node tests).
// Pure functions over the vault object. No DOM, no storage, no crypto.
//
// The vault object (version 2, inside the same encrypted envelope as the
// old app — PBKDF2 + AES-256-GCM, see vault.js):
//   { version: 2, householdName, monthStartDay,
//     staff: [{ id, name, role, salaryPkr, joinedDate, leavePerMonth,
//               phone, advances: [{ id, amount, date, note,
//               recovery: 'full'|'instalments', instalmentPkr, recoveredPkr }],
//               attendance: { 'YYYY-MM-DD': 'present'|'absent'|'half' },
//               paidMonths: [{ month: 'YYYY-MM', working, netPkr, paidDate }] }],
//     deliveries: [{ id, name, kind, unit, ratePkr, usualQty,
//               log: { 'YYYY-MM-DD': qty },
//               paidMonths: [{ month, totalPkr, paidDate }] }],
//     udhaar: [{ id, person, entries: [{ id, direction: 'lent'|'borrowed',
//               amountPkr, date, reason, dueDate,
//               repayments: [{ amountPkr, date }], forgivenPkr, settled: bool }] }],
//     bills: [{ id, type, provider, accountNo, amountPkr, dueDate,
//             surchargeNote, status: 'due'|'paid', paidDate }],
//     documents: [{ id, type, owner, issueDate, expiryDate,
//               photo: { dataUrl, mime } | null, checklistKey }],
//     medicines: [{ id, name, qtyLeft, unit, expiryDate, place, person,
//               dosesPerDay, lowStockAt, dosesTaken: [{ date, time }] }],
//     settings: { reminders: { docDays: [30,14,7,1], medDays: [30,7] } } }
//
// Rules (binding, from the vault failure):
//   R1: the app never claims anything about the data. Every record is
//       shown "as you entered it"; every computed figure shows its working.
//   R2: no live data. Every number and date is typed by the user.
//   R3: value in the first minute.
// Money: integer rupees only, never decimals; every total is a pure
// function of the stored rows (recompute, never store a total).
// Migration: a v1 vault (card data) is NOT migrated. The first run of
// this app creates a fresh v2 vault; an old encrypted backup restores
// only into the old code. isGharVault() tells the two apart.
'use strict';

const STAFF_ROLES = ['maid', 'cook', 'driver', 'guard', 'gardener', 'caretaker', 'other'];
const DELIVERY_KINDS = ['Doodhwala', 'Newspaper', 'Gas cylinder', 'Water can', 'Ironing', 'other'];
const DELIVERY_UNITS = ['litre', 'day', 'cylinder', 'piece'];
const BILL_TYPES = ['electricity', 'gas', 'water', 'internet', 'mobile', 'rent', 'school fee', 'other'];
const DOCUMENT_TYPES = ['CNIC', 'passport', 'driving licence', 'vehicle registration',
  'vehicle token', 'domicile', 'birth certificate', 'insurance', 'warranty', 'other'];
const MEDICINE_PLACES = ['fridge', 'cupboard', 'first-aid box', 'travel kit'];
const ATTENDANCE_MARKS = ['present', 'absent', 'half'];
const MAX_MONEY = 1000000000000; // Rs 1 trillion sanity cap per value
const MAX_PHOTO_BYTES = 500 * 1024; // 500 KB photo cap (downscaled before storing)

function fail(code, message, errors) {
  const e = new Error(message);
  e.code = code;
  if (errors) e.errors = errors;
  return e;
}
function newId() {
  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}
function roundRs(x) { return Math.round(x); }
function isIntRs(n) {
  return typeof n === 'number' && Number.isFinite(n) && Number.isInteger(n) && n >= 0 && n <= MAX_MONEY;
}
function isDateStr(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}
function todayStr() { return new Date().toISOString().slice(0, 10); }
function daysBetween(fromDateStr, toDateStr) {
  const from = new Date(fromDateStr + 'T00:00:00Z');
  const to = new Date(toDateStr + 'T00:00:00Z');
  if (isNaN(from.getTime()) || isNaN(to.getTime())) return Infinity;
  return Math.floor((to - from) / 86400000);
}
function fmtRs(n) { return 'Rs ' + Number(n || 0).toLocaleString('en-PK'); }
function trimStr(v, max) {
  const s = String(v == null ? '' : v).trim();
  return max ? s.slice(0, max) : s;
}

// A v2 vault is the only vault this app opens. A v1 vault (the old card
// app: { v: 1, accounts: [...] }) is NOT migrated — it opens only in the
// old code, and the app says so instead of guessing.
function isGharVault(v) {
  return !!v && typeof v === 'object' && v.version === 2
    && Array.isArray(v.staff) && Array.isArray(v.deliveries)
    && Array.isArray(v.udhaar) && Array.isArray(v.bills)
    && Array.isArray(v.documents) && Array.isArray(v.medicines);
}

function emptyVault() {
  return {
    version: 2,
    householdName: '',
    monthStartDay: 1,
    createdAt: new Date().toISOString(),
    staff: [],
    deliveries: [],
    udhaar: [],
    bills: [],
    documents: [],
    medicines: [],
    settings: { reminders: { docDays: [30, 14, 7, 1], medDays: [30, 7] } },
  };
}

// ---- Household settings (Profile page) ----
function setHousehold(vault, input) {
  const errors = [];
  if (!vault || typeof vault !== 'object') throw fail('VALIDATION', 'Vault is required.');
  const name = trimStr(input && input.householdName, 60);
  const day = Number(input && input.monthStartDay);
  if (!Number.isInteger(day) || day < 1 || day > 28) {
    errors.push('month start day must be a day from 1 to 28');
  }
  if (errors.length) throw fail('VALIDATION', 'Household settings are not valid.', errors);
  vault.householdName = name;
  vault.monthStartDay = day;
  return { householdName: name, monthStartDay: day };
}

// ---- Staff ----
function validateStaff(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['helper is required'];
  const name = trimStr(input.name, 60);
  if (!name) errors.push('name is required');
  if (!STAFF_ROLES.includes(input.role)) errors.push('role must be one of: ' + STAFF_ROLES.join(', '));
  if (!isIntRs(Number(input.salaryPkr)) || Number(input.salaryPkr) <= 0) {
    errors.push('monthly salary must be whole rupees above 0');
  }
  if (!isDateStr(input.joinedDate)) errors.push('joined date must be YYYY-MM-DD');
  const leave = Number(input.leavePerMonth);
  if (!Number.isInteger(leave) || leave < 0 || leave > 31) {
    errors.push('paid leave per month must be a whole number from 0 to 31');
  }
  const phone = trimStr(input.phone, 20);
  if (phone && !/^03\d{9}$/.test(phone.replace(/[\s-]/g, ''))) {
    errors.push('phone must look like an 03xx number, or be left empty');
  }
  return errors;
}
function addStaff(vault, input) {
  const errors = validateStaff(input);
  if (errors.length) throw fail('VALIDATION', 'Helper is not valid.', errors);
  const helper = {
    id: newId(),
    name: trimStr(input.name, 60),
    role: input.role,
    salaryPkr: Number(input.salaryPkr),
    joinedDate: input.joinedDate,
    leavePerMonth: Number(input.leavePerMonth),
    phone: trimStr(input.phone, 20),
    advances: [],
    attendance: {},
    paidMonths: [],
  };
  vault.staff.push(helper);
  return helper;
}
function findStaff(vault, id) {
  return (vault.staff || []).find((s) => s.id === id) || null;
}
function isMonthKey(s) {
  return typeof s === 'string' && /^\d{4}-(0[1-9]|1[0-2])$/.test(s);
}
function daysInMonth(monthKey) {
  const y = Number(monthKey.slice(0, 4));
  const m = Number(monthKey.slice(5, 7));
  return new Date(Date.UTC(y, m, 0)).getUTCDate();
}
function monthKeyOf(dateStr) { return String(dateStr).slice(0, 7); }
function findPaidStaffMonth(helper, monthKey) {
  return (helper.paidMonths || []).find((pm) => pm.month === monthKey) || null;
}
function isStaffMonthPaid(helper, monthKey) { return !!findPaidStaffMonth(helper, monthKey); }

// Attendance: only exceptions are stored. Marking a day 'present' deletes
// any stored mark for it (present is the default); 'absent' / 'half' store
// the exception. A month already marked paid is locked: no edits to it.
function markAttendance(vault, staffId, dateStr, mark) {
  const helper = findStaff(vault, staffId);
  if (!helper) throw fail('NOT_FOUND', 'Helper does not exist.');
  const m = mark === undefined || mark === null ? 'present' : mark;
  if (!isDateStr(dateStr)) throw fail('VALIDATION', 'Date must be YYYY-MM-DD.');
  if (!ATTENDANCE_MARKS.includes(m)) throw fail('VALIDATION', 'Attendance mark must be present, absent or half.');
  if (isStaffMonthPaid(helper, monthKeyOf(dateStr))) {
    throw fail('LOCKED', 'That month is already marked paid and cannot be edited.');
  }
  if (m === 'present') delete helper.attendance[dateStr];
  else helper.attendance[dateStr] = m;
  return { date: dateStr, mark: m };
}
function attendanceCounts(helper, monthKey) {
  let absentDays = 0, halfDays = 0;
  for (const [dateStr, mark] of Object.entries(helper.attendance || {})) {
    if (monthKeyOf(dateStr) !== monthKey) continue;
    if (mark === 'absent') absentDays++;
    else if (mark === 'half') halfDays++;
  }
  return { absentDays, halfDays };
}

// Advances: amount is whole rupees; 'instalments' needs a whole-rupee
// instalment above 0. recoveredPkr starts at 0 and only grows when a
// month is marked paid (see markMonthPaid).
function addAdvance(vault, staffId, input) {
  const helper = findStaff(vault, staffId);
  if (!helper) throw fail('NOT_FOUND', 'Helper does not exist.');
  const errors = [];
  if (!input || typeof input !== 'object') errors.push('advance is required');
  const amount = Number(input && input.amount);
  if (!isIntRs(amount) || amount <= 0) errors.push('advance amount must be whole rupees above 0');
  if (!isDateStr(input && input.date)) errors.push('advance date must be YYYY-MM-DD');
  const recovery = (input && input.recovery) || 'full';
  if (recovery !== 'full' && recovery !== 'instalments') {
    errors.push("recovery must be 'full' or 'instalments'");
  }
  const instalment = Number(input && input.instalmentPkr);
  if (recovery === 'instalments' && (!isIntRs(instalment) || instalment <= 0)) {
    errors.push('instalment amount must be whole rupees above 0 for instalment recovery');
  }
  const note = trimStr(input && input.note, 120);
  if (String((input && input.note) || '').trim().length > 120) errors.push('advance note must be 120 characters or fewer');
  if (errors.length) throw fail('VALIDATION', 'Advance is not valid.', errors);
  if (isStaffMonthPaid(helper, monthKeyOf(input.date))) {
    throw fail('LOCKED', 'That month is already marked paid and cannot be edited.');
  }
  const adv = {
    id: newId(),
    amount,
    date: input.date,
    note,
    recovery,
    instalmentPkr: recovery === 'instalments' ? instalment : 0,
    recoveredPkr: 0,
  };
  helper.advances.push(adv);
  return adv;
}
function advanceRemaining(adv) {
  return roundRs(Number(adv.amount || 0) - Number(adv.recoveredPkr || 0));
}
function staffRemainingAdvance(helper) {
  return (helper.advances || []).reduce((s, a) => s + advanceRemaining(a), 0);
}
// What this month recovers from one advance: 'full' takes everything
// still remaining; 'instalments' takes exactly one instalment (or the
// remainder, when less than one instalment is left).
function advanceMonthRecovery(adv) {
  const remaining = advanceRemaining(adv);
  if (remaining <= 0) return 0;
  if (adv.recovery === 'instalments') return Math.min(Number(adv.instalmentPkr) || 0, remaining);
  return remaining;
}

// Month-end pay, worked out line by line. Rounding: every deduction is
// rounded to the nearest whole rupee (halves round up, Math.round) —
// absent deduction = absentDays x (salary / 30), half-day deduction =
// halfDays x (salary / 60). The paid-leave allowance is recorded on the
// helper but does not change the working: every absent day is deducted,
// exactly as the acceptance example shows (3 absent days on Rs 15,000
// deduct Rs 1,500). Returns exactly the working fields; nothing is stored.
function payWorkingForHelper(helper, monthKey) {
  const salary = Number(helper.salaryPkr || 0);
  const counts = attendanceCounts(helper, monthKey);
  const absentDeduction = roundRs(counts.absentDays * salary / 30);
  const halfDeduction = roundRs(counts.halfDays * salary / 60);
  const advanceRecovery = (helper.advances || []).reduce((s, a) => s + advanceMonthRecovery(a), 0);
  return {
    salaryPkr: salary,
    absentDays: counts.absentDays,
    halfDays: counts.halfDays,
    absentDeduction,
    halfDeduction,
    advanceRecovery,
    netPkr: roundRs(salary - absentDeduction - halfDeduction - advanceRecovery),
    daysInMonth: daysInMonth(monthKey),
  };
}
function computeMonthPay(vault, staffId, monthKey) {
  const helper = findStaff(vault, staffId);
  if (!helper) throw fail('NOT_FOUND', 'Helper does not exist.');
  if (!isMonthKey(monthKey)) throw fail('VALIDATION', 'Month must be YYYY-MM.');
  if (isStaffMonthPaid(helper, monthKey)) {
    throw fail('LOCKED', 'That month is already marked paid and cannot be edited.');
  }
  return payWorkingForHelper(helper, monthKey);
}
// Mark a month paid: stores the working + net + paid date, applies this
// month's advance recovery to each advance (recoveredPkr grows), and
// locks the month — after this, attendance / advances / pay for the
// month all refuse. Marking an already-paid month refuses.
function markMonthPaid(vault, staffId, monthKey, paidDate) {
  const helper = findStaff(vault, staffId);
  if (!helper) throw fail('NOT_FOUND', 'Helper does not exist.');
  if (!isMonthKey(monthKey)) throw fail('VALIDATION', 'Month must be YYYY-MM.');
  if (paidDate !== undefined && paidDate !== null && paidDate !== '' && !isDateStr(paidDate)) {
    throw fail('VALIDATION', 'Paid date must be YYYY-MM-DD or empty.');
  }
  if (isStaffMonthPaid(helper, monthKey)) {
    throw fail('LOCKED', 'That month is already marked paid.');
  }
  const working = payWorkingForHelper(helper, monthKey);
  for (const adv of (helper.advances || [])) {
    adv.recoveredPkr = roundRs(Number(adv.recoveredPkr || 0) + advanceMonthRecovery(adv));
  }
  const record = { month: monthKey, working, netPkr: working.netPkr, paidDate: paidDate || todayStr() };
  helper.paidMonths.push(record);
  return record;
}
// Plain-text pay statement, ready to copy to WhatsApp. The app sends
// nothing itself. For a paid month the stored working is used; for an
// open month the working is worked out from the rows as entered.
function staffPayStatement(helper, monthKey) {
  if (!helper || typeof helper !== 'object') throw fail('NOT_FOUND', 'Helper does not exist.');
  if (!isMonthKey(monthKey)) throw fail('VALIDATION', 'Month must be YYYY-MM.');
  const paid = findPaidStaffMonth(helper, monthKey);
  const w = paid ? paid.working : payWorkingForHelper(helper, monthKey);
  const absentRate = roundRs(Number(helper.salaryPkr || 0) / 30);
  const halfRate = roundRs(Number(helper.salaryPkr || 0) / 60);
  const lines = [
    'Ghar ka Register — pay statement (as you entered it)',
    'Helper: ' + helper.name + ' (' + helper.role + ')',
    'Month: ' + monthKey,
    'Monthly salary: ' + fmtRs(w.salaryPkr),
    'Absent days: ' + w.absentDays + ' x ' + fmtRs(absentRate) + ' = ' + fmtRs(w.absentDeduction),
    'Half days: ' + w.halfDays + ' x ' + fmtRs(halfRate) + ' = ' + fmtRs(w.halfDeduction),
    'Advance recovery: ' + fmtRs(w.advanceRecovery),
    'Net payable: ' + fmtRs(w.salaryPkr) + ' - ' + fmtRs(w.absentDeduction)
      + ' - ' + fmtRs(w.halfDeduction) + ' - ' + fmtRs(w.advanceRecovery)
      + ' = ' + fmtRs(w.netPkr),
  ];
  if (paid) lines.push('Paid on ' + paid.paidDate + ' — this month is locked.');
  else lines.push('Not yet marked paid — as you entered it.');
  return lines.join('\n');
}

// ---- Deliveries ----
function validateDelivery(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['delivery is required'];
  const name = trimStr(input.name, 60);
  if (!name) errors.push('name is required');
  if (!DELIVERY_KINDS.includes(input.kind)) errors.push('kind must be one of: ' + DELIVERY_KINDS.join(', '));
  if (!DELIVERY_UNITS.includes(input.unit)) errors.push('unit must be one of: ' + DELIVERY_UNITS.join(', '));
  if (!isIntRs(Number(input.ratePkr)) || Number(input.ratePkr) <= 0) {
    errors.push('rate per unit must be whole rupees above 0');
  }
  const qty = Number(input.usualQty);
  if (!Number.isFinite(qty) || qty < 0 || qty > 10000) {
    errors.push('usual quantity per day must be a number from 0 up');
  }
  return errors;
}
function addDelivery(vault, input) {
  const errors = validateDelivery(input);
  if (errors.length) throw fail('VALIDATION', 'Delivery is not valid.', errors);
  const d = {
    id: newId(),
    name: trimStr(input.name, 60),
    kind: input.kind,
    unit: input.unit,
    ratePkr: Number(input.ratePkr),
    usualQty: Number(input.usualQty),
    log: {},
    refills: [],
    paidMonths: [],
  };
  vault.deliveries.push(d);
  return d;
}
function findDelivery(vault, id) {
  return (vault.deliveries || []).find((d) => d.id === id) || null;
}
function findPaidDeliveryMonth(delivery, monthKey) {
  return (delivery.paidMonths || []).find((pm) => pm.month === monthKey) || null;
}
function isDeliveryMonthPaid(delivery, monthKey) { return !!findPaidDeliveryMonth(delivery, monthKey); }

// Daily log: quantity delivered that day (default the usual; the page
// fills it in). qty 0 = a skipped day, stored as 0 so the month total
// can show the skipped days. A paid month is locked: no log edits to it.
function logDelivery(vault, deliveryId, dateStr, qty) {
  const d = findDelivery(vault, deliveryId);
  if (!d) throw fail('NOT_FOUND', 'Delivery does not exist.');
  if (!isDateStr(dateStr)) throw fail('VALIDATION', 'Date must be YYYY-MM-DD.');
  const q = Number(qty);
  if (!Number.isFinite(q) || q < 0 || q > 10000) {
    throw fail('VALIDATION', 'Quantity must be a number from 0 to 10000.');
  }
  if (isDeliveryMonthPaid(d, monthKeyOf(dateStr))) {
    throw fail('LOCKED', 'That month is already marked paid and cannot be edited.');
  }
  d.log[dateStr] = q;
  return { date: dateStr, qty: q };
}
// Gas cylinder refills: a refill record { date, pricePkr }. The price is
// whole rupees, as entered. Days since the last refill is worked out
// from the refill dates, never stored.
function addGasRefill(vault, deliveryId, input) {
  const d = findDelivery(vault, deliveryId);
  if (!d) throw fail('NOT_FOUND', 'Delivery does not exist.');
  const errors = [];
  if (!input || typeof input !== 'object') errors.push('refill is required');
  if (!isDateStr(input && input.date)) errors.push('refill date must be YYYY-MM-DD');
  const price = Number(input && input.pricePkr);
  if (!isIntRs(price) || price <= 0) errors.push('refill price must be whole rupees above 0');
  if (errors.length) throw fail('VALIDATION', 'Refill is not valid.', errors);
  const refill = { date: input.date, pricePkr: price };
  d.refills.push(refill);
  d.refills.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
  return refill;
}
function lastGasRefill(delivery) {
  const list = (delivery && delivery.refills) || [];
  return list.length ? list[list.length - 1] : null;
}
function gasDaysSinceLastRefill(delivery, today) {
  const last = lastGasRefill(delivery);
  if (!last) return null;
  return daysBetween(last.date, today || todayStr());
}
// Monthly total, recomputed from the daily log rows every time. Days
// that were never logged contribute nothing. lines groups the logged
// days by quantity, so the working reads like "28 x 1 litre x Rs 220 =
// Rs 6,160" (and a skipped-days line shows "2 x 0 = Rs 0").
function deliveryMonthTotal(vault, deliveryId, monthKey) {
  const d = findDelivery(vault, deliveryId);
  if (!d) throw fail('NOT_FOUND', 'Delivery does not exist.');
  if (!isMonthKey(monthKey)) throw fail('VALIDATION', 'Month must be YYYY-MM.');
  const byQty = {};
  let days = 0, skippedDays = 0, total = 0;
  for (const [dateStr, qty] of Object.entries(d.log || {})) {
    if (monthKeyOf(dateStr) !== monthKey) continue;
    const q = Number(qty) || 0;
    days++;
    if (q === 0) skippedDays++;
    total += q * Number(d.ratePkr);
    byQty[String(q)] = (byQty[String(q)] || 0) + 1;
  }
  const lines = Object.keys(byQty)
    .map((k) => Number(k))
    .sort((a, b) => b - a)
    .map((q) => {
      const n = byQty[String(q)];
      const amount = roundRs(q * n * Number(d.ratePkr));
      return {
        qty: q, days: n, ratePkr: Number(d.ratePkr), amountPkr: amount,
        text: n + ' x ' + q + ' ' + d.unit + ' x ' + fmtRs(d.ratePkr) + ' = ' + fmtRs(amount),
      };
    });
  return { totalPkr: roundRs(total), days, skippedDays, lines };
}
// Mark a delivery month paid: stores the recomputed total + paid date
// and locks the month — no further log edits for it. Already paid refuses.
function markDeliveryMonthPaid(vault, deliveryId, monthKey, paidDate) {
  const d = findDelivery(vault, deliveryId);
  if (!d) throw fail('NOT_FOUND', 'Delivery does not exist.');
  if (!isMonthKey(monthKey)) throw fail('VALIDATION', 'Month must be YYYY-MM.');
  if (paidDate !== undefined && paidDate !== null && paidDate !== '' && !isDateStr(paidDate)) {
    throw fail('VALIDATION', 'Paid date must be YYYY-MM-DD or empty.');
  }
  if (isDeliveryMonthPaid(d, monthKey)) {
    throw fail('LOCKED', 'That month is already marked paid.');
  }
  const total = deliveryMonthTotal(vault, deliveryId, monthKey);
  const record = { month: monthKey, totalPkr: total.totalPkr, paidDate: paidDate || todayStr() };
  d.paidMonths.push(record);
  return record;
}

// ---- Udhaar ----
function validateUdhaarPerson(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['person is required'];
  if (!trimStr(input.person, 60)) errors.push('person name is required');
  return errors;
}
function addUdhaarPerson(vault, input) {
  const errors = validateUdhaarPerson(input);
  if (errors.length) throw fail('VALIDATION', 'Person is not valid.', errors);
  const p = { id: newId(), person: trimStr(input.person, 60), entries: [] };
  vault.udhaar.push(p);
  return p;
}
function findUdhaarPerson(vault, id) {
  return (vault.udhaar || []).find((p) => p.id === id) || null;
}
function validateUdhaarEntry(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['udhaar entry is required'];
  if (input.direction !== 'lent' && input.direction !== 'borrowed') {
    errors.push('direction must be lent or borrowed');
  }
  if (!isIntRs(Number(input.amountPkr)) || Number(input.amountPkr) <= 0) {
    errors.push('amount must be whole rupees above 0');
  }
  if (!isDateStr(input.date)) errors.push('date must be YYYY-MM-DD');
  const reason = trimStr(input.reason, 120);
  if (String(input.reason || '').trim().length > 120) errors.push('reason must be 120 characters or fewer');
  if (input.dueDate !== undefined && input.dueDate !== null && input.dueDate !== '' && !isDateStr(input.dueDate)) {
    errors.push('due date must be YYYY-MM-DD or empty');
  }
  return errors;
}
function addUdhaarEntry(vault, personId, input) {
  const person = findUdhaarPerson(vault, personId);
  if (!person) throw fail('NOT_FOUND', 'Person does not exist.');
  const errors = validateUdhaarEntry(input);
  if (errors.length) throw fail('VALIDATION', 'Udhaar entry is not valid.', errors);
  const entry = {
    id: newId(),
    direction: input.direction,
    amountPkr: Number(input.amountPkr),
    date: input.date,
    reason: trimStr(input.reason, 120),
    dueDate: input.dueDate || null,
    repayments: [],
    forgivenPkr: 0,
    settled: false,
  };
  person.entries.push(entry);
  return entry;
}
// Running balance of one entry: amount − repayments − forgiven. Pure
// recompute from the rows; the balance is never stored.
function udhaarEntryBalance(entry) {
  if (!entry) return 0;
  const repaid = (entry.repayments || []).reduce((s, r) => s + (Number(r.amountPkr) || 0), 0);
  return roundRs(Number(entry.amountPkr || 0) - repaid - (Number(entry.forgivenPkr) || 0));
}
function udhaarPersonBalance(person) {
  if (!person) return { lent: 0, borrowed: 0 };
  let lent = 0, borrowed = 0;
  for (const e of (person.entries || [])) {
    const bal = udhaarEntryBalance(e);
    if (e.direction === 'lent') lent = roundRs(lent + bal);
    else borrowed = roundRs(borrowed + bal);
  }
  return { lent, borrowed };
}
function findUdhaarEntry(person, entryId) {
  if (!person) return null;
  return (person.entries || []).find((e) => e.id === entryId) || null;
}
// Record one repayment against an entry. Repayments are append-only in
// v1: there is no edit or delete for them. The amount must be whole
// rupees above 0 and must not exceed the outstanding balance — an
// overpayment is refused, never silently trimmed. When the balance hits
// zero the entry is stamped settled. A settled entry refuses any further
// repayment (code SETTLED): settling is the end of the entry, and a
// repayment after settling would mean the balance was wrong — the user
// reopens it by recording the entry again, not by paying into a settled
// one. (There is no edit in v1 that could reopen a settled entry.)
function recordRepayment(vault, personId, entryId, input) {
  const person = findUdhaarPerson(vault, personId);
  if (!person) throw fail('NOT_FOUND', 'Person does not exist.');
  const entry = findUdhaarEntry(person, entryId);
  if (!entry) throw fail('NOT_FOUND', 'Udhaar entry does not exist.');
  if (entry.settled) throw fail('SETTLED', 'That entry is already settled — nothing is outstanding.');
  const errors = [];
  if (!input || typeof input !== 'object') errors.push('repayment is required');
  const amount = Number(input && input.amountPkr);
  if (!isIntRs(amount) || amount <= 0) errors.push('repayment amount must be whole rupees above 0');
  if (!isDateStr(input && input.date)) errors.push('repayment date must be YYYY-MM-DD');
  if (errors.length) throw fail('VALIDATION', 'Repayment is not valid.', errors);
  const outstanding = udhaarEntryBalance(entry);
  if (amount > outstanding) {
    throw fail('VALIDATION', 'Repayment of ' + fmtRs(amount) + ' is more than the outstanding balance of ' + fmtRs(outstanding) + '.');
  }
  const repayment = { amountPkr: amount, date: input.date };
  entry.repayments.push(repayment);
  if (udhaarEntryBalance(entry) === 0) entry.settled = true;
  return repayment;
}
// Forgive an amount: forgivenPkr grows by the amount, capped at the
// outstanding balance. The forgiven amount is recorded as forgiven,
// never as a payment that never happened. Forgiving the last of the
// balance stamps the entry settled, like a final repayment does.
function forgiveUdhaar(vault, personId, entryId, amountPkr) {
  const person = findUdhaarPerson(vault, personId);
  if (!person) throw fail('NOT_FOUND', 'Person does not exist.');
  const entry = findUdhaarEntry(person, entryId);
  if (!entry) throw fail('NOT_FOUND', 'Udhaar entry does not exist.');
  if (entry.settled) throw fail('SETTLED', 'That entry is already settled — nothing is outstanding.');
  const amount = Number(amountPkr);
  if (!isIntRs(amount) || amount <= 0) {
    throw fail('VALIDATION', 'Forgiven amount must be whole rupees above 0.');
  }
  const outstanding = udhaarEntryBalance(entry);
  if (amount > outstanding) {
    throw fail('VALIDATION', 'Forgiven amount of ' + fmtRs(amount) + ' is more than the outstanding balance of ' + fmtRs(outstanding) + '.');
  }
  entry.forgivenPkr = roundRs(Number(entry.forgivenPkr || 0) + amount);
  if (udhaarEntryBalance(entry) === 0) entry.settled = true;
  return { forgivenPkr: entry.forgivenPkr, balance: udhaarEntryBalance(entry), settled: entry.settled };
}
// Plain-text reminder, ready to copy to WhatsApp. The app sends nothing
// itself. It names the person, the outstanding balance, the original
// amount, what was already repaid or forgiven, and the date — all as
// entered. A settled entry gets a settled note, not a payment request.
function udhaarReminderText(person, entry) {
  if (!person || typeof person !== 'object' || !entry || typeof entry !== 'object') {
    throw fail('NOT_FOUND', 'Person or entry does not exist.');
  }
  const name = person.person || '';
  const bal = udhaarEntryBalance(entry);
  if (bal <= 0) {
    return 'Assalam-o-Alaikum ' + name + ', the udhaar of ' + fmtRs(entry.amountPkr)
      + ' from ' + entry.date + ' is now settled — nothing is outstanding. Shukriya!';
  }
  const repaid = (entry.repayments || []).reduce((s, r) => s + (Number(r.amountPkr) || 0), 0);
  const forgiven = Number(entry.forgivenPkr || 0);
  // Lent: ask the person to pay when they can. Borrowed: the direction
  // is the other way round — this is a promise to pay them back, not a
  // request that they pay us. (Fixed in the Phase 5 second pass: the old
  // text asked a lender to "ada kar dein" for money we owed them.)
  if (entry.direction === 'borrowed') {
    let text = 'Assalam-o-Alaikum ' + name + ', I borrowed ' + fmtRs(bal) + ' from you on ' + entry.date
      + ' — ' + fmtRs(entry.amountPkr) + ' in total';
    if (repaid > 0) text += ', ' + fmtRs(repaid) + ' already repaid';
    if (forgiven > 0) text += ', ' + fmtRs(forgiven) + ' forgiven';
    if (entry.reason) text += ', for ' + entry.reason;
    text += '. I will pay the rest back as soon as I can. Shukriya!';
    return text;
  }
  let text = 'Assalam-o-Alaikum ' + name + ', ' + fmtRs(bal) + ' udhaar tha'
    + ' (you borrowed it from me on ' + entry.date + ')'
    + ' — ' + fmtRs(entry.amountPkr) + ' in total';
  if (repaid > 0) text += ', ' + fmtRs(repaid) + ' already repaid';
  if (forgiven > 0) text += ', ' + fmtRs(forgiven) + ' forgiven';
  if (entry.reason) text += ', for ' + entry.reason;
  text += '. Jab asani ho to ada kar dein. Shukriya!';
  return text;
}

// ---- Bills (typed only — never fetched) ----
function validateBill(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['bill is required'];
  if (!BILL_TYPES.includes(input.type)) errors.push('type must be one of: ' + BILL_TYPES.join(', '));
  const provider = trimStr(input.provider, 60);
  if (!provider) errors.push('provider name is required');
  if (!isIntRs(Number(input.amountPkr)) || Number(input.amountPkr) <= 0) {
    errors.push('amount must be whole rupees above 0');
  }
  if (!isDateStr(input.dueDate)) errors.push('due date must be YYYY-MM-DD');
  if (input.accountNo !== undefined && input.accountNo !== null && String(input.accountNo).length > 40) {
    errors.push('account number must be 40 characters or fewer');
  }
  if (input.surchargeNote !== undefined && input.surchargeNote !== null && String(input.surchargeNote).length > 120) {
    errors.push('late-surcharge note must be 120 characters or fewer');
  }
  return errors;
}
function addBill(vault, input) {
  const errors = validateBill(input);
  if (errors.length) throw fail('VALIDATION', 'Bill is not valid.', errors);
  const bill = {
    id: newId(),
    type: input.type,
    provider: trimStr(input.provider, 60),
    accountNo: trimStr(input.accountNo, 40),
    amountPkr: Number(input.amountPkr),
    dueDate: input.dueDate,
    surchargeNote: trimStr(input.surchargeNote, 120),
    status: 'due',
    paidDate: null,
  };
  vault.bills.push(bill);
  return bill;
}
function findBill(vault, id) {
  return (vault.bills || []).find((b) => b.id === id) || null;
}
// Mark a bill paid: status 'due' -> 'paid', paid date recorded (today
// when none is given). A paid bill keeps its history and never shows on
// Today again (todayItems only lists 'due' bills). Marking an already
// paid bill refuses — the paid date is the record, not a toggle to tap
// twice.
function markBillPaid(vault, billId, paidDate) {
  const bill = findBill(vault, billId);
  if (!bill) throw fail('NOT_FOUND', 'Bill does not exist.');
  if (paidDate !== undefined && paidDate !== null && paidDate !== '' && !isDateStr(paidDate)) {
    throw fail('VALIDATION', 'Paid date must be YYYY-MM-DD or empty.');
  }
  if (bill.status === 'paid') throw fail('VALIDATION', 'That bill is already marked paid.');
  bill.status = 'paid';
  bill.paidDate = paidDate || todayStr();
  return bill;
}
// Back to 'due' with the paid date cleared, for a mistaken tap. It is
// the user's own record, so un-marking is allowed — the bill shows on
// Today again from its due date.
function markBillUnpaid(vault, billId) {
  const bill = findBill(vault, billId);
  if (!bill) throw fail('NOT_FOUND', 'Bill does not exist.');
  if (bill.status !== 'paid') throw fail('VALIDATION', 'That bill is not marked paid.');
  bill.status = 'due';
  bill.paidDate = null;
  return bill;
}
// Remove a bill (the user's own data). The UI asks twice; the model
// just removes it and returns it.
function deleteBill(vault, billId) {
  const idx = (vault.bills || []).findIndex((b) => b.id === billId);
  if (idx < 0) throw fail('NOT_FOUND', 'Bill does not exist.');
  return vault.bills.splice(idx, 1)[0];
}

// ---- Documents ----
// Days from today to the expiry date. Negative = already expired.
function documentDaysUntil(doc, today) {
  if (!doc || typeof doc !== 'object' || !isDateStr(doc.expiryDate)) return Infinity;
  return daysBetween(today || todayStr(), doc.expiryDate);
}
// Which reminder applies: 'expired' when past expiry, 'due-30' /
// 'due-14' / 'due-7' / 'due-1' when the expiry falls inside that
// reminder window, null when it is further away than the widest window.
// docDays defaults to settings.reminders.docDays ([30, 14, 7, 1]).
function documentReminder(doc, today, docDays) {
  const d = documentDaysUntil(doc, today);
  if (d === Infinity) return null;
  if (d < 0) return 'expired';
  const days = Array.isArray(docDays) && docDays.length
    ? docDays.slice().sort((a, b) => a - b) : [1, 7, 14, 30];
  for (const w of days) {
    if (d <= w) return 'due-' + w;
  }
  return null;
}
function findDocument(vault, id) {
  return (vault.documents || []).find((d) => d.id === id) || null;
}
// Renewal checklists: short static text, dated, for the 4 v1 types only.
// What to bring, where, and the fee as printed on the official site —
// each checklist carries its date and the note that rules change, so no
// fee or rule here is ever claimed as current. Fee figures matched
// against the official pages on 2026-11-06 (Phase 5), via secondary
// pages that cite them, because the official pages block automated reads:
//   CNIC Smart NIC Rs 750/1,500/2,500 + ordinary renewal Rs 400 — NADRA
//     fee structure, nadra.gov.pk/feeStructure (NADRA page last updated
//     17 Sep 2026, as reported Oct–Nov 2026).
//   Passport e-passport 36 pages / 5 years Rs 9,000 normal, Rs 15,000
//     urgent — DGIP fee schedule, dgip.gov.pk (DGIP page last modified
//     23 Oct 2026, as reported 3 Nov 2026; fee doubled 15 Oct 2026).
//   Driving licence renewal (Punjab, 1 year) motorcycle Rs 450, car
//     Rs 1,350, courier Rs 480 — DLIMS fee structure,
//     dlims.punjab.gov.pk (fee table as reported 31 Oct 2026).
//   Vehicle token (Punjab FY 2026-27) up to 1000cc Rs 20,000 once,
//     1001–2000cc 0.3% of invoice price a year, above 2000cc 0.4% —
//     Punjab Excise motor vehicle tax page, excise.punjab.gov.pk
//     (FY 2026-27 table; Punjab Finance Act 2026).
// Anything NOT matched to a source was softened to "ask the office"
// instead of printed as a figure (passport processing times, how early
// a licence can be renewed). Other types: no checklist yet.
const CHECKLIST_UPDATED = '2026-11-06';
const CHECKLISTS = {
  'CNIC': {
    title: 'CNIC renewal checklist',
    updated: CHECKLIST_UPDATED,
    items: [
      'Bring: your old CNIC (and your B-Form if it is a first CNIC).',
      'Where: a NADRA Registration Centre, or the Pak-ID app (id.nadra.gov.pk).',
      'Fee as printed by NADRA: Smart NIC renewal Rs 750 normal / Rs 1,500 urgent / Rs 2,500 executive; ordinary CNIC renewal Rs 400 normal.',
    ],
    note: 'Check with the office; rules change.',
  },
  'passport': {
    title: 'Passport renewal checklist',
    updated: CHECKLIST_UPDATED,
    items: [
      'Bring: your old passport and your CNIC.',
      'Where: a DGIP passport office, or onlinemrp.dgip.gov.pk.',
      'Fee as printed by DGIP (e-passport, 36 pages, 5 years): Rs 9,000 normal, Rs 15,000 urgent.',
      'Ask the office how long it takes — times change.',
    ],
    note: 'Check with the office; rules change.',
  },
  'driving licence': {
    title: 'Driving licence renewal checklist',
    updated: CHECKLIST_UPDATED,
    items: [
      'Bring: your old licence and your CNIC.',
      'Where: Dastak (dastak.punjab.gov.pk) or a Punjab Traffic Police licence centre.',
      'Fee as printed by DLIMS (Punjab, one year): motorcycle Rs 450, car Rs 1,350, plus Rs 480 courier. Late renewal adds a fine.',
      'Ask the office how early you can renew — rules change.',
    ],
    note: 'Check with the office; rules change.',
  },
  'vehicle token': {
    title: 'Vehicle token checklist',
    updated: CHECKLIST_UPDATED,
    items: [
      'Bring: the vehicle registration book or smart card, and your CNIC.',
      'Where: the Excise office, or ePay Punjab.',
      'Fee — token tax as printed by Excise (Punjab 2026-27): up to 1000cc Rs 20,000 once; 1001–2000cc 0.3% of the invoice price a year; above 2000cc 0.4% a year.',
      '10% off if the whole year is paid by 31 August.',
    ],
    note: 'Check with the office; rules change.',
  },
};
function getChecklist(type) {
  return CHECKLISTS[type] || null;
}
// Remove a document (the user's own data). The photo is stored inside
// the document, so deleting the document deletes its photo too. The UI
// asks twice; the model just removes it and returns it.
function deleteDocument(vault, docId) {
  const idx = (vault.documents || []).findIndex((d) => d.id === docId);
  if (idx < 0) throw fail('NOT_FOUND', 'Document does not exist.');
  return vault.documents.splice(idx, 1)[0];
}

// ---- Document photos ----
// A photo is a JPEG or PNG data URL. The type is read from the file's
// magic bytes — never from the file name or the claimed MIME. JPEG:
// FF D8 FF. PNG: 89 50 4E 47 0D 0A 1A 0A. (Same pattern as proof.js.)
const MAX_PHOTO_INPUT_BYTES = 5 * 1024 * 1024; // 5 MB input cap, before downscaling
function photoBytesFromDataUrl(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  const m = dataUrl.match(/^data:([^;,]+);base64,(.*)$/);
  if (!m) return null;
  try {
    if (typeof Buffer !== 'undefined') return Buffer.from(m[2], 'base64');
    const bin = atob(m[2]);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  } catch (_e) { return null; }
}
function photoMimeFromBytes(bytes) {
  if (!bytes || bytes.length < 3) return null;
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'image/jpeg';
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47
    && bytes[4] === 0x0D && bytes[5] === 0x0A && bytes[6] === 0x1A && bytes[7] === 0x0A) return 'image/png';
  return null;
}
// Validate a photo data URL before it is stored: JPEG/PNG by magic
// bytes, and under the 5 MB input cap. The browser downscales to
// 500 KB before saving; this is the backstop, not the downscaler.
function validatePhotoDataUrl(dataUrl) {
  const errors = [];
  let mime = null;
  if (typeof dataUrl !== 'string' || dataUrl.indexOf('data:') !== 0) {
    errors.push('Photo must be a JPEG or PNG file.');
    return { ok: false, errors, mime: null };
  }
  const bytes = photoBytesFromDataUrl(dataUrl);
  if (!bytes) {
    errors.push('Photo could not be read — pick the file again.');
    return { ok: false, errors, mime: null };
  }
  mime = photoMimeFromBytes(bytes);
  if (!mime) errors.push('Only a JPEG or PNG photo can be stored.');
  if (bytes.length > MAX_PHOTO_INPUT_BYTES) {
    errors.push('Photo is larger than 5 MB — pick a smaller photo.');
  }
  return { ok: errors.length === 0, errors, mime };
}
// Does this data URL fit the 500 KB vault cap? The decoded byte size
// decides, never the string length.
function photoFitsCap(dataUrl) {
  const bytes = photoBytesFromDataUrl(dataUrl);
  if (!bytes) return false;
  return bytes.length <= MAX_PHOTO_BYTES;
}
function validateDocument(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['document is required'];
  if (!DOCUMENT_TYPES.includes(input.type)) errors.push('type must be one of: ' + DOCUMENT_TYPES.join(', '));
  const owner = trimStr(input.owner, 60);
  if (!owner) errors.push('owner is required');
  if (input.issueDate !== undefined && input.issueDate !== null && input.issueDate !== '' && !isDateStr(input.issueDate)) {
    errors.push('issue date must be YYYY-MM-DD or empty');
  }
  if (!isDateStr(input.expiryDate)) errors.push('expiry date must be YYYY-MM-DD');
  if (input.photo !== undefined && input.photo !== null) {
    if (typeof input.photo !== 'object' || typeof input.photo.dataUrl !== 'string'
      || input.photo.dataUrl.indexOf('data:image/') !== 0) {
      errors.push('photo must be a JPEG/PNG data URL or empty');
    } else {
      const pv = validatePhotoDataUrl(input.photo.dataUrl);
      if (!pv.ok) errors.push.apply(errors, pv.errors);
      else if (!photoFitsCap(input.photo.dataUrl)) {
        errors.push('photo is larger than 500 KB — it is shrunk in the app before saving');
      }
    }
  }
  return errors;
}
function addDocument(vault, input) {
  const errors = validateDocument(input);
  if (errors.length) throw fail('VALIDATION', 'Document is not valid.', errors);
  const doc = {
    id: newId(),
    type: input.type,
    owner: trimStr(input.owner, 60),
    issueDate: input.issueDate || null,
    expiryDate: input.expiryDate,
    // The stored mime is the one read from the magic bytes, never the
    // claimed one — so a mislabelled file is stored under its true type.
    photo: input.photo ? {
      dataUrl: input.photo.dataUrl,
      mime: validatePhotoDataUrl(input.photo.dataUrl).mime || input.photo.mime,
    } : null,
    checklistKey: ['CNIC', 'passport', 'driving licence', 'vehicle token'].includes(input.type) ? input.type : null,
  };
  vault.documents.push(doc);
  return doc;
}

// ---- Medicines ----
function validateMedicine(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['medicine is required'];
  const name = trimStr(input.name, 80);
  if (!name) errors.push('name is required');
  const qty = Number(input.qtyLeft);
  if (!Number.isInteger(qty) || qty < 0 || qty > 100000) {
    errors.push('quantity left must be a whole number from 0 up');
  }
  if (!isDateStr(input.expiryDate)) errors.push('expiry date must be YYYY-MM-DD');
  if (input.place !== undefined && input.place !== null && input.place !== '' && !MEDICINE_PLACES.includes(input.place)) {
    errors.push('place must be one of: ' + MEDICINE_PLACES.join(', '));
  }
  const doses = Number(input.dosesPerDay);
  if (input.dosesPerDay !== undefined && input.dosesPerDay !== null && input.dosesPerDay !== ''
    && (!Number.isInteger(doses) || doses < 0 || doses > 24)) {
    errors.push('doses per day must be a whole number from 0 to 24');
  }
  const low = Number(input.lowStockAt);
  if (input.lowStockAt !== undefined && input.lowStockAt !== null && input.lowStockAt !== ''
    && (!Number.isInteger(low) || low < 0 || low > 100000)) {
    errors.push('low-stock number must be a whole number from 0 up');
  }
  return errors;
}
function addMedicine(vault, input) {
  const errors = validateMedicine(input);
  if (errors.length) throw fail('VALIDATION', 'Medicine is not valid.', errors);
  const med = {
    id: newId(),
    name: trimStr(input.name, 80),
    qtyLeft: Number(input.qtyLeft),
    unit: trimStr(input.unit, 20) || 'tablets',
    expiryDate: input.expiryDate,
    place: input.place || '',
    person: trimStr(input.person, 60),
    dosesPerDay: input.dosesPerDay === '' || input.dosesPerDay == null ? null : Number(input.dosesPerDay),
    lowStockAt: input.lowStockAt === '' || input.lowStockAt == null ? null : Number(input.lowStockAt),
    dosesTaken: [],
  };
  vault.medicines.push(med);
  return med;
}
function findMedicine(vault, id) {
  return (vault.medicines || []).find((m) => m.id === id) || null;
}
// Expiry + stock warnings for one medicine. expired: past the expiry
// date. daysUntil: days from today to expiry (negative = expired).
// lowStock: quantity left is at or below the low-stock number you set
// (only when you set one). warning: anything on this page needs your
// attention — expired, low stock, or expiring inside the widest
// reminder window (settings.reminders.medDays, [30, 7] by default).
// An expired medicine stays visible — it is never removed by the app.
function medicineWarnings(med, today, medDays) {
  if (!med || typeof med !== 'object') throw fail('NOT_FOUND', 'Medicine does not exist.');
  const d = isDateStr(med.expiryDate) ? daysBetween(today || todayStr(), med.expiryDate) : Infinity;
  const expired = d < 0;
  const lowStock = med.lowStockAt != null && Number(med.qtyLeft) <= Number(med.lowStockAt);
  const days = Array.isArray(medDays) && medDays.length ? medDays : [30, 7];
  const window = Math.max.apply(null, days);
  const warning = expired || lowStock || d <= window;
  return { expired, daysUntil: d, lowStock, warning };
}
function isTimeStr(s) {
  if (typeof s !== 'string' || !/^\d{2}:\d{2}$/.test(s)) return false;
  const h = Number(s.slice(0, 2)), m = Number(s.slice(3, 5));
  return h >= 0 && h <= 23 && m >= 0 && m <= 59;
}
// Mark one dose taken: appends { date, time } to dosesTaken and lowers
// the quantity left by exactly one. The app never suggests a dose — it
// only records the one you took. qtyLeft never goes below 0: at 0 the
// tick is refused.
function recordDose(vault, medId, input) {
  const med = findMedicine(vault, medId);
  if (!med) throw fail('NOT_FOUND', 'Medicine does not exist.');
  const errors = [];
  if (!input || typeof input !== 'object') errors.push('dose is required');
  if (!isDateStr(input && input.date)) errors.push('dose date must be YYYY-MM-DD');
  if (!isTimeStr(input && input.time)) errors.push('dose time must be HH:MM (24-hour)');
  if (errors.length) throw fail('VALIDATION', 'Dose is not valid.', errors);
  if (Number(med.qtyLeft) <= 0) {
    throw fail('VALIDATION', 'None left — quantity is 0, so no dose can be recorded.');
  }
  const dose = { date: input.date, time: input.time };
  med.dosesTaken.push(dose);
  med.qtyLeft = Number(med.qtyLeft) - 1;
  return dose;
}
// Remove a medicine (the user's own data). The UI asks twice; the model
// just removes it and returns it. An expired medicine is removed only
// when the user deletes it — never by the app on its own.
function deleteMedicine(vault, medId) {
  const idx = (vault.medicines || []).findIndex((m) => m.id === medId);
  if (idx < 0) throw fail('NOT_FOUND', 'Medicine does not exist.');
  return vault.medicines.splice(idx, 1)[0];
}

// ---- Summary (Phase 5) ----
// The previous calendar month, for the this-month-vs-last-month rows.
function prevMonthKey(monthKey) {
  const y = Number(monthKey.slice(0, 4));
  const m = Number(monthKey.slice(5, 7));
  const d = new Date(Date.UTC(y, m - 2, 1));
  return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0');
}
// Staff paid in one month: the stored paid-month records for that month.
// Recomputed from the records (sum of netPkr), never stored as a total.
function staffPaidInMonth(vault, monthKey) {
  let total = 0, count = 0;
  for (const s of (vault.staff || [])) {
    const paid = findPaidStaffMonth(s, monthKey);
    if (paid) { total = roundRs(total + Number(paid.netPkr || 0)); count++; }
  }
  return { totalPkr: total, count };
}
// Staff not yet paid in one month: the working as it stands today, per
// helper (computeMonthPay recomputes from attendance + advances).
function staffUnpaidWorkingInMonth(vault, monthKey) {
  let total = 0, count = 0;
  for (const s of (vault.staff || [])) {
    if (isStaffMonthPaid(s, monthKey)) continue;
    try {
      const w = payWorkingForHelper(s, monthKey);
      total = roundRs(total + w.netPkr);
      count++;
    } catch (_e) { /* a helper with no usable rows contributes nothing */ }
  }
  return { totalPkr: total, count };
}
function deliveriesInMonth(vault, monthKey) {
  let total = 0, paid = 0, count = 0;
  for (const d of (vault.deliveries || [])) {
    try {
      total = roundRs(total + deliveryMonthTotal(vault, d.id, monthKey).totalPkr);
      count++;
    } catch (_e) { /* no usable log contributes nothing */ }
    const pm = findPaidDeliveryMonth(d, monthKey);
    if (pm) paid = roundRs(paid + Number(pm.totalPkr || 0));
  }
  return { totalPkr: total, paidPkr: paid, unpaidPkr: roundRs(total - paid), count };
}
function udhaarTotals(vault) {
  let lent = 0, borrowed = 0, settled = 0;
  for (const p of (vault.udhaar || [])) {
    const bal = udhaarPersonBalance(p);
    lent = roundRs(lent + bal.lent);
    borrowed = roundRs(borrowed + bal.borrowed);
    for (const e of (p.entries || [])) if (e.settled) settled++;
  }
  return { lentOutstandingPkr: lent, borrowedOutstandingPkr: borrowed, settledCount: settled };
}
function udhaarInMonth(vault, monthKey) {
  let lent = 0, borrowed = 0;
  for (const p of (vault.udhaar || [])) {
    for (const e of (p.entries || [])) {
      if (monthKeyOf(e.date) !== monthKey) continue;
      if (e.direction === 'lent') lent = roundRs(lent + Number(e.amountPkr || 0));
      else borrowed = roundRs(borrowed + Number(e.amountPkr || 0));
    }
  }
  return { lentPkr: lent, borrowedPkr: borrowed };
}
function billsInMonth(vault, monthKey, today) {
  const t = today || todayStr();
  let paid = 0, paidCount = 0, dueThisMonth = 0, dueCount = 0, dueAll = 0, overdue = 0;
  for (const b of (vault.bills || [])) {
    if (b.status === 'paid') {
      if (b.paidDate && monthKeyOf(b.paidDate) === monthKey) {
        paid = roundRs(paid + Number(b.amountPkr || 0));
        paidCount++;
      }
    } else {
      dueAll = roundRs(dueAll + Number(b.amountPkr || 0));
      if (monthKeyOf(b.dueDate) === monthKey) {
        dueThisMonth = roundRs(dueThisMonth + Number(b.amountPkr || 0));
        dueCount++;
      }
      if (daysBetween(t, b.dueDate) < 0) overdue = roundRs(overdue + Number(b.amountPkr || 0));
    }
  }
  return { paidPkr: paid, paidCount, dueThisMonthPkr: dueThisMonth, dueThisMonthCount: dueCount, dueAllPkr: dueAll, overduePkr: overdue };
}
function expiringInMonth(list, monthKey, today) {
  const t = today || todayStr();
  const expiring = [], expired = [];
  for (const item of list) {
    if (!isDateStr(item.expiryDate)) continue;
    if (monthKeyOf(item.expiryDate) === monthKey) expiring.push(item);
    if (daysBetween(t, item.expiryDate) < 0) expired.push(item);
  }
  return { expiring, expired };
}
// This month's totals per section + this month vs last month. Every
// figure is recomputed from the section rows here, never stored: the
// summary is a view, not a second copy of the data. Outstanding udhaar
// is a point-in-time figure (all open entries), labelled as such — it is
// not a monthly total. "This month" for paid figures means the paid
// date falls in the month; for deliveries it means the logged days.
function summaryForMonth(vault, monthKey, today) {
  if (!isMonthKey(monthKey)) throw fail('VALIDATION', 'Month must be YYYY-MM.');
  const prev = prevMonthKey(monthKey);
  const staffPaid = staffPaidInMonth(vault, monthKey);
  const staffPaidPrev = staffPaidInMonth(vault, prev);
  const staffUnpaid = staffUnpaidWorkingInMonth(vault, monthKey);
  const del = deliveriesInMonth(vault, monthKey);
  const delPrev = deliveriesInMonth(vault, prev);
  const udh = udhaarTotals(vault);
  const udhMonth = udhaarInMonth(vault, monthKey);
  const bills = billsInMonth(vault, monthKey, today);
  const billsPrev = billsInMonth(vault, prev, today);
  const docs = expiringInMonth(vault.documents || [], monthKey, today);
  const meds = expiringInMonth(vault.medicines || [], monthKey, today);
  const lowStock = (vault.medicines || []).filter((m) =>
    m.lowStockAt != null && Number(m.qtyLeft) <= Number(m.lowStockAt)).length;
  return {
    month: monthKey,
    prevMonth: prev,
    staff: {
      paidPkr: staffPaid.totalPkr, paidCount: staffPaid.count,
      unpaidWorkingPkr: staffUnpaid.totalPkr, unpaidCount: staffUnpaid.count,
      advancesOutstandingPkr: (vault.staff || []).reduce((s, h) => s + staffRemainingAdvance(h), 0),
    },
    deliveries: del,
    udhaar: {
      lentOutstandingPkr: udh.lentOutstandingPkr,
      borrowedOutstandingPkr: udh.borrowedOutstandingPkr,
      lentThisMonthPkr: udhMonth.lentPkr, borrowedThisMonthPkr: udhMonth.borrowedPkr,
      settledCount: udh.settledCount,
    },
    bills,
    documents: {
      expiringThisMonth: docs.expiring.map((d) => ({ type: d.type, owner: d.owner, expiryDate: d.expiryDate })),
      expiringCount: docs.expiring.length,
      expiredCount: docs.expired.length,
    },
    medicines: {
      expiringThisMonth: meds.expiring.map((m) => ({ name: m.name, person: m.person, expiryDate: m.expiryDate })),
      expiringCount: meds.expiring.length,
      expiredCount: meds.expired.length,
      lowStockCount: lowStock,
    },
    compare: {
      staffPaidDeltaPkr: roundRs(staffPaid.totalPkr - staffPaidPrev.totalPkr),
      staffPaidPrevPkr: staffPaidPrev.totalPkr,
      deliveriesDeltaPkr: roundRs(del.totalPkr - delPrev.totalPkr),
      deliveriesPrevPkr: delPrev.totalPkr,
      billsPaidDeltaPkr: roundRs(bills.paidPkr - billsPrev.paidPkr),
      billsPaidPrevPkr: billsPrev.paidPkr,
    },
  };
}
// Rows for the CSV export, per section — the same rows the section pages
// show, with a TOTAL row that adds up the rows above it (recomputed
// here, from the same rows). Money columns are plain integers (no "Rs",
// no commas) so the file opens as readable CSV in a spreadsheet. Photos
// are never exported: a CSV carries text only, and the photo stays in
// the encrypted book.
function sectionCsvRows(vault, monthKey, today) {
  const t = today || todayStr();
  const staffRows = [];
  for (const s of (vault.staff || [])) {
    const paid = findPaidStaffMonth(s, monthKey);
    const w = paid ? paid.working : payWorkingForHelper(s, monthKey);
    staffRows.push([s.name, s.role, s.salaryPkr, w.absentDays, w.halfDays, w.absentDeduction,
      w.halfDeduction, w.advanceRecovery, w.netPkr, paid ? 'paid ' + paid.paidDate : 'not yet paid']);
  }
  const staffTotal = staffRows.reduce((s, r) => s + Number(r[8] || 0), 0);
  staffRows.push(['TOTAL', '', '', '', '', '', '', '', staffTotal, monthKey]);
  const delRows = [];
  for (const d of (vault.deliveries || [])) {
    const tot = deliveryMonthTotal(vault, d.id, monthKey);
    const paid = findPaidDeliveryMonth(d, monthKey);
    delRows.push([d.name, d.kind, d.unit, d.ratePkr, tot.days, tot.skippedDays, tot.totalPkr,
      paid ? 'paid ' + paid.paidDate : 'not yet paid']);
  }
  const delTotal = delRows.reduce((s, r) => s + Number(r[6] || 0), 0);
  delRows.push(['TOTAL', '', '', '', '', '', delTotal, monthKey]);
  const udhRows = [];
  for (const p of (vault.udhaar || [])) {
    for (const e of (p.entries || [])) {
      const repaid = (e.repayments || []).reduce((s, r) => s + (Number(r.amountPkr) || 0), 0);
      udhRows.push([p.person, e.direction, e.amountPkr, e.date, e.reason || '', e.dueDate || '',
        repaid, e.forgivenPkr, udhaarEntryBalance(e), e.settled ? 'settled' : 'open']);
    }
  }
  const udhLent = udhRows.filter((r) => r[1] === 'lent').reduce((s, r) => s + Number(r[8] || 0), 0);
  const udhBorrowed = udhRows.filter((r) => r[1] === 'borrowed').reduce((s, r) => s + Number(r[8] || 0), 0);
  udhRows.push(['TOTAL outstanding', 'lent', udhLent, '', '', '', '', '', udhLent, '']);
  udhRows.push(['TOTAL outstanding', 'borrowed', udhBorrowed, '', '', '', '', '', udhBorrowed, '']);
  const billRows = [];
  for (const b of (vault.bills || [])) {
    billRows.push([b.type, b.provider, b.accountNo || '', b.amountPkr, b.dueDate,
      b.surchargeNote || '', b.status, b.paidDate || '']);
  }
  const billDue = billRows.filter((r) => r[6] === 'due').reduce((s, r) => s + Number(r[3] || 0), 0);
  const billPaid = billRows.filter((r) => r[6] === 'paid').reduce((s, r) => s + Number(r[3] || 0), 0);
  billRows.push(['TOTAL', '', '', billDue, '', '', 'due (all unpaid)', '']);
  billRows.push(['TOTAL', '', '', billPaid, '', '', 'paid (all)', '']);
  const docRows = [];
  for (const d of (vault.documents || [])) {
    docRows.push([d.type, d.owner, d.issueDate || '', d.expiryDate, documentDaysUntil(d, t),
      d.photo ? 'photo stored in the book' : 'no photo']);
  }
  const medRows = [];
  for (const m of (vault.medicines || [])) {
    const w = medicineWarnings(m, t);
    medRows.push([m.name, m.qtyLeft, m.unit, m.expiryDate, w.daysUntil, m.place || '',
      m.person || '', m.dosesPerDay == null ? '' : m.dosesPerDay,
      m.lowStockAt == null ? '' : m.lowStockAt, (m.dosesTaken || []).length,
      w.expired ? 'EXPIRED — do not use — check with a pharmacist' : w.lowStock ? 'low stock' : '']);
  }
  return {
    staff: { headers: ['Helper', 'Role', 'Monthly salary (Rs)', 'Absent days', 'Half days', 'Absent deduction (Rs)', 'Half-day deduction (Rs)', 'Advance recovery (Rs)', 'Net payable (Rs)', 'Status'], rows: staffRows },
    deliveries: { headers: ['Delivery', 'Kind', 'Unit', 'Rate per unit (Rs)', 'Days logged', 'Skipped days', 'Total (Rs)', 'Status'], rows: delRows },
    udhaar: { headers: ['Person', 'Direction', 'Amount (Rs)', 'Date', 'Reason', 'Due date', 'Repaid (Rs)', 'Forgiven (Rs)', 'Outstanding (Rs)', 'Status'], rows: udhRows },
    bills: { headers: ['Type', 'Provider', 'Account number', 'Amount (Rs)', 'Due date', 'Late-surcharge note', 'Status', 'Paid date'], rows: billRows },
    documents: { headers: ['Type', 'Owner', 'Issue date', 'Expiry date', 'Days until expiry', 'Photo'], rows: docRows },
    medicines: { headers: ['Medicine', 'Quantity left', 'Unit', 'Expiry date', 'Days until expiry', 'Place', 'Person', 'Doses per day', 'Low-stock number', 'Doses taken', 'Warning'], rows: medRows },
  };
}

// ---- Today (Home page) ----
// Everything due, overdue and coming in the next 7 days, in one list.
// Each item: { kind, title, detail, date, overdue, daysUntil, link }.
// Dates and amounts are exactly as the user typed them; the list shows
// its working (e.g. "due in 4 days", "OVERDUE by 2 days"). Empty
// collections contribute nothing — an empty vault renders the empty state.
function todayItems(vault, today) {
  const t = today || todayStr();
  const items = [];
  const docDays = (vault.settings && vault.settings.reminders && vault.settings.reminders.docDays) || [30, 14, 7, 1];
  const medDays = (vault.settings && vault.settings.reminders && vault.settings.reminders.medDays) || [30, 7];
  const within = (dateStr, days) => {
    const d = daysBetween(t, dateStr);
    return d <= days;
  };

  // Bills: due, overdue, or due in the next 7 days.
  for (const b of (vault.bills || [])) {
    if (b.status !== 'due') continue;
    const d = daysBetween(t, b.dueDate);
    if (d > 7) continue;
    items.push({
      kind: 'bill', title: b.type + ' bill — ' + b.provider,
      detail: fmtRs(b.amountPkr) + (b.accountNo ? ' · account ' + b.accountNo : '') + ' · as you entered it',
      date: b.dueDate, overdue: d < 0, daysUntil: d, link: '#/bills',
    });
  }
  // Documents: expiring within the reminder window, or already expired.
  // The reminder decides what shows — the list does not redo the logic.
  for (const doc of (vault.documents || [])) {
    const reminder = documentReminder(doc, t, docDays);
    if (!reminder) continue;
    const d = documentDaysUntil(doc, t);
    items.push({
      kind: 'document', title: doc.type + ' — ' + doc.owner,
      detail: d < 0 ? 'expired ' + (-d) + (d === -1 ? ' day ago' : ' days ago')
        : d === 0 ? 'expires today' : 'expires in ' + d + (d === 1 ? ' day' : ' days'),
      date: doc.expiryDate, overdue: d < 0, daysUntil: d, link: '#/documents',
    });
  }
  // Medicines: expiring within the reminder window, expired, or low stock.
  // The warning decides what shows — the list does not redo the logic.
  for (const m of (vault.medicines || [])) {
    const w = medicineWarnings(m, t, medDays);
    if (!w.warning) continue;
    const d = w.daysUntil;
    const low = w.lowStock;
    const parts = [];
    if (d < 0) parts.push('expired ' + (-d) + (d === -1 ? ' day ago' : ' days ago'));
    else if (d === 0) parts.push('expires today');
    else parts.push('expires in ' + d + (d === 1 ? ' day' : ' days'));
    if (low) parts.push('low stock — ' + m.qtyLeft + ' ' + m.unit + ' left');
    else parts.push(m.qtyLeft + ' ' + m.unit + ' left');
    items.push({
      kind: 'medicine', title: m.name + (m.person ? ' — ' + m.person : ''),
      detail: parts.join(' · '),
      date: m.expiryDate, overdue: d < 0, daysUntil: d, link: '#/medicine',
    });
  }
  // Udhaar: an entry past its due date with money still outstanding.
  for (const p of (vault.udhaar || [])) {
    for (const e of (p.entries || [])) {
      if (e.settled) continue;
      const bal = udhaarEntryBalance(e);
      if (bal <= 0) continue;
      if (!e.dueDate) continue;
      const d = daysBetween(t, e.dueDate);
      if (d > 7) continue;
      items.push({
        kind: 'udhaar',
        title: (e.direction === 'lent' ? 'Lent to ' : 'Borrowed from ') + p.person,
        detail: fmtRs(bal) + ' still outstanding of ' + fmtRs(e.amountPkr)
          + (e.reason ? ' · ' + e.reason : '') + ' · as you entered it',
        date: e.dueDate, overdue: d < 0, daysUntil: d, link: '#/udhaar',
      });
    }
  }
  // Staff pay: the month's pay falls due at month end. From 7 days before
  // the last day of the month (and after it, until marked paid) the helper
  // shows on Today. Paid months never show.
  const year = Number(t.slice(0, 4));
  const month = Number(t.slice(5, 7));
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const monthKey = t.slice(0, 7);
  const lastDateStr = monthKey + '-' + String(lastDay).padStart(2, '0');
  const daysToMonthEnd = daysBetween(t, lastDateStr);
  if (daysToMonthEnd <= 7) {
    for (const s of (vault.staff || [])) {
      if ((s.paidMonths || []).some((pm) => pm.month === monthKey)) continue;
      items.push({
        kind: 'staff', title: s.name + ' — pay due (' + s.role + ')',
        detail: fmtRs(s.salaryPkr) + ' monthly salary · as you entered it',
        date: lastDateStr, overdue: daysToMonthEnd < 0, daysUntil: daysToMonthEnd, link: '#/staff',
      });
    }
  }
  // Soonest first; overdue first within the same date.
  items.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
  return items;
}

function dueLabel(item) {
  if (!item) return '';
  if (item.daysUntil < 0) return 'OVERDUE by ' + (-item.daysUntil) + ((-item.daysUntil) === 1 ? ' day' : ' days');
  if (item.daysUntil === 0) return 'due today';
  return 'due in ' + item.daysUntil + (item.daysUntil === 1 ? ' day' : ' days');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    STAFF_ROLES, DELIVERY_KINDS, DELIVERY_UNITS, BILL_TYPES, DOCUMENT_TYPES,
    MEDICINE_PLACES, ATTENDANCE_MARKS, MAX_MONEY, MAX_PHOTO_BYTES,
    newId, roundRs, isIntRs, isDateStr, todayStr, daysBetween, fmtRs,
    isMonthKey, daysInMonth, monthKeyOf,
    isGharVault, emptyVault, setHousehold,
    validateStaff, addStaff, findStaff,
    markAttendance, attendanceCounts, addAdvance, advanceRemaining,
    staffRemainingAdvance, advanceMonthRecovery, payWorkingForHelper,
    computeMonthPay, markMonthPaid, staffPayStatement,
    findPaidStaffMonth, isStaffMonthPaid,
    validateDelivery, addDelivery, findDelivery,
    logDelivery, addGasRefill, lastGasRefill, gasDaysSinceLastRefill,
    deliveryMonthTotal, markDeliveryMonthPaid,
    findPaidDeliveryMonth, isDeliveryMonthPaid,
    validateUdhaarPerson, addUdhaarPerson, findUdhaarPerson,
    validateUdhaarEntry, addUdhaarEntry, udhaarEntryBalance, udhaarPersonBalance,
    findUdhaarEntry, recordRepayment, forgiveUdhaar, udhaarReminderText,
    validateBill, addBill, findBill, markBillPaid, markBillUnpaid, deleteBill,
    validateDocument, addDocument, findDocument, documentDaysUntil,
    documentReminder, deleteDocument, getChecklist, CHECKLISTS,
    CHECKLIST_UPDATED, validatePhotoDataUrl, photoFitsCap, MAX_PHOTO_INPUT_BYTES,
    validateMedicine, addMedicine, findMedicine, recordDose, medicineWarnings,
    deleteMedicine, isTimeStr,
    prevMonthKey, staffPaidInMonth, staffUnpaidWorkingInMonth, deliveriesInMonth,
    udhaarTotals, udhaarInMonth, billsInMonth, summaryForMonth, sectionCsvRows,
    todayItems, dueLabel,
  };
}
if (typeof window !== 'undefined') {
  window.GharModel = {
    STAFF_ROLES, DELIVERY_KINDS, DELIVERY_UNITS, BILL_TYPES, DOCUMENT_TYPES,
    MEDICINE_PLACES, ATTENDANCE_MARKS, MAX_MONEY, MAX_PHOTO_BYTES,
    newId, roundRs, isIntRs, isDateStr, todayStr, daysBetween, fmtRs,
    isMonthKey, daysInMonth, monthKeyOf,
    isGharVault, emptyVault, setHousehold,
    validateStaff, addStaff, findStaff,
    markAttendance, attendanceCounts, addAdvance, advanceRemaining,
    staffRemainingAdvance, advanceMonthRecovery, payWorkingForHelper,
    computeMonthPay, markMonthPaid, staffPayStatement,
    findPaidStaffMonth, isStaffMonthPaid,
    validateDelivery, addDelivery, findDelivery,
    logDelivery, addGasRefill, lastGasRefill, gasDaysSinceLastRefill,
    deliveryMonthTotal, markDeliveryMonthPaid,
    findPaidDeliveryMonth, isDeliveryMonthPaid,
    validateUdhaarPerson, addUdhaarPerson, findUdhaarPerson,
    validateUdhaarEntry, addUdhaarEntry, udhaarEntryBalance, udhaarPersonBalance,
    findUdhaarEntry, recordRepayment, forgiveUdhaar, udhaarReminderText,
    validateBill, addBill, findBill, markBillPaid, markBillUnpaid, deleteBill,
    validateDocument, addDocument, findDocument, documentDaysUntil,
    documentReminder, deleteDocument, getChecklist, CHECKLISTS,
    CHECKLIST_UPDATED, validatePhotoDataUrl, photoFitsCap, MAX_PHOTO_INPUT_BYTES,
    validateMedicine, addMedicine, findMedicine, recordDose, medicineWarnings,
    deleteMedicine, isTimeStr,
    prevMonthKey, staffPaidInMonth, staffUnpaidWorkingInMonth, deliveriesInMonth,
    udhaarTotals, udhaarInMonth, billsInMonth, summaryForMonth, sectionCsvRows,
    todayItems, dueLabel,
  };
}
