// Ghar ka Register — app shell (browser only).
// Wires the setup/unlock screens, hash routing (nav.js), page rendering
// (model.js) and the encrypted vault (vault.js). No page is reachable
// while locked. Nothing here is fetched, checked or looked up anywhere:
// every record is shown as you entered it, and every figure shows its
// working. A v1 vault (the old Card Vault) is NOT migrated — first run
// creates a fresh v2 vault; an old backup restores only into the old code.
'use strict';
(function () {
  var VaultCrypto = window.VaultCrypto;
  var GharModel = window.GharModel;
  var Nav = window.Nav;

  var LS_VAULT = 'ghar-register-vault';
  var LS_LOCKOUT = 'ghar-register-lockout';

  var state = {
    envelope: null,
    key: null,
    vault: null,
    lockout: VaultCrypto.createLockoutState(),
    lastActiveMs: 0,
    pendingImport: null,
    pendingDeleteBillId: null,
    pendingDocPhoto: null,
    pendingDeleteDocId: null,
    pendingDeleteMedId: null,
    currentPage: 'home',
  };

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function setText(id, text) { var el = $(id); if (el) el.textContent = text || ''; }
  function show(el, on) { if (el) el.classList.toggle('hidden', !on); }
  function setVal(id, v) { var el = $(id); if (el) el.value = v == null ? '' : v; }
  function currentMonthKey() { return GharModel.todayStr().slice(0, 7); }
  function monthInputVal(id) {
    var el = $(id);
    if (el && el.value) return el.value;
    if (el) el.value = currentMonthKey();
    return currentMonthKey();
  }

  // ---- storage (envelope + lockout live outside the vault, as before) ----
  function loadStored() {
    try {
      var raw = localStorage.getItem(LS_VAULT);
      if (raw) {
        var env = JSON.parse(raw);
        if (env && typeof env === 'object' && typeof env.data === 'string') state.envelope = env;
      }
    } catch (_e) { state.envelope = null; }
    try {
      var lr = localStorage.getItem(LS_LOCKOUT);
      if (lr) {
        var s = JSON.parse(lr);
        if (s && typeof s.failures === 'number') {
          state.lockout = { failures: s.failures, lockoutUntil: Number(s.lockoutUntil) || 0 };
        }
      }
    } catch (_e) { /* keep a fresh lockout state */ }
  }
  function saveEnvelope() {
    try { localStorage.setItem(LS_VAULT, JSON.stringify(state.envelope)); } catch (_e) { /* storage full/blocked */ }
  }
  function saveLockout() {
    try { localStorage.setItem(LS_LOCKOUT, JSON.stringify(state.lockout)); } catch (_e) { /* storage full/blocked */ }
  }
  async function persist() {
    state.envelope = await VaultCrypto.saveVault(state.key, state.envelope, state.vault);
    saveEnvelope();
  }

  // ---- screens ----
  function showScreen(which) {
    show($('setup-screen'), which === 'setup');
    show($('unlock-screen'), which === 'unlock');
    show($('vault-screen'), which === 'vault');
    var pill = $('lock-pill');
    if (pill) {
      pill.textContent = which === 'vault' ? 'Unlocked' : 'Locked';
      pill.classList.toggle('locked', which !== 'vault');
    }
    if (which === 'unlock') updateLockoutNote();
  }
  function updateLockoutNote() {
    var el = $('lockout-note');
    if (!el) return;
    if (VaultCrypto.isLocked(state.lockout, Date.now())) {
      var secs = Math.ceil(VaultCrypto.lockoutRemainingMs(state.lockout, Date.now()) / 1000);
      el.textContent = 'Too many wrong PINs. Wait ' + secs + ' seconds, then try again.';
      el.classList.remove('hidden');
    } else {
      el.classList.add('hidden');
      el.textContent = '';
    }
  }

  function lock() {
    state.key = null;
    state.vault = null;
    state.pendingImport = null;
    state.pendingDocPhoto = null;
    state.pendingDeleteDocId = null;
    state.pendingDeleteMedId = null;
    setText('doc-photo-note', '');
    state.lastActiveMs = 0;
    setVal('unlock-pin', '');
    setVal('unlock-pass', '');
    showScreen(state.envelope ? 'unlock' : 'setup');
  }
  function markActive() { state.lastActiveMs = Date.now(); }
  function autoLockCheck() {
    if (state.key && VaultCrypto.isIdleLocked(state.lastActiveMs, Date.now())) lock();
  }

  // ---- setup (first run: fresh v2 vault, no migration) ----
  async function onSetup() {
    var pin = $('setup-pin').value.trim();
    var pin2 = $('setup-pin2').value.trim();
    var pass = $('setup-pass').value || '';
    setText('setup-error', '');
    if (!VaultCrypto.validPin(pin)) { setText('setup-error', 'PIN must be exactly 6 digits.'); return; }
    if (pin !== pin2) { setText('setup-error', 'The two PINs do not match.'); return; }
    if (!VaultCrypto.validPassphrase(pass)) { setText('setup-error', 'Passphrase must be empty or at least 4 characters.'); return; }
    try {
      var fresh = GharModel.emptyVault();
      var made = await VaultCrypto.createVault(pin, pass, fresh);
      state.envelope = made.envelope;
      state.key = made.key;
      state.vault = fresh;
      saveEnvelope();
      state.lockout = VaultCrypto.recordSuccess();
      saveLockout();
      state.lastActiveMs = Date.now();
      setVal('setup-pin', '');
      setVal('setup-pin2', '');
      setVal('setup-pass', '');
      window.location.hash = '#/home';
      showScreen('vault');
      renderAll();
      route();
    } catch (e) {
      setText('setup-error', 'Could not create the book — try again.');
    }
  }

  // ---- unlock ----
  async function onUnlock() {
    var pin = $('unlock-pin').value.trim();
    var pass = $('unlock-pass').value || '';
    setText('unlock-error', '');
    if (VaultCrypto.isLocked(state.lockout, Date.now())) { updateLockoutNote(); return; }
    if (!VaultCrypto.validPin(pin)) { setText('unlock-error', 'PIN must be exactly 6 digits.'); return; }
    try {
      var res = await VaultCrypto.unlockVault(pin, pass, state.envelope);
      if (!GharModel.isGharVault(res.vault)) {
        setText('unlock-error', 'This book is from the old Card Vault. It does not open here — an old backup restores only into the old code.');
        return;
      }
      state.key = res.key;
      state.vault = res.vault;
      state.lockout = VaultCrypto.recordSuccess();
      saveLockout();
      state.lastActiveMs = Date.now();
      setVal('unlock-pin', '');
      setVal('unlock-pass', '');
      showScreen('vault');
      renderAll();
      route();
    } catch (e) {
      state.lockout = VaultCrypto.recordFailure(state.lockout, Date.now());
      saveLockout();
      if (VaultCrypto.isLocked(state.lockout, Date.now())) {
        updateLockoutNote();
        setText('unlock-error', 'Wrong PIN. The book is now locked for a while.');
      } else {
        setText('unlock-error', 'Wrong PIN — try again. (' + state.lockout.failures
          + (state.lockout.failures === 1 ? ' wrong try' : ' wrong tries') + ')');
      }
    }
  }

  // ---- routing (no page is reachable while locked) ----
  function route() {
    if (!state.key) { showScreen(state.envelope ? 'unlock' : 'setup'); return; }
    showScreen('vault');
    var page = Nav.routeForHash(window.location.hash || '#/home');
    state.currentPage = page;
    Nav.PAGES.forEach(function (p) {
      show($('page-' + p), p === page);
      var btn = $('nav-' + p);
      if (btn) btn.classList.toggle('active', p === page);
    });
    renderPage(page);
    markActive();
  }

  // ---- rendering ----
  function renderList(listId, emptyId, rows) {
    show($(emptyId), rows.length === 0);
    $(listId).innerHTML = rows.join('');
  }
  function renderToday() {
    var items = GharModel.todayItems(state.vault);
    show($('today-empty'), items.length === 0);
    var html = '';
    items.forEach(function (it) {
      html += '<div class="sum-row"><div class="nm">' + esc(it.title)
        + '<span class="sub">' + esc(it.detail) + '</span></div>'
        + '<span class="pill' + (it.overdue ? ' amber' : '') + '">' + esc(GharModel.dueLabel(it)) + '</span>'
        + '<a class="pill" href="' + esc(it.link) + '">Open</a></div>';
    });
    $('today-list').innerHTML = html;
  }
  function renderStaff() {
    var month = monthInputVal('staff-month');
    var staff = state.vault.staff || [];
    // Advance form: pick the helper from a dropdown (static ids, so the
    // fake-DOM tests can drive it exactly like the other forms).
    var advSel = $('adv-helper');
    if (advSel) {
      advSel.innerHTML = staff.map(function (s) {
        return '<option value="' + esc(s.id) + '">' + esc(s.name) + ' — ' + esc(s.role) + '</option>';
      }).join('');
    }
    var rows = staff.map(function (s) {
      var paid = GharModel.findPaidStaffMonth(s, month);
      var locked = !!paid;
      var working = null;
      if (locked) working = paid.working;
      else {
        try { working = GharModel.computeMonthPay(state.vault, s.id, month); }
        catch (_e) { working = null; }
      }
      var html = '<div class="card"><div class="sum-row"><div class="nm">' + esc(s.name) + ' — ' + esc(s.role)
        + '<span class="sub">' + esc(GharModel.fmtRs(s.salaryPkr)) + ' monthly salary · joined ' + esc(s.joinedDate)
        + ' · paid leave ' + esc(String(s.leavePerMonth)) + ' days/month'
        + (s.phone ? ' · ' + esc(s.phone) : '') + ' · as you entered it</span></div></div>';
      // Attendance: one tap per day cycles present -> absent -> half ->
      // present. Present is the default, so only exceptions are stored.
      var dim = GharModel.daysInMonth(month);
      var counts = GharModel.attendanceCounts(s, month);
      html += '<h3>Attendance — ' + esc(month) + '</h3>'
        + '<p class="muted">Tap a day to mark it: present (P) → absent (A) → half day (H). '
        + 'Absent: ' + counts.absentDays + ' · Half: ' + counts.halfDays + ' · the rest count as present.</p><div class="row">';
      for (var d = 1; d <= dim; d++) {
        var dateStr = month + '-' + String(d).padStart(2, '0');
        var mark = (s.attendance && s.attendance[dateStr]) || 'present';
        var letter = mark === 'absent' ? 'A' : mark === 'half' ? 'H' : 'P';
        html += '<button type="button" class="small" style="flex:0 0 auto;min-width:44px;min-height:44px"'
          + ' data-action="att" data-helper="' + esc(s.id) + '" data-date="' + esc(dateStr) + '"'
          + (locked ? ' disabled' : '') + '>' + d + ' · ' + letter + '</button>';
      }
      html += '</div>';
      // Advances: each advance with what is still left to recover.
      html += '<h3>Advances</h3>';
      var remaining = GharModel.staffRemainingAdvance(s);
      if (!s.advances || s.advances.length === 0) {
        html += '<p class="muted">No advances — remaining advance: Rs 0.</p>';
      } else {
        html += '<p class="muted">Remaining advance: ' + esc(GharModel.fmtRs(remaining)) + '.</p>';
        s.advances.forEach(function (a) {
          html += '<div class="sum-row"><div class="nm">' + esc(GharModel.fmtRs(a.amount))
            + ' on ' + esc(a.date)
            + '<span class="sub">' + (a.note ? esc(a.note) + ' · ' : '')
            + (a.recovery === 'instalments'
              ? 'instalments of ' + esc(GharModel.fmtRs(a.instalmentPkr)) + ' a month'
              : 'full recovery from the next pay')
            + ' · recovered ' + esc(GharModel.fmtRs(a.recoveredPkr))
            + ' · remaining ' + esc(GharModel.fmtRs(GharModel.advanceRemaining(a)))
            + ' · as you entered it</span></div></div>';
        });
      }
      // Month-end pay: the full working, line by line.
      html += '<h3>Pay — ' + esc(month) + '</h3>';
      if (working) {
        var absentRate = Math.round(Number(s.salaryPkr || 0) / 30);
        var halfRate = Math.round(Number(s.salaryPkr || 0) / 60);
        html += '<div class="sum-row"><div class="nm">Monthly salary<span class="sub">as you entered it</span></div>'
          + '<span class="amt">' + esc(GharModel.fmtRs(working.salaryPkr)) + '</span></div>'
          + '<div class="sum-row"><div class="nm">Absent: ' + working.absentDays + ' × ' + esc(GharModel.fmtRs(absentRate))
          + '<span class="sub">' + working.absentDays + ' days × (salary ÷ 30)</span></div>'
          + '<span class="amt">− ' + esc(GharModel.fmtRs(working.absentDeduction)) + '</span></div>'
          + '<div class="sum-row"><div class="nm">Half days: ' + working.halfDays + ' × ' + esc(GharModel.fmtRs(halfRate))
          + '<span class="sub">' + working.halfDays + ' days × (salary ÷ 60)</span></div>'
          + '<span class="amt">− ' + esc(GharModel.fmtRs(working.halfDeduction)) + '</span></div>'
          + '<div class="sum-row"><div class="nm">Advance recovery<span class="sub">from the advances above, as you entered them</span></div>'
          + '<span class="amt">− ' + esc(GharModel.fmtRs(working.advanceRecovery)) + '</span></div>'
          + '<div class="sum-total"><span>Net payable</span><span>' + esc(GharModel.fmtRs(working.netPkr)) + '</span></div>'
          + '<p class="muted">' + esc(GharModel.fmtRs(working.salaryPkr)) + ' − ' + esc(GharModel.fmtRs(working.absentDeduction))
          + ' − ' + esc(GharModel.fmtRs(working.halfDeduction)) + ' − ' + esc(GharModel.fmtRs(working.advanceRecovery))
          + ' = ' + esc(GharModel.fmtRs(working.netPkr)) + ' · ' + working.daysInMonth + ' days in the month.</p>';
        if (locked) {
          html += '<p class="muted"><strong>Paid on ' + esc(paid.paidDate) + ' — this month is locked and cannot be edited.</strong></p>'
            + '<div class="row"><button type="button" class="small secondary" data-action="copy" data-helper="' + esc(s.id) + '">Copy statement for WhatsApp</button></div>';
        } else {
          html += '<div class="row"><button type="button" data-action="pay" data-helper="' + esc(s.id) + '">Mark paid</button>'
            + '<button type="button" class="secondary" data-action="copy" data-helper="' + esc(s.id) + '">Copy statement for WhatsApp</button></div>';
        }
      }
      html += '</div>';
      return html;
    });
    renderList('staff-list', 'staff-empty', rows);
  }
  function renderDeliveries() {
    var month = monthInputVal('del-month');
    var list = state.vault.deliveries || [];
    var logSel = $('log-delivery');
    if (logSel) {
      logSel.innerHTML = list.map(function (d) {
        return '<option value="' + esc(d.id) + '">' + esc(d.name) + ' — ' + esc(d.kind) + '</option>';
      }).join('');
    }
    var refSel = $('refill-delivery');
    if (refSel) {
      // Refills are for gas cylinders only — other deliveries never take
      // one. (Phase 5 second pass: the list used to offer every delivery,
      // so a refill could be recorded against a doodhwala.)
      var gas = list.filter(function (d) { return d.kind === 'Gas cylinder'; });
      refSel.innerHTML = gas.length
        ? gas.map(function (d) {
            return '<option value="' + esc(d.id) + '">' + esc(d.name) + ' — ' + esc(d.kind) + '</option>';
          }).join('')
        : '<option value="">No gas cylinder delivery yet — add one above</option>';
    }
    var rows = list.map(function (d) {
      var paid = GharModel.findPaidDeliveryMonth(d, month);
      var locked = !!paid;
      var total = null;
      try { total = GharModel.deliveryMonthTotal(state.vault, d.id, month); }
      catch (_e) { total = null; }
      var html = '<div class="card"><div class="sum-row"><div class="nm">' + esc(d.name) + ' — ' + esc(d.kind)
        + '<span class="sub">' + esc(GharModel.fmtRs(d.ratePkr)) + ' per ' + esc(d.unit)
        + ' · usual ' + esc(String(d.usualQty)) + ' a day · as you entered it</span></div></div>';
      if (d.kind === 'Gas cylinder') {
        var last = GharModel.lastGasRefill(d);
        var since = GharModel.gasDaysSinceLastRefill(d);
        html += '<h3>Gas refills</h3>';
        if (!last) html += '<p class="muted">No refill recorded yet.</p>';
        else {
          html += '<p class="muted">Last refill: ' + esc(last.date) + ' · ' + esc(GharModel.fmtRs(last.pricePkr))
            + ' · ' + (since === 0 ? 'refilled today' : since + (since === 1 ? ' day ago' : ' days ago')) + '.</p>';
          d.refills.forEach(function (r) {
            html += '<div class="sum-row"><div class="nm">Refill ' + esc(r.date)
              + '<span class="sub">as you entered it</span></div><span class="amt">'
              + esc(GharModel.fmtRs(r.pricePkr)) + '</span></div>';
          });
        }
      }
      html += '<h3>Bill — ' + esc(month) + '</h3>';
      if (total) {
        if (total.lines.length === 0) html += '<p class="muted">Nothing logged this month yet — log a day below.</p>';
        total.lines.forEach(function (ln) {
          html += '<div class="sum-row"><div class="nm">' + esc(ln.text)
            + '<span class="sub">added up from the daily log</span></div><span class="amt">'
            + esc(GharModel.fmtRs(ln.amountPkr)) + '</span></div>';
        });
        html += '<div class="sum-total"><span>Total for ' + esc(month) + '</span><span>'
          + esc(GharModel.fmtRs(total.totalPkr)) + '</span></div>'
          + '<p class="muted">' + total.days + ' days logged · ' + total.skippedDays + ' skipped day'
          + (total.skippedDays === 1 ? '' : 's') + ' (0 quantity) · each skipped day removes one day\u2019s charge.</p>';
      }
      if (locked) {
        html += '<p class="muted"><strong>Paid on ' + esc(paid.paidDate) + ' — this month is locked and cannot be edited.</strong></p>';
      } else if (total) {
        html += '<div class="row"><button type="button" data-action="delpay" data-delivery="' + esc(d.id) + '">Mark paid</button></div>';
      }
      html += '</div>';
      return html;
    });
    renderList('deliveries-list', 'deliveries-empty', rows);
  }
  function renderUdhaar() {
    fillUdhaarSelects();
    var people = state.vault.udhaar || [];
    var rows = people.map(function (p) {
      var bal = GharModel.udhaarPersonBalance(p);
      var html = '<div class="card"><div class="sum-row"><div class="nm">' + esc(p.person)
        + '<span class="sub">Lent outstanding ' + esc(GharModel.fmtRs(bal.lent))
        + ' · Borrowed outstanding ' + esc(GharModel.fmtRs(bal.borrowed))
        + ' · as you entered it</span></div></div>';
      if (!p.entries || p.entries.length === 0) {
        html += '<p class="muted">No entries for this person yet.</p>';
      }
      p.entries.forEach(function (e) {
        var entryBal = GharModel.udhaarEntryBalance(e);
        var repaid = (e.repayments || []).reduce(function (s, r) { return s + (Number(r.amountPkr) || 0); }, 0);
        html += '<div class="sum-row"><div class="nm">' + esc(e.direction === 'lent' ? 'Lent ' : 'Borrowed ')
          + esc(GharModel.fmtRs(e.amountPkr)) + ' on ' + esc(e.date)
          + '<span class="sub">' + (e.reason ? esc(e.reason) + ' · ' : '')
          + (e.dueDate ? 'due ' + esc(e.dueDate) + ' · ' : 'no due date · ')
          + 'repaid ' + esc(GharModel.fmtRs(repaid)) + ' · forgiven ' + esc(GharModel.fmtRs(e.forgivenPkr))
          + ' · as you entered it</span></div>'
          + '<span class="amt">' + esc(GharModel.fmtRs(entryBal)) + ' left</span>'
          + (e.settled ? '<span class="pill green">Settled — nothing outstanding</span>' : '')
          + '</div>';
        html += '<p class="muted">' + esc(GharModel.fmtRs(e.amountPkr)) + ' − ' + esc(GharModel.fmtRs(repaid))
          + ' repaid − ' + esc(GharModel.fmtRs(e.forgivenPkr)) + ' forgiven = '
          + esc(GharModel.fmtRs(entryBal)) + ' outstanding.</p>';
        if (e.repayments && e.repayments.length) {
          html += '<h3>Repayments</h3>';
          e.repayments.forEach(function (r) {
            html += '<div class="sum-row"><div class="nm">Repayment ' + esc(r.date)
              + '<span class="sub">as you entered it</span></div><span class="amt">'
              + esc(GharModel.fmtRs(r.amountPkr)) + '</span></div>';
          });
        }
        if (e.forgivenPkr > 0) {
          html += '<p class="muted">' + esc(GharModel.fmtRs(e.forgivenPkr))
            + ' forgiven — recorded as forgiven, not as a payment.</p>';
        }
        html += '<div class="row"><button type="button" class="small secondary" data-action="reminder" data-person="'
          + esc(p.id) + '" data-entry="' + esc(e.id) + '">Copy reminder for WhatsApp</button></div>';
      });
      html += '</div>';
      return html;
    });
    renderList('udhaar-list', 'udhaar-empty', rows);
  }
  // The person/entry dropdowns on the Udhaar page follow the vault: the
  // entry dropdowns follow their person dropdown.
  function udhaarEntryOptions(person) {
    return (person.entries || []).map(function (e) {
      return '<option value="' + esc(e.id) + '">' + esc(e.direction) + ' ' + esc(GharModel.fmtRs(e.amountPkr))
        + ' on ' + esc(e.date) + ' — balance ' + esc(GharModel.fmtRs(GharModel.udhaarEntryBalance(e)))
        + (e.settled ? ' (settled)' : '') + '</option>';
    }).join('');
  }
  function syncUdhaarEntrySelect(personSelId, entrySelId) {
    var psel = $(personSelId), esel = $(entrySelId);
    if (!psel || !esel) return;
    var people = state.vault.udhaar || [];
    var person = GharModel.findUdhaarPerson(state.vault, psel.value) || people[0] || null;
    var prev = esel.value;
    esel.innerHTML = person ? udhaarEntryOptions(person) : '';
    if (prev) esel.value = prev;
  }
  function fillUdhaarSelects() {
    var people = state.vault.udhaar || [];
    var personOpts = people.map(function (p) {
      return '<option value="' + esc(p.id) + '">' + esc(p.person) + '</option>';
    }).join('');
    ['udh-entry-person', 'repay-person', 'forgive-person'].forEach(function (id) {
      var sel = $(id);
      if (sel) {
        var prev = sel.value;
        sel.innerHTML = personOpts;
        if (prev) sel.value = prev;
      }
    });
    syncUdhaarEntrySelect('repay-person', 'repay-entry');
    syncUdhaarEntrySelect('forgive-person', 'forgive-entry');
  }
  function renderBills() {
    var today = GharModel.todayStr();
    var bills = state.vault.bills || [];
    var due = bills.filter(function (b) { return b.status === 'due'; });
    var paid = bills.filter(function (b) { return b.status === 'paid'; });
    function billRow(b) {
      var d = GharModel.daysBetween(today, b.dueDate);
      var html = '<div class="card"><div class="sum-row"><div class="nm">' + esc(b.type) + ' bill — ' + esc(b.provider)
        + '<span class="sub">' + esc(GharModel.fmtRs(b.amountPkr)) + ' · due ' + esc(b.dueDate)
        + (b.accountNo ? ' · account ' + esc(b.accountNo) : '')
        + (b.surchargeNote ? ' · late-surcharge note: ' + esc(b.surchargeNote) : '')
        + ' · as you entered it</span></div>'
        + (b.status === 'due'
          ? '<span class="pill' + (d < 0 ? ' amber' : '') + '">' + esc(GharModel.dueLabel({ daysUntil: d })) + '</span>'
          : '<span class="pill green">Paid on ' + esc(b.paidDate) + '</span>')
        + '</div>';
      var delLabel = state.pendingDeleteBillId === b.id ? 'Tap again to delete' : 'Delete';
      if (b.status === 'due') {
        html += '<div class="row"><button type="button" data-action="billpay" data-bill="' + esc(b.id) + '">Mark paid</button>'
          + '<button type="button" class="secondary" data-action="billdel" data-bill="' + esc(b.id) + '">' + delLabel + '</button></div>';
      } else {
        html += '<p class="muted">Paid on ' + esc(b.paidDate)
          + ' — kept in history. Mark unpaid only if the tap was a mistake.</p>'
          + '<div class="row"><button type="button" class="secondary" data-action="billunpay" data-bill="' + esc(b.id) + '">Mark unpaid</button>'
          + '<button type="button" class="secondary" data-action="billdel" data-bill="' + esc(b.id) + '">' + delLabel + '</button></div>';
      }
      html += '</div>';
      return html;
    }
    var rows = [];
    if (due.length) {
      rows.push('<h3>Due</h3>');
      due.forEach(function (b) { rows.push(billRow(b)); });
    }
    if (paid.length) {
      rows.push('<h3>Paid — history</h3>');
      paid.forEach(function (b) { rows.push(billRow(b)); });
    }
    renderList('bills-list', 'bills-empty', rows);
  }
  // ---- documents + medicine (Phase 4) ----
  function docCountdownText(doc) {
    var d = GharModel.documentDaysUntil(doc);
    if (d < 0) return 'EXPIRED ' + (-d) + ((-d) === 1 ? ' day ago' : ' days ago');
    if (d === 0) return 'expires today';
    return 'expires in ' + d + (d === 1 ? ' day' : ' days');
  }
  function renderDocuments() {
    var today = GharModel.todayStr();
    var docs = state.vault.documents || [];
    var rows = docs.map(function (doc) {
      var d = GharModel.documentDaysUntil(doc, today);
      var expired = d < 0;
      var html = '<div class="card"><div class="sum-row"><div class="nm">' + esc(doc.type) + ' — ' + esc(doc.owner)
        + '<span class="sub">Expires ' + esc(doc.expiryDate)
        + (doc.issueDate ? ' · issued ' + esc(doc.issueDate) : '')
        + ' · as you entered it</span></div>'
        + '<span class="pill' + (expired ? ' amber' : '') + '">' + esc(docCountdownText(doc)) + '</span></div>';
      if (doc.photo && doc.photo.dataUrl) {
        html += '<p class="muted"><a href="' + esc(doc.photo.dataUrl) + '" target="_blank" rel="noopener">'
          + '<img src="' + esc(doc.photo.dataUrl) + '" alt="Photo of ' + esc(doc.type) + ' — ' + esc(doc.owner)
          + '" style="max-width:120px;max-height:120px;border-radius:12px"></a>'
          + '<br>Tap the photo to see it full size. Stored inside the book, as you picked it.</p>';
      }
      var checklist = GharModel.getChecklist(doc.type);
      html += '<h3>Renewal checklist</h3>';
      if (checklist) {
        html += '<p class="muted">' + esc(checklist.title) + ' — updated ' + esc(checklist.updated) + '.</p><ul>';
        checklist.items.forEach(function (item) {
          html += '<li>' + esc(item) + '</li>';
        });
        html += '</ul><p class="muted">' + esc(checklist.note) + '</p>';
      } else {
        html += '<p class="muted">No checklist yet for this type.</p>';
      }
      var delLabel = state.pendingDeleteDocId === doc.id ? 'Tap again to delete' : 'Delete';
      html += '<div class="row"><button type="button" class="secondary" data-action="docdel" data-doc="' + esc(doc.id) + '">' + delLabel + '</button></div>';
      html += '</div>';
      return html;
    });
    renderList('documents-list', 'documents-empty', rows);
  }
  function renderMedicine() {
    var today = GharModel.todayStr();
    var medDays = (state.vault.settings && state.vault.settings.reminders && state.vault.settings.reminders.medDays) || [30, 7];
    var meds = state.vault.medicines || [];
    var rows = meds.map(function (m) {
      var w = GharModel.medicineWarnings(m, today, medDays);
      var html = '<div class="card"><div class="sum-row"><div class="nm">' + esc(m.name) + (m.person ? ' — ' + esc(m.person) : '')
        + '<span class="sub">' + esc(String(m.qtyLeft)) + ' ' + esc(m.unit) + ' left · expires ' + esc(m.expiryDate)
        + (m.place ? ' · ' + esc(m.place) : '')
        + (m.dosesPerDay != null ? ' · ' + esc(String(m.dosesPerDay)) + ' doses a day, as you typed it' : '')
        + ' · as you entered it</span></div>'
        + '<span class="pill' + (w.expired ? ' amber' : '') + '">'
        + esc(w.expired ? 'EXPIRED ' + (-w.daysUntil) + ((-w.daysUntil) === 1 ? ' day ago' : ' days ago')
          : w.daysUntil === 0 ? 'expires today'
          : 'expires in ' + w.daysUntil + (w.daysUntil === 1 ? ' day' : ' days'))
        + '</span></div>';
      if (w.expired) {
        html += '<p class="error">EXPIRED — do not use — check with a pharmacist.</p>';
      } else if (w.daysUntil <= Math.max.apply(null, medDays)) {
        // Expiry warning shows even when the medicine is also low stock:
        // the two warnings are different problems. (Phase 5 second pass:
        // the old condition hid the expiry warning whenever low stock
        // was also true.)
        html += '<p class="muted">Expires in ' + w.daysUntil + (w.daysUntil === 1 ? ' day' : ' days')
          + ' — inside the reminder window (' + medDays.join(', ') + ' days).</p>';
      }
      if (w.lowStock) {
        html += '<p class="muted"><strong>Low stock</strong> — ' + esc(String(m.qtyLeft)) + ' ' + esc(m.unit)
          + ' left, and the low-stock number you set is ' + esc(String(m.lowStockAt)) + '.</p>';
      }
      if (m.dosesTaken && m.dosesTaken.length) {
        var last = m.dosesTaken[m.dosesTaken.length - 1];
        html += '<p class="muted">Doses taken: ' + m.dosesTaken.length
          + ' · last ' + esc(last.date) + ' at ' + esc(last.time)
          + ' · quantity drops by one each time you mark a dose.</p>';
      } else {
        html += '<p class="muted">No doses recorded yet — quantity drops by one each time you mark a dose.</p>';
      }
      var delLabel = state.pendingDeleteMedId === m.id ? 'Tap again to delete' : 'Delete';
      html += '<div class="row"><button type="button" data-action="dose" data-med="' + esc(m.id) + '">Mark dose taken</button>'
        + '<button type="button" class="secondary" data-action="meddel" data-med="' + esc(m.id) + '">' + delLabel + '</button></div>';
      html += '</div>';
      return html;
    });
    renderList('medicine-list', 'medicine-empty', rows);
  }
  function renderSummary() {
    var month = monthInputVal('summary-month');
    var vault = state.vault;
    var hasRows = (vault.staff || []).length || (vault.deliveries || []).length
      || (vault.udhaar || []).length || (vault.bills || []).length
      || (vault.documents || []).length || (vault.medicines || []).length;
    if (!hasRows) { renderList('summary-list', 'summary-empty', []); return; }
    var s;
    try { s = GharModel.summaryForMonth(vault, month); }
    catch (_e) { renderList('summary-list', 'summary-empty', []); return; }
    function row(label, sub, amount) {
      return '<div class="sum-row"><div class="nm">' + esc(label)
        + '<span class="sub">' + esc(sub) + '</span></div>'
        + '<span class="amt">' + esc(amount) + '</span></div>';
    }
    function deltaLine(delta, prev, label) {
      var word = delta > 0 ? 'more' : delta < 0 ? 'less' : 'the same as';
      var amt = delta === 0 ? 'Rs 0' : GharModel.fmtRs(Math.abs(delta));
      return '<p class="muted">' + esc(label) + ': ' + amt + ' ' + word + ' than last month ('
        + esc(s.prevMonth) + ': ' + esc(GharModel.fmtRs(prev)) + ').</p>';
    }
    var html = '';
    html += '<h3>Staff — ' + esc(month) + '</h3>';
    html += row('Staff paid', s.staff.paidCount + ' helper' + (s.staff.paidCount === 1 ? '' : 's')
      + ' marked paid this month · sum of the paid months\u2019 net pay',
      GharModel.fmtRs(s.staff.paidPkr));
    html += row('Staff pay still to pay', s.staff.unpaidCount + ' helper' + (s.staff.unpaidCount === 1 ? '' : 's')
      + ' not yet marked paid · sum of their worked-out net pay for ' + month,
      GharModel.fmtRs(s.staff.unpaidWorkingPkr));
    html += row('Advances still outstanding', 'all helpers · sum of what is left to recover on every advance',
      GharModel.fmtRs(s.staff.advancesOutstandingPkr));
    html += deltaLine(s.compare.staffPaidDeltaPkr, s.compare.staffPaidPrevPkr, 'Staff paid');
    html += '<h3>Deliveries — ' + esc(month) + '</h3>';
    html += row('Deliveries total', s.deliveries.count + ' deliver' + (s.deliveries.count === 1 ? 'y' : 'ies')
      + ' · added up from the daily logs for ' + month, GharModel.fmtRs(s.deliveries.totalPkr));
    html += row('Deliveries paid', 'marked paid for ' + month, GharModel.fmtRs(s.deliveries.paidPkr));
    html += row('Deliveries not yet paid', 'total − paid for ' + month, GharModel.fmtRs(s.deliveries.unpaidPkr));
    html += deltaLine(s.compare.deliveriesDeltaPkr, s.compare.deliveriesPrevPkr, 'Deliveries total');
    html += '<h3>Udhaar</h3>';
    html += row('Lent — still outstanding', 'all open lent entries, all months · not a monthly total',
      GharModel.fmtRs(s.udhaar.lentOutstandingPkr));
    html += row('Borrowed — still outstanding', 'all open borrowed entries, all months · not a monthly total',
      GharModel.fmtRs(s.udhaar.borrowedOutstandingPkr));
    html += row('Lent in ' + month, 'entries dated in ' + month, GharModel.fmtRs(s.udhaar.lentThisMonthPkr));
    html += row('Borrowed in ' + month, 'entries dated in ' + month, GharModel.fmtRs(s.udhaar.borrowedThisMonthPkr));
    html += '<p class="muted">' + s.udhaar.settledCount + ' entr' + (s.udhaar.settledCount === 1 ? 'y' : 'ies')
      + ' settled (balance zero).</p>';
    html += '<h3>Bills — ' + esc(month) + '</h3>';
    html += row('Bills paid in ' + month, s.bills.paidCount + ' bill' + (s.bills.paidCount === 1 ? '' : 's')
      + ' with a paid date in ' + month, GharModel.fmtRs(s.bills.paidPkr));
    html += row('Bills due in ' + month, s.bills.dueThisMonthCount + ' unpaid bill'
      + (s.bills.dueThisMonthCount === 1 ? '' : 's') + ' with a due date in ' + month,
      GharModel.fmtRs(s.bills.dueThisMonthPkr));
    html += row('All unpaid bills', 'every bill still marked due, any month', GharModel.fmtRs(s.bills.dueAllPkr));
    html += row('Overdue bills', 'unpaid and past the due date', GharModel.fmtRs(s.bills.overduePkr));
    html += deltaLine(s.compare.billsPaidDeltaPkr, s.compare.billsPaidPrevPkr, 'Bills paid');
    html += '<h3>Documents</h3>';
    html += row('Expiring in ' + month, s.documents.expiringThisMonth.map(function (d) {
      return d.type + ' — ' + d.owner + ' (' + d.expiryDate + ')';
    }).join('; ') || 'none expiring this month', String(s.documents.expiringCount));
    html += row('Already expired', 'expiry date already passed · as you entered it', String(s.documents.expiredCount));
    html += '<h3>Medicine</h3>';
    html += row('Expiring in ' + month, s.medicines.expiringThisMonth.map(function (m) {
      return m.name + (m.person ? ' — ' + m.person : '') + ' (' + m.expiryDate + ')';
    }).join('; ') || 'none expiring this month', String(s.medicines.expiringCount));
    html += row('Already expired', 'expiry date already passed · do not use — check with a pharmacist',
      String(s.medicines.expiredCount));
    html += row('Low stock', 'quantity at or below the low-stock number you set', String(s.medicines.lowStockCount));
    html += '<p class="muted">Every total above is recomputed from the section pages when this page opens — nothing here is stored. The CSV export below carries the same rows.</p>';
    show($('summary-empty'), false);
    $('summary-list').innerHTML = html;
  }
  // ---- CSV export (Phase 5) ----
  function downloadText(filename, text, type) {
    var blob = new Blob([text], { type: type || 'text/csv' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function onCsvExport(section) {
    setText('summary-error', '');
    setText('summary-ok', '');
    try {
      if (typeof window === 'undefined' || !window.CsvExport) {
        throw new Error('CSV export is not loaded in this browser — reload the page and try again.');
      }
      var month = monthInputVal('summary-month');
      var sections = GharModel.sectionCsvRows(state.vault, month);
      if (section === 'all') {
        downloadText('ghar-ka-register-all-' + month + '.csv',
          window.CsvExport.buildCombinedCsv(sections));
        setText('summary-ok', 'All six sections exported as one CSV file for ' + month
          + '. A CSV is plain text — anyone who opens the file can read it.');
      } else {
        var sec = sections[section];
        if (!sec) throw new Error('Unknown section.');
        downloadText('ghar-ka-register-' + section + '-' + month + '.csv',
          window.CsvExport.rowsToCsv(sec.headers, sec.rows));
        setText('summary-ok', 'Exported the ' + section + ' CSV for ' + month
          + '. A CSV is plain text — anyone who opens the file can read it.');
      }
    } catch (e) {
      setText('summary-error', (e && e.message) || 'Could not export the CSV.');
    }
  }
  function fillProfile() {
    setVal('profile-household', state.vault.householdName || '');
    setVal('profile-monthstart', String(state.vault.monthStartDay || 1));
  }
  function renderSidebarName() {
    var name = (state.vault && state.vault.householdName) || 'My Home';
    setText('sidebar-name', name);
  }
  function renderPage(page) {
    if (page === 'home') renderToday();
    else if (page === 'staff') renderStaff();
    else if (page === 'deliveries') renderDeliveries();
    else if (page === 'udhaar') renderUdhaar();
    else if (page === 'bills') renderBills();
    else if (page === 'documents') renderDocuments();
    else if (page === 'medicine') renderMedicine();
    else if (page === 'summary') renderSummary();
    else if (page === 'profile') fillProfile();
  }
  function renderAll() {
    renderSidebarName();
    renderToday();
    renderStaff();
    renderDeliveries();
    renderUdhaar();
    renderBills();
    renderDocuments();
    renderMedicine();
    renderSummary();
    fillProfile();
  }

  // ---- staff + deliveries (Phase 2) ----
  function actionEl(ev) {
    var t = ev && ev.target;
    while (t) {
      if (t.dataset && t.dataset.action) return t;
      t = t.parentElement || t.parentNode;
    }
    return null;
  }
  async function onStaffAdd() {
    setText('staff-add-error', '');
    setText('staff-add-ok', '');
    try {
      var s = GharModel.addStaff(state.vault, {
        name: $('staff-name').value,
        role: $('staff-role').value,
        salaryPkr: parseInt($('staff-salary').value, 10),
        joinedDate: $('staff-joined').value,
        leavePerMonth: parseInt($('staff-leave').value, 10),
        phone: $('staff-phone').value,
      });
      await persist();
      setVal('staff-name', '');
      setVal('staff-salary', '');
      setVal('staff-phone', '');
      renderStaff();
      renderToday();
      setText('staff-add-ok', 'Helper added: ' + s.name + ' (' + s.role + '), ' + GharModel.fmtRs(s.salaryPkr) + ' a month, as you entered it.');
    } catch (e) {
      setText('staff-add-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onAdvanceAdd() {
    setText('adv-error', '');
    setText('adv-ok', '');
    try {
      var adv = GharModel.addAdvance(state.vault, $('adv-helper').value, {
        amount: parseInt($('adv-amount').value, 10),
        date: $('adv-date').value,
        note: $('adv-note').value,
        recovery: $('adv-recovery').value,
        instalmentPkr: parseInt($('adv-instalment').value, 10),
      });
      await persist();
      setVal('adv-amount', '');
      setVal('adv-note', '');
      setVal('adv-instalment', '');
      renderStaff();
      setText('adv-ok', 'Advance recorded: ' + GharModel.fmtRs(adv.amount) + ' on ' + adv.date
        + (adv.recovery === 'instalments' ? ' (' + GharModel.fmtRs(adv.instalmentPkr) + ' a month)' : ' (full recovery)') + '.');
    } catch (e) {
      setText('adv-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onStaffListClick(ev) {
    var b = actionEl(ev);
    if (!b) return;
    var helper = GharModel.findStaff(state.vault, b.dataset.helper);
    if (!helper) return;
    var month = monthInputVal('staff-month');
    try {
      if (b.dataset.action === 'att') {
        var dateStr = b.dataset.date;
        var current = (helper.attendance && helper.attendance[dateStr]) || 'present';
        var next = current === 'present' ? 'absent' : current === 'absent' ? 'half' : 'present';
        GharModel.markAttendance(state.vault, helper.id, dateStr, next);
        await persist();
        renderStaff();
      } else if (b.dataset.action === 'pay') {
        var rec = GharModel.markMonthPaid(state.vault, helper.id, month);
        await persist();
        renderStaff();
        renderToday();
        setText('staff-add-ok', 'Paid ' + helper.name + ' for ' + month + ': ' + GharModel.fmtRs(rec.netPkr) + '. The month is now locked.');
      } else if (b.dataset.action === 'copy') {
        var statement = GharModel.staffPayStatement(helper, month);
        var box = $('staff-statement');
        if (box) {
          box.textContent = statement;
          box.classList.remove('hidden');
        }
        if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
          try { await navigator.clipboard.writeText(statement); } catch (_e) { /* shown on screen instead */ }
        }
        setText('staff-add-ok', 'Statement ready below — copy it to WhatsApp. The app sends nothing itself.');
      }
    } catch (e) {
      setText('staff-add-error', e.message || 'Could not do that.');
    }
  }
  async function onDeliveryAdd() {
    setText('del-add-error', '');
    setText('del-add-ok', '');
    try {
      var d = GharModel.addDelivery(state.vault, {
        name: $('del-name').value,
        kind: $('del-kind').value,
        unit: $('del-unit').value,
        ratePkr: parseInt($('del-rate').value, 10),
        usualQty: Number($('del-qty').value),
      });
      await persist();
      setVal('del-name', '');
      setVal('del-rate', '');
      setVal('del-qty', '');
      renderDeliveries();
      setText('del-add-ok', 'Delivery added: ' + d.name + ' (' + d.kind + '), ' + GharModel.fmtRs(d.ratePkr) + ' per ' + d.unit + ', as you entered it.');
    } catch (e) {
      setText('del-add-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onLogDay() {
    setText('log-error', '');
    setText('log-ok', '');
    try {
      var logged = GharModel.logDelivery(state.vault, $('log-delivery').value, $('log-date').value, Number($('log-qty').value));
      await persist();
      renderDeliveries();
      setText('log-ok', logged.qty === 0
        ? 'Skipped day logged for ' + logged.date + ' — one day\u2019s charge removed.'
        : 'Logged ' + logged.qty + ' on ' + logged.date + '.');
    } catch (e) {
      setText('log-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onRefillAdd() {
    setText('refill-error', '');
    setText('refill-ok', '');
    if (!$('refill-delivery').value) {
      setText('refill-error', 'Add a gas cylinder delivery first — refills are for gas cylinders only.');
      return;
    }
    try {
      var r = GharModel.addGasRefill(state.vault, $('refill-delivery').value, {
        date: $('refill-date').value,
        pricePkr: parseInt($('refill-price').value, 10),
      });
      await persist();
      setVal('refill-price', '');
      renderDeliveries();
      setText('refill-ok', 'Refill recorded: ' + r.date + ' · ' + GharModel.fmtRs(r.pricePkr) + ', as you entered it.');
    } catch (e) {
      setText('refill-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onDeliveriesListClick(ev) {
    var b = actionEl(ev);
    if (!b || b.dataset.action !== 'delpay') return;
    var month = monthInputVal('del-month');
    try {
      var rec = GharModel.markDeliveryMonthPaid(state.vault, b.dataset.delivery, month);
      await persist();
      renderDeliveries();
      setText('del-add-ok', 'Marked paid for ' + month + ': ' + GharModel.fmtRs(rec.totalPkr) + '. The month is now locked.');
    } catch (e) {
      setText('del-add-error', e.message || 'Could not do that.');
    }
  }

  // ---- udhaar + bills (Phase 3) ----
  async function onUdhaarPersonAdd() {
    setText('udh-person-error', '');
    setText('udh-person-ok', '');
    try {
      var p = GharModel.addUdhaarPerson(state.vault, { person: $('udh-person-name').value });
      await persist();
      setVal('udh-person-name', '');
      renderUdhaar();
      setText('udh-person-ok', 'Person added: ' + p.person + '.');
    } catch (e) {
      setText('udh-person-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onUdhaarEntryAdd() {
    setText('udh-entry-error', '');
    setText('udh-entry-ok', '');
    try {
      var e = GharModel.addUdhaarEntry(state.vault, $('udh-entry-person').value, {
        direction: $('udh-entry-direction').value,
        amountPkr: parseInt($('udh-entry-amount').value, 10),
        date: $('udh-entry-date').value,
        reason: $('udh-entry-reason').value,
        dueDate: $('udh-entry-due').value,
      });
      await persist();
      setVal('udh-entry-amount', '');
      setVal('udh-entry-reason', '');
      setVal('udh-entry-due', '');
      renderUdhaar();
      renderToday();
      setText('udh-entry-ok', 'Entry added: ' + e.direction + ' ' + GharModel.fmtRs(e.amountPkr)
        + ' on ' + e.date + ', as you entered it.');
    } catch (e) {
      setText('udh-entry-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onRepayAdd() {
    setText('repay-error', '');
    setText('repay-ok', '');
    try {
      var r = GharModel.recordRepayment(state.vault, $('repay-person').value, $('repay-entry').value, {
        amountPkr: parseInt($('repay-amount').value, 10),
        date: $('repay-date').value,
      });
      await persist();
      var person = GharModel.findUdhaarPerson(state.vault, $('repay-person').value);
      var entry = person ? GharModel.findUdhaarEntry(person, $('repay-entry').value) : null;
      var bal = entry ? GharModel.udhaarEntryBalance(entry) : 0;
      setVal('repay-amount', '');
      renderUdhaar();
      renderToday();
      setText('repay-ok', 'Repayment recorded: ' + GharModel.fmtRs(r.amountPkr) + ' on ' + r.date
        + '. Balance now ' + GharModel.fmtRs(bal) + (entry && entry.settled ? ' — settled, nothing outstanding.' : '.'));
    } catch (e) {
      setText('repay-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onForgiveAdd() {
    setText('forgive-error', '');
    setText('forgive-ok', '');
    try {
      var res = GharModel.forgiveUdhaar(state.vault, $('forgive-person').value, $('forgive-entry').value,
        parseInt($('forgive-amount').value, 10));
      await persist();
      setVal('forgive-amount', '');
      renderUdhaar();
      renderToday();
      setText('forgive-ok', 'Recorded as forgiven: ' + GharModel.fmtRs(res.forgivenPkr)
        + ' forgiven in total on this entry. Balance now ' + GharModel.fmtRs(res.balance)
        + (res.settled ? ' — settled, nothing outstanding.' : '.'));
    } catch (e) {
      setText('forgive-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onUdhaarListClick(ev) {
    var b = actionEl(ev);
    if (!b || b.dataset.action !== 'reminder') return;
    try {
      var person = GharModel.findUdhaarPerson(state.vault, b.dataset.person);
      var entry = person ? GharModel.findUdhaarEntry(person, b.dataset.entry) : null;
      if (!person || !entry) throw new Error('That entry does not exist any more.');
      var text = GharModel.udhaarReminderText(person, entry);
      var box = $('udh-reminder');
      if (box) {
        box.textContent = text;
        box.classList.remove('hidden');
      }
      if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
        try { await navigator.clipboard.writeText(text); } catch (_e) { /* shown on screen instead */ }
      }
      setText('udh-entry-ok', 'Reminder ready below — copy it to WhatsApp. The app sends nothing itself.');
    } catch (e) {
      setText('udh-entry-error', e.message || 'Could not do that.');
    }
  }
  async function onBillAdd() {
    setText('bill-add-error', '');
    setText('bill-add-ok', '');
    try {
      var bill = GharModel.addBill(state.vault, {
        type: $('bill-type').value,
        provider: $('bill-provider').value,
        accountNo: $('bill-account').value,
        amountPkr: parseInt($('bill-amount').value, 10),
        dueDate: $('bill-due').value,
        surchargeNote: $('bill-surcharge').value,
      });
      await persist();
      setVal('bill-provider', '');
      setVal('bill-account', '');
      setVal('bill-amount', '');
      setVal('bill-surcharge', '');
      renderBills();
      renderToday();
      setText('bill-add-ok', 'Bill added: ' + bill.type + ' — ' + bill.provider + ', '
        + GharModel.fmtRs(bill.amountPkr) + ' due ' + bill.dueDate + ', as you entered it.');
    } catch (e) {
      setText('bill-add-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onBillsListClick(ev) {
    var b = actionEl(ev);
    if (!b) return;
    var bill = GharModel.findBill(state.vault, b.dataset.bill);
    if (!bill) return;
    try {
      if (b.dataset.action === 'billpay') {
        state.pendingDeleteBillId = null;
        var paid = GharModel.markBillPaid(state.vault, bill.id);
        await persist();
        renderBills();
        renderToday();
        setText('bill-add-ok', 'Marked paid: ' + bill.type + ' — ' + bill.provider + ' on ' + paid.paidDate
          + '. It stays in history below.');
      } else if (b.dataset.action === 'billunpay') {
        state.pendingDeleteBillId = null;
        GharModel.markBillUnpaid(state.vault, bill.id);
        await persist();
        renderBills();
        renderToday();
        setText('bill-add-ok', 'Marked unpaid again: ' + bill.type + ' — ' + bill.provider
          + '. It shows on Today again from its due date.');
      } else if (b.dataset.action === 'billdel') {
        if (state.pendingDeleteBillId !== bill.id) {
          state.pendingDeleteBillId = bill.id;
          renderBills();
        } else {
          state.pendingDeleteBillId = null;
          GharModel.deleteBill(state.vault, bill.id);
          await persist();
          renderBills();
          renderToday();
          setText('bill-add-ok', 'Bill deleted: ' + bill.type + ' — ' + bill.provider + '.');
        }
      }
    } catch (e) {
      state.pendingDeleteBillId = null;
      setText('bill-add-error', e.message || 'Could not do that.');
    }
  }

  // ---- documents + medicine (Phase 4) ----
  // Shrink a photo data URL to a JPEG of 500 KB or less, in the browser.
  // Steps the JPEG quality down (0.9 -> 0.5), then shrinks the picture
  // itself and tries again. If it still does not fit, it refuses with a
  // plain message — the photo is never silently dropped, and nothing is
  // stored half-shrunk. Refuses when the browser has no canvas/Image.
  function downscalePhoto(dataUrl) {
    return new Promise(function (resolve, reject) {
      if (typeof Image === 'undefined' || typeof document === 'undefined') {
        reject(new Error('This browser cannot shrink photos — pick a photo under 500 KB.'));
        return;
      }
      var img = new Image();
      img.onload = function () {
        try {
          var canvas = document.createElement('canvas');
          if (!canvas.getContext) {
            reject(new Error('This browser cannot shrink photos — pick a photo under 500 KB.'));
            return;
          }
          var maxDim = 1600;
          var scale = 1;
          if (Math.max(img.naturalWidth, img.naturalHeight) > maxDim) {
            scale = maxDim / Math.max(img.naturalWidth, img.naturalHeight);
          }
          var attempt = function (dimScale, quality) {
            var w = Math.max(1, Math.round(img.naturalWidth * scale * dimScale));
            var h = Math.max(1, Math.round(img.naturalHeight * scale * dimScale));
            canvas.width = w;
            canvas.height = h;
            var ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, w, h);
            return canvas.toDataURL('image/jpeg', quality);
          };
          var out = null;
          var quality = 0.9;
          var dimScale = 1;
          for (var round = 0; round < 12; round++) {
            out = attempt(dimScale, quality);
            if (GharModel.photoFitsCap(out)) break;
            if (quality > 0.5) quality = Math.max(0.5, quality - 0.1);
            else dimScale *= 0.75;
            if (dimScale < 0.1) break;
          }
          if (!out || !GharModel.photoFitsCap(out)) {
            reject(new Error('This photo is still over 500 KB after shrinking — try a smaller photo.'));
            return;
          }
          resolve({ dataUrl: out, mime: 'image/jpeg' });
        } catch (e) {
          reject(new Error('This photo could not be shrunk — try a smaller photo.'));
        }
      };
      img.onerror = function () {
        reject(new Error('This photo could not be read — pick the file again.'));
      };
      img.src = dataUrl;
    });
  }
  // The photo file input: read the file, run the magic-byte test, and
  // shrink it to 500 KB or less when it is over the cap. The shrunk
  // photo waits in state.pendingDocPhoto until the document is added.
  // Any failure shows a plain error — the photo is never silently
  // dropped, and the document can still be added without it.
  async function onDocPhotoChange() {
    setText('doc-add-error', '');
    setText('doc-photo-note', '');
    state.pendingDocPhoto = null;
    var input = $('doc-photo');
    var file = input && input.files && input.files[0];
    if (!file) return;
    if (typeof FileReader === 'undefined') {
      setText('doc-add-error', 'This browser cannot read photo files — add the document without a photo.');
      return;
    }
    var reader = new FileReader();
    reader.onload = async function () {
      try {
        var dataUrl = String(reader.result || '');
        var pv = GharModel.validatePhotoDataUrl(dataUrl);
        if (!pv.ok) {
          setText('doc-add-error', pv.errors.join(' '));
          return;
        }
        if (GharModel.photoFitsCap(dataUrl)) {
          state.pendingDocPhoto = { dataUrl: dataUrl, mime: pv.mime };
          setText('doc-photo-note', 'Photo ready — under 500 KB, as you picked it.');
          return;
        }
        setText('doc-photo-note', 'Photo is over 500 KB — shrinking it now…');
        var shrunk = await downscalePhoto(dataUrl);
        state.pendingDocPhoto = shrunk;
        setText('doc-photo-note', 'Photo ready — shrunk to under 500 KB, as you picked it.');
      } catch (e) {
        state.pendingDocPhoto = null;
        setText('doc-add-error', (e && e.message) || 'This photo could not be used — pick another one.');
      }
    };
    reader.onerror = function () {
      setText('doc-add-error', 'This photo could not be read — pick the file again.');
    };
    if (typeof reader.readAsDataURL === 'function') reader.readAsDataURL(file);
    else setText('doc-add-error', 'This browser cannot read photo files — add the document without a photo.');
  }
  // Clear a picked photo without adding the document: the picked photo
  // used to stay attached and land on the next document added.
  // (Phase 5 second pass.)
  function onDocPhotoClear() {
    state.pendingDocPhoto = null;
    var input = $('doc-photo');
    if (input) input.value = '';
    setText('doc-photo-note', '');
    setText('doc-add-error', '');
  }
  async function onDocumentAdd() {
    setText('doc-add-error', '');
    setText('doc-add-ok', '');
    try {
      var doc = GharModel.addDocument(state.vault, {
        type: $('doc-type').value,
        owner: $('doc-owner').value,
        issueDate: $('doc-issue').value,
        expiryDate: $('doc-expiry').value,
        photo: state.pendingDocPhoto,
      });
      await persist();
      state.pendingDocPhoto = null;
      setVal('doc-owner', '');
      setVal('doc-issue', '');
      setVal('doc-expiry', '');
      var photoInput = $('doc-photo');
      if (photoInput) photoInput.value = '';
      setText('doc-photo-note', '');
      renderDocuments();
      renderToday();
      var d = GharModel.documentDaysUntil(doc);
      setText('doc-add-ok', 'Document added: ' + doc.type + ' — ' + doc.owner + ', expires ' + doc.expiryDate
        + (d < 0 ? ' (expired ' + (-d) + ' days ago)' : d === 0 ? ' (expires today)' : ' (expires in ' + d + ' days)')
        + ', as you entered it.');
    } catch (e) {
      setText('doc-add-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onDocumentsListClick(ev) {
    var b = actionEl(ev);
    if (!b || b.dataset.action !== 'docdel') return;
    var doc = GharModel.findDocument(state.vault, b.dataset.doc);
    if (!doc) return;
    try {
      if (state.pendingDeleteDocId !== doc.id) {
        state.pendingDeleteDocId = doc.id;
        renderDocuments();
      } else {
        state.pendingDeleteDocId = null;
        GharModel.deleteDocument(state.vault, doc.id);
        await persist();
        renderDocuments();
        renderToday();
        setText('doc-add-ok', 'Document deleted: ' + doc.type + ' — ' + doc.owner + '.');
      }
    } catch (e) {
      state.pendingDeleteDocId = null;
      setText('doc-add-error', e.message || 'Could not do that.');
    }
  }
  async function onMedicineAdd() {
    setText('med-add-error', '');
    setText('med-add-ok', '');
    try {
      var med = GharModel.addMedicine(state.vault, {
        name: $('med-name').value,
        qtyLeft: parseInt($('med-qty').value, 10),
        unit: $('med-unit').value,
        expiryDate: $('med-expiry').value,
        place: $('med-place').value,
        person: $('med-person').value,
        dosesPerDay: $('med-doses').value,
        lowStockAt: $('med-low').value,
      });
      await persist();
      setVal('med-name', '');
      setVal('med-qty', '');
      setVal('med-unit', '');
      setVal('med-expiry', '');
      setVal('med-person', '');
      setVal('med-doses', '');
      setVal('med-low', '');
      renderMedicine();
      renderToday();
      setText('med-add-ok', 'Medicine added: ' + med.name + ', ' + med.qtyLeft + ' ' + med.unit
        + ' left, expires ' + med.expiryDate + ', as you entered it.');
    } catch (e) {
      setText('med-add-error', (e.errors || [e.message]).join(' '));
    }
  }
  async function onMedicineListClick(ev) {
    var b = actionEl(ev);
    if (!b) return;
    var med = GharModel.findMedicine(state.vault, b.dataset.med);
    if (!med) return;
    try {
      if (b.dataset.action === 'dose') {
        state.pendingDeleteMedId = null;
        var now = new Date();
        var dateStr = GharModel.todayStr();
        var timeStr = String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
        GharModel.recordDose(state.vault, med.id, { date: dateStr, time: timeStr });
        await persist();
        renderMedicine();
        renderToday();
        setText('med-add-ok', 'Dose recorded for ' + med.name + ' on ' + dateStr + ' at ' + timeStr
          + ' — quantity now ' + med.qtyLeft + ' ' + med.unit + '.');
      } else if (b.dataset.action === 'meddel') {
        if (state.pendingDeleteMedId !== med.id) {
          state.pendingDeleteMedId = med.id;
          renderMedicine();
        } else {
          state.pendingDeleteMedId = null;
          GharModel.deleteMedicine(state.vault, med.id);
          await persist();
          renderMedicine();
          renderToday();
          setText('med-add-ok', 'Medicine deleted: ' + med.name + '.');
        }
      }
    } catch (e) {
      state.pendingDeleteMedId = null;
      setText('med-add-error', e.message || 'Could not do that.');
    }
  }

  // ---- profile ----
  async function onProfileSave() {
    setText('profile-error', '');
    setText('profile-ok', '');
    try {
      var res = GharModel.setHousehold(state.vault, {
        householdName: $('profile-household').value,
        monthStartDay: parseInt($('profile-monthstart').value, 10),
      });
      await persist();
      setText('profile-ok', 'Saved. Household: ' + (res.householdName || 'My Home')
        + ', month starts on day ' + res.monthStartDay + '.');
      renderSidebarName();
    } catch (e) {
      setText('profile-error', (e.errors || [e.message]).join(' '));
    }
  }

  // ---- security: change PIN / change passphrase ----
  async function onChangePin() {
    setText('change-pin-error', '');
    setText('change-pin-ok', '');
    var oldPin = $('change-pin-old').value.trim();
    var oldPass = $('change-pin-pass').value || '';
    var next = $('change-pin-new').value.trim();
    var next2 = $('change-pin-new2').value.trim();
    if (!VaultCrypto.validPin(oldPin)) { setText('change-pin-error', 'Current PIN must be exactly 6 digits.'); return; }
    if (!VaultCrypto.validPin(next)) { setText('change-pin-error', 'New PIN must be exactly 6 digits.'); return; }
    if (next !== next2) { setText('change-pin-error', 'The two new PINs do not match.'); return; }
    try {
      var res = await VaultCrypto.unlockVault(oldPin, oldPass, state.envelope);
      if (!GharModel.isGharVault(res.vault)) throw new Error('not-ghar');
      var made = await VaultCrypto.createVault(next, oldPass, state.vault);
      state.envelope = made.envelope;
      state.key = made.key;
      saveEnvelope();
      setVal('change-pin-old', '');
      setVal('change-pin-pass', '');
      setVal('change-pin-new', '');
      setVal('change-pin-new2', '');
      setText('change-pin-ok', 'PIN changed. The book stays unlocked.');
    } catch (e) {
      setText('change-pin-error', e && e.code === 'DECRYPT_FAILED'
        ? 'Current PIN (or passphrase) is wrong.'
        : 'Could not change the PIN — try again.');
    }
  }
  async function onChangePass() {
    setText('change-pass-error', '');
    setText('change-pass-ok', '');
    var pin = $('change-pass-old').value.trim();
    var oldPass = $('change-pass-pass').value || '';
    var next = $('change-pass-new').value || '';
    if (!VaultCrypto.validPin(pin)) { setText('change-pass-error', 'Current PIN must be exactly 6 digits.'); return; }
    if (!VaultCrypto.validPassphrase(next)) { setText('change-pass-error', 'New passphrase must be empty or at least 4 characters.'); return; }
    try {
      var res = await VaultCrypto.unlockVault(pin, oldPass, state.envelope);
      if (!GharModel.isGharVault(res.vault)) throw new Error('not-ghar');
      var made = await VaultCrypto.createVault(pin, next, state.vault);
      state.envelope = made.envelope;
      state.key = made.key;
      saveEnvelope();
      setVal('change-pass-old', '');
      setVal('change-pass-pass', '');
      setVal('change-pass-new', '');
      setText('change-pass-ok', next === ''
        ? 'Passphrase removed. The book now opens with the PIN only.'
        : 'Passphrase changed. The book now opens with the PIN + new passphrase.');
    } catch (e) {
      setText('change-pass-error', e && e.code === 'DECRYPT_FAILED'
        ? 'Current PIN (or passphrase) is wrong.'
        : 'Could not change the passphrase — try again.');
    }
  }

  // ---- backup: encrypted export / import ----
  function onExport() {
    setText('backup-error', '');
    setText('backup-ok', '');
    try {
      var backup = VaultCrypto.createBackup(state.envelope);
      var text = JSON.stringify(backup, null, 2);
      var stamp = new Date().toISOString().slice(0, 10);
      var blob = new Blob([text], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'ghar-ka-register-backup-' + stamp + '.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      setText('backup-ok', 'Backup exported. It opens only with this book\u2019s PIN (and passphrase, if you set one). Keep the file somewhere safe.');
    } catch (e) {
      setText('backup-error', (e && e.message) || 'Could not export the backup.');
    }
  }
  function onImportFileChange() {
    setText('backup-error', '');
    setText('backup-ok', '');
    var input = $('import-file');
    var file = input.files && input.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      try {
        state.pendingImport = VaultCrypto.parseBackup(String(reader.result));
        setText('backup-ok', 'Backup file read. Enter its PIN below, then tap Restore backup.');
      } catch (e) {
        state.pendingImport = null;
        setText('backup-error', (e && e.message) || 'That file is not a backup.');
      }
    };
    reader.onerror = function () { setText('backup-error', 'Could not read that file.'); };
    reader.readAsText(file);
  }
  async function onImportRestore() {
    setText('backup-error', '');
    setText('backup-ok', '');
    if (!state.pendingImport) { setText('backup-error', 'Choose a backup file first.'); return; }
    var pin = $('import-pin').value.trim();
    var pass = $('import-pass').value || '';
    if (!VaultCrypto.validPin(pin)) { setText('backup-error', 'Backup PIN must be exactly 6 digits.'); return; }
    try {
      var res = await VaultCrypto.unlockVault(pin, pass, state.pendingImport);
      if (!GharModel.isGharVault(res.vault)) {
        setText('backup-error', 'This backup is from the old Card Vault. It does not open here — an old backup restores only into the old code.');
        return;
      }
      state.envelope = state.pendingImport;
      state.key = res.key;
      state.vault = res.vault;
      state.pendingImport = null;
      saveEnvelope();
      state.lockout = VaultCrypto.recordSuccess();
      saveLockout();
      state.lastActiveMs = Date.now();
      setVal('import-pin', '');
      setVal('import-pass', '');
      showScreen('vault');
      renderAll();
      route();
      setText('backup-ok', 'Backup restored. The book is open.');
    } catch (e) {
      setText('backup-error', e && e.code === 'DECRYPT_FAILED'
        ? 'Wrong backup PIN (or passphrase).'
        : ((e && e.message) || 'Could not restore that backup.'));
    }
  }

  // ---- init ----
  function init() {
    loadStored();
    state.lastActiveMs = Date.now();
    $('setup-btn').addEventListener('click', onSetup);
    $('setup-pin2').addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') onSetup();
    });
    $('unlock-btn').addEventListener('click', onUnlock);
    $('unlock-pin').addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') onUnlock();
    });
    $('lock-btn').addEventListener('click', lock);
    $('profile-save-btn').addEventListener('click', onProfileSave);
    $('staff-add-btn').addEventListener('click', onStaffAdd);
    $('adv-add-btn').addEventListener('click', onAdvanceAdd);
    $('staff-list').addEventListener('click', onStaffListClick);
    $('staff-month').addEventListener('change', renderStaff);
    $('del-add-btn').addEventListener('click', onDeliveryAdd);
    $('log-btn').addEventListener('click', onLogDay);
    $('refill-btn').addEventListener('click', onRefillAdd);
    $('deliveries-list').addEventListener('click', onDeliveriesListClick);
    $('del-month').addEventListener('change', renderDeliveries);
    $('udh-person-add-btn').addEventListener('click', onUdhaarPersonAdd);
    $('udh-entry-add-btn').addEventListener('click', onUdhaarEntryAdd);
    $('repay-add-btn').addEventListener('click', onRepayAdd);
    $('forgive-add-btn').addEventListener('click', onForgiveAdd);
    $('udhaar-list').addEventListener('click', onUdhaarListClick);
    $('repay-person').addEventListener('change', function () { syncUdhaarEntrySelect('repay-person', 'repay-entry'); });
    $('forgive-person').addEventListener('change', function () { syncUdhaarEntrySelect('forgive-person', 'forgive-entry'); });
    $('bill-add-btn').addEventListener('click', onBillAdd);
    $('bills-list').addEventListener('click', onBillsListClick);
    $('doc-add-btn').addEventListener('click', onDocumentAdd);
    $('doc-photo').addEventListener('change', onDocPhotoChange);
    $('doc-photo-clear-btn').addEventListener('click', onDocPhotoClear);
    $('documents-list').addEventListener('click', onDocumentsListClick);
    $('med-add-btn').addEventListener('click', onMedicineAdd);
    $('medicine-list').addEventListener('click', onMedicineListClick);
    setVal('staff-month', currentMonthKey());
    setVal('del-month', currentMonthKey());
    setVal('summary-month', currentMonthKey());
    $('summary-month').addEventListener('change', renderSummary);
    $('csv-staff-btn').addEventListener('click', function () { onCsvExport('staff'); });
    $('csv-deliveries-btn').addEventListener('click', function () { onCsvExport('deliveries'); });
    $('csv-udhaar-btn').addEventListener('click', function () { onCsvExport('udhaar'); });
    $('csv-bills-btn').addEventListener('click', function () { onCsvExport('bills'); });
    $('csv-documents-btn').addEventListener('click', function () { onCsvExport('documents'); });
    $('csv-medicines-btn').addEventListener('click', function () { onCsvExport('medicines'); });
    $('csv-all-btn').addEventListener('click', function () { onCsvExport('all'); });
    $('change-pin-btn').addEventListener('click', onChangePin);
    $('change-pass-btn').addEventListener('click', onChangePass);
    $('export-btn').addEventListener('click', onExport);
    $('import-file').addEventListener('change', onImportFileChange);
    $('import-btn').addEventListener('click', onImportRestore);
    Nav.PAGES.forEach(function (p) {
      var btn = $('nav-' + p);
      if (btn) btn.addEventListener('click', function () { window.location.hash = '#/' + p; });
    });
    window.addEventListener('hashchange', route);
    document.addEventListener('click', markActive);
    document.addEventListener('keydown', markActive);
    document.addEventListener('input', markActive);
    setInterval(autoLockCheck, 15000);
    route();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
