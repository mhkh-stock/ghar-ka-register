// Personal Card Vault — app shell (browser only).
// Phase 2: the reel-exact glass frontend (Code XR "Glassy Payment Checkout
// V2" look) + Intelligence (paste-an-SMS direct update) + two-factor auth.
// The element IDs and flows stay the same as Phase 1.
// Storage: localStorage only. Keys: pcv.vault (encrypted envelope JSON),
// pcv.lockout (failure count + lockoutUntil), pcv.backup (SHA-256 hashes of
// the one-time backup codes — never the codes themselves). The CryptoKey
// lives in memory only and is wiped on lock. The server stores NOTHING.
'use strict';
/* global VaultCrypto, VaultModel, SmsParser, CsvImport, Cards, Intel, Proof, Totp */
(function () {
  var LS_VAULT = 'pcv.vault';
  var LS_LOCKOUT = 'pcv.lockout';

  var state = {
    key: null, envelope: null, vault: null, passphrase: '',
    lockout: VaultCrypto.createLockoutState(),
    lastActive: Date.now(), hideBalances: false,
    smsDraft: null, csvDraft: null,
    selectedAccountId: null, intelUndo: null,
    editingAccountId: null, pendingDeleteId: null, pendingProofRemoveId: null,
    addProof: null, addProofBalance: null, reconcileSkipped: {},
    pending2fa: null, twoFaSetup: null,
    currentPage: 'wallet', profileDpDataUrl: null,
  };

  // Backup-code hashes live OUTSIDE the vault (localStorage) so a code can
  // be checked while the vault is still locked. Only hashes, never codes.
  var LS_BACKUP = 'pcv.backup';
  function loadBackupHashes() {
    try {
      var raw = localStorage.getItem(LS_BACKUP);
      if (!raw) return [];
      var o = JSON.parse(raw);
      return Array.isArray(o.hashes) ? o.hashes : [];
    } catch (_e) { return []; }
  }
  function saveBackupHashes(hashes) {
    if (!hashes || !hashes.length) { localStorage.removeItem(LS_BACKUP); return; }
    localStorage.setItem(LS_BACKUP, JSON.stringify({ hashes: hashes }));
  }

  function $(id) { return document.getElementById(id); }
  function show(el) { el.classList.remove('hidden'); }
  function hide(el) { el.classList.add('hidden'); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmtRs(n) { return 'Rs ' + Number(n || 0).toLocaleString('en-PK'); }
  // Unknown balance (Phase 3.5): say so plainly — never "Rs 0" for a number
// the bank never stated. Hide-balances only masks a real number.
function maskBal(n) {
  if (n === null || n === undefined) return 'Balance not set yet';
  return state.hideBalances ? 'Rs ••••' : fmtRs(n);
}

  function loadStored() {
    try { state.envelope = JSON.parse(localStorage.getItem(LS_VAULT) || 'null'); } catch (_e) { state.envelope = null; }
    try {
      var l = JSON.parse(localStorage.getItem(LS_LOCKOUT) || 'null');
      if (l && typeof l.failures === 'number') state.lockout = l;
    } catch (_e) { state.lockout = VaultCrypto.createLockoutState(); }
  }
  function saveEnvelope(env) {
    state.envelope = env;
    localStorage.setItem(LS_VAULT, JSON.stringify(env));
  }
  function saveLockout() { localStorage.setItem(LS_LOCKOUT, JSON.stringify(state.lockout)); }

  function emptyVault() {
    return VaultModel.emptyVault();
  }

  async function persist() {
    if (!state.key || !state.envelope || !state.vault) return;
    var env = await VaultCrypto.saveVault(state.key, state.envelope, state.vault);
    saveEnvelope(env);
  }

  function showScreen(name) {
    hide($('setup-screen')); hide($('unlock-screen')); hide($('totp-screen')); hide($('vault-screen'));
    if (name) show($(name + '-screen'));
  }

  function lockoutMessage() {
    if (!VaultCrypto.isLocked(state.lockout, Date.now())) return '';
    var secs = Math.ceil(VaultCrypto.lockoutRemainingMs(state.lockout, Date.now()) / 1000);
    return 'Too many wrong PINs. Try again in ' + secs + ' seconds.';
  }

  function refreshLockoutNote() {
    var msg = lockoutMessage();
    var note = $('lockout-note');
    if (msg) { note.textContent = msg; show(note); } else { hide(note); }
  }

  function lock() {
    state.key = null; state.vault = null; state.passphrase = '';
    state.smsDraft = null; state.csvDraft = null;
    state.intelUndo = null; state.pending2fa = null; state.twoFaSetup = null;
    hideSecuring();
    closeBell();
    setLockPill(true);
    showScreen('unlock');
    $('unlock-pin').value = ''; $('unlock-pass').value = '';
    $('unlock-error').textContent = '';
    $('totp-code').value = ''; $('totp-error').textContent = '';
    refreshLockoutNote();
  }

  function setLockPill(locked) {
    var pill = $('lock-pill');
    pill.textContent = locked ? 'Locked' : 'Unlocked';
    pill.classList.toggle('locked', locked);
  }
  function setStep(id, cls, dot) {
    var el = $(id);
    el.className = 'step' + (cls ? ' ' + cls : '');
    var d = el.querySelector('.dot');
    if (d) d.textContent = dot;
  }
  function updateStepper() {
    var has = !!(state.vault && state.vault.accounts.length > 0);
    setStep('step-setup', 'done', '✓');
    setStep('step-add', has ? 'done' : 'active', has ? '✓' : '2');
    setStep('step-done', has ? 'active' : '', '3');
  }
  function markStepperDone() {
    setStep('step-setup', 'done', '✓');
    setStep('step-add', 'done', '✓');
    setStep('step-done', 'done', '✓');
  }
  // Reel "Securing your payment" -> "You're all set": the panels blur out
  // behind the overlay, the card floats centre with a shimmer + a thin green
  // progress line, then the card turns green.
  var securingTimers = [];
  function hideSecuring() {
    securingTimers.forEach(clearTimeout);
    securingTimers = [];
    hide($('securing-overlay'));
  }
  function showSecuring(account, doneLabel) {
    var overlay = $('securing-overlay');
    var visual = account || { provider: 'Custom', type: 'wallet', nickname: 'Your vault', last4: '', balance: 0 };
    $('securing-card-slot').innerHTML = Cards.buildCardVisual(visual, { hideBalances: false, selected: true });
    var cardEl = $('securing-card-slot').querySelector('.card-visual');
    if (cardEl) cardEl.classList.add('shimmer');
    $('securing-title').textContent = 'Securing your payment';
    $('securing-sub').textContent = 'Processing Secure Transaction… · Encrypting card details…';
    overlay.classList.remove('done');
    $('securing-progress').style.width = '0';
    show(overlay);
    requestAnimationFrame(function () { $('securing-progress').style.width = '100%'; });
    securingTimers.push(setTimeout(function () {
      if (cardEl) { cardEl.classList.remove('shimmer'); cardEl.classList.add('success'); }
      $('securing-title').textContent = "You're all set";
      $('securing-sub').textContent = doneLabel || 'Saved securely!';
      overlay.classList.add('done');
      markStepperDone();
      var pill = $('lock-pill');
      pill.textContent = '✓ Saved';
      pill.classList.remove('locked');
    }, 1400));
    securingTimers.push(setTimeout(function () {
      hideSecuring();
      if (state.key) { setLockPill(false); updateStepper(); }
    }, 2400));
  }

  function render() {
    if (!state.vault) return;
    var v = state.vault;
    // Totals add ONLY known balances (Phase 3.5) — VaultModel.totals()
    // skips unknown balances and counts them, never as 0.
    var tot = VaultModel.totals(v);
    $('total-balance').textContent = (v.accounts.length > 0 && tot.unknownCount === v.accounts.length)
      ? 'Balance not set yet' : maskBal(tot.total);
    $('total-unknown').textContent = tot.unknownCount > 0
      ? ' · ' + tot.unknownCount + (tot.unknownCount === 1 ? ' balance' : ' balances') + ' not set yet' : '';
    // Card carousel (reel card visual, per-provider gradient). Each card
    // sits in a slot with its own compact action row (Phase 3.2).
    var list = $('accounts-list');
    if (!v.accounts.some(function (a) { return a.id === state.selectedAccountId; })) {
      state.selectedAccountId = v.accounts.length ? v.accounts[0].id : null;
    }
    list.innerHTML = v.accounts.map(function (a, i) {
      return '<div class="card-slot">' + Cards.buildCardVisual(a, { hideBalances: state.hideBalances, selected: a.id === state.selectedAccountId })
        + cardActionsHtml(a, i, v.accounts.length) + '</div>';
    }).join('');
    list.querySelectorAll('.card-visual').forEach(function (el) {
      el.addEventListener('click', function () { state.selectedAccountId = el.getAttribute('data-id'); render(); });
    });
    $('accounts-empty').classList.toggle('hidden', v.accounts.length > 0);
    // Summary panel (reel "Order summary"): one row per account + total.
    var sl = $('summary-list');
    sl.innerHTML = v.accounts.map(function (a, i) {
      return '<div class="sum-row"><span class="mark ' + Cards.providerClass(a.provider) + '">'
        + esc(a.provider.slice(0, 2).toUpperCase()) + '</span><span class="nm">' + esc(a.nickname)
        + '<span class="sub">' + esc(a.provider) + ' · ' + esc(a.type) + ' •••• ' + esc(a.last4) + '</span></span>'
        + '<span class="amt">' + esc(maskBal(a.balance)) + '</span>' + Cards.confirmationBadge(a)
        + sumActionsHtml(a, i, v.accounts.length) + '</div>';
    }).join('');
    $('summary-total').textContent = (v.accounts.length > 0 && tot.unknownCount === v.accounts.length)
      ? 'Balance not set yet' : maskBal(tot.total);
    $('summary-unknown').textContent = tot.unknownCount > 0
      ? 'Total across ' + v.accounts.length + (v.accounts.length === 1 ? ' account' : ' accounts')
        + ' · ' + tot.unknownCount + (tot.unknownCount === 1 ? ' balance' : ' balances') + ' not set yet' : '';
    $('summary-empty').classList.toggle('hidden', v.accounts.length > 0);
    // Edit panel (Phase 3.2): visible only while editing one card.
    $('edit-account-card').classList.toggle('hidden', !state.editingAccountId);
    $('hide-btn').classList.toggle('on', state.hideBalances);
    updateStepper();
    refreshSecuritySettings();
    var tx = $('txns-list');
    tx.innerHTML = '';
    $('txns-empty').classList.toggle('hidden', v.transactions.length > 0);
    v.transactions.slice().reverse().slice(0, 50).forEach(function (t) {
      var div = document.createElement('div');
      div.className = 'txn';
      div.innerHTML = '<span class="amt">' + (t.direction === 'debit' ? '−' : '+') + ' ' + esc(maskBal(t.amount)) + '</span> · ' +
        esc(t.merchant || '—') + ' <span class="muted">(' + esc(t.date) + ' · ' + esc(t.source) + ' · ' + esc(t.status) + ')</span>';
      tx.appendChild(div);
    });
    // Notifications live behind the bell, not on a page.
    renderBell();
    renderProfileHeader();
    // Monthly check (Phase 4): banner + done line + the reconcile view.
    renderReconcile();
  }

  function renderReconcile() {
    var v = state.vault;
    if (!v) return;
    var due = VaultModel.monthlyCheckDue(v);
    $('monthly-banner').classList.toggle('hidden', !due);
    $('monthly-done-line').classList.toggle('hidden', due);
    if (!due) {
      $('monthly-done-date').textContent = v.lastReconcileAt || '';
      var skipped = Number(v.lastReconcileSkipped) || 0;
      $('monthly-done-skipped').textContent = skipped > 0
        ? ' — ' + skipped + (skipped === 1 ? ' account' : ' accounts') + ' skipped' : '';
    }
    var list = $('reconcile-list');
    $('reconcile-empty').classList.toggle('hidden', v.accounts.length > 0);
    list.innerHTML = v.accounts.map(function (a) {
      var ready = VaultModel.accountCheckReady(a);
      var skipped = !!state.reconcileSkipped[a.id];
      var last = VaultModel.lastConfirmedAt(a);
      var status = ready ? '<span class="pill green">Checked</span>'
        : skipped ? '<span class="pill">Skipped</span>'
        : '<span class="pill amber">Needs re-check</span>';
      return '<div class="rec-row"><span class="nm">' + esc(a.nickname)
        + '<span class="sub">' + esc(a.provider) + ' · ' + esc(a.type) + ' •••• ' + esc(a.last4)
        + ' · last confirmed: ' + esc(last || 'never') + '</span></span>'
        + '<span class="amt">' + esc(maskBal(a.balance)) + '</span>' + Cards.confirmationBadge(a) + status
        + '<span class="rec-actions">'
        + '<a href="#/intelligence">Re-check by SMS</a>'
        + '<label class="rec-upload">Upload statement<input type="file" accept=".pdf,image/*" data-proof-account="' + esc(a.id) + '" class="file-input-hidden"></label>'
        + (ready ? '' : '<button data-rec-skip="' + esc(a.id) + '">' + (skipped ? 'Unskip' : 'Skip') + '</button>')
        + '</span></div>';
    }).join('');
    var st = VaultModel.monthlyCheckStatus(v, state.reconcileSkipped);
    $('reconcile-summary').textContent = v.accounts.length === 0 ? ''
      : st.ready
        ? (st.skippedCount > 0 ? 'All accounts checked — ' + st.skippedCount + (st.skippedCount === 1 ? ' account' : ' accounts') + ' skipped.' : 'All accounts checked.')
        : st.pending.length + (st.pending.length === 1 ? ' account' : ' accounts') + ' still need' + (st.pending.length === 1 ? 's' : '') + ' a re-check or a skip.';
    $('reconcile-done-btn').disabled = !st.ready;
  }

  // Re-check one account by uploading its statement (Phase 4). This reuses
  // the Phase 3.3 proof flow (same validation, same match check) — it does
  // not rebuild it. A screenshot is kept as a record only: it cannot count
  // as a re-check, because the app cannot read its text.
  async function onReconcileProof(file, accountId) {
    var a = VaultModel.findAccount(state.vault, accountId);
    var err = $('reconcile-error');
    var ok = $('reconcile-ok');
    err.textContent = ''; ok.textContent = '';
    if (!file || !a) return;
    var dataUrl;
    try { dataUrl = await readFileAsDataUrl(file); }
    catch (e) { err.textContent = e.message; return; }
    var checked = Proof.validateProofData(dataUrl, file.size);
    if (!checked.ok) { err.textContent = checked.errors.join(' '); return; }
    var profileName = (state.vault.profile && state.vault.profile.displayName) || '';
    if (checked.kind === 'image') {
      VaultModel.attachProof(state.vault, accountId, {
        kind: 'image', name: file.name, mime: file.type || 'image/jpeg', dataUrl: dataUrl, status: 'attached', at: new Date().toISOString(),
      });
      await persist();
      render();
      ok.textContent = 'Screenshot saved as your record — it does not count as a re-check. Paste a bank SMS or upload the matching PDF statement.';
      return;
    }
    var text = await Proof.extractPdfText(Proof.dataUrlToBytes(dataUrl));
    var result = Proof.checkProofMatch('pdf', text, a, profileName);
    if (result === 'mismatch') {
      var missing = Proof.missingProofTerms('pdf', text, a, profileName);
      err.textContent = 'This statement doesn\'t mention ' + missing.join(', ') + ' — check you uploaded the right statement.';
      return;
    }
    VaultModel.attachProof(state.vault, accountId, {
      kind: 'pdf', name: file.name, mime: 'application/pdf', dataUrl: dataUrl,
      status: result === 'match' ? 'match' : 'attached', at: new Date().toISOString(),
    });
    // Baseline from the bank (Phase 3.5): a PDF with exactly ONE clear
    // balance sets it now. An image, a PDF with no clear balance, or
    // several balances sets nothing. (A mismatched statement never reaches
    // here — it returns above.)
    var baselineNote = '';
    if (text) {
      var found = Proof.extractStatementBalance(text);
      if (found.status === 'one') {
        VaultModel.setBaselineFromBank(state.vault, accountId, found.amount, 'statement');
        baselineNote = ' Balance read from your statement: ' + fmtRs(found.amount) + '.';
      }
    }
    await persist();
    render();
    ok.textContent = (result === 'match'
      ? '✓ Statement matches — this card is checked.'
      : 'Statement attached — couldn\'t read the text, kept as your record. It does not count as a re-check.') + baselineNote;
  }
  function toggleReconcileSkip(accountId) {
    if (state.reconcileSkipped[accountId]) delete state.reconcileSkipped[accountId];
    else state.reconcileSkipped[accountId] = true;
    render();
  }
  async function markMonthlyCheckDoneClick() {
    var err = $('reconcile-error');
    var ok = $('reconcile-ok');
    err.textContent = ''; ok.textContent = '';
    var st = VaultModel.monthlyCheckStatus(state.vault, state.reconcileSkipped);
    if (!st.ready) { err.textContent = 'Some accounts still need a re-check or a skip first.'; return; }
    VaultModel.markMonthlyCheckDone(state.vault, st.skippedCount);
    state.reconcileSkipped = {};
    await persist();
    render();
    ok.textContent = 'Monthly check done' + (st.skippedCount > 0
      ? ' — ' + st.skippedCount + ' account' + (st.skippedCount === 1 ? '' : 's') + ' skipped.' : ' — all accounts checked.');
  }

  // ---- Phase 3: one page per job (hash routing) ----
  function currentRoute() { return Nav.routeForHash(location.hash); }
  function showPage(name) {
    if (Nav.PAGES.indexOf(name) < 0) name = 'wallet';
    state.currentPage = name;
    document.querySelectorAll('.page').forEach(function (el) {
      el.classList.toggle('hidden', el.id !== 'page-' + name);
    });
    document.querySelectorAll('.nav-btn[data-page]').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-page') === name);
    });
    closeBell();
    if (name === 'profile') fillProfileForm();
  }
  function closeBell() { hide($('notif-panel')); }
  // Notifications live behind the bell, not on a page. The badge shows the
  // unread count; opening the bell marks everything read and clears it.
  function renderBell() {
    if (!state.vault) return;
    var unread = VaultModel.unreadNotificationCount(state.vault);
    var badge = $('bell-badge');
    badge.textContent = String(unread);
    badge.classList.toggle('hidden', unread === 0);
    var list = $('bell-list');
    list.innerHTML = '';
    $('bell-empty').classList.toggle('hidden', state.vault.notifications.length > 0);
    state.vault.notifications.slice().reverse().slice(0, 50).forEach(function (n) {
      var div = document.createElement('div');
      div.className = 'notif';
      div.innerHTML = '<span class="pill ' + (n.kind === 'low-balance' ? 'amber' : 'green') + '">' + esc(n.kind) + '</span> ' +
        esc(n.text) + ' <span class="muted">(' + esc(String(n.at || '').slice(0, 16).replace('T', ' ')) + ')</span>';
      list.appendChild(div);
    });
  }
  async function toggleBell() {
    var panel = $('notif-panel');
    if (panel.classList.contains('hidden')) {
      renderBell();
      show(panel);
      if (state.vault && VaultModel.markAllNotificationsRead(state.vault) > 0) {
        await persist();
        renderBell();
      }
    } else {
      closeBell();
    }
  }
  function renderProfileHeader() {
    if (!state.vault) return;
    var p = state.vault.profile || { displayName: '', dp: null };
    var name = (p.displayName || '').trim() || 'My Vault';
    var initial = name.charAt(0).toUpperCase() || 'V';
    $('sidebar-name').textContent = name;
    $('topbar-name').textContent = name;
    [['sidebar-dp', 'sidebar-dp-initials'], ['topbar-dp', 'topbar-dp-initials']].forEach(function (pair) {
      var img = $(pair[0]), ini = $(pair[1]);
      ini.textContent = initial;
      if (p.dp) { img.src = p.dp; show(img); hide(ini); }
      else { hide(img); show(ini); }
    });
  }
  function fillProfileForm() {
    if (!state.vault) return;
    var p = state.vault.profile || { displayName: '', phone: '', email: '', dp: null };
    $('profile-name').value = p.displayName || '';
    $('profile-phone').value = p.phone || '';
    $('profile-email').value = p.email || '';
    state.profileDpDataUrl = null;
    var prev = $('profile-dp-preview'), ini = $('profile-dp-initials');
    var name = (p.displayName || '').trim() || 'My Vault';
    ini.textContent = name.charAt(0).toUpperCase() || 'V';
    if (p.dp) { prev.src = p.dp; show(prev); hide(ini); }
    else { hide(prev); show(ini); }
    $('profile-error').textContent = '';
    $('profile-ok').textContent = '';
  }
  // Shrink a chosen photo to max 256px JPEG (quality steps down until it fits
  // the 100 KB cap). The pure dimension math lives in model.js (dpTargetSize).
  function downscaleDp(file) {
    return new Promise(function (resolve, reject) {
      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = function () {
        URL.revokeObjectURL(url);
        var t = VaultModel.dpTargetSize(img.naturalWidth, img.naturalHeight);
        var canvas = document.createElement('canvas');
        canvas.width = t.width; canvas.height = t.height;
        var ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, t.width, t.height);
        var qualities = [0.8, 0.6, 0.4];
        for (var i = 0; i < qualities.length; i++) {
          var dataUrl = canvas.toDataURL('image/jpeg', qualities[i]);
          if (VaultModel.dpByteLength(dataUrl) <= VaultModel.MAX_DP_BYTES) { resolve(dataUrl); return; }
        }
        reject(new Error('That photo is too large even after shrinking — try a smaller one.'));
      };
      img.onerror = function () { URL.revokeObjectURL(url); reject(new Error('That file is not a photo I can read.')); };
      img.src = url;
    });
  }
  async function onProfileDpFile() {
    var file = $('profile-dp-input').files && $('profile-dp-input').files[0];
    var err = $('profile-error');
    err.textContent = '';
    if (!file) return;
    if (!file.type || file.type.indexOf('image/') !== 0) { err.textContent = 'Pick an image file.'; return; }
    try {
      state.profileDpDataUrl = await downscaleDp(file);
      var prev = $('profile-dp-preview'), ini = $('profile-dp-initials');
      prev.src = state.profileDpDataUrl;
      show(prev); hide(ini);
      $('profile-ok').textContent = 'Photo ready — tap Save profile to keep it.';
    } catch (e) {
      err.textContent = e.message;
      state.profileDpDataUrl = null;
    }
  }
  async function saveProfile() {
    var err = $('profile-error'), ok = $('profile-ok');
    err.textContent = ''; ok.textContent = '';
    var input = {
      displayName: $('profile-name').value,
      phone: $('profile-phone').value,
      email: $('profile-email').value,
    };
    if (state.profileDpDataUrl) input.dp = state.profileDpDataUrl;
    try {
      VaultModel.setProfile(state.vault, input);
      state.profileDpDataUrl = null;
      await persist();
      render();
      ok.textContent = 'Profile saved.';
    } catch (e) {
      err.textContent = (e.errors && e.errors.length) ? e.errors.join(' ') : e.message;
    }
  }

  // Enter the vault after the PIN (and, when on, the 2FA code) has passed.
  function enterVault(doneLabel) {
    state.lastActive = Date.now();
    setLockPill(false);
    showScreen('vault');
    showPage(currentRoute());
    render();
    showSecuring(state.vault.accounts[0] || null, doneLabel || 'Vault unlocked — welcome back.');
  }

  // ---- Step 1: setup / unlock ----
  async function setup() {
    var pin = $('setup-pin').value.trim();
    var pin2 = $('setup-pin2').value.trim();
    var pass = $('setup-pass').value;
    var err = $('setup-error');
    err.textContent = '';
    if (!VaultCrypto.validPin(pin)) { err.textContent = 'PIN must be exactly 6 digits.'; return; }
    if (pin !== pin2) { err.textContent = 'The two PINs do not match.'; return; }
    if (!VaultCrypto.validPassphrase(pass)) { err.textContent = 'Passphrase must be empty or at least 4 characters.'; return; }
    $('setup-btn').disabled = true;
    try {
      var made = await VaultCrypto.createVault(pin, pass, emptyVault());
      saveEnvelope(made.envelope);
      state.key = made.key;
      state.vault = emptyVault();
      state.passphrase = pass;
      state.lockout = VaultCrypto.recordSuccess();
      saveLockout();
      enterVault('Vault created — you\'re all set.');
    } catch (e) {
      err.textContent = 'Could not create the vault: ' + e.message;
    } finally {
      $('setup-btn').disabled = false;
    }
  }

  async function unlock() {
    var pin = $('unlock-pin').value.trim();
    var pass = $('unlock-pass').value;
    var err = $('unlock-error');
    err.textContent = '';
    refreshLockoutNote();
    if (VaultCrypto.isLocked(state.lockout, Date.now())) return;
    if (!VaultCrypto.validPin(pin)) { err.textContent = 'PIN must be exactly 6 digits.'; return; }
    $('unlock-btn').disabled = true;
    try {
      var out = await VaultCrypto.unlockVault(pin, pass, state.envelope);
      // Phase 1/2 vaults have no profile key — migrate so they load fine.
      out.vault = VaultModel.migrateVault(out.vault);
      state.lockout = VaultCrypto.recordSuccess();
      saveLockout();
      // Second factor: if 2FA is on, the PIN alone only unlocks the vault
      // into a pending slot — the vault screen stays hidden until the
      // authenticator (or backup) code passes.
      if (out.vault.settings && out.vault.settings.twoFactor && out.vault.settings.twoFactor.enabled) {
        state.pending2fa = { key: out.key, vault: out.vault, passphrase: pass };
        state.key = null; state.vault = null; state.passphrase = '';
        $('totp-code').value = ''; $('totp-error').textContent = '';
        showScreen('totp');
        $('totp-code').focus();
        return;
      }
      state.key = out.key;
      state.vault = out.vault;
      state.passphrase = pass;
      enterVault();
    } catch (e) {
      state.lockout = VaultCrypto.recordFailure(state.lockout, Date.now());
      saveLockout();
      err.textContent = e.code === 'DECRYPT_FAILED'
        ? 'Wrong PIN or passphrase — the vault could not be opened.'
        : 'The vault could not be opened: ' + e.message;
      refreshLockoutNote();
    } finally {
      $('unlock-btn').disabled = false;
    }
  }

  // ---- Two-factor: verify the authenticator (or backup) code ----
  async function totpSubmit() {
    var err = $('totp-error');
    var pending = state.pending2fa;
    if (!pending) { err.textContent = 'Start again with your PIN.'; showScreen('unlock'); return; }
    var code = $('totp-code').value.trim();
    var secret = pending.vault.settings.twoFactor.secret;
    var ok = await Totp.verifyTotp(secret, code);
    if (!ok) {
      // A backup code works in place of the authenticator code (PIN still
      // required — it already passed). A used code is burned.
      var checked = await Totp.checkBackupCode(code, loadBackupHashes());
      if (checked.ok) {
        saveBackupHashes(checked.remaining);
        ok = true;
      }
    }
    if (!ok) {
      state.lockout = VaultCrypto.recordFailure(state.lockout, Date.now());
      saveLockout();
      if (VaultCrypto.isLocked(state.lockout, Date.now())) {
        state.pending2fa = null;
        err.textContent = 'Too many wrong codes. ' + lockoutMessage();
        showScreen('unlock');
        refreshLockoutNote();
      } else {
        err.textContent = 'That code doesn\'t match. Check your authenticator app and try again.';
      }
      return;
    }
    state.key = pending.key;
    state.vault = pending.vault;
    state.passphrase = pending.passphrase;
    state.pending2fa = null;
    state.lockout = VaultCrypto.recordSuccess();
    saveLockout();
    enterVault();
  }

  // ---- Security settings ----
  function refreshSecuritySettings() {
    if (!state.vault) return;
    var tf = state.vault.settings.twoFactor;
    var on = !!(tf && tf.enabled);
    $('2fa-status').textContent = on
      ? 'On — unlocking also needs a code from your authenticator app.'
      : 'Off — your vault opens with the PIN only.';
    $('2fa-toggle-btn').textContent = on ? 'Disable two-factor' : 'Enable two-factor';
    hide($('2fa-setup')); hide($('2fa-disable'));
    var mins = state.vault.settings.autoLockMinutes || 5;
    $('autolock-select').value = String(mins);
    $('settings-hide-btn').textContent = state.hideBalances ? 'Show balances' : 'Hide balances';
    $('settings-hide-btn').classList.toggle('on', state.hideBalances);
    var n = loadBackupHashes().length;
    $('backup-count').textContent = n
      ? n + ' backup code' + (n === 1 ? '' : 's') + ' remaining.'
      : 'No backup codes are stored.';
  }
  async function verifyPinForSettings(pin) {
    // Prove the PIN by decrypting the envelope with it (same check as unlock).
    await VaultCrypto.unlockVault(pin, state.passphrase, state.envelope);
    return true;
  }
  function start2faSetup() {
    var secret = Totp.generateSecret();
    state.twoFaSetup = secret;
    $('2fa-secret-text').textContent = secret;
    $('2fa-otpauth-link').href = Totp.otpauthUrl(secret);
    $('2fa-confirm-code').value = '';
    $('2fa-error').textContent = '';
    hide($('2fa-backup-box'));
    show($('2fa-secret-box'));
    show($('2fa-confirm-form'));
    show($('2fa-setup'));
    hide($('2fa-disable'));
  }
  async function confirm2faSetup() {
    var err = $('2fa-error');
    var code = $('2fa-confirm-code').value.trim();
    if (!state.twoFaSetup) { err.textContent = 'Tap "Enable two-factor" again to get a fresh key.'; return; }
    if (!(await Totp.verifyTotp(state.twoFaSetup, code))) {
      err.textContent = 'That code doesn\'t match — check your authenticator app and try again.';
      return;
    }
    VaultModel.enableTwoFactor(state.vault, state.twoFaSetup);
    var codes = await Totp.generateBackupCodes(10);
    saveBackupHashes(codes.hashes);
    await persist();
    state.twoFaSetup = null;
    $('2fa-backup-codes').innerHTML = codes.codes.map(function (c) { return '<div>' + esc(c) + '</div>'; }).join('');
    err.textContent = '';
    refreshSecuritySettings();
    // refreshSecuritySettings() hides the setup panel; re-open it showing
    // only the backup codes (the secret + confirm form are done).
    show($('2fa-setup'));
    hide($('2fa-secret-box'));
    hide($('2fa-confirm-form'));
    show($('2fa-backup-box'));
  }
  async function disable2fa() {
    var err = $('2fa-disable-error');
    var pin = $('2fa-off-pin').value;
    var code = $('2fa-off-code').value.trim();
    try { await verifyPinForSettings(pin); }
    catch (_e) { err.textContent = 'Wrong PIN.'; return; }
    var secret = state.vault.settings.twoFactor && state.vault.settings.twoFactor.secret;
    if (!(await Totp.canDisableTwoFactor(secret, code))) {
      err.textContent = 'That code doesn\'t match — enter the current code from your authenticator app.';
      return;
    }
    VaultModel.disableTwoFactor(state.vault);
    saveBackupHashes([]);
    await persist();
    $('2fa-off-pin').value = ''; $('2fa-off-code').value = '';
    err.textContent = '';
    refreshSecuritySettings();
  }
  async function changePin() {
    var err = $('change-pin-error');
    var ok = $('change-pin-ok');
    err.textContent = ''; ok.textContent = '';
    var oldPin = $('change-pin-old').value;
    var newPin = $('change-pin-new').value;
    var newPin2 = $('change-pin-new2').value;
    if (!VaultCrypto.validPin(newPin)) { err.textContent = 'The new PIN must be exactly 6 digits.'; return; }
    if (newPin !== newPin2) { err.textContent = 'The new PINs don\'t match.'; return; }
    try { await verifyPinForSettings(oldPin); }
    catch (_e) { err.textContent = 'Wrong current PIN.'; return; }
    var made = await VaultCrypto.createVault(newPin, state.passphrase, state.vault);
    saveEnvelope(made.envelope);
    state.key = made.key;
    $('change-pin-old').value = ''; $('change-pin-new').value = ''; $('change-pin-new2').value = '';
    ok.textContent = 'PIN changed. Use the new PIN next time.';
  }
  async function changePassphrase() {
    var err = $('change-pass-error');
    var ok = $('change-pass-ok');
    err.textContent = ''; ok.textContent = '';
    var pin = $('change-pass-old').value;
    var newPass = $('change-pass-new').value;
    if (!VaultCrypto.validPassphrase(newPass)) { err.textContent = 'The passphrase must be empty or at least 4 characters.'; return; }
    try { await verifyPinForSettings(pin); }
    catch (_e) { err.textContent = 'Wrong PIN.'; return; }
    var made = await VaultCrypto.createVault(pin, newPass, state.vault);
    saveEnvelope(made.envelope);
    state.key = made.key;
    state.passphrase = newPass;
    $('change-pass-old').value = ''; $('change-pass-new').value = '';
    ok.textContent = newPass ? 'Passphrase changed.' : 'Passphrase removed.';
  }
  async function regenerateBackupCodes() {
    var err = $('show-codes-error');
    err.textContent = '';
    var pin = $('show-codes-pin').value;
    try { await verifyPinForSettings(pin); }
    catch (_e) { err.textContent = 'Wrong PIN.'; return; }
    var codes = await Totp.generateBackupCodes(10);
    saveBackupHashes(codes.hashes);
    $('show-codes-list').innerHTML = codes.codes.map(function (c) { return '<div>' + esc(c) + '</div>'; }).join('');
    show($('show-codes-box'));
    $('show-codes-pin').value = '';
    refreshSecuritySettings();
  }

  // ---- Step 2: manual add-account ----
  function populateProviders() {
    var sel = $('add-provider');
    sel.innerHTML = '';
    VaultModel.PROVIDERS.forEach(function (p) {
      var o = document.createElement('option');
      o.value = p; o.textContent = p;
      sel.appendChild(o);
    });
  }

  async function addAccount() {
    var err = $('add-account-error');
    var ok = $('add-account-ok');
    err.textContent = ''; ok.textContent = '';
    var input = {
      provider: $('add-provider').value,
      type: $('add-type').value,
      nickname: $('add-nick').value,
      last4: $('add-last4').value.trim(),
      // No balance here (Phase 3.5): a balance is never typed — it is set
      // only by the bank, from a statement (below) or a bank SMS.
      proof: state.addProof || null,
    };
    try {
      var created = VaultModel.createAccount(state.vault, input);
      // Baseline from the bank (Phase 3.5): a statement uploaded with the
      // card may already carry one clear balance — set it from the bank's
      // own document, never from the user's hand.
      var baselineNote = '';
      if (state.addProofBalance) {
        VaultModel.setBaselineFromBank(state.vault, created.id, state.addProofBalance.amount, 'statement');
        baselineNote = ' Balance read from your statement: ' + fmtRs(state.addProofBalance.amount) + '.';
      }
      await persist();
      render();
      ok.textContent = 'Account added: ' + input.nickname + ' (•••• ' + input.last4 + ').' + baselineNote;
      $('add-nick').value = ''; $('add-last4').value = '';
      resetAddProof();
      showSecuring(created, 'Saved securely!');
    } catch (e) {
      err.textContent = (e.errors && e.errors.length ? e.errors.join(' ') : e.message);
    }
  }

  // ---- Phase 3.3: statement proof on the Add Card page (optional) ----
  // The proof is the user's own record, checked only against what they
  // typed (provider + last-4 + profile name). It never proves a card is
  // real — only a real bank SMS does that (Phase 3.1).
  function resetAddProof() {
    state.addProof = null;
    state.addProofBalance = null;
    $('add-proof').value = '';
    $('add-proof-status').textContent = '';
    $('add-proof-error').textContent = '';
    hide($('add-proof-preview'));
  }
  function readFileAsDataUrl(file) {
    return new Promise(function (resolve, reject) {
      var r = new FileReader();
      r.onload = function () { resolve(r.result); };
      r.onerror = function () { reject(new Error('Could not read that file.')); };
      r.readAsDataURL(file);
    });
  }
  async function onProofFile() {
    var err = $('add-proof-error');
    var status = $('add-proof-status');
    err.textContent = ''; status.textContent = ''; hide($('add-proof-preview'));
    state.addProof = null;
    state.addProofBalance = null;
    var file = $('add-proof').files[0];
    if (!file) return;
    var dataUrl;
    try { dataUrl = await readFileAsDataUrl(file); }
    catch (e) { err.textContent = e.message; return; }
    var checked = Proof.validateProofData(dataUrl, file.size);
    if (!checked.ok) { err.textContent = checked.errors.join(' '); return; }
    var provider = $('add-provider').value;
    var last4 = $('add-last4').value.trim();
    var profileName = (state.vault && state.vault.profile && state.vault.profile.displayName) || '';
    if (!last4) {
      status.textContent = 'Type the last 4 digits first — the statement is checked against them.';
      return;
    }
    var record = {
      kind: checked.kind, name: file.name,
      mime: checked.kind === 'pdf' ? 'application/pdf' : (file.type || 'image/jpeg'),
      dataUrl: dataUrl, status: 'attached', at: new Date().toISOString(),
    };
    if (checked.kind === 'image') {
      // No OCR in this app: show the screenshot next to the typed data and
      // let the user confirm by eye. Never an automatic match for an image.
      state.addProof = record;
      $('add-proof-img').src = dataUrl;
      $('add-proof-typed').textContent = 'Provider: ' + provider + ' · Last 4: ' + last4
        + ' · Name: ' + (profileName || 'not set — set it on the Profile page to check it too');
      status.textContent = 'Photo attached — the app can\'t read text from a screenshot, so check it yourself below.';
      show($('add-proof-preview'));
      return;
    }
    var text = await Proof.extractPdfText(Proof.dataUrlToBytes(dataUrl));
    var result = Proof.checkProofMatch('pdf', text, { provider: provider, last4: last4 }, profileName);
    if (result === 'match') {
      record.status = 'match';
      status.textContent = '✓ Statement matches — the PDF mentions ' + provider + ', ••••' + last4
        + (profileName ? ' and ' + profileName : '') + '.';
    } else if (result === 'mismatch') {
      var missing = Proof.missingProofTerms('pdf', text, { provider: provider, last4: last4 }, profileName);
      record.status = 'mismatch';
      status.textContent = 'This statement doesn\'t mention ' + missing.join(', ')
        + ' — check you uploaded the right statement. It is kept only as "doesn\'t match".';
    } else {
      status.textContent = 'Statement attached — couldn\'t read the text, kept as your record.';
    }
    // Balance from the bank (Phase 3.5): a PDF with exactly ONE clear
    // balance sets the baseline when the card is added. No clear balance,
    // or several different ones, sets nothing — the user is told so
    // plainly and can paste a bank SMS instead. Never guessed.
    if (text) {
      var found = Proof.extractStatementBalance(text);
      if (found.status === 'one') {
        state.addProofBalance = { amount: found.amount, label: found.label, match: found.match };
        status.textContent += ' Balance read from your statement: ' + fmtRs(found.amount) + '.';
      } else if (found.status === 'ambiguous') {
        status.textContent += ' The statement has several different balances — no balance was set. Paste a bank SMS instead.';
      } else {
        status.textContent += ' No clear balance found in this statement — paste a bank SMS instead.';
      }
    }
    if (!profileName) status.textContent += ' Set your name on the Profile page to check it against the statement too.';
    state.addProof = record;
  }
  function onProofSelfCheck() {
    // A deliberate tap by the user, never automatic: they checked the
    // screenshot against the typed data with their own eyes.
    if (!state.addProof || state.addProof.kind !== 'image') return;
    state.addProof.status = 'self-checked';
    $('add-proof-status').textContent = '✓ You checked this screenshot yourself — saved as "self-checked".';
    hide($('add-proof-preview'));
  }

  // Remove a statement proof from a saved card (two-tap, like delete).
  function requestProofRemove(accountId) { state.pendingProofRemoveId = accountId; render(); }
  async function confirmProofRemove(accountId) {
    if (state.pendingProofRemoveId !== accountId) return;
    VaultModel.removeProof(state.vault, accountId);
    state.pendingProofRemoveId = null;
    await persist();
    render();
  }
  function cancelProofRemove() { state.pendingProofRemoveId = null; render(); }

  // ---- Phase 3.2: edit / reorder / delete a card ----
  // Per-card action buttons. Delete is two-tap: the first tap only arms
  // (pendingDeleteId), the confirm row says plainly that the card's
  // transactions go too, and only the second tap deletes. One tap can
  // never delete a card.
  function cardActionsHtml(a, i, n) {
    if (state.pendingDeleteId === a.id) {
      return '<div class="card-actions"><span class="confirm-note">Remove this card? This also removes its transactions.</span>'
        + '<button data-action="confirm-remove" data-id="' + esc(a.id) + '" class="danger">Yes, remove</button>'
        + '<button data-action="cancel-remove" data-id="' + esc(a.id) + '" class="secondary">Cancel</button></div>';
    }
    return '<div class="card-actions">'
      + '<button data-action="edit" data-id="' + esc(a.id) + '">Edit</button>'
      + '<button data-action="move-up" data-id="' + esc(a.id) + '"' + (i === 0 ? ' disabled' : '') + '>↑</button>'
      + '<button data-action="move-down" data-id="' + esc(a.id) + '"' + (i === n - 1 ? ' disabled' : '') + '>↓</button>'
      + '<button data-action="remove" data-id="' + esc(a.id) + '" class="danger">Remove</button>'
      + proofActionsHtml(a) + '</div>';
  }
  // Statement proof on a saved card (Phase 3.3): a link to view the stored
  // file, and a two-tap remove (like delete — never one tap).
  function proofActionsHtml(a) {
    if (!a.proof) return '';
    if (state.pendingProofRemoveId === a.id) {
      return '<span class="confirm-note">Remove this proof?</span>'
        + '<button data-action="confirm-remove-proof" data-id="' + esc(a.id) + '" class="danger">Yes, remove proof</button>'
        + '<button data-action="cancel-remove-proof" data-id="' + esc(a.id) + '" class="secondary">Cancel</button>';
    }
    return '<a class="proof-link" href="' + esc(a.proof.dataUrl) + '" target="_blank" download="' + esc(a.proof.name || 'statement') + '">View proof</a>'
      + '<button data-action="remove-proof" data-id="' + esc(a.id) + '">Remove proof</button>';
  }
  function sumActionsHtml(a, i, n) {
    if (state.pendingDeleteId === a.id) {
      return '<span class="sum-actions"><button data-action="confirm-remove" data-id="' + esc(a.id) + '" class="danger">Yes, remove</button>'
        + '<button data-action="cancel-remove" data-id="' + esc(a.id) + '" class="secondary">Cancel</button></span>';
    }
    return '<span class="sum-actions">'
      + '<button data-action="edit" data-id="' + esc(a.id) + '">Edit</button>'
      + '<button data-action="move-up" data-id="' + esc(a.id) + '"' + (i === 0 ? ' disabled' : '') + '>↑</button>'
      + '<button data-action="move-down" data-id="' + esc(a.id) + '"' + (i === n - 1 ? ' disabled' : '') + '>↓</button>'
      + '<button data-action="remove" data-id="' + esc(a.id) + '" class="danger">Remove</button></span>';
  }
  function openEdit(accountId) {
    var a = VaultModel.findAccount(state.vault, accountId);
    if (!a) return;
    state.editingAccountId = accountId;
    state.pendingDeleteId = null;
    $('edit-provider').value = a.provider;
    $('edit-last4').value = a.last4;
    $('edit-nick').value = a.nickname;
    $('edit-account-error').textContent = '';
    $('edit-account-ok').textContent = '';
    show($('edit-account-card'));
    $('edit-account-card').scrollIntoView({ block: 'nearest' });
  }
  async function saveEdit() {
    var err = $('edit-account-error');
    err.textContent = '';
    var id = state.editingAccountId;
    if (!id) return;
    try {
      // Rename only (Hashir's rule): a hand may change the nickname — never
      // the balance or the type. Those change only when the bank says so.
      var updated = VaultModel.renameAccount(state.vault, id, $('edit-nick').value);
      await persist();
      state.editingAccountId = null;
      render();
      showSecuring(updated, 'Saved!');
    } catch (e) {
      err.textContent = (e.errors && e.errors.length ? e.errors.join(' ') : e.message);
    }
  }
  function cancelEdit() {
    state.editingAccountId = null;
    render();
  }
  async function moveCard(accountId, direction) {
    if (!state.vault) return;
    try {
      if (VaultModel.moveAccount(state.vault, accountId, direction)) { await persist(); render(); }
    } catch (e) { /* unknown id — nothing to move */ }
  }
  function requestDelete(accountId) {
    state.pendingDeleteId = accountId;
    state.editingAccountId = null;
    render();
  }
  async function confirmDelete(accountId) {
    if (state.pendingDeleteId !== accountId) return;
    VaultModel.deleteAccount(state.vault, accountId);
    state.pendingDeleteId = null;
    if (state.editingAccountId === accountId) state.editingAccountId = null;
    if (state.selectedAccountId === accountId) state.selectedAccountId = null;
    await persist();
    render();
  }
  function cancelDelete() {
    state.pendingDeleteId = null;
    render();
  }

  function accountOptions(sel, preselectId) {
    sel.innerHTML = '';
    state.vault.accounts.forEach(function (a) {
      var o = document.createElement('option');
      o.value = a.id;
      // Unknown balance (Phase 3.5): say so — never "Rs 0" for a number
      // the bank never stated.
      var balText = (a.balance === null || a.balance === undefined) ? 'balance not set yet' : fmtRs(a.balance);
      o.textContent = a.nickname + ' — ' + a.provider + ' •••• ' + a.last4 + ' (' + balText + ')';
      if (a.id === preselectId) o.selected = true;
      sel.appendChild(o);
    });
  }

  // ---- Step 3: Intelligence — paste a bank SMS, the wallet updates itself ----
  async function parseSmsClick() {
    var err = $('sms-error');
    var box = $('sms-review');
    var res = $('intel-result');
    err.textContent = ''; box.innerHTML = ''; res.innerHTML = ''; hide(res);
    state.smsDraft = null; state.intelUndo = null;
    var draft = SmsParser.parseSms($('sms-text').value);
    if (!draft) {
      err.textContent = "Couldn't read this message — paste the full SMS your bank or wallet sent. OTPs are never read.";
      return;
    }
    if (!state.vault.accounts.length) {
      err.textContent = 'Add an account first, then paste an SMS for it.';
      return;
    }
    // Intelligence: an exact (provider + last-4) match updates directly —
    // no amount entry, no account picking.
    var match = Intel.findIntelMatch(state.vault.accounts, draft.provider, draft.last4);
    if (match.status === 'match') {
      try {
        var out = Intel.applyIntelUpdate(state.vault, draft, match.account);
        await persist();
        render();
        var text = Intel.intelResultText(match.account, draft, out.prevBalance, out.newBalance, out.baselineSet);
        res.innerHTML = '<div class="big">' + esc(text.line) + '</div>'
          + (text.cross ? '<div class="cross">' + esc(text.cross) + '</div>' : '')
          + '<button id="intel-undo-btn" class="secondary">Undo this update</button>';
        show(res);
        state.intelUndo = { txnId: out.txn.id, notifId: out.notifId };
        $('intel-undo-btn').addEventListener('click', undoIntel);
        $('sms-text').value = '';
        showSecuring(match.account, 'Saved securely!');
      } catch (e) {
        err.textContent = e.message;
      }
      return;
    }
    // No match (or several match) -> the review card with the account picker.
    // Nothing is saved until approved.
    state.smsDraft = draft;
    // Pre-select the matching account: same provider + last 4, else same provider.
    var match = null;
    if (draft.last4) match = state.vault.accounts.find(function (a) { return a.provider === draft.provider && a.last4 === draft.last4; });
    if (!match) match = state.vault.accounts.find(function (a) { return a.provider === draft.provider; });
    var div = document.createElement('div');
    div.className = 'review';
    div.innerHTML = '<h3>Review — nothing is saved yet</h3>' +
      '<div>Provider: <strong>' + esc(draft.provider) + '</strong></div>' +
      '<div>Amount: <strong>' + (draft.direction === 'debit' ? '−' : '+') + ' ' + esc(fmtRs(draft.amount)) + '</strong> (' + esc(draft.direction) + ')</div>' +
      '<div>Merchant: <strong>' + esc(draft.merchant || '— not in the SMS') + '</strong></div>' +
      '<div>Date: <strong>' + esc(draft.date) + '</strong>' + (draft.dateGuessed ? ' <span class="muted">(no date in the SMS — today assumed)</span>' : '') + '</div>' +
      (draft.availableBalance != null ? '<div>Bank says available balance: <strong>' + esc(fmtRs(draft.availableBalance)) + '</strong></div>' : '') +
      '<label for="sms-account">Apply to account</label><select id="sms-account"></select>' +
      '<div id="sms-balance-note" class="muted"></div>' +
      '<div class="row"><button id="sms-approve-btn">Approve — save + update balance</button>' +
      '<button id="sms-discard-btn" class="secondary">Discard</button></div>';
    box.appendChild(div);
    var sel = $('sms-account');
    accountOptions(sel, match ? match.id : null);
    var note = $('sms-balance-note');
    var updateNote = function () {
      var a = state.vault.accounts.find(function (x) { return x.id === sel.value; });
      if (!a) { note.textContent = ''; return; }
      // Unknown balance (Phase 3.5): approving records the transaction;
      // the balance stays unknown unless this SMS states an available
      // balance — never show a computed number from nothing.
      if (a.balance === null || a.balance === undefined) {
        note.textContent = 'After approval, ' + a.nickname + ' records this transaction. Its balance is not set yet — it stays unknown'
          + (draft.availableBalance != null
            ? ' unless the bank\'s available balance (' + fmtRs(draft.availableBalance) + ') sets it.' : ' unless this SMS states an available balance.')
          + ' Paste another SMS or upload a statement to set it.';
        return;
      }
      var after = draft.direction === 'debit' ? a.balance - draft.amount : a.balance + draft.amount;
      note.textContent = 'After approval, ' + a.nickname + ' will show ' + fmtRs(after)
        + (draft.availableBalance != null && draft.availableBalance !== after
          ? ' (bank says ' + fmtRs(draft.availableBalance) + ' — small differences happen when other transactions are not in the vault yet).' : '.');
    };
    sel.addEventListener('change', updateNote);
    updateNote();
    $('sms-approve-btn').addEventListener('click', approveSms);
    $('sms-discard-btn').addEventListener('click', function () { box.innerHTML = ''; $('sms-text').value = ''; state.smsDraft = null; });
  }

  async function approveSms() {
    var draft = state.smsDraft;
    var accountId = $('sms-account').value;
    if (!draft || !accountId) return;
    try {
      var txn = VaultModel.addTransaction(state.vault, {
        accountId, amount: draft.amount, direction: draft.direction,
        merchant: draft.merchant, date: draft.date, source: 'sms',
      });
      VaultModel.approveTransaction(state.vault, txn.id);
      // Baseline from the bank (Phase 3.5): the review path never
      // bank-confirms (only the direct match does), but if the balance was
      // unknown and this SMS states an available balance, that number IS
      // the balance now.
      var account = VaultModel.findAccount(state.vault, accountId);
      var baselineSet = false;
      if (account && (account.balance === null || account.balance === undefined) && draft.availableBalance != null) {
        VaultModel.setBaselineFromBank(state.vault, accountId, draft.availableBalance, 'sms');
        baselineSet = true;
      }
      await persist();
      $('sms-review').innerHTML = '';
      $('sms-text').value = '';
      state.smsDraft = null;
      if (baselineSet) {
        var res = $('intel-result');
        res.innerHTML = '<div class="ok">Balance set from this SMS: ' + esc(fmtRs(account.balance)) + '.</div>';
        show(res);
      }
      render();
    } catch (e) {
      $('sms-error').textContent = e.message;
    }
  }

  async function undoIntel() {
    if (!state.intelUndo) return;
    var out = Intel.undoIntelUpdate(state.vault, state.intelUndo.txnId, state.intelUndo.notifId);
    state.intelUndo = null;
    await persist();
    render();
    var res = $('intel-result');
    res.innerHTML = '<div class="big">Undone — balance ' + (out.balance === null || out.balance === undefined
      ? 'still not set.' : 'back to ' + esc(fmtRs(out.balance)) + '.') + '</div>';
    show(res);
  }

  // ---- Step 3: CSV import ----
  function onCsvFile() {
    var file = $('csv-file').files[0];
    var err = $('csv-error');
    err.textContent = ''; $('csv-review').innerHTML = ''; state.csvDraft = null;
    hide($('csv-mapping'));
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var parsed = CsvImport.parseCsv(String(reader.result || ''));
      if (!parsed.headers.length || !parsed.rows.length) {
        err.textContent = 'That file has no rows I can read. Upload a statement CSV with a header row.';
        return;
      }
      var mapping = CsvImport.guessMapping(parsed.headers);
      state.csvDraft = { parsed, mapping };
      var fill = function (selId, value) {
        var sel = $(selId);
        sel.innerHTML = '';
        parsed.headers.forEach(function (h) {
          var o = document.createElement('option');
          o.value = h; o.textContent = h;
          if (h === value) o.selected = true;
          sel.appendChild(o);
        });
      };
      fill('csv-col-date', mapping.date);
      fill('csv-col-amount', mapping.amount);
      fill('csv-col-merchant', mapping.merchant);
      var dirSel = $('csv-col-direction');
      dirSel.innerHTML = '<option value="">— none (amount sign) —</option>';
      parsed.headers.forEach(function (h) {
        var o = document.createElement('option');
        o.value = h; o.textContent = h;
        if (h === mapping.direction) o.selected = true;
        dirSel.appendChild(o);
      });
      accountOptions($('csv-account'), null);
      show($('csv-mapping'));
    };
    reader.onerror = function () { err.textContent = 'Could not read that file.'; };
    reader.readAsText(file);
  }

  function previewCsv() {
    var draft = state.csvDraft;
    var err = $('csv-error');
    var box = $('csv-review');
    err.textContent = ''; box.innerHTML = '';
    if (!draft) return;
    var mapping = {
      date: $('csv-col-date').value,
      amount: $('csv-col-amount').value,
      merchant: $('csv-col-merchant').value,
      direction: $('csv-col-direction').value,
    };
    var accountId = $('csv-account').value;
    if (!accountId) { err.textContent = 'Pick the account these transactions belong to.'; return; }
    var conv = CsvImport.rowsToTransactions(draft.parsed, mapping, accountId);
    if (conv.errors.length) err.textContent = conv.errors.join(' ');
    if (!conv.drafts.length) { err.textContent += (err.textContent ? ' ' : '') + 'No usable rows.'; return; }
    var marked = CsvImport.markDuplicates(state.vault, conv.drafts);
    state.csvDraft.marked = marked;
    state.csvDraft.accountId = accountId;
    var div = document.createElement('div');
    div.className = 'review';
    var html = '<h3>Review rows — tick the ones to save</h3><table><tr><th></th><th>Date</th><th>Merchant</th><th>Amount</th><th></th></tr>';
    marked.forEach(function (d, i) {
      html += '<tr><td><input type="checkbox" data-i="' + i + '"' + (d.duplicate ? '' : ' checked') + '></td>'
        + '<td>' + esc(d.date) + '</td><td>' + esc(d.merchant || '—') + '</td>'
        + '<td>' + (d.direction === 'debit' ? '−' : '+') + ' ' + esc(fmtRs(d.amount)) + '</td>'
        + '<td>' + (d.duplicate ? '<span class="pill amber">duplicate — skipped</span>' : '') + '</td></tr>';
    });
    html += '</table><button id="csv-approve-btn">Approve selected — save + update balance</button>';
    div.innerHTML = html;
    box.appendChild(div);
    $('csv-approve-btn').addEventListener('click', approveCsv);
  }

  async function approveCsv() {
    var draft = state.csvDraft;
    if (!draft || !draft.marked) return;
    var boxes = document.querySelectorAll('#csv-review input[type="checkbox"]');
    var saved = 0;
    try {
      boxes.forEach(function (box) {
        if (!box.checked) return;
        var d = draft.marked[Number(box.getAttribute('data-i'))];
        if (d.duplicate) return;
        var txn = VaultModel.addTransaction(state.vault, {
          accountId: d.accountId, amount: d.amount, direction: d.direction,
          merchant: d.merchant, date: d.date, source: 'csv',
        });
        VaultModel.approveTransaction(state.vault, txn.id);
        saved++;
      });
      await persist();
      $('csv-review').innerHTML = '';
      $('csv-file').value = '';
      hide($('csv-mapping'));
      state.csvDraft = null;
      $('csv-error').textContent = saved ? '' : 'Nothing was selected.';
      render();
    } catch (e) {
      $('csv-error').textContent = e.message;
    }
  }

  // ---- Step 4: encrypted backup ----
  function exportBackup() {
    var err = $('backup-error');
    var ok = $('backup-ok');
    err.textContent = ''; ok.textContent = '';
    try {
      var backup = VaultCrypto.createBackup(state.envelope);
      var blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'card-vault-backup-' + new Date().toISOString().slice(0, 10) + '.json';
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      ok.textContent = 'Backup downloaded. It can only be restored with your PIN'
        + ' (and passphrase, if you set one). Keep the file somewhere safe.';
    } catch (e) {
      err.textContent = e.message;
    }
  }

  function onImportFile() {
    var file = $('import-file').files[0];
    var err = $('backup-error');
    var ok = $('backup-ok');
    err.textContent = ''; ok.textContent = '';
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var envelope;
      try {
        envelope = VaultCrypto.parseBackup(String(reader.result || ''));
      } catch (e) {
        err.textContent = e.message;
        $('import-file').value = '';
        return;
      }
      var old = document.getElementById('import-prompt');
      if (old) old.remove();
      // Ask for the BACKUP's own PIN — it may differ from this vault's PIN.
      var div = document.createElement('div');
      div.className = 'review';
      div.id = 'import-prompt';
      div.innerHTML = '<h3>Restore this backup?</h3>'
        + '<p class="muted">Restoring <strong>replaces</strong> the vault on this device with the backup. '
        + 'Enter the PIN (and passphrase) that backup was created with.</p>'
        + '<label for="import-pin">Backup PIN (6 digits)</label>'
        + '<input id="import-pin" type="password" inputmode="numeric" maxlength="6" placeholder="••••••">'
        + '<label for="import-pass">Backup passphrase (only if one was set)</label>'
        + '<input id="import-pass" type="password" placeholder="leave empty if none">'
        + '<div class="row"><button id="import-restore-btn">Restore backup</button>'
        + '<button id="import-cancel-btn" class="secondary">Cancel</button></div>';
      $('backup-card').appendChild(div);
      $('import-cancel-btn').addEventListener('click', function () {
        div.remove(); $('import-file').value = '';
      });
      $('import-restore-btn').addEventListener('click', async function () {
        var pin = $('import-pin').value.trim();
        var pass = $('import-pass').value;
        try {
          var out = await VaultCrypto.unlockVault(pin, pass, envelope);
          saveEnvelope(envelope);
          state.key = out.key;
          state.vault = VaultModel.migrateVault(out.vault);
          state.lockout = VaultCrypto.recordSuccess();
          saveLockout();
          div.remove();
          $('import-file').value = '';
          ok.textContent = 'Backup restored. The vault on this device now holds the backup data.';
          render();
        } catch (e) {
          err.textContent = e.code === 'DECRYPT_FAILED'
            ? 'Wrong PIN or passphrase for this backup (or the file is damaged).'
            : e.message;
        }
      });
    };
    reader.onerror = function () { err.textContent = 'Could not read that file.'; };
    reader.readAsText(file);
  }

  function boot() {
    loadStored();
    populateProviders();
    // Phase 3: sidebar navigation (hash routing) + bell + profile.
    document.querySelectorAll('.nav-btn[data-page]').forEach(function (b) {
      b.addEventListener('click', function () { location.hash = '#/' + b.getAttribute('data-page'); });
    });
    window.addEventListener('hashchange', function () { if (state.vault) showPage(currentRoute()); });
    $('bell-btn').addEventListener('click', function (e) { e.stopPropagation(); toggleBell(); });
    $('bell-mark-read').addEventListener('click', async function () {
      if (state.vault && VaultModel.markAllNotificationsRead(state.vault) > 0) { await persist(); renderBell(); }
    });
    document.addEventListener('click', function (e) {
      var panel = $('notif-panel');
      if (!panel.classList.contains('hidden') && !panel.contains(e.target) && !$('bell-btn').contains(e.target)) closeBell();
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeBell(); });
    $('monthly-banner-btn').addEventListener('click', function () { location.hash = '#/reconcile'; });
    $('reconcile-export-btn').addEventListener('click', exportBackup);
    $('reconcile-done-btn').addEventListener('click', markMonthlyCheckDoneClick);
    $('reconcile-list').addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-rec-skip]') : null;
      if (btn) toggleReconcileSkip(btn.getAttribute('data-rec-skip'));
    });
    $('reconcile-list').addEventListener('change', function (e) {
      var input = e.target.closest ? e.target.closest('input[data-proof-account]') : null;
      if (input && input.files && input.files[0]) onReconcileProof(input.files[0], input.getAttribute('data-proof-account'));
    });
    $('wallet-add-btn').addEventListener('click', function () { location.hash = '#/add'; });
    $('profile-dp-input').addEventListener('change', onProfileDpFile);
    $('profile-save-btn').addEventListener('click', saveProfile);
    $('setup-btn').addEventListener('click', setup);
    $('unlock-btn').addEventListener('click', unlock);
    $('totp-btn').addEventListener('click', totpSubmit);
    $('totp-code').addEventListener('keydown', function (e) { if (e.key === 'Enter') totpSubmit(); });
    $('2fa-toggle-btn').addEventListener('click', function () {
      if (state.vault && state.vault.settings.twoFactor && state.vault.settings.twoFactor.enabled) {
        hide($('2fa-setup')); show($('2fa-disable'));
      } else {
        start2faSetup();
      }
    });
    $('2fa-copy-btn').addEventListener('click', function () {
      var key = $('2fa-secret-text').textContent;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(key).then(function () { $('2fa-copy-btn').textContent = 'Copied'; })
          .catch(function () { $('2fa-copy-btn').textContent = 'Copy failed — select the key'; });
      } else { $('2fa-copy-btn').textContent = 'Select the key and copy it'; }
    });
    $('2fa-confirm-btn').addEventListener('click', confirm2faSetup);
    $('2fa-disable-btn').addEventListener('click', disable2fa);
    $('autolock-select').addEventListener('change', async function () {
      try {
        VaultModel.setAutoLockMinutes(state.vault, Number($('autolock-select').value));
        await persist();
      } catch (e) { $('autolock-select').value = String(state.vault.settings.autoLockMinutes || 5); }
    });
    $('settings-hide-btn').addEventListener('click', function () {
      state.hideBalances = !state.hideBalances;
      $('hide-btn').textContent = state.hideBalances ? 'Show balances' : 'Hide balances';
      render();
    });
    $('change-pin-btn').addEventListener('click', changePin);
    $('change-pass-btn').addEventListener('click', changePassphrase);
    $('show-codes-btn').addEventListener('click', regenerateBackupCodes);
    // Phase 3.2: card actions (Edit / ↑ / ↓ / Remove) — one delegated
    // handler on each list, so it survives render() rebuilding the rows.
    function onCardAction(e) {
      var btn = e.target.closest ? e.target.closest('[data-action]') : null;
      if (!btn || btn.disabled) return;
      var id = btn.getAttribute('data-id');
      var action = btn.getAttribute('data-action');
      if (action === 'edit') openEdit(id);
      else if (action === 'move-up') moveCard(id, 'up');
      else if (action === 'move-down') moveCard(id, 'down');
      else if (action === 'remove') requestDelete(id);
      else if (action === 'confirm-remove') confirmDelete(id);
      else if (action === 'cancel-remove') cancelDelete();
      else if (action === 'remove-proof') requestProofRemove(id);
      else if (action === 'confirm-remove-proof') confirmProofRemove(id);
      else if (action === 'cancel-remove-proof') cancelProofRemove();
    }
    $('accounts-list').addEventListener('click', onCardAction);
    $('summary-list').addEventListener('click', onCardAction);
    $('edit-save-btn').addEventListener('click', saveEdit);
    $('edit-cancel-btn').addEventListener('click', cancelEdit);
    $('lock-btn').addEventListener('click', lock);
    $('add-account-btn').addEventListener('click', addAccount);
    $('add-proof').addEventListener('change', onProofFile);
    $('add-proof-selfcheck-btn').addEventListener('click', onProofSelfCheck);
    // If the card details change after a proof was attached, the proof no
    // longer matches what was typed — clear it so it must be re-uploaded.
    ['add-provider', 'add-last4'].forEach(function (id) {
      $(id).addEventListener('change', function () {
        if (state.addProof) {
          state.addProof = null;
          state.addProofBalance = null;
          $('add-proof').value = '';
          $('add-proof-status').textContent = 'Card details changed — upload the statement again.';
          hide($('add-proof-preview'));
        }
      });
    });
    $('sms-parse-btn').addEventListener('click', parseSmsClick);
    $('sms-text').addEventListener('paste', function () { setTimeout(parseSmsClick, 0); });
    $('csv-file').addEventListener('change', onCsvFile);
    $('csv-preview-btn').addEventListener('click', previewCsv);
    $('export-btn').addEventListener('click', exportBackup);
    $('import-file').addEventListener('change', onImportFile);
    $('hide-btn').addEventListener('click', function () {
      state.hideBalances = !state.hideBalances;
      $('hide-btn').textContent = state.hideBalances ? 'Show balances' : 'Hide balances';
      render();
    });
    ['pointerdown', 'keydown'].forEach(function (ev) {
      document.addEventListener(ev, function () { state.lastActive = Date.now(); }, { passive: true });
    });
    setInterval(function () {
      if (state.key && state.vault) {
        var mins = (state.vault.settings && state.vault.settings.autoLockMinutes) || 5;
        if (Date.now() - state.lastActive >= mins * 60 * 1000) lock();
      }
      refreshLockoutNote();
    }, 20000);
    if (!state.envelope) showScreen('setup');
    else showScreen('unlock');
    refreshLockoutNote();
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
