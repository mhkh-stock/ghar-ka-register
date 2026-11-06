// Personal Card Vault — app shell (browser only).
// Phase 2: the reel-exact glass frontend (Code XR "Glassy Payment Checkout
// V2" look) + Intelligence (paste-an-SMS direct update) + two-factor auth.
// The element IDs and flows stay the same as Phase 1.
// Storage: localStorage only. Keys: pcv.vault (encrypted envelope JSON),
// pcv.lockout (failure count + lockoutUntil), pcv.backup (SHA-256 hashes of
// the one-time backup codes — never the codes themselves). The CryptoKey
// lives in memory only and is wiped on lock. The server stores NOTHING.
'use strict';
/* global VaultCrypto, VaultModel, SmsParser, CsvImport, Cards, Intel, Totp */
(function () {
  var LS_VAULT = 'pcv.vault';
  var LS_LOCKOUT = 'pcv.lockout';

  // Cards are revealed as their Phase 1 step lands (1 = crypto, 2 = model,
  // 3 = add-account flows, 4 = backup). Security + connect cards are static
  // information and always visible.
  var STEP_DONE = 4;
  var STEP_CARDS = {
    2: ['accounts-card'],
    3: ['add-account-card', 'sms-card', 'csv-card', 'txns-card', 'notifs-card'],
    4: ['backup-card'],
  };

  var state = {
    key: null, envelope: null, vault: null, passphrase: '',
    lockout: VaultCrypto.createLockoutState(),
    lastActive: Date.now(), hideBalances: false,
    smsDraft: null, csvDraft: null,
    selectedAccountId: null, intelUndo: null,
    pending2fa: null, twoFaSetup: null,
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
  function maskBal(n) { return state.hideBalances ? 'Rs ••••' : fmtRs(n); }

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
    hide($('setup-screen')); hide($('unlock-screen')); hide($('vault-screen'));
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
    var total = 0;
    v.accounts.forEach(function (a) { total += Number(a.balance) || 0; });
    $('total-balance').textContent = maskBal(total);
    // Card carousel (reel card visual, per-provider gradient).
    var list = $('accounts-list');
    if (!v.accounts.some(function (a) { return a.id === state.selectedAccountId; })) {
      state.selectedAccountId = v.accounts.length ? v.accounts[0].id : null;
    }
    list.innerHTML = v.accounts.map(function (a) {
      return Cards.buildCardVisual(a, { hideBalances: state.hideBalances, selected: a.id === state.selectedAccountId });
    }).join('');
    list.querySelectorAll('.card-visual').forEach(function (el) {
      el.addEventListener('click', function () { state.selectedAccountId = el.getAttribute('data-id'); render(); });
    });
    $('accounts-empty').classList.toggle('hidden', v.accounts.length > 0);
    // Summary panel (reel "Order summary"): one row per account + total.
    var sl = $('summary-list');
    sl.innerHTML = v.accounts.map(function (a) {
      return '<div class="sum-row"><span class="mark ' + Cards.providerClass(a.provider) + '">'
        + esc(a.provider.slice(0, 2).toUpperCase()) + '</span><span class="nm">' + esc(a.nickname)
        + '<span class="sub">' + esc(a.provider) + ' · ' + esc(a.type) + ' •••• ' + esc(a.last4) + '</span></span>'
        + '<span class="amt">' + esc(maskBal(a.balance)) + '</span></div>';
    }).join('');
    $('summary-total').textContent = maskBal(total);
    $('summary-empty').classList.toggle('hidden', v.accounts.length > 0);
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
    var nf = $('notifs-list');
    nf.innerHTML = '';
    $('notifs-empty').classList.toggle('hidden', v.notifications.length > 0);
    v.notifications.slice().reverse().slice(0, 50).forEach(function (n) {
      var div = document.createElement('div');
      div.className = 'notif';
      div.innerHTML = '<span class="pill ' + (n.kind === 'low-balance' ? 'amber' : 'green') + '">' + esc(n.kind) + '</span> ' +
        esc(n.text) + ' <span class="muted">(' + esc(String(n.at || '').slice(0, 16).replace('T', ' ')) + ')</span>';
      nf.appendChild(div);
    });
  }

  // Enter the vault after the PIN (and, when on, the 2FA code) has passed.
  function enterVault(doneLabel) {
    state.lastActive = Date.now();
    setLockPill(false);
    showScreen('vault');
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
      balance: $('add-balance').value === '' ? 0 : Number($('add-balance').value),
    };
    try {
      var created = VaultModel.createAccount(state.vault, input);
      await persist();
      render();
      ok.textContent = 'Account added: ' + input.nickname + ' (•••• ' + input.last4 + ').';
      $('add-nick').value = ''; $('add-last4').value = ''; $('add-balance').value = '';
      showSecuring(created, 'Saved securely!');
    } catch (e) {
      err.textContent = (e.errors && e.errors.length ? e.errors.join(' ') : e.message);
    }
  }

  function accountOptions(sel, preselectId) {
    sel.innerHTML = '';
    state.vault.accounts.forEach(function (a) {
      var o = document.createElement('option');
      o.value = a.id;
      o.textContent = a.nickname + ' — ' + a.provider + ' •••• ' + a.last4 + ' (' + fmtRs(a.balance) + ')';
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
        var text = Intel.intelResultText(match.account, draft, out.prevBalance, out.newBalance);
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
      await persist();
      $('sms-review').innerHTML = '';
      $('sms-text').value = '';
      state.smsDraft = null;
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
    res.innerHTML = '<div class="big">Undone — balance back to ' + esc(fmtRs(out.balance)) + '.</div>';
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
          state.vault = out.vault;
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

  function revealStepCards() {
    Object.keys(STEP_CARDS).forEach(function (step) {
      if (Number(step) <= STEP_DONE) return; // not landed yet: keep hidden
      STEP_CARDS[step].forEach(function (id) { var el = $(id); if (el) hide(el); });
    });
  }

  function boot() {
    revealStepCards();
    loadStored();
    populateProviders();
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
    $('lock-btn').addEventListener('click', lock);
    $('add-account-btn').addEventListener('click', addAccount);
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
