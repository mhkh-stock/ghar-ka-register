// Personal Card Vault — Intelligence (browser + Node tests).
// Paste an SMS -> match the saved account by (provider + last 4) -> update
// the balance directly, with Undo. Uses the model only (add/approve/delete
// transaction); no crypto, no model changes.
// Fallback rule: no match, several matches, unknown provider or no last-4
// in the SMS -> NO direct update (the app shows the review card instead).
'use strict';

// VaultModel comes from the window global in the browser, or from require()
// under Node (tests). It is only USED, never changed.
const VaultModel = (typeof window !== 'undefined' && window.VaultModel)
  || (typeof module !== 'undefined' && module.exports ? require('./model.js') : null);

function findIntelMatch(accounts, provider, last4) {
  if (!provider || provider === 'Unknown' || !last4) return { status: 'none' };
  const matches = (accounts || []).filter(function (a) {
    return a.provider === provider && a.last4 === last4;
  });
  if (matches.length === 1) return { status: 'match', account: matches[0] };
  if (matches.length > 1) return { status: 'ambiguous', matches: matches };
  return { status: 'none' };
}

function fmtRs(n) { return 'Rs ' + Number(n || 0).toLocaleString('en-PK'); }

// Apply a parsed SMS draft to the matched account: transaction is added
// AND approved at once, so the balance updates immediately and the
// notification appears. Returns the txn + balances + the notification id
// (kept so Undo can remove exactly that notification).
function applyIntelUpdate(vault, draft, account) {
  const prevBalance = account.balance;
  // Baseline from the bank (Phase 3.5): remember whether the balance was
  // unknown before this SMS — if it was, and the SMS states an available
  // balance, that number IS the balance now (see below).
  const wasUnknown = !VaultModel.isBalanceKnown(account);
  const txn = VaultModel.addTransaction(vault, {
    accountId: account.id, amount: draft.amount, direction: draft.direction,
    merchant: draft.merchant, date: draft.date, source: 'sms',
  });
  const before = vault.notifications.length;
  VaultModel.approveTransaction(vault, txn.id);
  // An SMS NEVER confirms a card (Hashir's rule, 2026-11-06): it can set
  // the balance — it is bank data — but the "Bank-confirmed" badge is
  // earned ONLY by a total-amount screenshot or a bank statement PDF.
  // confirmedBy is never set here, on purpose. Only this direct-match
  // path and the review fallback update from an SMS; neither confirms.
  // Baseline from the bank (Phase 3.5): if the balance was never set and
  // this SMS states an available balance, set the baseline from it. The
  // back-computed starting balance accounts for this transaction, so
  // reconcile() stays clean. No available balance in the SMS → the balance
  // stays unknown; the transaction is still recorded.
  let baselineSet = false;
  if (wasUnknown && draft.availableBalance != null) {
    VaultModel.setBaselineFromBank(vault, account.id, draft.availableBalance, 'sms');
    baselineSet = true;
  }
  const notif = vault.notifications[before] || null;
  return { txn: txn, prevBalance: prevBalance, newBalance: account.balance, notifId: notif ? notif.id : null, baselineSet: baselineSet };
}

// Reverse a direct update: the approved transaction is deleted (the model
// reverses its balance effect) and its notification is removed.
function undoIntelUpdate(vault, txnId, notifId) {
  const txn = VaultModel.deleteTransaction(vault, txnId);
  if (notifId) {
    const i = vault.notifications.findIndex(function (n) { return n.id === notifId; });
    if (i >= 0) vault.notifications.splice(i, 1);
  }
  const account = VaultModel.findAccount(vault, txn.accountId);
  return { account: account, balance: account ? account.balance : null, txn: txn };
}

// The inline result line, plus the bank's available-balance cross-check
// when the SMS carried one. `baselineSet` is true when this SMS supplied
// the account's first balance (Phase 3.5). When the balance is still
// unknown after the update, the line says so plainly — never "Rs 0" for a
// number that was never set.
function intelResultText(account, draft, prevBalance, newBalance, baselineSet) {
  const sign = draft.direction === 'debit' ? '−' : '+';
  let line;
  if (newBalance === null || newBalance === undefined) {
    line = account.provider + ' ••' + account.last4 + ' updated: ' + sign
      + fmtRs(draft.amount) + ' → balance still not set — this SMS had no available balance. Paste another SMS or upload a statement.';
  } else if (baselineSet) {
    line = account.provider + ' ••' + account.last4 + ' updated: ' + sign
      + fmtRs(draft.amount) + ' → new balance ' + fmtRs(newBalance) + ' · balance set from this SMS';
  } else {
    line = account.provider + ' ••' + account.last4 + ' updated: ' + sign
      + fmtRs(draft.amount) + ' → new balance ' + fmtRs(newBalance);
  }
  let cross = null;
  if (draft.availableBalance != null && newBalance != null) {
    if (draft.availableBalance === newBalance) {
      cross = 'Bank says available balance ' + fmtRs(draft.availableBalance) + ' — matches the vault.';
    } else {
      const diff = Math.abs(draft.availableBalance - newBalance);
      cross = 'Bank says available balance ' + fmtRs(draft.availableBalance) + ' — '
        + fmtRs(diff) + (draft.availableBalance > newBalance ? ' more' : ' less')
        + ' than the vault shows (other transactions may not be in the vault yet).';
    }
  }
  return { line: line, cross: cross, baselineSet: !!baselineSet };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { findIntelMatch, applyIntelUpdate, undoIntelUpdate, intelResultText };
}
if (typeof window !== 'undefined') {
  window.Intel = { findIntelMatch, applyIntelUpdate, undoIntelUpdate, intelResultText };
}
