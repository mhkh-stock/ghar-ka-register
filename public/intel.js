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
  const wasConfirmed = VaultModel.isBankConfirmed(account);
  const txn = VaultModel.addTransaction(vault, {
    accountId: account.id, amount: draft.amount, direction: draft.direction,
    merchant: draft.merchant, date: draft.date, source: 'sms',
  });
  const before = vault.notifications.length;
  VaultModel.approveTransaction(vault, txn.id);
  // Bank-confirmed (Phase 3.1): a real bank SMS matched this exact account —
  // the only proof an app can have in Pakistan today. Sticky: Undo reverses
  // the balance change only, never this confirmation — the bank SMS itself
  // was real. Only this direct-match path confirms; the review fallback,
  // manual entry and CSV import never call this function.
  VaultModel.markAccountBankConfirmed(vault, account.id);
  const notif = vault.notifications[before] || null;
  return { txn: txn, prevBalance: prevBalance, newBalance: account.balance, notifId: notif ? notif.id : null, confirmed: !wasConfirmed };
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
// when the SMS carried one.
function intelResultText(account, draft, prevBalance, newBalance) {
  const sign = draft.direction === 'debit' ? '−' : '+';
  const line = account.provider + ' ••' + account.last4 + ' updated: ' + sign
    + fmtRs(draft.amount) + ' → new balance ' + fmtRs(newBalance);
  let cross = null;
  if (draft.availableBalance != null) {
    if (draft.availableBalance === newBalance) {
      cross = 'Bank says available balance ' + fmtRs(draft.availableBalance) + ' — matches the vault.';
    } else {
      const diff = Math.abs(draft.availableBalance - newBalance);
      cross = 'Bank says available balance ' + fmtRs(draft.availableBalance) + ' — '
        + fmtRs(diff) + (draft.availableBalance > newBalance ? ' more' : ' less')
        + ' than the vault shows (other transactions may not be in the vault yet).';
    }
  }
  return { line: line, cross: cross };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { findIntelMatch, applyIntelUpdate, undoIntelUpdate, intelResultText };
}
if (typeof window !== 'undefined') {
  window.Intel = { findIntelMatch, applyIntelUpdate, undoIntelUpdate, intelResultText };
}
