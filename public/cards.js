// Personal Card Vault — card visuals (browser + Node tests).
// Pure functions: provider gradient map + the reel-style card visual HTML.
// White text on every gradient stop passes WCAG AA (checked in test.js §6).
// No DOM, no storage, no crypto.
'use strict';

const PROVIDER_GRADIENTS = {
  'HBL': { cls: 'card-hbl', stops: [[29, 78, 216], [30, 64, 175]] },
  'Meezan': { cls: 'card-meezan', stops: [[15, 118, 110], [17, 94, 89]] },
  'UBL': { cls: 'card-ubl', stops: [[30, 58, 138], [23, 37, 84]] },
  'MCB': { cls: 'card-mcb', stops: [[124, 45, 18], [67, 20, 7]] },
  'Allied': { cls: 'card-allied', stops: [[6, 95, 70], [6, 78, 59]] },
  'Bank Alfalah': { cls: 'card-bank-alfalah', stops: [[159, 18, 57], [136, 19, 55]] },
  'Askari': { cls: 'card-askari', stops: [[54, 83, 20], [26, 46, 5]] },
  'Faysal': { cls: 'card-faysal', stops: [[14, 116, 144], [21, 94, 117]] },
  'JS': { cls: 'card-js', stops: [[109, 40, 217], [91, 33, 182]] },
  'Standard Chartered': { cls: 'card-standard-chartered', stops: [[30, 64, 175], [30, 58, 138]] },
  'NBP': { cls: 'card-nbp', stops: [[22, 101, 52], [20, 83, 45]] },
  'BOP': { cls: 'card-bop', stops: [[146, 64, 14], [120, 53, 15]] },
  'SadaPay': { cls: 'card-sadapay', stops: [[15, 118, 110], [19, 78, 74]] },
  'NayaPay': { cls: 'card-nayapay', stops: [[190, 24, 93], [157, 23, 77]] },
  'Zindigi': { cls: 'card-zindigi', stops: [[133, 77, 14], [113, 63, 18]] },
  'Easypaisa': { cls: 'card-easypaisa', stops: [[21, 128, 61], [22, 101, 52]] },
  'JazzCash': { cls: 'card-jazzcash', stops: [[185, 28, 28], [153, 27, 27]] },
  'Payoneer': { cls: 'card-payoneer', stops: [[146, 64, 14], [120, 53, 15]] },
  'Custom': { cls: 'card-custom', stops: [[68, 64, 60], [41, 37, 36]] },
};
const DEFAULT_GRADIENT = { cls: 'card-default', stops: [[185, 28, 28], [154, 52, 18]] };

function providerClass(provider) {
  const g = PROVIDER_GRADIENTS[provider] || DEFAULT_GRADIENT;
  return g.cls;
}
function providerGradient(provider) {
  return PROVIDER_GRADIENTS[provider] || DEFAULT_GRADIENT;
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function fmtRs(n) { return 'Rs ' + Number(n || 0).toLocaleString('en-PK'); }

// The reel's red-orange VISA card, recoloured per provider. Shows only the
// last 4 digits — never a full number. `opts.hideBalances` masks the amount;
// `opts.selected` enlarges the card; `opts.success` turns it green.
function buildCardVisual(account, opts) {
  const o = opts || {};
  const a = account || {};
  const cls = providerClass(a.provider);
  const last4 = String(a.last4 || '');
  const num = last4 ? '•••• ' + last4 : '•••• ••••';
  const bal = o.hideBalances ? 'Rs ••••' : fmtRs(a.balance);
  return '<div class="card-visual ' + cls + (o.selected ? ' selected' : '')
    + (o.success ? ' success' : '') + '" data-id="' + esc(a.id || '')
    + '" role="button" tabindex="0">'
    + '<div class="cv-top"><span class="cv-chip"></span>'
    + '<span><span class="cv-provider">' + esc(a.provider || 'Card') + '</span><br>'
    + '<span class="cv-type">' + esc(a.type || 'card') + '</span></span></div>'
    + '<div class="cv-num">' + esc(num) + '</div>'
    + '<div class="cv-bottom"><span class="cv-holder">' + esc(a.nickname || 'My card') + '</span>'
    + '<span class="cv-bal">' + esc(bal) + '</span></div>'
    + '<div class="cv-tap">Tap to pay</div></div>';
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PROVIDER_GRADIENTS, DEFAULT_GRADIENT, providerClass, providerGradient, buildCardVisual };
}
if (typeof window !== 'undefined') {
  window.Cards = { PROVIDER_GRADIENTS, DEFAULT_GRADIENT, providerClass, providerGradient, buildCardVisual };
}
