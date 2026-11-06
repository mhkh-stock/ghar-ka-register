// Personal Card Vault — navigation (browser + Node tests).
// Pure hash routing + the sidebar button order (Phase 3). No DOM, no vault.
'use strict';

const PAGES = ['wallet', 'add', 'intelligence', 'security', 'backup', 'profile'];

// The sidebar buttons, in Hashir's exact order. The HTML sidebar must list
// the labels in this same order (checked in test.js §9).
const NAV_ORDER = [
  { id: 'wallet', label: 'Wallet', hash: '#/wallet' },
  { id: 'add', label: 'Add Card', hash: '#/add' },
  { id: 'intelligence', label: 'Intelligence', hash: '#/intelligence' },
  { id: 'security', label: 'Security', hash: '#/security' },
  { id: 'backup', label: 'Backup & Import', hash: '#/backup' },
  { id: 'profile', label: 'Profile', hash: '#/profile' },
];

function routeForHash(hash) {
  if (typeof hash !== 'string') return 'wallet';
  const m = hash.match(/^#\/([a-z]+)/);
  const page = m ? m[1] : null;
  return PAGES.indexOf(page) >= 0 ? page : 'wallet';
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PAGES, NAV_ORDER, routeForHash };
}
if (typeof window !== 'undefined') {
  window.Nav = { PAGES, NAV_ORDER, routeForHash };
}
