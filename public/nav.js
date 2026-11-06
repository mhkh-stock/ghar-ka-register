// Ghar ka Register — navigation (browser + Node tests).
// Pure hash routing + the sidebar button order (Phase 1). No DOM, no vault.
'use strict';

const PAGES = ['home', 'staff', 'deliveries', 'udhaar', 'bills', 'documents',
  'medicine', 'summary', 'security', 'backup', 'profile'];

// The sidebar buttons, in order. The HTML sidebar must list the labels
// in this same order (checked in test.js). Home is "Today".
const NAV_ORDER = [
  { id: 'home', label: 'Today', hash: '#/home' },
  { id: 'staff', label: 'Staff', hash: '#/staff' },
  { id: 'deliveries', label: 'Deliveries', hash: '#/deliveries' },
  { id: 'udhaar', label: 'Udhaar', hash: '#/udhaar' },
  { id: 'bills', label: 'Bills', hash: '#/bills' },
  { id: 'documents', label: 'Documents', hash: '#/documents' },
  { id: 'medicine', label: 'Medicine', hash: '#/medicine' },
  { id: 'summary', label: 'Summary', hash: '#/summary' },
  { id: 'security', label: 'Security', hash: '#/security' },
  { id: 'backup', label: 'Backup & Import', hash: '#/backup' },
  { id: 'profile', label: 'Profile', hash: '#/profile' },
];

function routeForHash(hash) {
  if (typeof hash !== 'string') return 'home';
  const m = hash.match(/^#\/([a-z]+)/);
  const page = m ? m[1] : null;
  return PAGES.indexOf(page) >= 0 ? page : 'home';
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PAGES, NAV_ORDER, routeForHash };
}
if (typeof window !== 'undefined') {
  window.Nav = { PAGES, NAV_ORDER, routeForHash };
}
