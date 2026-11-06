# Personal Card Vault — your cards, only yours

A local-first, private card/account wallet for Pakistan. Add bank accounts,
debit/credit cards and wallets (HBL, Meezan, UBL, MCB, Allied, Bank Alfalah,
Askari, Faysal, JS, Standard Chartered, NBP, BOP, SadaPay, NayaPay, Zindigi,
Easypaisa, JazzCash, Payoneer, + Custom). Every card shows its details and
balance, updated through every transaction, with an in-app notification feed.

## Security — how it works

- **Local-first:** all vault data lives ONLY in this browser (localStorage).
  The server serves the app shell only and stores NOTHING. No account on a
  server, no sync, no one else can see it — including us.
- **Unlock:** a 6-digit PIN (plus an optional passphrase) set on first run.
  PIN → PBKDF2 (600,000 iterations, SHA-256) → AES-256-GCM encrypts the
  whole vault at rest. No PIN = no data, even if someone copies the files.
- **Never stored:** full card numbers, CVV, card PIN, expiry, bank passwords.
  Only the last 4 digits + provider + nickname + type + balance.
- **Auto-lock** after 5 minutes without use (changeable to 1 or 15 minutes
  in Security settings); hide-balances eye toggle; 5 wrong PINs → growing
  lockout delay (30s, doubling, cap 15 min).
- **Two-factor authentication (optional, in Security settings):** a 6-digit
  code from your authenticator app (Google Authenticator, Authy, any TOTP
  app — RFC 6238, HMAC-SHA1, 30-second step, ±1 step window) on top of the
  PIN. The secret is generated in the app, enrolled by tapping the
  `otpauth://` link or typing the manual key, and confirmed with one code
  before 2FA turns on; the secret lives INSIDE the vault (protected by the
  PIN). **10 one-time backup codes** are generated at setup (shown once —
  write them down); each works once in place of the authenticator code and
  is then burned. Only SHA-256 hashes of the codes are stored, outside the
  vault, so they can be checked while the vault is locked. Disabling 2FA
  needs the PIN + a current code. Security settings also offer change PIN,
  change passphrase, auto-lock timeout, hide-balances, and regenerating
  backup codes.
- **No recovery, by design:** forgotten PIN = data unrecoverable. There is
  no "forgot PIN" — that is the point of "up to me only".
- **Encrypted backup:** export a backup file (restorable only with your PIN
  + passphrase); import restores it.

## Honest limits

- **No live bank sync.** No Pakistani bank or wallet offers a personal API
  today, so balances cannot update themselves. They update when you add a
  transaction, approve a pasted bank SMS, or import a statement CSV.
- **The web app cannot read your phone's SMS.** Pasting a bank SMS is the
  web equivalent: if the SMS names one of your saved accounts (provider +
  last-4), Intelligence updates it directly with an Undo button; otherwise
  the parser shows a review card and nothing is saved until you approve it.
- **Open banking is not live.** SBP published draft Open Banking Regulations
  on 30 Oct 2026 (comments due 30 Nov 2026). When it goes live, the Connect
  Bank slot in the app is where it will appear — never faked as working.
- Software encryption is only as secure as the device. On a rooted phone or
  a shared unlocked device, someone with the app open can see plaintext.

## How an account gets added

1. **Manual add** — provider → type → nickname → last 4 digits → starting
   balance → done.
2. **Intelligence — paste a bank SMS, the wallet updates itself** — on the
   home screen, paste the transaction SMS (money cut OR received). The
   parser reads the amount, direction, merchant, date, available balance
   and the account identifier (last-4 + provider). If exactly one saved
   account matches (provider + last-4), the balance updates DIRECTLY — no
   amount entry, no account picking — and the result shows inline
   ("JazzCash ••1234 updated: −Rs 2,500 → new balance Rs 47,500", plus a
   cross-check against the bank's available balance and an Undo button).
   If no account matches, or several do, it falls back to the review card
   with the account picker — nothing is saved until approved. Garbage, OTPs
   and amount-less messages change nothing.
3. **CSV import** — upload a statement, map columns, duplicates flagged,
   review every row, approve.
4. **Connect bank** — "coming when SBP open banking goes live" placeholder.

## Run

```
node server.js        # serves on :3036
node test.js          # tests (must print ALL TESTS PASSED)
```

Node 24+, zero dependencies. Design: Phase 2 (complete 2026-11-06) recreates
the Code XR "Glassy Payment Checkout V2" reel for the wallet screens (warm
frosted glass over a blurred warm interior photo, red-orange card, black pill
buttons, green success accents, "Securing your payment" shimmer state, bottom
stepper) — see `~/workspace/new-projects/p7-card-vault-research.md` and
`~/workspace/p7-reel/`. Deviations from the reel, stated plainly: the card
shows •••• last-4 + balance instead of a full number + expiry (the vault
never stores full numbers, CVV or expiry); there is no countdown timer or
cart (no checkout session); the stepper has 3 steps (Setup → Add card →
Done) instead of 4; the "Paid" pill is "✓ Saved"; 2FA enrolment is an
`otpauth://` tap-to-open link + manual key (no rendered QR image — a local
QR encoder would need a bundled dependency, and the secret must never be
sent to an external QR service); backup codes cannot be shown again (only
their hashes are stored) — generate a new set to replace them.
