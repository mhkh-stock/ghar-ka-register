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
  Only the last 4 digits + provider + nickname + type + balance (the
  balance is set only by the bank — never typed).
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

1. **Manual add** — provider → type → nickname → last 4 digits → done.
   There is NO balance field: **a balance is never typed** — not even at
   creation. A new card starts with its balance unknown ("Balance not set
   yet"). It is set only by your bank — paste a bank SMS (Intelligence) or
   upload a statement (here, or in the monthly check).
2. **Intelligence — paste a bank SMS, the wallet updates itself** — on the
   Intelligence page, paste the transaction SMS (money cut OR received). The
   parser reads the amount, direction, merchant, date, available balance
   and the account identifier (last-4 + provider). If exactly one saved
   account matches (provider + last-4), the balance updates DIRECTLY — no
   amount entry, no account picking — and the result shows inline
   ("JazzCash ••1234 updated: −Rs 2,500 → new balance Rs 47,500", plus a
   cross-check against the bank's available balance and an Undo button).
   If the card's balance was never set and the SMS states an available
   balance, that number IS the balance now ("balance set from this SMS").
   If the SMS states no available balance, the balance stays unknown and
   the result says so plainly. If no account matches, or several do, it
   falls back to the review card with the account picker — nothing is saved
   until approved. Garbage, OTPs and amount-less messages change nothing.
3. **CSV import** — upload a statement, map columns, duplicates flagged,
   review every row, approve. Statement rows are bank data, so they set
   balances from the statement.
4. **Connect bank** — "coming when SBP open banking goes live" placeholder.

## Verification — how a card earns trust

A typed card is only a claim. The app marks every card with one status, in
this order of strength:

1. **✓ Bank-confirmed** — earned ONLY by a total-amount screenshot or a
   bank statement PDF. NEVER by an SMS: a bank SMS can set the balance,
   but it never verifies the card. (Total-amount screenshot verification
   is not built yet — it needs on-device OCR — so today a matching
   statement PDF is the only way to earn verification, at rung 2 below.)
2. **Statement matches** — a bank-statement PDF you uploaded, whose text
   the app checked for the bank name, the last 4 digits, and your profile
   name. This is the strongest proof the app can give today — and when a
   statement matches, its balance (if the statement carries one clear
   balance) becomes the card's balance too.
3. **Statement attached — self-checked** — a screenshot you looked at
   yourself next to the typed details and confirmed. The app cannot read
   text from a screenshot; this is labelled as your check, not the app's.
4. **Statement attached** — a file kept as your record (unreadable text).
5. **Not confirmed yet** — typed by hand, no proof. A fake card stays here.

Rules that keep the data honest: no two cards with the same bank + last 4;
**a balance is never typed — not even at creation.** It is set only by a
bank SMS or a statement (a forged statement can still carry a false
balance — only a bank SMS is hard to fake). A saved card's balance can
never be edited by hand — only a bank SMS, a statement, or a statement CSV
can change it. You can rename a card, move it up or down, or delete it
(two-tap confirm; deleting a card also removes its transactions). Old
vaults keep their existing balances exactly as they are; new cards start
with the balance unknown until a bank source sets it.

## Monthly check

Once a month the home page reminds you to re-check every balance against
the new statement and to export an encrypted backup. The monthly-check view
lists every card with its status and last confirmed date. A lost phone with
no backup means the vault is gone — there is no recovery by design.

## Navigation (Phase 3)

Sidebar, in order: Wallet (cards + summary only) → Add Card → Intelligence
→ Security → Backup & Import → Profile (photo + details). Notifications
are a bell in the sidebar, not a page. Your photo and name at the top of the
sidebar and in the top bar open the Profile page.

## Run

```
node server.js        # serves on :3036
node test.js          # tests (must print ALL TESTS PASSED)
```

Node 24+, zero dependencies. Design: Phase 2 (complete 2026-11-06) recreates
the Code XR "Glassy Payment Checkout V2" reel for the wallet screens; Phase 3
(complete 2026-11-06) reorganised it into a sidebar with one page per job,
keeping the same glass look on every new page. The reel itself (warm
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
