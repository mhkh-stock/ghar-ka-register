# Ghar ka Register — your home's book, on this device only

A free, open-source, local-first household book for a Pakistani home:
staff pay and advances, daily deliveries (doodhwala, gas, water…),
money lent and borrowed (udhaar), bill due dates, documents and their
expiry, and the medicine cabinet — in one private, PIN-locked place,
in English with Roman Urdu where it helps. Nothing ever leaves the
device.

This app replaced the Personal Card Vault in this repo (same repo,
same link, replaced in place). The old vault code is gone from the
codebase but stays in git history. **A v1 Card Vault is NOT migrated:**
the first run of this app creates a fresh v2 vault. An old encrypted
Card Vault backup does not open here — it restores only into the old
code.

## The three rules (binding, from the vault failure)

- **R1 — nothing is ever "confirmed", "verified" or "real".** Every
  record is shown "as you entered it"; every computed figure shows its
  working. A wrong date is a wrong date — the app shows it, it does
  not bless it.
- **R2 — no live data of any kind.** No balances, no fetched bills, no
  rates, no government records. Every number and date is typed by the
  user and visible to the user.
- **R3 — value in the first minute.** Add a helper → the month's pay
  is worked out; add a document → the countdown shows.

## What it does

- **Today** — everything due, overdue and coming in the next 7 days
  in one list: staff pay day, bill due, document expiring, medicine
  expiring or running low, udhaar overdue. Each row says what it is,
  the amount/date, and links to its page.
- **Staff** — helpers (maid / cook / driver / guard / gardener /
  caretaker / other), monthly salary, attendance (tap a day:
  present → absent → half day; present is the default, only
  exceptions are stored), advances (full recovery or instalments),
  month-end pay worked out line by line
  (salary — prorated from the join date if the helper joined
  mid-month — − charged absent × (salary ÷ 30) − charged half ×
  (salary ÷ 60) − advance recovery = net payable), "Mark paid" locks
  the month, and a plain-text pay statement ready to copy to WhatsApp.
  The first 2 absent days each month are free (paid leave — as many as
  the helper's paid leave allows); extra absent days deduct one day's
  pay, a half day deducts half that. Example: Rs 15,000 salary,
  3 absent days, Rs 2,000 advance (full recovery), 2 days paid leave:
  the first 2 absent days are free, so it pays
  Rs 15,000 − Rs 500 − Rs 2,000 = **Rs 12,500**. With no paid leave
  left it would pay Rs 11,500. A helper who joins on the 16th of a
  30-day month is paid for 15 days: Rs 7,500 before any deductions.
  Net pay never goes below Rs 0: if an advance is bigger than the
  month's pay, only what the month can pay is recovered and the rest
  carries to next month (Rs 15,000 salary + Rs 20,000 advance →
  net Rs 0, Rs 5,000 carries). An advance is recovered only from its
  own month onward. Attendance cannot be marked before the join date
  or in the future, and future days are disabled on the page.
- **Deliveries** — doodhwala, newspaper, gas cylinder, water can,
  ironing, other; daily log (usual quantity, 0 = skipped day), monthly
  bill auto-summed from the log, "mark paid" per month, gas refill
  date + price with days since the last refill. Example: 1 litre/day
  × Rs 220 × 30 days with 2 skipped days = **Rs 6,160** (28 × 220).
- **Udhaar** — people, lent/borrowed entries, partial repayments,
  running balance per person and per entry, "settled" stamp at zero,
  forgive (recorded as forgiven, never as a payment), and a polite
  reminder text ready to copy to WhatsApp. For a lent entry the
  reminder asks the person to pay when they can; for a borrowed entry
  it promises to pay them back — the direction matters.
- **Bills** — type, provider name, account/consumer number, amount,
  due date, late-surcharge note — all typed by you, nothing fetched
  from any provider. Due countdowns on Today; marking paid moves the
  bill to history with the paid date.
- **Documents** — CNIC, passport, driving licence, vehicle
  registration/token, domicile, birth certificate, insurance,
  warranty, other; issue + expiry dates, photo (JPEG/PNG, magic-byte
  checked, downscaled to ≤ 500 KB, stored encrypted in the vault),
  reminders at 30 / 14 / 7 / 1 days, renewal checklists for CNIC,
  passport, driving licence and vehicle token only (other types show
  "no checklist yet").
- **Medicine** — name, quantity left, expiry, place, person, dose
  schedule you typed; dose ticks lower the quantity by one; low-stock
  warning at the number you set; expiry warnings at 30 and 7 days;
  expired items stay red until you remove them ("do not use — check
  with a pharmacist").
- **Summary** — this month's totals per section (staff paid / still to
  pay, deliveries total / paid, udhaar lent/borrowed outstanding,
  bills paid / due / overdue, documents and medicines expiring) plus
  this month vs last month for staff paid, deliveries and bills paid.
  Every total is recomputed from the section rows when the page opens
  — nothing is stored.
- **Export** — CSV of every section (one file per section, or all six
  in one file). Money is plain whole rupees, so the file opens as
  readable CSV in a spreadsheet; totals reconcile with the section
  pages to the rupee. Photos are never in a CSV. A CSV is plain text:
  anyone who opens the file can read it. The encrypted backup is
  separate (Backup & Import).
- **Profile** — household name, month start day (1–28), and optional
  phone, email and a profile picture (JPEG/PNG, magic-byte checked,
  downscaled to ≤ 500 KB, stored encrypted inside the vault). All three
  are optional — the book works the same with them empty. They stay on
  this device only and are never sent anywhere. The picture also shows
  as a small round photo at the top of the sidebar.

## Security — how it works

- **Local-first:** all data lives ONLY in this browser (localStorage).
  The server serves the app shell only and stores NOTHING. No account
  on a server, no sync, no one else can see it.
- **Login portal (first run):** register with your Gmail, set a
  6-digit code (+ an optional passphrase), and type the 6-digit code
  sent to your Gmail. Next times the login shows your saved Gmail and
  asks only for the code — the code is never saved, you type it every
  time. The code → PBKDF2 (600,000 iterations, SHA-256) → AES-256-GCM
  encrypts the whole vault at rest. No code = no data, even if someone
  copies the files.
- **Forgot your code?** If a Gmail is linked, the login screen sends a
  6-digit code to it; a new code opens the book (the old code stops
  working, the passphrase is removed, and the spare key is replaced).
  A book with no Gmail linked, or with recovery turned off, cannot be
  reset — restore from a backup instead.
- **Spare key (the trade-off, printed on the setup screen):** recovery
  works through a random spare key kept in `data/recovery.key` on this
  PC only (never committed, never uploaded). If someone can open the
  files on your PC, they can find the spare key and open the book
  without your code. Keep your PC locked. You can turn this recovery
  off later in Security.
- **Change login Gmail / recovery on-off:** on the Security page, only
  while unlocked. Changing the Gmail sends a code to the NEW Gmail
  first; the old Gmail gets a plain note that it changed (no code in
  it). Turning recovery off deletes the spare key file and the spare
  envelope; turning it back on makes a new pair (it asks for your
  current code). Deleting the spare key file on its own only stops
  forgot-code recovery — the book still opens with your code. The Profile page shows the login Gmail with a Change
  link — the household contact email there is separate and untouched.
- **Mail setup (for the codes to arrive):** the app sends the codes
  from YOUR Gmail. Turn on 2-Step Verification on that Google
  account, make an app password (Google Account → Security → App
  passwords → Mail), then start the app with the two values below
  (see Run). Without them, the code steps answer "mail is not set up"
  and the book still works with a code only (no forgot-code) — link a
  Gmail later in Security.
- **Auto-lock** after 5 minutes without use; 5 wrong PINs → growing
  lockout delay (30s, doubling, cap 15 min).
- **Change PIN / passphrase:** on the Security page you type your
  current PIN (and passphrase, if you set one) once at the top; both
  changes use those — the same credentials are never asked twice.
- **Migration:** a book made before the portal (code only, no Gmail)
  is asked once, after unlocking, to link a Gmail. The book, code,
  passphrase and data stay the same. "Skip for now" asks again next
  time; "Don't ask again" never asks again (link it later in Security).
- **Encrypted backup:** export a backup file (restorable only with
  your PIN + passphrase). Backups made by the earlier builds of this
  app carry the old `personal-card-vault` label; backups made from
  Phase 5 on carry `ghar-ka-register`. Both restore — the label is
  metadata only. An old **Card Vault** backup still does not open
  here.

## Honest limits (printed in the app, not buried)

- Nothing is fetched, checked or looked up — every record is "as you
  entered it". A wrong date is a wrong date; the book shows it, it
  does not bless it.
- No reminders when the app is closed (a local web app cannot push).
  Open the app and Today tells you what is due.
- No recovery if the code is forgotten AND no Gmail is linked (or
  recovery is turned off). Link a Gmail to turn forgot-code on, or
  restore from an encrypted backup.
- Renewal checklists are dated static text — rules change; the app
  says "check with the office". Fee figures in the checklists were
  checked against the official pages on 2026-11-06: NADRA Smart NIC
  renewal Rs 750 / 1,500 / 2,500 (nadra.gov.pk fee structure),
  DGIP e-passport 36 pages / 5 years Rs 9,000 normal / 15,000 urgent
  (dgip.gov.pk), Punjab DLIMS licence renewal motorcycle Rs 450 /
  car Rs 1,350 + Rs 480 courier (dlims.punjab.gov.pk), Punjab Excise
  token tax FY 2026-27 up to 1000cc Rs 20,000 once, 1001–2000cc 0.3%
  and above 2000cc 0.4% of invoice price a year
  (excise.punjab.gov.pk). Processing times and "how early you can
  renew" are not printed as figures — the checklists say to ask the
  office.
- Medicine entries are a cabinet list, not medical advice; the app
  never suggests a dose — it only records the schedule you typed.
- Photos live inside the encrypted vault blob; a very large vault
  slows the first open. The 500 KB downscale cap keeps it small.
- The month start day on the Profile page is recorded for your
  reference only: staff pay and delivery bills follow the calendar
  month.
- The app never reads SMS, never fetches anything, and has no
  verification of any kind. The old vault's OCR files
  (`public/ocr.js`, `public/vendor/`) and the old statement-proof
  file (`public/proof.js`) were deleted in the D9/D11 cleanup
  (2026-11-07) — they were never loaded by any page, and the OCR
  module could not even be required (it depended on the deleted
  `sms.js`). An optional "read the date off this photo" helper is a
  later phase and would be built fresh, with a review step.

## Not in v1 (closed list)

OCR date-reading helper, Mera Plot File, Student Kit, any live
fetching, any push notification, multi-device sync, family sharing,
any verification claim.

## Run

```
node server.js        # serves on 127.0.0.1:3036 (localhost only — nothing on the network can reach it)
GMAIL_USER=you@gmail.com GMAIL_APP_PASSWORD=xxxx node server.js   # with mail (codes by Gmail)
node test.js          # tests (844 checks, must print ALL TESTS PASSED)
```

Node 24+, zero dependencies. Design: the Code XR "Glassy Payment
Checkout V2" reel look (warm frosted glass over a blurred warm
interior photo, black pill buttons, green success accents) carried
over from the vault. Hosting is deferred until a container slot frees
(4/4 full) — the app runs on a PC on port 3036 meanwhile.
