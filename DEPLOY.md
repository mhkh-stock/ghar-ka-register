# Ghar ka Register — deploy notes

## Honest note first: this app is LOCAL-FIRST by design

Ghar ka Register is **not deployable to a public host as-is**, and that
is deliberate, not a gap:

- The server binds **`127.0.0.1` only** (`server.js`: `server.listen(PORT,
  '127.0.0.1', …)`). Nothing on the network can reach it — not even
  another device on the same Wi-Fi.
- The API has a **same-origin gate**: requests with a foreign `Origin`
  header are refused. The app is served from this same origin only.
- Forgot-code recovery works through a random spare key kept in
  `data/recovery.key` **on this PC only** (mode `0600`, never
  committed, never uploaded). If the app ran on a shared host, whoever
  runs that host could read the spare key and open any book without
  its code — the trade-off printed on the setup screen only holds
  because the PC is yours.
- There is **no `/tmp` fallback and no cloud store by design**: all
  vault data lives in the browser on this device (localStorage,
  encrypted with the PIN). A public host would have nowhere safe to
  put `data/` and no device to trust.

To run it on another device, copy the folder to that PC and run it
there. Do not expose the port with a tunnel or a reverse proxy: the
same-origin gate and the spare-key trade-off both assume localhost.

## Run (local)

```sh
node server.js        # serves on 127.0.0.1:3036
npm start             # same thing
node test.js          # tests — must print ALL TESTS PASSED
```

Node **24+**, zero dependencies, no `npm install` needed.

## Environment variables

| Variable | Default | What it does |
| --- | --- | --- |
| `PORT` | `3036` | Port the server listens on (still `127.0.0.1` only). |
| `GMAIL_USER` | — (unset) | Your Gmail address, the sender of the 6-digit codes. |
| `GMAIL_APP_PASSWORD` | — (unset) | A Gmail **app password** (Google Account → Security → 2-Step Verification → App passwords → Mail). Never your Gmail password. |

`GMAIL_USER` + `GMAIL_APP_PASSWORD` are **optional and fail-soft**:
when either is unset, mail is not configured and the OTP endpoints
answer `503 MAIL_NOT_CONFIGURED` — the book still works exactly as
before, PIN-only (no forgot-code). Link a Gmail later in Security
once mail is set up. The values are read at call time, kept in memory
only, never logged, never sent to the browser, never written to a
file.

```sh
GMAIL_USER=you@gmail.com GMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx node server.js
```

## Files the server writes

- `data/recovery.key` — the spare key (32 bytes, mode `0600`).
  Created when a Gmail is linked; deleted when recovery is turned
  off. Never served over HTTP (`/data/…` 404s).
- `data/account.json` — the bound login Gmail (mode `0600`). Never
  served over HTTP.

Both live next to `server.js` by design. Restoring another book's
backup clears the login Gmail in the browser but leaves these two
files behind: linking the restored book first says the PC already has
recovery for a different book, and a second tap moves recovery to
this book (the old book loses forgot-code recovery).
