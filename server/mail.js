// Ghar ka Register — minimal hand-rolled SMTP client (server only, Node).
// node:net + node:tls only, zero dependencies. Sends ONE text email via
// the user's own Gmail (smtp.gmail.com:587, STARTTLS required).
//
// Why hand-rolled: the whole project family is zero-dependency Node and
// the RUN file promises "no npm install". Sending one text email is four
// SMTP commands; a mail dependency would add a supply chain and install
// friction for every user who downloads the app.
//
// The app password comes from env (GMAIL_USER, GMAIL_APP_PASSWORD),
// read at call time, kept in memory only, never logged, never sent to
// the browser, never written to a file. If the env vars are absent,
// mail is not configured and the OTP endpoints answer 503 — the book
// itself still works (PIN-only, as today).
//
// Test hooks (never used by server.js in production):
//   sendMail(to, subject, text, transport) — an injected transport
//     ({ send({ from, to, subject, text }) }) replaces SMTP entirely.
//   GMAIL_FAKE_OUTBOX env var — if set, sent mail is appended as one
//     JSON line per mail to that file (used by the test suite's spawned
//     server so tests can read the OTP without sending real mail).
//     Production never sets this variable.
'use strict';
const net = require('node:net');
const tls = require('node:tls');
const fs = require('node:fs');

const SMTP_HOST = 'smtp.gmail.com';
const SMTP_PORT = 587;
const SOCKET_TIMEOUT_MS = 15000;

function isMailConfigured() {
  return !!(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD);
}
function mailFrom() {
  return process.env.GMAIL_USER || '';
}

function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

// ---- line-based reply reader over a socket ----
// SMTP replies are "DDD text" or multi-line "DDD-text ... DDD text".
function createReplyReader(socket) {
  let buf = '';
  let waiters = [];
  let ended = false;
  socket.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    let idx;
    while ((idx = buf.indexOf('\r\n')) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const w = waiters.shift();
      if (w) w(line);
    }
  });
  socket.on('close', () => {
    ended = true;
    while (waiters.length) waiters.shift()(null);
  });
  socket.on('error', () => {
    ended = true;
    while (waiters.length) waiters.shift()(null);
  });
  function readLine(timeoutMs) {
    return new Promise((resolve, reject) => {
      if (ended) return reject(fail('SMTP_CLOSED', 'Connection closed.'));
      const timer = setTimeout(() => reject(fail('SMTP_TIMEOUT', 'SMTP server did not answer in time.')), timeoutMs);
      waiters.push((line) => {
        clearTimeout(timer);
        if (line === null) reject(fail('SMTP_CLOSED', 'Connection closed.'));
        else resolve(line);
      });
    });
  }
  // Read one full reply (possibly multi-line). Returns { code, text }.
  async function readReply(timeoutMs) {
    const lines = [];
    for (;;) {
      const line = await readLine(timeoutMs);
      if (!/^\d{3}[ -]/.test(line)) {
        throw fail('SMTP_PROTOCOL', 'Unexpected SMTP reply: ' + line.slice(0, 80));
      }
      lines.push(line);
      if (line[3] === ' ') break;
    }
    return { code: Number(lines[0].slice(0, 3)), text: lines.join('\n') };
  }
  return { readReply };
}

function sendLine(socket, line) {
  return new Promise((resolve, reject) => {
    socket.write(line + '\r\n', (err) => {
      if (err) reject(fail('SMTP_SEND', 'Could not write to the SMTP server.'));
      else resolve();
    });
  });
}
async function expectCode(reader, want, what) {
  const r = await reader.readReply(SOCKET_TIMEOUT_MS);
  if (r.code !== want) {
    throw fail('SMTP_PROTOCOL', what + ' failed (SMTP ' + r.code + ').');
  }
  return r;
}

// The raw SMTP conversation. `opts.requireStartTls` defaults to true —
// the client refuses to continue without STARTTLS. Tests may pass
// false to speak plain SMTP to a local fake server (never used by
// server.js). `opts.host/port/user/pass` override the Gmail defaults
// (tests point at a local fake server).
async function smtpSend(opts) {
  const host = (opts && opts.host) || SMTP_HOST;
  const port = (opts && opts.port) || SMTP_PORT;
  const user = (opts && opts.user) || process.env.GMAIL_USER || '';
  const pass = (opts && opts.pass) || process.env.GMAIL_APP_PASSWORD || '';
  const from = (opts && opts.from) || user;
  const to = opts && opts.to;
  const subject = (opts && opts.subject) || '';
  const text = (opts && opts.text) || '';
  const requireStartTls = !opts || opts.requireStartTls !== false;
  if (!user || !pass) throw fail('MAIL_NOT_CONFIGURED', 'Mail is not set up.');
  if (!to || typeof to !== 'string' || to.indexOf('@') < 0) {
    throw fail('BAD_ADDRESS', 'No valid recipient address.');
  }
  let socket = net.connect(port, host);
  socket.setTimeout(SOCKET_TIMEOUT_MS);
  socket.on('timeout', () => socket.destroy(fail('SMTP_TIMEOUT', 'SMTP server did not answer in time.')));
  try {
    let reader = createReplyReader(socket);
    await expectCode(reader, 220, 'SMTP greeting');
    await sendLine(socket, 'EHLO localhost');
    let ehlo = await expectCode(reader, 250, 'EHLO');
    const offersStartTls = /STARTTLS/i.test(ehlo.text);
    if (requireStartTls) {
      if (!offersStartTls) throw fail('NO_STARTTLS', 'The mail server does not offer STARTTLS — refusing to continue without it.');
      await sendLine(socket, 'STARTTLS');
      await expectCode(reader, 220, 'STARTTLS');
      const secure = tls.connect({ socket, servername: host });
      secure.setTimeout(SOCKET_TIMEOUT_MS);
      await new Promise((resolve, reject) => {
        secure.once('secureConnect', resolve);
        secure.once('error', (e) => reject(fail('SMTP_TLS', 'Could not secure the connection: ' + (e && e.message ? e.message : 'TLS error'))));
        secure.once('timeout', () => reject(fail('SMTP_TIMEOUT', 'SMTP server did not answer in time.')));
      });
      socket = secure;
      reader = createReplyReader(socket);
      await sendLine(socket, 'EHLO localhost');
      await expectCode(reader, 250, 'EHLO after STARTTLS');
    }
    await sendLine(socket, 'AUTH LOGIN');
    await expectCode(reader, 334, 'AUTH LOGIN');
    await sendLine(socket, Buffer.from(user, 'utf8').toString('base64'));
    await expectCode(reader, 334, 'AUTH username');
    await sendLine(socket, Buffer.from(pass, 'utf8').toString('base64'));
    const auth = await reader.readReply(SOCKET_TIMEOUT_MS);
    if (auth.code !== 235) throw fail('AUTH_FAILED', 'The mail server refused the Gmail app password.');
    await sendLine(socket, 'MAIL FROM:<' + from + '>');
    await expectCode(reader, 250, 'MAIL FROM');
    await sendLine(socket, 'RCPT TO:<' + to + '>');
    await expectCode(reader, 250, 'RCPT TO');
    await sendLine(socket, 'DATA');
    await expectCode(reader, 354, 'DATA');
    const body = 'From: ' + from + '\r\n'
      + 'To: ' + to + '\r\n'
      + 'Subject: ' + String(subject).replace(/[\r\n]/g, ' ') + '\r\n'
      + 'Content-Type: text/plain; charset=utf-8\r\n'
      + '\r\n'
      + String(text).replace(/\r?\n/g, '\r\n')
      + '\r\n.\r\n';
    // Raw write (not sendLine): the body already ends with the DATA
    // terminator, and an extra blank line after it would be a stray
    // empty command.
    await new Promise((resolve, reject) => {
      socket.write(body, (err) => {
        if (err) reject(fail('SMTP_SEND', 'Could not write to the SMTP server.'));
        else resolve();
      });
    });
    await expectCode(reader, 250, 'message accepted');
    try {
      await sendLine(socket, 'QUIT');
      await reader.readReply(3000);
    } catch (_e) { /* QUIT is best-effort; the mail is already accepted. */ }
    return { ok: true };
  } finally {
    try { socket.destroy(); } catch (_e) { /* already gone */ }
  }
}

// Send one mail. `transport` (optional, tests only) replaces SMTP:
//   transport.send({ from, to, subject, text }) -> Promise.
// If the GMAIL_FAKE_OUTBOX env var is set (test suite only), the mail
// is appended as one JSON line to that file instead of being sent.
async function sendMail(to, subject, text, transport) {
  const from = mailFrom();
  if (transport) {
    await transport.send({ from, to, subject, text });
    return { ok: true };
  }
  if (process.env.GMAIL_FAKE_OUTBOX) {
    fs.appendFileSync(process.env.GMAIL_FAKE_OUTBOX,
      JSON.stringify({ from, to, subject, text, at: new Date().toISOString() }) + '\n');
    return { ok: true };
  }
  if (!isMailConfigured()) throw fail('MAIL_NOT_CONFIGURED', 'Mail is not set up.');
  return smtpSend({ to, subject, text });
}

module.exports = {
  SMTP_HOST,
  SMTP_PORT,
  isMailConfigured,
  mailFrom,
  smtpSend,
  sendMail,
};
