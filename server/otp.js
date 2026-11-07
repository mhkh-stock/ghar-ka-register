// Ghar ka Register — OTP + reset-token store (server only, Node).
// Pure functions over a plain in-memory store. Nothing here is ever
// written to disk, to a log, or sent to the browser except the reset
// token (which is itself stored hashed, single-use, 5-minute life).
//
// Rules (research §4, frozen by the plan):
//   OTP: 6 digits, crypto.randomInt, 10-minute expiry, single use.
//   5 wrong tries -> that OTP is dead + 15-minute cooldown on new
//   requests for that Gmail.
//   Request limits: 3 OTPs per hour per Gmail, 60 seconds between sends.
//   Storage: SHA-256(salt || code) only — NEVER the plaintext code.
//   Reset token: 32 random bytes, 5-minute life, single use, stored
//   hashed, purpose-bound. The reset endpoint never accepts a raw OTP.
//
// The store dies when the server restarts — that is a feature: no OTP
// survives a restart.
'use strict';
const crypto = require('node:crypto');

const OTP_TTL_MS = 10 * 60 * 1000;       // 10 minutes
const OTP_MAX_TRIES = 5;                  // wrong tries before the OTP dies
const OTP_COOLDOWN_MS = 15 * 60 * 1000;   // cooldown after a dead OTP
const OTP_MAX_PER_HOUR = 3;
const OTP_MIN_GAP_MS = 60 * 1000;         // 60 seconds between sends
const TOKEN_TTL_MS = 5 * 60 * 1000;       // reset token life
const TOKEN_BYTES = 32;

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}
function randomOtpCode() {
  return String(crypto.randomInt(100000, 1000000));
}
function randomToken() {
  return crypto.randomBytes(TOKEN_BYTES).toString('hex');
}
function normalizeGmail(gmail) {
  return String(gmail == null ? '' : gmail).trim().toLowerCase();
}

function createOtpStore() {
  // byGmail: gmail -> { otp: { salt, codeHash, expiresAt, triesLeft, purpose } | null,
  //                     sentAt: [ms, ...] (successful sends, last hour),
  //                     lastSentAt: ms, cooldownUntil: ms }
  // tokens: tokenHash -> { gmail, purpose, expiresAt }
  return { byGmail: new Map(), tokens: new Map() };
}

function _record(store, gmail) {
  let rec = store.byGmail.get(gmail);
  if (!rec) {
    rec = { otp: null, sentAt: [], lastSentAt: 0, cooldownUntil: 0 };
    store.byGmail.set(gmail, rec);
  }
  return rec;
}
function _pruneSent(rec, nowMs) {
  rec.sentAt = rec.sentAt.filter((t) => nowMs - t < 60 * 60 * 1000);
}

// Issue a fresh OTP for (purpose, gmail). The plaintext code is returned
// to the CALLER (the server, which emails it) and is never stored —
// only its salted hash is kept. Call noteOtpSent() after the mail is
// actually sent; call revokeOtp() if sending fails, so a mail failure
// does not burn the user's rate limit.
// Returns { ok: true, code } or { ok: false, error: 'TRY_LATER' | 'COOLDOWN' }.
function issueOtp(store, purpose, gmail, nowMs) {
  const g = normalizeGmail(gmail);
  const now = Number(nowMs) || 0;
  const rec = _record(store, g);
  if (rec.cooldownUntil > now) return { ok: false, error: 'COOLDOWN' };
  _pruneSent(rec, now);
  if (rec.sentAt.length >= OTP_MAX_PER_HOUR) return { ok: false, error: 'TRY_LATER' };
  if (now - rec.lastSentAt < OTP_MIN_GAP_MS && rec.lastSentAt > 0) {
    return { ok: false, error: 'TRY_LATER' };
  }
  const code = randomOtpCode();
  const salt = crypto.randomBytes(16).toString('hex');
  rec.otp = {
    salt,
    codeHash: sha256Hex(salt + '|' + code),
    expiresAt: now + OTP_TTL_MS,
    triesLeft: OTP_MAX_TRIES,
    purpose,
  };
  return { ok: true, code };
}

// Record a successful send (counts toward the 3/hour limit and the
// 60-second gap). Called by the server only after the mail went out.
function noteOtpSent(store, gmail, nowMs) {
  const rec = _record(store, normalizeGmail(gmail));
  const now = Number(nowMs) || 0;
  rec.sentAt.push(now);
  rec.lastSentAt = now;
}

// Drop the pending OTP without counting the send (mail failed).
function revokeOtp(store, purpose, gmail) {
  const rec = store.byGmail.get(normalizeGmail(gmail));
  if (rec && rec.otp && rec.otp.purpose === purpose) rec.otp = null;
}

// Verify an OTP. On success the OTP is consumed and a reset token is
// issued. Returns { ok: true, token } or
// { ok: false, error: 'NONE' | 'EXPIRED' | 'WRONG' | 'DEAD' | 'BAD_CODE',
//   triesLeft? }.
function verifyOtp(store, purpose, gmail, code, nowMs) {
  const g = normalizeGmail(gmail);
  const now = Number(nowMs) || 0;
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return { ok: false, error: 'BAD_CODE' };
  }
  const rec = store.byGmail.get(g);
  if (!rec || !rec.otp || rec.otp.purpose !== purpose) {
    return { ok: false, error: 'NONE' };
  }
  const otp = rec.otp;
  if (otp.expiresAt <= now) {
    rec.otp = null;
    return { ok: false, error: 'EXPIRED' };
  }
  if (sha256Hex(otp.salt + '|' + code) !== otp.codeHash) {
    otp.triesLeft -= 1;
    if (otp.triesLeft <= 0) {
      rec.otp = null;
      rec.cooldownUntil = now + OTP_COOLDOWN_MS;
      return { ok: false, error: 'DEAD', triesLeft: 0 };
    }
    return { ok: false, error: 'WRONG', triesLeft: otp.triesLeft };
  }
  rec.otp = null;
  const token = randomToken();
  store.tokens.set(sha256Hex(token), {
    gmail: g,
    purpose,
    expiresAt: now + TOKEN_TTL_MS,
  });
  return { ok: true, token };
}

// Consume a reset token (single use). Returns { ok: true, gmail } or
// { ok: false, error: 'BAD_TOKEN' | 'EXPIRED' | 'WRONG_PURPOSE' }.
function consumeToken(store, token, purpose, nowMs) {
  const now = Number(nowMs) || 0;
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) {
    return { ok: false, error: 'BAD_TOKEN' };
  }
  const rec = store.tokens.get(sha256Hex(token));
  if (!rec) return { ok: false, error: 'BAD_TOKEN' };
  store.tokens.delete(sha256Hex(token));
  if (rec.expiresAt <= now) return { ok: false, error: 'EXPIRED' };
  if (rec.purpose !== purpose) return { ok: false, error: 'WRONG_PURPOSE' };
  return { ok: true, gmail: rec.gmail };
}

module.exports = {
  OTP_TTL_MS,
  OTP_MAX_TRIES,
  OTP_COOLDOWN_MS,
  OTP_MAX_PER_HOUR,
  OTP_MIN_GAP_MS,
  TOKEN_TTL_MS,
  sha256Hex,
  randomOtpCode,
  randomToken,
  normalizeGmail,
  createOtpStore,
  issueOtp,
  noteOtpSent,
  revokeOtp,
  verifyOtp,
  consumeToken,
};
