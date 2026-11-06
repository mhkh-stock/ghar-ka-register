// Personal Card Vault — on-device OCR (browser + Node tests).
// One module, two uses: (1) read the total amount off a screenshot of the
// account (Add page verification), (2) read the text off a bank SMS
// screenshot (Intelligence, when there is no time to paste).
//
// HARD RULE: OCR runs 100% ON-DEVICE. The image is NEVER sent to any
// server or external OCR service — that would leak bank SMS content. The
// engine is Tesseract.js v5.1.1, VENDORED as local files under
// public/vendor/tesseract/ (tesseract.min.js, worker.min.js,
// tesseract-core.wasm.js/.wasm, eng.traineddata — the "fast" English
// model, ~12 MB total) and loaded ON DEMAND only, from this same origin.
// No CDN dependency, no external request on the OCR path. The app stays
// zero-dependency server-side; the vendor files are served as static
// files by server.js. First use takes a few seconds while the engine
// loads; later screenshots reuse the same worker.
//
// OCR is not perfect: it misreads characters on real phone photos. The
// module never guesses an amount — extractScreenshotAmount returns
// 'none' / 'ambiguous' unless exactly ONE clear amount is found, and the
// SMS path always shows the review card before anything is saved.
// Pure functions where possible; the Tesseract wrapper is injectable so
// Node tests can stub the engine (a real browser run is the final check
// for the engine itself).
'use strict';

const Proof = (typeof window !== 'undefined' && window.Proof)
  || (typeof module !== 'undefined' && module.exports ? require('./proof.js') : null);
const SmsParser = (typeof window !== 'undefined' && window.SmsParser)
  || (typeof module !== 'undefined' && module.exports ? require('./sms.js') : null);

const VENDOR_BASE = '/vendor/tesseract/';
const OCR_FILES = [
  'tesseract.min.js', 'worker.min.js', 'tesseract-core.wasm.js',
  'tesseract-core.wasm', 'eng.traineddata',
];

// A screenshot for verification must be a photo (JPEG/PNG), under the
// same 500 KB cap as statement proof. A PDF belongs in the statement
// box, not here.
function validateScreenshotFile(dataUrl, sizeBytes) {
  const base = Proof.validateProofData(dataUrl, sizeBytes);
  if (!base.ok) return base;
  if (base.kind !== 'image') {
    return {
      ok: false,
      errors: ['Upload a screenshot photo (JPEG or PNG) here — a statement PDF goes in the statement box.'],
      kind: base.kind,
    };
  }
  return base;
}

// Collapse OCR line breaks to spaces — amounts and labels are matched on
// one line. Then repair the two OCR artefacts that show up in money
// amounts and nowhere else: a space after a thousands comma ("47, 500"
// -> "47,500") and the letter O for a zero inside an Rs/PKR amount
// ("Rs 47,5O0" -> "Rs 47,500"). Both repairs are narrow — they only fire
// inside a currency amount token — and anything else is left alone, so a
// bad read still fails plainly instead of being guessed.
function normalizeOcrText(text) {
  let t = String(text || '').replace(/\s+/g, ' ').trim();
  t = t.replace(/(\d), (\d{3})\b/g, '$1,$2');
  t = t.replace(/((?:Rs\.?|PKR)\s*[\d,]*)([Oo])(?=[\d,])/g, function (_m, head) { return head + '0'; });
  return t;
}

// The total amount off a screenshot: exactly ONE clear balance amount,
// or 'none' / 'ambiguous' — never a guess. Reuses the statement balance
// extractor (same "available balance / closing balance / balance" rules),
// so a screenshot and a statement are judged by the same standard.
function extractScreenshotAmount(text) {
  return Proof.extractStatementBalance(normalizeOcrText(text));
}

// An SMS screenshot read as text goes through the EXISTING parser, so a
// screenshot and a paste produce the same draft. Garbage / OTP -> null,
// exactly as pasting does.
function parseSmsFromOcrText(text) {
  return SmsParser.parseSms(text);
}

// ---- Tesseract wrapper (browser only) ----
let _workerPromise = null;
function loadScriptOnce(src) {
  return new Promise(function (resolve, reject) {
    const s = document.createElement('script');
    s.src = src;
    s.onload = function () { resolve(); };
    s.onerror = function () { reject(new Error('Could not load the on-device OCR engine.')); };
    document.head.appendChild(s);
  });
}
async function createOcrWorker() {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    throw new Error('OCR runs in the browser — the image never leaves this device.');
  }
  if (!window.Tesseract) await loadScriptOnce(VENDOR_BASE + 'tesseract.min.js');
  // One worker for the life of the page: creating it loads the engine
  // (~8 MB) and the language data (~4 MB) from this same origin.
  const worker = await window.Tesseract.createWorker('eng', 1, {
    workerPath: VENDOR_BASE + 'worker.min.js',
    corePath: VENDOR_BASE + 'tesseract-core.wasm.js',
    langPath: VENDOR_BASE,
    gzip: false, // the vendored language data is a plain .traineddata file
  });
  return worker;
}
// Read the text off an image (File / Blob / data URL). `engine` is an
// injectable stub for tests — the real engine is the vendored Tesseract
// worker, loaded on demand. Returns the raw OCR text ('' when nothing
// was read). The image is never uploaded anywhere.
async function recognizeImage(image, engine) {
  if (engine) {
    const out = await engine(image);
    return typeof out === 'string' ? out : (out && out.text) || '';
  }
  if (!_workerPromise) _workerPromise = createOcrWorker();
  let worker;
  try { worker = await _workerPromise; }
  catch (e) { _workerPromise = null; throw e; } // a failed load must not poison later tries
  const result = await worker.recognize(image);
  return (result && result.data && result.data.text) || '';
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    VENDOR_BASE, OCR_FILES,
    validateScreenshotFile, normalizeOcrText, extractScreenshotAmount,
    parseSmsFromOcrText, recognizeImage,
  };
}
if (typeof window !== 'undefined') {
  window.Ocr = {
    VENDOR_BASE, OCR_FILES,
    validateScreenshotFile, normalizeOcrText, extractScreenshotAmount,
    parseSmsFromOcrText, recognizeImage,
  };
}
