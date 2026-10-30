/**
 * Chu ky HMAC-SHA256 cho request/response de dam bao TINH VEN TOAN du lieu.
 *
 * Chuoi chuan hoa (canonical string) duoc ky:
 *   v2 \n METHOD \n PATH?QUERY \n TIMESTAMP \n NONCE \n REQUEST_ID \n SHA256_HEX(body)
 *
 * Client gui kem 4 header:
 *   X-Request-Id : ma dinh danh request (nam trong chu ky -> khong sua duoc)
 *   X-Timestamp  : unix seconds
 *   X-Nonce      : chuoi ngau nhien, dung DUNG MOT LAN
 *   X-Signature  : base64url(HMAC-SHA256(signing_key, canonical))
 *
 * Bao ve:
 *  - Sua doi du lieu tren duong truyen -> chu ky khong con khop
 *  - Replay (gui lai request cu)       -> timestamp qua han hoac nonce da dung
 *  - Doi endpoint/method               -> method & path nam trong chuoi ky
 *
 * LUU Y: signing_key duoc phat rieng cho tung phien va co thoi han
 * (xem deriveSigningKey). Day KHONG phai thay the HTTPS.
 */
const crypto = require('crypto');

const VERSION = 'v2';
// Cua so cho phech lech dong ho giua client va server
const MAX_SKEW_SECONDS = 300; // 5 phut
// Gioi han bo nho cua kho nonce (chong tan cong lam can bo nho - API4)
const MAX_NONCE_ENTRIES = 100000;

/* ---------------------------------------------------------------
 * Khoa ky rieng theo phien
 * -------------------------------------------------------------*/

function getSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 32) {
    throw new Error('SESSION_SECRET thieu hoac qua ngan (can >= 32 ky tu)');
  }
  return s;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Sinh khoa ky tu jti cua token phien.
 * Stateless: server tinh lai duoc tu token, khong can luu DB.
 * Moi phien -> mot khoa khac nhau; token het han -> khoa vo dung.
 */
function deriveSigningKey(jti) {
  return b64url(
    crypto.createHmac('sha256', getSecret()).update(`sig:${jti}`).digest()
  );
}

/* ---------------------------------------------------------------
 * Chuoi chuan hoa + tinh chu ky
 * -------------------------------------------------------------*/

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf || Buffer.alloc(0)).digest('hex');
}

function buildCanonical({ method, path, timestamp, nonce, requestId, bodyHash }) {
  return [VERSION, String(method).toUpperCase(), path,
    String(timestamp), String(nonce), String(requestId || ''), bodyHash].join('\n');
}

function computeSignature(signingKey, canonical) {
  const keyBytes = Buffer.from(signingKey, 'base64url');
  return b64url(crypto.createHmac('sha256', keyBytes).update(canonical, 'utf8').digest());
}

function signaturesMatch(a, b) {
  const ba = Buffer.from(String(a ?? ''), 'utf8');
  const bb = Buffer.from(String(b ?? ''), 'utf8');
  // Hash truoc de do dai luon bang nhau -> timingSafeEqual khong nem loi
  const ha = crypto.createHash('sha256').update(ba).digest();
  const hb = crypto.createHash('sha256').update(bb).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/* ---------------------------------------------------------------
 * Kho nonce: moi nonce chi dung duoc 1 lan (chong replay)
 * -------------------------------------------------------------*/

const usedNonces = new Map(); // nonce -> thoi diem het han (ms)

function pruneNonces(now) {
  for (const [nonce, exp] of usedNonces) {
    if (exp <= now) usedNonces.delete(nonce);
  }
}

/** Tra true neu nonce con moi (va danh dau da dung). */
function consumeNonce(nonce, now) {
  if (usedNonces.has(nonce)) return false;

  if (usedNonces.size >= MAX_NONCE_ENTRIES) {
    pruneNonces(now);
    if (usedNonces.size >= MAX_NONCE_ENTRIES) return false; // qua tai -> tu choi
  }
  // Giu nonce den khi timestamp cua no chac chan het han
  usedNonces.set(nonce, now + (MAX_SKEW_SECONDS + 60) * 1000);
  return true;
}

// Don dep dinh ky
const sweeper = setInterval(() => pruneNonces(Date.now()), 60 * 1000);
sweeper.unref(); // khong giu process song

/* ---------------------------------------------------------------
 * Xac minh chu ky cua request
 * -------------------------------------------------------------*/

/**
 * @returns {{ok: true} | {ok: false, status: number, error: string}}
 */
function verifyRequestSignature(req, signingKey) {
  const timestamp = req.get('x-timestamp');
  const nonce = req.get('x-nonce');
  const signature = req.get('x-signature');

  if (!timestamp || !nonce || !signature) {
    return { ok: false, status: 400, error: 'Thieu chu ky request (X-Timestamp / X-Nonce / X-Signature)' };
  }
  // request_id phai do client gui va nam trong chu ky, de nhat ky audit
  // ghi lai dung ma dinh danh ma client da ky (khong the sua giua duong).
  if (req.requestIdSource !== 'client') {
    return { ok: false, status: 400, error: 'Thieu header X-Request-Id' };
  }
  if (!/^\d{1,15}$/.test(timestamp)) {
    return { ok: false, status: 400, error: 'X-Timestamp khong hop le' };
  }
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) {
    return { ok: false, status: 400, error: 'X-Nonce khong hop le' };
  }

  // 1. Chong replay theo thoi gian
  const now = Date.now();
  const skew = Math.abs(Math.floor(now / 1000) - Number(timestamp));
  if (skew > MAX_SKEW_SECONDS) {
    return { ok: false, status: 401, error: 'Request da qua han (lech thoi gian qua lon)' };
  }

  // 2. Kiem tra chu ky TRUOC khi tieu thu nonce, de ke tan cong khong the
  //    "dot" nonce hop le cua nguoi dung bang chu ky rac.
  const bodyHash = sha256Hex(req.rawBody);
  const canonical = buildCanonical({
    method: req.method,
    path: req.originalUrl,
    timestamp, nonce,
    requestId: req.requestId,
    bodyHash,
  });

  if (!signaturesMatch(signature, computeSignature(signingKey, canonical))) {
    return { ok: false, status: 401, error: 'Chu ky khong hop le: du lieu co the da bi sua doi' };
  }

  // 3. Nonce chi dung mot lan
  if (!consumeNonce(nonce, now)) {
    return { ok: false, status: 409, error: 'Request da duoc gui truoc do (replay bi chan)' };
  }

  return { ok: true };
}

/* ---------------------------------------------------------------
 * Ky response de client xac minh du lieu nhan ve
 * -------------------------------------------------------------*/

function signResponseBody(signingKey, { method, path, timestamp, requestId, body }) {
  const canonical = buildCanonical({
    method, path, timestamp,
    nonce: '-', // response khong can nonce
    requestId,  // rang buoc response voi dung request da gui
    bodyHash: sha256Hex(Buffer.from(body, 'utf8')),
  });
  return computeSignature(signingKey, canonical);
}

module.exports = {
  deriveSigningKey,
  verifyRequestSignature,
  signResponseBody,
  computeSignature,
  buildCanonical,
  sha256Hex,
  MAX_SKEW_SECONDS,
  // chi dung cho test
  _usedNonces: usedNonces,
};
