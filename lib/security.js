/**
 * Cac tien ich bao mat dung chung:
 *  - Token phien co han cho admin (HMAC-SHA256), thay vi gui master key moi request
 *  - So sanh chuoi chong timing attack
 *  - Validate / lam sach dau vao
 *
 * Tham chieu: OWASP API Security Top 10 (2023) - API2, API3, API4, API8.
 */
const crypto = require('crypto');

const TOKEN_TTL_SECONDS = 2 * 60 * 60; // token admin song 2 gio

// --- So sanh chong timing attack (API2) ---

/**
 * So sanh 2 chuoi bang thoi gian hang so.
 * Dung cho ADMIN_KEY / chu ky token de khong lo thong tin qua thoi gian phan hoi.
 */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a ?? ''), 'utf8');
  const bb = Buffer.from(String(b ?? ''), 'utf8');
  // timingSafeEqual yeu cau 2 buffer cung do dai.
  // Hash truoc de do dai luon bang nhau -> khong lo do dai chuoi.
  const ha = crypto.createHash('sha256').update(ba).digest();
  const hb = crypto.createHash('sha256').update(bb).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// --- Token phien admin (API2) ---

function getSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 32) {
    throw new Error(
      'SESSION_SECRET thieu hoac qua ngan (can >= 32 ky tu). Tao moi: npm run gen-key'
    );
  }
  return s;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  return Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function hmac(data) {
  return b64url(crypto.createHmac('sha256', getSecret()).update(data).digest());
}

// Token phien cho khach (chi de ky request), song ngan hon token admin
const CLIENT_TTL_SECONDS = 60 * 60; // 1 gio

/**
 * Tao token phien co thoi han.
 * @param {'admin'|'client'} role
 */
function issueToken(role) {
  const now = Math.floor(Date.now() / 1000);
  const ttl = role === 'admin' ? TOKEN_TTL_SECONDS : CLIENT_TTL_SECONDS;
  const payload = {
    role,
    iat: now,
    exp: now + ttl,
    jti: crypto.randomBytes(12).toString('hex'),
  };
  const body = b64url(JSON.stringify(payload));
  return {
    token: `${body}.${hmac(body)}`,
    jti: payload.jti,
    expires_in: ttl,
  };
}

/**
 * Kiem tra token. Tra payload neu hop le, nguoc lai tra null.
 * @param {string} token
 * @param {'admin'|'client'} [expectedRole] - bo trong = nhan moi role
 */
function verifyToken(token, expectedRole) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [body, sig] = parts;
  if (!safeEqual(sig, hmac(body))) return null; // chu ky sai / bi sua

  let payload;
  try {
    payload = JSON.parse(b64urlDecode(body).toString('utf8'));
  } catch {
    return null;
  }
  if (payload.role !== 'admin' && payload.role !== 'client') return null;
  if (expectedRole && payload.role !== expectedRole) return null;
  if (typeof payload.jti !== 'string' || !payload.jti) return null;
  if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) {
    return null; // het han
  }
  return payload;
}

// Giu ten cu cho tuong thich
const issueAdminToken = () => issueToken('admin');
const verifyAdminToken = (token) => verifyToken(token, 'admin');

// --- Validate dau vao (API3 / API8) ---

const RE = {
  airport: /^[A-Z]{3}$/,
  date: /^\d{4}-\d{2}-\d{2}$/,
  datetime: /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$/,
  bookingCode: /^[A-Z0-9]{4,12}$/,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,
  phone: /^0\d{9,10}$/,
  cccd: /^(\d{9}|\d{12})$/,
  flightNumber: /^[A-Z0-9]{2,10}$/i,
  // Ho ten: chu cai Unicode (ke ca tieng Viet co dau), dau cach, ' . -
  name: /^[\p{L}\p{M}\s'.-]{2,120}$/u,
  // Ten hang bay: chu, so, dau cach va mot so dau cau thong thuong.
  // KHONG cho < > " ` de khong luu duoc payload XSS vao database (du frontend
  // da escape khi hien thi - phong truong hop sau nay co cho render thieu escape).
  airline: /^[\p{L}\p{M}\p{N}\s.\-&()/']{2,80}$/u,
};

/** Gioi han so nguyen trong [min, max]; tra def neu khong parse duoc. */
function clampInt(value, min, max, def) {
  const n = parseInt(value, 10);
  if (Number.isNaN(n)) return def;
  return Math.min(max, Math.max(min, n));
}

/** Bo ky tu dieu khien va cat bot khoang trang. */
function cleanText(value, maxLen = 200) {
  return String(value ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim()
    .slice(0, maxLen);
}

/** Kiem tra chuoi ngay that su hop le (chan 2026-02-31). */
function isValidDate(str) {
  if (!RE.date.test(str)) return false;
  const d = new Date(str + 'T00:00:00Z');
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === str;
}

module.exports = {
  safeEqual,
  issueToken,
  verifyToken,
  issueAdminToken,
  verifyAdminToken,
  TOKEN_TTL_SECONDS,
  CLIENT_TTL_SECONDS,
  RE,
  clampInt,
  cleanText,
  isValidDate,
};
