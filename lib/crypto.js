/**
 * Ma hoa / giai ma du lieu ca nhan.
 *
 * TRUOC: AES-256-GCM cuc bo, khoa 32 byte doc tu ENCRYPTION_KEY va cache trong
 *        bien `cachedKey` cua process. Doc duoc .env hoac dump duoc RAM la giai
 *        ma duoc toan bo PII, vinh vien, khong thu hoi duoc.
 *
 * NAY:   Goi OpenBao Transit. Khoa nam trong OpenBao va KHONG BAO GIO vao
 *        process nay. App chi co token - thu hoi duoc, rate-limit duoc, va moi
 *        lan ma hoa/giai ma deu nam trong audit log cua OpenBao.
 *
 * HAI DINH DANG CUNG TON TAI trong giai doan chuyen doi:
 *   v1:<iv>:<tag>:<ct>   - du lieu CU, giai ma cuc bo bang ENCRYPTION_KEY
 *   vault:v1:<...>       - du lieu MOI qua Transit
 * Doc ho tro ca hai; GHI luon dung Transit. Sau khi chay db/migrateToBao.js
 * va xac nhan khong con dong `v1:` nao thi co the bo ENCRYPTION_KEY.
 *
 * THAY DOI PHA VO TUONG THICH: encrypt / decrypt / decryptSafe gio la ASYNC.
 */
'use strict';

const crypto = require('crypto');
const bao = require('./bao');

const ALGO = 'aes-256-gcm';
const LEGACY_VERSION = 'v1';

let cachedLegacyKey = null;

/* ---------------------------------------------------------------
 * Duong giai ma CU (chi de doc du lieu chua migrate)
 * -------------------------------------------------------------*/

function getLegacyKey() {
  if (cachedLegacyKey) return cachedLegacyKey;
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) {
    throw new Error(
      'Gap du lieu dinh dang cu (v1:) nhung thieu ENCRYPTION_KEY. ' +
      'Giu lai bien nay cho den khi chay xong: node db/migrateToBao.js'
    );
  }
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) {
    throw new Error(`ENCRYPTION_KEY phai la 32 byte base64 (hien tai ${key.length} byte)`);
  }
  cachedLegacyKey = key;
  return key;
}

function decryptLegacy(stored) {
  const parts = String(stored).split(':');
  if (parts.length !== 4 || parts[0] !== LEGACY_VERSION) {
    throw new Error('Du lieu khong dung dinh dang ma hoa');
  }
  const [, ivB64, tagB64, ctB64] = parts;
  const decipher = crypto.createDecipheriv(ALGO, getLegacyKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(ctB64, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

/* ---------------------------------------------------------------
 * Nhan dang dinh dang
 * -------------------------------------------------------------*/

/** Da o dang ma hoa chua (nhan ca hai dinh dang)? Dung cho migration. */
function isEncrypted(value) {
  if (!value || typeof value !== 'string') return false;
  if (value.startsWith('vault:')) return true;
  const parts = value.split(':');
  return parts.length === 4 && parts[0] === LEGACY_VERSION;
}

/** Dinh dang cu, tuc con can migrate? */
function isLegacyFormat(value) {
  return typeof value === 'string'
    && !value.startsWith('vault:')
    && value.startsWith(`${LEGACY_VERSION}:`)
    && value.split(':').length === 4;
}

/* ---------------------------------------------------------------
 * GHI: luon qua Transit
 * -------------------------------------------------------------*/

/** Ma hoa 1 chuoi. Tra null neu dau vao rong. ASYNC. */
async function encrypt(plain) {
  if (plain === null || plain === undefined || String(plain) === '') return null;
  return bao.encryptOne(plain);
}

/**
 * Ma hoa nhieu gia tri trong MOT request toi OpenBao.
 * Dung khi ghi nhieu truong cung luc (vi du 3 truong PII cua mot ve).
 */
async function encryptBatch(values) {
  return bao.encryptBatch(values);
}

/* ---------------------------------------------------------------
 * DOC: ho tro ca hai dinh dang
 * -------------------------------------------------------------*/

/** Giai ma 1 gia tri. Throw neu that bai. ASYNC. */
async function decrypt(stored) {
  if (stored === null || stored === undefined || stored === '') return '';
  if (isLegacyFormat(stored)) return decryptLegacy(stored);
  if (typeof stored === 'string' && stored.startsWith('vault:')) {
    const pt = await bao.decryptOne(stored);
    if (pt === null) throw new Error('Transit khong giai ma duoc gia tri nay');
    return pt;
  }
  throw new Error('Du lieu khong dung dinh dang ma hoa');
}

function reportFailure(err) {
  // require trong ham de tranh vong lap phu thuoc (alerting -> mailer -> crypto)
  const alerting = require('./alerting');
  const line = alerting.summarizeError(
    `crypto:${err.message}`,
    `[CRYPTO] Giai ma that bai: ${err.message}`
  );
  if (line) console.error(line);
  // Sai khoa, du lieu bi sua doi, hoac OpenBao sealed -> bao dong (A09:2025)
  alerting.recordEvent('DECRYPT_FAILED', { detail: err.message });
}

/** Giai ma an toan cho UI: khong lam sap request neu 1 dong bi loi. ASYNC. */
async function decryptSafe(stored) {
  try {
    return await decrypt(stored);
  } catch (err) {
    reportFailure(err);
    return '(khong giai ma duoc)';
  }
}

/**
 * Giai ma MOT LO gia tri, khong bao gio throw.
 *
 * Day la ham quan trong nhat ve hieu nang: GET /api/admin/bookings voi
 * limit=200 can giai ma 3 truong x 200 dong = 600 gia tri. Ham nay gop toan bo
 * phan `vault:` vao MOT request Transit, va xu ly phan `v1:` cu ngay tai local.
 * Goi decryptSafe 600 lan se la 600 HTTP round-trip - khong dung duoc.
 *
 * @param {(string|null)[]} values
 * @returns {Promise<string[]>} cung do dai, cung thu tu voi dau vao
 */
async function decryptBatchSafe(values) {
  const out = new Array(values.length);
  const vaultIdx = [];

  // Buoc 1: xu ly gia tri rong + dinh dang cu ngay tai local
  values.forEach((v, i) => {
    if (v === null || v === undefined || v === '') { out[i] = ''; return; }
    if (isLegacyFormat(v)) {
      try { out[i] = decryptLegacy(v); }
      catch (err) { reportFailure(err); out[i] = '(khong giai ma duoc)'; }
      return;
    }
    if (typeof v === 'string' && v.startsWith('vault:')) { vaultIdx.push(i); return; }
    reportFailure(new Error('Du lieu khong dung dinh dang ma hoa'));
    out[i] = '(khong giai ma duoc)';
  });

  // Buoc 2: gop toan bo phan Transit vao MOT request
  if (vaultIdx.length > 0) {
    try {
      const plain = await bao.decryptBatch(vaultIdx.map((i) => values[i]));
      vaultIdx.forEach((origIndex, k) => {
        out[origIndex] = plain[k] === null ? '(khong giai ma duoc)' : plain[k];
      });
    } catch (err) {
      // Ca lo that bai (OpenBao sealed / mat ket noi) -> FAIL CLOSED:
      // tra placeholder, TUYET DOI khong fallback sang khoa cuc bo.
      reportFailure(err);
      vaultIdx.forEach((i) => { out[i] = '(khong giai ma duoc)'; });
    }
  }

  return out;
}

/* ---------------------------------------------------------------
 * Che bot thong tin (dong bo, khong thay doi)
 * -------------------------------------------------------------*/

function maskEmail(email) {
  if (!email || !email.includes('@')) return '***';
  const [local, domain] = email.split('@');
  const head = local.slice(0, 2);
  return `${head}${'*'.repeat(Math.max(3, local.length - 2))}@${domain}`;
}

function maskPhone(phone) {
  if (!phone) return '***';
  const tail = phone.slice(-3);
  return `${'*'.repeat(Math.max(3, phone.length - 3))}${tail}`;
}

function maskCccd(cccd) {
  if (!cccd) return '***';
  const tail = cccd.slice(-4);
  return `${'*'.repeat(Math.max(4, cccd.length - 4))}${tail}`;
}

module.exports = {
  encrypt,
  encryptBatch,
  decrypt,
  decryptSafe,
  decryptBatchSafe,
  isEncrypted,
  isLegacyFormat,
  maskEmail,
  maskPhone,
  maskCccd,
};
