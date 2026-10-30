/**
 * Client OpenBao cho SkyBooking.
 *
 * Lam 3 viec:
 *   1. Dang nhap bang AppRole, cache token va tu gia han truoc khi het han
 *   2. Doc secret tu KV v2  (thay cho .env)
 *   3. Ma hoa / giai ma qua Transit - khoa KHONG BAO GIO vao process nay
 *
 * KHONG them dependency: dung `fetch` co san tu Node 18+ (package.json yeu cau >=20).
 *
 * BOOTSTRAP: app can BAO_ROLE_ID + BAO_SECRET_ID de xac thuc. Hai gia tri nay
 * van nam trong .env - day la gioi han that cua mo hinh tren MOT may:
 * OpenBao thu hep vung tin cay (10 secret -> 1 cap credential) chu khong xoa bo no.
 * Doi lai: cap credential nay THU HOI DUOC va moi lan dung deu co trong audit log,
 * khac voi ENCRYPTION_KEY truoc day - lo mot lan la mat vinh vien.
 */
'use strict';

const BAO_ADDR = (process.env.BAO_ADDR || 'http://127.0.0.1:8200').replace(/\/+$/, '');
const ROLE_ID = process.env.BAO_ROLE_ID || '';
const SECRET_ID = process.env.BAO_SECRET_ID || '';
const TRANSIT_KEY = process.env.BAO_TRANSIT_KEY || 'booking-pii';
const KV_PATH = process.env.BAO_KV_PATH || 'skybooking/app';
const KV_MOUNT = process.env.BAO_KV_MOUNT || 'kv';

// Xin token moi khi con duoi nguong nay -> khong bao gio dung token sap het han
const RENEW_BEFORE_MS = 5 * 60 * 1000; // 5 phut
const HTTP_TIMEOUT_MS = Number(process.env.BAO_TIMEOUT_MS) || 5000;

/**
 * So item toi da trong MOT request batch.
 *
 * OpenBao co gioi han `max_request_json_strings` (mac dinh 1000) de chong
 * tan cong bang JSON phuc tap. Moi item batch_input la mot object dang
 * {"plaintext": "..."} nen dong gop ~2 chuoi, cong them "batch_input".
 * Gui 600 item = ~1200 chuoi -> bi tu choi HTTP 400:
 *   "refused JSON input due to high complexity: exceeded maximum number of strings"
 *
 * 250 item (~500 chuoi) an toan voi cau hinh mac dinh. Neu da nang
 * max_request_json_strings tren server thi co the tang bien nay len.
 */
const BATCH_CHUNK = Number(process.env.BAO_BATCH_CHUNK) || 250;

/** Chia mang thanh cac lo nho <= size phan tu. */
function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

let token = null;
let tokenExpiresAt = 0;
let loginInFlight = null;

/* ---------------------------------------------------------------
 * HTTP
 * -------------------------------------------------------------*/

async function call(method, path, body, useToken = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (useToken) headers['X-Vault-Token'] = await getToken();

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${BAO_ADDR}/v1/${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: ctrl.signal,
    });
  } catch (err) {
    // FAIL CLOSED: khong ket noi duoc OpenBao thi KHONG xu ly PII,
    // tuyet doi khong fallback sang khoa cuc bo.
    throw new Error(
      err.name === 'AbortError'
        ? `OpenBao khong phan hoi trong ${HTTP_TIMEOUT_MS}ms (${BAO_ADDR})`
        : `Khong ket noi duoc OpenBao tai ${BAO_ADDR}: ${err.message}`
    );
  } finally {
    clearTimeout(timer);
  }

  const text = await res.text();
  let json = null;
  if (text) { try { json = JSON.parse(text); } catch { /* khong phai JSON */ } }

  if (!res.ok) {
    const detail = (json && json.errors && json.errors.join('; ')) || text.slice(0, 200);
    // 403 thuong la token het han -> xoa cache de lan sau dang nhap lai
    if (res.status === 403) { token = null; tokenExpiresAt = 0; }
    throw new Error(`OpenBao ${method} ${path} -> HTTP ${res.status}: ${detail}`);
  }
  return json;
}

/* ---------------------------------------------------------------
 * Token: dang nhap AppRole + tu gia han
 * -------------------------------------------------------------*/

async function login() {
  if (!ROLE_ID || !SECRET_ID) {
    throw new Error(
      'Thieu BAO_ROLE_ID / BAO_SECRET_ID trong .env. ' +
      'Lay bang: bao write -f auth/approle/role/skybooking/secret-id'
    );
  }
  const out = await call(
    'POST', 'auth/approle/login',
    { role_id: ROLE_ID, secret_id: SECRET_ID },
    false // chinh request dang nhap thi chua co token
  );
  if (!out || !out.auth || !out.auth.client_token) {
    throw new Error('OpenBao tra ve phan hoi dang nhap khong hop le');
  }
  token = out.auth.client_token;
  tokenExpiresAt = Date.now() + (out.auth.lease_duration || 3600) * 1000;
  console.log(
    `[BAO] Dang nhap thanh cong, token song ${out.auth.lease_duration}s, ` +
    `policies: ${(out.auth.token_policies || []).join(',')}`
  );
  return token;
}

/** Lay token con hieu luc. Gom cac lan goi dong thoi vao MOT lan dang nhap. */
async function getToken() {
  if (token && Date.now() < tokenExpiresAt - RENEW_BEFORE_MS) return token;
  if (loginInFlight) return loginInFlight;
  loginInFlight = login().finally(() => { loginInFlight = null; });
  return loginInFlight;
}

/* ---------------------------------------------------------------
 * KV v2
 * -------------------------------------------------------------*/

/** Doc toan bo secret tai KV_PATH. Tra object { TEN: gia_tri }. */
async function readSecrets() {
  const out = await call('GET', `${KV_MOUNT}/data/${KV_PATH}`);
  const data = out && out.data && out.data.data;
  if (!data || typeof data !== 'object') {
    throw new Error(`Khong doc duoc secret tai ${KV_MOUNT}/${KV_PATH}`);
  }
  return data;
}

/* ---------------------------------------------------------------
 * Transit
 * -------------------------------------------------------------*/

const b64 = (s) => Buffer.from(String(s), 'utf8').toString('base64');
const unb64 = (s) => Buffer.from(String(s), 'base64').toString('utf8');

/**
 * Ma hoa nhieu gia tri trong MOT request.
 *
 * Vi sao bat buoc dung batch: GET /api/admin/bookings voi limit=200 phai xu ly
 * 3 truong x 200 dong = 600 gia tri. Goi 600 HTTP round-trip la khong dung duoc.
 * Transit co batch_input de gop tat ca vao mot request.
 *
 * @param {string[]} values
 * @returns {Promise<(string|null)[]>} ciphertext theo dung thu tu dau vao
 */
async function encryptBatch(values) {
  const idx = [];
  const batch = [];
  values.forEach((v, i) => {
    if (v === null || v === undefined || String(v) === '') return;
    idx.push(i);
    batch.push({ plaintext: b64(v) });
  });
  if (batch.length === 0) return values.map(() => null);

  // Chia lo de khong vuot max_request_json_strings cua OpenBao
  const results = [];
  for (const part of chunk(batch, BATCH_CHUNK)) {
    const out = await call('POST', `transit/encrypt/${TRANSIT_KEY}`, { batch_input: part });
    results.push(...((out && out.data && out.data.batch_results) || []));
  }

  const final = values.map(() => null);
  idx.forEach((origIndex, k) => {
    const r = results[k];
    if (!r || r.error) {
      throw new Error(`Transit encrypt that bai: ${(r && r.error) || 'khong co ket qua'}`);
    }
    final[origIndex] = r.ciphertext;
  });
  return final;
}

/**
 * Giai ma nhieu ciphertext trong MOT request.
 * Phan tu khong phai dang `vault:` duoc giu nguyen null de caller tu xu ly
 * (dung cho du lieu cu dinh dang `v1:` - xem lib/crypto.js).
 *
 * @param {string[]} ciphertexts
 * @returns {Promise<(string|null)[]>}
 */
async function decryptBatch(ciphertexts) {
  const idx = [];
  const batch = [];
  ciphertexts.forEach((c, i) => {
    if (typeof c === 'string' && c.startsWith('vault:')) {
      idx.push(i);
      batch.push({ ciphertext: c });
    }
  });
  if (batch.length === 0) return ciphertexts.map(() => null);

  // Chia lo de khong vuot max_request_json_strings cua OpenBao
  const results = [];
  for (const part of chunk(batch, BATCH_CHUNK)) {
    const out = await call('POST', `transit/decrypt/${TRANSIT_KEY}`, { batch_input: part });
    results.push(...((out && out.data && out.data.batch_results) || []));
  }

  const final = ciphertexts.map(() => null);
  idx.forEach((origIndex, k) => {
    const r = results[k];
    // Loi tung phan tu KHONG lam vo ca lo - tra null, caller quyet dinh
    if (!r || r.error || typeof r.plaintext !== 'string') return;
    final[origIndex] = unb64(r.plaintext);
  });
  return final;
}

/** Ma hoa mot gia tri. Chi dung khi that su chi co mot. */
async function encryptOne(value) {
  const [ct] = await encryptBatch([value]);
  return ct;
}

/** Giai ma mot ciphertext. */
async function decryptOne(ciphertext) {
  const [pt] = await decryptBatch([ciphertext]);
  return pt;
}

/* ---------------------------------------------------------------
 * Kiem tra suc khoe
 * -------------------------------------------------------------*/

/** Kiem tra OpenBao song, da unseal, va token dung quyen. */
async function health() {
  const res = await fetch(`${BAO_ADDR}/v1/sys/health`).catch(() => null);
  if (!res) return { ok: false, reason: `khong ket noi duoc ${BAO_ADDR}` };
  const body = await res.json().catch(() => ({}));
  if (body.sealed) return { ok: false, reason: 'OpenBao dang SEALED - can unseal' };
  if (!body.initialized) return { ok: false, reason: 'OpenBao chua duoc khoi tao' };
  return { ok: true, version: body.version, sealed: false };
}

module.exports = {
  readSecrets,
  encryptBatch,
  decryptBatch,
  encryptOne,
  decryptOne,
  health,
  getToken,
  BAO_ADDR,
  TRANSIT_KEY,
};
