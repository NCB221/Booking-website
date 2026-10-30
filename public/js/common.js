// Ham dung chung cho toan bo frontend

/**
 * Escape HTML truoc khi nhet vao innerHTML (chong XSS).
 * Vi du: ten hanh khach "<img src=x onerror=alert(1)>" se hien thi
 * nhu van ban thuong thay vi bi thuc thi.
 */
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

function money(n) {
  return new Intl.NumberFormat('vi-VN').format(Math.round(Number(n))) + ' đ';
}

function pad(n) { return String(n).padStart(2, '0'); }

// "2026-10-20 06:30:00" -> gio HH:mm
function hhmm(dt) {
  const d = new Date(dt.replace(' ', 'T'));
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// -> "20/10/2026"
function dateLabel(dt) {
  const d = new Date(dt.replace(' ', 'T'));
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
}

function duration(a, b) {
  const mins = Math.round((new Date(b.replace(' ', 'T')) - new Date(a.replace(' ', 'T'))) / 60000);
  const h = Math.floor(mins / 60), m = mins % 60;
  return `${h}h${m ? pad(m) : '00'}`;
}

function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function toast(msg, type = 'ok') {
  let el = document.getElementById('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.className = 'toast show ' + (type === 'err' ? 'err' : type === 'ok' ? 'ok' : '');
  el.textContent = msg;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = 'toast'; }, 3200);
}

/* ===============================================================
 * CHU KY HMAC-SHA256 - dam bao toan ven du lieu truyen di
 *
 * Moi request duoc ky tren chuoi chuan hoa:
 *   v2 \n METHOD \n PATH \n TIMESTAMP \n NONCE \n REQUEST_ID \n SHA256(body)
 * Server tinh lai chu ky; lech mot byte la tu choi.
 * Response cung duoc server ky, client xac minh lai o duoi.
 * request_id nam trong chu ky nen khong the bi sua tren duong truyen -
 * dieu nay quan trong vi no la ma doi chieu trong nhat ky audit.
 * ===============================================================*/

const SIG_VERSION = 'v2';

// --- Tien ich ma hoa (dung Web Crypto san co cua trinh duyet) ---

function bytesToB64url(buf) {
  const arr = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlToBytes(str) {
  const b64 = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text || ''));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSign(signingKeyB64url, message) {
  const key = await crypto.subtle.importKey(
    'raw', b64urlToBytes(signingKeyB64url),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return bytesToB64url(sig);
}

function randomNonce() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function buildCanonical(method, path, timestamp, nonce, requestId, bodyHash) {
  return [SIG_VERSION, method.toUpperCase(), path,
    String(timestamp), String(nonce), String(requestId || ''), bodyHash].join('\n');
}

/** Sinh request_id (UUID v4) de doi chieu voi nhat ky audit cua server. */
function newRequestId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

// --- Quan ly phien khach (lay khoa ky tu server) ---

const SESSION_STORE_KEY = 'clientSession';
let clientSession = null;

function loadStoredSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_STORE_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw);
    // Con it nhat 60s moi dung tiep
    if (s && s.exp && s.exp - 60 > Date.now() / 1000) return s;
  } catch { /* sessionStorage co the bi chan */ }
  return null;
}

/**
 * Lay (hoac tao moi) phien khach kem khoa ky.
 * Khoa ky la rieng cho tung phien va het han sau 1 gio -> khong co
 * khoa tinh nao bi nhung san trong ma nguon.
 */
async function ensureClientSession() {
  if (clientSession && clientSession.exp - 60 > Date.now() / 1000) return clientSession;

  const stored = loadStoredSession();
  if (stored) { clientSession = stored; return clientSession; }

  // Request bootstrap nay khong the ky (chua co khoa)
  const res = await fetch('/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) throw new Error('Khong lay duoc phien lam viec tu server');
  const d = await res.json();

  clientSession = {
    token: d.client_token,
    signingKey: d.signing_key,
    exp: Math.floor(Date.now() / 1000) + d.expires_in,
  };
  try {
    sessionStorage.setItem(SESSION_STORE_KEY, JSON.stringify(clientSession));
  } catch { /* bo qua neu khong luu duoc */ }
  return clientSession;
}

function clearClientSession() {
  clientSession = null;
  try { sessionStorage.removeItem(SESSION_STORE_KEY); } catch { /* bo qua */ }
}

/** Thong tin dang nhap admin do admin.js nap vao (neu dang o trang quan tri). */
const AdminCreds = { token: null, signingKey: null };

/* ---------------------------------------------------------------
 * api() - goi API kem chu ky, va xac minh chu ky cua response
 * -------------------------------------------------------------*/
async function api(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const body = options.body || null;

  // Chon bo thong tin phien: admin dung khoa rieng sau khi dang nhap
  let token, signingKey, tokenHeader;
  if (options.admin) {
    if (!AdminCreds.token) throw new Error('Phien dang nhap khong hop le hoac da het han');
    token = AdminCreds.token;
    signingKey = AdminCreds.signingKey;
    tokenHeader = 'Authorization';
    token = `Bearer ${token}`;
  } else {
    const s = await ensureClientSession();
    token = s.token;
    signingKey = s.signingKey;
    tokenHeader = 'X-Client-Token';
  }

  // --- Ky request (request_id nam trong chu ky) ---
  const requestId = newRequestId();
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomNonce();
  const bodyHash = await sha256Hex(body || '');
  const signature = await hmacSign(
    signingKey, buildCanonical(method, url, timestamp, nonce, requestId, bodyHash)
  );

  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      [tokenHeader]: token,
      'X-Request-Id': requestId,
      'X-Timestamp': String(timestamp),
      'X-Nonce': nonce,
      'X-Signature': signature,
      ...(options.headers || {}),
    },
  });

  const text = await res.text();

  // --- Xac minh chu ky cua response ---
  const resSig = res.headers.get('X-Signature');
  const resTs = res.headers.get('X-Timestamp');
  if (resSig && resTs) {
    const expected = await hmacSign(
      signingKey,
      buildCanonical(method, url, resTs, '-', requestId, await sha256Hex(text))
    );
    if (expected !== resSig) {
      console.error('[SIG] Chu ky response khong khop', { url });
      throw new Error('Du lieu phan hoi khong toan ven (chu ky khong khop)');
    }
  } else if (res.ok) {
    // Response thanh cong BAT BUOC phai co chu ky -> chong tan cong
    // go bo header de qua buoc kiem tra.
    console.error('[SIG] Response thanh cong nhung thieu chu ky', { url });
    throw new Error('Phan hoi thieu chu ky xac thuc');
  }

  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* khong phai JSON */ }

  if (!res.ok) {
    // Phien het han -> xoa de lan sau tu dong lay phien moi
    if (res.status === 401 && !options.admin) clearClientSession();
    throw new Error((data && data.error) || `Loi ${res.status}`);
  }
  return data;
}
