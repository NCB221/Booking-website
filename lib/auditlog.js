/**
 * Nhat ky API phuc vu audit & dieu tra so (digital forensics).
 *
 * Dac diem:
 *  - Ghi KHONG DONG BO (sau khi response da gui) -> khong lam cham API.
 *  - HASH CHAIN: moi dong luu prev_hash (row_hash cua dong truoc) va row_hash
 *    cua chinh no. Sua hoac xoa bat ky dong nao se lam dut chuoi -> phat hien duoc.
 *  - KHONG luu noi dung body (chua CCCD/email/dien thoai). Chi luu SHA-256 cua body,
 *    du de doi chieu "request nay co dung la ban goc khong" ma khong ro ri PII.
 *
 *  - Luu o DATABASE RIENG (booking_audit) voi 2 user tach quyen:
 *      writer: chi INSERT  -> ung dung khong the sua/xoa log da ghi
 *      reader: chi SELECT  -> nap hash chain, verify, admin xem log
 *
 * Chuoi hash yeu cau DUY NHAT MOT process ghi (vi lastHash giu trong RAM).
 * Neu 2 process cung ghi, chung se cung noi tiep tu mot prev_hash -> chuoi re
 * nhanh va bi bao dut. Vi vay init() giu mot KHOA MySQL (GET_LOCK) suot doi
 * process; instance thu hai se bi tu choi khoi dong thay vi lam hong chuoi.
 */
const crypto = require('crypto');

const GENESIS_HASH = '0'.repeat(64);
// Ky tu phan cach khong xuat hien trong du lieu thuc -> bam khong bi nhap nhang
const FIELD_SEP = '\u001f';
const CHAIN_SEP = '\u001e';

let writerPool = null;  // chi INSERT
let readerPool = null;  // chi SELECT
let lastHash = GENESIS_HASH;
let ready = false;
const queue = [];
let draining = false;
let dropped = 0;

// Chan hang doi phinh to neu database cham (tranh het bo nho)
const MAX_QUEUE = 5000;

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Dinh dang DATETIME(3) cho MySQL: 'YYYY-MM-DD HH:MM:SS.mmm' */
function fmtDateTime(ms) {
  if (ms === null || ms === undefined) return null;
  const d = new Date(ms);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
         `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

/** Cac truong duoc bam, theo DUNG thu tu nay (doi thu tu se lam sai chuoi hash). */
const HASHED_FIELDS = [
  'request_id', 'request_time', 'client_time', 'clock_skew_ms', 'method', 'path',
  'status_code', 'duration_ms', 'ip', 'user_agent', 'actor_role', 'session_jti',
  'signature', 'signature_valid', 'nonce', 'body_sha256', 'body_bytes',
  'response_bytes', 'error_message', 'booking_code',
];

function canonicalRow(e) {
  return HASHED_FIELDS.map((k) => {
    const v = e[k];
    if (v === null || v === undefined) return '';
    if (typeof v === 'boolean') return v ? '1' : '0';
    return String(v);
  }).join(FIELD_SEP);
}

function computeRowHash(prevHash, entry) {
  return sha256Hex(prevHash + CHAIN_SEP + canonicalRow(entry));
}

/**
 * Nap trang thai chuoi hash tu database nhat ky khi khoi dong.
 * Phai goi truoc khi ghi dong dau tien.
 * Doc bang readerPool (chi SELECT), ghi bang writerPool (chi INSERT).
 */
const CHAIN_LOCK_NAME = 'booking_audit_chain_writer';
let lockConn = null;

/**
 * Giu khoa single-writer suot doi process.
 * Tra ve false neu mot process khac dang giu khoa.
 */
async function acquireWriterLock() {
  // Dung ket noi RIENG (khong lay tu pool) vi khoa chi ton tai theo ket noi
  lockConn = await writerPool.getConnection();
  const [[r]] = await lockConn.query('SELECT GET_LOCK(?, 0) g', [CHAIN_LOCK_NAME]);
  if (r.g !== 1) {
    lockConn.release();
    lockConn = null;
    return false;
  }
  return true;
}

async function releaseWriterLock() {
  if (!lockConn) return;
  try {
    await lockConn.query('SELECT RELEASE_LOCK(?)', [CHAIN_LOCK_NAME]);
  } catch { /* ket noi co the da dong */ }
  lockConn.release();
  lockConn = null;
}

async function init() {
  const { getWriterPool, getReaderPool } = require('../db/auditPool');
  writerPool = getWriterPool();
  readerPool = getReaderPool();

  // Bao dam chi mot process ghi vao chuoi hash
  if (!(await acquireWriterLock())) {
    throw new Error(
      'Mot tien trinh khac dang ghi nhat ky audit. Chi duoc chay MOT instance ' +
      'server tai mot thoi diem (neu khong chuoi hash se bi re nhanh).'
    );
  }
  // Luoi an toan cuoi: nha ket noi giu khoa khi process thoat.
  // Viec tat may co trat tu (ghi not hang doi roi nha khoa) do shutdown()
  // trong server.js dam nhan - KHONG dang ky SIGINT/SIGTERM o day de tranh
  // hai noi cung goi process.exit() va cat ngang nhau.
  process.once('exit', () => { if (lockConn) lockConn.destroy(); });

  const [rows] = await readerPool.query(
    'SELECT row_hash FROM api_request_logs ORDER BY id DESC LIMIT 1'
  );
  lastHash = rows.length > 0 ? rows[0].row_hash : GENESIS_HASH;
  ready = true;
  drain();
  return { lastHash, existing: rows.length > 0 };
}

/** Dua mot ban ghi vao hang doi (khong cho ghi xong). */
function enqueue(entry) {
  if (queue.length >= MAX_QUEUE) {
    dropped++;
    if (dropped % 100 === 1) {
      console.error(`[AUDIT] Hang doi day, da bo ${dropped} ban ghi`);
    }
    return;
  }
  queue.push(entry);
  drain();
}

async function drain() {
  if (draining || !ready || queue.length === 0) return;
  draining = true;
  try {
    while (queue.length > 0) {
      const entry = queue.shift();
      try {
        await writeOne(entry);
      } catch (err) {
        console.error('[AUDIT] Khong ghi duoc nhat ky:', err.message);
      }
    }
  } finally {
    draining = false;
  }
}

async function writeOne(entry) {
  const row = {
    request_id: entry.request_id,
    request_time: fmtDateTime(entry.request_time_ms),
    client_time: fmtDateTime(entry.client_time_ms),
    clock_skew_ms: entry.clock_skew_ms ?? null,
    method: entry.method,
    path: String(entry.path || '').slice(0, 512),
    status_code: entry.status_code,
    duration_ms: entry.duration_ms,
    ip: String(entry.ip || '').slice(0, 45),
    user_agent: entry.user_agent ? String(entry.user_agent).slice(0, 255) : null,
    actor_role: entry.actor_role || 'anonymous',
    session_jti: entry.session_jti || null,
    signature: entry.signature ? String(entry.signature).slice(0, 64) : null,
    signature_valid: entry.signature_valid === null || entry.signature_valid === undefined
      ? null : (entry.signature_valid ? 1 : 0),
    nonce: entry.nonce ? String(entry.nonce).slice(0, 64) : null,
    body_sha256: entry.body_sha256 || null,
    body_bytes: entry.body_bytes || 0,
    response_bytes: entry.response_bytes || 0,
    error_message: entry.error_message ? String(entry.error_message).slice(0, 255) : null,
    booking_code: entry.booking_code ? String(entry.booking_code).slice(0, 12) : null,
  };

  const prev_hash = lastHash;
  const row_hash = computeRowHash(prev_hash, row);

  // Ghi bang user CHI co quyen INSERT
  await writerPool.query(
    `INSERT INTO api_request_logs
       (request_id, request_time, client_time, clock_skew_ms, method, path,
        status_code, duration_ms, ip, user_agent, actor_role, session_jti,
        signature, signature_valid, nonce, body_sha256, body_bytes,
        response_bytes, error_message, booking_code, prev_hash, row_hash)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [...HASHED_FIELDS.map((k) => row[k]), prev_hash, row_hash]
  );

  // Chi cap nhat sau khi ghi thanh cong -> chuoi khong bi lech khi loi DB
  lastHash = row_hash;
}

/**
 * Kiem tra tinh toan ven cua chuoi hash.
 * Tra ve { ok, checked, broken_at, reason }.
 */
async function verifyChain(limit = 10000) {
  const [rows] = await readerPool.query(
    `SELECT * FROM api_request_logs ORDER BY id ASC LIMIT ?`, [limit]
  );

  let expectedPrev = GENESIS_HASH;
  for (const r of rows) {
    if (r.prev_hash !== expectedPrev) {
      return {
        ok: false, checked: rows.length, broken_at: r.id,
        reason: 'prev_hash khong khop row_hash cua dong truoc (co dong bi xoa hoac chen them)',
      };
    }
    if (computeRowHash(r.prev_hash, r) !== r.row_hash) {
      return {
        ok: false, checked: rows.length, broken_at: r.id,
        reason: 'row_hash khong khop noi dung dong (du lieu dong nay da bi sua)',
      };
    }
    expectedPrev = r.row_hash;
  }
  return { ok: true, checked: rows.length, last_hash: expectedPrev };
}

function stats() {
  return { queued: queue.length, dropped, ready, last_hash: lastHash };
}

/**
 * Ghi het cac ban ghi con trong hang doi (dung khi tat server).
 * A10:2025 - khong de mat du lieu nhat ky khi thoat bat thuong.
 */
async function flush(timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  drain();
  while ((queue.length > 0 || draining) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 50));
  }
  return { remaining: queue.length };
}

/**
 * Khoi tao CHI DOC: chi mo readerPool, khong lay khoa writer.
 * Dung cho cac script kiem tra doc lap (npm run verify-audit) de khong
 * tranh khoa voi server dang chay.
 */
function initReadOnly() {
  const { getReaderPool } = require('../db/auditPool');
  readerPool = getReaderPool();
}

/** Truy van doc tren database nhat ky (dung user chi co quyen SELECT). */
function readerQuery(sql, params) {
  if (!readerPool) throw new Error('Nhat ky audit chua duoc khoi tao');
  return readerPool.query(sql, params);
}

module.exports = {
  init, initReadOnly, enqueue, verifyChain, computeRowHash, stats, flush,
  readerQuery, releaseWriterLock, GENESIS_HASH, HASHED_FIELDS,
};
