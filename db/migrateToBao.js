/**
 * Chuyen du lieu PII tu dinh dang cu sang OpenBao Transit.
 *
 *   v1:<iv>:<tag>:<ct>  (AES-256-GCM cuc bo, khoa tu ENCRYPTION_KEY)
 *     -> vault:v1:<...>  (Transit, khoa nam trong OpenBao)
 *
 * Can ENCRYPTION_KEY con trong .env de doc du lieu cu. Sau khi script bao
 * "khong con dong v1: nao" thi moi duoc xoa ENCRYPTION_KEY.
 *
 * Chay thu (khong ghi gi):   node db/migrateToBao.js --dry-run
 * Chay that:                 npm run bao-migrate
 *
 * AN TOAN:
 *  - Moi lo duoc boc trong mot transaction; loi la rollback ca lo
 *  - Giai ma lai de KIEM CHUNG sau khi ghi, truoc khi commit
 *  - Khong bao gio ghi plaintext vao database
 *  - Chay lai nhieu lan khong sao (bo qua dong da o dang vault:)
 */
'use strict';

require('dotenv').config();

const pool = require('./pool');
const bao = require('../lib/bao');
const { isLegacyFormat, decrypt } = require('../lib/crypto');

const COLS = ['passenger_email', 'passenger_phone', 'passenger_cccd'];
const BATCH_SIZE = Number(process.env.MIGRATE_BATCH_SIZE) || 50;
const DRY_RUN = process.argv.includes('--dry-run');

async function countLegacy() {
  const where = COLS.map((c) => `${c} LIKE 'v1:%'`).join(' OR ');
  const [[{ n }]] = await pool.query(`SELECT COUNT(*) n FROM bookings WHERE ${where}`);
  return n;
}

async function fetchBatch() {
  const where = COLS.map((c) => `${c} LIKE 'v1:%'`).join(' OR ');
  const [rows] = await pool.query(
    `SELECT id, ${COLS.join(', ')} FROM bookings WHERE ${where} ORDER BY id LIMIT ?`,
    [BATCH_SIZE]
  );
  return rows;
}

async function migrateBatch(rows) {
  // 1. Giai ma cuc bo (dinh dang cu)
  const jobs = []; // { rowId, col, plain }
  for (const r of rows) {
    for (const col of COLS) {
      if (isLegacyFormat(r[col])) {
        jobs.push({ rowId: r.id, col, plain: await decrypt(r[col]) });
      }
    }
  }
  if (jobs.length === 0) return 0;

  // 2. Ma hoa lai qua Transit - MOT request cho ca lo
  const cts = await bao.encryptBatch(jobs.map((j) => j.plain));
  jobs.forEach((j, i) => { j.ct = cts[i]; });

  if (jobs.some((j) => !j.ct || !j.ct.startsWith('vault:'))) {
    throw new Error('Transit tra ve ciphertext khong hop le, dung lai');
  }

  if (DRY_RUN) {
    console.log(`   [DRY-RUN] se cap nhat ${jobs.length} gia tri cua ${rows.length} dong`);
    return jobs.length;
  }

  // 3. Ghi trong transaction + kiem chung truoc khi commit
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const byRow = new Map();
    for (const j of jobs) {
      if (!byRow.has(j.rowId)) byRow.set(j.rowId, []);
      byRow.get(j.rowId).push(j);
    }
    for (const [rowId, items] of byRow) {
      const sets = items.map((j) => `${j.col} = ?`).join(', ');
      await conn.query(
        `UPDATE bookings SET ${sets} WHERE id = ?`,
        [...items.map((j) => j.ct), rowId]
      );
    }

    // KIEM CHUNG: doc lai tu DB, giai ma qua Transit, so voi plaintext ban dau
    const ids = [...byRow.keys()];
    const [check] = await conn.query(
      `SELECT id, ${COLS.join(', ')} FROM bookings WHERE id IN (${ids.map(() => '?').join(',')})`,
      ids
    );
    const stored = new Map(check.map((r) => [r.id, r]));
    const verifyCts = jobs.map((j) => stored.get(j.rowId)[j.col]);
    const verifyPts = await bao.decryptBatch(verifyCts);

    for (let i = 0; i < jobs.length; i++) {
      if (verifyPts[i] !== jobs[i].plain) {
        throw new Error(
          `Kiem chung THAT BAI o dong id=${jobs[i].rowId} cot ${jobs[i].col} - rollback ca lo`
        );
      }
    }

    await conn.commit();
    return jobs.length;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

async function main() {
  console.log(DRY_RUN ? '=== CHAY THU (khong ghi gi) ===' : '=== MIGRATION THAT ===');

  const h = await bao.health();
  if (!h.ok) { console.error(`OpenBao khong san sang: ${h.reason}`); process.exit(1); }
  console.log(`OpenBao v${h.version} da unseal`);

  if (!process.env.ENCRYPTION_KEY) {
    console.error('Thieu ENCRYPTION_KEY - khong the doc du lieu dinh dang cu.');
    process.exit(1);
  }

  const before = await countLegacy();
  console.log(`So dong con dinh dang cu (v1:): ${before}`);
  if (before === 0) {
    console.log('\nKhong con gi de migrate.');
    console.log('=> An toan de XOA ENCRYPTION_KEY khoi .env va khoi OpenBao KV.');
    await pool.end();
    return;
  }

  let done = 0;
  let round = 0;
  for (;;) {
    const rows = await fetchBatch();
    if (rows.length === 0) break;
    round++;
    console.log(`-- Lo ${round}: ${rows.length} dong`);
    const n = await migrateBatch(rows);
    done += n;
    console.log(`   da xu ly ${n} gia tri (tong ${done})`);
    if (DRY_RUN) break; // dry-run chi xem mot lo cho biet
  }

  const after = await countLegacy();
  console.log('');
  console.log(`Truoc : ${before} dong dinh dang cu`);
  console.log(`Sau   : ${after} dong dinh dang cu`);
  console.log(`Da chuyen: ${done} gia tri`);

  if (!DRY_RUN && after === 0) {
    console.log('\nHOAN TAT. Gio co the:');
    console.log('  1. Xoa ENCRYPTION_KEY khoi .env');
    console.log('  2. Xoa khoi OpenBao:  bao kv patch -method=delete kv/skybooking/app ENCRYPTION_KEY');
    console.log('  3. Giu BAN SAO LUU khoa cu o noi an toan cho den khi chac chan');
  }

  await pool.end();
}

main().catch(async (err) => {
  console.error('\n!!! Migration that bai:', err.message);
  console.error('    Khong co du lieu nao bi mat: moi lo chay trong transaction.');
  try { await pool.end(); } catch { /* ignore */ }
  process.exit(1);
});
