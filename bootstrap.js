/**
 * Entrypoint cua ung dung. Nap secret tu OpenBao TRUOC khi require server.
 *
 * VI SAO CAN FILE NAY:
 * db/pool.js goi mysql.createPool() ngay luc load module, doc truc tiep
 * process.env.DB_PASSWORD. `require` la dong bo con doc KV la async, nen
 * khong the nap secret tu trong server.js - luc do pool da duoc tao xong roi.
 * File nay nap secret vao process.env roi moi require('./server').
 *
 * THU TU UU TIEN: gia tri tu OpenBao GHI DE gia tri trong .env.
 * Nho vay ban co the xoa dan secret khoi .env ma app van chay.
 *
 * Chay: npm start   (package.json da tro vao file nay)
 */
'use strict';

require('dotenv').config();

const bao = require('./lib/bao');

// Cac bien bat buoc phai co sau khi nap, neu thieu thi dung han
const REQUIRED = ['SESSION_SECRET', 'ADMIN_KEY', 'DB_PASSWORD'];

async function main() {
  console.log('[BOOTSTRAP] Dang kiem tra OpenBao...');

  // 1. OpenBao phai song va da unseal. FAIL CLOSED neu khong.
  const h = await bao.health();
  if (!h.ok) {
    console.error(`\n!!! OpenBao khong san sang: ${h.reason}`);
    console.error('    Dia chi dang dung:', bao.BAO_ADDR);
    console.error('    Neu dang SEALED, chay:  bao operator unseal   (can 3/5 khoa)');
    console.error('    Neu chua chay, khoi dong task "OpenBao-Server"\n');
    process.exit(1);
  }
  console.log(`[BOOTSTRAP] OpenBao v${h.version} da unseal tai ${bao.BAO_ADDR}`);

  // 2. Nap secret tu KV v2 vao process.env
  let secrets;
  try {
    secrets = await bao.readSecrets();
  } catch (err) {
    console.error('\n!!! Khong doc duoc secret tu OpenBao:', err.message);
    console.error('    Kiem tra BAO_ROLE_ID / BAO_SECRET_ID trong .env\n');
    process.exit(1);
  }

  const loaded = [];
  for (const [k, v] of Object.entries(secrets)) {
    if (typeof v === 'string' && v !== '') {
      process.env[k] = v; // OpenBao ghi de .env
      loaded.push(k);
    }
  }
  console.log(`[BOOTSTRAP] Da nap ${loaded.length} secret tu OpenBao: ${loaded.sort().join(', ')}`);

  // 3. Kiem tra cac bien bat buoc
  const missing = REQUIRED.filter((k) => !process.env[k]);
  if (missing.length > 0) {
    console.error(`\n!!! Thieu secret bat buoc: ${missing.join(', ')}`);
    console.error('    Them vao OpenBao:  bao kv put kv/skybooking/app <TEN>=<gia tri>\n');
    process.exit(1);
  }

  // 4. Kiem tra Transit hoat dong thuc su (khong chi tin vao health)
  try {
    const ct = await bao.encryptOne('bootstrap-selftest');
    const pt = await bao.decryptOne(ct);
    if (pt !== 'bootstrap-selftest') throw new Error('giai ma khong khop plaintext');
    console.log(`[BOOTSTRAP] Transit key "${bao.TRANSIT_KEY}" hoat dong (da test ma hoa + giai ma)`);
  } catch (err) {
    console.error('\n!!! Transit khong dung duoc:', err.message);
    console.error('    App se khong ma hoa duoc PII -> tu choi khoi dong.\n');
    process.exit(1);
  }

  // 5. Gio moi nap server (luc nay process.env da day du)
  console.log('[BOOTSTRAP] Khoi dong ung dung...\n');
  require('./server');
}

main().catch((err) => {
  console.error('\n!!! Bootstrap that bai:', err.message, '\n');
  process.exit(1);
});
