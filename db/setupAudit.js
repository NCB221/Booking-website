/**
 * Khoi tao database nhat ky audit RIENG BIET + 2 user han che quyen.
 * Chay: npm run setup-audit
 *
 * Script nay can quyen admin (dung DB_USER/DB_PASSWORD trong .env) de:
 *   1. Tao database AUDIT_DB_NAME
 *   2. Tao bang api_request_logs
 *   3. Tao user writer (chi INSERT) va reader (chi SELECT)
 *   4. Di chuyen du lieu cu tu <DB_NAME>.api_request_logs (neu con)
 *   5. Xac minh chuoi hash + so dong, roi MOI xoa bang cu
 *
 * Idempotent: chay lai nhieu lan khong gay hai.
 */
require('dotenv').config();
const mysql = require('mysql2/promise');
const audit = require('../lib/auditlog');

const APP_DB = process.env.DB_NAME || 'booking';
const AUDIT_DB = process.env.AUDIT_DB_NAME || 'booking_audit';
const W_USER = process.env.AUDIT_DB_WRITER_USER || 'booking_audit_w';
const W_PASS = process.env.AUDIT_DB_WRITER_PASSWORD;
const R_USER = process.env.AUDIT_DB_READER_USER || 'booking_audit_r';
const R_PASS = process.env.AUDIT_DB_READER_PASSWORD;
const HOST_SCOPE = process.env.AUDIT_DB_USER_HOST || 'localhost';

const TABLE_DDL = `
CREATE TABLE IF NOT EXISTS api_request_logs (
  id              BIGINT AUTO_INCREMENT PRIMARY KEY,
  request_id      VARCHAR(64)  NOT NULL,
  request_time    DATETIME(3)  NOT NULL,
  client_time     DATETIME(3)  NULL,
  clock_skew_ms   INT          NULL,
  method          VARCHAR(10)  NOT NULL,
  path            VARCHAR(512) NOT NULL,
  status_code     SMALLINT     NOT NULL,
  duration_ms     INT          NOT NULL,
  ip              VARCHAR(45)  NOT NULL,
  user_agent      VARCHAR(255) NULL,
  actor_role      VARCHAR(20)  NOT NULL DEFAULT 'anonymous',
  session_jti     VARCHAR(32)  NULL,
  signature       VARCHAR(64)  NULL,
  signature_valid TINYINT(1)   NULL,
  nonce           VARCHAR(64)  NULL,
  body_sha256     CHAR(64)     NULL,
  body_bytes      INT          NOT NULL DEFAULT 0,
  response_bytes  INT          NOT NULL DEFAULT 0,
  error_message   VARCHAR(255) NULL,
  booking_code    VARCHAR(12)  NULL,
  prev_hash       CHAR(64)     NOT NULL,
  row_hash        CHAR(64)     NOT NULL,
  created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_request_id (request_id),
  INDEX idx_request_time (request_time),
  INDEX idx_ip (ip),
  INDEX idx_actor (actor_role),
  INDEX idx_booking_code (booking_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

// Cac cot duoc copy khi di chuyen (giu nguyen id de chuoi hash khong doi thu tu)
const COPY_COLS = [
  'id', 'request_id', 'request_time', 'client_time', 'clock_skew_ms', 'method', 'path',
  'status_code', 'duration_ms', 'ip', 'user_agent', 'actor_role', 'session_jti',
  'signature', 'signature_valid', 'nonce', 'body_sha256', 'body_bytes',
  'response_bytes', 'error_message', 'booking_code', 'prev_hash', 'row_hash', 'created_at',
];

async function main() {
  if (!W_PASS || !R_PASS) {
    throw new Error(
      'Thieu AUDIT_DB_WRITER_PASSWORD hoac AUDIT_DB_READER_PASSWORD trong .env'
    );
  }

  const admin = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    multipleStatements: true,
    // BAT BUOC: hash chain duoc tinh tren DATETIME dang CHUOI.
    // Thieu co nay thi mysql2 tra ve object Date -> hash tinh ra khac -> bao dut chuoi oan.
    dateStrings: true,
  });
  console.log('-> Ket noi MySQL bang quyen admin OK');

  // 1. Database rieng
  await admin.query(
    `CREATE DATABASE IF NOT EXISTS \`${AUDIT_DB}\` ` +
    'CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
  );
  console.log(`-> Database "${AUDIT_DB}" san sang`);

  // 2. Bang nhat ky
  await admin.changeUser({ database: AUDIT_DB });
  await admin.query(TABLE_DDL);
  console.log('-> Bang api_request_logs san sang');

  // 3. Hai user han che quyen
  for (const [user, pass, priv] of [[W_USER, W_PASS, 'INSERT'], [R_USER, R_PASS, 'SELECT']]) {
    await admin.query(
      `CREATE USER IF NOT EXISTS ?@? IDENTIFIED BY ?`, [user, HOST_SCOPE, pass]
    );
    // Dat lai mat khau de khop .env ngay ca khi user da ton tai
    await admin.query(`ALTER USER ?@? IDENTIFIED BY ?`, [user, HOST_SCOPE, pass]);
    // Thu hoi het quyen cu roi cap lai DUNG mot quyen can thiet
    await admin.query(`REVOKE ALL PRIVILEGES ON *.* FROM ?@?`, [user, HOST_SCOPE])
      .catch(() => { /* chua co quyen nao thi bo qua */ });
    await admin.query(
      `REVOKE ALL PRIVILEGES ON \`${AUDIT_DB}\`.* FROM ?@?`, [user, HOST_SCOPE]
    ).catch(() => { /* bo qua */ });
    await admin.query(
      `GRANT ${priv} ON \`${AUDIT_DB}\`.api_request_logs TO ?@?`, [user, HOST_SCOPE]
    );
    console.log(`-> User ${user}@${HOST_SCOPE}: CHI co quyen ${priv} tren api_request_logs`);
  }
  await admin.query('FLUSH PRIVILEGES');

  // 3b. Xoa sach nhat ky THU NGHIEM (chi khi co co --reset-test-data)
  if (process.argv.includes('--reset-test-data')) {
    const [[{ c }]] = await admin.query('SELECT COUNT(*) c FROM api_request_logs');
    await admin.query('TRUNCATE TABLE api_request_logs');
    console.log('');
    console.log('*** DA XOA SACH NHAT KY ***');
    console.log(`    Da xoa ${c} ban ghi va bat dau chuoi hash MOI tu genesis.`);
    console.log('    Chi dung co nay cho du lieu THU NGHIEM. O moi truong that,');
    console.log('    xoa nhat ky audit la hanh vi can bi cam.');
    console.log('');
  }

  // 4. Di chuyen du lieu cu (neu bang cu van con)
  const [oldTable] = await admin.query(
    `SELECT COUNT(*) c FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'api_request_logs'`, [APP_DB]
  );
  if (oldTable[0].c === 0) {
    console.log(`-> Khong con bang cu ${APP_DB}.api_request_logs, bo qua di chuyen`);
    await admin.end();
    return;
  }

  const [[{ c: oldCount }]] = await admin.query(
    `SELECT COUNT(*) c FROM \`${APP_DB}\`.api_request_logs`
  );
  const [[{ c: newCount }]] = await admin.query('SELECT COUNT(*) c FROM api_request_logs');
  console.log(`-> Bang cu co ${oldCount} dong, bang moi co ${newCount} dong`);

  if (newCount === 0 && oldCount > 0) {
    const cols = COPY_COLS.map((c) => `\`${c}\``).join(', ');
    await admin.query(
      `INSERT INTO api_request_logs (${cols})
       SELECT ${cols} FROM \`${APP_DB}\`.api_request_logs ORDER BY id ASC`
    );
    console.log(`-> Da di chuyen ${oldCount} dong sang ${AUDIT_DB} (giu nguyen id va hash)`);
  } else if (newCount > 0) {
    console.log('-> Bang moi da co du lieu, KHONG ghi de');
  }

  // 5. Xac minh truoc khi xoa bang cu
  const [[{ c: finalCount }]] = await admin.query('SELECT COUNT(*) c FROM api_request_logs');
  const [rows] = await admin.query('SELECT * FROM api_request_logs ORDER BY id ASC');

  let chainOk = true, brokenAt = null;
  let expectedPrev = audit.GENESIS_HASH;
  for (const r of rows) {
    if (r.prev_hash !== expectedPrev || audit.computeRowHash(r.prev_hash, r) !== r.row_hash) {
      chainOk = false; brokenAt = r.id; break;
    }
    expectedPrev = r.row_hash;
  }

  console.log('');
  console.log('--- Xac minh truoc khi xoa bang cu ---');
  console.log(`   So dong: cu=${oldCount}, moi=${finalCount} ->`,
    finalCount >= oldCount ? 'DU' : 'THIEU');
  console.log('   Chuoi hash o DB moi:', chainOk ? 'NGUYEN VEN' : `DUT tai id=${brokenAt}`);

  if (finalCount >= oldCount && chainOk) {
    await admin.query(`DROP TABLE \`${APP_DB}\`.api_request_logs`);
    console.log(`=> Da xoa bang cu ${APP_DB}.api_request_logs`);
  } else {
    console.log(`=> KHONG xoa bang cu (xac minh that bai). Hay kiem tra lai thu cong.`);
  }

  await admin.end();
}

if (require.main === module) {
  main()
    .then(() => { console.log('\n=> Hoan tat thiet lap nhat ky audit.\n'); process.exit(0); })
    .catch((err) => { console.error('LOI setup audit:', err.message); process.exit(1); });
}

module.exports = main;
