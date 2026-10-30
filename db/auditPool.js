require('dotenv').config();
const mysql = require('mysql2/promise');

/**
 * Hai pool RIENG BIET toi database nhat ky audit, tach quyen ro rang:
 *
 *   writerPool - user chi co quyen INSERT  -> ghi log, KHONG the sua/xoa
 *   readerPool - user chi co quyen SELECT  -> nap hash chain, verify, admin xem
 *
 * Nho tach quyen nay, ke tan cong chiem duoc ung dung cung khong the
 * sua hay xoa cac ban ghi nhat ky da duoc ghi truoc do.
 *
 * Khoi tao DB va 2 user: npm run setup-audit
 */
const BASE = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  database: process.env.AUDIT_DB_NAME || 'booking_audit',
  waitForConnections: true,
  queueLimit: 0,
  dateStrings: true,
  charset: 'utf8mb4_general_ci',
};

function requireEnv(name) {
  const v = process.env[name];
  if (!v) {
    throw new Error(
      `Thieu ${name} trong file .env. Chay "npm run setup-audit" de khoi tao ` +
      'database nhat ky audit va 2 user han che quyen.'
    );
  }
  return v;
}

let writerPool = null;
let readerPool = null;

function getWriterPool() {
  if (!writerPool) {
    writerPool = mysql.createPool({
      ...BASE,
      user: requireEnv('AUDIT_DB_WRITER_USER'),
      password: requireEnv('AUDIT_DB_WRITER_PASSWORD'),
      connectionLimit: 5,
    });
  }
  return writerPool;
}

function getReaderPool() {
  if (!readerPool) {
    readerPool = mysql.createPool({
      ...BASE,
      user: requireEnv('AUDIT_DB_READER_USER'),
      password: requireEnv('AUDIT_DB_READER_PASSWORD'),
      connectionLimit: 5,
    });
  }
  return readerPool;
}

module.exports = { getWriterPool, getReaderPool, AUDIT_DB_NAME: BASE.database };
