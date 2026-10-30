/**
 * Kiem tra doc lap tinh toan ven cua nhat ky audit.
 * Chay: npm run verify-audit
 *
 * Dung user CHI CO QUYEN SELECT nen chay duoc song song voi server dang chay,
 * va khong the lam thay doi nhat ky.
 */
require('dotenv').config();
const audit = require('../lib/auditlog');
const { getReaderPool } = require('../db/auditPool');

async function main() {
  audit.initReadOnly();
  const pool = getReaderPool();

  const [[{ total }]] = await pool.query('SELECT COUNT(*) total FROM api_request_logs');
  console.log(`\nDatabase nhat ky: ${process.env.AUDIT_DB_NAME}`);
  console.log(`Tong ban ghi    : ${total}\n`);

  const result = await audit.verifyChain(1000000);

  if (result.ok) {
    console.log('=> CHUOI HASH NGUYEN VEN');
    console.log(`   Da kiem tra ${result.checked} ban ghi, khong co dau hieu bi sua hay xoa.`);
    console.log(`   Hash cuoi: ${result.last_hash}`);
  } else {
    console.log('=> CHUOI HASH BI DUT');
    console.log(`   Diem dut : ban ghi #${result.broken_at}`);
    console.log(`   Nguyen nhan: ${result.reason}`);
    console.log(`   Da kiem tra ${result.checked} ban ghi.`);

    // Phan biet "bi sua" voi "2 process cung ghi" (chuoi re nhanh)
    const [forks] = await pool.query(
      `SELECT prev_hash, COUNT(*) c, GROUP_CONCAT(id ORDER BY id) ids
         FROM api_request_logs GROUP BY prev_hash HAVING c > 1`
    );
    if (forks.length > 0) {
      console.log('\n   Phat hien chuoi RE NHANH (nhieu dong cung prev_hash):');
      for (const f of forks) console.log(`     prev_hash ${f.prev_hash.slice(0, 16)}... <- id ${f.ids}`);
      console.log('   => Dau hieu co NHIEU TIEN TRINH cung ghi, khong phai du lieu bi sua.');
    }

    // Kiem tra tung dong: noi dung con khop hash cua chinh no khong?
    const [rows] = await pool.query('SELECT * FROM api_request_logs ORDER BY id ASC');
    const tampered = rows.filter((r) => audit.computeRowHash(r.prev_hash, r) !== r.row_hash);
    console.log(`\n   So dong bi SUA NOI DUNG: ${tampered.length}`);
    if (tampered.length > 0) {
      console.log('     id:', tampered.map((r) => r.id).join(', '));
    } else {
      console.log('     => Khong dong nao bi sua noi dung.');
    }
  }
  console.log('');
  process.exit(result.ok ? 0 : 1);
}

main().catch((err) => { console.error('LOI verify:', err.message); process.exit(2); });
