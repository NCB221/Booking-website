/**
 * Sinh cac khoa bi mat cho file .env
 * Chay: npm run gen-key
 */
const crypto = require('crypto');

const encKey = crypto.randomBytes(32).toString('base64');       // AES-256 (32 byte)
const sessionSecret = crypto.randomBytes(48).toString('base64'); // ky token admin
const adminKey = crypto.randomBytes(18).toString('base64url');   // mat khau admin

console.log('\nDan cac dong sau vao file .env:\n');
console.log(`ENCRYPTION_KEY=${encKey}`);
console.log(`SESSION_SECRET=${sessionSecret}`);
console.log(`ADMIN_KEY=${adminKey}\n`);
console.log('CANH BAO:');
console.log(' - Doi ENCRYPTION_KEY = mat vinh vien CCCD/email/dien thoai da ma hoa.');
console.log('   Chi tao khoa nay 1 lan va sao luu an toan.');
console.log(' - Doi SESSION_SECRET = dang xuat tat ca phien admin (an toan, khong mat du lieu).');
console.log(' - Khong commit file .env vao git.\n');
