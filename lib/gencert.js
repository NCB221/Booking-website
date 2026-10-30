/**
 * Tao chung chi TLS tu ky (self-signed) cho moi truong phat trien.
 * Chay: npm run gen-cert
 *
 * Cert duoc tao kem SAN (Subject Alternative Name) gom localhost, 127.0.0.1
 * va tat ca IP LAN cua may, nen mo duoc bang ca dia chi LAN - dieu nay quan
 * trong vi crypto.subtle (dung de ky request) chi hoat dong tren HTTPS hoac
 * localhost.
 *
 * LUU Y: cert tu ky KHONG duoc trinh duyet tin tuong san, se co canh bao
 * "Your connection is not private" -> bam Advanced > Proceed de bo qua.
 * Muon khong con canh bao, dung mkcert; muon dung that, dung Let's Encrypt.
 */
const os = require('os');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const CERT_DIR = path.resolve(process.cwd(), 'certs');
const KEY_FILE = path.join(CERT_DIR, 'server.key');
const CERT_FILE = path.join(CERT_DIR, 'server.crt');
const DAYS = 825; // gioi han toi da ma trinh duyet con chap nhan

function lanIPv4() {
  const out = [];
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) out.push(a.address);
    }
  }
  return [...new Set(out)];
}

function buildSan() {
  const entries = ['DNS:localhost', 'IP:127.0.0.1', 'IP:::1'];
  for (const ip of lanIPv4()) entries.push(`IP:${ip}`);
  return entries.join(',');
}

/**
 * Han quyen doc file khoa private.
 *  - Linux/macOS: chmod 600
 *  - Windows: chmod KHONG co tac dung (chi la lop gia lap POSIX), phai dung
 *    icacls. Bo ke thua ACL roi chi cap quyen cho chu so huu + SYSTEM.
 *    Luu y: bo Administrators chi mang tinh hinh thuc - admin van co the
 *    chiem lai quyen so huu. Khong the bao ve khoa khoi admin cung may.
 */
function restrictKeyPermissions() {
  if (process.platform !== 'win32') {
    try {
      fs.chmodSync(KEY_FILE, 0o600);
      console.log('-> Da dat quyen 600 cho khoa private');
    } catch (err) {
      console.warn('! Khong dat duoc quyen 600:', err.message);
    }
    return;
  }

  const user = process.env.USERDOMAIN && process.env.USERNAME
    ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}`
    : process.env.USERNAME;
  if (!user) {
    console.warn('! Khong xac dinh duoc tai khoan hien tai, bo qua buoc siet quyen.');
    return;
  }

  try {
    // /inheritance:r bo moi ACE ke thua; /grant:r thay the quyen cua user
    execFileSync('icacls', [
      KEY_FILE, '/inheritance:r',
      '/grant:r', `${user}:(R,W)`,
      '/grant:r', 'NT AUTHORITY\\SYSTEM:(F)',
    ], { stdio: 'ignore' });
    // icacls co the giu lai Administrators -> xoa rieng
    try {
      execFileSync('icacls', [KEY_FILE, '/remove:g', 'BUILTIN\\Administrators'],
        { stdio: 'ignore' });
    } catch { /* khong co ACE nay thi bo qua */ }

    console.log(`-> Da siet ACL khoa private: chi ${user} (R,W) va SYSTEM (F)`);
  } catch (err) {
    console.warn('! Khong siet duoc ACL bang icacls:', err.message);
    console.warn('  Hay kiem tra thu cong:  icacls certs\\server.key');
  }
}

function main() {
  // Kiem tra openssl co san
  try {
    const v = execFileSync('openssl', ['version'], { encoding: 'utf8' }).trim();
    console.log(`-> ${v}`);
  } catch {
    console.error('LOI: khong tim thay "openssl" trong PATH.');
    console.error('     Tren Windows, Git Bash co kem openssl - hay chay lenh nay trong Git Bash.');
    process.exit(1);
  }

  fs.mkdirSync(CERT_DIR, { recursive: true });

  if (fs.existsSync(KEY_FILE) && !process.argv.includes('--force')) {
    console.log(`-> Da co cert tai ${CERT_DIR}, khong tao lai.`);
    console.log('   Dung "npm run gen-cert -- --force" de tao moi.');
    return;
  }

  const san = buildSan();
  console.log(`-> SAN: ${san}`);

  execFileSync('openssl', [
    'req', '-x509',
    '-newkey', 'rsa:2048',
    '-nodes',                      // khong dat passphrase (server tu doc duoc)
    '-keyout', KEY_FILE,
    '-out', CERT_FILE,
    '-days', String(DAYS),
    '-sha256',
    '-subj', '/C=VN/ST=Ha Noi/L=Ha Noi/O=SkyBooking Dev/CN=localhost',
    '-addext', `subjectAltName=${san}`,
    '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
    '-addext', 'extendedKeyUsage=serverAuth',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  restrictKeyPermissions();

  console.log(`-> Da tao khoa  : ${KEY_FILE}`);
  console.log(`-> Da tao cert  : ${CERT_FILE}`);
  console.log(`-> Han su dung  : ${DAYS} ngay`);
  console.log('');
  console.log('Them 2 dong sau vao .env roi khoi dong lai server:');
  console.log('  HTTPS_KEY_FILE=certs/server.key');
  console.log('  HTTPS_CERT_FILE=certs/server.crt');
  console.log('');
  console.log('CANH BAO: day la cert TU KY, trinh duyet se bao "Not private".');
  console.log('          Bam Advanced > Proceed to localhost de tiep tuc.');
  console.log('          KHONG commit thu muc certs/ vao git.');
}

if (require.main === module) {
  try { main(); } catch (err) {
    console.error('LOI tao cert:', err.message);
    if (err.stderr) console.error(String(err.stderr));
    process.exit(1);
  }
}

module.exports = { main, KEY_FILE, CERT_FILE, CERT_DIR };
