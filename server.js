require('dotenv').config();
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const pool = require('./db/pool');
const initDb = require('./db/init');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Khong tiet lo "X-Powered-By: Express" (API8 - Security Misconfiguration)
app.disable('x-powered-by');

/* ---------------------------------------------------------------
 * trust proxy - PHAI MAC DINH TAT.
 *
 * Neu bat ma KHONG thuc su co reverse proxy phia truoc, bat ky ai cung co
 * the gui header "X-Forwarded-For: <ip bat ky>" de:
 *   - Bypass toan bo rate limit (xoay IP moi request -> bucket moi)
 *   - Dau doc cot `ip` trong nhat ky audit (mat gia tri dieu tra)
 *   - Lam sai IP trong canh bao bao mat
 *
 * Chi bat khi THUC SU dung sau nginx/Caddy/Cloudflare, va dat bang SO LUONG
 * proxy tin cay (vi du TRUST_PROXY=1 cho dung mot proxy).
 * -------------------------------------------------------------*/
const TRUST_PROXY = (process.env.TRUST_PROXY || '').trim();
if (!TRUST_PROXY || TRUST_PROXY === 'false' || TRUST_PROXY === '0') {
  app.set('trust proxy', false);
} else if (/^\d+$/.test(TRUST_PROXY)) {
  app.set('trust proxy', Number(TRUST_PROXY));
} else {
  // Danh sach IP/subnet tin cay, vi du "127.0.0.1, 10.0.0.0/8"
  app.set('trust proxy', TRUST_PROXY);
}

/* ---------------------------------------------------------------
 * API8: Security Misconfiguration - HTTP security headers
 * -------------------------------------------------------------*/
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // Chi cho phep script tu chinh server -> chan script chen vao (XSS)
      scriptSrc: ["'self'"],
      // Trang dung style inline nen can 'unsafe-inline' cho CSS
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"], // chong clickjacking
      formAction: ["'self'"],
      baseUri: ["'self'"],
      upgradeInsecureRequests: IS_PROD ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'no-referrer' },
  // HSTS bat buoc trinh duyet CHI dung HTTPS voi host nay.
  // CANH BAO: HSTS ap dung cho CA HOST, khong phan biet cong. Bat HSTS tren
  // localhost se khien MOI du an khac cua ban tren localhost bi buoc sang
  // HTTPS va hong. Vi vay mac dinh TAT, chi bat o production (domain that).
  hsts: (IS_PROD || process.env.ENABLE_HSTS === 'true')
    ? { maxAge: 15552000, includeSubDomains: true }
    : false,
}));

// A02:2025 - Permissions-Policy: tat cac API thiet bi ma web nay khong dung.
// helmet khong tu dat header nay nen phai khai bao thu cong.
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), usb=(), payment=(), ' +
    'magnetometer=(), gyroscope=(), accelerometer=(), midi=(), ' +
    'display-capture=(), screen-wake-lock=(), serial=(), bluetooth=()');
  next();
});

/* ---------------------------------------------------------------
 * API8: CORS chat - mac dinh CHI cho phep cung origin.
 * Chi mo cho domain khac khi ALLOWED_ORIGINS duoc khai bao trong .env
 * -------------------------------------------------------------*/
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);

if (allowedOrigins.length > 0) {
  app.use(cors({
    origin(origin, cb) {
      // Khong co origin = request cung origin hoac tu curl -> cho qua
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      cb(new Error('Origin khong duoc phep (CORS)'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  }));
}

/* ---------------------------------------------------------------
 * API4: Unrestricted Resource Consumption - gioi han kich thuoc body
 * -------------------------------------------------------------*/
// verify: giu lai RAW body de bam SHA-256 dung chinh byte da nhan.
// Neu bam lai tu object da parse thi mot thay doi nho (vi du thu tu khoa)
// cung lam chu ky lech -> bat buoc phai dung raw body.
app.use(express.json({
  limit: '16kb',
  verify(req, res, buf) { req.rawBody = buf; },
}));
app.use(express.urlencoded({
  extended: false,
  limit: '16kb',
  verify(req, res, buf) { req.rawBody = buf; },
}));

/* ---------------------------------------------------------------
 * API4: Rate limiting theo tung nhom endpoint
 * -------------------------------------------------------------*/
const alerting = require('./lib/alerting');

const limiterMessage = (msg) => ({
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: msg },
  // A09:2025 - ghi nhan de phat hien tan cong tu dong / bot quet
  handler(req, res, next, options) {
    alerting.recordEvent('RATE_LIMITED', {
      ip: req.ip, path: req.originalUrl, requestId: req.requestId,
    });
    res.status(options.statusCode).json({ error: msg });
  },
});

// Gioi han chung cho toan bo /api
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120, // 120 request/phut/IP
  ...limiterMessage('Ban gui qua nhieu yeu cau. Vui long thu lai sau 1 phut.'),
});

// Chong do ma ve (API1 - BOLA) va chong brute-force dang nhap (API2)
const lookupLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20, // 20 lan tra cuu / 10 phut / IP
  ...limiterMessage('Ban tra cuu qua nhieu lan. Vui long thu lai sau 10 phut.'),
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 lan dang nhap sai / 15 phut / IP
  skipSuccessfulRequests: true,
  ...limiterMessage('Qua nhieu lan dang nhap that bai. Thu lai sau 15 phut.'),
});

// API6: chong bot dat ve hang loat (denial of inventory)
const bookingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10, // 10 ve / gio / IP
  ...limiterMessage('Ban da dat qua nhieu ve trong 1 gio. Vui long thu lai sau.'),
});

// Cap phien + khoa ky: gioi han de tranh bi xin khoa hang loat
const sessionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 60, // 60 phien / gio / IP
  ...limiterMessage('Ban yeu cau qua nhieu phien. Vui long thu lai sau.'),
});

/* ---------------------------------------------------------------
 * request_id + request_time cho MOI request, va nhat ky audit.
 * Dat TRUOC rate limiter de ghi duoc ca cac request bi chan (429).
 * -------------------------------------------------------------*/
const {
  requestContext, auditLogger, auditPayloadCapture,
} = require('./middleware/requestContext');
app.use('/api', requestContext);
app.use('/api', auditLogger);

// Do tai khi qua nhieu request dang xu ly dong thoi (chong can kiet tai nguyen).
// Dat TRUOC rate limiter vi rate limit theo IP khong chan duoc tan cong phan tan.
const { loadShed } = require('./middleware/loadshed');
app.use('/api', loadShed);

app.use('/api', generalLimiter);

// Chia se cac limiter cho router thong qua app.locals
app.locals.limiters = { lookupLimiter, loginLimiter, bookingLimiter };

/* ---------------------------------------------------------------
 * Toan ven du lieu truyen di: chu ky HMAC-SHA256
 *  - attachSession: doc token phien -> lay khoa ky
 *  - signResponses: ky moi response JSON de client xac minh
 * (requireSignature duoc gan rieng o tung router can bao ve)
 * -------------------------------------------------------------*/
const { attachSession, signResponses } = require('./middleware/signature');
app.use('/api', attachSession);
app.use('/api', signResponses);
// Dang ky SAU signResponses -> boc ngoai cung res.json de doc duoc payload
app.use('/api', auditPayloadCapture);

/* ---------------------------------------------------------------
 * Routes
 * -------------------------------------------------------------*/
app.get('/api/health', (req, res) => {
  // API9: endpoint kiem tra suc khoe, KHONG tiet lo phien ban / cau hinh
  res.json({ status: 'ok' });
});

app.use('/api', sessionLimiter, require('./routes/session'));
app.use('/api', require('./routes/flights'));
app.use('/api', require('./routes/bookings'));
app.use('/api/admin', require('./routes/admin'));

// Frontend tinh
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
  },
}));

// 404 cho API (khong tra ve HTML)
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Khong tim thay endpoint' });
});

/* ---------------------------------------------------------------
 * API8: Xu ly loi - KHONG tiet lo chi tiet noi bo cho client
 * -------------------------------------------------------------*/
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // Log day du o server (khong chua du lieu ca nhan).
  // request_id giup doi chieu voi bang api_request_logs khi dieu tra.
  // Gop loi giong nhau de log khong bi tran (A10:2025 rec #8).
  const line = alerting.summarizeError(
    `api:${req.method}:${err.message}`,
    `[API ERROR] ${req.method} ${req.path} (request_id ${req.requestId}) - ${err.message}`
  );
  if (line) console.error(line);

  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Du lieu gui len qua lon' });
  }
  if (err && /CORS/i.test(err.message)) {
    return res.status(403).json({ error: 'Origin khong duoc phep' });
  }
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: 'JSON khong hop le' });
  }

  // A09:2025 - nhieu loi 500 lien tiep co the la dau hieu bi khai thac
  alerting.recordEvent('SERVER_ERROR', {
    ip: req.ip, path: req.originalUrl, requestId: req.requestId,
    detail: err.message,
  });

  // A10:2025 - FAIL CLOSED: tra loi chung chung, khong co gang "phuc hoi
  // mot phan", khong lo SQL / duong dan / stack trace.
  res.status(500).json({ error: 'Loi may chu. Vui long thu lai sau.' });
});

/* ---------------------------------------------------------------
 * Khoi dong
 * -------------------------------------------------------------*/
function checkSecrets() {
  const warnings = [];
  const weakKeys = ['admin123', 'admin', 'password', '123456', 'changeme'];
  const adminKey = process.env.ADMIN_KEY || '';

  if (weakKeys.includes(adminKey.toLowerCase()) || adminKey.length < 16) {
    warnings.push('ADMIN_KEY qua yeu (can >= 16 ky tu ngau nhien). Tao moi: npm run gen-key');
  }
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    warnings.push('SESSION_SECRET thieu hoac < 32 ky tu. Tao moi: npm run gen-key');
  }
  // Ma hoa PII gio di qua OpenBao Transit, khong con dung ENCRYPTION_KEY de GHI.
  // ENCRYPTION_KEY chi can khi DB con dong dinh dang cu (v1:) chua migrate.
  if (!process.env.BAO_ROLE_ID || !process.env.BAO_SECRET_ID) {
    warnings.push(
      'Thieu BAO_ROLE_ID / BAO_SECRET_ID - khong xac thuc duoc voi OpenBao ' +
      'nen KHONG ma hoa duoc du lieu ca nhan.'
    );
  }
  if (process.env.ENCRYPTION_KEY) {
    warnings.push(
      'ENCRYPTION_KEY van con trong cau hinh. Neu da chay xong ' +
      '"npm run bao-migrate" thi hay xoa di - de lai la giu mot ban khoa ' +
      'ngoai OpenBao, dung voi muc dich chuyen sang Transit.'
    );
  }
  if (IS_PROD && allowedOrigins.includes('*')) {
    warnings.push('ALLOWED_ORIGINS=* rat nguy hiem o moi truong production.');
  }
  // Bat trust proxy ma Node lai tu lo HTTPS = gan nhu chac chan khong co proxy
  // -> ai cung gia mao duoc IP qua X-Forwarded-For.
  if (app.get('trust proxy') && process.env.HTTPS_KEY_FILE) {
    warnings.push(
      'TRUST_PROXY dang BAT nhung Node tu chay HTTPS (khong co reverse proxy). ' +
      'Bat ky ai cung co the gia mao IP qua X-Forwarded-For -> bypass rate limit ' +
      'va dau doc nhat ky. Hay dat TRUST_PROXY= (rong).'
    );
  }
  return warnings;
}

async function start() {
  const warnings = checkSecrets();
  if (warnings.length > 0) {
    console.warn('\n*** CANH BAO BAO MAT ***');
    warnings.forEach((w) => console.warn('  ! ' + w));
    console.warn('');
    if (IS_PROD) {
      console.error('Tu choi khoi dong o che do production voi cau hinh khong an toan.');
      process.exit(1);
    }
  }

  try {
    await initDb();
  } catch (err) {
    console.error('\n!!! Khong the khoi tao database MySQL.');
    console.error('    Kiem tra MySQL dang chay va thong tin trong file .env.');
    console.error('    Chi tiet:', err.message, '\n');
    process.exit(1);
  }

  await pool.query('SELECT 1');

  // Nap trang thai hash chain tu DATABASE NHAT KY RIENG
  const audit = require('./lib/auditlog');
  const { AUDIT_DB_NAME } = require('./db/auditPool');
  try {
    const chain = await audit.init();
    console.log(
      `-> Nhat ky audit "${AUDIT_DB_NAME}" san sang ` +
      `(${chain.existing ? 'tiep tuc chuoi hash cu' : 'chuoi hash moi'})`
    );
  } catch (err) {
    if (/tien trinh khac/i.test(err.message)) {
      // Da co instance khac dang ghi nhat ky
      console.error('\n!!! Da co mot server khac dang chay.');
      console.error('    ' + err.message);
      console.error('    Hay dung instance cu truoc khi khoi dong lai.\n');
    } else {
      console.error('\n!!! Khong ket noi duoc database nhat ky audit.');
      console.error('    Chay "npm run setup-audit" de tao database va 2 user han che quyen.');
      console.error('    Chi tiet:', err.message, '\n');
    }
    process.exit(1);
  }

  // Kiem tra cau hinh email (khong lam sap server neu loi)
  const mailer = require('./lib/mailer');
  const mail = await mailer.verifyConnection();
  if (mail.ok) {
    console.log(`-> Email (${mail.mode}): ${mail.detail}`);
  } else {
    console.warn(`\n! Canh bao email (${mail.mode}): ${mail.detail}`);
    console.warn('  Khach se KHONG nhan duoc email xac nhan. Kiem tra SMTP_* trong .env\n');
  }

  startListening();
}

/* ---------------------------------------------------------------
 * Lang nghe: HTTPS khi khai bao cert trong .env, nguoc lai HTTP.
 * Chay HTTP chi phu hop khi: (a) phat trien tren localhost, hoac
 * (b) dung sau reverse proxy (nginx/Caddy) da lo HTTPS.
 * -------------------------------------------------------------*/
function startListening() {
  const keyFile = (process.env.HTTPS_KEY_FILE || '').trim();
  const certFile = (process.env.HTTPS_CERT_FILE || '').trim();

  installProcessSafetyNet();

  if (!keyFile || !certFile) {
    // Dung http.createServer (khong dung app.listen) de truyen duoc
    // connectionsCheckingInterval - xem giai thich trong hardenServerTimeouts.
    const srv = http.createServer({ connectionsCheckingInterval: CHECK_INTERVAL_MS }, app);
    httpServer = hardenServerTimeouts(srv);
    srv.listen(PORT, () => banner('http'));
    if (IS_PROD) {
      console.warn('! Dang chay HTTP o che do production.');
      console.warn('  Chi an toan neu co reverse proxy (nginx/Caddy) xu ly HTTPS phia truoc.\n');
    }
    return;
  }

  let creds;
  try {
    creds = {
      key: fs.readFileSync(path.resolve(keyFile)),
      cert: fs.readFileSync(path.resolve(certFile)),
    };
  } catch (err) {
    console.error('\n!!! Khong doc duoc file chung chi TLS.');
    console.error(`    key : ${keyFile}`);
    console.error(`    cert: ${certFile}`);
    console.error('    Tao cert tu ky bang: npm run gen-cert');
    console.error('    Chi tiet:', err.message, '\n');
    process.exit(1);
  }

  const srv = https.createServer({
    ...creds,
    minVersion: 'TLSv1.2',   // khong nhan TLS 1.0/1.1 (da bi coi la khong an toan)
    honorCipherOrder: true,
    connectionsCheckingInterval: CHECK_INTERVAL_MS,
  }, app);
  httpServer = hardenServerTimeouts(srv);
  srv.listen(PORT, () => banner('https'));
}

/* ---------------------------------------------------------------
 * A10:2025 - Mishandling of Exceptional Conditions
 * Luoi an toan muc process (rec #4: global exception handler) va
 * tat may co trat tu (rec #6: fail closed, khong phuc hoi mot phan).
 * -------------------------------------------------------------*/
let httpServer = null;
let shuttingDown = false;

async function shutdown(reason, exitCode) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.error(`\n[SHUTDOWN] ${reason} - dang dong co trat tu...`);

  // Ngung nhan ket noi moi
  if (httpServer) {
    await new Promise((resolve) => httpServer.close(resolve)).catch(() => {});
  }

  // Ghi het nhat ky audit con trong hang doi (khong de mat dau vet)
  try {
    const audit = require('./lib/auditlog');
    const { remaining } = await audit.flush(5000);
    console.error(`[SHUTDOWN] Nhat ky audit: da ghi het` +
      (remaining > 0 ? `, con ${remaining} ban ghi chua ghi duoc` : ''));
    await audit.releaseWriterLock();
  } catch (err) {
    console.error('[SHUTDOWN] Loi khi ghi not nhat ky:', err.message);
  }

  // Dong pool database
  try { await pool.end(); } catch { /* bo qua */ }

  console.error('[SHUTDOWN] Hoan tat.\n');
  process.exit(exitCode);
}

function installProcessSafetyNet() {
  // Promise bi reject ma khong ai bat: la BUG, nhung khong lam sap server
  process.on('unhandledRejection', (reason) => {
    const msg = reason instanceof Error ? reason.message : String(reason);
    const line = alerting.summarizeError(
      `unhandledRejection:${msg}`,
      `[UNHANDLED REJECTION] ${msg}`
    );
    if (line) {
      console.error(line);
      if (reason instanceof Error && reason.stack) console.error(reason.stack);
    }
    alerting.recordEvent('UNCAUGHT_ERROR', { detail: `unhandledRejection: ${msg}` });
  });

  // Exception khong duoc bat: process dang o trang thai KHONG XAC DINH
  // -> phai thoat (fail closed), khong co gang chay tiep.
  process.on('uncaughtException', (err) => {
    console.error(`\n[UNCAUGHT EXCEPTION] ${err.message}`);
    if (err.stack) console.error(err.stack);
    alerting.recordEvent('UNCAUGHT_ERROR', { detail: `uncaughtException: ${err.message}` });
    shutdown('Loi khong duoc bat', 1);
  });

  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => shutdown(`Nhan tin hieu ${sig}`, 0));
  }
}

/**
 * Chu ky Node quet cac ket noi de ap dung headersTimeout/requestTimeout.
 * MAC DINH CUA NODE LA 30 GIAY, nghia la mot ket noi slowloris co the song
 * tron 30s du headersTimeout chi la 15s (da kiem chung bang thuc nghiem).
 * Ha xuong 2s de cat ket noi treo nhanh hon nhieu.
 */
const CHECK_INTERVAL_MS = 2_000;

/**
 * Siet timeout o tang socket de chong Slowloris va cac bien the "slow HTTP":
 * ke tan cong mo rat nhieu ket noi roi gui du lieu cuc cham de giu ket noi,
 * lam can kiet so socket ma khong can bang thong lon.
 */
function hardenServerTimeouts(server) {
  // Thoi gian toi da de client gui XONG phan header
  server.headersTimeout = 15_000;
  // Thoi gian toi da cho TOAN BO mot request (header + body).
  // Day la gioi han CUNG: slowloris nho giot du lieu lien tuc van bi cat.
  server.requestTimeout = 20_000;
  // Dong ket noi keep-alive khi khong hoat dong
  server.keepAliveTimeout = 5_000;
  // Tran so ket noi dong thoi
  server.maxConnections = Number(process.env.MAX_CONNECTIONS) || 512;

  server.on('clientError', (err, socket) => {
    // Gop log: ke tan cong gui hang nghin ket noi loi co the lam tran log
    const line = alerting.summarizeError(
      `clientError:${err.code}`,
      `[NET] Loi client: ${err.code}`
    );
    if (line) console.warn(line);

    // Ket noi bi cat vi qua han -> tra 408 cho dung nghia
    const isTimeout = err.code === 'ERR_HTTP_REQUEST_TIMEOUT'
      || /timeout/i.test(err.code || '');
    const status = isTimeout ? '408 Request Timeout' : '400 Bad Request';

    if (!socket.destroyed && socket.writable) {
      socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
    } else {
      socket.destroy();
    }
  });

  return server;
}

function banner(scheme) {
  const base = `${scheme}://localhost:${PORT}`;
  console.log('\n==============================================');
  console.log('  Web dat ve may bay dang chay!');
  console.log(`  Trang chu : ${base}`);
  console.log(`  Quan tri  : ${base}/admin.html`);
  console.log(`  Giao thuc : ${scheme.toUpperCase()}${scheme === 'https' ? ' (TLS >= 1.2)' : ''}`);
  console.log(`  Moi truong: ${process.env.NODE_ENV || 'development'}`);
  console.log('==============================================\n');

  if (scheme === 'http') {
    console.log('Luu y: dang chay HTTP. Du lieu ca nhan (CCCD/email/dien thoai) di qua');
    console.log('       mang o dang plaintext. Xem muc HTTPS trong README.\n');
  }
}

start();
