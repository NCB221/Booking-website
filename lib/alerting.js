/**
 * Phat hien va bao dong su co bao mat.
 *
 * OWASP A09:2025 doi ten thanh "Security Logging and ALERTING Failures":
 * ghi log khong con du - he thong phai BIET PHAT HIEN va BAO DONG.
 * OWASP A10:2025 cung yeu cau (rec #5) giam sat de phat hien loi lap lai /
 * mau tan cong, va (rec #8) gop cac loi giong nhau thanh thong ke.
 *
 * Cach hoat dong:
 *  - recordEvent() dem su kien trong cua so truot
 *  - Vuot nguong -> phat canh bao (console + email neu cau hinh ALERT_EMAIL)
 *  - Co thoi gian nghi (cooldown) de khong spam cung mot canh bao
 *  - Loi giong nhau lap lai duoc GOP thanh thong ke thay vi in tung dong
 */
const { sendMailAsync } = require('./mailer');

const ALERT_EMAIL = (process.env.ALERT_EMAIL || '').trim();

/**
 * Nguong canh bao: <so lan> trong <windowMs>, nghi <cooldownMs> sau khi bao.
 * severity: 'critical' can xu ly ngay, 'warning' theo doi.
 */
const RULES = {
  SIGNATURE_INVALID: {
    count: 5, windowMs: 5 * 60e3, cooldownMs: 15 * 60e3, severity: 'critical',
    label: 'Nhieu request co chu ky khong hop le',
    hint: 'Co the dang bi do chu ky hoac sua du lieu tren duong truyen.',
  },
  AUTH_FAILED: {
    count: 3, windowMs: 5 * 60e3, cooldownMs: 15 * 60e3, severity: 'critical',
    label: 'Nhieu lan dang nhap admin that bai',
    hint: 'Co the dang bi do khoa quan tri (brute-force).',
  },
  LOOKUP_FAILED: {
    count: 10, windowMs: 5 * 60e3, cooldownMs: 15 * 60e3, severity: 'warning',
    label: 'Nhieu lan tra cuu ve that bai',
    hint: 'Co the dang bi do ma ve (enumeration).',
  },
  RATE_LIMITED: {
    count: 50, windowMs: 5 * 60e3, cooldownMs: 30 * 60e3, severity: 'warning',
    label: 'Rat nhieu request bi chan boi rate limit',
    hint: 'Co the dang bi tan cong tu dong hoac bot quet.',
  },
  SERVER_ERROR: {
    count: 10, windowMs: 5 * 60e3, cooldownMs: 15 * 60e3, severity: 'warning',
    label: 'Nhieu loi 500 lien tiep',
    hint: 'Ung dung dang gap su co, hoac bi khai thac loi xu ly ngoai le.',
  },
  // Cac su kien bao ngay lan dau (nguong = 1)
  DECRYPT_FAILED: {
    count: 1, windowMs: 60e3, cooldownMs: 30 * 60e3, severity: 'critical',
    label: 'Giai ma du lieu ca nhan that bai',
    hint: 'OpenBao dang SEALED hoac khong ket noi duoc, khoa Transit da bi xoay/xoa, '
      + 'hoac du lieu trong database da bi sua doi. Kiem tra: npm run bao-status',
  },
  AUDIT_CHAIN_BROKEN: {
    count: 1, windowMs: 60e3, cooldownMs: 60 * 60e3, severity: 'critical',
    label: 'Chuoi hash nhat ky audit bi dut',
    hint: 'Nhat ky co the da bi can thiep. Dieu tra ngay.',
  },
  UNCAUGHT_ERROR: {
    count: 1, windowMs: 60e3, cooldownMs: 10 * 60e3, severity: 'critical',
    label: 'Loi khong duoc bat (uncaught/unhandled)',
    hint: 'Co lo hong xu ly ngoai le - xem A10:2025.',
  },
};

// type -> mang moc thoi gian cac su kien
const events = new Map();
// type -> thoi diem bao dong gan nhat
const lastAlertAt = new Map();
// Cac canh bao gan nhat (de admin xem lai)
const alertLog = [];
const MAX_ALERT_LOG = 200;

// --- Gop loi giong nhau thanh thong ke (A10 rec #8) ---
const errorGroups = new Map(); // key -> { count, firstAt, lastLoggedAt }
const ERROR_SUMMARY_WINDOW_MS = 60e3;

function now() { return Date.now(); }

/**
 * Ghi nhan mot su kien bao mat. Tra ve canh bao vua phat (hoac null).
 * @param {keyof RULES} type
 * @param {{ip?:string, path?:string, requestId?:string, detail?:string}} ctx
 */
function recordEvent(type, ctx = {}) {
  const rule = RULES[type];
  if (!rule) return null;

  const t = now();
  const arr = events.get(type) || [];
  // Bo cac moc da ra khoi cua so
  const fresh = arr.filter((x) => t - x.at <= rule.windowMs);
  fresh.push({ at: t, ...ctx });
  events.set(type, fresh);

  if (fresh.length < rule.count) return null;

  // Dang trong thoi gian nghi -> khong bao lai
  const last = lastAlertAt.get(type) || 0;
  if (t - last < rule.cooldownMs) return null;
  lastAlertAt.set(type, t);

  // Thong ke IP noi bat nhat trong cua so
  const byIp = new Map();
  for (const e of fresh) if (e.ip) byIp.set(e.ip, (byIp.get(e.ip) || 0) + 1);
  const topIps = [...byIp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);

  const alert = {
    type,
    severity: rule.severity,
    label: rule.label,
    hint: rule.hint,
    occurrences: fresh.length,
    window_minutes: Math.round(rule.windowMs / 60e3),
    top_ips: topIps.map(([ip, c]) => ({ ip, count: c })),
    sample_path: ctx.path || null,
    sample_request_id: ctx.requestId || null,
    at: new Date(t).toISOString(),
  };

  emit(alert);
  // Reset de dem lai tu dau sau khi bao
  events.set(type, []);
  return alert;
}

function emit(alert) {
  alertLog.unshift(alert);
  if (alertLog.length > MAX_ALERT_LOG) alertLog.length = MAX_ALERT_LOG;

  const tag = alert.severity === 'critical' ? 'NGHIEM TRONG' : 'CANH BAO';
  console.error('');
  console.error(`*** [ALERT/${tag}] ${alert.label} ***`);
  console.error(`    ${alert.hint}`);
  console.error(`    ${alert.occurrences} lan trong ${alert.window_minutes} phut` +
    (alert.top_ips.length ? ` | IP: ${alert.top_ips.map((x) => `${x.ip}(${x.count})`).join(', ')}` : ''));
  if (alert.sample_request_id) console.error(`    request_id mau: ${alert.sample_request_id}`);
  console.error('');

  if (ALERT_EMAIL) notifyByEmail(alert);
}

function notifyByEmail(alert) {
  const lines = [
    `[${alert.severity.toUpperCase()}] ${alert.label}`,
    '',
    alert.hint,
    '',
    `So lan      : ${alert.occurrences} trong ${alert.window_minutes} phut`,
    `Thoi diem   : ${alert.at}`,
    alert.top_ips.length ? `IP noi bat  : ${alert.top_ips.map((x) => `${x.ip} (${x.count} lan)`).join(', ')}` : '',
    alert.sample_path ? `Endpoint    : ${alert.sample_path}` : '',
    alert.sample_request_id ? `request_id  : ${alert.sample_request_id}` : '',
    '',
    'Tra cuu chi tiet trong bang booking_audit.api_request_logs',
    `hoac trang quan tri > Nhat ky API (loc theo request_id).`,
  ].filter(Boolean);

  sendMailAsync({
    to: ALERT_EMAIL,
    subject: `[SkyBooking ${alert.severity === 'critical' ? 'NGHIEM TRONG' : 'Canh bao'}] ${alert.label}`,
    text: lines.join('\n'),
    tag: 'alert-' + alert.type,
  });
}

/**
 * Gop loi giong nhau: chi in dong log dau tien, sau do moi phut in mot dong
 * tong ket "da xay ra N lan". Tranh log bi tran khi mot loi lap lien tuc.
 * @returns {string|null} chuoi nen log, hoac null neu nen bo qua
 */
function summarizeError(key, message) {
  const t = now();
  let g = errorGroups.get(key);

  if (!g || t - g.firstAt > ERROR_SUMMARY_WINDOW_MS) {
    errorGroups.set(key, { count: 1, firstAt: t, lastLoggedAt: t });
    return message;
  }

  g.count++;
  if (t - g.lastLoggedAt >= ERROR_SUMMARY_WINDOW_MS) {
    g.lastLoggedAt = t;
    const seconds = Math.round((t - g.firstAt) / 1000);
    return `${message} [da xay ra ${g.count} lan trong ${seconds}s]`;
  }
  return null; // dang trong cua so gop -> khong in nua
}

/** Danh sach canh bao gan nhat (cho API quan tri). */
function recentAlerts(limit = 50) {
  return alertLog.slice(0, Math.min(limit, alertLog.length));
}

/** Trang thai hien tai cua cac bo dem (cho API quan tri). */
function counters() {
  const t = now();
  const out = {};
  for (const [type, arr] of events) {
    const rule = RULES[type];
    const fresh = arr.filter((x) => t - x.at <= rule.windowMs);
    out[type] = {
      current: fresh.length,
      threshold: rule.count,
      window_minutes: Math.round(rule.windowMs / 60e3),
    };
  }
  return out;
}

module.exports = {
  recordEvent, summarizeError, recentAlerts, counters,
  RULES, alertEmailConfigured: () => Boolean(ALERT_EMAIL),
};
