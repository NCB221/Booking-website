/**
 * Chong can kiet tai nguyen o tang ung dung (OWASP A10:2025 rec #7).
 *
 * Rate limit theo IP khong du: trong tan cong phan tan (DDoS) moi IP chi gui
 * vai request nen khong IP nao vuot nguong, nhung TONG tai van lam server sap.
 * Middleware nay gioi han SO REQUEST DANG XU LY DONG THOI va "do tai"
 * (load shedding) bang 503 khi vuot - tra loi nhanh con hon treo het.
 *
 * LUU Y QUAN TRONG: day chi la lop phong thu CUOI o tang ung dung.
 * DDoS the tich (volumetric) lam nghen bang thong TRUOC khi goi tin den duoc
 * Node, nen bat buoc phai co CDN/scrubbing (Cloudflare) hoac reverse proxy.
 */
const alerting = require('../lib/alerting');

const MAX_IN_FLIGHT = Number(process.env.MAX_CONCURRENT_REQUESTS) || 200;

let inFlight = 0;
let shedCount = 0;
let peakInFlight = 0;

function loadShed(req, res, next) {
  if (inFlight >= MAX_IN_FLIGHT) {
    shedCount++;
    // Bao dong khi bi do tai nhieu -> dau hieu dang bi tan cong
    alerting.recordEvent('RATE_LIMITED', {
      ip: req.ip, path: req.originalUrl, detail: 'load shedding',
    });
    res.setHeader('Retry-After', '5');
    return res.status(503).json({
      error: 'May chu dang qua tai, vui long thu lai sau vai giay.',
    });
  }

  inFlight++;
  if (inFlight > peakInFlight) peakInFlight = inFlight;

  // 'close' luon phat (ca khi client ngat giua duong), 'finish' thi khong.
  // Dung co de khong tru 2 lan.
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    inFlight--;
  };
  res.once('finish', release);
  res.once('close', release);

  next();
}

function stats() {
  return { in_flight: inFlight, peak: peakInFlight, shed: shedCount, max: MAX_IN_FLIGHT };
}

module.exports = { loadShed, stats, MAX_IN_FLIGHT };
