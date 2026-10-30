/**
 * Gan request_id + request_time cho MOI request API, va ghi nhat ky audit
 * sau khi response da duoc gui.
 *
 *  requestContext      - sinh/nhan request_id, ghi nhan thoi diem nhan request,
 *                        tra lai 2 header X-Request-Id / X-Request-Time cho client.
 *  auditLogger         - dang ky res.on('finish') de day ban ghi vao hang doi.
 *                        Dat SOM trong chuoi middleware de ghi duoc ca cac response
 *                        bi rate limit chan (429) hay loi tu middleware.
 *  auditPayloadCapture - boc res.json de doc error/booking_code/kich thuoc.
 *                        Phai dang ky SAU signResponses de nam ngoai cung.
 */
const crypto = require('crypto');
const audit = require('../lib/auditlog');
const { sha256Hex } = require('../lib/signature');

// UUID v4 hoac chuoi hex/base64url an toan do client gui len
const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

/**
 * request_id: uu tien gia tri client gui (de doi chieu log 2 phia),
 * nhung phai dung dinh dang; neu khong co/khong hop le thi server tu sinh.
 */
function requestContext(req, res, next) {
  const supplied = (req.get('x-request-id') || '').trim();
  req.requestId = REQUEST_ID_RE.test(supplied) ? supplied : crypto.randomUUID();
  req.requestIdSource = REQUEST_ID_RE.test(supplied) ? 'client' : 'server';

  req.requestTimeMs = Date.now();
  req.requestTimeIso = new Date(req.requestTimeMs).toISOString();
  req.startHr = process.hrtime.bigint();

  // Tra lai cho client de doi chieu khi can dieu tra
  res.setHeader('X-Request-Id', req.requestId);
  res.setHeader('X-Request-Time', req.requestTimeIso);

  const exposed = res.getHeader('Access-Control-Expose-Headers');
  res.setHeader(
    'Access-Control-Expose-Headers',
    [exposed, 'X-Request-Id', 'X-Request-Time'].filter(Boolean).join(', ')
  );

  next();
}

/** Lay ma ve de lien ket nghiep vu (ma ve KHONG phai du lieu ca nhan). */
function extractBookingCode(req, payload) {
  if (payload && typeof payload === 'object' && payload.booking_code) {
    return payload.booking_code;
  }
  if (req.body && typeof req.body.code === 'string') return req.body.code;
  // /api/bookings/<CODE>/cancel
  const m = /^\/api\/bookings\/([A-Z0-9]{4,12})\/cancel/i.exec(req.path);
  return m ? m[1] : null;
}

/**
 * Boc res.json de doc payload. Dang ky SAU signResponses nen nam ngoai cung:
 *   route -> auditPayloadCapture -> signResponses -> res.send
 */
function auditPayloadCapture(req, res, next) {
  const originalJson = res.json.bind(res);

  res.json = (payload) => {
    try {
      res.locals._auditError =
        payload && typeof payload === 'object' && payload.error ? payload.error : null;
      res.locals._auditBookingCode = extractBookingCode(req, payload);
      res.locals._auditResponseBytes = Buffer.byteLength(JSON.stringify(payload) || '', 'utf8');
    } catch { /* khong de loi audit lam vo response */ }
    return originalJson(payload);
  };

  next();
}

function auditLogger(req, res, next) {
  res.on('finish', () => {
    try {
      const durationMs = Number((process.hrtime.bigint() - req.startHr) / 1000000n);

      // Thoi diem client khai bao (X-Timestamp da duoc ky) -> do lech dong ho
      const tsHeader = req.get('x-timestamp');
      let clientTimeMs = null, clockSkewMs = null;
      if (tsHeader && /^\d{1,15}$/.test(tsHeader)) {
        clientTimeMs = Number(tsHeader) * 1000;
        clockSkewMs = req.requestTimeMs - clientTimeMs;
      }

      audit.enqueue({
        request_id: req.requestId,
        request_time_ms: req.requestTimeMs,
        client_time_ms: clientTimeMs,
        clock_skew_ms: clockSkewMs,
        method: req.method,
        path: req.originalUrl,
        status_code: res.statusCode,
        duration_ms: durationMs,
        ip: req.ip,
        user_agent: req.get('user-agent'),
        actor_role: (req.session && req.session.role) || 'anonymous',
        session_jti: (req.session && req.session.jti) || null,
        signature: req.get('x-signature') || null,
        // true/false khi endpoint co kiem chu ky; null khi endpoint khong yeu cau
        signature_valid: res.locals._signatureValid === undefined
          ? null : res.locals._signatureValid,
        nonce: req.get('x-nonce') || null,
        // CHI luu hash cua body - khong luu CCCD/email/dien thoai
        body_sha256: req.rawBody && req.rawBody.length > 0 ? sha256Hex(req.rawBody) : null,
        body_bytes: req.rawBody ? req.rawBody.length : 0,
        response_bytes: res.locals._auditResponseBytes
          || Number(res.getHeader('content-length')) || 0,
        error_message: res.locals._auditError || null,
        booking_code: res.locals._auditBookingCode || null,
      });
    } catch (err) {
      console.error('[AUDIT] Loi thu thap nhat ky:', err.message);
    }
  });

  next();
}

module.exports = { requestContext, auditLogger, auditPayloadCapture };
