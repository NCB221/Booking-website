/**
 * Middleware xu ly chu ky HMAC cho request va response.
 *
 *  attachSession      - doc token phien (neu co) -> req.signingKey. Khong tu choi.
 *  requireSignature   - BAT BUOC request phai co chu ky hop le.
 *  signResponses      - ky moi response JSON de client xac minh.
 */
const { verifyToken } = require('../lib/security');
const { deriveSigningKey, verifyRequestSignature, signResponseBody } = require('../lib/signature');
const alerting = require('../lib/alerting');

/**
 * Lay token phien tu header:
 *   - Admin : Authorization: Bearer <token>
 *   - Khach : X-Client-Token: <token>
 */
function readSessionToken(req) {
  const auth = req.get('authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return (req.get('x-client-token') || '').trim();
}

/**
 * Gan thong tin phien vao request neu token hop le.
 * KHONG tu choi request - de cac endpoint cong khai van chay binh thuong.
 */
function attachSession(req, res, next) {
  const token = readSessionToken(req);
  if (token) {
    const payload = verifyToken(token);
    if (payload) {
      req.session = payload;
      req.signingKey = deriveSigningKey(payload.jti);
    }
  }
  next();
}

/**
 * Bat buoc request mang chu ky hop le.
 * Dung cho moi endpoint thay doi du lieu (POST/PUT/DELETE) va cac API nhay cam.
 */
function requireSignature(req, res, next) {
  if (!req.signingKey) {
    return res.status(401).json({
      error: 'Thieu phien lam viec. Hay goi POST /api/session de lay khoa ky.',
    });
  }

  const result = verifyRequestSignature(req, req.signingKey);
  // Ghi lai ket qua xac minh vao nhat ky audit
  res.locals._signatureValid = result.ok;
  if (!result.ok) {
    // Gop cac loi giong nhau de log khong bi tran (A10:2025 rec #8)
    const line = alerting.summarizeError(
      `sig:${result.error}`,
      `[SIG] ${req.method} ${req.originalUrl} - ${result.error} ` +
      `(IP ${req.ip}, request_id ${req.requestId})`
    );
    if (line) console.warn(line);

    // Phat hien mau tan cong (A09:2025)
    alerting.recordEvent('SIGNATURE_INVALID', {
      ip: req.ip, path: req.originalUrl, requestId: req.requestId,
    });
    return res.status(result.status).json({ error: result.error });
  }
  next();
}

/**
 * Ky response JSON bang khoa cua phien goi request.
 * Client xac minh header X-Signature de chac chan du lieu nhan ve
 * khong bi sua tren duong truyen.
 */
function signResponses(req, res, next) {
  const originalJson = res.json.bind(res);

  res.json = (payload) => {
    if (req.signingKey) {
      try {
        const body = JSON.stringify(payload);
        const timestamp = Math.floor(Date.now() / 1000);
        const signature = signResponseBody(req.signingKey, {
          method: req.method,
          path: req.originalUrl,
          timestamp,
          requestId: req.requestId,
          body,
        });
        res.setHeader('X-Timestamp', String(timestamp));
        res.setHeader('X-Signature', signature);
        // De trinh duyet doc duoc 2 header nay khi goi cross-origin
        res.setHeader('Access-Control-Expose-Headers', 'X-Timestamp, X-Signature');
        // Gui chinh xac chuoi da ky (tranh lech do serialize lai)
        res.type('application/json').send(body);
        return res;
      } catch (err) {
        console.error('[SIG] Khong ky duoc response:', err.message);
      }
    }
    return originalJson(payload);
  };

  next();
}

module.exports = { attachSession, requireSignature, signResponses };
