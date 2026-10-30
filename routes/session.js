const express = require('express');
const { issueToken } = require('../lib/security');
const { deriveSigningKey, MAX_SKEW_SECONDS } = require('../lib/signature');

const router = express.Router();

/**
 * POST /api/session
 * Cap mot phien lam viec cho khach, gom:
 *   - client_token : gui lai qua header X-Client-Token
 *   - signing_key  : dung de ky request (HMAC-SHA256)
 *
 * Khoa ky la RIENG cho tung phien va het han sau 1 gio, nen khong co
 * khoa tinh nao bi hardcode trong ma nguon frontend.
 */
router.post('/session', (req, res) => {
  const { token, jti, expires_in } = issueToken('client');
  res.json({
    client_token: token,
    signing_key: deriveSigningKey(jti),
    expires_in,
    // Cho client biet quy tac ky de tu dong bo dong ho
    signature: {
      algorithm: 'HMAC-SHA256',
      version: 'v1',
      headers: ['X-Timestamp', 'X-Nonce', 'X-Signature'],
      max_skew_seconds: MAX_SKEW_SECONDS,
      server_time: Math.floor(Date.now() / 1000),
    },
  });
});

module.exports = router;
