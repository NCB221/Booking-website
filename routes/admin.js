const express = require('express');
const pool = require('../db/pool');
const { decryptBatchSafe } = require('../lib/crypto');
const {
  safeEqual, issueAdminToken, verifyAdminToken,
  RE, clampInt, cleanText,
} = require('../lib/security');
const { deriveSigningKey } = require('../lib/signature');
const { requireSignature } = require('../middleware/signature');
const audit = require('../lib/auditlog');
const alerting = require('../lib/alerting');

const router = express.Router();

const ADMIN_KEY = process.env.ADMIN_KEY || '';

// Lay limiter tu app.locals tai thoi diem co request
const loginLimiter = (req, res, next) =>
  req.app.locals.limiters.loginLimiter(req, res, next);

/* ---------------------------------------------------------------
 * API2: Broken Authentication
 *  - So sanh khoa bang thoi gian hang so (chong timing attack)
 *  - Tra ve token co han 2 gio; cac request sau dung token, KHONG gui lai khoa
 *  - Rate limit 5 lan sai / 15 phut (chong brute-force)
 * -------------------------------------------------------------*/
// requireSignature: chinh request dang nhap cung phai co chu ky (bang khoa
// cua phien khach), de khoa admin khong bi sua doi tren duong truyen.
router.post('/login', loginLimiter, requireSignature, (req, res) => {
  const key = (req.body && req.body.key) || '';

  if (!ADMIN_KEY || !safeEqual(key, ADMIN_KEY)) {
    // Log de phat hien tan cong, KHONG log khoa nguoi dung nhap
    console.warn(`[AUTH] Dang nhap admin that bai tu IP ${req.ip}`);
    // Bao dong khi co dau hieu brute-force (A09:2025)
    alerting.recordEvent('AUTH_FAILED', {
      ip: req.ip, path: req.originalUrl, requestId: req.requestId,
    });
    // Thong bao chung chung, khong tiet lo khoa dung/sai o dau
    return res.status(401).json({ error: 'Khoa quan tri khong dung' });
  }

  const { token, jti, expires_in } = issueAdminToken();
  console.log(`[AUTH] Dang nhap admin thanh cong tu IP ${req.ip}`);
  // Khoa ky RIENG cho phien admin nay (khac khoa cua phien khach)
  res.json({
    ok: true,
    token,
    signing_key: deriveSigningKey(jti),
    expires_in,
  });
});

/* ---------------------------------------------------------------
 * API5: Broken Function Level Authorization
 * Moi route ben duoi deu phai qua middleware nay.
 * -------------------------------------------------------------*/
function requireAdmin(req, res, next) {
  const auth = req.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';

  const payload = verifyAdminToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Phien dang nhap khong hop le hoac da het han' });
  }
  req.admin = payload;
  // Khong cache du lieu quan tri o proxy/browser
  res.setHeader('Cache-Control', 'no-store');
  next();
}

router.use(requireAdmin);
// Moi API quan tri deu phai co chu ky HMAC hop le (toan ven + chong replay)
router.use(requireSignature);

/* ---------------------------------------------------------------
 * Validate du lieu chuyen bay (API3: chi nhan dung cac truong cho phep)
 * -------------------------------------------------------------*/
async function validateFlight(body) {
  const flight_number = cleanText(body.flight_number, 10).toUpperCase();
  const airline = cleanText(body.airline, 80);
  const from_airport = cleanText(body.from_airport, 3).toUpperCase();
  const to_airport = cleanText(body.to_airport, 3).toUpperCase();
  const departure_time = cleanText(body.departure_time, 25).replace('T', ' ');
  const arrival_time = cleanText(body.arrival_time, 25).replace('T', ' ');
  const price = Number(body.price);
  const total_seats = parseInt(body.total_seats, 10);

  if (!RE.flightNumber.test(flight_number)) return { error: 'So hieu chuyen bay khong hop le' };
  if (!RE.airline.test(airline)) {
    return { error: 'Ten hang bay khong hop le (chi chu, so, dau cach va . - & ( ) /)' };
  }
  if (!RE.airport.test(from_airport) || !RE.airport.test(to_airport)) {
    return { error: 'Ma san bay khong hop le' };
  }
  if (from_airport === to_airport) return { error: 'San bay di va den phai khac nhau' };
  if (!RE.datetime.test(departure_time) || !RE.datetime.test(arrival_time)) {
    return { error: 'Thoi gian khong hop le' };
  }
  if (new Date(arrival_time.replace(' ', 'T')) <= new Date(departure_time.replace(' ', 'T'))) {
    return { error: 'Gio den phai sau gio khoi hanh' };
  }
  if (!Number.isFinite(price) || price < 0 || price > 500000000) {
    return { error: 'Gia ve khong hop le (0 - 500.000.000)' };
  }
  if (!Number.isInteger(total_seats) || total_seats < 1 || total_seats > 1000) {
    return { error: 'So ghe phai tu 1 den 1000' };
  }

  // San bay phai ton tai (bao loi ro rang thay vi de FK nem loi 500)
  const [ap] = await pool.query(
    'SELECT code FROM airports WHERE code IN (?, ?)',
    [from_airport, to_airport]
  );
  if (ap.length < 2) return { error: 'San bay khong ton tai trong he thong' };

  return {
    data: {
      flight_number, airline, from_airport, to_airport,
      departure_time: departure_time.slice(0, 19),
      arrival_time: arrival_time.slice(0, 19),
      price, total_seats,
    },
  };
}

/* --- QUAN LY CHUYEN BAY --- */

// GET /api/admin/flights?page=1&limit=100  (API4: bat buoc phan trang)
router.get('/flights', async (req, res, next) => {
  try {
    const limit = clampInt(req.query.limit, 1, 200, 100);
    const page = clampInt(req.query.page, 1, 10000, 1);
    const offset = (page - 1) * limit;

    const [[{ total }]] = await pool.query('SELECT COUNT(*) total FROM flights');
    const [rows] = await pool.query(
      `SELECT f.id, f.flight_number, f.airline, f.from_airport, f.to_airport,
              f.departure_time, f.arrival_time, f.price, f.total_seats, f.available_seats,
              fa.city AS from_city, ta.city AS to_city,
              (SELECT COUNT(*) FROM bookings b
                WHERE b.flight_id = f.id AND b.status='CONFIRMED') AS bookings_count
         FROM flights f
         JOIN airports fa ON fa.code = f.from_airport
         JOIN airports ta ON ta.code = f.to_airport
        ORDER BY f.departure_time DESC
        LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    res.json({ data: rows, page, limit, total });
  } catch (err) { next(err); }
});

// POST /api/admin/flights
router.post('/flights', async (req, res, next) => {
  try {
    const { error, data } = await validateFlight(req.body || {});
    if (error) return res.status(400).json({ error });

    const [result] = await pool.query(
      `INSERT INTO flights
         (flight_number, airline, from_airport, to_airport, departure_time, arrival_time, price, total_seats, available_seats)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [data.flight_number, data.airline, data.from_airport, data.to_airport,
       data.departure_time, data.arrival_time, data.price, data.total_seats, data.total_seats]
    );
    res.status(201).json({ id: result.insertId });
  } catch (err) { next(err); }
});

// PUT /api/admin/flights/:id
router.put('/flights/:id', async (req, res, next) => {
  try {
    const id = clampInt(req.params.id, 1, Number.MAX_SAFE_INTEGER, 0);
    if (!id) return res.status(400).json({ error: 'ID khong hop le' });

    const { error, data } = await validateFlight(req.body || {});
    if (error) return res.status(400).json({ error });

    const [cur] = await pool.query(
      'SELECT total_seats, available_seats FROM flights WHERE id = ?', [id]
    );
    if (cur.length === 0) return res.status(404).json({ error: 'Khong tim thay chuyen bay' });

    // Giu nguyen so ghe da ban khi doi tong so ghe
    const sold = cur[0].total_seats - cur[0].available_seats;
    if (data.total_seats < sold) {
      return res.status(409).json({
        error: `Khong the giam xuong ${data.total_seats} ghe: da ban ${sold} ghe`,
      });
    }
    const newAvailable = data.total_seats - sold;

    await pool.query(
      `UPDATE flights SET
         flight_number = ?, airline = ?, from_airport = ?, to_airport = ?,
         departure_time = ?, arrival_time = ?, price = ?,
         total_seats = ?, available_seats = ?
       WHERE id = ?`,
      [data.flight_number, data.airline, data.from_airport, data.to_airport,
       data.departure_time, data.arrival_time, data.price,
       data.total_seats, newAvailable, id]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// DELETE /api/admin/flights/:id
router.delete('/flights/:id', async (req, res, next) => {
  try {
    const id = clampInt(req.params.id, 1, Number.MAX_SAFE_INTEGER, 0);
    if (!id) return res.status(400).json({ error: 'ID khong hop le' });

    const [b] = await pool.query('SELECT COUNT(*) c FROM bookings WHERE flight_id = ?', [id]);
    if (b[0].c > 0) {
      return res.status(409).json({
        error: 'Khong the xoa: chuyen bay da co ve dat. Hay huy cac ve truoc.',
      });
    }
    const [r] = await pool.query('DELETE FROM flights WHERE id = ?', [id]);
    if (r.affectedRows === 0) return res.status(404).json({ error: 'Khong tim thay chuyen bay' });
    console.log(`[ADMIN] Xoa chuyen bay id=${id} boi IP ${req.ip}`);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

/* --- QUAN LY VE DAT --- */

// GET /api/admin/bookings?page=1&limit=100
router.get('/bookings', async (req, res, next) => {
  try {
    const limit = clampInt(req.query.limit, 1, 200, 100);
    const page = clampInt(req.query.page, 1, 10000, 1);
    const offset = (page - 1) * limit;

    const [[{ total }]] = await pool.query('SELECT COUNT(*) total FROM bookings');
    const [rows] = await pool.query(
      `SELECT b.id, b.booking_code, b.passenger_name, b.passenger_email,
              b.passenger_phone, b.passenger_cccd, b.seat_count, b.total_price,
              b.status, b.created_at,
              f.flight_number, f.airline, f.from_airport, f.to_airport, f.departure_time
         FROM bookings b
         JOIN flights f ON f.id = b.flight_id
        ORDER BY b.created_at DESC
        LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    // Admin duoc xem ban DAY DU: giai ma qua OpenBao Transit.
    // Ghi log viec truy cap du lieu ca nhan (phuc vu audit).
    console.log(`[AUDIT] Admin xem ${rows.length} ve (co PII) tu IP ${req.ip}`);

    // Gom TOAN BO 3 truong x N dong vao MOT request Transit.
    // Voi limit=200 la 600 gia tri: goi tung cai se la 600 HTTP round-trip
    // (khong dung duoc), con batch chi la 1.
    const flat = [];
    for (const b of rows) {
      flat.push(b.passenger_email, b.passenger_phone, b.passenger_cccd);
    }
    const plain = await decryptBatchSafe(flat);

    res.json({
      data: rows.map((b, i) => ({
        ...b,
        passenger_email: plain[i * 3],
        passenger_phone: plain[i * 3 + 1],
        passenger_cccd: plain[i * 3 + 2],
      })),
      page, limit, total,
    });
  } catch (err) { next(err); }
});

// POST /api/admin/bookings/:id/cancel
router.post('/bookings/:id/cancel', async (req, res, next) => {
  const conn = await pool.getConnection();
  try {
    const id = clampInt(req.params.id, 1, Number.MAX_SAFE_INTEGER, 0);
    if (!id) {
      conn.release();
      return res.status(400).json({ error: 'ID khong hop le' });
    }

    await conn.beginTransaction();
    const [rows] = await conn.query(
      'SELECT id, flight_id, seat_count, status FROM bookings WHERE id = ? FOR UPDATE', [id]
    );
    if (rows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'Khong tim thay ve' });
    }
    if (rows[0].status === 'CANCELLED') {
      await conn.rollback();
      return res.status(409).json({ error: 'Ve da bi huy' });
    }
    await conn.query('UPDATE bookings SET status = ? WHERE id = ?', ['CANCELLED', rows[0].id]);
    await conn.query(
      'UPDATE flights SET available_seats = available_seats + ? WHERE id = ?',
      [rows[0].seat_count, rows[0].flight_id]
    );
    await conn.commit();
    console.log(`[ADMIN] Huy ve id=${id} boi IP ${req.ip}`);
    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    next(err);
  } finally {
    conn.release();
  }
});

/* --- NHAT KY AUDIT / DIGITAL FORENSICS --- */

// GET /api/admin/audit-logs?page=&limit=&request_id=&ip=&actor=&booking_code=&status
router.get('/audit-logs', async (req, res, next) => {
  try {
    const limit = clampInt(req.query.limit, 1, 200, 50);
    const page = clampInt(req.query.page, 1, 100000, 1);
    const offset = (page - 1) * limit;

    const where = [];
    const params = [];

    const requestId = cleanText(req.query.request_id, 64);
    if (requestId) { where.push('request_id = ?'); params.push(requestId); }

    const ip = cleanText(req.query.ip, 45);
    if (ip) { where.push('ip = ?'); params.push(ip); }

    const actor = cleanText(req.query.actor, 20);
    if (actor) { where.push('actor_role = ?'); params.push(actor); }

    const bookingCode = cleanText(req.query.booking_code, 12).toUpperCase();
    if (bookingCode) { where.push('booking_code = ?'); params.push(bookingCode); }

    const status = clampInt(req.query.status, 100, 599, 0);
    if (status) { where.push('status_code = ?'); params.push(status); }

    // Chi xem cac request bi tu choi (phuc vu dieu tra)
    if (req.query.failed === '1') where.push('status_code >= 400');

    const clause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    // Doc tu DATABASE NHAT KY RIENG bang user chi co quyen SELECT
    const [[{ total }]] = await audit.readerQuery(
      `SELECT COUNT(*) total FROM api_request_logs ${clause}`, params
    );
    const [rows] = await audit.readerQuery(
      `SELECT id, request_id, request_time, client_time, clock_skew_ms, method, path,
              status_code, duration_ms, ip, user_agent, actor_role, session_jti,
              signature, signature_valid, nonce, body_sha256, body_bytes,
              response_bytes, error_message, booking_code, prev_hash, row_hash
         FROM api_request_logs
         ${clause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    res.json({ data: rows, page, limit, total });
  } catch (err) { next(err); }
});

// GET /api/admin/audit-logs/verify - kiem tra chuoi hash con nguyen ven khong
router.get('/audit-logs/verify', async (req, res, next) => {
  try {
    const limit = clampInt(req.query.limit, 1, 100000, 10000);
    const result = await audit.verifyChain(limit);
    console.log(
      `[AUDIT] Kiem tra chuoi hash boi IP ${req.ip}: ` +
      `${result.ok ? 'NGUYEN VEN' : 'DUT CHUOI tai id=' + result.broken_at}`
    );
    if (!result.ok) {
      // Nhat ky co the da bi can thiep -> bao dong ngay (A09:2025)
      alerting.recordEvent('AUDIT_CHAIN_BROKEN', {
        ip: req.ip, detail: `broken_at=${result.broken_at}`,
      });
    }
    res.json({ ...result, queue: audit.stats() });
  } catch (err) { next(err); }
});

// GET /api/admin/alerts - canh bao bao mat gan nhat + trang thai bo dem
router.get('/alerts', (req, res) => {
  const limit = clampInt(req.query.limit, 1, 200, 50);
  res.json({
    alerts: alerting.recentAlerts(limit),
    counters: alerting.counters(),
    email_configured: alerting.alertEmailConfigured(),
    load: require('../middleware/loadshed').stats(),
  });
});

// GET /api/admin/stats
router.get('/stats', async (req, res, next) => {
  try {
    const [[flights]] = await pool.query('SELECT COUNT(*) c FROM flights');
    const [[confirmed]] = await pool.query(
      "SELECT COUNT(*) c, COALESCE(SUM(total_price),0) revenue FROM bookings WHERE status='CONFIRMED'"
    );
    const [[cancelled]] = await pool.query(
      "SELECT COUNT(*) c FROM bookings WHERE status='CANCELLED'"
    );
    res.json({
      flights: flights.c,
      confirmed_bookings: confirmed.c,
      cancelled_bookings: cancelled.c,
      revenue: Number(confirmed.revenue),
    });
  } catch (err) { next(err); }
});

module.exports = router;
