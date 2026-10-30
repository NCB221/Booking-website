const crypto = require('crypto');
const express = require('express');
const pool = require('../db/pool');
const {
  encryptBatch, decryptSafe, decryptBatchSafe, maskEmail, maskPhone, maskCccd,
} = require('../lib/crypto');
const { safeEqual, RE, clampInt, cleanText } = require('../lib/security');
const { requireSignature } = require('../middleware/signature');
const alerting = require('../lib/alerting');
const { sendMailAsync } = require('../lib/mailer');
const { bookingConfirmation, bookingCancellation } = require('../lib/emailTemplates');

const router = express.Router();

const MAX_SEATS_PER_BOOKING = 9;

// Lay limiter tu app.locals tai thoi diem co request
const lookupLimiter = (req, res, next) =>
  req.app.locals.limiters.lookupLimiter(req, res, next);
const bookingLimiter = (req, res, next) =>
  req.app.locals.limiters.bookingLimiter(req, res, next);

/** Sinh ma ve bang crypto an toan (khong dung Math.random de kho doan hon). */
function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(8);
  let s = '';
  for (let i = 0; i < 8; i++) s += chars[bytes[i] % chars.length];
  return s;
}

/**
 * API1 - Broken Object Level Authorization:
 * Chi co mot ma ve KHONG du de xem/huy ve. Phai kem email dung chu so huu.
 * Vi email duoc ma hoa, ta lay dung 1 dong theo ma ve roi giai ma de so sanh.
 */
async function ownsBooking(row, email) {
  const real = (await decryptSafe(row.passenger_email)).trim().toLowerCase();
  return safeEqual(real, String(email || '').trim().toLowerCase());
}

/**
 * Tra ve DTO cho khach: chi cac truong can thiet, PII da che bot (API3).
 * ASYNC vi giai ma gio di qua OpenBao Transit. Gom 3 truong vao MOT request.
 */
async function toCustomerDto(b) {
  const [email, phone, cccd] = await decryptBatchSafe([
    b.passenger_email, b.passenger_phone, b.passenger_cccd,
  ]);
  return {
    booking_code: b.booking_code,
    passenger_name: b.passenger_name,
    passenger_email: maskEmail(email),
    passenger_phone: maskPhone(phone),
    passenger_cccd: maskCccd(cccd),
    seat_count: b.seat_count,
    total_price: b.total_price,
    status: b.status,
    created_at: b.created_at,
    flight_number: b.flight_number,
    airline: b.airline,
    from_airport: b.from_airport,
    to_airport: b.to_airport,
    from_city: b.from_city,
    to_city: b.to_city,
    departure_time: b.departure_time,
    arrival_time: b.arrival_time,
  };
}

const BOOKING_SELECT = `
  SELECT b.id, b.booking_code, b.flight_id, b.passenger_name, b.passenger_email,
         b.passenger_phone, b.passenger_cccd, b.seat_count, b.total_price,
         b.status, b.created_at,
         f.flight_number, f.airline, f.from_airport, f.to_airport,
         f.departure_time, f.arrival_time,
         fa.city AS from_city, ta.city AS to_city
    FROM bookings b
    JOIN flights f   ON f.id = b.flight_id
    JOIN airports fa ON fa.code = f.from_airport
    JOIN airports ta ON ta.code = f.to_airport`;

/**
 * Lay chi tiet chuyen bay roi gui email cho khach.
 * Chay o background (khong await o route) va tu bat moi loi, nen su co
 * email KHONG BAO GIO lam vo luong dat ve / huy ve.
 */
async function sendBookingEmail(data) {
  try {
    const [rows] = await pool.query(
      `SELECT f.flight_number, f.airline, f.from_airport, f.to_airport,
              f.departure_time, f.arrival_time,
              fa.city AS from_city, ta.city AS to_city
         FROM flights f
         JOIN airports fa ON fa.code = f.from_airport
         JOIN airports ta ON ta.code = f.to_airport
        WHERE f.id = ?`,
      [data.flight_id]
    );
    if (rows.length === 0) {
      console.error(
        `[MAIL] Khong tim thay chuyen bay ${data.flight_id} de gui email ve ${data.booking_code}`
      );
      return;
    }

    const payload = { ...rows[0], ...data };
    const mail = data.template === 'cancellation'
      ? bookingCancellation(payload)
      : bookingConfirmation(payload);

    sendMailAsync({ to: data.email, ...mail, tag: data.booking_code });
  } catch (err) {
    console.error(`[MAIL] Loi chuan bi email cho ve ${data.booking_code}: ${err.message}`);
  }
}

/* ---------------------------------------------------------------
 * POST /api/bookings - dat ve
 * API4/API6: gioi han so ghe + rate limit chong bot dat ve hang loat
 * -------------------------------------------------------------*/
router.post('/bookings', bookingLimiter, requireSignature, async (req, res, next) => {
  const body = req.body || {};

  // API3: chi doc dung cac truong cho phep (chong mass assignment).
  // total_price LUON tinh o server, khong bao gio nhan tu client.
  const passenger_name = cleanText(body.passenger_name, 120);
  const email = cleanText(body.passenger_email, 120).toLowerCase();
  const phone = cleanText(body.passenger_phone, 30).replace(/[\s.-]/g, '');
  const cccd = cleanText(body.passenger_cccd, 20).replace(/[\s.-]/g, '');
  const flight_id = clampInt(body.flight_id, 1, Number.MAX_SAFE_INTEGER, 0);
  const seat_count = clampInt(body.seat_count, 1, MAX_SEATS_PER_BOOKING, 1);

  if (!flight_id) return res.status(400).json({ error: 'Chuyen bay khong hop le' });
  if (!passenger_name || !email || !phone || !cccd) {
    return res.status(400).json({ error: 'Vui long dien day du thong tin hanh khach (gom ca CCCD)' });
  }
  if (!RE.name.test(passenger_name)) {
    return res.status(400).json({ error: 'Ho ten chi duoc chua chu cai, dau cach, dau - va .' });
  }
  if (!RE.email.test(email)) return res.status(400).json({ error: 'Email khong hop le' });
  if (!RE.phone.test(phone)) {
    return res.status(400).json({ error: 'So dien thoai khong hop le (vi du: 0901234567)' });
  }
  if (!RE.cccd.test(cccd)) {
    return res.status(400).json({ error: 'CCCD phai gom 12 so (hoac CMND 9 so)' });
  }
  if (Number(body.seat_count) > MAX_SEATS_PER_BOOKING) {
    return res.status(400).json({
      error: `Moi lan dat toi da ${MAX_SEATS_PER_BOOKING} ghe. Vui long chia thanh nhieu don.`,
    });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Khoa dong chuyen bay de tranh dat trung ghe
    const [flights] = await conn.query(
      'SELECT id, price, available_seats, departure_time FROM flights WHERE id = ? FOR UPDATE',
      [flight_id]
    );
    if (flights.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'Chuyen bay khong ton tai' });
    }
    const flight = flights[0];

    // Khong cho dat chuyen bay da khoi hanh
    if (new Date(flight.departure_time.replace(' ', 'T')) <= new Date()) {
      await conn.rollback();
      return res.status(409).json({ error: 'Chuyen bay nay da khoi hanh' });
    }
    if (flight.available_seats < seat_count) {
      await conn.rollback();
      return res.status(409).json({ error: `Chi con ${flight.available_seats} ghe trong` });
    }

    const total_price = Number(flight.price) * seat_count;

    // Sinh ma ve duy nhat
    let code = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      const candidate = genCode();
      const [dup] = await conn.query(
        'SELECT 1 FROM bookings WHERE booking_code = ?', [candidate]
      );
      if (dup.length === 0) { code = candidate; break; }
    }
    if (!code) {
      await conn.rollback();
      return res.status(503).json({ error: 'Khong tao duoc ma ve, vui long thu lai' });
    }

    // Ma hoa qua OpenBao Transit truoc khi luu. Gom 3 truong vao MOT request
    // de chi mat 1 round-trip thay vi 3.
    // Neu OpenBao khong san sang, lenh nay throw -> catch ben duoi rollback,
    // nen KHONG BAO GIO luu plaintext vao database (fail closed).
    const [encEmail, encPhone, encCccd] = await encryptBatch([email, phone, cccd]);

    const [result] = await conn.query(
      `INSERT INTO bookings
         (booking_code, flight_id, passenger_name, passenger_email, passenger_phone, passenger_cccd, seat_count, total_price)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [code, flight_id, passenger_name, encEmail, encPhone, encCccd,
       seat_count, total_price]
    );

    await conn.query(
      'UPDATE flights SET available_seats = available_seats - ? WHERE id = ?',
      [seat_count, flight_id]
    );

    await conn.commit();
    // Log khong chua PII
    console.log(`[BOOKING] Tao ve ${code} (${seat_count} ghe) cho chuyen ${flight_id}`);

    // Tra ket qua cho khach NGAY, roi moi gui email o background.
    res.status(201).json({ id: result.insertId, booking_code: code, total_price });

    // Gui email xac nhan (sau commit nen khong gui cho ve bi rollback).
    // Dung plaintext dang co san o day, khong can giai ma lai tu DB.
    sendBookingEmail({
      booking_code: code,
      flight_id,
      email,
      passenger_name,
      passenger_phone: phone,
      passenger_cccd: cccd,
      seat_count,
      total_price,
      template: 'confirmation',
    });
  } catch (err) {
    await conn.rollback();
    next(err);
  } finally {
    conn.release();
  }
});

/* ---------------------------------------------------------------
 * POST /api/bookings/lookup - tra cuu ve
 * Dung POST (khong phai GET) de email khong bi ghi vao log truy cap
 * va lich su trinh duyet.
 * API1: bat buoc ma ve + email dung chu so huu.
 * -------------------------------------------------------------*/
router.post('/bookings/lookup', lookupLimiter, requireSignature, async (req, res, next) => {
  try {
    const body = req.body || {};
    const code = cleanText(body.code, 12).toUpperCase();
    const email = cleanText(body.email, 120).toLowerCase();

    if (!RE.bookingCode.test(code) || !RE.email.test(email)) {
      return res.status(400).json({ error: 'Vui long nhap dung ma ve va email da dung khi dat' });
    }

    const [rows] = await pool.query(`${BOOKING_SELECT} WHERE b.booking_code = ?`, [code]);

    // Tra ve CUNG MOT thong bao cho ca 2 truong hop (khong co ma ve / sai email)
    // -> khong the do xem ma ve nao ton tai (chong enumeration).
    if (rows.length === 0 || !(await ownsBooking(rows[0], email))) {
      console.warn(`[LOOKUP] Tra cuu that bai cho ma ${code} tu IP ${req.ip}`);
      // Nhieu lan that bai -> co the dang do ma ve (A09:2025)
      alerting.recordEvent('LOOKUP_FAILED', {
        ip: req.ip, path: req.originalUrl, requestId: req.requestId,
      });
      return res.status(404).json({ error: 'Khong tim thay ve khop voi ma ve va email da nhap' });
    }

    res.setHeader('Cache-Control', 'no-store');
    res.json(await toCustomerDto(rows[0]));
  } catch (err) { next(err); }
});

/* ---------------------------------------------------------------
 * POST /api/bookings/:code/cancel - huy ve
 * API1: phai co email chu so huu moi huy duoc.
 * -------------------------------------------------------------*/
router.post('/bookings/:code/cancel', lookupLimiter, requireSignature, async (req, res, next) => {
  const conn = await pool.getConnection();
  try {
    const code = cleanText(req.params.code, 12).toUpperCase();
    const email = cleanText((req.body || {}).email, 120).toLowerCase();

    if (!RE.bookingCode.test(code) || !RE.email.test(email)) {
      conn.release();
      return res.status(400).json({ error: 'Vui long nhap dung ma ve va email' });
    }

    await conn.beginTransaction();
    const [rows] = await conn.query(
      `SELECT id, flight_id, seat_count, status, total_price, passenger_name,
              passenger_email, passenger_phone, passenger_cccd
         FROM bookings WHERE booking_code = ? FOR UPDATE`,
      [code]
    );

    if (rows.length === 0 || !(await ownsBooking(rows[0], email))) {
      await conn.rollback();
      console.warn(`[CANCEL] Huy ve that bai cho ma ${code} tu IP ${req.ip}`);
      return res.status(404).json({ error: 'Khong tim thay ve khop voi ma ve va email da nhap' });
    }

    const booking = rows[0];
    if (booking.status === 'CANCELLED') {
      await conn.rollback();
      return res.status(409).json({ error: 'Ve nay da bi huy truoc do' });
    }

    await conn.query('UPDATE bookings SET status = ? WHERE id = ?', ['CANCELLED', booking.id]);
    await conn.query(
      'UPDATE flights SET available_seats = available_seats + ? WHERE id = ?',
      [booking.seat_count, booking.flight_id]
    );

    await conn.commit();
    console.log(`[CANCEL] Da huy ve ${code}`);
    res.json({ ok: true, message: 'Da huy ve thanh cong' });

    // Giai ma 2 truong con lai trong MOT request de dua vao email thong bao.
    // Dat SAU res.json nen cham tre cua OpenBao khong lam khach phai cho.
    const [cPhone, cCccd] = await decryptBatchSafe([
      booking.passenger_phone, booking.passenger_cccd,
    ]);

    // Gui email thong bao da huy (giup khach phat hien neu bi huy trai phep)
    sendBookingEmail({
      booking_code: code,
      flight_id: booking.flight_id,
      email, // da duoc xac thuc khop chu so huu o tren
      passenger_name: booking.passenger_name,
      passenger_phone: cPhone,
      passenger_cccd: cCccd,
      seat_count: booking.seat_count,
      total_price: booking.total_price,
      template: 'cancellation',
    });
  } catch (err) {
    await conn.rollback();
    next(err);
  } finally {
    conn.release();
  }
});

module.exports = router;
