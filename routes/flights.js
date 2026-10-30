const express = require('express');
const pool = require('../db/pool');
const { RE, clampInt, cleanText, isValidDate } = require('../lib/security');

const router = express.Router();

// GET /api/airports - danh sach san bay (du lieu cong khai, khong co PII)
router.get('/airports', async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT code, name, city FROM airports ORDER BY city');
    // Du lieu it thay doi -> cho cache ngan
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.json(rows);
  } catch (err) { next(err); }
});

/**
 * GET /api/flights - tim kiem chuyen bay
 * query: from, to, date (YYYY-MM-DD), passengers, page, limit
 * API3: chi tra ve cac cot can thiet (khong dung SELECT f.*)
 * API4: luon gioi han so dong tra ve
 */
router.get('/flights', async (req, res, next) => {
  try {
    const from = cleanText(req.query.from, 3).toUpperCase();
    const to = cleanText(req.query.to, 3).toUpperCase();
    const date = cleanText(req.query.date, 10);
    const need = clampInt(req.query.passengers, 1, 9, 1);
    const limit = clampInt(req.query.limit, 1, 100, 50);
    const page = clampInt(req.query.page, 1, 200, 1);
    const offset = (page - 1) * limit;

    // Validate dau vao thay vi nhet thang vao cau query
    if (from && !RE.airport.test(from)) {
      return res.status(400).json({ error: 'Ma san bay di khong hop le' });
    }
    if (to && !RE.airport.test(to)) {
      return res.status(400).json({ error: 'Ma san bay den khong hop le' });
    }
    if (date && !isValidDate(date)) {
      return res.status(400).json({ error: 'Ngay khong hop le (dinh dang YYYY-MM-DD)' });
    }

    const where = ['f.available_seats >= ?', 'f.departure_time >= NOW()'];
    const params = [need];

    if (from) { where.push('f.from_airport = ?'); params.push(from); }
    if (to) { where.push('f.to_airport = ?'); params.push(to); }
    if (date) { where.push('DATE(f.departure_time) = ?'); params.push(date); }

    const [rows] = await pool.query(
      `SELECT f.id, f.flight_number, f.airline, f.from_airport, f.to_airport,
              f.departure_time, f.arrival_time, f.price, f.available_seats,
              fa.name AS from_name, fa.city AS from_city,
              ta.name AS to_name,   ta.city AS to_city
         FROM flights f
         JOIN airports fa ON fa.code = f.from_airport
         JOIN airports ta ON ta.code = f.to_airport
        WHERE ${where.join(' AND ')}
        ORDER BY f.departure_time ASC
        LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// GET /api/flights/:id - chi tiet 1 chuyen bay
router.get('/flights/:id', async (req, res, next) => {
  try {
    const id = clampInt(req.params.id, 1, Number.MAX_SAFE_INTEGER, 0);
    if (!id) return res.status(400).json({ error: 'ID chuyen bay khong hop le' });

    const [rows] = await pool.query(
      `SELECT f.id, f.flight_number, f.airline, f.from_airport, f.to_airport,
              f.departure_time, f.arrival_time, f.price, f.available_seats,
              fa.name AS from_name, fa.city AS from_city,
              ta.name AS to_name,   ta.city AS to_city
         FROM flights f
         JOIN airports fa ON fa.code = f.from_airport
         JOIN airports ta ON ta.code = f.to_airport
        WHERE f.id = ?`,
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Khong tim thay chuyen bay' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
