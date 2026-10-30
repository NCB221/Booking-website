require('dotenv').config();
const mysql = require('mysql2/promise');
const { encryptBatch, isEncrypted } = require('../lib/crypto');

const DB_NAME = process.env.DB_NAME || 'booking';

const CONN = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  multipleStatements: true,
};

const DDL = `
CREATE TABLE IF NOT EXISTS airports (
  code    VARCHAR(3)  NOT NULL PRIMARY KEY,
  name    VARCHAR(120) NOT NULL,
  city    VARCHAR(80)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS flights (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  flight_number   VARCHAR(10)  NOT NULL,
  airline         VARCHAR(80)  NOT NULL,
  from_airport    VARCHAR(3)   NOT NULL,
  to_airport      VARCHAR(3)   NOT NULL,
  departure_time  DATETIME     NOT NULL,
  arrival_time    DATETIME     NOT NULL,
  price           DECIMAL(12,2) NOT NULL,
  total_seats     INT          NOT NULL DEFAULT 180,
  available_seats INT          NOT NULL DEFAULT 180,
  created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_flight_from FOREIGN KEY (from_airport) REFERENCES airports(code),
  CONSTRAINT fk_flight_to   FOREIGN KEY (to_airport)   REFERENCES airports(code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS bookings (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  booking_code    VARCHAR(12)  NOT NULL UNIQUE,
  flight_id       INT          NOT NULL,
  passenger_name  VARCHAR(120) NOT NULL,
  -- 3 cot duoi day luu du lieu DA MA HOA AES-256-GCM (khong bao gio plaintext)
  passenger_email VARCHAR(512) NOT NULL,
  passenger_phone VARCHAR(512) NOT NULL,
  passenger_cccd  VARCHAR(512) NOT NULL,
  seat_count      INT          NOT NULL DEFAULT 1,
  total_price     DECIMAL(12,2) NOT NULL,
  status          ENUM('CONFIRMED','CANCELLED') NOT NULL DEFAULT 'CONFIRMED',
  created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_booking_flight FOREIGN KEY (flight_id) REFERENCES flights(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- LUU Y: bang nhat ky api_request_logs KHONG nam o day.
-- No duoc tach sang database rieng (booking_audit) voi 2 user han che quyen,
-- de ung dung khong the sua/xoa log. Khoi tao: npm run setup-audit
`;

const AIRPORTS = [
  ['HAN', 'San bay Noi Bai', 'Ha Noi'],
  ['SGN', 'San bay Tan Son Nhat', 'TP. Ho Chi Minh'],
  ['DAD', 'San bay Da Nang', 'Da Nang'],
  ['CXR', 'San bay Cam Ranh', 'Nha Trang'],
  ['PQC', 'San bay Phu Quoc', 'Phu Quoc'],
  ['HPH', 'San bay Cat Bi', 'Hai Phong'],
  ['HUI', 'San bay Phu Bai', 'Hue'],
  ['VCA', 'San bay Can Tho', 'Can Tho'],
  ['DLI', 'San bay Lien Khuong', 'Da Lat'],
  ['VII', 'San bay Vinh', 'Vinh'],
];

const AIRLINES = ['Vietnam Airlines', 'VietJet Air', 'Bamboo Airways', 'Vietravel Airlines'];

// Mot so chang bay pho bien (gio bay xap xi tinh bang phut)
const ROUTES = [
  ['HAN', 'SGN', 125], ['SGN', 'HAN', 125],
  ['HAN', 'DAD', 80],  ['DAD', 'HAN', 80],
  ['SGN', 'DAD', 85],  ['DAD', 'SGN', 85],
  ['HAN', 'CXR', 115], ['CXR', 'HAN', 115],
  ['SGN', 'CXR', 60],  ['CXR', 'SGN', 60],
  ['HAN', 'PQC', 130], ['PQC', 'HAN', 130],
  ['SGN', 'PQC', 60],  ['PQC', 'SGN', 60],
  ['HAN', 'DLI', 105], ['DLI', 'HAN', 105],
  ['SGN', 'HUI', 80],  ['HUI', 'SGN', 80],
  ['HAN', 'VCA', 130], ['VCA', 'HAN', 130],
];

function pad(n) { return String(n).padStart(2, '0'); }
function fmt(d) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}:00`;
}
function priceFor(mins) {
  // Gia co ban theo thoi gian bay + chut ngau nhien, lam tron nghin
  const base = 450000 + mins * 3500 + Math.floor(Math.random() * 400000);
  return Math.round(base / 1000) * 1000;
}

function buildFlights() {
  const rows = [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const departHours = [6, 9, 12, 15, 18, 21];
  let seq = 100;

  // Tao chuyen bay cho 14 ngay toi
  for (let day = 0; day < 14; day++) {
    for (const [from, to, mins] of ROUTES) {
      // moi chang ~2 chuyen/ngay
      const picks = [departHours[Math.floor(Math.random() * 3)],
                     departHours[3 + Math.floor(Math.random() * 3)]];
      for (const h of picks) {
        const dep = new Date(today);
        dep.setDate(dep.getDate() + day);
        dep.setHours(h, [0, 15, 30, 45][Math.floor(Math.random() * 4)], 0, 0);
        const arr = new Date(dep.getTime() + mins * 60000);
        const airline = AIRLINES[Math.floor(Math.random() * AIRLINES.length)];
        const code = airline.split(' ')[0].substring(0, 2).toUpperCase();
        const totalSeats = [150, 180, 186, 220][Math.floor(Math.random() * 4)];
        const sold = Math.floor(Math.random() * 40);
        rows.push([
          `${code}${++seq}`, airline, from, to, fmt(dep), fmt(arr),
          priceFor(mins), totalSeats, totalSeats - sold,
        ]);
      }
    }
  }
  return rows;
}

/**
 * Chuyen database cu sang dang ma hoa:
 *  1. Them cot passenger_cccd neu chua co
 *  2. Noi rong cac cot email/phone (ban ma hoa dai hon plaintext)
 *  3. Ma hoa cac dong con dang plaintext
 * Ham nay idempotent - chay nhieu lan khong gay hai.
 */
async function migrateEncryption(conn) {
  const [cols] = await conn.query(
    `SELECT COLUMN_NAME, CHARACTER_MAXIMUM_LENGTH AS len
       FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'bookings'`,
    [DB_NAME]
  );
  const byName = new Map(cols.map((c) => [c.COLUMN_NAME, c.len]));

  // 1. Cot CCCD
  if (!byName.has('passenger_cccd')) {
    await conn.query(
      `ALTER TABLE bookings
         ADD COLUMN passenger_cccd VARCHAR(512) NOT NULL DEFAULT ''
         AFTER passenger_phone`
    );
    console.log('-> Da them cot passenger_cccd');
  }

  // 2. Noi rong cot de chua ban ma hoa
  for (const col of ['passenger_email', 'passenger_phone']) {
    if ((byName.get(col) || 0) < 512) {
      await conn.query(`ALTER TABLE bookings MODIFY ${col} VARCHAR(512) NOT NULL`);
      console.log(`-> Da noi rong cot ${col} -> VARCHAR(512)`);
    }
  }

  // 3. Ma hoa cac dong con plaintext
  const [rows] = await conn.query(
    'SELECT id, passenger_email, passenger_phone, passenger_cccd FROM bookings'
  );
  let migrated = 0;
  for (const r of rows) {
    const sets = [];
    const plainVals = [];
    for (const col of ['passenger_email', 'passenger_phone', 'passenger_cccd']) {
      const val = r[col];
      // Chi ma hoa gia tri chua ma hoa va khong rong
      if (val && !isEncrypted(val)) {
        sets.push(`${col} = ?`);
        plainVals.push(val);
      }
    }
    if (sets.length > 0) {
      // Ma hoa qua OpenBao Transit, gom ca dong vao MOT request
      const params = await encryptBatch(plainVals);
      params.push(r.id);
      await conn.query(`UPDATE bookings SET ${sets.join(', ')} WHERE id = ?`, params);
      migrated++;
    }
  }
  if (migrated > 0) {
    console.log(`-> Da ma hoa du lieu ca nhan cua ${migrated} ve (plaintext -> OpenBao Transit)`);
  } else {
    console.log('-> Du lieu ca nhan da duoc ma hoa san, khong can migrate');
  }
}

async function main() {
  // Ket noi KHONG chon database de co the tao database neu chua co
  const conn = await mysql.createConnection(CONN);
  console.log(`-> Ket noi MySQL ${CONN.host}:${CONN.port} OK`);

  await conn.query(
    `CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` ` +
    `CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
  );
  await conn.changeUser({ database: DB_NAME });
  console.log(`-> Database "${DB_NAME}" san sang`);

  await conn.query(DDL);
  console.log('-> Da tao cac bang: airports, flights, bookings');

  // Nang cap schema + ma hoa du lieu cu (neu co)
  await migrateEncryption(conn);

  // Seed airports neu trong
  const [[{ c: airportCount }]] = await conn.query('SELECT COUNT(*) c FROM airports');
  if (airportCount === 0) {
    await conn.query('INSERT INTO airports (code, name, city) VALUES ?', [AIRPORTS]);
    console.log(`-> Da them ${AIRPORTS.length} san bay`);
  } else {
    console.log(`-> Airports da co ${airportCount} dong, bo qua seed`);
  }

  // Seed flights neu trong
  const [[{ c: flightCount }]] = await conn.query('SELECT COUNT(*) c FROM flights');
  if (flightCount === 0) {
    const flights = buildFlights();
    await conn.query(
      'INSERT INTO flights (flight_number, airline, from_airport, to_airport, departure_time, arrival_time, price, total_seats, available_seats) VALUES ?',
      [flights]
    );
    console.log(`-> Da them ${flights.length} chuyen bay mau (14 ngay toi)`);
  } else {
    console.log(`-> Flights da co ${flightCount} dong, bo qua seed`);
  }

  await conn.end();
  console.log('=> Khoi tao database hoan tat.');
}

// Cho phep goi truc tiep (npm run init-db) hoac require tu server.js
if (require.main === module) {
  main().catch((err) => {
    console.error('LOI khoi tao DB:', err.message);
    process.exit(1);
  });
}

module.exports = main;
