-- Schema tham khao cho database "booking".
-- Ung dung tu dong chay cac lenh nay khi khoi dong (xem db/init.js),
-- nen ban KHONG bat buoc phai chay file nay thu cong.
-- Neu muon chay tay: mysql -u root < db/schema.sql

CREATE DATABASE IF NOT EXISTS booking
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE booking;

-- Bang san bay
CREATE TABLE IF NOT EXISTS airports (
  code    VARCHAR(3)  NOT NULL PRIMARY KEY,
  name    VARCHAR(120) NOT NULL,
  city    VARCHAR(80)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bang chuyen bay
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

-- Bang dat ve
CREATE TABLE IF NOT EXISTS bookings (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  booking_code    VARCHAR(12)  NOT NULL UNIQUE,
  flight_id       INT          NOT NULL,
  passenger_name  VARCHAR(120) NOT NULL,
  -- 3 cot duoi day luu du lieu DA MA HOA bang AES-256-GCM.
  -- Dinh dang: v1:<iv_base64>:<authTag_base64>:<ciphertext_base64>
  -- KHONG BAO GIO luu plaintext. Giai ma o tang ung dung (lib/crypto.js).
  passenger_email VARCHAR(512) NOT NULL,
  passenger_phone VARCHAR(512) NOT NULL,
  passenger_cccd  VARCHAR(512) NOT NULL,
  seat_count      INT          NOT NULL DEFAULT 1,
  total_price     DECIMAL(12,2) NOT NULL,
  status          ENUM('CONFIRMED','CANCELLED') NOT NULL DEFAULT 'CONFIRMED',
  created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_booking_flight FOREIGN KEY (flight_id) REFERENCES flights(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
