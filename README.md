# SkyBooking — Web đặt vé máy bay

Ứng dụng đặt vé máy bay nội địa: **Node.js + Express** (REST API) cho backend,
**HTML/CSS/JavaScript thuần** cho frontend, **MySQL** cho cơ sở dữ liệu.

> 🔐 **Tài liệu bảo mật được giữ riêng, không công khai trong repo này.** File này chỉ mô tả
> kiến trúc kỹ thuật. Hệ thống có mã hóa dữ liệu cá nhân, HTTPS/TLS, chữ ký HMAC cho request,
> và nhật ký audit — liên hệ người bảo trì nếu cần tài liệu chi tiết.

---

## Yêu cầu

| Thành phần | Phiên bản |
|---|---|
| Node.js | ≥ 20 (đã test v24) |
| MySQL | ≥ 8 (đã test 9.1) |
| OpenSSL | có sẵn trong Git Bash (dùng để tạo chứng chỉ TLS) |

---

## Cài đặt và chạy

```bash
npm ci               # cài thư viện theo lockfile (dùng cái này, không dùng npm install)
npm run setup-audit  # tạo database nhật ký riêng + user hạn chế quyền  (1 lần)
npm run gen-cert     # tạo chứng chỉ TLS cho localhost                  (1 lần)
npm start            # chạy server tại https://localhost:3000
```

Khi khởi động, server **tự động** tạo database `booking`, các bảng và ~560 chuyến bay mẫu
nếu chưa có. Muốn seed lại thủ công: `npm run init-db`.

Lần đầu mở trình duyệt sẽ báo **"Your connection is not private"** (chứng chỉ tự ký) →
bấm **Advanced → Proceed to localhost** (chứng chỉ do `npm run gen-cert` sinh ra, chỉ dùng
cho môi trường phát triển).

> ⚠️ Phải truy cập qua **`https://localhost:3000`**. Mở trực tiếp file `.html` bằng
> `file://` sẽ không hoạt động vì JavaScript không gọi được API.

### Các lệnh npm

| Lệnh | Việc |
|---|---|
| `npm start` | Chạy server |
| `npm run dev` | Chạy có tự khởi động lại khi sửa code |
| `npm run init-db` | Tạo lại schema + dữ liệu mẫu cho database `booking` |
| `npm run setup-audit` | Tạo database nhật ký + user hạn chế quyền (idempotent) |
| `npm run verify-audit` | Kiểm tra tính toàn vẹn nhật ký (chỉ đọc) |
| `npm run gen-cert` | Tạo chứng chỉ TLS tự ký |
| `npm run gen-key` | Sinh các khóa bí mật cho `.env` |
| `npm run audit` | Quét lỗ hổng dependency |
| `npm run sbom` | Sinh `sbom.cyclonedx.json` |
| `npm run security-check` | `audit` + `verify-audit` |

---

## Kiến trúc

```
Trình duyệt (HTML/CSS/JS thuần, không build tool)
        │  HTTPS, fetch() + chữ ký HMAC trên mỗi request
        ▼
Express  ──  middleware xếp tầng  ──  routes  ──  mysql2 (pool)
        │                                              │
        │                                              ├── MySQL: booking        (nghiệp vụ)
        │                                              └── MySQL: booking_audit  (nhật ký)
        └── nodemailer ──> SMTP (hoặc ghi file .eml ở chế độ dev)
```

Frontend và backend **cùng origin** — Express vừa chạy API vừa phục vụ file tĩnh, nên
frontend gọi API bằng đường dẫn tương đối `/api/...`, không cần cấu hình CORS.

### Thứ tự middleware

Thứ tự này quan trọng, không đổi được tùy ý:

| # | Middleware | Lý do phải nằm ở vị trí đó |
|---|---|---|
| 1 | `helmet` + security headers | Đặt header trước khi có bất kỳ response nào |
| 2 | `express.json` (giữ `rawBody`) | Chữ ký HMAC băm **raw bytes**, không băm object đã parse |
| 3 | `requestContext` | Gán `request_id` / `request_time` cho mọi request |
| 4 | `auditLogger` | Trước rate limiter, để ghi được cả request bị chặn `429` |
| 5 | `loadShed` | Trước rate limiter: rate limit theo IP không chặn được tải phân tán |
| 6 | Rate limiters | Theo nhóm endpoint |
| 7 | `attachSession` | Đọc token phiên → lấy khóa ký |
| 8 | `signResponses` | Bọc `res.json` để ký response |
| 9 | `auditPayloadCapture` | Phải **sau** `signResponses` để bọc ngoài cùng và đọc được payload |
| 10 | Routes | |
| 11 | `express.static` | Phục vụ `public/` |
| 12 | Error handler | Bắt mọi lỗi còn lại |

---

## Cấu trúc thư mục

```
server.js                  Khởi động, middleware, timeout, tắt máy có trật tự
├── routes/
│   ├── flights.js         Tìm kiếm & chi tiết chuyến bay
│   ├── bookings.js        Đặt vé, tra cứu, hủy vé
│   ├── admin.js           CRUD chuyến bay, quản lý vé, nhật ký, cảnh báo
│   └── session.js         Cấp token phiên cho client
├── middleware/
│   ├── signature.js       Xác minh chữ ký request, ký response
│   ├── requestContext.js  request_id/request_time + thu thập nhật ký
│   └── loadshed.js        Đổ tải khi quá nhiều request đồng thời
├── lib/
│   ├── crypto.js          Mã hóa/giải mã dữ liệu cá nhân
│   ├── security.js        Token phiên, so sánh an toàn, các regex validate
│   ├── signature.js       Chuỗi chuẩn hóa + HMAC + chống replay
│   ├── auditlog.js        Hàng đợi ghi nhật ký + chuỗi hash
│   ├── alerting.js        Phát hiện mẫu tấn công và báo động
│   ├── mailer.js          Gửi email (SMTP hoặc ghi file .eml)
│   ├── emailTemplates.js  Nội dung email HTML + plain text
│   ├── genkey.js          Sinh khóa bí mật
│   └── gencert.js         Sinh chứng chỉ TLS
├── db/
│   ├── pool.js            Pool kết nối database nghiệp vụ
│   ├── auditPool.js       Pool kết nối database nhật ký
│   ├── init.js            Tạo schema + seed + migration
│   ├── setupAudit.js      Tạo database nhật ký + user hạn chế quyền
│   ├── verifyAudit.js     Kiểm tra toàn vẹn nhật ký
│   └── schema.sql         Schema tham khảo
└── public/
    ├── index.html         Tìm & đặt vé
    ├── my-bookings.html   Tra cứu & hủy vé
    ├── admin.html         Trang quản trị
    ├── css/style.css
    └── js/
        ├── common.js      api() có ký request, escape HTML, format
        ├── main.js        Logic trang chủ
        ├── mybookings.js  Logic tra cứu vé
        └── admin.js       Logic trang quản trị
```

Khoảng 4.600 dòng code, không dùng build tool — sửa file JS rồi F5 là thấy ngay.

---

## Các trang

| Trang | Đường dẫn | Chức năng |
|---|---|---|
| Trang chủ | `/` | Tìm chuyến bay theo chặng/ngày/số khách, đặt vé |
| Vé của tôi | `/my-bookings.html` | Tra cứu và hủy vé (cần mã vé + email) |
| Quản trị | `/admin.html` | Chuyến bay, vé, thống kê, nhật ký API, cảnh báo |

---

## Cơ sở dữ liệu

Hệ thống dùng **hai database tách biệt**:

### `booking` — dữ liệu nghiệp vụ

| Bảng | Nội dung |
|---|---|
| `airports` | Sân bay: mã IATA, tên, thành phố |
| `flights` | Chuyến bay: số hiệu, hãng, chặng, giờ đi/đến, giá, tổng ghế, ghế còn |
| `bookings` | Vé: mã vé, hành khách, số ghế, tổng tiền, trạng thái |

Ba cột `passenger_email`, `passenger_phone`, `passenger_cccd` trong `bookings` lưu dữ liệu
**đã mã hóa**, nên không truy vấn trực tiếp bằng `WHERE passenger_email = ?` được —
việc giải mã thực hiện ở tầng ứng dụng ([lib/crypto.js](lib/crypto.js)).

### `booking_audit` — nhật ký API

| Bảng | Nội dung |
|---|---|
| `api_request_logs` | Mọi request API: thời điểm, endpoint, trạng thái, IP, thời lượng… |

Database này tách riêng và dùng hai MySQL user có quyền hạn chế (một chỉ `INSERT`, một chỉ
`SELECT`), được tạo bởi `npm run setup-audit`.

Schema tham khảo: [db/schema.sql](db/schema.sql). Migration trong
[db/init.js](db/init.js) là **idempotent** — chạy lại nhiều lần vô hại.

---

## API

Mọi endpoint trả JSON. Lỗi có dạng `{ "error": "<thông báo>" }`.

### Công khai

| Method | Endpoint | Mô tả |
|---|---|---|
| GET | `/api/health` | Kiểm tra server sống |
| POST | `/api/session` | Cấp token phiên cho client |
| GET | `/api/airports` | Danh sách sân bay |
| GET | `/api/flights?from=&to=&date=&passengers=&page=&limit=` | Tìm chuyến bay |
| GET | `/api/flights/:id` | Chi tiết một chuyến bay |
| POST | `/api/bookings` | Đặt vé |
| POST | `/api/bookings/lookup` | Tra cứu vé — body `{code, email}` |
| POST | `/api/bookings/:code/cancel` | Hủy vé — body `{email}` |

### Quản trị

Cần `Authorization: Bearer <token>` lấy từ `POST /api/admin/login`.

| Method | Endpoint | Mô tả |
|---|---|---|
| POST | `/api/admin/login` | Đổi khóa quản trị → token phiên |
| GET | `/api/admin/stats` | Số chuyến bay, vé, doanh thu |
| GET | `/api/admin/flights?page=&limit=` | Danh sách chuyến bay |
| POST | `/api/admin/flights` | Thêm chuyến bay |
| PUT | `/api/admin/flights/:id` | Sửa chuyến bay |
| DELETE | `/api/admin/flights/:id` | Xóa chuyến bay (chặn nếu đã có vé) |
| GET | `/api/admin/bookings?page=&limit=` | Danh sách vé |
| POST | `/api/admin/bookings/:id/cancel` | Hủy vé |
| GET | `/api/admin/audit-logs` | Nhật ký API, lọc theo `request_id`/`ip`/`booking_code`/`status`/`failed` |
| GET | `/api/admin/audit-logs/verify` | Kiểm tra toàn vẹn nhật ký |
| GET | `/api/admin/alerts` | Cảnh báo gần nhất + tình trạng tải |

> Các endpoint thay đổi dữ liệu và toàn bộ `/api/admin/*` yêu cầu thêm **chữ ký HMAC** trên
> request — xem cách dựng chữ ký trong [lib/signature.js](lib/signature.js) (phía server) và
> [public/js/common.js](public/js/common.js) (phía client).
> Danh sách trả về đều **bắt buộc phân trang** (`limit` tối đa 200).

---

## Biến môi trường

Khai báo trong `.env`. File này **không được commit** (đã có trong `.gitignore`).
Sinh các giá trị bí mật bằng `npm run gen-key`.

| Biến | Mục đích |
|---|---|
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | Kết nối database nghiệp vụ |
| `AUDIT_DB_NAME` | Tên database nhật ký |
| `AUDIT_DB_WRITER_USER` / `AUDIT_DB_WRITER_PASSWORD` | User chỉ ghi được nhật ký |
| `AUDIT_DB_READER_USER` / `AUDIT_DB_READER_PASSWORD` | User chỉ đọc được nhật ký |
| `PORT` | Cổng HTTP/HTTPS (mặc định 3000) |
| `NODE_ENV` | `development` hoặc `production` |
| `HTTPS_KEY_FILE` / `HTTPS_CERT_FILE` | Đường dẫn khóa + chứng chỉ TLS. Để trống → chạy HTTP |
| `ADMIN_KEY` | Khóa đăng nhập trang quản trị |
| `SESSION_SECRET` | Khóa ký token phiên |
| `ENCRYPTION_KEY` | Khóa mã hóa dữ liệu cá nhân |
| `ENABLE_HSTS` | Bật HSTS (mặc định tắt) |
| `TRUST_PROXY` | Số lớp reverse proxy phía trước. **Để trống nếu không có proxy** |
| `ALLOWED_ORIGINS` | Origin được phép gọi API từ domain khác |
| `MAX_CONCURRENT_REQUESTS` / `MAX_CONNECTIONS` | Giới hạn tải |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURE` / `SMTP_USER` / `SMTP_PASSWORD` | Gửi email. Để trống `SMTP_HOST` → ghi file `.eml` vào `mail-dev/` |
| `MAIL_FROM` / `MAIL_DEV_DIR` | Người gửi và thư mục email chế độ dev |
| `ALERT_EMAIL` | Email nhận cảnh báo. Để trống → chỉ in console |

Xem [.env.example](.env.example) để biết ý nghĩa từng biến và giá trị mặc định an toàn.

> ⚠️ **Sao lưu `ENCRYPTION_KEY`.** Mất khóa này là mất vĩnh viễn dữ liệu cá nhân đã mã hóa,
> không có cách khôi phục.

---

## Ghi chú kỹ thuật

**Đặt vé an toàn khi nhiều người cùng đặt.** Dùng transaction với
`SELECT ... FOR UPDATE` để khóa dòng chuyến bay, nên không xảy ra tình trạng hai người
cùng đặt vào một ghế cuối. Giá tiền **luôn tính ở server**, không nhận từ client.

**Hủy vé trả lại ghế.** Cập nhật trạng thái vé và cộng lại `available_seats` trong cùng
một transaction.

**Email gửi bất đồng bộ.** Gửi sau khi transaction commit và sau khi response đã trả về,
nên SMTP chậm hoặc lỗi không làm chậm việc đặt vé. Vé bị rollback thì không gửi email.

**Không tìm được theo email/CCCD.** Các cột này mã hóa nên `WHERE passenger_email = ?`
không khớp. Nếu sau này cần tìm chính xác theo email, thêm cột *blind index*
(HMAC-SHA256 của email) để so sánh bằng mà không lưu plaintext.

**Nhật ký ghi bất đồng bộ.** Dùng hàng đợi trong tiến trình, ghi sau khi response đã gửi
nên không làm chậm API. Chỉ được chạy **một instance server** tại một thời điểm — server giữ
một khóa MySQL (`GET_LOCK`) và từ chối khởi động nếu phát hiện instance khác đang chạy.

---

## Xử lý sự cố

| Hiện tượng | Nguyên nhân thường gặp |
|---|---|
| `Access denied for user` khi khởi động | Sai `DB_USER`/`DB_PASSWORD` trong `.env` |
| `Khong ket noi duoc database nhat ky audit` | Chưa chạy `npm run setup-audit` |
| `Da co mot server khac dang chay` | Instance cũ chưa tắt — chỉ được chạy một server |
| Trình duyệt báo "Not private" | Bình thường với chứng chỉ tự ký → Advanced → Proceed |
| Trang trắng, JS không gọi được API | Đang mở bằng `file://` — phải mở `https://localhost:3000` |
| API trả `Thieu chu ky request` | Client chưa ký request — xem [public/js/common.js](public/js/common.js) |
| API trả `503 May chu dang qua tai` | Vượt `MAX_CONCURRENT_REQUESTS` |
| Không thấy bảng mới trong MySQL Workbench | Bấm **Refresh** ở panel schema |

Mỗi response đều có header `X-Request-Id`. Khi gặp lỗi, dùng mã đó tra trong trang quản trị
→ **Nhật ký API** để xem chi tiết request.
