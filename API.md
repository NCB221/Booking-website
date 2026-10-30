# Đặc tả API — SkyBooking

Tài liệu dành cho lập trình viên tích hợp hoặc bảo trì API. Mô tả trong đây được trích trực tiếp từ mã nguồn (`server.js`, `routes/*.js`, `middleware/*.js`, `lib/security.js`, `lib/signature.js`).

- **Base URL**: `http://localhost:3000` (hoặc `https://` khi cấu hình `HTTPS_KEY_FILE`)
- **Tiền tố**: mọi endpoint nằm dưới `/api`
- **Định dạng**: JSON cho cả request và response
- **Phiên bản chữ ký**: `v2`

---

## 1. Quy ước chung

### 1.1 Định dạng lỗi

Mọi lỗi đều có cùng một hình dạng:

```json
{ "error": "<thông báo tiếng Việt>" }
```

Không có mã lỗi dạng số hay chuỗi định danh. Client **không nên** so khớp chuỗi `error` để phân nhánh logic — hãy dùng HTTP status code.

### 1.2 Mã trạng thái dùng trong hệ thống

| Mã | Ý nghĩa trong API này |
|---|---|
| `200` | Thành công |
| `201` | Đã tạo (đặt vé, tạo chuyến bay) |
| `400` | Dữ liệu vào không hợp lệ, thiếu header chữ ký, JSON sai cú pháp |
| `401` | Thiếu/sai phiên, chữ ký không hợp lệ, lệch đồng hồ quá hạn, sai khoá admin |
| `403` | Origin không được phép (CORS) |
| `404` | Không tìm thấy tài nguyên hoặc không tìm thấy endpoint |
| `409` | Xung đột trạng thái: replay bị chặn, vé đã huỷ, hết ghế, chuyến đã khởi hành |
| `413` | Body vượt 16 KB |
| `429` | Vượt rate limit |
| `500` | Lỗi nội bộ (thông báo chung chung, không tiết lộ chi tiết) |
| `503` | Quá tải (load shedding) hoặc không sinh được mã vé |

### 1.3 Header server luôn trả về

| Header | Nội dung |
|---|---|
| `X-Request-Id` | Mã định danh request. Dùng lại giá trị client gửi nếu khớp `^[A-Za-z0-9_-]{8,64}$`, ngược lại server sinh UUID v4 |
| `X-Request-Time` | Thời điểm server nhận request, dạng ISO 8601 |
| `X-Timestamp`, `X-Signature` | Chỉ có khi request mang phiên hợp lệ (xem §3.4) |

Ba header này được liệt kê trong `Access-Control-Expose-Headers` để đọc được khi gọi cross-origin.

### 1.4 Giới hạn kích thước và tải

- Body tối đa **16 KB** (`express.json` và `express.urlencoded`). Vượt → `413`.
- Số request đồng thời tối đa `MAX_CONCURRENT_REQUESTS` (mặc định **200**). Vượt → `503` kèm `Retry-After: 5`.

### 1.5 Rate limit

Tính theo IP. Vượt giới hạn trả `429`.

| Nhóm | Cửa sổ | Giới hạn | Áp dụng cho |
|---|---|---|---|
| Chung | 1 phút | 120 | toàn bộ `/api` |
| Phiên | 1 giờ | 60 | `POST /api/session` |
| Đặt vé | 1 giờ | 10 | `POST /api/bookings` |
| Tra cứu | 10 phút | 20 | `POST /api/bookings/lookup`, `POST /api/bookings/:code/cancel` |
| Đăng nhập | 15 phút | 5 | `POST /api/admin/login` — chỉ đếm lần **thất bại** |

Rate limiter dùng `standardHeaders: true`, nên response kèm `RateLimit-*`.

### 1.6 CORS

Chỉ bật khi biến môi trường `ALLOWED_ORIGINS` được khai báo. Khi đó: methods `GET, POST, PUT, DELETE`, `allowedHeaders: Content-Type, Authorization`, `maxAge: 600`. Origin không nằm trong danh sách → `403`.

> Xem §7 về hạn chế của `allowedHeaders` đối với client cross-origin.

---

## 2. Mô hình xác thực

Hệ thống có **hai loại phiên**, cả hai đều là token HMAC-SHA256 stateless (không lưu DB).

| | Phiên khách | Phiên admin |
|---|---|---|
| Lấy từ | `POST /api/session` | `POST /api/admin/login` |
| Thời hạn | 1 giờ (3600s) | 2 giờ (7200s) |
| Gửi kèm qua | `X-Client-Token: <token>` | `Authorization: Bearer <token>` |
| Dùng để | ký request | ký request **và** phân quyền admin |

Cấu trúc token: `base64url(payload).base64url(HMAC-SHA256(SESSION_SECRET, payload))`, trong đó payload gồm `{ role, iat, exp, jti }`.

Khoá ký (`signing_key`) được dẫn xuất từ `jti`:

```
signing_key = base64url(HMAC-SHA256(SESSION_SECRET, "sig:" + jti))
```

Nên khoá ký là **riêng cho từng phiên**, hết hạn cùng token, và không có khoá tĩnh nào nằm trong mã nguồn frontend.

### 2.1 Luồng khởi tạo đầy đủ

```
1. POST /api/session                        → client_token + signing_key (khách)
2. Ký mọi request thay đổi dữ liệu bằng signing_key khách
3. (nếu cần quyền admin)
   POST /api/admin/login                    ← phải ký bằng signing_key KHÁCH
                                            → admin token + signing_key ADMIN
4. Gọi /api/admin/*                         ← Bearer admin token
                                            ← ký bằng signing_key ADMIN
```

Lưu ý bước 3: chính request đăng nhập admin cũng phải có chữ ký hợp lệ của một phiên khách, để khoá quản trị không bị sửa trên đường truyền. Không thể gọi `/api/admin/login` mà chưa có phiên khách.

---

## 3. Chữ ký HMAC (v2)

Áp dụng cho **mọi endpoint thay đổi dữ liệu** và **toàn bộ `/api/admin/*`**. Mục đích: bảo đảm toàn vẹn dữ liệu trên đường truyền và chống replay. Đây **không** phải thay thế cho HTTPS.

### 3.1 Header bắt buộc

| Header | Định dạng | Ghi chú |
|---|---|---|
| `X-Request-Id` | `^[A-Za-z0-9_-]{8,64}$` | **Bắt buộc do client sinh.** Nếu thiếu, server tự sinh và chữ ký sẽ bị từ chối với `400` |
| `X-Timestamp` | `^\d{1,15}$` | Unix seconds |
| `X-Nonce` | `^[A-Za-z0-9_-]{16,64}$` | Chuỗi ngẫu nhiên, **dùng đúng một lần** |
| `X-Signature` | base64url | Kết quả HMAC |

### 3.2 Chuỗi chuẩn hoá

Bảy thành phần nối bằng ký tự `\n`:

```
v2
<METHOD viết hoa>
<PATH kèm query string>
<TIMESTAMP>
<NONCE>
<REQUEST_ID>
<SHA256_HEX của raw body>
```

Chi tiết quan trọng:

- `PATH` là `req.originalUrl` — **bao gồm cả query string**. Ví dụ `/api/admin/flights?page=2&limit=50`.
- Body hash tính trên **raw bytes đúng như đã gửi**, không phải trên object đã parse lại. Serialize lại có thể đổi thứ tự khoá và làm lệch chữ ký.
- Body rỗng → hash của buffer rỗng: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### 3.3 Tính chữ ký

```js
const keyBytes = Buffer.from(signing_key, 'base64url');
const sig = crypto.createHmac('sha256', keyBytes)
  .update(canonical, 'utf8')
  .digest('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
```

Ví dụ hoàn chỉnh cho `POST /api/bookings`:

```js
const body = JSON.stringify({ flight_id: 12, seat_count: 2, /* ... */ });
const requestId = crypto.randomUUID();
const nonce = crypto.randomBytes(16).toString('base64url');
const timestamp = Math.floor(Date.now() / 1000);
const bodyHash = crypto.createHash('sha256').update(body, 'utf8').digest('hex');

const canonical = [
  'v2', 'POST', '/api/bookings',
  String(timestamp), nonce, requestId, bodyHash,
].join('\n');

await fetch('/api/bookings', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Client-Token': clientToken,
    'X-Request-Id': requestId,
    'X-Timestamp': String(timestamp),
    'X-Nonce': nonce,
    'X-Signature': computeHmac(signingKey, canonical),
  },
  body,
});
```

### 3.4 Chữ ký của response

Khi request mang phiên hợp lệ, server ký lại body trả về. Canonical dùng `nonce = '-'` và **cùng `REQUEST_ID`** của request, nên response bị ràng buộc với đúng request đã gửi — không thể tráo response giữa hai request.

Client xác minh bằng `X-Timestamp` + `X-Signature` trong response header.

### 3.5 Thứ tự kiểm tra và lỗi tương ứng

Server kiểm tra theo đúng thứ tự sau:

| Bước | Điều kiện | Lỗi khi sai |
|---|---|---|
| 1 | Có đủ `X-Timestamp`, `X-Nonce`, `X-Signature` | `400 Thieu chu ky request` |
| 2 | `X-Request-Id` do client gửi và đúng định dạng | `400 Thieu header X-Request-Id` |
| 3 | `X-Timestamp`, `X-Nonce` đúng định dạng | `400 ... khong hop le` |
| 4 | Lệch đồng hồ ≤ **300 giây** | `401 Request da qua han` |
| 5 | Chữ ký khớp | `401 Chu ky khong hop le` |
| 6 | Nonce chưa dùng | `409 Request da duoc gui truoc do` |

Thiếu phiên hoàn toàn (không có `signing_key`) → `401 Thieu phien lam viec`.

> Bước 5 đặt **trước** bước 6 là có chủ đích: kẻ tấn công không thể "đốt" nonce hợp lệ của người dùng khác bằng cách gửi chữ ký rác.

Kho nonce giữ tối đa 100 000 bản ghi, mỗi nonce lưu trong `300 + 60` giây. Khi kho đầy và không dọn được, request bị từ chối.

---

## 4. Endpoint công khai

### `GET /api/health`

Không cần phiên, không cần chữ ký.

```json
{ "status": "ok" }
```

Cố tình không trả về phiên bản hay cấu hình.

---

### `POST /api/session`

Cấp phiên khách. Đây là endpoint bootstrap duy nhất **không** yêu cầu chữ ký.

**Response `200`**

```json
{
  "client_token": "eyJyb2xlIjoi...abc",
  "signing_key": "k7Hs9...",
  "expires_in": 3600,
  "signature": {
    "algorithm": "HMAC-SHA256",
    "version": "v1",
    "headers": ["X-Timestamp", "X-Nonce", "X-Signature"],
    "max_skew_seconds": 300,
    "server_time": 1761200000
  }
}
```

`server_time` dùng để client tự đồng bộ đồng hồ, tránh lỗi lệch thời gian.

> ⚠️ Trường `signature.version` và `signature.headers` trong response này **không khớp với hành vi thật của server**. Xem §7.

---

### `GET /api/airports`

Dữ liệu công khai, không chứa PII. `Cache-Control: public, max-age=300`.

**Response `200`** — mảng, sắp xếp theo `city`:

```json
[{ "code": "HAN", "name": "Sân bay Nội Bài", "city": "Hà Nội" }]
```

---

### `GET /api/flights`

Tìm kiếm chuyến bay. Chỉ trả về chuyến **chưa khởi hành** và **còn đủ ghe** theo số khách yêu cầu.

**Query**

| Tham số | Kiểu | Mặc định | Giới hạn | Ghi chú |
|---|---|---|---|---|
| `from` | `[A-Z]{3}` | — | | Tự viết hoa. Sai định dạng → `400` |
| `to` | `[A-Z]{3}` | — | | Tự viết hoa. Sai định dạng → `400` |
| `date` | `YYYY-MM-DD` | — | | Kiểm tra ngày thật (chặn `2026-02-31`) → `400` |
| `passengers` | int | `1` | 1–9 | Lọc `available_seats >= passengers` |
| `limit` | int | `50` | 1–100 | |
| `page` | int | `1` | 1–200 | |

Giá trị ngoài khoảng bị **kẹp về biên**, không báo lỗi. `limit=999` được xử lý như `limit=100`.

**Response `200`** — mảng phẳng, **không có bao phân trang**:

```json
[{
  "id": 12, "flight_number": "VN123", "airline": "Vietnam Airlines",
  "from_airport": "HAN", "to_airport": "SGN",
  "departure_time": "2026-11-01 07:30:00", "arrival_time": "2026-11-01 09:35:00",
  "price": "1850000.00", "available_seats": 142,
  "from_name": "Sân bay Nội Bài", "from_city": "Hà Nội",
  "to_name": "Sân bay Tân Sơn Nhất", "to_city": "Hồ Chí Minh"
}]
```

`price` và `total_price` là `DECIMAL(12,2)` nên driver MySQL trả về dạng **chuỗi**, không phải số. Client phải tự chuyển đổi.

---

### `GET /api/flights/:id`

**Path**: `id` — số nguyên ≥ 1. Không parse được → `400`.

**Response `200`**: một object cùng hình dạng phần tử của `GET /api/flights`.
**`404`**: không tìm thấy chuyến bay.

---

## 5. Endpoint đặt vé

Cả ba endpoint dưới đây **đều yêu cầu chữ ký**.

### `POST /api/bookings`

Đặt vé. Rate limit 10 vé/giờ/IP.

**Body**

| Trường | Kiểu | Bắt buộc | Quy tắc |
|---|---|---|---|
| `flight_id` | int | ✓ | ≥ 1 |
| `passenger_name` | string | ✓ | `^[\p{L}\p{M}\s'.-]{2,120}$` — chữ Unicode có dấu, dấu cách, `'`, `.`, `-` |
| `passenger_email` | string | ✓ | `^[^\s@]+@[^\s@]+\.[^\s@]{2,}$`, tự chuyển chữ thường |
| `passenger_phone` | string | ✓ | `^0\d{9,10}$`. Khoảng trắng, `.`, `-` bị loại trước khi kiểm |
| `passenger_cccd` | string | ✓ | `^(\d{9}\|\d{12})$` — CCCD 12 số hoặc CMND 9 số |
| `seat_count` | int | — | 1–9, mặc định `1` |

**Mass assignment**: server chỉ đọc đúng 6 trường trên. `total_price` **luôn** tính tại server (`price × seat_count`); gửi `total_price` từ client không có tác dụng.

**Response `201`**

```json
{ "id": 48, "booking_code": "K7M2PQRS", "total_price": 3700000 }
```

Mã vé gồm 8 ký tự sinh bằng `crypto.randomBytes`, từ tập `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (đã bỏ các ký tự dễ nhìn lẫn: `I`, `O`, `0`, `1`).

**Lỗi**

| Mã | Trường hợp |
|---|---|
| `400` | Thiếu trường, sai định dạng, hoặc `seat_count > 9` |
| `404` | Chuyến bay không tồn tại |
| `409` | Chuyến bay đã khởi hành / không còn đủ ghế (`Chi con N ghe trong`) |
| `503` | Thử 5 lần vẫn không sinh được mã vé không trùng |

**Hành vi đáng chú ý**: `seat_count = 10` trả `400` chứ không bị kẹp im lặng về 9 — có một lần kiểm tra tường minh trên giá trị gốc.

Giao dịch dùng `SELECT ... FOR UPDATE` trên dòng chuyến bay nên không bị đặt trùng ghế khi có nhiều request đồng thời. Email xác nhận gửi **sau khi commit**, chạy nền và tự bắt lỗi — sự cố email không bao giờ làm vỡ luồng đặt vé.

---

### `POST /api/bookings/lookup`

Tra cứu vé. Dùng `POST` thay vì `GET` để email không bị ghi vào access log và lịch sử trình duyệt.

**Body**: `{ "code": "K7M2PQRS", "email": "a@b.com" }`

Cả hai bắt buộc. `code` khớp `^[A-Z0-9]{4,12}$`, tự viết hoa.

**Response `200`** — PII đã che bớt, `Cache-Control: no-store`:

```json
{
  "booking_code": "K7M2PQRS",
  "passenger_name": "Nguyễn Văn A",
  "passenger_email": "ng****@gmail.com",
  "passenger_phone": "*******567",
  "passenger_cccd": "********1234",
  "seat_count": 2, "total_price": "3700000.00", "status": "CONFIRMED",
  "created_at": "2026-10-20T10:00:00.000Z",
  "flight_number": "VN123", "airline": "Vietnam Airlines",
  "from_airport": "HAN", "to_airport": "SGN",
  "from_city": "Hà Nội", "to_city": "Hồ Chí Minh",
  "departure_time": "2026-11-01 07:30:00", "arrival_time": "2026-11-01 09:35:00"
}
```

Quy tắc che: email giữ 2 ký tự đầu phần local; điện thoại giữ 3 số cuối; CCCD giữ 4 số cuối.

**`404`**: dùng **đúng một thông báo** cho cả hai trường hợp *mã vé không tồn tại* và *email không khớp chủ sở hữu*. Đây là chủ đích — không thể dò xem mã vé nào tồn tại. Client không thể phân biệt hai nguyên nhân này.

---

### `POST /api/bookings/:code/cancel`

Huỷ vé. Chỉ cần mã vé là **không đủ** — phải kèm email đúng chủ sở hữu.

**Body**: `{ "email": "a@b.com" }`

**Response `200`**: `{ "ok": true, "message": "Da huy ve thanh cong" }`

| Mã | Trường hợp |
|---|---|
| `400` | Mã vé hoặc email sai định dạng |
| `404` | Không tìm thấy vé khớp mã vé **và** email |
| `409` | Vé đã bị huỷ trước đó |

Huỷ thành công sẽ hoàn lại `seat_count` vào `available_seats` của chuyến bay, và gửi email thông báo để khách phát hiện nếu bị huỷ trái phép.

---

## 6. Endpoint quản trị

Mọi endpoint `/api/admin/*` (trừ `login`) yêu cầu **cả hai**:

- `Authorization: Bearer <admin token>`
- Chữ ký HMAC hợp lệ bằng `signing_key` của phiên admin

Token sai hoặc hết hạn → `401 Phien dang nhap khong hop le hoac da het han`. Tất cả response quản trị đều có `Cache-Control: no-store`.

### `POST /api/admin/login`

Yêu cầu chữ ký bằng `signing_key` của **phiên khách** (xem §2.1). Rate limit 5 lần sai/15 phút.

**Body**: `{ "key": "<ADMIN_KEY>" }`

**Response `200`**

```json
{ "ok": true, "token": "eyJyb2xlIjoiYWRtaW4...", "signing_key": "...", "expires_in": 7200 }
```

**`401`**: `Khoa quan tri khong dung`. So sánh khoá bằng thời gian hằng số (hash trước rồi `timingSafeEqual`) nên không lộ thông tin qua thời gian phản hồi.

---

### Quản lý chuyến bay

| Method | Path | Mô tả |
|---|---|---|
| `GET` | `/api/admin/flights` | Danh sách, có phân trang |
| `POST` | `/api/admin/flights` | Tạo mới |
| `PUT` | `/api/admin/flights/:id` | Cập nhật toàn bộ |
| `DELETE` | `/api/admin/flights/:id` | Xoá |

**`GET`** — query `page` (1–10000, mặc định 1), `limit` (1–200, mặc định 100).

```json
{ "data": [ { "...": "...", "bookings_count": 7 } ], "page": 1, "limit": 100, "total": 253 }
```

Khác với `GET /api/flights` công khai, endpoint này **có bao phân trang** và trả về cả `total_seats` lẫn `bookings_count`.

**`POST` / `PUT` body** — cùng bộ trường, tất cả bắt buộc:

| Trường | Quy tắc |
|---|---|
| `flight_number` | `^[A-Z0-9]{2,10}$` (không phân biệt hoa thường, tự viết hoa) |
| `airline` | `^[\p{L}\p{M}\p{N}\s.\-&()/']{2,80}$` — cố tình chặn `<`, `>`, `"`, `` ` `` để không lưu được payload XSS vào DB |
| `from_airport`, `to_airport` | `^[A-Z]{3}$`, phải **khác nhau**, phải tồn tại trong bảng `airports` |
| `departure_time`, `arrival_time` | `YYYY-MM-DD HH:MM[:SS]` hoặc dùng `T` thay dấu cách. `arrival` phải **sau** `departure` |
| `price` | số, `0` – `500000000` |
| `total_seats` | số nguyên, `1` – `1000` |

`POST` trả `201 { "id": 42 }`. `PUT` trả `200 { "ok": true }`.

**`PUT` — ràng buộc riêng**: không thể giảm `total_seats` xuống dưới số ghế đã bán. Vi phạm → `409 Khong the giam xuong N ghe: da ban M ghe`. Khi đổi `total_seats`, `available_seats` được tính lại thành `total_seats - đã_bán`.

**`DELETE`** — `409` nếu chuyến bay đã có vé đặt (kể cả vé đã huỷ, vì điều kiện đếm là mọi dòng `bookings` của chuyến đó). `404` nếu không có dòng nào bị xoá.

---

### `GET /api/admin/bookings`

Query `page` (1–10000, mặc định 1), `limit` (1–200, mặc định 100).

**Response `200`** — PII được **giải mã đầy đủ**, khác hẳn bản che của khách:

```json
{
  "data": [{
    "id": 48, "booking_code": "K7M2PQRS", "passenger_name": "Nguyễn Văn A",
    "passenger_email": "nguyenvana@gmail.com",
    "passenger_phone": "0901234567",
    "passenger_cccd": "001234567890",
    "seat_count": 2, "total_price": "3700000.00", "status": "CONFIRMED",
    "created_at": "2026-10-20T10:00:00.000Z",
    "flight_number": "VN123", "airline": "Vietnam Airlines",
    "from_airport": "HAN", "to_airport": "SGN", "departure_time": "2026-11-01 07:30:00"
  }],
  "page": 1, "limit": 100, "total": 48
}
```

Mỗi lần gọi đều ghi một dòng `[AUDIT] Admin xem N ve (co PII) tu IP ...` vào log ứng dụng.

### `POST /api/admin/bookings/:id/cancel`

Huỷ vé theo **`id` số nguyên**, không phải `booking_code`, và **không cần email** chủ sở hữu — đây là đặc quyền admin. Body rỗng.

`200 { "ok": true }` · `400` id sai · `404` không tìm thấy · `409` vé đã huỷ.

---

### Nhật ký audit

Nhật ký nằm ở **database riêng** (`booking_audit`), đọc qua user chỉ có quyền `SELECT`. Mỗi dòng có `prev_hash` và `row_hash` tạo thành chuỗi hash để phát hiện can thiệp.

#### `GET /api/admin/audit-logs`

| Query | Kiểu | Mặc định | Tác dụng |
|---|---|---|---|
| `page` | int 1–100000 | 1 | |
| `limit` | int 1–200 | 50 | |
| `request_id` | string ≤64 | — | Khớp chính xác |
| `ip` | string ≤45 | — | Khớp chính xác |
| `actor` | string ≤20 | — | `anonymous` \| `client` \| `admin` |
| `booking_code` | string ≤12 | — | Tự viết hoa |
| `status` | int 100–599 | — | Khớp chính xác status code |
| `failed` | `"1"` | — | Chỉ lấy dòng có `status_code >= 400` |

Response `{ data, page, limit, total }`. Mỗi dòng gồm: `request_id`, `request_time`, `client_time`, `clock_skew_ms`, `method`, `path`, `status_code`, `duration_ms`, `ip`, `user_agent`, `actor_role`, `session_jti`, `signature`, `signature_valid`, `nonce`, `body_sha256`, `body_bytes`, `response_bytes`, `error_message`, `booking_code`, `prev_hash`, `row_hash`.

`signature_valid` có ba trạng thái: `true`/`false` khi endpoint kiểm chữ ký, `null` khi endpoint không yêu cầu.

Nhật ký **chỉ lưu `body_sha256`**, không lưu nội dung body — nên CCCD, email, số điện thoại không bao giờ xuất hiện trong nhật ký.

#### `GET /api/admin/audit-logs/verify`

Kiểm tra chuỗi hash còn nguyên vẹn. Query `limit` (1–100000, mặc định 10000).

Khi nguyên vẹn:

```json
{
  "ok": true, "checked": 10000,
  "last_hash": "9f2c...",
  "queue": { "queued": 0, "dropped": 0, "ready": true, "last_hash": "9f2c..." }
}
```

Khi phát hiện can thiệp — **hình dạng khác**, không có `last_hash` mà thêm `broken_at` và `reason`:

```json
{
  "ok": false, "checked": 4821, "broken_at": 3307,
  "reason": "prev_hash khong khop row_hash cua dong truoc (co dong bi xoa hoac chen them)",
  "queue": { "...": "..." }
}
```

`reason` có hai giá trị: `prev_hash` không khớp (có dòng bị xoá hoặc chèn thêm), hoặc `row_hash` không khớp nội dung (dòng đó đã bị sửa). Trường hợp `ok: false` còn phát cảnh báo `AUDIT_CHAIN_BROKEN`.

#### `GET /api/admin/alerts`

Query `limit` (1–200, mặc định 50).

```json
{
  "alerts": [{ "type": "AUTH_FAILED", "...": "..." }],
  "counters": {
    "AUTH_FAILED": { "current": 2, "threshold": 5, "window_minutes": 15 }
  },
  "email_configured": true,
  "load": { "in_flight": 3, "peak": 41, "shed": 0, "max": 200 }
}
```

`alerts` là danh sách cảnh báo gần nhất, mới nhất trước.

`counters` có một khoá cho mỗi loại sự kiện, mỗi khoá gồm `current` (số lần trong cửa sổ hiện tại), `threshold` (ngưỡng phát cảnh báo) và `window_minutes`.

Các loại sự kiện được ghi nhận: `SIGNATURE_INVALID`, `LOOKUP_FAILED`, `AUTH_FAILED`, `RATE_LIMITED`, `SERVER_ERROR`, `AUDIT_CHAIN_BROKEN`.

#### `GET /api/admin/stats`

```json
{ "flights": 253, "confirmed_bookings": 41, "cancelled_bookings": 7, "revenue": 152300000 }
```

`revenue` chỉ tính vé `CONFIRMED`. Đây là trường duy nhất trong API trả về tiền dưới dạng **số** thật (đã qua `Number()`), khác với `price`/`total_price` ở các endpoint khác.

---

## 7. Điểm lệch giữa đặc tả công bố và hành vi thật

Ba điểm dưới đây được phát hiện khi đối chiếu mã nguồn. Client tích hợp cần biết để không đi theo metadata sai.

### 7.1 `signature.version` báo `v1` nhưng server dùng `v2`

`POST /api/session` trả về `signature.version: "v1"` (`routes/session.js`), trong khi chuỗi chuẩn hoá thực tế bắt đầu bằng `v2` (`lib/signature.js`: `const VERSION = 'v2'`).

**Hệ quả**: client dựng theo metadata sẽ ký chuỗi bắt đầu bằng `v1` và nhận `401 Chu ky khong hop le`. Frontend kèm theo dự án không bị ảnh hưởng vì nó hardcode `SIG_VERSION = 'v2'` (`public/js/common.js`) thay vì đọc từ response.

### 7.2 `signature.headers` thiếu `X-Request-Id`

Metadata liệt kê `["X-Timestamp", "X-Nonce", "X-Signature"]`, nhưng `verifyRequestSignature` từ chối request không có `X-Request-Id` do client gửi:

```js
if (req.requestIdSource !== 'client') {
  return { ok: false, status: 400, error: 'Thieu header X-Request-Id' };
}
```

`X-Request-Id` còn nằm **trong** chuỗi chuẩn hoá, nên bắt buộc phải có.

**Hệ quả**: client gửi đúng 3 header như metadata chỉ dẫn sẽ nhận `400`.

### 7.3 CORS `allowedHeaders` không chứa các header chữ ký

Khi `ALLOWED_ORIGINS` được khai báo, `server.js` cấu hình:

```js
allowedHeaders: ['Content-Type', 'Authorization']
```

Thiếu `X-Client-Token`, `X-Request-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`.

**Hệ quả**: trình duyệt sẽ chặn ngay ở bước preflight đối với mọi request cross-origin có chữ ký — tức **client cross-origin không thể gọi bất kỳ endpoint cần chữ ký nào**. Vấn đề không lộ ra khi dùng frontend cùng origin (trường hợp mặc định), vì request cùng origin không qua preflight.

Khắc phục: bổ sung 5 header trên vào `allowedHeaders`.

---

## 8. Tham chiếu nhanh

### 8.1 Biểu thức kiểm tra đầu vào

Tập trung tại `lib/security.js`, dùng chung toàn hệ thống:

| Tên | Biểu thức |
|---|---|
| `airport` | `^[A-Z]{3}$` |
| `date` | `^\d{4}-\d{2}-\d{2}$` |
| `datetime` | `^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$` |
| `bookingCode` | `^[A-Z0-9]{4,12}$` |
| `email` | `^[^\s@]+@[^\s@]+\.[^\s@]{2,}$` |
| `phone` | `^0\d{9,10}$` |
| `cccd` | `^(\d{9}\|\d{12})$` |
| `flightNumber` | `^[A-Z0-9]{2,10}$` (ignore case) |
| `name` | `^[\p{L}\p{M}\s'.-]{2,120}$` |
| `airline` | `^[\p{L}\p{M}\p{N}\s.\-&()/']{2,80}$` |

Mọi chuỗi đi qua `cleanText()`: loại ký tự điều khiển `U+0000`–`U+001F` và `U+007F`, `trim()`, rồi cắt theo độ dài tối đa.

### 8.2 Mô hình dữ liệu

**`airports`** — `code` (PK, 3 ký tự), `name`, `city`

**`flights`** — `id`, `flight_number`, `airline`, `from_airport` → FK, `to_airport` → FK, `departure_time`, `arrival_time`, `price` `DECIMAL(12,2)`, `total_seats`, `available_seats`, `created_at`

**`bookings`** — `id`, `booking_code` (UNIQUE), `flight_id` → FK, `passenger_name`, `passenger_email`, `passenger_phone`, `passenger_cccd`, `seat_count`, `total_price`, `status` `ENUM('CONFIRMED','CANCELLED')`, `created_at`

Ba cột PII lưu **đã mã hoá AES-256-GCM**, định dạng `v1:<iv_b64>:<authTag_b64>:<ciphertext_b64>`, dài tối đa 512 ký tự. Giải mã ở tầng ứng dụng (`lib/crypto.js`), không bao giờ lưu plaintext. `passenger_name` **không** mã hoá.

### 8.3 Bảng endpoint

| Method | Path | Phiên | Chữ ký | Rate limit |
|---|---|---|---|---|
| `GET` | `/api/health` | — | — | chung |
| `POST` | `/api/session` | — | — | 60/giờ |
| `GET` | `/api/airports` | — | — | chung |
| `GET` | `/api/flights` | — | — | chung |
| `GET` | `/api/flights/:id` | — | — | chung |
| `POST` | `/api/bookings` | khách | ✓ | 10/giờ |
| `POST` | `/api/bookings/lookup` | khách | ✓ | 20/10 phút |
| `POST` | `/api/bookings/:code/cancel` | khách | ✓ | 20/10 phút |
| `POST` | `/api/admin/login` | khách | ✓ | 5/15 phút |
| `GET` | `/api/admin/flights` | admin | ✓ | chung |
| `POST` | `/api/admin/flights` | admin | ✓ | chung |
| `PUT` | `/api/admin/flights/:id` | admin | ✓ | chung |
| `DELETE` | `/api/admin/flights/:id` | admin | ✓ | chung |
| `GET` | `/api/admin/bookings` | admin | ✓ | chung |
| `POST` | `/api/admin/bookings/:id/cancel` | admin | ✓ | chung |
| `GET` | `/api/admin/audit-logs` | admin | ✓ | chung |
| `GET` | `/api/admin/audit-logs/verify` | admin | ✓ | chung |
| `GET` | `/api/admin/alerts` | admin | ✓ | chung |
| `GET` | `/api/admin/stats` | admin | ✓ | chung |

Endpoint `/api` không tồn tại → `404 { "error": "Khong tim thay endpoint" }` (JSON, không trả HTML).
