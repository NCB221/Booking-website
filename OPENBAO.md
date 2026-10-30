# Tích hợp OpenBao — SkyBooking

Tài liệu vận hành cho người triển khai và bảo trì. OpenBao **v2.7.1**, chạy trên Windows host, lưu trữ `raft`, unseal thủ công.

---

## 1. OpenBao giải quyết vấn đề gì

Trước đây khoá mã hoá PII (`ENCRYPTION_KEY`) nằm trong `.env` dạng plaintext và được nạp vào biến `cachedKey` trong RAM của process Node. Ai đọc được `.env` hoặc dump được memory sẽ giải mã được CCCD, email, điện thoại của **mọi** khách hàng — vĩnh viễn, không thu hồi được.

Nay khoá nằm trong OpenBao và **không bao giờ vào process của app**. App chỉ có token để gọi `encrypt`/`decrypt`. Thay đổi cụ thể về khả năng phòng thủ:

| | Trước | Nay |
|---|---|---|
| Nơi giữ khoá | `.env` + RAM của app | Chỉ trong OpenBao |
| Chiếm được app host | Mất khoá, giải mã vĩnh viễn | Chỉ có token — thu hồi được |
| Dấu vết khi bị lạm dụng | Không có | Audit log từng lần encrypt/decrypt |
| Xoay khoá | Phải giải mã rồi mã hoá lại toàn bộ | `rotate` + `rewrap`, không cần plaintext |
| Số secret trên đĩa | 10 | 1 cặp (role_id + secret_id) |

**Giới hạn phải thừa nhận**: app vẫn cần `BAO_ROLE_ID` + `BAO_SECRET_ID` trong `.env` để xác thực. Trên một máy đơn, cặp credential này vẫn nằm trên đĩa. OpenBao **thu hẹp** vùng tin cậy chứ không xoá bỏ nó. Điểm khác biệt thật: cặp này thu hồi được và mọi lần dùng đều có trong audit log.

---

## 2. Bố cục trên máy

```
C:\Users\ncong\openbao\
├── bin\bao.exe              binary v2.7.1 (đã kiểm SHA256)
├── bin\run-server.cmd        wrapper khởi động, ghi log ra bao.log
├── config\bao.hcl            cấu hình server
├── config\policy-skybooking-app.hcl
├── data\                     dữ liệu raft (đã mã hoá bằng master key)
├── INIT-KEYS.json            5 unseal key + root token  ← PHẢI DI CHUYỂN, xem §6
├── APP-CREDS.json            role_id + secret_id của app
├── unseal.ps1                script unseal (hỏi khoá, không tự đọc file)
└── bao.log
```

| Mục | Giá trị |
|---|---|
| Địa chỉ | `http://127.0.0.1:8200` (chỉ loopback) |
| UI | http://127.0.0.1:8200/ui |
| Storage | `raft`, node id `skybooking-node1` |
| Task Windows | `OpenBao-Server` — chạy lúc đăng nhập, lặp mỗi phút |

---

## 3. Những gì đã cấu hình trong OpenBao

**KV v2 tại `kv/`** — secret của app ở `kv/skybooking/app`, hiện có 9 giá trị: `ADMIN_KEY`, `SESSION_SECRET`, `DB_USER`, `DB_PASSWORD`, `AUDIT_DB_WRITER_USER`, `AUDIT_DB_WRITER_PASSWORD`, `AUDIT_DB_READER_USER`, `AUDIT_DB_READER_PASSWORD`, `ENCRYPTION_KEY`.

`ENCRYPTION_KEY` chỉ còn để đọc dữ liệu cũ. Xoá sau khi migrate xong.

**Transit tại `transit/`** — khoá `booking-pii`, loại `aes256-gcm96`.

**Policy `skybooking-app`** — đặc quyền tối thiểu. Được phép: đọc `kv/data/skybooking/app`, gọi `transit/encrypt|decrypt|rewrap/booking-pii`, tự gia hạn token. **Không** được phép: đọc `transit/keys/*` (không export được khoá), ghi vào KV, truy cập `sys/*`, hay `transit/datakey/*`.

Đã kiểm chứng bằng phép thử ngược: token của app đọc `transit/keys/booking-pii` → `permission denied`; ghi vào KV → `permission denied`.

**AppRole `skybooking`** — `token_ttl=1h`, `token_max_ttl=24h`, `secret_id_ttl=0` (không hết hạn), `secret_id_num_uses=0` (không giới hạn).

> `secret_id_ttl=0` là đánh đổi cho máy đơn: nếu secret_id hết hạn, app không tự khởi động lại được. Trên môi trường thật nên đặt TTL và cấp secret_id qua CI/CD hoặc response wrapping.

---

## 4. Thay đổi trong mã nguồn

| File | Thay đổi |
|---|---|
| `lib/bao.js` | **Mới.** Client OpenBao: AppRole login + tự gia hạn token, đọc KV, Transit encrypt/decrypt có chia lô. Dùng `fetch` của Node, **không thêm dependency** |
| `lib/crypto.js` | Viết lại. `encrypt`/`decrypt`/`decryptSafe` thành **async**. Thêm `encryptBatch`, `decryptBatchSafe`, `isLegacyFormat` |
| `bootstrap.js` | **Mới.** Entrypoint: nạp secret từ KV vào `process.env` rồi mới `require('./server')` |
| `db/migrateToBao.js` | **Mới.** Chuyển dữ liệu `v1:` → `vault:v1:` |
| `routes/bookings.js` | `ownsBooking`, `toCustomerDto` thành async; `encryptBatch` khi tạo vé |
| `routes/admin.js` | `GET /bookings` gom toàn bộ 3×N giá trị vào batch |
| `db/init.js` | Dùng `encryptBatch` |
| `server.js` | `checkSecrets()` kiểm `BAO_*` thay vì `ENCRYPTION_KEY` |
| `lib/alerting.js` | Sửa gợi ý của `DECRYPT_FAILED` cho đúng ngữ cảnh mới |
| `package.json` | `start` trỏ vào `bootstrap.js`; thêm `bao-migrate`, `bao-status` |

### Vì sao cần `bootstrap.js` thay vì nạp secret trong `server.js`

`db/pool.js` gọi `mysql.createPool()` **ngay lúc load module**, đọc trực tiếp `process.env.DB_PASSWORD`. `require` là đồng bộ còn đọc KV là async, nên không thể nạp secret từ trong `server.js` — lúc đó pool đã tạo xong. `bootstrap.js` nạp secret trước, rồi mới require server.

Thứ tự ưu tiên: **giá trị từ OpenBao ghi đè `.env`**. Nhờ vậy xoá dần secret khỏi `.env` mà app vẫn chạy.

### Hai định dạng cùng tồn tại

```
v1:<iv>:<tag>:<ct>   dữ liệu CŨ, giải mã cục bộ bằng ENCRYPTION_KEY
vault:v1:<...>       dữ liệu MỚI qua Transit
```

Đọc hỗ trợ cả hai; ghi luôn dùng Transit. `decryptBatchSafe` tách lô: phần `v1:` xử lý tại local, phần `vault:` gộp vào request Transit.

### Chia lô là bắt buộc, không phải tối ưu

`GET /api/admin/bookings?limit=200` cần giải mã 3 trường × 200 dòng = **600 giá trị**. Gọi từng cái là 600 HTTP round-trip — không dùng được.

Nhưng gộp cả 600 vào một request **cũng không được**: OpenBao có `max_request_json_strings` mặc định 1000, mỗi item batch đóng góp ~2 chuỗi nên 600 item ≈ 1200 chuỗi và bị từ chối:

```
HTTP 400: refused JSON input due to high complexity: exceeded maximum number of strings
```

`lib/bao.js` chia lô 250 item/request (`BAO_BATCH_CHUNK`). Đo thực tế: 600 giá trị encrypt 58ms + decrypt 37ms = **0.08ms/giá trị**.

Cố ý **không** nâng `max_request_json_strings` trên server: chia lô ở client đã giải quyết triệt để, nâng giới hạn chỉ làm yếu một lớp chống DoS.

---

## 5. Vận hành

### Khởi động hằng ngày

```powershell
# 1. Server (thường đã tự chạy qua Task Scheduler)
Start-ScheduledTask -TaskName "OpenBao-Server"

# 2. Unseal - cần 3 trong 5 khoá
powershell -ExecutionPolicy Bypass -File C:\Users\ncong\openbao\unseal.ps1

# 3. App
cd C:\Users\ncong\Downloads\Booking
npm start
```

`npm start` sẽ tự kiểm tra OpenBao sống, đã unseal, đọc được KV, và Transit mã hoá/giải mã được. Thiếu bất cứ điều kiện nào thì **từ chối khởi động** thay vì chạy với PII không được bảo vệ.

### Kiểm tra nhanh

```powershell
$env:BAO_ADDR="http://127.0.0.1:8200"
C:\Users\ncong\openbao\bin\bao.exe status
npm run bao-status
```

### Migrate dữ liệu cũ

```powershell
node db/migrateToBao.js --dry-run   # xem trước, không ghi gì
npm run bao-migrate                 # chạy thật
```

Mỗi lô trong một transaction, giải mã lại để kiểm chứng **trước khi commit**, lỗi là rollback cả lô. Chạy lại nhiều lần không sao.

### Xoay khoá Transit

```powershell
$env:BAO_TOKEN="<root token>"
bao write -f transit/keys/booking-pii/rotate      # tạo version mới
bao write transit/rewrap/booking-pii ciphertext=<ct>   # nâng ciphertext cũ
```

Dữ liệu mã hoá bằng version cũ **vẫn giải mã được** sau khi rotate, nên rewrap làm dần được. App có quyền `rewrap` nhưng không có quyền `rotate` — rotate là việc của admin.

### Thu hồi credential của app

```powershell
bao write -f auth/approle/role/skybooking/secret-id   # cấp cặp mới
bao list auth/approle/role/skybooking/secret-id       # xem các secret_id đang có
```

---

## 6. Ba việc cần làm ngay

### 6.1 Di chuyển `INIT-KEYS.json` ra khỏi máy này

File này chứa 5 unseal key và root token. **Để nó cùng ổ đĩa với `data\` thì việc niêm phong gần như vô nghĩa** — ai lấy được ổ đĩa là có cả dữ liệu đã mã hoá lẫn khoá để mở.

Đưa vào password manager, hoặc in ra giấy chia cho nhiều người giữ, rồi xoá khỏi máy. Chỉ cần 3 trong 5 khoá để unseal. `unseal.ps1` cố ý hỏi khoá chứ không tự đọc file, đúng vì lý do này.

### 6.2 Chạy migration rồi xoá `ENCRYPTION_KEY`

Còn `ENCRYPTION_KEY` trong `.env` là còn một bản khoá nằm ngoài OpenBao — đúng thứ ta muốn loại bỏ. `server.js` sẽ cảnh báo cho đến khi bạn xoá nó.

```powershell
npm run bao-migrate
# khi báo "khong con gi de migrate":
#   - xoá ENCRYPTION_KEY khỏi .env
#   - bao kv patch -method=delete kv/skybooking/app ENCRYPTION_KEY
#   - giữ bản sao lưu khoá cũ ở nơi an toàn cho đến khi chắc chắn
```

### 6.3 Backup `data\` và unseal key ở **hai nơi khác nhau**

Mất `data\` mà có khoá: mất dữ liệu. Mất khoá mà có `data\`: không mở được. Mất cả hai: mất hết. Hai bản sao lưu phải tách biệt, nếu không thì backup chẳng bảo vệ gì.

---

## 7. Giới hạn còn lại

**Unseal thủ công.** Sau mỗi lần reboot, app không tự khởi động được cho tới khi có người unseal. Đây là cái giá của việc không dùng auto-unseal. Muốn tự động hoàn toàn thì cần cloud KMS (AWS/GCP/Azure) — nhưng khi đó tin cậy chuyển sang nhà cung cấp cloud.

**`tls_disable = 1`.** App và OpenBao cùng máy, chỉ nghe loopback nên traffic không ra mạng. Khi tách sang hai máy thì **bắt buộc** bật TLS — xem chú thích trong `config\bao.hcl`.

**`disable_mlock` không khả dụng.** Windows không hỗ trợ, và OpenBao 2.x đã bỏ field này. Nghĩa là bộ nhớ của OpenBao có thể bị ghi ra pagefile. Trên Linux thì mlock xử lý được việc này.

**Một node, không HA.** `raft` báo "HA available" nhưng chỉ có một node. Node chết là OpenBao không truy cập được, và app sẽ từ chối xử lý PII (fail closed) — đúng thiết kế, nhưng nghĩa là OpenBao thành điểm chết đơn.

**Vẫn còn bootstrap secret trên đĩa.** Như đã nói ở §1.
