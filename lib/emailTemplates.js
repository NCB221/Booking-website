/**
 * Noi dung email gui cho khach. Moi template tra ve { subject, text, html }.
 *
 * Luu y bao mat:
 *  - CCCD duoc CHE BOT trong email. Email la kenh khong duoc ma hoa dau-cuoi,
 *    khong gui so CCCD day du qua email.
 *  - Moi gia tri dong deu duoc escape HTML (phong HTML injection qua ho ten).
 */
const { maskCccd, maskPhone } = require('./crypto');

const BRAND = 'SkyBooking';
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function esc(v) {
  return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

function money(n) {
  return new Intl.NumberFormat('vi-VN').format(Math.round(Number(n))) + ' đ';
}

function pad(n) { return String(n).padStart(2, '0'); }

/** '2026-10-20 06:30:00' -> '06:30 ngày 20/10/2026' */
function dateTimeVi(dt) {
  const d = new Date(String(dt).replace(' ', 'T'));
  return `${pad(d.getHours())}:${pad(d.getMinutes())} ngày ` +
         `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
}

function duration(a, b) {
  const mins = Math.round(
    (new Date(String(b).replace(' ', 'T')) - new Date(String(a).replace(' ', 'T'))) / 60000
  );
  return `${Math.floor(mins / 60)}h${mins % 60 ? pad(mins % 60) : '00'}`;
}

/* --- Khung HTML dung chung (bang long nhau cho tuong thich email client) --- */

function layout({ title, accent, preheader, bodyHtml }) {
  return `<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Roboto,Arial,sans-serif;color:#1e293b">
  <span style="display:none;max-height:0;overflow:hidden">${esc(preheader)}</span>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:24px 12px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="max-width:600px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 6px 20px rgba(2,8,23,.08)">
        <tr>
          <td style="background:${accent};padding:22px 26px;color:#ffffff">
            <div style="font-size:20px;font-weight:700">&#9992; ${BRAND}</div>
            <div style="font-size:15px;opacity:.92;margin-top:3px">${esc(title)}</div>
          </td>
        </tr>
        <tr><td style="padding:26px">${bodyHtml}</td></tr>
        <tr>
          <td style="background:#f8fafc;padding:18px 26px;font-size:12px;color:#64748b;border-top:1px solid #e2e8f0">
            Đây là email tự động, vui lòng không trả lời.<br>
            Thông tin cá nhân của bạn được mã hóa khi lưu trữ. Số CCCD trong email
            được che bớt để bảo mật.
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

function row(label, value, bold = false) {
  return `<tr>
    <td style="padding:7px 0;color:#64748b;font-size:14px;width:42%">${esc(label)}</td>
    <td style="padding:7px 0;font-size:14px;${bold ? 'font-weight:700' : ''}">${esc(value)}</td>
  </tr>`;
}

function flightBlock(b) {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0"
           style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px;margin-bottom:16px">
    ${row('Chuyến bay', `${b.flight_number} · ${b.airline}`, true)}
    ${row('Chặng bay', `${b.from_city} (${b.from_airport}) → ${b.to_city} (${b.to_airport})`)}
    ${row('Khởi hành', dateTimeVi(b.departure_time), true)}
    ${row('Đến nơi', `${dateTimeVi(b.arrival_time)} (bay ${duration(b.departure_time, b.arrival_time)})`)}
  </table>`;
}

function passengerBlock(b) {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0"
           style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px;margin-bottom:16px">
    ${row('Hành khách', b.passenger_name, true)}
    ${row('Số điện thoại', maskPhone(b.passenger_phone || ''))}
    ${row('Số CCCD', maskCccd(b.passenger_cccd || ''))}
    ${row('Số ghế', String(b.seat_count))}
    ${row('Tổng tiền', money(b.total_price), true)}
  </table>`;
}

/* --- Template 1: xac nhan dat ve --- */

function bookingConfirmation(b) {
  const subject = `Xác nhận đặt vé ${b.booking_code} · ${BRAND}`;

  const text = [
    `${BRAND} - XÁC NHẬN ĐẶT VÉ`,
    '',
    `Chào ${b.passenger_name},`,
    '',
    `Vé của bạn đã được xác nhận. Mã vé: ${b.booking_code}`,
    '',
    'THÔNG TIN CHUYẾN BAY',
    `  Chuyến bay : ${b.flight_number} (${b.airline})`,
    `  Chặng bay  : ${b.from_city} (${b.from_airport}) -> ${b.to_city} (${b.to_airport})`,
    `  Khởi hành  : ${dateTimeVi(b.departure_time)}`,
    `  Đến nơi    : ${dateTimeVi(b.arrival_time)} (bay ${duration(b.departure_time, b.arrival_time)})`,
    '',
    'THÔNG TIN HÀNH KHÁCH',
    `  Hành khách : ${b.passenger_name}`,
    `  Số CCCD    : ${maskCccd(b.passenger_cccd || '')}`,
    `  Số ghế     : ${b.seat_count}`,
    `  Tổng tiền  : ${money(b.total_price)}`,
    '',
    `Để tra cứu hoặc hủy vé, bạn cần MÃ VÉ (${b.booking_code}) và chính email này.`,
    'Vui lòng giữ lại mã vé. Mang theo CCCD khi làm thủ tục tại sân bay.',
    '',
    'Đây là email tự động, vui lòng không trả lời.',
  ].join('\n');

  const html = layout({
    title: 'Xác nhận đặt vé',
    accent: 'linear-gradient(120deg,#1e3a8a,#2563eb 55%,#0ea5e9)',
    preheader: `Mã vé ${b.booking_code} - ${b.from_city} đi ${b.to_city}`,
    bodyHtml: `
      <p style="margin:0 0 14px;font-size:15px">Chào <strong>${esc(b.passenger_name)}</strong>,</p>
      <p style="margin:0 0 18px;font-size:15px">
        Vé của bạn đã được <strong style="color:#16a34a">xác nhận</strong>. Vui lòng giữ lại mã vé dưới đây.
      </p>

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="background:#eff6ff;border:1px dashed #2563eb;border-radius:10px;margin-bottom:18px">
        <tr><td align="center" style="padding:16px">
          <div style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:1px">Mã vé</div>
          <div style="font-size:30px;font-weight:800;letter-spacing:3px;color:#1d4ed8;margin-top:4px">
            ${esc(b.booking_code)}
          </div>
        </td></tr>
      </table>

      <h3 style="margin:0 0 8px;font-size:15px">Thông tin chuyến bay</h3>
      ${flightBlock(b)}

      <h3 style="margin:0 0 8px;font-size:15px">Thông tin hành khách</h3>
      ${passengerBlock(b)}

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="background:#fffbeb;border-left:4px solid #d97706;border-radius:8px">
        <tr><td style="padding:14px 16px;font-size:14px">
          <strong>Lưu ý</strong>
          <ul style="margin:8px 0 0;padding-left:20px;line-height:1.7">
            <li>Để tra cứu hoặc hủy vé, bạn cần <strong>mã vé</strong> và <strong>chính email này</strong>.</li>
            <li>Vui lòng mang theo <strong>CCCD</strong> khi làm thủ tục tại sân bay.</li>
            <li>Có mặt tại sân bay trước giờ khởi hành ít nhất <strong>60 phút</strong>.</li>
          </ul>
        </td></tr>
      </table>`,
  });

  return { subject, text, html };
}

/* --- Template 2: xac nhan huy ve --- */

function bookingCancellation(b) {
  const subject = `Đã hủy vé ${b.booking_code} · ${BRAND}`;

  const text = [
    `${BRAND} - ĐÃ HỦY VÉ`,
    '',
    `Chào ${b.passenger_name},`,
    '',
    `Vé ${b.booking_code} của bạn đã được hủy theo yêu cầu.`,
    '',
    `  Chuyến bay : ${b.flight_number} (${b.airline})`,
    `  Chặng bay  : ${b.from_city} (${b.from_airport}) -> ${b.to_city} (${b.to_airport})`,
    `  Khởi hành  : ${dateTimeVi(b.departure_time)}`,
    `  Số ghế     : ${b.seat_count}`,
    `  Số tiền    : ${money(b.total_price)}`,
    '',
    'Nếu bạn KHÔNG thực hiện yêu cầu hủy này, vui lòng liên hệ ngay với chúng tôi.',
    '',
    'Đây là email tự động, vui lòng không trả lời.',
  ].join('\n');

  const html = layout({
    title: 'Vé đã được hủy',
    accent: 'linear-gradient(120deg,#7f1d1d,#dc2626 60%,#f87171)',
    preheader: `Vé ${b.booking_code} đã được hủy`,
    bodyHtml: `
      <p style="margin:0 0 14px;font-size:15px">Chào <strong>${esc(b.passenger_name)}</strong>,</p>
      <p style="margin:0 0 18px;font-size:15px">
        Vé <strong>${esc(b.booking_code)}</strong> của bạn đã được
        <strong style="color:#dc2626">hủy</strong> theo yêu cầu.
      </p>

      ${flightBlock(b)}

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px;margin-bottom:16px">
        ${row('Số ghế đã hủy', String(b.seat_count))}
        ${row('Số tiền', money(b.total_price), true)}
      </table>

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="background:#fef2f2;border-left:4px solid #dc2626;border-radius:8px">
        <tr><td style="padding:14px 16px;font-size:14px">
          Nếu bạn <strong>không</strong> thực hiện yêu cầu hủy này, vui lòng liên hệ ngay
          với chúng tôi để được hỗ trợ.
        </td></tr>
      </table>`,
  });

  return { subject, text, html };
}

module.exports = { bookingConfirmation, bookingCancellation };
