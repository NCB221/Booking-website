const $ = (id) => document.getElementById(id);

// Giu lai email da xac thuc de dung cho thao tac huy ve
let verifiedEmail = '';

function render(b) {
  const cancelled = b.status === 'CANCELLED';
  $('result').innerHTML = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:16px">
        <div>
          <div class="muted" style="font-size:13px">Ma ve</div>
          <div style="font-size:26px;font-weight:800;letter-spacing:2px">${esc(b.booking_code)}</div>
        </div>
        <span class="badge ${cancelled ? 'badge-cancel' : 'badge-ok'}">
          ${cancelled ? 'Da huy' : 'Da xac nhan'}
        </span>
      </div>

      <div class="summary-box">
        <div class="row"><span>Chuyen bay</span><strong>${esc(b.flight_number)} &middot; ${esc(b.airline)}</strong></div>
        <div class="row"><span>Chang bay</span><strong>${esc(b.from_city)} (${esc(b.from_airport)}) &#8594; ${esc(b.to_city)} (${esc(b.to_airport)})</strong></div>
        <div class="row"><span>Khoi hanh</span><strong>${dateLabel(b.departure_time)} luc ${hhmm(b.departure_time)}</strong></div>
        <div class="row"><span>Den noi</span><strong>${hhmm(b.arrival_time)} (${duration(b.departure_time, b.arrival_time)})</strong></div>
      </div>

      <div class="summary-box">
        <div class="row"><span>Hanh khach</span><strong>${esc(b.passenger_name)}</strong></div>
        <div class="row"><span>Email</span><strong>${esc(b.passenger_email)}</strong></div>
        <div class="row"><span>Dien thoai</span><strong>${esc(b.passenger_phone)}</strong></div>
        <div class="row"><span>CCCD</span><strong>${esc(b.passenger_cccd)}</strong></div>
        <div class="row"><span>So ghe</span><strong>${esc(b.seat_count)}</strong></div>
        <div class="row total"><span>Tong tien</span><span>${money(b.total_price)}</span></div>
      </div>
      <p class="muted" style="font-size:12px;margin-bottom:14px">
        &#128274; Thong tin ca nhan duoc ma hoa AES-256-GCM trong he thong va hien thi
        che bot o day de bao mat. Lien he quay ve neu can xem ban day du.
      </p>

      ${cancelled ? '' : `
        <div style="text-align:right">
          <button class="btn btn-danger" id="cancelBtn">Huy ve nay</button>
        </div>`}
    </div>`;

  const cb = $('cancelBtn');
  if (cb) cb.addEventListener('click', () => cancelBooking(b.booking_code));
}

async function lookup(code, email) {
  $('result').innerHTML = '<div class="loading">Dang tra cuu...</div>';
  try {
    // Dung POST de email khong bi ghi vao URL / lich su trinh duyet
    const b = await api('/api/bookings/lookup', {
      method: 'POST',
      body: JSON.stringify({ code, email }),
    });
    verifiedEmail = email;
    render(b);
  } catch (e) {
    verifiedEmail = '';
    $('result').innerHTML = `<div class="empty">${esc(e.message)}</div>`;
  }
}

async function cancelBooking(code) {
  if (!verifiedEmail) return;
  if (!confirm('Ban chac chan muon huy ve ' + code + '?')) return;
  try {
    await api('/api/bookings/' + encodeURIComponent(code) + '/cancel', {
      method: 'POST',
      body: JSON.stringify({ email: verifiedEmail }),
    });
    toast('Da huy ve thanh cong', 'ok');
    lookup(code, verifiedEmail);
  } catch (e) { toast(e.message, 'err'); }
}

document.addEventListener('DOMContentLoaded', () => {
  $('lookupForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const code = $('code').value.trim().toUpperCase();
    const email = $('email').value.trim().toLowerCase();
    if (code && email) lookup(code, email);
  });

  // Dien san ma ve neu duoc chuyen tu trang dat ve (?code=...).
  // Khach van phai nhap email de xac thuc moi xem duoc.
  const code = new URLSearchParams(location.search).get('code');
  if (code) {
    $('code').value = code.toUpperCase().slice(0, 12);
    $('email').focus();
  }
});
