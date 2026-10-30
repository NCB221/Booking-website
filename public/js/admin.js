const $ = (id) => document.getElementById(id);

// Luu TOKEN + KHOA KY cua phien admin (han 2 gio).
// Khong bao gio luu master key (ADMIN_KEY) o phia client.
let airports = [];

/** Nap thong tin phien admin vao AdminCreds de api() dung khi ky request. */
function setAdminCreds(token, signingKey) {
  AdminCreds.token = token;
  AdminCreds.signingKey = signingKey;
}

/** Goi API quan tri: ky bang khoa rieng cua phien admin. */
async function adminApi(url, options = {}) {
  try {
    return await api(url, { ...options, admin: true });
  } catch (err) {
    if (/het han|khong hop le/i.test(err.message)) {
      toast('Phien dang nhap da het han, vui long dang nhap lai', 'err');
      logout();
    }
    throw err;
  }
}

// --- Dang nhap ---
async function doLogin(key) {
  // Request dang nhap duoc ky bang khoa cua phien KHACH (chua co phien admin)
  const res = await api('/api/admin/login', {
    method: 'POST',
    body: JSON.stringify({ key }),
  });
  setAdminCreds(res.token, res.signing_key);
  try {
    sessionStorage.setItem('adminToken', res.token);
    sessionStorage.setItem('adminSigningKey', res.signing_key);
  } catch { /* bo qua neu khong luu duoc */ }
  showDashboard();
}

function showDashboard() {
  $('loginView').style.display = 'none';
  $('dashView').style.display = 'block';
  $('logoutBtn').style.display = 'inline-block';
  loadAll();
}

function logout() {
  try {
    sessionStorage.removeItem('adminToken');
    sessionStorage.removeItem('adminSigningKey');
  } catch { /* bo qua */ }
  setAdminCreds(null, null);
  $('loginView').style.display = 'block';
  $('dashView').style.display = 'none';
  $('logoutBtn').style.display = 'none';
}

/* --- NHAT KY AUDIT --- */

let auditPage = 1;

function sigBadge(v) {
  if (v === null || v === undefined) return '<span class="muted">-</span>';
  return v
    ? '<span class="badge badge-ok">hop le</span>'
    : '<span class="badge badge-cancel">SAI</span>';
}

function statusColor(code) {
  if (code >= 500) return 'color:#dc2626;font-weight:700';
  if (code >= 400) return 'color:#d97706;font-weight:600';
  return 'color:#16a34a';
}

async function loadAuditLogs(page = 1) {
  auditPage = page;
  const body = $('auditBody');
  try {
    const q = new URLSearchParams({ page: String(page), limit: '50' });
    const filter = $('auditFilter').value.trim();
    if (filter) {
      // Doan loai filter: UUID -> request_id, co dau ':' hoac '.' -> IP, con lai -> ma ve
      if (/^[0-9a-f-]{16,64}$/i.test(filter)) q.set('request_id', filter);
      else if (/[.:]/.test(filter)) q.set('ip', filter);
      else q.set('booking_code', filter.toUpperCase());
    }
    if ($('auditFailedOnly').checked) q.set('failed', '1');

    const res = await adminApi('/api/admin/audit-logs?' + q.toString());
    const rows = res.data;
    if (rows.length === 0) {
      body.innerHTML = '<tr><td colspan="13" class="empty">Khong co ban ghi phu hop</td></tr>';
      $('auditPager').textContent = '';
      return;
    }
    body.innerHTML = rows.map((r) => `
      <tr>
        <td>${r.id}</td>
        <td style="white-space:nowrap;font-size:12px">${esc(r.request_time)}</td>
        <td style="font-family:monospace;font-size:11px">${esc(String(r.request_id).slice(0, 13))}...</td>
        <td>${esc(r.method)}</td>
        <td style="font-size:12px;max-width:220px;overflow:hidden;text-overflow:ellipsis">${esc(r.path)}</td>
        <td style="${statusColor(r.status_code)}">${r.status_code}</td>
        <td>${r.duration_ms}</td>
        <td style="font-size:12px">${esc(r.ip)}</td>
        <td style="font-size:12px">${esc(r.actor_role)}</td>
        <td>${sigBadge(r.signature_valid)}</td>
        <td style="font-size:12px">${r.clock_skew_ms === null ? '-' : r.clock_skew_ms + 'ms'}</td>
        <td style="font-family:monospace;font-size:11px">${r.body_sha256 ? esc(r.body_sha256.slice(0, 10)) + '...' : '-'}</td>
        <td style="font-size:12px">${esc(r.booking_code || '-')}</td>
      </tr>`).join('');

    const from = (res.page - 1) * res.limit + 1;
    const to = Math.min(res.page * res.limit, res.total);
    const pages = Math.ceil(res.total / res.limit);
    $('auditPager').innerHTML =
      `Hien ${from}-${to} / ${res.total} ban ghi &nbsp;` +
      (res.page > 1 ? '<button class="btn btn-ghost btn-sm" id="auditPrev">&larr; Truoc</button> ' : '') +
      (res.page < pages ? '<button class="btn btn-ghost btn-sm" id="auditNext">Sau &rarr;</button>' : '');
    const prev = $('auditPrev'), next = $('auditNext');
    if (prev) prev.addEventListener('click', () => loadAuditLogs(auditPage - 1));
    if (next) next.addEventListener('click', () => loadAuditLogs(auditPage + 1));
  } catch (e) {
    body.innerHTML = `<tr><td colspan="13" class="empty">${esc(e.message)}</td></tr>`;
  }
}

async function verifyAuditChain() {
  const box = $('auditVerifyResult');
  box.innerHTML = '<div class="loading">Dang kiem tra chuoi hash...</div>';
  try {
    const r = await adminApi('/api/admin/audit-logs/verify');
    if (r.ok) {
      box.innerHTML = `
        <div class="summary-box" style="border-color:#16a34a">
          <strong style="color:#16a34a">&#10004; Chuoi hash NGUYEN VEN</strong> &mdash;
          da kiem tra ${esc(r.checked)} ban ghi, khong co dau hieu bi sua hay xoa.
          <div class="muted" style="font-size:12px;margin-top:6px;font-family:monospace">
            hash cuoi: ${esc(r.last_hash)}
          </div>
        </div>`;
    } else {
      box.innerHTML = `
        <div class="summary-box" style="border-color:#dc2626">
          <strong style="color:#dc2626">&#10008; CHUOI HASH BI DUT tai ban ghi #${esc(r.broken_at)}</strong>
          <div style="margin-top:6px">${esc(r.reason)}</div>
          <div class="muted" style="font-size:12px;margin-top:6px">
            Da kiem tra ${esc(r.checked)} ban ghi. Nhat ky co the da bi can thiep.
          </div>
        </div>`;
    }
  } catch (e) {
    box.innerHTML = `<div class="summary-box" style="border-color:#dc2626">${esc(e.message)}</div>`;
  }
}

async function loadAll() {
  loadStats();
  loadFlights();
  loadBookings();
  loadAuditLogs(1);
  if (airports.length === 0) {
    airports = await api('/api/airports');
    const opts = airports
      .map((a) => `<option value="${esc(a.code)}">${esc(a.city)} (${esc(a.code)})</option>`)
      .join('');
    $('fFrom').innerHTML = opts;
    $('fTo').innerHTML = opts;
  }
}

async function loadStats() {
  try {
    const s = await adminApi('/api/admin/stats');
    $('stats').innerHTML = `
      <div class="stat"><div class="num">${s.flights}</div><div class="label">Chuyen bay</div></div>
      <div class="stat"><div class="num">${s.confirmed_bookings}</div><div class="label">Ve da xac nhan</div></div>
      <div class="stat"><div class="num">${s.cancelled_bookings}</div><div class="label">Ve da huy</div></div>
      <div class="stat"><div class="num">${money(s.revenue)}</div><div class="label">Doanh thu</div></div>`;
  } catch (e) { /* loi da hien thi qua toast */ }
}

async function loadFlights() {
  try {
    const res = await adminApi('/api/admin/flights?limit=200');
    const flights = res.data;
    const body = $('flightsBody');
    if (flights.length === 0) {
      body.innerHTML = '<tr><td colspan="8" class="empty">Chua co chuyen bay</td></tr>';
      return;
    }
    body.innerHTML = flights.map((f) => `
      <tr>
        <td><strong>${esc(f.flight_number)}</strong></td>
        <td>${esc(f.airline)}</td>
        <td>${esc(f.from_airport)} &#8594; ${esc(f.to_airport)}</td>
        <td>${dateLabel(f.departure_time)} ${hhmm(f.departure_time)}</td>
        <td>${money(f.price)}</td>
        <td>${f.available_seats}/${f.total_seats}</td>
        <td>${f.bookings_count}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-ghost btn-sm" data-edit="${f.id}">Sua</button>
          <button class="btn btn-danger btn-sm" data-del="${f.id}">Xoa</button>
        </td>
      </tr>`).join('');

    body.querySelectorAll('[data-edit]').forEach((b) =>
      b.addEventListener('click', () =>
        openFlightModal(flights.find((x) => String(x.id) === b.dataset.edit))));
    body.querySelectorAll('[data-del]').forEach((b) =>
      b.addEventListener('click', () => deleteFlight(b.dataset.del)));
  } catch (e) {
    $('flightsBody').innerHTML = `<tr><td colspan="8" class="empty">${esc(e.message)}</td></tr>`;
  }
}

async function loadBookings() {
  try {
    const res = await adminApi('/api/admin/bookings?limit=200');
    const list = res.data;
    const body = $('bookingsBody');
    if (list.length === 0) {
      body.innerHTML = '<tr><td colspan="9" class="empty">Chua co ve dat</td></tr>';
      return;
    }
    body.innerHTML = list.map((b) => {
      const cancelled = b.status === 'CANCELLED';
      return `
      <tr>
        <td><strong>${esc(b.booking_code)}</strong></td>
        <td>${esc(b.passenger_name)}</td>
        <td style="font-family:monospace;font-size:13px">${esc(b.passenger_cccd || '-')}</td>
        <td style="font-size:12px">${esc(b.passenger_email)}<br>${esc(b.passenger_phone)}</td>
        <td>${esc(b.flight_number)}<br><span class="muted" style="font-size:12px">${esc(b.from_airport)}&#8594;${esc(b.to_airport)}</span></td>
        <td>${b.seat_count}</td>
        <td>${money(b.total_price)}</td>
        <td><span class="badge ${cancelled ? 'badge-cancel' : 'badge-ok'}">${cancelled ? 'Da huy' : 'Xac nhan'}</span></td>
        <td>${cancelled ? '' : `<button class="btn btn-danger btn-sm" data-cancel="${b.id}">Huy</button>`}</td>
      </tr>`;
    }).join('');
    body.querySelectorAll('[data-cancel]').forEach((b) =>
      b.addEventListener('click', () => cancelBooking(b.dataset.cancel)));
  } catch (e) {
    $('bookingsBody').innerHTML = `<tr><td colspan="9" class="empty">${esc(e.message)}</td></tr>`;
  }
}

// --- Modal chuyen bay ---
function toLocalInput(dt) { return dt ? dt.replace(' ', 'T').slice(0, 16) : ''; }
function fromLocalInput(v) { return v.replace('T', ' ') + ':00'; }

function openFlightModal(f) {
  $('flightForm').reset();
  if (f) {
    $('flightModalTitle').textContent = 'Sua chuyen bay';
    $('fId').value = f.id;
    $('fNumber').value = f.flight_number;
    $('fAirline').value = f.airline;
    $('fFrom').value = f.from_airport;
    $('fTo').value = f.to_airport;
    $('fDep').value = toLocalInput(f.departure_time);
    $('fArr').value = toLocalInput(f.arrival_time);
    $('fPrice').value = Math.round(f.price);
    $('fSeats').value = f.total_seats;
  } else {
    $('flightModalTitle').textContent = 'Them chuyen bay';
    $('fId').value = '';
  }
  $('flightModal').classList.add('show');
}

function closeFlightModal() { $('flightModal').classList.remove('show'); }

async function saveFlight(e) {
  e.preventDefault();
  const payload = {
    flight_number: $('fNumber').value.trim(),
    airline: $('fAirline').value.trim(),
    from_airport: $('fFrom').value,
    to_airport: $('fTo').value,
    departure_time: fromLocalInput($('fDep').value),
    arrival_time: fromLocalInput($('fArr').value),
    price: Number($('fPrice').value),
    total_seats: Number($('fSeats').value),
  };
  const id = $('fId').value;
  try {
    if (id) {
      await adminApi('/api/admin/flights/' + encodeURIComponent(id), {
        method: 'PUT', body: JSON.stringify(payload),
      });
      toast('Da cap nhat chuyen bay', 'ok');
    } else {
      await adminApi('/api/admin/flights', { method: 'POST', body: JSON.stringify(payload) });
      toast('Da them chuyen bay', 'ok');
    }
    closeFlightModal();
    loadFlights(); loadStats();
  } catch (err) { toast(err.message, 'err'); }
}

async function deleteFlight(id) {
  if (!confirm('Xoa chuyen bay nay?')) return;
  try {
    await adminApi('/api/admin/flights/' + encodeURIComponent(id), { method: 'DELETE' });
    toast('Da xoa chuyen bay', 'ok');
    loadFlights(); loadStats();
  } catch (e) { toast(e.message, 'err'); }
}

async function cancelBooking(id) {
  if (!confirm('Huy ve nay? Ghe se duoc tra lai chuyen bay.')) return;
  try {
    await adminApi('/api/admin/bookings/' + encodeURIComponent(id) + '/cancel', { method: 'POST' });
    toast('Da huy ve', 'ok');
    loadBookings(); loadFlights(); loadStats();
  } catch (e) { toast(e.message, 'err'); }
}

document.addEventListener('DOMContentLoaded', () => {
  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      await doLogin($('adminKey').value);
      $('adminKey').value = '';
    } catch (err) {
      toast(err.message, 'err');
    } finally {
      btn.disabled = false;
    }
  });

  $('logoutBtn').addEventListener('click', (e) => { e.preventDefault(); logout(); });
  $('auditReloadBtn').addEventListener('click', () => loadAuditLogs(1));
  $('auditVerifyBtn').addEventListener('click', verifyAuditChain);
  $('auditFilter').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); loadAuditLogs(1); }
  });
  $('auditFailedOnly').addEventListener('change', () => loadAuditLogs(1));
  $('addFlightBtn').addEventListener('click', () => openFlightModal(null));
  $('flightCancelBtn').addEventListener('click', closeFlightModal);
  $('flightForm').addEventListener('submit', saveFlight);
  $('flightModal').addEventListener('click', (e) => {
    if (e.target === $('flightModal')) closeFlightModal();
  });

  // Neu con token + khoa ky trong phien thi vao thang dashboard
  let savedToken = null, savedKey = null;
  try {
    savedToken = sessionStorage.getItem('adminToken');
    savedKey = sessionStorage.getItem('adminSigningKey');
  } catch { /* bo qua */ }
  if (savedToken && savedKey) {
    setAdminCreds(savedToken, savedKey);
    showDashboard();
  }
});
