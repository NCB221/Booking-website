let currentFlight = null;
let currentPax = 1;

const $ = (id) => document.getElementById(id);

async function loadAirports() {
  try {
    const airports = await api('/api/airports');
    const opts = airports
      .map((a) => `<option value="${esc(a.code)}">${esc(a.city)} (${esc(a.code)})</option>`)
      .join('');
    $('from').insertAdjacentHTML('beforeend', opts);
    $('to').insertAdjacentHTML('beforeend', opts);
  } catch (e) { toast(e.message, 'err'); }
}

function flightCard(f) {
  const low = f.available_seats <= 10;
  return `
    <div class="flight">
      <div class="flight-main">
        <div class="flight-top">
          <span class="airline-badge">${esc(f.airline)}</span>
          <span class="flight-no">${esc(f.flight_number)} &middot; ${dateLabel(f.departure_time)}</span>
        </div>
        <div class="route">
          <div class="point">
            <div class="time">${hhmm(f.departure_time)}</div>
            <div class="airport">${esc(f.from_city)} (${esc(f.from_airport)})</div>
          </div>
          <div class="arrow">&#8594;</div>
          <div class="point">
            <div class="time">${hhmm(f.arrival_time)}</div>
            <div class="airport">${esc(f.to_city)} (${esc(f.to_airport)})</div>
          </div>
          <div class="duration">&#128336; ${duration(f.departure_time, f.arrival_time)}</div>
        </div>
      </div>
      <div class="flight-side">
        <div class="price">${money(f.price)}</div>
        <div class="seats-left ${low ? 'low' : ''}">Con ${f.available_seats} ghe</div>
        <button class="btn btn-primary btn-sm" data-id="${f.id}">Dat ve</button>
      </div>
    </div>`;
}

async function search(params = {}) {
  const box = $('results');
  box.innerHTML = '<div class="loading">Dang tim chuyen bay...</div>';
  const qs = new URLSearchParams();
  if (params.from) qs.set('from', params.from);
  if (params.to) qs.set('to', params.to);
  if (params.date) qs.set('date', params.date);
  if (params.passengers) qs.set('passengers', params.passengers);
  currentPax = parseInt(params.passengers, 10) || 1;

  try {
    const flights = await api('/api/flights?' + qs.toString());
    $('resultsCount').textContent = `${flights.length} chuyen bay`;
    if (flights.length === 0) {
      box.innerHTML = '<div class="empty">Khong tim thay chuyen bay phu hop. Thu doi ngay hoac diem den.</div>';
      return;
    }
    box.innerHTML = flights.map(flightCard).join('');
    box.querySelectorAll('button[data-id]').forEach(btn => {
      btn.addEventListener('click', () => openBooking(btn.dataset.id, flights));
    });
  } catch (e) {
    box.innerHTML = `<div class="empty">Loi tai du lieu: ${esc(e.message)}</div>`;
  }
}

function openBooking(id, flights) {
  currentFlight = flights.find(f => String(f.id) === String(id));
  if (!currentFlight) return;
  const seats = Math.min(currentPax, currentFlight.available_seats);
  currentPax = seats;
  const total = Number(currentFlight.price) * seats;
  $('bookSummary').innerHTML = `
    <div class="row"><span>Chuyen bay</span><strong>${esc(currentFlight.flight_number)} - ${esc(currentFlight.airline)}</strong></div>
    <div class="row"><span>Chang</span><strong>${esc(currentFlight.from_city)} &#8594; ${esc(currentFlight.to_city)}</strong></div>
    <div class="row"><span>Khoi hanh</span><strong>${dateLabel(currentFlight.departure_time)} ${hhmm(currentFlight.departure_time)}</strong></div>
    <div class="row"><span>So khach</span><strong>${seats}</strong></div>
    <div class="row total"><span>Tong tien</span><span>${money(total)}</span></div>`;
  $('bookModal').classList.add('show');
}

function closeBooking() {
  $('bookModal').classList.remove('show');
  $('bookForm').reset();
}

async function submitBooking(e) {
  e.preventDefault();
  if (!currentFlight) return;
  const btn = $('bookSubmit');
  btn.disabled = true; btn.textContent = 'Dang xu ly...';
  try {
    const res = await api('/api/bookings', {
      method: 'POST',
      body: JSON.stringify({
        flight_id: currentFlight.id,
        passenger_name: $('pname').value,
        passenger_email: $('pemail').value,
        passenger_phone: $('pphone').value,
        passenger_cccd: $('pcccd').value,
        seat_count: currentPax,
      }),
    });
    closeBooking();
    toast(`Dat ve thanh cong! Ma ve: ${res.booking_code}`, 'ok');
    setTimeout(() => {
      if (confirm(`Dat ve thanh cong!\nMa ve cua ban: ${res.booking_code}\n\nHay luu lai ma ve nay. De tra cuu ve, ban can ma ve VA email vua dung de dat.\n\nXem chi tiet ve ngay bay gio?`)) {
        location.href = `/my-bookings.html?code=${encodeURIComponent(res.booking_code)}`;
      } else {
        // refresh ket qua de cap nhat so ghe
        document.getElementById('searchForm').dispatchEvent(new Event('submit'));
      }
    }, 300);
  } catch (err) {
    toast(err.message, 'err');
  } finally {
    btn.disabled = false; btn.textContent = 'Xac nhan dat';
  }
}

// Khoi tao
document.addEventListener('DOMContentLoaded', () => {
  $('date').min = todayStr();
  loadAirports();
  search({}); // hien chuyen bay goi y

  $('searchForm').addEventListener('submit', (e) => {
    e.preventDefault();
    search({
      from: $('from').value,
      to: $('to').value,
      date: $('date').value,
      passengers: $('passengers').value,
    });
    $('resultsTitle').textContent = 'Ket qua tim kiem';
  });

  $('bookCancel').addEventListener('click', closeBooking);
  $('bookForm').addEventListener('submit', submitBooking);
  $('bookModal').addEventListener('click', (e) => {
    if (e.target === $('bookModal')) closeBooking();
  });
});
