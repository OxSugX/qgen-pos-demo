const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const csrf = () => $('meta[name="csrf-token"]')?.content || '';
const toast = (message) => {
  const el = $('.toast'); if (!el) return;
  el.textContent = message; el.classList.add('show');
  clearTimeout(window.__toastTimer); window.__toastTimer = setTimeout(()=>el.classList.remove('show'), 2600);
};
async function api(url, options={}) {
  const headers = {'X-CSRF-Token': csrf(), ...(options.headers || {})};
  if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const response = await fetch(url, {...options, headers});
  let data = {};
  try { data = await response.json(); } catch {}
  if (!response.ok || data.ok === false) throw new Error(data.error || 'Permintaan gagal.');
  return data;
}
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('qgen-theme', theme);
  const select = $('#theme-select'); if (select) select.value = theme;
}
function initTheme() {
  const saved = localStorage.getItem('qgen-theme') || 'system';
  setTheme(saved);
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  media.addEventListener?.('change', () => {
    if ((localStorage.getItem('qgen-theme') || 'system') === 'system') document.documentElement.dataset.theme = 'system';
  });
}
initTheme();
$('[data-theme-toggle]')?.addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme === 'dark' ||
    (document.documentElement.dataset.theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  setTheme(dark ? 'light' : 'dark');
});
$('#theme-select')?.addEventListener('change', e => setTheme(e.target.value));
$('#today-label') && ($('#today-label').textContent = new Intl.DateTimeFormat('id-ID',{day:'numeric',month:'short',year:'numeric'}).format(new Date()));

$$('[data-open]').forEach(btn => btn.addEventListener('click', () => {
  const modal = $(`[data-modal="${btn.dataset.open}"]`); modal?.classList.add('visible');
}));
$$('[data-close]').forEach(btn => btn.addEventListener('click', () => btn.closest('.modal-backdrop')?.classList.remove('visible')));
$$('.modal-backdrop').forEach(backdrop => backdrop.addEventListener('click', e => {
  if (e.target === backdrop) backdrop.classList.remove('visible');
}));
$$('[data-transaction]').forEach(form => form.addEventListener('submit', async e => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(form));
  data.type = form.dataset.transaction;
  data.amount = Number(data.amount);
  data.method ||= 'cash';
  try {
    await api('/api/transactions', {method:'POST', body:JSON.stringify(data)});
    toast('Transaksi tersimpan.'); setTimeout(()=>location.reload(), 450);
  } catch(err) { toast(err.message); }
}));
$('#save-profile')?.addEventListener('click', async () => {
  try {
    await api('/api/profile',{method:'POST',body:JSON.stringify({store_name:$('#store-name').value})});
    toast('Nama toko diperbarui.'); setTimeout(()=>location.reload(),500);
  } catch(e) { toast(e.message); }
});
$('#change-pin')?.addEventListener('click', async () => {
  try {
    await api('/api/change-pin',{method:'POST',body:JSON.stringify({old_pin:$('#old-pin').value,new_pin:$('#new-pin').value})});
    $('#old-pin').value=''; $('#new-pin').value=''; toast('PIN berhasil diganti.');
  } catch(e) { toast(e.message); }
});
$('#save-qris')?.addEventListener('click', async () => {
  try {
    await api('/api/qris/static',{method:'POST',body:JSON.stringify({payload:$('#qris-payload').value})});
    toast('QRIS statis tersimpan.');
  } catch(e) { toast(e.message); }
});
$('#make-qris')?.addEventListener('click', async () => {
  const amount = Number($('#qris-amount').value);
  const result = $('#qris-result');
  try {
    result.hidden = false; result.innerHTML = '<p class="muted">Membuat QRIS…</p>';
    const data = await api('/api/qris',{method:'POST',body:JSON.stringify({amount})});
    result.innerHTML = `<img class="generated-qr" src="/qr/${encodeURIComponent(data.token)}.png" alt="QRIS tagihan"><b>Rp ${new Intl.NumberFormat('id-ID').format(data.amount)}</b><p class="tiny muted">QR ini adalah permintaan pembayaran. Periksa pembayaran melalui kanal merchant sebelum mencatat transaksi sebagai lunas.</p>`;
  } catch(e) { result.hidden=false; result.textContent=e.message; }
});
$$('[data-copy]').forEach(btn=>btn.addEventListener('click',async()=>{
  const el=$(btn.dataset.copy); try { await navigator.clipboard.writeText(el.textContent.trim()); toast('Recovery Key disalin.'); } catch { toast('Tidak dapat menyalin otomatis.'); }
}));
if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
  window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));
}
