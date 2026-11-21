# QGEN POS Demo

**Developer:** OxSugX

Demo publik QGEN POS — aplikasi kasir digital berbasis web yang dikembangkan oleh OxSugX.

## Tentang Demo

Versi ini dibuat untuk memperlihatkan tampilan dan pengalaman penggunaan QGEN POS tanpa perlu membuat akun atau login.

- Dashboard dengan tampilan responsif
- Ringkasan pemasukan dan pengeluaran
- Riwayat transaksi contoh
- Grafik dengan data simulasi
- Tampilan Light dan Dark
- Fitur QRIS dan pendukung lainnya pada aplikasi utama

## Catatan Demo

- Tidak memerlukan login.
- Seluruh transaksi dan grafik menggunakan data contoh.
- Demo bersifat hanya untuk dilihat.
- Penambahan, pengubahan, dan penghapusan data dinonaktifkan.
- Tidak terhubung ke payment gateway atau sistem pembayaran sungguhan.
- Jangan gunakan demo ini untuk mencatat transaksi atau menyimpan data keuangan nyata.

## Teknologi

- Python
- Flask
- HTML, CSS, dan JavaScript
- SQLite untuk aplikasi lokal

## Menjalankan Demo Secara Lokal

Pasang dependensi:

```bash
pip install -r requirements.txt
```

Jalankan dalam mode demo:

```bash
QGEN_DEMO=1 python app.py
```

Buka browser:

`http://127.0.0.1:5000`

Developer: [OxSugX](https://github.com/OxSugX)
