# ============================================================
# QGEN v4 FINAL — Kasir, QRIS, Grafik, Struk (dengan Qty)
# Siap Produksi - Copy & Paste
# ============================================================
from flask import (Flask, request, render_template_string, send_file,
                   abort, jsonify, redirect, url_for, session, flash, Response)
import qrcode
from PIL import Image, ImageDraw, ImageFont
import io, uuid, sqlite3, os, random, secrets

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None
    np = None
import hashlib, hmac, json, csv, threading, time, re
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import closing

# ---------------- APP CONFIG ----------------
app = Flask(__name__)
_secret = os.environ.get("QGEN_SECRET_KEY")
if not _secret:
    _secret = "dev-only-insecure-key-" + secrets.token_hex(8)
    print("⚠️  WARNING: Set QGEN_SECRET_KEY env var untuk production.")
app.secret_key = _secret
app.config.update(
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("QGEN_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

DB_PATH = (
    (
        Path("/tmp/qgen-demo.db")
        if os.environ.get("VERCEL") == "1"
        else Path(__file__).parent / "instance" / "qgen-demo.db"
    )
    if os.environ.get("QGEN_DEMO") == "1"
    else Path(__file__).parent / "qgen.db"
)
QR_STORE: dict = {}
QR_TTL_MINUTES = 5
QR_STATIC_TTL_HOURS = 24

# ---------------- DATABASE ----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(get_db()) as conn:
        conn.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                pin_hash TEXT,
                recovery_key TEXT UNIQUE,
                device_id TEXT,
                otp_code TEXT,
                otp_expires_at TIMESTAMP,
                qris_static TEXT DEFAULT '',
                store_name TEXT DEFAULT 'Toko Saya'
            );
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                type TEXT,
                method TEXT,
                title TEXT,
                amount INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_ledger_user_date ON ledger(user_id, created_at);
        """)
        for statement in (
            "ALTER TABLE users ADD COLUMN otp_expires_at TIMESTAMP",
            "ALTER TABLE ledger ADD COLUMN items_json TEXT NOT NULL DEFAULT '[]'",
        ):
            try:
                conn.execute(statement)
            except sqlite3.OperationalError:
                pass
        conn.commit()

init_db()

# ---------------- AUTH HELPERS ----------------
def hash_pin(pin: str) -> str:
    return hashlib.sha256(("qgen-v1:" + pin).encode()).hexdigest()

def verify_pin(stored: str, pin: str) -> bool:
    return hmac.compare_digest(stored or "", hash_pin(pin))

def get_device_id() -> str:
    return request.cookies.get("qgen_device", "")

# ---------------- QRIS LOGIC ----------------
def parse_tlv(data: str) -> dict:
    res, i = {}, 0
    while i + 4 <= len(data):
        tag = data[i:i+2]
        try:
            length = int(data[i+2:i+4])
        except ValueError:
            break
        if i + 4 + length > len(data):
            break
        res[tag] = data[i+4:i+4+length]
        i += 4 + length
    return res

def tlv(tag: str, value: str) -> str:
    if len(value) > 99:
        raise ValueError(f"TLV value tag {tag} exceeds 99 chars")
    return f"{tag}{len(value):02d}{value}"

def crc16(data: str) -> str:
    crc = 0xFFFF
    for b in data.encode("utf-8"):
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"

def build_qris(static_payload: str, amount: int, bill_no: str = "") -> str:
    body = static_payload.strip()
    idx58 = body.find("5802ID")
    if idx58 == -1:
        raise ValueError("Payload bukan QRIS Indonesia yang valid.")

    head, tail = body[:idx58], body[idx58:]

    i53 = head.rfind("5303360")
    if i53 != -1:
        after53 = head[i53 + len("5303360"):]
        if after53.startswith("54"):
            try:
                ln = int(after53[2:4])
                head = head[:i53 + len("5303360")] + after53[4 + ln:]
            except ValueError:
                pass

    i63 = tail.find("6304")
    before_crc = tail[:i63] if i63 != -1 else tail

    i = 0
    while i + 4 <= len(before_crc):
        tag = before_crc[i:i+2]
        try:
            length = int(before_crc[i+2:i+4])
        except ValueError:
            break
        if tag == "62":
            before_crc = before_crc[:i] + before_crc[i + 4 + length:]
            break
        i += 4 + length

    head = head + tlv("54", str(amount))
    if bill_no:
        before_crc = before_crc + tlv("62", tlv("01", bill_no))

    body = head + before_crc + "6304"
    return body + crc16(body)

def _load_font(size, bold=False):
    candidates = [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        ("/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
        ("/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf"),
        ("C:\\Windows\\Fonts\\arialbd.ttf" if bold else "C:\\Windows\\Fonts\\arial.ttf"),
        ("arialbd.ttf" if bold else "arial.ttf"),
    ]
    for f in candidates:
        try: return ImageFont.truetype(f, size)
        except (OSError, IOError): continue
    return ImageFont.load_default()

def make_qr_bytes(payload: str, amount: int = 0) -> bytes:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=12, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    if amount <= 0:
        buf = io.BytesIO()
        qr_img.save(buf, format="PNG")
        return buf.getvalue()

    qr_w, qr_h = qr_img.size
    pad_x, pad_y, label_h = 24, 20, 100
    canvas = Image.new("RGB", (qr_w + pad_x * 2, qr_h + label_h + pad_y * 2), "white")
    canvas.paste(qr_img, (pad_x, pad_y + label_h))
    draw = ImageDraw.Draw(canvas)

    font_label = _load_font(22, False)
    font_price = _load_font(42, True)

    lbl = "TOTAL TAGIHAN"
    b = draw.textbbox((0, 0), lbl, font=font_label)
    draw.text(((canvas.width - (b[2]-b[0]))//2, pad_y), lbl, fill=(110,110,110), font=font_label)

    price = f"Rp {amount:,}".replace(",", ".")
    b = draw.textbbox((0, 0), price, font=font_price)
    draw.text(((canvas.width - (b[2]-b[0]))//2, pad_y + 30), price, fill=(15,15,15), font=font_price)
    draw.line([(pad_x, pad_y+label_h-8), (canvas.width-pad_x, pad_y+label_h-8)], fill=(220,220,220), width=1)

    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    return buf.getvalue()

def _truncate(text, max_width, font, draw):
    if draw.textlength(text, font=font) <= max_width:
        return text
    ell = "..."
    while text and draw.textlength(text + ell, font=font) > max_width:
        text = text[:-1]
    return text + ell

def _receipt_items(row):
    try:
        saved = json.loads(row["items_json"] or "[]")
    except (ValueError, TypeError, KeyError):
        saved = []
    if saved:
        return saved
    # Backward compatibility for transactions created before itemized receipts.
    title = str(row["title"] or "Transaksi")
    match = re.search(r"\s*[xX]\s*(\d+)$", title)
    qty = int(match.group(1)) if match else 1
    name = title[:match.start()].strip() if match else title
    amount = int(row["amount"] or 0)
    return [{"name": name or "Barang", "qty": qty,
             "price": amount // qty if qty and amount % qty == 0 else amount,
             "subtotal": amount}]

def make_receipt_bytes(row):
    W, PAD = 480, 22
    items = _receipt_items(row)
    dt = row["created_at"]
    if isinstance(dt, str):
        try: dt = datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
        except ValueError: dt = datetime.now()
    store_name = (row["store_name"] or "TOKO SAYA").upper()
    tx_no = f"QGN-{row['id']:06d}"
    date_str = dt.strftime("%d/%m/%Y %H:%M")
    method_map = {"cash":"TUNAI", "debt":"UTANG / BON", "qris":"QRIS"}
    method = method_map.get(row["method"], str(row["method"] or "-").upper())
    total_amount = int(row["amount"] or 0)
    F_HEAD = _load_font(25, True)
    F_BODY = _load_font(15)
    F_SMALL = _load_font(13)
    F_BOLD = _load_font(15, True)
    F_TOTAL = _load_font(21, True)
    F_FOOT = _load_font(16, True)

    # Measure height based on item count and wrapped item names.
    probe = Image.new("RGB", (W, 10), "white")
    probe_draw = ImageDraw.Draw(probe)
    wrapped = []
    for item in items:
        name = str(item.get("name") or "Barang")[:100]
        words, lines, line = name.split(), [], ""
        for word in words:
            test = (line + " " + word).strip()
            if probe_draw.textlength(test, font=F_BODY) <= 265:
                line = test
            else:
                if line: lines.append(line)
                line = word
        if line: lines.append(line)
        wrapped.append((item, lines or [name]))
    H = 210 + sum(max(1, len(lines))*23 + 38 for _, lines in wrapped) + 110
    img = Image.new("RGB", (W, H), "white")
    draw = ImageDraw.Draw(img)
    y = 22
    def centered(text, font, fill=(20, 25, 35)):
        nonlocal y
        b = draw.textbbox((0,0), text, font=font)
        draw.text(((W-(b[2]-b[0]))//2, y), text, font=font, fill=fill)
        y += b[3]-b[1]+8
    def rule():
        nonlocal y
        draw.line((PAD, y, W-PAD, y), fill=(190,195,205), width=1)
        y += 14
    centered(store_name, F_HEAD)
    centered("STRUK PEMBELIAN", F_BOLD, (80,90,105))
    rule()
    for label, value in (("No. Transaksi", tx_no), ("Tanggal", date_str), ("Pembayaran", method)):
        draw.text((PAD, y), label, font=F_SMALL, fill=(105,112,125))
        b = draw.textbbox((0,0), value, font=F_SMALL)
        draw.text((W-PAD-(b[2]-b[0]), y), value, font=F_SMALL, fill=(25,30,40))
        y += 25
    rule()
    draw.text((PAD, y), "BARANG", font=F_SMALL, fill=(100,108,120))
    draw.text((W-175, y), "QTY", font=F_SMALL, fill=(100,108,120))
    b = draw.textbbox((0,0), "SUBTOTAL", font=F_SMALL)
    draw.text((W-PAD-(b[2]-b[0]), y), "SUBTOTAL", font=F_SMALL, fill=(100,108,120))
    y += 26
    for item, lines in wrapped:
        for line in lines:
            draw.text((PAD, y), line, font=F_BODY, fill=(25,30,40)); y += 22
        qty = int(item.get("qty", 1))
        price = int(item.get("price", 0))
        subtotal = int(item.get("subtotal", qty*price))
        draw.text((PAD, y), f"@ Rp {price:,}".replace(",", "."), font=F_SMALL, fill=(105,112,125))
        draw.text((W-175, y), str(qty), font=F_BODY, fill=(25,30,40))
        val = f"Rp {subtotal:,}".replace(",", ".")
        b = draw.textbbox((0,0), val, font=F_BODY)
        draw.text((W-PAD-(b[2]-b[0]), y), val, font=F_BODY, fill=(25,30,40))
        y += 29
    rule()
    draw.text((PAD, y), "TOTAL", font=F_TOTAL, fill=(15,20,30))
    val = f"Rp {total_amount:,}".replace(",", ".")
    b = draw.textbbox((0,0), val, font=F_TOTAL)
    draw.text((W-PAD-(b[2]-b[0]), y), val, font=F_TOTAL, fill=(15,20,30))
    y += 40
    rule()
    centered("Terima kasih sudah berbelanja!", F_FOOT)
    centered("Simpan struk ini sebagai bukti transaksi.", F_SMALL, (105,112,125))
    img = img.crop((0, 0, W, y+18))
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()

def cleanup_qr():
    now = datetime.now()
    for k in [k for k, v in QR_STORE.items() if now > v["expires_at"]]:
        QR_STORE.pop(k, None)

def _bg_cleanup():
    while True:
        time.sleep(300)
        try: cleanup_qr()
        except Exception: pass

threading.Thread(target=_bg_cleanup, daemon=True).start()

def _csv_safe(v) -> str:
    s = str(v)
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

def _fmt(n):
    return f"{n:,}".replace(",", ".")

# ---------------- AFTER REQUEST ----------------
@app.after_request
def _after(resp):
    if not request.cookies.get("qgen_device"):
        resp.set_cookie("qgen_device", uuid.uuid4().hex[:16], max_age=63072000, httponly=True, samesite="Lax")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

# ---------------- TEMPLATES ----------------
BASE_STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
:root{
  --bg:#f9fafb;--card:#fff;--fg:#0f172a;--muted:#64748b;--border:#e5e7eb;
  --primary:#4f46e5;--primary-soft:#eef2ff;--primary-hover:#4338ca;
  --danger:#dc2626;--danger-soft:#fef2f2;
  --ok:#059669;--ok-soft:#ecfdf5;
  --warn:#d97706;--warn-soft:#fffbeb;
  --input-bg:#f3f4f6;--dash:#cbd5e1;
  --shadow-sm:0 1px 2px rgba(0,0,0,.04);
  --shadow:0 4px 12px -4px rgba(15,23,42,.08);
}
[data-theme="dark"]{
  --bg:#0b1120;--card:#1a2332;--fg:#f1f5f9;--muted:#94a3b8;--border:#2d3b4f;
  --primary:#818cf8;--primary-soft:#1e293b;--primary-hover:#a5b4fc;
  --danger:#f87171;--danger-soft:#450a0a;
  --ok:#34d399;--ok-soft:#022c22;
  --warn:#fbbf24;--warn-soft:#3f2a0a;
  --input-bg:#0f172a;--dash:#475569;
  --shadow-sm:0 1px 2px rgba(0,0,0,.3);
  --shadow:0 4px 12px -4px rgba(0,0,0,.4);
}
*{box-sizing:border-box;margin:0;padding:0;font-family:'Plus Jakarta Sans',-apple-system,sans-serif;-webkit-tap-highlight-color:transparent;}
body{background:var(--bg);color:var(--fg);min-height:100vh;transition:background .2s,color .2s;line-height:1.5;}
button{font-family:inherit;cursor:pointer;border:none;background:none;color:inherit;}
input,textarea,select{font-family:inherit;}
svg{display:block;}

.header{background:var(--primary);color:#fff;padding:calc(20px + env(safe-area-inset-top)) 20px 32px;
  border-bottom-left-radius:24px;border-bottom-right-radius:24px;
  display:flex;justify-content:space-between;align-items:center;
  box-shadow:0 4px 20px -8px rgba(0,0,0,.15);position:relative;}
.brand{display:flex;align-items:center;gap:10px;min-width:0;}
.brand-logo{width:36px;height:36px;border-radius:10px;background:rgba(255,255,255,.18);
  display:flex;align-items:center;justify-content:center;backdrop-filter:blur(8px);flex-shrink:0;}
.brand-logo svg{width:20px;height:20px;stroke:#fff;stroke-width:2.2;fill:none;}
.brand-name{font-size:15px;font-weight:700;letter-spacing:-.01em;line-height:1.15;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px;}
.brand-sub{font-size:10px;font-weight:600;opacity:.75;letter-spacing:.06em;margin-top:1px;}
.header-icons{display:flex;gap:8px;flex-shrink:0;}
.icon-btn{width:38px;height:38px;border-radius:10px;background:rgba(255,255,255,.15);
  display:flex;align-items:center;justify-content:center;transition:background .15s;}
.icon-btn:active{background:rgba(255,255,255,.3);}
.icon-btn svg{width:18px;height:18px;stroke:#fff;stroke-width:2;fill:none;}

.container{padding:0 16px;max-width:560px;margin:-16px auto 0;}
.greeting{font-size:13px;font-weight:500;color:var(--muted);margin-bottom:12px;padding-left:4px;}

.card{background:var(--card);border-radius:16px;padding:18px;border:1px solid var(--border);
  box-shadow:var(--shadow-sm);margin-bottom:14px;}

.saldo-card{position:relative;overflow:hidden;}
.saldo-label{font-size:12px;font-weight:600;color:var(--muted);margin-bottom:4px;letter-spacing:.02em;text-transform:uppercase;}
.saldo-val{font-size:30px;font-weight:800;color:var(--fg);margin-bottom:16px;letter-spacing:-.03em;line-height:1.1;font-variant-numeric:tabular-nums;}
.saldo-row{display:flex;justify-content:space-between;border-top:1px solid var(--border);padding-top:14px;gap:12px;}
.saldo-col{flex:1;}
.saldo-col p:first-child{font-size:11px;color:var(--muted);font-weight:600;margin-bottom:2px;letter-spacing:.02em;text-transform:uppercase;}
.saldo-col p:last-child{font-size:15px;font-weight:700;font-variant-numeric:tabular-nums;}
.saldo-col.income p:last-child{color:var(--ok);}
.saldo-col.expense p:last-child{color:var(--danger);text-align:right;}
.saldo-col.expense{text-align:right;}

.menu-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px;}
.menu-item{background:var(--card);border-radius:14px;padding:16px 8px 12px;border:1px solid var(--border);
  text-align:center;cursor:pointer;transition:transform .1s,background .15s;box-shadow:var(--shadow-sm);}
.menu-item:active{transform:scale(.96);background:var(--input-bg);}
.menu-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;
  margin:0 auto 10px;background:var(--primary-soft);color:var(--primary);}
.menu-icon svg{width:22px;height:22px;stroke:currentColor;stroke-width:2;fill:none;stroke-linecap:round;stroke-linejoin:round;}
.menu-icon.income{background:var(--ok-soft);color:var(--ok);}
.menu-icon.expense{background:var(--danger-soft);color:var(--danger);}
.menu-icon.warn{background:var(--warn-soft);color:var(--warn);}
.menu-text{font-size:12px;font-weight:600;color:var(--fg);line-height:1.25;}

.section-title{font-size:15px;font-weight:700;margin:4px 0 10px;display:flex;justify-content:space-between;align-items:center;}
.section-link{font-size:12px;font-weight:600;color:var(--primary);text-decoration:none;}

.history-list{background:var(--card);border-radius:14px;border:1px solid var(--border);box-shadow:var(--shadow-sm);overflow:hidden;margin-bottom:16px;}
.history-item{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;
  border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;gap:12px;}
.history-item:last-child{border-bottom:none;}
.history-item:active{background:var(--input-bg);}
.history-info{flex:1;min-width:0;}
.history-title{font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.history-meta{font-size:11px;color:var(--muted);margin-top:2px;}
.history-amount{font-size:14px;font-weight:700;white-space:nowrap;font-variant-numeric:tabular-nums;}
.history-amount.income{color:var(--ok);}
.history-amount.expense{color:var(--danger);}

.empty-state{text-align:center;padding:32px 20px;background:var(--card);
  border-radius:14px;border:1px dashed var(--border);margin-bottom:16px;}
.empty-state svg{width:32px;height:32px;stroke:var(--muted);stroke-width:1.5;fill:none;margin:0 auto 10px;opacity:.6;}
.empty-title{font-size:14px;font-weight:600;margin-bottom:4px;}
.empty-sub{font-size:12px;color:var(--muted);margin-bottom:14px;}

.btn-primary{width:100%;padding:14px;background:var(--primary);color:#fff;border-radius:12px;
  font-size:14px;font-weight:700;margin-top:10px;transition:opacity .15s;display:flex;align-items:center;justify-content:center;gap:6px;}
.btn-primary:active{opacity:.85;}
.btn-primary:disabled{opacity:.6;cursor:not-allowed;}
.btn-primary.success{background:var(--ok);}
.btn-primary.danger{background:var(--danger);}
.btn-ghost{width:100%;padding:14px;background:var(--input-bg);color:var(--fg);border-radius:12px;
  font-size:14px;font-weight:600;margin-top:8px;display:flex;align-items:center;justify-content:center;gap:6px;}
.btn-ghost:active{opacity:.8;}

.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;
  border-radius:50%;animation:spin .6s linear infinite;display:inline-block;}
@keyframes spin{to{transform:rotate(360deg);}}

.modal-overlay{position:fixed;inset:0;background:rgba(15,23,42,.5);display:none;align-items:flex-end;
  z-index:50;backdrop-filter:blur(4px);opacity:0;transition:opacity .2s;}
.modal-overlay.active{display:flex;opacity:1;}
.modal{background:var(--card);width:100%;border-top-left-radius:24px;border-top-right-radius:24px;
  padding:8px 20px calc(20px + env(safe-area-inset-bottom));max-height:88vh;overflow-y:auto;
  transform:translateY(20px);transition:transform .25s cubic-bezier(.4,0,.2,1);}
.modal-overlay.active .modal{transform:translateY(0);}
.modal-handle{width:36px;height:4px;background:var(--dash);border-radius:2px;margin:0 auto 16px;}
.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;}
.modal-header h2{font-size:18px;font-weight:700;letter-spacing:-.01em;}
.modal-close{background:var(--input-bg);width:32px;height:32px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;color:var(--muted);}
.modal-close svg{width:16px;height:16px;stroke:currentColor;stroke-width:2.2;fill:none;}

.label{font-size:12px;font-weight:600;color:var(--muted);margin-bottom:6px;display:block;
  text-transform:uppercase;letter-spacing:.03em;}
.field{border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:14px;
  background:var(--input-bg);transition:border-color .15s,background .15s;}
.field:focus-within{border-color:var(--primary);background:var(--card);}
.field input,.field textarea,.field select{width:100%;background:transparent;border:none;
  font-size:15px;font-weight:600;color:var(--fg);outline:none;}
.field input::placeholder,.field textarea::placeholder{color:var(--muted);font-weight:500;}
.field input[type=number]{font-size:22px;font-weight:800;color:var(--primary);text-align:center;}
.field textarea{resize:none;height:60px;font-family:ui-monospace,monospace;font-size:12px;font-weight:500;text-align:left;}
.field select{cursor:pointer;}
.field.center{text-align:center;}

.auth-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;
  min-height:100vh;padding:20px;}
.auth-card{background:var(--card);padding:28px 24px;border-radius:20px;
  box-shadow:var(--shadow);width:100%;max-width:400px;border:1px solid var(--border);}
.auth-card h2{text-align:center;font-size:22px;font-weight:800;margin-bottom:6px;letter-spacing:-.02em;}
.auth-sub{text-align:center;font-size:13px;color:var(--muted);margin-bottom:20px;}
.auth-card input{width:100%;padding:14px;margin:6px 0;border:1px solid var(--border);
  border-radius:12px;font-size:15px;background:var(--input-bg);color:var(--fg);outline:none;font-weight:500;transition:border-color .15s;}
.auth-card input:focus{border-color:var(--primary);background:var(--card);}
.auth-link{display:block;text-align:center;margin-top:16px;color:var(--primary);
  text-decoration:none;font-size:13px;font-weight:600;}
.auth-link.muted{color:var(--muted);margin-top:8px;}

.flash{padding:12px 14px;border-radius:10px;margin-bottom:14px;text-align:center;
  font-size:13px;font-weight:600;}
.flash-error{background:var(--danger-soft);color:var(--danger);}
.flash-success{background:var(--ok-soft);color:var(--ok);}

.key-box{background:var(--input-bg);border:2px dashed var(--primary);padding:14px;border-radius:10px;
  font-family:ui-monospace,monospace;font-size:12px;word-break:break-all;margin:14px 0;
  color:var(--fg);font-weight:600;line-height:1.5;text-align:center;}

.toast{position:fixed;bottom:calc(24px + env(safe-area-inset-bottom));left:50%;
  transform:translateX(-50%) translateY(100px);background:var(--fg);color:var(--bg);
  padding:12px 18px;border-radius:12px;font-size:13px;font-weight:600;z-index:9999;
  opacity:0;transition:all .3s cubic-bezier(.4,0,.2,1);pointer-events:none;
  box-shadow:0 10px 30px -5px rgba(0,0,0,.3);max-width:90vw;text-align:center;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
.toast-success{background:var(--ok);color:#fff;}
.toast-error{background:var(--danger);color:#fff;}

.footer{text-align:center;padding:20px 16px;font-size:11px;color:var(--muted);line-height:1.6;}

.setting-item{display:flex;justify-content:space-between;align-items:center;padding:14px 0;
  border-bottom:1px solid var(--border);cursor:pointer;}
.setting-item:last-child{border-bottom:none;}
.setting-item span:first-child{font-size:14px;font-weight:600;}
.setting-item span:last-child{font-size:13px;color:var(--muted);}

/* Chart */
.chart-tabs{display:flex;gap:4px;margin-bottom:14px;background:var(--input-bg);padding:4px;border-radius:10px;}
.chart-tabs button{flex:1;padding:9px 4px;font-size:11px;font-weight:600;color:var(--muted);border-radius:7px;transition:all .15s;}
.chart-tabs button.active{background:var(--card);color:var(--fg);box-shadow:var(--shadow-sm);}
.chart-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:12px;}
.chart-summary-item{background:var(--input-bg);padding:10px 6px;border-radius:10px;text-align:center;}
.chart-summary-label{display:block;font-size:9px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-bottom:3px;}
.chart-summary-val{display:block;font-size:11px;font-weight:700;color:var(--fg);font-variant-numeric:tabular-nums;line-height:1.3;word-break:break-word;}
.chart-detail{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:var(--primary-soft);border-radius:8px;margin-bottom:10px;font-size:12px;}
.chart-detail #detail-label{color:var(--muted);font-weight:600;}
.chart-detail #detail-value{color:var(--primary);font-weight:800;font-variant-numeric:tabular-nums;}
.chart-wrap{height:180px;padding:0 2px;margin-bottom:4px;}
.chart-bars{display:flex;align-items:flex-end;gap:2px;height:100%;}
.chart-bar{flex:1;border-radius:3px 3px 0 0;background:var(--ok);min-height:2px;transition:opacity .15s;cursor:pointer;}
.chart-bar:hover,.chart-bar:active{opacity:.7;}
.chart-bar.empty{background:var(--dash);opacity:.3;}
.chart-labels{display:flex;gap:2px;padding:0 2px;font-size:9px;color:var(--muted);font-weight:600;margin-bottom:6px;}
.chart-label{flex:1;text-align:center;overflow:hidden;white-space:nowrap;}

/* Receipt */
.receipt-wrap{background:var(--input-bg);border-radius:12px;padding:14px;margin-bottom:14px;text-align:center;}
.receipt-img{max-width:280px;width:100%;border-radius:6px;display:block;margin:0 auto;background:#fff;}
.receipt-actions{display:flex;flex-direction:column;gap:8px;}
.receipt-actions .btn-primary{margin-top:0;}
</style>
<script>
function toggleTheme(){
  const r=document.documentElement;
  const n=(r.getAttribute('data-theme')==='dark')?'light':'dark';
  r.setAttribute('data-theme',n);localStorage.setItem('theme',n);
}
document.addEventListener("DOMContentLoaded",()=>{
  const r=document.documentElement;
  if(localStorage.getItem('theme'))r.setAttribute('data-theme',localStorage.getItem('theme'));
  else if(window.matchMedia('(prefers-color-scheme: dark)').matches)r.setAttribute('data-theme','dark');
});
</script>
"""

AUTH_TEMPLATE = BASE_STYLE + """
<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#4f46e5"><title>Qgen</title></head>
<body>
<div class="auth-wrap">
  <div class="auth-card">
    <div style="text-align:center;margin-bottom:20px;">
      <div style="width:52px;height:52px;border-radius:14px;background:var(--primary);
        display:inline-flex;align-items:center;justify-content:center;margin-bottom:12px;">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" style="width:26px;height:26px;">
          <rect x="3" y="3" width="7" height="7" rx="1.5"/>
          <rect x="14" y="3" width="7" height="7" rx="1.5"/>
          <rect x="3" y="14" width="7" height="7" rx="1.5"/>
          <path d="M14 14h3v3h-3z"/><path d="M20 14v3M17 20h4M20 20v.01"/>
        </svg>
      </div>
      <h2 style="text-align:center;font-size:20px;font-weight:800;letter-spacing:-.02em;">Qgen</h2>
      {% if store_name %}
      <p style="text-align:center;font-size:12px;color:var(--muted);margin-top:4px;">{{ store_name }}</p>
      {% endif %}
    </div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}{% for cat, msg in messages %}
        <div class="flash {{ 'flash-success' if cat == 'success' else 'flash-error' }}">{{ msg }}</div>
      {% endfor %}{% endif %}
    {% endwith %}
    {{ content|safe }}
  </div>
  <div class="footer">&copy; <span id="yr"></span> Qgen</div>
</div>
<script>document.getElementById('yr').textContent=new Date().getFullYear();</script>
</body></html>
"""

MAIN_TEMPLATE = BASE_STYLE + """
<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#4f46e5"><title>{{ store_name }} · Qgen</title></head>
<body>

<header class="header">
  <div class="brand">
    <div class="brand-logo">
      <svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="3" width="7" height="7" rx="1.5"/>
        <rect x="14" y="3" width="7" height="7" rx="1.5"/>
        <rect x="3" y="14" width="7" height="7" rx="1.5"/>
        <path d="M14 14h3v3h-3z"/><path d="M20 14v3M17 20h4M20 20v.01"/>
      </svg>
    </div>
    <div style="min-width:0;">
      <div class="brand-name">{{ store_name }}</div>
      <div class="brand-sub">QGEN</div>
    </div>
  </div>
  <div class="header-icons">
    <button class="icon-btn" onclick="openModal('modal-grafik')" aria-label="Grafik">
      <svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>
        <polyline points="17 6 23 6 23 12"/>
      </svg>
    </button>
    <button class="icon-btn" onclick="toggleTheme()" aria-label="Ganti tema">
      <svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
      </svg>
    </button>
  </div>
</header>

<div style="background:linear-gradient(135deg,#172554,#14532d);border:1px solid #25634a;border-radius:14px;padding:15px 17px;margin:0 0 18px;color:#fff;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:7px;">
    <span style="background:#22c55e;color:#052e16;padding:4px 9px;border-radius:6px;font-size:11px;font-weight:800;">DEMO</span>
    <strong style="font-size:14px;">QGEN POS V1.0</strong>
  </div>
  <p style="font-size:13px;line-height:1.6;margin:0 0 9px;color:#e2e8f0;">
    Ini adalah versi demonstrasi QGEN POS. Data transaksi dan grafik yang ditampilkan merupakan data contoh, bukan transaksi nyata.
  </p>
  <a href="https://github.com/OxSugX/qgen-pos" target="_blank" rel="noopener" style="color:#86efac;font-size:12px;font-weight:700;text-decoration:none;">
    Dikembangkan oleh OxSugX · Lihat GitHub →
  </a>
</div>
<div class="container">
  <p class="greeting">Selamat datang kembali 👋</p>

  <div class="card saldo-card">
    <p class="saldo-label">Laba Bersih Hari Ini</p>
    <p class="saldo-val">Rp {{ kas_bersih }}</p>
    <div class="saldo-row">
      <div class="saldo-col income">
        <p>Pemasukan</p><p>+ Rp {{ pemasukan }}</p>
      </div>
      <div class="saldo-col expense">
        <p>Pengeluaran</p><p>− Rp {{ pengeluaran }}</p>
      </div>
    </div>
  </div>

  <div class="menu-grid">
    <button class="menu-item" onclick="openModal('modal-jual')">
      <div class="menu-icon income"><svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg></div>
      <div class="menu-text">Penjualan</div>
    </button>
    <button class="menu-item" onclick="openModal('modal-beli')">
      <div class="menu-icon expense"><svg viewBox="0 0 24 24"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/></svg></div>
      <div class="menu-text">Pengeluaran</div>
    </button>
    <button class="menu-item" onclick="openModal('modal-qris')">
      <div class="menu-icon"><svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>
      <div class="menu-text">QRIS Dinamis</div>
    </button>
    <button class="menu-item" onclick="showStaticQRIS()">
      <div class="menu-icon warn"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></div>
      <div class="menu-text">QRIS Statis</div>
    </button>
    <button class="menu-item" onclick="openModal('modal-setting')">
      <div class="menu-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></div>
      <div class="menu-text">Pengaturan</div>
    </button>
    <button class="menu-item" onclick="window.location.href='/download_csv'">
      <div class="menu-icon"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></div>
      <div class="menu-text">Download</div>
    </button>
  </div>

  <div class="section-title">
    <span>Riwayat Hari Ini</span>
    <a href="#" class="section-link" onclick="openModal('modal-all-history');return false;">Lihat Semua →</a>
  </div>
  <div id="history-today"></div>

  <div class="footer">&copy; <span id="yr"></span> Qgen</div>
</div>

<!-- MODAL: PENJUALAN -->
<div class="modal-overlay" id="modal-jual" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>Catat Penjualan</h2>
      <button class="modal-close" onclick="closeModal('modal-jual')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <form onsubmit="submitLedger(event,'income')">
      <div class="section-title" style="margin:4px 0 10px;"><span>Daftar Barang</span><button type="button" class="btn-ghost" onclick="addSaleItem()">＋ Tambah Barang</button></div>
      <div id="sale-items" style="display:grid;gap:10px;"></div>
      <div style="background:var(--input-bg);border:1px solid var(--border);border-radius:12px;padding:14px;margin:12px 0;">
        <div style="display:flex;justify-content:space-between;font-size:13px;color:var(--muted);"><span>Total barang</span><b id="sale-qty-total">0 item</b></div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;"><b>Total pembayaran</b><strong id="sale-grand-total" style="font-size:22px;">Rp 0</strong></div>
      </div>
      <label class="label" for="method-jual">Metode Bayar</label>
      <div class="field">
        <select id="method-jual">
          <option value="cash">Tunai (Cash)</option>
          <option value="debt">Utang / Bon</option>
          <option value="qris">QRIS</option>
        </select>
      </div>
      <button type="submit" class="btn-primary success" id="btn-jual">Simpan Penjualan</button>
    </form>
  </div>
</div>

<!-- MODAL: PENGELUARAN -->
<div class="modal-overlay" id="modal-beli" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>Catat Pengeluaran</h2>
      <button class="modal-close" onclick="closeModal('modal-beli')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <form onsubmit="submitLedger(event,'expense')">
      <label class="label" for="title-beli">Keterangan</label>
      <div class="field"><input type="text" id="title-beli" placeholder="Misal: Beli Gas, Tepung" required maxlength="100"></div>
      <label class="label" for="amount-beli">Nominal (Rp)</label>
      <div class="field center"><input type="number" id="amount-beli" placeholder="20000" required min="1" inputmode="numeric"></div>
      <button type="submit" class="btn-primary danger" id="btn-beli">Simpan Pengeluaran</button>
    </form>
  </div>
</div>

<!-- MODAL: QRIS DINAMIS -->
<div class="modal-overlay" id="modal-qris" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>Buat Tagihan QRIS</h2>
      <button class="modal-close" onclick="closeModal('modal-qris')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div id="qris-form">
      <label class="label" for="qris-amount">Nominal Tagihan (Rp)</label>
      <div class="field center"><input type="number" id="qris-amount" placeholder="15000" min="1" max="999999999" inputmode="numeric"></div>
      <button class="btn-primary" id="btn-gen-qris" onclick="generateQR()">Generate QRIS</button>
    </div>
    <div id="qris-view" style="display:none;text-align:center;">
      <p id="qris-timer" style="font-size:12px;color:var(--muted);margin-bottom:8px;"></p>
      <img id="img-qr" src="" alt="QRIS" style="width:100%;max-width:240px;border-radius:12px;margin:0 auto 14px;display:block;">
      <button class="btn-primary success" onclick="confirmQRIS()" id="btn-lunas">✓ Uang Diterima</button>
      <button class="btn-ghost" onclick="closeModal('modal-qris')">Batal</button>
    </div>
  </div>
</div>

<!-- MODAL: QRIS STATIS -->
<div class="modal-overlay" id="modal-statis" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>QRIS Statis Toko</h2>
      <button class="modal-close" onclick="closeModal('modal-statis')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div id="static-area"></div>
  </div>
</div>

<!-- MODAL: SETTING -->
<div class="modal-overlay" id="modal-setting" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>Pengaturan</h2>
      <button class="modal-close" onclick="closeModal('modal-setting')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <form onsubmit="updateStoreName(event)">
      <label class="label" for="input-store-name">Nama Toko</label>
      <div class="field"><input type="text" id="input-store-name" placeholder="Warung Bu Sari" value="{{ store_name }}" maxlength="60"></div>
      <button type="submit" class="btn-primary">Simpan Nama Toko</button>
    </form>
    <hr style="border:none;border-top:1px solid var(--border);margin:20px 0;">
    <form onsubmit="changePin(event)">
      <label class="label" for="input-old-pin">PIN Lama</label>
      <div class="field"><input type="password" id="input-old-pin" placeholder="PIN Lama" maxlength="6" inputmode="numeric" required></div>
      <label class="label" for="input-new-pin">PIN Baru</label>
      <div class="field"><input type="password" id="input-new-pin" placeholder="PIN Baru (6 angka)" maxlength="6" inputmode="numeric" required></div>
      <button type="submit" class="btn-primary">Ganti PIN</button>
    </form>
    <a href="/logout" class="btn-primary danger" style="text-decoration:none;margin-top:16px;"
       onclick="return confirm('Yakin ingin logout?');">Logout Akun</a>
  </div>
</div>

<!-- MODAL: GRAFIK -->
<div class="modal-overlay" id="modal-grafik" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>Grafik Penjualan</h2>
      <button class="modal-close" onclick="closeModal('modal-grafik')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="chart-tabs">
      <button data-range="1d">1 Hari</button>
      <button data-range="7d" class="active">7 Hari</button>
      <button data-range="30d">30 Hari</button>
      <button data-range="3m">3 Bulan</button>
    </div>
    <div class="chart-summary">
      <div class="chart-summary-item">
        <span class="chart-summary-label">Total</span>
        <span class="chart-summary-val" id="summary-total">—</span>
      </div>
      <div class="chart-summary-item">
        <span class="chart-summary-label">Rata²</span>
        <span class="chart-summary-val" id="summary-avg">—</span>
      </div>
      <div class="chart-summary-item">
        <span class="chart-summary-label">Terbaik</span>
        <span class="chart-summary-val" id="summary-peak">—</span>
      </div>
    </div>
    <div class="chart-detail" id="chart-detail" style="display:none;">
      <span id="detail-label">—</span>
      <span id="detail-value">—</span>
    </div>
    <div class="chart-wrap">
      <div class="chart-bars" id="chart-bars">
        <div style="text-align:center;padding:40px 0;color:var(--muted);font-size:12px;width:100%;">Memuat...</div>
      </div>
    </div>
    <div class="chart-labels" id="chart-labels"></div>
    <p style="text-align:center;font-size:11px;color:var(--muted);margin-top:10px;">Tap batang untuk detail</p>
  </div>
</div>

<!-- MODAL: EDIT TRANSAKSI -->
<div class="modal-overlay" id="modal-edit" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>Edit Transaksi</h2>
      <button class="modal-close" onclick="closeModal('modal-edit')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <form onsubmit="saveEditTx(event)">
      <input type="hidden" id="edit-id">
      <label class="label" for="edit-title">Keterangan</label>
      <div class="field"><input type="text" id="edit-title" placeholder="Misal: Kopi Susu x2" required maxlength="100"></div>
      <label class="label" for="edit-amount">Nominal (Rp)</label>
      <div class="field center"><input type="number" id="edit-amount" required min="1" inputmode="numeric"></div>
      <label class="label" for="edit-method">Metode</label>
      <div class="field">
        <select id="edit-method">
          <option value="cash">Tunai</option>
          <option value="debt">Utang</option>
          <option value="qris">QRIS</option>
        </select>
      </div>
      <button type="submit" class="btn-primary" id="btn-edit">Simpan Perubahan</button>
      <button type="button" class="btn-primary success" onclick="showReceipt(document.getElementById('edit-id').value)" style="margin-top:8px;">🖨️ Cetak Struk</button>
      <button type="button" class="btn-primary danger" onclick="deleteTx()" id="btn-del">Hapus Transaksi</button>
    </form>
  </div>
</div>

<!-- MODAL: ALL HISTORY -->
<div class="modal-overlay" id="modal-all-history" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>Semua Riwayat</h2>
      <button class="modal-close" onclick="closeModal('modal-all-history')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div id="all-history-area"></div>
  </div>
</div>

<!-- MODAL: STRUK -->
<div class="modal-overlay" id="modal-struk" data-modal>
  <div class="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <h2>Struk Transaksi</h2>
      <button class="modal-close" onclick="closeModal('modal-struk')" aria-label="Tutup">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="receipt-wrap">
      <img id="receipt-img" class="receipt-img" src="" alt="Struk">
    </div>
    <div class="receipt-actions">
      <button class="btn-primary success" onclick="shareReceipt()">📲 Bagikan ke WhatsApp</button>
      <a id="receipt-download" class="btn-ghost" href="#" download style="text-align:center;text-decoration:none;">⬇️ Unduh Struk PNG</a>
      <a id="receipt-pdf" class="btn-ghost" href="#" download style="text-align:center;text-decoration:none;">📄 Unduh Struk PDF</a>
      <button class="btn-ghost" onclick="printReceipt()">🖨️ Cetak Struk</button>
    </div>
  </div>
</div>

<script>
// ============ DATA ============
const TXS = {{ all_history_json|safe }};
const TX_TODAY_IDS = {{ today_ids_json|safe }};

// ============ TOAST ============
function toast(msg, type='info'){
  const el = document.createElement('div');
  el.className = 'toast toast-'+type;
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(()=>el.classList.add('show'));
  setTimeout(()=>{el.classList.remove('show');setTimeout(()=>el.remove(),300);},2800);
}

// ============ MODAL ============
let chartData=null, chartRange='7d', chartLoaded=false;
function openModal(id){
  document.getElementById(id).classList.add('active');
  if(id==='modal-grafik' && !chartLoaded) loadChart('7d');
}
function closeModal(id){document.getElementById(id).classList.remove('active');}
document.querySelectorAll('[data-modal]').forEach(el=>{
  el.addEventListener('click',e=>{if(e.target===el)el.classList.remove('active');});
});
document.addEventListener('keydown',e=>{
  if(e.key==='Escape')document.querySelectorAll('.modal-overlay.active')
    .forEach(m=>m.classList.remove('active'));
});

// ============ HELPERS ============
function fmtRp(n){return 'Rp '+Number(n).toLocaleString('id-ID');}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
async function withLoading(btn,fn){
  const orig=btn.innerHTML;
  btn.disabled=true;
  btn.innerHTML='<span class="spinner"></span>';
  try{return await fn();}
  finally{btn.disabled=false;btn.innerHTML=orig;}
}

// ============ RENDER HISTORY ============
function renderHistoryItem(tx){
  const isIncome = tx.type==='income';
  const sign = isIncome?'+':'−';
  const cls = isIncome?'income':'expense';
  return `<div class="history-item" onclick="openEdit(${tx.id})">
    <div class="history-info">
      <div class="history-title">${esc(tx.title)}</div>
      <div class="history-meta">${tx.time} • ${(tx.method||'').toUpperCase()}</div>
    </div>
    <div class="history-amount ${cls}">${sign} ${fmtRp(tx.amount)}</div>
  </div>`;
}

function renderToday(){
  const el = document.getElementById('history-today');
  const items = TXS.filter(t=>TX_TODAY_IDS.includes(t.id));
  const LIMIT = 4;

  if(!items.length){
    el.innerHTML = `<div class="empty-state">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
      <p class="empty-title">Belum ada transaksi</p>
      <p class="empty-sub">Mulai catat penjualan hari ini</p>
      <button class="btn-primary" style="width:auto;padding:10px 20px;margin:0 auto;" onclick="openModal('modal-jual')">+ Catat Penjualan</button>
    </div>`;
    return;
  }

  const visibleItems = items.slice(0, LIMIT);
  const remaining = items.length - LIMIT;

  let html = `<div class="history-list">${visibleItems.map(renderHistoryItem).join('')}</div>`;
  
  if (remaining > 0) {
    html += `<button class="btn-ghost" style="margin-top:-8px; font-size:12px; padding:10px;" onclick="openModal('modal-all-history')">
      Lihat ${remaining} transaksi lainnya ↓
    </button>`;
  }

  el.innerHTML = html;
}

function renderAllHistory(){
  const el = document.getElementById('all-history-area');
  if(!TXS.length){
    el.innerHTML = '<p style="text-align:center;padding:20px;color:var(--muted);">Belum ada transaksi.</p>';
    return;
  }
  el.innerHTML = `<div class="history-list" style="border:none;box-shadow:none;">${TXS.map(renderHistoryItem).join('')}</div>`;
}

renderToday();
renderAllHistory();

// ============ SUBMIT LEDGER ============
function addSaleItem(name='', qty=1, price=''){
  const host=document.getElementById('sale-items');
  const row=document.createElement('div');
  row.className='sale-item-row';
  row.style.cssText='display:grid;grid-template-columns:minmax(72px,1fr) 54px 90px 30px;gap:6px;align-items:end;';
  row.innerHTML=`<label class="label" style="margin:0;">Barang<input class="sale-name" maxlength="100" placeholder="Nama barang" value="${String(name).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}" required style="display:block;width:100%;margin-top:5px;padding:11px 8px;border:1px solid var(--border);border-radius:9px;background:var(--card);color:var(--fg);"></label>
  <label class="label" style="margin:0;">Qty<input class="sale-qty" type="number" min="1" max="9999" value="${qty}" inputmode="numeric" required style="display:block;width:100%;margin-top:5px;padding:11px 5px;border:1px solid var(--border);border-radius:9px;background:var(--card);color:var(--fg);"></label>
  <label class="label" style="margin:0;">Harga<input class="sale-price" type="number" min="1" max="999999999" value="${price}" placeholder="Rp" inputmode="numeric" required style="display:block;width:100%;margin-top:5px;padding:11px 6px;border:1px solid var(--border);border-radius:9px;background:var(--card);color:var(--fg);"></label>
  <button type="button" aria-label="Hapus barang" onclick="this.closest('.sale-item-row').remove();updateSaleTotal();" style="height:42px;border-radius:9px;background:var(--danger-soft);color:var(--danger);font-size:20px;">×</button>`;
  host.appendChild(row);
  row.querySelectorAll('input').forEach(el=>el.addEventListener('input',updateSaleTotal));
  updateSaleTotal();
}
function updateSaleTotal(){
  const rows=[...document.querySelectorAll('.sale-item-row')];
  let total=0,qty=0;
  rows.forEach(r=>{const q=Math.max(0,parseInt(r.querySelector('.sale-qty').value||0,10));const p=Math.max(0,parseInt(r.querySelector('.sale-price').value||0,10));total+=q*p;qty+=q;});
  document.getElementById('sale-qty-total').textContent=qty+' item';
  document.getElementById('sale-grand-total').textContent='Rp '+total.toLocaleString('id-ID');
  return {total,qty};
}
function initSaleItems(){if(document.getElementById('sale-items') && !document.querySelector('.sale-item-row'))addSaleItem();}
initSaleItems();
async function submitLedger(e,type){
  e.preventDefault();
  const isIncome=type==='income';
  const method=isIncome?document.getElementById('method-jual').value:'cash';
  let payload;
  if(isIncome){
    const rows=[...document.querySelectorAll('.sale-item-row')];
    const items=rows.map(r=>({name:r.querySelector('.sale-name').value.trim(),qty:parseInt(r.querySelector('.sale-qty').value,10),price:parseInt(r.querySelector('.sale-price').value,10)}));
    if(!items.length || items.some(x=>!x.name||!Number.isInteger(x.qty)||x.qty<1||!Number.isInteger(x.price)||x.price<1)){toast('Lengkapi nama, jumlah, dan harga barang','error');return;}
    const amount=items.reduce((sum,x)=>sum+x.qty*x.price,0);
    if(!Number.isSafeInteger(amount)||amount<1||amount>999999999){toast('Total transaksi di luar batas','error');return;}
    payload={type,title:items.length===1?items[0].name:`${items[0].name} + ${items.length-1} barang`,amount,method,items};
  }else{
    const title=document.getElementById('title-beli').value.trim();
    const amount=parseInt(document.getElementById('amount-beli').value,10);
    if(!title||!Number.isFinite(amount)||amount<1){toast('Data tidak valid','error');return;}
    payload={type,title,amount,method};
  }
  const btn=document.getElementById(isIncome?'btn-jual':'btn-beli');
  await withLoading(btn,async()=>{
    try{
      const res=await fetch('/add_transaction',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      const data=await res.json();
      if(data.ok){toast('Transaksi dan rincian barang tersimpan','success');setTimeout(()=>location.reload(),500);}
      else toast(data.error||'Gagal','error');
    }catch(err){toast('Koneksi error','error');}
  });
}

// ============ SETTINGS ============
async function updateStoreName(e){
  e.preventDefault();
  const name = document.getElementById('input-store-name').value.trim();
  if(!name){toast('Nama toko tidak boleh kosong','error');return;}
  try{
    const res = await fetch('/update_profile',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({store_name:name})
    });
    if(res.ok){toast('Nama toko disimpan','success');setTimeout(()=>location.reload(),500);}
    else toast('Gagal','error');
  }catch(err){toast('Koneksi error','error');}
}

async function changePin(e){
  e.preventDefault();
  const oldPin = document.getElementById('input-old-pin').value;
  const newPin = document.getElementById('input-new-pin').value;
  if(!/^\d{6}$/.test(newPin)){toast('PIN baru harus 6 angka','error');return;}
  try{
    const res = await fetch('/change_pin',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({old_pin:oldPin,pin:newPin})
    });
    const data = await res.json();
    if(data.ok){
      toast('PIN diubah','success');
      document.getElementById('input-old-pin').value='';
      document.getElementById('input-new-pin').value='';
    }else toast(data.error||'Gagal','error');
  }catch(err){toast('Koneksi error','error');}
}

// ============ QRIS DINAMIS ============
let currentQRIS = null, qrisInterval = null;
async function generateQR(){
  const amount = parseInt(document.getElementById('qris-amount').value,10);
  if(!Number.isFinite(amount)||amount<1||amount>999999999){
    toast('Nominal harus Rp 1 – Rp 999.999.999','error');return;
  }
  const btn = document.getElementById('btn-gen-qris');
  await withLoading(btn,async()=>{
    try{
      const res = await fetch('/generate_qris',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({amount})
      });
      const data = await res.json();
      if(data.ok){
        currentQRIS = data;
        document.getElementById('img-qr').src = '/img/'+data.token+'.png';
        document.getElementById('qris-form').style.display='none';
        document.getElementById('qris-view').style.display='block';
        startQrisCountdown(data.expires_in||300);
      }else toast(data.error||'Gagal','error');
    }catch(err){toast('Koneksi error','error');}
  });
}

function startQrisCountdown(seconds){
  clearInterval(qrisInterval);
  const el = document.getElementById('qris-timer');
  let s = seconds;
  const tick=()=>{
    if(s<=0){clearInterval(qrisInterval);el.textContent='⏱️ QR kadaluarsa';return;}
    const m=Math.floor(s/60),ss=s%60;
    el.textContent=`⏱️ Berlaku ${m}:${String(ss).padStart(2,'0')}`;
    s--;
  };
  tick();qrisInterval=setInterval(tick,1000);
}

async function confirmQRIS(){
  if(!currentQRIS)return;
  const btn = document.getElementById('btn-lunas');
  await withLoading(btn,async()=>{
    try{
      const res = await fetch('/add_transaction',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({type:'income',title:'Penjualan QRIS',amount:currentQRIS.amount,method:'qris'})
      });
      if(res.ok){toast('Lunas! 🎉','success');setTimeout(()=>location.reload(),500);}
    }catch(err){toast('Koneksi error','error');}
  });
}

// ============ QRIS STATIS ============
async function showStaticQRIS(){
  document.getElementById('static-area').innerHTML =
    '<p style="text-align:center;color:var(--muted);">Memuat...</p>';
  openModal('modal-statis');
  try{
    const res = await fetch('/get_static_qris');
    const data = await res.json();
    if(data.payload){
      document.getElementById('static-area').innerHTML = `
        <img src="/img/${data.token}.png" alt="QRIS" style="width:100%;max-width:240px;border-radius:12px;margin:0 auto 14px;display:block;">
        <p style="font-size:12px;color:var(--muted);text-align:center;">Pembeli scan & memasukkan nominal sendiri.</p>`;
    }else{
      document.getElementById('static-area').innerHTML = `
        <p style="font-size:13px;color:var(--danger);margin-bottom:12px;">QRIS Statis belum diatur.</p>
        <label class="btn-ghost" style="position:relative;display:flex;align-items:center;justify-content:center;cursor:pointer;">
          Upload Gambar QRIS
          <input type="file" accept="image/*" onchange="decodeStaticQRIS(this)" style="position:absolute;inset:0;opacity:0;cursor:pointer;">
        </label>
        <label class="label" for="static-payload" style="margin-top:14px;">Atau paste payload:</label>
        <div class="field"><textarea id="static-payload" placeholder="000201..."></textarea></div>
        <button class="btn-primary" onclick="saveStaticQRIS()">Simpan QRIS</button>`;
    }
  }catch(err){toast('Koneksi error','error');}
}

async function decodeStaticQRIS(input){
  if(!input.files || !input.files[0]) return;

  const file = input.files[0];
  toast('Membaca QR...', 'info');

  try {
    if (!('BarcodeDetector' in window)) {
      toast('Browser belum mendukung pembaca QR. Coba Chrome terbaru.', 'error');
      return;
    }

    const detector = new BarcodeDetector({formats: ['qr_code']});
    const bitmap = await createImageBitmap(file);
    const results = await detector.detect(bitmap);
    bitmap.close();

    if (results.length && results[0].rawValue) {
      document.getElementById('static-payload').value = results[0].rawValue;
      toast('QR terbaca! Klik Simpan.', 'success');
    } else {
      toast('QR tidak terdeteksi. Coba gambar yang lebih jelas.', 'error');
    }
  } catch(err) {
    console.error(err);
    toast('Gagal membaca QR dari gambar.', 'error');
  }
}
async function saveStaticQRIS(){
  const payload = document.getElementById('static-payload').value.trim();
  if(!payload||payload.length<50){toast('Payload tidak valid','error');return;}
  try{
    const res = await fetch('/save_static_qris',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({payload})
    });
    if(res.ok){toast('QRIS disimpan','success');showStaticQRIS();}
    else toast('Gagal','error');
  }catch(err){toast('Koneksi error','error');}
}

// ============ EDIT / DELETE ============
function openEdit(id){
  const tx = TXS.find(t=>t.id===id);
  if(!tx)return;
  document.getElementById('edit-id').value = tx.id;
  document.getElementById('edit-title').value = tx.title;
  document.getElementById('edit-amount').value = tx.amount;
  document.getElementById('edit-method').value = tx.method||'cash';
  openModal('modal-edit');
}

async function saveEditTx(e){
  e.preventDefault();
  const id = document.getElementById('edit-id').value;
  const title = document.getElementById('edit-title').value.trim();
  const amount = parseInt(document.getElementById('edit-amount').value,10);
  const method = document.getElementById('edit-method').value;
  if(!title||!Number.isFinite(amount)||amount<1){toast('Data tidak valid','error');return;}
  const btn = document.getElementById('btn-edit');
  await withLoading(btn,async()=>{
    try{
      const res = await fetch('/transaction/'+id,{
        method:'PATCH',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({title,amount,method})
      });
      const data = await res.json();
      if(data.ok){toast('Diperbarui','success');setTimeout(()=>location.reload(),500);}
      else toast(data.error||'Gagal','error');
    }catch(err){toast('Koneksi error','error');}
  });
}

async function deleteTx(){
  const id = document.getElementById('edit-id').value;
  if(!confirm('Hapus transaksi ini?'))return;
  const btn = document.getElementById('btn-del');
  await withLoading(btn,async()=>{
    try{
      const res = await fetch('/transaction/'+id,{method:'DELETE'});
      const data = await res.json();
      if(data.ok){toast('Dihapus','success');setTimeout(()=>location.reload(),500);}
      else toast(data.error||'Gagal','error');
    }catch(err){toast('Koneksi error','error');}
  });
}

// ============ CHART ============
function fmtShort(n){
  n = Number(n)||0;
  if(n >= 1_000_000) return (n/1_000_000).toFixed(1).replace('.0','')+'jt';
  if(n >= 1_000) return Math.round(n/1_000)+'rb';
  return String(n);
}

async function loadChart(range){
  chartRange = range;
  document.querySelectorAll('.chart-tabs button').forEach(b=>{
    b.classList.toggle('active', b.dataset.range===range);
  });
  document.getElementById('chart-bars').innerHTML =
    '<div style="text-align:center;padding:40px 0;color:var(--muted);font-size:12px;width:100%;">Memuat...</div>';
  try{
    const res = await fetch('/api/chart?range='+range);
    const data = await res.json();
    if(!data.ok) return;
    chartData = data; chartLoaded = true;
    renderChart();
  }catch(e){
    document.getElementById('chart-bars').innerHTML =
      '<div style="text-align:center;padding:40px 0;color:var(--danger);font-size:12px;width:100%;">Gagal memuat</div>';
  }
}

function renderChart(){
  const d = chartData;
  const bars = document.getElementById('chart-bars');
  const labels = document.getElementById('chart-labels');
  document.getElementById('chart-detail').style.display = 'none';

  const n = d.buckets.length;
  const maxVal = Math.max(1, ...d.buckets.map(b=>b.income));

  bars.innerHTML = d.buckets.map((b,i)=>{
    const h = b.income > 0 ? Math.max((b.income/maxVal)*100, 3) : 2;
    const cls = b.income > 0 ? '' : 'empty';
    return `<div class="chart-bar ${cls}" style="height:${h}%" onclick="showBarDetail(${i})" title="${b.full_label}: Rp ${b.income.toLocaleString('id-ID')}"></div>`;
  }).join('');

  const step = n > 20 ? 4 : (n > 10 ? 2 : 1);
  labels.innerHTML = d.buckets.map((b,i)=>{
    const show = i % step === 0 || i === n-1;
    return `<div class="chart-label">${show ? b.label : ''}</div>`;
  }).join('');

  const days = {'1d':1,'7d':7,'30d':30,'3m':90};
  const avg = Math.round(d.total_income / days[chartRange]);
  document.getElementById('summary-total').textContent = 'Rp '+fmtShort(d.total_income);
  document.getElementById('summary-avg').textContent = 'Rp '+fmtShort(avg)+(chartRange==='1d'?'/jam':'/hari');
  document.getElementById('summary-peak').textContent = d.peak_amount > 0
    ? 'Rp '+fmtShort(d.peak_amount)+' ('+d.peak_label+')'
    : '—';
}

function showBarDetail(i){
  const b = chartData.buckets[i];
  document.getElementById('detail-label').textContent = b.full_label;
  document.getElementById('detail-value').textContent = 'Rp ' + b.income.toLocaleString('id-ID');
  document.getElementById('chart-detail').style.display = 'flex';
}

document.querySelectorAll('.chart-tabs button').forEach(b=>{
  b.addEventListener('click', ()=>loadChart(b.dataset.range));
});

// ============ STRUK ============
let _receiptId = null;

function showReceipt(txId){
  if(!txId) return;
  _receiptId = txId;
  const url = '/receipt/' + txId + '.png';
  document.getElementById('receipt-img').src = url;
  const dl = document.getElementById('receipt-download');
  dl.href = url;
  dl.download = 'struk-' + txId + '.png';
  const pdf=document.getElementById('receipt-pdf');
  pdf.href='/receipt/'+txId+'.pdf';
  pdf.download='struk-'+txId+'.pdf';
  openModal('modal-struk');
}

async function shareReceipt(){
  if(!_receiptId)return;
  const url='/receipt/'+_receiptId+'.png';
  const textMsg='Terima kasih sudah berbelanja! Berikut struk transaksi Qgen.';
  try{
    const res=await fetch(url);
    if(!res.ok)throw new Error('Struk tidak ditemukan');
    const blob=await res.blob();
    const file=new File([blob],`struk-QGN-${String(_receiptId).padStart(6,'0')}.png`,{type:'image/png'});
    if(navigator.canShare && navigator.canShare({files:[file]})){
      await navigator.share({files:[file],title:'Struk Qgen',text:textMsg});
      return;
    }
    // Browser desktop may not support file sharing; open WhatsApp with a message
    // and keep the receipt download ready for manual attachment.
    document.getElementById('receipt-download').click();
    const wa='https://wa.me/?text='+encodeURIComponent(textMsg+' No. transaksi QGN-'+String(_receiptId).padStart(6,'0'));
    window.open(wa,'_blank','noopener');
    toast('Struk diunduh. Lampirkan gambar di WhatsApp.','info');
  }catch(err){if(err.name!=='AbortError')toast('Gagal membagikan struk','error');}
}

function printReceipt(){
  if(!_receiptId) return;
  const src = '/receipt/' + _receiptId + '.png';
  const w = window.open('', '_blank');
  w.document.write(`
    <html><head><title>Struk</title></head>
    <body style="margin:0;display:flex;justify-content:center;padding:10px;">
      <img src="${src}" style="width:58mm;display:block;" onload="setTimeout(()=>{window.print();window.close();},200);">
    </body></html>
  `);
  w.document.close();
}

document.getElementById('yr').textContent = new Date().getFullYear();
</script>
</body></html>
"""

# ============================================================
# ROUTES
# ============================================================
@app.before_request
def require_login():
    if os.environ.get("QGEN_DEMO") == "1":
        if request.endpoint in ("index", "api_chart", "static") and request.method == "GET":
            return None
        return ("Mode demo: fitur ini hanya untuk dilihat dan tidak dapat mengubah data.", 403)

    allowed = ["login","register","forgot_pin","reset_pin","verify_device","img"]
    if request.endpoint not in allowed and "user_id" not in session:
        return redirect(url_for("login"))

# ---------- AUTH ----------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pin = request.form.get("pin","")
        if not email or len(pin)!=6 or not pin.isdigit():
            flash("Email wajib & PIN harus 6 angka.","error")
            return redirect(url_for("register"))
        recovery_key = secrets.token_hex(32)
        dev = get_device_id()
        with closing(get_db()) as conn:
            try:
                conn.execute(
                    "INSERT INTO users (email,pin_hash,recovery_key,device_id) VALUES (?,?,?,?)",
                    (email, hash_pin(pin), recovery_key, dev)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                flash("Email sudah terdaftar.","error")
                return redirect(url_for("register"))
        content = f"""
            <h2 style="text-align:center;margin-bottom:10px;">Pendaftaran Berhasil</h2>
            <p style="text-align:center;font-size:13px;color:var(--muted);margin-bottom:14px;">
              Simpan Recovery Key ini. Wajib jika login dari HP/perangkat baru.</p>
            <div class="key-box">{recovery_key}</div>
            <a href="/login" class="btn-primary" style="display:block;text-align:center;text-decoration:none;">Lanjut Login</a>"""
        return render_template_string(AUTH_TEMPLATE, content=content, store_name=None)

    content = """
        <p class="auth-sub">Buat akun Qgen baru</p>
        <form method="POST">
            <input type="email" name="email" placeholder="Email" required autocomplete="email">
            <input type="password" name="pin" placeholder="PIN 6 angka" maxlength="6"
                   inputmode="numeric" pattern="[0-9]{6}" required>
            <button type="submit" class="btn-primary">Daftar</button>
        </form>
        <a href="/login" class="auth-link">Sudah punya akun? Login</a>"""
    return render_template_string(AUTH_TEMPLATE, content=content, store_name=None)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pin = request.form.get("pin","")
        current_dev = get_device_id()
        with closing(get_db()) as conn:
            user = conn.execute(
                "SELECT id, email, pin_hash, device_id FROM users WHERE email=?",
                (email,)
            ).fetchone()
        stored_hash = user["pin_hash"] if user else "0"*64
        if not user or not verify_pin(stored_hash, pin):
            flash("Email atau PIN salah.","error")
            return redirect(url_for("login"))
        if user["device_id"] and user["device_id"] != current_dev:
            flash("Perangkat baru. Masukkan Recovery Key.","error")
            return redirect(url_for("verify_device", email=email))
        session.clear()
        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        session.permanent = True
        return redirect(url_for("index"))

    content = """
        <p class="auth-sub">Masuk ke akun Qgen</p>
        <form method="POST">
            <input type="email" name="email" placeholder="Email" required autocomplete="email">
            <input type="password" name="pin" placeholder="PIN 6 angka" maxlength="6"
                   inputmode="numeric" pattern="[0-9]{6}" required>
            <button type="submit" class="btn-primary">Masuk</button>
        </form>
        <a href="/forgot-pin" class="auth-link muted">Lupa PIN?</a>
        <a href="/register" class="auth-link">Belum punya akun? Daftar</a>"""
    return render_template_string(AUTH_TEMPLATE, content=content, store_name=None)

@app.route("/verify-device/<email>", methods=["GET","POST"])
def verify_device(email):
    if request.method == "POST":
        key = request.form.get("recovery_key","").strip()
        dev = get_device_id()
        with closing(get_db()) as conn:
            user = conn.execute(
                "SELECT id, recovery_key FROM users WHERE email=?", (email,)
            ).fetchone()
            if user and hmac.compare_digest(user["recovery_key"], key):
                conn.execute("UPDATE users SET device_id=? WHERE email=?", (dev, email))
                conn.commit()
                session.clear()
                session["user_id"] = user["id"]
                session["user_email"] = email
                session.permanent = True
                return redirect(url_for("index"))
        flash("Recovery Key salah.","error")

    content = """
        <p class="auth-sub">Perangkat baru terdeteksi</p>
        <form method="POST">
            <input type="text" name="recovery_key" placeholder="Recovery Key (64 karakter)" required>
            <button type="submit" class="btn-primary">Verifikasi</button>
        </form>
        <a href="/login" class="auth-link muted">Kembali ke Login</a>"""
    return render_template_string(AUTH_TEMPLATE, content=content, store_name=None)

@app.route("/forgot-pin", methods=["GET","POST"])
def forgot_pin():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        with closing(get_db()) as conn:
            user = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if user:
                otp = str(random.randint(100000, 999999))
                expires = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute("UPDATE users SET otp_code=?, otp_expires_at=? WHERE email=?",
                             (otp, expires, email))
                conn.commit()
                print(f"\n📧 OTP untuk {email}: {otp} (berlaku 10 menit)\n")
                flash("OTP dikirim. Cek terminal server.","success")
                return redirect(url_for("reset_pin", email=email))
        flash("Email tidak ditemukan.","error")

    content = """
        <p class="auth-sub">Masukkan email untuk menerima OTP</p>
        <form method="POST">
            <input type="email" name="email" placeholder="Email" required>
            <button type="submit" class="btn-primary">Kirim OTP</button>
        </form>
        <a href="/login" class="auth-link">Kembali</a>"""
    return render_template_string(AUTH_TEMPLATE, content=content, store_name=None)

@app.route("/reset-pin/<email>", methods=["GET","POST"])
def reset_pin(email):
    if request.method == "POST":
        otp_input = request.form.get("otp","").strip()
        new_pin = request.form.get("new_pin","")
        if len(new_pin)!=6 or not new_pin.isdigit():
            flash("PIN harus 6 angka.","error")
            return redirect(url_for("reset_pin", email=email))
        with closing(get_db()) as conn:
            row = conn.execute(
                "SELECT otp_code, otp_expires_at FROM users WHERE email=?", (email,)
            ).fetchone()
            if not row or not row["otp_code"]:
                flash("Minta OTP baru.","error")
                return redirect(url_for("forgot_pin"))
            if not hmac.compare_digest(row["otp_code"], otp_input):
                flash("OTP salah.","error")
                return redirect(url_for("reset_pin", email=email))
            if not row["otp_expires_at"] or datetime.now() > datetime.strptime(
                row["otp_expires_at"], "%Y-%m-%d %H:%M:%S"):
                flash("OTP kadaluarsa. Minta yang baru.","error")
                return redirect(url_for("forgot_pin"))
            conn.execute("UPDATE users SET pin_hash=?, otp_code=NULL, otp_expires_at=NULL WHERE email=?",
                         (hash_pin(new_pin), email))
            conn.commit()
        flash("PIN direset. Silakan login.","success")
        return redirect(url_for("login"))

    content = """
        <p class="auth-sub">Masukkan OTP & PIN baru</p>
        <form method="POST">
            <input type="text" name="otp" placeholder="Kode OTP (6 angka)" maxlength="6"
                   inputmode="numeric" required>
            <input type="password" name="new_pin" placeholder="PIN Baru (6 angka)" maxlength="6"
                   inputmode="numeric" required>
            <button type="submit" class="btn-primary">Simpan PIN</button>
        </form>"""
    return render_template_string(AUTH_TEMPLATE, content=content, store_name=None)

@app.route("/logout")
def logout():
    session.clear()
    flash("Anda telah logout.","success")
    return redirect(url_for("login"))

# ---------- MAIN ----------
@app.route("/")
def index():
    if os.environ.get("QGEN_DEMO") == "1":
        demo_txs = [
            {"id": 1, "type": "income", "method": "cash", "title": "Penjualan Kopi Susu", "amount": 45000, "items": [], "time": "09:15"},
            {"id": 2, "type": "income", "method": "qris", "title": "Penjualan Roti Bakar", "amount": 32000, "items": [], "time": "10:20"},
            {"id": 3, "type": "expense", "method": "cash", "title": "Beli bahan baku", "amount": 25000, "items": [], "time": "11:05"},
            {"id": 4, "type": "income", "method": "cash", "title": "Penjualan Es Teh", "amount": 58000, "items": [], "time": "12:30"},
            {"id": 5, "type": "expense", "method": "cash", "title": "Biaya operasional", "amount": 18000, "items": [], "time": "13:10"},
        ]
        demo_income = 135000
        demo_expense = 43000

        return render_template_string(
            MAIN_TEMPLATE,
            store_name="Kedai Demo",
            kas_bersih=_fmt(demo_income - demo_expense),
            pemasukan=_fmt(demo_income),
            pengeluaran=_fmt(demo_expense),
            stat_income=_fmt(1850000),
            stat_expense=_fmt(640000),
            stat_laba=_fmt(1210000),
            all_history_json=json.dumps(demo_txs),
            today_ids_json=json.dumps([1, 2, 3, 4, 5]),
        )

    user_id = session["user_id"]
    today = datetime.now().strftime("%Y-%m-%d")

    with closing(get_db()) as conn:
        user = conn.execute("SELECT store_name FROM users WHERE id=?", (user_id,)).fetchone()
        store_name = user["store_name"] if user and user["store_name"] else "Toko Saya"

        stats = conn.execute("""
            SELECT
              COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) inc,
              COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) exp
            FROM ledger WHERE user_id=? AND date(created_at)=?
        """, (user_id, today)).fetchone()
        pemasukan, pengeluaran = stats["inc"], stats["exp"]
        kas_bersih = pemasukan - pengeluaran

        today_rows = conn.execute("""
            SELECT id, type, method, title, amount, created_at, items_json
            FROM ledger WHERE user_id=? AND date(created_at)=?
            ORDER BY created_at DESC
        """, (user_id, today)).fetchall()

        all_rows = conn.execute("""
            SELECT id, type, method, title, amount, created_at, items_json
            FROM ledger WHERE user_id=?
            ORDER BY created_at DESC LIMIT 500
        """, (user_id,)).fetchall()

        stat30 = conn.execute("""
            SELECT
              COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) inc,
              COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) exp
            FROM ledger WHERE user_id=? AND date(created_at) >= date('now','-30 day')
        """, (user_id,)).fetchone()

    def _tx(r):
        dt = r["created_at"]
        if isinstance(dt, str):
            dt = datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
        return {
            "id": r["id"], "type": r["type"], "method": r["method"],
            "title": r["title"], "amount": r["amount"],
            "items": _receipt_items(r),
            "time": dt.strftime("%d/%m %H:%M")
        }

    all_txs = [_tx(r) for r in all_rows]
    today_ids = [r["id"] for r in today_rows]

    stat_inc, stat_exp = stat30["inc"], stat30["exp"]

    return render_template_string(
        MAIN_TEMPLATE,
        store_name=store_name,
        kas_bersih=_fmt(kas_bersih), pemasukan=_fmt(pemasukan),
        pengeluaran=_fmt(pengeluaran),
        stat_income=_fmt(stat_inc), stat_expense=_fmt(stat_exp),
        stat_laba=_fmt(stat_inc - stat_exp),
        all_history_json=json.dumps(all_txs),
        today_ids_json=json.dumps(today_ids),
    )

# ---------- TRANSACTIONS ----------
@app.route("/add_transaction", methods=["POST"])
def add_transaction():
    user_id = session["user_id"]
    data = request.json or {}
    ttype = data.get("type")
    method = data.get("method", "cash")
    title = str(data.get("title", "")).strip()[:100]
    try:
        amount = int(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="Nominal tidak valid"), 400
    if ttype not in ("income", "expense") or not title or not (1 <= amount <= 999_999_999):
        return jsonify(ok=False, error="Data tidak valid"), 400
    if method not in ("cash", "debt", "qris"):
        return jsonify(ok=False, error="Metode tidak valid"), 400

    raw_items = data.get("items") or []
    items = []
    if raw_items:
        if ttype != "income" or not isinstance(raw_items, list) or len(raw_items) > 100:
            return jsonify(ok=False, error="Rincian barang tidak valid"), 400
        computed = 0
        for item in raw_items:
            if not isinstance(item, dict):
                return jsonify(ok=False, error="Format barang tidak valid"), 400
            name = str(item.get("name", "")).strip()[:100]
            try:
                qty, price = int(item.get("qty", 0)), int(item.get("price", 0))
            except (TypeError, ValueError):
                return jsonify(ok=False, error="Jumlah atau harga barang tidak valid"), 400
            if not name or not (1 <= qty <= 9999) or not (1 <= price <= 999_999_999):
                return jsonify(ok=False, error="Nama, jumlah, atau harga barang tidak valid"), 400
            subtotal = qty * price
            computed += subtotal
            items.append({"name": name, "qty": qty, "price": price, "subtotal": subtotal})
        if computed != amount:
            return jsonify(ok=False, error="Total tidak sesuai dengan rincian barang"), 400
    else:
        # Legacy transactions and QRIS entries remain compatible.
        items = [{"name": title, "qty": 1, "price": amount, "subtotal": amount}]

    with closing(get_db()) as conn:
        cur = conn.execute("""
            INSERT INTO ledger (user_id,type,method,title,amount,created_at,items_json)
            VALUES (?,?,?,?,?,datetime('now','localtime'),?)
        """, (user_id, ttype, method, title, amount, json.dumps(items, ensure_ascii=False)))
        tx_id = cur.lastrowid
        conn.commit()
    return jsonify(ok=True, id=tx_id)

@app.route("/transaction/<int:tx_id>", methods=["PATCH","DELETE"])
def modify_transaction(tx_id):
    user_id = session["user_id"]
    with closing(get_db()) as conn:
        row = conn.execute(
            "SELECT id FROM ledger WHERE id=? AND user_id=?", (tx_id, user_id)
        ).fetchone()
        if not row:
            return jsonify(ok=False, error="Tidak ditemukan"), 404

        if request.method == "DELETE":
            conn.execute("DELETE FROM ledger WHERE id=?", (tx_id,))
            conn.commit()
            return jsonify(ok=True)

        data = request.json or {}
        fields, params = [], []
        if "title" in data:
            t = str(data["title"]).strip()[:100]
            if not t:
                return jsonify(ok=False, error="Judul tidak boleh kosong"), 400
            fields.append("title=?"); params.append(t)
        if "amount" in data:
            try:
                a = int(data["amount"])
            except (TypeError, ValueError):
                return jsonify(ok=False, error="Nominal tidak valid"), 400
            if not (1 <= a <= 999_999_999):
                return jsonify(ok=False, error="Nominal tidak valid"), 400
            fields.append("amount=?"); params.append(a)
        if "method" in data:
            m = data["method"]
            if m not in ("cash","debt","qris"):
                return jsonify(ok=False, error="Metode tidak valid"), 400
            fields.append("method=?"); params.append(m)

        if not fields:
            return jsonify(ok=False, error="Tidak ada perubahan"), 400
        params.append(tx_id)
        conn.execute(f"UPDATE ledger SET {', '.join(fields)} WHERE id=?", params)
        conn.commit()
    return jsonify(ok=True)

# ---------- PROFILE ----------
@app.route("/update_profile", methods=["POST"])
def update_profile():
    user_id = session["user_id"]
    name = str((request.json or {}).get("store_name", "")).strip()[:60]
    if not name:
        return jsonify(ok=False, error="Nama toko tidak boleh kosong"), 400
    with closing(get_db()) as conn:
        conn.execute("UPDATE users SET store_name=? WHERE id=?", (name, user_id))
        conn.commit()
    return jsonify(ok=True)

@app.route("/change_pin", methods=["POST"])
def change_pin():
    user_id = session["user_id"]
    data = request.json or {}
    old_pin = data.get("old_pin", "")
    new_pin = data.get("pin", "")
    if len(new_pin)!=6 or not new_pin.isdigit():
        return jsonify(ok=False, error="PIN baru harus 6 angka"), 400
    with closing(get_db()) as conn:
        row = conn.execute("SELECT pin_hash FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not verify_pin(row["pin_hash"], old_pin):
            return jsonify(ok=False, error="PIN lama salah"), 400
        conn.execute("UPDATE users SET pin_hash=? WHERE id=?", (hash_pin(new_pin), user_id))
        conn.commit()
    return jsonify(ok=True)

# ---------- CSV ----------
@app.route("/download_csv")
def download_csv():
    user_id = session["user_id"]
    with closing(get_db()) as conn:
        rows = conn.execute("""
            SELECT created_at,type,method,title,amount FROM ledger
            WHERE user_id=? ORDER BY created_at DESC
        """, (user_id,)).fetchall()

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Tanggal","Tipe","Metode","Keterangan","Nominal"])
        for r in rows:
            w.writerow([_csv_safe(r["created_at"]), _csv_safe(r["type"]),
                        _csv_safe(r["method"]), _csv_safe(r["title"]), r["amount"]])
        yield "\ufeff" + buf.getvalue()

    resp = Response(gen(), mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = 'attachment; filename="laporan-qgen.csv"'
    return resp

# ---------- QRIS ----------
@app.route("/generate_qris", methods=["POST"])
def generate_qris():
    user_id = session["user_id"]
    try:
        amount = int((request.json or {}).get("amount", 0))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="Nominal tidak valid"), 400
    if not (1 <= amount <= 999_999_999):
        return jsonify(ok=False, error="Nominal harus Rp 1 – Rp 999.999.999"), 400

    with closing(get_db()) as conn:
        row = conn.execute("SELECT qris_static FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or not row["qris_static"]:
        return jsonify(ok=False, error="Atur QRIS Statis terlebih dahulu"), 400

    try:
        payload = build_qris(row["qris_static"], amount)
        png = make_qr_bytes(payload, amount)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400

    cleanup_qr()
    token = uuid.uuid4().hex
    QR_STORE[token] = {
        "png": png, "amount": amount,
        "expires_at": datetime.now() + timedelta(minutes=QR_TTL_MINUTES)
    }
    return jsonify(ok=True, token=token, amount=amount,
                   expires_in=QR_TTL_MINUTES * 60)

@app.route("/get_static_qris")
def get_static_qris():
    user_id = session["user_id"]
    with closing(get_db()) as conn:
        row = conn.execute("SELECT qris_static FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or not row["qris_static"]:
        return jsonify(payload=None)
    cleanup_qr()
    key = f"static_{user_id}"
    if key in QR_STORE and datetime.now() < QR_STORE[key]["expires_at"]:
        return jsonify(payload=row["qris_static"], token=key.replace("static_",""))
    png = make_qr_bytes(row["qris_static"], 0)
    token = uuid.uuid4().hex
    QR_STORE[token] = {
        "png": png, "amount": 0,
        "expires_at": datetime.now() + timedelta(hours=QR_STATIC_TTL_HOURS)
    }
    return jsonify(payload=row["qris_static"], token=token)

@app.route("/save_static_qris", methods=["POST"])
def save_static_qris():
    user_id = session["user_id"]
    payload = str((request.json or {}).get("payload", "")).strip()
    if not payload.startswith("000201") or len(payload) < 50:
        return jsonify(ok=False, error="Payload QRIS tidak valid"), 400
    with closing(get_db()) as conn:
        conn.execute("UPDATE users SET qris_static=? WHERE id=?", (payload, user_id))
        conn.commit()
    return jsonify(ok=True)

@app.route("/decode", methods=["POST"])
def decode():
    if cv2 is None or np is None:
        return jsonify(error="Pemindaian QR gambar belum tersedia di perangkat ini"), 501
    if "image" not in request.files:
        return jsonify(error="Tidak ada gambar"), 400
    f = request.files["image"]
    try:
        img_bytes = np.frombuffer(f.read(), np.uint8)
        img = cv2.imdecode(img_bytes, cv2.IMREAD_COLOR)
    except Exception:
        return jsonify(error="Gambar tidak valid"), 400
    if img is None:
        return jsonify(error="Gambar tidak valid"), 400
    if max(img.shape[:2]) > 1000:
        scale = 1000 / max(img.shape[:2])
        img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    if not data:
        return jsonify(error="QR tidak terdeteksi"), 400
    return jsonify(payload=data)

@app.route("/img/<token>.png")
def img(token):
    cleanup_qr()
    d = QR_STORE.get(token)
    if not d:
        abort(404)
    if datetime.now() > d["expires_at"]:
        QR_STORE.pop(token, None)
        return "QR kadaluarsa", 410
    return send_file(io.BytesIO(d["png"]), mimetype="image/png")

# ---------- RECEIPT ----------
@app.route("/receipt/<int:tx_id>.png")
def receipt(tx_id):
    user_id = session["user_id"]
    with closing(get_db()) as conn:
        row = conn.execute("""
            SELECT l.id, l.type, l.method, l.title, l.amount, l.created_at, l.items_json,
                   u.store_name
            FROM ledger l
            JOIN users u ON u.id = l.user_id
            WHERE l.id = ? AND l.user_id = ?
        """, (tx_id, user_id)).fetchone()
    if not row:
        abort(404)
    return send_file(io.BytesIO(make_receipt_bytes(row)), mimetype="image/png",
                     download_name=f"struk-QGN-{tx_id:06d}.png")

@app.route("/receipt/<int:tx_id>.pdf")
def receipt_pdf(tx_id):
    user_id = session["user_id"]
    with closing(get_db()) as conn:
        row = conn.execute("""
            SELECT l.id, l.type, l.method, l.title, l.amount, l.created_at, l.items_json,
                   u.store_name
            FROM ledger l JOIN users u ON u.id=l.user_id
            WHERE l.id=? AND l.user_id=?
        """, (tx_id, user_id)).fetchone()
    if not row:
        abort(404)
    image = Image.open(io.BytesIO(make_receipt_bytes(row))).convert("RGB")
    output = io.BytesIO()
    image.save(output, format="PDF", resolution=150.0)
    output.seek(0)
    return send_file(output, mimetype="application/pdf", as_attachment=True,
                     download_name=f"struk-QGN-{tx_id:06d}.pdf")

# ---------- CHART API ----------
@app.route("/api/chart")
def api_chart():
    if os.environ.get("QGEN_DEMO") == "1":
        range_ = request.args.get("range", "7d")
        if range_ not in ("1d", "7d", "30d", "3m"):
            return jsonify(ok=False, error="Range tidak valid"), 400

        count = {"1d": 8, "7d": 7, "30d": 10, "3m": 7}[range_]
        demo_buckets = []
        for i in range(count):
            inc = [18000, 32000, 45000, 28000, 58000, 39000, 52000][i % 7]
            exp = [5000, 8000, 12000, 6000, 15000, 9000, 11000][i % 7]
            label = f"{i + 8:02d}" if range_ == "1d" else f"Hari {i + 1}"
            demo_buckets.append({
                "label": label,
                "full_label": label,
                "income": inc,
                "expense": exp,
            })

        total_inc = sum(b["income"] for b in demo_buckets)
        total_exp = sum(b["expense"] for b in demo_buckets)
        peak = max(demo_buckets, key=lambda b: b["income"])
        return jsonify(
            ok=True, buckets=demo_buckets,
            total_income=total_inc, total_expense=total_exp,
            peak_label=peak["full_label"], peak_amount=peak["income"],
        )

    user_id = session["user_id"]
    range_ = request.args.get("range", "7d")
    now = datetime.now()
    day_names = ["Sen","Sel","Rab","Kam","Jum","Sab","Min"]

    with closing(get_db()) as conn:
        if range_ == "1d":
            today = now.strftime("%Y-%m-%d")
            rows = conn.execute("""
                SELECT CAST(strftime('%H', created_at) AS INTEGER) h,
                       SUM(CASE WHEN type='income' THEN amount ELSE 0 END) inc,
                       SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) exp
                FROM ledger WHERE user_id=? AND date(created_at)=?
                GROUP BY h
            """, (user_id, today)).fetchall()
            rmap = {r["h"]: r for r in rows}
            buckets = []
            for h in range(24):
                r = rmap.get(h)
                buckets.append({
                    "label": f"{h:02d}",
                    "full_label": f"Jam {h:02d}:00 – {h:02d}:59",
                    "income": (r["inc"] if r is not None else 0) or 0,
                    "expense": (r["exp"] if r is not None else 0) or 0,
                })

        elif range_ == "7d":
            start = (now - timedelta(days=6)).strftime("%Y-%m-%d")
            rows = conn.execute("""
                SELECT date(created_at) d,
                       SUM(CASE WHEN type='income' THEN amount ELSE 0 END) inc,
                       SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) exp
                FROM ledger WHERE user_id=? AND date(created_at)>=?
                GROUP BY d
            """, (user_id, start)).fetchall()
            rmap = {r["d"]: r for r in rows}
            buckets = []
            for i in range(7):
                d = now - timedelta(days=6 - i)
                key = d.strftime("%Y-%m-%d")
                r = rmap.get(key)
                buckets.append({
                    "label": day_names[d.weekday()],
                    "full_label": d.strftime("%d/%m/%Y"),
                    "income": (r["inc"] if r is not None else 0) or 0,
                    "expense": (r["exp"] if r is not None else 0) or 0,
                })

        elif range_ == "30d":
            start = (now - timedelta(days=29)).strftime("%Y-%m-%d")
            rows = conn.execute("""
                SELECT date(created_at) d,
                       SUM(CASE WHEN type='income' THEN amount ELSE 0 END) inc,
                       SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) exp
                FROM ledger WHERE user_id=? AND date(created_at)>=?
                GROUP BY d
            """, (user_id, start)).fetchall()
            rmap = {r["d"]: (r["inc"] or 0, r["exp"] or 0) for r in rows}
            buckets = []
            for i in range(0, 30, 3):
                inc = exp = 0
                for j in range(i, min(i + 3, 30)):
                    d = (now - timedelta(days=29 - j)).strftime("%Y-%m-%d")
                    if d in rmap:
                        inc += rmap[d][0]; exp += rmap[d][1]
                s_d = now - timedelta(days=29 - i)
                e_d = now - timedelta(days=29 - min(i + 2, 29))
                buckets.append({
                    "label": f"{s_d.day}-{e_d.day}",
                    "full_label": f"{s_d.strftime('%d/%m')} – {e_d.strftime('%d/%m')}",
                    "income": inc, "expense": exp,
                })

        elif range_ == "3m":
            start = (now - timedelta(days=89)).strftime("%Y-%m-%d")
            rows = conn.execute("""
                SELECT date(created_at) d,
                       SUM(CASE WHEN type='income' THEN amount ELSE 0 END) inc,
                       SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) exp
                FROM ledger WHERE user_id=? AND date(created_at)>=?
                GROUP BY d
            """, (user_id, start)).fetchall()
            rmap = {r["d"]: (r["inc"] or 0, r["exp"] or 0) for r in rows}
            buckets = []
            for i in range(0, 90, 14):
                inc = exp = 0
                for j in range(i, min(i + 14, 90)):
                    d = (now - timedelta(days=89 - j)).strftime("%Y-%m-%d")
                    if d in rmap:
                        inc += rmap[d][0]; exp += rmap[d][1]
                s_d = now - timedelta(days=89 - i)
                e_d = now - timedelta(days=89 - min(i + 13, 89))
                buckets.append({
                    "label": s_d.strftime("%d/%m"),
                    "full_label": f"{s_d.strftime('%d/%m')} – {e_d.strftime('%d/%m')}",
                    "income": inc, "expense": exp,
                })
        else:
            return jsonify(ok=False, error="Range tidak valid"), 400

    total_inc = sum(b["income"] for b in buckets)
    total_exp = sum(b["expense"] for b in buckets)
    peak = max(buckets, key=lambda b: b["income"]) if buckets else {"income": 0, "full_label": "-"}

    return jsonify(
        ok=True, buckets=buckets,
        total_income=total_inc, total_expense=total_exp,
        peak_label=peak["full_label"], peak_amount=peak["income"],
    )

# ---------------- MAIN ----------------
if __name__ == "__main__":
    print("\n✨ Qgen v4 siap di http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
