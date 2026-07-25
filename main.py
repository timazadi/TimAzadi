import asyncio
import secrets
import socket
import time
from datetime import datetime, timedelta
from urllib.parse import quote

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import os

from state import (
    logger, CONFIG, sanitize_text,
    connections, stats, error_logs, activity_logs, hourly_traffic,
    LINKS, LINKS_LOCK, SUBS, SUBS_LOCK,
    PROTOCOLS, DEFAULT_PROTOCOL, log_activity,
    SESSION_COOKIE, SESSION_TTL, hash_password, verify_password, is_legacy_hash, AUTH,
    SESSIONS, SESSIONS_LOCK,
    create_session, is_valid_session, destroy_session, require_auth,
    load_state, save_state,
    get_host, generate_uuid, now_ir, generate_vless_link, generate_all_vless_links, uptime,
    parse_size_to_bytes, is_link_expired, is_link_allowed, fmt_bytes, client_ip,
    ensure_default_link,
    check_login_rate_limit, record_login_attempt,
    is_blocked_proxy_target,
    parse_expiry_to_timedelta, sub_permissions,
    is_device_allowed, TELEGRAM_SETTINGS, daily_traffic, link_daily_traffic,
    JOIN_SETTINGS, USER_LINKS,
    get_join_settings, update_join_settings,
    create_join_link, check_channel_membership,
    PUBLIC_SETTINGS,
    FILTER_SETTINGS, refresh_adult_blocklist,
)

from rate_limiter import check_rate_limit

_public_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
_extra_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
ALLOWED_ORIGINS = list({
    *( [f"https://{_public_domain}"] if _public_domain else [] ),
    *_extra_origins,
}) or ["http://localhost:8000"]

SECURE_COOKIES = os.environ.get("DISABLE_SECURE_COOKIE", "0") != "1"

_sub_cache = {}
CACHE_TTL = 30

def get_cached_sub(key: str):
    now = time.time()
    if key in _sub_cache and _sub_cache[key]["expires"] > now:
        return _sub_cache[key]["data"]
    return None

def set_cached_sub(key: str, content: bytes, media_type: str, headers: dict):
    _sub_cache[key] = {
        "data": {
            "content": content,
            "media_type": media_type,
            "headers": headers
        },
        "expires": time.time() + CACHE_TTL
    }

def clear_sub_cache():
    _sub_cache.clear()

_save_task = None
SAVE_DELAY = 10

async def schedule_save():
    global _save_task
    if _save_task and not _save_task.done():
        _save_task.cancel()
        try:
            await _save_task
        except asyncio.CancelledError:
            pass
    _save_task = asyncio.create_task(delayed_save())

async def delayed_save():
    await asyncio.sleep(SAVE_DELAY)
    await save_state()

app = FastAPI(title="تیم آزادی Gateway", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """دفاع در عمق: حتی اگر یک‌جا فراموش شد ورودی escape شود، این هدرها جلوی
    اجرای اسکریپت از دامنه‌های خارجی (مثل حمله‌ی اخیر sftaq.ir) و embed غیرمجاز
    پنل داخل iframe سایت‌های دیگر را می‌گیرند."""
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        # ✅ فیکس: Chart.js داشبورد از cdnjs لود می‌شود؛ قبلاً script-src فقط
        # 'self' بود و این کتابخانه بی‌صدا بلاک می‌شد (چارت داشبورد لود نمی‌شد).
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        # ✅ فیکس: فونت Vazirmatn (fonts.googleapis.com) و CSS آیکون‌های Tabler
        # (cdn.jsdelivr.net) شیت‌های استایل خارجی هستند؛ قبلاً style-src فقط
        # 'self' بود پس این دو بی‌صدا بلاک می‌شدند → بدون فونت فارسی و بدون
        # هیچ آیکونی (دقیقاً همان چیزی که صفحه‌ی ساب/لاگین/داشبورد را «یه‌جوری»
        # و ناقص نشان می‌داد).
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        # ✅ فیکس: فایل واقعیِ فونت‌ها از fonts.gstatic.com سرو می‌شود و فونت
        # آیکون Tabler هم از cdn.jsdelivr.net؛ font-src اصلاً تعریف نشده بود و
        # به default-src 'self' سقوط می‌کرد → فونت‌ها دانلود نمی‌شدند.
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
        # ✅ فیکس: عکس QR کد از api.qrserver.com لود می‌شود؛ قبلاً img-src این
        # دامنه را نداشت → مودال QR همیشه یک عکس شکسته نشان می‌داد.
        "img-src 'self' data: blob: https://api.qrserver.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    if SECURE_COOKIES:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


http_client: httpx.AsyncClient | None = None

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2MB — کافی برای این پنل، جلوی درخواست‌های حجیم مخرب را می‌گیرد

@app.middleware("http")
async def _harden_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "درخواست بیش از حد بزرگ است"}, status_code=413)
    try:
        response = await call_next(request)
    except Exception as exc:
        # هرگز نباید یک اکسپشن مدیریت‌نشده کل ورکر یونیکورن را از کار بیندازد یا
        # جزئیات داخلی را به کلاینت لو بدهد؛ اینجا لاگ می‌کنیم و یک ۵۰۰ تمیز برمی‌گردانیم.
        logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
        try:
            stats["total_errors"] += 1
            error_logs.append({"error": str(exc), "url": str(request.url), "time": datetime.now().isoformat()})
        except Exception:
            pass
        response = JSONResponse({"detail": "خطای داخلی سرور"}, status_code=500)
    response.headers["server"] = "nginx"
    response.headers.setdefault("x-content-type-options", "nosniff")
    response.headers.setdefault("referrer-policy", "no-referrer")
    response.headers.setdefault("x-frame-options", "SAMEORIGIN")
    return response

async def send_telegram_message(text: str) -> tuple[bool, str]:
    token = TELEGRAM_SETTINGS.get("bot_token")
    chat_id = TELEGRAM_SETTINGS.get("chat_id")
    if not token or not chat_id:
        return False, "توکن بات یا چت‌آیدی تنظیم نشده"
    if http_client is None:
        return False, "سرور هنوز آماده نیست"
    api_ip = (TELEGRAM_SETTINGS.get("api_ip") or "").strip()
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    try:
        if api_ip:
            host_for_url = f"[{api_ip}]" if ":" in api_ip else api_ip
            url = f"https://{host_for_url}/bot{token}/sendMessage"
            resp = await http_client.post(
                url,
                json=payload,
                headers={"Host": "api.telegram.org"},
                extensions={"sni_hostname": "api.telegram.org"},
                timeout=15.0,
            )
        else:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            resp = await http_client.post(url, json=payload, timeout=15.0)
        if resp.status_code == 200:
            return True, "ok"
        return False, f"تلگرام خطا داد: {resp.status_code}"
    except Exception as e:
        return False, f"خطا در اتصال به تلگرام: {e}"

async def telegram_notifier_loop():
    while True:
        try:
            if TELEGRAM_SETTINGS.get("enabled") and TELEGRAM_SETTINGS.get("bot_token") and TELEGRAM_SETTINGS.get("chat_id"):
                quota_pct = TELEGRAM_SETTINGS.get("notify_quota_pct", 90)
                expiry_hours = TELEGRAM_SETTINGS.get("notify_expiry_hours", 24)
                async with LINKS_LOCK:
                    items = list(LINKS.items())
                for uid, link in items:
                    label = link.get("label", uid)
                    limit_bytes = link.get("limit_bytes", 0)
                    used_bytes = link.get("used_bytes", 0)
                    if limit_bytes > 0 and not link.get("quota_notified"):
                        pct = used_bytes / limit_bytes * 100
                        if pct >= quota_pct:
                            ok, _ = await send_telegram_message(
                                f"⚠️ <b>{label}</b>\nمصرف به {pct:.0f}٪ از سقف رسید ({fmt_bytes(used_bytes)} از {fmt_bytes(limit_bytes)})."
                            )
                            if ok:
                                link["quota_notified"] = True
                    exp_at = link.get("expires_at")
                    if exp_at and not link.get("expiry_notified"):
                        try:
                            remaining = (datetime.fromisoformat(exp_at) - datetime.now()).total_seconds() / 3600
                        except Exception:
                            remaining = None
                        if remaining is not None and 0 < remaining <= expiry_hours:
                            ok, _ = await send_telegram_message(
                                f"⏰ <b>{label}</b>\nکمتر از {expiry_hours} ساعت تا انقضا مانده."
                            )
                            if ok:
                                link["expiry_notified"] = True
        except Exception as e:
            logger.warning(f"telegram_notifier_loop error: {e}")
        await asyncio.sleep(300)

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True,
    )
    await load_state()
    if os.environ.get("ADMIN_PASSWORD") is None:
        logger.warning("ADMIN_PASSWORD در env تنظیم نشده")
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    asyncio.create_task(telegram_notifier_loop())
    if FILTER_SETTINGS.get("block_adult"):
        # اگه ادمین قبلاً فیلتر بزرگسال رو فعال کرده، همون اول لیست رو در پس‌زمینه دانلود کن
        # (بدون این‌که استارتاپ سرور رو معطل کنه)
        asyncio.create_task(refresh_adult_blocklist())
    try:
        import telegram_bot
        asyncio.create_task(telegram_bot.polling_loop())
        asyncio.create_task(telegram_bot.channel_watch_loop())
    except Exception as e:
        # اگر بات تلگرام هر مشکلی داشت (توکن غلط، خطای import و ...) نباید کل سرور
        # بالا نیاید؛ فقط این قسمت غیرفعال می‌ماند و بقیه‌ی پنل کار می‌کند.
        logger.error(f"telegram_bot could not start: {e}")
    loop_name = type(asyncio.get_event_loop()).__module__
    is_fast_loop = "uvloop" in loop_name
    logger.info(f"event loop: {loop_name} ({'⚡ uvloop فعال است' if is_fast_loop else '⚠️ uvloop فعال نیست — uvloop را در requirements.txt نصب کن تا throughput بهتری بگیری'})")
    logger.info(f"تیم آزادی Gateway v10.0 started on port {CONFIG['port']}")

@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()

_DECOY_HOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#fafafa;color:#333;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center}
h1{font-weight:500;font-size:22px;color:#555}
p{color:#888;font-size:14px}
</style>
</head>
<body>
<div class="box">
<h1>Site is running</h1>
<p>If you are the owner of this site, check back soon.</p>
</div>
</body>
</html>"""

@app.get("/")
async def root():
    # قبلاً اینجا یک JSON خام برمی‌گشت ({"status":"ok"})، که خودش یک امضای قابل‌تشخیص
    # برای اسکنرها/پروب‌های فعال است — یک سایت واقعی معمولاً HTML برمی‌گرداند، نه JSON API.
    # یک IP که با پروب دیدن «این یک بک‌اند/API است» علامت‌گذاری بشود، شانس بیشتری برای
    # قرار گرفتن در فهرست بلاک دارد. این‌جا الان یک صفحه‌ی ساده و بی‌ربط (decoy) نشان داده می‌شود.
    return HTMLResponse(_DECOY_HOME_HTML)

@app.get("/health")
async def health():
    return JSONResponse({"status": "ok"})

@app.get("/api/health")
async def health_admin(_=Depends(require_auth)):
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.get("/sub/{uuid}")
async def subscription_single(uuid: str, request: Request):
    import base64
    
    ip = client_ip(request)
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="درخواست‌های شما زیاد است، لطفاً ۳۰ ثانیه صبر کنید")
    
    cache_key = f"sub_{uuid}_{request.query_params.get('pw', '')}"
    cached = get_cached_sub(cache_key)
    if cached:
        return Response(
            content=cached["content"],
            media_type=cached["media_type"],
            headers=cached["headers"]
        )
    
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")

    host = get_host()
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    used_bytes = link.get("used_bytes", 0)
    limit_bytes = link.get("limit_bytes", 0)
    owning_sub = SUBS.get(link.get("sub_id")) if link.get("sub_id") else None
    white_label = bool(link.get("white_label")) or bool(owning_sub and owning_sub.get("white_label"))
    bundle = generate_all_vless_links(uuid, host, link["label"], used_bytes, limit_bytes, brand=not white_label, flag=link.get("flag", ""))
    vless = next((b["vless_link"] for b in bundle if b["protocol"] == proto), bundle[0]["vless_link"])
    sub_url = f"https://{host}/sub/{uuid}"

    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        from pages import get_single_link_page_html
        link_data = {
            "uuid": uuid,
            **link,
            "expired": is_link_expired(link),
            "vless_link": vless,
            "vless_links": bundle,
            "sub_url": sub_url,
            "used_fmt": fmt_bytes(used_bytes),
            "limit_fmt": "∞" if limit_bytes == 0 else fmt_bytes(limit_bytes),
            "protocol": proto,
            "white_label": white_label,
        }
        return HTMLResponse(content=get_single_link_page_html(uuid, link_data))

    content = base64.b64encode("\n".join(b["vless_link"] for b in bundle).encode()).decode()
    headers = {"profile-title": quote(link["label"])}
    if not white_label:
        headers["support-url"] = "https://t.me/TimAzadi"
    
    set_cached_sub(cache_key, content.encode(), "text/plain", headers)
    return Response(content=content, media_type="text/plain", headers=headers)

@app.get("/sub-all")
async def subscription_all(_=Depends(require_auth)):
    import base64
    host = get_host()
    async with LINKS_LOCK:
        lines = []
        for uid, d in LINKS.items():
            if is_link_allowed(d):
                bundle = generate_all_vless_links(uid, host, d["label"], d.get("used_bytes", 0), d.get("limit_bytes", 0), flag=d.get("flag", ""))
                lines.extend(b["vless_link"] for b in bundle)
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")

MAX_CHILDREN_PER_LINK = 50
MIN_SPLIT_BYTES = 1 * 1024 * 1024

def _child_view(uid: str, d: dict, host: str, perms: dict | None = None) -> dict:
    perms = perms or {"client_can_delete": True, "client_can_disable": True}
    return {
        "uuid": uid,
        "label": d["label"],
        "used_bytes": d.get("used_bytes", 0),
        "used_fmt": fmt_bytes(d.get("used_bytes", 0)),
        "limit_bytes": d.get("limit_bytes", 0),
        "limit_fmt": "∞" if not d.get("limit_bytes") else fmt_bytes(d["limit_bytes"]),
        "active": d.get("active", True),
        "expired": is_link_expired(d),
        "expires_at": d.get("expires_at"),
        "created_at": d.get("created_at"),
        "sub_url": f"https://{host}/sub/{uid}",
        "client_can_delete": perms["client_can_delete"],
        "client_can_disable": perms["client_can_disable"],
    }

@app.post("/api/public/split/{uuid}")
async def create_split_child(uuid: str, request: Request):
    if not PUBLIC_SETTINGS.get("allow_public_create", True):
        raise HTTPException(status_code=403, detail="ساخت کانفیگ عمومی غیرفعال شده است")
    
    ip = client_ip(request)
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="درخواست‌های شما زیاد است، لطفاً کمی صبر کنید")
    body = await request.json()
    amount = float(body.get("amount") or 0)
    unit = body.get("unit") or "GB"
    label = sanitize_text(body.get("label") or "اشتراکی", 60)
    exp_delta = parse_expiry_to_timedelta(float(body.get("expires_value") or 0), body.get("expires_unit") or "days")
    child_expires_at = (datetime.now() + exp_delta).isoformat() if exp_delta else None
    if amount <= 0:
        raise HTTPException(status_code=400, detail="مقدار حجم نامعتبر است")
    amount_bytes = parse_size_to_bytes(amount, unit)
    if amount_bytes < MIN_SPLIT_BYTES:
        raise HTTPException(status_code=400, detail="حداقل حجم قابل‌جداسازی ۱ مگابایت است")

    host = get_host()
    async with LINKS_LOCK:
        parent = LINKS.get(uuid)
        if not parent or not is_link_allowed(parent):
            raise HTTPException(status_code=404, detail="not found or inactive")
        n_children = sum(1 for d in LINKS.values() if d.get("parent_id") == uuid)
        if n_children >= MAX_CHILDREN_PER_LINK:
            raise HTTPException(status_code=400, detail="سقف تعداد ساب‌های ساخته‌شده از این لینک پر شده")

        parent_limit = parent.get("limit_bytes", 0)
        if parent_limit > 0:
            remaining = parent_limit - parent.get("used_bytes", 0)
            if amount_bytes > remaining:
                raise HTTPException(status_code=400, detail="این مقدار بیشتر از سهمیه‌ی باقی‌مانده‌ی توست")
            parent["limit_bytes"] = parent_limit - amount_bytes

        child_uid = generate_uuid()
        LINKS[child_uid] = {
            "label": label,
            "limit_bytes": amount_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": child_expires_at,
            "note": "",
            "is_default": False,
            "sub_id": None,
            "protocol": parent.get("protocol", DEFAULT_PROTOCOL),
            "parent_id": uuid,
            "white_label": True,
            "flag": parent.get("flag", "🇺🇸"),
        }
        perms = sub_permissions(parent.get("sub_id"))
        parent_view = _child_view(uuid, parent, host, perms)
        child_view = _child_view(child_uid, LINKS[child_uid], host, perms)

    clear_sub_cache()
    await schedule_save()
    log_activity("link", f"سهمیه‌ی «{fmt_bytes(amount_bytes)}» از «{parent['label']}» جدا و ساب جدید «{label}» ساخته شد", "ok")
    return {"child": child_view, "parent": parent_view}

@app.get("/api/public/children/{uuid}")
async def list_split_children(uuid: str):
    host = get_host()
    async with LINKS_LOCK:
        if uuid not in LINKS:
            raise HTTPException(status_code=404, detail="not found")
        parent = LINKS[uuid]
        perms = sub_permissions(parent.get("sub_id"))
        children = [_child_view(uid, d, host, perms) for uid, d in LINKS.items() if d.get("parent_id") == uuid]
    children.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return {"children": children, "permissions": perms}

@app.delete("/api/public/split/{uuid}/{child_uuid}")
async def revoke_split_child(uuid: str, child_uuid: str, request: Request):
    if not PUBLIC_SETTINGS.get("allow_public_delete", True):
        raise HTTPException(status_code=403, detail="حذف کانفیگ عمومی غیرفعال شده است")
    ip = client_ip(request)
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="درخواست‌های شما زیاد است، لطفاً کمی صبر کنید")

    host = get_host()
    async with LINKS_LOCK:
        parent = LINKS.get(uuid)
        child = LINKS.get(child_uuid)
        if not parent or not child or child.get("parent_id") != uuid:
            raise HTTPException(status_code=404, detail="not found")
        if not sub_permissions(parent.get("sub_id"))["client_can_delete"]:
            raise HTTPException(status_code=403, detail="حذف کانفیگ‌های هدیه‌ای توسط مدیر غیرفعال شده است")
        if parent.get("limit_bytes", 0) > 0:
            unused = max(0, child.get("limit_bytes", 0) - child.get("used_bytes", 0))
            parent["limit_bytes"] += unused
        del LINKS[child_uuid]
        connections.pop(child_uuid, None)
        parent_view = _child_view(uuid, parent, host, sub_permissions(parent.get("sub_id")))

    clear_sub_cache()
    await schedule_save()
    log_activity("link", f"ساب «{child['label']}» لغو شد", "warn")
    return {"parent": parent_view}

@app.post("/api/public/split/{uuid}/{child_uuid}/toggle")
async def toggle_split_child(uuid: str, child_uuid: str, request: Request):
    if not PUBLIC_SETTINGS.get("allow_public_toggle", True):
        raise HTTPException(status_code=403, detail="تغییر وضعیت کانفیگ عمومی غیرفعال شده است")
    ip = client_ip(request)
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="درخواست‌های شما زیاد است، لطفاً کمی صبر کنید")
    body = await request.json()
    active = bool(body.get("active", True))
    host = get_host()
    async with LINKS_LOCK:
        parent = LINKS.get(uuid)
        child = LINKS.get(child_uuid)
        if not parent or not child or child.get("parent_id") != uuid:
            raise HTTPException(status_code=404, detail="not found")
        if not sub_permissions(parent.get("sub_id"))["client_can_disable"]:
            raise HTTPException(status_code=403, detail="فعال/غیرفعال‌کردن کانفیگ‌های هدیه‌ای توسط مدیر غیرفعال شده است")
        child["active"] = active
        child_view = _child_view(child_uuid, child, host, sub_permissions(parent.get("sub_id")))
    
    clear_sub_cache()
    await schedule_save()
    log_activity("link", f"کانفیگ هدیه‌ای «{child['label']}» {'فعال' if active else 'غیرفعال'} شد", "ok" if active else "warn")
    return {"child": child_view}

@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = sanitize_text(body.get("name") or "گروه جدید", 60)
    desc = sanitize_text(body.get("desc") or "", 200)
    password = (body.get("password") or "").strip()
    pool_value = float(body.get("pool_value") or 0)
    pool_unit = str(body.get("pool_unit") or "GB")
    pool_limit_bytes = parse_size_to_bytes(pool_value, pool_unit) if pool_value > 0 else 0
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key": uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [],
            "pool_limit_bytes": pool_limit_bytes,
            "pool_allocated_bytes": 0,
            "parent_sub_id": None,
            "child_sub_ids": [],
            "white_label": False,
            "locked": False,
            "client_can_delete": bool(body.get("client_can_delete", True)),
            "client_can_disable": bool(body.get("client_can_disable", True)),
        }
    clear_sub_cache()
    await schedule_save()
    log_activity("sub", f"گروه «{name}» ساخته شد", "ok")
    host = get_host()
    return {
        "sub_id": sub_id,
        **SUBS[sub_id],
        "public_url": f"https://{host}/p/{uuid_key}",
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
    }

@app.get("/api/subs")
async def list_subs(_=Depends(require_auth)):
    host = get_host()
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        link_ids = s.get("link_ids", [])
        active_count = sum(1 for lid in link_ids if is_link_allowed(snap_links.get(lid)))
        total_used = sum(snap_links[lid].get("used_bytes", 0) for lid in link_ids if lid in snap_links)
        pool_limit = s.get("pool_limit_bytes", 0)
        pool_alloc = s.get("pool_allocated_bytes", 0)
        result.append({
            "sub_id": sid,
            **s,
            "password_hash": None,
            "has_password": s.get("password_hash") is not None,
            "links_count": len(link_ids),
            "active_count": active_count,
            "total_used_bytes": total_used,
            "total_used_fmt": fmt_bytes(total_used),
            "pool_limit_bytes": pool_limit,
            "pool_allocated_bytes": pool_alloc,
            "pool_available_bytes": max(0, pool_limit - pool_alloc) if pool_limit else 0,
            "pool_limit_fmt": fmt_bytes(pool_limit) if pool_limit else "—",
            "pool_available_fmt": fmt_bytes(max(0, pool_limit - pool_alloc)) if pool_limit else "—",
            "public_url": f"https://{host}/p/{s['uuid_key']}",
            "sub_url": f"https://{host}/sub-group/{s['uuid_key']}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"subs": result}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        if "name" in body:
            s["name"] = sanitize_text(body["name"], 60)
        if "desc" in body:
            s["desc"] = sanitize_text(body["desc"], 200)
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = hash_password(pw) if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
        if "pool_value" in body:
            pool_value = float(body.get("pool_value") or 0)
            pool_unit = str(body.get("pool_unit") or "GB")
            s["pool_limit_bytes"] = parse_size_to_bytes(pool_value, pool_unit) if pool_value > 0 else 0
            s.setdefault("pool_allocated_bytes", 0)
        if "client_can_delete" in body:
            s["client_can_delete"] = bool(body["client_can_delete"])
        if "client_can_disable" in body:
            s["client_can_disable"] = bool(body["client_can_disable"])
        if "locked" in body:
            s["locked"] = bool(body["locked"])
    clear_sub_cache()
    await schedule_save()
    return {"ok": True}

@app.post("/api/subs/{sub_id}/lock")
async def toggle_sub_lock(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    locked = bool(body.get("locked", True))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        SUBS[sub_id]["locked"] = locked
        name = SUBS[sub_id].get("name", sub_id)
    clear_sub_cache()
    await schedule_save()
    log_activity("sub", f"گروه «{name}» {'قفل' if locked else 'باز'} شد", "warn" if locked else "ok")
    return {"ok": True, "locked": locked}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        name = SUBS[sub_id].get("name", sub_id)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    clear_sub_cache()
    await schedule_save()
    log_activity("sub", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": sub_id}

@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    link_id = str(body.get("link_id", ""))
    action = str(body.get("action", "add"))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        ids = s.setdefault("link_ids", [])
        if action == "add":
            if link_id not in ids:
                ids.append(link_id)
        else:
            if link_id in ids:
                ids.remove(link_id)
    async with LINKS_LOCK:
        if link_id in LINKS:
            LINKS[link_id]["sub_id"] = sub_id if action == "add" else None
    clear_sub_cache()
    await schedule_save()
    return {"ok": True}

@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    import base64
    
    ip = client_ip(request)
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="درخواست‌های شما زیاد است، لطفاً ۳۰ ثانیه صبر کنید")
    
    cache_key = f"subgroup_{uuid_key}_{request.query_params.get('pw', '')}"
    cached = get_cached_sub(cache_key)
    if cached:
        return Response(
            content=cached["content"],
            media_type=cached["media_type"],
            headers=cached["headers"]
        )
    
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")

    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="wrong password")

    host = get_host()
    link_ids = sub.get("link_ids", [])
    white_label = bool(sub.get("white_label"))
    async with LINKS_LOCK:
        lines = []
        for lid in link_ids:
            link = LINKS.get(lid)
            if link and is_link_allowed(link):
                bundle = generate_all_vless_links(lid, host, link["label"], link.get("used_bytes", 0), link.get("limit_bytes", 0), brand=not white_label, flag=link.get("flag", ""))
                lines.extend(b["vless_link"] for b in bundle)

    content = base64.b64encode("\n".join(lines).encode()).decode()
    headers = {"profile-title": quote(sub["name"]), "profile-update-interval": "12"}
    if not white_label:
        headers["support-url"] = "https://t.me/TimAzadi"
    
    set_cached_sub(cache_key, content.encode(), "text/plain", headers)
    return Response(content=content, media_type="text/plain", headers=headers)

@app.post("/api/login")
async def api_login(request: Request):
    ip = client_ip(request)
    if not await check_login_rate_limit(ip):
        log_activity("auth", f"مسدود شدن موقت تلاش‌های ورود از {ip}", "err")
        raise HTTPException(status_code=429, detail="تعداد تلاش‌ها بیش از حد است")
    body = await request.json()
    password = str(body.get("password", ""))
    if not verify_password(password, AUTH["password_hash"]):
        await record_login_attempt(ip)
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    if is_legacy_hash(AUTH["password_hash"]):
        AUTH["password_hash"] = hash_password(password)
        await schedule_save()
    token = await create_session()
    log_activity("auth", f"ورود موفق به پنل از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE, token, max_age=SESSION_TTL,
        httponly=True, samesite="lax", secure=SECURE_COOKIES, path="/",
    )
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}

@app.post("/api/change-password")
async def api_change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    if not verify_password(str(body.get("current_password", "")), AUTH["password_hash"]):
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = str(body.get("new_password", ""))
    if len(new) < 10:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۱۰ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await schedule_save()
    log_activity("auth", "رمز عبور پنل تغییر کرد", "ok")
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
        "subs_count": len(SUBS),
    }

@app.get("/api/activity")
async def get_activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[-150:]}

@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    grouped: dict[str, dict] = {}
    for conn_id, c in connections.items():
        ip = c.get("ip", "نامشخص")
        link = snap.get(c.get("uuid"))
        label = link.get("label") if link else "نامشخص"
        g = grouped.get(ip)
        if g is None:
            g = {
                "ip": ip,
                "sessions": 0,
                "bytes": 0,
                "labels": set(),
                "transports": set(),
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            grouped[ip] = g
        g["sessions"] += 1
        g["bytes"] += c.get("bytes", 0)
        g["labels"].add(label)
        g["transports"].add(c.get("transport", "vless-ws"))
        ca = c.get("connected_at")
        if ca:
            if not g["first_connected_at"] or ca < g["first_connected_at"]:
                g["first_connected_at"] = ca
            if not g["last_connected_at"] or ca > g["last_connected_at"]:
                g["last_connected_at"] = ca
    result = []
    for ip, g in grouped.items():
        result.append({
            "ip": ip,
            "sessions": g["sessions"],
            "labels": sorted(g["labels"]),
            "label": " · ".join(sorted(g["labels"])) if g["labels"] else "نامشخص",
            "transports": sorted(g["transports"]),
            "bytes": g["bytes"],
            "bytes_fmt": fmt_bytes(g["bytes"]),
            "connected_at": g["first_connected_at"],
            "last_connected_at": g["last_connected_at"],
        })
    result.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)
    return {
        "connections": result,
        "count": len(result),
        "raw_count": len(connections),
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = sanitize_text(body.get("label") or "لینک جدید", 60)
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    if "expires_value" in body:
        exp_delta = parse_expiry_to_timedelta(float(body.get("expires_value") or 0), body.get("expires_unit") or "days")
    else:
        exp_days = int(body.get("expires_days") or 0)
        exp_delta = parse_expiry_to_timedelta(exp_days, "days")
    expires_at = (datetime.now() + exp_delta).isoformat() if exp_delta else None
    note = sanitize_text(body.get("note") or "", 200)
    sub_id = body.get("sub_id") or None
    protocol = body.get("protocol") or DEFAULT_PROTOCOL
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL
    flag = str(body.get("flag") or "🇺🇸").strip()[:8]
    max_devices = max(0, int(body.get("max_devices") or 0))

    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expires_at,
            "note": note,
            "is_default": False,
            "sub_id": sub_id,
            "protocol": protocol,
            "parent_id": None,
            "white_label": False,
            "flag": flag,
            "max_devices": max_devices,
            "quota_notified": False,
            "expiry_notified": False,
        }

    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    clear_sub_cache()
    await schedule_save()
    log_activity("link", f"کانفیگ «{label}» ساخته شد", "ok")
    host = get_host()
    return {
        "uuid": uid,
        **LINKS[uid],
        "expired": False,
        "vless_link": generate_vless_link(uid, host, remark=f"تیم‌آزادی-{label}", protocol=protocol),
        "sub_url": f"https://{host}/sub/{uid}",
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = get_host()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        proto = d.get("protocol", DEFAULT_PROTOCOL)
        used_bytes = d.get("used_bytes", 0)
        limit_bytes = d.get("limit_bytes", 0)
        bundle = generate_all_vless_links(uid, host, d["label"], used_bytes, limit_bytes, flag=d.get("flag", ""))
        link_conns = [c for c in connections.values() if c.get("uuid") == uid]
        result.append({
            "uuid": uid,
            **d,
            "protocol": proto,
            "expired": is_link_expired(d),
            "vless_link": next((b["vless_link"] for b in bundle if b["protocol"] == proto), bundle[0]["vless_link"]),
            "vless_links": bundle,
            "sub_url": f"https://{host}/sub/{uid}",
            "live_connections": len(link_conns),
            "live_unique_ips": len({c.get("ip") for c in link_conns}),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        old_sub = link.get("sub_id")
        label = link.get("label")
        if "active" in body:
            link["active"] = bool(body["active"])
        if "label" in body:
            link["label"] = sanitize_text(body["label"], 60)
        if "note" in body:
            link["note"] = sanitize_text(body["note"], 200)
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
            link["quota_notified"] = False
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
            link["quota_notified"] = False
        if "max_devices" in body:
            link["max_devices"] = max(0, int(body.get("max_devices") or 0))
        if "expires_value" in body:
            exp_delta = parse_expiry_to_timedelta(float(body.get("expires_value") or 0), body.get("expires_unit") or "days")
            if exp_delta:
                link["expires_at"] = (datetime.now() + exp_delta).isoformat()
                link["expiry_notified"] = False
        elif "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            exp_delta = parse_expiry_to_timedelta(ed, "days")
            if exp_delta:
                link["expires_at"] = (datetime.now() + exp_delta).isoformat()
                link["expiry_notified"] = False
        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None

    if new_sub != "UNCHANGED":
        async with SUBS_LOCK:
            if old_sub and old_sub in SUBS:
                ids = SUBS[old_sub].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
            if new_sub and new_sub in SUBS:
                ids = SUBS[new_sub].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    clear_sub_cache()
    await schedule_save()
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        label = LINKS[uid].get("label", uid)
        sub_id = LINKS[uid].get("sub_id")
        del LINKS[uid]
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
    clear_sub_cache()
    await schedule_save()
    log_activity("link", f"کانفیگ «{label}» حذف شد", "err")
    return {"ok": True, "deleted": uid}

@app.get("/api/top-usage")
async def top_usage(limit: int = 10, _=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    conn_by_uid: dict[str, list] = {}
    for c in connections.values():
        conn_by_uid.setdefault(c.get("uuid"), []).append(c)
    rows = []
    for uid, d in snap.items():
        conns = conn_by_uid.get(uid, [])
        rows.append({
            "uuid": uid,
            "label": d.get("label", "?"),
            "used_bytes": d.get("used_bytes", 0),
            "used_fmt": fmt_bytes(d.get("used_bytes", 0)),
            "limit_bytes": d.get("limit_bytes", 0),
            "limit_fmt": "∞" if not d.get("limit_bytes") else fmt_bytes(d["limit_bytes"]),
            "pct": (d.get("used_bytes", 0) / d["limit_bytes"] * 100) if d.get("limit_bytes") else None,
            "live_connections": len(conns),
            "live_unique_ips": len({c.get("ip") for c in conns}),
            "session_bytes": sum(c.get("bytes", 0) for c in conns),
            "active": is_link_allowed(d),
        })
    by_total = sorted(rows, key=lambda r: r["used_bytes"], reverse=True)[:limit]
    by_live = sorted([r for r in rows if r["live_connections"] > 0], key=lambda r: r["session_bytes"], reverse=True)[:limit]
    return {"top_total": by_total, "top_live": by_live}

@app.get("/api/links/{uid}/daily")
async def link_daily_usage(uid: str, days: int = 14, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
    from datetime import timedelta as _td
    today = now_ir().date()
    hist = link_daily_traffic.get(uid, {})
    out = []
    for i in range(days - 1, -1, -1):
        day = today - _td(days=i)
        key = day.strftime("%Y-%m-%d")
        out.append({"date": key, "bytes": hist.get(key, 0), "fmt": fmt_bytes(hist.get(key, 0))})
    return {"days": out}

@app.get("/api/settings/telegram")
async def get_telegram_settings(_=Depends(require_auth)):
    s = dict(TELEGRAM_SETTINGS)
    if s.get("bot_token"):
        s["bot_token_masked"] = s["bot_token"][:6] + "…" + s["bot_token"][-4:]
    return s

@app.post("/api/settings/telegram")
async def set_telegram_settings(request: Request, _=Depends(require_auth)):
    body = await request.json()
    if "enabled" in body:
        TELEGRAM_SETTINGS["enabled"] = bool(body["enabled"])
    if "bot_token" in body and body["bot_token"]:
        TELEGRAM_SETTINGS["bot_token"] = str(body["bot_token"]).strip()
    if "chat_id" in body and body["chat_id"]:
        TELEGRAM_SETTINGS["chat_id"] = str(body["chat_id"]).strip()
    if "notify_quota_pct" in body:
        TELEGRAM_SETTINGS["notify_quota_pct"] = max(1, min(100, int(body["notify_quota_pct"])))
    if "notify_expiry_hours" in body:
        TELEGRAM_SETTINGS["notify_expiry_hours"] = max(1, int(body["notify_expiry_hours"]))
    if "api_ip" in body:
        TELEGRAM_SETTINGS["api_ip"] = str(body["api_ip"] or "").strip()
    if "bot_username" in body and body["bot_username"]:
        TELEGRAM_SETTINGS["bot_username"] = str(body["bot_username"]).strip()
    await schedule_save()
    log_activity("system", "تنظیمات نوتیفیکیشن تلگرام بروزرسانی شد", "ok")
    return {"ok": True}

@app.get("/api/settings/telegram/resolve")
async def resolve_telegram_ip(_=Depends(require_auth)):
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo("api.telegram.org", 443, type=socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        return {"ok": True, "ips": ips}
    except Exception as e:
        return {"ok": False, "detail": f"DNS error: {e}"}

@app.post("/api/settings/telegram/test")
async def test_telegram(_=Depends(require_auth)):
    ok, msg = await send_telegram_message("🔔 این یک پیام تست از پنل تیم‌آزادی Gateway است.")
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"ok": True}

@app.get("/api/settings/public")
async def get_public_settings(_=Depends(require_auth)):
    return PUBLIC_SETTINGS

@app.post("/api/settings/public")
async def set_public_settings(request: Request, _=Depends(require_auth)):
    body = await request.json()
    for key in ["allow_public_create", "allow_public_delete", "allow_public_toggle"]:
        if key in body:
            PUBLIC_SETTINGS[key] = bool(body[key])
    clear_sub_cache()
    await schedule_save()
    log_activity("system", f"تنظیمات عمومی بروزرسانی شد: {body}", "ok")
    return {"ok": True}

@app.get("/api/settings/join")
async def get_join_settings_api(_=Depends(require_auth)):
    return get_join_settings()

@app.post("/api/settings/join")
async def set_join_settings_api(request: Request, _=Depends(require_auth)):
    body = await request.json()
    update_join_settings(body)
    await schedule_save()
    log_activity("system", "تنظیمات عضویت اجباری بروزرسانی شد", "ok")
    return {"ok": True}

@app.get("/api/join/stats")
async def get_join_stats(_=Depends(require_auth)):
    return {"total_users": len(USER_LINKS)}

@app.get("/api/join/user/{user_id}")
async def get_user_join_link(user_id: str, _=Depends(require_auth)):
    uid = USER_LINKS.get(user_id)
    link = None
    if uid:
        async with LINKS_LOCK:
            if uid in LINKS:
                link = {"uuid": uid, **LINKS[uid]}
    return {"user_id": user_id, "link": link}

from relay_vless import websocket_tunnel
app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)

from xhttp_siz10 import router as xhttp_router
app.include_router(xhttp_router)

_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request, _=Depends(require_auth)):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    if await is_blocked_proxy_target(target_url):
        raise HTTPException(status_code=400, detail="این آدرس مجاز نیست")
    MAX_REDIRECTS = 5
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        method = request.method
        url = target_url
        for _hop in range(MAX_REDIRECTS + 1):
            resp = await http_client.request(
                method=method, url=url, headers=headers, content=body, follow_redirects=False,
            )
            if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                next_url = str(httpx.URL(url).join(resp.headers["location"]))
                if await is_blocked_proxy_target(next_url):
                    raise HTTPException(status_code=400, detail="این آدرس مجاز نیست")
                url = next_url
                if resp.status_code == 303:
                    method = "GET"
                    body = b""
                continue
            break
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except HTTPException:
        raise
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")

@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    from pages import get_public_page_html
    ip = client_ip(request)
    if not await check_rate_limit(ip):
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>درخواست‌های شما زیاد است، کمی صبر کنید.</h2>", status_code=429)
    async with SUBS_LOCK:
        sub = next(({"sub_id": sid, **s} for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>گروه پیدا نشد</h2>", status_code=404)
    return HTMLResponse(content=get_public_page_html(uuid_key, white_label=bool(sub.get("white_label"))))

@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    ip = client_ip(request)
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="درخواست‌های شما زیاد است، لطفاً کمی صبر کنید")
    async with SUBS_LOCK:
        sub_entry = next(((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub_entry:
        raise HTTPException(status_code=404, detail="not found")
    sub_id, sub = sub_entry
    has_pw = sub.get("password_hash") is not None
    if has_pw:
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            return JSONResponse({"locked": True, "name": sub["name"]})
    host = get_host()
    link_ids = sub.get("link_ids", [])
    white_label = bool(sub.get("white_label"))
    perms = {"client_can_delete": sub.get("client_can_delete", True), "client_can_disable": sub.get("client_can_disable", True)}
    locked = bool(sub.get("locked"))
    async with LINKS_LOCK:
        snap = dict(LINKS)
    links_out = []
    active_conns = 0
    for lid in link_ids:
        link = snap.get(lid)
        if not link:
            continue
        allowed = is_link_allowed(link)
        conn_count = sum(1 for c in connections.values() if c.get("uuid") == lid)
        active_conns += conn_count
        proto = link.get("protocol", DEFAULT_PROTOCOL)
        used_bytes = link.get("used_bytes", 0)
        limit_bytes = link.get("limit_bytes", 0)
        bundle = generate_all_vless_links(lid, host, link["label"], used_bytes, limit_bytes, brand=not white_label, flag=link.get("flag", ""))
        children = [_child_view(cid, cd, host, perms) for cid, cd in snap.items() if cd.get("parent_id") == lid]
        children.sort(key=lambda x: x["created_at"] or "", reverse=True)
        links_out.append({
            "uuid": lid,
            "label": link["label"],
            "active": allowed,
            "protocol": proto,
            "used_bytes": used_bytes,
            "used_fmt": fmt_bytes(used_bytes),
            "limit_bytes": limit_bytes,
            "limit_fmt": "∞" if limit_bytes == 0 else fmt_bytes(limit_bytes),
            "expires_at": link.get("expires_at"),
            "vless_link": next((b["vless_link"] for b in bundle if b["protocol"] == proto), bundle[0]["vless_link"]),
            "vless_links": bundle,
            "sub_url": f"https://{host}/sub/{lid}",
            "connections": conn_count,
            "flag": link.get("flag", ""),
            "children": children,
        })
    total_used = sum(l["used_bytes"] for l in links_out)
    pool_limit = sub.get("pool_limit_bytes", 0)
    pool_alloc = sub.get("pool_allocated_bytes", 0)
    pool_available = max(0, pool_limit - pool_alloc) if pool_limit else 0
    return {
        "locked": False,
        "name": sub["name"],
        "desc": sub.get("desc", ""),
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
        "active_connections": active_conns,
        "total_used_fmt": fmt_bytes(total_used),
        "links": links_out,
        "white_label": white_label,
        "locked_by_admin": locked,
        "permissions": perms,
        "pool_enabled": pool_limit > 0,
        "pool_limit_bytes": pool_limit,
        "pool_allocated_bytes": pool_alloc,
        "pool_available_bytes": pool_available,
        "pool_limit_fmt": fmt_bytes(pool_limit) if pool_limit else "—",
        "pool_available_fmt": fmt_bytes(pool_available) if pool_limit else "—",
    }

@app.post("/api/public/sub/{uuid_key}/split")
async def split_sub_quota(uuid_key: str, request: Request):
    ip = client_ip(request)
    if not await check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="درخواست‌های شما زیاد است، لطفاً کمی صبر کنید")
    body = await request.json()
    pw = str(body.get("pw", ""))
    amount_value = float(body.get("amount_value") or 0)
    amount_unit = str(body.get("amount_unit") or "GB")
    child_label = sanitize_text(body.get("label") or "کانفیگ هدیه", 60)
    child_name = sanitize_text(body.get("name") or "ساب هدیه", 60)
    async with SUBS_LOCK:
        sub_entry = next(((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
        if not sub_entry:
            raise HTTPException(status_code=404, detail="not found")
        sub_id, sub = sub_entry
        if sub.get("password_hash") and hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="رمز اشتباه است")
        pool_limit = sub.get("pool_limit_bytes", 0)
        if pool_limit <= 0:
            raise HTTPException(status_code=400, detail="این ساب قابلیت تقسیم حجم ندارد")
        pool_alloc = sub.get("pool_allocated_bytes", 0)
        available = max(0, pool_limit - pool_alloc)
        amount_bytes = parse_size_to_bytes(amount_value, amount_unit) if amount_value > 0 else 0
        if amount_bytes <= 0:
            raise HTTPException(status_code=400, detail="حجم نامعتبر است")
        if amount_bytes > available:
            raise HTTPException(status_code=400, detail=f"فقط {fmt_bytes(available)} از این ساب باقی مانده است")
        host = get_host()
        child_uuid = generate_uuid()
        child_sub_id = generate_uuid()
        child_uuid_key = secrets.token_urlsafe(16)
        sub["pool_allocated_bytes"] = pool_alloc + amount_bytes
        sub.setdefault("child_sub_ids", []).append(child_sub_id)
        SUBS[child_sub_id] = {
            "name": child_name,
            "desc": "",
            "password_hash": None,
            "uuid_key": child_uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [child_uuid],
            "pool_limit_bytes": amount_bytes,
            "pool_allocated_bytes": amount_bytes,
            "parent_sub_id": sub_id,
            "child_sub_ids": [],
            "white_label": True,
        }
    async with LINKS_LOCK:
        LINKS[child_uuid] = {
            "label": child_label,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "used_bytes": 0,
            "limit_bytes": amount_bytes,
            "expires_at": None,
            "note": "",
            "protocol": DEFAULT_PROTOCOL,
            "sub_id": child_sub_id,
        }
    clear_sub_cache()
    await schedule_save()
    log_activity("sub", f"«{sub['name']}» مقدار {fmt_bytes(amount_bytes)} را تقسیم کرد", "ok")
    return {
        "ok": True,
        "public_url": f"https://{host}/p/{child_uuid_key}",
        "sub_url": f"https://{host}/sub-group/{child_uuid_key}",
        "amount_fmt": fmt_bytes(amount_bytes),
        "pool_available_fmt": fmt_bytes(max(0, pool_limit - sub['pool_allocated_bytes'])),
    }

from pages import LOGIN_HTML, DASHBOARD_HTML

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/timazadi")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/timazadi", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    await ensure_default_link()
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_redirect(request: Request):
    return RedirectResponse(url="/timazadi")

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/timazadi'</script>")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=CONFIG["port"],
        log_level="info",
        workers=1,
        loop="auto",
        http="auto",
        ws_ping_interval=20.0,
        ws_ping_timeout=20.0,
    )
