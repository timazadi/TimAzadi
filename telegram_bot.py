# telegram_bot.py
# ══════════════════════════════════════════════════════════════════════════════
# مدیریت پنل از طریق بات تلگرام — دو-طرفه (نه فقط نوتیفیکیشن)
# هرکسی وارد بات شود (/start)، پس از تأیید عضویت اجباری در کانال، به‌طور خودکار
# یک کانفیگ اختصاصی با حجم هدیه (پیش‌فرض ۱۰۰GB) دریافت می‌کند. پنل مدیریتی فقط
# برای ادمین (chat_id های تنظیم‌شده) باز است. سیستم رفرال هم اضافه شده: هر کاربر
# یک لینک دعوت اختصاصی دارد و به ازای هر دعوت موفق (عضویت واقعی در کانال) حجم
# هدیه می‌گیرد.
# ══════════════════════════════════════════════════════════════════════════════
import asyncio
import html
import time
from datetime import datetime
from urllib.parse import quote as _urlquote

from state import (
    LINKS, LINKS_LOCK, SUBS, SUBS_LOCK,
    TELEGRAM_SETTINGS, connections, stats,
    generate_uuid, generate_all_vless_links,
    is_link_allowed, is_link_expired, fmt_bytes, parse_size_to_bytes,
    parse_expiry_to_timedelta, get_host, log_activity, logger,
    DEFAULT_PROTOCOL, uptime,
    JOIN_SETTINGS, USER_LINKS,
    check_channel_membership, check_channel_membership_status, check_join_status,
    get_join_channels, create_join_link,
    save_state,
    REFERRAL_SETTINGS, REFERRALS, record_referral, top_referrers,
    top_by_points, rank_of, adjust_points,
    FILTER_SETTINGS, CUSTOM_BLOCK_DOMAINS, ADULT_BLOCK_DOMAINS,
    add_custom_blocked_domain, refresh_adult_blocklist,
    claim_gift_bytes,
)

PAGE_SIZE = 6

# آیدی سازنده و مالک ربات — برای نمایش در بخش «سازنده ربات» و پشتیبانی نهایی.
OWNER_USERNAME = "uimmd"

# واحدهایی که کاربر می‌تواند برای برداشت هدیه‌ی ورودش انتخاب کند.
GIFT_UNITS = {"MB": 1024 ** 2, "GB": 1024 ** 3}

# ══════════════════════════════════════════════════════════════════════════════
# ✅ فیکس: قبلاً _pending_referrer و _wizard دیکشنری‌های ساده بودن که فقط با
# pop صریح خالی می‌شدن. اگر کاربری یک فلو (مثلاً «افزودن کانفیگ» یا رفرال در
# انتظار) رو شروع می‌کرد ولی نصفه‌کاره رهاش می‌کرد (مثلاً چت رو می‌بست)، همون
# entry برای همیشه توی حافظه می‌موند. با گذشت زمان و رشد تعداد کاربرها، این یه
# نشتی حافظه‌ی آهسته و پیوسته‌ست — دقیقاً همون الگویی که قبلاً توی rate_limiter.py
# برای IP-ها فیکس شد. _TTLDict همون رفتار dict معمولی رو داره (get/pop/[]) پس
# نیازی به تغییر جاهای دیگه‌ی کد نبود، فقط یک متد prune() اضافه داره که توسط
# housekeeping_loop پایین‌تر صدا زده می‌شه.
class _TTLDict(dict):
    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.__dict__.setdefault("_ts", {})[key] = time.monotonic()

    def pop(self, key, default=None):
        self.__dict__.get("_ts", {}).pop(key, None)
        return super().pop(key, default)

    def prune(self, max_idle: float) -> int:
        ts = self.__dict__.get("_ts", {})
        now = time.monotonic()
        stale = [k for k, t in ts.items() if now - t > max_idle]
        for k in stale:
            self.pop(k, None)
        return len(stale)


# رفرال در حال انتظار: وقتی کاربر با /start ref_<id> وارد می‌شه ولی هنوز عضویت کانال
# رو تایید نکرده، اینجا نگه می‌داریم تا بعد از ساخته‌شدن کانفیگش، رفرال ثبت بشه.
# فقط در حافظه است (نیازی به ماندگاری ندارد چون فلوی onboarding کوتاهه) —
# اگر کاربر هیچ‌وقت عضویتش رو تایید نکنه، housekeeping_loop بعد از یک ساعت پاکش می‌کنه.
_pending_referrer: "_TTLDict" = _TTLDict()

# کش نام‌نمایشی هر chat_id — برای اینکه وقتی می‌خوایم رفرال یک نفر رو با اسمش توی
# لیدربورد نشون بدیم، لازم نیست همون لحظه از تلگرام getChat بگیریم.
_display_names: dict[str, dict] = {}


def _remember_display_name(chat_id, from_user: dict | None):
    if not from_user:
        return
    name = " ".join(filter(None, [from_user.get("first_name"), from_user.get("last_name")])).strip()
    _display_names[str(chat_id)] = {"name": name or str(chat_id), "username": from_user.get("username") or ""}
_offset = 0
# ویزارد ادمین/کاربر (مراحل چندقدمی مثل «افزودن کانفیگ»، «پیام همگانی» و ...) —
# رها شده‌ها بعد از WIZARD_IDLE_TTL توسط housekeeping_loop پاک می‌شن.
_wizard: "_TTLDict" = _TTLDict()
_running = False

# ══════════════════════════════════════════════════════════════════════════════
# ✅ فیچر: ضد اسپم — قبلاً هیچ سقفی روی تعداد پیام/کلیکی که یک کاربر در واحد
# زمان می‌فرستاد نبود. یک کاربر (عمدی یا با یه کلاینت باگ‌دار که پیام رو
# چندبار می‌فرسته) می‌تونست با ارسال سریع ده‌ها پیام/callback پشت‌سرهم، حجم
# زیادی کار async (هرکدوم شامل چند تا await _api → درخواست HTTP واقعی به
# تلگرام) روی سرور تحمیل کنه و صف پردازش رو برای بقیه‌ی کاربرها کند کنه، چون
# polling_loop آپدیت‌ها رو پشت‌سرهم پردازش می‌کنه. این یک sliding-window ساده،
# شبیه rate_limiter.py، ولی مخصوص هر chat_id تلگرام (نه IP). ادمین‌ها معافن
# چون تعدادشون کمه و کارهای مدیریتی نباید بخاطر این گیر کنه.
_FLOOD_LIMIT = 8            # حداکثر ۸ پیام/کلیک مجاز
_FLOOD_WINDOW = 10.0        # در هر ۱۰ ثانیه
_flood_store: dict[str, list] = {}
_flood_calls_since_cleanup = 0
_FLOOD_CLEANUP_EVERY = 300


def _flood_check(chat_id) -> bool:
    """True یعنی این پیام/کلیک اجازه‌ی پردازش داره. اگر از سقف رد شده باشه،
    بی‌صدا نادیده گرفته می‌شه (نه پیام خطا — چون خودِ پیام خطا هم می‌تونه به
    اسپم دامن بزنه)."""
    global _flood_calls_since_cleanup
    key = str(chat_id)
    now = time.monotonic()
    bucket = _flood_store.setdefault(key, [])
    bucket[:] = [t for t in bucket if now - t < _FLOOD_WINDOW]
    allowed = len(bucket) < _FLOOD_LIMIT
    if allowed:
        bucket.append(now)
    # پاک‌سازی دوره‌ای IPـهای/کاربرهای غیرفعال، دقیقاً مثل الگوی rate_limiter.py —
    # وگرنه _flood_store برای هر کاربری که تا حالا یک پیام فرستاده، تا ابد بزرگ می‌شه.
    _flood_calls_since_cleanup += 1
    if _flood_calls_since_cleanup >= _FLOOD_CLEANUP_EVERY:
        _flood_calls_since_cleanup = 0
        stale = [k for k, v in _flood_store.items() if not v]
        for k in stale:
            _flood_store.pop(k, None)
    return allowed




def _allowed_chats() -> set[str]:
    raw = (TELEGRAM_SETTINGS.get("chat_id") or "").strip()
    if not raw:
        return set()
    return {p.strip() for p in raw.replace(";", ",").split(",") if p.strip()}


def _is_admin(chat_id) -> bool:
    """ادمین یعنی chat_id داخل لیست TELEGRAM_SETTINGS.chat_id باشد."""
    return str(chat_id) in _allowed_chats()


# ── یوزرنیم بات: خودکار از API تلگرام (getMe) گرفته می‌شود ─────────────────────
# قبلاً از یک فیلد دستی (TELEGRAM_SETTINGS["bot_username"]) خونده می‌شد که اگر
# خالی می‌ماند، لینک رفرال به‌صورت t.me/bot?start=... یا t.me/?start=... ساخته
# می‌شد که آدرس معتبری نیست و مرورگر آن را به گوگل هدایت می‌کرد. این تابع به‌جای
# آن، یوزرنیم واقعی بات را مستقیماً از تلگرام می‌گیرد و کش می‌کند.
_bot_username_cache: str | None = None


async def _get_bot_username() -> str | None:
    global _bot_username_cache
    if _bot_username_cache:
        return _bot_username_cache
    result = await _api("getMe")
    if result and result.get("username"):
        _bot_username_cache = result["username"]
        return _bot_username_cache
    return None


# دسته‌بندی‌های callback که فقط مخصوص ادمین است (مدیریت کانفیگ‌ها، آمار، گروه‌های ساب و ...)
ADMIN_ONLY_PREFIXES = (
    "m:new", "m:list:", "m:stats", "m:search", "m:subs:", "m:help",
    "q:", "e:", "l:", "lt:", "lr:", "li:", "lg:", "ld", "st:",
    "sup:reply:", "m:ref", "m:broadcast", "ref:toggle", "ref:setbonus", "ref:setdaily", "ref:settemplate",
    "ref:givepoints", "m:filter", "filter:",
)


def _is_admin_only_action(data: str) -> bool:
    return any(data == p or data.startswith(p) for p in ADMIN_ONLY_PREFIXES)


def _channel_username() -> str:
    """اولین کانال از لیست کانال‌های اجباری (برای متن‌هایی که فقط یک کانال را نشان می‌دهند)."""
    chans = get_join_channels()
    return chans[0] if chans else "TimAzadi"


def _channels_kb_rows(channels: list[str]) -> list[list[dict]]:
    """یک دکمه‌ی «عضویت» برای هر کانال اجباری می‌سازد."""
    rows = []
    for ch in channels:
        rows.append([{"text": f"📢 عضویت در @{ch}", "url": f"https://t.me/{ch}"}])
    return rows


def _channels_text_block(channels: list[str]) -> str:
    return "\n".join(f"👉 https://t.me/{ch}" for ch in channels)


def _safe_host() -> str:
    """
    get_host() را می‌گیرد؛ قبلاً وقتی RAILWAY_PUBLIC_DOMAIN تنظیم نبود این تابع
    یک دامین هارد-کد شده‌ی متعلق به یک دیپلوی دیگر (mmd-mimi-mikham.up.railway.app)
    برمی‌گرداند که باعث می‌شد لینک‌های کاربران به یک سایت اشتباه/غیرمرتبط اشاره کند.
    حالا در این حالت فقط لاگ هشدار می‌زند و از CONFIG['host'] واقعی استفاده می‌کند.
    """
    host = get_host()
    if not host or host == "localhost":
        logger.warning(
            "RAILWAY_PUBLIC_DOMAIN تنظیم نشده — لینک‌های ساخته‌شده ممکن است نادرست باشند؛ "
            "این متغیر را در Railway تنظیم کن."
        )
    return host


async def _api(method: str, payload: dict | None = None) -> dict | None:
    from main import http_client
    token = TELEGRAM_SETTINGS.get("bot_token")
    if not token or http_client is None:
        return None
    api_ip = (TELEGRAM_SETTINGS.get("api_ip") or "").strip()
    try:
        if api_ip:
            host_for_url = f"[{api_ip}]" if ":" in api_ip else api_ip
            url = f"https://{host_for_url}/bot{token}/{method}"
            resp = await http_client.post(
                url, json=payload or {},
                headers={"Host": "api.telegram.org"},
                extensions={"sni_hostname": "api.telegram.org"},
                timeout=35.0,
            )
        else:
            url = f"https://api.telegram.org/bot{token}/{method}"
            resp = await http_client.post(url, json=payload or {}, timeout=35.0)
        data = resp.json()
        if not data.get("ok"):
            logger.warning(f"telegram_bot: {method} failed: {data}")
            return None
        return data.get("result")
    except Exception as e:
        logger.warning(f"telegram_bot: {method} error: {e}")
        return None


async def _send(chat_id, text, kb=None, photo=None, reply_kb=None):
    payload = {"chat_id": chat_id, "parse_mode": "HTML"}
    if reply_kb is not None:
        # reply_kb یک کیبورد ثابت پایین صفحه است (نه دکمه‌ی زیر پیام)؛ نمی‌شود
        # هم‌زمان با inline_keyboard در یک پیام استفاده شود، پس اولویت با reply_kb است.
        payload["reply_markup"] = reply_kb
    elif kb is not None:
        payload["reply_markup"] = {"inline_keyboard": kb}
    if photo:
        payload["photo"] = photo
        payload["caption"] = text
        return await _api("sendPhoto", payload)
    payload["text"] = text
    return await _api("sendMessage", payload)


def _bottom_menu_kb(is_admin: bool) -> dict:
    """کیبورد ثابت پایین صفحه؛ همیشه در دسترس است، حتی وسط یک مکالمه‌ی دیگر."""
    rows = [
        ["🎁 دریافت هدیه", "📊 وضعیت من"],
        ["🎁 دعوت دوستان", "🏆 برترین‌ها"],
        ["📩 پشتیبانی", "👑 سازنده ربات"],
    ]
    if is_admin:
        rows.insert(0, ["📋 پنل مدیریت"])
    return {"keyboard": rows, "resize_keyboard": True, "is_persistent": True}


async def _send_bottom_menu(chat_id, is_admin: bool):
    await _send(
        chat_id,
        "📌 از دکمه‌های پایین صفحه هم می‌تونی هر وقت خواستی استفاده کنی 👇",
        reply_kb=_bottom_menu_kb(is_admin),
    )


async def _show_owner_info(chat_id, message_id=None):
    text = (
        "👑 <b>سازنده و مالک ربات</b>\n\n"
        f"برای هرگونه سوال، پیشنهاد یا مشکل فنی درباره‌ی خودِ ربات می‌تونی مستقیم پیام بدی:\n"
        f"🆔 @{OWNER_USERNAME}"
    )
    kb = [
        [{"text": "💬 ارسال پیام به سازنده", "url": f"https://t.me/{OWNER_USERNAME}"}],
        [{"text": "⬅️ بازگشت", "callback_data": "m:main"}],
    ]
    if message_id:
        await _edit(chat_id, message_id, text, kb)
    else:
        await _send(chat_id, text, kb)


async def _edit(chat_id, message_id, text, kb=None):
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
    if kb is not None:
        payload["reply_markup"] = {"inline_keyboard": kb}
    res = await _api("editMessageText", payload)
    if res is None:
        await _send(chat_id, text, kb)


async def _answer_cb(cb_id, text=None):
    payload = {"callback_query_id": cb_id}
    if text:
        payload["text"] = text
        payload["show_alert"] = False
    await _api("answerCallbackQuery", payload)


def _link_line(uid: str, d: dict) -> str:
    ok = is_link_allowed(d)
    dot = "🟢" if ok else "🔴"
    used = fmt_bytes(d.get("used_bytes", 0))
    limit = "∞" if not d.get("limit_bytes") else fmt_bytes(d["limit_bytes"])
    return f"{dot} {d.get('label','?')} — {used}/{limit}"


def _main_menu_kb():
    return [
        [{"text": "➕ کانفیگ جدید", "callback_data": "m:new"}],
        [{"text": "📋 لیست کانفیگ‌ها", "callback_data": "m:list:0"}, {"text": "🔍 جستجو", "callback_data": "m:search"}],
        [{"text": "📂 گروه‌های ساب", "callback_data": "m:subs:0"}, {"text": "📊 آمار سیستم", "callback_data": "m:stats"}],
        [{"text": "🏆 رفرال", "callback_data": "m:ref"}, {"text": "🛡️ فیلتر محتوا", "callback_data": "m:filter"}],
        [{"text": "📢 پیام همگانی", "callback_data": "m:broadcast"}],
        [{"text": "❓ راهنما", "callback_data": "m:help"}, {"text": "👑 سازنده ربات", "callback_data": "owner:info"}],
    ]


async def _show_main_menu(chat_id, message_id=None):
    text = (
        "🤖 <b>پنل مدیریت تیم آزادی</b>\n"
        "یکی از گزینه‌ها رو انتخاب کن 👇"
    )
    kb = _main_menu_kb()
    if message_id:
        await _edit(chat_id, message_id, text, kb)
    else:
        await _send(chat_id, text, kb)


async def _show_help(chat_id, message_id=None):
    text = (
        "❓ <b>راهنمای پنل</b>\n\n"
        "➕ <b>کانفیگ جدید</b> — ساخت دستی یک کانفیگ با حجم و انقضای دلخواه\n"
        "📋 <b>لیست کانفیگ‌ها</b> — مدیریت، ویرایش و حذف کانفیگ‌های موجود\n"
        "🔍 <b>جستجو</b> — پیدا کردن سریع یک کانفیگ با بخشی از اسمش\n"
        "📂 <b>گروه‌های ساب</b> — مدیریت گروه‌بندی ساب‌لینک‌ها\n"
        "📊 <b>آمار سیستم</b> — وضعیت لحظه‌ای مصرف و کانکشن‌ها\n"
        "🏆 <b>رفرال</b> — تنظیمات دعوت دوستان و لیدربورد\n"
        "🛡️ <b>فیلتر محتوا</b> — مدیریت دامنه‌های مسدود\n"
        "📢 <b>پیام همگانی</b> — ارسال اطلاع‌رسانی به همه‌ی کاربران\n\n"
        "💡 هر جا خواستی، با /menu به همین منو برمی‌گردی."
    )
    kb = [[{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}]]
    if message_id:
        await _edit(chat_id, message_id, text, kb)
    else:
        await _send(chat_id, text, kb)


async def _show_list(chat_id, message_id, page: int):
    async with LINKS_LOCK:
        items = sorted(LINKS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    chunk = items[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    kb = [[{"text": _link_line(uid, d), "callback_data": f"l:{uid}"}] for uid, d in chunk]
    nav = []
    if page > 0:
        nav.append({"text": "◀️ قبلی", "callback_data": f"m:list:{page-1}"})
    nav.append({"text": f"{page+1}/{pages}", "callback_data": "noop"})
    if page < pages - 1:
        nav.append({"text": "بعدی ▶️", "callback_data": f"m:list:{page+1}"})
    kb.append(nav)
    kb.append([{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}])
    text = f"📋 <b>لیست کانفیگ‌ها</b> ({total} مورد)\nروی هرکدام بزن برای مدیریت:" if total else "هیچ کانفیگی هنوز ساخته نشده."
    await _edit(chat_id, message_id, text, kb)


async def _show_link_detail(chat_id, message_id, uid: str):
    async with LINKS_LOCK:
        d = LINKS.get(uid)
    if not d:
        await _edit(chat_id, message_id, "این کانفیگ دیگر وجود ندارد.", [[{"text": "⬅️ لیست", "callback_data": "m:list:0"}]])
        return
    ok = is_link_allowed(d)
    expired = is_link_expired(d)
    used = fmt_bytes(d.get("used_bytes", 0))
    limit = "∞" if not d.get("limit_bytes") else fmt_bytes(d["limit_bytes"])
    exp_txt = "بدون انقضا"
    if d.get("expires_at"):
        try:
            exp_txt = datetime.fromisoformat(d["expires_at"]).strftime("%Y-%m-%d %H:%M")
        except Exception:
            exp_txt = d["expires_at"]
    gift_txt = "\n🎁 این یک کانفیگ هدیه‌داده‌شده است." if d.get("parent_id") else ""
    text = (
        f"🔧 <b>{d.get('label','?')}</b>\n\n"
        f"وضعیت: {'🟢 فعال' if ok else ('⏰ منقضی' if expired else '🔴 غیرفعال/اتمام حجم')}\n"
        f"مصرف: {used} از {limit}\n"
        f"انقضا: {exp_txt}\n"
        f"پروتکل پیش‌فرض: {d.get('protocol', DEFAULT_PROTOCOL)}"
        f"{gift_txt}"
    )
    kb = [
        [
            {"text": ("🔒 غیرفعال کن" if d.get("active", True) else "🔓 فعال کن"), "callback_data": f"lt:{uid}"},
            {"text": "♻️ ریست مصرف", "callback_data": f"lr:{uid}"},
        ],
        [
            {"text": "➕ افزایش حجم", "callback_data": f"li:{uid}"},
            {"text": "🔗 دریافت لینک/QR", "callback_data": f"lg:{uid}"},
        ],
        [{"text": "🗑 حذف کامل", "callback_data": f"ld:{uid}"}],
        [{"text": "⬅️ لیست", "callback_data": "m:list:0"}],
    ]
    await _edit(chat_id, message_id, text, kb)


async def _send_link_and_qr(chat_id, uid: str):
    try:
        async with LINKS_LOCK:
            d = LINKS.get(uid)
        if not d:
            await _send(chat_id, "❌ این کانفیگ دیگر وجود ندارد.")
            return
        host = _safe_host()
        label = d.get("label", "کانفیگ")
        sub_url = f"https://{host}/sub/{uid}"
        text = f"🔗 <b>{label}</b>\n\n📡 لینک ساب:\n<code>{sub_url}</code>"
        kb = [[{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}]]
        await _send(chat_id, text, kb)
    except Exception:
        await _send(chat_id, "❌ خطا در دریافت لینک. لطفاً دوباره تلاش کنید.")


QUOTA_OPTIONS = [("1GB", 1), ("5GB", 5), ("10GB", 10), ("20GB", 20), ("50GB", 50), ("100GB", 100), ("∞ نامحدود", 0)]
EXPIRY_OPTIONS = [("بدون انقضا", None), ("۱ روز", 1), ("۷ روز", 7), ("۳۰ روز", 30)]


async def _wizard_start(chat_id, message_id):
    _wizard[str(chat_id)] = {"step": "label", "data": {}}
    await _edit(chat_id, message_id, "✏️ اسم این کانفیگ رو بفرست (مثلاً: کاربر علی):", [[{"text": "❌ انصراف", "callback_data": "m:main"}]])


async def _wizard_ask_quota(chat_id, message_id=None):
    kb = [[{"text": t, "callback_data": f"q:{v}"} for t, v in QUOTA_OPTIONS[i:i+2]] for i in range(0, len(QUOTA_OPTIONS), 2)]
    kb.append([{"text": "✏️ مقدار دلخواه (GB)", "callback_data": "q:custom"}])
    kb.append([{"text": "❌ انصراف", "callback_data": "m:main"}])
    text = "📦 چه مقدار حجم بدیم؟"
    if message_id:
        await _edit(chat_id, message_id, text, kb)
    else:
        await _send(chat_id, text, kb)


async def _wizard_ask_expiry(chat_id, message_id=None):
    kb = [[{"text": t, "callback_data": f"e:{v if v is not None else 0}"} for t, v in EXPIRY_OPTIONS[i:i+2]] for i in range(0, len(EXPIRY_OPTIONS), 2)]
    kb.append([{"text": "✏️ مقدار دلخواه (روز)", "callback_data": "e:custom"}])
    kb.append([{"text": "❌ انصراف", "callback_data": "m:main"}])
    text = "⏰ تا کِی معتبر باشه؟"
    if message_id:
        await _edit(chat_id, message_id, text, kb)
    else:
        await _send(chat_id, text, kb)


async def _wizard_finish(chat_id, message_id=None):
    w = _wizard.pop(str(chat_id), None)
    if not w:
        return
    d = w["data"]
    label = d.get("label", "کانفیگ جدید")[:60]
    limit_bytes = parse_size_to_bytes(d.get("quota_gb", 0), "GB") if d.get("quota_gb", 0) else 0
    exp_days = d.get("expiry_days")
    expires_at = None
    if exp_days:
        td = parse_expiry_to_timedelta(float(exp_days), "days")
        if td:
            expires_at = (datetime.now() + td).isoformat()
    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
            "created_at": datetime.now().isoformat(), "active": True,
            "expires_at": expires_at, "note": "از بات تلگرام ساخته شد",
            "is_default": False, "sub_id": None, "protocol": DEFAULT_PROTOCOL,
            "parent_id": None, "white_label": False, "flag": "🇺🇸",
            "max_devices": 0, "quota_notified": False, "expiry_notified": False,
        }
    from main import schedule_save
    await schedule_save()
    log_activity("link", f"کانفیگ «{label}» از بات تلگرام ساخته شد", "ok")
    limit_txt = "∞" if not limit_bytes else fmt_bytes(limit_bytes)
    exp_txt = "بدون انقضا" if not expires_at else f"{exp_days} روز دیگر"
    text = f"✅ کانفیگ ساخته شد!\n\n<b>{label}</b>\nحجم: {limit_txt}\nانقضا: {exp_txt}"
    kb = [[{"text": "🔗 دریافت لینک/QR", "callback_data": f"lg:{uid}"}], [{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}]]
    if message_id:
        await _edit(chat_id, message_id, text, kb)
    else:
        await _send(chat_id, text, kb)


_MEDALS = ["🥇", "🥈", "🥉"]


def _display_name_for(entry: dict, fallback_id: str) -> str:
    # نام و یوزرنیم تلگرام کاملاً توسط خود کاربر قابل‌تنظیمه (هرکسی می‌تونه
    # اسمشو به هر چیزی از جمله تگ HTML تغییر بده)، پس قبل از قرار دادن داخل
    # پیامی که با parse_mode=HTML فرستاده می‌شه، حتماً باید escape بشه.
    name = html.escape(str(entry.get("name") or fallback_id))
    uname = f" (@{html.escape(str(entry['username']))})" if entry.get("username") else ""
    return f"{name}{uname}"


async def _send_leaderboard(chat_id):
    top = top_by_points(10)
    if not top:
        await _send(chat_id, "🏆 <b>لیست برترین‌ها</b>\n\nهنوز کسی امتیازی کسب نکرده — اولین نفر تو باش! برای شروع، از «🎁 دعوت دوستان» لینکت رو بگیر.")
        return

    lines = ["🏆 <b>لیست برترین‌های تیم آزادی</b>", "━━━━━━━━━━━━━━━", ""]
    for i, r in enumerate(top, 1):
        medal = _MEDALS[i - 1] if i <= 3 else f"{i}."
        name = _display_name_for(r, r["user_id"])
        lines.append(f"{medal} {name}\n     🎯 {r.get('points', 0)} امتیاز · 👥 {r.get('count', 0)} دعوت")
    lines.append("")
    lines.append("━━━━━━━━━━━━━━━")

    user_id = str(chat_id)
    rank, total, mine = rank_of(user_id)
    if rank:
        lines.append(f"📍 جایگاه تو: <b>#{rank}</b> از {total} نفر — {mine.get('points', 0)} امتیاز · {mine.get('count', 0)} دعوت")
    else:
        lines.append("📍 هنوز جایگاهی نداری — با دعوت از دوستات وارد لیست شو!")

    await _send(chat_id, "\n".join(lines))


async def _show_referral_admin(chat_id, message_id):
    top = top_referrers(10)
    lines = []
    for i, r in enumerate(top, 1):
        name = html.escape(str(r.get("name") or r["user_id"]))
        uname = f" (@{html.escape(str(r['username']))})" if r.get("username") else ""
        lines.append(f"{i}. {name}{uname} — <code>{r['user_id']}</code> — {r.get('count', 0)} رفرال")
    board = "\n".join(lines) if lines else "هنوز هیچ رفرالی ثبت نشده."

    status = "🟢 فعال" if REFERRAL_SETTINGS.get("enabled", True) else "🔴 غیرفعال"
    daily_cap = REFERRAL_SETTINGS.get("max_daily_credits", 0)
    daily_txt = "بدون سقف (نامحدود)" if daily_cap <= 0 else f"{daily_cap} رفرال در روز"
    text = (
        "🏆 <b>سیستم رفرال</b>\n\n"
        f"وضعیت: {status}\n"
        f"هدیه‌ی هر رفرال: {REFERRAL_SETTINGS.get('bonus_gb', 5)} گیگ\n"
        f"سقف روزانه‌ی هر نفر: {daily_txt}\n\n"
        f"🥇 <b>برترین‌ها:</b>\n{board}"
    )
    kb = [
        [{"text": "🔴 غیرفعال کن" if REFERRAL_SETTINGS.get("enabled", True) else "🟢 فعال کن", "callback_data": "ref:toggle"}],
        [{"text": "✏️ تغییر مقدار هدیه", "callback_data": "ref:setbonus"}],
        [{"text": "✏️ تغییر سقف روزانه", "callback_data": "ref:setdaily"}],
        [{"text": "✏️ تغییر متن پیام رفرال", "callback_data": "ref:settemplate"}],
        [{"text": "🏅 امتیاز دادن به کاربر", "callback_data": "ref:givepoints"}],
        [{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}],
    ]
    await _edit(chat_id, message_id, text, kb)


async def _show_filter_admin(chat_id, message_id):
    ads_on = FILTER_SETTINGS.get("block_ads", False)
    adult_on = FILTER_SETTINGS.get("block_adult", False)
    adult_count = len(ADULT_BLOCK_DOMAINS)
    custom_ads = len(CUSTOM_BLOCK_DOMAINS["ads"])
    custom_adult = len(CUSTOM_BLOCK_DOMAINS["adult"])
    text = (
        "🛡️ <b>فیلتر محتوای ساب‌ها</b>\n\n"
        f"مسدودسازی تبلیغات: {'🟢 فعال' if ads_on else '🔴 غیرفعال'} (+{custom_ads} دامنه‌ی دستی)\n"
        f"مسدودسازی محتوای بزرگسال: {'🟢 فعال' if adult_on else '🔴 غیرفعال'} ({adult_count} دامنه در لیست، +{custom_adult} دستی)\n\n"
        "این فیلتر روی سطح اتصال کار می‌کنه: قبل از وصل‌شدن به مقصد، دامنه‌اش با لیست چک می‌شه و اگه مسدود بود، اصلاً وصل نمی‌شه — روی همه‌ی ساب‌ها اثر می‌ذاره."
    )
    kb = [
        [{"text": ("🔴 خاموش کن" if ads_on else "🟢 روشن کن") + " — تبلیغات", "callback_data": "filter:toggle:ads"}],
        [{"text": ("🔴 خاموش کن" if adult_on else "🟢 روشن کن") + " — بزرگسال", "callback_data": "filter:toggle:adult"}],
        [{"text": "🔄 بروزرسانی لیست بزرگسال", "callback_data": "filter:refreshadult"}],
        [{"text": "➕ افزودن دامنه‌ی دلخواه", "callback_data": "filter:addcustom"}],
        [{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}],
    ]
    await _edit(chat_id, message_id, text, kb)


async def _show_stats(chat_id, message_id):
    async with LINKS_LOCK:
        total = len(LINKS)
        active = sum(1 for d in LINKS.values() if is_link_allowed(d))
    text = (
        "📊 <b>آمار سیستم</b>\n\n"
        f"کل کانفیگ‌ها: {total}\n"
        f"فعال: {active}\n"
        f"اتصالات زنده: {len(connections)}\n"
        f"کل ترافیک: {fmt_bytes(stats.get('total_bytes', 0))}\n"
        f"کل درخواست‌ها: {stats.get('total_requests', 0)}\n"
        f"آپ‌تایم: {uptime()}"
    )
    await _edit(chat_id, message_id, text, [[{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}]])


async def _handle_join_start(chat_id, message_id=None):
    """هر کاربر عادی که /start یا /menu بزند از این مسیر عبور می‌کند."""
    user_id = str(chat_id)

    # اگر کاربر قبلاً کانفیگ خودش را گرفته، دیگر لازم نیست دوباره چک عضویت شود؛
    # مستقیم همان لینک قبلی‌اش را نشان بده.
    existing_uid = USER_LINKS.get(user_id)
    if existing_uid and existing_uid in LINKS:
        await _grant_join_link(chat_id, message_id)
        return

    if JOIN_SETTINGS.get("channel_required", True):
        status, missing = await check_join_status(user_id, TELEGRAM_SETTINGS.get("bot_token"))
        if status is not True:
            # اگر وضعیت نامعلوم بود (خطای موقت تلگرام)، همان کانال‌های تنظیم‌شده را
            # به‌عنوان نیازمند عضویت نشان می‌دهیم تا کاربر گیر نکند، ولی هرگز رد نمی‌کنیمش
            # به‌خاطر یک خطای شبکه‌ای که تقصیر او نیست.
            channels = missing if missing else get_join_channels()
            count = len(channels)
            plural = "کانال‌های زیر" if count > 1 else "کانال زیر"
            text = (
                f"❌ برای دریافت کانفیگ رایگان، ابتدا باید در {plural} عضو شوید.\n\n"
                f"📢 لطفاً عضو {plural} شوید:\n"
                f"{_channels_text_block(channels)}\n\n"
                "سپس روی «بررسی مجدد عضویت» بزنید."
            )
            kb = _channels_kb_rows(channels)
            kb.append([{"text": "🔄 بررسی مجدد عضویت", "callback_data": "j:check"}])
            kb.append([{"text": "📩 پیام به پشتیبانی", "callback_data": "sup:start"}])
            if message_id:
                await _edit(chat_id, message_id, text, kb)
            else:
                await _send(chat_id, text, kb)
            return

    await _grant_join_link(chat_id, message_id)


async def _credit_pending_referral(user_id: str):
    """
    بعد از این‌که یک کانفیگ کاملاً جدید ساخته شد (یعنی کاربر واقعاً عضویت کانال را
    رد کرده)، اگر این کاربر از طریق لینک رفرال یک نفر دیگر آمده بود، رفرال را ثبت
    و به رفرردهنده حجم هدیه می‌دهد.
    """
    referrer_id = _pending_referrer.pop(user_id, None)
    if not referrer_id:
        return
    referrer_uid = USER_LINKS.get(referrer_id)
    if not referrer_uid or referrer_uid not in LINKS:
        return  # رفرردهنده خودش هیچ‌وقت کانفیگ نگرفته؛ رفرال معتبر نیست

    disp = _display_names.get(referrer_id, {})
    ok = record_referral(referrer_id, user_id, USER_LINKS.get(user_id, ""), disp.get("name", ""), disp.get("username", ""))
    if not ok:
        return

    bonus_gb = REFERRAL_SETTINGS.get("bonus_gb", 5)
    async with LINKS_LOCK:
        rlink = LINKS.get(referrer_uid)
        # باگ قبلی: اینجا بونوس رو به limit_bytes لینک اصلی (primary) اضافه می‌کرد، ولی از
        # وقتی هر برداشت هدیه لینک جدا می‌سازه، limit_bytes لینک اصلی همیشه ۰ می‌مونه و
        # هیچ‌وقت مستقیم استفاده نمی‌شه — پس شرط «limit_bytes > 0» هیچ‌وقت true نمی‌شد و
        # هدیه‌ی رفرال اصلاً اضافه نمی‌شد. الان درست مثل هدیه‌ی ورود، به gift_pool_bytes
        # (استخر قابل‌برداشت) اضافه می‌شه تا کاربر بتونه با دکمه‌ی «دریافت هدیه» برش داره.
        if rlink and bonus_gb > 0:
            rlink["gift_pool_bytes"] = rlink.get("gift_pool_bytes", 0) + parse_size_to_bytes(bonus_gb, "GB")
    await save_state()

    new_count = REFERRALS.get(referrer_id, {}).get("count", 0)
    log_activity("system", f"رفرال موفق: کاربر {referrer_id} یک دعوت جدید گرفت (مجموع {new_count})", "ok")
    if bonus_gb > 0:
        await _send(referrer_id, f"🎉 یکی از دوستات با لینک تو وارد شد و عضو کانال شد!\n\n🎁 {bonus_gb} گیگ به استخر هدیه‌ات اضافه شد؛ از دکمه‌ی «🎁 دریافت هدیه» می‌تونی برش داری.\n✅ مجموع رفرال موفق تو: {new_count}")
    else:
        await _send(referrer_id, f"🎉 یکی از دوستات با لینک تو وارد شد و عضو کانال شد!\n\n✅ مجموع رفرال موفق تو: {new_count}")


async def _grant_join_link(chat_id, message_id=None):
    """کانفیگ اختصاصی کاربر را می‌سازد (اگر قبلاً نساخته) و نشان می‌دهد."""
    user_id = str(chat_id)
    uid = USER_LINKS.get(user_id)
    is_new_user = not uid or uid not in LINKS
    if is_new_user:
        uid = await create_join_link(user_id)
    d = LINKS.get(uid) if uid else None
    if not uid or not d:
        text = "❌ خطا در ساخت کانفیگ. لطفاً بعداً دوباره تلاش کنید."
        kb = [[{"text": "🔄 تلاش مجدد", "callback_data": "j:check"}]]
        if message_id:
            await _edit(chat_id, message_id, text, kb)
        else:
            await _send(chat_id, text, kb)
        return

    if is_new_user:
        await _credit_pending_referral(user_id)

    host = _safe_host()
    exp_txt = "بدون انقضا"
    if d.get("expires_at"):
        try:
            exp_txt = datetime.fromisoformat(d["expires_at"]).strftime("%Y-%m-%d %H:%M")
        except Exception:
            exp_txt = d["expires_at"]
    channels = get_join_channels()
    channels_block = _channels_text_block(channels) if channels else f"https://t.me/{_channel_username()}"
    channels_label = "📢 کانال‌های تیم آزادی:" if len(channels) > 1 else "📢 کانال تیم آزادی:"
    gift_pool = d.get("gift_pool_bytes", 0)
    gift_line = (
        f"🎁 مانده‌ی هدیه‌ی ورود (قابل برداشت): {fmt_bytes(gift_pool)}\n"
        if gift_pool > 0 else
        "🎁 هدیه‌ی ورودت رو کامل برداشت کردی.\n"
    )
    my_links = [(u, dd) for u, dd in LINKS.items() if dd.get("join_user") == user_id and u != uid]
    count_line = f"📦 تعداد کانفیگ‌های فعالت: {len(my_links)}\n" if my_links else ""
    text = (
        "🎉 <b>خوش اومدی به تیم آزادی!</b>\n\n"
        "هر بار که بخشی از هدیه‌ات رو برداری، یک <b>لینک ساب کاملاً جدا و مستقل</b> برات ساخته می‌شه "
        "(نه یک لینک ثابت که فقط حجمش زیاد بشه).\n\n"
        f"{count_line}"
        f"{gift_line}"
        f"⏰ انقضا: {exp_txt}\n\n"
        f"{channels_label}\n{channels_block}"
    )
    kb = []
    if gift_pool > 0:
        kb.append([{"text": "🎁 برداشت از هدیه", "callback_data": "gift:start"}])
    if my_links:
        kb.append([{"text": "📊 مشاهده‌ی کانفیگ‌هام", "callback_data": "mystatus"}])
    kb.append([{"text": "🎁 دعوت دوستان", "callback_data": "ref:me"}, {"text": "🏆 برترین‌ها", "callback_data": "ref:board"}])
    kb.append([{"text": "🔄 بروزرسانی وضعیت", "callback_data": "j:check"}, {"text": "📩 پشتیبانی", "callback_data": "sup:start"}])
    if message_id:
        await _edit(chat_id, message_id, text, kb)
    else:
        await _send(chat_id, text, kb)
    if is_new_user:
        await _send_bottom_menu(chat_id, False)


async def _gift_start_as_message(chat_id):
    """مثل کال‌بک gift:start ولی به‌جای ادیت یک پیام موجود، پیام تازه می‌فرستد (برای دکمه‌ی پایین صفحه)."""
    user_id = str(chat_id)
    uid = USER_LINKS.get(user_id)
    d = LINKS.get(uid) if uid else None
    if not uid or not d:
        await _send(chat_id, "اول باید خودت یک کانفیگ داشته باشی؛ از /menu شروع کن.")
        return
    pool = d.get("gift_pool_bytes", 0)
    if pool <= 0:
        await _send(chat_id, "🎁 دیگه چیزی از هدیه‌ی ورودت باقی نمونده.")
        return
    _wizard.pop(str(chat_id), None)
    text = f"🎁 مانده‌ی هدیه‌ات: <b>{fmt_bytes(pool)}</b>\n\nبا چه واحدی می‌خوای برداشت کنی؟"
    kb = [
        [{"text": "مگابایت (MB)", "callback_data": "gift:unit:MB"}, {"text": "گیگابایت (GB)", "callback_data": "gift:unit:GB"}],
        [{"text": "❌ انصراف", "callback_data": "m:main"}],
    ]
    await _send(chat_id, text, kb)


async def _ref_me_as_message(chat_id):
    """مثل کال‌بک ref:me ولی برای فراخوانی از دکمه‌ی پایین صفحه (بدون message_id)."""
    user_id = str(chat_id)
    if not USER_LINKS.get(user_id):
        await _send(chat_id, "اول باید خودت یک کانفیگ داشته باشی. از /menu شروع کن.")
        return
    bot_username = await _get_bot_username()
    if not bot_username:
        await _send(chat_id, "⚠️ فعلاً لینک رفرال در دسترس نیست، بعداً امتحان کن.")
        return
    ref_link = f"https://t.me/{bot_username}?start=ref_{user_id}"
    ref_count = REFERRALS.get(user_id, {}).get("count", 0)
    template = REFERRAL_SETTINGS.get("message_template", "{ref_link}")
    try:
        text = template.format(bonus_gb=REFERRAL_SETTINGS.get("bonus_gb", 5), ref_link=ref_link, ref_count=ref_count)
    except Exception:
        text = f"🔗 لینک رفرال تو:\n<code>{ref_link}</code>\n\nتعداد رفرال موفق: {ref_count}"
    if not REFERRAL_SETTINGS.get("enabled", True):
        text += "\n\n⚠️ سیستم رفرال فعلاً موقتاً غیرفعاله."
    await _send(chat_id, text)


async def _show_my_status(chat_id, message_id=None):
    user_id = str(chat_id)
    primary_uid = USER_LINKS.get(user_id)
    primary = LINKS.get(primary_uid) if primary_uid else None
    if not primary_uid or not primary:
        text = "هنوز کانفیگی نداری؛ از /menu شروع کن."
        kb = [[{"text": "🚀 شروع", "callback_data": "j:check"}]]
        if message_id:
            await _edit(chat_id, message_id, text, kb)
        else:
            await _send(chat_id, text, kb)
        return
    pool = primary.get("gift_pool_bytes", 0)
    claims = primary.get("gift_claims", [])
    # هر برداشت هدیه یک کانفیگ/لینک مستقل با join_user برابر همین کاربره؛
    # لینک اولیه (primary) خودش هیچ‌وقت مستقیم استفاده نمی‌شه، فقط نگهدارنده‌ی استخره.
    my_links = [(u, dd) for u, dd in LINKS.items() if dd.get("join_user") == user_id and u != primary_uid]
    my_links.sort(key=lambda kv: kv[1].get("created_at", ""))

    lines = []
    kb = []
    if my_links:
        for i, (u, dd) in enumerate(my_links, 1):
            used = fmt_bytes(dd.get("used_bytes", 0))
            limit = fmt_bytes(dd.get("limit_bytes", 0))
            status = "🟢" if is_link_allowed(dd) else "🔴"
            lines.append(f"{status} کانفیگ {i}: {used} از {limit}")
            kb.append([{"text": f"🔗 لینک کانفیگ {i}", "callback_data": f"m:copy:{u}"}])
        links_txt = "\n\n📦 <b>کانفیگ‌های تو (هرکدوم از یه برداشت هدیه):</b>\n" + "\n".join(lines)
    else:
        links_txt = "\n\nهنوز هیچ کانفیگی نساختی — چون هنوز از هدیه‌ی ورودت چیزی برنداشتی."

    claims_txt = ""
    if claims:
        clines = [f"{i}. {fmt_bytes(c['amount_bytes'])} — {c.get('date','')} {c.get('time','')}" for i, c in enumerate(claims, 1)]
        claims_txt = f"\n\n🧾 <b>تاریخچه‌ی برداشت‌ها ({len(claims)} مورد، به ترتیب):</b>\n" + "\n".join(clines)

    text = (
        f"📊 <b>وضعیت تو</b>\n\n"
        f"🎁 مانده‌ی هدیه‌ی قابل برداشت: {fmt_bytes(pool)}"
        f"{links_txt}"
        f"{claims_txt}"
    )
    if pool > 0:
        kb.append([{"text": "🎁 برداشت از هدیه", "callback_data": "gift:start"}])
    kb.append([{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}])
    if message_id:
        await _edit(chat_id, message_id, text, kb)
    else:
        await _send(chat_id, text, kb)


SUPPORT_MSG_COOLDOWN = 60  # ثانیه؛ فاصله‌ی حداقل بین دو پیام پشتیبانی از یک کاربر — ضد اسپم
_last_support_msg: dict[str, float] = {}


async def _handle_support_message(chat_id, text):
    _wizard.pop(str(chat_id), None)
    user_id = str(chat_id)
    msg = (text or "").strip()
    if not msg:
        await _send(chat_id, "پیام خالی بود؛ دوباره از منو امتحان کن.")
        return

    now = time.time()
    last = _last_support_msg.get(user_id, 0)
    if now - last < SUPPORT_MSG_COOLDOWN:
        wait = int(SUPPORT_MSG_COOLDOWN - (now - last))
        await _send(chat_id, f"⏳ لطفاً {wait} ثانیه صبر کن و بعد دوباره بفرست.")
        return
    _last_support_msg[user_id] = now

    admins = _allowed_chats()
    if not admins:
        await _send(chat_id, "⚠️ فعلاً پشتیبانی در دسترس نیست، بعداً دوباره امتحان کن.")
        return

    uid = USER_LINKS.get(user_id)
    label = LINKS.get(uid, {}).get("label", "?") if uid else "بدون کانفیگ"
    # مهم: msg مستقیماً چیزیه که یک کاربر عادی (بدون نیاز به پنل یا دسترسی ساب)
    # تایپ کرده و اینجا با parse_mode=HTML برای ادمین فرستاده می‌شه. اگر escape
    # نشه، هرکسی می‌تونه یک لینک فیشینگ به‌شکل متن آبی/قابل‌کلیک مستقیم داخل
    # چت تلگرام خود ادمین جا بزنه. همینطور label هم از قبل ممکنه دستکاری شده باشد.
    safe_msg = html.escape(msg[:3500])
    safe_label = html.escape(str(label))
    for admin_chat in admins:
        await _send(
            admin_chat,
            f"📩 <b>پیام پشتیبانی جدید</b>\nاز کاربر: <code>{user_id}</code> (کانفیگ: {safe_label})\n\n{safe_msg}",
            [[{"text": "↩️ پاسخ", "callback_data": f"sup:reply:{user_id}"}]],
        )
    await _send(chat_id, "✅ پیامت برای پشتیبانی ارسال شد؛ به‌زودی جواب می‌گیری.")
    log_activity("system", f"پیام پشتیبانی جدید از کاربر {user_id}", "info")


_BOTTOM_BUTTON_TEXTS = {
    "🎁 دریافت هدیه", "📊 وضعیت من", "🎁 دعوت دوستان", "🏆 برترین‌ها",
    "📩 پشتیبانی", "👑 سازنده ربات", "📋 پنل مدیریت",
}


async def _run_broadcast(admin_chat_id, targets: list, msg: str):
    """پیام همگانی رو در پس‌زمینه (background task) می‌فرسته، نه inline داخل
    پردازش آپدیت — تا بقیه‌ی کاربرها هم‌زمان بتونن با بات کار کنن."""
    sent, failed = 0, 0
    for user_id in targets:
        res = await _send(user_id, msg)
        if res is not None:
            sent += 1
        else:
            failed += 1
        await asyncio.sleep(0.05)  # ضد رگبار به API تلگرام تا ریت‌لیمیت/بن نشیم
    await _send(admin_chat_id, f"✅ تموم شد. ارسال موفق: {sent} | ناموفق: {failed}")
    log_activity("system", f"پیام همگانی توسط ادمین {admin_chat_id} برای {len(targets)} کاربر ارسال شد", "ok")


async def _handle_text(chat_id, text, is_admin: bool = False, from_user: dict | None = None, chat_type: str = "private"):
    w = _wizard.get(str(chat_id))
    text = (text or "").strip()
    from_user = from_user or {}
    _remember_display_name(chat_id, from_user)

    # ── باگ قبلی: هر پیام معمولی توی گروه (نه فقط دستورها) باعث می‌شد بات سعی کنه
    # برای «آیدی گروه» یک کانفیگ شخصی بسازه/عضویت چک کنه — که نه معنی داشت و نه
    # کاربر واقعی‌ای پشتش بود. حالا توی گروه/سوپرگروه، بات فقط به /start و /menu
    # (به همراه @یوزرنیم بات، همونطور که تلگرام توی گروه می‌فرسته) جواب کوتاه می‌ده
    # و کاربر رو به چت خصوصی هدایت می‌کنه؛ بقیه‌ی پیام‌های گروه کاملاً نادیده گرفته می‌شن.
    # نکته‌ی مهم: اگر بات توی گروه اصلاً به هیچ پیامی (even دستورها) جواب نمی‌ده،
    # این کد کمکی نمی‌کنه — باید توی BotFather روی /setprivacy این بات رو Disable کنی،
    # وگرنه تلگرام به‌خاطر «Privacy Mode» پیش‌فرض، پیام‌های معمولی گروه رو اصلاً
    # برای بات ارسال نمی‌کنه (فقط دستورهایی مثل /start@نام_بات می‌رسن).
    if chat_type in ("group", "supergroup"):
        cmd = text.split()[0].split("@")[0].lower() if text else ""
        if cmd in ("/start", "/menu"):
            await _send(
                chat_id,
                "👋 برای گرفتن کانفیگ اختصاصی یا استفاده از پنل مدیریت، لطفاً به‌صورت خصوصی با من پیام بده؛ "
                "این کار توی گروه انجام نمی‌شه.",
            )
        return

    if text in _BOTTOM_BUTTON_TEXTS:
        _wizard.pop(str(chat_id), None)
        if text == "📋 پنل مدیریت" and is_admin:
            await _show_main_menu(chat_id)
        elif text == "🎁 دریافت هدیه":
            await _gift_start_as_message(chat_id)
        elif text == "📊 وضعیت من":
            await _show_my_status(chat_id)
        elif text == "🎁 دعوت دوستان":
            await _ref_me_as_message(chat_id)
        elif text == "🏆 برترین‌ها":
            await _send_leaderboard(chat_id)
        elif text == "📩 پشتیبانی":
            _wizard[str(chat_id)] = {"step": "support_wait", "data": {}}
            await _send(chat_id, "✍️ پیامت رو بنویس و بفرست، مستقیم برای پشتیبانی ارسال می‌شه:\n\n❌ برای انصراف /menu رو بزن.")
        elif text == "👑 سازنده ربات":
            await _show_owner_info(chat_id)
        return

    if text.startswith("/start"):
        parts = text.split(maxsplit=1)
        payload = parts[1].strip() if len(parts) > 1 else ""
        if not is_admin and payload.startswith("ref_"):
            referrer_id = payload[4:].strip()
            user_id = str(chat_id)
            already_has_config = user_id in USER_LINKS and USER_LINKS[user_id] in LINKS
            if referrer_id and referrer_id != user_id and not already_has_config:
                _pending_referrer[user_id] = referrer_id
        if is_admin:
            await _show_main_menu(chat_id)
            await _send_bottom_menu(chat_id, True)
        else:
            await _handle_join_start(chat_id)
        return

    if text.startswith("/menu"):
        if is_admin:
            await _show_main_menu(chat_id)
            await _send_bottom_menu(chat_id, True)
        else:
            await _handle_join_start(chat_id)
        return

    if text.startswith("/broadcast") and is_admin:
        _wizard[str(chat_id)] = {"step": "broadcast_wait", "data": {}}
        await _send(chat_id, "📢 متن پیامی که می‌خوای برای همه‌ی کاربرای بات فرستاده بشه رو بفرست (مثلاً اطلاع‌رسانی دامنه‌ی جدید):\n\n❌ برای انصراف /menu رو بزن.")
        return

    if not is_admin:
        if w and w.get("step") == "support_wait":
            await _handle_support_message(chat_id, text)
            return
        if w and w.get("step") == "gift_amount_wait":
            # این مرحله (وارد کردن عدد برداشت از هدیه) مال کاربر عادیه، نه ویزارد ادمین؛
            # قبلاً این‌جا مثل بقیه‌ی مراحل ویزارد نادیده گرفته می‌شد و عدد کاربر هیچ‌وقت
            # پردازش نمی‌شد (در نتیجه حجمش هیچ‌وقت واقعی نمی‌شد و همیشه «∞» می‌ماند).
            pass  # از منطق مشترک مراحل ویزارد در پایین همین تابع عبور می‌کند
        else:
            # مراحل ویزارد ساخت کانفیگ فقط برای ادمین است؛ کاربر عادی همیشه به فلوی دریافت کانفیگ می‌رود
            _wizard.pop(str(chat_id), None)
            await _handle_join_start(chat_id)
            return

    if not w:
        await _send(chat_id, "برای شروع /menu رو بزن یا از دکمه‌های پایین پیام‌های قبلی استفاده کن.")
        return

    step = w["step"]
    if step == "label":
        w["data"]["label"] = text[:60] or "کانفیگ جدید"
        w["step"] = "quota"
        await _wizard_ask_quota(chat_id)
    elif step == "quota_custom":
        try:
            w["data"]["quota_gb"] = max(0.0, float(text.replace(",", ".")))
        except ValueError:
            await _send(chat_id, "عدد معتبر نبود؛ دوباره بفرست (مثلاً 7.5):")
            return
        w["step"] = "expiry"
        await _wizard_ask_expiry(chat_id)
    elif step == "expiry_custom":
        try:
            w["data"]["expiry_days"] = max(0.0, float(text.replace(",", ".")))
        except ValueError:
            await _send(chat_id, "عدد معتبر نبود؛ دوباره بفرست (مثلاً 3):")
            return
        await _wizard_finish(chat_id)
    elif step == "support_reply_wait":
        _wizard.pop(str(chat_id), None)
        target = w["data"].get("target")
        msg = text[:3500]
        if not target or not msg:
            await _send(chat_id, "لغو شد.")
            return
        res = await _send(target, f"💬 <b>پاسخ پشتیبانی:</b>\n\n{msg}")
        if res is not None:
            await _send(chat_id, "✅ پاسخ ارسال شد.")
            log_activity("system", f"ادمین {chat_id} به پیام پشتیبانی کاربر {target} پاسخ داد", "ok")
        else:
            await _send(chat_id, "❌ ارسال ناموفق بود (شاید کاربر بات رو بلاک کرده).")
    elif step == "broadcast_wait":
        _wizard.pop(str(chat_id), None)
        msg = text[:3500]
        if not msg:
            await _send(chat_id, "متن خالی بود، لغو شد.")
            return
        async with LINKS_LOCK:
            targets = sorted({d.get("join_user") for d in LINKS.values() if d.get("join_user")})
        await _send(chat_id, f"⏳ در حال ارسال برای {len(targets)} کاربر در پس‌زمینه — بات همزمان به بقیه‌ی کاربرها هم جواب می‌ده...")
        # ✅ فیکس: قبلاً این حلقه inline (داخل همون پردازش آپدیت) اجرا می‌شد. چون
        # polling_loop آپدیت‌ها رو پشت‌سرهم پردازش می‌کنه، broadcast به چند هزار
        # کاربر (با فاصله‌ی 0.05s بین هرکدوم) می‌تونست چند دقیقه طول بکشه و در
        # تمام این مدت بات برای هیچ کاربر دیگه‌ای (even خودِ ادمین) جواب نمی‌داد.
        # حالا به‌صورت یک task مستقل در پس‌زمینه اجرا می‌شه.
        asyncio.create_task(_run_broadcast(chat_id, targets, msg))
    elif step == "ref_bonus_wait":
        _wizard.pop(str(chat_id), None)
        try:
            gb = max(0.0, float(text.replace(",", ".")))
        except ValueError:
            await _send(chat_id, "عدد معتبر نبود، لغو شد.")
            return
        REFERRAL_SETTINGS["bonus_gb"] = gb
        await save_state()
        await _send(chat_id, f"✅ مقدار هدیه‌ی رفرال روی {gb} گیگ تنظیم شد.")
        log_activity("system", f"ادمین {chat_id} مقدار هدیه‌ی رفرال را به {gb}GB تغییر داد", "ok")
    elif step == "ref_daily_wait":
        _wizard.pop(str(chat_id), None)
        try:
            cap = int(float(text.replace(",", ".")))
        except ValueError:
            await _send(chat_id, "عدد معتبر نبود، لغو شد.")
            return
        cap = max(0, cap)
        REFERRAL_SETTINGS["max_daily_credits"] = cap
        await save_state()
        cap_txt = "بدون سقف (نامحدود)" if cap == 0 else f"{cap} رفرال در روز"
        await _send(chat_id, f"✅ سقف روزانه‌ی رفرال روی «{cap_txt}» تنظیم شد.")
        log_activity("system", f"ادمین {chat_id} سقف روزانه‌ی رفرال را به {cap} تغییر داد", "ok")
    elif step == "ref_points_uid_wait":
        target = text.strip()
        if not target.lstrip("-").isdigit():
            await _send(chat_id, "این یه آیدی عددی معتبر نبود؛ دوباره بفرست یا /menu بزن.")
            return
        _wizard[str(chat_id)] = {"step": "ref_points_amount_wait", "data": {"target": target}}
        cur = REFERRALS.get(target, {}).get("points", 0)
        await _send(chat_id, f"امتیاز فعلی این کاربر: {cur}\n\nچند امتیاز بدم؟ (برای کم‌کردن، عدد منفی بزن، مثلاً -5):")
    elif step == "ref_points_amount_wait":
        _wizard.pop(str(chat_id), None)
        target = w["data"].get("target")
        try:
            delta = int(float(text.replace(",", ".")))
        except ValueError:
            await _send(chat_id, "عدد معتبر نبود، لغو شد.")
            return
        disp = _display_names.get(target, {})
        new_total = adjust_points(target, delta, disp.get("name", ""), disp.get("username", ""))
        await save_state()
        await _send(chat_id, f"✅ امتیاز کاربر <code>{target}</code> بروزرسانی شد. امتیاز فعلی: {new_total}")
        log_activity("system", f"ادمین {chat_id} به کاربر {target} {delta:+d} امتیاز داد (مجموع: {new_total})", "ok")
        if delta > 0:
            await _send(target, f"🎖 تبریک! ادمین بهت {delta} امتیاز داد.\nامتیاز فعلی‌ت: {new_total}")
        elif delta < 0:
            await _send(target, f"⚠️ {abs(delta)} امتیاز از حسابت کم شد.\nامتیاز فعلی‌ت: {new_total}")
    elif step == "filter_addcustom_cat_wait":
        cat = text.strip().lower()
        if cat not in ("ads", "adult"):
            await _send(chat_id, "فقط <code>ads</code> یا <code>adult</code> معتبره؛ دوباره بفرست یا /menu بزن.")
            return
        _wizard[str(chat_id)] = {"step": "filter_addcustom_domain_wait", "data": {"cat": cat}}
        await _send(chat_id, "دامنه رو بفرست (مثلاً example.com):")
    elif step == "filter_addcustom_domain_wait":
        _wizard.pop(str(chat_id), None)
        cat = w["data"].get("cat", "ads")
        ok = add_custom_blocked_domain(text, cat)
        if not ok:
            await _send(chat_id, "این دامنه معتبر نبود، لغو شد.")
            return
        await save_state()
        cat_fa = "تبلیغات" if cat == "ads" else "بزرگسال"
        await _send(chat_id, f"✅ دامنه به لیست {cat_fa} اضافه شد.")
        log_activity("system", f"ادمین {chat_id} دامنه‌ی «{text.strip()}» را به فیلتر {cat} اضافه کرد", "ok")
    elif step == "ref_template_wait":
        _wizard.pop(str(chat_id), None)
        new_template = text[:2000]
        if not new_template:
            await _send(chat_id, "متن خالی بود، لغو شد.")
            return
        REFERRAL_SETTINGS["message_template"] = new_template
        await save_state()
        await _send(chat_id, "✅ متن پیام رفرال بروزرسانی شد.")
        log_activity("system", f"ادمین {chat_id} متن پیام رفرال را تغییر داد", "ok")
    elif step == "search":
        _wizard.pop(str(chat_id), None)
        q = text.lower()
        async with LINKS_LOCK:
            hits = [(uid, d) for uid, d in LINKS.items() if q in d.get("label", "").lower()][:20]
        if not hits:
            await _send(chat_id, "چیزی پیدا نشد.", [[{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}]])
            return
        kb = [[{"text": _link_line(uid, d), "callback_data": f"l:{uid}"}] for uid, d in hits]
        kb.append([{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}])
        await _send(chat_id, f"🔍 {len(hits)} نتیجه:", kb)
    elif step == "gift_amount_wait":
        unit = w["data"]["unit"]
        user_id = str(chat_id)
        try:
            amount = float(text.replace(",", "."))
        except ValueError:
            await _send(chat_id, "عدد معتبر نبود؛ دوباره بفرست:")
            return
        if amount <= 0:
            await _send(chat_id, "عدد باید بزرگ‌تر از صفر باشه؛ دوباره بفرست:")
            return
        amount_bytes = int(amount * GIFT_UNITS[unit])
        ok, err, new_uid = await claim_gift_bytes(user_id, amount_bytes)
        if not ok:
            await _send(chat_id, f"❌ {err}\n\nدوباره یه عدد کوچیک‌تر بفرست یا /menu بزن.")
            return
        _wizard.pop(str(chat_id), None)
        async with LINKS_LOCK:
            primary_uid = USER_LINKS.get(user_id)
            primary = LINKS.get(primary_uid, {})
            remaining = fmt_bytes(primary.get("gift_pool_bytes", 0))
            claim_no = len(primary.get("gift_claims", []))
        now = datetime.now().strftime("%Y-%m-%d ساعت %H:%M:%S")
        unit_fa = "مگابایت" if unit == "MB" else "گیگابایت"
        log_activity("link", f"کاربر {chat_id} از هدیه‌ی ورودش {amount} {unit_fa} برداشت کرد", "ok")
        host = _safe_host()
        sub_url = f"https://{host}/sub/{new_uid}"
        await _send(
            chat_id,
            f"✅ برداشت شماره {claim_no} با موفقیت انجام شد!\n\n"
            f"📦 مقدار این برداشت: {amount} {unit_fa}\n"
            f"🕒 تاریخ و ساعت: {now}\n\n"
            f"🎁 مانده‌ی هدیه: {remaining}\n\n"
            f"🔗 لینک ساب مخصوص همین برداشت (جدا از بقیه‌ی برداشت‌هات):\n<code>{sub_url}</code>",
            [[{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}]],
        )
    elif step == "increase_quota":
        uid = w["data"]["uid"]
        try:
            extra_gb = max(0.0, float(text.replace(",", ".")))
        except ValueError:
            await _send(chat_id, "عدد معتبر نبود؛ دوباره بفرست:")
            return
        _wizard.pop(str(chat_id), None)
        async with LINKS_LOCK:
            link = LINKS.get(uid)
            if link:
                if link.get("limit_bytes", 0) == 0:
                    await _send(chat_id, "این کانفیگ نامحدود است؛ افزایش حجم لازم نیست.")
                    return
                link["limit_bytes"] += parse_size_to_bytes(extra_gb, "GB")
                link["quota_notified"] = False
        from main import schedule_save
        await schedule_save()
        await _send(chat_id, f"✅ {extra_gb}GB اضافه شد.", [[{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}]])


async def _handle_callback(chat_id, message_id, cb_id, data, is_admin: bool = False):
    await _answer_cb(cb_id)
    if data == "noop":
        return

    if _is_admin_only_action(data) and not is_admin:
        await _edit(
            chat_id, message_id, "⛔️ این بخش فقط برای مدیر پنل در دسترس است.",
            [[{"text": "🔄 بروزرسانی وضعیت کانفیگ من", "callback_data": "j:check"}]]
        )
        return

    if data == "j:check":
        await _handle_join_start(chat_id, message_id)
        return

    if data == "owner:info":
        await _show_owner_info(chat_id, message_id)
        return

    if data == "mystatus":
        await _show_my_status(chat_id, message_id)
        return

    if data == "gift:start":
        user_id = str(chat_id)
        uid = USER_LINKS.get(user_id)
        d = LINKS.get(uid) if uid else None
        if not uid or not d:
            await _send(chat_id, "اول باید خودت یک کانفیگ داشته باشی؛ از /menu شروع کن.")
            return
        pool = d.get("gift_pool_bytes", 0)
        if pool <= 0:
            await _edit(chat_id, message_id, "🎁 دیگه چیزی از هدیه‌ی ورودت باقی نمونده.", [[{"text": "⬅️ بازگشت", "callback_data": "m:main"}]])
            return
        _wizard.pop(str(chat_id), None)
        text = f"🎁 مانده‌ی هدیه‌ات: <b>{fmt_bytes(pool)}</b>\n\nبا چه واحدی می‌خوای برداشت کنی؟"
        kb = [
            [{"text": "مگابایت (MB)", "callback_data": "gift:unit:MB"}, {"text": "گیگابایت (GB)", "callback_data": "gift:unit:GB"}],
            [{"text": "❌ انصراف", "callback_data": "m:main"}],
        ]
        await _edit(chat_id, message_id, text, kb)
        return

    if data.startswith("gift:unit:"):
        unit = data.split(":", 2)[2]
        if unit not in GIFT_UNITS:
            return
        user_id = str(chat_id)
        uid = USER_LINKS.get(user_id)
        d = LINKS.get(uid) if uid else None
        if not uid or not d:
            await _send(chat_id, "اول باید خودت یک کانفیگ داشته باشی؛ از /menu شروع کن.")
            return
        pool = d.get("gift_pool_bytes", 0)
        pool_in_unit = pool / GIFT_UNITS[unit]
        _wizard[str(chat_id)] = {"step": "gift_amount_wait", "data": {"uid": uid, "unit": unit}}
        unit_fa = "مگابایت" if unit == "MB" else "گیگابایت"
        await _edit(
            chat_id, message_id,
            f"🎁 مانده‌ی هدیه به {unit_fa}: <b>{pool_in_unit:.2f}</b>\n\nچقدر می‌خوای برداشت کنی؟ عدد رو بفرست:",
            [[{"text": "❌ انصراف", "callback_data": "m:main"}]],
        )
        return

    if data == "sup:start":
        _wizard[str(chat_id)] = {"step": "support_wait", "data": {}}
        await _send(chat_id, "✍️ پیامت رو بنویس و بفرست، مستقیم برای پشتیبانی ارسال می‌شه:\n\n❌ برای انصراف /menu رو بزن.")
        return

    if data == "ref:me":
        user_id = str(chat_id)
        if not USER_LINKS.get(user_id):
            await _send(chat_id, "اول باید خودت یک کانفیگ داشته باشی. از /menu شروع کن.")
            return
        bot_username = await _get_bot_username()
        if not bot_username:
            await _send(chat_id, "⚠️ فعلاً لینک رفرال در دسترس نیست، بعداً امتحان کن.")
            return
        ref_link = f"https://t.me/{bot_username}?start=ref_{user_id}"
        ref_count = REFERRALS.get(user_id, {}).get("count", 0)
        template = REFERRAL_SETTINGS.get("message_template", "{ref_link}")
        try:
            text = template.format(bonus_gb=REFERRAL_SETTINGS.get("bonus_gb", 5), ref_link=ref_link, ref_count=ref_count)
        except Exception:
            text = f"🔗 لینک رفرال تو:\n<code>{ref_link}</code>\n\nتعداد رفرال موفق: {ref_count}"
        if not REFERRAL_SETTINGS.get("enabled", True):
            text += "\n\n⚠️ سیستم رفرال فعلاً موقتاً غیرفعاله."
        await _send(chat_id, text)
        return

    if data == "ref:board":
        await _send_leaderboard(chat_id)
        return

    if data.startswith("sup:reply:"):
        target = data.split(":", 2)[2]
        _wizard[str(chat_id)] = {"step": "support_reply_wait", "data": {"target": target}}
        await _send(chat_id, f"✍️ پاسخت به کاربر <code>{target}</code> رو بنویس:")
        return

    if data == "m:broadcast":
        _wizard[str(chat_id)] = {"step": "broadcast_wait", "data": {}}
        await _send(chat_id, "📢 متن پیامی که می‌خوای برای همه‌ی کاربرای بات فرستاده بشه رو بفرست:\n\n❌ برای انصراف /menu رو بزن.")
        return

    if data == "m:ref":
        await _show_referral_admin(chat_id, message_id)
        return

    if data == "ref:toggle":
        REFERRAL_SETTINGS["enabled"] = not REFERRAL_SETTINGS.get("enabled", True)
        await save_state()
        await _show_referral_admin(chat_id, message_id)
        return

    if data == "ref:setbonus":
        _wizard[str(chat_id)] = {"step": "ref_bonus_wait", "data": {}}
        await _send(chat_id, f"مقدار فعلی هدیه: {REFERRAL_SETTINGS.get('bonus_gb', 5)} گیگ.\n\nمقدار جدید (گیگابایت) رو بفرست:")
        return

    if data == "ref:setdaily":
        _wizard[str(chat_id)] = {"step": "ref_daily_wait", "data": {}}
        cur = REFERRAL_SETTINGS.get("max_daily_credits", 0)
        cur_txt = "بدون سقف" if cur <= 0 else str(cur)
        await _send(chat_id, f"سقف فعلی: {cur_txt}\n\nعدد جدید رو بفرست (۰ یعنی نامحدود/بدون سقف):")
        return

    if data == "ref:settemplate":
        _wizard[str(chat_id)] = {"step": "ref_template_wait", "data": {}}
        await _send(
            chat_id,
            "متن جدید پیام رفرال رو بفرست. می‌تونی از این جاهای‌خالی استفاده کنی:\n"
            "<code>{bonus_gb}</code> عدد هدیه، <code>{ref_link}</code> لینک اختصاصی، <code>{ref_count}</code> تعداد رفرال موفق.\n\n"
            f"متن فعلی:\n{REFERRAL_SETTINGS.get('message_template', '')}",
        )
        return

    if data == "ref:givepoints":
        _wizard[str(chat_id)] = {"step": "ref_points_uid_wait", "data": {}}
        await _send(chat_id, "آیدی عددی کاربر (chat_id) رو بفرست:")
        return

    if data == "m:filter":
        await _show_filter_admin(chat_id, message_id)
        return

    if data == "filter:toggle:ads":
        FILTER_SETTINGS["block_ads"] = not FILTER_SETTINGS.get("block_ads", False)
        await save_state()
        await _show_filter_admin(chat_id, message_id)
        return

    if data == "filter:toggle:adult":
        FILTER_SETTINGS["block_adult"] = not FILTER_SETTINGS.get("block_adult", False)
        await save_state()
        await _show_filter_admin(chat_id, message_id)
        return

    if data == "filter:refreshadult":
        await _answer_cb(cb_id, "در حال دانلود لیست...")
        count = await refresh_adult_blocklist()
        if count < 0:
            await _send(chat_id, "❌ دانلود لیست ناموفق بود (شاید دسترسی شبکه یا منبع موقتاً در دسترس نیست). لیست قبلی دست‌نخورده موند.")
        else:
            await _send(chat_id, f"✅ لیست بزرگسال بروزرسانی شد: {count} دامنه.")
            log_activity("system", f"لیست فیلتر بزرگسال توسط ادمین {chat_id} بروزرسانی شد ({count} دامنه)", "ok")
        await _show_filter_admin(chat_id, message_id)
        return

    if data == "filter:addcustom":
        _wizard[str(chat_id)] = {"step": "filter_addcustom_cat_wait", "data": {}}
        await _send(chat_id, "این دامنه رو به کدوم دسته اضافه کنم؟\nبنویس: <code>ads</code> یا <code>adult</code>")
        return

    if data == "m:main":
        _wizard.pop(str(chat_id), None)
        if is_admin:
            await _show_main_menu(chat_id, message_id)
        else:
            await _handle_join_start(chat_id, message_id)
    elif data == "m:help":
        await _show_help(chat_id, message_id)
    elif data == "m:new":
        await _wizard_start(chat_id, message_id)
    elif data.startswith("m:list:"):
        await _show_list(chat_id, message_id, int(data.split(":")[2]))
    elif data == "m:stats":
        await _show_stats(chat_id, message_id)
    elif data == "m:search":
        _wizard[str(chat_id)] = {"step": "search", "data": {}}
        await _edit(chat_id, message_id, "🔍 بخشی از اسم کانفیگ رو بفرست:", [[{"text": "❌ انصراف", "callback_data": "m:main"}]])
    elif data.startswith("m:subs:"):
        await _show_subs(chat_id, message_id, int(data.split(":")[2]))
    elif data.startswith("m:copy:"):
        uid = data.split(":", 2)[2]
        # هر کاربر می‌تونه یا لینک اصلی خودش (USER_LINKS) یا هرکدوم از لینک‌های
        # جداگانه‌ای که از برداشت‌های هدیه ساخته (join_user == خودش) رو بگیره.
        owns_it = USER_LINKS.get(str(chat_id)) == uid or LINKS.get(uid, {}).get("join_user") == str(chat_id)
        if not is_admin and not owns_it:
            await _answer_cb(cb_id, "⛔️ اجازه دسترسی به این کانفیگ را نداری.")
            return
        host = _safe_host()
        await _send(chat_id, f"✅ لینک ساب کپی شد!\n\n<code>https://{host}/sub/{uid}</code>")
    elif data.startswith("q:"):
        val = data[2:]
        w = _wizard.get(str(chat_id))
        if not w:
            return
        if val == "custom":
            w["step"] = "quota_custom"
            await _edit(chat_id, message_id, "✏️ مقدار حجم رو به گیگابایت بفرست (مثلاً 7.5):", [[{"text": "❌ انصراف", "callback_data": "m:main"}]])
        else:
            w["data"]["quota_gb"] = float(val)
            w["step"] = "expiry"
            await _wizard_ask_expiry(chat_id, message_id)
    elif data.startswith("e:"):
        val = data[2:]
        w = _wizard.get(str(chat_id))
        if not w:
            return
        if val == "custom":
            w["step"] = "expiry_custom"
            await _edit(chat_id, message_id, "✏️ تعداد روز رو بفرست (مثلاً 3):", [[{"text": "❌ انصراف", "callback_data": "m:main"}]])
        else:
            w["data"]["expiry_days"] = float(val) if val != "0" else None
            await _wizard_finish(chat_id, message_id)
    elif data.startswith("l:"):
        await _show_link_detail(chat_id, message_id, data[2:])
    elif data.startswith("lt:"):
        uid = data[3:]
        async with LINKS_LOCK:
            link = LINKS.get(uid)
            if link:
                link["active"] = not link.get("active", True)
        from main import schedule_save
        await schedule_save()
        await _show_link_detail(chat_id, message_id, uid)
    elif data.startswith("lr:"):
        uid = data[3:]
        async with LINKS_LOCK:
            link = LINKS.get(uid)
            if link:
                link["used_bytes"] = 0
                link["quota_notified"] = False
        from main import schedule_save
        await schedule_save()
        await _answer_cb(cb_id, "مصرف ریست شد ✓")
        await _show_link_detail(chat_id, message_id, uid)
    elif data.startswith("li:"):
        uid = data[3:]
        _wizard[str(chat_id)] = {"step": "increase_quota", "data": {"uid": uid}}
        await _edit(chat_id, message_id, "✏️ چند گیگابایت اضافه شود؟ (مثلاً 5):", [[{"text": "❌ انصراف", "callback_data": "m:main"}]])
    elif data.startswith("lg:"):
        await _send_link_and_qr(chat_id, data[3:])
    elif data.startswith("ldc:"):
        uid = data[4:]
        async with LINKS_LOCK:
            label = LINKS.get(uid, {}).get("label", uid)
            LINKS.pop(uid, None)
        from main import schedule_save
        await schedule_save()
        log_activity("link", f"کانفیگ «{label}» از بات تلگرام حذف شد", "warn")
        await _edit(chat_id, message_id, f"🗑 «{label}» حذف شد.", [[{"text": "⬅️ لیست", "callback_data": "m:list:0"}]])
    elif data.startswith("ldn:"):
        await _show_link_detail(chat_id, message_id, data[4:])
    elif data.startswith("ld:"):
        uid = data[3:]
        await _edit(chat_id, message_id, "⚠️ مطمئنی این کانفیگ کامل حذف شود؟ این عمل قابل بازگشت نیست.",
                     [[{"text": "✅ بله، حذف شود", "callback_data": f"ldc:{uid}"}, {"text": "❌ نه", "callback_data": f"ldn:{uid}"}]])
    elif data.startswith("st:"):
        sub_id = data[3:]
        await _toggle_sub_lock(chat_id, message_id, sub_id)


async def _show_subs(chat_id, message_id, page: int):
    async with SUBS_LOCK:
        items = sorted(SUBS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    chunk = items[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    kb = []
    for sid, s in chunk:
        lock_icon = "🔒" if s.get("locked") else "🔓"
        kb.append([
            {"text": f"{'🔒' if s.get('locked') else '📂'} {s.get('name','?')} ({len(s.get('link_ids', []))})", "callback_data": "noop"},
            {"text": f"{lock_icon} {'باز کن' if s.get('locked') else 'قفل کن'}", "callback_data": f"st:{sid}"},
        ])
    nav = []
    if page > 0:
        nav.append({"text": "◀️ قبلی", "callback_data": f"m:subs:{page-1}"})
    nav.append({"text": f"{page+1}/{pages}", "callback_data": "noop"})
    if page < pages - 1:
        nav.append({"text": "بعدی ▶️", "callback_data": f"m:subs:{page+1}"})
    kb.append(nav)
    kb.append([{"text": "⬅️ منوی اصلی", "callback_data": "m:main"}])
    text = f"📂 <b>گروه‌های ساب</b> ({total} گروه)" if total else "هنوز هیچ گروه سابی ساخته نشده."
    await _edit(chat_id, message_id, text, kb)


async def _toggle_sub_lock(chat_id, message_id, sub_id):
    async with SUBS_LOCK:
        s = SUBS.get(sub_id)
        if s:
            s["locked"] = not s.get("locked")
            name, locked = s["name"], s["locked"]
    from main import schedule_save
    await schedule_save()
    if s:
        log_activity("sub", f"گروه «{name}» از بات تلگرام {'قفل' if locked else 'باز'} شد", "warn" if locked else "ok")
    await _show_subs(chat_id, message_id, 0)


async def _process_update(update: dict):
    try:
        if "callback_query" in update:
            cq = update["callback_query"]
            chat_id = cq["message"]["chat"]["id"]
            is_admin = _is_admin(chat_id)
            if not is_admin and not _flood_check(chat_id):
                # بی‌صدا نادیده می‌گیریم؛ فقط لودینگ روی دکمه رو (بی‌صدا) می‌بندیم
                # تا برای کاربر لوپ لودینگ نمونه.
                await _answer_cb(cq["id"])
                return
            _remember_display_name(chat_id, cq.get("from") or {})
            await _handle_callback(chat_id, cq["message"]["message_id"], cq["id"], cq.get("data", ""), is_admin)
        elif "message" in update:
            msg = update["message"]
            chat_id = msg["chat"]["id"]
            chat_type = msg["chat"].get("type", "private")
            if not _is_admin(chat_id) and not _flood_check(chat_id):
                return  # بی‌صدا نادیده می‌گیریم — پیام هشدار هم خودش می‌تونه اسپم بشه
            await _handle_text(chat_id, msg.get("text", ""), _is_admin(chat_id), msg.get("from") or {}, chat_type)
    except Exception as e:
        logger.warning(f"telegram_bot: process_update error: {e}")


async def polling_loop():
    global _offset, _running
    _running = True
    logger.info("telegram_bot: polling loop started [build: gift-pool-v2 + group-fix]")
    await _get_bot_username()  # پیش‌گرم کردن کش یوزرنیم بات تا لینک رفرال از همون اول درست باشد

    # آپدیت‌های قدیمی/باقی‌مانده از قبل از استارت را فقط یک‌بار در ابتدا دور بریز؛
    # قبلاً drop_pending_updates روی هر تک تک درخواست‌های getUpdates فرستاده می‌شد که
    # اصلاً پارامتر معتبری برای این متد نیست (فقط برای setWebhook/deleteWebhook تعریف شده)
    # و صرفاً نادیده گرفته می‌شد؛ اینجا کار درستش را یک‌بار با offset=-1 انجام می‌دهیم.
    try:
        pending = await _api("getUpdates", {"offset": -1, "timeout": 0})
        if pending:
            _offset = pending[-1]["update_id"] + 1
    except Exception:
        pass

    consecutive_errors = 0
    while True:
        try:
            if not (TELEGRAM_SETTINGS.get("enabled") and TELEGRAM_SETTINGS.get("bot_token")):
                await asyncio.sleep(5)
                continue
            result = await _api("getUpdates", {
                "offset": _offset,
                "timeout": 25,
                "allowed_updates": ["message", "callback_query"],
            })
            if result is None:
                # چند بار پشت‌سرهم خطا یعنی احتمالاً توکن غلط است یا تلگرام موقتاً محدودمان کرده؛
                # backoff نمایی می‌زنیم تا به جای اسپم کردن API، فشار را کم کنیم و ریت‌لیمیت/بن نشویم.
                consecutive_errors += 1
                await asyncio.sleep(min(60, 5 * (2 ** min(consecutive_errors, 4))))
                continue
            consecutive_errors = 0
            for update in result:
                _offset = update["update_id"] + 1
                await _process_update(update)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"telegram_bot: polling_loop error: {e}")
            consecutive_errors += 1
            await asyncio.sleep(min(60, 5 * (2 ** min(consecutive_errors, 4))))
    _running = False
    logger.info("telegram_bot: polling loop stopped")


# ══════════════════════════════════════════════════════════════════════════════
# فیچر: قفل/بازکردن خودکار کانفیگ بر اساس عضویت در کانال
# هر چند دقیقه یک‌بار عضویت کاربرانی که کانفیگشان را از مسیر «ورود به بات + عضویت
# در کانال» گرفته‌اند (link["join_user"] ست شده) چک می‌شود:
#   - اگر کانال را ترک کرده و کانفیگش فعال است → غیرفعال می‌شود + پیام هشدار.
#   - اگر دوباره عضو شده و قبلاً همین سیستم غیرفعالش کرده بود → دوباره فعال می‌شود + پیام اطلاع.
# کانفیگ‌هایی که ادمین دستی ساخته (join_user ندارند) هرگز دست‌خورده نمی‌شوند.
# توجه: این پیام از طریق خودِ بات تلگرام فرستاده می‌شود، نه پیامک واقعی — این
# پروژه هیچ سرویس ارسال SMS ندارد.
# ══════════════════════════════════════════════════════════════════════════════
CHANNEL_WATCH_INTERVAL = 600   # هر ۱۰ دقیقه یک دور کامل چک
CHANNEL_WATCH_STAGGER = 0.35   # فاصله بین هر getChatMember تا به API تلگرام فشار نیاریم و ریت‌لیمیت/بن نشیم

# ✅ فیچر: پاک‌سازی دوره‌ای state‌های موقتی رهاشده. بدون این، هر کاربری که یک
# فلوی چندمرحله‌ای (ویزارد) یا رفرال در انتظار رو شروع کنه و نصفه‌کاره رها
# کنه، برای همیشه یک entry تو حافظه می‌مونه — با رشد تعداد کاربرها در طول
# ماه‌ها، این خودش یه نشتی حافظه‌ی آهسته و پیوسته می‌شه.
WIZARD_IDLE_TTL = 1800     # ۳۰ دقیقه بی‌فعالیت → ویزارد رهاشده حساب می‌شه
PENDING_REF_TTL = 3600     # ۱ ساعت — بیشتر از این یعنی onboarding کاربر کامل نشده
HOUSEKEEPING_INTERVAL = 300  # هر ۵ دقیقه


async def housekeeping_loop():
    logger.info("telegram_bot: housekeeping_loop started")
    while True:
        await asyncio.sleep(HOUSEKEEPING_INTERVAL)
        try:
            n1 = _wizard.prune(WIZARD_IDLE_TTL)
            n2 = _pending_referrer.prune(PENDING_REF_TTL)
            if n1 or n2:
                logger.info(f"telegram_bot: housekeeping پاک کرد → ویزارد رهاشده={n1}, رفرال رهاشده={n2}")
        except Exception as e:
            logger.warning(f"telegram_bot: housekeeping_loop error: {e}")


async def channel_watch_loop():
    logger.info("telegram_bot: channel_watch_loop started")
    while True:
        await asyncio.sleep(CHANNEL_WATCH_INTERVAL)
        try:
            if not (TELEGRAM_SETTINGS.get("enabled") and TELEGRAM_SETTINGS.get("bot_token")):
                continue
            if not JOIN_SETTINGS.get("channel_required", True):
                continue

            async with LINKS_LOCK:
                # اسنپ‌شات می‌گیریم تا در طول چک عضویت (که چند ثانیه طول می‌کشد) قفل را نگه نداریم
                candidates = [(uid, d.get("join_user")) for uid, d in LINKS.items() if d.get("join_user")]

            changed = False
            for uid, user_id in candidates:
                if not user_id:
                    continue
                try:
                    status, missing = await check_join_status(user_id, TELEGRAM_SETTINGS.get("bot_token"))
                except Exception:
                    continue
                await asyncio.sleep(CHANNEL_WATCH_STAGGER)

                # اگر وضعیت نامعلوم بود (خطای شبکه/تایم‌اوت/ریت‌لیمیت تلگرام)، هیچ کاری نکن —
                # قبلاً اینجا چنین حالتی مثل «کاربر کانال را ترک کرده» رفتار می‌شد و باعث
                # غیرفعال‌شدن اشتباهِ کانفیگ کاربرهای واقعی به‌خاطر یک خطای موقت تلگرام می‌شد.
                if status is None:
                    continue

                async with LINKS_LOCK:
                    link = LINKS.get(uid)
                    if link is None:
                        continue
                    was_active = link.get("active", True)
                    disabled_by_leave = link.get("disabled_by_leave", False)

                    if status is False and was_active:
                        link["active"] = False
                        link["disabled_by_leave"] = True
                        label = link.get("label", "کانفیگ")
                        action = "disabled"
                    elif status is True and (not was_active) and disabled_by_leave:
                        link["active"] = True
                        link["disabled_by_leave"] = False
                        label = link.get("label", "کانفیگ")
                        action = "enabled"
                    else:
                        continue

                changed = True
                if action == "disabled":
                    bad = missing if missing else get_join_channels()
                    plural = "کانال‌های" if len(bad) > 1 else "کانال"
                    log_activity("sub", f"کانفیگ «{label}» به‌خاطر ترک {plural} توسط کاربر {user_id} غیرفعال شد", "warn")
                    kb = _channels_kb_rows(bad) if bad else None
                    await _send(
                        user_id,
                        f"⚠️ متوجه شدیم از {plural} زیر خارج شدید:\n{_channels_text_block(bad)}\n\n"
                        f"طبق قوانین، کانفیگ رایگان «{label}» شما موقتاً <b>غیرفعال</b> شد.\n"
                        f"برای فعال‌سازی دوباره، کافیه دوباره عضو {plural} بشید — خودکار فعال می‌شه.",
                        kb,
                    )
                else:
                    channels = get_join_channels()
                    plural = "کانال‌های" if len(channels) > 1 else "کانال"
                    log_activity("sub", f"کانفیگ «{label}» بعد از بازگشت کاربر {user_id} به {plural} دوباره فعال شد", "ok")
                    await _send(
                        user_id,
                        f"✅ عضویت شما در {plural} زیر دوباره تایید شد:\n{_channels_text_block(channels)}\n\n"
                        f"کانفیگ «{label}» شما دوباره <b>فعال</b> شد. لینک ساب همانی است که قبلاً داشتید.",
                    )

            if changed:
                asyncio.create_task(save_state())
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"telegram_bot: channel_watch_loop error: {e}")
