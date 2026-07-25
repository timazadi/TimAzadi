# rate_limiter.py
# ============================================================
# 🛡️ Rate Limiting - جلوگیری از اسپم درخواست
# ============================================================
from collections import defaultdict
import time
import asyncio

RATE_LIMIT = 20
RATE_WINDOW = 60

_rate_store = defaultdict(list)
_rate_lock = asyncio.Lock()

# باگ قبلی: IPهایی که دیگر درخواست نمی‌فرستند هیچ‌وقت از دیکشنری پاک نمی‌شدند →
# نشتی حافظه‌ی پیوسته روی سرور طولانی‌مدت (و می‌تواند خودش به یک بردار DoS تبدیل شود
# چون هر IP جدید یک entry دائمی می‌سازد). هر چند تماس، یک پاک‌سازی سبک انجام می‌دهیم.
_CLEANUP_EVERY = 500
_calls_since_cleanup = 0

async def check_rate_limit(ip: str) -> bool:
    global _calls_since_cleanup
    now = time.time()
    async with _rate_lock:
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
        allowed = len(_rate_store[ip]) < RATE_LIMIT
        if allowed:
            _rate_store[ip].append(now)
        elif not _rate_store[ip]:
            # اگر لیست خالی مانده (rate limit رد نشده ولی چیزی هم اضافه نشد) پاکش کن
            _rate_store.pop(ip, None)

        _calls_since_cleanup += 1
        if _calls_since_cleanup >= _CLEANUP_EVERY:
            _calls_since_cleanup = 0
            stale_ips = [k for k, v in _rate_store.items() if not v]
            for k in stale_ips:
                _rate_store.pop(k, None)

        return allowed
