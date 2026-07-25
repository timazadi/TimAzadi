# relay_vless.py
# بخش VLESS Relay — جدا شده از main.py (منطق اصلی دست‌نخورده)
# تغییر: ثبت IP واقعی کلاینت (با احتساب هدر x-forwarded-for پشت پراکسی) در connections

import asyncio
import hashlib
import secrets
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from state import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    save_state,
    log_activity,
    now_ir,
    client_ip,  # ✅ یکی‌سازی شد: قبلاً نسخه‌ی جداگانه‌ی _ws_client_ip اینجا بود
    is_device_allowed,
    record_traffic,
    is_domain_blocked,
    CONN_LIMITER,  # ✅ سقف سراسری تعداد کانکشن هم‌زمان (جلوگیری از OOM زیر فشار)
)
import time

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay — بهینه‌شده برای حداکثر throughput
# ══════════════════════════════════════════════════════════════════════════════

RELAY_BUF = 512 * 1024   # 512 KB — هماهنگ با xhttp_siz10؛ چانک بزرگ‌تر یعنی syscall/context-switch کمتر به‌ازای هر بایت روی لینک‌های پرسرعت

# قبلاً هیچ idle-timeout ای روی تونل خام WS نبود؛ یک کلاینت که وصل می‌مونه ولی
# دیگه هیچ دیتایی رد و بدل نمی‌کنه (قطعی شبکه بی‌خبر، اپلیکیشن فرانت که کرش کرده
# ولی سوکت هنوز باز مونده و ...) برای همیشه یک کانکشن (و یک تسک asyncio، و یک
# سوکت TCP سمت مقصد) را زنده نگه می‌داشت. با تعداد زیاد این‌ها، حافظه/فایل-دیسکریپتور
# روی Railway تمام می‌شه و کانتینر کرش/ری‌استارت می‌کنه. الان بعد از این مدت بی‌فعالیت
# (بدون هیچ بایت رد و بدل شده در هیچ جهتی) کانکشن بسته می‌شه.
IDLE_TIMEOUT = 180  # ثانیه

async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]

# ✅ فیچر: پروتکل Trojan (روی همان WebSocket) — فریم روی سیم متفاوت از VLESS
# است: ۵۶ کاراکتر هگزِ SHA224(پسورد) + CRLF + یک درخواست به‌سبک SOCKS5
# (cmd, atyp, addr, port) + CRLF + payload. پسورد همان UUID کانفیگ است، پس
# سرور مقدار مورد انتظار را بدون ذخیره‌ی جداگانه، از خودِ uuid حساب می‌کند.
def trojan_expected_hex(uuid: str) -> str:
    return hashlib.sha224(uuid.encode()).hexdigest()

async def parse_trojan_header(chunk: bytes, expected_hex: str):
    if len(chunk) < 56 + 2 + 1 + 1 + 2 + 2:
        raise ValueError("chunk too small")
    if chunk[:56].decode("ascii", errors="ignore") != expected_hex:
        raise ValueError("bad trojan password")
    pos = 56 + 2  # 56 هگز + CRLF
    _cmd = chunk[pos]; pos += 1
    atyp = chunk[pos]; pos += 1
    if atyp == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif atyp == 3:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif atyp == 4:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown atyp: {atyp}")
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    pos += 2  # CRLF پایانی
    return address, port, chunk[pos:]

async def check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[now_ir().strftime("%H:00")] += n
        record_traffic(uid, n)
    return True


# ══════════════════════════════════════════════════════════════════════════════
# ✅ فیکس: قبلاً check_and_use (که هر بار یک قفل سراسری LINKS_LOCK می‌گیرد) به‌ازای
# هر تک تکه‌ی دیتا در هر دو جهت رله صدا زده می‌شد. زیر بار سنگین (صدها کانکشن
# هم‌زمان با ترافیک بالا) این باعث می‌شد قفل سراسری مدام بین کانکشن‌ها رقابت شود و
# event loop کند شود — تا جایی که حتی /health هم دیر جواب می‌داد و Railway سرویس را
# unhealthy تشخیص می‌داد. اینجا مثل الگوی _QuotaGate در xhttp_siz10.py، مصرف را
# batch می‌کنیم و فقط هر چند بار یا هر چند میلی‌ثانیه یک‌بار قفل سراسری را می‌گیریم.
_GATE_MIN_BATCH = 32 * 1024
_GATE_MAX_BATCH = 512 * 1024
_GATE_CHECK_INTERVAL = 0.2


class _RelayQuotaGate:
    __slots__ = ("uid", "pending", "last_check", "ok", "batch_bytes", "rate_ewma")

    def __init__(self, uid: str):
        self.uid = uid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = _GATE_MIN_BATCH
        self.rate_ewma = 0.0

    async def add(self, nbytes: int) -> bool:
        if not self.ok:
            return False
        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check
        if self.pending >= self.batch_bytes or elapsed >= _GATE_CHECK_INTERVAL:
            flush, self.pending = self.pending, 0
            if elapsed > 0:
                inst_rate = flush / elapsed
                self.rate_ewma = (
                    inst_rate if self.rate_ewma == 0
                    else 0.7 * self.rate_ewma + 0.3 * inst_rate
                )
                target = int(self.rate_ewma * _GATE_CHECK_INTERVAL)
                self.batch_bytes = max(_GATE_MIN_BATCH, min(_GATE_MAX_BATCH, target or _GATE_MIN_BATCH))
            self.last_check = now
            self.ok = await check_and_use(self.uid, flush)
            return self.ok
        return True

    async def flush(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            self.ok = self.ok and await check_and_use(self.uid, flush)
        return self.ok

async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str, gate: "_RelayQuotaGate"):
    try:
        while True:
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                logger.info(f"⏱ WS [{conn_id}] idle timeout, closing")
                break
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await gate.add(len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        await gate.flush()
        try:
            writer.write_eof()
        except Exception:
            pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str, gate: "_RelayQuotaGate", reply_prefix: bytes = b"\x00\x00"):
    first = True
    try:
        while True:
            try:
                data = await asyncio.wait_for(reader.read(RELAY_BUF), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                logger.info(f"⏱ TCP [{conn_id}] idle timeout, closing")
                break
            if not data:
                break
            if not await gate.add(len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            connections[conn_id]["bytes"] += len(data)
            # ✅ پرانتز پروتکلی: VLESS انتظار ۲ بایت پاسخ نسخه در اولین پکت
            # جواب را دارد؛ Trojan همچین چیزی نمی‌خواهد (raw passthrough)،
            # پس برای آن reply_prefix خالی پاس داده می‌شود.
            payload = (reply_prefix + data) if (first and reply_prefix) else data
            first = False
            await ws.send_bytes(payload)
    except Exception:
        pass
    finally:
        await gate.flush()

async def websocket_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… (not allowed)")
        # ✅ ضد-پروبینگ: قبلاً reason="not authorized" در فریم close فرستاده
        # می‌شد که یک امضای شناسایی‌شدنی برای ابزارهای پروب فعال DPI است.
        # کد بستن عمومی (1000) بدون متن اختصاصی، رفتار سرور را از یک
        # وب‌سرور معمولی که یک اتصال WS نامعتبر را می‌بندد، کمتر متمایز می‌کند.
        await ws.close(code=1000)
        return

    ip = client_ip(ws)

    # ✅ فیچر: محدودیت تعداد دستگاه/IP هم‌زمان — اگر ادمین برای این کانفیگ
    # سقفی گذاشته و همین حالا از تعداد IPهای مجاز رد شده، اتصال جدید (از
    # یک IP جدید) رد می‌شود بدون این‌که به کلاینت پروبینگ‌پذیر اطلاع بدهد.
    if not is_device_allowed(uuid, ip):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… (device/IP limit reached, ip={ip})")
        log_activity("connection", f"اتصال از {ip} به‌خاطر سقف تعداد دستگاه رد شد (کانفیگ {link.get('label','?')})", "warn")
        await ws.close(code=1000)
        return

    # ✅ فیکس: سقف سراسری تعداد کانکشن هم‌زمان — قبل از این‌که هیچ منبعی (سوکت TCP،
    # بافر، تسک) تخصیص بدیم چک می‌کنیم؛ اگر سرویس به سقف رسیده، اتصال را رد می‌کنیم
    # به‌جای این‌که بی‌حدوحصر بپذیریم و زیر فشار حافظه‌ی کانتینر را منفجر کنیم.
    if not await CONN_LIMITER.try_acquire():
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… (server at max concurrent connections)")
        await ws.close(code=1013)  # 1013 = Try Again Later
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",  # بعد از تشخیص واقعی پروتکل از روی بایت‌ها، پایین‌تر اصلاح می‌شود
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"✅ WS [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    log_activity("connection", f"اتصال جدید از {ip} (کانفیگ {link.get('label','?')})", "info")
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        # ✅ تشخیصِ پروتکل از روی خودِ بایت‌های رسیده، نه فیلد protocol
        # ذخیره‌شده‌ی لینک — چون هر uuid همزمان هم یک لینک vless و هم یک
        # لینک trojan معتبر دارد (هر دو به همین یک روت /ws/{uuid} وصل
        # می‌شوند) و protocol ذخیره‌شده فقط برای نمایش پیش‌فرض در پنل است.
        expected_hex = trojan_expected_hex(uuid).encode()
        is_trojan = first_chunk[:56] == expected_hex
        connections[conn_id]["transport"] = "trojan-ws" if is_trojan else "vless-ws"
        if is_trojan:
            address, port, payload = await parse_trojan_header(first_chunk, trojan_expected_hex(uuid))
        else:
            _command, address, port, payload = await parse_vless_header(first_chunk)

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        blocked, category = is_domain_blocked(address)
        if blocked:
            logger.info(f"🚫 [{conn_id}] blocked ({category}): {address}")
            log_activity("connection", f"اتصال به {address} به‌خاطر فیلتر {category} مسدود شد", "warn")
            await ws.close(code=1000)
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"➡️  [{conn_id}] → {address}:{port}")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port),
            timeout=10.0
        )
        sock = writer.transport.get_extra_info('socket')
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                # ✅ فیکس: قبلاً ۲MB بود؛ با سقف سراسری کانکشن جدید هم ترکیب می‌شود ولی
                # همچنان هرچه بافر هر کانکشن کوچک‌تر باشد، مصرف کل حافظه زیر بار
                # پایین‌تر می‌آید. ۱MB برای throughput کافی و امن‌تر برای حافظه است.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 * 1024 * 1024)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 * 1024 * 1024)
                if hasattr(socket, "TCP_QUICKACK"):  # فقط لینوکس؛ تاخیر ACK رو حذف می‌کنه
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
            except OSError:
                pass

        if payload:
            writer.write(payload)
            await writer.drain()

        gate = _RelayQuotaGate(uuid)
        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid, gate)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid, gate, reply_prefix=(b"" if is_trojan else b"\x00\x00"))),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        # قبلاً بعد از پایان رله، خودِ ws هیچ‌وقت صریحاً بسته نمی‌شد (فقط سوکت
        # TCP مقصد در finally پایینی بسته می‌شد). یعنی اگر طرف مقابل (سایت مقصد)
        # کانکشن را عادی می‌بست، سوکت WebSocket سمت کلاینت باز/معلق باقی می‌ماند
        # تا زمانی که خودِ کلاینت یا timeout سطح uvicorn آن را ببندد — یعنی کانکشن‌های
        # زامبی که فقط منابع مصرف می‌کنند. حالا صریحاً می‌بندیمش.
        try:
            await ws.close()
        except Exception:
            pass

        asyncio.create_task(save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        await CONN_LIMITER.release()
        logger.info(f"🔌 WS closed [{conn_id}] total={len(connections)}")
