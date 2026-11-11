"""স্তর ২ রেট লিমিট (হাইব্রিড shared/local) ও স্তর ৩ lockout (§১০)।"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy import text

from config import get_settings
from db import engine, read_one, run, utcnow
from errors import ApiError
from security import ip_bytes

log = logging.getLogger("ratelimit")


class MemoryStore:
    """একক-প্রসেস বা লোকাল বাকেটের জন্য। Fixed window।"""

    def __init__(self) -> None:
        self._hits: dict[tuple[str, int], int] = {}
        self._lock = asyncio.Lock()

    async def hit(self, key: str, window_start: int) -> int:
        async with self._lock:
            k = (key, window_start)
            n = self._hits.get(k, 0) + 1
            self._hits[k] = n
            if len(self._hits) > 50_000:  # পুরনো উইন্ডো ছাঁটাই
                cutoff = window_start - 86_400
                self._hits = {kk: v for kk, v in self._hits.items() if kk[1] >= cutoff}
            return n


class MysqlStore:
    """Multi-worker-এর জন্য shared store (rate_limit_hits)। Atomic upsert।"""

    async def hit(self, key: str, window_start: int) -> int:
        params = {"k": key[:160], "w": window_start}
        async with engine().begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO rate_limit_hits (bucket_key, window_start, hits) VALUES (:k, :w, 1) "
                    "ON DUPLICATE KEY UPDATE hits = hits + 1"
                ),
                params,
            )
            row = await conn.execute(
                text("SELECT hits FROM rate_limit_hits WHERE bucket_key = :k AND window_start = :w"),
                params,
            )
            return int(row.scalar_one())


_local = MemoryStore()
_shared: MemoryStore | MysqlStore | None = None


def _shared_store():
    global _shared
    if _shared is None:
        _shared = MysqlStore() if get_settings().rate_limit_backend == "mysql" else MemoryStore()
    return _shared


@dataclass(frozen=True)
class Rule:
    windows: tuple[tuple[int, int], ...]  # (সর্বোচ্চ hits, উইন্ডো সেকেন্ড)
    shared: bool
    fail_closed: bool = True  # store ব্যর্থ হলে 503 (auth/reveal/write) নাকি খোলা ছাড়া (public read)


RULES: dict[str, Rule] = {
    "global": Rule(((120, 60),), shared=False, fail_closed=False),
    "login": Rule(((5, 60),), shared=True),
    "signup": Rule(((3, 3600),), shared=True),
    "check_phone": Rule(((20, 60),), shared=True),
    "google": Rule(((10, 60),), shared=True),
    "me": Rule(((60, 60),), shared=False, fail_closed=False),
    "donor_create": Rule(((3, 3600),), shared=True),
    "emergency": Rule(((3, 3600), (10, 86_400)), shared=True),
    "contact": Rule(((5, 3600),), shared=True),
    "report": Rule(((5, 3600),), shared=True),
    "reveal": Rule(((20, 3600),), shared=True),
    "otp_ip": Rule(((10, 3600),), shared=True),
    "otp": Rule(((5, 3600),), shared=True),  # প্রতি ফোনে
    "search": Rule(((60, 60),), shared=False, fail_closed=False),
    "public_read": Rule(((120, 60),), shared=False, fail_closed=False),
    "admin_login": Rule(((5, 60),), shared=True),
    "admin_pwchange": Rule(((5, 60),), shared=True),
    "admin_api": Rule(((120, 60),), shared=False),
    "ws_connect": Rule(((10, 60),), shared=False, fail_closed=False),
    "ws_msg": Rule(((20, 60),), shared=False, fail_closed=False),
}


async def enforce(bucket: str, key: str) -> None:
    """বাকেটের সব উইন্ডো পরীক্ষা। সীমা ছাড়ালে 429 + Retry-After।"""
    rule = RULES[bucket]
    store = _shared_store() if rule.shared else _local
    # লোকাল বাকেট: মোট সীমা ÷ WORKERS (প্রতি worker আলাদা গোনে)
    divisor = 1 if rule.shared else max(1, get_settings().workers)
    now = int(time.time())
    for max_hits, window in rule.windows:
        window_start = now - now % window
        limit = max(1, max_hits // divisor)
        try:
            n = await store.hit(f"{bucket}:{key}:{window}", window_start)
        except Exception:
            log.exception("rate store failure bucket=%s", bucket)
            if rule.fail_closed:
                raise ApiError(503, "service_unavailable", "সেবা সাময়িকভাবে অনুপলব্ধ")
            return
        if n > limit:
            raise ApiError(
                429,
                "rate_limited",
                "অনুগ্রহ করে কিছুক্ষণ পরে চেষ্টা করুন",
                retry_after=window - now % window,
            )


def rate(bucket: str):
    """Route dependency: `dependencies=[Depends(rate("login"))]` (IP-ভিত্তিক)।"""

    async def _dep(request: Request) -> None:
        await enforce(bucket, request.state.ip)

    return _dep


# ───────────── Lockout (স্তর ৩) ─────────────
USER_FAIL_LIMIT = 5
USER_FAIL_WINDOW = timedelta(minutes=15)
ADMIN_USER_FAIL_LIMIT = 5
ADMIN_USER_FAIL_WINDOW = timedelta(minutes=15)
ADMIN_IP_FAIL_LIMIT = 5
ADMIN_TOTAL_FAIL_LIMIT = 20
ADMIN_FAIL_WINDOW = timedelta(minutes=30)


async def assert_user_not_locked(phone: str) -> None:
    """শেষ সফল লগইনের পরের ব্যর্থতা গণনা; লক থাকলে সঠিক PIN-ও প্রত্যাখ্যাত।"""
    row = await read_one(
        """SELECT COUNT(*) AS n FROM login_attempts
           WHERE scope = 'user' AND subject = :sub AND success = 0
             AND created_at > GREATEST(
                   :since,
                   COALESCE((SELECT MAX(created_at) FROM login_attempts
                             WHERE scope = 'user' AND subject = :sub2 AND success = 1),
                            :epoch))""",
        sub=phone,
        sub2=phone,
        since=utcnow() - USER_FAIL_WINDOW,
        epoch=datetime(1970, 1, 1),
    )
    if row and row["n"] >= USER_FAIL_LIMIT:
        raise ApiError(
            429,
            "locked_out",
            "অনেকবার ভুল চেষ্টা হয়েছে। ১৫ মিনিট পরে আবার চেষ্টা করুন",
            retry_after=int(USER_FAIL_WINDOW.total_seconds()),
        )


async def assert_admin_user_not_locked(username: str) -> None:
    """প্রতি অ্যাডমিন-ইউজারনেমে: শেষ সফল লগইনের পরের ব্যর্থতা গণনা; লক থাকলে সঠিক পাসওয়ার্ডও প্রত্যাখ্যাত।"""
    row = await read_one(
        """SELECT COUNT(*) AS n FROM login_attempts
           WHERE scope = 'admin' AND subject = :sub AND success = 0
             AND created_at > GREATEST(
                   :since,
                   COALESCE((SELECT MAX(created_at) FROM login_attempts
                             WHERE scope = 'admin' AND subject = :sub2 AND success = 1),
                            :epoch))""",
        sub=username[:64],
        sub2=username[:64],
        since=utcnow() - ADMIN_USER_FAIL_WINDOW,
        epoch=datetime(1970, 1, 1),
    )
    if row and row["n"] >= ADMIN_USER_FAIL_LIMIT:
        raise ApiError(
            429,
            "locked_out",
            "অনেকবার ভুল চেষ্টা হয়েছে। ১৫ মিনিট পরে আবার চেষ্টা করুন",
            retry_after=int(ADMIN_USER_FAIL_WINDOW.total_seconds()),
        )


async def assert_admin_not_locked(ip: str | None) -> None:
    row = await read_one(
        """SELECT COUNT(CASE WHEN ip = :ip THEN 1 END) AS per_ip, COUNT(*) AS total
           FROM login_attempts
           WHERE scope = 'admin' AND success = 0 AND created_at > :since""",
        ip=ip_bytes(ip),
        since=utcnow() - ADMIN_FAIL_WINDOW,
    )
    if row and (row["per_ip"] >= ADMIN_IP_FAIL_LIMIT or row["total"] >= ADMIN_TOTAL_FAIL_LIMIT):
        raise ApiError(
            429,
            "locked_out",
            "অনেকবার ভুল চেষ্টা হয়েছে। পরে আবার চেষ্টা করুন",
            retry_after=int(ADMIN_FAIL_WINDOW.total_seconds()),
        )


async def record_attempt(scope: str, subject: str, ip: str | None, success: bool) -> None:
    async with engine().begin() as conn:
        await run(
            conn,
            "INSERT INTO login_attempts (scope, subject, ip, success) VALUES (:sc, :sb, :ip, :ok)",
            sc=scope,
            sb=subject[:64],
            ip=ip_bytes(ip),
            ok=success,
        )
