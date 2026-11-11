"""ব্যাকগ্রাউন্ড টাস্ক (§১৩): ঘণ্টায় ক্লিনআপ, দৈনিক expiry। সব idempotent।"""

import asyncio
import logging
import time
from datetime import timedelta

from db import bump_version, engine, run, utcnow
from realtime import announce

log = logging.getLogger("jobs")
DAY = 86_400
HOUR = 3_600


async def cleanup_once() -> None:
    now = utcnow()
    async with engine().begin() as conn:
        await run(conn, "DELETE FROM sessions WHERE expires_at < :n", n=now)
        await run(conn, "DELETE FROM admin_sessions WHERE expires_at < :n", n=now)
        await run(conn, "DELETE FROM otp_codes WHERE expires_at < :n", n=now)
        await run(conn, "DELETE FROM change_log WHERE created_at < :c", c=now - timedelta(hours=1))
        await run(conn, "DELETE FROM rate_limit_hits WHERE window_start < :w", w=int(time.time()) - DAY)
        await run(conn, "DELETE FROM login_attempts WHERE created_at < :c", c=now - timedelta(days=30))
        await run(conn, "DELETE FROM phone_reveals WHERE created_at < :c", c=now - timedelta(days=180))


async def expire_daily() -> None:
    now = utcnow()
    version = None
    scopes: list[str] = []
    async with engine().begin() as conn:
        r1 = await run(
            conn,
            "UPDATE blood_requests SET status = 'expired' WHERE status = 'verified' AND needed_at < :n",
            n=now,
        )
        r2 = await run(
            conn,
            """UPDATE donors SET availability = 'available'
               WHERE next_available IS NOT NULL AND next_available <= CURDATE()
                 AND availability <> 'available'""",
        )
        if r1.rowcount:
            scopes += ["requests", "stats"]
        if r2.rowcount:
            scopes += ["donors", "stats"]
        if scopes:
            version = await bump_version(conn, sorted(set(scopes)))
    if version is not None:
        await announce(version, sorted(set(scopes)))


async def background_loop() -> None:
    last_daily: float | None = None
    while True:
        try:
            await cleanup_once()
            if last_daily is None or time.monotonic() - last_daily >= DAY:
                await expire_daily()
                last_daily = time.monotonic()
        except Exception:
            log.exception("background job failed")
        await asyncio.sleep(HOUR)
