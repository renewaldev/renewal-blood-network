"""SMS OTP। OTP_ENABLED=false (ডিফল্ট) হলে সব কিছু বন্ধ (D11)।

- কোড HMAC-হ্যাশ হয়ে সংরক্ষিত; কাঁচা কোড DB-তে যায় না।
- মেয়াদ ৫ মিনিট; ৫ বার ভুল হলে কোড বাতিল।
- কোড মেলার পর সারি মুছে যায় (একবার ব্যবহার)।
"""

import hashlib
import hmac
import secrets
from datetime import timedelta

from config import get_settings
from db import engine, one, run, utcnow
from errors import ApiError
from sms import SmsError, send_sms

OTP_TTL = timedelta(minutes=5)
OTP_MAX_ATTEMPTS = 5


def require_enabled() -> None:
    if not get_settings().otp_enabled:
        raise ApiError(404, "otp_disabled", "OTP এখন বন্ধ আছে")


def _mac(phone: str, purpose: str, code: str) -> str:
    msg = f"{phone}|{purpose}|{code}".encode()
    return hmac.new(get_settings().csrf_secret.encode(), msg, hashlib.sha256).hexdigest()


async def issue(phone: str, purpose: str) -> None:
    code = f"{secrets.randbelow(10**6):06d}"
    async with engine().begin() as conn:
        await run(
            conn,
            """INSERT INTO otp_codes (phone, purpose, code_hash, attempts, expires_at)
               VALUES (:p, :pu, :h, 0, :e)
               ON DUPLICATE KEY UPDATE code_hash = VALUES(code_hash),
                   attempts = 0, expires_at = VALUES(expires_at)""",
            p=phone, pu=purpose, h=_mac(phone, purpose, code), e=utcnow() + OTP_TTL,
        )
    try:
        await send_sms(phone, f"রিনিউয়েল ব্লাড: আপনার কোড {code}। ৫ মিনিটের মধ্যে ব্যবহার করুন।")
    except SmsError:
        async with engine().begin() as conn:
            await run(conn, "DELETE FROM otp_codes WHERE phone = :p AND purpose = :pu", p=phone, pu=purpose)
        raise ApiError(503, "sms_unavailable", "এখন কোড পাঠানো যাচ্ছে না, পরে চেষ্টা করুন")


async def consume(phone: str, purpose: str, code: str | None) -> None:
    """কোড সঠিক হলে সারি মুছে ফেলে; না হলে ApiError। যাচাই ও আপডেট একই transaction-এ।"""
    ok = False
    async with engine().begin() as conn:
        row = await one(
            conn,
            "SELECT code_hash, expires_at, attempts FROM otp_codes "
            "WHERE phone = :p AND purpose = :pu FOR UPDATE",
            p=phone, pu=purpose,
        )
        if row and row["expires_at"] >= utcnow() and row["attempts"] < OTP_MAX_ATTEMPTS and code:
            ok = hmac.compare_digest(row["code_hash"], _mac(phone, purpose, code))
        if ok:
            await run(conn, "DELETE FROM otp_codes WHERE phone = :p AND purpose = :pu", p=phone, pu=purpose)
        elif row:
            await run(conn, "UPDATE otp_codes SET attempts = attempts + 1 WHERE phone = :p AND purpose = :pu", p=phone, pu=purpose)
    if not ok:
        raise ApiError(401, "otp_invalid", "OTP সঠিক নয় বা মেয়াদোত্তীর্ণ")
