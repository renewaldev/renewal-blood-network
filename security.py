"""ক্রিপ্টো, কুকি/CSRF, Turnstile, real-IP ও auth dependency (§৮)।"""

import base64
import getpass
import hashlib
import hmac
import ipaddress
import secrets
from datetime import timedelta

import httpx
from fastapi import Depends, Request, Response

from config import get_settings
from db import read_one, run, utcnow
from errors import ApiError
from passwords import SCRYPT, make_hash, run_hash, verify_hash

TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
COOKIE_BASE = {"user": "sid", "admin": "asid"}
_DUMMY_SALT = b"\x00" * 16


# ───────────── PIN (ইউজার) ─────────────
def _pin_key(pin: str) -> bytes:
    """Pepper দিয়ে HMAC; শুধু DB ফাঁসে PIN নিরাপদ রাখে (§৮)।"""
    return hmac.new(get_settings().pin_pepper.encode(), pin.encode(), hashlib.sha256).digest()


def hash_pin(pin: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(_pin_key(pin), salt=salt, dklen=32, **SCRYPT)
    return digest, salt


def verify_pin(pin: str, digest: bytes, salt: bytes) -> bool:
    candidate, _ = hash_pin(pin, salt)
    return hmac.compare_digest(candidate, digest)


async def ahash_pin(pin: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    return await run_hash(hash_pin, pin, salt)


async def averify_pin(pin: str, digest: bytes, salt: bytes) -> bool:
    return await run_hash(verify_pin, pin, digest, salt)


async def aburn_pin_time(pin: str) -> None:
    await run_hash(burn_pin_time, pin)


def burn_pin_time(pin: str) -> None:
    """অজানা ফোনেও একই পরিমাণ কাজ করে, যাতে timing থেকে অস্তিত্ব বোঝা না যায়।"""
    hash_pin(pin, _DUMMY_SALT)


# ───────────── Admin password ─────────────
def make_admin_hash(password: str) -> str:
    """scrypt হ্যাশ তৈরি: `python -m security` চালান।"""
    return make_hash(password)


def verify_admin_password(password: str, stored: str) -> bool:
    return verify_hash(password, stored)


# ───────────── Tokens, CSRF, cookies ─────────────
def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 বিট


def token_hash(token: str) -> str:
    """DB-তে শুধু এই হ্যাশ যায় (CHAR(64))।"""
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_for(session_hash: str) -> str:
    """Stateless synchronizer: কোনো সারি লাগে না (§৮.২)।"""
    mac = hmac.new(get_settings().csrf_secret.encode(), session_hash.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def cookie_name(kind: str) -> str:
    base = COOKIE_BASE[kind]
    return f"__Host-{base}" if get_settings().cookie_secure else base


def _samesite(kind: str) -> str:
    return "strict" if kind == "admin" else "lax"


def set_session_cookie(response: Response, kind: str, token: str, max_age: int) -> None:
    response.set_cookie(
        cookie_name(kind),
        token,
        max_age=max_age,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite=_samesite(kind),
        path="/",
    )


def clear_session_cookie(response: Response, kind: str) -> None:
    response.delete_cookie(
        cookie_name(kind),
        path="/",
        secure=get_settings().cookie_secure,
        httponly=True,
        samesite=_samesite(kind),
    )


# ───────────── Real IP (§৫.১) ─────────────
def _is_trusted(peer: str) -> bool:
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in net for net in get_settings().trusted_networks)


def client_ip(request: Request) -> str:
    """Forwarded হেডার শুধু বিশ্বস্ত প্রক্সি থেকে এলে মানা হয়।"""
    peer = request.client.host if request.client else "0.0.0.0"
    if _is_trusted(peer):
        cf = request.headers.get("cf-connecting-ip")
        if cf:
            return cf.strip()
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return peer


def ip_bytes(ip: str | None) -> bytes | None:
    """VARBINARY(16) কলামের জন্য।"""
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip).packed
    except ValueError:
        return None


# ───────────── Turnstile (fail-closed, §৮) ─────────────
async def verify_turnstile(token: str | None, ip: str) -> None:
    s = get_settings()
    if not s.turnstile_enabled:
        return
    ok = False
    if token:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    TURNSTILE_URL,
                    data={"secret": s.turnstile_secret_key, "response": token, "remoteip": ip},
                )
                ok = r.status_code == 200 and r.json().get("success") is True
        except (httpx.HTTPError, ValueError):
            ok = False  # fail-closed
    if not ok:
        raise ApiError(403, "turnstile_failed", "বট যাচাই ব্যর্থ হয়েছে, আবার চেষ্টা করুন")


# ───────────── Sessions ─────────────
async def start_user_session(conn, user_id: str, request: Request, response: Response, old_raw: str | None) -> str:
    """নতুন সেশন (fixation প্রতিরোধে পুরনোটি বাতিল)। CSRF টোকেন ফেরত।"""
    if old_raw:
        await run(conn, "DELETE FROM sessions WHERE token_hash = :th", th=token_hash(old_raw))
    token = new_token()
    ttl = get_settings().session_ttl_days
    await run(
        conn,
        """INSERT INTO sessions (token_hash, user_id, ip, user_agent, expires_at)
           VALUES (:th, :uid, :ip, :ua, :exp)""",
        th=token_hash(token),
        uid=user_id,
        ip=ip_bytes(request.state.ip),
        ua=(request.headers.get("user-agent") or "")[:255],
        exp=utcnow() + timedelta(days=ttl),
    )
    set_session_cookie(response, "user", token, max_age=ttl * 86400)
    return csrf_for(token_hash(token))


async def current_user(request: Request) -> dict:
    raw = request.cookies.get(cookie_name("user"))
    if not raw:
        raise ApiError(401, "unauthorized", "লগইন প্রয়োজন")
    th = token_hash(raw)
    row = await read_one(
        """SELECT u.id, u.phone, u.status, u.flagged, u.created_at
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = :th AND s.expires_at > :now""",
        th=th,
        now=utcnow(),
    )
    if not row:
        raise ApiError(401, "unauthorized", "লগইন প্রয়োজন")
    if row["status"] != "active":
        raise ApiError(403, "forbidden", "অ্যাকাউন্ট বন্ধ আছে")
    row["session_hash"] = th
    return row


async def current_admin_any(request: Request) -> dict:
    """বৈধ অ্যাডমিন সেশন (পাসওয়ার্ড বদলানো বাকি থাকলেও)। শুধু /me, /logout, /change-password ব্যবহার করে।"""
    raw = request.cookies.get(cookie_name("admin"))
    if not raw:
        raise ApiError(401, "unauthorized", "অ্যাডমিন লগইন প্রয়োজন")
    th = token_hash(raw)
    row = await read_one(
        """SELECT a.id, a.username, a.role, a.must_change_password
           FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
           WHERE s.token_hash = :th AND s.expires_at > :now""",
        th=th,
        now=utcnow(),
    )
    if not row:
        raise ApiError(401, "unauthorized", "অ্যাডমিন লগইন প্রয়োজন")
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "must_change_password": bool(row["must_change_password"]),
        "session_hash": th,
    }


async def current_admin(admin: dict = Depends(current_admin_any)) -> dict:
    """সাধারণ অ্যাডমিন রুটের গেট: প্রথম লগইনের পাসওয়ার্ড না বদলানো পর্যন্ত সব বন্ধ।"""
    if admin["must_change_password"]:
        raise ApiError(403, "password_change_required", "চালিয়ে যেতে আগে পাসওয়ার্ড বদলান")
    return admin


def check_csrf(request: Request, session_hash: str) -> None:
    sent = request.headers.get("x-csrf-token", "")
    if not sent or not hmac.compare_digest(sent, csrf_for(session_hash)):
        raise ApiError(403, "csrf_failed", "নিরাপত্তা যাচাই ব্যর্থ, পেজ রিফ্রেশ করুন")


async def user_write(request: Request, user: dict = Depends(current_user)) -> dict:
    """সেশন + CSRF — ইউজারের প্রতিটি mutation এটি ব্যবহার করবে।"""
    check_csrf(request, user["session_hash"])
    return user


async def admin_write_any(request: Request, admin: dict = Depends(current_admin_any)) -> dict:
    check_csrf(request, admin["session_hash"])
    return admin


async def admin_write(request: Request, admin: dict = Depends(current_admin)) -> dict:
    check_csrf(request, admin["session_hash"])
    return admin


def _require_superadmin(admin: dict) -> dict:
    if admin["role"] != "superadmin":
        raise ApiError(403, "forbidden", "শুধু সুপার অ্যাডমিন এটি করতে পারেন")
    return admin


async def superadmin_read(admin: dict = Depends(current_admin)) -> dict:
    return _require_superadmin(admin)


async def superadmin_write(admin: dict = Depends(admin_write)) -> dict:
    return _require_superadmin(admin)


# ───────────── CLI ─────────────
async def _reset_superadmin() -> None:
    """সুপারঅ্যাডমিনের পাসওয়ার্ড ভুলে গেলে: ADMIN_TEMP_PASSWORD-এ ফিরিয়ে প্রথম-লগইন অবস্থায় নেয়।"""
    from db import dispose, engine

    s = get_settings()
    if not s.admin_temp_password:
        raise SystemExit("ADMIN_TEMP_PASSWORD .env-এ সেট করুন")
    async with engine().begin() as conn:
        res = await run(
            conn,
            """UPDATE admins SET password_hash = :h, must_change_password = TRUE
               WHERE role = 'superadmin' ORDER BY created_at LIMIT 1""",
            h=make_hash(s.admin_temp_password),
        )
        if not res.rowcount:
            raise SystemExit("কোনো সুপারঅ্যাডমিন নেই — অ্যাপ একবার চালু করলে তৈরি হবে")
        await run(
            conn,
            "DELETE FROM admin_sessions WHERE admin_id IN (SELECT id FROM admins WHERE role = 'superadmin')",
        )
    await dispose()
    print(f"সুপারঅ্যাডমিন '{s.superadmin_login}' রিসেট হয়েছে: ADMIN_TEMP_PASSWORD দিয়ে লগইন করে নতুন পাসওয়ার্ড দিন।")


if __name__ == "__main__":
    import asyncio
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "reset-superadmin":
        asyncio.run(_reset_superadmin())
    else:
        print(make_admin_hash(getpass.getpass("Admin password: ")))
