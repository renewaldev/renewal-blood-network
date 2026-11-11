"""অ্যাডমিন পাসওয়ার্ড হ্যাশ (scrypt) ও ইউজারনেম নিয়ম।

কোনো অভ্যন্তরীণ import নেই — তাই db.py (সুপারঅ্যাডমিন সিড) ও security.py দুটোই নিরাপদে ব্যবহার করতে পারে।
হ্যাশ ফরম্যাট: scrypt$n$r$p$salt_hex$hash_hex (আগের ADMIN_PASSWORD_HASH-এর হুবহু একই)।
"""

import asyncio
import hashlib
import hmac
import re
import secrets

SCRYPT = {"n": 2**14, "r": 8, "p": 1}
ADMIN_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@+-]{2,63}$")
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128

_dummy_hash: str | None = None


def make_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **SCRYPT)
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${salt.hex()}${digest.hex()}"


def verify_hash(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt_hex, hash_hex = stored.split("$")
        digest = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(hash_hex) // 2,
        )
        return hmac.compare_digest(digest, bytes.fromhex(hash_hex))
    except ValueError:
        return False


def burn_admin_time(password: str) -> None:
    """অজানা ইউজারনেমেও একই পরিমাণ কাজ করে, যাতে সময় দেখে অ্যাকাউন্টের অস্তিত্ব বোঝা না যায়।"""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = make_hash("dummy-password-for-timing")
    verify_hash(password, _dummy_hash)


_sem: asyncio.Semaphore | None = None


def _semaphore() -> asyncio.Semaphore:
    """একসাথে চলা scrypt সীমিত (প্রতিটি ~১৬ MB)। সীমা প্রতি প্রসেসে; HASH_CONCURRENCY (.env)।"""
    global _sem
    if _sem is None:
        from config import get_settings  # lazy: config এই মডিউল import করে

        _sem = asyncio.Semaphore(get_settings().hash_concurrency)
    return _sem


async def run_hash(fn, *args):
    """ভারী হ্যাশ থ্রেডে চালায় (event loop আটকায় না); সেমাফোর সীমা মানে, বাকিরা await-এ অপেক্ষা করে।"""
    async with _semaphore():
        return await asyncio.to_thread(fn, *args)


async def amake_hash(password: str) -> str:
    return await run_hash(make_hash, password)


async def averify_hash(password: str, stored: str) -> bool:
    return await run_hash(verify_hash, password, stored)


async def aburn_admin_time(password: str) -> None:
    await run_hash(burn_admin_time, password)


def normalize_username(raw: str) -> str:
    return raw.strip().lower()
