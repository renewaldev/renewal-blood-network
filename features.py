"""বৈশিষ্ট্য রুট: দাতা প্রোফাইল সম্পাদনা, রিপোর্ট, যোগাযোগ অনুরোধ, মানচিত্র,
Google sign-in, ফোন যুক্তকরণ ও OTP অনুরোধ। app.py-তে include করা হয়।"""

import hashlib
import hmac
import json
import logging
import uuid
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool

from config import get_settings
from db import bump_version, engine, one, read_many, read_one, run, utcnow
from errors import ApiError
from otp import consume as otp_consume
from otp import issue as otp_issue
from otp import require_enabled as otp_require
from ratelimit import enforce, rate
from realtime import announce
from schemas import ContactIn, DonorUpdateIn, GoogleIn, OtpRequestIn, PhoneAuthIn, ReportIn
from security import (
    check_csrf,
    cookie_name,
    current_user,
    ahash_pin,
    ip_bytes,
    start_user_session,
    user_write,
    verify_turnstile,
)
from trust import recalc

BASE_DIR = Path(__file__).resolve().parent
log = logging.getLogger("features")
router = APIRouter()

DONOR_SCOPES = ["donors", "stats", "leaderboard"]
REQUEST_SCOPES = ["requests", "stats"]
_DONOR_FIELD_COLUMNS = {
    "name": "name",
    "name_en": "name_en",
    "area": "area",
    "profession": "profession",
    "phone_visibility": "phone_visibility",
    "availability": "availability",
    "can_donate": "can_donate",
    "next_available": "next_available",
    "last_donation": "last_donation",
    "district": "district",
    "upazila": "upazila",
}


async def optional_user(request: Request) -> dict | None:
    """লগইন থাকলে ইউজার, না থাকলে None (গেস্টও অনুমোদিত)।"""
    try:
        return await current_user(request)
    except ApiError:
        return None


# ───────────── দাতা প্রোফাইল সম্পাদনা ─────────────
@router.put("/api/donors/{donor_id}")
async def update_donor(donor_id: str, body: DonorUpdateIn, user: dict = Depends(user_write)):
    data = body.model_dump(exclude_unset=True)
    sets: list[str] = []
    params: dict = {"id": donor_id}
    # কলামের নাম _DONOR_FIELD_COLUMNS থেকে আসে, ব্যবহারকারীর ইনপুট থেকে নয়
    for field, column in _DONOR_FIELD_COLUMNS.items():
        if data.get(field) is not None:
            sets.append(f"{column} = :{field}")
            params[field] = data[field]

    async with engine().begin() as conn:
        own = await one(
            conn,
            "SELECT id FROM donors WHERE id = :id AND user_id = :u FOR UPDATE",
            id=donor_id, u=user["id"],
        )
        if not own:
            raise ApiError(403, "forbidden", "শুধু নিজের প্রোফাইল সম্পাদনা করা যায়")
        if not sets:
            return {"ok": True}
        await run(conn, f"UPDATE donors SET {', '.join(sets)} WHERE id = :id", **params)
        version = await bump_version(conn, DONOR_SCOPES)
    await announce(version, DONOR_SCOPES)
    return {"ok": True}


# ───────────── রিপোর্ট ─────────────
def _reporter_key(request: Request, user: dict | None) -> str:
    """ইউজার বা IP-এর HMAC; কাঁচা IP/ID DB-তে যায় না (§১১)।"""
    raw = f"u:{user['id']}" if user else f"ip:{request.state.ip}"
    return hmac.new(get_settings().csrf_secret.encode(), raw.encode(), hashlib.sha256).hexdigest()


async def _record_report(request: Request, user: dict | None, target_type: str, target_id: str, reason: str | None):
    key = _reporter_key(request, user)
    async with engine().begin() as conn:
        if target_type == "donor":
            exists = await one(conn, "SELECT id FROM donors WHERE id = :id FOR UPDATE", id=target_id)
        else:
            exists = await one(conn, "SELECT id FROM blood_requests WHERE id = :id FOR UPDATE", id=target_id)
        if not exists:
            raise ApiError(404, "not_found", "পাওয়া যায়নি")
        try:
            await run(
                conn,
                """INSERT INTO reports (target_type, target_id, reporter_key, reason)
                   VALUES (:t, :i, :k, :r)""",
                t=target_type, i=target_id, k=key, r=reason,
            )
        except IntegrityError:
            raise ApiError(409, "conflict", "আপনি ইতিমধ্যে রিপোর্ট করেছেন")

        count = (await one(
            conn,
            "SELECT COUNT(*) AS n FROM reports WHERE target_type = :t AND target_id = :i",
            t=target_type, i=target_id,
        ))["n"]

        if target_type == "donor":
            await run(
                conn,
                "UPDATE donors SET report_count = :c, suspicious = :sus WHERE id = :id",
                c=count, sus=count >= 3, id=target_id,
            )
            await recalc(conn, target_id)
            scopes = ["donors", "admin_donors", "admin_reports"]
        else:
            await run(
                conn,
                "UPDATE blood_requests SET report_count = :c WHERE id = :id",
                c=count, id=target_id,
            )
            scopes = ["requests", "admin_requests", "admin_reports"]
        version = await bump_version(conn, scopes)
    await announce(version, scopes)


@router.post("/api/donors/{donor_id}/report", status_code=201, dependencies=[Depends(rate("report"))])
async def report_donor(donor_id: str, body: ReportIn, request: Request, user: dict | None = Depends(optional_user)):
    if user:
        check_csrf(request, user["session_hash"])
    await verify_turnstile(body.turnstile_token, request.state.ip)
    await _record_report(request, user, "donor", donor_id, body.reason)
    return {"ok": True}


@router.post("/api/requests/{request_id}/report", status_code=201, dependencies=[Depends(rate("report"))])
async def report_request(request_id: str, body: ReportIn, request: Request, user: dict | None = Depends(optional_user)):
    if user:
        check_csrf(request, user["session_hash"])
    await verify_turnstile(body.turnstile_token, request.state.ip)
    await _record_report(request, user, "request", request_id, body.reason)
    return {"ok": True}


# ───────────── যোগাযোগ অনুরোধ (§৭) ─────────────
@router.post("/api/contacts", status_code=201, dependencies=[Depends(rate("contact"))])
async def create_contact(body: ContactIn, request: Request):
    await verify_turnstile(body.turnstile_token, request.state.ip)
    cid = uuid.uuid4().hex
    async with engine().begin() as conn:
        donor = await one(conn, "SELECT id FROM donors WHERE id = :id FOR UPDATE", id=body.donor_id)
        if not donor:
            raise ApiError(404, "not_found", "দাতা পাওয়া যায়নি")
        recent = await one(
            conn,
            "SELECT COUNT(*) AS n FROM contact_requests WHERE donor_id = :id AND submitted_at > :since",
            id=body.donor_id, since=utcnow() - timedelta(days=1),
        )
        if recent["n"] >= 3:
            raise ApiError(429, "quota_exceeded", "এই দাতার জন্য আজকের যোগাযোগ-অনুরোধের সীমা শেষ")
        await run(
            conn,
            """INSERT INTO contact_requests (id, donor_id, patient, blood_group, hospital,
                   units, phone, status, submitted_ip)
               VALUES (:id, :d, :pt, :bg, :h, :u, :ph, 'pending', :ip)""",
            id=cid, d=body.donor_id, pt=body.patient, bg=body.blood_group, h=body.hospital,
            u=body.units, ph=body.phone, ip=ip_bytes(request.state.ip),
        )
        version = await bump_version(conn, ["admin_contacts"])
    await announce(version, ["admin_contacts"])
    return {"id": cid, "status": "pending"}


# ───────────── মানচিত্র (জেলা-ভিত্তিক, নির্ভুল ঠিকানা নয়) ─────────────
_coords_cache: dict[str, tuple[float, float]] | None = None


def _district_coords() -> dict[str, tuple[float, float]]:
    global _coords_cache
    if _coords_cache is None:
        data = json.loads((BASE_DIR / "static" / "data" / "bd-districts.json").read_text(encoding="utf-8"))
        _coords_cache = {
            d["name"]: (float(d["lat"]), float(d["long"])) for d in data["districts"]
        }
    return _coords_cache


@router.get("/api/map", dependencies=[Depends(rate("public_read"))])
async def map_data():
    rows = await read_many(
        """SELECT district, COUNT(*) AS donors,
                  CAST(SUM(availability = 'available') AS UNSIGNED) AS available
           FROM donors GROUP BY district"""
    )
    coords = _district_coords()
    items = []
    for r in rows:
        if r["district"] in coords:
            lat, lng = coords[r["district"]]
            items.append({
                "district": r["district"],
                "lat": lat,
                "lng": lng,
                "donors": r["donors"],
                "available": r["available"] or 0,
            })
    return {"items": items}


# ───────────── Google sign-in (§৮) ─────────────
def _verify_google_sync(token: str) -> dict:
    from google.auth.transport import requests as g_requests  # noqa: PLC0415
    from google.oauth2 import id_token  # noqa: PLC0415

    return id_token.verify_oauth2_token(token, g_requests.Request(), get_settings().google_client_id)


async def _verify_google(token: str) -> dict:
    try:
        info = await run_in_threadpool(_verify_google_sync, token)
    except Exception:
        raise ApiError(401, "unauthorized", "Google যাচাই ব্যর্থ হয়েছে")
    if not info.get("email_verified"):
        raise ApiError(401, "unauthorized", "Google ইমেইল যাচাইকৃত নয়")
    return info


@router.post("/api/auth/google", dependencies=[Depends(rate("google"))])
async def google_login(body: GoogleIn, request: Request, response: Response):
    if not get_settings().google_login_enabled:
        raise ApiError(404, "not_found", "Google লগইন বন্ধ আছে")
    info = await _verify_google(body.credential)
    sub = info["sub"]
    email = info.get("email")
    name = info.get("name")
    picture = info.get("picture")

    async with engine().begin() as conn:
        link = await one(
            conn,
            "SELECT user_id FROM oauth_accounts WHERE provider = 'google' AND provider_user_id = :s",
            s=sub,
        )
        if link:
            uid = link["user_id"]
        else:
            # একই যাচাইকৃত ইমেইলের বিদ্যমান ইউজার থাকলে লিংক, নইলে নতুন ইউজার
            existing = None
            if email:
                existing = await one(conn, "SELECT id FROM users WHERE email = :e LIMIT 1", e=email)
            if existing:
                uid = existing["id"]
            else:
                uid = uuid.uuid4().hex
                await run(conn, "INSERT INTO users (id, email, status) VALUES (:id, :e, 'active')", id=uid, e=email)
            await run(
                conn,
                """INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, name, picture)
                   VALUES (:id, :u, 'google', :s, :e, :n, :pic)""",
                id=uuid.uuid4().hex, u=uid, s=sub, e=email, n=name, pic=picture,
            )
        user = await one(conn, "SELECT status, phone FROM users WHERE id = :id", id=uid)
        if user["status"] != "active":
            raise ApiError(403, "forbidden", "অ্যাকাউন্ট বন্ধ আছে")
        csrf = await start_user_session(
            conn, uid, request, response, request.cookies.get(cookie_name("user"))
        )
    return {"ok": True, "csrfToken": csrf, "needsPhone": user["phone"] is None}


@router.post("/api/auth/link-phone", dependencies=[Depends(rate("signup"))])
async def link_phone(body: PhoneAuthIn, request: Request, user: dict = Depends(user_write)):
    """Google ইউজার ফোন ও PIN যুক্ত করে (দাতা নিবন্ধনের আগে ফোন লাগে)।"""
    await verify_turnstile(body.turnstile_token, request.state.ip)
    if user["phone"]:
        raise ApiError(409, "conflict", "ফোন আগে থেকেই যুক্ত আছে")
    if get_settings().otp_enabled:
        await otp_consume(body.phone, "link", body.otp_code)
    digest, salt = await ahash_pin(body.pin)
    try:
        async with engine().begin() as conn:
            await run(
                conn,
                "UPDATE users SET phone = :p, pin_hash = :h, pin_salt = :s WHERE id = :id AND phone IS NULL",
                p=body.phone, h=digest, s=salt, id=user["id"],
            )
    except IntegrityError:
        raise ApiError(409, "conflict", "এই নম্বর আগে থেকেই নিবন্ধিত")
    return {"ok": True}


# ───────────── OTP অনুরোধ (বর্তমানে বন্ধ — OTP_ENABLED=true হলে কার্যকর) ─────────────
@router.post("/api/auth/otp/request", dependencies=[Depends(rate("otp_ip"))])
async def otp_request(body: OtpRequestIn, request: Request, user: dict | None = Depends(optional_user)):
    otp_require()
    if body.purpose == "link":
        if not user:
            raise ApiError(401, "unauthorized", "লগইন প্রয়োজন")
        check_csrf(request, user["session_hash"])
    await verify_turnstile(body.turnstile_token, request.state.ip)
    await enforce("otp", body.phone)

    registered = await read_one("SELECT 1 AS x FROM users WHERE phone = :p", p=body.phone)
    if body.purpose == "login":
        # অজানা নম্বরে SMS যায় না, কিন্তু উত্তর একই থাকে (অস্তিত্ব গোপন)
        if not registered:
            return {"ok": True, "expiresIn": 300}
    elif registered:
        raise ApiError(409, "conflict", "এই নম্বর আগে থেকেই নিবন্ধিত")

    await otp_issue(body.phone, body.purpose)
    return {"ok": True, "expiresIn": 300}
