"""অ্যাডমিন: একটি APIRouter(prefix="/admin") — আলাদা প্রসেস নয় (D1)।"""

import hmac
import ipaddress
import json
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.templating import Jinja2Templates

from config import get_settings
from db import bump_version, engine, one, read_many, read_one, run, utcnow
from errors import ApiError
from ratelimit import assert_admin_not_locked, assert_admin_user_not_locked, rate, record_attempt
from passwords import aburn_admin_time, amake_hash, averify_hash, normalize_username
from realtime import announce
from schemas import AdminLoginIn, ChangePasswordIn, RequestUpdateIn
from security import (
    admin_write,
    admin_write_any,
    clear_session_cookie,
    cookie_name,
    csrf_for,
    current_admin,
    current_admin_any,
    ip_bytes,
    new_token,
    set_session_cookie,
    token_hash,
    verify_turnstile,
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

REQUEST_STATUSES = ("pending", "verified", "rejected", "fulfilled", "expired")
# অনুমোদিত স্ট্যাটাস পরিবর্তন; অন্য যেকোনোটি 409
ALLOWED_TRANSITIONS = {
    "pending": {"verified", "rejected"},
    "verified": {"fulfilled", "rejected"},
}


async def ip_allowlist(request: Request) -> None:
    networks = get_settings().admin_networks
    if not networks:
        return
    addr = ipaddress.ip_address(request.state.ip)
    if not any(addr in net for net in networks):
        raise ApiError(403, "forbidden", "অনুমতি নেই")


router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(ip_allowlist), Depends(rate("admin_api"))],
)


@router.get("")
async def admin_page(request: Request):
    return templates.TemplateResponse(request, "admin.html", {"nonce": request.state.nonce})


async def audit(conn, request: Request, admin: dict, action: str, target_type: str, target_id: str | None, detail: dict) -> None:
    """audit_log-এ লেখে; actor = অ্যাডমিনের ইউজারনেম (অ্যাডমিন ডিলিট হলেও লগে নাম থাকে)।"""
    await run(
        conn,
        """INSERT INTO audit_log (actor, action, target_type, target_id, detail, ip)
           VALUES (:actor, :a, :tt, :tid, :d, :ip)""",
        actor=admin["username"],
        a=action,
        tt=target_type,
        tid=target_id,
        d=json.dumps(detail, ensure_ascii=False, default=str),
        ip=ip_bytes(request.state.ip),
    )


def _me_payload(admin: dict) -> dict:
    return {
        "ok": True,
        "csrfToken": csrf_for(admin["session_hash"]),
        "username": admin["username"],
        "role": admin["role"],
        "mustChangePassword": admin["must_change_password"],
    }


@router.post("/api/login", dependencies=[Depends(rate("admin_login"))])
async def admin_login(body: AdminLoginIn, request: Request, response: Response):
    ip = request.state.ip
    username = normalize_username(body.username)
    await verify_turnstile(body.turnstile_token, ip)
    await assert_admin_not_locked(ip)
    await assert_admin_user_not_locked(username)

    row = await read_one(
        "SELECT id, username, role, must_change_password, password_hash FROM admins WHERE username = :u",
        u=username,
    )
    if row:
        ok = await averify_hash(body.password, row["password_hash"])
    else:
        await aburn_admin_time(body.password)  # অজানা ইউজারনেমেও একই সময় লাগে
        ok = False
    if not ok:
        await record_attempt("admin", username, ip, False)
        raise ApiError(401, "unauthorized", "ইউজারনেম বা পাসওয়ার্ড ভুল")
    await record_attempt("admin", username, ip, True)

    old = request.cookies.get(cookie_name("admin"))
    token = new_token()
    th = token_hash(token)
    ttl_hours = get_settings().admin_session_ttl_hours
    async with engine().begin() as conn:
        if old:
            await run(conn, "DELETE FROM admin_sessions WHERE token_hash = :th", th=token_hash(old))
        await run(
            conn,
            "INSERT INTO admin_sessions (token_hash, admin_id, ip, expires_at) VALUES (:th, :aid, :ip, :exp)",
            th=th,
            aid=row["id"],
            ip=ip_bytes(ip),
            exp=utcnow() + timedelta(hours=ttl_hours),
        )
        await run(conn, "UPDATE admins SET last_login_at = :now WHERE id = :id", now=utcnow(), id=row["id"])
    set_session_cookie(response, "admin", token, max_age=ttl_hours * 3600)
    return _me_payload(
        {
            "session_hash": th,
            "username": row["username"],
            "role": row["role"],
            "must_change_password": bool(row["must_change_password"]),
        }
    )


@router.get("/api/me")
async def admin_me(admin: dict = Depends(current_admin_any)):
    return _me_payload(admin)


@router.post("/api/logout")
async def admin_logout(response: Response, admin: dict = Depends(admin_write_any)):
    async with engine().begin() as conn:
        await run(conn, "DELETE FROM admin_sessions WHERE token_hash = :th", th=admin["session_hash"])
    clear_session_cookie(response, "admin")
    return {"ok": True}


@router.post("/api/change-password", dependencies=[Depends(rate("admin_pwchange"))])
async def admin_change_password(body: ChangePasswordIn, request: Request, admin: dict = Depends(admin_write_any)):
    ip = request.state.ip
    await assert_admin_user_not_locked(admin["username"])
    row = await read_one("SELECT password_hash FROM admins WHERE id = :id", id=admin["id"])
    if not row or not await averify_hash(body.current_password, row["password_hash"]):
        await record_attempt("admin", admin["username"], ip, False)
        raise ApiError(400, "validation_error", "বর্তমান পাসওয়ার্ড ভুল")
    if hmac.compare_digest(body.new_password.encode(), body.current_password.encode()):
        raise ApiError(400, "validation_error", "নতুন পাসওয়ার্ড আগেরটির মতো হতে পারবে না")
    temp = get_settings().admin_temp_password
    if temp and hmac.compare_digest(body.new_password.encode(), temp.encode()):
        raise ApiError(400, "validation_error", "এই পাসওয়ার্ড অস্থায়ী; অন্য একটি দিন")

    new_hash = await amake_hash(body.new_password)  # কানেকশন ধরার আগে
    async with engine().begin() as conn:
        await run(
            conn,
            "UPDATE admins SET password_hash = :h, must_change_password = FALSE WHERE id = :id",
            h=new_hash,
            id=admin["id"],
        )
        # অন্য সব ডিভাইসের সেশন বাতিল; বর্তমানটি থাকে
        await run(
            conn,
            "DELETE FROM admin_sessions WHERE admin_id = :id AND token_hash <> :th",
            id=admin["id"],
            th=admin["session_hash"],
        )
        await audit(conn, request, admin, "admin.password_change", "admin", admin["id"], {})
    await record_attempt("admin", admin["username"], ip, True)
    return {"ok": True}


@router.get("/api/requests")
async def admin_list_requests(
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(current_admin),
):
    """অ্যাডমিন দেখে সম্পূর্ণ (unmasked) তথ্য, যার মধ্যে contact।"""
    where = "1=1"
    params: dict = {"lim": limit, "off": offset}
    if status:
        if status not in REQUEST_STATUSES:
            raise ApiError(400, "validation_error", "অবৈধ স্ট্যাটাস")
        where = "status = :status"
        params["status"] = status
    # where শুধু উপরের স্থির অংশ থেকে তৈরি; ব্যবহারকারীর ইনপুট SQL-এ যায় না।
    rows = await read_many(
        f"""SELECT id, patient_name, blood_group, units, hospital, district, upazila,
                   needed_at, attendant_name, contact, reason, status, verification_note,
                   report_count, submitted_at, verified_at
            FROM blood_requests WHERE {where}
            ORDER BY submitted_at DESC LIMIT :lim OFFSET :off""",
        **params,
    )
    return {"items": [_admin_request(r) for r in rows], "limit": limit, "offset": offset}


@router.put("/api/requests/{request_id}")
async def admin_update_request(
    request_id: str,
    body: RequestUpdateIn,
    request: Request,
    admin: dict = Depends(admin_write),
):
    scopes = ["requests", "stats", "admin_requests"]
    async with engine().begin() as conn:
        row = await one(conn, "SELECT status FROM blood_requests WHERE id = :id FOR UPDATE", id=request_id)
        if not row:
            raise ApiError(404, "not_found", "অনুরোধ পাওয়া যায়নি")
        old_status = row["status"]
        if body.status not in ALLOWED_TRANSITIONS.get(old_status, set()):
            raise ApiError(409, "conflict", f"'{old_status}' থেকে '{body.status}' সম্ভব নয়")

        if body.status == "verified":
            await run(
                conn,
                """UPDATE blood_requests SET status = :s, verification_note = :n, verified_at = :now
                   WHERE id = :id""",
                s=body.status, n=body.note, now=utcnow(), id=request_id,
            )
        else:
            await run(
                conn,
                "UPDATE blood_requests SET status = :s, verification_note = :n WHERE id = :id",
                s=body.status, n=body.note, id=request_id,
            )
        await audit(
            conn, request, admin, f"request.{body.status}", "request", request_id,
            {"from": old_status, "to": body.status, "note": body.note},
        )
        version = await bump_version(conn, scopes)
    await announce(version, scopes)
    return {"ok": True, "status": body.status}


def _admin_request(r: dict) -> dict:
    return {
        "id": r["id"],
        "patientName": r["patient_name"],
        "bloodGroup": r["blood_group"],
        "units": r["units"],
        "hospital": r["hospital"],
        "district": r["district"],
        "upazila": r["upazila"],
        "neededAt": r["needed_at"].isoformat() if r["needed_at"] else None,
        "attendantName": r["attendant_name"],
        "contact": r["contact"],
        "reason": r["reason"],
        "status": r["status"],
        "verificationNote": r["verification_note"],
        "reportCount": r["report_count"],
        "submittedAt": r["submitted_at"].isoformat() if r["submitted_at"] else None,
        "verifiedAt": r["verified_at"].isoformat() if r["verified_at"] else None,
    }
