"""অ্যাডমিন এক্সটেনশন: দাতা, যোগাযোগ অনুরোধ, রিপোর্ট, ইউজার, reveal লগ, audit।

admin.py-এর একই নিরাপত্তা (IP allowlist, rate limit, সেশন, CSRF) প্রয়োগ হয়।
প্রতিটি mutation audit_log-এ লেখা হয় ও change_log বাড়ায়।
"""

import json
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.exc import IntegrityError

from config import get_settings
from db import bump_version, engine, one, read_many, run
from errors import ApiError
from passwords import amake_hash
from ratelimit import rate
from realtime import announce
from schemas import AdminContactUpdateIn, AdminCreateIn, AdminDonationIn, AdminDonorUpdateIn, AdminUserUpdateIn
from security import admin_write, current_admin, superadmin_read, superadmin_write
from trust import recalc
from admin import audit, ip_allowlist

router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(ip_allowlist), Depends(rate("admin_api"))],
)

CONTACT_STATUSES = ("pending", "contacted", "done", "rejected")
DONATION_GAP_DAYS = 90  # শেষ দানের কত দিন পর আবার দিতে পারবেন (next_available)


def _page(limit: int, offset: int) -> dict:
    return {"limit": limit, "offset": offset}


# ───────────── দাতা (পূর্ণ, unmasked) ─────────────
@router.get("/api/donors")
async def admin_list_donors(
    suspicious: bool = False,
    district: str | None = Query(default=None, max_length=64),
    donor_id: str | None = Query(default=None, max_length=32),
    q: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(current_admin),
):
    clauses = ["1=1"]
    params: dict = {"lim": limit, "off": offset}
    if donor_id and donor_id.strip():
        clauses.append("id = :did")
        params["did"] = donor_id.strip()
    if q and q.strip():
        # নাম (যেকোনো অংশ) বা ফোন (শুরু থেকে); LIKE-এর বিশেষ চিহ্ন escape করা
        esc = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("(name LIKE :qn OR name_en LIKE :qn OR phone LIKE :qp)")
        params["qn"] = f"%{esc}%"
        params["qp"] = f"{esc}%"
    if suspicious:
        clauses.append("suspicious = TRUE")
    if district:
        clauses.append("district = :d")
        params["d"] = district
    rows = await read_many(
        f"""SELECT id, name, phone, blood_group, district, upazila, availability, can_donate,
                   verification_level, trust_score, badge, suspicious, report_count,
                   donation_count, created_at
            FROM donors WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC LIMIT :lim OFFSET :off""",
        **params,
    )
    items = [{**r, "created_at": r["created_at"].isoformat()} for r in rows]
    return {"items": items, **_page(limit, offset)}


@router.put("/api/donors/{donor_id}")
async def admin_update_donor(donor_id: str, body: AdminDonorUpdateIn, request: Request, admin: dict = Depends(admin_write)):
    data = body.model_dump(exclude_unset=True)
    scopes = ["donors", "stats", "leaderboard", "admin_donors"]
    async with engine().begin() as conn:
        d = await one(conn, "SELECT verification_level FROM donors WHERE id = :id FOR UPDATE", id=donor_id)
        if not d:
            raise ApiError(404, "not_found", "দাতা পাওয়া যায়নি")
        if not data:
            return {"ok": True}

        sets: list[str] = []
        params: dict = {"id": donor_id}
        if data.get("suspicious") is not None:
            sets.append("suspicious = :sus")
            params["sus"] = data["suspicious"]
        if data.get("can_donate") is not None:
            sets.append("can_donate = :cd")
            params["cd"] = data["can_donate"]
        if data.get("verification_level") is not None:
            new, old = data["verification_level"], d["verification_level"]
            sets.append("verification_level = :vl")
            params["vl"] = new
            if new != old:
                await run(
                    conn,
                    """INSERT INTO verification_events (donor_id, old_level, new_level, note)
                       VALUES (:id, :o, :n, 'admin')""",
                    id=donor_id, o=old, n=new,
                )
        if sets:
            await run(conn, f"UPDATE donors SET {', '.join(sets)} WHERE id = :id", **params)
        await recalc(conn, donor_id)
        await audit(conn, request, admin, "donor.update", "donor", donor_id, data)
        version = await bump_version(conn, scopes)
    await announce(version, scopes)
    return {"ok": True}


@router.post("/api/donors/{donor_id}/donations", status_code=201)
async def admin_add_donation(donor_id: str, body: AdminDonationIn, request: Request, admin: dict = Depends(admin_write)):
    """একটি যাচাইকৃত রক্তদান নথিভুক্ত করে; donation_count/last_donation/trust_score একই transaction-এ বদলায়।"""
    scopes = ["donors", "stats", "leaderboard", "admin_donors"]
    async with engine().begin() as conn:
        d = await one(
            conn,
            "SELECT donation_count, last_donation FROM donors WHERE id = :id FOR UPDATE",
            id=donor_id,
        )
        if not d:
            raise ApiError(404, "not_found", "দাতা পাওয়া যায়নি")
        # একই দিনে একই দাতার দ্বিতীয় এন্ট্রি (ডাবল-ক্লিক/ভুল) আটকানো
        dup = await one(
            conn,
            "SELECT id FROM donations WHERE donor_id = :id AND donated_at = :d LIMIT 1",
            id=donor_id, d=body.donated_at,
        )
        if dup:
            raise ApiError(409, "conflict", "এই তারিখে দান আগেই নথিভুক্ত আছে")
        donation_id = uuid.uuid4().hex
        await run(
            conn,
            """INSERT INTO donations (id, donor_id, donated_at, place, note)
               VALUES (:i, :did, :d, :p, :n)""",
            i=donation_id, did=donor_id, d=body.donated_at, p=body.place, n=body.note,
        )
        # আগে থেকে থাকা গণনা/তারিখ (পুরনো বা ইমপোর্ট করা ডেটা, যার সারি donations-এ নেই) কমতে দেওয়া হয় না:
        # নতুন গণনা = max(আগের + ১, donations-এর সারি সংখ্যা); শেষ দান = max(আগের তারিখ, নতুন তারিখ)
        rows_n = (await one(conn, "SELECT COUNT(*) AS n FROM donations WHERE donor_id = :id", id=donor_id))["n"]
        new_count = max(int(d["donation_count"]) + 1, int(rows_n))
        last = max(filter(None, [d["last_donation"], body.donated_at]))
        await run(
            conn,
            """UPDATE donors SET donation_count = :n, last_donation = :l, next_available = :na
               WHERE id = :id""",
            n=new_count, l=last, na=last + timedelta(days=DONATION_GAP_DAYS), id=donor_id,
        )
        await recalc(conn, donor_id)
        await audit(
            conn, request, admin, "donation.add", "donor", donor_id,
            {"donation_id": donation_id, "donated_at": body.donated_at.isoformat(), "place": body.place},
        )
        version = await bump_version(conn, scopes)
    await announce(version, scopes)
    return {"ok": True, "id": donation_id, "donationCount": new_count}


# ───────────── যোগাযোগ অনুরোধ ─────────────
@router.get("/api/contacts")
async def admin_list_contacts(
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(current_admin),
):
    clauses = ["1=1"]
    params: dict = {"lim": limit, "off": offset}
    if status:
        if status not in CONTACT_STATUSES:
            raise ApiError(400, "validation_error", "অবৈধ স্ট্যাটাস")
        clauses.append("c.status = :s")
        params["s"] = status
    rows = await read_many(
        f"""SELECT c.id, c.donor_id, c.patient, c.blood_group, c.hospital, c.units, c.phone, c.status,
                   c.submitted_at, d.name AS donor_name, d.phone AS donor_phone,
                   d.district AS donor_district, d.upazila AS donor_upazila
            FROM contact_requests c JOIN donors d ON d.id = c.donor_id
            WHERE {' AND '.join(clauses)}
            ORDER BY c.submitted_at DESC LIMIT :lim OFFSET :off""",
        **params,
    )
    items = [{**r, "submitted_at": r["submitted_at"].isoformat()} for r in rows]
    return {"items": items, **_page(limit, offset)}


@router.put("/api/contacts/{contact_id}")
async def admin_update_contact(contact_id: str, body: AdminContactUpdateIn, request: Request, admin: dict = Depends(admin_write)):
    async with engine().begin() as conn:
        row = await one(conn, "SELECT status FROM contact_requests WHERE id = :id FOR UPDATE", id=contact_id)
        if not row:
            raise ApiError(404, "not_found", "অনুরোধ পাওয়া যায়নি")
        await run(conn, "UPDATE contact_requests SET status = :s WHERE id = :id", s=body.status, id=contact_id)
        await audit(conn, request, admin, f"contact.{body.status}", "contact", contact_id, {"from": row["status"], "to": body.status})
        version = await bump_version(conn, ["admin_contacts"])
    await announce(version, ["admin_contacts"])
    return {"ok": True, "status": body.status}


# ───────────── রিপোর্ট (তালিকা) ─────────────
@router.get("/api/reports")
async def admin_list_reports(
    target_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(current_admin),
):
    clauses = ["1=1"]
    params: dict = {"lim": limit, "off": offset}
    if target_type:
        if target_type not in ("donor", "request"):
            raise ApiError(400, "validation_error", "অবৈধ target_type")
        clauses.append("target_type = :tt")
        params["tt"] = target_type
    # reporter_key (HMAC) ফেরত দেওয়া হয় না
    rows = await read_many(
        f"""SELECT id, target_type, target_id, reason, created_at
            FROM reports WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC LIMIT :lim OFFSET :off""",
        **params,
    )
    items = [{**r, "created_at": r["created_at"].isoformat()} for r in rows]
    return {"items": items, **_page(limit, offset)}


# ───────────── ইউজার ─────────────
@router.get("/api/users")
async def admin_list_users(
    flagged: bool = False,
    limit: int = Query(default=50, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(current_admin),
):
    where = "flagged = TRUE" if flagged else "1=1"
    rows = await read_many(
        f"""SELECT id, phone, email, status, flagged, created_at, last_login_at
            FROM users WHERE {where}
            ORDER BY created_at DESC LIMIT :lim OFFSET :off""",
        lim=limit, off=offset,
    )
    items = [
        {
            **r,
            "created_at": r["created_at"].isoformat(),
            "last_login_at": r["last_login_at"].isoformat() if r["last_login_at"] else None,
        }
        for r in rows
    ]
    return {"items": items, **_page(limit, offset)}


@router.put("/api/users/{user_id}")
async def admin_update_user(user_id: str, body: AdminUserUpdateIn, request: Request, admin: dict = Depends(admin_write)):
    if body.flagged is True:
        raise ApiError(400, "validation_error", "flagged শুধু সাফ করা যায় (false)")
    data = body.model_dump(exclude_unset=True)
    async with engine().begin() as conn:
        u = await one(conn, "SELECT id FROM users WHERE id = :id FOR UPDATE", id=user_id)
        if not u:
            raise ApiError(404, "not_found", "ব্যবহারকারী পাওয়া যায়নি")
        if data.get("status") is not None:
            await run(conn, "UPDATE users SET status = :s WHERE id = :id", s=data["status"], id=user_id)
            if data["status"] == "blocked":
                # ব্লক হলে সব সেশন বাতিল
                await run(conn, "DELETE FROM sessions WHERE user_id = :id", id=user_id)
        if data.get("flagged") is False:
            await run(conn, "UPDATE users SET flagged = FALSE WHERE id = :id", id=user_id)
        await audit(conn, request, admin, "user.update", "user", user_id, data)
        version = await bump_version(conn, ["admin_donors"])
    await announce(version, ["admin_donors"])
    return {"ok": True}


# ───────────── নম্বর দেখার লগ (অভিযোগ তদন্তে) ─────────────
@router.get("/api/reveals")
async def admin_list_reveals(
    user_id: str | None = Query(default=None, max_length=32),
    target_id: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(current_admin),
):
    clauses = ["1=1"]
    params: dict = {"lim": limit, "off": offset}
    if user_id:
        clauses.append("user_id = :u")
        params["u"] = user_id
    if target_id:
        clauses.append("target_id = :t")
        params["t"] = target_id
    rows = await read_many(
        f"""SELECT user_id, target_type, target_id, created_at
            FROM phone_reveals WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC LIMIT :lim OFFSET :off""",
        **params,
    )
    items = [{**r, "created_at": r["created_at"].isoformat()} for r in rows]
    return {"items": items, **_page(limit, offset)}


# ───────────── অ্যাডমিন ব্যবস্থাপনা (শুধু সুপার অ্যাডমিন) ─────────────
@router.get("/api/admins")
async def admin_list_admins(_admin: dict = Depends(superadmin_read)):
    rows = await read_many(
        """SELECT a.id, a.username, a.role, a.must_change_password, a.created_at, a.last_login_at,
                  c.username AS created_by
           FROM admins a LEFT JOIN admins c ON c.id = a.created_by
           ORDER BY (a.role = 'superadmin') DESC, a.created_at"""
    )
    items = [
        {
            **r,
            "must_change_password": bool(r["must_change_password"]),
            "created_at": r["created_at"].isoformat(),
            "last_login_at": r["last_login_at"].isoformat() if r["last_login_at"] else None,
        }
        for r in rows
    ]
    return {"items": items}


@router.post("/api/admins")
async def admin_create_admin(body: AdminCreateIn, request: Request, admin: dict = Depends(superadmin_write)):
    """নতুন অ্যাডমিন: অস্থায়ী পাসওয়ার্ড .env-এর ADMIN_TEMP_PASSWORD; প্রথম লগইনে বদলাতে বাধ্য।"""
    temp = get_settings().admin_temp_password
    if not temp:
        raise ApiError(500, "config_error", "সার্ভারে ADMIN_TEMP_PASSWORD সেট করা নেই")
    new_id = uuid.uuid4().hex
    pw_hash = await amake_hash(temp)  # কানেকশন ধরার আগে
    try:
        async with engine().begin() as conn:
            if await one(conn, "SELECT id FROM admins WHERE username = :u FOR UPDATE", u=body.username):
                raise ApiError(409, "conflict", "এই ইউজারনেম আগে থেকেই আছে")
            await run(
                conn,
                """INSERT INTO admins (id, username, password_hash, role, must_change_password, created_by)
                   VALUES (:id, :u, :h, 'admin', TRUE, :by)""",
                id=new_id, u=body.username, h=pw_hash, by=admin["id"],
            )
            await audit(conn, request, admin, "admin.create", "admin", new_id, {"username": body.username})
    except IntegrityError:
        raise ApiError(409, "conflict", "এই ইউজারনেম আগে থেকেই আছে")
    return {"ok": True, "id": new_id, "username": body.username}


@router.delete("/api/admins/{admin_id}")
async def admin_delete_admin(admin_id: str, request: Request, admin: dict = Depends(superadmin_write)):
    async with engine().begin() as conn:
        row = await one(conn, "SELECT id, username, role FROM admins WHERE id = :id FOR UPDATE", id=admin_id)
        if not row:
            raise ApiError(404, "not_found", "অ্যাডমিন পাওয়া যায়নি")
        if row["role"] == "superadmin" or row["id"] == admin["id"]:
            raise ApiError(409, "conflict", "সুপার অ্যাডমিনকে ডিলিট করা যায় না")
        await run(conn, "DELETE FROM admins WHERE id = :id", id=admin_id)  # তার সব সেশন FK cascade-এ মুছে যায়
        await audit(conn, request, admin, "admin.delete", "admin", admin_id, {"username": row["username"]})
    return {"ok": True}


# ───────────── Audit log ─────────────
@router.get("/api/audit")
async def admin_list_audit(
    limit: int = Query(default=50, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
    _admin: dict = Depends(current_admin),
):
    rows = await read_many(
        """SELECT id, actor, action, target_type, target_id, detail, created_at
           FROM audit_log ORDER BY id DESC LIMIT :lim OFFSET :off""",
        lim=limit, off=offset,
    )
    items = []
    for r in rows:
        detail = r["detail"]
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except ValueError:
                pass
        items.append({**r, "detail": detail, "created_at": r["created_at"].isoformat()})
    return {"items": items, **_page(limit, offset)}