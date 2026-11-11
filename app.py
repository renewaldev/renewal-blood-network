"""FastAPI entry: lifespan, middleware, পাবলিক API ও পেজ রুট (§৪, §৫, §৭)।

চালানো: uvicorn app:app --host 127.0.0.1 --port 5500 --proxy-headers
"""

import asyncio
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException

from admin import router as admin_router
from admin_ext import router as admin_ext_router
from features import router as features_router
from config import get_settings
from db import bump_version, dispose, engine, ensure_schema, many, one, read_many, read_one, run, utcnow
from errors import ApiError
from jobs import background_loop
from otp import consume as otp_consume
from ratelimit import assert_user_not_locked, enforce, rate, record_attempt
from realtime import announce, poll_changes, ws_endpoint
from schemas import BLOOD_GROUPS, AVAILABILITY, DonorIn, PhoneAuthIn, RequestIn, RevealIn, geo, normalize_phone
from security import (
    aburn_pin_time,
    ahash_pin,
    averify_pin,
    client_ip,
    clear_session_cookie,
    cookie_name,
    csrf_for,
    current_user,
    ip_bytes,
    start_user_session,
    user_write,
    verify_turnstile,
)
from trust import recalc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
BASE_DIR = Path(__file__).resolve().parent
log = logging.getLogger("app")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SCOPES_DONOR = ["donors", "stats", "leaderboard"]
SCOPES_REQUEST = ["requests", "stats"]


# ───────────── Lifespan ─────────────
@asynccontextmanager
async def lifespan(_app: FastAPI):
    get_settings()
    geo()  # bd-geo.json না থাকলে এখানেই ব্যর্থ — ইচ্ছাকৃত
    await ensure_schema()  # ডাটাবেস ও টেবিল না থাকলে তৈরি
    tasks = [asyncio.create_task(poll_changes()), asyncio.create_task(background_loop())]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await dispose()


app = FastAPI(title="Renewal Blood Network", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(admin_router)
app.include_router(admin_ext_router)
app.include_router(features_router)
app.add_api_websocket_route("/ws/realtime", ws_endpoint)


# ───────────── Middleware (§৫ ক্রম) ─────────────
def _origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        ref = request.headers.get("referer")
        if not ref:
            return False
        parts = urlsplit(ref)
        origin = f"{parts.scheme}://{parts.netloc}"
    return origin.rstrip("/") in get_settings().origins


def _ws_sources() -> str:
    """CSP connect-src-এর জন্য ALLOWED_ORIGINS থেকে ws/wss উৎস (পুরোনো ব্রাউজারে 'self' ws কভার করে না)।"""
    out = []
    for o in sorted(get_settings().origins):
        if o.startswith("https://"):
            out.append("wss://" + o[len("https://"):])
        elif o.startswith("http://"):
            out.append("ws://" + o[len("http://"):])
    return " ".join(out)


def _csp(nonce: str) -> str:
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://challenges.cloudflare.com https://accounts.google.com; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data: https://*.tile.openstreetmap.org https://lh3.googleusercontent.com; "
        f"connect-src 'self' {_ws_sources()}; "
        "frame-src https://challenges.cloudflare.com https://accounts.google.com; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )


@app.middleware("http")
async def edge_middleware(request: Request, call_next):
    request.state.request_id = uuid.uuid4().hex
    request.state.ip = client_ip(request)
    request.state.nonce = secrets.token_urlsafe(16)
    path = request.url.path

    try:
        if path.startswith(("/api/", "/admin")):
            if request.method in UNSAFE_METHODS and not _origin_allowed(request):
                raise ApiError(403, "csrf_failed", "অনুরোধের উৎস যাচাই ব্যর্থ")
            await enforce("global", request.state.ip)
        response = await call_next(request)
    except ApiError as exc:
        response = JSONResponse(exc.payload(), status_code=exc.status, headers=exc.headers())

    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Content-Security-Policy"] = _csp(request.state.nonce)
    if path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=86400"
    settings = get_settings()
    if settings.is_prod and settings.cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ───────────── Error handlers ─────────────
@app.exception_handler(ApiError)
async def _api_error(_request: Request, exc: ApiError):
    return JSONResponse(exc.payload(), status_code=exc.status, headers=exc.headers())


@app.exception_handler(RequestValidationError)
async def _validation_error(_request: Request, exc: RequestValidationError):
    # মান (PIN/ফোন) কখনো উত্তরে বা লগে যায় না — শুধু ফিল্ড নাম ও বার্তা
    details = [
        {"field": ".".join(str(p) for p in err.get("loc", ())[1:]), "message": err.get("msg", "")}
        for err in exc.errors()
    ]
    return JSONResponse(
        {"error": {"code": "validation_error", "message": "ইনপুট সঠিক নয়", "details": details}},
        status_code=422,
    )


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        code = "not_found" if exc.status_code == 404 else "error"
        return JSONResponse({"error": {"code": code, "message": str(exc.detail)}}, status_code=exc.status_code)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


# ───────────── Helpers ─────────────
_cache: dict[str, tuple[float, object]] = {}


async def _cached(key: str, ttl: float, loader):
    """ইন-মেমরি TTL ক্যাশ — expensive endpoint-এর DB লোড কমায় (§১০)।"""
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    value = await loader()
    _cache[key] = (now, value)
    return value


def _iso(v):
    return v.isoformat() if v else None


def donor_public(r: dict) -> dict:
    """পাবলিক দাতা প্রোফাইল — ফোন নম্বর কখনো নয় (§৭)।"""
    return {
        "id": r["id"],
        "name": r["name"],
        "nameEn": r["name_en"],
        "bloodGroup": r["blood_group"],
        "district": r["district"],
        "upazila": r["upazila"],
        "area": r["area"],
        "availability": r["availability"],
        "canDonate": bool(r["can_donate"]),
        "nextAvailable": _iso(r["next_available"]),
        "donationCount": r["donation_count"],
        "verificationLevel": r["verification_level"],
        "trustScore": r["trust_score"],
        "badge": r["badge"],
        "phoneVisible": r["phone_visibility"] == "members",
    }


def donor_own(r: dict) -> dict:
    """নিজের প্রোফাইল — নিজের নম্বরসহ।"""
    return {
        **donor_public(r),
        "phone": r["phone"],
        "age": r["age"],
        "gender": r["gender"],
        "profession": r["profession"],
        "phoneVisibility": r["phone_visibility"],
        "lastDonation": _iso(r["last_donation"]),
    }


DONOR_PUBLIC_COLS = (
    "id, name, name_en, blood_group, district, upazila, area, availability, can_donate, "
    "next_available, donation_count, verification_level, trust_score, badge, phone_visibility"
)
DONOR_OWN_COLS = (
    DONOR_PUBLIC_COLS + ", phone, age, gender, profession, last_donation"
)


def _public_request(r: dict) -> dict:
    """জরুরি অনুরোধ — attendant নম্বর (contact) বাদ।"""
    return {
        "id": r["id"],
        "patientName": r["patient_name"],
        "bloodGroup": r["blood_group"],
        "units": r["units"],
        "hospital": r["hospital"],
        "district": r["district"],
        "upazila": r["upazila"],
        "neededAt": _iso(r["needed_at"]),
        "reason": r["reason"],
        "status": r["status"],
    }


# ───────────── Reveal (§৮.৩) ─────────────
async def _check_quota(conn, user: dict, ip: bytes | None) -> None:
    s = get_settings()
    now = utcnow()
    lvl = await one(conn, "SELECT verification_level AS lvl FROM donors WHERE user_id = :u", u=user["id"])
    level = lvl["lvl"] if lvl else 0
    day_cap = s.reveal_quota_verified if level >= 1 else s.reveal_quota_new

    day = (
        await one(
            conn,
            "SELECT COUNT(*) AS n FROM phone_reveals WHERE user_id = :u AND created_at > :since",
            u=user["id"],
            since=now - timedelta(hours=24),
        )
    )["n"]
    hour = (
        await one(
            conn,
            "SELECT COUNT(*) AS n FROM phone_reveals WHERE user_id = :u AND created_at > :since",
            u=user["id"],
            since=now - timedelta(hours=1),
        )
    )["n"]

    quota_msg = "নম্বর দেখার সীমা শেষ হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন"
    if day >= day_cap or hour >= s.reveal_hourly_limit:
        raise ApiError(429, "quota_exceeded", quota_msg)
    # ১ ঘণ্টার কম পুরনো একাউন্টের প্রথম ঘণ্টার সীমা
    if now - user["created_at"] < timedelta(hours=1) and hour >= s.reveal_newaccount_limit:
        raise ApiError(429, "quota_exceeded", quota_msg)


async def _flag_if_abusive(conn, ip: bytes | None) -> None:
    """একই IP থেকে ২৪ ঘণ্টায় ৩টির বেশি আলাদা একাউন্ট → flagged (স্বয়ংক্রিয় ব্যান নয়)।"""
    if ip is None:
        return
    row = await one(
        conn,
        "SELECT COUNT(DISTINCT user_id) AS n FROM phone_reveals WHERE ip = :ip AND created_at > :since",
        ip=ip,
        since=utcnow() - timedelta(hours=24),
    )
    if row and row["n"] > 3:
        await run(
            conn,
            """UPDATE users SET flagged = TRUE WHERE id IN (
                   SELECT user_id FROM phone_reveals WHERE ip = :ip AND created_at > :since)""",
            ip=ip,
            since=utcnow() - timedelta(hours=24),
        )


async def _reveal(request: Request, user: dict, target_type: str, target_id: str) -> dict:
    await enforce("reveal", user["id"])

    if target_type == "donor":
        t = await read_one("SELECT phone, phone_visibility AS vis FROM donors WHERE id = :id", id=target_id)
        if not t:
            raise ApiError(404, "not_found", "দাতা পাওয়া যায়নি")
        if t["vis"] != "members":
            raise ApiError(403, "phone_hidden", "এই দাতা শুধু অ্যাডমিনের মাধ্যমে যোগাযোগ চান")
        phone = t["phone"]
    else:
        t = await read_one("SELECT contact, status FROM blood_requests WHERE id = :id", id=target_id)
        if not t or t["status"] != "verified":
            raise ApiError(404, "not_found", "অনুরোধ পাওয়া যায়নি")
        phone = t["contact"]

    ip = ip_bytes(request.state.ip)
    async with engine().begin() as conn:
        # ইউজার সারি লক: একই ইউজারের সমান্তরাল reveal কোটা এড়ায়
        await one(conn, "SELECT id FROM users WHERE id = :id FOR UPDATE", id=user["id"])
        seen = await one(
            conn,
            "SELECT 1 AS x FROM phone_reveals WHERE user_id = :u AND target_type = :t AND target_id = :i",
            u=user["id"], t=target_type, i=target_id,
        )
        if not seen:  # আগে দেখা নম্বরে কোটা কমে না
            await _check_quota(conn, user, ip)
            await run(
                conn,
                """INSERT INTO phone_reveals (user_id, target_type, target_id, ip)
                   VALUES (:u, :t, :i, :ip)""",
                u=user["id"], t=target_type, i=target_id, ip=ip,
            )
            await _flag_if_abusive(conn, ip)
    return {"phone": phone}


# ───────────── Pages ─────────────
@app.get("/", include_in_schema=False)
async def index_page(request: Request):
    return templates.TemplateResponse(request, "index.html", {"nonce": request.state.nonce})


# ───────────── Public API ─────────────
@app.get("/api/health")
async def health():
    try:
        await read_one("SELECT 1 AS ok")
    except Exception:
        return JSONResponse({"status": "degraded", "db": "down"}, status_code=503)
    return {"status": "ok", "db": "ok"}


@app.get("/api/config")
async def public_config():
    s = get_settings()
    return {
        "turnstileEnabled": s.turnstile_enabled,
        "otpEnabled": s.otp_enabled,
        "turnstileSiteKey": s.turnstile_site_key,
        "googleEnabled": s.google_login_enabled,
        "googleClientId": s.google_client_id if s.google_login_enabled else None,
    }


async def _load_stats() -> dict:
    async with engine().connect() as conn:
        totals = await one(
            conn,
            """SELECT COUNT(*) AS total,
                      CAST(SUM(availability = 'available') AS UNSIGNED) AS available
               FROM donors""",
        )
        verified = await one(conn, "SELECT COUNT(*) AS n FROM blood_requests WHERE status = 'verified'")
        groups = await many(
            conn,
            """SELECT blood_group, COUNT(*) AS donors,
                      CAST(SUM(availability = 'available') AS UNSIGNED) AS available
               FROM donors GROUP BY blood_group""",
        )
        ver = await one(conn, "SELECT COALESCE(MAX(version), 0) AS v FROM change_log")
    by_group = {g: {"donors": 0, "available": 0} for g in BLOOD_GROUPS}
    for g in groups:
        by_group[g["blood_group"]] = {"donors": g["donors"], "available": g["available"] or 0}
    return {
        "totalDonors": totals["total"],
        "availableDonors": totals["available"] or 0,
        "verifiedRequests": verified["n"],
        "byBloodGroup": by_group,
        "version": int(ver["v"]),
    }


@app.get("/api/stats", dependencies=[Depends(rate("public_read"))])
async def stats():
    return await _cached("stats", 10, _load_stats)


@app.get("/api/auth/check-phone", dependencies=[Depends(rate("check_phone"))])
async def check_phone(phone: str = Query(..., max_length=32)):
    try:
        p = normalize_phone(phone)
    except ValueError:
        raise ApiError(400, "validation_error", "ফোন নম্বর সঠিক নয়")
    row = await read_one("SELECT 1 AS x FROM users WHERE phone = :p", p=p)
    return {"exists": row is not None}


@app.post("/api/auth/signup", status_code=201, dependencies=[Depends(rate("signup"))])
async def signup(body: PhoneAuthIn, request: Request, response: Response):
    await verify_turnstile(body.turnstile_token, request.state.ip)
    if get_settings().otp_enabled:
        await otp_consume(body.phone, "signup", body.otp_code)
    digest, salt = await ahash_pin(body.pin)
    uid = uuid.uuid4().hex
    async with engine().begin() as conn:
        if await one(conn, "SELECT id FROM users WHERE phone = :p FOR UPDATE", p=body.phone):
            raise ApiError(409, "conflict", "এই নম্বর আগে থেকেই নিবন্ধিত")
        try:
            await run(
                conn,
                """INSERT INTO users (id, phone, pin_hash, pin_salt, status)
                   VALUES (:id, :p, :h, :s, 'active')""",
                id=uid, p=body.phone, h=digest, s=salt,
            )
        except IntegrityError:
            raise ApiError(409, "conflict", "এই নম্বর আগে থেকেই নিবন্ধিত")
        csrf = await start_user_session(conn, uid, request, response, None)
    return {"ok": True, "csrfToken": csrf, "user": {"id": uid, "phone": body.phone}}


@app.post("/api/auth/login", dependencies=[Depends(rate("login"))])
async def login(body: PhoneAuthIn, request: Request, response: Response):
    await verify_turnstile(body.turnstile_token, request.state.ip)
    await assert_user_not_locked(body.phone)

    user = await read_one("SELECT id, status, pin_hash, pin_salt FROM users WHERE phone = :p", p=body.phone)
    ip = request.state.ip
    if not user or not user["pin_hash"]:
        await aburn_pin_time(body.pin)
        await record_attempt("user", body.phone, ip, False)
        raise ApiError(401, "unauthorized", "ফোন নম্বর বা PIN ভুল")
    if not await averify_pin(body.pin, user["pin_hash"], user["pin_salt"]):
        await record_attempt("user", body.phone, ip, False)
        raise ApiError(401, "unauthorized", "ফোন নম্বর বা PIN ভুল")
    if get_settings().otp_enabled:
        try:
            await otp_consume(body.phone, "login", body.otp_code)
        except ApiError:
            await record_attempt("user", body.phone, ip, False)
            raise
    await record_attempt("user", body.phone, ip, True)
    if user["status"] != "active":
        raise ApiError(403, "forbidden", "অ্যাকাউন্ট বন্ধ আছে")

    async with engine().begin() as conn:
        csrf = await start_user_session(
            conn, user["id"], request, response, request.cookies.get(cookie_name("user"))
        )
        await run(conn, "UPDATE users SET last_login_at = :n WHERE id = :id", n=utcnow(), id=user["id"])
    return {"ok": True, "csrfToken": csrf}


@app.get("/api/auth/me", dependencies=[Depends(rate("me"))])
async def me(user: dict = Depends(current_user)):
    donor = await read_one(f"SELECT {DONOR_OWN_COLS} FROM donors WHERE user_id = :u", u=user["id"])
    return {
        "user": {"id": user["id"], "phone": user["phone"], "flagged": bool(user["flagged"])},
        "donor": donor_own(donor) if donor else None,
        "csrfToken": csrf_for(user["session_hash"]),
    }


@app.post("/api/auth/logout")
async def logout(response: Response, user: dict = Depends(user_write)):
    async with engine().begin() as conn:
        await run(conn, "DELETE FROM sessions WHERE token_hash = :th", th=user["session_hash"])
    clear_session_cookie(response, "user")
    return {"ok": True}


@app.get("/api/donors/search", dependencies=[Depends(rate("search"))])
async def donor_search(
    blood_group: str | None = Query(default=None, alias="bloodGroup"),
    district: str | None = Query(default=None, max_length=64),
    upazila: str | None = Query(default=None, max_length=64),
    area: str | None = Query(default=None, max_length=120),
    availability: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
):
    clauses = ["1=1"]
    params: dict = {"lim": limit, "off": offset}
    if blood_group:
        if blood_group not in BLOOD_GROUPS:
            raise ApiError(400, "validation_error", "রক্তের গ্রুপ সঠিক নয়")
        clauses.append("blood_group = :bg")
        params["bg"] = blood_group
    if district:
        clauses.append("district = :d")
        params["d"] = district
    if upazila:
        clauses.append("upazila = :u")
        params["u"] = upazila
    if area:
        clauses.append("area LIKE :area")
        escaped = area.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params["area"] = f"%{escaped}%"
    if availability:
        if availability not in AVAILABILITY:
            raise ApiError(400, "validation_error", "availability সঠিক নয়")
        clauses.append("availability = :av")
        params["av"] = availability
    # clauses শুধু উপরের স্থির শর্ত থেকে তৈরি; ব্যবহারকারীর মান সব params দিয়ে যায়।
    rows = await read_many(
        f"""SELECT {DONOR_PUBLIC_COLS} FROM donors WHERE {' AND '.join(clauses)}
            ORDER BY trust_score DESC, id LIMIT :lim OFFSET :off""",
        **params,
    )
    return {"items": [donor_public(r) for r in rows], "limit": limit, "offset": offset}


@app.post("/api/donors", status_code=201, dependencies=[Depends(rate("donor_create"))])
async def create_donor(body: DonorIn, request: Request, user: dict = Depends(user_write)):
    await verify_turnstile(body.turnstile_token, request.state.ip)
    if not user["phone"]:
        raise ApiError(400, "validation_error", "প্রথমে অ্যাকাউন্টে ফোন নম্বর থাকতে হবে")
    donor_id = uuid.uuid4().hex
    async with engine().begin() as conn:
        if await one(conn, "SELECT id FROM donors WHERE user_id = :u", u=user["id"]):
            raise ApiError(409, "conflict", "আপনার দাতা প্রোফাইল আগে থেকেই আছে")
        try:
            await run(
                conn,
                """INSERT INTO donors (id, user_id, name, name_en, phone, phone_visibility,
                       blood_group, district, upazila, area, age, gender, profession)
                   VALUES (:id, :u, :name, :name_en, :phone, :vis, :bg, :d, :up, :area,
                           :age, :gender, :prof)""",
                id=donor_id, u=user["id"], name=body.name, name_en=body.name_en,
                phone=user["phone"], vis=body.phone_visibility, bg=body.blood_group,
                d=body.district, up=body.upazila, area=body.area, age=body.age,
                gender=body.gender, prof=body.profession,
            )
        except IntegrityError:
            raise ApiError(409, "conflict", "এই নম্বরে আগেই একটি দাতা প্রোফাইল আছে")
        await recalc(conn, donor_id)
        version = await bump_version(conn, SCOPES_DONOR)
    await announce(version, SCOPES_DONOR)
    return {"id": donor_id}


@app.get("/api/donors/{donor_id}")
async def get_donor(donor_id: str):
    row = await read_one(f"SELECT {DONOR_PUBLIC_COLS} FROM donors WHERE id = :id", id=donor_id)
    if not row:
        raise ApiError(404, "not_found", "দাতা পাওয়া যায়নি")
    return donor_public(row)


@app.post("/api/donors/{donor_id}/reveal")
async def reveal_donor(donor_id: str, body: RevealIn, request: Request, user: dict = Depends(user_write)):
    await verify_turnstile(body.turnstile_token, request.state.ip)
    return await _reveal(request, user, "donor", donor_id)


@app.get("/api/donors/{donor_id}/reveal-stats")
async def reveal_stats(donor_id: str, user: dict = Depends(current_user)):
    """নিজের দাতা প্রোফাইলের সংখ্যা। কে দেখেছে তা দাতাকে দেখানো হয় না (§৮.৩)।"""
    own = await read_one("SELECT id FROM donors WHERE id = :id AND user_id = :u", id=donor_id, u=user["id"])
    if not own:
        raise ApiError(403, "forbidden", "অনুমতি নেই")
    now = utcnow()
    async with engine().connect() as conn:
        total = await one(
            conn,
            "SELECT COUNT(*) AS n FROM phone_reveals WHERE target_type = 'donor' AND target_id = :id",
            id=donor_id,
        )
        week = await one(
            conn,
            """SELECT COUNT(*) AS n FROM phone_reveals
               WHERE target_type = 'donor' AND target_id = :id AND created_at > :since""",
            id=donor_id, since=now - timedelta(days=7),
        )
    return {"total": total["n"], "last7Days": week["n"]}


@app.get("/api/requests")
async def list_requests(limit: int = Query(default=20, ge=1, le=50), offset: int = Query(default=0, ge=0)):
    rows = await read_many(
        """SELECT id, patient_name, blood_group, units, hospital, district, upazila,
                  needed_at, reason, status
           FROM blood_requests WHERE status = 'verified'
           ORDER BY needed_at ASC LIMIT :lim OFFSET :off""",
        lim=limit, off=offset,
    )
    return {"items": [_public_request(r) for r in rows], "limit": limit, "offset": offset}


@app.post("/api/requests", status_code=201, dependencies=[Depends(rate("emergency"))])
async def create_request(body: RequestIn, request: Request):
    await verify_turnstile(body.turnstile_token, request.state.ip)
    rid = uuid.uuid4().hex
    async with engine().begin() as conn:
        dup = await one(
            conn,
            """SELECT id FROM blood_requests
               WHERE contact = :c AND hospital = :h AND blood_group = :bg
                 AND submitted_at > :since LIMIT 1""",
            c=body.contact, h=body.hospital, bg=body.blood_group,
            since=utcnow() - timedelta(minutes=10),
        )
        if dup:
            raise ApiError(409, "conflict", "একই অনুরোধ ইতিমধ্যে জমা হয়েছে")
        await run(
            conn,
            """INSERT INTO blood_requests (id, patient_name, blood_group, units, hospital,
                   district, upazila, needed_at, attendant_name, contact, reason,
                   status, submitted_ip)
               VALUES (:id, :pn, :bg, :units, :h, :d, :up, :na, :an, :c, :r, 'pending', :ip)""",
            id=rid, pn=body.patient_name, bg=body.blood_group, units=body.units, h=body.hospital,
            d=body.district, up=body.upazila, na=body.needed_at, an=body.attendant_name,
            c=body.contact, r=body.reason, ip=ip_bytes(request.state.ip),
        )
        version = await bump_version(conn, SCOPES_REQUEST)
    await announce(version, SCOPES_REQUEST)
    return {"id": rid, "status": "pending"}


@app.post("/api/requests/{request_id}/reveal")
async def reveal_request(request_id: str, body: RevealIn, request: Request, user: dict = Depends(user_write)):
    await verify_turnstile(body.turnstile_token, request.state.ip)
    return await _reveal(request, user, "request", request_id)


@app.get("/api/leaderboard", dependencies=[Depends(rate("public_read"))])
async def leaderboard():
    async def load():
        rows = await read_many(
            """SELECT id, name, district, blood_group, trust_score, badge, donation_count
               FROM donors ORDER BY trust_score DESC, donation_count DESC, id LIMIT 20"""
        )
        return {
            "items": [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "district": r["district"],
                    "bloodGroup": r["blood_group"],
                    "trustScore": r["trust_score"],
                    "badge": r["badge"],
                    "donationCount": r["donation_count"],
                }
                for r in rows
            ]
        }

    return await _cached("leaderboard", 10, load)