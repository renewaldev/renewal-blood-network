# Renewal Blood Network

A real-time, volunteer blood-donor network for Bangladesh, covering every district and upazila.
Donors register, people in need search for donors or post urgent blood requests, and admins verify everything, all from a single server.

> Full design notes (in Bengali) live in [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Features

**For the public / members**
- Search donors by blood group, district, upazila, area and availability.
- Post urgent blood requests (reviewed by an admin before they go public).
- Donor registration with a profile (blood group, location, availability, phone visibility).
- Trust score and leaderboard.
- District-level map of donors.
- Phone numbers are never shown to guests. Logged-in users reveal them one by one, under quotas and with an audit log.
- Contact-request flow: if a donor does not want to show their number, the admin connects the two sides.
- Report abusive donors or requests.
- Login with phone + 4-digit PIN, or Google Sign-In (optional).
- Live updates over WebSocket, with a LIVE / SYNC / OFFLINE indicator in the navbar.

**For admins** (`/admin`)
- Verify, reject or fulfil blood requests; manage donors, contact requests, reports and users.
- Raise a donor's verification level (affects trust score and reveal quota).
- Record a verified blood donation for a donor (updates donation count, last donation date, next available date and trust score).
- View the phone-reveal log and the audit log.
- Multi-admin support with `superadmin` / `admin` roles, forced password change on first login, optional IP allow-list.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, Uvicorn |
| Database | MySQL 8+ / MariaDB 10.6+ (InnoDB, `utf8mb4`) via SQLAlchemy Core + `asyncmy` |
| Frontend | Two single-file SPAs: `templates/index.html`, `templates/admin.html` (inline CSS/JS, CSP nonce) |
| Real-time | WebSocket `/ws/realtime` backed by a `change_log` table (no Redis needed) |
| Bot protection | Cloudflare Turnstile |
| Sessions | `HttpOnly` cookie + CSRF token (`X-CSRF-Token`) |
| Validation / config | Pydantic v2, pydantic-settings |

---

## Project layout

```
app.py            FastAPI app, middleware, public API, reveal logic, pages
admin.py          Admin login, requests moderation, audit helper
admin_ext.py      Admin: donors, donations, contacts, reports, users, admins, logs
features.py       Contact requests, reports, Google login, OTP endpoints
realtime.py       WebSocket hub + change_log poller
trust.py          Trust score and badge calculation
security.py       PIN hashing, tokens, sessions, CSRF, Turnstile, client IP
ratelimit.py      Rate limiter (memory / mysql) and login lockout
passwords.py      Admin password hashing (scrypt) and rules
db.py             Async engine, helpers, schema, bump_version()
config.py         Settings loaded from .env, production startup checks
schemas.py        Pydantic request models and input validation
jobs.py           Background tasks (hourly cleanup, daily expiry)
otp.py, sms.py    SMS OTP plumbing (disabled by default)
errors.py         ApiError and error handlers
templates/        index.html (public SPA), admin.html (admin SPA)
static/           Geo data (bd-geo.json), fonts, assets
tools/build_geo.py  Builds static/data/bd-geo.json from district/upazila files
```

---

## Quick start (local development)

### 1. Requirements
- Python 3.12 or 3.13 recommended. Very new Python versions may lack prebuilt wheels for some dependencies.
- A running MySQL 8+ / MariaDB server. The DB user needs the `CREATE DATABASE` privilege, because the app creates the database and tables on first start.

### 2. Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure
```bash
cp .env.example .env
```
Minimum changes for local development:
```env
APP_ENV=development
COOKIE_SECURE=false
TURNSTILE_ENABLED=false
RATE_LIMIT_BACKEND=memory
WORKERS=1
ALLOWED_ORIGINS=http://localhost:5500,http://127.0.0.1:5500
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
```
In production the secrets below are mandatory (the app refuses to start without them):
`DB_USER`, `DB_PASSWORD`, `PIN_PEPPER`, `CSRF_SECRET`, `ADMIN_TEMP_PASSWORD`, `ALLOWED_ORIGINS`.
Generate secrets (at least 32 bytes) with:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 4. Run
```bash
uvicorn app:app --host 127.0.0.1 --port 5500 --proxy-headers --reload
```
Open `http://localhost:5500`. On first start the app creates the database, the tables and a super admin (`SUPERADMIN_USERNAME`, password from `ADMIN_TEMP_PASSWORD`). The admin panel is at `/admin`, and the password must be changed at first login.

> If `OFFLINE` stays in the navbar, the WebSocket is being rejected. The most common cause is an `ALLOWED_ORIGINS` value that does not exactly match the address in your browser (scheme, host and port).

---

## Configuration

All settings come from `.env` (see `.env.example` for every variable with comments). Highlights:

| Variable | Purpose |
|---|---|
| `APP_ENV` | `production` enforces strict startup checks; `development` relaxes them |
| `ALLOWED_ORIGINS` | Allowed Origins for HTTP and the WebSocket handshake |
| `RATE_LIMIT_BACKEND` | `memory` (single worker) or `mysql` (required if `WORKERS > 1` in production) |
| `TURNSTILE_ENABLED` | Must be `true` in production |
| `TRUSTED_PROXIES` | Proxies whose `X-Forwarded-For` / `CF-Connecting-IP` are trusted |
| `ADMIN_IP_ALLOWLIST` | Optional CIDR list allowed to reach `/admin` |
| `REVEAL_QUOTA_NEW`, `REVEAL_QUOTA_VERIFIED`, `REVEAL_HOURLY_LIMIT`, `REVEAL_NEWACCOUNT_LIMIT` | Phone-reveal quotas (see below) |

Settings are cached at startup, so restart the server after editing `.env`.

---

## How it works

### Real-time updates
Every write bumps a version in the `change_log` table and the server broadcasts a small `{"t":"change","v":…,"scopes":[…]}` signal over `/ws/realtime`. The WebSocket **never carries sensitive data**, only "something changed" signals. The browser then re-fetches the affected data through the normal API. Each worker also polls `change_log` every second so changes made by other workers reach its clients (no Redis needed).

Client behaviour: automatic reconnect with exponential backoff and jitter, ping every 25 s, refresh of missed changes after a reconnect, and pause while the tab is hidden.

Public scopes: `donors`, `requests`, `stats`, `leaderboard`. Admin scopes (admin channel only): `admin_requests`, `admin_contacts`, `admin_donors`, `admin_reports`.

### Trust score and badges
Computed from scratch on every relevant change (`trust.py`):

```
score = verification-level points (max 80)
      + 2 x min(donation_count, 10)        (max 20)
      + 5 if the donor has no reports
capped at 100
```
Badges: `registered` < 25 <= `bronze` < 50 <= `silver` < 75 <= `gold`. The thresholds are provisional.

### Phone reveal quotas
Guests never see numbers. A logged-in user may reveal a **new** number only within these rolling-window limits (re-viewing a number already revealed is free):

| Limit | Default |
|---|---|
| New numbers per 24 h (no profile or verification level 0) | 5 |
| New numbers per 24 h (verification level >= 1) | 20 |
| New numbers per hour (everyone) | 10 |
| New numbers in the first hour of a new account | 2 |

Every reveal needs a Turnstile check and is written to `phone_reveals`. If more than 3 different accounts reveal numbers from one IP within 24 h, those accounts are flagged for admin review.

### Security notes
- PINs are hashed with a server-side pepper; admin passwords use scrypt.
- Strict CSP with per-request nonce; `HttpOnly` cookies plus CSRF tokens; nothing sensitive in `localStorage`.
- WebSocket handshake checks `Origin` (blocks cross-site WebSocket hijacking).
- Layered rate limiting (edge, application, account lockout); Turnstile fails closed.

---

## API overview

| Area | Endpoints |
|---|---|
| Public | `GET /api/config`, `/api/stats`, `/api/leaderboard`, `/api/map`, `/api/donors/search`, `/api/requests`, `/api/health` |
| Auth | `POST /api/auth/signup`, `/login`, `/logout`, `/google`, `/link-phone`; `GET /api/auth/me` |
| Donors | `POST /api/donors`, `PUT /api/donors/{id}`, `POST /api/donors/{id}/reveal` |
| Requests | `POST /api/requests`, `POST /api/requests/{id}/reveal` |
| Contact / reports | `POST /api/contacts`, `POST /api/{donors\|requests}/{id}/report` |
| Admin | `/admin/api/*`: requests, donors, `POST /donors/{id}/donations`, contacts, reports, users, reveals, audit, admins |
| Real-time | `WS /ws/realtime` |

---

## Deployment notes

- Run behind Nginx or Cloudflare with TLS: `uvicorn app:app --host 127.0.0.1 --port 5500 --workers 2 --proxy-headers`.
- With `WORKERS > 1`, set `RATE_LIMIT_BACKEND=mysql`.
- Nginx must forward WebSocket upgrades for `/ws/realtime`:
  `proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; proxy_read_timeout 75s;` and should limit connections per IP (e.g. `limit_conn`, max 5).
- Add your `wss://` origin to the CSP `connect-src` (the app builds it from `ALLOWED_ORIGINS`).
- `ARCHITECTURE.md` references a systemd unit at `deploy/renewal.service`; that file is not included in this repository snapshot.
- Pin exact dependency versions for production: after a successful run, `pip freeze > requirements.lock` and deploy from the lock file.

---

## Known limitations and incomplete features

These were found by reading the code. They are listed so nobody assumes they work.

### Features that exist but have no effect
| Item | What happens today |
|---|---|
| **`suspicious` donors** | A donor with 3 or more reports gets `suspicious = TRUE`, but search, display and phone reveal ignore it. Only the admin panel shows a badge. |
| **`can_donate` checkbox** | Stored and editable, but search does not filter on it, so donors who untick "ready to donate" still appear. |
| **`flagged` users** | Set by the IP-abuse check, but flagged users face no restriction. It is only a hint for admins. |
| **Badges** (`gold` / `silver` / `bronze`) | Calculated on the server and styled in CSS, but not rendered anywhere in the UI. Only the numeric trust score is shown. Badge thresholds are marked provisional (`TODO(spec)` in `trust.py`). |
| **Availability after a donation** | Recording a donation sets `next_available` (+90 days) but does not change `availability`. The daily job only moves donors back to `available`, never away from it, so a donor who just gave blood still appears "available". |

### Missing functionality
- **No donation history view and no way to delete or correct a recorded donation.** Admins can only add donations, so a mistaken entry cannot be undone without editing the database.
- **Donors cannot record their own donations**; only admins can, so `donation_count` stays `0` until an admin adds entries. Existing counts are never recomputed.
- **Verification history is write-only.** Changes to a donor's verification level are saved in `verification_events`, but nothing displays them.
- **No production SMS provider.** `OTP_ENABLED=true` is rejected in production, so phone numbers stay unverified (this is why the reveal quotas are strict). `SMS_PROVIDER=log` is for development only.
- **No admin tooling for flagged users** beyond clearing the flag.
- **Quota is the same for emergencies.** A new user searching for blood urgently can reveal only 2 numbers in the first hour and 5 per day. Consider a looser quota for verified emergency requests.

### Unused database schema
These columns and tables are created but never written or read:
- `donors.alt_phone`, `donors.emergency_call`, `donors.donation_types`, `donors.contact_prefs`, `donors.lat`, `donors.lng`
- `meta` table

The map works at district level and does not use `lat` / `lng`.

### Dead or leftover code
- `GET /api/auth/check-phone` exists on the backend but the UI never calls it.
- `ADMIN_PASSWORD_HASH` is a legacy fallback for seeding the super admin when `ADMIN_TEMP_PASSWORD` is empty.

### Disabled by configuration (not broken)
- **SMS OTP**: off by default (`OTP_ENABLED=false`).
- **Google Sign-In**: off by default (`GOOGLE_LOGIN_ENABLED=false`); set `GOOGLE_CLIENT_ID` to enable.
- **Admin real-time updates**: the admin panel (`admin.html`) does not yet connect to the WebSocket, so admin lists do not refresh live. Only the public site does.

### Other things to keep in mind
- Dependencies in `requirements.txt` are unpinned; behaviour can change with new releases. Use a lock file for production.
- The project has no automated tests.
- Trust-score points for donations are only meaningful once donations are actually being recorded.

---

## Suggested roadmap

1. Hide or rank down `suspicious` donors; respect `can_donate` in search.
2. After a donation, set `availability` to `soon` automatically.
3. Show badges on donor cards.
4. Donation history with admin-side correction/removal.
5. Admin WebSocket client for live admin lists.
6. Looser reveal quota for verified emergency requests; admin-assisted contact as a fallback when the quota runs out.
7. Remove or implement the unused schema (`lat`/`lng`, `donation_types`, `contact_prefs`, `alt_phone`, `emergency_call`, `meta`).
8. Add tests and a CI pipeline; commit a dependency lock file.

---

## Contributing

Issues and pull requests are welcome. Please keep user-facing text consistent with the existing bilingual (Bengali / English) UI, and never send sensitive data (phone numbers, notes) over the WebSocket.

## License

No license has been specified yet. Add one before publishing.
