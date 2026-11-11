"""Async MySQL engine, ছোট helper (D4), এবং স্কিমা স্বয়ংক্রিয় তৈরি।

সব SQL parameterized; ORM নেই। স্কিমা এই ফাইলে এম্বেড করা; `ensure_schema()`
স্টার্টআপে ডাটাবেস ও টেবিল না থাকলে তৈরি করে। সব স্টেটমেন্ট IF NOT EXISTS,
তাই বারবার চালালে ক্ষতি হয় না।
"""

import logging
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import quote_plus

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from config import get_settings
from passwords import make_hash

log = logging.getLogger("db")

_engine: AsyncEngine | None = None
_DB_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_SCHEMA_LOCK = "renewal_blood_schema_init"


def utcnow() -> datetime:
    """DB-তে সব টাইমস্ট্যাম্প UTC naive হিসেবে সংরক্ষিত।"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _credentials() -> str:
    s = get_settings()
    return f"{quote_plus(s.db_user)}:{quote_plus(s.db_password)}@{s.db_host}:{s.db_port}"


def engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        s = get_settings()
        url = f"mysql+asyncmy://{_credentials()}/{s.db_name}?charset=utf8mb4"
        _engine = create_async_engine(
            url,
            pool_size=s.db_pool_size,
            max_overflow=5,
            pool_pre_ping=True,
            pool_recycle=1800,
            # DEFAULT CURRENT_TIMESTAMP ও NOW() সেশন টাইমজোনে লেখে; অ্যাপ সব তুলনা utcnow() দিয়ে করে।
            # তাই প্রতিটি সংযোগে UTC বাধ্য করা হয় (নইলে লকআউট/কোটা উইন্ডো সার্ভার-অফসেট পরিমাণ সরে যায়)।
            connect_args={"init_command": "SET time_zone = '+00:00'"},
        )
    return _engine


async def dispose() -> None:
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None


async def one(conn: AsyncConnection, sql: str, **params) -> dict | None:
    row = (await conn.execute(text(sql), params)).mappings().first()
    return dict(row) if row else None


async def many(conn: AsyncConnection, sql: str, **params) -> list[dict]:
    return [dict(r) for r in (await conn.execute(text(sql), params)).mappings().all()]


async def run(conn: AsyncConnection, sql: str, **params):
    """INSERT/UPDATE/DELETE। ফলাফল (rowcount, lastrowid) সহ ফেরত।"""
    return await conn.execute(text(sql), params)


async def read_one(sql: str, **params) -> dict | None:
    async with engine().connect() as conn:
        return await one(conn, sql, **params)


async def read_many(sql: str, **params) -> list[dict]:
    async with engine().connect() as conn:
        return await many(conn, sql, **params)


async def bump_version(conn: AsyncConnection, scopes: list[str]) -> int:
    """change_log-এ সারি যোগ করে নতুন version ফেরত (§৯)। একই transaction-এ থাকতে হবে।"""
    result = await run(conn, "INSERT INTO change_log (scopes) VALUES (:s)", s=",".join(scopes))
    return int(result.lastrowid)


# ───────────── Schema (embedded) ─────────────
# মূল উৎস: ARCHITECTURE.md §১২। এখানে SQL কমেন্ট বাদ দেওয়া হয়েছে, কারণ কমেন্টে ':'
# থাকলে SQLAlchemy সেটিকে bind parameter ভাবতে পারে। স্কিমা বদলালে এই তালিকাও বদলান।
SCHEMA_STATEMENTS: list[str] = [
    # ───── Identity ─────
    """CREATE TABLE IF NOT EXISTS users (
      id            CHAR(32)      NOT NULL PRIMARY KEY,
      phone         VARCHAR(16)   NULL UNIQUE,
      email         VARCHAR(255)  NULL,
      pin_hash      VARBINARY(64) NULL,
      pin_salt      VARBINARY(32) NULL,
      status        ENUM('active','blocked') NOT NULL DEFAULT 'active',
      flagged       BOOLEAN       NOT NULL DEFAULT FALSE,
      created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_login_at DATETIME      NULL,
      INDEX idx_users_email (email)
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS oauth_accounts (
      id               CHAR(32)     NOT NULL PRIMARY KEY,
      user_id          CHAR(32)     NOT NULL,
      provider         VARCHAR(32)  NOT NULL,
      provider_user_id VARCHAR(128) NOT NULL,
      email            VARCHAR(255) NULL,
      name             VARCHAR(255) NULL,
      picture          VARCHAR(512) NULL,
      created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_provider_user (provider, provider_user_id),
      INDEX idx_oauth_user (user_id),
      CONSTRAINT fk_oauth_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS sessions (
      token_hash CHAR(64)     NOT NULL PRIMARY KEY,
      user_id    CHAR(32)     NOT NULL,
      ip         VARBINARY(16) NULL,
      user_agent VARCHAR(255) NULL,
      expires_at DATETIME     NOT NULL,
      created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_sessions_user (user_id),
      INDEX idx_sessions_exp (expires_at),
      CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS admins (
      id                   CHAR(32)     NOT NULL PRIMARY KEY,
      username             VARCHAR(64)  NOT NULL,
      password_hash        VARCHAR(255) NOT NULL,
      role                 ENUM('superadmin','admin') NOT NULL DEFAULT 'admin',
      must_change_password BOOLEAN      NOT NULL DEFAULT TRUE,
      created_by           CHAR(32)     NULL,
      created_at           DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_login_at        DATETIME     NULL,
      UNIQUE KEY uk_admins_username (username)
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS admin_sessions (
      token_hash CHAR(64)      NOT NULL PRIMARY KEY,
      admin_id   CHAR(32)      NOT NULL,
      ip         VARBINARY(16) NULL,
      expires_at DATETIME      NOT NULL,
      created_at DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_admin_sessions_exp (expires_at),
      INDEX idx_admin_sessions_admin (admin_id),
      CONSTRAINT fk_admin_sessions_admin FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
    ) ENGINE=InnoDB""",
    # ───── Core domain ─────
    """CREATE TABLE IF NOT EXISTS donors (
      id                 CHAR(32)     NOT NULL PRIMARY KEY,
      user_id            CHAR(32)     NULL UNIQUE,
      name               VARCHAR(120) NOT NULL,
      name_en            VARCHAR(120) NULL,
      phone              VARCHAR(16)  NOT NULL UNIQUE,
      alt_phone          VARCHAR(16)  NULL,
      phone_visibility   ENUM('members','admin_only') NOT NULL DEFAULT 'members',
      blood_group        ENUM('A+','A-','B+','B-','AB+','AB-','O+','O-') NOT NULL,
      district           VARCHAR(64)  NOT NULL,
      upazila            VARCHAR(64)  NOT NULL,
      area               VARCHAR(120) NULL,
      age                TINYINT UNSIGNED NULL,
      gender             ENUM('male','female','other') NULL,
      profession         VARCHAR(120) NULL,
      last_donation      DATE         NULL,
      next_available     DATE         NULL,
      donation_count     SMALLINT UNSIGNED NOT NULL DEFAULT 0,
      can_donate         BOOLEAN      NOT NULL DEFAULT TRUE,
      availability       ENUM('available','soon','unavailable') NOT NULL DEFAULT 'available',
      emergency_call     BOOLEAN      NOT NULL DEFAULT FALSE,
      donation_types     JSON         NULL,
      contact_prefs      JSON         NULL,
      verification_level TINYINT UNSIGNED NOT NULL DEFAULT 0,
      trust_score        TINYINT UNSIGNED NOT NULL DEFAULT 0,
      badge              VARCHAR(32)  NOT NULL DEFAULT 'registered',
      suspicious         BOOLEAN      NOT NULL DEFAULT FALSE,
      report_count       INT UNSIGNED NOT NULL DEFAULT 0,
      lat                DECIMAL(9,6) NULL,
      lng                DECIMAL(9,6) NULL,
      created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT chk_donor_level CHECK (verification_level <= 4),
      CONSTRAINT chk_donor_trust CHECK (trust_score <= 100),
      INDEX idx_donors_search (blood_group, district, upazila, availability),
      INDEX idx_donors_trust (trust_score),
      INDEX idx_donors_flags (suspicious, report_count),
      CONSTRAINT fk_donors_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS donations (
      id         CHAR(32)     NOT NULL PRIMARY KEY,
      donor_id   CHAR(32)     NOT NULL,
      donated_at DATE         NOT NULL,
      place      VARCHAR(160) NULL,
      note       VARCHAR(255) NULL,
      created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_donations_donor (donor_id, donated_at),
      CONSTRAINT fk_donations_donor FOREIGN KEY (donor_id) REFERENCES donors(id) ON DELETE CASCADE
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS verification_events (
      id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      donor_id   CHAR(32)     NOT NULL,
      old_level  TINYINT UNSIGNED NOT NULL,
      new_level  TINYINT UNSIGNED NOT NULL,
      note       VARCHAR(255) NULL,
      created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_verif_donor (donor_id, created_at),
      CONSTRAINT fk_verif_donor FOREIGN KEY (donor_id) REFERENCES donors(id) ON DELETE CASCADE
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS blood_requests (
      id                CHAR(32)     NOT NULL PRIMARY KEY,
      user_id           CHAR(32)     NULL,
      patient_name      VARCHAR(120) NOT NULL,
      blood_group       ENUM('A+','A-','B+','B-','AB+','AB-','O+','O-') NOT NULL,
      units             TINYINT UNSIGNED NOT NULL DEFAULT 1,
      hospital          VARCHAR(160) NOT NULL,
      district          VARCHAR(64)  NOT NULL,
      upazila           VARCHAR(64)  NULL,
      needed_at         DATETIME     NOT NULL,
      attendant_name    VARCHAR(120) NOT NULL,
      contact           VARCHAR(16)  NOT NULL,
      reason            VARCHAR(500) NULL,
      status            ENUM('pending','verified','rejected','fulfilled','expired') NOT NULL DEFAULT 'pending',
      verification_note VARCHAR(500) NULL,
      report_count      INT UNSIGNED NOT NULL DEFAULT 0,
      submitted_ip      VARBINARY(16) NULL,
      submitted_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      verified_at       DATETIME     NULL,
      CONSTRAINT chk_req_units CHECK (units BETWEEN 1 AND 10),
      INDEX idx_requests_status_time (status, submitted_at),
      INDEX idx_requests_match (blood_group, district, status),
      INDEX idx_requests_needed (needed_at),
      CONSTRAINT fk_requests_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS contact_requests (
      id           CHAR(32)     NOT NULL PRIMARY KEY,
      user_id      CHAR(32)     NULL,
      donor_id     CHAR(32)     NOT NULL,
      patient      VARCHAR(120) NOT NULL,
      blood_group  ENUM('A+','A-','B+','B-','AB+','AB-','O+','O-') NOT NULL,
      hospital     VARCHAR(160) NOT NULL,
      units        TINYINT UNSIGNED NOT NULL DEFAULT 1,
      phone        VARCHAR(16)  NOT NULL,
      status       ENUM('pending','contacted','done','rejected') NOT NULL DEFAULT 'pending',
      submitted_ip VARBINARY(16) NULL,
      submitted_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_contact_status (status, submitted_at),
      INDEX idx_contact_donor (donor_id, submitted_at),
      CONSTRAINT fk_contact_user  FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE SET NULL,
      CONSTRAINT fk_contact_donor FOREIGN KEY (donor_id) REFERENCES donors(id) ON DELETE CASCADE
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS reports (
      id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      target_type  ENUM('donor','request') NOT NULL,
      target_id    CHAR(32)     NOT NULL,
      reporter_key CHAR(64)     NOT NULL,
      reason       VARCHAR(255) NULL,
      created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_report_once (target_type, target_id, reporter_key),
      INDEX idx_reports_target (target_type, target_id)
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS phone_reveals (
      id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      user_id     CHAR(32)     NOT NULL,
      target_type ENUM('donor','request') NOT NULL,
      target_id   CHAR(32)     NOT NULL,
      ip          VARBINARY(16) NULL,
      created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_reveal_once (user_id, target_type, target_id),
      INDEX idx_reveal_user_time (user_id, created_at),
      INDEX idx_reveal_ip_time (ip, created_at),
      INDEX idx_reveal_target (target_type, target_id, created_at),
      CONSTRAINT fk_reveal_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB""",
    # ───── Security & abuse ─────
    """CREATE TABLE IF NOT EXISTS login_attempts (
      id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      scope      ENUM('user','admin') NOT NULL,
      subject    VARCHAR(64)  NOT NULL,
      ip         VARBINARY(16) NULL,
      success    BOOLEAN      NOT NULL,
      created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_attempts_subject (scope, subject, created_at),
      INDEX idx_attempts_ip (scope, ip, created_at)
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS rate_limit_hits (
      bucket_key   VARCHAR(160) NOT NULL,
      window_start INT UNSIGNED NOT NULL,
      hits         INT UNSIGNED NOT NULL DEFAULT 1,
      PRIMARY KEY (bucket_key, window_start),
      INDEX idx_rlh_window (window_start)
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS audit_log (
      id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      actor       VARCHAR(64)  NOT NULL DEFAULT 'admin',
      action      VARCHAR(64)  NOT NULL,
      target_type VARCHAR(32)  NULL,
      target_id   CHAR(32)     NULL,
      detail      JSON         NULL,
      ip          VARBINARY(16) NULL,
      created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_audit_time (created_at),
      INDEX idx_audit_target (target_type, target_id)
    ) ENGINE=InnoDB""",
    # ───── Real-time & misc ─────
    """CREATE TABLE IF NOT EXISTS change_log (
      version    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      scopes     VARCHAR(128) NOT NULL,
      created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_change_time (created_at)
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS meta (
      mkey       VARCHAR(64) NOT NULL PRIMARY KEY,
      mval       VARCHAR(255) NULL,
      updated_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS otp_codes (
      phone      VARCHAR(16) NOT NULL,
      purpose    ENUM('signup','login','link') NOT NULL,
      code_hash  CHAR(64)    NOT NULL,
      attempts   TINYINT UNSIGNED NOT NULL DEFAULT 0,
      expires_at DATETIME    NOT NULL,
      created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (phone, purpose),
      INDEX idx_otp_exp (expires_at)
    ) ENGINE=InnoDB""",
    "INSERT IGNORE INTO meta (mkey, mval) VALUES ('schema_version', '1')",
]


async def _create_database_if_missing() -> None:
    """ডাটাবেস না থাকলে তৈরি। DB নাম প্যারামিটার হিসেবে যায় না, তাই কড়া regex যাচাই।"""
    s = get_settings()
    if not _DB_NAME_RE.match(s.db_name):
        raise RuntimeError(f"DB_NAME অবৈধ: {s.db_name!r} (শুধু ইংরেজি অক্ষর, সংখ্যা, _)")
    # ডাটাবেস নির্দিষ্ট না করে সার্ভারে সংযোগ
    server = create_async_engine(f"mysql+asyncmy://{_credentials()}/?charset=utf8mb4")
    try:
        async with server.connect() as conn:
            await conn.execute(
                text(
                    f"CREATE DATABASE IF NOT EXISTS `{s.db_name}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
            )
            await conn.commit()
    finally:
        await server.dispose()


async def _column_info(conn, table: str, column: str):
    return (
        await conn.execute(
            text(
                """SELECT CHARACTER_MAXIMUM_LENGTH AS len FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c"""
            ),
            {"t": table, "c": column},
        )
    ).mappings().first()


async def _migrate(conn) -> None:
    """পুরনো ডাটাবেস (একক-অ্যাডমিন) থেকে মাল্টি-অ্যাডমিনে আপগ্রেড। বারবার চালালে ক্ষতি নেই।"""
    # ১) admin_sessions.admin_id — পুরনো সেশন কোনো অ্যাডমিনের নয়, তাই মুছে (মেয়াদ মাত্র ৮ ঘণ্টা)
    if not await _column_info(conn, "admin_sessions", "admin_id"):
        await conn.execute(text("DELETE FROM admin_sessions"))
        await conn.execute(text("ALTER TABLE admin_sessions ADD COLUMN admin_id CHAR(32) NOT NULL AFTER token_hash"))
        await conn.execute(text("ALTER TABLE admin_sessions ADD INDEX idx_admin_sessions_admin (admin_id)"))
        await conn.execute(
            text(
                """ALTER TABLE admin_sessions ADD CONSTRAINT fk_admin_sessions_admin
                   FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE"""
            )
        )
        log.info("migrated: admin_sessions.admin_id")
    # ২) audit_log.actor এখন ইউজারনেম (৬৪ অক্ষর পর্যন্ত)
    col = await _column_info(conn, "audit_log", "actor")
    if col and (col["len"] or 0) < 64:
        await conn.execute(text("ALTER TABLE audit_log MODIFY actor VARCHAR(64) NOT NULL DEFAULT 'admin'"))
        log.info("migrated: audit_log.actor VARCHAR(64)")


async def _seed_superadmin(conn) -> None:
    """admins টেবিল খালি থাকলে একজন সুপারঅ্যাডমিন তৈরি। প্রাথমিক পাসওয়ার্ড .env থেকে (হ্যাশ হয়ে DB-তে যায়)।"""
    count = (await conn.execute(text("SELECT COUNT(*) FROM admins"))).scalar()
    if count:
        return
    s = get_settings()
    if s.admin_temp_password:
        pw_hash = make_hash(s.admin_temp_password)
    elif s.admin_password_hash:
        pw_hash = s.admin_password_hash
    else:
        log.warning("কোনো অ্যাডমিন নেই এবং ADMIN_TEMP_PASSWORD সেট নেই — অ্যাডমিন লগইন সম্ভব নয়")
        return
    await conn.execute(
        text(
            """INSERT IGNORE INTO admins (id, username, password_hash, role, must_change_password)
               VALUES (:id, :u, :h, 'superadmin', TRUE)"""
        ),
        {"id": uuid.uuid4().hex, "u": s.superadmin_login, "h": pw_hash},
    )
    log.info("সুপারঅ্যাডমিন '%s' তৈরি হয়েছে (প্রথম লগইনে পাসওয়ার্ড বদলাতে হবে)", s.superadmin_login)


async def ensure_schema() -> None:
    """স্টার্টআপে চালানো: ডাটাবেস ও সব টেবিল নিশ্চিত করে।

    একাধিক worker একসাথে শুরু হলে GET_LOCK দিয়ে একজনই কাজটি করে; বাকিরা অপেক্ষা করে।
    """
    await _create_database_if_missing()

    async with engine().connect() as conn:
        got = (await conn.execute(text("SELECT GET_LOCK(:name, 60)"), {"name": _SCHEMA_LOCK})).scalar()
        if got != 1:
            raise RuntimeError("স্কিমা লক পাওয়া যায়নি (অন্য প্রক্রিয়া আটকে আছে?)")
        try:
            for stmt in SCHEMA_STATEMENTS:
                await conn.execute(text(stmt))
            await _migrate(conn)
            await _seed_superadmin(conn)
            await conn.commit()
            log.info("schema ensured (%d statements)", len(SCHEMA_STATEMENTS))
        finally:
            await conn.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": _SCHEMA_LOCK})
            await conn.commit()