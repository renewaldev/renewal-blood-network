"""কনফিগারেশন: .env থেকে লোড ও প্রোডাকশন স্টার্টআপ যাচাই (§১৪)।"""

import ipaddress
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from passwords import ADMIN_USERNAME_RE, MIN_PASSWORD_LEN, MAX_PASSWORD_LEN, normalize_username


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "production"

    db_host: str = "127.0.0.1"
    db_port: int = 3306
    db_user: str = ""
    db_password: str = ""
    db_name: str = "renewal_blood"
    db_pool_size: int = 10

    pin_pepper: str = ""
    csrf_secret: str = ""
    admin_password_hash: str = ""  # ঐচ্ছিক/পুরনো: সুপারঅ্যাডমিন সিডে ADMIN_TEMP_PASSWORD না থাকলে ব্যবহার হয়
    admin_temp_password: str = ""  # সুপারঅ্যাডমিনের প্রাথমিক ও নতুন অ্যাডমিনের অস্থায়ী পাসওয়ার্ড (প্রথম লগইনে বদলাতে হয়)
    superadmin_username: str = "superadmin"
    hash_concurrency: int = 2  # একসাথে সর্বোচ্চ scrypt (প্রতি প্রসেসে; প্রতিটি ~১৬ MB)
    admin_ip_allowlist: str = ""

    turnstile_enabled: bool = True
    turnstile_site_key: str = ""
    turnstile_secret_key: str = ""

    google_login_enabled: bool = False
    google_client_id: str = ""

    otp_enabled: bool = False  # SMS OTP; এখন বন্ধ (D11)
    sms_provider: str = "none"  # none | log (শুধু ডেভ). প্রোডাকশন provider এখনো যুক্ত নেই

    trusted_proxies: str = "127.0.0.1/32"
    rate_limit_backend: str = "memory"  # memory | mysql  (redis: ভবিষ্যৎ)
    session_ttl_days: int = 30
    admin_session_ttl_hours: int = 8
    cookie_secure: bool = True
    allowed_origins: str = ""

    reveal_quota_new: int = 5
    reveal_quota_verified: int = 20
    reveal_hourly_limit: int = 10
    reveal_newaccount_limit: int = 2

    host: str = "0.0.0.0"
    port: int = 5500
    workers: int = 2

    @property
    def is_prod(self) -> bool:
        return self.app_env == "production"

    @property
    def origins(self) -> set[str]:
        return {o.strip().rstrip("/") for o in self.allowed_origins.split(",") if o.strip()}

    @property
    def trusted_networks(self) -> list:
        return [ipaddress.ip_network(n.strip(), strict=False) for n in self.trusted_proxies.split(",") if n.strip()]

    @property
    def admin_networks(self) -> list:
        return [ipaddress.ip_network(n.strip(), strict=False) for n in self.admin_ip_allowlist.split(",") if n.strip()]

    @property
    def superadmin_login(self) -> str:
        return normalize_username(self.superadmin_username)

    @model_validator(mode="after")
    def _check(self):
        if not 1 <= self.hash_concurrency <= 8:
            raise ValueError("HASH_CONCURRENCY: ১ থেকে ৮ হতে হবে")
        if not ADMIN_USERNAME_RE.match(self.superadmin_login):
            raise ValueError("SUPERADMIN_USERNAME: ৩–৬৪ অক্ষর; ইংরেজি ছোট অক্ষর, সংখ্যা ও . _ @ + - চলবে")
        if self.admin_temp_password and not (MIN_PASSWORD_LEN <= len(self.admin_temp_password) <= MAX_PASSWORD_LEN):
            raise ValueError(f"ADMIN_TEMP_PASSWORD: {MIN_PASSWORD_LEN}–{MAX_PASSWORD_LEN} অক্ষর হতে হবে")
        if self.rate_limit_backend not in ("memory", "mysql"):
            raise ValueError("RATE_LIMIT_BACKEND: memory বা mysql হতে হবে")
        if self.sms_provider not in ("none", "log"):
            raise ValueError("SMS_PROVIDER: অজানা provider")
        if not self.is_prod:
            return self
        required = {
            "DB_USER": self.db_user,
            "DB_PASSWORD": self.db_password,
            "PIN_PEPPER": self.pin_pepper,
            "CSRF_SECRET": self.csrf_secret,
            "ADMIN_TEMP_PASSWORD": self.admin_temp_password,
            "ALLOWED_ORIGINS": self.allowed_origins,
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            raise ValueError(f"প্রোডাকশনে অনুপস্থিত: {', '.join(missing)}")
        if len(self.pin_pepper.encode()) < 32 or len(self.csrf_secret.encode()) < 32:
            raise ValueError("PIN_PEPPER ও CSRF_SECRET অন্তত ৩২ বাইট হতে হবে")
        if self.workers > 1 and self.rate_limit_backend == "memory":
            raise ValueError("WORKERS > 1 হলে RATE_LIMIT_BACKEND=mysql লাগবে")
        if not self.turnstile_enabled:
            raise ValueError("প্রোডাকশনে TURNSTILE_ENABLED=false সম্ভব নয়")
        if self.otp_enabled and self.sms_provider in ("none", "log"):
            raise ValueError("OTP চালু করতে প্রোডাকশন SMS provider লাগবে (এখনো যুক্ত হয়নি)")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
