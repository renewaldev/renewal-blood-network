"""ইনপুট যাচাই (§৭ ভ্যালিডেশন নিয়ম)। JSON-এ camelCase, Python-এ snake_case।"""

import json
import re
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

BASE_DIR = Path(__file__).resolve().parent
BLOOD_GROUPS = ("A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-")
AVAILABILITY = ("available", "soon", "unavailable")

BloodGroup = Literal["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]

_BN_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")
_PHONE_RE = re.compile(r"^01[3-9]\d{8}$")
_PIN_RE = re.compile(r"^\d{4}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def normalize_phone(raw: str) -> str:
    """বাংলা অঙ্ক, +880/880 ও ফাঁকা/ড্যাশ সরিয়ে `01XXXXXXXXX` বানায়।"""
    s = raw.translate(_BN_DIGITS)
    s = re.sub(r"[\s\-()]", "", s)
    if s.startswith("+880"):
        s = "0" + s[4:]
    elif s.startswith("880"):
        s = "0" + s[3:]
    if not _PHONE_RE.match(s):
        raise ValueError("ফোন নম্বর সঠিক নয়")
    return s


def clean_text(value: str | None, max_len: int) -> str | None:
    """নিয়ন্ত্রণ-ক্যারেক্টার বাদ, ছাঁটাই, দৈর্ঘ্যসীমা।"""
    if value is None:
        return None
    v = _CONTROL_RE.sub("", value).strip()
    if len(v) > max_len:
        raise ValueError(f"সর্বোচ্চ {max_len} অক্ষর")
    return v or None


@lru_cache(maxsize=1)
def geo() -> dict[str, frozenset[str]]:
    """static/data/bd-geo.json — ফরম্যাট: {"জেলা": ["উপজেলা", ...]}। স্টার্টআপে লোড হয়।"""
    path = BASE_DIR / "static" / "data" / "bd-geo.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return {district: frozenset(upazilas) for district, upazilas in data.items()}


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


class PhoneAuthIn(_Base):
    phone: str
    pin: str
    turnstile_token: str | None = Field(default=None, max_length=2048)
    otp_code: str | None = Field(default=None, max_length=8)  # OTP_ENABLED=true হলে লাগবে

    @field_validator("phone", mode="before")
    @classmethod
    def _phone(cls, v) -> str:
        return normalize_phone(str(v))

    @field_validator("pin")
    @classmethod
    def _pin(cls, v: str) -> str:
        if not _PIN_RE.match(v):
            raise ValueError("PIN ঠিক ৪টি অঙ্কের হতে হবে")
        return v


class DonorIn(_Base):
    name: str = Field(min_length=1, max_length=120)
    name_en: str | None = Field(default=None, max_length=120)
    blood_group: BloodGroup
    district: str = Field(min_length=1, max_length=64)
    upazila: str = Field(min_length=1, max_length=64)
    area: str | None = Field(default=None, max_length=120)
    age: int = Field(ge=18, le=60)
    gender: Literal["male", "female", "other"] | None = None
    profession: str | None = Field(default=None, max_length=120)
    phone_visibility: Literal["members", "admin_only"] = "members"
    turnstile_token: str | None = Field(default=None, max_length=2048)

    @field_validator("name", "name_en", "area", "profession")
    @classmethod
    def _clean(cls, v: str | None) -> str | None:
        return clean_text(v, 120)

    @model_validator(mode="after")
    def _geo(self):
        if not self.name:
            raise ValueError("নাম দিন")
        upazilas = geo().get(self.district)
        if upazilas is None:
            raise ValueError("জেলা সঠিক নয়")
        if self.upazila not in upazilas:
            raise ValueError("উপজেলা সঠিক নয়")
        return self


class RequestIn(_Base):
    patient_name: str = Field(min_length=1, max_length=120)
    blood_group: BloodGroup
    units: int = Field(default=1, ge=1, le=10)
    hospital: str = Field(min_length=1, max_length=160)
    district: str = Field(min_length=1, max_length=64)
    upazila: str | None = Field(default=None, max_length=64)
    needed_at: datetime  # naive হলে UTC ধরা হয়
    attendant_name: str = Field(min_length=1, max_length=120)
    contact: str
    reason: str | None = Field(default=None, max_length=500)
    turnstile_token: str | None = Field(default=None, max_length=2048)

    @field_validator("contact", mode="before")
    @classmethod
    def _contact(cls, v) -> str:
        return normalize_phone(str(v))

    @field_validator("patient_name", "hospital", "attendant_name", "reason")
    @classmethod
    def _clean(cls, v: str | None) -> str | None:
        return clean_text(v, 500)

    @model_validator(mode="after")
    def _rules(self):
        if self.district not in geo():
            raise ValueError("জেলা সঠিক নয়")
        if self.upazila and self.upazila not in geo()[self.district]:
            raise ValueError("উপজেলা সঠিক নয়")
        now = datetime.now(timezone.utc)
        needed = self.needed_at if self.needed_at.tzinfo else self.needed_at.replace(tzinfo=timezone.utc)
        if needed <= now or needed > now + timedelta(days=7):
            raise ValueError("প্রয়োজনের সময় আজ থেকে ৭ দিনের মধ্যে হতে হবে")
        self.needed_at = needed.astimezone(timezone.utc).replace(tzinfo=None)
        return self


class RevealIn(_Base):
    turnstile_token: str | None = Field(default=None, max_length=2048)


class AdminLoginIn(_Base):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    turnstile_token: str | None = Field(default=None, max_length=2048)


class ChangePasswordIn(_Base):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=128)


class AdminCreateIn(_Base):
    username: str = Field(min_length=3, max_length=64)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        from passwords import ADMIN_USERNAME_RE, normalize_username

        v = normalize_username(v)
        if not ADMIN_USERNAME_RE.match(v):
            raise ValueError("ইউজারনেম/ইমেইল: ৩–৬৪ অক্ষর; ইংরেজি ছোট অক্ষর, সংখ্যা ও . _ @ + - চলবে")
        return v


class RequestUpdateIn(_Base):
    status: Literal["verified", "rejected", "fulfilled"]
    note: str | None = Field(default=None, max_length=500)

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        return clean_text(v, 500)


class OtpRequestIn(_Base):
    phone: str
    purpose: Literal["signup", "login", "link"]
    turnstile_token: str | None = Field(default=None, max_length=2048)

    @field_validator("phone", mode="before")
    @classmethod
    def _phone(cls, v) -> str:
        return normalize_phone(str(v))


class GoogleIn(_Base):
    credential: str = Field(min_length=1, max_length=4096)


class ReportIn(_Base):
    reason: str | None = Field(default=None, max_length=255)
    turnstile_token: str | None = Field(default=None, max_length=2048)

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str | None) -> str | None:
        return clean_text(v, 255)


class ContactIn(_Base):
    donor_id: str = Field(min_length=32, max_length=32)
    patient: str = Field(min_length=1, max_length=120)
    blood_group: BloodGroup
    hospital: str = Field(min_length=1, max_length=160)
    units: int = Field(default=1, ge=1, le=10)
    phone: str
    turnstile_token: str | None = Field(default=None, max_length=2048)

    @field_validator("phone", mode="before")
    @classmethod
    def _phone(cls, v) -> str:
        return normalize_phone(str(v))

    @field_validator("patient", "hospital")
    @classmethod
    def _clean(cls, v: str | None) -> str | None:
        return clean_text(v, 160)


class DonorUpdateIn(_Base):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    name_en: str | None = Field(default=None, max_length=120)
    area: str | None = Field(default=None, max_length=120)
    profession: str | None = Field(default=None, max_length=120)
    phone_visibility: Literal["members", "admin_only"] | None = None
    availability: Literal["available", "soon", "unavailable"] | None = None
    can_donate: bool | None = None
    next_available: date | None = None
    last_donation: date | None = None
    district: str | None = Field(default=None, max_length=64)
    upazila: str | None = Field(default=None, max_length=64)

    @field_validator("name", "name_en", "area", "profession")
    @classmethod
    def _clean(cls, v: str | None) -> str | None:
        return clean_text(v, 120) if v is not None else None

    @model_validator(mode="after")
    def _geo(self):
        if (self.district is None) != (self.upazila is None):
            raise ValueError("জেলা ও উপজেলা একসাথে দিন")
        if self.district is not None:
            upazilas = geo().get(self.district)
            if upazilas is None or self.upazila not in upazilas:
                raise ValueError("জেলা বা উপজেলা সঠিক নয়")
        return self


class AdminDonorUpdateIn(_Base):
    verification_level: int | None = Field(default=None, ge=0, le=4)
    suspicious: bool | None = None
    can_donate: bool | None = None


class AdminDonationIn(_Base):
    """অ্যাডমিন যাচাই করে একটি রক্তদান নথিভুক্ত করে।"""

    donated_at: date
    place: str | None = Field(default=None, max_length=160)
    note: str | None = Field(default=None, max_length=255)

    @field_validator("donated_at")
    @classmethod
    def _date_range(cls, v: date) -> date:
        # টাইমজোন ফারাক সামলাতে আগামীকাল পর্যন্ত সহনীয়
        if v > datetime.now(timezone.utc).date() + timedelta(days=1):
            raise ValueError("ভবিষ্যতের তারিখ দেওয়া যাবে না")
        if v < date(1970, 1, 1):
            raise ValueError("তারিখ সঠিক নয়")
        return v

    @field_validator("place")
    @classmethod
    def _place(cls, v: str | None) -> str | None:
        return clean_text(v, 160)

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        return clean_text(v, 255)


class AdminContactUpdateIn(_Base):
    status: Literal["pending", "contacted", "done", "rejected"]


class AdminUserUpdateIn(_Base):
    status: Literal["active", "blocked"] | None = None
    flagged: bool | None = None  # শুধু False (সাফ করা) অনুমোদিত