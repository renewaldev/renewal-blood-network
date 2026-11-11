"""SMS প্রেরণ। এখন কোনো প্রোডাকশন provider যুক্ত নেই।

- sms_provider = "none": সব পাঠানো ব্যর্থ (503)। OTP বন্ধ থাকলে এটি ব্যবহৃত হয় না।
- sms_provider = "log":  শুধু ডেভেলপমেন্টে, কোড লগে যায়। config প্রোডাকশনে এটি আটকায়।

প্রোডাকশন provider (যেমন একটি BD SMS gateway) যোগ করতে এই ফাইলে একটি শাখা যোগ করুন।
"""

import logging

from config import get_settings

log = logging.getLogger("sms")


class SmsError(Exception):
    pass


def _mask(phone: str) -> str:
    return phone[:4] + "****" + phone[-2:]


async def send_sms(phone: str, text: str) -> None:
    provider = get_settings().sms_provider
    if provider == "log":
        log.warning("DEV SMS to %s: %s", _mask(phone), text)
        return
    raise SmsError(f"SMS provider '{provider}' কনফিগার করা নেই")
