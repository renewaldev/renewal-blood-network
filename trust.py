"""Trust Score ও ব্যাজ (§১৩)। পুনর্গণনা একই transaction-এ হয়।"""

from db import one, run

# Verification level ≥ N হলে cumulative পয়েন্ট; সর্বোচ্চ 80
_LEVEL_POINTS = {1: 15, 2: 20, 3: 25, 4: 20}


def calc_trust_score(verification_level: int, donation_count: int, report_count: int) -> int:
    points = sum(p for lvl, p in _LEVEL_POINTS.items() if verification_level >= lvl)
    points += min(donation_count, 10) * 2
    if report_count == 0:
        points += 5
    return min(points, 100)


def badge_for(score: int) -> str:
    # TODO(spec): badge নিয়ম §১৩-তে সংজ্ঞায়িত নয়; এই থ্রেশহোল্ড অস্থায়ী।
    if score >= 75:
        return "gold"
    if score >= 50:
        return "silver"
    if score >= 25:
        return "bronze"
    return "registered"


async def recalc(conn, donor_id: str) -> None:
    d = await one(
        conn,
        "SELECT verification_level, donation_count, report_count FROM donors WHERE id = :id FOR UPDATE",
        id=donor_id,
    )
    if not d:
        return
    score = calc_trust_score(d["verification_level"], d["donation_count"], d["report_count"])
    await run(
        conn,
        "UPDATE donors SET trust_score = :s, badge = :b WHERE id = :id",
        s=score,
        b=badge_for(score),
        id=donor_id,
    )
