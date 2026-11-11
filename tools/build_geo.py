"""bd-districts.json + bd-upazilas.json → static/data/bd-geo.json

ফরম্যাট (schemas.geo() আশা করে):
    { "Dhaka": ["Dhamrai", "Dohar", ...], "Chattogram": [...], ... }

Key ও মান ইংরেজি নাম (canonical value; DB-তে এটিই সংরক্ষিত হয়)।
বাংলা নাম চাইলে --lang bn দিন।

ব্যবহার:
    python tools/build_geo.py --src /path/to/uploads --out static/data/bd-geo.json
"""

import argparse
import json
from pathlib import Path


def load(path: Path, key: str) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))[key]


def build(src: Path, lang: str) -> dict[str, list[str]]:
    name_key = "bn_name" if lang == "bn" else "name"
    districts = load(src / "bd-districts.json", "districts")
    upazilas = load(src / "bd-upazilas.json", "upazilas")

    by_id = {d["id"]: d[name_key].strip() for d in districts}
    geo: dict[str, list[str]] = {name: [] for name in by_id.values()}

    for u in upazilas:
        district = by_id.get(u["district_id"])
        if district is None:
            raise SystemExit(f"অজানা district_id={u['district_id']} (upazila {u['name']})")
        name = u[name_key].strip()
        # উৎস ফাইলে একই জেলায় একই উপজেলা একাধিকবার আছে (ভিন্ন id) — প্রথমটি রাখা হয়
        if name in geo[district]:
            print(f"সতর্কতা: {district} → '{name}' (id={u['id']}) ডুপ্লিকেট, বাদ দেওয়া হলো")
            continue
        geo[district].append(name)

    return dict(sorted(geo.items()))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", type=Path, default=Path("/mnt/user-data/uploads"))
    parser.add_argument("--out", type=Path, default=Path("static/data/bd-geo.json"))
    parser.add_argument("--lang", choices=["en", "bn"], default="en")
    args = parser.parse_args()

    geo = build(args.src, args.lang)

    # যাচাই: ৬৪ জেলা, ৪৯৪ উৎস-রেকর্ড থেকে ২ ডুপ্লিকেট বাদে ৪৯২ উপজেলা, কোনো খালি জেলা নেই
    total = sum(len(v) for v in geo.values())
    assert len(geo) == 64, f"জেলা সংখ্যা {len(geo)}, প্রত্যাশা 64"
    assert total == 492, f"অনন্য উপজেলা সংখ্যা {total}, প্রত্যাশা 492 (494 - ২ ডুপ্লিকেট)"
    empty = [d for d, v in geo.items() if not v]
    assert not empty, f"উপজেলা নেই: {empty}"

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(geo, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"লেখা হয়েছে: {args.out} — {len(geo)} জেলা, {total} অনন্য উপজেলা")


if __name__ == "__main__":
    main()
