#!/usr/bin/env python3
import json
import re
import sys
import time
from datetime import datetime, timezone
from typing import Set

import requests

BASE_PAGE = "https://www.coresecurity.com/core-labs/exploits"
JSON_ENDPOINT = "https://www.coresecurity.com/core-labs/exploits/json"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

def extract_cves_from_item(item: dict) -> Set[str]:
    blobs = []
    for k in ("title", "body", "field_cve_link"):
        v = item.get(k)
        if isinstance(v, str) and v:
            blobs.append(v)
    text = " ".join(blobs)
    return {m.group(0).upper() for m in CVE_RE.finditer(text)}

def main() -> int:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "cves-json-updater/1.0 (GitHub Actions)",
            "Accept": "application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": BASE_PAGE,
        }
    )

    all_cves: Set[str] = set()
    pages_fetched = 0

    EMPTY_PAGES_STOP = 5
    HARD_CAP_PAGES = 800  # safety cap
    empty_in_a_row = 0

    for page_idx in range(HARD_CAP_PAGES):
        url = f"{JSON_ENDPOINT}?_format=json&page={page_idx}"
        r = s.get(url, timeout=30)

        if r.status_code == 403:
            print(f"ERROR: 403 Forbidden from Core Security endpoint: {url}", file=sys.stderr)
            print("This runner/IP is blocked. You’ll need an allowed egress or allowlisting.", file=sys.stderr)
            return 2

        r.raise_for_status()

        data = r.json()
        if not isinstance(data, list) or len(data) == 0:
            empty_in_a_row += 1
            if empty_in_a_row >= EMPTY_PAGES_STOP:
                break
            continue

        empty_in_a_row = 0
        pages_fetched += 1

        for item in data:
            if isinstance(item, dict):
                all_cves.update(extract_cves_from_item(item))

        time.sleep(0.15)

    out = {
        "source": BASE_PAGE,
        "json_endpoint": JSON_ENDPOINT,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "pages_fetched": pages_fetched,
        "cve_count": len(all_cves),
        "cves": sorted(all_cves),
    }

    with open("cves.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")

    print(f"Wrote cves.json with {len(all_cves)} CVEs (pages_fetched={pages_fetched})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
