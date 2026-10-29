"""CyberWatch news collector.

Fetches public security news feeds and the CISA Known Exploited
Vulnerabilities (KEV) catalog, then saves them as JSON files that the
website reads. No AI and no API key are needed for this step.

Run it locally with:  python collector/collect.py
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import feedparser
import requests

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
NEWS_FILE = DATA_DIR / "news.json"
KEV_FILE = DATA_DIR / "kev.json"

FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "SecurityWeek": "https://feeds.feedburner.com/securityweek",
}
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
MAX_NEWS = 500
MAX_KEV = 300
HEADERS = {"User-Agent": "CyberWatch/0.1 (portfolio project)"}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def clean(text, limit=300):
    """Strip HTML and keep only a short snippet (link back to the source)."""
    text = TAG_RE.sub("", text or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def fetch_kev():
    """Download the CISA KEV catalog. Returns (recent_list, cve_index)."""
    resp = requests.get(KEV_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    index = {
        v["cveID"].upper(): {
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
        }
        for v in vulns
    }
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    recent = [
        {
            "cve": v["cveID"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "dateAdded": v.get("dateAdded", ""),
            "ransomwareUse": v.get("knownRansomwareCampaignUse", ""),
        }
        for v in vulns[:MAX_KEV]
    ]
    return recent, index


def fetch_news():
    """Read every feed. A broken feed is skipped, not fatal."""
    items = []
    for source, url in FEEDS.items():
        try:
            resp = requests.get(url, headers=HEADERS, timeout=30)
            resp.raise_for_status()
            feed = feedparser.parse(resp.content)
        except Exception as err:  # keep going if one source is down
            print(f"  ! {source}: {err}")
            continue
        count = 0
        for entry in feed.entries:
            link = entry.get("link")
            if not link:
                continue
            if entry.get("published_parsed"):
                published = datetime(
                    *entry.published_parsed[:6], tzinfo=timezone.utc
                ).isoformat(timespec="seconds")
            else:
                published = now_iso()
            title = clean(entry.get("title"), 200)
            summary = clean(entry.get("summary"))
            cves = sorted(
                {c.upper() for c in CVE_RE.findall(f"{title} {summary}")}
            )
            items.append(
                {
                    "title": title,
                    "link": link,
                    "source": source,
                    "published": published,
                    "summary": summary,
                    "cves": cves,
                }
            )
            count += 1
        print(f"  + {source}: {count} items")
    return items


def add_software_hints(items, kev_index):
    """If a story mentions a CVE listed in CISA KEV, we know the software."""
    for item in items:
        hints = []
        for cve in item.get("cves", []):
            info = kev_index.get(cve)
            if info:
                label = f"{info['vendor']} {info['product']}".strip()
                if label and label not in hints:
                    hints.append(label)
        item["software_hints"] = hints


def main():
    print("Fetching CISA KEV catalog...")
    try:
        kev_recent, kev_index = fetch_kev()
        save_json(KEV_FILE, {"updated": now_iso(), "items": kev_recent})
        print(f"  + {len(kev_recent)} recent KEV entries")
    except Exception as err:
        print(f"  ! KEV failed: {err}")
        kev_index = {}

    print("Fetching news feeds...")
    fresh = fetch_news()

    existing = load_json(NEWS_FILE, {"items": []}).get("items", [])
    merged = {item["link"]: item for item in existing}
    for item in fresh:
        merged[item["link"]] = item
    items = sorted(merged.values(), key=lambda i: i["published"], reverse=True)
    items = items[:MAX_NEWS]

    add_software_hints(items, kev_index)
    save_json(NEWS_FILE, {"updated": now_iso(), "items": items})
    with_hints = sum(1 for i in items if i["software_hints"])
    print(f"Saved {len(items)} stories ({with_hints} with software hints).")


if __name__ == "__main__":
    main()
