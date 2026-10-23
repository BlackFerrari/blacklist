"""Threat Intelligence Feed Synchronizer for Blacklist IP Manager.

Fetches all active threat intel feed URLs (defined in feeds.json),
parses and validates all IP addresses, and updates blacklist.txt so that:
- All IPs present in active threat intel feeds are included in blacklist.txt.
- Any IP not present in any integrated threat intel feed is removed.
"""

from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

DIRECTORY = Path(__file__).resolve().parent
FEEDS_FILE = DIRECTORY / "feeds.json"
BLACKLIST_FILE = DIRECTORY / "blacklist.txt"
USER_IPS_FILE = DIRECTORY / "user-ips.json"
DATES_FILE = DIRECTORY / "blacklist-dates.json"

IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def is_valid_ip(val: str) -> bool:
    if not val or len(val) > 45 or any(c.isspace() for c in val):
        return False
    if "." in val and IPV4_PATTERN.match(val):
        return True
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def fetch_and_parse_feed(url: str, timeout: int = 45) -> set:
    """Fetches a threat intel feed URL and extracts all valid IP addresses."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatIntelSync/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as res:
        data = res.read().decode("utf-8", errors="ignore")

    found_ips = set()
    for raw_line in data.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
            continue
        # Split on whitespace, tab, or comma
        token = re.split(r"[\s,;\t]+", line)[0].strip()
        if is_valid_ip(token):
            found_ips.add(token)

    return found_ips


def sync_all_feeds() -> dict:
    """Main synchronization routine."""
    if not FEEDS_FILE.exists():
        return {"error": "feeds.json does not exist."}

    raw_feeds = json.loads(FEEDS_FILE.read_text(encoding="utf-8"))
    feeds = raw_feeds if isinstance(raw_feeds, list) else raw_feeds.get("feeds", [])
    all_intel_ips = set()
    today_str = datetime.now().strftime("%Y-%m-%d")
    now_iso = datetime.now().isoformat()

    feed_results = []
    for feed in feeds:
        if not feed.get("enabled", True):
            continue

        url = feed.get("url")
        if not url:
            continue

        try:
            feed_ips = fetch_and_parse_feed(url)
            feed["ipCount"] = len(feed_ips)
            feed["lastSynced"] = now_iso
            feed["lastStatus"] = "ok"
            all_intel_ips.update(feed_ips)
            feed_results.append({"name": feed.get("name"), "count": len(feed_ips), "status": "ok"})
        except Exception as e:
            feed["lastSynced"] = now_iso
            feed["lastStatus"] = f"error: {str(e)}"
            feed_results.append({"name": feed.get("name"), "count": 0, "status": f"error: {str(e)}"})

    # Read current blacklist
    existing_ips = set()
    if BLACKLIST_FILE.exists():
        existing_ips = {
            line.strip()
            for line in BLACKLIST_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }

    # Load user-inserted IPs (manual entries and bulk uploads)
    user_ips = {}
    if USER_IPS_FILE.exists():
        try:
            user_ips = json.loads(USER_IPS_FILE.read_text(encoding="utf-8"))
        except Exception:
            user_ips = {}

    user_ip_set = {ip.strip() for ip in user_ips.keys() if is_valid_ip(ip.strip())}

    # Combined target list: Threat Intel IPs + User-Inserted IPs
    target_ips = all_intel_ips.union(user_ip_set)

    # If any active feeds responded or user IPs exist, update blacklist.txt
    if target_ips:
        to_add = target_ips - existing_ips
        to_remove = existing_ips - target_ips

        # Sort IPs naturally
        sorted_ips = sorted(
            target_ips,
            key=lambda ip: ipaddress.ip_address(ip) if is_valid_ip(ip) else 0,
        )

        BLACKLIST_FILE.write_text("\n".join(sorted_ips) + "\n", encoding="utf-8")

        # Update dates metadata
        dates = {}
        if DATES_FILE.exists():
            try:
                dates = json.loads(DATES_FILE.read_text(encoding="utf-8"))
            except Exception:
                dates = {}

        # Remove stale IPs from dates
        for ip in to_remove:
            dates.pop(ip, None)

        # Preserve / set user IPs dates
        for ip, meta in user_ips.items():
            if isinstance(meta, dict) and meta.get("date"):
                dates[ip] = meta["date"]

        # Add new IPs with today's date
        for ip in to_add:
            if ip not in dates:
                dates[ip] = today_str

        DATES_FILE.write_text(json.dumps(dates, indent=2), encoding="utf-8")

        # Save feeds.json
        FEEDS_FILE.write_text(json.dumps(feeds, indent=2), encoding="utf-8")

        return {
            "success": True,
            "totalIps": len(target_ips),
            "threatIntelIps": len(all_intel_ips),
            "userInsertedIps": len(user_ip_set),
            "added": len(to_add),
            "removed": len(to_remove),
            "feeds": feeds,
            "results": feed_results,
        }

    # Save feeds.json even if no active feeds returned IPs
    FEEDS_FILE.write_text(json.dumps(feeds, indent=2), encoding="utf-8")
    return {
        "success": False,
        "error": "No active threat intel feeds could be reached or no valid IPs found.",
        "feeds": feeds,
        "results": feed_results,
    }


if __name__ == "__main__":
    print("Starting Threat Intel Feed synchronization...")
    res = sync_all_feeds()
    print("Result:", json.dumps(res, indent=2))
