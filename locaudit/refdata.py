"""Download and cache raw authoritative reference feeds in data/refdata/.

Producer -> Consumer contract:
- Producer: `refdata.ensure()` downloads raw reference JSON feeds into `data/refdata/`
  (called by `uv run locaudit capture` or when `data/refdata/` is missing):
    - `iab_gvl.json`         https://vendor-list.consensu.org/v3/vendor-list.json
    - `disconnect.json`      https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json
    - `ddg_entities.json`    https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/build-data/generated/entity_map.json
    - `exodus_trackers.json` https://reports.exodus-privacy.eu.org/api/trackers
- Consumer: The LLM Agent, which greps or reads `data/refdata/*.json` to verify
  unfamiliar component namespaces, tracker categories, corporate owners, and
  IAB TCF precise-geolocation declarations (Special Feature 1).
"""
import os
import time
import urllib.error
import urllib.request

from . import paths

FEEDS = {
    "iab_gvl.json": "https://vendor-list.consensu.org/v3/vendor-list.json",
    "disconnect.json": "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json",
    "ddg_entities.json": "https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/build-data/generated/entity_map.json",
    "exodus_trackers.json": "https://reports.exodus-privacy.eu.org/api/trackers",
}

TTL_SECONDS = 7 * 24 * 3600
USER_AGENT = "android-loc-audit/0.1 (+https://github.com/tsaarni/android-loc-audit)"


def feed_path(filename):
    return paths.refdata(filename)


def cached_feeds():
    """Return list of feed filenames present and non-empty in data/refdata/."""
    root = paths.refdata()
    if not os.path.isdir(root):
        return []
    return sorted(
        name for name in FEEDS
        if os.path.exists(os.path.join(root, name)) and os.path.getsize(os.path.join(root, name)) > 0
    )


def ensure(max_age=TTL_SECONDS):
    """Download any missing or expired reference feeds into data/refdata/.

    Gracefully ignores network errors if an existing cached file is present.
    """
    os.makedirs(paths.refdata(), exist_ok=True)
    now = time.time()
    downloaded, reused, errors = [], [], {}

    for filename, url in FEEDS.items():
        target = feed_path(filename)
        if os.path.exists(target) and os.path.getsize(target) > 0:
            if (now - os.path.getmtime(target)) < max_age:
                reused.append(filename)
                continue
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
            with open(target, "wb") as f:
                f.write(data)
            downloaded.append(filename)
        except (urllib.error.URLError, OSError) as exc:
            if os.path.exists(target) and os.path.getsize(target) > 0:
                reused.append(filename)
            else:
                errors[filename] = str(exc)

    return {"downloaded": downloaded, "reused": reused, "errors": errors}
