"""
feeds_live.py  —  optionally fetch threat-intel feeds live, with safe fallback
=============================================================================

WHY THIS EXISTS
---------------
KEV and EPSS are small, key-less, reliable feeds. Fetching them live means the
triage reflects *today's* exploited-vulnerability list rather than a snapshot —
a genuine production-thinking improvement.

NVD is the opposite. It is rate-limited (5 requests / 30s without a key), the
full feed is ~211,000 CVEs (~106 paged requests, >10 minutes), and it is
frequently slow or returns 503s. Pulling it live during a 15-minute
presentation is a real risk, so we DO NOT. The 2,000-record snapshot is kept
as the deterministic, reproducible input. What we add instead is a *delta*
updater (fetch only CVEs modified since the snapshot date) — shown and
explained, run offline.

THE DESIGN RULE: LIVE IS A BONUS, NEVER A DEPENDENCY
---------------------------------------------------
Every function here tries the network with a short timeout and, on ANY failure
(no internet, timeout, 503, blocked egress), falls back to the local file and
says so. The agent must never hang or crash because a feed was unreachable.
This mirrors the degraded-mode philosophy of threat_intel.py.

LEGALITY (asked and confirmed):
  * NVD  — US Government, public domain. API TOU permits automated "get" use.
  * KEV  — CISA, US Government, public domain.
  * EPSS — FIRST, free for any use.
All three are explicitly free public feeds. Fetching them programmatically is
their intended use. NVD asks for an API key only to raise rate limits, not to
grant permission.
"""
from __future__ import annotations

import gzip
import io
import json
import shutil
import ssl
import urllib.request
from pathlib import Path

# Feed URLs. Verified against public docs at project time; if one 404s, the
# fallback to the local file kicks in automatically.
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_TIMEOUT = 8      # seconds — short on purpose; we fall back fast


def _fetch(url: str, timeout: int = DEFAULT_TIMEOUT) -> bytes | None:
    """GET url, returning bytes or None on ANY failure. Never raises."""
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url, headers={"User-Agent": "IT-Security-Agent/1.0 (coursework)"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------

def refresh_kev(local_path: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[bool, str]:
    """Try to download the latest KEV to local_path. Returns (live?, message).
    On failure, leaves any existing local file untouched."""
    data = _fetch(KEV_URL, timeout)
    if data is None:
        if Path(local_path).exists():
            return False, "KEV: network unavailable — using existing local file"
        return False, "KEV: network unavailable and no local file — DISABLED"
    try:
        json.loads(data)                    # validate before overwriting
    except Exception:
        return False, "KEV: downloaded data was not valid JSON — kept local file"
    Path(local_path).write_bytes(data)
    return True, "KEV: refreshed live from CISA"


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

def refresh_epss(local_path: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[bool, str]:
    """Try to download the latest EPSS csv.gz to local_path. Returns (live?, msg)."""
    data = _fetch(EPSS_URL, timeout)
    if data is None:
        if Path(local_path).exists():
            return False, "EPSS: network unavailable — using existing local file"
        return False, "EPSS: network unavailable and no local file — DISABLED"
    try:
        # validate: it must gunzip and contain a cve column
        with gzip.open(io.BytesIO(data), "rt") as f:
            head = "".join(f.readline() for _ in range(3))
        if "cve" not in head.lower():
            return False, "EPSS: downloaded data missing 'cve' column — kept local"
    except Exception:
        return False, "EPSS: downloaded data was not valid gzip — kept local file"
    Path(local_path).write_bytes(data)
    return True, "EPSS: refreshed live from FIRST"


# ---------------------------------------------------------------------------
# NVD delta updater — the answer to "what about NEW vulnerabilities?"
# ---------------------------------------------------------------------------

def fetch_nvd_delta(since_iso: str, until_iso: str | None = None,
                    api_key: str | None = None, timeout: int = 20,
                    max_pages: int = 5) -> tuple[list, str]:
    """Fetch ONLY CVEs modified in a date window — the incremental-update path.

    This is how you keep a local snapshot current WITHOUT re-downloading all
    ~211,000 CVEs: the NVD API accepts lastModStartDate / lastModEndDate and
    returns only what changed. We cap at `max_pages` (2000 CVEs/page) so a demo
    can never run away.

    Returns (list_of_raw_cve_records, message). Designed to be SHOWN and
    explained, and run offline — not executed live during a presentation.

    NOTE: NVD requires both dates when filtering by modification date, and the
    window must be <= 120 days. Datetime format: 2026-01-01T00:00:00.000
    """
    import time
    from urllib.parse import urlencode

    if until_iso is None:
        # default to a 30-day window from `since`
        until_iso = since_iso  # caller should pass a real end; kept explicit

    headers = {"User-Agent": "IT-Security-Agent/1.0 (coursework)"}
    if api_key:
        headers["apiKey"] = api_key
    delay = 0.6 if api_key else 6.0        # respect NVD rate limits

    collected, start, msg = [], 0, ""
    for page in range(max_pages):
        params = urlencode({
            "lastModStartDate": since_iso,
            "lastModEndDate": until_iso,
            "resultsPerPage": 2000,
            "startIndex": start,
        })
        url = f"{NVD_CVE_API}?{params}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                payload = json.loads(r.read())
        except Exception as e:
            return collected, (f"NVD delta: stopped after {len(collected)} CVEs "
                               f"({type(e).__name__}). Partial result returned.")
        vulns = payload.get("vulnerabilities", [])
        collected.extend(vulns)
        total = payload.get("totalResults", 0)
        start += len(vulns)
        if start >= total or not vulns:
            break
        time.sleep(delay)                  # be a good API citizen

    return collected, f"NVD delta: fetched {len(collected)} modified CVEs since {since_iso}"


# ---------------------------------------------------------------------------
# convenience: refresh both small feeds before a scan
# ---------------------------------------------------------------------------

def refresh_feeds(kev_path: str, epss_path: str, live: bool = True,
                  timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """Refresh KEV + EPSS if live=True. Returns a list of status messages.
    Always safe: any failure falls back to the local file."""
    msgs = []
    if not live:
        return ["live refresh disabled — using local feed files as-is"]
    ok, m = refresh_kev(kev_path, timeout); msgs.append(m)
    ok, m = refresh_epss(epss_path, timeout); msgs.append(m)
    return msgs


if __name__ == "__main__":
    import sys
    kev = sys.argv[1] if len(sys.argv) > 1 else "../feeds/known_exploited_vulnerabilities.json"
    epss = sys.argv[2] if len(sys.argv) > 2 else "../feeds/epss_scores-current.csv.gz"
    print("Attempting live refresh (falls back to local on any failure)...\n")
    for m in refresh_feeds(kev, epss, live=True):
        print("  " + m)
    print("\nNVD is deliberately NOT refreshed live — the snapshot stays put.")
    print("To pull only NEW CVEs since your snapshot (run offline, not in a demo):")
    print('  from feeds_live import fetch_nvd_delta')
    print('  new, msg = fetch_nvd_delta("2026-01-01T00:00:00.000", "2026-01-31T00:00:00.000")')
