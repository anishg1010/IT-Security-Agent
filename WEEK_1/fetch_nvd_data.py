"""
Download a real batch of NVD CVE data (run this on YOUR machine, not in a
sandboxed environment -- it needs normal internet access to nvd.nist.gov).

NVD API 2.0 rate limits:
  - No API key: 5 requests per rolling 30 seconds
  - With a free API key (https://nvd.nist.gov/developers/request-an-api-key):
    50 requests per rolling 30 seconds
  - Max 2000 results per page -> use startIndex to page through more

This script pulls recent CVEs (published in the last N days) as a
manageable, genuinely current dataset. Adjust `days_back` and `max_records`
to control how much you pull.
"""
import json
import time
from datetime import datetime, timedelta, timezone

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = None  # paste your free NVD API key here to raise the rate limit

def fetch_recent_cves(days_back: int = 30, max_records: int = 2000, page_size: int = 200):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)

    headers = {"apiKey": API_KEY} if API_KEY else {}
    delay = 6 if not API_KEY else 0.7  # stay under the rate limit

    all_vulns = []
    start_index = 0
    while len(all_vulns) < max_records:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        resp = requests.get(API_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        batch = data.get("vulnerabilities", [])
        if not batch:
            break
        all_vulns.extend(batch)
        print(f"Fetched {len(all_vulns)} / {data.get('totalResults')} available")

        start_index += page_size
        if start_index >= data.get("totalResults", 0):
            break
        time.sleep(delay)

    return {"vulnerabilities": all_vulns[:max_records]}


if __name__ == "__main__":
    result = fetch_recent_cves(days_back=30, max_records=2000)
    with open("nvd_real_bulk.json", "w", encoding="utf-8") as f:
        json.dump(result, f)
    print(f"Saved {len(result['vulnerabilities'])} real CVE records to nvd_real_bulk.json")
