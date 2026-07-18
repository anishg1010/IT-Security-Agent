"""
threat_intel.py  —  KEV + EPSS + CWE enrichment
===============================================

THE PROBLEM THIS SOLVES
-----------------------
Severity is not priority. In our own NVD snapshot, 1,053 of 2,000 CVEs (53%)
are CVSS HIGH or CRITICAL. Telling an engineer "you have 1,053 critical
vulnerabilities" is an unusable alert — it guarantees alert fatigue, which is
itself a harm: an engineer who stops reading warnings misses the real one.

Three extra signals turn a scanner into a triage tool:

  CVSS  (already have)  "how bad IF exploited?"     deterministic formula, 0-10
  KEV   (CISA)          "is it being exploited NOW?" a curated FACT list
  EPSS  (FIRST)         "how LIKELY is exploitation?" an ML model, P(exploit/30d)
  CWE   (in NVD data)   "what KIND of weakness?"     taxonomy, bridge to MITRE

CVSS asks about severity in the abstract. KEV and EPSS ask about the real world.
A CVSS 9.8 that nobody exploits matters less than a CVSS 6.5 on CISA's KEV list
that attackers are using today.

HONEST CAVEATS (these belong in the model card)
-----------------------------------------------
* KEV is a FACT list but an INCOMPLETE one: absence from KEV does not mean
  "not exploited", only "CISA has not confirmed exploitation". It is biased
  toward software used by US federal agencies.
* EPSS is itself a MACHINE LEARNING MODEL. Consuming it means inheriting its
  training biases and its errors. We are chaining a model onto our model, and
  that must be disclosed rather than hidden.
* CWE -> CAPEC -> MITRE ATT&CK is a LOSSY chain. CWE-79 (XSS) does not map to
  one clean ATT&CK technique. We therefore use CWE directly for weakness-type
  analysis and treat ATT&CK as context, not as a rigorous mapping. Overclaiming
  here would be worse than saying nothing.

OFFLINE BY DESIGN
-----------------
Everything degrades gracefully. If a feed file is absent, the enrichment is
skipped with a clear warning and the agent still works — it just prioritises
with CVSS alone. Nothing here needs network access at runtime.

FEEDS (download once, drop next to this file):
  KEV  : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  EPSS : https://epss.empiricalsecurity.com/epss_scores-current.csv.gz   (leave gzipped)
"""
from __future__ import annotations

import csv
import gzip
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

# --- path resolution (works whether run from repo root, src/, or a notebook) ---
def _resolve(name):
    """Find a data/feed file whether we are run from the repo root, from src/,
    or from a notebook. Falls back to the bare name so flat layouts still work."""
    import os
    from pathlib import Path
    here = Path(__file__).resolve().parent
    for cand in (Path(name),                       # cwd / absolute
                 here.parent / "data" / name,      # WEEK_3/data/
                 here.parent / "feeds" / name,     # WEEK_3/feeds/
                 here / name):                     # next to the module
        if cand.exists():
            return str(cand)
    return name


KEV_FILE = "known_exploited_vulnerabilities.json"
EPSS_FILE = "epss_scores-current.csv.gz"


# ---------------------------------------------------------------------------
# KEV — CISA Known Exploited Vulnerabilities
# ---------------------------------------------------------------------------

def load_kev(path: str = KEV_FILE) -> tuple[set[str], list[str]]:
    """Return (set_of_kev_cve_ids, warnings).

    KEV is a curated list of CVEs CISA has CONFIRMED are exploited in the wild.
    It is the single highest-value prioritisation signal available, and it is
    a fact list rather than a prediction.
    """
    warnings: list[str] = []
    p = Path(_resolve(path))
    if not p.exists():
        warnings.append(
            f"KEV feed '{path}' not found — exploited-in-the-wild flagging is "
            f"DISABLED. Download from cisa.gov to enable.")
        return set(), warnings

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        warnings.append(f"KEV feed unreadable ({e}) — flagging disabled.")
        return set(), warnings

    # CISA's schema: {"catalogVersion":..., "vulnerabilities":[{"cveID":...}]}
    entries = data.get("vulnerabilities", data if isinstance(data, list) else [])
    ids = {e.get("cveID", "").strip().upper() for e in entries if e.get("cveID")}
    ids.discard("")
    if not ids:
        warnings.append("KEV feed parsed but contained no CVE IDs — check format.")
    return ids, warnings


def load_kev_details(path: str = KEV_FILE) -> dict[str, dict]:
    """Full KEV records keyed by CVE id (adds ransomware flag, due date)."""
    p = Path(_resolve(path))
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for e in data.get("vulnerabilities", []):
        cid = (e.get("cveID") or "").strip().upper()
        if cid:
            out[cid] = {
                "vendor": e.get("vendorProject"),
                "product": e.get("product"),
                "name": e.get("vulnerabilityName"),
                "date_added": e.get("dateAdded"),
                "due_date": e.get("dueDate"),
                "known_ransomware": (e.get("knownRansomwareCampaignUse") or
                                     "Unknown"),
            }
    return out


# ---------------------------------------------------------------------------
# EPSS — Exploit Prediction Scoring System
# ---------------------------------------------------------------------------

def load_epss(path: str = EPSS_FILE) -> tuple[dict[str, float], list[str]]:
    """Return ({cve_id: epss_probability}, warnings).

    Reads the gzipped CSV directly — no need to decompress by hand.

    FORMAT GOTCHA: the first line is a comment like
        #model_version:v2025.03.14,score_date:...
    and the real header is on line 2. A naive csv.DictReader would treat the
    comment as the header and silently return garbage, so we skip '#' lines.
    """
    warnings: list[str] = []
    p = Path(_resolve(path))
    if not p.exists():
        # tolerate an already-decompressed file
        alt = Path(_resolve(path.replace(".gz", "")))
        if alt.exists():
            p = alt
        else:
            warnings.append(
                f"EPSS feed '{path}' not found — exploit-probability ranking is "
                f"DISABLED. Download from FIRST to enable.")
            return {}, warnings

    try:
        if p.suffix == ".gz":
            fh = gzip.open(p, "rt", encoding="utf-8")
        else:
            fh = open(p, "rt", encoding="utf-8")
        with fh:
            # skip leading comment lines, keep the real header
            lines = (ln for ln in fh if not ln.startswith("#"))
            reader = csv.DictReader(lines)
            scores = {}
            for row in reader:
                cid = (row.get("cve") or "").strip().upper()
                if not cid:
                    continue
                try:
                    scores[cid] = float(row.get("epss", 0) or 0)
                except ValueError:
                    continue
    except Exception as e:
        warnings.append(f"EPSS feed unreadable ({e}) — ranking disabled.")
        return {}, warnings

    if not scores:
        warnings.append("EPSS feed parsed but contained no scores — check format.")
    return scores, warnings


# ---------------------------------------------------------------------------
# CWE — already inside the NVD records, just unused until now
# ---------------------------------------------------------------------------

# A small, honest CWE -> plain-English map for the most common classes.
# Deliberately short: each entry is a claim, and a wrong claim misleads a user.
CWE_NAMES = {
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-416": "Use After Free",
    "CWE-190": "Integer Overflow",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-287": "Improper Authentication",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-269": "Improper Privilege Management",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-798": "Hard-coded Credentials",
    "CWE-94": "Code Injection",
    "CWE-434": "Unrestricted File Upload",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-noinfo": "Not categorised",
    "NVD-CWE-noinfo": "Not categorised",
    "NVD-CWE-Other": "Other",
}


def extract_cwes(raw_cve: dict) -> list[str]:
    """Pull CWE ids out of a raw NVD 'cve' object. 1,922/2,000 records have them."""
    out = []
    for w in raw_cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = (d.get("value") or "").strip()
            if v:
                out.append(v)
    return sorted(set(out))


def cwe_label(cwe_id: str) -> str:
    return CWE_NAMES.get(cwe_id, cwe_id)


# ---------------------------------------------------------------------------
# Priority scoring — the point of the whole module
# ---------------------------------------------------------------------------

@dataclass
class ThreatIntel:
    """Bundle of enrichment feeds, loaded once and passed around."""
    kev: set[str] = field(default_factory=set)
    kev_details: dict = field(default_factory=dict)
    epss: dict[str, float] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def available(self) -> dict[str, bool]:
        return {"kev": bool(self.kev), "epss": bool(self.epss)}

    def summary(self) -> str:
        bits = []
        bits.append(f"KEV: {len(self.kev)} exploited CVEs" if self.kev
                    else "KEV: UNAVAILABLE")
        bits.append(f"EPSS: {len(self.epss)} scored CVEs" if self.epss
                    else "EPSS: UNAVAILABLE")
        s = " | ".join(bits)
        if self.warnings:
            s += "\n  " + "\n  ".join("WARNING: " + w for w in self.warnings)
        return s


def load_threat_intel(kev_path=KEV_FILE, epss_path=EPSS_FILE) -> ThreatIntel:
    kev, w1 = load_kev(kev_path)
    epss, w2 = load_epss(epss_path)
    return ThreatIntel(kev=kev, kev_details=load_kev_details(kev_path),
                       epss=epss, warnings=w1 + w2)


# Priority bands. These are a POLICY, not a discovered truth — they encode the
# judgement "confirmed exploitation beats theoretical severity". A different
# organisation could justify different cut-offs, so the thresholds are named
# constants rather than magic numbers buried in an if-statement.
EPSS_HIGH = 0.10      # >=10% chance of exploitation in the next 30 days
EPSS_MED = 0.01       # >=1%


def priority(cve_id: str, cvss: float | None, intel: ThreatIntel) -> tuple[str, str]:
    """Return (band, reason). Bands: ACT NOW / SCHEDULE / MONITOR / BACKLOG.

    The ordering is deliberate and defensible:
      1. On KEV            -> attackers are USING this. Nothing outranks a fact.
      2. High EPSS         -> likely to be exploited soon.
      3. High CVSS         -> severe if exploited, but no evidence anyone is.
      4. Everything else   -> backlog.
    """
    cid = (cve_id or "").upper()
    e = intel.epss.get(cid)

    if cid in intel.kev:
        d = intel.kev_details.get(cid, {})
        ransom = d.get("known_ransomware", "Unknown")
        extra = " (used in ransomware campaigns)" if ransom == "Known" else ""
        return "ACT NOW", f"on CISA KEV — confirmed exploited in the wild{extra}"

    if e is not None and e >= EPSS_HIGH:
        return "SCHEDULE", f"EPSS {e:.1%} — likely exploited within 30 days"

    if cvss is not None and cvss >= 9.0:
        if e is not None:
            return "MONITOR", (f"CVSS {cvss} critical, but EPSS only {e:.1%} — "
                               f"severe in theory, little real-world activity")
        return "MONITOR", f"CVSS {cvss} critical (no EPSS data)"

    if e is not None and e >= EPSS_MED:
        return "MONITOR", f"EPSS {e:.1%} — some exploitation signal"

    if cvss is not None and cvss >= 7.0:
        return "BACKLOG", f"CVSS {cvss} high, no exploitation signal"

    return "BACKLOG", "low severity, no exploitation signal"


BAND_ORDER = {"ACT NOW": 0, "SCHEDULE": 1, "MONITOR": 2, "BACKLOG": 3}


if __name__ == "__main__":
    intel = load_threat_intel()
    print(intel.summary())
    print()
    if not (intel.kev or intel.epss):
        print("No feeds present. Download them next to this file:")
        print("  KEV : https://www.cisa.gov/sites/default/files/feeds/"
              "known_exploited_vulnerabilities.json")
        print("  EPSS: https://epss.empiricalsecurity.com/"
              "epss_scores-current.csv.gz  (keep it gzipped)")
        print("\nThe agent still runs without them — it just prioritises with "
              "CVSS alone, which is exactly the problem this module fixes.")
    else:
        for cid in ("CVE-2021-44228", "CVE-2022-0778"):
            band, why = priority(cid, 9.8, intel)
            print(f"  {cid}: {band} — {why}")
