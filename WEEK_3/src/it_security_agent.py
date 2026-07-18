"""
IT Security Agent - Baseline Vulnerability Matcher
====================================================

Pipeline:  SBOM (or manual component list) --> normalize to CPE-like string
           --> match against local NVD CVE data --> risk report (+ simple
           explanation of WHY each match fired).

This is a RULE-BASED baseline (exact / substring matching on vendor,
product, version). It intentionally does NOT do fuzzy/embedding matching
yet -- that's the "open design question" from the architecture slide.
Use this as the thing you benchmark fuzzy matching against later.

Data sources
------------
1. NVD CVE data: download a JSON feed from the NVD API and save locally.
   NVD API 2.0 docs: https://nvd.nist.gov/developers/vulnerabilities
   Example (run once, outside this script, to get sample data):

       import requests
       r = requests.get(
           "https://services.nvd.nist.gov/rest/json/cves/2.0",
           params={"keywordSearch": "log4j", "resultsPerPage": 50},
       )
       with open("nvd_sample.json", "w") as f:
           f.write(r.text)

2. SBOM: a CycloneDX-style JSON file (simplified loader below also accepts
   a plain list of {"name": ..., "version": ...} dicts for quick testing).

Usage
-----
    python it_security_agent.py --nvd nvd_sample.json --sbom sample_sbom.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any

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



# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Component:
    """One piece of software we are scanning (from an SBOM or manual entry)."""
    name: str
    version: str
    vendor: str | None = None  # optional, SBOMs don't always have it

    def normalized(self, use_resolver: bool = True) -> tuple[str, str, str]:
        """Return a normalized (vendor, product, version) triple for matching.

        Two-tier normalization:
        1. If name_resolver is available AND use_resolver is True, use the alias/
           purl resolver (handles 'apache-log4j', maven coords, etc.). This
           closes the biggest accuracy gap -- same software written many ways.
        2. Otherwise fall back to the original simple regex rules, so the matcher
           still works standalone with no extra dependency.
        Both paths are deterministic and explainable.
        """
        if use_resolver:
            try:
                from name_resolver import resolve_component
                v, product, version, _reason = resolve_component(
                    self.name, self.version, self.vendor)
                vendor = (v or "*").lower().strip()
                return vendor, product.lower().strip(), (version or "").lower().strip().lstrip("v")
            except Exception:
                pass  # resolver missing or errored -> fall through to baseline

        vendor = (self.vendor or "*").lower().strip()
        product = self.name.lower().strip()
        product = re.sub(r"[-_](core|client|server|lib)$", "", product)
        product = re.sub(r"\.(jar|whl|tar\.gz|zip)$", "", product)
        version = self.version.lower().strip().lstrip("v")
        return vendor, product, version


@dataclass
class CVEMatch:
    cve_id: str
    severity: float | None
    severity_label: str
    description: str
    matched_component: Component
    match_reason: str  # explainability: WHY did this fire


@dataclass
class RiskReport:
    matches: list[CVEMatch] = field(default_factory=list)
    components_scanned: int = 0
    components_unmatched: list[Component] = field(default_factory=list)

    def summary(self) -> str:
        by_sev: dict[str, int] = {}
        for m in self.matches:
            by_sev[m.severity_label] = by_sev.get(m.severity_label, 0) + 1
        lines = [
            f"Scanned {self.components_scanned} component(s).",
            f"Found {len(self.matches)} potential vulnerability match(es).",
            f"Severity breakdown: {by_sev if by_sev else 'none'}",
            f"Unmatched (no CPE hit, not necessarily safe): "
            f"{len(self.components_unmatched)}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CVSS severity bucketing (standard NVD thresholds)
# ---------------------------------------------------------------------------

def severity_label(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


# ---------------------------------------------------------------------------
# Loading NVD data
# ---------------------------------------------------------------------------

def load_nvd_feed(path: str) -> list[dict[str, Any]]:
    """Load NVD API 2.0 JSON response and flatten to a simple list of records.

    Each returned record: {cve_id, description, cvss_score, cpe_strings}
    """
    path = _resolve(path)
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    records = []
    vulnerabilities = raw.get("vulnerabilities", raw if isinstance(raw, list) else [])
    for entry in vulnerabilities:
        cve = entry.get("cve", entry)  # tolerate flattened test fixtures too
        cve_id = cve.get("id", "UNKNOWN-CVE")

        # Description (English)
        descriptions = cve.get("descriptions", [])
        desc_text = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS score - prefer v3.1, then v4.0, then v3.0, then v2.
        # NOTE: v4.0 was added after finding 98 records in a real NVD batch
        # that only had a v4.0 score and were silently dropping to UNKNOWN
        # under the original v3.1/v3.0/v2-only priority list.
        score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0]["cvssData"]["baseScore"]
                break

        # CPE match entries from configurations. We keep the FULL entry, not
        # just the criteria string, because real NVD records frequently use
        # a wildcard version in `criteria` (e.g. "openssl:*") and encode the
        # actual affected range separately via versionStartIncluding /
        # versionEndExcluding. Dropping those fields (as an earlier version
        # of this parser did) causes wildcard entries to match EVERY scanned
        # version -- a real false-positive bug, confirmed against a live
        # NVD batch where it inflated one component's matches 17x.
        cpe_entries: list[dict] = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", True):
                        cpe_entries.append({
                            "criteria": match.get("criteria", ""),
                            "versionStartIncluding": match.get("versionStartIncluding"),
                            "versionStartExcluding": match.get("versionStartExcluding"),
                            "versionEndIncluding": match.get("versionEndIncluding"),
                            "versionEndExcluding": match.get("versionEndExcluding"),
                        })

        # Fallback data: the newer CVE Record Format ships an "affected"
        # array with vendor/product/version-range strings directly, even
        # when no CPE has been assigned yet. In this real batch, CPE data
        # covers only 62% of records but "affected" covers ~99% -- so this
        # fallback recovers real matching capability for CVEs that would
        # otherwise be invisible to a CPE-only matcher.
        affected_entries: list[dict] = []
        for src in cve.get("affected", []):
            for ad in src.get("affectedData", []):
                affected_entries.append({
                    "vendor": (ad.get("vendor") or "").lower().strip(),
                    "product": (ad.get("product") or "").lower().strip(),
                    "versions": [v.get("version", "") for v in ad.get("versions", [])
                                 if v.get("status") == "affected"],
                })

        records.append(
            {
                "cve_id": cve_id,
                "description": desc_text,
                "cvss_score": score,
                "cpe_entries": cpe_entries,
                # kept for backward compatibility with code that only needs criteria strings
                "cpe_strings": [e["criteria"] for e in cpe_entries],
                "affected_entries": affected_entries,
            }
        )
    return records


def parse_cpe(cpe_string: str) -> tuple[str, str, str] | None:
    """Parse a CPE 2.3 string: cpe:2.3:a:vendor:product:version:...

    Returns (vendor, product, version) or None if malformed.
    """
    parts = cpe_string.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    # cpe:2.3:a:vendor:product:version:update:edition:...
    vendor, product, version = parts[3], parts[4], parts[5]
    return vendor.lower(), product.lower(), version.lower()


# ---------------------------------------------------------------------------
# Loading SBOM / component list
# ---------------------------------------------------------------------------

def load_sbom(path: str) -> list[Component]:
    """Load components from a CycloneDX SBOM, or a plain JSON list fallback.

    CycloneDX shape (simplified):
        {"components": [{"name": "...", "version": "...", "publisher": "..."}]}

    Plain fallback:
        [{"name": "...", "version": "...", "vendor": "..."}]
    """
    path = _resolve(path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    components: list[Component] = []
    entries = data.get("components", data) if isinstance(data, dict) else data
    for entry in entries:
        components.append(
            Component(
                name=entry.get("name", ""),
                version=str(entry.get("version", "")),
                vendor=entry.get("vendor") or entry.get("publisher"),
            )
        )
    return components


# ---------------------------------------------------------------------------
# Matching (the "Matcher" box in the architecture diagram)
# ---------------------------------------------------------------------------

def _parse_range_string(s: str) -> dict:
    """Parse a version constraint string like '>= 5.0.0, < 5.0.13' or
    '< 4.0.63' (as used in the CVE Record Format's `affected` field) into
    the same shape as an NVD cpeMatch entry's range fields, so it can reuse
    version_matches().
    """
    result = {}
    for clause in s.split(","):
        clause = clause.strip()
        # Check 2-char operators before 1-char ones (>= before >).
        for op, key in ((">=", "versionStartIncluding"), ("<=", "versionEndIncluding"),
                        (">", "versionStartExcluding"), ("<", "versionEndExcluding"),
                        ("=", "versionStartIncluding")):
            if clause.startswith(op):
                value = clause[len(op):].strip()
                result[key] = value
                if op == "=":
                    result["versionEndIncluding"] = value
                break
    return result


def match_component_fallback(component: Component, nvd_records: list[dict]) -> list["CVEMatch"]:
    """Fallback matcher using the affected[] vendor/product/version-range
    data instead of CPE. Only checked for records with NO cpe_entries, so it
    adds coverage rather than duplicating CPE-based matches.
    """
    matches = []
    vendor, product, version = component.normalized()

    for record in nvd_records:
        if record.get("cpe_entries"):
            continue  # already covered by the primary CPE matcher
        for entry in record.get("affected_entries", []):
            product_hit = (entry["product"] == product) or (product in entry["product"]) or (entry["product"] in product)
            vendor_hit = (vendor == "*") or (entry["vendor"] == vendor) or (vendor in entry["vendor"])
            if not (product_hit and vendor_hit):
                continue

            for range_str in entry["versions"]:
                range_fields = _parse_range_string(range_str)
                if version_matches(version, range_fields):
                    score = record["cvss_score"]
                    matches.append(CVEMatch(
                        cve_id=record["cve_id"],
                        severity=score,
                        severity_label=severity_label(score),
                        description=record["description"],
                        matched_component=component,
                        match_reason=(
                            f"[fallback: affected[] data, no CPE] product '{product}' "
                            f"matched '{entry['product']}', version '{version}' matched "
                            f"range '{range_str}' (vendor='{entry['vendor']}')"
                        ),
                    ))
                    break
    return matches


def _version_key(v: str):
    """Turn a version string into a tuple that sorts correctly even with
    alpha suffixes like OpenSSL's "1.1.1zh" or "3.0.21". Splits into
    alternating digit/non-digit runs and tags each so digit-runs compare
    numerically and letter-runs compare lexicographically, without ever
    comparing an int to a str (which would raise in Python 3).
    """
    chunks = re.findall(r"\d+|[a-zA-Z]+|[^a-zA-Z0-9]+", v)
    key = []
    for c in chunks:
        if c.isdigit():
            key.append((0, int(c)))
        else:
            key.append((1, c))
    return tuple(key)


def version_matches(scanned_version: str, cpe_entry: dict) -> bool:
    """Version matching that actually honors NVD's range fields when present.

    Priority:
    1. If the cpeMatch entry has versionStartIncluding/Excluding or
       versionEndIncluding/Excluding, do a real range comparison against
       the scanned version -- this is the common case for wildcard criteria.
    2. Otherwise, fall back to comparing against the version embedded in
       the criteria string itself (exact match, or '*'/'-' wildcard).
    """
    start_inc = cpe_entry.get("versionStartIncluding")
    start_exc = cpe_entry.get("versionStartExcluding")
    end_inc = cpe_entry.get("versionEndIncluding")
    end_exc = cpe_entry.get("versionEndExcluding")

    if any([start_inc, start_exc, end_inc, end_exc]):
        v = _version_key(scanned_version)
        if start_inc and v < _version_key(start_inc):
            return False
        if start_exc and v <= _version_key(start_exc):
            return False
        if end_inc and v > _version_key(end_inc):
            return False
        if end_exc and v >= _version_key(end_exc):
            return False
        return True

    # No range fields -- fall back to the version baked into criteria.
    parsed = parse_cpe(cpe_entry.get("criteria", ""))
    cpe_version = parsed[2] if parsed else "*"
    if cpe_version in ("*", "-", ""):
        return True
    return scanned_version == cpe_version or scanned_version.startswith(cpe_version)


def match_component(component: Component, nvd_records: list[dict]) -> list[CVEMatch]:
    matches: list[CVEMatch] = []
    vendor, product, version = component.normalized()

    for record in nvd_records:
        for cpe_entry in record.get("cpe_entries", []):
            parsed = parse_cpe(cpe_entry["criteria"])
            if not parsed:
                continue
            cpe_vendor, cpe_product, cpe_version = parsed

            product_hit = (cpe_product == product) or (product in cpe_product)
            vendor_hit = vendor == "*" or cpe_vendor == vendor
            version_hit = version_matches(version, cpe_entry)

            if product_hit and vendor_hit and version_hit:
                score = record["cvss_score"]
                has_range = any(cpe_entry.get(k) for k in
                                ("versionStartIncluding", "versionStartExcluding",
                                 "versionEndIncluding", "versionEndExcluding"))
                if has_range:
                    lo = cpe_entry.get("versionStartIncluding") or cpe_entry.get("versionStartExcluding") or "..."
                    hi = cpe_entry.get("versionEndExcluding") or cpe_entry.get("versionEndIncluding") or "..."
                    version_note = f"via range [{lo} .. {hi})"
                else:
                    version_note = f"CPE version '{cpe_version}'"

                matches.append(
                    CVEMatch(
                        cve_id=record["cve_id"],
                        severity=score,
                        severity_label=severity_label(score),
                        description=record["description"],
                        matched_component=component,
                        match_reason=(
                            f"product '{product}' matched CPE product "
                            f"'{cpe_product}', version '{version}' matched "
                            f"{version_note} (vendor='{cpe_vendor}')"
                        ),
                    )
                )
                break  # one match per record is enough for the baseline
    return matches


def scan(components: list[Component], nvd_records: list[dict]) -> RiskReport:
    report = RiskReport(components_scanned=len(components))
    for component in components:
        found = match_component(component, nvd_records)
        found += match_component_fallback(component, nvd_records)
        if found:
            report.matches.extend(found)
        else:
            report.components_unmatched.append(component)
    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(report: RiskReport) -> None:
    print("=" * 70)
    print("IT SECURITY AGENT - RISK REPORT")
    print("=" * 70)
    print(report.summary())
    print("-" * 70)

    # Sort worst-first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "NONE": 5}
    for m in sorted(report.matches, key=lambda m: order.get(m.severity_label, 9)):
        comp = m.matched_component
        print(f"[{m.severity_label:8}] {m.cve_id}  <-  {comp.name} {comp.version}")
        print(f"           score: {m.severity}")
        print(f"           why:   {m.match_reason}")
        print(f"           desc:  {m.description[:140]}...")
        print()

    if report.components_unmatched:
        print("-" * 70)
        print("Unmatched components (no known CVE found - NOT a safety guarantee,")
        print("just means nothing matched our current NVD sample / matching rules):")
        for c in report.components_unmatched:
            print(f"  - {c.name} {c.version}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Baseline IT Security Agent")
    parser.add_argument("--nvd", required=True, help="Path to local NVD JSON feed")
    parser.add_argument("--sbom", required=True, help="Path to SBOM / component JSON")
    args = parser.parse_args()

    try:
        nvd_records = load_nvd_feed(args.nvd)
    except FileNotFoundError:
        print(f"NVD feed not found: {args.nvd}", file=sys.stderr)
        sys.exit(1)

    try:
        components = load_sbom(args.sbom)
    except FileNotFoundError:
        print(f"SBOM not found: {args.sbom}", file=sys.stderr)
        sys.exit(1)

    report = scan(components, nvd_records)
    print_report(report)


if __name__ == "__main__":
    main()
