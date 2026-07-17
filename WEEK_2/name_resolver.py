"""
IT Security Agent - Name Normalization & Alias Resolution
=========================================================

The single biggest accuracy gap in a string-based CVE matcher is *naming*: the
same software is written many ways, and NVD picks one. Examples that are all
Log4Shell-vulnerable but look different to a naive matcher:

    log4j-core   apache-log4j   log4j2   org.apache.logging.log4j:log4j-core

This module normalizes a component name toward the identity NVD actually uses,
using three transparent, ordered steps:

  1. purl / Maven-coordinate parsing   ("pkg:maven/org.apache.logging.log4j/
     log4j-core@2.14.1"  ->  vendor=apache, product=log4j-core)
  2. a small, auditable ALIAS table    (curated known-hard cases)
  3. generic suffix/prefix stripping   (-core, -js, apache- , etc.)

Design choices that keep it responsible + scalable:
  - Every normalization is RULE-BASED and inspectable (no ML black box here).
  - `normalize_name()` returns the result AND the reason, so a match can explain
    "matched because we treated 'apache-log4j' as 'log4j'".
  - The alias table is data, not code: extend it in one place. For a real
    deployment you'd load this from the official CPE dictionary / purl repo;
    the interface is identical.
  - It never *invents* a match — it only widens how a name is written. A wrong
    alias would cause a false positive, so aliases are conservative and few.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# 1. Curated alias table.  key = a name people actually type,
#    value = the canonical (vendor_hint, product) NVD tends to use.
#    vendor_hint may be None when the alias only fixes the product name.
#    Keep this SMALL and well-justified; each entry is a claim "these are the
#    same software", and a wrong claim is a false positive.
# ---------------------------------------------------------------------------

ALIASES: dict[str, tuple[str | None, str]] = {
    # Log4Shell family — the textbook case
    "log4j-core":       ("apache", "log4j"),
    "apache-log4j":     ("apache", "log4j"),
    "log4j2":           ("apache", "log4j"),
    "log4j-api":        ("apache", "log4j"),
    # OpenSSL packaging variants
    "libssl":           ("openssl", "openssl"),
    "openssl-libs":     ("openssl", "openssl"),
    # common Java/JS packaging noise
    "spring-core":      ("vmware", "spring_framework"),
    "spring-web":       ("vmware", "spring_framework"),
    "springframework":  ("vmware", "spring_framework"),
    # nginx / node naming
    "nodejs":           ("nodejs", "node.js"),
    "node":             ("nodejs", "node.js"),
}


# ---------------------------------------------------------------------------
# 2. purl / Maven coordinate parsing
# ---------------------------------------------------------------------------

_PURL_RE = re.compile(
    r"^pkg:(?P<type>[a-z]+)/(?P<ns>[^/]+)/(?P<name>[^@]+?)(?:@(?P<ver>.+))?$",
    re.I,
)
# Maven-style "group:artifact" or "group:artifact:version"
_MAVEN_RE = re.compile(r"^(?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+)(?::(?P<ver>[\w.\-]+))?$")

# Map a purl namespace to a likely NVD vendor. Conservative; unknown -> None.
_PURL_VENDOR_HINT = {
    "org.apache.logging.log4j": "apache",
    "org.apache": "apache",
    "org.springframework": "vmware",
    "com.fasterxml.jackson.core": "fasterxml",
}


@dataclass
class NameResolution:
    vendor: str | None      # resolved vendor hint (may be None)
    product: str            # resolved product name for matching
    version: str | None     # version if the identifier carried one
    reason: str             # human-readable explanation of what we did


def _from_purl(raw: str) -> NameResolution | None:
    m = _PURL_RE.match(raw.strip())
    if not m:
        return None
    ns = m.group("ns").lower()
    name = m.group("name").lower()
    ver = m.group("ver")
    vendor = _PURL_VENDOR_HINT.get(ns)
    # If the artifact itself is a known alias, prefer that resolution.
    if name in ALIASES:
        av, ap = ALIASES[name]
        return NameResolution(av or vendor, ap, ver,
                              f"purl namespace '{ns}' + alias '{name}' -> {ap}")
    return NameResolution(vendor, name, ver,
                          f"parsed purl (namespace '{ns}' -> vendor '{vendor}')")


def _from_maven(raw: str) -> NameResolution | None:
    # Avoid eating normal "vendor:product" that isn't Maven — require a dot in group.
    m = _MAVEN_RE.match(raw.strip())
    if not m or "." not in m.group("group"):
        return None
    group = m.group("group").lower()
    artifact = m.group("artifact").lower()
    ver = m.group("ver")
    vendor = _PURL_VENDOR_HINT.get(group)
    if artifact in ALIASES:
        av, ap = ALIASES[artifact]
        return NameResolution(av or vendor, ap, ver,
                              f"maven coord + alias '{artifact}' -> {ap}")
    return NameResolution(vendor, artifact, ver,
                          f"parsed maven coordinate (group '{group}')")


# ---------------------------------------------------------------------------
# 3. Generic suffix/prefix stripping (last resort, mirrors Component.normalized)
# ---------------------------------------------------------------------------

_STRIP_SUFFIX = re.compile(r"[-_](core|client|server|lib|api|js|bin|dev|common)$")
_STRIP_PREFIX = re.compile(r"^(apache|eclipse|google|microsoft|the)[-_]")
_STRIP_EXT = re.compile(r"\.(jar|whl|tar\.gz|zip|war|min\.js|js)$")


def _generic_normalize(name: str) -> tuple[str, list[str]]:
    steps = []
    n = name.lower().strip()
    if _STRIP_EXT.search(n):
        n = _STRIP_EXT.sub("", n); steps.append("stripped file extension")
    if _STRIP_PREFIX.search(n):
        n = _STRIP_PREFIX.sub("", n); steps.append("stripped vendor prefix")
    if _STRIP_SUFFIX.search(n):
        n = _STRIP_SUFFIX.sub("", n); steps.append("stripped packaging suffix")
    return n, steps


# ---------------------------------------------------------------------------
# The public entry point
# ---------------------------------------------------------------------------

def normalize_name(name: str, vendor: str | None = None) -> NameResolution:
    """Resolve a raw component name toward NVD's canonical identity.

    Order matters (most specific first): purl > maven coord > alias table >
    generic stripping. Returns the resolved (vendor, product) plus a reason.
    """
    raw = (name or "").strip()

    # 1. structured identifiers
    res = _from_purl(raw)
    if res:
        return res
    res = _from_maven(raw)
    if res:
        return res

    low = raw.lower()

    # 2. direct alias hit
    if low in ALIASES:
        av, ap = ALIASES[low]
        return NameResolution(av or vendor, ap, None,
                              f"alias table: '{low}' -> '{ap}'")

    # 3. generic normalization, then re-check the alias table on the result
    normalized, steps = _generic_normalize(low)
    if normalized in ALIASES:
        av, ap = ALIASES[normalized]
        return NameResolution(av or vendor, ap, None,
                              f"{', '.join(steps) or 'normalized'} then alias -> '{ap}'")
    if normalized != low:
        return NameResolution(vendor, normalized, None,
                              f"generic normalize: {', '.join(steps)}")

    # 4. nothing to do
    return NameResolution(vendor, low, None, "no change (already canonical)")


def resolve_component(name: str, version: str, vendor: str | None = None):
    """Convenience: apply normalize_name and merge any version it recovered.
    Returns (vendor, product, version, reason)."""
    r = normalize_name(name, vendor)
    return (r.vendor or vendor, r.product, r.version or version, r.reason)


if __name__ == "__main__":
    tests = [
        ("log4j-core", "2.14.1", "apache"),
        ("apache-log4j", "2.14.1", None),
        ("log4j2", "2.14.1", None),
        ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "", None),
        ("org.apache.logging.log4j:log4j-core:2.14.1", "", None),
        ("openssl", "1.1.1", "openssl"),
        ("some-random-lib", "1.0.0", "acme"),
    ]
    for name, ver, vend in tests:
        v, p, ov, why = resolve_component(name, ver, vend)
        print(f"{name:55} -> vendor={v}, product={p}, version={ov}\n    reason: {why}")
