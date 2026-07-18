"""
build_match_dataset.py
──────────────────────
Week 3 fix for the central Week 2 weakness: there was no model and no error
signal. This module manufactures a *real* supervised learning problem out of
the NVD data the agent already loads.

The learning task (defensible, not circular)
--------------------------------------------
We are NOT predicting a CVE's CVSS score — that field is already in NVD, so
"predicting" it would be memorisation. The genuine decision the agent makes,
and the one that can be WRONG, is:

    given a scanned component and a candidate CVE, is this a TRUE match
    or a FALSE POSITIVE?

That is a binary classification problem. We build a labeled dataset of
(component, CVE) pairs:

  POSITIVES  — component drawn from a real CPE entry: same vendor/product,
               a version that genuinely falls in the vulnerable range.
  NEGATIVES  — adversarial near-misses the matcher SHOULD reject:
                 · wrong version (outside the vulnerable range)
                 · wrong vendor  (right product, adjacent/other vendor)
                 · near-miss name (suffix swap, substring trap, token reorder)
                 · unrelated pair (random product vs. random CVE)

Each row is described by transparent features (the same signals the Week 2
hand-set score used, plus a few) so the resulting model stays a glass box we
can explain with XAI and calibrate against ground truth.

Output: a list of {"features": [...], "label": 0/1, "meta": {...}} rows.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass

import it_security_agent as agent

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


FEATURE_NAMES = [
    "product_exact",        # scanned product == CPE product (1/0)
    "product_substr",       # one is a substring of the other (1/0)
    "vendor_exact",         # scanned vendor == CPE vendor (1/0)
    "vendor_wildcard",      # scanned vendor is '*'/unknown (1/0)
    "version_in_range",     # version satisfies the CPE range/exact (1/0)
    "version_specificity",  # 1.0 exact CPE ver, 0.5 range, 0.0 wildcard
    "name_edit_ratio",      # normalized char-overlap of names [0,1]
    "has_cpe_path",         # candidate came from CPE (1) vs affected[] (0.5)
]


# ---------------------------------------------------------------------------
# feature extraction for one (component, candidate CPE) pair
# ---------------------------------------------------------------------------

def _char_overlap(a: str, b: str) -> float:
    """Cheap, transparent name-similarity in [0,1]: size of shared char
    trigram set over the union. No ML, fully inspectable."""
    def tri(s):
        s = f"  {s} "
        return {s[i:i+3] for i in range(len(s) - 2)}
    A, B = tri(a), tri(b)
    if not A or not B:
        return 0.0
    return len(A & B) / len(A | B)


def featurize_pair(comp_vendor, comp_product, comp_version,
                   cpe_vendor, cpe_product, cpe_entry, has_cpe_path=1.0):
    product_exact = float(comp_product == cpe_product)
    product_substr = float(
        comp_product in cpe_product or cpe_product in comp_product)
    vendor_exact = float(comp_vendor == cpe_vendor)
    vendor_wildcard = float(comp_vendor in ("*", "", "n/a", None))
    version_in_range = float(agent.version_matches(comp_version, cpe_entry))

    has_range = any(cpe_entry.get(k) for k in (
        "versionStartIncluding", "versionStartExcluding",
        "versionEndIncluding", "versionEndExcluding"))
    parsed = agent.parse_cpe(cpe_entry.get("criteria", ""))
    cpe_ver = parsed[2] if parsed else "*"
    if cpe_ver not in ("*", "-", ""):
        version_specificity = 1.0
    elif has_range:
        version_specificity = 0.5
    else:
        version_specificity = 0.0

    name_ratio = _char_overlap(comp_product, cpe_product)

    return [
        product_exact, product_substr, vendor_exact, vendor_wildcard,
        version_in_range, version_specificity, name_ratio, has_cpe_path,
    ]


# ---------------------------------------------------------------------------
# harvest real CPE facts to build positives / negatives from
# ---------------------------------------------------------------------------

@dataclass
class CpeFact:
    vendor: str
    product: str
    entry: dict          # full cpe_entry (criteria + range fields)
    cve_id: str


def harvest_cpe_facts(records) -> list[CpeFact]:
    facts = []
    for r in records:
        for e in r.get("cpe_entries", []):
            p = agent.parse_cpe(e.get("criteria", ""))
            if not p:
                continue
            v, prod, _ = p
            if prod in ("*", "-", "") or v in ("*", "-", ""):
                continue
            facts.append(CpeFact(v, prod, e, r["cve_id"]))
    return facts


@dataclass
class FallbackFact:
    """A (vendor, product, version-range) drawn from a CVE's affected[] block
    rather than from CPE.

    This population MATTERS: 744 of our 2,000 records have affected[] data but
    NO CPE entry at all, so a CPE-only matcher is blind to more than a third of
    the feed. The fallback path exists to cover them, and it is genuinely less
    reliable than CPE (free-text vendor/product strings, looser version syntax),
    which is exactly why `has_cpe_path` must be a real, varying feature rather
    than a constant.
    """
    vendor: str
    product: str
    entry: dict          # synthesised range dict, same shape as a cpe_entry
    cve_id: str


def harvest_fallback_facts(records) -> list[FallbackFact]:
    """Harvest (vendor, product, range) triples from affected[] on records that
    have NO CPE data — the population the CPE path cannot see."""
    facts = []
    for r in records:
        if r.get("cpe_entries"):
            continue                      # CPE path already covers this record
        for a in r.get("affected_entries", []) or []:
            vendor = (a.get("vendor") or "").strip().lower()
            product = (a.get("product") or "").strip().lower()
            if not vendor or not product or vendor == "n/a" or product == "n/a":
                continue
            for vs in (a.get("versions") or []):
                rng = agent._parse_range_string(vs)
                if not rng:
                    continue
                # Give it the same shape a cpe_entry has, with a wildcard
                # criteria, so featurize_pair can treat both paths uniformly.
                entry = {"criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"}
                entry.update(rng)
                facts.append(FallbackFact(vendor, product, entry, r["cve_id"]))
    return facts


# ---------------------------------------------------------------------------
# concrete version pickers: a version that IS in range, and one that is NOT
# ---------------------------------------------------------------------------

def _in_range_version(entry) -> str | None:
    """Produce a scanned version that should satisfy the entry."""
    parsed = agent.parse_cpe(entry.get("criteria", ""))
    cpe_ver = parsed[2] if parsed else "*"
    if cpe_ver not in ("*", "-", ""):
        return cpe_ver                                   # exact CPE version
    lo = entry.get("versionStartIncluding") or entry.get("versionStartExcluding")
    hi = entry.get("versionEndExcluding") or entry.get("versionEndIncluding")
    if entry.get("versionStartIncluding"):
        return entry["versionStartIncluding"]            # boundary is in-range
    if hi:
        # step just below an exclusive upper bound
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)", hi)
        if m:
            a, b, c = map(int, m.groups())
            if c > 0:
                return f"{a}.{b}.{c-1}"
            if b > 0:
                return f"{a}.{b-1}.99"
        if lo:
            return lo
    if lo:
        return lo
    return None


def _out_of_range_version(entry) -> str | None:
    """Produce a scanned version that should FALL OUTSIDE the entry."""
    parsed = agent.parse_cpe(entry.get("criteria", ""))
    cpe_ver = parsed[2] if parsed else "*"
    if cpe_ver not in ("*", "-", ""):
        # bump the major version far past the fixed one
        m = re.match(r"^(\d+)", cpe_ver)
        base = int(m.group(1)) if m else 9
        return f"{base + 90}.0.0"
    hi = entry.get("versionEndExcluding") or entry.get("versionEndIncluding")
    if hi:
        m = re.match(r"^(\d+)", hi)
        base = int(m.group(1)) if m else 9
        return f"{base + 90}.0.0"                          # way above the ceiling
    lo = entry.get("versionStartIncluding") or entry.get("versionStartExcluding")
    if lo:
        return "0.0.1"                                     # below the floor
    return None


# name perturbations for near-miss negatives
def _suffix_swap(p):
    for s in ("-core", "-api", "-libs", "-common", "-client"):
        if p.endswith(s):
            return p[:-len(s)] + random.choice(["-testkit", "-mock", "-shim"])
    return p + random.choice(["-testkit", "-shim", "-mock"])

def _substring_trap(p):
    return random.choice(["py-", "node-", "go-", "rust-"]) + p

def _token_reorder(p):
    parts = re.split(r"[-_]", p)
    if len(parts) >= 2:
        random.shuffle(parts)
        return "-".join(parts)
    return p + "-ng"

_NAME_PERTURB = [_suffix_swap, _substring_trap, _token_reorder]


# ---------------------------------------------------------------------------
# main builder
# ---------------------------------------------------------------------------

def _corrupt(vendor, product, version, rng):
    """Simulate upstream ingestion noise on a component BEFORE featurisation.
    Mimics OCR errors, dropped vendors, and fuzzy versions from screenshots /
    hand entry. Returns a (possibly) mangled (vendor, product, version)."""
    # drop the vendor entirely (common: requirements.txt, OCR)
    if rng.random() < 0.35:
        vendor = "*"
    # typo / OCR substitution in the product name
    if product and rng.random() < 0.45:
        i = rng.randrange(len(product))
        sub = rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
        product = product[:i] + sub + product[i + 1:]
    # truncate a version to a coarser precision (e.g. "1.2.3" -> "1.2")
    if version and rng.random() < 0.35 and version.count(".") >= 2:
        version = version.rsplit(".", 1)[0]
    return vendor, product, version


def build_dataset(records, seed=1234, max_per_type=400, noise=0.0):
    """Return labeled rows: dict(features, label, meta). Balanced-ish.

    `noise` in [0,1] simulates real-world upstream feature corruption BEFORE
    featurisation: OCR mangling a product name, a missing vendor, a fuzzy
    version. This is what makes the problem realistically hard — a clean SBOM
    is linearly separable (wrong-vendor => vendor_exact=0), but a screenshot or
    a hand-typed name is not. Set noise>0 to stress-test the matcher the way a
    deployment actually would."""
    random.seed(seed)
    _rng = random.Random(seed + 7)
    facts = harvest_cpe_facts(records)
    if not facts:
        raise SystemExit("no CPE facts harvested — check NVD file shape")

    vendors = sorted({f.vendor for f in facts})
    products = sorted({f.product for f in facts})
    rows = []

    def add(vend, prod, ver, fact, label, kind, has_cpe=1.0):
        obs_vend, obs_prod, obs_ver = vend, prod, ver
        if noise and _rng.random() < noise:
            obs_vend, obs_prod, obs_ver = _corrupt(vend, prod, ver, _rng)
        feats = featurize_pair(obs_vend, obs_prod, obs_ver,
                               fact.vendor, fact.product, fact.entry,
                               has_cpe_path=has_cpe)
        rows.append({"features": feats, "label": label,
                     "meta": {"kind": kind, "vendor": obs_vend, "product": obs_prod,
                              "version": obs_ver, "cve": fact.cve_id,
                              "cpe_vendor": fact.vendor, "cpe_product": fact.product,
                              "path": "cpe" if has_cpe == 1.0 else "fallback",
                              "noised": (obs_prod != prod or obs_vend != vend or obs_ver != ver)}})

    # ---- POSITIVES: real vendor/product, in-range version ----
    pos = 0
    for f in random.sample(facts, min(len(facts), max_per_type)):
        ver = _in_range_version(f.entry)
        if ver is None:
            continue
        add(f.vendor, f.product, ver, f, 1, "true_match")
        pos += 1

    # ---- NEG 1: wrong version (right vendor+product, version out of range) ----
    n1 = 0
    for f in random.sample(facts, min(len(facts), max_per_type)):
        ver = _out_of_range_version(f.entry)
        if ver is None:
            continue
        # confirm it truly is out of range before labeling it a negative
        if agent.version_matches(ver, f.entry):
            continue
        add(f.vendor, f.product, ver, f, 0, "wrong_version")
        n1 += 1
        if n1 >= max_per_type // 2:
            break

    # ---- NEG 2: wrong vendor (right product, different vendor) ----
    n2 = 0
    for f in random.sample(facts, min(len(facts), max_per_type)):
        other = random.choice(vendors)
        if other == f.vendor:
            continue
        ver = _in_range_version(f.entry) or "1.0.0"
        add(other, f.product, ver, f, 0, "wrong_vendor")
        n2 += 1
        if n2 >= max_per_type // 2:
            break

    # ---- NEG 3: near-miss name (perturbed product) ----
    n3 = 0
    for f in random.sample(facts, min(len(facts), max_per_type)):
        perturbed = random.choice(_NAME_PERTURB)(f.product)
        if perturbed == f.product:
            continue
        ver = _in_range_version(f.entry) or "1.0.0"
        add(f.vendor, perturbed, ver, f, 0, "near_miss_name")
        n3 += 1
        if n3 >= max_per_type // 2:
            break

    # ---- NEG 4: unrelated pair (random product vs this CVE's CPE) ----
    n4 = 0
    for f in random.sample(facts, min(len(facts), max_per_type)):
        other_prod = random.choice(products)
        if other_prod == f.product:
            continue
        add(f.vendor, other_prod, "1.0.0", f, 0, "unrelated")
        n4 += 1
        if n4 >= max_per_type // 2:
            break

    # ---- FALLBACK PATH rows (has_cpe_path = 0.5) ----------------------------
    # 744 of our records have affected[] data but NO CPE. The fallback matcher
    # covers them, and it is genuinely weaker: vendor/product are free text and
    # version syntax is looser. Including these rows is what makes
    # `has_cpe_path` a real feature instead of a constant, and lets the model
    # LEARN how much to discount a fallback match rather than us asserting it.
    fb_facts = harvest_fallback_facts(records)
    if fb_facts:
        n_fb = max(1, max_per_type // 3)
        # fallback positives
        for f in random.sample(fb_facts, min(len(fb_facts), n_fb)):
            ver = _in_range_version(f.entry)
            if ver is None:
                continue
            add(f.vendor, f.product, ver, f, 1, "fallback_true_match", has_cpe=0.5)
        # fallback negatives: wrong version on the fallback path
        c = 0
        for f in random.sample(fb_facts, min(len(fb_facts), n_fb)):
            ver = _out_of_range_version(f.entry)
            if ver is None or agent.version_matches(ver, f.entry):
                continue
            add(f.vendor, f.product, ver, f, 0, "fallback_wrong_version", has_cpe=0.5)
            c += 1
            if c >= n_fb // 2:
                break
        # fallback negatives: wrong vendor on the fallback path
        fb_vendors = sorted({f.vendor for f in fb_facts})
        c = 0
        for f in random.sample(fb_facts, min(len(fb_facts), n_fb)):
            other = random.choice(fb_vendors)
            if other == f.vendor:
                continue
            ver = _in_range_version(f.entry) or "1.0.0"
            add(other, f.product, ver, f, 0, "fallback_wrong_vendor", has_cpe=0.5)
            c += 1
            if c >= n_fb // 2:
                break

    random.shuffle(rows)
    return rows


def summarize(rows):
    from collections import Counter
    lab = Counter(r["label"] for r in rows)
    kinds = Counter(r["meta"]["kind"] for r in rows)
    print(f"rows: {len(rows)}  positives: {lab[1]}  negatives: {lab[0]}")
    for k, n in kinds.most_common():
        print(f"  {k:16} {n}")


if __name__ == "__main__":
    import json, sys
    recs = agent.load_nvd_feed(sys.argv[1] if len(sys.argv) > 1 else "nvd_real_bulk.json")
    rows = build_dataset(recs)
    summarize(rows)
    json.dump(rows, open("match_dataset.json", "w"), indent=1)
    print("-> match_dataset.json")
