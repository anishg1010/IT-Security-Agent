"""
generate_negatives.py
─────────────────────
The eval set has no case where a match FIRES and is WRONG. Without those,
confidence weights cannot be fit — there is no error signal.

This generates near-miss components: names close enough to plausibly trigger
the fuzzy fallback matcher, but which refer to different software. Each is a
labeled false positive if the matcher fires.

Strategy: take real (vendor, product) pairs from the NVD snapshot and perturb
them along the axes the fallback is vulnerable to.
"""
import json, random, re
from pathlib import Path

random.seed(1010)


# ── perturbations the fuzzy matcher should resist ──────────────────────────

def suffix_swap(product):
    """log4j -> log4j-client  (different artifact, same project prefix)"""
    for s in ("-core", "-api", "-libs", "-common"):
        if product.endswith(s):
            return product[: -len(s)] + random.choice(["-client", "-testkit", "-mock"])
    return product + random.choice(["-client", "-shim", "-testkit"])


def version_family(product):
    """log4j -> log4j3   (a major version that does not exist)"""
    m = re.search(r"(\d+)$", product)
    if m:
        return product[: m.start()] + str(int(m.group(1)) + 1)
    return product + "2"


def vendor_lookalike(vendor):
    """apache -> apache-labs   (typosquat / unrelated org, same prefix)"""
    return vendor + random.choice(["-labs", "-community", "-contrib", "2"])


def substring_trap(product):
    """openssl -> openssl-wrapper   (contains the real name as a substring)"""
    return random.choice(["py-", "node-", "go-", "rust-"]) + product


def token_reorder(product):
    """apache-log4j -> log4j-apache"""
    parts = re.split(r"[-_]", product)
    if len(parts) >= 2:
        random.shuffle(parts)
        return "-".join(parts)
    return product


PERTURBATIONS = [
    ("suffix_swap",     suffix_swap,     "product", "sibling artifact, not the vulnerable one"),
    ("version_family",  version_family,  "product", "major version that does not exist"),
    ("substring_trap",  substring_trap,  "product", "real name embedded as substring"),
    ("token_reorder",   token_reorder,   "product", "same tokens, different project"),
]


def build_negatives(nvd_path, n=40):
    """Emit near-miss cases from real NVD vendor/product pairs."""
    records = json.load(open(nvd_path))
    if isinstance(records, dict):
        records = records.get("vulnerabilities", records.get("records", []))

    # Harvest real (vendor, product) pairs that DO have CPE entries.
    pairs = set()
    for r in records:
        for e in r.get("cpe_entries", []) or []:
            parts = (e.get("criteria") or "").split(":")
            if len(parts) > 4 and parts[3] not in ("*", "-", "") and parts[4] not in ("*", "-", ""):
                pairs.add((parts[3], parts[4]))
    pairs = sorted(pairs)
    if not pairs:
        raise SystemExit("no CPE pairs found — check nvd_real_bulk.json shape")

    cases = []
    for vendor, product in random.sample(pairs, min(n, len(pairs))):
        name, fn, axis, why = random.choice(PERTURBATIONS)
        new_product = fn(product) if axis == "product" else product
        if new_product == product:
            continue
        cases.append({
            "name": new_product,
            "version": "1.0.0",
            "vendor": vendor,
            "expect_vulnerable": False,
            "true_cves": [],
            "case_type": "fallback_negative",
            "note": f"{why} (perturbed from {vendor}/{product} via {name})",
        })

    # Vendor lookalikes: correct product, adjacent vendor.
    for vendor, product in random.sample(pairs, min(n // 3, len(pairs))):
        cases.append({
            "name": product,
            "version": "1.0.0",
            "vendor": vendor_lookalike(vendor),
            "expect_vulnerable": False,
            "true_cves": [],
            "case_type": "fallback_negative",
            "note": f"vendor lookalike of {vendor} (should not inherit its CVEs)",
        })

    return cases


if __name__ == "__main__":
    import sys
    nvd = sys.argv[1] if len(sys.argv) > 1 else "nvd_real_bulk.json"
    cases = build_negatives(nvd)
    Path("eval_negatives.json").write_text(json.dumps(cases, indent=2))
    print(f"{len(cases)} near-miss negatives -> eval_negatives.json")
    for c in cases[:6]:
        print(f"  {c['vendor']}/{c['name']:28} {c['note']}")
