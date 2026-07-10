"""
Evaluation harness for the IT Security Agent
============================================

Measures the matcher against a labeled evaluation set (eval_set.json) whose
labels are derived from NVD's own CPE data -- so we are testing whether the
MATCHER rediscovers the ground truth NVD already encodes, not guessing answers.

Metrics produced (all standard, all defensible):
  - Precision  = TP / (TP + FP)   "when it flags, how often right"
  - Recall     = TP / (TP + FN)   "of real vulns, how many caught"
  - FP rate    = FP / (FP + TN)   "false-alarm rate on safe components"
  - Per-vendor FP rate            "does the fairness fix add noise per vendor?"
  - Calibration (reliability)     "when it says 0.8, is it right ~80%?"
                                  reported as an EARLY SIGNAL (small n per bin)

Scope statement (say this in Q&A):
  "Ground truth = presence/absence of a CVE for a component in the NVD snapshot
   as of the data pull. True negatives mean 'no KNOWN CVE', not proven-safe.
   The set is a targeted 20-case probe of specific failure modes, not a
   statistically representative sample of all software."
"""

from __future__ import annotations
import json
from collections import defaultdict

import it_security_agent as agent


def load_eval(path="eval_set.json"):
    return json.load(open(path))["cases"]


def _confidence(match, input_confidence=1.0):
    """Same transparent confidence used in the Week 2 model."""
    r = match.match_reason.lower()
    path = 0.40 if "fallback" not in r else 0.20
    vspec = 0.25 if "cpe version" in r else (0.15 if "range" in r else 0.05)
    vendor = 0.15 if ("vendor='*'" not in r and "vendor='n/a'" not in r) else 0.0
    return round(min(1.0, path + vspec + vendor + 0.20 * input_confidence), 3)


def evaluate(cases, bulk_records, sample_records):
    """Run every case through the matcher and score it against its label.

    A case is a COMPONENT-LEVEL prediction: did the agent correctly decide
    whether this component is vulnerable at all? (We score at component level
    for the confusion matrix; CVE-level overlap is reported separately.)
    """
    rows = []
    TP = FP = TN = FN = 0
    per_vendor = defaultdict(lambda: {"fp": 0, "tn": 0, "flags": 0})
    calib = []  # (confidence, correct_bool) for matches that fired

    for c in cases:
        recs = sample_records if c.get("eval_source") == "sample" else bulk_records
        comp = agent.Component(c["name"], c["version"], c["vendor"])
        report = agent.scan([comp], recs)
        fired = len(report.matches) > 0
        predicted_vulnerable = fired
        actual_vulnerable = c["expect_vulnerable"]

        # confusion matrix at component level
        if predicted_vulnerable and actual_vulnerable:
            TP += 1; outcome = "TP"
        elif predicted_vulnerable and not actual_vulnerable:
            FP += 1; outcome = "FP"
            per_vendor[c["vendor"]]["fp"] += 1
        elif not predicted_vulnerable and not actual_vulnerable:
            TN += 1; outcome = "TN"
            per_vendor[c["vendor"]]["tn"] += 1
        else:
            FN += 1; outcome = "FN"

        if predicted_vulnerable:
            per_vendor[c["vendor"]]["flags"] += 1

        # calibration: for each fired match, was the matched CVE correct?
        # IMPORTANT honesty rule: our labels enumerate the FULL CVE set only for
        # components whose truth came from complete NVD CPE data (true/hard
        # positives). For fallback_positive cases we labeled ONE representative
        # CVE, so extra fired CVEs there are "unlabeled", not proven-wrong -- we
        # exclude them from calibration rather than scoring them as errors.
        true_cve_set = set(c.get("true_cves", []))
        fully_labeled = c["case_type"] in ("true_positive", "hard_positive", "true_negative", "boundary")
        for m in report.matches:
            conf = _confidence(m)
            if not actual_vulnerable:
                calib.append((conf, False))              # a match on a safe comp = wrong
            elif true_cve_set:
                if m.cve_id in true_cve_set:
                    calib.append((conf, True))
                elif fully_labeled:
                    calib.append((conf, False))          # labeled set complete -> real error
                # else: fallback case, unlabeled CVE -> skip (can't judge)
            else:
                calib.append((conf, True))               # vulnerable, matched, no enumerated list

        rows.append({
            "name": c["name"], "vendor": c["vendor"], "type": c["case_type"],
            "expected": actual_vulnerable, "predicted": predicted_vulnerable,
            "outcome": outcome, "n_matches": len(report.matches),
        })

    precision = TP / (TP + FP) if (TP + FP) else float("nan")
    recall = TP / (TP + FN) if (TP + FN) else float("nan")
    fp_rate = FP / (FP + TN) if (FP + TN) else float("nan")

    return {
        "rows": rows,
        "confusion": {"TP": TP, "FP": FP, "TN": TN, "FN": FN},
        "precision": precision, "recall": recall, "fp_rate": fp_rate,
        "per_vendor": dict(per_vendor), "calibration": calib,
    }


def calibration_bins(calib, edges=(0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 1.01)):
    """Bucket (confidence, correct) pairs and report per-bin accuracy + count.
    Small counts are expected -- this is an EARLY SIGNAL, not a precise curve."""
    bins = []
    for lo, hi in zip(edges, edges[1:]):
        pts = [ok for conf, ok in calib if lo <= conf < hi]
        if pts:
            bins.append({"range": f"{lo:.1f}-{hi:.1f}", "n": len(pts),
                         "accuracy": sum(pts) / len(pts),
                         "mid": (lo + hi) / 2})
    return bins


if __name__ == "__main__":
    bulk = agent.load_nvd_feed("nvd_real_bulk.json")
    sample = agent.load_nvd_feed("nvd_sample.json")
    cases = load_eval()
    res = evaluate(cases, bulk, sample)

    cm = res["confusion"]
    print("=== Confusion matrix (component level) ===")
    print(f"  TP={cm['TP']}  FP={cm['FP']}  TN={cm['TN']}  FN={cm['FN']}")
    print(f"\n  Precision : {res['precision']:.2f}")
    print(f"  Recall    : {res['recall']:.2f}")
    print(f"  FP rate   : {res['fp_rate']:.2f}")

    print("\n=== Per-vendor false positives ===")
    for v, d in sorted(res["per_vendor"].items()):
        fpr = d["fp"] / (d["fp"] + d["tn"]) if (d["fp"] + d["tn"]) else 0
        print(f"  {v:12} flags={d['flags']} fp={d['fp']} fpRate={fpr:.2f}")

    print("\n=== Calibration (EARLY SIGNAL - small n per bin) ===")
    for b in calibration_bins(res["calibration"]):
        print(f"  conf {b['range']}: claimed~{b['mid']:.2f}, actual {b['accuracy']:.2f} (n={b['n']})")

    print("\n=== Case-by-case ===")
    for r in res["rows"]:
        flag = "OK " if r["outcome"] in ("TP", "TN") else "!! "
        print(f"  {flag}[{r['outcome']}] {r['type']:14} {r['vendor']}/{r['name']} {r['version'] if 'version' in r else ''}")
