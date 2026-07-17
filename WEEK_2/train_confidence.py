"""
train_confidence.py
───────────────────
Replaces the four hand-set weights with fitted ones, then calibrates the
output so a score of 0.75 actually means "correct 75% of the time".

Two stages, deliberately separate:

  1. LogisticRegression  -> learns feature weights (replaces 0.40/0.25/0.20/0.15)
  2. Isotonic regression -> maps raw scores onto true probabilities

Stage 2 matters. A logistic model's output is not automatically calibrated,
especially on small or imbalanced data. Fitting weights without calibrating
them just moves the miscalibration around.

Requires: an eval set containing FIRED-AND-WRONG matches. Run
generate_negatives.py first, or this exits with an explanation.
"""
import json, sys
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import brier_score_loss, roc_auc_score

FEATURES = ["match_path", "version_specificity", "input_source", "vendor_known"]
HAND_SET = np.array([0.40, 0.25, 0.20, 0.15])


def featurize(match, component, ingest_conf=1.0):
    """Same four signals as the Week 2 hand-set model — now as a feature vector."""
    return [
        1.0 if match.get("via") == "cpe" else 0.5,          # match_path
        match.get("version_specificity", 0.5),               # exact > range > wildcard
        ingest_conf,                                         # SBOM 1.0, OCR ~0.5
        1.0 if component.get("vendor") not in (None, "", "n/a", "*") else 0.0,
    ]


def load(path):
    rows = json.load(open(path))
    X = np.array([r["features"] for r in rows], dtype=float)
    y = np.array([int(r["correct"]) for r in rows])
    return X, y


def check_trainable(y):
    n_pos, n_neg = (y == 1).sum(), (y == 0).sum()
    print(f"fired matches: {len(y)}   correct: {n_pos}   incorrect: {n_neg}")
    if n_neg == 0:
        sys.exit(
            "\nSTOP. Every fired match in this set is correct.\n"
            "There is no error signal, so no weight can be learned — sklearn will\n"
            "refuse to fit a single-class problem.\n\n"
            "This is not a bug in the code. It is the eval set telling you it is\n"
            "too easy. Run generate_negatives.py to add near-miss cases first.\n"
        )
    if n_neg < 15:
        print(f"\nWARNING: only {n_neg} negatives. Coefficients will be unstable.\n"
              f"Treat the fitted weights as a direction, not a measurement.\n")


def fit(X, y, seed=0):
    check_trainable(y)

    n_splits = min(5, (y == 0).sum(), (y == 1).sum())
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)

    # Stage 1 — weights. L2, balanced, because negatives will be the minority.
    base = LogisticRegression(
        C=1.0, class_weight="balanced",
        max_iter=2000, random_state=seed,
    )

    # Honest score: every prediction made by a model that never saw that row.
    raw = cross_val_predict(base, X, y, cv=cv, method="predict_proba")[:, 1]

    # Stage 2 — calibration. Isotonic is non-parametric; needs >~50 samples to
    # beat sigmoid. Below that, Platt scaling is the safer default.
    method = "isotonic" if len(y) >= 50 else "sigmoid"
    cal = CalibratedClassifierCV(base, method=method, cv=cv)
    cal.fit(X, y)
    cal_scores = cross_val_predict(
        CalibratedClassifierCV(base, method=method, cv=cv),
        X, y, cv=cv, method="predict_proba")[:, 1]

    base.fit(X, y)
    return base, cal, raw, cal_scores, method


def report(base, y, raw, cal_scores, method):
    w = base.coef_[0]
    norm = np.abs(w) / np.abs(w).sum()

    print("\nLearned weights vs hand-set")
    print(f"{'feature':22} {'hand':>7} {'learned':>9} {'|w| share':>10}")
    for f, h, lw, nw in zip(FEATURES, HAND_SET, w, norm):
        print(f"{f:22} {h:7.2f} {lw:9.3f} {nw:10.3f}")

    print(f"\nintercept {base.intercept_[0]:.3f}")
    print(f"\ncalibration method: {method}")
    print(f"Brier  raw {brier_score_loss(y, raw):.4f}  ->  calibrated {brier_score_loss(y, cal_scores):.4f}")
    print("  (lower is better; this is the number that says calibration helped)")

    if len(set(y)) > 1:
        print(f"ROC-AUC (cross-validated) {roc_auc_score(y, raw):.3f}")

    print("\nReliability — cross-validated, so no row scored by a model that saw it")
    print(f"{'bin':12} {'n':>5} {'claimed':>9} {'actual':>8}")
    edges = np.linspace(0, 1, 6)
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (cal_scores >= lo) & (cal_scores < hi if hi < 1.0 else cal_scores <= hi)
        if m.sum():
            print(f"{lo:.1f}-{hi:.1f}      {m.sum():5d} {cal_scores[m].mean():9.3f} {y[m].mean():8.3f}")

    print("\nEmpty bins are the honest part. A bin with n<10 is an anecdote.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "confidence_training.json"
    X, y = load(path)
    base, cal, raw, cal_scores, method = fit(X, y)
    report(base, y, raw, cal_scores, method)

    import joblib
    joblib.dump({"model": cal, "features": FEATURES}, "confidence_model.joblib")
    print("\ncalibrated model -> confidence_model.joblib")
