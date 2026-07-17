"""
match_model.py
──────────────
Week 3: the model Week 2 was missing.

Trains a genuine binary classifier for the match-decision task
(true CVE match vs. false positive) on the adversarial dataset from
build_match_dataset.py, then CALIBRATES it so a score of 0.8 means
"right about 80% of the time".

Why this is a real model and the Week 2 "confidence" was not
-----------------------------------------------------------
Week 2: four constants (0.40/0.25/0.20/0.15) multiplied by hand-picked
        signals. Nothing fit to data, no error signal, cannot be wrong on
        the eval set by construction.
Week 3: weights are LEARNED from labeled (component, CVE) pairs that include
        cases the matcher gets wrong; performance is measured with
        cross-validation (every score comes from a model that never saw that
        row); the output is calibrated and reported with Brier score + a
        reliability table. It is still a glass box (logistic regression), so
        the XAI story is honest.

Two models are provided:
  · LogisticRegression  — the interpretable baseline (coefficients ARE the
    explanation; drop-in replacement for the hand-set score).
  · GradientBoosting    — a stronger non-linear model, to show the linear
    model isn't leaving accuracy on the table (and to have something to run
    SHAP against for the XAI deliverable).
"""
from __future__ import annotations

import json
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import (brier_score_loss, roc_auc_score, average_precision_score,
                             precision_recall_fscore_support, confusion_matrix)

from build_match_dataset import FEATURE_NAMES, build_dataset
import it_security_agent as agent


def load_rows(path="match_dataset.json"):
    rows = json.load(open(path))
    X = np.array([r["features"] for r in rows], dtype=float)
    y = np.array([r["label"] for r in rows], dtype=int)
    meta = [r["meta"] for r in rows]
    return X, y, meta


def make_dataset_from_nvd(nvd_path="nvd_real_bulk.json", seed=1234, noise=0.5):
    recs = agent.load_nvd_feed(nvd_path)
    rows = build_dataset(recs, seed=seed, noise=noise)
    X = np.array([r["features"] for r in rows], dtype=float)
    y = np.array([r["label"] for r in rows], dtype=int)
    meta = [r["meta"] for r in rows]
    return X, y, meta


def cv_scores(estimator, X, y, seed=0):
    """Honest cross-validated probabilities: no row scored by a model that
    trained on it."""
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    proba = cross_val_predict(estimator, X, y, cv=cv, method="predict_proba")[:, 1]
    return proba


def fit_calibrated(X, y, kind="logreg", seed=0):
    if kind == "logreg":
        base = LogisticRegression(C=1.0, class_weight="balanced",
                                  max_iter=2000, random_state=seed)
    elif kind == "gbdt":
        base = GradientBoostingClassifier(random_state=seed)
    else:
        raise ValueError(kind)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    method = "isotonic" if len(y) >= 500 else "sigmoid"
    cal = CalibratedClassifierCV(base, method=method, cv=cv)
    cal.fit(X, y)

    # cross-validated calibrated scores for honest reliability reporting
    cal_scores = cross_val_predict(
        CalibratedClassifierCV(base, method=method, cv=cv),
        X, y, cv=cv, method="predict_proba")[:, 1]

    base.fit(X, y)
    return base, cal, cal_scores, method


def metrics_at(y, proba, threshold=0.5):
    pred = (proba >= threshold).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(
        y, pred, average="binary", zero_division=0)
    cm = confusion_matrix(y, pred)
    return {
        "threshold": threshold,
        "precision": p, "recall": r, "f1": f1,
        "roc_auc": roc_auc_score(y, proba),
        "pr_auc": average_precision_score(y, proba),
        "brier": brier_score_loss(y, proba),
        "confusion": cm,
    }


def reliability_table(y, proba, n_bins=5):
    edges = np.linspace(0, 1, n_bins + 1)
    table = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (proba >= lo) & (proba < hi if hi < 1.0 else proba <= hi)
        if m.sum():
            table.append({"range": (lo, hi), "n": int(m.sum()),
                          "claimed": float(proba[m].mean()),
                          "actual": float(y[m].mean())})
    return table


def per_negative_type_recall(y, proba, meta, threshold=0.5):
    """For each adversarial negative type, what fraction did the model
    correctly REJECT? (recall on the 'should-not-fire' set.)"""
    pred = (proba >= threshold).astype(int)
    from collections import defaultdict
    stat = defaultdict(lambda: [0, 0])  # [correct_reject, total]
    for i, mt in enumerate(meta):
        if y[i] == 0:
            stat[mt["kind"]][1] += 1
            if pred[i] == 0:
                stat[mt["kind"]][0] += 1
    return {k: (c / t if t else float("nan"), t) for k, (c, t) in stat.items()}


def linear_weight_report(base):
    """The logistic model's coefficients ARE the global explanation."""
    w = base.coef_[0]
    share = np.abs(w) / np.abs(w).sum()
    return [{"feature": f, "coef": float(c), "abs_share": float(s)}
            for f, c, s in sorted(zip(FEATURE_NAMES, w, share),
                                   key=lambda t: -abs(t[1]))]


if __name__ == "__main__":
    X, y, meta = make_dataset_from_nvd()
    print(f"dataset: {len(y)} rows, {y.sum()} pos / {(y==0).sum()} neg\n")

    for kind in ("logreg", "gbdt"):
        base, cal, cal_scores, method = fit_calibrated(X, y, kind=kind)
        raw = cv_scores(base, X, y)
        m_raw = metrics_at(y, raw)
        m_cal = metrics_at(y, cal_scores)
        print(f"=== {kind} (calibration={method}) ===")
        print(f"  ROC-AUC {m_raw['roc_auc']:.3f}  PR-AUC {m_raw['pr_auc']:.3f}")
        print(f"  precision {m_cal['precision']:.3f}  recall {m_cal['recall']:.3f}  f1 {m_cal['f1']:.3f}")
        print(f"  Brier raw {m_raw['brier']:.4f} -> calibrated {m_cal['brier']:.4f}")
        if kind == "logreg":
            print("  learned weights (glass box):")
            for row in linear_weight_report(base):
                print(f"    {row['feature']:20} coef={row['coef']:+.3f}  |share|={row['abs_share']:.3f}")
        print("  rejection recall by negative type:")
        for k, (rec, n) in sorted(per_negative_type_recall(y, cal_scores, meta).items()):
            print(f"    {k:16} {rec:5.2f}  (n={n})")
        print()

    import joblib
    base, cal, cal_scores, method = fit_calibrated(X, y, kind="logreg")
    joblib.dump({"model": cal, "features": FEATURE_NAMES, "kind": "logreg",
                 "calibration": method}, "match_model.joblib")
    print("calibrated logistic model -> match_model.joblib")
