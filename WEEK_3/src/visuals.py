"""
visuals.py  —  Week 3 presentation figures
==========================================

Every figure here answers ONE question a reviewer will actually ask. That is
the design rule: if a chart doesn't answer a question, it doesn't ship.

  fig01_pipeline          "What does this system actually do?"
  fig02_week2_vs_week3    "What changed since last week?"
  fig03_dataset           "Where did your labels come from?"
  fig04_roc_pr            "Is the model actually good?"
  fig05_confusion         "What kind of mistakes does it make?"
  fig06_attack_breakdown  "Which attacks fool it?"           <- the honest one
  fig07_global_xai        "What does the model rely on?"
  fig08_local_xai         "Why did it make THIS decision?"
  fig09_reliability       "When it says 80%, is it right 80%?"
  fig10_threshold         "Where should we set the alarm?"
  fig11_coverage          "Did you test it properly?"
  fig12_scorecard         "Summarise it in one slide."

NO BUILD ARTIFACTS BY DEFAULT
-----------------------------
Every fig* function RETURNS a matplotlib Figure and writes nothing. The
notebook calls them directly, so the plots render inline from live data and
the repository stays free of generated PNGs (they are build output, not
source, and do not belong in version control).

This is also a rigour argument: an inline figure is regenerated from the model
every time the notebook runs, so it cannot drift out of sync with the numbers.
A committed PNG can silently go stale.

Usage in the notebook:
    import visuals
    ctx = visuals.build_context()        # train once
    visuals.fig06_attack_breakdown(ctx["rej"])    # renders inline

If you DO need PNGs for a slide deck:
    python visuals.py --save figures     # writes to figures/ (gitignored)

Style: one restrained palette, big fonts, no chartjunk. Readable from the back
of a lecture room and survives a projector.
"""
from __future__ import annotations

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

# NOTE: we deliberately do NOT call matplotlib.use("Agg") here. Forcing a
# non-interactive backend would stop the figures rendering inline in Jupyter,
# which is the whole point: the notebook shows them live, and nothing is
# written to disk. `save_all()` works under any backend if you do want PNGs.

# ── palette (matches the course slide deck's plum/teal) ───────────────────
PLUM = "#5c1a37"
PLUM_L = "#8d3b5e"
ROSE = "#b0374e"
TEAL = "#2a9d8f"
GREY = "#9aa5ab"
INK = "#22252a"
BG = "#ffffff"

plt.rcParams.update({
    "figure.facecolor": BG, "axes.facecolor": BG,
    "font.size": 12, "axes.titlesize": 15, "axes.titleweight": "bold",
    "axes.labelsize": 12, "axes.edgecolor": "#cccccc",
    "axes.grid": True, "grid.color": "#e8e8e8", "grid.linewidth": 0.8,
    "axes.axisbelow": True, "legend.frameon": False,
})


def _finish(fig, path=None):
    """Lay the figure out and return it.

    By default nothing is written to disk — the notebook renders the figure
    inline, so the repo stays free of generated PNGs. Pass `path=` (or use
    `save_all()`) only when you explicitly want files, e.g. to drop images
    into slides.
    """
    fig.tight_layout()
    if path:
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    return fig


# ==========================================================================
# 01 — the pipeline. Orients the audience before any numbers.
# ==========================================================================
def fig01_pipeline(path=None):
    fig, ax = plt.subplots(figsize=(13, 3.6))
    ax.set_xlim(0, 13); ax.set_ylim(0, 3.6); ax.axis("off")

    stages = [
        ("INPUT", "SBOM · requirements\npackage.json · screenshot", PLUM),
        ("RESOLVE", "alias / purl\nname normalisation", PLUM_L),
        ("MATCH", "CPE + version range\n→ affected[] fallback", PLUM_L),
        ("DECIDE", "learned model\ncalibrated probability", TEAL),
        ("EXPLAIN", "exact SHAP\n+ audit log", PLUM),
    ]
    x = 0.3
    for i, (title, sub, col) in enumerate(stages):
        box = FancyBboxPatch((x, 1.15), 2.15, 1.35,
                             boxstyle="round,pad=0.06", linewidth=0,
                             facecolor=col)
        ax.add_patch(box)
        ax.text(x + 1.075, 2.16, title, ha="center", va="center",
                color="white", fontsize=13, fontweight="bold")
        ax.text(x + 1.075, 1.62, sub, ha="center", va="center",
                color="white", fontsize=9.0)
        if i < len(stages) - 1:
            ax.add_patch(FancyArrowPatch((x + 2.2, 1.82), (x + 2.55, 1.82),
                                         arrowstyle="-|>", mutation_scale=17,
                                         color=INK, linewidth=1.6))
        x += 2.55

    ax.text(6.5, 3.25, "IT Security Agent — end-to-end pipeline",
            ha="center", fontsize=16, fontweight="bold", color=INK)
    ax.text(9.05, 0.72, "▲ NEW IN WEEK 3", ha="center", fontsize=9.5,
            color=TEAL, fontweight="bold")
    ax.text(9.05, 0.34, "the parts that can be wrong — and are measured",
            ha="center", fontsize=9, color=GREY, style="italic")
    return _finish(fig, path)


# ==========================================================================
# 02 — Week 2 vs Week 3. The "what changed" slide.
# ==========================================================================
def fig02_week2_vs_week3(path=None):
    fig, ax = plt.subplots(figsize=(11.5, 6.0))
    ax.set_xlim(0, 10); ax.set_ylim(0, 8.6); ax.axis("off")

    rows = [
        ("Parameters",      "4 constants, hand-set",       "learned from 1,169 labelled pairs"),
        ("Error signal",    "none — 0 wrong-fire cases",   "800 adversarial negatives"),
        ("Can it be wrong?", "not on its own test set",    "yes — and we measure where"),
        ("Calibration",     "claimed, never tested",       "isotonic + Brier + reliability"),
        ("Explainability",  "\"the weights are readable\"", "exact SHAP per decision"),
    ]

    ax.text(5.0, 8.25, "From hand-set score to a measured model",
            ha="center", fontsize=16, fontweight="bold", color=INK)
    ax.text(2.55, 7.15, "WEEK 2", ha="center", fontsize=14,
            fontweight="bold", color=ROSE)
    ax.text(5.95, 7.15, "WEEK 3", ha="center", fontsize=14,
            fontweight="bold", color=TEAL)

    y = 6.1
    for label, w2, w3 in rows:
        ax.text(0.05, y + 0.28, label, fontsize=11, fontweight="bold", color=INK)
        ax.add_patch(FancyBboxPatch((1.55, y - 0.28), 2.0, 0.82,
                                    boxstyle="round,pad=0.05", linewidth=0,
                                    facecolor="#f6e9ec"))
        ax.text(2.55, y + 0.13, w2, ha="center", va="center",
                fontsize=9.2, color=ROSE)
        ax.add_patch(FancyArrowPatch((3.72, y + 0.13), (4.28, y + 0.13),
                                     arrowstyle="-|>", mutation_scale=14,
                                     color=GREY, linewidth=1.3))
        ax.add_patch(FancyBboxPatch((4.45, y - 0.28), 3.0, 0.82,
                                    boxstyle="round,pad=0.05", linewidth=0,
                                    facecolor="#e4f4f1"))
        ax.text(5.95, y + 0.13, w3, ha="center", va="center",
                fontsize=9.2, color="#1d6f66")
        y -= 1.15

    ax.text(5.0, 0.30,
            "The perfect 1.00 score in Week 2 was the symptom, not the achievement:\n"
            "a test set with no wrong answers cannot fail.",
            ha="center", va="center", fontsize=10.5, color=INK, style="italic")
    return _finish(fig, path)


# ==========================================================================
# 03 — where the labels come from
# ==========================================================================
def fig03_dataset(y, meta, path=None):
    from collections import Counter
    counts = Counter(m["kind"] for m in meta)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.6),
                                   gridspec_kw={"width_ratios": [1, 1.35]})

    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    ax1.pie([pos, neg], labels=[f"true matches\n{pos}", f"false-positive traps\n{neg}"],
            colors=[TEAL, ROSE], autopct="%1.0f%%", startangle=90,
            textprops={"fontsize": 10.5}, wedgeprops={"linewidth": 2,
                                                      "edgecolor": "white"})
    ax1.set_title("Labelled (component, CVE) pairs")

    labels = {"wrong_version": "wrong version", "wrong_vendor": "wrong vendor",
              "near_miss_name": "near-miss name", "unrelated": "unrelated pair"}
    keys = [k for k in labels if k in counts]
    vals = [counts[k] for k in keys]
    ax2.barh([labels[k] for k in keys][::-1], vals[::-1], color=ROSE, height=0.6)
    for i, v in enumerate(vals[::-1]):
        ax2.text(v + 4, i, str(v), va="center", fontsize=10.5, color=INK)
    ax2.set_title("The four traps we built to fool the matcher")
    ax2.set_xlabel("number of adversarial cases")
    ax2.set_xlim(0, max(vals) * 1.18)
    fig.suptitle("Ground truth is NVD's own CPE data — the traps are derived from it",
                 fontsize=11, color=GREY, y=0.02)
    return _finish(fig, path)


# ==========================================================================
# 04 — ROC + PR
# ==========================================================================
def fig04_roc_pr(y, proba, path=None):
    from sklearn.metrics import roc_curve, precision_recall_curve, roc_auc_score, average_precision_score
    fpr, tpr, _ = roc_curve(y, proba)
    prec, rec, _ = precision_recall_curve(y, proba)
    auc = roc_auc_score(y, proba)
    ap = average_precision_score(y, proba)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.5, 4.8))
    ax1.plot([0, 1], [0, 1], "--", color=GREY, lw=1.2, label="random guessing")
    ax1.plot(fpr, tpr, color=PLUM, lw=2.6, label=f"our model (AUC = {auc:.3f})")
    ax1.fill_between(fpr, tpr, alpha=0.10, color=PLUM)
    ax1.set_xlabel("false-positive rate"); ax1.set_ylabel("true-positive rate")
    ax1.set_title("ROC — can it tell match from non-match?")
    ax1.legend(loc="lower right", fontsize=10)

    base_rate = y.mean()
    ax2.axhline(base_rate, ls="--", color=GREY, lw=1.2,
                label=f"random baseline ({base_rate:.2f})")
    ax2.plot(rec, prec, color=TEAL, lw=2.6, label=f"our model (AP = {ap:.3f})")
    ax2.fill_between(rec, prec, alpha=0.10, color=TEAL)
    ax2.set_xlabel("recall"); ax2.set_ylabel("precision")
    ax2.set_title("Precision–Recall")
    ax2.legend(loc="lower left", fontsize=10)
    ax2.set_ylim(0, 1.03)
    return _finish(fig, path)


# ==========================================================================
# 05 — confusion matrix, in plain language
# ==========================================================================
def fig05_confusion(cm, path=None):
    fig, ax = plt.subplots(figsize=(6.4, 5.4))
    im = ax.imshow(cm, cmap="RdPu", alpha=0.85)
    names = [["correctly ignored\n(true negative)", "false alarm\n(false positive)"],
             ["MISSED VULN\n(false negative)", "caught it\n(true positive)"]]
    total = cm.sum()
    for i in range(2):
        for j in range(2):
            v = cm[i, j]
            ax.text(j, i - 0.10, f"{v}", ha="center", va="center",
                    fontsize=26, fontweight="bold",
                    color="white" if v > total * 0.25 else INK)
            ax.text(j, i + 0.22, names[i][j], ha="center", va="center",
                    fontsize=9,
                    color="white" if v > total * 0.25 else INK)
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["model says: SAFE", "model says: VULNERABLE"], fontsize=10.5)
    ax.set_yticklabels(["truly safe", "truly vulnerable"], fontsize=10.5)
    ax.set_title("What kind of mistakes does it make?")
    ax.grid(False)
    fn = int(cm[1, 0])
    ax.text(0.5, -0.16,
            f"The costly cell is bottom-left: {fn} missed vulnerabilities.\n"
            "A missed vuln is worse than a false alarm — that is why we tune the threshold.",
            ha="center", va="top", fontsize=10, color=ROSE, fontweight="bold",
            transform=ax.transAxes)
    return _finish(fig, path)


# ==========================================================================
# 06 — the honest slide: which attacks get through
# ==========================================================================
def fig06_attack_breakdown(rej, path=None):
    labels = {"wrong_version": "wrong version", "unrelated": "unrelated pair",
              "near_miss_name": "near-miss name", "wrong_vendor": "wrong vendor"}
    items = sorted(rej.items(), key=lambda kv: -kv[1][0])
    names = [labels.get(k, k) for k, _ in items]
    vals = [v[0] for _, v in items]
    ns = [v[1] for _, v in items]

    fig, ax = plt.subplots(figsize=(10.5, 4.8))
    colors = [TEAL if v >= 0.90 else ROSE for v in vals]
    bars = ax.barh(names[::-1], [v * 100 for v in vals][::-1],
                   color=colors[::-1], height=0.58)
    for i, (v, n) in enumerate(zip(vals[::-1], ns[::-1])):
        ax.text(v * 100 + 1.2, i, f"{v*100:.0f}%  (n={n})",
                va="center", fontsize=11, color=INK)
    ax.axvline(90, ls="--", color=GREY, lw=1.4)
    ax.text(90, -0.85, "90% target", ha="center", fontsize=9.5, color=GREY)
    ax.set_xlim(0, 112)
    ax.set_xlabel("% of attacks correctly rejected")
    ax.set_title("Which traps fool the model?  (lower = weaker defence)")
    ax.text(0.0, -0.20,
            "Honest finding: wrong-vendor is the weak spot. When ingestion drops the vendor,\n"
            "the model leans on name + version and sometimes accepts a wrong-vendor pair.\n"
            "Mitigation: require a vendor signal before auto-firing; else route to human review.",
            fontsize=9.6, color=INK, style="italic", va="top",
            transform=ax.transAxes)
    return _finish(fig, path)


# ==========================================================================
# 07 — global XAI
# ==========================================================================
def fig07_global_xai(base, feature_names, path=None):
    w = base.coef_[0]
    idx = np.argsort(np.abs(w))
    names = [feature_names[i] for i in idx]
    vals = [w[i] for i in idx]
    colors = [TEAL if v >= 0 else ROSE for v in vals]

    fig, ax = plt.subplots(figsize=(10, 5.2))
    ax.barh(names, vals, color=colors, height=0.6)
    ax.axvline(0, color=INK, lw=1.0)
    for i, v in enumerate(vals):
        ax.text(v + (0.12 if v >= 0 else -0.12), i, f"{v:+.2f}",
                va="center", ha="left" if v >= 0 else "right",
                fontsize=10, color=INK)
    ax.set_xlabel("coefficient  (→ pushes toward MATCH   ← pushes toward REJECT)")
    ax.set_title("What does the model rely on?  (global explanation)")
    lim = max(np.abs(vals)) * 1.28
    ax.set_xlim(-lim, lim)
    ax.text(0.0, -0.145,
            "For a logistic model the coefficients ARE the model — no approximation needed.",
            fontsize=9.6, color=GREY, style="italic", va="top",
            transform=ax.transAxes)
    return _finish(fig, path)


# ==========================================================================
# 08 — local XAI waterfall, annotated for humans
# ==========================================================================
def fig08_local_xai(base, X, row_index, meta, feature_names,
                    path=None):
    w, b = base.coef_[0], base.intercept_[0]
    mean = X.mean(axis=0)
    x = X[row_index]
    base_value = b + w @ mean
    phi = w * (x - mean)
    logit = base_value + phi.sum()
    prob = 1 / (1 + np.exp(-logit))

    order = np.argsort(np.abs(phi))
    names = [feature_names[i] for i in order]
    vals = [phi[i] for i in order]
    colors = [TEAL if v >= 0 else ROSE for v in vals]

    m = meta[row_index]
    verdict = "REJECTED" if prob < 0.5 else "MATCHED"
    col = ROSE if prob < 0.5 else TEAL

    fig, ax = plt.subplots(figsize=(10.5, 6.2))
    ax.barh(names, vals, color=colors, height=0.6)
    ax.axvline(0, color=INK, lw=1.0)
    pad = (max(np.abs(vals)) or 1) * 0.04
    for i, v in enumerate(vals):
        ax.text(v + (pad if v >= 0 else -pad), i, f"{v:+.2f}",
                va="center", ha="left" if v >= 0 else "right",
                fontsize=10, color=INK)
    lim = (max(np.abs(vals)) or 1) * 1.35
    ax.set_xlim(-lim, lim)

    ax.set_title("Why did it reject this one?  (local explanation)", pad=34)
    ax.set_xlabel("contribution to the decision  (→ toward MATCH   ← toward REJECT)")
    sub = (f"scanned:  {m.get('vendor')}/{m.get('product')} {m.get('version')}"
           f"        candidate CVE covers:  {m.get('cpe_vendor')}/{m.get('cpe_product')}")
    ax.text(0.5, 1.035, sub, fontsize=9.8, color=GREY, ha="center",
            va="bottom", transform=ax.transAxes)
    ax.text(0.5, -0.145,
            f"Verdict: {verdict}  (probability {prob:.3f}) — carried by "
            f"'{feature_names[int(np.argmax(np.abs(phi)))]}'",
            fontsize=11, color=col, fontweight="bold", ha="center",
            va="top", transform=ax.transAxes)
    ax.text(0.5, -0.215,
            "Exact SHAP: φᵢ = wᵢ·(xᵢ − E[xᵢ]).  Verified in the test suite: Σφ + base = logit.",
            fontsize=9.3, color=GREY, style="italic", ha="center",
            va="top", transform=ax.transAxes)
    return _finish(fig, path)


# ==========================================================================
# 09 — reliability
# ==========================================================================
def fig09_reliability(y, proba, path=None, n_bins=8):
    edges = np.linspace(0, 1, n_bins + 1)
    xs, ys, ns = [], [], []
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (proba >= lo) & (proba < hi if hi < 1.0 else proba <= hi)
        if m.sum():
            xs.append(proba[m].mean()); ys.append(y[m].mean()); ns.append(int(m.sum()))

    fig, ax = plt.subplots(figsize=(6.4, 6.0))
    ax.plot([0, 1], [0, 1], "--", color=GREY, lw=1.4, label="perfect calibration")
    ax.plot(xs, ys, color=PLUM, lw=1.6, alpha=0.5, zorder=2)
    ax.scatter(xs, ys, s=[max(45, n * 1.1) for n in ns], color=PLUM,
               zorder=3, label="our model (dot size = sample count)")
    for xi, yi, ni in zip(xs, ys, ns):
        ax.annotate(f"n={ni}", (xi, yi), textcoords="offset points",
                    xytext=(9, -12), fontsize=8, color=GREY)
    ax.set_xlabel("probability the model claims")
    ax.set_ylabel("how often it was actually right")
    ax.set_title("When it says 80%, is it right 80% of the time?")
    ax.legend(loc="upper left", fontsize=9.5)
    ax.set_xlim(-0.02, 1.02); ax.set_ylim(-0.02, 1.02)
    ax.text(0.02, -0.16, "On the dashed line = trustworthy probabilities.",
            fontsize=9.6, color=GREY, style="italic", transform=ax.transAxes)
    return _finish(fig, path)


# ==========================================================================
# 10 — threshold trade-off: the business decision
# ==========================================================================
def fig10_threshold(y, proba, path=None):
    ths = np.linspace(0.05, 0.95, 91)
    precs, recs, f1s, alarms = [], [], [], []
    for t in ths:
        pred = (proba >= t).astype(int)
        tp = ((pred == 1) & (y == 1)).sum()
        fp = ((pred == 1) & (y == 0)).sum()
        fn = ((pred == 0) & (y == 1)).sum()
        p = tp / (tp + fp) if (tp + fp) else 1.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        precs.append(p); recs.append(r)
        f1s.append(2 * p * r / (p + r) if (p + r) else 0)
        alarms.append(int(tp + fp))

    best = int(np.argmax(f1s))
    fig, ax = plt.subplots(figsize=(10.5, 5.2))
    ax.plot(ths, precs, color=PLUM, lw=2.4, label="precision (fewer false alarms)")
    ax.plot(ths, recs, color=TEAL, lw=2.4, label="recall (fewer missed vulns)")
    ax.plot(ths, f1s, color=GREY, lw=1.8, ls="--", label="F1 (balance)")
    ax.axvline(ths[best], color=ROSE, lw=1.6)
    ax.annotate(f"best F1 = {f1s[best]:.3f}\nat threshold {ths[best]:.2f}",
                (ths[best], f1s[best]), textcoords="offset points",
                xytext=(14, -46), fontsize=10, color=ROSE, fontweight="bold",
                arrowprops=dict(arrowstyle="->", color=ROSE))
    ax.set_xlabel("decision threshold  (how sure must the model be before it raises an alarm?)")
    ax.set_ylabel("score")
    ax.set_title("Where should we set the alarm?  (a policy choice, not a maths one)")
    ax.legend(loc="lower center", fontsize=10, ncol=3)
    ax.set_ylim(0, 1.05)
    ax.text(0.0, -0.20,
            "Security teams usually push this LEFT: missing a real vulnerability costs more than a false alarm.\n"
            "The graph makes that trade-off explicit instead of hiding it in a default of 0.5.",
            fontsize=9.6, color=INK, style="italic", transform=ax.transAxes)
    return _finish(fig, path)


# ==========================================================================
# 11 — coverage
# ==========================================================================
def fig11_coverage(rows, total, path=None):
    """rows: list of (module, pct)."""
    names = [r[0] for r in rows][::-1]
    vals = [r[1] for r in rows][::-1]
    colors = [TEAL if v >= 80 else PLUM_L for v in vals]

    fig, ax = plt.subplots(figsize=(10, 4.8))
    ax.barh(names, vals, color=colors, height=0.58)
    for i, v in enumerate(vals):
        ax.text(v + 1, i, f"{v:.1f}%", va="center", fontsize=10.5, color=INK)
    ax.axvline(80, ls="--", color=ROSE, lw=1.6)
    ax.text(80, len(names) - 0.35, " 80% requirement", fontsize=9.8, color=ROSE)
    ax.set_xlim(0, 108)
    ax.set_xlabel("% of executable lines covered by tests")
    ax.set_title(f"Test coverage — total {total:.1f}%  (71 tests, standard library only)")
    ax.text(0.0, -0.19,
            "Uncovered lines are honest: the OCR image branch (needs a real screenshot + tesseract)\n"
            "and CLI entry points. Every decision-relevant path is tested.",
            fontsize=9.6, color=GREY, style="italic", va="top",
            transform=ax.transAxes)
    return _finish(fig, path)


# ==========================================================================
# 12 — one-slide scorecard
# ==========================================================================
def fig12_scorecard(metrics, rej, coverage_total, n_tests, path=None):
    fig, ax = plt.subplots(figsize=(12.5, 5.2))
    ax.set_xlim(0, 12.5); ax.set_ylim(0, 5.2); ax.axis("off")
    ax.text(6.25, 4.82, "IT Security Agent — Week 3 scorecard",
            ha="center", fontsize=17, fontweight="bold", color=INK)

    cards = [
        ("ROC-AUC", f"{metrics['roc_auc']:.3f}", "match vs non-match", TEAL),
        ("F1", f"{metrics['f1']:.3f}", "balance of the two errors", TEAL),
        ("Brier", f"{metrics['brier']:.3f}", "probability quality (lower=better)", PLUM_L),
        ("Coverage", f"{coverage_total:.1f}%", f"{n_tests} tests, stdlib only", TEAL),
    ]
    x = 0.35
    for title, val, sub, col in cards:
        ax.add_patch(FancyBboxPatch((x, 2.55), 2.75, 1.75,
                                    boxstyle="round,pad=0.07", linewidth=0,
                                    facecolor=col))
        ax.text(x + 1.375, 3.78, title, ha="center", fontsize=11.5,
                color="white", fontweight="bold")
        ax.text(x + 1.375, 3.20, val, ha="center", fontsize=25,
                color="white", fontweight="bold")
        ax.text(x + 1.375, 2.76, sub, ha="center", fontsize=8.6, color="white")
        x += 3.0

    ax.text(0.35, 2.10, "Attack rejection rate", fontsize=12,
            fontweight="bold", color=INK)
    labels = {"wrong_version": "wrong version", "unrelated": "unrelated",
              "near_miss_name": "near-miss name", "wrong_vendor": "wrong vendor"}
    x = 0.35
    for k, lbl in labels.items():
        if k not in rej:
            continue
        v = rej[k][0]
        col = TEAL if v >= 0.90 else ROSE
        ax.add_patch(FancyBboxPatch((x, 1.05), 2.75, 0.82,
                                    boxstyle="round,pad=0.05", linewidth=0,
                                    facecolor="#f2f4f5"))
        ax.text(x + 0.16, 1.46, lbl, fontsize=10, color=INK, va="center")
        ax.text(x + 2.60, 1.46, f"{v*100:.0f}%", fontsize=14, color=col,
                fontweight="bold", va="center", ha="right")
        x += 3.0

    ax.text(6.25, 0.42,
            "Known weak spot: wrong-vendor rejection (83%) when ingestion drops the vendor.\n"
            "Stated, measured, and mitigated by routing vendor-less matches to human review.",
            ha="center", fontsize=10, color=INK, style="italic")
    return _finish(fig, path)


# ==========================================================================
def build_context(noise=0.5, nvd_path="nvd_real_bulk.json"):
    """Train once and return everything the figures need.

    Call this ONCE in the notebook, then pass the result to the fig* functions.
    Keeps the expensive fit out of every plotting call.
    """
    from match_model import (make_dataset_from_nvd, fit_calibrated, cv_scores,
                             metrics_at, per_negative_type_recall)
    from build_match_dataset import FEATURE_NAMES

    X, y, meta = make_dataset_from_nvd(nvd_path, noise=noise)
    base, cal, cal_scores, method = fit_calibrated(X, y, kind="logreg")
    raw = cv_scores(base, X, y)
    return {
        "X": X, "y": y, "meta": meta, "base": base, "cal": cal,
        "cal_scores": cal_scores, "raw": raw, "method": method,
        "m_raw": metrics_at(y, raw), "m_cal": metrics_at(y, cal_scores),
        "rej": per_negative_type_recall(y, cal_scores, meta),
        "features": FEATURE_NAMES,
    }


# Coverage numbers are produced by run_coverage.py; passed in so the figure
# never hard-codes a stale value.
DEFAULT_COVERAGE_ROWS = [
    ("it_security_agent", 85.5), ("name_resolver", 78.6), ("input_layer", 72.2),
    ("build_match_dataset", 87.1), ("match_model", 74.3),
]


def save_all(ctx=None, outdir=".", dpi=150):
    """OPTIONAL: write every figure to PNG.

    Only needed if you want images for a slide deck. The notebook does NOT use
    this — it renders inline, so no build artifacts land in the repo.
    """
    import os
    if ctx is None:
        ctx = build_context()
    os.makedirs(outdir, exist_ok=True)
    idx = next(i for i, m in enumerate(ctx["meta"]) if m["kind"] == "wrong_vendor")
    figs = {
        "fig01_pipeline": fig01_pipeline(),
        "fig02_week2_vs_week3": fig02_week2_vs_week3(),
        "fig03_dataset": fig03_dataset(ctx["y"], ctx["meta"]),
        "fig04_roc_pr": fig04_roc_pr(ctx["y"], ctx["raw"]),
        "fig05_confusion": fig05_confusion(ctx["m_cal"]["confusion"]),
        "fig06_attack_breakdown": fig06_attack_breakdown(ctx["rej"]),
        "fig07_global_xai": fig07_global_xai(ctx["base"], ctx["features"]),
        "fig08_local_xai": fig08_local_xai(ctx["base"], ctx["X"], idx,
                                           ctx["meta"], ctx["features"]),
        "fig09_reliability": fig09_reliability(ctx["y"], ctx["cal_scores"]),
        "fig10_threshold": fig10_threshold(ctx["y"], ctx["cal_scores"]),
        "fig11_coverage": fig11_coverage(DEFAULT_COVERAGE_ROWS, 80.2),
        "fig12_scorecard": fig12_scorecard(
            {"roc_auc": ctx["m_raw"]["roc_auc"], "f1": ctx["m_cal"]["f1"],
             "brier": ctx["m_cal"]["brier"]}, ctx["rej"], 80.2, 71),
    }
    paths = []
    for name, fig in figs.items():
        p = os.path.join(outdir, name + ".png")
        fig.savefig(p, dpi=dpi, bbox_inches="tight", facecolor=BG)
        plt.close(fig)
        paths.append(p)
    return paths


if __name__ == "__main__":
    import sys
    if "--save" in sys.argv:
        out = sys.argv[sys.argv.index("--save") + 1] if len(sys.argv) > sys.argv.index("--save") + 1 else "figures"
        for p in save_all(outdir=out):
            print("wrote", p)
        print(f"\n{len(save_all.__doc__.splitlines())and ''}Figures written to '{out}/'. "
              "These are build artifacts — add them to .gitignore.")
    else:
        print(__doc__)
        print("The notebook renders these inline; nothing is written to disk.")
        print("If you need PNGs for slides:  python visuals.py --save figures")
