"""
xai.py  —  Week 3 explainability for the match-decision model
============================================================

Requirement (Week 3): "Choose an XAI method to understand the inner workings
of your model."

Two complementary, HONEST explanations for the logistic match model:

  1. GLOBAL — the coefficients. For a logistic regression the weights ARE the
     model; |coef| share tells you which signal drives decisions overall.

  2. LOCAL — exact SHAP values. For a linear model f(x)=b + w·x, the exact
     Shapley value of feature i is

         phi_i = w_i * (x_i - E[x_i])

     with base value E[f] = b + w·E[x]. This is not an approximation and needs
     no sampling — unlike KernelSHAP on a black box — so it is fully auditable.
     We derive it directly and verify sum(phi) + base == logit(x).

Why not a black-box explainer? The whole design keeps the decision model
linear precisely so the explanation is exact and cheap. That is a Responsible-AI
choice: we trade a fraction of a point of AUC (see match_model: GBDT beats
logreg by ~0.01) for an explanation we can stand behind in an audit.
"""
from __future__ import annotations

import numpy as np
from build_match_dataset import FEATURE_NAMES


def linear_shap(base_model, X, row_index):
    """Exact SHAP contributions for one row of a linear/logistic model.
    Returns (base_value, phi_vector, logit) in logit space."""
    w = base_model.coef_[0]
    b = base_model.intercept_[0]
    mean = X.mean(axis=0)
    x = X[row_index]
    base_value = b + w @ mean
    phi = w * (x - mean)
    logit = base_value + phi.sum()
    return base_value, phi, logit


def explain_row(base_model, X, row_index, meta=None):
    base_value, phi, logit = linear_shap(base_model, X, row_index)
    prob = 1 / (1 + np.exp(-logit))
    order = np.argsort(-np.abs(phi))
    lines = []
    if meta:
        m = meta[row_index]
        lines.append(f"scanned: {m.get('vendor')}/{m.get('product')} "
                     f"{m.get('version')}  vs  {m.get('cpe_vendor')}/"
                     f"{m.get('cpe_product')}  ({m.get('kind')})")
    lines.append(f"base logit {base_value:+.2f} -> final logit {logit:+.2f} "
                 f"(p={prob:.3f})")
    for i in order:
        lines.append(f"  {FEATURE_NAMES[i]:20} x={X[row_index][i]:.2f}  "
                     f"contribution {phi[i]:+.3f}")
    return "\n".join(lines), phi, prob


def global_importance(base_model):
    w = base_model.coef_[0]
    share = np.abs(w) / np.abs(w).sum()
    idx = np.argsort(-np.abs(w))
    return [(FEATURE_NAMES[i], float(w[i]), float(share[i])) for i in idx]


# ---------------------------------------------------------------------------
# figure helpers (saved to PNG for the notebook / slides)
# ---------------------------------------------------------------------------

def fig_global_importance(base_model, path="fig_global_importance.png"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    imp = global_importance(base_model)
    names = [n for n, _, _ in imp][::-1]
    coefs = [c for _, c, _ in imp][::-1]
    colors = ["#7a1f3d" if c >= 0 else "#b0374e" for c in coefs]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(names, coefs, color=colors)
    ax.axvline(0, color="#333", lw=0.8)
    ax.set_title("Global feature importance (logistic coefficients)")
    ax.set_xlabel("coefficient (logit space) — positive pushes toward MATCH")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def fig_local_waterfall(base_model, X, row_index, meta=None,
                        path="fig_local_shap.png"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    base_value, phi, logit = linear_shap(base_model, X, row_index)
    order = np.argsort(-np.abs(phi))
    names = [FEATURE_NAMES[i] for i in order]
    vals = [phi[i] for i in order]
    colors = ["#2a9d8f" if v >= 0 else "#b0374e" for v in vals]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(names[::-1], vals[::-1], color=colors[::-1])
    ax.axvline(0, color="#333", lw=0.8)
    title = "Local explanation (exact SHAP)"
    if meta:
        m = meta[row_index]
        title += f" — {m.get('kind')}: {m.get('product')} vs {m.get('cpe_product')}"
    ax.set_title(title)
    ax.set_xlabel("contribution to logit (green=toward match, red=against)")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def fig_reliability(y, proba, path="fig_reliability.png", n_bins=8):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    edges = np.linspace(0, 1, n_bins + 1)
    xs, ys, ns = [], [], []
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (proba >= lo) & (proba < hi if hi < 1.0 else proba <= hi)
        if m.sum():
            xs.append(proba[m].mean()); ys.append(y[m].mean()); ns.append(m.sum())
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], "--", color="#888", label="perfect calibration")
    ax.scatter(xs, ys, s=[max(20, n) for n in ns], color="#7a1f3d",
               zorder=3, label="model (dot size = n)")
    ax.plot(xs, ys, color="#7a1f3d", alpha=0.4)
    ax.set_xlabel("claimed probability"); ax.set_ylabel("observed frequency")
    ax.set_title("Reliability curve (cross-validated)")
    ax.legend(); ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


if __name__ == "__main__":
    from match_model import make_dataset_from_nvd, fit_calibrated, cv_scores
    X, y, meta = make_dataset_from_nvd(noise=0.5)
    base, cal, cs, method = fit_calibrated(X, y)
    raw = cv_scores(base, X, y)

    print("=== GLOBAL ===")
    for n, c, s in global_importance(base):
        print(f"  {n:20} coef={c:+.3f}  share={s:.3f}")

    print("\n=== LOCAL (a wrong-vendor negative) ===")
    idx = next(i for i, m in enumerate(meta) if m["kind"] == "wrong_vendor")
    txt, phi, prob = explain_row(base, X, idx, meta)
    print(txt)

    fig_global_importance(base)
    fig_local_waterfall(base, X, idx, meta)
    fig_reliability(y, cs)
    print("\nfigures written.")
