# Week 3 — IT Security Agent

**This folder is self-contained.** Nothing from your Week 1 / Week 2 folders is
needed — the engine files they share are already copied in here.

---

## Quick start

```bash
cd week3
pip install -r requirements.txt      # numpy, scikit-learn, matplotlib, joblib

python -m unittest test_agent        # 1. run the 71 tests
python run_coverage.py               # 2. prove >=80% coverage
python match_model.py                # 3. train + calibrate the model
jupyter notebook week3_it_security_agent.ipynb   # 4. the deliverable
```

**The figures render inline in the notebook — there are no PNGs in this repo.**
Generated images are build artifacts, not source, so they are `.gitignore`d.
Every chart is drawn live from the trained model when you run the notebook,
which also means it can never drift out of sync with the numbers.

If you need images for a slide deck:

```bash
python visuals.py --save figures     # writes figures/ (gitignored)
```

Expected output:

| Command | Expect |
|---|---|
| `python -m unittest test_agent` | `Ran 71 tests ... OK` |
| `python run_coverage.py` | `TOTAL ... 80.2%` → `PASS: 80.2% >= 80%` |
| `python match_model.py` | `ROC-AUC 0.966  PR-AUC 0.946`, F1 ≈ 0.88 |

If you only run one thing for the grader: **the notebook**. It runs the tests
and the coverage check inside itself.

---

## What each file is

### New in Week 3 — the actual work
| File | Role |
|---|---|
| `week3_it_security_agent.ipynb` | **The deliverable.** Critique of Week 2 → real model → XAI → tests → model card. |
| `build_match_dataset.py` | Builds the labelled `(component, CVE)` match-decision dataset: 369 true matches + 800 adversarial negatives, with ingestion noise. **This is what Week 2 was missing.** |
| `match_model.py` | Trains + calibrates the classifier (logistic regression shipped; GBDT as challenger). Cross-validated metrics. |
| `xai.py` | Exact closed-form SHAP for the linear model (the explanation engine). |
| `visuals.py` | The 12 presentation figures. Each answers one question a reviewer will ask. Functions **return** figures (render inline); nothing is written unless you pass `--save`. |
| `test_agent.py` | 71 tests organised by failure mode. Stdlib `unittest` only. |
| `run_coverage.py` | Coverage via stdlib `trace`. No `coverage.py` needed. |

### The 12 figures — and the question each one answers
| Figure | Answers |
|---|---|
| `fig01_pipeline` | What does this system actually do? |
| `fig02_week2_vs_week3` | What changed since last week? |
| `fig03_dataset` | Where did your labels come from? |
| `fig04_roc_pr` | Is the model actually good? |
| `fig05_confusion` | What kind of mistakes does it make? |
| `fig06_attack_breakdown` | **Which attacks fool it?** (the honest one) |
| `fig07_global_xai` | What does the model rely on? |
| `fig08_local_xai` | Why did it make *this* decision? |
| `fig09_reliability` | When it says 80%, is it right 80%? |
| `fig10_threshold` | Where should we set the alarm? |
| `fig11_coverage` | Did you test it properly? |
| `fig12_scorecard` | Summarise it in one slide. |

These render **inline in the notebook**. To export as PNGs for slides:
`python visuals.py --save figures`.

### Reused from Week 1/2 (unchanged — already copied in)
| File | Role |
|---|---|
| `it_security_agent.py` | CPE parsing, version ranges, matcher, fallback, reporting. |
| `name_resolver.py` | Alias / purl / Maven name normalisation. |
| `input_layer.py` | SBOM / requirements / package.json / OCR ingestion + confidence. |
| `evaluate.py`, `eval_set.json` | Week 2 evaluation harness (kept for comparison). |

### Data & generated artifacts
| File | Role |
|---|---|
| `nvd_real_bulk.json` | **Required.** 2000 real NVD records — the model trains on this. |
| `nvd_sample.json` | Small fixture used by tests. |
| `sample_cyclonedx_sbom.json`, `sample_spdx_sbom.json` | SBOM fixtures used by tests. |
**Not committed (all `.gitignore`d, all regenerable):**
`match_dataset.json` (`python build_match_dataset.py`), `match_model.joblib`
(`python match_model.py`), and any `fig*.png` (`python visuals.py --save figures`).
The notebook needs none of them — it builds what it needs on the fly.

---

## Dependency map

```
it_security_agent.py   (no local deps — the base engine)
        ▲
        ├── name_resolver.py      (used via Component.normalized)
        ├── input_layer.py        (independent ingestion funnel)
        │
build_match_dataset.py  ──imports──▶ it_security_agent
        ▲
match_model.py          ──imports──▶ build_match_dataset, it_security_agent
        ▲
xai.py                  ──imports──▶ build_match_dataset, match_model
        ▲
test_agent.py           ──imports──▶ all of the above
week3_...ipynb          ──imports──▶ all of the above
```

**Minimum set to train the model:** `it_security_agent.py`,
`build_match_dataset.py`, `match_model.py`, `nvd_real_bulk.json`.

---

## Troubleshooting

- **`ModuleNotFoundError: sklearn`** → `pip install scikit-learn` (the import
  name differs from the package name).
- **`FileNotFoundError: nvd_real_bulk.json`** → run commands *from inside* the
  `week3` folder; the paths are relative.
- **OCR warnings in tests** → expected and harmless. The image path degrades
  gracefully; tests assert that behaviour rather than requiring tesseract.
- **Numbers differ slightly from the notebook** → the dataset builder is seeded
  (`seed=1234`), so it should be stable. Regenerating with a different seed
  changes the sample, not the conclusions.
