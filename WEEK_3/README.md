# WEEK 3 — IT Security Agent

**Responsible AI & Data Ethics — SS2026**

A vulnerability-scanning agent that reads SBOMs (or screenshots), matches
components against NVD, and **triages** the results so a security engineer
knows what to fix first.

---

## Quick start

```bash
cd WEEK_3
pip install -r requirements.txt

# 1. the deliverable — open and Run All
jupyter notebook week3_it_security_agent.ipynb

# 2. the tests (from tests/)
cd tests
python -m unittest test_agent          # 107 tests -> OK
python run_coverage.py                 # 81.9% -> PASS

# 3. the CLI (from src/)
cd ../src
python scan_cli.py --sbom ../data/sample_cyclonedx_sbom.json

# 4. the Streamlit UI (from WEEK_3/)
pip install streamlit
streamlit run src/app.py        # or: ./run_app.sh  (Windows: run_app.bat)
```

Everything works from any directory — `paths.py` resolves file locations, so
you never have to be in a specific folder.

---

## Folder structure

```
WEEK_3/
├── week3_it_security_agent.ipynb   ← THE DELIVERABLE (open this first)
├── paths.py                        ← makes src/ importable, finds data/
├── requirements.txt
├── README.md
│
├── src/                            ← the system
│   ├── it_security_agent.py          CPE parsing, version ranges, matcher
│   ├── name_resolver.py              alias / purl / Maven normalisation
│   ├── input_layer.py                SBOM / requirements / OCR ingestion
│   ├── build_match_dataset.py        builds the labelled training set
│   ├── match_model.py                trains + calibrates the classifier
│   ├── xai.py                        exact closed-form SHAP
│   ├── threat_intel.py               KEV + EPSS + CWE enrichment
│   ├── triage.py                     detection -> decision (the priority layer)
│   ├── feeds_live.py                 optional live KEV/EPSS fetch + NVD delta
│   ├── visuals.py                    the 12 inline figures
│   ├── scan_cli.py                   the security engineer's CLI
│   └── app.py                        the Streamlit exploration UI
│
├── tests/
│   ├── test_agent.py                 107 tests, organised by failure mode
│   └── run_coverage.py               coverage via stdlib trace (no pip needed)
│
├── data/                           ← inputs + fixtures (committed on purpose)
│   ├── nvd_real_bulk.json            2,000 real NVD records — the input data
│   ├── nvd_sample.json               small fixture for tests
│   ├── sample_cyclonedx_sbom.json
│   ├── sample_spdx_sbom.json
│   └── eval_set.json                 Week 2 eval set (kept for comparison)
│
├── feeds/                          ← threat intel (download these)
│   ├── known_exploited_vulnerabilities.json
│   └── epss_scores-current.csv.gz
│
└── docs/
    └── evaluate.py                   Week 2 harness (kept for comparison)
```

---

## Threat-intel feeds

The agent runs **without** these — it just warns that it is prioritising on
CVSS alone. To enable the full triage, either download them into `feeds/` (see
`feeds/README.md`) or fetch them **live**:

```bash
cd src
python feeds_live.py        # refreshes KEV + EPSS live, falls back to local
```

### Live vs snapshot — a deliberate choice

| Feed | Strategy | Why |
|---|---|---|
| **KEV** (CISA) | live-refresh, local fallback | small, key-less, reliable |
| **EPSS** (FIRST) | live-refresh, local fallback | single CSV, no key |
| **NVD** | **snapshot, not live** | 211k CVEs, rate-limited, often slow/503 |

Fetching KEV/EPSS live means the triage reflects *today's* exploited-vuln list.
NVD is kept as a snapshot on purpose: a live pull of the full feed is ~106
paged requests at 6s each (>10 min) and frequently times out — an unacceptable
risk to run during a presentation. `feeds_live.fetch_nvd_delta()` shows how to
pull *only new CVEs* since the snapshot date (the incremental-update pattern a
real tool uses), designed to be run offline, not in a demo.

Live fetching is a **bonus, never a dependency**: any network failure falls
back to the local file with a clear message. Verified by tests that simulate a
dead connection.

---

## What Week 3 delivers

| Requirement | Where | Result |
|---|---|---|
| Analyze your models | §3–§4 | ROC-AUC 0.96, F1 0.87, cross-validated |
| Use XAI | §5 | exact closed-form SHAP, verified `Σφ + base = logit` |
| Tests to detect weaknesses | §6 | 107 tests, organised by failure mode |
| ≥80% code coverage | §6 | **81.9%** |
| **How users interact (Interface?)** | §7 | user, stakeholder harms, routing, CLI |

Plus the thing that makes it a product rather than a scanner: **KEV + EPSS +
CWE prioritisation** (§6b).

---

## The core arguments

**Severity is not priority.** 1,053 of our 2,000 CVEs (53%) are CVSS HIGH or
CRITICAL. That ranking is noise. KEV says which are *actually* being exploited.
A CVSS 7.5 on KEV outranks a CVSS 9.8 nobody is attacking — the CLI shows this
inversion live.

**A perfect score is a symptom, not an achievement.** Week 2 scored 1.00/1.00
because its eval set contained no case it could get wrong. Week 3 builds a
decision that *can* be wrong, then measures exactly where.

**The human stays in the loop where the machine is unsure.** AUTO (≥0.85) /
SUGGEST (0.50–0.85) / FLAG (<0.50). An OCR screenshot carries confidence ≈0.5
by construction, so it lands in FLAG automatically.

**"No match" is never "safe."** It means no *known* CVE. Zero-days are invisible
to any NVD-based tool, and ~34% of our records are not fully enriched by NVD
(563 Deferred + 116 Awaiting Analysis).

---

## Troubleshooting

- **`ModuleNotFoundError: sklearn`** → `pip install scikit-learn` (import name
  differs from package name).
- **`ModuleNotFoundError: it_security_agent`** → the notebook's first cell runs
  `import paths`; make sure you ran it. From a script, `import paths` first.
- **Coverage seems to hang** → it doesn't; `run_coverage.py` scopes tracing to
  our modules only. Use `python run_coverage.py --fast` (~7s) to skip the slow
  GBDT test.
- **KEV/EPSS warnings** → expected if you haven't downloaded the feeds. The
  tool still runs, in degraded mode, and says so.
- **OCR warnings in tests** → expected and harmless; the image path degrades
  gracefully and the tests assert that behaviour.

---

## Regenerating everything

Nothing generated is committed — it is all rebuilt from the code:

```bash
cd src
python build_match_dataset.py     # -> match_dataset.json
python match_model.py             # -> match_model.joblib
python visuals.py --save figures  # -> PNGs (only if you want slide images)
```

The notebook renders its figures **inline** from the live model, so they can
never drift out of sync with the numbers.
