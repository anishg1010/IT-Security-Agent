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

## Architecture — in detail

The system is a **deterministic five-stage pipeline**, not an autonomous agent.
This is a deliberate choice: in security, every decision must be auditable and a
human must stay in the loop wherever the model is unsure. An autonomous agent
optimises for *minimal* human involvement — the wrong objective when a missed
vulnerability means a breach.

```
  ┌─────────┐   ┌─────────┐   ┌────────┐   ┌──────────────┐   ┌─────────┐
  │ 1 INPUT │──▶│2 RESOLVE│──▶│3 MATCH │──▶│  4 DECIDE    │──▶│5 EXPLAIN│
  └─────────┘   └─────────┘   └────────┘   └──────────────┘   └─────────┘
   SBOM/image    normalise     find CVEs    is it real? +      why, with
   /typed        the names     in NVD       how urgent?        exact SHAP
```

### Stage 1 — Input  (`input_layer.py`)
Accepts three sources and stamps each with a **trust score** that follows the
data all the way to the routing decision:

| Source | Parser | Trust (confidence) |
|---|---|---|
| CycloneDX / SPDX SBOM | `load_any` | 1.0 (machine-readable) |
| `requirements.txt` / `package.json` | `load_requirements_txt` / `load_package_json` | 1.0 |
| Screenshot (OCR) | `load_image` → tesseract | **0.5** (can misread) |
| Typed manually | `load_manual` | 0.8 |

The trust score is the responsible-AI hinge: a screenshot can never be trusted
like a signed SBOM, so it enters at 0.5 and, by construction, is routed to human
review in stage 4.

### Stage 2 — Resolve  (`name_resolver.py`)
Software names are inconsistent. `log4j-core`, `apache-log4j`, and
`pkg:maven/org.apache.logging.log4j/log4j-core` all mean the same library. This
stage normalises aliases, package-URL (purl) coordinates, and Maven coordinates
to a canonical `(vendor, product, version)` triple so matching can work.

### Stage 3 — Match  (`it_security_agent.py`)
For each component, find NVD records whose CPE (Common Platform Enumeration)
entry covers it: same vendor, same product, and a version inside the vulnerable
range. Two matching paths:
- **CPE path** — the structured, reliable path (1,242 of 2,000 records).
- **Fallback path** — for the 744 records that have `affected[]` data but *no*
  CPE. Weaker signal, and the model learns to discount it (see stage 4).

Version ranges handle the four NVD range operators
(`versionStart/EndIncluding/Excluding`) plus exact and wildcard versions.

### Stage 4 — Decide  (`match_model.py` + `threat_intel.py` + `triage.py`)
Two **separate** questions, deliberately never collapsed into one number:

**(a) Is this match real?** — `match_model.py`
A logistic-regression **classifier** trained on 1,370 labelled
`(component, CVE)` pairs. Output is a calibrated probability 0–1 — this is the
"confidence". Eight transparent features (name/vendor/version signals). Isotonic
calibration so 0.8 genuinely means "right ~80% of the time". Cross-validated:
ROC-AUC 0.96, F1 0.87.

**(b) How urgent is it?** — `threat_intel.py`
Combines four signals that answer four different questions:

| Signal | Source | Question |
|---|---|---|
| CVSS | NVD | how bad *if* exploited? |
| KEV | CISA | is it exploited *right now*? (fact list) |
| EPSS | FIRST | how *likely* is exploitation? (ML model) |
| CWE | NVD | what *kind* of weakness? |

Priority bands: ACT NOW → SCHEDULE → MONITOR → BACKLOG.

**(c) Route it** — `triage.py`
Confidence decides who acts:

| Confidence | Route | Meaning |
|---|---|---|
| ≥ 0.85 | AUTO | raise a ticket automatically |
| 0.50–0.85 | SUGGEST | show it, human confirms |
| < 0.50 | FLAG | human review, never auto-act |

Confidence (is it real?) and priority (how urgent?) are reported **separately**.
Collapsing them into one score would hide uncertainty from the person who has to
act — "urgent but unsure" and "certain but trivial" are different situations.

### Stage 5 — Explain  (`xai.py`)
For any decision, exact closed-form SHAP values show which feature drove it:
`φ_i = w_i · (x_i − E[x_i])`. Not a sampled approximation — exact, and verified
in the test suite (`Σφ + base = logit`). A security engineer can defend every
alert.

### The two interfaces  (`scan_cli.py`, `app.py`)
Same engine, two front doors for the same user (a security engineer):
- **CLI** — for pipelines and terminals. Composable (`--json | jq`), returns a
  CI exit code keyed on ACT NOW findings only.
- **Streamlit** — for investigation. Upload, rank, click for reasoning, toggle
  live-feed refresh.

---

## Code flow — in detail

What actually happens, in order, when a scan runs (this is the path through the
notebook, the CLI, and the app — they all share it):

```
1. INGEST
   input_layer.load_any(file)
     → detects CycloneDX / SPDX / requirements / image
     → returns IngestResult(components, warnings, source, confidence)

2. RESOLVE  (inside the matcher, per component)
   name_resolver.resolve_component(name, version, vendor)
     → canonical (vendor, product, version)

3. LOAD DATA
   it_security_agent.load_nvd_feed("nvd_real_bulk.json")   → 2000 records
   threat_intel.load_threat_intel(kev_path, epss_path)     → KEV set + EPSS map
     → if a feed is missing: warn loudly, continue in DEGRADED mode

4. MATCH
   it_security_agent.scan(components, records)
     → for each component: match_component() (CPE path)
                           match_component_fallback() (affected[] path)
     → RiskReport(matches, components_unmatched)

5. DECIDE + RANK
   triage.build_findings(report, records, intel, raw_nvd)
     → for each match:
         confidence = model probability (match_model)   "is it real?"
         band, reason = threat_intel.priority(cve, cvss, intel)  "how urgent?"
         routing = route(confidence)                     AUTO / SUGGEST / FLAG
     → rank(): sort by band, then EPSS, then CVSS, then confidence
       (confidence is the LAST tiebreak — an urgent-but-unsure finding must not
        be buried below a certain-but-trivial one)

6. PRESENT
   CLI  → print_human() / --json / --csv,  exit code from ACT NOW count
   app  → ranked list, expanders with per-finding explanation
   nb   → inline figures from visuals.py, live from the model

7. EXPLAIN (on demand)
   xai.explain_row(model, X, i)  → exact SHAP contributions per feature
```

**Degraded mode is a first-class path, not an error.** If KEV/EPSS are absent,
the pipeline still completes — it just prioritises on CVSS alone and says so.
A tool that silently loses a signal is more dangerous than one that fails loudly.

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
