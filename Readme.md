# IT Security Agent — Responsible AI & Data Ethics (SS2026)

An agent that scans a project for known vulnerabilities. Input is **a picture of
software** *or* **an SBOM** (or a dependency file); it matches components against
the **NVD** vulnerability database and produces an explainable, confidence-scored
risk report.

## What's here

| File | What it is |
|---|---|
| `week1_it_security_agent_clean.ipynb` | Week 1: data analysis, baseline matcher, multi-format input layer, regulatory + risk + model card |
| `week2_it_security_agent.ipynb` | Week 2: confidence-scored model, KEV/EPSS threat intel, quantitative fairness audit, risk register |
| `input_layer.py` | **The scalable input layer** — turns every input type into one `Component` contract |
| `it_security_agent.py` | Core matcher: CPE + version-range + `affected[]` fallback, explainable matches |
| `it_Security_Agent_Week2_Status.pptx` | Week 2 status-meeting deck |
| `sample_cyclonedx_sbom.json` | Industry-standard CycloneDX SBOM (the default demo input) |
| `sample_spdx_sbom.json` | SPDX SBOM sample |
| `sample_sbom.json` | Legacy simple `{components:[...]}` SBOM |
| `sample_requirements.txt` | pip dependency-file sample |
| `sample_screenshot.png` | A picture of software → OCR path demo |

**Not included (large, reproducible):** `nvd_real_bulk.json` — the real 2000-record
NVD batch. Keep it in the same folder as the notebooks. Regenerate anytime with
`fetch_nvd_data.py` (pulls the last 30 days from the live NVD API).

## The input layer (why the project is scalable)

Every input type funnels through `input_layer.load_any(path)` and comes out as a
list of `Component` objects, each tagged with a **source** (provenance) and an
extraction **confidence** in `[0,1]`:

| Input type | Loader | Confidence |
|---|---|---|
| CycloneDX JSON | auto | 1.00 |
| SPDX JSON | auto | 1.00 |
| Simple JSON | auto | 1.00 |
| `requirements.txt` | auto | 0.90 |
| `package.json` | auto | 0.85 |
| Image / screenshot (OCR) | auto | 0.50 |
| Plain text | auto | 0.70 |
| Manual line / list | `load_manual` | 0.80 |

Because the matcher, the risk scoring, and every chart are written **once**
against the `Component` contract, adding a new input format later is one new
`load_*` function plus one line in the registry — nothing downstream changes.

The confidence signal is not cosmetic: deterministic SBOM parses score high and
can be auto-actioned, while OCR-sourced components score low and are routed to
human review (the AUTO / SUGGEST / FLAG bands in Week 2). That is the
responsibility guarantee — the system says *how sure it is* about where each
component came from.

## Run it

```bash
python3 -m venv venv && source venv/bin/activate
pip install matplotlib numpy jupyter pillow pytesseract opencv-python-headless
# OCR path also needs the tesseract binary:  apt install tesseract-ocr

# put nvd_real_bulk.json next to the notebooks (or run fetch_nvd_data.py)
jupyter notebook week1_it_security_agent_clean.ipynb
```

Try any input type from the command line:

```bash
python3 input_layer.py sample_cyclonedx_sbom.json
python3 input_layer.py sample_screenshot.png
python3 input_layer.py sample_requirements.txt
```

## Pipeline

```
INPUT LAYER (input_layer.py)  →  EXTRACTION  →  MATCHING (CPE + affected[])
   →  RISK SCORING (CVSS; Week 2: + KEV/EPSS)
   →  RESPONSIBLE-AI ROUTING (AUTO / SUGGEST / FLAG by confidence)
   →  AUDIT LOG + REPORT
```
