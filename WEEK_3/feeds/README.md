# Threat-intel feeds — download these

This folder is **empty on purpose**. The two feeds below are downloaded, not
generated, and they change daily upstream — so they are not shipped with the
code. The agent runs without them and warns that it is prioritising on CVSS
alone.

## 1. CISA KEV — Known Exploited Vulnerabilities

<https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>

Opens as JSON in the browser. Save it here as:

    known_exploited_vulnerabilities.json

**What it is:** a curated list of CVEs CISA has *confirmed* are being exploited
in the wild. It is a FACT list, not a prediction, and it is the single
highest-value prioritisation signal available.

**Caveat for the model card:** absence from KEV does **not** mean "not
exploited" — only "CISA has not confirmed it". The catalog is also biased
toward software used by US federal agencies.

## 2. EPSS — Exploit Prediction Scoring System (FIRST)

<https://epss.empiricalsecurity.com/epss_scores-current.csv.gz>

Downloads as a `.gz`. **Leave it compressed** — Python reads it directly. Save
it here as:

    epss_scores-current.csv.gz

**What it is:** a probability (0–1) that a CVE will be exploited in the next 30
days.

**Caveat for the model card:** EPSS is itself a **machine-learning model**.
Consuming it means chaining a model onto our model and inheriting its biases
and errors. Disclose this rather than hiding it.

**Format gotcha:** the first line is a comment (`#model_version:...`) and the
real header is on line 2. A naive CSV parser treats the comment as the header
and silently returns garbage. `threat_intel.py` skips `#` lines — and there is
a test that guards this.

## Verify

```bash
cd ../src
python threat_intel.py
```

Expect something like:

    KEV: 1200+ exploited CVEs | EPSS: 250000+ scored CVEs

If a feed is missing you will see a loud WARNING and the agent will run in
degraded mode. That is by design: a tool that silently loses a signal is more
dangerous than one that fails.

*(URLs verified as of the project date — if one 404s, search for "CISA KEV
catalog JSON" or "EPSS download".)*
