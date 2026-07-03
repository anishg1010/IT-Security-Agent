Data flow.

    A[Input Layer<br/>SBOM / Screenshot / Manual Input]

    A --> B[Extraction Layer<br/>Parser / OCR / Text Cleaning]

    B --> C[Software Matching<br/>CPE + Version Detection]

    C --> D[NVD Retrieval Engine<br/>CVE + CVSS + CWE]

    D --> E[Threat Intelligence Layer<br/>KEV + EPSS + MITRE]

    E --> F[LLM Reasoning Engine<br/>Risk Analysis + Recommendation]

    F --> G[Responsible AI Layer<br/>Bias Audit + Confidence + Explainability]

    G --> H[Audit Logs & Compliance]

    H --> I[Final Dashboard / Vulnerability Report]


    
Project structure

.
├── it_security_agent.py          # Core matcher: loading, normalizing, matching, scoring
├── visualize_analysis.py         # Data analysis + chart generation
├── week1_it_security_agent.ipynb # Main notebook deliverable (self-contained)
├── fetch_nvd_data.py             # Pulls real bulk CVE data from the live NVD API
├── sample_sbom.json              # Small hand-built test SBOM (safe to commit)
├── nvd_sample.json               # Tiny fabricated 2-CVE fixture, for quick unit testing
├── .gitignore
└── README.md

nvd_real_bulk.json (the real 2000-record pull) is intentionally not committed by default — see .gitignore. Regenerate it locally with fetch_nvd_data.py.


Setup

bashpython3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows

pip install --upgrade pip
pip install matplotlib jupyter ipykernel requests


Usage

1. Get real NVD data

bashpython fetch_nvd_data.py

Pulls the last 30 days of real CVEs from the live NVD API (rate-limited to 5 req/30s without a key; get a free key at nvd.nist.gov/developers/request-an-api-key for 50 req/30s).

2. Run the matcher from the command line

bashpython it_security_agent.py --nvd nvd_real_bulk.json --sbom sample_sbom.json

3. Run the full analysis + charts

bashpython visualize_analysis.py --nvd nvd_real_bulk.json --sbom sample_sbom.json --outdir .

4. Or open the notebook

bashjupyter notebook week1_it_security_agent.ipynb

(Or open it directly in VS Code with the Jupyter extension — select the venv kernel, then Run All.)


