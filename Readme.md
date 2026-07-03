flowchart TD

    A[Input Layer<br/>SBOM / Screenshot / Manual Input]

    A --> B[Extraction Layer<br/>Parser / OCR / Text Cleaning]

    B --> C[Software Matching<br/>CPE + Version Detection]

    C --> D[NVD Retrieval Engine<br/>CVE + CVSS + CWE]

    D --> E[Threat Intelligence Layer<br/>KEV + EPSS + MITRE]

    E --> F[LLM Reasoning Engine<br/>Risk Analysis + Recommendation]

    F --> G[Responsible AI Layer<br/>Bias Audit + Confidence + Explainability]

    G --> H[Audit Logs & Compliance]

    H --> I[Final Dashboard / Vulnerability Report]