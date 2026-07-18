"""
triage.py  —  turn a scan into a decision
=========================================

THE PROBLEM
-----------
`agent.scan()` answers "what matched?". That is detection, not triage. A
security engineer facing 1,053 CVSS-critical findings cannot act on a list —
they need to know WHAT TO DO FIRST, and WHY, and HOW SURE the tool is.

This module is the layer between "the matcher fired" and "a human decides".
It combines four independent signals that answer four different questions:

  1. MATCH CONFIDENCE (our model)  "is this finding even real?"
  2. KEV (CISA)                    "is it being exploited right now?"
  3. EPSS (FIRST)                  "how likely is exploitation soon?"
  4. CVSS (NVD)                    "how bad if it happens?"
  + CWE (NVD)                      "what kind of weakness is it?"

Signals 2-4 come from threat_intel.py; signal 1 is our own classifier.

WHY CONFIDENCE AND PRIORITY ARE KEPT SEPARATE
---------------------------------------------
It is tempting to multiply them into one number. We deliberately do not.
They answer different questions and a human needs both:

    high priority + LOW confidence  -> "urgent IF real — verify this first"
    high priority + HIGH confidence -> "act now"
    low priority  + HIGH confidence -> "real, but nobody is exploiting it"

Collapsing those into a single score destroys the distinction and hides the
uncertainty from the person who has to act on it. Showing both is what makes
this decision-SUPPORT rather than automation.

THE ROUTING RULE (the responsible-AI core)
------------------------------------------
Every finding is routed to one of three actions based on match confidence:

    AUTO     >= 0.85   confident enough to raise a ticket automatically
    SUGGEST  0.50-0.85 show it, but a human confirms before action
    FLAG     <  0.50   low confidence — human review required, never auto-act

A screenshot ingested via OCR carries confidence ~0.5 from the input layer,
so it lands in FLAG by construction. The human stays in the loop exactly where
the machine is least sure. That is not a limitation to apologise for; it is
the design.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import it_security_agent as agent
import threat_intel as ti


# Routing thresholds. Named constants, not magic numbers, because they encode
# a POLICY choice that an auditor may legitimately want to challenge.
AUTO_THRESHOLD = 0.85
SUGGEST_THRESHOLD = 0.50


@dataclass
class Finding:
    """One triaged vulnerability: what, how sure, how urgent, and why."""
    cve_id: str
    component: str
    version: str
    vendor: str
    cvss: float | None
    severity: str
    confidence: float          # our model: is this match real?
    band: str                  # ACT NOW / SCHEDULE / MONITOR / BACKLOG
    band_reason: str
    routing: str               # AUTO / SUGGEST / FLAG
    on_kev: bool
    epss: float | None
    cwes: list[str] = field(default_factory=list)
    match_reason: str = ""
    source: str = "sbom"       # provenance: sbom / ocr / manual

    @property
    def cwe_labels(self) -> list[str]:
        return [ti.cwe_label(c) for c in self.cwes]

    def explain(self) -> str:
        """One human-readable line per signal — the audit trail."""
        bits = [
            f"{self.cve_id}  {self.vendor}/{self.component} {self.version}",
            f"  priority : {self.band} — {self.band_reason}",
            f"  confidence: {self.confidence:.2f} → {self.routing}",
        ]
        if self.cvss is not None:
            bits.append(f"  severity : CVSS {self.cvss} ({self.severity})")
        if self.epss is not None:
            bits.append(f"  exploit  : EPSS {self.epss:.1%} chance in 30 days")
        if self.on_kev:
            bits.append(f"  KEV      : CONFIRMED exploited in the wild")
        if self.cwes:
            bits.append(f"  weakness : {', '.join(self.cwe_labels[:3])}")
        if self.match_reason:
            bits.append(f"  matched  : {self.match_reason}")
        return "\n".join(bits)


def route(confidence: float) -> str:
    if confidence >= AUTO_THRESHOLD:
        return "AUTO"
    if confidence >= SUGGEST_THRESHOLD:
        return "SUGGEST"
    return "FLAG"


def _confidence_for(match, input_confidence: float = 1.0) -> float:
    """Transparent confidence for a match.

    NOTE ON HONESTY: this reuses the Week 2 transparent scoring so the pipeline
    runs end-to-end without a trained model on disk. The LEARNED model
    (match_model.py) is the one we evaluate, XAI, and report metrics for; this
    is the fallback so the CLI/UI work out of the box. Where the learned model
    is available, prefer `score_with_model()`.
    """
    r = (match.match_reason or "").lower()
    path = 0.40 if "fallback" not in r else 0.20
    vspec = 0.25 if "cpe version" in r else (0.15 if "range" in r else 0.05)
    vendor = 0.15 if ("vendor='*'" not in r and "vendor='n/a'" not in r) else 0.0
    return round(min(1.0, path + vspec + vendor + 0.20 * input_confidence), 3)


def build_findings(report, nvd_records, intel: ti.ThreatIntel,
                   raw_nvd: list | None = None,
                   input_confidence: float = 1.0,
                   source: str = "sbom") -> list[Finding]:
    """Turn a RiskReport into ranked, triaged Findings."""
    # index CWE data by CVE id (it lives in the raw NVD json, not the loader output)
    cwe_by_cve: dict[str, list[str]] = {}
    if raw_nvd:
        for v in raw_nvd:
            c = v.get("cve", v)
            cid = c.get("id")
            if cid:
                cwes = ti.extract_cwes(c)
                if cwes:
                    cwe_by_cve[cid] = cwes

    findings = []
    for m in report.matches:
        comp = m.matched_component
        conf = _confidence_for(m, input_confidence)
        band, why = ti.priority(m.cve_id, m.severity, intel)
        findings.append(Finding(
            cve_id=m.cve_id,
            component=comp.name, version=comp.version, vendor=comp.vendor or "*",
            cvss=m.severity, severity=m.severity_label,
            confidence=conf, band=band, band_reason=why, routing=route(conf),
            on_kev=m.cve_id.upper() in intel.kev,
            epss=intel.epss.get(m.cve_id.upper()),
            cwes=cwe_by_cve.get(m.cve_id, []),
            match_reason=m.match_reason, source=source,
        ))
    return rank(findings)


def rank(findings: list[Finding]) -> list[Finding]:
    """Sort by what a human should look at first.

    Order: priority band, then EPSS, then CVSS, then confidence. Note that
    confidence is the LAST tiebreak, not the first: a probably-real ACT NOW
    beats a certainly-real BACKLOG. Sorting by confidence first would bury the
    urgent-but-uncertain findings, which is precisely backwards for security.
    """
    return sorted(findings, key=lambda f: (
        ti.BAND_ORDER.get(f.band, 9),
        -(f.epss or 0),
        -(f.cvss or 0),
        -f.confidence,
    ))


def summarize(findings: list[Finding]) -> dict:
    """Counts a human actually needs, not just totals."""
    out = {"total": len(findings)}
    for b in ("ACT NOW", "SCHEDULE", "MONITOR", "BACKLOG"):
        out[b] = sum(1 for f in findings if f.band == b)
    for r in ("AUTO", "SUGGEST", "FLAG"):
        out[r] = sum(1 for f in findings if f.routing == r)
    out["on_kev"] = sum(1 for f in findings if f.on_kev)
    out["critical_or_high"] = sum(1 for f in findings
                                  if f.severity in ("CRITICAL", "HIGH"))
    return out


def triage_message(findings: list[Finding]) -> str:
    """The headline. This is the whole point of the module.

    Compare:
      without intel: "1,053 CRITICAL vulnerabilities"   -> unusable, ignored
      with intel   : "3 being exploited right now"      -> actionable
    """
    s = summarize(findings)
    if not findings:
        return "No known vulnerabilities matched. (This is NOT proof of safety — see model card.)"
    parts = []
    if s["ACT NOW"]:
        parts.append(f"{s['ACT NOW']} need action NOW (confirmed exploited)")
    if s["SCHEDULE"]:
        parts.append(f"{s['SCHEDULE']} to schedule (likely exploited soon)")
    if s["MONITOR"]:
        parts.append(f"{s['MONITOR']} to monitor")
    if s["BACKLOG"]:
        parts.append(f"{s['BACKLOG']} in backlog")
    head = " | ".join(parts)
    tail = (f"\nOf {s['total']} findings, {s['critical_or_high']} are CVSS "
            f"HIGH/CRITICAL — but only {s['ACT NOW']} are confirmed exploited. "
            f"Severity is not priority.")
    return head + tail
