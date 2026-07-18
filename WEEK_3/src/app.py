"""
app.py  —  Streamlit interface for the IT Security Agent
=======================================================

WHO IT IS FOR
-------------
The same security engineer the CLI serves, but in "exploration" mode: upload an
SBOM, see the triaged findings ranked by real-world urgency, click any finding
to see WHY the model decided what it did (the SHAP explanation), and adjust the
refresh / threshold controls.

The CLI is the tool that runs in a pipeline; this is the tool you open to
investigate. Same engine underneath — this file only draws; it does not decide.

RUN IT
    cd WEEK_3
    pip install streamlit
    streamlit run src/app.py

DESIGN SEPARATION (so the logic is testable without a browser)
--------------------------------------------------------------
All the actual work lives in `run_scan()`, a pure function returning plain data.
The Streamlit calls below just render what it returns. That means the test suite
can exercise the app's behaviour without launching a server — and it does.
"""
from __future__ import annotations

import json
from pathlib import Path

# make src/ + data/ + feeds/ importable no matter where streamlit is launched
import sys
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))
try:
    import paths  # noqa: F401
    _NVD = paths.NVD_BULK
    _KEV = paths.KEV
    _EPSS = paths.EPSS
except Exception:
    _NVD = str(_HERE.parent / "data" / "nvd_real_bulk.json")
    _KEV = str(_HERE.parent / "feeds" / "known_exploited_vulnerabilities.json")
    _EPSS = str(_HERE.parent / "feeds" / "epss_scores-current.csv.gz")

import it_security_agent as agent
import threat_intel as ti
import triage as tri


# ---------------------------------------------------------------------------
# LOGIC CORE — pure, no Streamlit, unit-testable
# ---------------------------------------------------------------------------

def run_scan(components, nvd_path=_NVD, kev_path=_KEV, epss_path=_EPSS,
             input_confidence=1.0, source="sbom", refresh_live=False):
    """Scan components and return (findings, summary, intel, notes).

    This is the whole app in one function. Streamlit just displays the result.
    `refresh_live` controls whether we try to pull fresh KEV/EPSS first — the
    toggle the user asked for. It is OFF by default: use what is on disk unless
    the user explicitly asks to refresh, so a time-pressed demo is never blocked
    on the network.
    """
    notes = []

    if refresh_live:
        try:
            import feeds_live
            notes.extend(feeds_live.refresh_feeds(kev_path, epss_path, live=True))
        except Exception as e:
            notes.append(f"live refresh skipped ({type(e).__name__}) — using cached feeds")
    else:
        notes.append("using cached feeds (no live refresh)")

    records = agent.load_nvd_feed(nvd_path)
    try:
        raw = json.load(open(nvd_path, encoding="utf-8"))["vulnerabilities"]
    except Exception:
        raw = None
    intel = ti.load_threat_intel(kev_path, epss_path)

    report = agent.scan(components, records)
    findings = tri.build_findings(report, records, intel, raw_nvd=raw,
                                  input_confidence=input_confidence, source=source)
    return findings, tri.summarize(findings), intel, notes


def load_components_from_bytes(data: bytes, filename: str):
    """Turn an uploaded file's bytes into components + provenance."""
    import tempfile, os
    import input_layer as il
    suffix = Path(filename).suffix or ".json"
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data); os.close(fd)
    try:
        if suffix.lower() in (".png", ".jpg", ".jpeg"):
            res = il.load_image(tmp)
            return res.components, res.warnings, "ocr", 0.5
        res = il.load_any(tmp)
        return res.components, res.warnings, "sbom", 1.0
    finally:
        os.unlink(tmp)


BAND_EMOJI = {"ACT NOW": "🔴", "SCHEDULE": "🟠", "MONITOR": "🔵", "BACKLOG": "⚪"}
ROUTE_EMOJI = {"AUTO": "🟢", "SUGGEST": "🟡", "FLAG": "🔴"}


# ---------------------------------------------------------------------------
# UI — everything below runs only under `streamlit run`
# ---------------------------------------------------------------------------

def _main():
    import streamlit as st

    st.set_page_config(page_title="IT Security Agent", page_icon="🛡️",
                       layout="wide")

    st.title("🛡️ IT Security Agent")
    st.caption("Upload an SBOM → see what to fix **first**, and **why**. "
               "Decision-support for a security engineer — not automation.")

    # ---- sidebar: the controls the user asked for ----
    with st.sidebar:
        st.header("Scan settings")
        refresh = st.toggle(
            "Refresh threat feeds live", value=False,
            help="ON: pull today's KEV/EPSS from CISA/FIRST (needs internet). "
                 "OFF: use the cached files — fast, works offline. "
                 "Leave OFF if you're short on time.")
        st.divider()
        st.subheader("Routing thresholds")
        st.caption("Confidence bands decide whether a finding is auto-actioned "
                   "or sent for human review.")
        st.markdown(
            f"- 🟢 **AUTO** ≥ {tri.AUTO_THRESHOLD:.2f}\n"
            f"- 🟡 **SUGGEST** {tri.SUGGEST_THRESHOLD:.2f}–{tri.AUTO_THRESHOLD:.2f}\n"
            f"- 🔴 **FLAG** < {tri.SUGGEST_THRESHOLD:.2f} (human review)")
        st.divider()
        st.caption("⚠️ 'No match' means no *known* CVE — never proof of safety.")

    # ---- input ----
    tab_upload, tab_sample, tab_manual = st.tabs(
        ["📤 Upload SBOM", "📋 Use a sample", "⌨️ Type a component"])

    components, warnings, source, in_conf = [], [], "sbom", 1.0

    with tab_upload:
        up = st.file_uploader("CycloneDX / SPDX / requirements.txt / screenshot",
                              type=["json", "txt", "png", "jpg", "jpeg"])
        if up is not None:
            components, warnings, source, in_conf = load_components_from_bytes(
                up.read(), up.name)
            st.success(f"Read {len(components)} components from {up.name}")

    with tab_sample:
        sample = st.selectbox("Sample SBOM",
                              ["sample_cyclonedx_sbom.json", "sample_spdx_sbom.json"])
        if st.button("Scan sample"):
            import input_layer as il
            p = str(_HERE.parent / "data" / sample)
            res = il.load_any(p)
            components, warnings, source, in_conf = res.components, res.warnings, "sbom", 1.0

    with tab_manual:
        name = st.text_input("Component name", "log4j-core")
        col1, col2 = st.columns(2)
        version = col1.text_input("Version", "2.14.1")
        vendor = col2.text_input("Vendor", "apache")
        if st.button("Scan component"):
            import input_layer as il
            res = il.load_manual(f"{name} {version} {vendor}")
            components, warnings, source, in_conf = res.components, res.warnings, "manual", 0.8

    if not components:
        st.info("Upload an SBOM, pick a sample, or type a component to begin.")
        return

    # ---- run ----
    findings, summary, intel, notes = run_scan(
        components, input_confidence=in_conf, source=source, refresh_live=refresh)

    for n in notes:
        st.caption("• " + n)
    if intel.warnings:
        for w in intel.warnings:
            st.warning(w)
        st.warning("Running in DEGRADED mode: prioritising on CVSS alone.")

    # ---- headline ----
    st.subheader("Triage")
    st.markdown(f"### {tri.triage_message(findings).splitlines()[0]}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🔴 Act now", summary["ACT NOW"])
    c2.metric("🟠 Schedule", summary["SCHEDULE"])
    c3.metric("🔵 Monitor", summary["MONITOR"])
    c4.metric("⚪ Backlog", summary["BACKLOG"])
    st.caption(f"{summary['critical_or_high']} of {summary['total']} are CVSS "
               f"HIGH/CRITICAL — but only {summary['ACT NOW']} are confirmed "
               f"exploited. **Severity is not priority.**")

    # ---- findings table + per-finding explanation ----
    st.subheader("Findings")
    for f in findings:
        emoji = BAND_EMOJI.get(f.band, "")
        kev = " 🔥KEV" if f.on_kev else ""
        title = (f"{emoji} **{f.band}** · {f.cve_id} · {f.component} "
                 f"{f.version}{kev}  ·  {ROUTE_EMOJI.get(f.routing,'')} {f.routing}")
        with st.expander(title):
            a, b = st.columns(2)
            a.markdown(f"**Why this priority**\n\n{f.band_reason}")
            a.markdown(f"**Match confidence:** {f.confidence:.2f} → "
                       f"**{f.routing}**")
            if f.cvss is not None:
                b.metric("CVSS", f.cvss, f.severity)
            if f.epss is not None:
                b.metric("EPSS (30-day exploit prob.)", f"{f.epss:.1%}")
            if f.cwes:
                st.markdown("**Weakness types:** " + ", ".join(f.cwe_labels[:4]))
            if f.match_reason:
                st.caption("Matched because: " + f.match_reason)

    # ---- export ----
    st.download_button(
        "⬇️ Download findings as JSON",
        json.dumps([{
            "cve": f.cve_id, "component": f.component, "version": f.version,
            "priority": f.band, "cvss": f.cvss, "epss": f.epss,
            "on_kev": f.on_kev, "confidence": f.confidence, "routing": f.routing,
        } for f in findings], indent=2),
        file_name="findings.json", mime="application/json")


if __name__ == "__main__":
    # Only import/launch Streamlit when actually run via `streamlit run`.
    try:
        _main()
    except ModuleNotFoundError as e:
        if "streamlit" in str(e):
            print("Streamlit is not installed. Install it with:\n"
                  "    pip install streamlit\n"
                  "then run:\n"
                  "    streamlit run src/app.py")
        else:
            raise
