#!/usr/bin/env python3
"""
scan_cli.py  —  the security engineer's interface
=================================================

WHO THIS IS FOR
---------------
A security engineer or DevSecOps analyst triaging a dependency inventory. They
live in terminals and CI pipelines, so the primary interface is a CLI that
prints a ranked, explained answer and returns a meaningful exit code.

WHY A CLI IS THE RIGHT PRIMARY INTERFACE
----------------------------------------
  * It composes: `scan_cli.py --sbom x.json --json | jq ...`
  * It automates: a non-zero exit code fails a CI build on exploited CVEs
  * It is where the user already works — no context switch
The Streamlit app (app.py) exists for exploration and demonstration; this is
the one that would actually run in a pipeline.

DESIGN DECISIONS THAT ENCODE RESPONSIBILITY
-------------------------------------------
  * Exit code reflects ACT NOW findings only, not total findings. A build
    should not fail because of 900 theoretical backlog items.
  * `--explain` is always available: no finding is unexplainable.
  * Missing threat feeds produce a visible WARNING, never silence. The user
    must know the tool is running degraded.
  * "No findings" is never printed as "you are safe".

USAGE
    python scan_cli.py --sbom sample_cyclonedx_sbom.json
    python scan_cli.py --sbom x.json --explain CVE-2021-44228
    python scan_cli.py --sbom x.json --json > findings.json
    python scan_cli.py --sbom x.json --csv > findings.csv
    python scan_cli.py --sbom x.json --fail-on ACT_NOW      # for CI
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict

import it_security_agent as agent
import threat_intel as ti
import triage


# ── plain-text colour (disabled when piped, so JSON/CSV stay clean) ────────
class C:
    RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"
    CYA = "\033[96m"; DIM = "\033[2m"; BLD = "\033[1m"; END = "\033[0m"

    @classmethod
    def off(cls):
        for k in ("RED", "YEL", "GRN", "CYA", "DIM", "BLD", "END"):
            setattr(cls, k, "")


# NOTE: these are FUNCTIONS, not dicts. A module-level dict would snapshot the
# escape codes at import time, before --no-color has had a chance to blank them
# — which silently leaks ANSI codes into piped/CI output.
def band_color(band):
    return {"ACT NOW": C.RED, "SCHEDULE": C.YEL,
            "MONITOR": C.CYA, "BACKLOG": C.DIM}.get(band, "")


def route_color(routing):
    return {"AUTO": C.GRN, "SUGGEST": C.YEL, "FLAG": C.RED}.get(routing, "")


def load_components(args):
    """Ingest from whichever source the user gave, preserving provenance."""
    import input_layer as il
    if args.sbom:
        res = il.load_any(args.sbom)
        return res.components, res.warnings, "sbom", 1.0
    if args.image:
        res = il.load_image(args.image)
        # OCR is low-trust by construction -> everything lands in FLAG
        return res.components, res.warnings, "ocr", 0.5
    if args.manual:
        res = il.load_manual(args.manual)
        return res.components, res.warnings, "manual", 0.8
    return [], ["no input given"], "none", 0.0


def print_human(findings, intel, warnings, source, args):
    print()
    print(f"{C.BLD}IT SECURITY AGENT — vulnerability triage{C.END}")
    print("=" * 66)

    # Degraded-mode warnings must be LOUD, never silent.
    if intel.warnings:
        for w in intel.warnings:
            print(f"{C.YEL}  ! {w}{C.END}")
        print(f"{C.YEL}  ! Running in DEGRADED mode: prioritising on CVSS alone.{C.END}")
        print()
    for w in warnings:
        print(f"{C.YEL}  ! {w}{C.END}")

    print(f"  input: {source}   feeds: {intel.summary().splitlines()[0]}")
    print()
    print(triage.triage_message(findings))
    print()

    if not findings:
        return

    print("-" * 66)
    print(f"{'PRIORITY':10} {'CVE':18} {'COMPONENT':22} {'CVSS':>5} {'CONF':>5} ROUTE")
    print("-" * 66)
    shown = findings if args.all else findings[:args.limit]
    for f in shown:
        bc, rc = band_color(f.band), route_color(f.routing)
        comp = f"{f.component} {f.version}"[:22]
        cvss = f"{f.cvss:.1f}" if f.cvss is not None else " n/a"
        kev = f"{C.RED}*{C.END}" if f.on_kev else " "
        print(f"{bc}{f.band:10}{C.END}{kev}{f.cve_id:17} {comp:22} "
              f"{cvss:>5} {f.confidence:>5.2f} {rc}{f.routing}{C.END}")

    if not args.all and len(findings) > args.limit:
        print(f"{C.DIM}  ... {len(findings) - args.limit} more "
              f"(use --all){C.END}")

    print("-" * 66)
    s = triage.summarize(findings)
    print(f"  routing: {C.GRN}{s['AUTO']} AUTO{C.END} · "
          f"{C.YEL}{s['SUGGEST']} SUGGEST{C.END} · "
          f"{C.RED}{s['FLAG']} FLAG (human review){C.END}")
    print(f"  {C.RED}*{C.END} = on CISA KEV (confirmed exploited in the wild)")
    print()
    print(f"{C.DIM}  'No match' means no KNOWN CVE — it is not proof of safety.{C.END}")
    print(f"{C.DIM}  Explain any finding:  --explain <CVE-ID>{C.END}")
    print()


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Scan an SBOM (or screenshot) for known vulnerabilities and triage them.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--sbom", help="path to a CycloneDX/SPDX/requirements file")
    src.add_argument("--image", help="path to a screenshot (OCR, low confidence)")
    src.add_argument("--manual", help="'name version vendor'")

    p.add_argument("--nvd", default="nvd_real_bulk.json", help="NVD feed json")
    p.add_argument("--kev", default=ti.KEV_FILE, help="CISA KEV json")
    p.add_argument("--epss", default=ti.EPSS_FILE, help="EPSS csv.gz")
    p.add_argument("--explain", metavar="CVE", help="show full reasoning for one CVE")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--csv", action="store_true", help="CSV output (opens in Excel)")
    p.add_argument("--all", action="store_true", help="show every finding")
    p.add_argument("--limit", type=int, default=15, help="rows to show (default 15)")
    p.add_argument("--fail-on", choices=["ACT_NOW", "SCHEDULE", "ANY", "NEVER"],
                   default="NEVER",
                   help="exit non-zero for CI when findings hit this band")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    if args.no_color or args.json or args.csv or not sys.stdout.isatty():
        C.off()

    components, warnings, source, in_conf = load_components(args)
    if not components:
        print("No components could be read from the input.", file=sys.stderr)
        for w in warnings:
            print("  !", w, file=sys.stderr)
        return 2

    records = agent.load_nvd_feed(args.nvd)
    try:
        raw = json.load(open(args.nvd, encoding="utf-8"))["vulnerabilities"]
    except Exception:
        raw = None
    intel = ti.load_threat_intel(args.kev, args.epss)

    report = agent.scan(components, records)
    findings = triage.build_findings(report, records, intel, raw_nvd=raw,
                                     input_confidence=in_conf, source=source)

    # ── one-CVE deep dive ────────────────────────────────────────────────
    if args.explain:
        want = args.explain.strip().upper()
        hit = [f for f in findings if f.cve_id.upper() == want]
        if not hit:
            print(f"{want} is not among the findings for this input.")
            return 1
        for f in hit:
            print()
            print(f.explain())
            print()
        return 0

    # ── machine-readable ─────────────────────────────────────────────────
    if args.json:
        print(json.dumps({
            "summary": triage.summarize(findings),
            "degraded": bool(intel.warnings),
            "warnings": intel.warnings + warnings,
            "findings": [asdict(f) for f in findings],
        }, indent=2))
    elif args.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["priority", "cve", "component", "version", "vendor",
                    "cvss", "severity", "epss", "on_kev", "confidence",
                    "routing", "cwe", "reason"])
        for f in findings:
            w.writerow([f.band, f.cve_id, f.component, f.version, f.vendor,
                        f.cvss, f.severity, f.epss, f.on_kev, f.confidence,
                        f.routing, "|".join(f.cwe_labels), f.band_reason])
    else:
        print_human(findings, intel, warnings, source, args)

    # ── CI exit code: deliberately based on ACT NOW, not raw count ───────
    s = triage.summarize(findings)
    if args.fail_on == "ACT_NOW" and s["ACT NOW"]:
        return 1
    if args.fail_on == "SCHEDULE" and (s["ACT NOW"] or s["SCHEDULE"]):
        return 1
    if args.fail_on == "ANY" and s["total"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
