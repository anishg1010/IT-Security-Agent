"""
paths.py  —  make the folder structure work without rewriting every import
=========================================================================
The code lives in src/, the data in data/, the feeds in feeds/. Rather than
hard-coding relative paths in ten modules (which then break depending on where
you run them from), everything imports this one file first.

    import paths        # puts src/ on sys.path, chdir-proofs data lookups

Why not a proper installable package? Because the deliverable is a notebook a
grader must open and run with zero setup. A sys.path shim is one line and
works from any working directory; `pip install -e .` is friction.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
DATA = ROOT / "data"
FEEDS = ROOT / "feeds"
TESTS = ROOT / "tests"

# make `import it_security_agent` work from anywhere
for p in (SRC, ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


def data(name: str) -> str:
    """Absolute path to a data file, regardless of cwd."""
    return str(DATA / name)


def feed(name: str) -> str:
    """Absolute path to a threat-intel feed file."""
    return str(FEEDS / name)


# Default file locations, resolved absolutely so nothing depends on cwd.
NVD_BULK = data("nvd_real_bulk.json")
NVD_SAMPLE = data("nvd_sample.json")
SBOM_CYCLONEDX = data("sample_cyclonedx_sbom.json")
SBOM_SPDX = data("sample_spdx_sbom.json")
EVAL_SET = data("eval_set.json")
KEV = feed("known_exploited_vulnerabilities.json")
EPSS = feed("epss_scores-current.csv.gz")
