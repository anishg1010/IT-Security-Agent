"""
run_coverage.py  —  measure test coverage using only the standard library
=========================================================================
The rubric asks for >=80% code coverage. We deliberately avoid the `coverage`
pip package so this runs in any grader's environment with zero installs.

WHY NOT `trace.Trace`?
----------------------
The obvious approach -- stdlib `trace` -- instruments EVERY line of Python that
executes, including all of scikit-learn's and numpy's internals. Our test suite
fits gradient-boosted trees, which is millions of traced line-events: the run
becomes so slow it looks like a hang (especially on Windows).

Instead we install a `sys.settrace` hook that filters to OUR files first and
returns None for everything else, so library code is never traced line by line.
Same measurement, a small fraction of the work.

Usage:
    python run_coverage.py            # measure and report
    python run_coverage.py --fast     # skip the slow GBDT test for a quick check
"""
import io
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import paths  # noqa: F401

TARGETS = ["it_security_agent", "name_resolver", "input_layer",
           "build_match_dataset", "match_model", "threat_intel",
           "triage", "scan_cli", "feeds_live"]
# NOTE: app.py is intentionally excluded from the coverage %: it is a Streamlit
# UI whose _main() cannot run headless. Its LOGIC core (run_scan,
# load_components_from_bytes) IS tested — see TestApp in test_agent.py.


def executable_lines(path):
    """Approximate the executable line numbers: non-blank, non-comment, and
    not inside a docstring. Good enough for an honest coverage estimate."""
    lines = set()
    with open(path, "rb") as f:
        src = f.read().decode("utf-8", errors="replace")
    in_doc = False
    for i, raw in enumerate(src.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        tq = s.count('"""') + s.count("'''")
        if in_doc:
            if tq % 2 == 1:
                in_doc = False
            continue
        if s.startswith(('"""', "'''")):
            if tq % 2 == 1:
                in_doc = True
            continue
        lines.add(i)
    return lines


class ProjectTracer:
    """A sys.settrace hook that records line hits for our modules only.

    Returning None from the call-event handler tells CPython not to trace
    inside that frame at all -- which is what stops sklearn being walked
    line by line, and is the whole performance trick.
    """

    def __init__(self, target_files):
        self.targets = target_files          # {abs_path: module_name}
        self.hits = {}                       # {module_name: set(lineno)}

    def _trace_lines(self, frame, event, arg):
        if event == "line":
            mod = self.targets.get(frame.f_code.co_filename)
            if mod is not None:
                self.hits.setdefault(mod, set()).add(frame.f_lineno)
        return self._trace_lines

    def global_trace(self, frame, event, arg):
        if event != "call":
            return None
        if frame.f_code.co_filename in self.targets:
            return self._trace_lines
        # Not one of our files: do not trace inside it. Returning None here is
        # what keeps sklearn/numpy from being walked line by line. Our own
        # functions still get traced because CPython calls this global hook for
        # every new frame, including ours, no matter who called it.
        return None

    def start(self):
        threading.settrace(self.global_trace)
        sys.settrace(self.global_trace)

    def stop(self):
        sys.settrace(None)
        threading.settrace(None)


def main(fast=False):
    target_files = {}
    for mod in TARGETS:
        p = paths.SRC / (mod + ".py")
        if not p.exists():
            print(f"  (skipping {mod}.py -- not found in this folder)")
            continue
        target_files[str(p.resolve())] = mod

    if not target_files:
        print("No target modules found. Run this from inside the WEEK_3 folder.")
        return 0.0

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("test_agent")

    if fast:
        # Drop the GBDT test: it fits hundreds of trees and dominates runtime
        # while adding almost no coverage of OUR code.
        def prune(s):
            kept = []
            for t in s:
                if isinstance(t, unittest.TestSuite):
                    prune(t)
                    kept.append(t)
                elif "gbdt" not in t.id().lower():
                    kept.append(t)
            s._tests = kept
        prune(suite)

    tracer = ProjectTracer(target_files)
    runner = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0)

    # Module-level code (constants, regex compiles, class/def statements) runs
    # at IMPORT time. If the modules are already imported before we start
    # tracing, those lines are never recorded and coverage is understated. So
    # we drop them from sys.modules and re-import them under the tracer.
    import importlib
    for mod in list(target_files.values()):
        sys.modules.pop(mod, None)

    tracer.start()
    try:
        for mod in target_files.values():
            importlib.import_module(mod)      # capture module-level lines
        result = runner.run(suite)
    finally:
        tracer.stop()

    print(f"tests run: {result.testsRun}   failures: {len(result.failures)}   "
          f"errors: {len(result.errors)}\n")

    print(f"{'module':26}{'exec':>7}{'hit':>7}{'cover':>8}")
    print("-" * 48)
    total_exec = total_hit = 0
    for path, mod in sorted(target_files.items(), key=lambda kv: TARGETS.index(kv[1])):
        exe = executable_lines(path)
        hit = tracer.hits.get(mod, set()) & exe
        cov = 100 * len(hit) / len(exe) if exe else 0
        total_exec += len(exe)
        total_hit += len(hit)
        print(f"{mod:26}{len(exe):>7}{len(hit):>7}{cov:>7.1f}%")
    print("-" * 48)
    total = 100 * total_hit / total_exec if total_exec else 0
    print(f"{'TOTAL':26}{total_exec:>7}{total_hit:>7}{total:>7.1f}%\n")

    if total >= 80:
        print(f"PASS: {total:.1f}% >= 80% coverage requirement")
    else:
        print(f"BELOW TARGET: {total:.1f}% < 80% -- add tests")
    return total


if __name__ == "__main__":
    main(fast="--fast" in sys.argv)
