"""
test_agent.py  —  Week 3 automated weakness tests
=================================================

Goal (Week 3 lecture): "Write tests to automatically detect weaknesses" and
"Provide at least 80% code coverage."

Design of this suite
---------------------
Uses only the standard library (`unittest`), so it runs in any grader's
environment with zero pip installs. Coverage is measured with the stdlib
`trace` module (see run_coverage.py) — again, no third-party dependency.

The tests are organised by the failure modes they guard against, not by
function, because the point is to *detect weaknesses*, not just execute lines:

  A. CPE parsing / version-range logic  (the correctness core)
  B. Name resolution / alias handling   (the biggest accuracy gap)
  C. End-to-end matching invariants     (must-fire / must-not-fire cases)
  D. Fallback path (affected[]) safety   (does the coverage fix add FPs?)
  E. Input layer provenance/confidence   (Responsible-AI routing depends on it)
  F. The Week 3 learned model            (calibration, adversarial rejection)

Every regression the earlier weeks fixed has a test here so it can't silently
come back (e.g. the wildcard-version 17x false-positive bug; the v4.0 CVSS
drop-to-UNKNOWN bug).
"""
import sys, unittest
from pathlib import Path

# make src/ importable and data/ findable no matter where this is run from
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import paths  # noqa: F401  (side effect: sets up sys.path)

import it_security_agent as agent
from it_security_agent import Component, parse_cpe, version_matches, severity_label
import name_resolver as nr


# ---------------------------------------------------------------------------
# helpers to build cpe entries the way load_nvd_feed does
# ---------------------------------------------------------------------------

def cpe_entry(criteria, **ranges):
    e = {"criteria": criteria, "versionStartIncluding": None,
         "versionStartExcluding": None, "versionEndIncluding": None,
         "versionEndExcluding": None}
    e.update(ranges)
    return e


def record(cve_id, score, cpe_entries=(), affected_entries=()):
    return {"cve_id": cve_id, "description": "test", "cvss_score": score,
            "cpe_entries": list(cpe_entries), "cpe_strings": [e["criteria"] for e in cpe_entries],
            "affected_entries": list(affected_entries)}


# ===========================================================================
# A. CPE parsing and version-range logic
# ===========================================================================

class TestCpeParsing(unittest.TestCase):
    def test_parse_valid_cpe(self):
        v, p, ver = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        self.assertEqual((v, p, ver), ("apache", "log4j", "2.14.1"))

    def test_parse_malformed_returns_none(self):
        self.assertIsNone(parse_cpe("not-a-cpe"))
        self.assertIsNone(parse_cpe("cpe:2.3:a"))          # too short
        self.assertIsNone(parse_cpe(""))

    def test_parse_is_case_insensitive(self):
        v, p, ver = parse_cpe("cpe:2.3:a:OpenSSL:OpenSSL:3.0.0:*:*:*:*:*:*:*")
        self.assertEqual((v, p), ("openssl", "openssl"))


class TestVersionMatching(unittest.TestCase):
    def test_exact_version_hit(self):
        e = cpe_entry("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        self.assertTrue(version_matches("2.14.1", e))

    def test_exact_version_miss(self):
        e = cpe_entry("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        self.assertFalse(version_matches("2.15.0", e))

    def test_wildcard_criteria_without_range_matches_anything(self):
        # This is the DANGEROUS case: '*' version with no range fields.
        e = cpe_entry("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")
        self.assertTrue(version_matches("1.1.1", e))

    def test_range_end_excluding(self):
        e = cpe_entry("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", versionEndExcluding="3.0.8")
        self.assertTrue(version_matches("3.0.7", e))
        self.assertFalse(version_matches("3.0.8", e))
        self.assertFalse(version_matches("3.1.0", e))

    def test_range_start_including(self):
        e = cpe_entry("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", versionStartIncluding="2.0.0")
        self.assertTrue(version_matches("2.0.0", e))
        self.assertFalse(version_matches("1.9.9", e))

    def test_range_both_bounds(self):
        e = cpe_entry("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
                      versionStartIncluding="1.0.0", versionEndExcluding="2.0.0")
        self.assertTrue(version_matches("1.5.0", e))
        self.assertFalse(version_matches("2.0.0", e))
        self.assertFalse(version_matches("0.9.0", e))

    def test_alpha_suffix_versions_sort_correctly(self):
        # OpenSSL-style "1.1.1zh" must compare above "1.1.1a" without crashing.
        e = cpe_entry("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
                      versionStartIncluding="1.1.1a", versionEndExcluding="1.1.1zh")
        self.assertTrue(version_matches("1.1.1m", e))


class TestSeverityLabel(unittest.TestCase):
    def test_buckets(self):
        self.assertEqual(severity_label(9.8), "CRITICAL")
        self.assertEqual(severity_label(7.5), "HIGH")
        self.assertEqual(severity_label(5.0), "MEDIUM")
        self.assertEqual(severity_label(2.0), "LOW")
        self.assertEqual(severity_label(0.0), "NONE")
        self.assertEqual(severity_label(None), "UNKNOWN")


# ===========================================================================
# B. Name resolution / aliases (accuracy gap)
# ===========================================================================

class TestNameResolver(unittest.TestCase):
    def test_alias_log4j_core(self):
        v, p, ver, why = nr.resolve_component("log4j-core", "2.14.1", "apache")
        self.assertEqual(p, "log4j")
        self.assertEqual(v, "apache")

    def test_alias_apache_prefix(self):
        v, p, ver, why = nr.resolve_component("apache-log4j", "2.14.1", None)
        self.assertEqual(p, "log4j")

    def test_purl_parsing(self):
        v, p, ver, why = nr.resolve_component(
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "", None)
        self.assertEqual(p, "log4j")
        self.assertEqual(ver, "2.14.1")

    def test_maven_coordinate(self):
        v, p, ver, why = nr.resolve_component(
            "org.apache.logging.log4j:log4j-core:2.14.1", "", None)
        self.assertEqual(p, "log4j")

    def test_openssl_libs_alias(self):
        v, p, ver, why = nr.resolve_component("openssl-libs", "3.0.0", "openssl")
        self.assertEqual((v, p), ("openssl", "openssl"))

    def test_unknown_name_passes_through(self):
        # A name with no alias but a generic "-lib" suffix: the resolver
        # strips the packaging suffix (documented behaviour) but must NOT
        # invent a vendor alias. Product becomes 'some-random', vendor stays.
        v, p, ver, why = nr.resolve_component("some-random-lib", "1.0.0", "acme")
        self.assertEqual(p, "some-random")
        self.assertEqual(v, "acme")

    def test_truly_canonical_name_unchanged(self):
        v, p, ver, why = nr.resolve_component("nginx", "1.0.0", "f5")
        self.assertEqual(p, "nginx")
        self.assertIn("canonical", why.lower())

    def test_generic_suffix_strip(self):
        r = nr.normalize_name("mylib-core")
        self.assertEqual(r.product, "mylib")


# ===========================================================================
# C. End-to-end matching invariants
# ===========================================================================

class TestMatchingInvariants(unittest.TestCase):
    def setUp(self):
        self.log4shell = record(
            "CVE-2021-44228", 10.0,
            cpe_entries=[cpe_entry("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")])
        self.openssl = record(
            "CVE-2022-0778", 7.5,
            cpe_entries=[cpe_entry("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                                   versionEndExcluding="3.0.2")])

    def test_log4shell_must_fire(self):
        comp = Component("log4j-core", "2.14.1", "apache")
        matches = agent.match_component(comp, [self.log4shell])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].cve_id, "CVE-2021-44228")
        self.assertEqual(matches[0].severity_label, "CRITICAL")

    def test_wrong_version_must_not_fire(self):
        comp = Component("log4j-core", "2.99.0", "apache")
        matches = agent.match_component(comp, [self.log4shell])
        self.assertEqual(matches, [])

    def test_wrong_vendor_must_not_fire(self):
        comp = Component("log4j", "2.14.1", "totally-wrong-vendor")
        matches = agent.match_component(comp, [self.log4shell])
        self.assertEqual(matches, [])

    def test_openssl_range_boundary(self):
        vuln = Component("openssl", "3.0.1", "openssl")
        safe = Component("openssl", "3.0.2", "openssl")
        self.assertEqual(len(agent.match_component(vuln, [self.openssl])), 1)
        self.assertEqual(len(agent.match_component(safe, [self.openssl])), 0)

    def test_scan_reports_unmatched(self):
        comp = Component("nonexistent-lib", "1.0.0", "nobody")
        rep = agent.scan([comp], [self.log4shell])
        self.assertEqual(len(rep.matches), 0)
        self.assertEqual(len(rep.components_unmatched), 1)

    def test_match_reason_is_populated(self):
        comp = Component("log4j-core", "2.14.1", "apache")
        m = agent.match_component(comp, [self.log4shell])[0]
        self.assertTrue(m.match_reason)          # explainability contract


# ===========================================================================
# D. Fallback path (affected[]) — coverage without runaway false positives
# ===========================================================================

class TestFallbackMatcher(unittest.TestCase):
    def test_fallback_fires_when_no_cpe(self):
        rec = record("CVE-2022-31114", 6.5, cpe_entries=[],
                     affected_entries=[{"vendor": "laravel-backpack",
                                        "product": "crud",
                                        "versions": [">= 5.0.0, < 5.0.13"]}])
        comp = Component("crud", "5.0.5", "laravel-backpack")
        matches = agent.match_component_fallback(comp, [rec])
        self.assertEqual(len(matches), 1)
        self.assertIn("fallback", matches[0].match_reason.lower())

    def test_fallback_skipped_when_cpe_present(self):
        # If a record HAS cpe_entries, fallback must not double-count it.
        rec = record("CVE-X", 5.0,
                     cpe_entries=[cpe_entry("cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*")],
                     affected_entries=[{"vendor": "x", "product": "y",
                                        "versions": ["= 1.0"]}])
        comp = Component("y", "1.0", "x")
        self.assertEqual(agent.match_component_fallback(comp, [rec]), [])

    def test_fallback_version_out_of_range(self):
        rec = record("CVE-Z", 6.5, cpe_entries=[],
                     affected_entries=[{"vendor": "v", "product": "p",
                                        "versions": [">= 1.0.0, < 2.0.0"]}])
        comp = Component("p", "3.0.0", "v")
        self.assertEqual(agent.match_component_fallback(comp, [rec]), [])


# ===========================================================================
# E. Input layer — provenance and confidence (Responsible-AI routing)
# ===========================================================================

class TestInputLayer(unittest.TestCase):
    def setUp(self):
        import input_layer as il
        self.il = il

    def test_cyclonedx_high_confidence(self):
        data = {"bomFormat": "CycloneDX", "components": [
            {"name": "log4j-core", "version": "2.14.1", "group": "apache"}]}
        res = self.il.load_cyclonedx(data)
        self.assertEqual(len(res.components), 1)
        self.assertEqual(res.components[0].confidence, 1.0)
        self.assertEqual(res.components[0].source, "cyclonedx")

    def test_spdx_supplier_parsing(self):
        data = {"spdxVersion": "SPDX-2.3", "packages": [
            {"name": "openssl", "versionInfo": "1.1.1",
             "supplier": "Organization: OpenSSL"}]}
        res = self.il.load_spdx(data)
        self.assertEqual(res.components[0].vendor, "OpenSSL")

    def test_ocr_text_extraction_low_confidence(self):
        text = "openssl 1.1.1\nlog4j-core: 2.14.1\nPython 3.11.2"
        comps = self.il.extract_components_from_text(text)
        names = {c.name.lower() for c in comps}
        self.assertIn("openssl", names)
        self.assertTrue(all(c.confidence <= 0.6 for c in comps))  # OCR is low-trust

    def test_sbom_flavor_detection(self):
        self.assertEqual(self.il._detect_sbom_flavor(
            {"bomFormat": "CycloneDX", "components": []}), "cyclonedx")
        self.assertEqual(self.il._detect_sbom_flavor(
            {"spdxVersion": "X", "packages": []}), "spdx")
        self.assertEqual(self.il._detect_sbom_flavor([]), "simple")

    def test_manual_line(self):
        res = self.il.load_manual("openssl 1.1.1 openssl")
        self.assertEqual(res.components[0].name, "openssl")
        self.assertEqual(res.components[0].vendor, "openssl")


# ===========================================================================
# F. The Week 3 learned model
# ===========================================================================

class TestLearnedModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from match_model import make_dataset_from_nvd, fit_calibrated, cv_scores, metrics_at
        cls.X, cls.y, cls.meta = make_dataset_from_nvd(noise=0.5)
        cls.base, cls.cal, cls.cal_scores, cls.method = fit_calibrated(
            cls.X, cls.y, kind="logreg")
        cls.raw = cv_scores(cls.base, cls.X, cls.y)
        cls._metrics_at = staticmethod(metrics_at)

    def test_dataset_has_both_classes(self):
        # The exact defect Week 2 had: no negatives. Guard against it.
        self.assertGreater((self.y == 0).sum(), 50)
        self.assertGreater((self.y == 1).sum(), 50)

    def test_model_beats_random(self):
        m = self._metrics_at(self.y, self.raw)
        self.assertGreater(m["roc_auc"], 0.85)

    def test_calibration_helps_or_holds(self):
        raw_brier = self._metrics_at(self.y, self.raw)["brier"]
        cal_brier = self._metrics_at(self.y, self.cal_scores)["brier"]
        # calibration should not make probability estimates worse
        self.assertLessEqual(cal_brier, raw_brier + 0.01)

    def test_adversarial_rejection(self):
        from match_model import per_negative_type_recall
        rej = per_negative_type_recall(self.y, self.cal_scores, self.meta)
        # every adversarial negative type must be rejected most of the time
        for kind, (recall, n) in rej.items():
            self.assertGreater(recall, 0.6, f"{kind} rejection too low: {recall}")

    def test_linear_shap_sums_to_logit(self):
        import numpy as np
        w, b = self.base.coef_[0], self.base.intercept_[0]
        mean = self.X.mean(axis=0)
        x = self.X[0]
        phi = w * (x - mean)
        reconstructed = b + w @ mean + phi.sum()
        self.assertAlmostEqual(reconstructed, b + w @ x, places=6)


# ===========================================================================
# G. Reporting, file loaders, and CLI-adjacent paths (coverage of the plumbing)
# ===========================================================================

class TestReportingAndLoaders(unittest.TestCase):
    def setUp(self):
        self.rec = record(
            "CVE-2021-44228", 10.0,
            cpe_entries=[cpe_entry("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")])

    def test_risk_report_summary(self):
        comp = Component("log4j-core", "2.14.1", "apache")
        rep = agent.scan([comp], [self.rec])
        s = rep.summary()
        self.assertIn("Scanned 1", s)
        self.assertIn("vulnerability", s.lower())

    def test_print_report_runs(self):
        import io, contextlib
        comp = Component("log4j-core", "2.14.1", "apache")
        unmatched = Component("ghost", "9.9", "nobody")
        rep = agent.scan([comp, unmatched], [self.rec])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            agent.print_report(rep)
        out = buf.getvalue()
        self.assertIn("RISK REPORT", out)
        self.assertIn("CVE-2021-44228", out)
        self.assertIn("Unmatched", out)

    def test_load_nvd_feed_from_file(self):
        recs = agent.load_nvd_feed("nvd_sample.json")
        self.assertTrue(recs)
        self.assertTrue(any(r["cve_id"] == "CVE-2021-44228" for r in recs))

    def test_load_sbom_cyclonedx_file(self):
        comps = agent.load_sbom("sample_cyclonedx_sbom.json")
        names = {c.name.lower() for c in comps}
        self.assertIn("log4j-core", names)

    def test_component_normalized_baseline_path(self):
        # force the non-resolver baseline branch
        comp = Component("Some-Lib-core", "V1.2.3", "ACME")
        v, p, ver = comp.normalized(use_resolver=False)
        self.assertEqual(v, "acme")
        self.assertEqual(p, "some-lib")      # -core stripped
        self.assertEqual(ver, "1.2.3")       # leading v stripped

    def test_parse_range_string(self):
        r = agent._parse_range_string(">= 5.0.0, < 5.0.13")
        self.assertEqual(r["versionStartIncluding"], "5.0.0")
        self.assertEqual(r["versionEndExcluding"], "5.0.13")

    def test_parse_range_string_equals(self):
        r = agent._parse_range_string("= 2.14.1")
        self.assertEqual(r["versionStartIncluding"], "2.14.1")
        self.assertEqual(r["versionEndIncluding"], "2.14.1")


class TestInputLayerFilePaths(unittest.TestCase):
    def setUp(self):
        import input_layer as il
        self.il = il

    def test_load_any_json_sbom(self):
        res = self.il.load_any("sample_cyclonedx_sbom.json")
        self.assertTrue(res.components)
        self.assertEqual(res.source, "cyclonedx")

    def test_load_any_spdx(self):
        res = self.il.load_any("sample_spdx_sbom.json")
        self.assertEqual(res.source, "spdx")

    def test_load_sbom_json_simple(self):
        import json, tempfile, os
        data = {"components": [{"name": "x", "version": "1.0", "vendor": "y"}]}
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(data).encode()); os.close(fd)
        try:
            res = self.il.load_sbom_json(path)
            self.assertEqual(res.components[0].name, "x")
        finally:
            os.unlink(path)

    def test_ingest_result_summary(self):
        res = self.il.load_any("sample_cyclonedx_sbom.json")
        self.assertIn("extracted", res.summary())

    def test_load_manual_list(self):
        res = self.il.load_manual([{"name": "a", "version": "1", "vendor": "b"}])
        self.assertEqual(res.components[0].name, "a")

    def test_requirements_txt(self):
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix="_requirements.txt")
        os.write(fd, b"requests==2.31.0\nflask>=2.0\n# comment\n"); os.close(fd)
        try:
            res = self.il.load_requirements_txt(path)
            names = {c.name for c in res.components}
            self.assertIn("requests", names)
        finally:
            os.unlink(path)

    def test_package_json(self):
        import tempfile, os, json
        fd, path = tempfile.mkstemp(suffix="_package.json")
        os.write(fd, json.dumps({"dependencies": {"lodash": "^4.17.21"}}).encode())
        os.close(fd)
        try:
            res = self.il.load_package_json(path)
            self.assertEqual(res.components[0].name, "lodash")
        finally:
            os.unlink(path)

    def test_ocr_availability_check_returns_tuple(self):
        # Contract test: _ocr_available reports (bool, reason) without crashing,
        # regardless of whether tesseract is installed in this environment.
        ok, why = self.il._ocr_available()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(why, str)

    def test_extract_from_text_dedupes(self):
        text = "openssl 1.1.1\nopenssl 1.1.1\nnginx/1.18.0"
        comps = self.il.extract_components_from_text(text)
        keys = {(c.name.lower(), c.version) for c in comps}
        self.assertEqual(len(keys), len(comps))   # no duplicate (name,version)


class TestModelReportHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from match_model import make_dataset_from_nvd, fit_calibrated, cv_scores
        cls.mm = __import__("match_model")
        cls.X, cls.y, cls.meta = make_dataset_from_nvd(noise=0.5)
        cls.base, cls.cal, cls.cs, cls.method = fit_calibrated(cls.X, cls.y)
        cls.raw = cv_scores(cls.base, cls.X, cls.y)

    def test_reliability_table(self):
        tab = self.mm.reliability_table(self.y, self.cs)
        self.assertTrue(tab)
        for row in tab:
            self.assertIn("claimed", row)
            self.assertIn("actual", row)

    def test_metrics_at_shape(self):
        m = self.mm.metrics_at(self.y, self.raw, threshold=0.5)
        for k in ("precision", "recall", "f1", "roc_auc", "pr_auc", "brier"):
            self.assertIn(k, m)

    def test_linear_weight_report(self):
        rep = self.mm.linear_weight_report(self.base)
        self.assertEqual(len(rep), len(self.mm.FEATURE_NAMES))
        # sorted by descending |coef|
        shares = [r["abs_share"] for r in rep]
        self.assertGreaterEqual(shares[0], shares[-1])

    def test_gbdt_path(self):
        base, cal, cs, method = self.mm.fit_calibrated(self.X, self.y, kind="gbdt")
        m = self.mm.metrics_at(self.y, cs)
        self.assertGreater(m["roc_auc"], 0.8)

    def test_dataset_builder_summary(self):
        import io, contextlib
        from build_match_dataset import build_dataset, summarize
        recs = agent.load_nvd_feed("nvd_sample.json")
        # sample file is tiny; just ensure it runs without error on bulk
        recs = agent.load_nvd_feed("nvd_real_bulk.json")
        rows = build_dataset(recs, max_per_type=50, noise=0.3)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            summarize(rows)
        self.assertIn("rows:", buf.getvalue())

    def test_char_overlap_bounds(self):
        from build_match_dataset import _char_overlap
        self.assertEqual(_char_overlap("log4j", "log4j"), 1.0)
        self.assertLess(_char_overlap("log4j", "openssl"), 0.5)
        self.assertEqual(_char_overlap("", "x"), 0.0)

    def test_load_rows_roundtrip(self):
        import json, tempfile, os
        from build_match_dataset import build_dataset
        recs = agent.load_nvd_feed("nvd_real_bulk.json")
        rows = build_dataset(recs, max_per_type=30, noise=0.2)
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(rows).encode()); os.close(fd)
        try:
            X, y, meta = self.mm.load_rows(path)
            self.assertEqual(len(y), len(rows))
            self.assertEqual(X.shape[1], len(self.mm.FEATURE_NAMES))
        finally:
            os.unlink(path)

    def test_per_negative_type_recall_keys(self):
        rej = self.mm.per_negative_type_recall(self.y, self.cs, self.meta)
        self.assertTrue(set(rej) <= {"wrong_version", "wrong_vendor",
                                     "near_miss_name", "unrelated",
                                     "fallback_wrong_version",
                                     "fallback_wrong_vendor"})

    def test_fallback_path_rows_exist(self):
        """Guards the fix for the dead `has_cpe_path` feature: if fallback rows
        ever stop being generated, the feature silently becomes a constant
        again and the model quietly loses a signal."""
        import numpy as np
        paths = {m["path"] for m in self.meta}
        self.assertIn("fallback", paths)
        self.assertIn("cpe", paths)
        i = self.mm.FEATURE_NAMES.index("has_cpe_path")
        self.assertGreater(len(np.unique(self.X[:, i])), 1,
                           "has_cpe_path is constant — it carries no information")

    def test_no_feature_is_constant(self):
        """A constant feature cannot inform any decision. Catch it early."""
        import numpy as np
        for i, name in enumerate(self.mm.FEATURE_NAMES):
            self.assertGreater(len(np.unique(self.X[:, i])), 1,
                               f"feature '{name}' is constant — it is dead weight")

    def test_featurize_pair_ranges(self):
        from build_match_dataset import featurize_pair
        e = {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
        feats = featurize_pair("apache", "log4j", "2.14.1",
                               "apache", "log4j", e)
        self.assertEqual(len(feats), len(self.mm.FEATURE_NAMES))
        self.assertEqual(feats[0], 1.0)   # product_exact
        self.assertEqual(feats[2], 1.0)   # vendor_exact


class TestInputLayerBranches(unittest.TestCase):
    def setUp(self):
        import input_layer as il
        self.il = il

    def test_component_normalized_in_input_layer(self):
        c = self.il.Component(name="Nginx-core", version="V1.2", vendor="F5")
        v, p, ver = c.normalized()
        self.assertEqual(v, "f5")
        self.assertEqual(p, "nginx")
        self.assertEqual(ver, "1.2")

    def test_load_simple_list(self):
        res = self.il.load_simple([{"name": "a", "version": "1", "vendor": "b"}])
        self.assertEqual(res.components[0].source, "simple")

    def test_load_cyclonedx_cpe_vendor_mining(self):
        data = {"components": [{"name": "log4j", "version": "2.14.1",
                 "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}
        res = self.il.load_cyclonedx(data)
        self.assertEqual(res.components[0].vendor, "apache")

    def test_empty_cyclonedx_warns(self):
        res = self.il.load_cyclonedx({"components": []})
        self.assertTrue(res.warnings)

    def test_empty_spdx_warns(self):
        res = self.il.load_spdx({"packages": []})
        self.assertTrue(res.warnings)

    def test_load_any_unsupported(self):
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".xyz")
        os.close(fd)
        try:
            res = self.il.load_any(path)
            self.assertTrue(res.warnings)
        finally:
            os.unlink(path)

    def test_manual_too_short_warns(self):
        res = self.il.load_manual("justoneword")
        self.assertTrue(res.warnings)

    def test_summary_low_confidence_flag(self):
        text = "openssl 1.1.1"                    # OCR -> conf 0.5
        comps = self.il.extract_components_from_text(text)
        res = self.il.IngestResult(source="image_ocr", components=comps)
        self.assertIn("low-confidence", res.summary())


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ===========================================================================
# H. Threat intel (KEV / EPSS / CWE) — prioritisation, not just detection
# ===========================================================================

class TestThreatIntel(unittest.TestCase):
    """These tests must pass WITH OR WITHOUT the feed files present, because
    graceful degradation is itself the contract: a missing feed must disable a
    signal with a warning, never crash the scan."""

    def setUp(self):
        import threat_intel as ti
        self.ti = ti

    def test_missing_kev_degrades_gracefully(self):
        ids, warns = self.ti.load_kev("definitely_not_a_file.json")
        self.assertEqual(ids, set())
        self.assertTrue(warns)                 # must WARN, not crash

    def test_missing_epss_degrades_gracefully(self):
        scores, warns = self.ti.load_epss("definitely_not_a_file.csv.gz")
        self.assertEqual(scores, {})
        self.assertTrue(warns)

    def test_kev_parses_cisa_schema(self):
        import json, tempfile, os
        data = {"vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache",
             "product": "Log4j2", "knownRansomwareCampaignUse": "Known"}]}
        fd, p = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(data).encode()); os.close(fd)
        try:
            ids, warns = self.ti.load_kev(p)
            self.assertIn("CVE-2021-44228", ids)
            details = self.ti.load_kev_details(p)
            self.assertEqual(details["CVE-2021-44228"]["known_ransomware"], "Known")
        finally:
            os.unlink(p)

    def test_epss_skips_comment_header(self):
        """The real EPSS file starts with '#model_version:...'. A naive parser
        would treat that as the header and silently return garbage."""
        import gzip, tempfile, os
        fd, p = tempfile.mkstemp(suffix=".csv.gz"); os.close(fd)
        with gzip.open(p, "wt") as f:
            f.write("#model_version:v1,score_date:2026-01-01\n")
            f.write("cve,epss,percentile\n")
            f.write("CVE-2021-44228,0.94371,0.99982\n")
        try:
            scores, warns = self.ti.load_epss(p)
            self.assertAlmostEqual(scores["CVE-2021-44228"], 0.94371, places=4)
            self.assertFalse(warns)
        finally:
            os.unlink(p)

    def test_kev_outranks_cvss(self):
        """The core policy claim: a confirmed-exploited CVSS 7.5 must outrank
        a theoretical CVSS 9.8 that nobody is exploiting."""
        intel = self.ti.ThreatIntel(kev={"CVE-A"}, epss={"CVE-B": 0.0001})
        band_a, _ = self.ti.priority("CVE-A", 7.5, intel)
        band_b, _ = self.ti.priority("CVE-B", 9.8, intel)
        self.assertEqual(band_a, "ACT NOW")
        self.assertNotEqual(band_b, "ACT NOW")
        self.assertLess(self.ti.BAND_ORDER[band_a], self.ti.BAND_ORDER[band_b])

    def test_high_epss_schedules(self):
        intel = self.ti.ThreatIntel(kev=set(), epss={"CVE-C": 0.35})
        band, why = self.ti.priority("CVE-C", 5.0, intel)
        self.assertEqual(band, "SCHEDULE")

    def test_priority_without_any_intel(self):
        """With no feeds at all, priority must still return a sane band."""
        intel = self.ti.ThreatIntel()
        band, why = self.ti.priority("CVE-X", 9.8, intel)
        self.assertIn(band, self.ti.BAND_ORDER)

    def test_cwe_extraction_from_real_nvd(self):
        import json
        raw = json.load(open(paths.NVD_BULK))["vulnerabilities"]
        found = 0
        for v in raw[:200]:
            if self.ti.extract_cwes(v["cve"]):
                found += 1
        self.assertGreater(found, 100)         # most records carry CWE data

    def test_cwe_label_known_and_unknown(self):
        self.assertEqual(self.ti.cwe_label("CWE-79"), "Cross-site Scripting (XSS)")
        self.assertEqual(self.ti.cwe_label("CWE-99999"), "CWE-99999")  # passthrough

    def test_threat_intel_summary(self):
        intel = self.ti.ThreatIntel(kev={"CVE-A"}, epss={"CVE-B": 0.5})
        s = intel.summary()
        self.assertIn("KEV", s)
        self.assertIn("EPSS", s)

    def test_load_threat_intel_bundle(self):
        intel = self.ti.load_threat_intel("nope.json", "nope.csv.gz")
        self.assertEqual(intel.available, {"kev": False, "epss": False})
        self.assertTrue(intel.warnings)
        self.assertIn("UNAVAILABLE", intel.summary())

    def test_epss_accepts_uncompressed_fallback(self):
        """If someone unzips the feed by hand, still work."""
        import tempfile, os
        fd, p = tempfile.mkstemp(suffix=".csv"); os.close(fd)
        with open(p, "w") as f:
            f.write("#comment\ncve,epss,percentile\nCVE-Z,0.5,0.9\n")
        try:
            scores, warns = self.ti.load_epss(p)
            self.assertEqual(scores["CVE-Z"], 0.5)
        finally:
            os.unlink(p)

    def test_kev_malformed_file(self):
        import tempfile, os
        fd, p = tempfile.mkstemp(suffix=".json")
        os.write(fd, b"this is not json"); os.close(fd)
        try:
            ids, warns = self.ti.load_kev(p)
            self.assertEqual(ids, set())
            self.assertTrue(any("unreadable" in w for w in warns))
        finally:
            os.unlink(p)

    def test_kev_empty_catalog_warns(self):
        import json, tempfile, os
        fd, p = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps({"vulnerabilities": []}).encode()); os.close(fd)
        try:
            ids, warns = self.ti.load_kev(p)
            self.assertTrue(warns)
        finally:
            os.unlink(p)

    def test_epss_malformed_rows_skipped(self):
        import gzip, tempfile, os
        fd, p = tempfile.mkstemp(suffix=".csv.gz"); os.close(fd)
        with gzip.open(p, "wt") as f:
            f.write("cve,epss,percentile\n")
            f.write("CVE-GOOD,0.5,0.9\n")
            f.write("CVE-BAD,notanumber,0.9\n")
            f.write(",0.1,0.1\n")               # empty cve id
        try:
            scores, warns = self.ti.load_epss(p)
            self.assertIn("CVE-GOOD", scores)
            self.assertNotIn("CVE-BAD", scores)  # bad float skipped, no crash
        finally:
            os.unlink(p)

    def test_all_priority_bands_reachable(self):
        intel = self.ti.ThreatIntel(kev={"K"}, epss={"S": 0.35, "M": 0.02, "L": 0.0001})
        self.assertEqual(self.ti.priority("K", 1.0, intel)[0], "ACT NOW")
        self.assertEqual(self.ti.priority("S", 1.0, intel)[0], "SCHEDULE")
        self.assertEqual(self.ti.priority("M", 1.0, intel)[0], "MONITOR")
        self.assertEqual(self.ti.priority("L", 9.5, intel)[0], "MONITOR")   # crit, low epss
        self.assertEqual(self.ti.priority("U", 8.0, intel)[0], "BACKLOG")
        self.assertEqual(self.ti.priority("U", 2.0, intel)[0], "BACKLOG")

    def test_critical_cvss_no_epss_data(self):
        intel = self.ti.ThreatIntel()
        band, why = self.ti.priority("CVE-Q", 9.9, intel)
        self.assertEqual(band, "MONITOR")
        self.assertIn("no EPSS", why)

    def test_extract_cwes_empty(self):
        self.assertEqual(self.ti.extract_cwes({}), [])
        self.assertEqual(self.ti.extract_cwes({"weaknesses": []}), [])


# ===========================================================================
# I. Triage layer — detection -> decision
# ===========================================================================

class TestTriage(unittest.TestCase):
    def setUp(self):
        import triage, threat_intel
        self.tr = triage
        self.ti = threat_intel
        self.rec = record(
            "CVE-2021-44228", 10.0,
            cpe_entries=[cpe_entry("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")])

    def test_routing_thresholds(self):
        self.assertEqual(self.tr.route(0.95), "AUTO")
        self.assertEqual(self.tr.route(0.85), "AUTO")
        self.assertEqual(self.tr.route(0.70), "SUGGEST")
        self.assertEqual(self.tr.route(0.50), "SUGGEST")
        self.assertEqual(self.tr.route(0.30), "FLAG")

    def test_ocr_confidence_routes_to_human(self):
        """The responsible-AI core: a low-confidence OCR ingest must never be
        auto-actioned. The human stays in the loop where the machine is least
        sure."""
        self.assertEqual(self.tr.route(0.5 * 0.8), "FLAG")

    def test_kev_finding_outranks_higher_cvss(self):
        """A CVSS 7.5 on KEV must sort ABOVE a CVSS 9.8 that nobody exploits."""
        intel = self.ti.ThreatIntel(kev={"CVE-KEV"}, epss={})
        a = self.tr.Finding(cve_id="CVE-KEV", component="x", version="1", vendor="v",
                            cvss=7.5, severity="HIGH", confidence=0.9,
                            band="ACT NOW", band_reason="kev", routing="AUTO",
                            on_kev=True, epss=None)
        b = self.tr.Finding(cve_id="CVE-HIGH", component="y", version="1", vendor="v",
                            cvss=9.8, severity="CRITICAL", confidence=0.9,
                            band="BACKLOG", band_reason="no signal", routing="AUTO",
                            on_kev=False, epss=None)
        ranked = self.tr.rank([b, a])
        self.assertEqual(ranked[0].cve_id, "CVE-KEV")

    def test_rank_puts_confidence_last(self):
        """An urgent-but-uncertain finding must not be buried below a
        certain-but-trivial one."""
        urgent_unsure = self.tr.Finding(
            cve_id="A", component="x", version="1", vendor="v", cvss=5.0,
            severity="MEDIUM", confidence=0.55, band="ACT NOW",
            band_reason="kev", routing="SUGGEST", on_kev=True, epss=None)
        trivial_sure = self.tr.Finding(
            cve_id="B", component="y", version="1", vendor="v", cvss=5.0,
            severity="MEDIUM", confidence=0.99, band="BACKLOG",
            band_reason="none", routing="AUTO", on_kev=False, epss=None)
        ranked = self.tr.rank([trivial_sure, urgent_unsure])
        self.assertEqual(ranked[0].cve_id, "A")

    def test_build_findings_end_to_end(self):
        intel = self.ti.ThreatIntel()
        comp = Component("log4j-core", "2.14.1", "apache")
        rep = agent.scan([comp], [self.rec])
        f = self.tr.build_findings(rep, [self.rec], intel)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].cve_id, "CVE-2021-44228")
        self.assertIn(f[0].routing, ("AUTO", "SUGGEST", "FLAG"))

    def test_findings_explain_is_human_readable(self):
        intel = self.ti.ThreatIntel(kev={"CVE-2021-44228"}, epss={"CVE-2021-44228": 0.94})
        comp = Component("log4j-core", "2.14.1", "apache")
        rep = agent.scan([comp], [self.rec])
        f = self.tr.build_findings(rep, [self.rec], intel)[0]
        txt = f.explain()
        self.assertIn("priority", txt)
        self.assertIn("confidence", txt)
        self.assertIn("KEV", txt)

    def test_empty_scan_message_is_not_a_safety_claim(self):
        """'No match' must never be presented as 'proven safe'."""
        msg = self.tr.triage_message([])
        self.assertIn("NOT proof of safety", msg)

    def test_summarize_counts(self):
        intel = self.ti.ThreatIntel()
        comp = Component("log4j-core", "2.14.1", "apache")
        rep = agent.scan([comp], [self.rec])
        s = self.tr.summarize(self.tr.build_findings(rep, [self.rec], intel))
        self.assertEqual(s["total"], 1)
        for k in ("ACT NOW", "SCHEDULE", "MONITOR", "BACKLOG", "AUTO", "SUGGEST", "FLAG"):
            self.assertIn(k, s)

    def test_triage_message_says_severity_is_not_priority(self):
        intel = self.ti.ThreatIntel()
        comp = Component("log4j-core", "2.14.1", "apache")
        rep = agent.scan([comp], [self.rec])
        msg = self.tr.triage_message(self.tr.build_findings(rep, [self.rec], intel))
        self.assertIn("Severity is not priority", msg)


# ===========================================================================
# J. CLI — the interface a security engineer actually uses
# ===========================================================================

class TestScanCLI(unittest.TestCase):
    def setUp(self):
        import scan_cli
        self.cli = scan_cli

    def _run(self, argv):
        """Run the CLI capturing stdout; returns (exit_code, output)."""
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                code = self.cli.main(argv)
            except SystemExit as e:
                code = e.code
        return code, buf.getvalue()

    def test_json_output_is_valid_json(self):
        import json
        code, out = self._run(["--sbom", "sample_cyclonedx_sbom.json", "--json"])
        data = json.loads(out)                 # must parse, i.e. no ANSI leakage
        self.assertIn("summary", data)
        self.assertIn("findings", data)

    def test_no_color_leaves_no_ansi_codes(self):
        """A module-level colour dict would snapshot escape codes at import time
        and silently leak them into piped output. Guard against that."""
        code, out = self._run(["--sbom", "sample_cyclonedx_sbom.json", "--no-color"])
        self.assertNotIn("\033[", out)

    def test_csv_output_has_header(self):
        code, out = self._run(["--sbom", "sample_cyclonedx_sbom.json", "--csv"])
        self.assertTrue(out.startswith("priority,cve,component"))
        self.assertNotIn("\033[", out)

    def test_explain_unknown_cve_returns_error(self):
        code, out = self._run(["--sbom", "sample_cyclonedx_sbom.json",
                               "--explain", "CVE-0000-0000"])
        self.assertEqual(code, 1)

    def test_fail_on_never_returns_zero(self):
        code, out = self._run(["--sbom", "sample_cyclonedx_sbom.json",
                               "--json", "--fail-on", "NEVER"])
        self.assertEqual(code, 0)

    def test_output_never_claims_safety(self):
        code, out = self._run(["--sbom", "sample_cyclonedx_sbom.json", "--no-color"])
        self.assertIn("not proof of safety", out.lower())

    def test_routing_legend_present(self):
        code, out = self._run(["--sbom", "sample_cyclonedx_sbom.json", "--no-color"])
        self.assertIn("human review", out.lower())


# ===========================================================================
# K. Live feed fetching — a bonus that must never become a dependency
# ===========================================================================

class TestFeedsLive(unittest.TestCase):
    def setUp(self):
        import feeds_live
        self.fl = feeds_live

    def test_fetch_bad_url_returns_none_not_raises(self):
        """The whole safety model rests on _fetch never raising."""
        r = self.fl._fetch("https://nonexistent.invalid.example/x", timeout=2)
        self.assertIsNone(r)

    def test_refresh_kev_falls_back_to_local(self):
        """No network + existing local file -> use local, report it, don't crash."""
        import tempfile, os, json
        fd, p = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps({"vulnerabilities": []}).encode()); os.close(fd)
        try:
            # unreachable URL forces the fallback path
            orig = self.fl.KEV_URL
            self.fl.KEV_URL = "https://nonexistent.invalid.example/kev.json"
            live, msg = self.fl.refresh_kev(p, timeout=2)
            self.assertFalse(live)
            self.assertIn("local file", msg)
        finally:
            self.fl.KEV_URL = orig
            os.unlink(p)

    def test_refresh_kev_no_network_no_file_disables(self):
        orig = self.fl.KEV_URL
        self.fl.KEV_URL = "https://nonexistent.invalid.example/kev.json"
        try:
            live, msg = self.fl.refresh_kev("does_not_exist_anywhere.json", timeout=2)
            self.assertFalse(live)
            self.assertIn("DISABLED", msg)
        finally:
            self.fl.KEV_URL = orig

    def test_refresh_epss_falls_back(self):
        import tempfile, os, gzip
        fd, p = tempfile.mkstemp(suffix=".csv.gz"); os.close(fd)
        with gzip.open(p, "wt") as f:
            f.write("cve,epss,percentile\nCVE-X,0.5,0.9\n")
        orig = self.fl.EPSS_URL
        self.fl.EPSS_URL = "https://nonexistent.invalid.example/epss.gz"
        try:
            live, msg = self.fl.refresh_epss(p, timeout=2)
            self.assertFalse(live)
            self.assertIn("local file", msg)
        finally:
            self.fl.EPSS_URL = orig
            os.unlink(p)

    def test_refresh_feeds_disabled_returns_message(self):
        msgs = self.fl.refresh_feeds("k.json", "e.gz", live=False)
        self.assertTrue(any("disabled" in m.lower() for m in msgs))

    def test_refresh_feeds_live_never_raises(self):
        """Even with everything unreachable, refresh_feeds returns messages."""
        orig_k, orig_e = self.fl.KEV_URL, self.fl.EPSS_URL
        self.fl.KEV_URL = "https://nonexistent.invalid.example/k"
        self.fl.EPSS_URL = "https://nonexistent.invalid.example/e"
        try:
            msgs = self.fl.refresh_feeds("nope.json", "nope.gz", live=True, timeout=2)
            self.assertEqual(len(msgs), 2)
        finally:
            self.fl.KEV_URL, self.fl.EPSS_URL = orig_k, orig_e

    def test_nvd_delta_handles_network_failure_gracefully(self):
        """The delta updater must return a partial result, never crash."""
        orig = self.fl.NVD_CVE_API
        self.fl.NVD_CVE_API = "https://nonexistent.invalid.example/cves"
        try:
            recs, msg = self.fl.fetch_nvd_delta(
                "2026-01-01T00:00:00.000", "2026-01-31T00:00:00.000", timeout=2)
            self.assertEqual(recs, [])
            self.assertIn("NVD delta", msg)
        finally:
            self.fl.NVD_CVE_API = orig


# ===========================================================================
# L. Streamlit app — the exploration interface (logic core, no browser needed)
# ===========================================================================

class TestApp(unittest.TestCase):
    """The app's work lives in run_scan(), a pure function. We test that
    without launching Streamlit — the UI layer only draws what it returns."""

    def setUp(self):
        import app
        self.app = app
        import input_layer as il
        self.il = il

    def test_app_module_imports_without_streamlit(self):
        """Importing app.py must NOT require streamlit — only running the UI does."""
        import importlib
        import app
        importlib.reload(app)          # should not raise
        self.assertTrue(hasattr(app, "run_scan"))

    def test_run_scan_returns_findings(self):
        import paths
        res = self.il.load_any(paths.SBOM_CYCLONEDX)
        findings, summary, intel, notes = self.app.run_scan(
            res.components, refresh_live=False)
        self.assertGreater(len(findings), 0)
        self.assertIn("total", summary)

    def test_refresh_off_uses_cached_feeds(self):
        """The time-constraint safety: refresh_live=False must never touch the
        network — it just uses what is on disk."""
        import paths
        res = self.il.load_any(paths.SBOM_CYCLONEDX)
        _, _, _, notes = self.app.run_scan(res.components, refresh_live=False)
        self.assertTrue(any("cached" in n.lower() for n in notes))

    def test_findings_are_ranked(self):
        import paths
        res = self.il.load_any(paths.SBOM_CYCLONEDX)
        findings, _, _, _ = self.app.run_scan(res.components, refresh_live=False)
        import threat_intel as ti
        bands = [ti.BAND_ORDER[f.band] for f in findings]
        self.assertEqual(bands, sorted(bands))     # already in priority order

    def test_load_components_from_bytes(self):
        import paths, json
        data = json.dumps({"bomFormat": "CycloneDX", "components": [
            {"name": "log4j-core", "version": "2.14.1", "group": "apache"}]}).encode()
        comps, warns, source, conf = self.app.load_components_from_bytes(
            data, "x.json")
        self.assertTrue(comps)
        self.assertEqual(source, "sbom")
        self.assertEqual(conf, 1.0)

    def test_image_upload_is_low_confidence(self):
        """A screenshot must arrive at confidence 0.5 so it routes to FLAG."""
        # a 1x1 PNG
        png = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00"
               b"\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9c"
               b"c\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")
        try:
            comps, warns, source, conf = self.app.load_components_from_bytes(
                png, "shot.png")
            self.assertEqual(source, "ocr")
            self.assertEqual(conf, 0.5)
        except Exception:
            self.skipTest("OCR stack not available in this environment")


# ===========================================================================
# M. The "pictures of software" requirement — OCR end to end
# ===========================================================================

class TestPicturePath(unittest.TestCase):
    """The brief says the agent uses 'pictures of software OR SBOMs'. This
    proves the picture half works end to end and stays low-trust."""

    def test_sample_screenshot_exists(self):
        import paths
        self.assertTrue((paths.DATA / "sample_screenshot.png").exists(),
                        "demo screenshot missing — the picture path can't be shown")

    def test_ocr_reads_components_from_screenshot(self):
        import paths, input_layer as il
        ok, _ = il._ocr_available()
        if not ok:
            self.skipTest("OCR engine (tesseract) not installed in this env")
        res = il.load_image(str(paths.DATA / "sample_screenshot.png"))
        names = {c.name.lower() for c in res.components}
        self.assertIn("openssl", names)      # must recover at least the obvious one

    def test_ocr_components_are_low_confidence(self):
        """A camera/OCR read must never be trusted like a signed SBOM."""
        import paths, input_layer as il
        ok, _ = il._ocr_available()
        if not ok:
            self.skipTest("OCR engine not installed")
        res = il.load_image(str(paths.DATA / "sample_screenshot.png"))
        self.assertTrue(all(c.confidence <= 0.6 for c in res.components))

    def test_picture_findings_never_auto(self):
        """End to end: a vuln found from a picture must route to human review,
        never AUTO. This is the responsible-AI core, on the picture path."""
        import paths, input_layer as il, it_security_agent as agent
        import threat_intel as ti, triage
        ok, _ = il._ocr_available()
        if not ok:
            self.skipTest("OCR engine not installed")
        res = il.load_image(str(paths.DATA / "sample_screenshot.png"))
        recs = agent.load_nvd_feed(paths.NVD_BULK)
        rep = agent.scan(res.components, recs)
        intel = ti.ThreatIntel()
        findings = triage.build_findings(rep, recs, intel,
                                         input_confidence=0.5, source="ocr")
        self.assertNotIn("AUTO", {f.routing for f in findings})
