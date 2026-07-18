"""
IT Security Agent - Input Layer (Stage A + B: Input + Extraction)
==================================================================

The project goal is an agent that ingests *pictures of software or SBOMs* and
finds vulnerabilities. The matching engine only understands one thing: a list of
normalized `Component` objects. This module is the single funnel that turns
every supported input type into that list -- so the rest of the pipeline
(matching, scoring, fairness, reporting) never has to know or care where a
component came from.

Design principles (why this is scalable)
----------------------------------------
1. ONE output contract. Every loader returns `list[Component]`. Add a new input
   format later = write one `load_*` function + register it. Nothing downstream
   changes.
2. PROVENANCE + CONFIDENCE travel with the data. Each Component carries a
   `source` ("cyclonedx", "spdx", "requirements", "image_ocr", "manual", ...)
   and an extraction `confidence` in [0,1]. Deterministic parses = high
   confidence; OCR from a screenshot = lower. Downstream Responsible-AI routing
   (AUTO / SUGGEST / FLAG) reads this directly.
3. GRACEFUL DEGRADATION. Optional heavy deps (OCR) are imported lazily. If the
   OCR stack is missing, the image path raises a clear, actionable error instead
   of crashing the import for everyone.
4. FORMAT AUTO-DETECTION. `load_any(path)` sniffs the file and dispatches, so a
   user (or an agent loop) can throw any supported file at one entry point.

Supported input types
----------------------
  SBOM (machine):   CycloneDX JSON, SPDX JSON, simple/legacy {"components":[...]}
  Dependency files: requirements.txt (pip), package.json (npm)
  Images:           PNG/JPG screenshots of software  -> OCR -> components
  Manual:           a single typed "name version vendor" line, or a Python list
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

def _resolve(name):
    """Find a data file whether run from repo root, src/, tests/, or a notebook."""
    from pathlib import Path
    here = Path(__file__).resolve().parent
    for cand in (Path(name), here.parent / "data" / name,
                 here.parent / "feeds" / name, here / name):
        if cand.exists():
            return str(cand)
    return name



# ---------------------------------------------------------------------------
# The universal contract: one Component type, one confidence, one provenance.
# (Kept import-light so this module can be reused without the matcher.)
# ---------------------------------------------------------------------------

@dataclass
class Component:
    """One piece of software to scan. Produced by ANY input path."""
    name: str
    version: str
    vendor: str | None = None
    source: str = "unknown"          # provenance: which loader produced this
    confidence: float = 1.0          # extraction confidence in [0,1]
    raw: str | None = None           # original text/line, for auditability

    def normalized(self) -> tuple[str, str, str]:
        """Normalized (vendor, product, version) triple for matching.
        Identical rules to the Week 1 matcher so behavior is unchanged."""
        vendor = (self.vendor or "*").lower().strip()
        product = self.name.lower().strip()
        product = re.sub(r"[-_](core|client|server|lib)$", "", product)
        product = re.sub(r"\.(jar|whl|tar\.gz|zip)$", "", product)
        version = self.version.lower().strip().lstrip("v")
        return vendor, product, version


@dataclass
class IngestResult:
    """What the input layer hands to the pipeline: the components plus a
    transparent record of how ingestion went (for the audit log / model card)."""
    components: list[Component] = field(default_factory=list)
    source: str = "unknown"
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        n = len(self.components)
        if not n:
            return f"[{self.source}] no components extracted. " + " ".join(self.warnings)
        avg_conf = sum(c.confidence for c in self.components) / n
        low = sum(1 for c in self.components if c.confidence < 0.6)
        line = f"[{self.source}] extracted {n} component(s), avg confidence {avg_conf:.2f}"
        if low:
            line += f"; {low} low-confidence (<0.60) -> should be human-reviewed"
        if self.warnings:
            line += "\n  warnings: " + "; ".join(self.warnings)
        return line


# ---------------------------------------------------------------------------
# 1. SBOM loaders (deterministic -> high confidence)
# ---------------------------------------------------------------------------

def load_cyclonedx(data: dict) -> IngestResult:
    """CycloneDX SBOM. Components live under `components`, each with
    name/version and often a `group` (the vendor-ish namespace) or a
    `cpe`/`purl` we can mine for a vendor."""
    res = IngestResult(source="cyclonedx")
    for c in data.get("components", []):
        vendor = c.get("group") or c.get("publisher") or c.get("author")
        # If a CPE is present it's the most authoritative vendor source.
        cpe = c.get("cpe")
        if cpe and not vendor:
            parts = cpe.split(":")
            if len(parts) >= 5:
                vendor = parts[3]
        res.components.append(Component(
            name=c.get("name", ""),
            version=str(c.get("version", "")),
            vendor=vendor,
            source="cyclonedx",
            confidence=1.0,           # machine-generated SBOM, deterministic
            raw=json.dumps({k: c.get(k) for k in ("name", "version", "group", "cpe") if k in c}),
        ))
    if not res.components:
        res.warnings.append("CycloneDX file had no `components` array")
    return res


def load_spdx(data: dict) -> IngestResult:
    """SPDX SBOM. Software lives under `packages`; each package has a name,
    versionInfo, and optionally a supplier ('Organization: Foo')."""
    res = IngestResult(source="spdx")
    for p in data.get("packages", []):
        supplier = p.get("supplier") or p.get("originator") or ""
        # SPDX suppliers look like "Organization: Apache" or "Person: Jane".
        vendor = None
        if ":" in supplier:
            vendor = supplier.split(":", 1)[1].strip()
        elif supplier:
            vendor = supplier.strip()
        res.components.append(Component(
            name=p.get("name", ""),
            version=str(p.get("versionInfo", "")),
            vendor=vendor or None,
            source="spdx",
            confidence=1.0,
            raw=p.get("SPDXID"),
        ))
    if not res.components:
        res.warnings.append("SPDX file had no `packages` array")
    return res


def load_simple(data: dict | list) -> IngestResult:
    """The legacy/hand-built format used in Week 1:
    {"components": [{"name","version","vendor"}]}  OR a bare list of those."""
    res = IngestResult(source="simple")
    entries = data.get("components", data) if isinstance(data, dict) else data
    for e in entries:
        res.components.append(Component(
            name=e.get("name", ""),
            version=str(e.get("version", "")),
            vendor=e.get("vendor") or e.get("publisher"),
            source="simple",
            confidence=1.0,
            raw=json.dumps(e),
        ))
    return res


def _detect_sbom_flavor(data: Any) -> str:
    """Sniff which SBOM dialect a parsed JSON object is."""
    if isinstance(data, dict):
        if data.get("bomFormat") == "CycloneDX" or "components" in data and "bomFormat" in data:
            return "cyclonedx"
        if data.get("spdxVersion") or "packages" in data:
            return "spdx"
        if "components" in data:
            return "simple"
    if isinstance(data, list):
        return "simple"
    return "unknown"


def load_sbom_json(path: str) -> IngestResult:
    """Load any JSON SBOM, auto-detecting CycloneDX / SPDX / simple."""
    path = _resolve(path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    flavor = _detect_sbom_flavor(data)
    if flavor == "cyclonedx":
        return load_cyclonedx(data)
    if flavor == "spdx":
        return load_spdx(data)
    if flavor == "simple":
        return load_simple(data)
    res = IngestResult(source="unknown")
    res.warnings.append("Unrecognized JSON SBOM shape; expected CycloneDX, SPDX, or {'components':[...]}")
    return res


# ---------------------------------------------------------------------------
# 2. Dependency-file loaders (deterministic, but vendor often unknown)
# ---------------------------------------------------------------------------

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|>|<)?\s*([0-9][\w.\-]*)?")

def load_requirements_txt(path: str) -> IngestResult:
    """pip requirements.txt. Vendor is genuinely unknown here (PyPI has no
    vendor field), so we leave vendor=None and let the matcher's wildcard
    vendor logic handle it -- confidence is high on name/version, so we keep
    it at 0.9 but flag the missing vendor."""
    path = _resolve(path)
    res = IngestResult(source="requirements")
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if not m or not m.group(1):
            continue
        name, version = m.group(1), m.group(2) or ""
        res.components.append(Component(
            name=name, version=version, vendor=None,
            source="requirements",
            confidence=0.9 if version else 0.6,   # unpinned = weaker
            raw=line,
        ))
    if not res.components:
        res.warnings.append("No pinned dependencies parsed from requirements file")
    return res


def load_package_json(path: str) -> IngestResult:
    """npm package.json dependencies + devDependencies."""
    path = _resolve(path)
    res = IngestResult(source="package_json")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = re.sub(r"^[\^~>=<\s]+", "", str(spec))  # strip ^ ~ >= etc.
            res.components.append(Component(
                name=name, version=version, vendor=None,
                source="package_json",
                confidence=0.85 if version else 0.6,
                raw=f"{name}: {spec}",
            ))
    if not res.components:
        res.warnings.append("No dependencies found in package.json")
    return res


# ---------------------------------------------------------------------------
# 3. Image / OCR loader  (the "pictures of software" requirement)
#    Lazy imports so the module still works where OCR isn't installed.
# ---------------------------------------------------------------------------

# Heuristic patterns for pulling "name version" pairs out of OCR'd text:
#   "openssl 1.1.1"  |  "log4j-core: 2.14.1"  |  "nginx/1.18.0"  |  "Python 3.11.2"
_OCR_PATTERNS = [
    re.compile(r"([A-Za-z][\w.\-+]{1,40})[\s:/@v]+((?:\d+\.){1,3}\d+[\w.\-]*)"),
    re.compile(r"([A-Za-z][\w.\-+]{1,40})\s+version\s+((?:\d+\.){1,3}\d+[\w.\-]*)", re.I),
]

def _ocr_available() -> tuple[bool, str]:
    try:
        import pytesseract  # noqa
        from PIL import Image  # noqa
    except Exception as e:  # pragma: no cover - env dependent
        return False, f"OCR deps missing ({e}). Install pytesseract + pillow + the tesseract binary."
    # Also verify the tesseract *binary* is reachable, not just the wrapper.
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
    except Exception as e:  # pragma: no cover
        return False, f"tesseract binary not found ({e}). `apt install tesseract-ocr`."
    return True, ""


def extract_components_from_text(text: str, source: str = "image_ocr",
                                 base_confidence: float = 0.5) -> list[Component]:
    """Pull (name, version) candidates out of free text (OCR output or pasted
    console text). This is deliberately conservative and fully transparent:
    every hit keeps the raw line it came from, and confidence is capped low
    because OCR/screenshots are the least reliable source."""
    found: dict[tuple[str, str], Component] = {}
    for line in text.splitlines():
        for pat in _OCR_PATTERNS:
            for m in pat.finditer(line):
                name, version = m.group(1).strip(" .:-"), m.group(2).strip()
                if len(name) < 2 or name.lower() in {"version", "v", "the"}:
                    continue
                key = (name.lower(), version)
                if key not in found:
                    found[key] = Component(
                        name=name, version=version, vendor=None,
                        source=source, confidence=base_confidence, raw=line.strip(),
                    )
    return list(found.values())


def load_image(path: str, preprocess: bool = True) -> IngestResult:
    """OCR a screenshot of software (an 'About' dialog, a dependency list, a
    terminal), then extract name/version pairs. Lower confidence by design."""
    path = _resolve(path)
    res = IngestResult(source="image_ocr")
    ok, why = _ocr_available()
    if not ok:
        res.warnings.append(f"Image input unavailable: {why}")
        return res

    import pytesseract
    from PIL import Image
    img = Image.open(path)

    # Light preprocessing improves OCR on UI screenshots: grayscale + upscale.
    if preprocess:
        try:
            import cv2, numpy as np
            arr = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2GRAY)
            arr = cv2.resize(arr, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
            arr = cv2.threshold(arr, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
            text = pytesseract.image_to_string(arr)
        except Exception as e:
            res.warnings.append(f"cv2 preprocessing failed, using raw OCR ({e})")
            text = pytesseract.image_to_string(img)
    else:
        text = pytesseract.image_to_string(img)

    res.components = extract_components_from_text(text, "image_ocr", base_confidence=0.5)
    if not res.components:
        res.warnings.append("OCR ran but found no recognizable 'name version' pairs")
    else:
        res.warnings.append("OCR-sourced components are low-confidence; verify before auto-actioning")
    return res


# ---------------------------------------------------------------------------
# 4. Manual entry (typed line or in-code list)
# ---------------------------------------------------------------------------

def load_manual(spec: str | list[dict]) -> IngestResult:
    """Accept a single typed line 'name version [vendor]' or a list of dicts.
    Useful for the interactive/agent-loop path and for quick tests."""
    res = IngestResult(source="manual")
    if isinstance(spec, str):
        parts = spec.split()
        if len(parts) >= 2:
            res.components.append(Component(
                name=parts[0], version=parts[1],
                vendor=parts[2] if len(parts) > 2 else None,
                source="manual", confidence=0.8, raw=spec,
            ))
        else:
            res.warnings.append("Manual entry needs at least 'name version'")
    else:
        for e in spec:
            res.components.append(Component(
                name=e.get("name", ""), version=str(e.get("version", "")),
                vendor=e.get("vendor"), source="manual", confidence=0.8,
                raw=json.dumps(e),
            ))
    return res


# ---------------------------------------------------------------------------
# 5. THE universal entry point: throw anything at it.
# ---------------------------------------------------------------------------

# Extension -> loader. Register a new format here in one line; nothing else
# in the pipeline needs to change. THIS is the scalability seam.
_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}

def load_any(path: str) -> IngestResult:
    """Auto-detect the input type from the file and dispatch to the right
    loader. Single funnel for users and for the agent loop."""
    path = _resolve(path)
    p = Path(path)
    ext = p.suffix.lower()
    name = p.name.lower()

    if ext in _IMAGE_EXTS:
        return load_image(path)
    if name == "requirements.txt" or name.endswith(".requirements.txt") or name.endswith("_requirements.txt"):
        return load_requirements_txt(path)
    if name == "package.json" or name.endswith("_package.json") or name.endswith(".package.json"):
        return load_package_json(path)
    if ext == ".json":
        return load_sbom_json(path)          # auto-detects CycloneDX/SPDX/simple
    if ext in {".txt"}:
        # try requirements-style first, then raw-text component extraction
        res = load_requirements_txt(path)
        if res.components:
            return res
        text = p.read_text(encoding="utf-8", errors="ignore")
        r = IngestResult(source="text")
        r.components = extract_components_from_text(text, "text", base_confidence=0.7)
        if not r.components:
            r.warnings.append("Could not extract components from plain text")
        return r

    res = IngestResult(source="unknown")
    res.warnings.append(f"Unsupported input type: {ext or name}")
    return res


# Registry exposed for docs / tests / the notebook's capability table.
SUPPORTED_INPUTS = {
    "CycloneDX JSON":   "load_sbom_json (auto)",
    "SPDX JSON":        "load_sbom_json (auto)",
    "Simple JSON":      "load_sbom_json (auto)",
    "requirements.txt": "load_requirements_txt",
    "package.json":     "load_package_json",
    "Image (PNG/JPG)":  "load_image (OCR)",
    "Plain text":       "extract_components_from_text",
    "Manual line/list": "load_manual",
}


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        r = load_any(sys.argv[1])
        print(r.summary())
        for c in r.components:
            print(f"  {c.source:12} conf={c.confidence:.2f}  {c.name} {c.version} "
                  f"(vendor={c.vendor})")
    else:
        print("Supported input types:")
        for k, v in SUPPORTED_INPUTS.items():
            print(f"  {k:18} -> {v}")
