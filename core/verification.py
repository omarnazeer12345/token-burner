"""
Enhanced verification layer v2.
Cross-checks AI findings, filters false positives, validates evidence.
"""
import re
from typing import Dict, List, Any, Tuple

from config.settings import logger

# Patterns for false positive detection
TEST_FILE_PATTERNS = [
    r"^test_", r"_test\.", r"\.test\.", r"\.spec\.", r"_spec\.",
    r"\.mock\.", r"_mock", r"__tests__", r"/tests?/", r"/testing/",
    r"/fixtures?/", r"/mocks?/", r"\.conftest", r"jest\.", r"karma\.",
    r"\.factory\.", r"\.stub\.", r"/e2e/", r"/integration_tests?/",
    r"/unit_tests?/", r"/specs?/", r"_tests?\.", r"test_.*\.",
]

PLACEHOLDER_PATTERNS = [
    r"example[_-]?key", r"your[_-]?(api[_-]?)?key", r"placeholder",
    r"xxx+", r"changeme", r"todo[_-]?key", r"fake[_-]", r"dummy[_-]?",
    r"sample[_-]?", r"test123", r"password123", r"admin123",
    r"default[_-]", r"INSERT_KEY_HERE", r"YOUR_", r"MY_",
    r"ENTER_", r"REPLACE_", r"TEMPLATE_", r"FILL_", r"NOT_SET",
    r"put_your_", r"your_\w+_here", r"my_\w+_here",
]

VENDOR_DIRS = [
    "vendor", "node_modules", "third_party", "third-party", ".git",
    "__pycache__", ".pytest_cache", ".tox", "venv", ".venv",
    "dist", "build", "target", ".gradle", ".idea",
    ".next", "coverage", "htmlcov", ".nyc_output",
]

# Heuristic severity re-assignment based on evidence strength
EVIDENCE_STRENGTH = {
    "Critical": {
        "keywords": ["password", "secret", "key", "token", "credential"],
        "min_length": 8,
    },
    "High": {
        "keywords": ["eval", "exec", "system", "subprocess", "sql"],
        "min_length": 6,
    },
}


def verify_findings(findings: List[Dict], files: List[Dict]) -> List[Dict]:
    """Cross-check each finding against actual source code."""
    file_map = {f["path"]: f for f in files}

    for finding in findings:
        fpath = finding.get("file", "")
        verified = True
        notes = []

        # Check file exists
        if fpath not in file_map:
            verified = False
            notes.append("File not found in analyzed files")
        else:
            file_content = file_map[fpath].get("content", "")
            lines = file_content.split("\n")

            # Check line numbers
            line_nums = finding.get("line_numbers", [])
            if line_nums:
                max_line = len(lines)
                for ln in line_nums:
                    if not isinstance(ln, int):
                        try:
                            ln = int(ln)
                            finding["line_numbers"] = [ln]
                        except (ValueError, TypeError):
                            verified = False
                            notes.append(f"Invalid line number: {ln}")
                            break
                    if ln < 1 or ln > max_line:
                        verified = False
                        notes.append(
                            f"Line {ln} out of range (file has {max_line} lines)"
                        )
                        break

            # Check evidence exists in file
            evidence = finding.get("evidence", "")
            if evidence:
                # Try exact match first
                if evidence not in file_content:
                    # Try normalized match (ignore whitespace differences)
                    norm_evidence = re.sub(r"\s+", "", evidence)
                    norm_content = re.sub(r"\s+", "", file_content)
                    if norm_evidence not in norm_content:
                        verified = False
                        notes.append("Evidence snippet not found in file content")

        finding["verified"] = verified
        finding["verification_notes"] = (
            "; ".join(notes) if notes else "All checks passed"
        )

    return findings


def filter_false_positives(findings: List[Dict]) -> List[Dict]:
    """Remove obvious false positives from findings list."""
    filtered = []

    for finding in findings:
        fpath = finding.get("file", "")
        evidence = finding.get("evidence", "").lower()
        description = finding.get("description", "").lower()
        category = finding.get("category", "")

        # ---- Rule 1: Skip vendor / generated / dependency directories ----
        if any(vd in fpath for vd in VENDOR_DIRS):
            continue

        # ---- Rule 2: Skip test files (except secret leaks) ----
        is_test = any(re.search(p, fpath, re.I) for p in TEST_FILE_PATTERNS)
        if is_test and category != "Secret Leak":
            continue

        # ---- Rule 3: Skip placeholder / example values ----
        if any(re.search(p, evidence, re.I) for p in PLACEHOLDER_PATTERNS):
            continue

        # Also check description for placeholder hints
        if any(re.search(p, description, re.I) for p in PLACEHOLDER_PATTERNS):
            continue

        # ---- Rule 4: Skip unverified findings ----
        if finding.get("verified") is False:
            continue

        # ---- Rule 5: Skip documentation files (except secret leaks) ----
        if fpath.endswith((".md", ".rst", ".txt", ".adoc")) and category != "Secret Leak":
            continue

        # ---- Rule 6: Skip minified / generated files ----
        if fpath.endswith((".min.js", ".min.css", ".bundle.js", ".map")):
            continue

        filtered.append(finding)

    return filtered


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """Remove duplicate findings (same file + same line + same category)."""
    seen: set = set()
    unique: List[Dict] = []

    for f in findings:
        line_nums = f.get("line_numbers", [])
        # Normalize line_numbers to a hashable tuple
        if isinstance(line_nums, list):
            key = (f.get("file", ""), tuple(line_nums), f.get("category", ""))
        elif isinstance(line_nums, int):
            key = (f.get("file", ""), (line_nums,), f.get("category", ""))
        else:
            key = (f.get("file", ""), tuple(), f.get("category", ""))

        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def score_confidence(finding: Dict) -> float:
    """
    Compute a numeric confidence score (0.0 - 1.0) for a finding.

    Factors:
      - verification status
      - evidence quality
      - confidence field value
      - category-specific heuristics
    """
    score = 0.5  # Baseline

    # Verification bonus
    if finding.get("verified") is True:
        score += 0.2
    elif finding.get("verified") is False:
        score -= 0.3

    # Confidence field
    conf = finding.get("confidence", "Medium")
    conf_scores = {"High": 0.2, "Medium": 0.0, "Low": -0.15}
    score += conf_scores.get(conf, 0.0)

    # Evidence quality
    evidence = finding.get("evidence", "")
    if len(evidence) > 20:
        score += 0.1
    if len(evidence) < 5:
        score -= 0.1

    # Severity alignment heuristic
    severity = finding.get("severity", "Info")
    cat = finding.get("category", "Other")
    evidence_lower = evidence.lower()

    # Check category-specific keyword presence
    strength = EVIDENCE_STRENGTH.get(severity, {})
    if strength:
        kw_hits = sum(
            1 for kw in strength.get("keywords", [])
            if kw in evidence_lower or kw in finding.get("description", "").lower()
        )
        if kw_hits > 0:
            score += 0.1 * min(kw_hits, 2)

    return round(max(0.0, min(1.0, score)), 2)


def verify_and_filter(findings: List[Dict], files: List[Dict]) -> List[Dict]:
    """
    Full verification pipeline: verify -> filter false positives -> dedup -> score.

    Returns clean, ranked findings ready for reporting.
    """
    logger.info(
        f"Verification pipeline: {len(findings)} findings before processing"
    )

    # Step 1: Cross-check evidence against source files
    findings = verify_findings(findings, files)

    # Step 2: Strip obvious false positives
    findings = filter_false_positives(findings)

    # Step 3: Remove duplicates
    findings = deduplicate_findings(findings)

    # Step 4: Compute confidence scores
    for f in findings:
        f["confidence_score"] = score_confidence(f)

    # Step 5: Sort by (severity desc, confidence_score desc)
    severity_order = {
        "Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1,
    }
    findings.sort(
        key=lambda f: (
            severity_order.get(f.get("severity", "Info"), 0),
            f.get("confidence_score", 0.5),
        ),
        reverse=True,
    )

    logger.info(
        f"Verification pipeline: {len(findings)} findings after processing"
    )
    return findings
