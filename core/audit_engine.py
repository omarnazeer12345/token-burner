"""
Enhanced AI Security Audit Engine v2.
Multi-pass analysis, CWE mapping, CVSS estimation, parallel processing support.
Uses Kimi API (Anthropic-compatible endpoint).
"""
import json
import os
import re
import time
import threading
import urllib.request
from typing import Dict, List, Any, Optional

from config.settings import (
    MAX_RETRIES, RETRY_DELAY, KIMI_API_SEMAPHORE,
    MAX_FILES_PER_REPO, logger
)

# ── Kimi API Configuration (Anthropic protocol) ───────────────────────────────
KIMI_BASE_URL = os.getenv("KIMI_BASE_URL", "https://api.kimi.com/coding/v1/messages")
KIMI_API_KEY = os.getenv("KIMI_API_KEY", "")
KIMI_MODEL = os.getenv("KIMI_MODEL", "kimi-for-coding")
KIMI_MAX_TOKENS = int(os.getenv("KIMI_MAX_TOKENS", "4096"))

# Thread-safe semaphore for API rate limiting
_api_semaphore = threading.Semaphore(KIMI_API_SEMAPHORE)

# CWE mapping for categories
CWE_MAP = {
    "Secret Leak": ["CWE-798", "CWE-200", "CWE-312"],
    "Injection": ["CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-917"],
    "RCE": ["CWE-94", "CWE-95", "CWE-96"],
    "SSRF": ["CWE-918"],
    "Path Traversal": ["CWE-22", "CWE-23"],
    "Auth Bypass": ["CWE-287", "CWE-306", "CWE-863"],
    "Crypto": ["CWE-326", "CWE-327", "CWE-330", "CWE-331"],
    "Memory Safety": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-416"],
    "Dependency": ["CWE-1104"],
    "Info Leak": ["CWE-200", "CWE-209", "CWE-532"],
    "Race Condition": ["CWE-362", "CWE-367"],
    "Misconfig": ["CWE-16", "CWE-276", "CWE-522"],
    "Deserialization": ["CWE-502"],
    "Other": ["CWE-20"],
}

SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}


def _get_api_key() -> str:
    """Get API key from environment or module-level fallback."""
    api_key = os.environ.get("KIMI_API_KEY", KIMI_API_KEY)
    if not api_key:
        raise RuntimeError("KIMI_API_KEY not set!")
    return api_key


def call_kimi_api(prompt: str, model: str = None, max_retries: int = MAX_RETRIES,
                  temperature: float = 0.1) -> str:
    """Call Kimi API (Anthropic protocol) with semaphore-controlled concurrency."""
    if not model:
        model = KIMI_MODEL

    api_key = _get_api_key()

    payload = {
        "model": model,
        "max_tokens": KIMI_MAX_TOKENS,
        "messages": [
            {"role": "user", "content": prompt},
        ],
    }

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "anthropic-version": "2023-06-01",
    }

    req = urllib.request.Request(KIMI_BASE_URL, data=body, headers=headers, method="POST")

    with _api_semaphore:
        for attempt in range(1, max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=None) as resp:
                    resp_bytes = resp.read()

                resp_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
                return resp_json["content"][0]["text"]

            except urllib.error.HTTPError as e:
                resp_text = e.read().decode("utf-8", errors="replace")
                error_str = resp_text.lower()
                if "invalid_authentication" in error_str or "incorrect_api_key" in error_str:
                    logger.error(f"Kimi API auth failed: {e.code} - {resp_text}")
                    raise RuntimeError(f"Kimi API auth failed: {e.code}")
                if "content_filter" in error_str:
                    logger.error(f"Kimi content filter triggered: {e.code} - {resp_text}")
                    raise RuntimeError(f"Kimi content filter: {e.code}")

                wait = RETRY_DELAY * (2 ** (attempt - 1))
                logger.warning(f"Kimi API attempt {attempt}/{max_retries} failed: HTTP {e.code} — {resp_text[:300]}. Retrying in {wait}s...")
                if attempt < max_retries:
                    time.sleep(wait)
                else:
                    logger.error(f"Kimi API failed after {max_retries} attempts: HTTP {e.code} — {resp_text[:500]}")
                    raise RuntimeError(f"Kimi API failed: HTTP {e.code}")

            except Exception as e:
                wait = RETRY_DELAY * (2 ** (attempt - 1))
                logger.warning(f"Kimi API attempt {attempt}/{max_retries} failed: {e}. Retrying in {wait}s...")
                if attempt < max_retries:
                    time.sleep(wait)
                else:
                    logger.error(f"Kimi API failed after {max_retries} attempts: {e}")
                    raise RuntimeError(f"Kimi API failed: {e}")

    return ""


def create_audit_prompt(files: List[Dict], repo_name: str, repo_metadata: Dict) -> str:
    """Create a comprehensive security audit prompt."""
    file_tree = "\n".join([f"  {i+1}. {f['path']} ({f.get('lines', '?')} lines)"
                          for i, f in enumerate(files[:MAX_FILES_PER_REPO])])

    file_contents = ""
    for f in files[:MAX_FILES_PER_REPO]:
        content = f.get('content', '')
        file_contents += f"\n{'='*60}\nFILE: {f['path']}\n{'='*60}\n{content}\n"

    prompt = f"""You are a professional application security engineer conducting a code review. Please review the following source files and produce a structured security assessment report.

REPOSITORY: {repo_name}
FILES ANALYZED: {len(files)}

FILE TREE:
{file_tree}

SOURCE CODE:
{file_contents}

INSTRUCTIONS:
1. Review the provided source files for potential security weaknesses
2. Identify issues such as: missing input validation, hardcoded credentials, unsafe use of eval/exec, SQL injection risks, XSS risks, insecure cryptographic practices, verbose error handling, path traversal risks, SSRF risks, missing authentication checks, and insecure deserialization
3. For each issue found, document: file path, line numbers, severity level (Critical/High/Medium/Low/Info), category, CWE identifier, description, evidence from the code, and recommended remediation
4. Include code snippets as evidence for each finding
5. Write your response as a professional Markdown security audit report with clear headings and bullet points

REPORT FORMAT:
# Security Audit Report: {repo_name}

## Executive Summary
(Overview of scope and key risk areas identified)

## Findings

### [SEVERITY] Finding Title
- **File:** `path/to/file`
- **Line(s):** 42
- **Category:** Injection / Secret Leak / etc.
- **CWE:** CWE-XXX
- **Description:** Clear explanation of the issue
- **Evidence:**
```python
code snippet showing the issue
```
- **Remediation:** Recommended fix

(Repeat for every finding)

## Recommendations
(Summary of prioritized remediation steps)
"""

    # Guard against oversized payload (~2 MB limit) — truncate files if needed
    MAX_PAYLOAD_BYTES = 1_800_000
    while len(prompt.encode("utf-8")) > MAX_PAYLOAD_BYTES and len(files) > 10:
        files = files[:len(files)//2]
        file_tree = "\n".join([f"  {i+1}. {f['path']} ({f.get('lines', '?')} lines)"
                              for i, f in enumerate(files[:MAX_FILES_PER_REPO])])
        file_contents = ""
        for f in files[:MAX_FILES_PER_REPO]:
            content = f.get('content', '')
            file_contents += f"\n{'='*60}\nFILE: {f['path']}\n{'='*60}\n{content}\n"
        prompt = f"""You are a professional application security engineer conducting a code review. Please review the following source files and produce a structured security assessment report.

REPOSITORY: {repo_name}
FILES ANALYZED: {len(files)}

FILE TREE:
{file_tree}

SOURCE CODE:
{file_contents}

INSTRUCTIONS:
1. Review the provided source files for potential security weaknesses
2. Identify issues such as: missing input validation, hardcoded credentials, unsafe use of eval/exec, SQL injection risks, XSS risks, insecure cryptographic practices, verbose error handling, path traversal risks, SSRF risks, missing authentication checks, and insecure deserialization
3. For each issue found, document: file path, line numbers, severity level (Critical/High/Medium/Low/Info), category, CWE identifier, description, evidence from the code, and recommended remediation
4. Include code snippets as evidence for each finding
5. Write your response as a professional Markdown security audit report with clear headings and bullet points

REPORT FORMAT:
# Security Audit Report: {repo_name}

## Executive Summary
(Overview of scope and key risk areas identified)

## Findings

### [SEVERITY] Finding Title
- **File:** `path/to/file`
- **Line(s):** 42
- **Category:** Injection / Secret Leak / etc.
- **CWE:** CWE-XXX
- **Description:** Clear explanation of the issue
- **Evidence:**
```python
code snippet showing the issue
```
- **Remediation:** Recommended fix

(Repeat for every finding)

## Recommendations
(Summary of prioritized remediation steps)
"""

    return prompt


def _repair_json(text: str) -> str:
    """Aggressively repair common JSON malformations from LLM output."""
    # 1. Strip markdown fences and surrounding text
    text = text.strip()
    if text.startswith('```'):
        text = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\n?```\s*$', '', text)
        text = text.strip()

    # 2. Remove single-line comments
    text = re.sub(r'//.*$', '', text, flags=re.MULTILINE)
    # Remove multi-line comments
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)

    # 3. Remove trailing commas before ] or }
    text = re.sub(r',(\s*[}\]])', r'\1', text)

    # 4. Fix unescaped newlines inside string values (basic heuristic)
    # Replace raw newlines that appear inside quotes with \n
    def fix_newlines_in_strings(s):
        result = []
        in_str = False
        escape = False
        for ch in s:
            if escape:
                result.append(ch)
                escape = False
                continue
            if ch == '\\':
                result.append(ch)
                escape = True
                continue
            if ch == '"':
                in_str = not in_str
                result.append(ch)
                continue
            if ch in '\n\r' and in_str:
                result.append('\\n')
                continue
            result.append(ch)
        return ''.join(result)
    text = fix_newlines_in_strings(text)

    # 5. Balance braces by truncating at the last valid closing brace
    open_count = 0
    last_valid_pos = -1
    for i, ch in enumerate(text):
        if ch == '{':
            open_count += 1
        elif ch == '}':
            open_count -= 1
            if open_count == 0:
                last_valid_pos = i
    if last_valid_pos > 0:
        text = text[:last_valid_pos + 1]

    return text.strip()


def _extract_json(text: str) -> Optional[Dict]:
    """Extract JSON from AI response with aggressive repair strategies."""
    # Strategy 1: Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Markdown fences
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL | re.IGNORECASE)
    if match:
        inner = match.group(1).strip()
        try:
            return json.loads(inner)
        except json.JSONDecodeError:
            repaired = _repair_json(inner)
            try:
                return json.loads(repaired)
            except json.JSONDecodeError:
                pass

    # Strategy 3: Find the largest { ... } block and repair it
    best = None
    best_len = 0
    for m in re.finditer(r'\{', text):
        start = m.start()
        depth = 0
        for i in range(start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    if len(candidate) > best_len:
                        best_len = len(candidate)
                        best = candidate
                    break
    if best:
        try:
            return json.loads(best)
        except json.JSONDecodeError:
            repaired = _repair_json(best)
            try:
                return json.loads(repaired)
            except json.JSONDecodeError:
                pass

    # Strategy 4: Repair the entire text and try again
    repaired = _repair_json(text)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    return None


def _assign_cwe(category: str) -> str:
    """Assign CWE ID based on category."""
    cwes = CWE_MAP.get(category, ["CWE-20"])
    return cwes[0] if cwes else "CWE-20"


def _estimate_cvss(finding: Dict) -> Dict:
    """Estimate CVSS 3.1 score."""
    sev = finding.get('severity', 'Info')
    scores = {'Critical': 9.0, 'High': 7.5, 'Medium': 5.5, 'Low': 3.5, 'Info': 0.0}
    base = scores.get(sev, 0.0)

    adjustments = {
        'Secret Leak': 0.5, 'RCE': 0.5, 'Injection': 0.3, 'Auth Bypass': 0.4,
        'SSRF': 0.3, 'Path Traversal': 0.2, 'Deserialization': 0.4,
    }
    base += adjustments.get(finding.get('category', ''), 0)
    base = min(10.0, base)

    vectors = {
        'Critical': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'High': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L',
        'Medium': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L',
        'Low': 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N',
        'Info': 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N',
    }
    return {'cvss_score': round(base, 1), 'cvss_vector': vectors.get(sev, ''), 'cvss_severity': sev}


def audit_repo(repo_name: str, files: List[Dict], metadata: Dict) -> Dict:
    """Perform full AI security audit on a repository. Returns raw report + optional structured findings."""
    start_time = time.time()

    try:
        prompt = create_audit_prompt(files, repo_name, metadata)
        raw_report = call_kimi_api(prompt, model=KIMI_MODEL)

        # Optionally try to extract structured findings for stats (best effort)
        findings = []
        try:
            result = _extract_json(raw_report)
            if result:
                raw_findings = result.get('findings', [])
                valid_files = {f['path'] for f in files}
                for i, f in enumerate(raw_findings):
                    if f.get('file') and f['file'] not in valid_files:
                        continue
                    f['id'] = f"F-{metadata.get('repo_id', '???')}-{i:03d}"
                    if not f.get('cwe_id'):
                        f['cwe_id'] = _assign_cwe(f.get('category', 'Other'))
                    f.update(_estimate_cvss(f))
                    sev = f.get('severity', 'Info')
                    if sev not in SEVERITY_ORDER:
                        f['severity'] = 'Info'
                    findings.append(f)
        except Exception:
            pass  # Raw text mode — structured findings are optional

        summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for f in findings:
            s = f.get('severity', 'Info')
            summary[s] = summary.get(s, 0) + 1

        duration = time.time() - start_time
        return {
            'repo': repo_name,
            'repo_id': metadata.get('repo_id', ''),
            'audit_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'files_analyzed': len(files),
            'raw_report': raw_report,
            'findings': findings,
            'summary': {
                'critical_count': summary['Critical'],
                'high_count': summary['High'],
                'medium_count': summary['Medium'],
                'low_count': summary['Low'],
                'info_count': summary['Info'],
                'total_files': len(files),
                'duration_seconds': round(duration, 2),
                'total_findings': len(findings),
            }
        }

    except Exception as e:
        logger.error(f"Audit failed for {repo_name}: {e}")
        return _empty_result(repo_name, str(e))


def _empty_result(repo_name: str, error: str = '') -> Dict:
    return {
        'repo': repo_name, 'repo_id': '',
        'audit_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'files_analyzed': 0, 'raw_report': '', 'findings': [],
        'summary': {
            'critical_count': 0, 'high_count': 0, 'medium_count': 0,
            'low_count': 0, 'info_count': 0, 'total_files': 0,
            'duration_seconds': 0, 'total_findings': 0,
        },
        'error': error,
    }
