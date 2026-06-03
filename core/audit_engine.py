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

    system_msg = (
        "You are an elite security vulnerability researcher with 20+ years of experience. "
        "You specialize in finding security flaws in open-source software. Always respond "
        "with ONLY valid JSON, no markdown, no explanations outside JSON."
    )

    payload = {
        "model": model,
        "max_tokens": KIMI_MAX_TOKENS,
        "system": system_msg,
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
                logger.warning(f"Kimi API attempt {attempt}/{max_retries} failed: HTTP {e.code}. Retrying in {wait}s...")
                if attempt < max_retries:
                    time.sleep(wait)
                else:
                    logger.error(f"Kimi API failed after {max_retries} attempts: HTTP {e.code}")
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

    prompt = f"""Perform a comprehensive security audit of the following open-source code repository.

REPOSITORY: {repo_name}
FILES ANALYZED: {len(files)}

FILE TREE:
{file_tree}

SOURCE CODE:
{file_contents}

INSTRUCTIONS:
1. Analyze ALL provided files for security vulnerabilities
2. Focus ONLY on ACTUAL exploitable vulnerabilities
3. For each finding, provide exact file path, line numbers, severity, category, CWE ID, description, evidence code snippet, and remediation
4. Check for: hardcoded secrets, injection vulns (SQLi, XSS, CMDi, XXE), RCE, SSRF, path traversal, auth bypass, crypto issues, memory safety, dependency issues, info leaks, race conditions, misconfigurations
5. Do NOT report test data, examples, documentation issues, or style problems
6. You MUST respond with ONLY valid JSON. No markdown, no explanations.

JSON FORMAT:
{{"findings": [{{"severity": "Critical|High|Medium|Low|Info", "category": "Secret Leak|Injection|RCE|SSRF|Path Traversal|Auth Bypass|Crypto|Memory Safety|Dependency|Info Leak|Race Condition|Misconfig|Deserialization|Other", "cwe_id": "CWE-XXX", "file": "path/to/file", "line_numbers": [1], "description": "...", "evidence": "code snippet", "remediation": "how to fix", "confidence": "High|Medium|Low"}}]}}
"""
    return prompt


def _extract_json(text: str) -> Optional[Dict]:
    """Extract JSON from AI response with multiple strategies."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try markdown fences
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Try raw JSON object
    match = re.search(r'\{[\s\S]*\}', text)
    if match:
        try:
            return json.loads(match.group(0))
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
    """Perform full AI security audit on a repository."""
    start_time = time.time()

    try:
        prompt = create_audit_prompt(files, repo_name, metadata)
        response = call_kimi_api(prompt, model=KIMI_MODEL)

        result = _extract_json(response)
        if not result:
            logger.warning(f"JSON parse failed for {repo_name}, retrying...")
            fixed_prompt = prompt + "\n\nIMPORTANT: Respond ONLY with valid JSON. No other text."
            response = call_kimi_api(fixed_prompt, model=KIMI_MODEL)
            result = _extract_json(response)

        if not result:
            logger.error(f"Failed to parse JSON for {repo_name} after retry")
            return _empty_result(repo_name)

        findings = result.get('findings', [])
        valid_files = {f['path'] for f in files}

        processed = []
        for i, f in enumerate(findings):
            if f.get('file') and f['file'] not in valid_files:
                continue
            f['id'] = f"F-{metadata.get('repo_id', '???')}-{i:03d}"
            if not f.get('cwe_id'):
                f['cwe_id'] = _assign_cwe(f.get('category', 'Other'))
            f.update(_estimate_cvss(f))
            sev = f.get('severity', 'Info')
            if sev not in SEVERITY_ORDER:
                f['severity'] = 'Info'
            processed.append(f)

        summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for f in processed:
            s = f.get('severity', 'Info')
            summary[s] = summary.get(s, 0) + 1

        duration = time.time() - start_time
        return {
            'repo': repo_name,
            'repo_id': metadata.get('repo_id', ''),
            'audit_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'files_analyzed': len(files),
            'findings': processed,
            'summary': {
                'critical_count': summary['Critical'],
                'high_count': summary['High'],
                'medium_count': summary['Medium'],
                'low_count': summary['Low'],
                'info_count': summary['Info'],
                'total_files': len(files),
                'duration_seconds': round(duration, 2),
                'total_findings': len(processed),
            }
        }

    except Exception as e:
        logger.error(f"Audit failed for {repo_name}: {e}")
        return _empty_result(repo_name, str(e))


def _empty_result(repo_name: str, error: str = '') -> Dict:
    return {
        'repo': repo_name, 'repo_id': '',
        'audit_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'files_analyzed': 0, 'findings': [],
        'summary': {
            'critical_count': 0, 'high_count': 0, 'medium_count': 0,
            'low_count': 0, 'info_count': 0, 'total_files': 0,
            'duration_seconds': 0, 'total_findings': 0,
        },
        'error': error,
    }
