"""
AWS VDP Security Audit Pipeline - Configuration v2
Production-grade config with validation and environment detection.
"""
import os
import sys
from pathlib import Path
from typing import List, Dict, Optional
import logging
import hashlib
from datetime import datetime

# -- API Configuration ---------------------------------------------------------
KIMI_API_KEY: str = os.getenv("KIMI_API_KEY", "")
KIMI_BASE_URL: str = os.getenv("KIMI_BASE_URL", "https://api.moonshot.cn/v1")
KIMI_MODEL: str = os.getenv("KIMI_MODEL", "moonshot-v1-128k")
KIMI_AUDIT_MODEL: str = os.getenv("KIMI_AUDIT_MODEL", "moonshot-v1-32k")
KIMI_QUICK_MODEL: str = os.getenv("KIMI_QUICK_MODEL", "moonshot-v1-8k")
KIMI_MAX_TOKENS: int = int(os.getenv("KIMI_MAX_TOKENS", "4096"))

# -- GitHub Configuration ------------------------------------------------------
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
GITHUB_API_BASE: str = "https://api.github.com"

# -- Parallel Processing -------------------------------------------------------
MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "3"))
RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "20"))
KIMI_API_SEMAPHORE: int = int(os.getenv("KIMI_API_SEMAPHORE", "5"))

# -- Pipeline Settings ---------------------------------------------------------
BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "5"))
MAX_REPOS: int = int(os.getenv("MAX_REPOS", "0"))
MAX_REPO_SIZE_MB: int = int(os.getenv("MAX_REPO_SIZE_MB", "500"))
MIN_DISK_GB: float = float(os.getenv("MIN_DISK_GB", "2.0"))
CLONE_DEPTH: int = int(os.getenv("CLONE_DEPTH", "1"))
CLONE_TIMEOUT: int = int(os.getenv("CLONE_TIMEOUT", "300"))
CLEANUP_AFTER_AUDIT: bool = os.getenv("CLEANUP_AFTER_AUDIT", "true").lower() == "true"
MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
RETRY_DELAY: float = float(os.getenv("RETRY_DELAY", "2.0"))

# -- Audit Settings ------------------------------------------------------------
AUDIT_FILE_EXTENSIONS: List[str] = [
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
    ".c", ".cpp", ".h", ".cs", ".swift", ".kt", ".scala",
    ".rs", ".sh", ".bash", ".ps1", ".yaml", ".yml",
    ".json", ".tf", ".hcl", ".dockerfile", ".docker", ".toml",
    ".ini", ".cfg", ".conf",
]
PRIORITY_KEYWORDS: List[str] = [
    "auth", "login", "password", "token", "secret", "key",
    "credential", "cert", "crypto", "encrypt", "hash", "sign",
    "permission", "role", "session", "cookie", "oauth", "jwt",
    "sql", "query", "exec", "eval", "shell", "subprocess",
    "request", "http", "url", "upload", "file", "path",
    "deserialize", "marshal", "pickle", "yaml.load",
]
MAX_FILES_PER_REPO: int = int(os.getenv("MAX_FILES_PER_REPO", "500"))
MAX_FILE_SIZE_KB: int = int(os.getenv("MAX_FILE_SIZE_KB", "500"))
MAX_LINES_PER_FILE: int = int(os.getenv("MAX_LINES_PER_FILE", "1000"))

# -- Paths ---------------------------------------------------------------------
BASE_DIR: Path = Path(__file__).parent.parent
REPOS_DIR: Path = BASE_DIR / "repos"
REPORTS_DIR: Path = BASE_DIR / "reports" / "individual"
DASHBOARD_DIR: Path = BASE_DIR / "reports" / "dashboard"
DB_PATH: Path = BASE_DIR / "db" / "audit_state.db"
LOGS_DIR: Path = BASE_DIR / "logs"
SCOPES_CSV: Path = BASE_DIR / "config" / "scopes.csv"

# -- Severity Ranking ----------------------------------------------------------
SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
SEVERITY_COLORS = {
    "Critical": "\033[91m",  # Red
    "High": "\033[93m",      # Yellow
    "Medium": "\033[94m",    # Blue
    "Low": "\033[92m",       # Green
    "Info": "\033[96m",      # Cyan
    "RESET": "\033[0m",
}

def validate_config() -> List[str]:
    """Validate configuration and return list of issues."""
    issues = []
    if not KIMI_API_KEY:
        issues.append("ERROR: KIMI_API_KEY not set. Set it via environment variable.")
    if not GITHUB_TOKEN:
        issues.append("WARNING: GITHUB_TOKEN not set. Rate limit will be 60 req/hour.")
    if MAX_WORKERS < 1:
        issues.append("ERROR: MAX_WORKERS must be >= 1")
    if MAX_WORKERS > 10:
        issues.append("WARNING: MAX_WORKERS > 10 may hit rate limits")
    return issues

def get_settings_summary() -> str:
    """Return formatted config summary."""
    kimi_status = f"{'*' * 8}{KIMI_API_KEY[-4:]}" if len(KIMI_API_KEY) >= 4 else "(NOT SET - REQUIRED)"
    lines = [
        "+======================================================================+",
        "|           AWS VDP Security Audit Pipeline v2 -- Configuration        |",
        "+======================================================================+",
        f"|  Kimi API Key    : {kimi_status:<53} |",
        f"|  Kimi Model      : {KIMI_AUDIT_MODEL:<53} |",
        f"|  GitHub Token    : {'(SET)' if GITHUB_TOKEN else '(NOT SET)':<53} |",
        f"|  Max Workers     : {MAX_WORKERS:<53} |",
        f"|  API Semaphore   : {KIMI_API_SEMAPHORE:<53} |",
        f"|  Batch Size      : {BATCH_SIZE:<53} |",
        f"|  Max Repos       : {MAX_REPOS if MAX_REPOS else 'UNLIMITED':<53} |",
        f"|  Max Repo Size   : {MAX_REPO_SIZE_MB} MB{'':<48} |",
        f"|  Min Disk Space  : {MIN_DISK_GB} GB{'':<49} |",
        f"|  File Extensions : {len(AUDIT_FILE_EXTENSIONS)} types{'':<44} |",
        f"|  Max Files/Repo  : {MAX_FILES_PER_REPO:<53} |",
        "+======================================================================+",
    ]
    return "\n".join(lines)

def compute_repo_id(full_name: str) -> str:
    """Compute unique 12-char repo ID."""
    return hashlib.sha256(full_name.encode()).hexdigest()[:12]

def setup_logging(logs_dir: Path = LOGS_DIR) -> logging.Logger:
    """Setup dual logging (console + file)."""
    logs_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = logs_dir / f"pipeline_{timestamp}.log"

    logger = logging.getLogger("aws_vdp_auditor")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        logger.handlers.clear()

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)

    # File handler
    file_h = logging.FileHandler(log_file, encoding="utf-8")
    file_h.setLevel(logging.DEBUG)
    file_h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d -- %(message)s"
    ))
    logger.addHandler(file_h)

    return logger

logger = setup_logging()
