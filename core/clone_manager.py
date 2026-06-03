"""
Repository clone manager with disk monitoring and smart file extraction.
"""
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from config.settings import (
    CLONE_DEPTH, CLONE_TIMEOUT, MAX_RETRIES, RETRY_DELAY,
    REPOS_DIR, MAX_REPO_SIZE_MB, AUDIT_FILE_EXTENSIONS,
    MAX_FILES_PER_REPO, MAX_FILE_SIZE_KB, MAX_LINES_PER_FILE,
    PRIORITY_KEYWORDS, logger
)
from core.disk_monitor import DiskMonitor

SKIP_DIRS = {
    '.git', '__pycache__', '.pytest_cache', 'node_modules', 'vendor',
    'third_party', 'third-party', 'venv', '.venv', 'dist', 'build',
    'target', '.gradle', '.idea', '.tox', '.eggs', '*.egg-info',
    'docs', 'documentation', 'examples', 'samples', 'test', 'tests',
    'spec', 'specs', 'benchmark', 'benchmarks', '.github', '.ci',
}

def clone_repo(repo_full_name: str, repos_dir: Path = REPOS_DIR, 
               depth: int = CLONE_DEPTH, timeout: int = CLONE_TIMEOUT) -> Optional[Path]:
    """Clone a repository with retries and disk monitoring."""
    repos_dir.mkdir(parents=True, exist_ok=True)
    repo_path = repos_dir / repo_full_name.replace('/', '_')
    
    # Clean up if exists
    if repo_path.exists():
        shutil.rmtree(repo_path, ignore_errors=True)
    
    url = f"https://github.com/{repo_full_name}.git"
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # Check disk space
            if not DiskMonitor.has_enough_space(repos_dir):
                logger.error("Not enough disk space to clone!")
                return None
            
            result = subprocess.run(
                ['git', 'clone', '--depth', str(depth), url, str(repo_path)],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return repo_path
            else:
                logger.warning(f"Clone attempt {attempt} failed: {result.stderr[:200]}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)
        except subprocess.TimeoutExpired:
            logger.warning(f"Clone timeout (attempt {attempt})")
            if repo_path.exists():
                shutil.rmtree(repo_path, ignore_errors=True)
        except Exception as e:
            logger.error(f"Clone error (attempt {attempt}): {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
    
    return None

def get_repo_size_mb(repo_path: Path) -> float:
    """Get repository size in MB."""
    return DiskMonitor.get_repo_size_mb(repo_path)

def cleanup_repo(repo_path: Path) -> bool:
    """Delete cloned repository."""
    try:
        if repo_path.exists():
            shutil.rmtree(repo_path, ignore_errors=True)
        return True
    except Exception as e:
        logger.error(f"Cleanup failed for {repo_path}: {e}")
        return False

def get_audit_files(repo_path: Path) -> List[Dict]:
    """Extract audit-worthy files from repository with smart prioritization."""
    files = []
    
    for entry in repo_path.rglob('*'):
        # Skip directories and non-files
        if not entry.is_file():
            continue
        
        # Skip hidden and unwanted directories
        try:
            rel_path = entry.relative_to(repo_path)
        except ValueError:
            continue
        
        path_str = str(rel_path)
        if any(part.startswith('.') and part != '.' for part in rel_path.parts):
            continue
        if any(skip in path_str for skip in SKIP_DIRS):
            continue
        
        # Check extension
        if entry.suffix not in AUDIT_FILE_EXTENSIONS:
            continue
        
        # Check file size
        size_kb = entry.stat().st_size / 1024
        if size_kb > MAX_FILE_SIZE_KB:
            continue
        
        # Read content with line limit
        try:
            with open(entry, 'r', encoding='utf-8', errors='replace') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= MAX_LINES_PER_FILE:
                        break
                    lines.append(line)
                content = ''.join(lines)
        except Exception:
            continue
        
        # Calculate priority score
        priority = 0
        path_lower = path_str.lower()
        content_lower = content.lower()
        for kw in PRIORITY_KEYWORDS:
            if kw.lower() in path_lower:
                priority += 3
            if kw.lower() in content_lower:
                priority += 1
        
        files.append({
            'path': path_str,
            'content': content,
            'lines': len(content.split('\n')),
            'size_kb': round(size_kb, 2),
            'priority': priority,
        })
    
    # Sort by priority (highest first) then take top N
    files.sort(key=lambda f: f['priority'], reverse=True)
    return files[:MAX_FILES_PER_REPO]
