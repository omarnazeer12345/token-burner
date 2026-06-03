"""
SQLite-based state manager for tracking audit progress.
Supports resume, statistics, and history.
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from config.settings import DB_PATH, logger


class StateManager:
    """Manages audit state using SQLite."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS repos (
                    repo_id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    url TEXT,
                    source TEXT,
                    status TEXT DEFAULT 'pending',
                    size_mb REAL DEFAULT 0,
                    started_at TEXT,
                    completed_at TEXT,
                    duration_seconds REAL,
                    files_analyzed INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    error_message TEXT,
                    UNIQUE(full_name)
                );
                CREATE INDEX IF NOT EXISTS idx_status ON repos(status);
                CREATE INDEX IF NOT EXISTS idx_source ON repos(source);

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    severity TEXT,
                    category TEXT,
                    file_path TEXT,
                    line_numbers TEXT,
                    description TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    confidence TEXT,
                    cwe_id TEXT,
                    verified INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (repo_id) REFERENCES repos(repo_id)
                );
                CREATE INDEX IF NOT EXISTS idx_repo_findings ON findings(repo_id);
                CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity);
            ''')

    def upsert_repo(self, repo_id: str, full_name: str, url: str, source: str):
        """Add or update a repo record."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO repos
                (repo_id, full_name, url, source, status)
                VALUES (?, ?, ?, ?, 'pending')
            ''', (repo_id, full_name, url, source))

    def mark_started(self, repo_id: str):
        """Mark repo as in-progress."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE repos SET status = 'in_progress', started_at = ?
                WHERE repo_id = ?
            ''', (datetime.now().isoformat(), repo_id))

    def mark_completed(self, repo_id: str, duration: float, stats: Dict):
        """Mark repo as completed with findings stats."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE repos SET
                    status = 'completed',
                    completed_at = ?,
                    duration_seconds = ?,
                    files_analyzed = ?,
                    critical_count = ?,
                    high_count = ?,
                    medium_count = ?,
                    low_count = ?,
                    info_count = ?,
                    total_findings = ?
                WHERE repo_id = ?
            ''', (
                datetime.now().isoformat(), duration,
                stats.get('files_analyzed', 0),
                stats.get('critical', 0), stats.get('high', 0),
                stats.get('medium', 0), stats.get('low', 0),
                stats.get('info', 0),
                stats.get('total', 0),
                repo_id
            ))

    def mark_failed(self, repo_id: str, error: str):
        """Mark repo as failed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE repos SET status = 'failed', error_message = ?
                WHERE repo_id = ?
            ''', (error, repo_id))

    def get_pending_repos(self) -> List[Dict]:
        """Get all repos that haven't been audited yet."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM repos WHERE status = 'pending'"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        """Get overall pipeline statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN status='in_progress' THEN 1 ELSE 0 END) as in_progress,
                    SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
                    SUM(critical_count) as total_critical,
                    SUM(high_count) as total_high,
                    SUM(medium_count) as total_medium,
                    SUM(low_count) as total_low,
                    SUM(info_count) as total_info,
                    SUM(total_findings) as total_findings,
                    SUM(duration_seconds) as total_time
                FROM repos
            ''').fetchone()
            return {
                'total_repos': cursor[0] or 0,
                'completed': cursor[1] or 0,
                'failed': cursor[2] or 0,
                'in_progress': cursor[3] or 0,
                'pending': cursor[4] or 0,
                'total_critical': cursor[5] or 0,
                'total_high': cursor[6] or 0,
                'total_medium': cursor[7] or 0,
                'total_low': cursor[8] or 0,
                'total_info': cursor[9] or 0,
                'total_findings': cursor[10] or 0,
                'total_time_seconds': cursor[11] or 0,
            }

    def get_top_vulnerable_repos(self, limit: int = 10) -> List[Dict]:
        """Get repos with most findings."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('''
                SELECT full_name, critical_count, high_count, medium_count,
                       low_count, total_findings, duration_seconds
                FROM repos WHERE status = 'completed' AND total_findings > 0
                ORDER BY (critical_count * 4 + high_count * 3 + medium_count * 2 + low_count) DESC
                LIMIT ?
            ''', (limit,)).fetchall()
            return [dict(r) for r in rows]

    def save_finding(self, repo_id: str, finding: Dict):
        """Save a single finding."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO findings
                (repo_id, finding_id, severity, category, file_path, line_numbers,
                 description, evidence, remediation, confidence, cwe_id, verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                repo_id, finding.get('id', ''), finding.get('severity', ''),
                finding.get('category', ''), finding.get('file', ''),
                json.dumps(finding.get('line_numbers', [])),
                finding.get('description', ''), finding.get('evidence', ''),
                finding.get('remediation', ''), finding.get('confidence', ''),
                finding.get('cwe_id', ''), 1 if finding.get('verified') else 0
            ))

    def export_findings_csv(self, output_path: Path):
        """Export all findings to CSV."""
        import csv
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            with open(output_path, 'w', newline='') as f:
                writer = None
                cursor = conn.execute('''
                    SELECT f.*, r.full_name
                    FROM findings f
                    JOIN repos r ON f.repo_id = r.repo_id
                    ORDER BY f.severity DESC
                ''')
                for row in cursor:
                    row_dict = dict(row)
                    if writer is None:
                        writer = csv.DictWriter(f, fieldnames=list(row_dict.keys()))
                        writer.writeheader()
                    writer.writerow(row_dict)
