"""
Enhanced report generation v2.

Generates beautiful Markdown reports, JSON exports, and interactive HTML dashboards
for the AWS VDP Security Audit Pipeline.

Features
--------
* Markdown reports with severity badges, evidence blocks, CWE references, CVSS scores
* Interactive HTML dashboard with Chart.js (doughnut + bar charts)
* Dark theme matching GitHub's aesthetic
* Responsive design for mobile viewing
* Top vulnerable repos table with colored badges
"""

import json
import html as html_module
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from config.settings import (
    SEVERITY_COLORS,
    SEVERITY_RANK,
    REPORTS_DIR,
    DASHBOARD_DIR,
    logger,
)

# ---------------------------------------------------------------------------
# Severity icons (emoji)
# ---------------------------------------------------------------------------
SEVERITY_ICONS: Dict[str, str] = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Info": "⚪",
}


def generate_repo_report(
    audit_result: Dict[str, Any],
    output_dir: Path = REPORTS_DIR,
) -> Path:
    """
    Generate a beautiful Markdown report for a single repository.

    Parameters
    ----------
    audit_result : dict
        Raw audit output containing ``repo``, ``audit_timestamp``, ``summary``,
        and ``findings`` keys.
    output_dir : Path
        Directory where the ``.md`` file will be written.  Defaults to
        :py:data:`config.settings.REPORTS_DIR`.

    Returns
    -------
    Path
        Absolute path to the generated Markdown file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    repo_name = audit_result.get("repo", "unknown").replace("/", "_")
    output_path = output_dir / f"{repo_name}.md"

    summary = audit_result.get("summary", {})
    findings: List[Dict[str, Any]] = audit_result.get("findings", [])

    lines: List[str] = []

    # ---- Header ------------------------------------------------------------
    lines.append(f"# Security Audit Report: `{audit_result.get('repo', 'unknown')}`")
    lines.append("")
    lines.append(f"**Audit Date:** {audit_result.get('audit_timestamp', 'N/A')}")
    lines.append(f"**Files Analyzed:** {summary.get('total_files', 0)}")
    lines.append(f"**Total Findings:** {len(findings)}")
    if summary.get("duration_seconds"):
        lines.append(f"**Duration:** {summary['duration_seconds']:.1f}s")
    lines.append("")

    # ---- Severity Summary (badges) -----------------------------------------
    lines.append("## Severity Summary")
    lines.append("")
    sev_counts: List[str] = []
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = summary.get(f"{sev.lower()}_count", 0)
        if count > 0:
            icon = SEVERITY_ICONS.get(sev, "")
            sev_counts.append(f"{icon} **{sev}:** {count}")
    lines.append(" | ".join(sev_counts) if sev_counts else "No findings.")
    lines.append("")

    # ---- ASCII bar chart ---------------------------------------------------
    max_count = max(
        [summary.get(f"{s.lower()}_count", 0) for s in SEVERITY_RANK.keys()],
        default=1,
    )
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = summary.get(f"{sev.lower()}_count", 0)
        bar_len = int((count / max_count) * 30) if max_count > 0 else 0
        bar = "█" * bar_len
        lines.append(f"{sev:<10} {bar} {count}")
    lines.append("")

    # ---- Findings table ----------------------------------------------------
    if findings:
        lines.append("## Findings")
        lines.append("")
        lines.append(
            "| ID | Severity | Category | CWE | File | Line | Confidence |"
        )
        lines.append(
            "|----|----------|----------|-----|------|------|------------|"
        )

        for f in sorted(
            findings,
            key=lambda x: SEVERITY_RANK.get(x.get("severity", "Info"), 0),
            reverse=True,
        ):
            icon = SEVERITY_ICONS.get(f.get("severity", ""), "")
            lines.append(
                f"| {f.get('id', 'N/A')} | {icon} {f.get('severity', '?')} | "
                f"{f.get('category', '?')} | {f.get('cwe_id', 'N/A')} | "
                f"`{f.get('file', '?')}` | {f.get('line_numbers', [])} | "
                f"{f.get('confidence', '?')} |"
            )
        lines.append("")

        # ---- Detailed findings --------------------------------------------
        lines.append("## Detailed Findings")
        lines.append("")

        for f in sorted(
            findings,
            key=lambda x: SEVERITY_RANK.get(x.get("severity", "Info"), 0),
            reverse=True,
        ):
            icon = SEVERITY_ICONS.get(f.get("severity", ""), "")
            lines.append(
                f"### {icon} [{f.get('severity', '?')}] "
                f"{f.get('id', 'N/A')}: {f.get('category', 'Unknown')}"
            )
            lines.append("")
            lines.append(f"- **File:** `{f.get('file', '?')}`")
            lines.append(f"- **Line(s):** {f.get('line_numbers', [])}")
            lines.append(f"- **CWE:** {f.get('cwe_id', 'N/A')}")
            lines.append(f"- **CVSS Score:** {f.get('cvss_score', 'N/A')}")
            lines.append(f"- **Confidence:** {f.get('confidence', 'N/A')}")
            lines.append(f"- **Verified:** {'Yes' if f.get('verified') else 'No'}")
            lines.append("")

            if f.get("description"):
                lines.append("**Description:**")
                lines.append(f"{f['description']}")
                lines.append("")

            if f.get("evidence"):
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(f"{f['evidence']}")
                lines.append("```")
                lines.append("")

            if f.get("remediation"):
                lines.append("**Remediation:**")
                lines.append(f"{f['remediation']}")
                lines.append("")

            lines.append("---")
            lines.append("")

    # ---- Write file --------------------------------------------------------
    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Report written: %s", output_path)
    return output_path


def generate_json_report(
    audit_result: Dict[str, Any],
    output_dir: Path = REPORTS_DIR,
) -> Path:
    """
    Save raw audit result as a pretty-printed JSON file.

    Parameters
    ----------
    audit_result : dict
        The full audit result dictionary.
    output_dir : Path
        Target directory.  Defaults to :py:data:`config.settings.REPORTS_DIR`.

    Returns
    -------
    Path
        Path to the written ``.json`` file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    repo_name = audit_result.get("repo", "unknown").replace("/", "_")
    output_path = output_dir / f"{repo_name}.json"
    output_path.write_text(
        json.dumps(audit_result, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    logger.info("JSON report written: %s", output_path)
    return output_path


def generate_html_dashboard(
    all_results: List[Dict[str, Any]],
    stats: Dict[str, Any],
    output_path: Path = None,
) -> Path:
    """
    Generate an interactive HTML dashboard with Chart.js visualisations.

    Parameters
    ----------
    all_results : list[dict]
        List of per-repository audit results.
    stats : dict
        Aggregated pipeline statistics (``total_repos``, ``completed``,
        ``total_findings``, ``total_critical``, ``total_high``, …).
    output_path : Path, optional
        Explicit destination path.  Defaults to
        ``DASHBOARD_DIR / "index.html"``.

    Returns
    -------
    Path
        Path to the generated ``index.html``.
    """
    if output_path is None:
        output_path = DASHBOARD_DIR / "index.html"
    DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)

    # ---- Prepare chart data ------------------------------------------------
    severity_data = {
        "Critical": stats.get("total_critical", 0),
        "High": stats.get("total_high", 0),
        "Medium": stats.get("total_medium", 0),
        "Low": stats.get("total_low", 0),
        "Info": stats.get("total_info", 0),
    }

    # Category breakdown across all results
    categories: Dict[str, int] = {}
    for result in all_results:
        for f in result.get("findings", []):
            cat = f.get("category", "Other")
            categories[cat] = categories.get(cat, 0) + 1

    # Top repos by risk score (Critical×4 + High×3)
    top_repos = sorted(
        all_results,
        key=lambda r: (
            r.get("summary", {}).get("critical_count", 0) * 4
            + r.get("summary", {}).get("high_count", 0) * 3
        ),
        reverse=True,
    )[:15]

    # ---- Chart colours -----------------------------------------------------
    sev_colors = ["#f85149", "#d29922", "#58a6ff", "#3fb950", "#8b949e"]
    cat_colors = [
        "#58a6ff",
        "#a371f7",
        "#3fb950",
        "#d29922",
        "#f85149",
        "#79c0ff",
        "#d2a8ff",
        "#56d364",
    ]

    # ---- Build HTML --------------------------------------------------------
    sev_labels = list(severity_data.keys())
    sev_values = list(severity_data.values())
    cat_labels = list(categories.keys())
    cat_values = list(categories.values())

    html_parts: List[str] = []
    html_parts.append(
        """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS VDP Security Audit Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg: #0d1117; --card: #161b22; --border: #30363d;
            --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
            --critical: #f85149; --high: #d29922; --medium: #58a6ff;
            --low: #3fb950; --info: #8b949e;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { text-align: center; padding: 30px 0; border-bottom: 1px solid var(--border); margin-bottom: 30px; }
        header h1 { font-size: 2rem; background: linear-gradient(90deg, #58a6ff, #a371f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        header p { color: var(--muted); margin-top: 8px; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
        .stat-card .value { font-size: 2rem; font-weight: 700; }
        .stat-card .label { color: var(--muted); font-size: 0.875rem; margin-top: 4px; }
        .stat-card.critical .value { color: var(--critical); }
        .stat-card.high .value { color: var(--high); }
        .stat-card.medium .value { color: var(--medium); }
        .stat-card.low .value { color: var(--low); }
        .stat-card.total .value { color: var(--accent); }

        .charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .chart-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
        .chart-card h3 { margin-bottom: 15px; font-size: 1rem; color: var(--muted); }

        .table-container { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid var(--border); }
        th { color: var(--muted); font-weight: 500; font-size: 0.8rem; text-transform: uppercase; }
        tr:hover { background: rgba(88, 166, 255, 0.05); }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .badge-critical { background: rgba(248, 81, 73, 0.2); color: var(--critical); }
        .badge-high { background: rgba(210, 153, 34, 0.2); color: var(--high); }
        .badge-medium { background: rgba(88, 166, 255, 0.2); color: var(--medium); }
        .badge-low { background: rgba(63, 185, 80, 0.2); color: var(--low); }
        .badge-info { background: rgba(139, 148, 158, 0.2); color: var(--info); }

        footer { text-align: center; padding: 30px; color: var(--muted); font-size: 0.8rem; margin-top: 40px; border-top: 1px solid var(--border); }
        @media (max-width: 768px) { .charts-row { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>AWS VDP Security Audit Dashboard</h1>
        <p>Generated on """
    )
    html_parts.append(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    html_parts.append(""" | Powered by Kimi AI</p>
    </header>

    <div class="stats-grid">
        <div class="stat-card total">
            <div class="value">""")
    html_parts.append(str(stats.get("total_repos", 0)))
    html_parts.append("""</div>
            <div class="label">Total Repos</div>
        </div>
        <div class="stat-card total">
            <div class="value">""")
    html_parts.append(str(stats.get("completed", 0)))
    html_parts.append("""</div>
            <div class="label">Audited</div>
        </div>
        <div class="stat-card total">
            <div class="value">""")
    html_parts.append(str(stats.get("total_findings", 0)))
    html_parts.append("""</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="stat-card critical">
            <div class="value">""")
    html_parts.append(str(stats.get("total_critical", 0)))
    html_parts.append("""</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
            <div class="value">""")
    html_parts.append(str(stats.get("total_high", 0)))
    html_parts.append("""</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card medium">
            <div class="value">""")
    html_parts.append(str(stats.get("total_medium", 0)))
    html_parts.append("""</div>
            <div class="label">Medium</div>
        </div>
        <div class="stat-card low">
            <div class="value">""")
    html_parts.append(str(stats.get("total_low", 0)))
    html_parts.append("""</div>
            <div class="label">Low</div>
        </div>
    </div>

    <div class="charts-row">
        <div class="chart-card">
            <h3>Findings by Severity</h3>
            <canvas id="severityChart"></canvas>
        </div>
        <div class="chart-card">
            <h3>Findings by Category</h3>
            <canvas id="categoryChart"></canvas>
        </div>
    </div>

    <div class="table-container">
        <h3 style="margin-bottom: 15px; color: var(--muted);">Top Vulnerable Repositories</h3>
        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Repository</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>Total</th>
                </tr>
            </thead>
            <tbody>
""")

    # ---- Top repos rows ----------------------------------------------------
    for i, repo in enumerate(top_repos, 1):
        s = repo.get("summary", {})
        repo_name = html_module.escape(repo.get("repo", "?"))
        html_parts.append(
            f"""                <tr>
                    <td>{i}</td>
                    <td><code>{repo_name}</code></td>
                    <td><span class=\"badge badge-critical\">{s.get('critical_count', 0)}</span></td>
                    <td><span class=\"badge badge-high\">{s.get('high_count', 0)}</span></td>
                    <td><span class=\"badge badge-medium\">{s.get('medium_count', 0)}</span></td>
                    <td><span class=\"badge badge-low\">{s.get('low_count', 0)}</span></td>
                    <td><strong>{s.get('total_findings', 0)}</strong></td>
                </tr>
"""
        )

    # ---- Close HTML with Chart.js -----------------------------------------
    html_parts.append(
        f"""            </tbody>
        </table>
    </div>

    <footer>
        <p>AWS VDP Security Audit Pipeline v2 &mdash; Built for the AWS Vulnerability Disclosure Program</p>
    </footer>
</div>

<script>
const severityCtx = document.getElementById('severityChart').getContext('2d');
new Chart(severityCtx, {{
    type: 'doughnut',
    data: {{
        labels: {json.dumps(sev_labels)},
        datasets: [{{
            data: {json.dumps(sev_values)},
            backgroundColor: {json.dumps(sev_colors)},
            borderWidth: 0
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#8b949e' }} }} }}
    }}
}});

const categoryCtx = document.getElementById('categoryChart').getContext('2d');
new Chart(categoryCtx, {{
    type: 'bar',
    data: {{
        labels: {json.dumps(cat_labels)},
        datasets: [{{
            label: 'Findings',
            data: {json.dumps(cat_values)},
            backgroundColor: {json.dumps(cat_colors[:len(cat_labels)])},
            borderWidth: 0,
            borderRadius: 4
        }}]
    }},
    options: {{
        responsive: true,
        indexAxis: 'y',
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
            x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
            y: {{ ticks: {{ color: '#8b949e' }}, grid: {{ display: false }} }}
        }}
    }}
}});
</script>
</body>
</html>
"""
    )

    # ---- Write file --------------------------------------------------------
    full_html = "".join(html_parts)
    output_path.write_text(full_html, encoding="utf-8")
    logger.info("HTML dashboard written: %s", output_path)
    return output_path
