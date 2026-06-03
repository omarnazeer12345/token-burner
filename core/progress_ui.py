"""
Rich progress UI for the AWS VDP Security Audit Pipeline.
Provides beautiful progress bars, colored output, live status tables,
and real-time dashboard display.
"""

import time
import shutil
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from config.settings import SEVERITY_COLORS, SEVERITY_RANK, logger

# ── Optional Dependency: colorama ────────────────────────────────────────
try:
    from colorama import init, Fore, Style

    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

    class _Fore:
        """Fallback ANSI color implementation when colorama is unavailable."""

        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        MAGENTA = "\033[95m"
        CYAN = "\033[96m"
        WHITE = "\033[97m"
        RESET = "\033[0m"
        BOLD = "\033[1m"

    Fore = _Fore()
    Style = type("Style", (), {"RESET_ALL": "\033[0m", "BRIGHT": "\033[1m"})()

# ── Optional Dependency: tqdm ────────────────────────────────────────────
try:
    from tqdm import tqdm

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    tqdm = None


# ═══════════════════════════════════════════════════════════════════════════
#  ProgressUI Class
# ═══════════════════════════════════════════════════════════════════════════


class ProgressUI:
    """Beautiful terminal progress UI for the audit pipeline.

    Tracks per-repository audit progress, displays coloured severity-coded
    findings, prints summary statistics and manages tqdm integration for
    batch operations.
    """

    def __init__(self, total_repos: int = 0):
        self.total_repos: int = total_repos
        self.completed: int = 0
        self.failed: int = 0
        self.current_repo: str = ""
        self.start_time: float = time.time()
        self.stage_times: Dict[str, float] = {}
        self.terminal_width: int = shutil.get_terminal_size().columns

    # ── Banner & Config ──────────────────────────────────────────────────

    def print_banner(self) -> None:
        """Print the pipeline startup banner."""
        banner = (
            f"\n{Fore.CYAN}{'═' * 70}\n"
            f"║{Fore.YELLOW + Style.BRIGHT}           AWS VDP Security Audit Pipeline v2{Fore.CYAN}                         ║\n"
            f"║{Fore.WHITE}       Automated AI-Powered Vulnerability Discovery{Fore.CYAN}                    ║\n"
            f"{'═' * 70}{Fore.RESET}\n"
        )
        print(banner)

    def print_config(self, config_lines: List[str]) -> None:
        """Print configuration summary in a box."""
        for line in config_lines:
            print(f"  {Fore.CYAN}▸{Fore.RESET} {line}")
        print()

    # ── Stage Headers ────────────────────────────────────────────────────

    def print_stage_header(self, stage_name: str) -> None:
        """Print a stage header with decorative framing."""
        print(f"\n{Fore.MAGENTA}{'─' * 70}{Fore.RESET}")
        print(f"{Fore.MAGENTA + Style.BRIGHT}  ▶ {stage_name}{Fore.RESET}")
        print(f"{Fore.MAGENTA}{'─' * 70}{Fore.RESET}")

    # ── Per-Repo Progress ────────────────────────────────────────────────

    def print_repo_start(self, index: int, total: int, repo_name: str, source: str = "") -> None:
        """Print when starting a new repo audit.

        Args:
            index:  1-based index of current repository.
            total:  Total number of repositories to audit.
            repo_name: Full repository name (e.g. "owner/repo").
            source: Optional source label (e.g. "GitHub", "S3").
        """
        self.current_repo = repo_name
        bar = self._make_bar(index, total, 25)
        source_tag = f" [{source}]" if source else ""
        print(
            f"\n{Fore.BLUE}[{index}/{total}]{Fore.RESET} "
            f"{Fore.YELLOW + Style.BRIGHT}{repo_name}{Fore.RESET}"
            f"{Fore.CYAN}{source_tag}{Fore.RESET}"
        )
        print(f"  {Fore.WHITE}{bar}{Fore.RESET}")

    def print_stage(self, stage: str, status: str = "running") -> None:
        """Print a sub-stage status with an icon.

        Args:
            stage: Human-readable stage name (e.g. "Clone repository").
            status: One of ``running``, ``done``, ``skip``, ``error``.
        """
        icons = {
            "running": f"{Fore.YELLOW}⟳{Fore.RESET}",
            "done": f"{Fore.GREEN}✓{Fore.RESET}",
            "skip": f"{Fore.CYAN}⊘{Fore.RESET}",
            "error": f"{Fore.RED}✗{Fore.RESET}",
        }
        icon = icons.get(status, "•")
        status_colors = {
            "running": Fore.YELLOW,
            "done": Fore.GREEN,
            "skip": Fore.CYAN,
            "error": Fore.RED,
        }
        color = status_colors.get(status, Fore.WHITE)
        print(f"    {icon} {color}{stage:<30}{Fore.RESET}")

    # ── Findings ─────────────────────────────────────────────────────────

    def print_finding(self, finding: Dict) -> None:
        """Print a single finding with severity-dependent colors.

        Args:
            finding: Dictionary with keys ``severity``, ``category``,
                     ``file``, ``line_numbers``, and optionally
                     ``description``.
        """
        sev = finding.get("severity", "Info")
        cat = finding.get("category", "Other")
        file = finding.get("file", "?")
        color = SEVERITY_COLORS.get(sev, Fore.WHITE)
        lines = finding.get("line_numbers", [])
        line_str = f":{lines[0]}" if lines else ""

        print(
            f"      {color}[{sev}]{Fore.RESET} "
            f"{Fore.WHITE}{cat}{Fore.RESET} — "
            f"{Fore.CYAN}{file}{Fore.RESET}"
            f"{Fore.YELLOW}{line_str}{Fore.RESET}"
        )

        if finding.get("description"):
            desc = (
                finding["description"][:80] + "..."
                if len(finding["description"]) > 80
                else finding["description"]
            )
            print(f"        {Fore.WHITE}↳ {desc}{Fore.RESET}")

    def print_repo_summary(self, findings_count: int, severity_counts: Dict[str, int]) -> None:
        """Print summary after auditing a repository.

        Args:
            findings_count: Total number of findings in this repo.
            severity_counts: Mapping of severity name → count.
        """
        parts = []
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(sev, Fore.WHITE)
                parts.append(f"{color}{sev[0]}{Fore.RESET}:{count}")

        if parts:
            summary = " | ".join(parts)
            print(f"  {Fore.GREEN}✓{Fore.RESET} {findings_count} finding(s) — {summary}")
        else:
            print(f"  {Fore.GREEN}✓{Fore.RESET} No findings")

    # ── Utility Messages ─────────────────────────────────────────────────

    def print_error(self, message: str) -> None:
        """Print an error message."""
        print(f"  {Fore.RED}✗ ERROR: {message}{Fore.RESET}")

    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        print(f"  {Fore.YELLOW}⚠ WARNING: {message}{Fore.RESET}")

    def print_success(self, message: str) -> None:
        """Print a success message."""
        print(f"  {Fore.GREEN}✓ {message}{Fore.RESET}")

    # ── Statistics ───────────────────────────────────────────────────────

    def print_stats(self, stats: Dict) -> None:
        """Print overall pipeline statistics.

        Args:
            stats: Dictionary with keys ``total_repos``, ``completed``,
                   ``failed``, ``pending``, ``total_findings``, and
                   ``total_<severity>`` for each severity level.
        """
        elapsed = time.time() - self.start_time
        elapsed_str = str(timedelta(seconds=int(elapsed)))

        print(f"\n{Fore.CYAN}{'═' * 70}{Fore.RESET}")
        print(f"{Fore.YELLOW + Style.BRIGHT}                    PIPELINE STATISTICS{Fore.RESET}")
        print(f"{Fore.CYAN}{'═' * 70}{Fore.RESET}")

        # Repository counts
        print(f"  {Fore.WHITE}Repos:{Fore.RESET}")
        print(f"    Total:      {stats.get('total_repos', 0)}")
        print(f"    Completed:  {Fore.GREEN}{stats.get('completed', 0)}{Fore.RESET}")
        print(f"    Failed:     {Fore.RED}{stats.get('failed', 0)}{Fore.RESET}")
        print(f"    Pending:    {Fore.YELLOW}{stats.get('pending', 0)}{Fore.RESET}")

        # Findings by severity with mini bar chart
        print(f"\n  {Fore.WHITE}Findings:{Fore.RESET}")
        total_findings = stats.get("total_findings", 1) or 1
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = stats.get(f"total_{sev.lower()}", 0)
            color = SEVERITY_COLORS.get(sev, Fore.WHITE)
            bar = self._make_bar(count, total_findings, 20)
            print(f"    {color}[{sev}]{Fore.RESET} {count:>4} {Fore.WHITE}{bar}{Fore.RESET}")

        # Summary line
        print(
            f"\n  {Fore.WHITE}Total Findings:{Fore.RESET} "
            f"{Fore.YELLOW + Style.BRIGHT}{stats.get('total_findings', 0)}{Fore.RESET}"
        )
        print(f"  {Fore.WHITE}Time Elapsed:{Fore.RESET}   {elapsed_str}")

        completed = stats.get("completed", 0)
        if completed > 0 and elapsed > 0:
            avg = elapsed / completed
            print(f"  {Fore.WHITE}Avg/Repo:{Fore.RESET}       {avg:.1f}s")

        print(f"{Fore.CYAN}{'═' * 70}{Fore.RESET}\n")

    # ── Top Vulnerable Repos ─────────────────────────────────────────────

    def print_top_repos(self, repos: List[Dict]) -> None:
        """Print a ranked table of the most vulnerable repositories.

        Args:
            repos: List of repository dictionaries, each containing
                   ``full_name``, ``critical_count``, ``high_count``,
                   ``medium_count``, and ``total_findings``.
        """
        if not repos:
            return

        print(
            f"\n{Fore.YELLOW + Style.BRIGHT}  "
            f"Top {len(repos)} Most Vulnerable Repositories:{Fore.RESET}"
        )
        print(f"  {Fore.WHITE}{'─' * 65}{Fore.RESET}")
        print(
            f"  {Fore.CYAN}{'Rank':<6}{'Repository':<35}"
            f"{'C':>4}{'H':>4}{'M':>4}{'Total':>6}{Fore.RESET}"
        )
        print(f"  {Fore.WHITE}{'─' * 65}{Fore.RESET}")

        for i, repo in enumerate(repos, 1):
            name = repo.get("full_name", "?")[:34]
            c = repo.get("critical_count", 0)
            h = repo.get("high_count", 0)
            m = repo.get("medium_count", 0)
            t = repo.get("total_findings", 0)
            c_color = Fore.RED if c > 0 else Fore.WHITE
            h_color = Fore.YELLOW if h > 0 else Fore.WHITE
            print(
                f"  {Fore.YELLOW}{i:<6}{Fore.CYAN}{name:<35}"
                f"{c_color}{c:>4}{h_color}{h:>4}"
                f"{Fore.WHITE}{m:>4}{Fore.YELLOW}{t:>6}{Fore.RESET}"
            )

    # ── Internal Helpers ─────────────────────────────────────────────────

    def _make_bar(self, current: int, total: int, width: int) -> str:
        """Create a Unicode text progress bar.

        Args:
            current: Filled portion.
            total:   Maximum value.
            width:   Character width of the bar.

        Returns:
            A string like ``█████░░░░░``.
        """
        if total <= 0:
            return ""
        filled = min(width, int(width * current / total))
        return f"{'█' * filled}{'░' * (width - filled)}"

    def get_tqdm_bar(self, total: int, desc: str = "Processing") -> Optional[object]:
        """Get a tqdm progress bar if the library is available.

        Args:
            total: Total number of items.
            desc:  Description shown to the left of the bar.

        Returns:
            A ``tqdm`` instance or ``None`` if tqdm is not installed.
        """
        if HAS_TQDM and tqdm is not None:
            return tqdm(
                total=total,
                desc=f"{Fore.CYAN}{desc}{Fore.RESET}",
                ncols=70,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
            )
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  Module-level convenience functions
# ═══════════════════════════════════════════════════════════════════════════


def print_startup_banner() -> None:
    """Print the full startup banner with ASCII art."""
    art = (
        f"\n{Fore.CYAN}    █████╗ ██╗    ██╗███████╗    ██╗   ██╗██████╗ ██████╗ \n"
        f"   ██╔══██╗██║    ██║██╔════╝    ██║   ██║██╔══██╗██╔══██╗\n"
        f"   ███████║██║ █╗ ██║███████╗    ██║   ██║██║  ██║██████╔╝\n"
        f"   ██╔══██║██║███╗██║╚════██║    ╚██╗ ██╔╝██║  ██║██╔═══╝ \n"
        f"   ██║  ██║╚███╔███╔╝███████║     ╚████╔╝ ██████╔╝██║     \n"
        f"   ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝      ╚═══╝  ╚═════╝ ╚═╝     {Fore.RESET}\n"
        f"{Fore.YELLOW}         Security Audit Pipeline v2 — Powered by Kimi AI{Fore.RESET}\n"
        f"{Fore.WHITE}              Automated Vulnerability Discovery{Fore.RESET}\n"
        f"{Fore.CYAN}{'═' * 70}{Fore.RESET}\n"
    )
    print(art)


def print_cwe_reference() -> None:
    """Print CWE categories reference table."""
    cwe_map = {
        "CWE-798": "Hardcoded Credentials",
        "CWE-89": "SQL Injection",
        "CWE-78": "OS Command Injection",
        "CWE-79": "XSS",
        "CWE-94": "Code Injection",
        "CWE-22": "Path Traversal",
        "CWE-502": "Deserialization",
        "CWE-200": "Info Exposure",
        "CWE-287": "Improper Auth",
        "CWE-306": "Missing Auth",
        "CWE-352": "CSRF",
        "CWE-434": "Unrestricted Upload",
        "CWE-20": "Input Validation",
        "CWE-119": "Buffer Overflow",
        "CWE-276": "Incorrect Permissions",
    }
    print(f"\n{Fore.CYAN}  CWE Reference:{Fore.RESET}")
    for code, name in cwe_map.items():
        print(f"    {Fore.YELLOW}{code}{Fore.RESET}: {Fore.WHITE}{name}{Fore.RESET}")
