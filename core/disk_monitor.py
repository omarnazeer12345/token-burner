"""
Disk space and resource monitoring utilities.
"""
import shutil
import psutil
from pathlib import Path
from typing import Tuple
from config.settings import MIN_DISK_GB, logger


class DiskMonitor:
    """Monitor disk space and system resources."""

    @staticmethod
    def get_disk_info(path: Path = Path(".")) -> Tuple[float, float, float]:
        """Return (total_gb, used_gb, free_gb)."""
        usage = shutil.disk_usage(path)
        total = usage.total / (1024**3)
        used = usage.used / (1024**3)
        free = usage.free / (1024**3)
        return round(total, 2), round(used, 2), round(free, 2)

    @staticmethod
    def has_enough_space(path: Path = Path("."), min_gb: float = MIN_DISK_GB) -> bool:
        """Check if there's enough disk space."""
        _, _, free = DiskMonitor.get_disk_info(path)
        if free < min_gb:
            logger.error(f"DISK FULL: Only {free:.1f}GB free (need {min_gb}GB). Pausing.")
            return False
        return True

    @staticmethod
    def get_memory_info() -> Tuple[float, float, float]:
        """Return (total_gb, available_gb, percent_used)."""
        mem = psutil.virtual_memory()
        total = mem.total / (1024**3)
        available = mem.available / (1024**3)
        return round(total, 2), round(available, 2), mem.percent

    @staticmethod
    def get_repo_size_mb(path: Path) -> float:
        """Get size of a directory in MB."""
        total = 0
        for entry in path.rglob('*'):
            try:
                if entry.is_file():
                    total += entry.stat().st_size
            except (OSError, PermissionError):
                pass
        return round(total / (1024**2), 2)

    @staticmethod
    def format_progress_bar(current: int, total: int, width: int = 30) -> str:
        """Create a text progress bar."""
        if total == 0:
            return "[{}] 0/0".format(" " * width)
        filled = int(width * current / total)
        bar = "#" * filled + "-" * (width - filled)
        pct = (current / total) * 100
        return f"[{bar}] {current}/{total} ({pct:.1f}%)"
