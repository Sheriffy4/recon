# path: core/pcap/cleanup_manager.py
"""
Cleanup Manager for temporary PCAP files.

This module provides automatic cleanup functionality for temporary PCAP files
created during strategy testing. It includes scheduled cleanup, size-based cleanup,
and emergency cleanup mechanisms.
"""

import os
import time
import threading
import logging
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timedelta


class PCAPCleanupManager:
    """
    Manager for automatic cleanup of temporary PCAP files.

    Features:
    - Automatic cleanup based on file age
    - Size-based cleanup when directory exceeds limits
    - Emergency cleanup when disk space is low
    - Background cleanup thread
    """

    def __init__(
        self,
        temp_dir: Optional[str] = None,
        max_age_hours: int = 24,
        max_dir_size_mb: int = 500,
        cleanup_interval_minutes: int = 30,
    ):
        """
        Initialize the cleanup manager.

        Args:
            temp_dir: Directory containing temporary PCAP files
            max_age_hours: Maximum age of files before cleanup (hours)
            max_dir_size_mb: Maximum directory size before cleanup (MB)
            cleanup_interval_minutes: Interval between cleanup runs (minutes)
        """
        self.logger = logging.getLogger("PCAPCleanupManager")

        # Configuration
        self.temp_dir = Path(temp_dir) if temp_dir else Path.cwd() / "temp_pcap"
        self.max_age_seconds = max_age_hours * 3600
        self.max_dir_size_bytes = max_dir_size_mb * 1024 * 1024
        self.cleanup_interval_seconds = cleanup_interval_minutes * 60

        # State
        self.running = False
        self.cleanup_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Statistics
        self.stats = {
            "files_cleaned": 0,
            "bytes_cleaned": 0,
            "last_cleanup": None,
            "cleanup_runs": 0,
        }

        self.logger.info(
            f"Cleanup manager initialized: dir={self.temp_dir}, "
            f"max_age={max_age_hours}h, max_size={max_dir_size_mb}MB"
        )

    def start_background_cleanup(self):
        """Start background cleanup thread"""
        with self._lock:
            if self.running:
                self.logger.warning("Background cleanup already running")
                return

            self.running = True
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_loop, name="PCAPCleanup", daemon=True
            )
            self.cleanup_thread.start()

        self.logger.info("✅ Background cleanup started")

    def stop_background_cleanup(self):
        """Stop background cleanup thread"""
        with self._lock:
            if not self.running:
                return

            self.running = False

        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5.0)

        self.logger.info("🛑 Background cleanup stopped")

    def _cleanup_loop(self):
        """Background cleanup loop"""
        while self.running:
            try:
                self.run_cleanup()

                # Wait for next cleanup interval
                for _ in range(int(self.cleanup_interval_seconds)):
                    if not self.running:
                        break
                    time.sleep(1.0)

            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying

    def run_cleanup(self) -> dict:
        """
        Run cleanup process.

        Returns:
            Dictionary with cleanup statistics
        """
        if not self.temp_dir.exists():
            return {"files_cleaned": 0, "bytes_cleaned": 0, "reason": "directory_not_exists"}

        start_time = time.time()
        files_cleaned = 0
        bytes_cleaned = 0

        try:
            # Get all PCAP files
            pcap_files = list(self.temp_dir.glob("*.pcap"))
            pcap_files.extend(self.temp_dir.glob("capture_*.pcap"))

            if not pcap_files:
                return {"files_cleaned": 0, "bytes_cleaned": 0, "reason": "no_files"}

            current_time = time.time()

            # Check directory size
            total_size = sum(f.stat().st_size for f in pcap_files if f.exists())
            size_cleanup_needed = total_size > self.max_dir_size_bytes

            # Cleanup old files
            for file_path in pcap_files:
                try:
                    if not file_path.exists():
                        continue

                    file_age = current_time - file_path.stat().st_mtime
                    file_size = file_path.stat().st_size

                    should_delete = False
                    reason = ""

                    # Age-based cleanup
                    if file_age > self.max_age_seconds:
                        should_delete = True
                        reason = f"age_{file_age/3600:.1f}h"

                    # Size-based cleanup (delete oldest files first)
                    elif size_cleanup_needed and file_age > 3600:  # At least 1 hour old
                        should_delete = True
                        reason = "size_limit"

                    if should_delete:
                        file_path.unlink()
                        files_cleaned += 1
                        bytes_cleaned += file_size

                        self.logger.debug(
                            f"Cleaned up {file_path.name} ({file_size} bytes, {reason})"
                        )

                except Exception as e:
                    self.logger.warning(f"Failed to clean up {file_path}: {e}")

            # Update statistics
            with self._lock:
                self.stats["files_cleaned"] += files_cleaned
                self.stats["bytes_cleaned"] += bytes_cleaned
                self.stats["last_cleanup"] = datetime.now().isoformat()
                self.stats["cleanup_runs"] += 1

            cleanup_time = time.time() - start_time

            if files_cleaned > 0:
                self.logger.info(
                    f"🗑️ Cleanup completed: {files_cleaned} files, "
                    f"{bytes_cleaned/1024/1024:.1f}MB in {cleanup_time:.2f}s"
                )

            return {
                "files_cleaned": files_cleaned,
                "bytes_cleaned": bytes_cleaned,
                "cleanup_time": cleanup_time,
                "reason": "scheduled",
            }

        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
            return {"files_cleaned": 0, "bytes_cleaned": 0, "error": str(e)}

    def emergency_cleanup(self) -> dict:
        """
        Emergency cleanup - removes all temporary PCAP files.

        Returns:
            Dictionary with cleanup statistics
        """
        self.logger.warning("🚨 Running emergency cleanup")

        if not self.temp_dir.exists():
            return {"files_cleaned": 0, "bytes_cleaned": 0}

        files_cleaned = 0
        bytes_cleaned = 0

        try:
            # Remove all PCAP files regardless of age
            for pattern in ["*.pcap", "capture_*.pcap", "temp_*.pcap"]:
                for file_path in self.temp_dir.glob(pattern):
                    try:
                        if file_path.exists():
                            file_size = file_path.stat().st_size
                            file_path.unlink()
                            files_cleaned += 1
                            bytes_cleaned += file_size
                    except Exception as e:
                        self.logger.error(f"Failed to remove {file_path}: {e}")

            self.logger.warning(
                f"🚨 Emergency cleanup completed: {files_cleaned} files, "
                f"{bytes_cleaned/1024/1024:.1f}MB"
            )

            return {"files_cleaned": files_cleaned, "bytes_cleaned": bytes_cleaned}

        except Exception as e:
            self.logger.error(f"Emergency cleanup failed: {e}")
            return {"files_cleaned": 0, "bytes_cleaned": 0, "error": str(e)}

    def get_directory_stats(self) -> dict:
        """
        Get statistics about the temporary directory.

        Returns:
            Dictionary with directory statistics
        """
        if not self.temp_dir.exists():
            return {"exists": False}

        try:
            pcap_files = list(self.temp_dir.glob("*.pcap"))
            pcap_files.extend(self.temp_dir.glob("capture_*.pcap"))

            total_size = sum(f.stat().st_size for f in pcap_files if f.exists())

            # Find oldest and newest files
            oldest_file = None
            newest_file = None

            if pcap_files:
                file_times = [(f, f.stat().st_mtime) for f in pcap_files if f.exists()]
                if file_times:
                    oldest_file = min(file_times, key=lambda x: x[1])
                    newest_file = max(file_times, key=lambda x: x[1])

            return {
                "exists": True,
                "directory": str(self.temp_dir),
                "file_count": len(pcap_files),
                "total_size_bytes": total_size,
                "total_size_mb": total_size / (1024 * 1024),
                "oldest_file": {
                    "name": oldest_file[0].name if oldest_file else None,
                    "age_hours": (time.time() - oldest_file[1]) / 3600 if oldest_file else None,
                },
                "newest_file": {
                    "name": newest_file[0].name if newest_file else None,
                    "age_hours": (time.time() - newest_file[1]) / 3600 if newest_file else None,
                },
            }

        except Exception as e:
            self.logger.error(f"Failed to get directory stats: {e}")
            return {"exists": True, "error": str(e)}

    def get_cleanup_stats(self) -> dict:
        """Get cleanup statistics"""
        with self._lock:
            return self.stats.copy()

    def __enter__(self):
        """Context manager entry"""
        self.start_background_cleanup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_background_cleanup()


# Global cleanup manager instance
_global_cleanup_manager: Optional[PCAPCleanupManager] = None


def get_global_cleanup_manager() -> PCAPCleanupManager:
    """Get or create global cleanup manager instance"""
    global _global_cleanup_manager

    if _global_cleanup_manager is None:
        _global_cleanup_manager = PCAPCleanupManager()

    return _global_cleanup_manager


def start_global_cleanup():
    """Start global cleanup manager"""
    manager = get_global_cleanup_manager()
    manager.start_background_cleanup()


def stop_global_cleanup():
    """Stop global cleanup manager"""
    global _global_cleanup_manager

    if _global_cleanup_manager:
        _global_cleanup_manager.stop_background_cleanup()
