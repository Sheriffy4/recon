"""
Periodic synchronization scheduler for signature database.

Manages background thread for automatic signature updates.
"""

import logging
import threading
import time
from typing import Callable, Optional

try:
    import schedule

    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

LOG = logging.getLogger("SignatureScheduler")


class SyncScheduler:
    """Manages periodic synchronization in background thread."""

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._job = None  # Store job reference for cleanup

    def start(self, sync_callback: Callable[[], None], interval_hours: int = 24):
        """
        Start periodic synchronization.

        Args:
            sync_callback: Function to call for synchronization
            interval_hours: Interval between syncs in hours
        """
        if not SCHEDULE_AVAILABLE:
            LOG.warning(
                "Библиотека 'schedule' не установлена. " "Автоматическая синхронизация отключена."
            )
            return

        if self._thread and self._thread.is_alive():
            LOG.warning("Планировщик уже запущен")
            return

        # Run immediately
        LOG.info("Auto-sync: Проверка обновлений в удаленной базе...")
        sync_callback()

        # Schedule periodic runs and store job reference
        self._job = schedule.every(interval_hours).hours.do(self._job_wrapper, sync_callback)

        # Start background thread
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_schedule, daemon=True)
        self._thread.start()

        LOG.info(
            f"✅ Автоматическая синхронизация базы сигнатур запущена "
            f"(интервал: {interval_hours} ч)."
        )

    def stop(self):
        """Stop the scheduler and background thread."""
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join(timeout=5)

            # Cancel scheduled job to prevent duplicates on restart
            if self._job and SCHEDULE_AVAILABLE:
                schedule.cancel_job(self._job)
                self._job = None

            LOG.info("Планировщик синхронизации остановлен")

    def _job_wrapper(self, sync_callback: Callable[[], None]):
        """Job wrapper for scheduled execution."""
        LOG.info("Auto-sync: Проверка обновлений в удаленной базе...")
        sync_callback()

    def _run_schedule(self):
        """Background thread main loop with responsive stop."""
        while not self._stop_event.is_set():
            schedule.run_pending()
            # Use wait instead of sleep for responsive stop
            self._stop_event.wait(60)  # Check every minute for responsiveness
