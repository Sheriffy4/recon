#!/usr/bin/env python3
"""
Background Task Manager for handling async operations in sync contexts.

This module provides utilities for managing background async tasks that need to run
alongside synchronous code, particularly for the dashboard and service operations.
"""

import asyncio
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, Optional

LOG = logging.getLogger("BackgroundTaskManager")


class TaskState(Enum):
    """States for background tasks."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RESTARTING = "restarting"


@dataclass
class TaskStatus:
    """Status information for a background task."""

    name: str
    state: TaskState
    start_time: datetime
    last_error: Optional[str] = None
    restart_count: int = 0
    last_restart: Optional[datetime] = None


@dataclass
class BackgroundTaskConfig:
    """Configuration for a background task."""

    name: str
    coroutine_func: Callable
    args: tuple = ()
    kwargs: dict = None
    restart_on_error: bool = True
    max_restarts: int = 3
    restart_delay: float = 1.0
    max_restart_delay: float = 60.0


class BackgroundTaskManager:
    """
    Manages background async tasks in a dedicated event loop thread.

    This class provides a way to run async operations from sync contexts
    without causing "no running event loop" errors.
    """

    def __init__(self):
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        self.tasks: Dict[str, asyncio.Task] = {}
        self.task_configs: Dict[str, BackgroundTaskConfig] = {}
        self.task_statuses: Dict[str, TaskStatus] = {}
        self.shutdown_event = threading.Event()
        self._lock = threading.Lock()
        self._running = False

    def start(self) -> None:
        """Start the background task manager."""
        if self._running:
            LOG.warning("BackgroundTaskManager is already running")
            return

        LOG.info("Starting BackgroundTaskManager...")
        self.shutdown_event.clear()
        self.thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self.thread.start()

        # Wait for event loop to be ready
        max_wait = 5.0
        start_time = time.time()
        while self.loop is None and (time.time() - start_time) < max_wait:
            time.sleep(0.01)

        if self.loop is None:
            raise RuntimeError("Failed to start background event loop")

        self._running = True
        LOG.info("BackgroundTaskManager started successfully")

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the background task manager and all tasks."""
        if not self._running:
            return

        LOG.info("Stopping BackgroundTaskManager...")

        # Cancel all tasks
        if self.loop and not self.loop.is_closed():
            future = asyncio.run_coroutine_threadsafe(
                self._cancel_all_tasks(), self.loop
            )
            try:
                future.result(timeout=timeout)
            except Exception as e:
                LOG.error(f"Error cancelling tasks: {e}")

        # Signal shutdown and wait for thread
        self.shutdown_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=timeout)

        self._running = False
        LOG.info("BackgroundTaskManager stopped")

    def schedule_task(self, config: BackgroundTaskConfig) -> bool:
        """
        Schedule a background task to run.

        Args:
            config: Task configuration

        Returns:
            True if task was scheduled successfully
        """
        if not self._running or not self.loop:
            LOG.error("BackgroundTaskManager is not running")
            return False

        try:
            future = asyncio.run_coroutine_threadsafe(
                self._schedule_task_async(config), self.loop
            )
            return future.result(timeout=5.0)
        except Exception as e:
            LOG.error(f"Failed to schedule task {config.name}: {e}")
            return False

    def cancel_task(self, task_name: str) -> bool:
        """
        Cancel a running background task.

        Args:
            task_name: Name of task to cancel

        Returns:
            True if task was cancelled successfully
        """
        if not self._running or not self.loop:
            return False

        try:
            future = asyncio.run_coroutine_threadsafe(
                self._cancel_task_async(task_name), self.loop
            )
            return future.result(timeout=5.0)
        except Exception as e:
            LOG.error(f"Failed to cancel task {task_name}: {e}")
            return False

    def get_task_status(self, task_name: str) -> Optional[TaskStatus]:
        """Get status of a background task."""
        with self._lock:
            return self.task_statuses.get(task_name)

    def get_all_task_statuses(self) -> Dict[str, TaskStatus]:
        """Get status of all background tasks."""
        with self._lock:
            return self.task_statuses.copy()

    def is_running(self) -> bool:
        """Check if the background task manager is running."""
        return self._running and self.loop is not None and not self.loop.is_closed()

    def _run_event_loop(self) -> None:
        """Run the background event loop in a separate thread."""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            LOG.debug("Background event loop started")

            # Run until shutdown is signaled
            while not self.shutdown_event.is_set():
                try:
                    self.loop.run_until_complete(asyncio.sleep(0.1))
                except Exception as e:
                    if not self.shutdown_event.is_set():
                        LOG.error(f"Error in background event loop: {e}")

        except Exception as e:
            LOG.error(f"Fatal error in background event loop: {e}")
        finally:
            if self.loop and not self.loop.is_closed():
                try:
                    self.loop.close()
                except Exception as e:
                    LOG.error(f"Error closing event loop: {e}")
            LOG.debug("Background event loop stopped")

    async def _schedule_task_async(self, config: BackgroundTaskConfig) -> bool:
        """Schedule a task in the async context."""
        try:
            # Cancel existing task with same name
            if config.name in self.tasks:
                await self._cancel_task_async(config.name)

            # Create task status
            status = TaskStatus(
                name=config.name, state=TaskState.PENDING, start_time=datetime.now()
            )

            with self._lock:
                self.task_configs[config.name] = config
                self.task_statuses[config.name] = status

            # Create and start task
            kwargs = config.kwargs or {}
            coro = config.coroutine_func(*config.args, **kwargs)
            task = asyncio.create_task(self._run_task_with_restart(config, coro))

            self.tasks[config.name] = task
            LOG.info(f"Scheduled background task: {config.name}")
            return True

        except Exception as e:
            LOG.error(f"Failed to schedule task {config.name}: {e}")
            return False

    async def _cancel_task_async(self, task_name: str) -> bool:
        """Cancel a task in the async context."""
        try:
            task = self.tasks.get(task_name)
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            # Update status
            with self._lock:
                if task_name in self.task_statuses:
                    self.task_statuses[task_name].state = TaskState.CANCELLED

            # Clean up
            self.tasks.pop(task_name, None)
            self.task_configs.pop(task_name, None)

            LOG.info(f"Cancelled background task: {task_name}")
            return True

        except Exception as e:
            LOG.error(f"Failed to cancel task {task_name}: {e}")
            return False

    async def _cancel_all_tasks(self) -> None:
        """Cancel all running tasks."""
        task_names = list(self.tasks.keys())
        for task_name in task_names:
            await self._cancel_task_async(task_name)

    async def _run_task_with_restart(self, config: BackgroundTaskConfig, coro) -> None:
        """Run a task with automatic restart on failure."""
        restart_count = 0

        while restart_count <= config.max_restarts:
            try:
                # Update status to running
                with self._lock:
                    if config.name in self.task_statuses:
                        self.task_statuses[config.name].state = TaskState.RUNNING

                # Run the coroutine
                await coro

                # Task completed successfully
                with self._lock:
                    if config.name in self.task_statuses:
                        self.task_statuses[config.name].state = TaskState.COMPLETED

                LOG.info(f"Background task completed: {config.name}")
                break

            except asyncio.CancelledError:
                LOG.info(f"Background task cancelled: {config.name}")
                break

            except Exception as e:
                restart_count += 1
                error_msg = f"Task {config.name} failed (attempt {restart_count}): {e}"
                LOG.error(error_msg)

                # Update status
                with self._lock:
                    if config.name in self.task_statuses:
                        status = self.task_statuses[config.name]
                        status.state = TaskState.FAILED
                        status.last_error = str(e)
                        status.restart_count = restart_count
                        status.last_restart = datetime.now()

                # Check if we should restart
                if not config.restart_on_error or restart_count > config.max_restarts:
                    LOG.error(
                        f"Task {config.name} failed permanently after {restart_count} attempts"
                    )
                    break

                # Calculate restart delay with exponential backoff
                delay = min(
                    config.restart_delay * (2 ** (restart_count - 1)),
                    config.max_restart_delay,
                )

                LOG.info(f"Restarting task {config.name} in {delay:.1f} seconds...")

                # Update status to restarting
                with self._lock:
                    if config.name in self.task_statuses:
                        self.task_statuses[config.name].state = TaskState.RESTARTING

                await asyncio.sleep(delay)

                # Recreate coroutine for restart
                kwargs = config.kwargs or {}
                coro = config.coroutine_func(*config.args, **kwargs)


class AsyncOperationWrapper:
    """Utilities for running async operations from sync contexts."""

    _manager: Optional[BackgroundTaskManager] = None

    @classmethod
    def get_manager(cls) -> BackgroundTaskManager:
        """Get or create the global background task manager."""
        if cls._manager is None:
            cls._manager = BackgroundTaskManager()
            cls._manager.start()
        return cls._manager

    @classmethod
    def run_async_from_sync(cls, coro, timeout: float = 30.0) -> Any:
        """
        Run an async operation from a sync context.

        Args:
            coro: Coroutine to run
            timeout: Timeout in seconds

        Returns:
            Result of the coroutine
        """
        manager = cls.get_manager()
        if not manager.is_running():
            raise RuntimeError("Background task manager is not running")

        future = asyncio.run_coroutine_threadsafe(coro, manager.loop)
        return future.result(timeout=timeout)

    @classmethod
    def schedule_background_task(cls, config: BackgroundTaskConfig) -> bool:
        """
        Schedule an async task to run in the background.

        Args:
            config: Task configuration

        Returns:
            True if task was scheduled successfully
        """
        manager = cls.get_manager()
        return manager.schedule_task(config)

    @classmethod
    def cancel_background_task(cls, task_name: str) -> bool:
        """
        Cancel a background task.

        Args:
            task_name: Name of task to cancel

        Returns:
            True if task was cancelled successfully
        """
        if cls._manager is None:
            return False
        return cls._manager.cancel_task(task_name)

    @classmethod
    def get_task_status(cls, task_name: str) -> Optional[TaskStatus]:
        """Get status of a background task."""
        if cls._manager is None:
            return None
        return cls._manager.get_task_status(task_name)

    @classmethod
    def shutdown(cls, timeout: float = 10.0) -> None:
        """Shutdown the background task manager."""
        if cls._manager is not None:
            cls._manager.stop(timeout=timeout)
            cls._manager = None


# Global instance for easy access
_global_manager: Optional[BackgroundTaskManager] = None


def get_background_task_manager() -> BackgroundTaskManager:
    """Get the global background task manager instance."""
    global _global_manager
    if _global_manager is None:
        _global_manager = BackgroundTaskManager()
        _global_manager.start()
    return _global_manager


def shutdown_background_tasks(timeout: float = 10.0) -> None:
    """Shutdown the global background task manager."""
    global _global_manager
    if _global_manager is not None:
        _global_manager.stop(timeout=timeout)
        _global_manager = None
