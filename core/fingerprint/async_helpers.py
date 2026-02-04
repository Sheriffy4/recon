"""
Async Task Execution Helpers

Provides reusable patterns for async task execution, gathering, and error handling.
Extracted from AdvancedFingerprinter to eliminate code duplication.

Requirements: 1.1, 3.1
"""

import asyncio
import logging
from typing import List, Tuple, Dict, Any, Coroutine, Optional


async def gather_analysis_tasks(
    tasks: List[Tuple[str, Coroutine]],
    logger: Optional[logging.Logger] = None,
    return_exceptions: bool = True,
) -> Dict[str, Any]:
    """
    Execute multiple named analysis tasks concurrently and gather results.

    Args:
        tasks: List of (task_name, coroutine) tuples
        logger: Optional logger for error reporting
        return_exceptions: Whether to return exceptions or raise them

    Returns:
        Dictionary mapping task names to their results

    Example:
        tasks = [
            ("tcp_analysis", tcp_analyzer.analyze(...)),
            ("http_analysis", http_analyzer.analyze(...)),
        ]
        results = await gather_analysis_tasks(tasks, logger)
        # results = {"tcp_analysis": {...}, "http_analysis": {...}}
    """
    if not tasks:
        return {}

    logger = logger or logging.getLogger(__name__)

    # Execute all tasks concurrently
    results = await asyncio.gather(
        *(safe_async_call(name, coro, logger) for name, coro in tasks),
        return_exceptions=return_exceptions,
    )

    # Build result dictionary
    result_dict = {}
    for i, (name, _) in enumerate(tasks):
        result = results[i]
        if isinstance(result, Exception):
            if not return_exceptions:
                raise result
            logger.debug(f"Task '{name}' failed: {result}")
            result_dict[name] = None
        else:
            task_name, task_result = result
            result_dict[task_name] = task_result

    return result_dict


async def safe_async_call(
    name: str, coro: Coroutine, logger: Optional[logging.Logger] = None
) -> Tuple[str, Any]:
    """
    Safely execute an async call with error handling.

    Args:
        name: Name of the task (for logging)
        coro: Coroutine to execute
        logger: Optional logger for error reporting

    Returns:
        Tuple of (task_name, result)

    Raises:
        Exception if the coroutine raises and error handling is disabled
    """
    logger = logger or logging.getLogger(__name__)

    try:
        result = await coro
        return (name, result)
    except Exception as e:
        logger.debug(f"Async call '{name}' failed: {e}")
        raise


async def execute_with_semaphore(sem: asyncio.Semaphore, coro: Coroutine) -> Any:
    """
    Execute a coroutine with semaphore-based concurrency control.

    Args:
        sem: Semaphore for concurrency control
        coro: Coroutine to execute

    Returns:
        Result of the coroutine
    """
    async with sem:
        return await coro


async def gather_with_semaphore(
    tasks: List[Coroutine], max_concurrent: int = 10, return_exceptions: bool = True
) -> List[Any]:
    """
    Execute multiple tasks with concurrency limit.

    Args:
        tasks: List of coroutines to execute
        max_concurrent: Maximum number of concurrent tasks
        return_exceptions: Whether to return exceptions or raise them

    Returns:
        List of results in the same order as tasks
    """
    sem = asyncio.Semaphore(max_concurrent)

    wrapped_tasks = [execute_with_semaphore(sem, task) for task in tasks]

    return await asyncio.gather(*wrapped_tasks, return_exceptions=return_exceptions)


async def execute_task_list_with_integration(
    tasks: List[Tuple[str, Coroutine]],
    integration_callback,
    target_object: Any,
    logger: Optional[logging.Logger] = None,
) -> None:
    """
    Execute tasks and integrate results into target object.

    This is a common pattern in fingerprinting where we:
    1. Execute multiple analysis tasks concurrently
    2. Integrate successful results into a fingerprint object

    Args:
        tasks: List of (task_name, coroutine) tuples
        integration_callback: Function to call with (target_object, task_name, result)
        target_object: Object to integrate results into (e.g., fingerprint)
        logger: Optional logger for error reporting
    """
    if not tasks:
        return

    logger = logger or logging.getLogger(__name__)

    # Execute all tasks
    results = await asyncio.gather(
        *(safe_async_call(name, coro, logger) for name, coro in tasks),
        return_exceptions=True,
    )

    # Integrate successful results
    for i, (name, _) in enumerate(tasks):
        result = results[i]
        if not isinstance(result, Exception):
            task_name, task_result = result
            if task_result:
                try:
                    integration_callback(target_object, task_name, task_result)
                except Exception as e:
                    logger.debug(f"Failed to integrate result from '{task_name}': {e}")


async def parallel_probe_execution(
    probes: List[Tuple[str, Coroutine]], logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Execute multiple probes in parallel and collect results.

    Similar to gather_analysis_tasks but specifically for probe operations
    that may fail without affecting other probes.

    Args:
        probes: List of (probe_name, coroutine) tuples
        logger: Optional logger for error reporting

    Returns:
        Dictionary mapping probe names to their results (None for failed probes)
    """
    if not probes:
        return {}

    logger = logger or logging.getLogger(__name__)

    # Execute all probes
    results = await asyncio.gather(*(coro for _, coro in probes), return_exceptions=True)

    # Build result dictionary
    probe_results = {}
    for i, (name, _) in enumerate(probes):
        result = results[i]
        if isinstance(result, Exception):
            logger.debug(f"Probe '{name}' failed: {result}")
            probe_results[name] = None
        else:
            probe_results[name] = result

    return probe_results


class TaskBatch:
    """
    Helper class for managing batches of async tasks.

    Useful for organizing complex analysis workflows with multiple phases.
    """

    def __init__(self, name: str, logger: Optional[logging.Logger] = None):
        """
        Initialize task batch.

        Args:
            name: Name of this batch (for logging)
            logger: Optional logger
        """
        self.name = name
        self.logger = logger or logging.getLogger(__name__)
        self.tasks: List[Tuple[str, Coroutine]] = []

    def add_task(self, name: str, coro: Coroutine) -> "TaskBatch":
        """
        Add a task to the batch.

        Args:
            name: Task name
            coro: Coroutine to execute

        Returns:
            Self for chaining
        """
        self.tasks.append((name, coro))
        return self

    def add_conditional_task(self, name: str, coro: Coroutine, condition: bool) -> "TaskBatch":
        """
        Add a task only if condition is true.

        Args:
            name: Task name
            coro: Coroutine to execute
            condition: Whether to add the task

        Returns:
            Self for chaining
        """
        if condition:
            self.tasks.append((name, coro))
        return self

    async def execute(self, return_exceptions: bool = True) -> Dict[str, Any]:
        """
        Execute all tasks in the batch.

        Args:
            return_exceptions: Whether to return exceptions or raise them

        Returns:
            Dictionary mapping task names to results
        """
        self.logger.debug(f"Executing task batch '{self.name}' with {len(self.tasks)} tasks")
        return await gather_analysis_tasks(self.tasks, self.logger, return_exceptions)

    def clear(self) -> "TaskBatch":
        """
        Clear all tasks from the batch.

        Returns:
            Self for chaining
        """
        self.tasks.clear()
        return self

    def __len__(self) -> int:
        """Return number of tasks in batch."""
        return len(self.tasks)

    def __bool__(self) -> bool:
        """Return True if batch has tasks."""
        return bool(self.tasks)
