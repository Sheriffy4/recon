"""
Async Subprocess Manager for non-blocking subprocess operations.

This module provides utilities for running subprocess operations in async contexts
without blocking the event loop, ensuring proper async/sync compatibility.

Requirements: 5.3 - Non-blocking subprocess operations for async contexts
"""

import asyncio
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


@dataclass
class SubprocessConfig:
    """
    Configuration for subprocess operations.

    Requirement 5.3: Non-blocking subprocess operations configuration
    """

    command: Union[str, List[str]]
    cwd: Optional[Union[str, Path]] = None
    env: Optional[Dict[str, str]] = None
    timeout: Optional[float] = 30.0
    capture_output: bool = True
    text: bool = True
    shell: bool = False
    check: bool = False
    input_data: Optional[str] = None
    encoding: str = "utf-8"
    errors: str = "replace"

    # Advanced options
    stdin: Optional[int] = None
    stdout: Optional[int] = None
    stderr: Optional[int] = None
    preexec_fn: Optional[callable] = None
    close_fds: bool = True

    def __post_init__(self):
        """Validate configuration after initialization."""
        if isinstance(self.command, str) and not self.shell:
            # Convert string command to list if not using shell
            self.command = self.command.split()

        if self.cwd and isinstance(self.cwd, str):
            self.cwd = Path(self.cwd)

    def to_subprocess_kwargs(self) -> Dict[str, Any]:
        """
        Convert config to subprocess.run kwargs.

        Returns:
            Dictionary of kwargs for subprocess operations
        """
        kwargs = {
            "cwd": str(self.cwd) if self.cwd else None,
            "env": self.env,
            "timeout": self.timeout,
            "capture_output": self.capture_output,
            "text": self.text,
            "shell": self.shell,
            "check": self.check,
            "input": self.input_data,
            "encoding": self.encoding,
            "errors": self.errors,
        }

        # Add advanced options if specified
        if self.stdin is not None:
            kwargs["stdin"] = self.stdin
        if self.stdout is not None:
            kwargs["stdout"] = self.stdout
        if self.stderr is not None:
            kwargs["stderr"] = self.stderr
        if self.preexec_fn is not None:
            kwargs["preexec_fn"] = self.preexec_fn

        kwargs["close_fds"] = self.close_fds

        # Remove None values
        return {k: v for k, v in kwargs.items() if v is not None}


class AsyncSubprocessManager:
    """
    Manager for async subprocess operations that don't block the event loop.

    This class provides both async and sync interfaces for subprocess operations,
    ensuring non-blocking behavior in async contexts.

    Requirement 5.3: Non-blocking subprocess operations for async contexts
    """

    def __init__(self, max_workers: int = 4):
        """
        Initialize AsyncSubprocessManager.

        Args:
            max_workers: Maximum number of worker threads for subprocess operations
        """
        self.max_workers = max_workers
        self._executor: Optional[ThreadPoolExecutor] = None
        self._active_processes: Dict[int, asyncio.subprocess.Process] = {}

    def __enter__(self):
        """Context manager entry."""
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None

        # Clean up any remaining processes
        for process in self._active_processes.values():
            try:
                process.terminate()
            except Exception:
                pass
        self._active_processes.clear()

    async def run_async(self, config: SubprocessConfig) -> subprocess.CompletedProcess:
        """
        Run subprocess asynchronously without blocking the event loop.

        Args:
            config: Subprocess configuration

        Returns:
            CompletedProcess result

        Raises:
            subprocess.TimeoutExpired: If timeout is exceeded
            subprocess.CalledProcessError: If check=True and process fails

        Requirement 5.3: Non-blocking subprocess operations for async contexts
        """
        try:
            # Use asyncio.create_subprocess_exec for true async subprocess
            if isinstance(config.command, str) and config.shell:
                process = await asyncio.create_subprocess_shell(
                    config.command,
                    stdin=asyncio.subprocess.PIPE if config.input_data else None,
                    stdout=asyncio.subprocess.PIPE if config.capture_output else None,
                    stderr=asyncio.subprocess.PIPE if config.capture_output else None,
                    cwd=str(config.cwd) if config.cwd else None,
                    env=config.env,
                )
            else:
                command = config.command if isinstance(config.command, list) else [config.command]
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdin=asyncio.subprocess.PIPE if config.input_data else None,
                    stdout=asyncio.subprocess.PIPE if config.capture_output else None,
                    stderr=asyncio.subprocess.PIPE if config.capture_output else None,
                    cwd=str(config.cwd) if config.cwd else None,
                    env=config.env,
                )

            # Track active process
            self._active_processes[process.pid] = process

            try:
                # Communicate with process
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(
                        input=(
                            config.input_data.encode(config.encoding) if config.input_data else None
                        )
                    ),
                    timeout=config.timeout,
                )

                # Decode output if text mode
                if config.text:
                    stdout_text = (
                        stdout_data.decode(config.encoding, config.errors) if stdout_data else ""
                    )
                    stderr_text = (
                        stderr_data.decode(config.encoding, config.errors) if stderr_data else ""
                    )
                else:
                    stdout_text = stdout_data
                    stderr_text = stderr_data

                # Create CompletedProcess result
                result = subprocess.CompletedProcess(
                    args=config.command,
                    returncode=process.returncode,
                    stdout=stdout_text,
                    stderr=stderr_text,
                )

                # Check for errors if requested
                if config.check and result.returncode != 0:
                    raise subprocess.CalledProcessError(
                        result.returncode,
                        config.command,
                        output=result.stdout,
                        stderr=result.stderr,
                    )

                logger.debug(
                    f"Async subprocess completed: {config.command} (exit code: {result.returncode})"
                )
                return result

            except asyncio.TimeoutError:
                # Kill process on timeout
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()

                raise subprocess.TimeoutExpired(config.command, config.timeout)

            finally:
                # Remove from active processes
                self._active_processes.pop(process.pid, None)

        except Exception as e:
            logger.error(f"Async subprocess failed: {config.command} - {e}")
            raise

    def run_sync(self, config: SubprocessConfig) -> subprocess.CompletedProcess:
        """
        Run subprocess synchronously.

        Args:
            config: Subprocess configuration

        Returns:
            CompletedProcess result

        Requirement 5.3: Sync wrapper for subprocess operations
        """
        try:
            kwargs = config.to_subprocess_kwargs()

            logger.debug(f"Running sync subprocess: {config.command}")
            result = subprocess.run(config.command, **kwargs)

            logger.debug(
                f"Sync subprocess completed: {config.command} (exit code: {result.returncode})"
            )
            return result

        except Exception as e:
            logger.error(f"Sync subprocess failed: {config.command} - {e}")
            raise

    async def run_in_thread_pool(self, config: SubprocessConfig) -> subprocess.CompletedProcess:
        """
        Run subprocess in thread pool to avoid blocking async event loop.

        This is an alternative to run_async that uses thread pool execution
        for cases where asyncio subprocess is not suitable.

        Args:
            config: Subprocess configuration

        Returns:
            CompletedProcess result

        Requirement 5.3: Non-blocking subprocess operations for async contexts
        """
        if not self._executor:
            raise RuntimeError("AsyncSubprocessManager not initialized as context manager")

        loop = asyncio.get_running_loop()

        def run_subprocess():
            return self.run_sync(config)

        try:
            result = await loop.run_in_executor(self._executor, run_subprocess)
            logger.debug(f"Thread pool subprocess completed: {config.command}")
            return result
        except Exception as e:
            logger.error(f"Thread pool subprocess failed: {config.command} - {e}")
            raise

    async def run_multiple_async(
        self, configs: List[SubprocessConfig], max_concurrent: int = 5
    ) -> List[subprocess.CompletedProcess]:
        """
        Run multiple subprocess operations concurrently.

        Args:
            configs: List of subprocess configurations
            max_concurrent: Maximum number of concurrent processes

        Returns:
            List of CompletedProcess results in same order as configs

        Requirement 5.3: Concurrent non-blocking subprocess operations
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_with_semaphore(config: SubprocessConfig) -> subprocess.CompletedProcess:
            async with semaphore:
                return await self.run_async(config)

        tasks = [run_with_semaphore(config) for config in configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to failed CompletedProcess objects
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Subprocess {i} failed: {result}")
                # Create failed CompletedProcess
                processed_results.append(
                    subprocess.CompletedProcess(
                        args=configs[i].command, returncode=-1, stdout="", stderr=str(result)
                    )
                )
            else:
                processed_results.append(result)

        return processed_results

    def terminate_all_processes(self):
        """
        Terminate all active subprocess operations.

        This method should be called during cleanup to ensure
        no subprocess operations are left running.
        """
        for process in self._active_processes.values():
            try:
                process.terminate()
            except Exception as e:
                logger.warning(f"Failed to terminate process {process.pid}: {e}")

        self._active_processes.clear()


# Global instance for convenience
_global_subprocess_manager: Optional[AsyncSubprocessManager] = None


def get_subprocess_manager() -> AsyncSubprocessManager:
    """
    Get global subprocess manager instance.

    Returns:
        Global AsyncSubprocessManager instance
    """
    global _global_subprocess_manager
    if _global_subprocess_manager is None:
        _global_subprocess_manager = AsyncSubprocessManager()
        _global_subprocess_manager.__enter__()
    return _global_subprocess_manager


async def run_subprocess_async(
    command: Union[str, List[str]], **kwargs
) -> subprocess.CompletedProcess:
    """
    Convenience function for running subprocess asynchronously.

    Args:
        command: Command to run
        **kwargs: Additional configuration options

    Returns:
        CompletedProcess result

    Requirement 5.3: Non-blocking subprocess operations for async contexts
    """
    config = SubprocessConfig(command=command, **kwargs)
    manager = get_subprocess_manager()
    return await manager.run_async(config)


def run_subprocess_sync(command: Union[str, List[str]], **kwargs) -> subprocess.CompletedProcess:
    """
    Convenience function for running subprocess synchronously.

    Args:
        command: Command to run
        **kwargs: Additional configuration options

    Returns:
        CompletedProcess result
    """
    config = SubprocessConfig(command=command, **kwargs)
    manager = get_subprocess_manager()
    return manager.run_sync(config)


def cleanup_subprocess_manager():
    """Clean up global subprocess manager."""
    global _global_subprocess_manager
    if _global_subprocess_manager:
        _global_subprocess_manager.__exit__(None, None, None)
        _global_subprocess_manager = None
