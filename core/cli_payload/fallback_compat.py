"""
Fallback compatibility classes.

This module provides fallback implementations for when Rich library or
AdaptiveEngine components are not available. These are compatibility stubs
that allow the CLI to function in degraded mode.
"""

import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from .unicode_utils import UnicodeReplacements


# ============================================================================
# FALLBACK CONSOLE
# ============================================================================


class FallbackConsole:
    """
    Fallback console without Rich support.

    Provides basic console functionality when Rich library is not available.
    Handles Unicode encoding issues and strips Rich markup tags.
    """

    # Precompile regex for markup stripping
    _MARKUP_PATTERN = re.compile(r"\[/?[^\]]+\]")

    def __init__(self):
        self._start_time = time.time()
        self.file = sys.stdout
        self.width = 80
        self.height = 24
        self._is_terminal = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        self.legacy_windows = True

    def print(self, *args, **kwargs):  # pylint: disable=unused-argument
        """
        Safe print with Unicode replacement.

        Strips Rich markup and handles Unicode encoding errors.
        """
        try:
            sep = kwargs.get("sep", " ")
            end = kwargs.get("end", "\n")
            file = kwargs.get("file", self.file)
            flush = kwargs.get("flush", False)

            message = sep.join(str(arg) for arg in args)
            message = UnicodeReplacements.make_safe(message)
            # Remove Rich markup
            message = self._strip_markup(message)
            safe_kwargs = {
                k: v for k, v in kwargs.items() if k not in ("style", "sep", "end", "file", "flush")
            }
            print(message, sep=sep, end=end, file=file, flush=flush, **safe_kwargs)
        except UnicodeEncodeError:
            sep = kwargs.get("sep", " ")
            end = kwargs.get("end", "\n")
            file = kwargs.get("file", self.file)
            flush = kwargs.get("flush", False)
            ascii_message = sep.join(
                str(arg).encode("ascii", "replace").decode("ascii") for arg in args
            )
            print(ascii_message, end=end, file=file, flush=flush)

    def _strip_markup(self, text: str) -> str:
        """Remove Rich markup tags from text."""
        return self._MARKUP_PATTERN.sub("", text)

    def get_time(self) -> float:
        """Get current time."""
        return time.time()

    def is_terminal(self) -> bool:
        """Check if output is a terminal."""
        return self._is_terminal

    def size(self) -> Tuple[int, int]:
        """Get console size."""
        return (self.width, self.height)

    def log(self, *args, **kwargs):
        """Log message (same as print in fallback)."""
        self.print(*args, **kwargs)

    def bell(self):  # pylint: disable=no-self-use
        """Ring terminal bell (no-op in fallback)."""
        pass

    def clear(self):  # pylint: disable=no-self-use
        """Clear console (no-op in fallback)."""
        pass

    def show_cursor(self, show: bool = True):  # pylint: disable=unused-argument,no-self-use
        """Show/hide cursor (no-op in fallback)."""
        pass


# ============================================================================
# FALLBACK PANEL
# ============================================================================


class FallbackPanel:
    """
    Fallback Panel without Rich.

    Simple text container when Rich Panel is not available.
    """

    def __init__(self, text: str, **kwargs):  # pylint: disable=unused-argument
        self.text = text

    def __str__(self) -> str:
        return str(self.text)


# ============================================================================
# FALLBACK PROGRESS
# ============================================================================


class FallbackProgress:
    """
    Fallback Progress without Rich.

    No-op progress indicator when Rich Progress is not available.
    """

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):  # pylint: disable=unused-argument
        pass

    def add_task(self, *args, **kwargs) -> int:  # pylint: disable=unused-argument,no-self-use
        """Add task (no-op, returns dummy task ID)."""
        return 0

    def update(self, *args, **kwargs):  # pylint: disable=unused-argument,no-self-use
        """Update task (no-op)."""
        pass


# ============================================================================
# FALLBACK ADAPTIVE ENGINE
# ============================================================================


class FallbackAdaptiveEngine:
    """
    Fallback AdaptiveEngine for compatibility.

    Stub implementation when AdaptiveEngine is not available.
    """

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        pass

    async def find_best_strategy(
        self, *args, **kwargs
    ):  # pylint: disable=unused-argument,no-self-use
        """Find best strategy (stub, returns None)."""
        return None

    def get_stats(self) -> Dict[str, Any]:  # pylint: disable=no-self-use
        """Get statistics (stub, returns empty dict)."""
        return {}


# ============================================================================
# FALLBACK DATA CLASSES
# ============================================================================


@dataclass
class FallbackAdaptiveConfig:
    """
    Fallback AdaptiveConfig for compatibility.

    Default configuration when AdaptiveConfig is not available.
    """

    max_trials: int = 10
    stop_on_success: bool = True
    enable_fingerprinting: bool = True
    enable_failure_analysis: bool = True
    mode: str = "balanced"
    enable_caching: bool = True
    enable_parallel_testing: bool = True
    max_parallel_workers: int = 10
    strategy_timeout: float = 30.0
    connection_timeout: float = 5.0
    verify_with_pcap: bool = False
    batch_mode: bool = False


@dataclass
class FallbackStrategyResult:
    """
    Fallback StrategyResult for compatibility.

    Default result structure when StrategyResult is not available.
    """

    success: bool = False
    message: str = ""
    strategy: Any = None
    trials_count: int = 0
    fingerprint_updated: bool = False
