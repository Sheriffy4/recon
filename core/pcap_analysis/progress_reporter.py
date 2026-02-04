"""
Progress reporting utilities for long-running PCAP analysis operations.
Provides visual feedback and timing information for user experience.
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Optional, Callable
from dataclasses import dataclass


@dataclass
class ProgressStep:
    """Represents a single step in a progress sequence."""

    name: str
    description: str
    weight: float = 1.0  # Relative weight for progress calculation
    estimated_duration: Optional[float] = None  # Estimated seconds


class ProgressBar:
    """Simple progress bar implementation."""

    def __init__(self, total: int = 100, width: int = 50, show_percentage: bool = True):
        self.total = total
        self.width = width
        self.show_percentage = show_percentage
        self.current = 0

    def update(self, current: int, message: str = ""):
        """Update progress bar."""
        self.current = current
        percentage = (current / self.total) * 100
        filled = int((current / self.total) * self.width)
        bar = "█" * filled + "░" * (self.width - filled)

        if self.show_percentage:
            display = f"\r[{bar}] {percentage:6.2f}% {message}"
        else:
            display = f"\r[{bar}] {current}/{self.total} {message}"

        print(display, end="", flush=True)

    def finish(self, message: str = "Complete"):
        """Mark progress as complete."""
        self.update(self.total, message)
        print()  # New line


class SpinnerProgress:
    """Spinning progress indicator for indeterminate operations."""

    def __init__(self, message: str = "Processing..."):
        self.message = message
        self.spinning = False
        self.thread = None
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.current_char = 0

    def start(self):
        """Start the spinner."""
        self.spinning = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.daemon = True
        self.thread.start()

    def stop(self, final_message: str = "Done"):
        """Stop the spinner."""
        self.spinning = False
        if self.thread:
            self.thread.join()
        print(f"\r{final_message}" + " " * (len(self.message) + 10))

    def _spin(self):
        """Internal spinning loop."""
        while self.spinning:
            char = self.spinner_chars[self.current_char]
            print(f"\r{char} {self.message}", end="", flush=True)
            self.current_char = (self.current_char + 1) % len(self.spinner_chars)
            time.sleep(0.1)


class DetailedProgressReporter:
    """Detailed progress reporter with step tracking and timing."""

    def __init__(self, steps: list[ProgressStep], show_details: bool = True):
        self.steps = steps
        self.show_details = show_details
        self.current_step_index = 0
        self.start_time = datetime.now()
        self.step_start_time = datetime.now()
        self.total_weight = sum(step.weight for step in steps)
        self.completed_weight = 0.0

    def start_step(self, step_index: int, custom_message: str = None):
        """Start a specific step."""
        if step_index >= len(self.steps):
            return

        self.current_step_index = step_index
        self.step_start_time = datetime.now()
        step = self.steps[step_index]

        message = custom_message or step.description

        if self.show_details:
            elapsed = datetime.now() - self.start_time
            progress_percentage = (self.completed_weight / self.total_weight) * 100

            print(
                f"\n[{progress_percentage:6.2f}%] Step {step_index + 1}/{len(self.steps)}: {step.name}"
            )
            print(f"         {message}")
            print(f"         Elapsed: {self._format_duration(elapsed)}")

            if step.estimated_duration:
                print(
                    f"         Estimated: {self._format_duration(timedelta(seconds=step.estimated_duration))}"
                )
        else:
            progress_percentage = (self.completed_weight / self.total_weight) * 100
            print(f"\r[{progress_percentage:6.2f}%] {message}", end="", flush=True)

    def complete_step(self, step_index: int = None, custom_message: str = None):
        """Mark a step as complete."""
        if step_index is None:
            step_index = self.current_step_index

        if step_index >= len(self.steps):
            return

        step = self.steps[step_index]
        step_duration = datetime.now() - self.step_start_time
        self.completed_weight += step.weight

        message = custom_message or f"{step.name} completed"

        if self.show_details:
            print(f"         ✓ {message} (took {self._format_duration(step_duration)})")

    def finish(self, final_message: str = "Analysis complete"):
        """Mark all progress as complete."""
        total_duration = datetime.now() - self.start_time

        if self.show_details:
            print(f"\n✓ {final_message}")
            print(f"  Total time: {self._format_duration(total_duration)}")
        else:
            print(f"\r[100.00%] {final_message} (took {self._format_duration(total_duration)})")

    def update_step_progress(self, sub_progress: float, message: str = ""):
        """Update progress within the current step."""
        if not self.show_details:
            step = self.steps[self.current_step_index]
            step_weight_progress = (
                self.completed_weight + step.weight * sub_progress
            ) / self.total_weight
            progress_percentage = step_weight_progress * 100
            print(f"\r[{progress_percentage:6.2f}%] {message}", end="", flush=True)

    def _format_duration(self, duration: timedelta) -> str:
        """Format duration for display."""
        total_seconds = int(duration.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


class AsyncProgressReporter:
    """Async-compatible progress reporter."""

    def __init__(self, total_steps: int = 100, show_progress: bool = True):
        self.total_steps = total_steps
        self.current_step = 0
        self.show_progress = show_progress
        self.start_time = datetime.now()
        self.step_times = []

    async def update(self, step: int, message: str = ""):
        """Update progress asynchronously."""
        self.current_step = step
        step_time = datetime.now()
        self.step_times.append(step_time)

        if self.show_progress:
            percentage = (step / self.total_steps) * 100
            elapsed = step_time - self.start_time

            # Estimate remaining time based on average step time
            if len(self.step_times) > 1:
                avg_step_time = elapsed.total_seconds() / step
                remaining_steps = self.total_steps - step
                estimated_remaining = timedelta(seconds=avg_step_time * remaining_steps)
                eta_str = f" ETA: {self._format_duration(estimated_remaining)}"
            else:
                eta_str = ""

            print(f"\r[{percentage:6.2f}%] {message}{eta_str}", end="", flush=True)

    async def finish(self, message: str = "Complete"):
        """Mark progress as finished asynchronously."""
        elapsed = datetime.now() - self.start_time
        if self.show_progress:
            print(f"\r[100.00%] {message} (took {self._format_duration(elapsed)})")

    def _format_duration(self, duration: timedelta) -> str:
        """Format duration for display."""
        total_seconds = int(duration.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


class ProgressCallback:
    """Callback-based progress reporting for integration with existing code."""

    def __init__(self, callback: Callable[[float, str], None]):
        self.callback = callback
        self.total_steps = 100
        self.current_step = 0

    def set_total_steps(self, total: int):
        """Set total number of steps."""
        self.total_steps = total

    def update(self, step: int, message: str = ""):
        """Update progress via callback."""
        self.current_step = step
        progress = step / self.total_steps
        self.callback(progress, message)

    def increment(self, message: str = ""):
        """Increment progress by one step."""
        self.update(self.current_step + 1, message)


# Convenience functions for common use cases
def create_analysis_progress() -> DetailedProgressReporter:
    """Create a progress reporter for typical PCAP analysis workflow."""
    steps = [
        ProgressStep("Initialize", "Initializing analysis components", 0.5, 2.0),
        ProgressStep("Load PCAPs", "Loading and parsing PCAP files", 2.0, 10.0),
        ProgressStep("Compare", "Comparing packet sequences", 1.5, 15.0),
        ProgressStep("Analyze Strategies", "Analyzing strategy parameters", 1.0, 8.0),
        ProgressStep("Detect Differences", "Detecting critical differences", 1.5, 12.0),
        ProgressStep("Pattern Recognition", "Recognizing DPI evasion patterns", 1.0, 10.0),
        ProgressStep("Root Cause Analysis", "Analyzing failure root causes", 1.5, 15.0),
        ProgressStep("Generate Fixes", "Generating code fixes", 1.0, 8.0),
        ProgressStep("Validate", "Validating generated fixes", 2.0, 20.0),
        ProgressStep("Report", "Generating analysis report", 0.5, 5.0),
    ]
    return DetailedProgressReporter(steps)


def create_batch_progress(num_comparisons: int) -> ProgressBar:
    """Create a progress bar for batch processing."""
    return ProgressBar(total=num_comparisons, width=60, show_percentage=True)


def create_spinner(message: str = "Processing...") -> SpinnerProgress:
    """Create a spinner for indeterminate operations."""
    return SpinnerProgress(message)
