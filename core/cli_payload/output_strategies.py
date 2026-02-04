"""
Output strategies for CLI wrapper.

This module provides different output formatting strategies for displaying
analysis results, progress, and errors.
"""

from typing import Any, Dict, Protocol

# Avoid importing adaptive_cli_wrapper to prevent circular imports
from .unicode_utils import UnicodeReplacements

# Conditional imports for Rich library
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = Any
    Panel = Any
    Table = Any


# ============================================================================
# OUTPUT STRATEGY PROTOCOL
# ============================================================================


class OutputStrategy(Protocol):
    """Protocol for output strategies."""

    def display_banner(
        self,
        domain: str,
        config: Any,
    ) -> None: ...

    def display_results(
        self,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
    ) -> None: ...

    def display_progress(self, message: str) -> None: ...

    def display_error(self, error: Exception, context: str) -> None: ...


# ============================================================================
# RICH OUTPUT STRATEGY
# ============================================================================


class RichOutputStrategy:
    """Rich-based output strategy with formatted tables and panels."""

    def __init__(self, console: Console):
        self.console = console

    def display_banner(self, domain: str, config: Any) -> None:
        """Display startup banner with configuration."""
        mode = getattr(config, "mode", "unknown")
        max_trials = getattr(config, "max_trials", "?")
        enable_fingerprinting = getattr(config, "enable_fingerprinting", False)
        enable_failure_analysis = getattr(config, "enable_failure_analysis", False)
        verify_with_pcap = getattr(config, "verify_with_pcap", False)

        panel_content = (
            f"[bold cyan]Recon: Adaptive Strategy Discovery[/bold cyan]\n"
            f"[dim]Target: {domain}[/dim]\n"
            f"[dim]Mode: {mode} (max {max_trials} trials)[/dim]\n"
            f"[dim]Fingerprinting: {'enabled' if enable_fingerprinting else 'disabled'}[/dim]\n"
            f"[dim]Failure Analysis: {'enabled' if enable_failure_analysis else 'disabled'}[/dim]\n"
            f"[dim]Verification Mode: {'enabled' if verify_with_pcap else 'disabled'}[/dim]"
        )
        self.console.print(Panel(panel_content, expand=False))

    def display_results(
        self,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
    ) -> None:
        """Display analysis results with Rich formatting."""
        self.console.print("\n" + "=" * 60)
        self.console.print("[bold]ADAPTIVE ANALYSIS RESULTS[/bold]")
        self.console.print("=" * 60)

        if result.success:
            self._display_success(result)
        else:
            self.console.print("[bold red][FAIL] FAILED[/bold red]")

        self.console.print(f"[dim]Message: {getattr(result, 'message', '')}[/dim]")

        # Performance metrics table
        self._display_metrics_table(result, execution_time)

        # Engine statistics
        if stats:
            self._display_stats_table(stats)

    def _display_success(self, result: Any) -> None:
        """Display success information."""
        self.console.print("[bold green][OK] SUCCESS[/bold green]")

        if not hasattr(result, "strategy") or not result.strategy:
            return

        strategy = result.strategy
        self.console.print(f"[green]Strategy: {strategy.name}[/green]")

        # Display attack combination
        if hasattr(strategy, "attack_combination") and strategy.attack_combination:
            filtered_attacks = [a for a in strategy.attack_combination if a]

            if len(filtered_attacks) > 1:
                attacks_str = " + ".join(filtered_attacks)
                self.console.print(f"[bold green]Attack Combination: {attacks_str}[/bold green]")
                self.console.print(f"[dim]  ({len(filtered_attacks)} attacks combined)[/dim]")
            elif filtered_attacks:
                self.console.print(f"[green]Attack: {filtered_attacks[0]}[/green]")
        elif hasattr(strategy, "attack_name"):
            self.console.print(f"[green]Attack: {strategy.attack_name}[/green]")

        if hasattr(strategy, "parameters"):
            self.console.print(f"[green]Parameters: {strategy.parameters}[/green]")

        if hasattr(strategy, "expected_success_rate"):
            self.console.print(
                f"[green]Expected Success Rate: {strategy.expected_success_rate:.1%}[/green]"
            )

        if hasattr(strategy, "rationale"):
            self.console.print(f"[dim]Rationale: {strategy.rationale}[/dim]")

    def _display_metrics_table(self, result: Any, execution_time: float) -> None:
        """Display performance metrics table."""
        table = Table(title="Performance Metrics", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Execution Time", f"{execution_time:.2f}s")
        table.add_row("Trials Performed", str(getattr(result, "trials_count", 0)))
        table.add_row("Fingerprint Updated", str(getattr(result, "fingerprint_updated", False)))

        self.console.print(table)

    def _display_stats_table(self, stats: Dict[str, Any]) -> None:
        """Display engine statistics table."""
        table = Table(title="Engine Statistics", show_header=True)
        table.add_column("Statistic", style="cyan")
        table.add_column("Count", style="yellow")

        for key, value in stats.items():
            table.add_row(key.replace("_", " ").title(), str(value))

        self.console.print(table)

    def display_progress(self, message: str) -> None:
        """Display progress message."""
        safe_message = UnicodeReplacements.make_safe(message)
        self.console.print(f"[cyan]{safe_message}[/cyan]")

    def display_error(self, error: Exception, context: str) -> None:
        """Display error message."""
        self.console.print(f"[bold red]Error in {context}: {error}[/bold red]")


# ============================================================================
# PLAIN OUTPUT STRATEGY
# ============================================================================


class PlainOutputStrategy:
    """Plain text output strategy without special formatting."""

    def __init__(self, console: Any):
        self.console = console

    def _print(self, text: str) -> None:
        """
        Print via provided console if possible (supports FallbackConsole),
        otherwise fallback to built-in print.
        """
        printer = getattr(self.console, "print", None)
        if callable(printer):
            printer(text)
        else:
            print(text)

    def display_banner(self, domain: str, config: Any) -> None:
        """Display startup banner in plain text."""
        mode = getattr(config, "mode", "unknown")
        max_trials = getattr(config, "max_trials", "?")
        enable_fingerprinting = getattr(config, "enable_fingerprinting", False)
        enable_failure_analysis = getattr(config, "enable_failure_analysis", False)
        verify_with_pcap = getattr(config, "verify_with_pcap", False)

        self._print("=" * 60)
        self._print("Recon: Adaptive Strategy Discovery")
        self._print(f"Target: {domain}")
        self._print(f"Mode: {mode} (max {max_trials} trials)")
        self._print(f"Fingerprinting: {'enabled' if enable_fingerprinting else 'disabled'}")
        self._print(f"Failure Analysis: {'enabled' if enable_failure_analysis else 'disabled'}")
        self._print(f"Verification Mode: {'enabled' if verify_with_pcap else 'disabled'}")
        self._print("=" * 60)

    def display_results(
        self,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
    ) -> None:
        """Display results in plain text."""
        self._print("\n" + "=" * 60)
        self._print("ADAPTIVE ANALYSIS RESULTS")
        self._print("=" * 60)

        if result.success:
            self._display_success_plain(result)
        else:
            self._print("[FAIL] FAILED")

        self._print(f"Message: {getattr(result, 'message', '')}")
        self._print(f"\nExecution Time: {execution_time:.2f}s")
        self._print(f"Trials Performed: {getattr(result, 'trials_count', 0)}")
        self._print(f"Fingerprint Updated: {getattr(result, 'fingerprint_updated', False)}")

        if stats:
            self._print("\nEngine Statistics:")
            for key, value in stats.items():
                self._print(f"  {key.replace('_', ' ').title()}: {value}")

    def _display_success_plain(self, result: Any) -> None:
        """Display success in plain text."""
        self._print("[OK] SUCCESS")

        if not hasattr(result, "strategy") or not result.strategy:
            return

        strategy = result.strategy
        self._print(f"Strategy: {getattr(strategy, 'name', '')}")

        if hasattr(strategy, "attack_combination") and strategy.attack_combination:
            filtered_attacks = [a for a in strategy.attack_combination if a]

            if len(filtered_attacks) > 1:
                self._print(f"Attack Combination: {' + '.join(filtered_attacks)}")
                self._print(f"  ({len(filtered_attacks)} attacks combined)")
            elif filtered_attacks:
                self._print(f"Attack: {filtered_attacks[0]}")
        elif hasattr(strategy, "attack_name"):
            self._print(f"Attack: {strategy.attack_name}")

        if hasattr(strategy, "parameters"):
            self._print(f"Parameters: {strategy.parameters}")

    def display_progress(self, message: str) -> None:
        """Display progress message."""
        safe_message = UnicodeReplacements.make_safe(message)
        self._print(f"[PROGRESS] {safe_message}")

    def display_error(self, error: Exception, context: str) -> None:
        """Display error message."""
        self._print(f"[ERROR] {context}: {error}")


# ============================================================================
# QUIET OUTPUT STRATEGY
# ============================================================================


class QuietOutputStrategy:
    """Quiet output strategy - minimal output only."""

    def display_banner(self, domain: str, config: Any) -> None:  # pylint: disable=unused-argument
        """No banner in quiet mode."""
        pass

    def display_results(
        self,
        result: Any,
        execution_time: float,  # pylint: disable=unused-argument
        stats: Dict[str, Any],  # pylint: disable=unused-argument
    ) -> None:
        """Only print final status in quiet mode."""
        status = "SUCCESS" if result.success else "FAILED"
        print(f"{status}: {result.message}")

    def display_progress(self, message: str) -> None:  # pylint: disable=unused-argument
        """No progress messages in quiet mode."""
        pass

    def display_error(
        self, error: Exception, context: str
    ) -> None:  # pylint: disable=unused-argument
        """Only print error in quiet mode."""
        print(f"ERROR: {error}")
