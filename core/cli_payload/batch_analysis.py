"""
Batch analysis functionality for AdaptiveCLIWrapper.

This module provides batch processing capabilities for analyzing multiple domains
with optimized strategy testing and parallel execution.
"""

import logging
from typing import Any, Dict, List

from .data_models import BatchResult, BatchSummary

LOG = logging.getLogger("AdaptiveCLIWrapper.BatchAnalysis")


# ============================================================================
# BATCH ANALYZER
# ============================================================================


class BatchAnalyzer:
    """
    Batch analysis coordinator for multiple domains.

    Optimizes strategy testing by:
    - Generating strategies from a sample domain
    - Testing each strategy across all domains in parallel
    - Stopping early when all domains have successful strategies
    """

    def __init__(self, console: Any, engine: Any, config: Any, quiet: bool = False):
        """
        Initialize batch analyzer.

        Args:
            console: Console for output
            engine: AdaptiveEngine instance
            config: Analysis configuration
            quiet: Suppress output
        """
        self.console = console
        self.engine = engine
        self.config = config
        self.quiet = quiet

    async def run_batch_analysis(
        self,
        domains: List[str],
        get_monotonic_time: callable,
    ) -> Dict[str, bool]:
        """
        Run batch adaptive analysis.

        Args:
            domains: List of domains to analyze
            get_monotonic_time: Function to get monotonic time

        Returns:
            Dict mapping domains to success status
        """
        if not domains:
            return {}

        start_time = get_monotonic_time()

        self.console.print(
            f"\n[bold blue][START] Batch analysis: {len(domains)} domains[/bold blue]"
        )
        self.console.print("[dim]Optimization: one strategy → all domains in parallel[/dim]")

        # Configure for batch mode
        self.config.batch_mode = True
        self.console.print("[dim]Batch mode: Saving to adaptive_knowledge.json only[/dim]")

        # Prepare results
        summary = BatchSummary(total_domains=len(domains))
        all_results: Dict[str, bool] = {}

        try:
            # Generate strategies from first domain
            strategies = await self._generate_strategies_for_batch(domains[0])

            if not strategies:
                self.console.print("[red][FAIL] No strategies generated[/red]")
                for domain in domains:
                    summary.results[domain] = BatchResult(
                        domain=domain,
                        success=False,
                        error="No strategies generated",
                    )
                self._display_batch_summary(summary, get_monotonic_time, start_time)
                return {d: False for d in domains}

            self.console.print(f"[green]✓ Generated {len(strategies)} strategies[/green]")

            # Test each strategy on all domains
            for i, strategy in enumerate(strategies, 1):
                self.console.print(
                    f"\n[bold][STATS] Strategy {i}/{len(strategies)}: {strategy.name}[/bold]"
                )

                strategy_results = await self.engine.test_strategy_on_multiple_domains(
                    domains, strategy, progress_callback=self.console.print
                )

                # Update results
                for domain, success in strategy_results.items():
                    if domain not in all_results or not all_results[domain]:
                        all_results[domain] = success
                        if success:
                            summary.results[domain] = BatchResult(
                                domain=domain,
                                success=True,
                                strategy_name=strategy.name,
                            )

                # Display strategy results
                successful = [d for d, s in strategy_results.items() if s]
                if successful:
                    self.console.print(
                        f"[green][OK] Strategy worked for {len(successful)} domains[/green]"
                    )
                else:
                    self.console.print("[red][FAIL] Strategy failed for all domains[/red]")

                # Check if all done
                if all(all_results.get(d, False) for d in domains):
                    self.console.print("[green][SUCCESS] All domains processed![/green]")
                    break

            # Mark remaining failed domains
            for domain in domains:
                if domain not in summary.results:
                    summary.results[domain] = BatchResult(
                        domain=domain,
                        success=False,
                        error="All strategies failed",
                    )

        except Exception as e:
            LOG.error(f"Batch analysis error: {e}")
            self.console.print(f"[red][FAIL] Batch error: {e}[/red]")
            for domain in domains:
                if domain not in summary.results:
                    summary.results[domain] = BatchResult(
                        domain=domain,
                        success=False,
                        error=str(e),
                    )

        # Finalize summary
        summary.total_time = get_monotonic_time() - start_time
        summary.successful_domains = sum(1 for r in summary.results.values() if r.success)
        summary.failed_domains = summary.total_domains - summary.successful_domains

        # Display summary
        self._display_batch_summary(summary, get_monotonic_time, start_time)

        return all_results

    async def _generate_strategies_for_batch(
        self,
        sample_domain: str,
    ) -> List[Any]:
        """Generate strategies based on sample domain."""
        self.console.print(f"[dim]Generating strategies from {sample_domain}...[/dim]")

        try:
            fingerprint = self.engine.fingerprint_service.get_or_create(sample_domain)
            intents = self.engine.intent_engine.propose_intents(fingerprint)
            strategies = await self.engine.strategy_generator.generate_strategies(
                intents[:10], fingerprint
            )
            return strategies
        except Exception as e:
            self.console.print(f"[yellow][WARN] Strategy generation failed: {e}[/yellow]")
            self.console.print("[dim]Using fallback strategies...[/dim]")
            return self._get_fallback_strategies()

    def _get_fallback_strategies(self) -> List[Any]:
        """Get fallback strategies when generation fails."""
        try:
            from core.strategy_failure_analyzer import Strategy

            return [
                Strategy(
                    name="fake_ttl3",
                    attack_name="fake",
                    # provide both ttl and fake_ttl for maximum compatibility
                    parameters={"ttl": 3, "fake_ttl": 3, "split_pos": "sni"},
                ),
                Strategy(
                    name="disorder_ttl4",
                    attack_name="disorder",
                    # ttl may be ignored by disorder handlers, but keep for traceability
                    parameters={
                        "ttl": 4,
                        "fake_ttl": 4,
                        "split_pos": 3,
                        "disorder_method": "reverse",
                    },
                ),
                Strategy(
                    name="split2_ttl5",
                    # "split2" is NOT an attack name; it's a describer token (split_pos=2).
                    attack_name="split",
                    parameters={"ttl": 5, "fake_ttl": 5, "split_pos": 2},
                ),
            ]
        except ImportError:
            return []

    def _display_batch_summary(
        self, summary: BatchSummary, get_monotonic_time: callable, start_time: float
    ) -> None:
        """Display batch processing summary."""
        self.console.print("\n" + "=" * 70)
        self.console.print("[bold blue]BATCH MODE SUMMARY REPORT[/bold blue]")
        self.console.print("=" * 70)

        # Overall statistics
        self.console.print("\n[bold]Overall Statistics:[/bold]")
        self.console.print(f"  Total domains: {summary.total_domains}")
        self.console.print(f"  [green]Successful: {summary.successful_domains}[/green]")
        self.console.print(f"  [red]Failed: {summary.failed_domains}[/red]")

        # Success rate with color
        rate = summary.success_rate
        color = "green" if rate >= 75 else ("yellow" if rate >= 50 else "red")
        self.console.print(f"  [{color}]Success rate: {rate:.1f}%[/{color}]")
        self.console.print(f"  Total time: {summary.total_time:.2f}s")

        # Display table
        try:
            from rich.table import Table  # noqa: F401

            if not self.quiet:
                self._display_batch_table(summary)
            else:
                self._display_batch_plain(summary)
        except ImportError:
            self._display_batch_plain(summary)

        # Successful domains
        successful = [d for d, r in summary.results.items() if r.success]
        if successful:
            self.console.print(f"\n[bold green]✓ Successful ({len(successful)}):[/bold green]")
            for domain in sorted(successful):
                result = summary.results[domain]
                self.console.print(f"  [green]✓[/green] {domain}")
                if result.strategy_name:
                    self.console.print(f"    [dim]Strategy: {result.strategy_name}[/dim]")

        # Failed domains
        failed = [d for d, r in summary.results.items() if not r.success]
        if failed:
            self.console.print(f"\n[bold red]✗ Failed ({len(failed)}):[/bold red]")
            for domain in sorted(failed):
                result = summary.results[domain]
                self.console.print(f"  [red]✗[/red] {domain}")
                if result.error:
                    self.console.print(f"    [dim]Reason: {result.error}[/dim]")

        self.console.print("\n" + "=" * 70)

    def _display_batch_table(self, summary: BatchSummary) -> None:
        """Display batch summary as Rich table."""
        try:
            from rich.table import Table

            table = Table(title="Per-Domain Results", show_header=True, header_style="bold")
            table.add_column("Domain", style="cyan", no_wrap=False)
            table.add_column("Status", justify="center")
            table.add_column("Strategy", style="dim")
            table.add_column("Notes", style="dim")

            for domain in sorted(summary.results.keys()):
                result = summary.results[domain]
                status = "[green]✓ SUCCESS[/green]" if result.success else "[red]✗ FAILED[/red]"
                strategy = result.strategy_name or "-"
                notes = result.error or "-" if not result.success else "-"

                table.add_row(domain, status, strategy, notes)

            self.console.print(f"\n{table}")
        except ImportError:
            self._display_batch_plain(summary)

    def _display_batch_plain(self, summary: BatchSummary) -> None:
        """Display batch summary in plain text."""
        self.console.print("\n[bold]Per-Domain Results:[/bold]")
        self.console.print("-" * 70)
        self.console.print(f"{'Domain':<40} {'Status':<15} {'Strategy':<15}")
        self.console.print("-" * 70)

        for domain in sorted(summary.results.keys()):
            result = summary.results[domain]
            status = "SUCCESS" if result.success else "FAILED"
            strategy = (result.strategy_name or "-")[:15]
            domain_display = domain[:37] + "..." if len(domain) > 40 else domain

            self.console.print(f"{domain_display:<40} {status:<15} {strategy:<15}")
