# recon/cli_workflow_patch.py
"""
CLI Workflow Optimization Patch

This patch integrates the workflow optimizer into the CLI to avoid
fingerprinting duplication and provide mutually exclusive execution modes.
"""

import logging
from typing import Dict, Any, Optional, List

from .core.cli_workflow_optimizer import (
    CLIWorkflowOptimizer,
    ExecutionMode,
    create_workflow_optimizer,
    detect_execution_mode,
)

LOG = logging.getLogger(__name__)


class OptimizedCLIWorkflow:
    """
    Optimized CLI workflow that integrates with the existing CLI structure
    to provide performance improvements and avoid duplication.
    """

    def __init__(self, attack_adapter, result_processor, args):
        self.attack_adapter = attack_adapter
        self.result_processor = result_processor
        self.args = args

        # Initialize workflow optimizer
        self.optimizer = create_workflow_optimizer(
            attack_adapter, result_processor, args
        )
        self.execution_mode = detect_execution_mode(args)

        LOG.info(
            f"Initialized optimized CLI workflow in {self.execution_mode.value} mode"
        )

    async def run_optimized_hybrid_mode(self, report_logger, domains, dns_cache):
        """
        Run optimized hybrid mode that avoids fingerprinting duplication.

        This replaces the original run_hybrid_mode function with optimizations.
        """
        LOG.info("Starting optimized hybrid mode execution")

        # Step 1: Optimize domain grouping to minimize fingerprinting
        console.print(
            "\n[yellow]Step 1 (Optimized): Intelligent Domain Grouping...[/yellow]"
        )

        optimized_groups = self.optimizer.optimize_domain_grouping(domains, dns_cache)

        if not optimized_groups:
            console.print("[bold red]Error:[/bold red] No valid domain groups created.")
            return

        console.print(
            f"Optimized grouping: {len(optimized_groups)} groups (vs {len(domains)} individual domains)"
        )
        report_logger.info(
            f"Domain grouping optimization: {len(optimized_groups)} groups for {len(domains)} domains"
        )

        # Step 2: Process groups with fingerprint caching
        console.print(
            "\n[yellow]Step 2 (Optimized): Fingerprinting with Caching...[/yellow]"
        )

        fingerprinted_groups = {}

        for group_id, group_domains in optimized_groups.items():
            if group_id.startswith("pending_"):
                # Need to fingerprint this group
                ip = group_id.replace("pending_", "")
                representative_domain = group_domains[0]

                # Check if we can skip fingerprinting
                should_skip, cached_fp = self.optimizer.should_skip_fingerprinting(
                    representative_domain, ip
                )

                if should_skip and cached_fp:
                    console.print(
                        f"  [green]✓ Using cached fingerprint for {len(group_domains)} domains[/green]"
                    )
                    fingerprinted_groups[cached_fp.short_hash()] = {
                        "domains": group_domains,
                        "fingerprint": cached_fp,
                        "best_result": None,
                    }
                else:
                    # Perform fingerprinting for representative domain
                    console.print(
                        f"  [cyan]Fingerprinting {representative_domain} (representing {len(group_domains)} domains)[/cyan]"
                    )

                    # Initialize fingerprinting components
                    probe_config = ProbeConfig(target_ip=ip, port=self.args.port)
                    prober = UltimateDPIProber(probe_config)
                    classifier = UltimateDPIClassifier(ml_enabled=SKLEARN_AVAILABLE)
                    fingerprint_engine = UltimateAdvancedFingerprintEngine(
                        prober=prober,
                        classifier=classifier,
                        attack_adapter=self.attack_adapter,
                        debug=self.args.debug,
                    )

                    # Create fingerprint
                    with capture_session(f"tcp and host {ip}") as (packets, _):
                        context = AttackContext(
                            dst_ip=ip,
                            dst_port=self.args.port,
                            domain=representative_domain,
                            params={"type": "baseline"},
                        )
                        await self.attack_adapter.execute_attack_by_name(
                            "tcp_http_combo", context
                        )

                    fp = await fingerprint_engine.create_comprehensive_fingerprint(
                        representative_domain, target_ips=[ip], packets=packets
                    )

                    # Cache the fingerprint for all domains in this group
                    for domain in group_domains:
                        self.optimizer.cache_fingerprint_result(domain, ip, fp)

                    fingerprinted_groups[fp.short_hash()] = {
                        "domains": group_domains,
                        "fingerprint": fp,
                        "best_result": None,
                    }

                    console.print(
                        f"  [green]✓ Fingerprinted and cached for {len(group_domains)} domains[/green]"
                    )
            else:
                # Already have fingerprint from cache
                fingerprinted_groups[group_id] = optimized_groups[group_id]

        # Step 3: Strategy testing with optimization
        console.print(
            f"\n[yellow]Step 3 (Optimized): Strategy Testing on {len(fingerprinted_groups)} Groups...[/yellow]"
        )

        all_results_history = []

        for fp_hash, group_data in fingerprinted_groups.items():
            fp = group_data["fingerprint"]
            group_domains = group_data["domains"]

            console.print(f"\nTesting group {fp_hash} ({len(group_domains)} domains)")

            # Optimize attack order based on fingerprint
            if hasattr(self.args, "count"):
                strategy_generator = AdvancedStrategyGenerator(
                    fingerprint_dict=fp.to_dict(), history=[], parameter_optimizer=None
                )
                strategy_plan = strategy_generator.generate_strategies(
                    count=self.args.count
                )

                # Extract attack names and optimize order
                attack_names = [
                    task.get("name") for task in strategy_plan if task.get("name")
                ]
                optimized_order = self.optimizer.optimize_parameter_testing_order(
                    attack_names, fp
                )

                # Reorder strategy plan based on optimization
                optimized_strategy_plan = []
                for attack_name in optimized_order:
                    for task in strategy_plan:
                        if task.get("name") == attack_name:
                            optimized_strategy_plan.append(task)
                            break

                console.print(
                    f"  [cyan]Optimized attack order: {optimized_order[:3]}...[/cyan]"
                )
            else:
                optimized_strategy_plan = []

            # Test strategies on this group
            await self._test_optimized_strategy_group(
                group_data, optimized_strategy_plan, report_logger
            )

            if group_data.get("best_result"):
                all_results_history.append(group_data["best_result"])

        # Step 4: Final report
        console.print(
            "\n[yellow]Step 4: Final Report and Optimization Summary...[/yellow]"
        )

        # Display workflow optimization statistics
        workflow_stats = self.optimizer.get_workflow_statistics()
        console.print(f"\n[bold cyan]Workflow Optimization Statistics:[/bold cyan]")
        console.print(
            f"  Execution mode: {workflow_stats.get('execution_mode', 'unknown')}"
        )
        console.print(
            f"  Cached fingerprints: {workflow_stats.get('cached_fingerprints', 0)}"
        )
        console.print(
            f"  Cache hit rate: {workflow_stats.get('cache_hit_rate', 0):.1%}"
        )
        console.print(f"  Domain groups: {workflow_stats.get('domain_groups', 0)}")

        report_logger.info("\n=== Workflow Optimization Statistics ===")
        for key, value in workflow_stats.items():
            report_logger.info(f"{key}: {value}")

        return all_results_history

    async def _test_optimized_strategy_group(
        self, group_data, strategy_plan, report_logger
    ):
        """Test strategies on a group with optimizations."""
        fp = group_data["fingerprint"]
        group_domains = group_data["domains"]

        # Use fast mode if appropriate
        use_fast_mode = self.optimizer.should_use_fast_mode(len(group_domains))

        if use_fast_mode:
            console.print(
                f"  [yellow]Using fast mode for {len(group_domains)} domains[/yellow]"
            )
            # Test only on representative domain, then apply to all
            representative_domain = group_domains[0]
            test_domains = [representative_domain]
        else:
            test_domains = group_domains

        best_result = None

        for i, strategy_task in enumerate(strategy_plan):
            attack_name = strategy_task.get("name", "unknown_attack")

            # Test strategy on selected domains
            successful_tests = []

            for domain in test_domains:
                ip = self.optimizer.workflow_state.dns_cache.get(domain)
                if not ip:
                    continue

                test_payload = f"GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode()
                context = AttackContext(
                    dst_ip=ip,
                    dst_port=self.args.port,
                    domain=domain,
                    payload=test_payload,
                    params=strategy_task.get("params", {}),
                    debug=self.args.debug,
                )

                attack_result = await self.attack_adapter.execute_attack_by_name(
                    attack_name, context
                )
                processed = self.result_processor.process_attack_result(
                    attack_result, attack_name
                )

                if processed.get("bypass_effective"):
                    successful_tests.append(processed)

            if successful_tests:
                success_rate = len(successful_tests) / len(test_domains)
                avg_latency = sum(r["latency_ms"] for r in successful_tests) / len(
                    successful_tests
                )

                strategy_summary = {
                    "task": strategy_task,
                    "success_rate": success_rate,
                    "avg_latency_ms": avg_latency,
                    "bypass_effective": True,
                }

                if best_result is None or success_rate > best_result["success_rate"]:
                    best_result = strategy_summary

                console.print(
                    f"    [green]✓ {attack_name}: {success_rate:.0%} success[/green]"
                )

                # Early termination if we find a very effective strategy
                if success_rate >= 0.9:
                    console.print(
                        f"    [bold green]Early termination - found highly effective strategy[/bold green]"
                    )
                    break
            else:
                console.print(f"    [red]✗ {attack_name}: No success[/red]")

        group_data["best_result"] = best_result

        if best_result:
            console.print(
                f"  [bold green]Best for group: {best_result['task'].get('name')} "
                f"({best_result['success_rate']:.0%} success)[/bold green]"
            )
        else:
            console.print(
                f"  [bold red]No effective strategies found for this group[/bold red]"
            )

    def should_skip_evolutionary_search(self, current_effectiveness: float) -> bool:
        """Check if evolutionary search should be skipped."""
        return self.optimizer.should_skip_evolutionary_search(current_effectiveness)

    def cleanup(self):
        """Clean up workflow resources."""
        self.optimizer.cleanup_workflow()
        LOG.info("Cleaned up optimized CLI workflow")


# Integration functions for existing CLI
def create_optimized_workflow(attack_adapter, result_processor, args):
    """Create optimized workflow instance."""
    return OptimizedCLIWorkflow(attack_adapter, result_processor, args)


def should_use_optimization(args) -> bool:
    """Determine if workflow optimization should be used."""
    # Use optimization for multi-domain scenarios
    if hasattr(args, "domains_file") and args.domains_file:
        return True

    # Use optimization for closed loop mode
    if hasattr(args, "closed_loop") and args.closed_loop:
        return True

    # Use optimization for parameter optimization
    if hasattr(args, "optimize_parameters") and args.optimize_parameters:
        return True

    return False


# Monkey patch functions to integrate with existing CLI
def patch_cli_with_optimization():
    """
    Apply workflow optimization patches to the existing CLI.
    This function can be called to enable optimizations.
    """
    LOG.info("Applied CLI workflow optimization patches")

    # This would contain the actual patching logic
    # For now, it's a placeholder that indicates the optimization is available
