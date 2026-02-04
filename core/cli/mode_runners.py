#!/usr/bin/env python3
"""
CLI Mode Runners Module

This module contains all mode execution functions for the Recon CLI.
Each function implements a specific operational mode for DPI bypass testing.

Modes Available:
    - run_profiling_mode: PCAP traffic analysis and profiling
    - run_hybrid_mode: Hybrid testing with real-world tools
    - run_single_strategy_mode: Test a single bypass strategy
    - run_evolutionary_mode: Evolutionary strategy search
    - run_per_domain_mode: Per-domain strategy optimization
    - run_adaptive_mode: Adaptive learning-based bypass
    - run_adaptive_mode_legacy: Legacy adaptive mode
    - run_optimization_mode: Strategy optimization mode
    - run_revalidate_mode: Revalidate existing strategies
    - run_status_mode: Display current bypass status
    - run_list_failures_mode: List failed bypass attempts
    - run_compare_modes_command: Compare different modes

Cleanup Functions:
    - cleanup_aiohttp_sessions: Cleanup aiohttp client sessions
    - run_adaptive_mode_with_cleanup: Adaptive mode with cleanup wrapper

Architecture:
    This module has been extensively refactored (Steps 1-11) to extract
    common patterns into reusable helper functions in core.cli.helpers.
    The result is cleaner, more maintainable code with 94% reduction in
    the main hybrid mode function (1128 → 63 lines).

Usage:
    These functions are typically called from cli.py based on command-line
    arguments. Each function is async and takes an args object with mode-specific
    configuration.

Example:
    >>> args = parse_args()
    >>> await run_hybrid_mode(args)

Note:
    All mode functions maintain backward compatibility and can be imported
    directly from this module or through cli.py.

Extracted from: cli.py (original 2869 lines)
Current size: ~1830 lines (36% reduction)
Helper functions: 32 (in core.cli.helpers)
"""

# Public API - explicitly define what can be imported from this module
__all__ = [
    # Main mode execution functions
    "run_profiling_mode",
    "run_hybrid_mode",
    "run_single_strategy_mode",
    "run_evolutionary_mode",
    "run_per_domain_mode",
    "run_adaptive_mode",
    "run_adaptive_mode_legacy",
    "run_adaptive_mode_with_cleanup",
    "run_optimization_mode",
    "run_revalidate_mode",
    "run_status_mode",
    "run_list_failures_mode",
    "run_compare_modes_command",
    # Cleanup utilities
    "cleanup_aiohttp_sessions",
]

import asyncio
import gc
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

# Import Rich components for UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress
    from rich.table import Table

    console = Console()
except ImportError:

    class Console:
        def print(self, *args, **kwargs):
            print(*args)

    console = Console()
    Panel = None
    Progress = None
    Table = None

# Import core components
from core.doh_resolver import DoHResolver
from core.learning.adaptive_cache import AdaptiveLearningCache
from core.fingerprint.simple_fingerprinter import SimpleFingerprinter
from ml.zapret_strategy_generator import ZapretStrategyGenerator

# Import CLI helpers
from core.cli.helpers import (
    cleanup_resources,
    display_and_save_strategy_results,
    display_kb_summary,
    generate_and_save_report,
    handle_baseline_validation,
    integrate_pcap_with_engine,
    load_domain_rules,
    perform_pcap_analysis,
    prepare_bypass_strategies,
    process_test_results,
    run_baseline_testing,
    run_dpi_fingerprinting,
    setup_domain_manager,
    setup_pcap_capture,
    setup_reporters,
    setup_unified_engine,
    with_async_cleanup,
)

# Get logger
LOG = logging.getLogger("recon.mode_runners")


# Extracted mode runner functions


async def run_profiling_mode(args):
    console.print(
        Panel(
            "[bold blue]Recon: Traffic Profiler[/bold blue]",
            title="PCAP Analysis Mode",
            expand=False,
        )
    )
    if not PROFILER_AVAILABLE:
        console.print("[red][X] AdvancedTrafficProfiler not available.[/red]")
        return
    pcap = args.profile_pcap
    if not pcap or not os.path.exists(pcap):
        console.print(f"[red]PCAP not found: {pcap}[/red]")
        return
    profiler = AdvancedTrafficProfiler()
    res = profiler.analyze_pcap_file(pcap)
    if not res or not res.success:
        console.print("[red][X] Profiling failed[/red]")
        return
    console.print("\n[bold green][OK] Traffic Profiling Complete[/bold green]")
    if res.detected_applications:
        console.print("[bold]Detected applications:[/bold] " + ", ".join(res.detected_applications))
    if res.steganographic_opportunities:
        console.print("[bold]Steganographic opportunities:[/bold]")
        for k, v in res.steganographic_opportunities.items():
            console.print(f"  - {k}: {v:.2f}")
    seq_len = res.metadata.get("sequence_length", 0)
    ctx = res.metadata.get("context", {})
    console.print(
        f"[dim]Packets analyzed: {seq_len}, TLS ClientHello: {ctx.get('tls_client_hello',0)}, TLS alerts: {ctx.get('tls_alert_count',0)}, QUIC initial: {ctx.get('quic_initial_count',0)}[/dim]"
    )


# --- Основные режимы выполнения ---


async def run_hybrid_mode(args):
    """Новый режим с гибридным тестированием через реальные инструменты."""
    console.print(
        Panel(
            "[bold cyan]Recon: Hybrid DPI Bypass Finder[/bold cyan]",
            title="Real-World Testing Mode",
            expand=False,
        )
    )

    # Setup domain manager with validation and normalization
    dm = setup_domain_manager(args, console)
    if not dm:
        return

    # Setup PCAP capture if requested (before creating engine)
    capturer = setup_pcap_capture(args, console)

    # Setup unified bypass engine with verbose logging
    DoHResolver()
    hybrid_engine = setup_unified_engine(args, console)

    # Integrate PCAP capture with engine if available
    integrate_pcap_with_engine(capturer, hybrid_engine, console)

    # Setup reporters (simple and advanced with fallback)
    reporter, advanced_reporter = await setup_reporters(args, console)

    learning_cache = AdaptiveLearningCache()
    simple_fingerprinter = SimpleFingerprinter(debug=args.debug)

    # Background PCAP insights worker (enhanced tracking)
    pcap_worker_task = None
    if args.enable_enhanced_tracking:
        try:
            from core.pcap.pcap_insights_worker import PcapInsightsWorker

            pcap_worker = PcapInsightsWorker()
            pcap_worker_task = asyncio.create_task(pcap_worker.run(interval=15.0))
            console.print("[dim][AI] Enhanced tracking enabled: PCAP insights worker started[/dim]")
        except Exception as e:
            console.print(f"[yellow][!] Could not start PCAP insights worker: {e}[/yellow]")

    # Step 1: Load domain rules configuration
    domain_rules = load_domain_rules(console)
    if not domain_rules:
        return  # Error already printed to console

    # Enhanced tracking disabled - requires IP-based approach which is being removed
    if args.enable_enhanced_tracking and args.pcap:
        console.print(
            "[yellow][!] Enhanced tracking disabled - incompatible with domain-based approach[/yellow]"
        )

    # Step 2: Run baseline testing to identify blocked sites
    baseline_results, blocked_sites = await run_baseline_testing(
        hybrid_engine, dm.domains, console, capturer
    )
    if not blocked_sites:
        return  # All sites working, early exit already handled

    # Step 2.5: Run DPI fingerprinting on blocked sites
    fingerprints, refiner = await run_dpi_fingerprinting(
        args, blocked_sites, simple_fingerprinter, console
    )

    # Step 3: Prepare bypass strategies from various sources
    structured_strategies = await prepare_bypass_strategies(
        args, dm, fingerprints, learning_cache, hybrid_engine, console
    )
    if not structured_strategies:
        return  # Error already printed to console

    # Initialize data structure for per-domain results
    domain_strategy_map = defaultdict(list)

    # Шаг 4: Гибридное тестирование
    console.print("\n[yellow]Step 4: Hybrid testing with forced DNS...[/yellow]")

    primary_domain = (
        urlparse(dm.domains[0]).hostname
        or dm.domains[0].replace("https://", "").replace("http://", "")
        if dm.domains
        else None
    )
    fingerprint_to_use = fingerprints.get(primary_domain)

    test_results = await hybrid_engine.test_strategies_hybrid(
        strategies=structured_strategies,
        test_sites=blocked_sites,
        ips=set(),  # Empty IP set - engine will resolve domains as needed
        dns_cache={},  # Empty DNS cache - engine will resolve domains as needed
        port=args.port,
        domain=primary_domain,
        fast_filter=not args.no_fast_filter,
        initial_ttl=None,
        enable_fingerprinting=bool(args.fingerprint and fingerprints),
        telemetry_full=args.telemetry_full,
        engine_override=args.engine,
        capturer=capturer,  # Fixed: was corr_capturer (undefined)
        fingerprint=fingerprint_to_use,
    )

    # Step 5: Process test results (refine fingerprints, update cache, validate PCAP)
    pcap_validation_result = await process_test_results(
        args,
        test_results,
        fingerprints,
        refiner,
        simple_fingerprinter,
        blocked_sites,
        learning_cache,
        domain_strategy_map,
        capturer,
        console,
    )

    # Perform PCAP analysis (correlation, pattern validation, profiling)
    await perform_pcap_analysis(args, capturer, console)

    # Display and save strategy results
    working_strategies, best_strategy_result = await display_and_save_strategy_results(
        test_results, domain_strategy_map, args, dm, hybrid_engine, console
    )

    # Generate comprehensive report
    final_report_data = await generate_and_save_report(
        args,
        test_results,
        working_strategies,
        domain_strategy_map,
        blocked_sites,
        dm,
        fingerprints,
        pcap_validation_result,
        reporter,
        advanced_reporter,
        console,
    )

    # Handle baseline validation if enabled
    await handle_baseline_validation(args, test_results, final_report_data, console)

    # Display knowledge base summary
    display_kb_summary(console)

    # Мониторинг
    if args.monitor and working_strategies:
        console.print("\n[yellow][REFRESH] Starting monitoring mode...[/yellow]")
        await start_monitoring_mode(args, blocked_sites, learning_cache)

    # Cleanup all resources
    await cleanup_resources(
        hybrid_engine,
        pcap_worker_task,
        refiner,
        None,  # unified_fingerprinter not used in hybrid mode
        advanced_reporter,
        capturer,
        None,  # corr_capturer not used
        console,
    )


async def run_single_strategy_mode(args):
    console.print(Panel("[bold cyan]Recon: Single Strategy Test[/bold cyan]", expand=False))
    if not args.strategy:
        console.print(
            "[bold red]Error:[/bold red] --strategy is required for single strategy mode."
        )
        return
    console.print(f"Testing strategy: [cyan]{args.strategy}[/cyan]")
    await run_hybrid_mode(args)


async def run_evolutionary_mode(args):
    console.print(
        Panel(
            "[bold magenta]Recon: Evolutionary Strategy Search[/bold magenta]",
            expand=False,
        )
    )
    try:
        import ctypes

        if platform.system() == "Windows" and ctypes.windll.shell32.IsUserAnAdmin() != 1:
            console.print(
                "[bold red]Error: Administrator privileges required for evolutionary search.[/bold red]"
            )
            console.print("Please run this command from an Administrator terminal.")
            return
    except Exception:
        pass

    # Setup domain manager with validation and normalization
    dm = setup_domain_manager(args, console)
    if not dm:
        return

    # Setup unified bypass engine with verbose logging
    DoHResolver()
    hybrid_engine = setup_unified_engine(args, console)

    learning_cache = AdaptiveLearningCache()
    simple_fingerprinter = SimpleFingerprinter(debug=args.debug)
    console.print("\n[yellow]Step 1: Baseline Testing...[/yellow]")
    baseline_results = await hybrid_engine.test_baseline_connectivity(
        dm.domains, {}  # Empty DNS cache - engine will resolve domains as needed
    )
    blocked_sites = [
        site for site, (status, _, _, _) in baseline_results.items() if status not in ["WORKING"]
    ]
    if not blocked_sites:
        console.print(
            "[bold green][OK] All sites are accessible! No evolution needed.[/bold green]"
        )
        return
    console.print(f"Found {len(blocked_sites)} blocked sites for evolution.")

    # Step 2.5: DPI Fingerprinting for better evolution
    fingerprints = {}
    console.print("\n[yellow]Step 2.5: DPI Fingerprinting for Evolution...[/yellow]")
    advanced_fingerprinter = None
    if ADV_FPR_AVAILABLE:
        try:
            from core.fingerprint.advanced_fingerprinter import (
                AdvancedFingerprinter,
                FingerprintingConfig,
            )

            cfg = FingerprintingConfig(
                analysis_level="balanced",
                max_parallel_targets=min(3, len(blocked_sites)),
                enable_fail_fast=True,
                connect_timeout=5.0,
                tls_timeout=10.0,
            )
            advanced_fingerprinter = AdvancedFingerprinter(config=cfg)

            with Progress(console=console, transient=True) as progress:
                task = progress.add_task(
                    "[cyan]Fingerprinting for evolution...", total=len(blocked_sites)
                )
                for site in blocked_sites:
                    hostname = urlparse(site).hostname or site
                    try:
                        fp = await advanced_fingerprinter.fingerprint_target(
                            hostname, port=args.port, protocols=["http", "https"]
                        )
                        fingerprints[hostname] = fp
                        try:
                            dpi_value = getattr(
                                fp.dpi_type,
                                "value",
                                str(getattr(fp.dpi_type, "name", "unknown")),
                            )
                            console.print(
                                f"  - {hostname}: [cyan]{dpi_value}[/cyan] "
                                f"(reliability: {getattr(fp, 'reliability_score', 0):.2f})"
                            )
                        except Exception:
                            console.print(f"  - {hostname}: fingerprint collected")
                    except Exception as e:
                        console.print(
                            f"[yellow]  - {hostname}: Advanced fingerprint failed ({e}), fallback...[/yellow]"
                        )
                        # Simple fingerprinter will resolve the domain internally
                        fp_simple = await simple_fingerprinter.create_fingerprint(
                            hostname,
                            None,
                            args.port,  # Pass None for IP - let fingerprinter resolve
                        )
                        if fp_simple:
                            fingerprints[hostname] = fp_simple
                    progress.update(task, advance=1)
            await advanced_fingerprinter.close()
        except Exception as e:
            console.print(
                f"[yellow]Advanced fingerprinting failed: {e}, using simple mode[/yellow]"
            )
            advanced_fingerprinter = None

    if not fingerprints:
        console.print("[yellow]Using simple fingerprinting fallback...[/yellow]")
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[cyan]Simple fingerprinting...", total=len(blocked_sites))
            for site in blocked_sites:
                hostname = urlparse(site).hostname or site
                # Simple fingerprinter will resolve the domain internally
                fp = await simple_fingerprinter.create_fingerprint(
                    hostname, None, args.port  # Pass None for IP - let fingerprinter resolve
                )
                if fp:
                    fingerprints[hostname] = fp
                    console.print(
                        f"  - {hostname}: [cyan]{fp.dpi_type}[/cyan] ({fp.blocking_method})"
                    )
                progress.update(task, advance=1)
    searcher = SimpleEvolutionarySearcher(
        population_size=args.population,
        generations=args.generations,
        mutation_rate=args.mutation_rate,
    )
    console.print(
        f"\n[bold magenta][DNA] Starting Evolution with {args.population} individuals, {args.generations} generations[/bold magenta]"
    )

    # Prepare fingerprint-informed evolution
    first_domain = (
        urlparse(dm.domains[0]).hostname
        or dm.domains[0].replace("https://", "").replace("http://", "")
        if dm.domains
        else None
    )
    dpi_hash = ""
    if fingerprints and first_domain and first_domain in fingerprints:
        try:
            fp = fingerprints[first_domain]
            if hasattr(fp, "short_hash"):
                dpi_hash = fp.short_hash()
            else:
                # Fallback hash generation for simple fingerprints
                dpi_hash = f"{fp.dpi_type}_{fp.blocking_method}"
            console.print(
                f"[dim][AI] Using fingerprint data for evolution (DPI hash: {dpi_hash[:8]}...)[/dim]"
            )
        except Exception as e:
            console.print(f"[yellow]Warning: Could not extract DPI hash: {e}[/yellow]")
            dpi_hash = ""

    start_time = time.time()
    best_chromosome = await searcher.evolve(
        hybrid_engine,
        blocked_sites,
        args.port,
        learning_cache=learning_cache,
        domain=first_domain,
        dpi_hash=dpi_hash,
        engine_override=args.engine,
    )
    evolution_time = time.time() - start_time
    best_strategy = searcher.genes_to_zapret_strategy(best_chromosome.genes)
    console.print("\n" + "=" * 60)
    console.print("[bold green][PARTY] Evolutionary Search Complete! [PARTY][/bold green]")
    console.print(f"Evolution time: {evolution_time:.1f}s")
    console.print(f"Best fitness: [green]{best_chromosome.fitness:.3f}[/green]")
    console.print(f"Best strategy: [cyan]{best_strategy}[/cyan]")
    evolution_result = {
        "strategy": best_strategy,
        "fitness": best_chromosome.fitness,
        "genes": best_chromosome.genes,
        "generation": best_chromosome.generation,
        "evolution_time_seconds": evolution_time,
        "fitness_history": searcher.best_fitness_history,
        "population_size": args.population,
        "generations": args.generations,
        "mutation_rate": args.mutation_rate,
        "timestamp": datetime.now().isoformat(),
        # Add fingerprint data to results
        "fingerprint_used": bool(fingerprints),
        "dpi_type": dpi_hash if dpi_hash else "unknown",
        "dpi_confidence": 0.8 if fingerprints else 0.2,
        "fingerprint_recommendations_used": True if dpi_hash else False,
    }
    try:
        with open(STRATEGY_FILE, "w", encoding="utf-8") as f:
            json.dump(evolution_result, f, indent=2, ensure_ascii=False)
        console.print(f"[green][SAVE] Evolution result saved to '{STRATEGY_FILE}'[/green]")
    except Exception as e:
        console.print(f"[red]Error saving evolution result: {e}[/red]")
    if searcher.best_fitness_history:
        console.print("\n[bold underline][CHART] Evolution History[/bold underline]")
        for entry in searcher.best_fitness_history:
            gen = entry["generation"]
            best_fit = entry["best_fitness"]
            avg_fit = entry["avg_fitness"]
            console.print(f"Gen {gen+1}: Best={best_fit:.3f}, Avg={avg_fit:.3f}")
    console.print("[dim][SAVE] Saving evolution results to learning cache...[/dim]")
    # Record results for each domain without IP dependency
    for site in blocked_sites:
        domain = urlparse(site).hostname or site.replace("https://", "").replace("http://", "")
        # Use the proper DPI hash if available
        fingerprint_hash = ""
        if fingerprints and domain in fingerprints:
            try:
                fp = fingerprints[domain]
                if hasattr(fp, "short_hash"):
                    fingerprint_hash = fp.short_hash()
                else:
                    fingerprint_hash = f"{fp.dpi_type}_{fp.blocking_method}"
            except Exception:
                fingerprint_hash = dpi_hash if dpi_hash else ""
        else:
            fingerprint_hash = dpi_hash if dpi_hash else ""

        learning_cache.record_strategy_performance(
            strategy=best_strategy,
            domain=domain,
            ip=None,  # No IP dependency in domain-based approach
            success_rate=best_chromosome.fitness,
            avg_latency=100.0,
            dpi_fingerprint_hash=fingerprint_hash,
        )
    learning_cache.save_cache()
    if best_chromosome.fitness > 0.5:
        if Confirm.ask("\n[bold]Found good strategy! Apply it system-wide?[/bold]", default=True):
            console.print("[yellow]Applying evolved strategy system-wide...[/yellow]")
            try:
                apply_system_bypass(best_strategy)
                console.print("[green][OK] Strategy applied successfully![/green]")
            except Exception as e:
                console.print(f"[red]Error applying strategy: {e}[/red]")
    hybrid_engine.cleanup()


async def run_per_domain_mode(args):
    """Режим поиска оптимальных стратегий для каждого домена отдельно."""
    console.print(
        Panel(
            "[bold green]Recon: Per-Domain Strategy Optimization[/bold green]",
            expand=False,
        )
    )

    # Setup domain manager with validation and normalization
    dm = setup_domain_manager(args, console)
    if not dm:
        return

    console.print(f"Testing {len(dm.domains)} domains individually for optimal strategies...")

    # Setup unified bypass engine with verbose logging
    DoHResolver()
    hybrid_engine = setup_unified_engine(args, console)

    try:
        from core.strategy_manager import StrategyManager

        strategy_manager = StrategyManager()
    except ImportError:
        console.print("[red][X] StrategyManager not available[/red]")
        return
    learning_cache = None
    if not args.disable_learning:
        try:
            learning_cache = AdaptiveLearningCache()
            console.print("[dim][AI] Adaptive learning cache loaded[/dim]")
        except Exception:
            console.print("[yellow][!] Adaptive learning not available[/yellow]")
    all_results = {}
    for i, site in enumerate(dm.domains, 1):
        hostname = urlparse(site).hostname or site.replace("https://", "").replace("http://", "")
        console.print(
            f"\n[bold yellow]Testing domain {i}/{len(dm.domains)}: {hostname}[/bold yellow]"
        )
        baseline_results = await hybrid_engine.test_baseline_connectivity(
            [site], {}  # Empty DNS cache - engine will resolve domains as needed
        )
        if baseline_results[site][0] == "WORKING":
            console.print(f"[green][OK] {hostname} is accessible without bypass[/green]")
            continue
        console.print(
            f"[yellow][SEARCH] {hostname} needs bypass, finding optimal strategy...[/yellow]"
        )
        generator = ZapretStrategyGenerator()
        strategies = generator.generate_strategies(None, count=args.count)

        # REFACTOR: The new UnifiedBypassEngine handles strategy parsing internally.
        # We can pass the raw strategy strings directly.
        structured_strategies = strategies

        if learning_cache:
            optimized_strategies = learning_cache.get_smart_strategy_order(strategies, hostname, ip)
            if optimized_strategies != strategies:
                console.print(f"[dim][AI] Applied learning optimization for {hostname}[/dim]")
                structured_strategies = optimized_strategies

        domain_results = await hybrid_engine.test_strategies_hybrid(
            strategies=structured_strategies,
            test_sites=[site],
            ips=set(),  # Empty IP set - engine will resolve domains as needed
            dns_cache={},  # Empty DNS cache - engine will resolve domains as needed
            port=args.port,
            domain=hostname,
            fast_filter=not args.no_fast_filter,
            initial_ttl=None,
            enable_fingerprinting=False,  # Per-domain mode doesn't use fingerprinting
            engine_override=args.engine,
        )
        working_strategies = [r for r in domain_results if r["success_rate"] > 0]
        if working_strategies:
            best_strategy = working_strategies[0]
            console.print(f"[green][OK] Found optimal strategy for {hostname}:[/green]")
            console.print(f"   Strategy: [cyan]{best_strategy['strategy']}[/cyan]")
            console.print(
                f"   Success: {best_strategy['success_rate']:.0%}, Latency: {best_strategy['avg_latency_ms']:.1f}ms"
            )
            strategy_manager.add_strategy(
                hostname,
                best_strategy["strategy"],
                best_strategy["success_rate"],
                best_strategy["avg_latency_ms"],
            )
            all_results[hostname] = best_strategy
        else:
            console.print(f"[red][X] No working strategy found for {hostname}[/red]")
            all_results[hostname] = None
        if learning_cache:
            for result in domain_results:
                learning_cache.record_strategy_performance(
                    strategy=result["strategy"],
                    domain=hostname,
                    ip=ip,
                    success_rate=result["success_rate"],
                    avg_latency=result["avg_latency_ms"],
                )
    strategy_manager.save_strategies()
    if learning_cache:
        learning_cache.save_cache()
    console.print("\n[bold underline][STATS] Per-Domain Optimization Results[/bold underline]")
    successful_domains = [d for d, r in all_results.items() if r is not None]
    failed_domains = [d for d, r in all_results.items() if r is None]
    console.print(
        f"Successfully optimized: [green]{len(successful_domains)}/{len(all_results)}[/green] domains"
    )
    if successful_domains:
        console.print("\n[bold green][OK] Domains with optimal strategies:[/bold green]")
        for domain in successful_domains:
            result = all_results[domain]
            console.print(
                f"  * {domain}: {result['success_rate']:.0%} success, {result['avg_latency_ms']:.1f}ms"
            )
    if failed_domains:
        console.print("\n[bold red][X] Domains without working strategies:[/bold red]")
        for domain in failed_domains:
            console.print(f"  * {domain}")
    stats = strategy_manager.get_statistics()
    if stats["total_domains"] > 0:
        console.print("\n[bold underline][CHART] Strategy Statistics[/bold underline]")
        console.print(f"Total domains: {stats['total_domains']}")
        console.print(f"Average success rate: {stats['avg_success_rate']:.1%}")
        console.print(f"Average latency: {stats['avg_latency']:.1f}ms")
        console.print(
            f"Best performing domain: [green]{stats['best_domain']}[/green] ({stats['best_success_rate']:.1%})"
        )
    console.print("\n[green][SAVE] All strategies saved to domain_strategies.json[/green]")
    console.print("[dim]Use 'python recon_service.py' to start the bypass service[/dim]")
    hybrid_engine.cleanup()


# Mode wrapper functions with automatic cleanup
# Using decorator pattern to eliminate duplication (addresses FD1 cluster)

run_hybrid_mode_with_cleanup = with_async_cleanup(run_hybrid_mode)
run_single_strategy_mode_with_cleanup = with_async_cleanup(run_single_strategy_mode)
run_evolutionary_mode_with_cleanup = with_async_cleanup(run_evolutionary_mode)
run_per_domain_mode_with_cleanup = with_async_cleanup(run_per_domain_mode)


async def cleanup_aiohttp_sessions():
    """
    Clean up any remaining aiohttp sessions and pending tasks.

    This comprehensive cleanup function handles:
    - Cancellation of pending asyncio tasks
    - Closure of global HTTP client pool
    - Cleanup of DoH resolvers
    - Closure of aiohttp sessions and connectors
    - Garbage collection to trigger __del__ methods

    Addresses SR1, SR2: Improved exception handling with specific error types.
    """
    try:
        # Get current task to exclude it from cleanup
        current_task = asyncio.current_task()

        # Get all pending tasks except the current cleanup task
        pending_tasks = [
            task for task in asyncio.all_tasks() if not task.done() and task != current_task
        ]

        if pending_tasks:
            console.print(f"[dim]Cleaning up {len(pending_tasks)} pending tasks...[/dim]")
            LOG.debug(f"Cancelling {len(pending_tasks)} pending tasks")

            # Cancel all pending tasks (except current)
            for task in pending_tasks:
                if not task.done() and task != current_task:
                    try:
                        task.cancel()
                    except RuntimeError as e:
                        LOG.warning(f"Failed to cancel task {task}: {e}")
                    except Exception as e:
                        LOG.error(f"Unexpected error cancelling task {task}: {e}")

            # Wait for tasks to complete with timeout
            if pending_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*pending_tasks, return_exceptions=True),
                        timeout=3.0,  # Reduced timeout
                    )
                except asyncio.TimeoutError:
                    console.print(
                        "[yellow]Warning: Some tasks didn't complete within timeout[/yellow]"
                    )
                    LOG.warning("Task cleanup timeout - some tasks may still be running")
                except asyncio.CancelledError:
                    LOG.debug("Task cleanup was cancelled")
                except Exception as e:
                    LOG.error(f"Error during task cleanup: {e}", exc_info=True)

        # Close global HTTP client pool if it exists
        try:
            from core.optimization.http_client_pool import _global_pool

            if _global_pool:
                await _global_pool.close()
                LOG.debug("Global HTTP client pool closed")
        except ImportError:
            pass  # Module not available
        except AttributeError as e:
            LOG.warning(f"HTTP client pool attribute error: {e}")
        except Exception as e:
            LOG.error(f"Error closing HTTP client pool: {e}", exc_info=True)

        # Close DoH resolvers
        try:
            from core.doh_resolver import DoHResolver

            for obj in gc.get_objects():
                if isinstance(obj, DoHResolver):
                    try:
                        await obj._cleanup()
                    except AttributeError:
                        pass  # Object doesn't have _cleanup method
                    except Exception as e:
                        LOG.warning(f"Error cleaning up DoH resolver: {e}")
        except ImportError:
            pass  # Module not available
        except Exception as e:
            LOG.error(f"Error during DoH resolver cleanup: {e}", exc_info=True)

        # Close any remaining aiohttp sessions and connectors
        try:
            import aiohttp

            sessions_closed = 0
            connectors_closed = 0

            # Force close all open sessions
            for obj in gc.get_objects():
                try:
                    if isinstance(obj, aiohttp.ClientSession) and not obj.closed:
                        await obj.close()
                        sessions_closed += 1
                    elif isinstance(obj, aiohttp.TCPConnector) and not obj.closed:
                        await obj.close()
                        connectors_closed += 1
                except RuntimeError as e:
                    LOG.warning(f"Runtime error closing aiohttp object: {e}")
                except Exception as e:
                    LOG.warning(f"Error closing aiohttp object: {e}")

            if sessions_closed > 0 or connectors_closed > 0:
                LOG.debug(f"Closed {sessions_closed} sessions and {connectors_closed} connectors")

        except ImportError:
            pass  # aiohttp not available
        except Exception as e:
            LOG.error(f"Error during aiohttp cleanup: {e}", exc_info=True)

        # Force garbage collection to trigger __del__ methods
        gc.collect()
        LOG.debug("Garbage collection completed")

    except Exception as e:
        console.print(f"[yellow]Warning: Cleanup error: {e}[/yellow]")
        LOG.error(f"Unexpected error during cleanup: {e}", exc_info=True)


async def run_adaptive_mode(args):
    """Enhanced adaptive mode using AdaptiveCLIWrapper for better integration."""
    # Task 7: Import discovery system components
    try:
        from core.discovery_controller import DiscoveryController, DiscoveryConfig
        from core.cli_payload.adaptive_cli_wrapper import create_cli_wrapper_from_args

        DISCOVERY_AVAILABLE = True
    except ImportError as e:
        console.print(f"[bold red]Error: Discovery system not available: {e}[/bold red]")
        console.print("[yellow]Falling back to legacy adaptive mode...[/yellow]")
        await run_adaptive_mode_legacy(args)
        return

    # Initialize validation integrator if --validate flag is set
    validation_integrator = None
    if getattr(args, "validate", False):
        try:
            from core.validation_integration import create_validator_from_args

            validation_integrator = create_validator_from_args(args)
            if validation_integrator:
                console.print("[green]✅ Packet validation enabled[/green]")
                console.print(
                    "[dim]  PCAP files will be validated against attack specifications[/dim]"
                )
        except ImportError as e:
            console.print(f"[yellow]Warning: Validation not available: {e}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not initialize validation: {e}[/yellow]")
            if args.debug:
                import traceback

                traceback.print_exc()

    # Get target domain or domains from file
    target = args.target
    if not target:
        console.print("[bold red]Error: No target domain specified[/bold red]")
        console.print("[dim]Usage: python cli.py auto <domain>[/dim]")
        console.print("[dim]       python cli.py auto -d <domains_file>[/dim]")
        return

    # Check if target is a file (when using -d flag)
    domains_to_test = []
    if args.domains_file and Path(target).exists():
        # Load domains from file
        try:
            with open(target, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains_to_test.append(line)

            if not domains_to_test:
                console.print(f"[bold red]Error: No valid domains found in {target}[/bold red]")
                return

            console.print(f"[green]Loaded {len(domains_to_test)} domains from {target}[/green]")

        except Exception as e:
            console.print(f"[bold red]Error reading domains file {target}: {e}[/bold red]")
            return
    else:
        # Single domain
        domains_to_test = [target]

    # Setup PCAP capture if requested (before creating CLI wrapper)
    capturer = setup_pcap_capture(args, console)

    # Task 6: Initialize discovery system and CLI/service parity disabler
    discovery_controller = None
    discovery_session_id = None
    cli_parity_disabler = None

    if DISCOVERY_AVAILABLE:
        try:
            discovery_controller = DiscoveryController()
            console.print("[green]✅ Discovery system initialized[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not initialize discovery system: {e}[/yellow]")
            if args.debug:
                import traceback

                traceback.print_exc()

    # Task 6: Initialize CLI/service parity disabler for auto mode
    try:
        from core.cli_service_parity_disabler import CLIServiceParityDisabler

        cli_parity_disabler = CLIServiceParityDisabler()
        console.print("[green]✅ CLI/service parity disabler initialized[/green]")
    except Exception as e:
        console.print(
            f"[yellow]Warning: Could not initialize CLI/service parity disabler: {e}[/yellow]"
        )
        if args.debug:
            import traceback

            traceback.print_exc()

    # Create CLI wrapper with enhanced error handling and Rich output
    try:
        cli_wrapper = create_cli_wrapper_from_args(args)

        # PCAP INTEGRATION: Передаем CLI PacketCapturer в bypass engine
        if capturer and hasattr(cli_wrapper, "adaptive_engine"):
            try:
                adaptive_engine = cli_wrapper.adaptive_engine
                if hasattr(adaptive_engine, "bypass_engine") and adaptive_engine.bypass_engine:
                    bypass_engine = adaptive_engine.bypass_engine
                    if hasattr(bypass_engine, "packet_sender") and bypass_engine.packet_sender:
                        bypass_engine.packet_sender.set_pcap_writer(capturer._writer)
                        console.print(
                            "[dim]✅ CLI PacketCapturer integrated with bypass engine[/dim]"
                        )
            except Exception as e:
                console.print(f"[yellow]⚠️ Failed to integrate CLI PacketCapturer: {e}[/yellow]")

        # Task 6: Configure CLI wrapper for discovery mode and parity override disabling
        if discovery_controller and hasattr(cli_wrapper, "set_discovery_controller"):
            cli_wrapper.set_discovery_controller(discovery_controller)
            console.print("[green]✅ CLI wrapper configured for discovery mode[/green]")

        # Task 6: Configure CLI/service parity disabler with bypass engine
        if cli_parity_disabler and hasattr(cli_wrapper, "adaptive_engine"):
            try:
                adaptive_engine = cli_wrapper.adaptive_engine
                if hasattr(adaptive_engine, "bypass_engine") and adaptive_engine.bypass_engine:
                    cli_parity_disabler.bypass_engine = adaptive_engine.bypass_engine
                    console.print(
                        "[green]✅ CLI/service parity disabler configured with bypass engine[/green]"
                    )
            except Exception as e:
                console.print(
                    f"[yellow]⚠️ Failed to configure CLI/service parity disabler: {e}[/yellow]"
                )

    except Exception as e:
        console.print(f"[bold red]Error creating CLI wrapper: {e}[/bold red]")
        if args.debug:
            import traceback

            traceback.print_exc()
        return

    # Run adaptive analysis with enhanced CLI integration
    try:
        if len(domains_to_test) == 1:
            # Task 7: Single domain analysis with discovery mode
            domain = domains_to_test[0]

            # Start discovery session if available
            if discovery_controller:
                try:
                    from core.discovery_config import StrategyConfig, PCAPConfig, IntegrationConfig

                    discovery_config = DiscoveryConfig(
                        target_domain=domain,
                        strategy=StrategyConfig(
                            max_strategies=getattr(args, "max_trials", 10),
                            max_duration_seconds=300,  # Fixed: use constant instead of args.timeout which is for payload capture
                        ),
                        pcap=PCAPConfig(enabled=bool(getattr(args, "pcap", False))),
                        integration=IntegrationConfig(
                            override_domain_rules=True, restore_rules_on_completion=True
                        ),
                    )

                    # Task 6: Disable CLI/service parity override before starting discovery
                    if cli_parity_disabler:
                        cli_parity_disabler.disable_parity_override()
                        console.print(
                            "[green]🔍 CLI/service parity override disabled for strategy diversity[/green]"
                        )

                    discovery_session_id = discovery_controller.start_discovery(discovery_config)
                    console.print(
                        f"[green]🎯 Discovery session started: {discovery_session_id}[/green]"
                    )
                    console.print(f"[dim]Target domain: {domain}[/dim]")
                    console.print(
                        f"[dim]Discovery mode: Domain filtering enabled, strategy diversity active[/dim]"
                    )

                    # Task 6: Verify that CLI/service parity override is disabled
                    if cli_parity_disabler:
                        status = cli_parity_disabler.get_parity_status()
                        if status.parity_override_disabled:
                            console.print(
                                "[green]✅ CLI/service parity override confirmed disabled[/green]"
                            )
                        else:
                            console.print(
                                "[yellow]⚠️ CLI/service parity override may still be active[/yellow]"
                            )

                except Exception as e:
                    console.print(
                        f"[yellow]Warning: Could not start discovery session: {e}[/yellow]"
                    )
                    if args.debug:
                        import traceback

                        traceback.print_exc()

            # Run analysis with discovery integration
            success = await cli_wrapper.run_adaptive_analysis(domain, args)

            # Stop discovery session if it was started
            if discovery_controller and discovery_session_id:
                try:
                    report = discovery_controller.stop_discovery(
                        discovery_session_id, "Analysis completed"
                    )
                    console.print(f"[green]📊 Discovery session completed[/green]")
                    console.print(f"[dim]Session duration: {report.duration_seconds:.1f}s[/dim]")
                    console.print(
                        f"[dim]Strategies tested: {report.aggregated_stats.total_tests}[/dim]"
                    )
                except Exception as e:
                    console.print(
                        f"[yellow]Warning: Error stopping discovery session: {e}[/yellow]"
                    )

            if not success:
                console.print("\n[yellow][TIP] Troubleshooting tips:[/yellow]")
                console.print("  • Check your internet connection")
                console.print("  • Verify the domain is accessible")
                console.print("  • Try with --mode comprehensive for more thorough analysis")
                console.print("  • Use --debug for detailed error information")
        else:
            # Task 6: Multiple domains analysis with discovery mode support
            console.print(
                f"\n[bold blue][START] Оптимизированный пакетный анализ {len(domains_to_test)} доменов[/bold blue]"
            )
            console.print("[dim]Режим: одна стратегия → все домены параллельно[/dim]")

            # Task 6: Disable CLI/service parity override for batch processing
            if cli_parity_disabler:
                cli_parity_disabler.disable_parity_override()
                console.print(
                    "[green]🔍 CLI/service parity override disabled for batch processing[/green]"
                )

            if discovery_controller:
                console.print(
                    "[green]🎯 Discovery mode: Domain filtering and strategy diversity enabled for batch processing[/green]"
                )

            try:
                # Task 7: Configure batch processing for discovery mode
                if discovery_controller and hasattr(cli_wrapper, "set_batch_discovery_mode"):
                    cli_wrapper.set_batch_discovery_mode(True)

                # Используем новый оптимизированный метод
                batch_results = await cli_wrapper.run_batch_adaptive_analysis(domains_to_test, args)

                successful_domains = [d for d, success in batch_results.items() if success]
                failed_domains = [d for d, success in batch_results.items() if not success]

                # Summary
                console.print(
                    f"\n[bold blue][STATS] Итоговая сводка оптимизированного анализа[/bold blue]"
                )
                console.print(
                    f"[green][OK] Успешно: {len(successful_domains)}/{len(domains_to_test)}[/green]"
                )
                console.print(
                    f"[red][FAIL] Неудачно: {len(failed_domains)}/{len(domains_to_test)}[/red]"
                )

                if successful_domains:
                    console.print(f"\n[green]Успешные домены:[/green]")
                    for domain in successful_domains:
                        console.print(f"  • {domain}")

                if failed_domains:
                    console.print(f"\n[red]Неудачные домены:[/red]")
                    for domain in failed_domains:
                        console.print(f"  • {domain}")

                # Task 12.1: Offer to promote best strategies to domain_rules.json
                if args.promote_best_to_rules and successful_domains:
                    await _offer_promote_to_rules(successful_domains, console)

            except Exception as e:
                console.print(f"[red][FAIL] Ошибка пакетного анализа: {e}[/red]")
                if args.debug:
                    import traceback

                    traceback.print_exc()

    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        # Task 7: Clean up discovery session on interruption
        if discovery_controller and discovery_session_id:
            try:
                discovery_controller.stop_discovery(discovery_session_id, "User interruption")
                console.print("[dim]Discovery session cleaned up[/dim]")
            except Exception as cleanup_error:
                console.print(
                    f"[yellow]Warning: Error cleaning up discovery session: {cleanup_error}[/yellow]"
                )
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        # Task 7: Clean up discovery session on error
        if discovery_controller and discovery_session_id:
            try:
                discovery_controller.stop_discovery(discovery_session_id, f"Error: {e}")
                console.print("[dim]Discovery session cleaned up[/dim]")
            except Exception as cleanup_error:
                console.print(
                    f"[yellow]Warning: Error cleaning up discovery session: {cleanup_error}[/yellow]"
                )
        if args.debug:
            import traceback

            traceback.print_exc()


async def run_adaptive_mode_legacy(args):
    """Legacy adaptive mode implementation (fallback)."""
    console.print(
        Panel(
            "[bold cyan]Recon: Adaptive Strategy Discovery (Legacy Mode)[/bold cyan]\n"
            "[dim]Using AI-powered DPI analysis and failure learning[/dim]",
            expand=False,
        )
    )

    # Import AdaptiveEngine
    try:
        from core.adaptive_refactored.facade import AdaptiveEngine, AdaptiveConfig
    except ImportError as e:
        console.print(f"[bold red]Error: AdaptiveEngine not available: {e}[/bold red]")
        console.print("[yellow]Falling back to hybrid mode...[/yellow]")
        await run_hybrid_mode(args)
        return

    # Get target domain
    domain = args.target
    if not domain:
        console.print("[bold red]Error: No target domain specified[/bold red]")
        return

    # Configure adaptive engine based on CLI arguments
    config = AdaptiveConfig()

    # Map CLI mode to max_trials
    mode_trials = {"quick": 5, "balanced": 10, "comprehensive": 15, "deep": 25}

    if args.max_trials:
        config.max_trials = args.max_trials
    else:
        config.max_trials = mode_trials.get(args.mode, 10)

    config.enable_fingerprinting = not args.no_fingerprinting
    config.enable_failure_analysis = not args.no_failure_analysis

    console.print(f"[dim]Target: {domain}[/dim]")
    console.print(f"[dim]Mode: {args.mode} (max {config.max_trials} trials)[/dim]")
    console.print(
        f"[dim]Fingerprinting: {'enabled' if config.enable_fingerprinting else 'disabled'}[/dim]"
    )
    console.print(
        f"[dim]Failure analysis: {'enabled' if config.enable_failure_analysis else 'disabled'}[/dim]"
    )

    # Initialize adaptive engine
    try:
        engine = AdaptiveEngine(config)
        console.print("[green]✓ AdaptiveEngine initialized[/green]")
    except Exception as e:
        console.print(f"[bold red]Error initializing AdaptiveEngine: {e}[/bold red]")
        if args.debug:
            import traceback

            traceback.print_exc()
        return

    # Enable reasoning logger if requested
    if args.debug_reasoning:
        try:
            from core.diagnostics.strategy_reasoning_logger import enable_reasoning_logging

            enable_reasoning_logging("data/reasoning_logs")
            console.print("[green]✓ Strategy reasoning logging enabled[/green]")
            console.print(f"[dim]Reasoning logs will be saved to: data/reasoning_logs/[/dim]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not enable reasoning logging: {e}[/yellow]")
            if args.debug:
                import traceback

                traceback.print_exc()

    # Progress callback for user feedback
    def progress_callback(message: str):
        console.print(f"[cyan]{message}[/cyan]")

    # Run adaptive analysis
    start_time = time.time()

    try:
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[cyan]Running adaptive analysis...", total=None)

            result = await engine.find_best_strategy(domain, progress_callback)

            progress.update(task, completed=True)

        execution_time = time.time() - start_time

        # Display results
        console.print("\n" + "=" * 60)
        console.print("[bold]ADAPTIVE ANALYSIS RESULTS[/bold]")
        console.print("=" * 60)

        if result.success:
            console.print(f"[bold green][OK] SUCCESS[/bold green]")
            if result.strategy:
                console.print(f"[green]Strategy found: {result.strategy.name}[/green]")
                console.print(f"[green]Attack type: {result.strategy.attack_name}[/green]")
                console.print(f"[green]Parameters: {result.strategy.parameters}[/green]")
            console.print(f"[green]Message: {result.message}[/green]")
        else:
            console.print(f"[bold red][FAIL] FAILED[/bold red]")
            console.print(f"[red]Message: {result.message}[/red]")

        console.print(f"\n[dim]Execution time: {execution_time:.2f}s[/dim]")
        console.print(f"[dim]Trials performed: {result.trials_count}[/dim]")
        console.print(f"[dim]Fingerprint updated: {result.fingerprint_updated}[/dim]")

        # Show engine statistics
        stats = engine.get_stats()
        console.print(f"\n[bold]Engine Statistics:[/bold]")
        console.print(f"  Domains processed: {stats['domains_processed']}")
        console.print(f"  Strategies found: {stats['strategies_found']}")
        console.print(f"  Total trials: {stats['total_trials']}")
        console.print(f"  Fingerprints created: {stats['fingerprints_created']}")
        console.print(f"  Failures analyzed: {stats['failures_analyzed']}")

        # Export results if requested
        if args.export_results:
            try:
                export_data = engine.export_results()
                export_data["domain"] = domain
                export_data["result"] = {
                    "success": result.success,
                    "strategy": result.strategy.name if result.strategy else None,
                    "message": result.message,
                    "execution_time": execution_time,
                    "trials_count": result.trials_count,
                }

                with open(args.export_results, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)

                console.print(f"[green]✓ Results exported to: {args.export_results}[/green]")
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to export results: {e}[/yellow]")

        # Save strategy to legacy format for compatibility
        if result.success and result.strategy:
            try:
                legacy_strategy = {
                    "domain": domain,
                    "strategy": result.strategy.name,
                    "attack_name": result.strategy.attack_name,
                    "parameters": result.strategy.parameters,
                    "timestamp": datetime.now().isoformat(),
                    "source": "adaptive_engine",
                }

                with open(STRATEGY_FILE, "w", encoding="utf-8") as f:
                    json.dump(legacy_strategy, f, indent=2, ensure_ascii=False)

                console.print(f"[green]✓ Strategy saved to: {STRATEGY_FILE}[/green]")
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to save legacy strategy: {e}[/yellow]")

    except Exception as e:
        console.print(f"[bold red]Error during adaptive analysis: {e}[/bold red]")
        if args.debug:
            import traceback

            traceback.print_exc()


async def run_adaptive_mode_with_cleanup(args):
    """Wrapper for run_adaptive_mode with proper async cleanup."""
    try:
        await run_adaptive_mode(args)
    finally:
        await cleanup_aiohttp_sessions()


async def run_optimization_mode(args):
    """
    Run strategy optimization mode to find the best performing strategies.

    This mode tests multiple strategy variations and ranks them by performance
    metrics including retransmissions, latency, and success rate.

    Task 15.1: Implements Requirements 1.1, 1.4, 1.5, 1.6, 1.7
    """
    from core.optimization.optimizer import StrategyOptimizer
    from core.optimization.metrics_collector import PerformanceMetricsCollector
    from core.optimization.variation_generator import VariationGenerator
    from rich.table import Table
    from rich.prompt import Confirm
    import json

    # Get target domain
    target = args.target
    if not target:
        console.print("[bold red]Error: No target domain specified[/bold red]")
        console.print("[dim]Usage: python cli.py auto --optimize <domain>[/dim]")
        return

    console.print(f"\n[bold cyan]🔍 Strategy Optimization Mode[/bold cyan]")
    console.print(f"[dim]Domain: {target}[/dim]")
    console.print(f"[dim]Max trials: {args.optimize_trials}[/dim]")
    console.print(f"[dim]Min strategies: {args.optimize_min_strategies}[/dim]\n")

    try:
        # Create adaptive engine (needed for testing)
        from core.adaptive_refactored.facade import AdaptiveEngine

        adaptive_engine = AdaptiveEngine()

        # Create optimizer components
        metrics_collector = PerformanceMetricsCollector()
        variation_generator = VariationGenerator()

        # Create optimizer
        optimizer = StrategyOptimizer(
            adaptive_engine=adaptive_engine,
            metrics_collector=metrics_collector,
            variation_generator=variation_generator,
        )

        # Run optimization
        console.print("[bold]Starting optimization...[/bold]\n")

        result = await optimizer.optimize(
            domain=target,
            min_strategies=args.optimize_min_strategies,
            max_trials=args.optimize_trials,
        )

        # Display results
        console.print(f"\n[bold green]✨ Optimization Complete![/bold green]")
        console.print(f"[dim]Time: {result.optimization_time:.2f}s[/dim]")
        console.print(f"[dim]Tested: {result.total_tested} strategies[/dim]")
        console.print(f"[dim]Working: {result.total_working} strategies[/dim]\n")

        if not result.strategies:
            console.print("[yellow]⚠️  No working strategies found[/yellow]")
            console.print("\n[bold]Suggestions:[/bold]")
            console.print("  • Try increasing --optimize-trials")
            console.print("  • Check if the domain is accessible")
            console.print("  • Try different attack types manually")
            return

        # Create results table (Requirement 1.4)
        table = Table(title=f"Strategy Rankings for {target}")
        table.add_column("Rank", style="cyan", justify="right")
        table.add_column("Strategy", style="yellow")
        table.add_column("Attacks", style="magenta")
        table.add_column("Score", style="green", justify="right")
        table.add_column("Retrans", style="red", justify="right")
        table.add_column("TTFB (ms)", style="blue", justify="right")
        table.add_column("Status", style="bold")

        # Add rows for each strategy
        for ranked in result.strategies[:10]:  # Show top 10
            status = "✅ Working" if ranked.metrics.success else "❌ Failed"

            # Format attacks list
            attacks_str = ", ".join(ranked.strategy.attacks[:3])
            if len(ranked.strategy.attacks) > 3:
                attacks_str += "..."

            table.add_row(
                str(ranked.rank),
                ranked.strategy.type,
                attacks_str,
                f"{ranked.score:.2f}",
                str(ranked.metrics.retransmission_count),
                f"{ranked.metrics.ttfb_ms:.2f}",
                status,
            )

        console.print(table)

        # Show best strategy details (Requirement 1.4)
        if result.best_strategy:
            console.print(f"\n[bold green]🏆 Best Strategy:[/bold green]")
            console.print(f"   Type: {result.best_strategy.strategy.type}")
            console.print(f"   Attacks: {', '.join(result.best_strategy.strategy.attacks)}")
            console.print(f"   Score: {result.best_strategy.score:.2f}")
            console.print(
                f"   Retransmissions: {result.best_strategy.metrics.retransmission_count}"
            )
            console.print(f"   TTFB: {result.best_strategy.metrics.ttfb_ms:.2f}ms")
            console.print(f"   Total Time: {result.best_strategy.metrics.total_time_ms:.2f}ms")

            # Offer to save best strategy (Requirement 1.7)
            console.print()
            if Confirm.ask(
                f"[bold]Save best strategy as default for {target}?[/bold]", default=True
            ):
                try:
                    # Load domain rules
                    from core.domain_manager import DomainRuleRegistry

                    registry = DomainRuleRegistry()

                    # Create rule from best strategy
                    best_strat = result.best_strategy.strategy

                    # Save to domain_rules.json
                    rule_data = {
                        "attacks": best_strat.attacks,
                        "params": best_strat.params,
                        "metadata": {
                            "source": "optimization",
                            "score": result.best_strategy.score,
                            "optimized_at": time.time(),
                        },
                    }

                    # Update registry
                    registry.add_or_update_rule(target, rule_data)

                    # Also add to sites.txt if not present
                    sites_file = Path("sites.txt")
                    if sites_file.exists():
                        with open(sites_file, "r", encoding="utf-8") as f:
                            sites = [line.strip() for line in f if line.strip()]

                        if target not in sites:
                            with open(sites_file, "a", encoding="utf-8") as f:
                                f.write(f"\n{target}\n")
                            console.print(f"[green]✅ Added {target} to sites.txt[/green]")

                    console.print(f"[green]✅ Saved best strategy to domain_rules.json[/green]")

                except Exception as e:
                    console.print(f"[red]❌ Failed to save strategy: {e}[/red]")
                    if args.debug:
                        import traceback

                        traceback.print_exc()

        # Export results if requested
        if args.export_results:
            try:
                export_data = {
                    "domain": result.domain,
                    "optimization_time": result.optimization_time,
                    "total_tested": result.total_tested,
                    "total_working": result.total_working,
                    "strategies": [
                        {
                            "rank": r.rank,
                            "type": r.strategy.type,
                            "attacks": r.strategy.attacks,
                            "params": r.strategy.params,
                            "score": r.score,
                            "metrics": {
                                "success": r.metrics.success,
                                "retransmission_count": r.metrics.retransmission_count,
                                "ttfb_ms": r.metrics.ttfb_ms,
                                "total_time_ms": r.metrics.total_time_ms,
                                "packets_sent": r.metrics.packets_sent,
                                "packets_received": r.metrics.packets_received,
                            },
                        }
                        for r in result.strategies
                    ],
                }

                with open(args.export_results, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2)

                console.print(f"\n[green]✅ Results exported to {args.export_results}[/green]")

            except Exception as e:
                console.print(f"[red]❌ Failed to export results: {e}[/red]")

    except ImportError as e:
        console.print(
            f"[bold red]Error: Required optimization modules not available: {e}[/bold red]"
        )
        console.print("[yellow]Please ensure all optimization components are installed[/yellow]")
        if args.debug:
            import traceback

            traceback.print_exc()
    except Exception as e:
        console.print(f"[bold red]Error during optimization: {e}[/bold red]")
        if args.debug:
            import traceback

            traceback.print_exc()
    finally:
        await cleanup_aiohttp_sessions()


async def run_revalidate_mode(args):
    """
    Re-validate a failed strategy for a domain.

    This mode re-tests a domain that has been marked as needing revalidation
    due to repeated failures in production.
    """
    from core.bypass.engine.strategy_failure_tracker import StrategyFailureTracker

    domain = args.target
    console.print(f"\n[bold cyan]Re-validating strategy for domain: {domain}[/bold cyan]\n")

    # Load failure tracker
    tracker = StrategyFailureTracker()

    # Check if domain needs revalidation
    failure_record = tracker.get_failure_record(domain)

    if failure_record:
        console.print(f"[yellow]Current failure count: {failure_record.failure_count}[/yellow]")
        console.print(f"[yellow]Last failure: {failure_record.last_failure_time}[/yellow]")
        if failure_record.failure_reason:
            console.print(f"[yellow]Reason: {failure_record.failure_reason}[/yellow]")
        console.print()
    else:
        console.print(f"[dim]No failure record found for {domain}[/dim]")
        console.print(f"[dim]Proceeding with strategy discovery anyway...[/dim]\n")

    # Run adaptive mode to find new strategy
    console.print(f"[bold]Running adaptive strategy discovery...[/bold]\n")

    try:
        await run_adaptive_mode(args)

        # If successful, reset failure count
        tracker.reset_failure_count(domain)
        console.print(f"\n[bold green]✅ Strategy revalidation successful![/bold green]")
        console.print(f"[green]Failure count reset for {domain}[/green]")

    except Exception as e:
        console.print(f"\n[bold red]❌ Strategy revalidation failed: {e}[/bold red]")
        if args.debug:
            import traceback

            traceback.print_exc()
    finally:
        await cleanup_aiohttp_sessions()


def run_status_mode(args):
    """
    Show service status including recent strategy changes.

    Task 15.2: Implements Requirement 8.5
    """
    from rich.table import Table
    from datetime import datetime
    from pathlib import Path
    import json

    console.print(f"\n[bold cyan]📊 Service Status[/bold cyan]\n")

    # Check if recovery log exists
    recovery_log_path = Path("logs/recovery_events.log")

    if not recovery_log_path.exists():
        console.print("[yellow]No recovery events recorded yet[/yellow]")
        console.print("[dim]Recovery events will appear here when auto-recovery is triggered[/dim]")
        return

    try:
        # Read recovery events
        events = []
        with open(recovery_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError:
                        continue

        if not events:
            console.print("[yellow]No recovery events found[/yellow]")
            return

        # Show recent events (last 10)
        recent_events = events[-10:]

        console.print(f"[bold]Recent Strategy Changes ({len(recent_events)} most recent)[/bold]\n")

        # Create table
        table = Table(title="Recovery Events")
        table.add_column("Time", style="cyan")
        table.add_column("Domain", style="yellow")
        table.add_column("Reason", style="magenta")
        table.add_column("Old Strategy", style="red")
        table.add_column("New Strategy", style="green")
        table.add_column("Status", style="bold")

        for event in reversed(recent_events):  # Most recent first
            timestamp = datetime.fromtimestamp(event["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            domain = event["domain"]
            reason = event["reason"]
            success = event["success"]

            # Format strategies
            old_strat = "None"
            if event.get("old_strategy"):
                old_strat = event["old_strategy"].get("type", "Unknown")

            new_strat = "None"
            if event.get("new_strategy"):
                new_strat = event["new_strategy"].get("type", "Unknown")

            status = "✅ Success" if success else "❌ Failed"

            table.add_row(
                timestamp,
                domain,
                reason,
                old_strat,
                new_strat,
                status,
            )

        console.print(table)

        # Show summary statistics
        total_events = len(events)
        successful_events = sum(1 for e in events if e["success"])
        failed_events = total_events - successful_events

        console.print(f"\n[bold]Summary Statistics:[/bold]")
        console.print(f"  Total recovery events: {total_events}")
        console.print(
            f"  Successful: {successful_events} ({successful_events/total_events*100:.1f}%)"
        )
        console.print(f"  Failed: {failed_events} ({failed_events/total_events*100:.1f}%)")

        # Show unique domains with recovery events
        unique_domains = set(e["domain"] for e in events)
        console.print(f"  Domains with recovery: {len(unique_domains)}")

    except Exception as e:
        console.print(f"[red]Error reading recovery log: {e}[/red]")
        if args.debug:
            import traceback

            traceback.print_exc()


def run_list_failures_mode(args):
    """
    List all domains that need revalidation due to failures.
    """
    from core.bypass.engine.strategy_failure_tracker import StrategyFailureTracker
    from rich.table import Table

    console.print(f"\n[bold cyan]Strategy Failure Report[/bold cyan]\n")

    # Load failure tracker
    tracker = StrategyFailureTracker()

    # Get all failure records
    failure_records = tracker.get_all_failure_records()

    if not failure_records:
        console.print("[green]No strategy failures recorded! 🎉[/green]")
        return

    # Get domains needing revalidation
    domains_needing_revalidation = tracker.get_domains_needing_revalidation()

    # Create table
    table = Table(title="Strategy Failures")
    table.add_column("Domain", style="cyan")
    table.add_column("Strategy Type", style="yellow")
    table.add_column("Failures", style="red")
    table.add_column("Last Failure", style="dim")
    table.add_column("Status", style="bold")

    # Sort by failure count (descending)
    sorted_records = sorted(failure_records.items(), key=lambda x: x[1].failure_count, reverse=True)

    for domain, record in sorted_records:
        status = "🚨 NEEDS REVALIDATION" if record.needs_revalidation else "⚠️  Warning"

        table.add_row(
            domain,
            record.strategy_type,
            str(record.failure_count),
            (
                record.last_failure_time.split("T")[0]
                if "T" in record.last_failure_time
                else record.last_failure_time
            ),
            status,
        )

    console.print(table)
    console.print()

    # Show statistics
    stats = tracker.get_statistics()
    console.print(f"[bold]Statistics:[/bold]")
    console.print(f"  Total domains tracked: {stats['tracked_domains']}")
    console.print(f"  Total failures: {stats['total_failures']}")
    console.print(f"  Domains needing revalidation: {stats['domains_needing_revalidation']}")
    console.print(f"  Failure threshold: {stats['failure_threshold']}")
    console.print(f"  Revalidation threshold: {stats['revalidation_threshold']}")
    console.print()

    # Show recommendations
    if domains_needing_revalidation:
        console.print(f"[bold yellow]💡 Recommendations:[/bold yellow]")
        console.print(f"  Run revalidation for critical domains:")
        for domain in domains_needing_revalidation[:5]:  # Show top 5
            console.print(f"    python cli.py revalidate {domain}")

        if len(domains_needing_revalidation) > 5:
            console.print(f"    ... and {len(domains_needing_revalidation) - 5} more")
        console.print()


def run_compare_modes_command(args):
    """
    Compare strategy application between testing and production modes.

    Requirements: 7.1, 7.3, 7.4, 7.5
    """
    from core.cli.strategy_diagnostics import StrategyDiffTool
    from pathlib import Path
    import json

    console.print(f"\n[bold cyan]Comparing Testing vs Production Modes[/bold cyan]")
    console.print(f"[dim]Domain: {args.target}[/dim]\n")

    domain = args.target

    # Load domain rules
    domain_rules_path = Path("domain_rules.json")
    if not domain_rules_path.exists():
        console.print(f"[bold red]Error: domain_rules.json not found[/bold red]")
        console.print(
            f"[yellow]Run 'python cli.py auto {domain}' first to find a strategy[/yellow]"
        )
        return

    try:
        with open(domain_rules_path, "r", encoding="utf-8") as f:
            domain_rules = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error loading domain_rules.json: {e}[/bold red]")
        return

    # Check if domain has a strategy
    if domain not in domain_rules:
        console.print(f"[bold red]Error: No strategy found for {domain}[/bold red]")
        console.print(
            f"[yellow]Run 'python cli.py auto {domain}' first to find a strategy[/yellow]"
        )
        return

    expected_strategy = domain_rules[domain]

    console.print(f"[bold]Expected Strategy (from domain_rules.json):[/bold]")
    console.print(json.dumps(expected_strategy, indent=2))
    console.print()

    # Initialize diff tool
    diff_tool = StrategyDiffTool()

    # Simulate production mode strategy application
    console.print(f"[bold]Simulating Production Mode Strategy Selection:[/bold]")

    try:
        from core.bypass.engine.hierarchical_domain_matcher import HierarchicalDomainMatcher

        # Create domain strategy engine
        matcher = HierarchicalDomainMatcher(domain_rules)

        # Find matching rule
        matched_rule, match_type = matcher.find_matching_rule(domain)

        if not matched_rule:
            console.print(f"[bold red]❌ No matching rule found in production mode[/bold red]")
            return

        console.print(f"  Matched Rule: [cyan]{matched_rule}[/cyan]")
        console.print(f"  Match Type: [yellow]{match_type}[/yellow]")

        if match_type == "parent":
            console.print(f"  [bold yellow]⚠️  WARNING: Using parent domain strategy![/bold yellow]")
            console.print(
                f"  [yellow]This may cause issues if subdomain needs different strategy[/yellow]"
            )

        actual_strategy = domain_rules[matched_rule]
        console.print()

        # Compare strategies
        is_match, diffs = diff_tool.compare_strategies(domain, actual_strategy)

        if is_match:
            console.print(
                f"[bold green]✅ Strategies match! Testing and production will behave identically.[/bold green]"
            )
        else:
            console.print(f"[bold red]❌ Strategy mismatch detected![/bold red]")
            console.print()
            report = diff_tool.format_diff_report(domain, diffs)
            console.print(report)

    except ImportError as e:
        console.print(f"[bold red]Error: Required modules not available: {e}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error during comparison: {e}[/bold red]")
        if args.debug:
            import traceback

            traceback.print_exc()
