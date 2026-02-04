"""
CLI Helper Functions

Shared utility functions for CLI mode runners.
Extracted to reduce code duplication and improve maintainability.
"""

import asyncio
import functools
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

LOG = logging.getLogger("recon.cli.helpers")


def _resolve_domain_rules_path(rules_file: str) -> Path:
    """
    Resolve domain rules path consistently across CLI/service.
    Allows override via env var RECON_DOMAIN_RULES_PATH to avoid cwd mismatch.
    """
    env_path = os.environ.get("RECON_DOMAIN_RULES_PATH", "").strip()
    p = Path(env_path or rules_file).expanduser()
    try:
        return p.resolve()
    except Exception:
        # resolve() can fail on some odd paths; return best-effort
        return p


def _normalize_domain_rules_schema(raw: Any) -> Dict[str, Any]:
    """
    Support both schemas:
      1) New: { version, last_updated, domain_rules: {...}, default_strategy: {...} }
      2) Legacy: { "<domain>": {..rule..}, ... }
    Also normalizes 'parameters' -> 'params' inside strategies without breaking compat.
    """
    now = datetime.now().isoformat()
    if isinstance(raw, dict) and "domain_rules" in raw and isinstance(raw["domain_rules"], dict):
        cfg = dict(raw)
        cfg.setdefault("version", "1.0")
        cfg.setdefault("last_updated", now)
        cfg.setdefault("default_strategy", {})
    elif isinstance(raw, dict):
        cfg = {
            "version": "1.0",
            "last_updated": now,
            "domain_rules": raw,
            "default_strategy": {},
        }
    else:
        cfg = {
            "version": "1.0",
            "last_updated": now,
            "domain_rules": {},
            "default_strategy": {},
        }

    # Normalize strategies: parameters -> params (keep both if present)
    dr = cfg.get("domain_rules", {})
    if isinstance(dr, dict):
        for d, rule in list(dr.items()):
            if (
                isinstance(rule, dict)
                and "params" not in rule
                and isinstance(rule.get("parameters"), dict)
            ):
                rule["params"] = rule["parameters"]
                dr[d] = rule
        cfg["domain_rules"] = dr

    ds = cfg.get("default_strategy")
    if isinstance(ds, dict) and "params" not in ds and isinstance(ds.get("parameters"), dict):
        ds["params"] = ds["parameters"]
        cfg["default_strategy"] = ds

    return cfg


def normalize_domains(domains: List[str]) -> List[str]:
    """
    Normalize domain list to ensure all domains have proper URL scheme.

    Adds 'https://' prefix to domains that don't start with http:// or https://.
    This ensures consistent URL format for all downstream processing.

    Args:
        domains: List of domain strings (may or may not have URL scheme)

    Returns:
        List of normalized domain URLs with https:// prefix

    Example:
        >>> normalize_domains(['example.com', 'https://test.com'])
        ['https://example.com', 'https://test.com']
    """
    normalized = []
    for site in domains:
        if not site:
            continue
        site = site.strip()
        if not site:
            continue
        if not site.startswith(("http://", "https://")):
            site = f"https://{site}"
        normalized.append(site)
    return normalized


def setup_domain_manager(args, console):
    """
    Setup and initialize DomainManager with proper configuration.

    Handles the common pattern of:
    1. Determining if domains come from file or single target
    2. Creating DomainManager instance
    3. Validating domains exist
    4. Normalizing domain URLs
    5. Providing user feedback

    Args:
        args: Command-line arguments with:
            - args.domains_file: Boolean indicating if target is a file
            - args.target: Either domain string or path to domains file
        console: Rich Console instance for output

    Returns:
        DomainManager instance with normalized domains, or None if no domains found

    Example:
        dm = setup_domain_manager(args, console)
        if not dm:
            return  # Error already printed to console
        # Use dm.domains for testing
    """
    from core.domain_manager import DomainManager

    # Determine domains source
    if args.domains_file:
        domains_file = args.target
        default_domains = []
    else:
        domains_file = None
        default_domains = [args.target]

    # Create domain manager
    dm = DomainManager(domains_file, default_domains=default_domains)

    # Validate domains exist
    if not dm.domains:
        console.print(
            "[bold red]Error:[/bold red] No domains to test. Please provide a target or a valid domain file."
        )
        return None

    # Normalize all domains to full URLs with https://
    dm.domains = normalize_domains(dm.domains)

    # Provide feedback
    console.print(f"[dim]Loaded {len(dm.domains)} domain(s) for testing[/dim]")

    return dm


def setup_unified_engine(args, console):
    """
    Setup and initialize UnifiedBypassEngine with proper configuration.

    Handles the common pattern of:
    1. Creating UnifiedEngineConfig with debug flag
    2. Creating UnifiedBypassEngine instance
    3. Enabling verbose strategy logging if requested

    Args:
        args: Command-line arguments with:
            - args.debug: Boolean for debug mode
            - args.verbose_strategy: Boolean for verbose strategy logging
        console: Rich Console instance for output

    Returns:
        UnifiedBypassEngine instance configured and ready to use

    Example:
        engine = setup_unified_engine(args, console)
        # Use engine for testing strategies
    """
    from core.unified_bypass_engine import UnifiedBypassEngine, UnifiedEngineConfig

    # Create engine configuration
    config = UnifiedEngineConfig(debug=args.debug)

    # Create engine instance
    engine = UnifiedBypassEngine(config)

    # Enable verbose strategy logging if requested
    enable_verbose_strategy_logging(engine, args, console)

    return engine


def integrate_pcap_with_engine(capturer, engine, console) -> bool:
    """
    Integrate CLI PacketCapturer with bypass engine's packet sender.

    This function navigates the engine hierarchy to find the packet sender
    and connects it with the PCAP writer for packet capture.

    Args:
        capturer: PacketCapturer instance (or None)
        engine: UnifiedBypassEngine instance
        console: Rich Console instance for output

    Returns:
        True if integration successful, False otherwise

    Note:
        Returns True even if capturer is None (no integration needed)
    """
    if not capturer:
        return True

    try:
        # Navigate engine hierarchy: UnifiedBypassEngine -> AdaptiveEngine -> BypassEngine
        if hasattr(engine, "engine") and engine.engine:
            adaptive_engine = engine.engine
            if hasattr(adaptive_engine, "bypass_engine") and adaptive_engine.bypass_engine:
                bypass_engine = adaptive_engine.bypass_engine
                if hasattr(bypass_engine, "packet_sender") and bypass_engine.packet_sender:
                    bypass_engine.packet_sender.set_pcap_writer(capturer._writer)
                    console.print("[dim]✅ CLI PacketCapturer integrated with bypass engine[/dim]")
                    return True

        LOG.warning("Could not find packet sender in engine hierarchy")
        return False

    except AttributeError as e:
        console.print(f"[yellow]⚠️ PCAP integration failed (missing attribute): {e}[/yellow]")
        LOG.error(f"PCAP integration attribute error: {e}")
        return False
    except Exception as e:
        console.print(f"[yellow]⚠️ Failed to integrate CLI PacketCapturer: {e}[/yellow]")
        LOG.error(f"PCAP integration unexpected error: {e}", exc_info=True)
        return False


def setup_pcap_capture(args, console) -> Optional[Any]:
    """
    Setup PCAP packet capture if requested via command-line arguments.

    Creates and starts a PacketCapturer instance with appropriate BPF filter
    and capture parameters. Handles errors gracefully and provides user feedback.

    Args:
        args: Command-line arguments with pcap capture settings:
            - args.pcap: Output PCAP file path (if None, capture is skipped)
            - args.capture_bpf: Custom BPF filter (optional)
            - args.port: Port number for default BPF filter
            - args.capture_iface: Network interface to capture on
            - args.capture_max_seconds: Maximum capture duration (0 = unlimited)
            - args.capture_max_packets: Maximum packets to capture (0 = unlimited)
        console: Rich Console instance for output

    Returns:
        PacketCapturer instance if capture started successfully, None otherwise

    Note:
        This function addresses SR3 (broad exception handler) by providing
        specific error logging while still handling all exceptions gracefully.
    """
    if not args.pcap:
        return None

    try:
        # Ensure parent directory exists for output PCAP
        try:
            Path(args.pcap).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        # Import PacketCapturer dynamically to avoid import errors if not available
        try:
            from core.utils.packet_capture import PacketCapturer
        except ImportError:
            console.print(
                "[yellow][!] PacketCapturer not available. Install required dependencies.[/yellow]"
            )
            LOG.warning("PacketCapturer import failed - packet capture unavailable")
            return None

        # Determine BPF filter
        if args.capture_bpf:
            bpf = args.capture_bpf
        else:
            # Use simple port-based filter instead of IP-based
            bpf = f"tcp port {args.port}"

        # Parse capture limits
        max_sec = args.capture_max_seconds if args.capture_max_seconds > 0 else None
        max_pkts = args.capture_max_packets if args.capture_max_packets > 0 else None

        # Create and start capturer
        capturer = PacketCapturer(
            args.pcap,
            bpf=bpf,
            iface=args.capture_iface,
            max_packets=max_pkts,
            max_seconds=max_sec,
        )
        capturer.start()

        console.print(f"[dim][CAPTURE] Packet capture started -> {args.pcap} (bpf='{bpf}')[/dim]")
        LOG.info(f"PCAP capture started: {args.pcap} with filter '{bpf}'")

        return capturer

    except ImportError as e:
        console.print(f"[yellow][!] Could not import capture module: {e}[/yellow]")
        LOG.error(f"PCAP capture import error: {e}")
        return None
    except PermissionError as e:
        console.print(f"[yellow][!] Permission denied for packet capture: {e}[/yellow]")
        console.print("[dim]Hint: Try running with administrator/root privileges[/dim]")
        LOG.error(f"PCAP capture permission error: {e}")
        return None
    except OSError as e:
        console.print(f"[yellow][!] Network interface error: {e}[/yellow]")
        LOG.error(f"PCAP capture OS error: {e}")
        return None
    except Exception as e:
        console.print(f"[yellow][!] Could not start capture: {e}[/yellow]")
        LOG.error(f"PCAP capture unexpected error: {e}", exc_info=True)
        return None


def enable_verbose_strategy_logging(hybrid_engine, args, console) -> None:
    """
    Enable verbose strategy logging if requested via --verbose-strategy flag.

    This function checks if the hybrid engine has a domain strategy engine
    and enables verbose logging mode with timestamped log file.

    Args:
        hybrid_engine: UnifiedBypassEngine instance
        args: Command-line arguments with verbose_strategy attribute
        console: Rich Console instance for output

    Task 13, Requirements 7.1, 7.3, 7.4, 7.5
    """
    if not args.verbose_strategy:
        return

    try:
        if hasattr(hybrid_engine, "engine") and hasattr(
            hybrid_engine.engine, "_domain_strategy_engine"
        ):
            domain_engine = hybrid_engine.engine._domain_strategy_engine
            if domain_engine and hasattr(domain_engine, "set_verbose_mode"):
                log_file = f"verbose_strategy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                domain_engine.set_verbose_mode(True, log_file)
                console.print(f"[green]✅ Verbose strategy logging enabled[/green]")
                console.print(f"[dim]Logs will be written to: {log_file}[/dim]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not enable verbose strategy logging: {e}[/yellow]")


async def setup_reporters(args, console):
    """
    Setup and initialize reporters (simple and advanced) with proper fallbacks.

    Handles the common pattern of:
    1. Creating SimpleReporter instance
    2. Attempting to create AdvancedReportingIntegration (if available)
    3. Providing fallback DummyAdvancedReporter if not available
    4. Initializing advanced reporter

    Args:
        args: Command-line arguments with:
            - args.debug: Boolean for debug mode
        console: Rich Console instance for output

    Returns:
        Tuple of (SimpleReporter, AdvancedReporter or DummyAdvancedReporter)

    Example:
        reporter, advanced_reporter = await setup_reporters(args, console)
        # Use reporters for result reporting
    """
    from core.reporting.simple_reporter import SimpleReporter

    # Create simple reporter
    reporter = SimpleReporter(debug=args.debug)

    class DummyAdvancedReporter:
        async def initialize(self):
            return None

        async def generate_system_performance_report(self, *args, **kwargs):
            return None

    # Try to create advanced reporter with fallback
    advanced_reporter = None
    try:
        from core.reporting.advanced_integration import AdvancedReportingIntegration

        advanced_reporter = AdvancedReportingIntegration()
        await advanced_reporter.initialize()
        LOG.debug("Advanced reporter initialized successfully")
    except ImportError:
        LOG.debug("AdvancedReportingIntegration not available, using dummy reporter")
        advanced_reporter = DummyAdvancedReporter()
    except Exception as e:
        LOG.warning(f"Failed to initialize advanced reporter: {e}")
        advanced_reporter = DummyAdvancedReporter()

    return reporter, advanced_reporter


def load_domain_rules(console, rules_file: str = "domain_rules.json") -> Optional[dict]:
    """
    Load domain rules configuration from JSON file.

    Handles the common pattern of:
    1. Checking if domain rules file exists
    2. Loading JSON configuration
    3. Providing user feedback
    4. Error handling with helpful messages

    Args:
        console: Rich Console instance for output
        rules_file: Path to domain rules JSON file (default: "domain_rules.json")

    Returns:
        Dictionary with domain rules, or None if loading failed

    Example:
        domain_rules = load_domain_rules(console)
        if not domain_rules:
            return  # Error already printed to console
        # Use domain_rules for strategy mapping
    """
    import json

    console.print(f"\n[yellow]Loading domain rules configuration...[/yellow]")

    rules_path = _resolve_domain_rules_path(rules_file)
    if not rules_path.exists():
        console.print(
            f"[bold red]Fatal Error:[/bold red] Domain rules file not found: '{rules_path}'"
        )
        console.print("Please create domain_rules.json with domain-to-strategy mappings.")
        LOG.error("Domain rules file not found: %s (cwd=%s)", rules_path, os.getcwd())
        return None

    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        normalized = _normalize_domain_rules_schema(raw)
        console.print(f"[dim]Domain rules loaded from {rules_path}[/dim]")
        LOG.info(
            "Successfully loaded domain rules from %s (cwd=%s, rules=%d)",
            rules_path,
            os.getcwd(),
            len(
                normalized.get("domain_rules", {})
                if isinstance(normalized.get("domain_rules"), dict)
                else {}
            ),
        )
        return normalized
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Fatal Error:[/bold red] Invalid JSON in domain rules file: {e}")
        LOG.error("JSON decode error in %s: %s", rules_path, e)
        return None
    except Exception as e:
        console.print(f"[bold red]Fatal Error:[/bold red] Could not load domain rules: {e}")
        LOG.error("Failed to load domain rules from %s: %s", rules_path, e, exc_info=True)
        return None


async def run_baseline_testing(engine, domains, console, capturer=None):
    """
    Run baseline connectivity testing to identify blocked sites.

    Handles the common pattern of:
    1. Testing baseline connectivity for all domains
    2. Identifying blocked sites that need bypass
    3. Providing early exit if all sites are working
    4. Displaying results to user
    5. Checking PyDivert availability

    Args:
        engine: UnifiedBypassEngine instance
        domains: List of domain URLs to test
        console: Rich Console instance for output
        capturer: Optional PacketCapturer instance to stop on early exit

    Returns:
        Tuple of (baseline_results dict, blocked_sites list)
        Returns (None, None) if all sites are working (early exit case)

    Example:
        baseline_results, blocked_sites = await run_baseline_testing(
            engine, dm.domains, console, capturer
        )
        if not blocked_sites:
            return  # All sites working, early exit already handled
        # Continue with fingerprinting and strategy testing
    """
    console.print("\n[yellow]Step 2: Testing baseline connectivity...[/yellow]")

    # Test baseline connectivity
    baseline_results = await engine.test_baseline_connectivity(
        domains, {}  # Empty DNS cache - engine will resolve domains as needed
    )

    # Identify blocked sites
    blocked_sites = [
        site for site, (status, _, _, _) in baseline_results.items() if status not in ["WORKING"]
    ]

    # Early exit if all sites are working
    if not blocked_sites:
        console.print(
            "[bold green][OK] All sites are accessible without bypass tools![/bold green]"
        )
        console.print("No DPI blocking detected. Bypass tools are not needed.")
        if capturer:
            capturer.stop()
        LOG.info("All sites accessible without bypass - no DPI blocking detected")
        return None, None

    # Display blocked sites
    console.print(f"Found {len(blocked_sites)} blocked sites that need bypass:")
    for site in blocked_sites[:5]:
        console.print(f"  - {site}")
    if len(blocked_sites) > 5:
        console.print(f"  ... and {len(blocked_sites) - 5} more")

    console.print(
        "\n[bold yellow]The following sites will be used for fingerprinting and strategy testing:[/bold yellow]"
    )
    for site in blocked_sites:
        console.print(f"  -> {site}")

    # Check PyDivert availability
    try:
        import pydivert

        console.print("[dim][OK] PyDivert available - system-level bypass enabled[/dim]")
        LOG.debug("PyDivert is available for system-level bypass")
    except ImportError:
        console.print("[yellow][!]  PyDivert not available - using fallback mode[/yellow]")
        console.print("[dim]   For better results, install: pip install pydivert[/dim]")
        LOG.warning("PyDivert not available - using fallback mode")

    LOG.info(f"Baseline testing complete: {len(blocked_sites)} blocked sites identified")
    return baseline_results, blocked_sites


async def run_dpi_fingerprinting(args, blocked_sites, simple_fingerprinter, console):
    """
    Run DPI fingerprinting on blocked sites to identify DPI characteristics.

    Handles the common pattern of:
    1. Checking if fingerprinting is enabled
    2. Attempting to use UnifiedFingerprinter (if available)
    3. Falling back to SimpleFingerprinter
    4. Displaying fingerprint results to user
    5. Returning fingerprints dictionary and refiner reference

    Args:
        args: Command-line arguments with:
            - args.fingerprint: Boolean to enable fingerprinting
            - args.connect_timeout: Connection timeout
            - args.tls_timeout: TLS timeout
            - args.analysis_level: Analysis level for fingerprinting
            - args.port: Port number for fingerprinting
            - args.parallel: Max concurrent fingerprinting operations
        blocked_sites: List of blocked site URLs to fingerprint
        simple_fingerprinter: SimpleFingerprinter instance (fallback)
        console: Rich Console instance for output

    Returns:
        Tuple of (fingerprints dict, refiner reference or None)
        fingerprints: Dict mapping hostname to fingerprint object
        refiner: UnifiedFingerprinter instance for refinement (or None)

    Example:
        fingerprints, refiner = await run_dpi_fingerprinting(
            args, blocked_sites, simple_fingerprinter, console
        )
        # Use fingerprints for strategy selection
        # Use refiner for fingerprint refinement (if available)
    """
    from urllib.parse import urlparse

    fingerprints = {}
    refiner = None

    if not args.fingerprint:
        console.print("[dim]Skipping fingerprinting (use --fingerprint to enable)[/dim]")
        return fingerprints, refiner

    console.print("\n[yellow]Step 2.5: DPI Fingerprinting...[/yellow]")

    # Try to use UnifiedFingerprinter (advanced)
    try:
        from core.fingerprint.unified_fingerprinter import (
            UnifiedFingerprinter,
            UnifiedFPConfig,
        )

        cfg = UnifiedFPConfig(
            timeout=args.connect_timeout + args.tls_timeout,
            enable_cache=False,
            analysis_level=args.analysis_level,
            connect_timeout=5.0,
            tls_timeout=10.0,
        )

        async with UnifiedFingerprinter(config=cfg) as unified_fingerprinter:
            refiner = unified_fingerprinter

            targets_to_probe = [
                (urlparse(site).hostname or site, args.port) for site in blocked_sites
            ]

            console.print(
                f"[dim][*] Using UnifiedFingerprinter with concurrency: {args.parallel}[/dim]"
            )

            fingerprint_results = await unified_fingerprinter.fingerprint_batch(
                targets=targets_to_probe,
                force_refresh=True,
                max_concurrent=args.parallel,
            )

        for fp in fingerprint_results:
            if fp:
                fingerprints[fp.target] = fp
                console.print(
                    f"  - {fp.target}: [cyan]{fp.dpi_type.value}[/cyan] "
                    f"(reliability: {fp.reliability_score:.2f})"
                )

        LOG.info(f"UnifiedFingerprinter completed: {len(fingerprints)} fingerprints collected")

    except ImportError:
        # UnifiedFingerprinter not available, use SimpleFingerprinter
        console.print(
            "[yellow]UnifiedFingerprinter not available, using fallback simple fingerprinting[/yellow]"
        )
        LOG.warning("UnifiedFingerprinter not available, falling back to SimpleFingerprinter")

        try:
            from rich.progress import Progress
        except ImportError:
            Progress = None

        if Progress:
            with Progress(console=console, transient=True) as progress:
                task = progress.add_task(
                    "[cyan]Fingerprinting (simple)...", total=len(blocked_sites)
                )
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
        else:
            # No Progress available, simple loop
            for site in blocked_sites:
                hostname = urlparse(site).hostname or site
                fp = await simple_fingerprinter.create_fingerprint(hostname, None, args.port)
                if fp:
                    fingerprints[hostname] = fp
                    console.print(
                        f"  - {hostname}: [cyan]{fp.dpi_type}[/cyan] ({fp.blocking_method})"
                    )

        LOG.info(f"SimpleFingerprinter completed: {len(fingerprints)} fingerprints collected")

    except Exception as e:
        console.print(f"[yellow]Warning: Fingerprinting failed: {e}[/yellow]")
        LOG.error(f"Fingerprinting error: {e}", exc_info=True)

    return fingerprints, refiner


async def prepare_bypass_strategies(args, dm, fingerprints, learning_cache, hybrid_engine, console):
    """
    Prepare bypass strategies from various sources with validation and optimization.

    Handles the complex pattern of:
    1. Loading strategies from domain_rules.json (if no explicit strategy specified)
    2. Loading strategies from file (if --strategies-file specified)
    3. Loading single strategy (if --strategy specified)
    4. Generating strategies (if --no-generate not specified)
    5. Validating strategies (if --validate specified)
    6. Optimizing strategy order using adaptive learning cache

    Args:
        args: Command-line arguments with:
            - args.strategy: Single strategy string (optional)
            - args.strategies_file: Path to strategies file (optional)
            - args.no_generate: Disable strategy generation
            - args.count: Number of strategies to generate
            - args.validate: Enable strategy validation
            - args.debug: Debug mode
        dm: DomainManager instance with domains list
        fingerprints: Dict mapping hostname to fingerprint objects
        learning_cache: AdaptiveLearningCache instance
        hybrid_engine: UnifiedBypassEngine instance
        console: Rich Console instance for output

    Returns:
        List of strategy strings ready for testing
        Returns None if no valid strategies could be prepared

    Example:
        strategies = await prepare_bypass_strategies(
            args, dm, fingerprints, learning_cache, hybrid_engine, console
        )
        if not strategies:
            return  # Error already printed
        # Use strategies for testing
    """
    from collections import defaultdict
    from urllib.parse import urlparse
    import os

    console.print("\n[yellow]Step 3: Preparing bypass strategies...[/yellow]")

    strategies = []

    # Task 9: Check domain_rules.json for existing strategies first
    domain_strategies_loaded = False
    if not args.strategy and not args.strategies_file:
        try:
            from core.strategy_loader import load_strategy_for_domain
            from core.attack_recipe_builder import build_attack_recipe
            from core.strategy_converter import convert_strategy_to_zapret_command

            console.print("[cyan]Checking domain_rules.json for existing strategies...[/cyan]")
            for domain_url in dm.domains:
                # Extract domain from URL
                parsed = urlparse(domain_url)
                domain = parsed.netloc or parsed.path

                # Load strategy for this domain
                strategy_dict = load_strategy_for_domain(
                    domain,
                    force=getattr(args, "force", False),
                    no_fallbacks=getattr(args, "no_fallbacks", False),
                )

                if strategy_dict:
                    # Build attack recipe to validate compatibility
                    recipe = build_attack_recipe(strategy_dict)
                    if recipe is None:
                        console.print(
                            f"  ✗ Failed to build recipe for {domain} (incompatible attacks)"
                        )
                        continue

                    # Log recipe details
                    console.print(f"  ✓ Loaded strategy for {domain}")
                    console.print(f"    Recipe: {' → '.join(s.attack_type for s in recipe.steps)}")

                    # Convert to zapret command format
                    zapret_cmd = convert_strategy_to_zapret_command(strategy_dict)
                    if zapret_cmd and zapret_cmd not in strategies:
                        strategies.append(zapret_cmd)
                        domain_strategies_loaded = True

            if domain_strategies_loaded:
                console.print(
                    f"[green]Loaded {len(strategies)} strategies from domain_rules.json[/green]"
                )
        except ImportError as e:
            LOG.debug(f"Could not load domain strategies: {e}")
        except Exception as e:
            LOG.warning(f"Error loading domain strategies: {e}")

    # 1. Priority: strategies file
    if args.strategies_file and os.path.exists(args.strategies_file):
        console.print(f"[cyan]Loading strategies from file: {args.strategies_file}[/cyan]")
        try:
            with open(args.strategies_file, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        strategies.append(s)
            strategies = list(dict.fromkeys(strategies))  # Remove duplicates, preserve order
            if not strategies:
                console.print("[yellow]Warning: strategies file is empty after filtering.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error reading strategies file: {e}[/red]")
            LOG.error(f"Failed to read strategies file {args.strategies_file}: {e}")

    # 2. If file exists and --no-generate flag is set, stop here
    if strategies and args.no_generate:
        console.print(f"Using {len(strategies)} strategies from file (auto-generation disabled).")
    # 3. Else, if single strategy specified via --strategy
    elif args.strategy:
        strategies = [args.strategy]
        console.print(f"Testing specific strategy: [cyan]{args.strategy}[/cyan]")
    # 4. Else (or if file is empty and --no-generate not specified), generate
    else:
        if not args.no_generate:
            from ml.zapret_strategy_generator import ZapretStrategyGenerator

            generator = ZapretStrategyGenerator()
            fingerprint_for_strategy = (
                next(iter(fingerprints.values()), None) if fingerprints else None
            )
            try:
                more_strategies = generator.generate_strategies(
                    fingerprint_for_strategy, count=args.count
                )
                # Add only unique strategies
                for s in more_strategies:
                    if s not in strategies:
                        strategies.append(s)
                console.print(
                    f"Generated {len(more_strategies)} strategies (total unique: {len(strategies)})."
                )
            except Exception as e:
                console.print(f"[red]✗ Error generating strategies: {e}[/red]")
                LOG.error(f"Strategy generation failed: {e}", exc_info=True)
                if not strategies:  # If nothing at all, add fallback
                    strategies.extend(
                        [
                            "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
                            "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badseq",
                        ]
                    )

        # Validate strategies if --validate flag is enabled
        if args.validate and strategies:
            strategies = await _validate_strategies(strategies, hybrid_engine, console, args.debug)

        # Optimize strategy order using adaptive learning cache
        if strategies and dm.domains:
            strategies = _optimize_strategy_order(
                strategies, dm, fingerprints, learning_cache, console
            )

    if not strategies:
        console.print("[bold red]Fatal Error: No valid strategies could be prepared.[/bold red]")
        LOG.error("No valid strategies could be prepared")
        return None

    LOG.info(f"Prepared {len(strategies)} strategies for testing")
    return strategies


async def _validate_strategies(strategies, hybrid_engine, console, debug=False):
    """Helper function to validate strategies."""
    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator

        console.print("\n[bold][VALIDATION] Validating generated strategies...[/bold]")
        orchestrator = CLIValidationOrchestrator()

        valid_strategies = []
        validation_errors = []
        validation_warnings = []

        for strategy_str in strategies:
            try:
                # Parse strategy to dict format for validation
                parsed = hybrid_engine.strategy_loader.load_strategy(
                    strategy_str
                ).to_engine_format()

                if parsed:
                    # Validate the parsed strategy
                    validation_result = orchestrator.validate_strategy(
                        parsed, check_attack_availability=True
                    )

                    if validation_result.passed:
                        valid_strategies.append(strategy_str)
                    else:
                        validation_errors.extend(validation_result.errors)
                        console.print(
                            f"[yellow]⚠ Strategy validation failed: {parsed.get('type', 'unknown')}[/yellow]"
                        )
                        for err in validation_result.errors:
                            console.print(f"  [red]- {err}[/red]")

                    validation_warnings.extend(validation_result.warnings)
            except Exception as e:
                console.print(
                    f"[yellow]Warning: Could not validate strategy '{strategy_str}': {e}[/yellow]"
                )
                # Keep the strategy if validation fails
                valid_strategies.append(strategy_str)

        # Display validation summary
        console.print("\n[bold]Strategy Validation Summary:[/bold]")
        console.print(f"  Total strategies: {len(strategies)}")
        console.print(f"  Valid strategies: [green]{len(valid_strategies)}[/green]")
        console.print(f"  Validation errors: [red]{len(validation_errors)}[/red]")
        console.print(f"  Validation warnings: [yellow]{len(validation_warnings)}[/yellow]")

        # Use only valid strategies
        if valid_strategies:
            console.print(
                f"[green]✓ Proceeding with {len(valid_strategies)} validated strategies[/green]"
            )
            return valid_strategies
        else:
            console.print(
                "[yellow]⚠ No valid strategies found, proceeding with all strategies anyway[/yellow]"
            )
            return strategies

    except ImportError as e:
        console.print(
            f"[yellow][!] Strategy validation skipped: Required modules not available ({e})[/yellow]"
        )
        return strategies
    except Exception as e:
        console.print(f"[yellow][!] Strategy validation failed: {e}[/yellow]")
        if debug:
            import traceback

            traceback.print_exc()
        return strategies


async def process_test_results(
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
):
    """
    Process test results: refine fingerprints, update learning cache, validate PCAP.

    Handles the post-testing processing pattern:
    1. Refine DPI fingerprints based on test results (if fingerprinting enabled)
    2. Update adaptive learning cache with strategy performance
    3. Build per-domain strategy mapping
    4. Stop packet capture
    5. Validate PCAP file (if validation enabled)

    Args:
        args: Command-line arguments with:
            - args.fingerprint: Boolean for fingerprinting
            - args.validate: Boolean for validation
            - args.pcap: PCAP file path
            - args.debug: Debug mode
        test_results: List of test result dictionaries
        fingerprints: Dict mapping hostname to fingerprint objects
        refiner: UnifiedFingerprinter instance for refinement (or None)
        simple_fingerprinter: SimpleFingerprinter instance
        blocked_sites: List of blocked site URLs
        learning_cache: AdaptiveLearningCache instance
        domain_strategy_map: Dict to populate with per-domain results
        capturer: PacketCapturer instance (or None)
        console: Rich Console instance for output

    Returns:
        Optional PCAP validation result (or None if validation not performed)

    Example:
        pcap_validation = await process_test_results(
            args, test_results, fingerprints, refiner, simple_fingerprinter,
            blocked_sites, learning_cache, domain_strategy_map, capturer, console
        )
    """
    from urllib.parse import urlparse
    import os
    from datetime import datetime

    # Step 5: Refine fingerprints based on test results
    if args.fingerprint and fingerprints:
        console.print("\n[yellow]Step 5: Refining DPI fingerprint with test results...[/yellow]")
        feedback_data = {
            "successful_strategies": [
                r["strategy"] for r in test_results if r["success_rate"] > 0.5
            ],
            "failed_strategies": [r["strategy"] for r in test_results if r["success_rate"] <= 0.5],
        }

        for domain, fp in fingerprints.items():
            try:
                # Try to import fingerprint types for isinstance check
                try:
                    from core.fingerprint.unified_fingerprinter import UnifiedFingerprint
                    from core.fingerprint.dpi_fingerprint import DPIFingerprint
                    from core.fingerprint.simple_fingerprinter import SimpleFingerprint
                except ImportError:
                    # If imports fail, use duck typing
                    UnifiedFingerprint = type(None)
                    DPIFingerprint = type(None)
                    SimpleFingerprint = type(None)

                if (
                    refiner
                    and hasattr(refiner, "refine_fingerprint")
                    and isinstance(fp, (UnifiedFingerprint, DPIFingerprint))
                ):
                    refined_fp = await refiner.refine_fingerprint(fp, feedback_data)
                elif isinstance(fp, SimpleFingerprint) or hasattr(fp, "refine"):
                    refined_fp = await simple_fingerprinter.refine_fingerprint(fp, feedback_data)
                else:
                    refined_fp = fp  # Skip refinement if no suitable refiner is found

                fingerprints[domain] = refined_fp
                new_type = getattr(refined_fp, "dpi_type", None)
                new_type_str = getattr(new_type, "value", str(new_type))
                console.print(f"  - Fingerprint for {domain} refined. New type: {new_type_str}")
            except Exception as e:
                console.print(f"[yellow]  - Fingerprint refine failed for {domain}: {e}[/yellow]")
                LOG.warning(f"Fingerprint refinement failed for {domain}: {e}")

    # Step 4.5: Update adaptive learning cache
    console.print("[dim][SAVE] Updating adaptive learning cache...[/dim]")
    for result in test_results:
        strategy = result["strategy"]
        success_rate = result["success_rate"]
        avg_latency = result["avg_latency_ms"]

        # Process detailed site_results to build per-domain map
        if "site_results" in result:
            for site_url, site_result_tuple in result["site_results"].items():
                # site_result_tuple is (status, ip, latency, http_code)
                status, _, latency, _ = site_result_tuple
                if status == "WORKING":
                    hostname = urlparse(site_url).hostname or site_url
                    domain_strategy_map[hostname].append(
                        {"strategy": strategy, "latency_ms": latency}
                    )

        # Record strategy performance for each domain without IP dependency
        for site in blocked_sites:
            domain = urlparse(site).hostname or site.replace("https://", "").replace("http://", "")
            dpi_hash = ""
            if (
                fingerprints
                and domain in fingerprints
                and hasattr(fingerprints[domain], "short_hash")
            ):
                try:
                    dpi_hash = fingerprints[domain].short_hash()
                except Exception:
                    dpi_hash = ""
            learning_cache.record_strategy_performance(
                strategy=strategy,
                domain=domain,
                ip=None,  # No IP dependency in domain-based approach
                success_rate=success_rate,
                avg_latency=avg_latency,
                dpi_fingerprint_hash=dpi_hash,
            )

    learning_cache.save_cache()
    LOG.info("Adaptive learning cache updated and saved")

    # Stop packet capture
    if capturer:
        try:
            capturer.stop()
            LOG.debug("Packet capture stopped")
        except Exception as e:
            LOG.warning(f"Failed to stop packet capture: {e}")

    # PCAP validation if --validate flag is enabled
    pcap_validation_result = None
    if args.validate and args.pcap and os.path.exists(args.pcap):
        pcap_validation_result = await _validate_pcap(args, console)

    return pcap_validation_result


async def _validate_pcap(args, console):
    """Helper function to validate PCAP file."""
    import os
    from datetime import datetime
    from pathlib import Path

    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator

        console.print("\n[bold][VALIDATION] Validating captured PCAP file...[/bold]")

        orchestrator = CLIValidationOrchestrator()
        pcap_path = Path(args.pcap)

        # Validate PCAP with basic attack spec
        attack_spec = {
            "validate_sequence": True,
            "validate_flag_combinations": True,
        }

        pcap_validation_result = orchestrator.validate_pcap(pcap_path, attack_spec)

        # Display validation summary
        if pcap_validation_result.passed:
            console.print("[green]✓ PCAP validation PASSED[/green]")
            console.print(f"  Packets: {pcap_validation_result.packet_count}")
            console.print(f"  Issues: {len(pcap_validation_result.issues)}")
            console.print(f"  Warnings: {len(pcap_validation_result.warnings)}")
        else:
            console.print("[yellow]⚠ PCAP validation FAILED[/yellow]")
            console.print(f"  Packets: {pcap_validation_result.packet_count}")
            console.print(
                f"  Errors: {len([i for i in pcap_validation_result.issues if i.severity == 'error'])}"
            )
            console.print(
                f"  Warnings: {len([i for i in pcap_validation_result.issues if i.severity == 'warning'])}"
            )

            # Show first few errors
            errors = [i for i in pcap_validation_result.issues if i.severity == "error"]
            if errors:
                console.print("\n  Top errors:")
                for err in errors[:3]:
                    console.print(f"    - {err.description}")

        # Save detailed validation report
        report_file = (
            orchestrator.output_dir
            / f"pcap_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        report = orchestrator.create_validation_report(pcap_validation=pcap_validation_result)
        report.save_to_file(report_file)
        console.print(f"  [dim]Detailed report: {report_file}[/dim]")

        LOG.info(f"PCAP validation completed: {pcap_validation_result.passed}")
        return pcap_validation_result

    except ImportError as e:
        console.print(
            f"[yellow][!] PCAP validation skipped: Required modules not available ({e})[/yellow]"
        )
        LOG.warning(f"PCAP validation skipped: {e}")
        return None
    except Exception as e:
        console.print(f"[yellow][!] PCAP validation failed: {e}[/yellow]")
        LOG.error(f"PCAP validation failed: {e}", exc_info=True)
        if args.debug:
            import traceback

            traceback.print_exc()
        return None


def _optimize_strategy_order(strategies, dm, fingerprints, learning_cache, console):
    """Helper function to optimize strategy order using adaptive learning."""
    from urllib.parse import urlparse

    # Use first domain from domain manager
    first_domain = urlparse(dm.domains[0]).hostname or dm.domains[0].replace(
        "https://", ""
    ).replace("http://", "")

    dpi_hash = ""
    if (
        fingerprints
        and first_domain in fingerprints
        and hasattr(fingerprints[first_domain], "short_hash")
    ):
        try:
            dpi_hash = fingerprints[first_domain].short_hash()
        except Exception:
            dpi_hash = ""

    # Use domain-based optimization without IP address
    optimized_strategies = learning_cache.get_smart_strategy_order(
        strategies, first_domain, None, dpi_hash
    )

    if optimized_strategies != strategies:
        console.print("[dim][AI] Applied adaptive learning to optimize strategy order[/dim]")
        LOG.debug("Strategy order optimized using adaptive learning")
        return optimized_strategies

    return strategies


def with_async_cleanup(mode_func: Callable) -> Callable:
    """
    Decorator that adds automatic async cleanup to mode runner functions.

    This decorator wraps async mode functions to ensure cleanup_aiohttp_sessions
    is always called after the mode completes, even if an exception occurs.

    Addresses FD1 cluster by consolidating 6 wrapper functions into single pattern.

    Args:
        mode_func: Async function to wrap (mode runner function)

    Returns:
        Wrapped async function with cleanup in finally block

    Example:
        @with_async_cleanup
        async def run_my_mode(args):
            # Mode implementation
            pass

        # Equivalent to:
        async def run_my_mode_with_cleanup(args):
            try:
                await run_my_mode(args)
            finally:
                await cleanup_aiohttp_sessions()
    """

    @functools.wraps(mode_func)
    async def wrapper(args):
        try:
            await mode_func(args)
        finally:
            # Import cleanup function from mode_runners to avoid circular import
            from core.cli.mode_runners import cleanup_aiohttp_sessions

            await cleanup_aiohttp_sessions()

    return wrapper


async def display_and_save_strategy_results(
    test_results,
    domain_strategy_map,
    args,
    dm,
    hybrid_engine,
    console,
):
    """
    Display strategy testing results and save optimal strategies.

    Handles the strategy results display pattern:
    1. Display strategy testing results summary
    2. Handle failure case (no working strategies) with auto-PCAP capture
    3. Display success case with top working strategies
    4. Display per-domain optimal strategy table
    5. Save strategies to files (domain_strategies.json and best_strategy.json)

    Args:
        test_results: List of test result dictionaries
        domain_strategy_map: Dict mapping domain to list of strategy results
        args: Command-line arguments with:
            - args.pcap: PCAP file path (for auto-capture check)
            - args.port: Port number
            - args.capture_iface: Capture interface
        dm: DomainManager instance
        hybrid_engine: UnifiedBypassEngine instance
        console: Rich Console instance for output

    Returns:
        Tuple of (working_strategies, best_strategy_result or None)

    Example:
        working_strategies, best_strategy = await display_and_save_strategy_results(
            test_results, domain_strategy_map, args, dm, hybrid_engine, console
        )
    """
    from datetime import datetime
    import json
    import os

    # Check for required imports
    try:
        from core.strategy_manager import StrategyManager
    except ImportError:
        StrategyManager = None
        LOG.warning("StrategyManager not available")

    # Check for optional imports
    SCAPY_AVAILABLE = False
    PROFILER_AVAILABLE = False
    try:
        from core.pcap.packet_capturer import PacketCapturer
        from core.pcap.bpf_builder import build_bpf_from_ips

        SCAPY_AVAILABLE = True
    except ImportError:
        pass

    try:
        from core.profiling.advanced_traffic_profiler import AdvancedTrafficProfiler

        PROFILER_AVAILABLE = True
    except ImportError:
        pass

    # Constants
    STRATEGY_FILE = "best_strategy.json"

    # Display strategy testing results
    console.print("\n[bold underline]Strategy Testing Results[/bold underline]")
    working_strategies = [r for r in test_results if r["success_rate"] > 0]

    if not working_strategies:
        # No working strategies found
        console.print("\n[bold red][X] No working strategies found![/bold red]")
        console.print("   All tested strategies failed to bypass the DPI.")
        console.print(
            "   Try increasing the number of strategies with `--count` or check if zapret tools are properly installed."
        )

        # Auto-PCAP capture on failure (if not manually enabled)
        try:
            if SCAPY_AVAILABLE and not args.pcap:
                console.print(
                    "[dim][CAPTURE] Auto-capture: starting short PCAP (8s) for failure profiling...[/dim]"
                )
                auto_pcap = f"recon_autofail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                bpf = build_bpf_from_ips(
                    set(), args.port
                )  # Use port-based filter instead of IP-based
                cap = PacketCapturer(auto_pcap, bpf=bpf, iface=args.capture_iface, max_seconds=8)
                cap.start()

                # Run another baseline to generate ClientHello during capture
                try:
                    await hybrid_engine.test_baseline_connectivity(
                        dm.domains, {}  # Empty DNS cache - engine will resolve domains as needed
                    )
                except Exception:
                    pass

                cap.stop()
                console.print(f"[green][OK] Auto-capture saved to {auto_pcap}[/green]")

                # Profile the auto-captured PCAP
                if PROFILER_AVAILABLE:
                    try:
                        profiler = AdvancedTrafficProfiler()
                        res = profiler.analyze_pcap_file(auto_pcap)
                        if res and res.success:
                            console.print("[bold][TEST] Auto PCAP profiling summary[/bold]")
                            apps = ", ".join(res.detected_applications) or "none"
                            ctx = res.metadata.get("context", {})
                            console.print(f"  Apps: [cyan]{apps}[/cyan]")
                            console.print(
                                f"  TLS ClientHello: {ctx.get('tls_client_hello',0)}, Alerts: {ctx.get('tls_alert_count',0)}, QUIC: {ctx.get('quic_initial_count',0)}"
                            )
                    except Exception as e:
                        console.print(f"[yellow][!] Auto profiling failed: {e}[/yellow]")
                        LOG.warning(f"Auto profiling failed: {e}")
        except Exception as e:
            LOG.warning(f"Auto-capture failed: {e}")

        return working_strategies, None

    # Working strategies found - display success
    console.print(
        f"\n[bold green][OK] Found {len(working_strategies)} working strategies![/bold green]"
    )

    # Display top 5 working strategies
    for i, result in enumerate(working_strategies[:5], 1):
        rate = result["success_rate"]
        latency = result["avg_latency_ms"]
        strategy = result["strategy"]
        console.print(
            f"{i}. Success: [bold green]{rate:.0%}[/bold green] ({result['successful_sites']}/{result['total_sites']}), "
            f"Latency: {latency:.1f}ms"
        )
        console.print(f"   Strategy: [cyan]{strategy}[/cyan]")

    best_strategy_result = working_strategies[0]
    best_strategy = best_strategy_result["strategy"]
    console.print(
        f"\n[bold green][TROPHY] Best Overall Strategy:[/bold green] [cyan]{best_strategy}[/cyan]"
    )

    # Display per-domain optimal strategies
    if domain_strategy_map:
        console.print("\n[bold underline]Per-Domain Optimal Strategy Report[/bold underline]")
        domain_best_strategies = {}

        # Find the best strategy for each domain
        for domain, results in domain_strategy_map.items():
            # Sort by latency (lower is better)
            best_result = sorted(results, key=lambda x: x["latency_ms"])[0]
            domain_best_strategies[domain] = best_result

        # Create and print the results table
        try:
            from rich.table import Table

            table = Table(title="Optimal Strategy per Domain")
            table.add_column("Domain", style="cyan", no_wrap=True)
            table.add_column("Best Strategy", style="green")
            table.add_column("Latency (ms)", justify="right", style="magenta")

            for domain, best in sorted(domain_best_strategies.items()):
                table.add_row(domain, best["strategy"], f"{best['latency_ms']:.1f}")

            console.print(table)
        except ImportError:
            # Fallback if Rich Table not available
            console.print("Per-Domain Optimal Strategies:")
            for domain, best in sorted(domain_best_strategies.items()):
                console.print(f"  {domain}: {best['strategy']} ({best['latency_ms']:.1f}ms)")

    # Save strategies to files
    try:
        if StrategyManager:
            strategy_manager = StrategyManager()

            # Save the BEST strategy for EACH domain
            if domain_strategy_map:
                for domain, results in domain_strategy_map.items():
                    best_result = sorted(results, key=lambda x: x["latency_ms"])[0]
                    strategy_manager.add_strategy(
                        domain,
                        best_result["strategy"],
                        1.0,  # Success rate is 100% for this specific domain
                        best_result["latency_ms"],
                    )

            strategy_manager.save_strategies()
            console.print(
                f"[green][SAVE] Optimal strategies saved for {len(domain_strategy_map)} domains to domain_strategies.json[/green]"
            )
            LOG.info(f"Saved {len(domain_strategy_map)} domain-specific strategies")

        # Save best overall strategy
        with open(STRATEGY_FILE, "w", encoding="utf-8") as f:
            json.dump(best_strategy_result, f, indent=2, ensure_ascii=False)
        console.print(f"[green][SAVE] Best overall strategy saved to '{STRATEGY_FILE}'[/green]")
        LOG.info(f"Best strategy saved to {STRATEGY_FILE}")

    except Exception as e:
        console.print(f"[red]Error saving strategies: {e}[/red]")
        LOG.error(f"Failed to save strategies: {e}", exc_info=True)

    # Display next steps message
    console.print("\n" + "=" * 50)
    console.print("[bold yellow]Что дальше?[/bold yellow]")
    console.print("Вы нашли рабочую стратегию! Чтобы применить ее для всех программ:")
    console.print("1. Запустите [bold cyan]setup.py[/bold cyan]")
    console.print("2. Выберите пункт меню [bold green]'[2] Запустить службу обхода'[/bold green]")
    console.print(f"Служба автоматически подхватит найденную стратегию из '{STRATEGY_FILE}'.")
    console.print("=" * 50 + "\n")

    return working_strategies, best_strategy_result


async def generate_and_save_report(
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
):
    """
    Generate comprehensive report and save to file.

    Handles the report generation pattern:
    1. Generate system performance report
    2. Build final report data structure with all metrics
    3. Add PCAP validation results if available
    4. Print summary to console
    5. Save report to JSON file

    Args:
        args: Command-line arguments with args.target
        test_results: List of test result dictionaries
        working_strategies: List of working strategy results
        domain_strategy_map: Dict mapping domain to list of strategy results
        blocked_sites: List of blocked site URLs
        dm: DomainManager instance
        fingerprints: Dict mapping hostname to fingerprint objects
        pcap_validation_result: PCAP validation result (or None)
        reporter: SimpleReporter instance
        advanced_reporter: AdvancedReporter instance
        console: Rich Console instance for output

    Returns:
        Dict containing final report data

    Example:
        final_report_data = await generate_and_save_report(
            args, test_results, working_strategies, domain_strategy_map,
            blocked_sites, dm, fingerprints, pcap_validation_result,
            reporter, advanced_reporter, console
        )
    """
    from datetime import datetime
    import time

    console.print("\n[yellow]Step 6: Generating Comprehensive Report...[/yellow]")

    # Helper function to convert fingerprint objects to dict
    def _fp_to_dict(v):
        try:
            return v.to_dict()
        except Exception:
            try:
                return v.__dict__
            except Exception:
                return str(v)

    # Generate system performance report
    system_report = await advanced_reporter.generate_system_performance_report(period_hours=24)

    # Build final report data structure
    final_report_data = {
        "target": args.target,
        "execution_time_seconds": time.time() - reporter.start_time,
        "total_strategies_tested": len(test_results),
        "working_strategies_found": len(working_strategies),
        "success_rate": (len(working_strategies) / len(test_results) if test_results else 0),
        "best_overall_strategy": working_strategies[0] if working_strategies else None,
        "domain_specific_results": {
            domain: sorted(results, key=lambda x: x["latency_ms"])[0]
            for domain, results in domain_strategy_map.items()
        },
        "report_summary": {
            "generated_at": datetime.now().isoformat(),
            "period": system_report.report_period if system_report else "N/A",
        },
        "key_metrics": {
            "overall_success_rate": (
                (len(working_strategies) / len(test_results) * 100) if test_results else 0
            ),
            "total_domains_tested": len(dm.domains),
            "blocked_domains_count": len(blocked_sites),
            "total_attacks_24h": (
                system_report.total_attacks if system_report else len(test_results)
            ),
            "average_effectiveness_24h": (
                system_report.average_effectiveness if system_report else 0
            ),
        },
        "metadata": {
            "working_strategies_found": len(working_strategies),
            "total_strategies_tested": len(test_results),
        },
        "fingerprints": {k: _fp_to_dict(v) for k, v in fingerprints.items()},
        "strategy_effectiveness": {
            "top_working": sorted(
                working_strategies, key=lambda x: x.get("success_rate", 0), reverse=True
            )[:5],
            "top_failing": sorted(
                [r for r in test_results if r.get("success_rate", 0) <= 0.5],
                key=lambda x: x.get("success_rate", 0),
            )[:5],
        },
        "all_results": test_results,
    }

    # Add PCAP validation results to report if validation was performed
    if pcap_validation_result:
        final_report_data["pcap_validation"] = {
            "enabled": True,
            "passed": pcap_validation_result.passed,
            "pcap_file": str(pcap_validation_result.pcap_file),
            "packet_count": pcap_validation_result.packet_count,
            "issues_count": len(pcap_validation_result.issues),
            "warnings_count": len(pcap_validation_result.warnings),
            "errors_count": len(
                [i for i in pcap_validation_result.issues if i.severity == "error"]
            ),
            "details": pcap_validation_result.details,
        }
    else:
        final_report_data["pcap_validation"] = {"enabled": False}

    # Print summary to console
    reporter.print_summary(final_report_data)

    # Save report to file
    report_filename = reporter.save_report(final_report_data, filename="recon_summary.json")
    if report_filename:
        console.print(f"[green][FILE] Detailed report saved to: {report_filename}[/green]")
        LOG.info(f"Report saved to {report_filename}")

    return final_report_data


async def handle_baseline_validation(args, test_results, final_report_data, console):
    """
    Handle baseline comparison and saving if validation is enabled.

    Handles the baseline validation pattern:
    1. Convert test results to baseline format
    2. Compare with existing baseline if requested
    3. Display comparison results (regressions, improvements)
    4. Save new baseline if requested
    5. Update final report with baseline data

    Args:
        args: Command-line arguments with:
            - args.validate: Boolean for validation mode
            - args.validate_baseline: Baseline name to compare with (or None)
            - args.save_baseline: Baseline name to save (or None)
            - args.debug: Debug mode
        test_results: List of test result dictionaries
        final_report_data: Dict containing final report data (will be modified)
        console: Rich Console instance for output

    Returns:
        None (modifies final_report_data in place)

    Example:
        await handle_baseline_validation(args, test_results, final_report_data, console)
    """
    if not args.validate:
        return

    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        from pathlib import Path

        orchestrator = CLIValidationOrchestrator()

        # Convert test results to baseline format
        baseline_results = []
        for result in test_results:
            # Handle strategy field - it can be string or dict
            strategy = result.get("strategy", {})
            if isinstance(strategy, str):
                attack_name = strategy
            elif isinstance(strategy, dict):
                attack_name = strategy.get("type", "unknown")
            else:
                attack_name = "unknown"

            baseline_results.append(
                {
                    "attack_name": attack_name,
                    "passed": result.get("success", False),
                    "packet_count": result.get("packet_count", 0),
                    "validation_passed": result.get("validation_passed", True),
                    "validation_issues": result.get("validation_issues", []),
                    "execution_time": result.get("execution_time", 0.0),
                    "metadata": {
                        "domain": result.get("domain", "unknown"),
                        "success_rate": result.get("success_rate", 0.0),
                        "strategy": result.get("strategy", {}),
                    },
                }
            )

        # Compare with baseline if requested
        if args.validate_baseline:
            console.print(
                f"\n[bold][VALIDATION] Comparing with baseline: {args.validate_baseline}[/bold]"
            )

            try:
                comparison = orchestrator.compare_with_baseline(
                    baseline_results, baseline_name=args.validate_baseline
                )

                # Display comparison results
                console.print("\n" + "=" * 70)
                console.print("[bold]BASELINE COMPARISON RESULTS[/bold]")
                console.print("=" * 70)
                console.print(f"Baseline: {comparison.baseline_name}")
                console.print(f"Baseline Date: {comparison.baseline_timestamp}")
                console.print(f"Current Date: {comparison.current_timestamp}")
                console.print(f"Total Tests: {comparison.total_tests}")
                console.print(f"Regressions: {len(comparison.regressions)}")
                console.print(f"Improvements: {len(comparison.improvements)}")
                console.print(f"Unchanged: {comparison.unchanged}")

                # Display regressions prominently
                if comparison.regressions:
                    console.print("\n[bold red]⚠ REGRESSIONS DETECTED:[/bold red]")
                    for reg in comparison.regressions:
                        severity_color = (
                            "red" if reg.severity.value in ["critical", "high"] else "yellow"
                        )
                        console.print(
                            f"  [{severity_color}][{reg.severity.value.upper()}][/{severity_color}] "
                            f"{reg.attack_name}: {reg.description}"
                        )
                        if reg.details:
                            console.print(f"    Details: {reg.details}")
                else:
                    console.print("\n[green]✓ No regressions detected[/green]")

                # Display improvements
                if comparison.improvements:
                    console.print("\n[bold green]✓ IMPROVEMENTS:[/bold green]")
                    for imp in comparison.improvements:
                        console.print(
                            f"  [green][IMPROVEMENT][/green] {imp.attack_name}: {imp.description}"
                        )

                console.print("=" * 70)

                # Add comparison to final report
                final_report_data["baseline_comparison"] = comparison.to_dict()
                LOG.info(
                    f"Baseline comparison completed: {len(comparison.regressions)} regressions, {len(comparison.improvements)} improvements"
                )

            except Exception as e:
                console.print(f"[bold red]Error comparing with baseline: {e}[/bold red]")
                LOG.error(f"Baseline comparison failed: {e}", exc_info=True)
                if args.debug:
                    import traceback

                    traceback.print_exc()

        # Save new baseline if requested
        if args.save_baseline:
            console.print(f"\n[bold][VALIDATION] Saving baseline: {args.save_baseline}[/bold]")

            try:
                baseline_file = orchestrator.save_baseline(
                    baseline_results, name=args.save_baseline
                )
                console.print(f"[green]✓ Baseline saved to: {baseline_file}[/green]")
                LOG.info(f"Baseline saved to {baseline_file}")

                # Add to final report
                final_report_data["baseline_saved"] = str(baseline_file)

            except Exception as e:
                console.print(f"[bold red]Error saving baseline: {e}[/bold red]")
                LOG.error(f"Baseline save failed: {e}", exc_info=True)
                if args.debug:
                    import traceback

                    traceback.print_exc()

    except ImportError as e:
        console.print(f"[yellow]Warning: Baseline functionality not available: {e}[/yellow]")
        LOG.warning(f"Baseline functionality not available: {e}")
    except Exception as e:
        console.print(f"[yellow]Warning: Baseline operation failed: {e}[/yellow]")
        LOG.error(f"Baseline operation failed: {e}", exc_info=True)
        if args.debug:
            import traceback

            traceback.print_exc()


async def perform_pcap_analysis(args, capturer, console):
    """
    Perform PCAP analysis: correlation, pattern validation, and profiling.

    Handles the PCAP analysis pattern:
    1. Offline correlation analysis (enhanced tracking)
    2. Packet pattern validation (zapret vs recon comparison)
    3. PCAP profiling with traffic analysis

    Args:
        args: Command-line arguments with:
            - args.enable_enhanced_tracking: Boolean for enhanced tracking
            - args.pcap: PCAP file path
        capturer: PacketCapturer instance (or None)
        console: Rich Console instance for output

    Returns:
        Optional PCAP profile result (or None if profiling not performed)

    Example:
        pcap_profile_result = await perform_pcap_analysis(args, capturer, console)
    """
    import os
    from pathlib import Path

    # Check for optional imports
    PKTVAL_AVAILABLE = False
    PROFILER_AVAILABLE = False

    try:
        import core.validation.packet_pattern_validator as pktval

        PKTVAL_AVAILABLE = True
    except ImportError:
        pass

    try:
        from core.profiling.advanced_traffic_profiler import AdvancedTrafficProfiler

        PROFILER_AVAILABLE = True
    except ImportError:
        pass

    # Offline correlation analysis (enhanced tracking)
    if args.enable_enhanced_tracking and capturer and args.pcap and os.path.exists(args.pcap):
        try:
            analysis = capturer.analyze_all_strategies_offline(
                pcap_file=args.pcap, window_slack=0.6
            )
            if analysis:
                console.print(
                    "\n[bold][ANALYZE] Enhanced tracking summary (PCAP -> strategies)[/bold]"
                )
                # Display top 5
                shown = 0
                for sid, info in analysis.items():
                    console.print(
                        f"  * {sid}: score={info.get('success_score',0):.2f}, SH/CH={info.get('tls_serverhellos',0)}/{info.get('tls_clienthellos',0)}, RST={info.get('rst_packets',0)}"
                    )
                    shown += 1
                    if shown >= 5:
                        break
                LOG.info(f"Correlation analysis completed: {len(analysis)} strategies analyzed")
        except Exception as e:
            console.print(f"[yellow][!] Correlation analysis failed: {e}[/yellow]")
            LOG.warning(f"Correlation analysis failed: {e}")

    # Packet pattern validation (zapret vs recon comparison)
    validator = None
    if PKTVAL_AVAILABLE and Path("zapret.pcap").exists() and Path("recon.pcap").exists():
        console.print("\n[yellow]Step 5.1: Packet pattern validation (zapret vs recon)...[/yellow]")
        try:
            validator = pktval.PacketPatternValidator(output_dir="packet_validation")
            comp = validator.compare_packet_patterns(
                "recon.pcap", "zapret.pcap", validator.critical_strategy
            )
            console.print(
                f"  Pattern match score: {comp.pattern_match_score:.2f} (passed={comp.validation_passed})"
            )
            if comp.critical_differences:
                console.print("  Critical differences:")
                for d in comp.critical_differences[:5]:
                    console.print(f"    - {d}")
            LOG.info(
                f"Pattern validation completed: score={comp.pattern_match_score:.2f}, passed={comp.validation_passed}"
            )
        except Exception as e:
            console.print(f"[yellow][!] Packet pattern validation failed: {e}[/yellow]")
            LOG.warning(f"Packet pattern validation failed: {e}")
        finally:
            if validator:
                try:
                    validator.close_logging()
                except Exception:
                    pass

    # PCAP profiling
    pcap_profile_result = None
    if args.pcap and PROFILER_AVAILABLE and os.path.exists(args.pcap):
        try:
            profiler = AdvancedTrafficProfiler()
            pcap_profile_result = profiler.analyze_pcap_file(args.pcap)
            if pcap_profile_result and pcap_profile_result.success:
                console.print("\n[bold][TEST] PCAP profiling summary[/bold]")
                apps = ", ".join(pcap_profile_result.detected_applications) or "none"
                ctx = pcap_profile_result.metadata.get("context", {})
                console.print(f"  Apps: [cyan]{apps}[/cyan]")
                console.print(
                    f"  TLS ClientHello: {ctx.get('tls_client_hello',0)}, Alerts: {ctx.get('tls_alert_count',0)}, QUIC: {ctx.get('quic_initial_count',0)}"
                )
                LOG.info(
                    f"PCAP profiling completed: {len(pcap_profile_result.detected_applications)} apps detected"
                )
        except Exception as e:
            console.print(f"[yellow][!] PCAP profiling failed: {e}[/yellow]")
            LOG.warning(f"PCAP profiling failed: {e}")

    return pcap_profile_result


async def cleanup_resources(
    hybrid_engine,
    pcap_worker_task,
    refiner,
    unified_fingerprinter,
    advanced_reporter,
    capturer,
    corr_capturer,
    console,
):
    """
    Clean up all resources at the end of hybrid mode execution.

    Handles the cleanup pattern:
    1. Cleanup hybrid engine
    2. Cancel and await PCAP worker task
    3. Close refiner
    4. Close unified fingerprinter
    5. Close advanced reporter
    6. Stop packet capturer
    7. Stop correlation capturer

    Args:
        hybrid_engine: UnifiedBypassEngine instance
        pcap_worker_task: Asyncio task for PCAP insights worker (or None)
        refiner: Fingerprint refiner instance (or None)
        unified_fingerprinter: UnifiedFingerprinter instance (or None)
        advanced_reporter: AdvancedReporter instance
        capturer: PacketCapturer instance (or None)
        corr_capturer: Correlation capturer instance (or None)
        console: Rich Console instance for output

    Returns:
        None

    Example:
        await cleanup_resources(
            hybrid_engine, pcap_worker_task, refiner, unified_fingerprinter,
            advanced_reporter, capturer, corr_capturer, console
        )
    """
    import asyncio

    # Cleanup hybrid engine
    try:
        hybrid_engine.cleanup()
        LOG.debug("Hybrid engine cleaned up")
    except Exception as e:
        console.print(f"[yellow]Warning: Engine cleanup error: {e}[/yellow]")
        LOG.warning(f"Engine cleanup error: {e}")

    # Cancel and await PCAP worker task
    if pcap_worker_task and not pcap_worker_task.done():
        pcap_worker_task.cancel()
        try:
            await asyncio.wait_for(pcap_worker_task, timeout=5.0)
            LOG.debug("PCAP worker task cancelled")
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass  # Expected
        except Exception as e:
            console.print(f"[yellow]Warning: PCAP worker cleanup error: {e}[/yellow]")
            LOG.warning(f"PCAP worker cleanup error: {e}")

    # Cleanup refiner if it was created
    if refiner and hasattr(refiner, "close"):
        try:
            await refiner.close()
            LOG.debug("Refiner closed")
        except Exception as e:
            console.print(f"[yellow]Warning: Refiner cleanup error: {e}[/yellow]")
            LOG.warning(f"Refiner cleanup error: {e}")

    # Cleanup unified fingerprinter if it was created
    if unified_fingerprinter and hasattr(unified_fingerprinter, "close"):
        try:
            await unified_fingerprinter.close()
            LOG.debug("Unified fingerprinter closed")
        except Exception as e:
            console.print(f"[yellow]Warning: Unified fingerprinter cleanup error: {e}[/yellow]")
            LOG.warning(f"Unified fingerprinter cleanup error: {e}")

    # Cleanup advanced reporter
    if advanced_reporter and hasattr(advanced_reporter, "close"):
        try:
            await advanced_reporter.close()
            LOG.debug("Advanced reporter closed")
        except Exception as e:
            console.print(f"[yellow]Warning: Advanced reporter cleanup error: {e}[/yellow]")
            LOG.warning(f"Advanced reporter cleanup error: {e}")

    # Stop packet capturer
    if capturer:
        try:
            capturer.stop()
            LOG.debug("Packet capturer stopped")
        except Exception as e:
            console.print(f"[yellow]Warning: Capturer stop error: {e}[/yellow]")
            LOG.warning(f"Capturer stop error: {e}")

    # Stop correlation capturer
    if corr_capturer:
        try:
            corr_capturer.stop()
            LOG.debug("Correlation capturer stopped")
        except Exception as e:
            console.print(f"[yellow]Warning: Correlation capturer stop error: {e}[/yellow]")
            LOG.warning(f"Correlation capturer stop error: {e}")


def display_kb_summary(console):
    """
    Display knowledge base summary of blocking reasons by CDN and domain.

    Handles the KB summary display pattern:
    1. Load CdnAsnKnowledgeBase
    2. Display top blocking reasons by CDN
    3. Display top blocking reasons by domain (top 10)

    Args:
        console: Rich Console instance for output

    Returns:
        None

    Example:
        display_kb_summary(console)
    """
    try:
        from core.knowledge.cdn_asn_knowledge import CdnAsnKnowledgeBase

        kb = CdnAsnKnowledgeBase()

        # Display blocking reasons by CDN
        if kb.cdn_profiles:
            console.print(
                "\n[bold underline][AI] KB Blocking Reasons Summary (by CDN)[/bold underline]"
            )
            for cdn, prof in kb.cdn_profiles.items():
                br = getattr(prof, "block_reasons", {}) or {}
                if br:
                    top = sorted(br.items(), key=lambda x: x[1], reverse=True)[:5]
                    s = ", ".join([f"{k}:{v}" for k, v in top])
                    console.print(f"  * {cdn}: {s}")
            LOG.debug(f"KB summary displayed for {len(kb.cdn_profiles)} CDN profiles")

        # Display blocking reasons by domain (top 10)
        if kb.domain_block_reasons:
            console.print(
                "\n[bold underline][AI] KB Blocking Reasons Summary (by domain)[/bold underline]"
            )
            items = sorted(
                kb.domain_block_reasons.items(),
                key=lambda kv: sum(kv[1].values()),
                reverse=True,
            )[:10]
            for domain, brmap in items:
                s = ", ".join(
                    [
                        f"{k}:{v}"
                        for k, v in sorted(brmap.items(), key=lambda x: x[1], reverse=True)[:3]
                    ]
                )
                console.print(f"  * {domain}: {s}")
            LOG.debug(f"KB summary displayed for {len(items)} domains")

    except ImportError as e:
        console.print(
            f"[yellow]KB summary unavailable: Knowledge base not available ({e})[/yellow]"
        )
        LOG.warning(f"KB summary unavailable: {e}")
    except Exception as e:
        console.print(f"[yellow]KB summary unavailable: {e}[/yellow]")
        LOG.warning(f"KB summary failed: {e}")


# ============================================================================
# STEP 11: Reporting Helper Functions
# ============================================================================
# These functions extract common reporting/display patterns to reduce
# duplication across different mode runner functions.
# ============================================================================


def print_mode_header(title: str, subtitle: Optional[str] = None, console=None):
    """
    Display a formatted mode header with Panel.

    Provides consistent header formatting across all mode functions.

    Args:
        title: Main title text (with Rich markup)
        subtitle: Optional subtitle for the panel
        console: Rich Console instance for output

    Returns:
        None

    Example:
        print_mode_header("[bold cyan]Recon: Hybrid Mode[/bold cyan]",
                         "Real-World Testing", console)
    """
    if console is None:
        return

    try:
        from rich.panel import Panel

        if subtitle:
            console.print(Panel(title, title=subtitle, expand=False))
        else:
            console.print(Panel(title, expand=False))
    except ImportError:
        # Fallback without Panel
        console.print(title)


def print_baseline_results(baseline_results: dict, console=None):
    """
    Display baseline connectivity test results in a formatted way.

    Shows which sites are working and which are blocked, with status indicators.

    Args:
        baseline_results: Dict mapping site URLs to (status, latency, error, metadata) tuples
        console: Rich Console instance for output

    Returns:
        List of blocked sites

    Example:
        blocked = print_baseline_results(baseline_results, console)
    """
    if console is None or not baseline_results:
        return []

    blocked_sites = []
    working_sites = []

    for site, (status, latency, error, metadata) in baseline_results.items():
        if status == "WORKING":
            working_sites.append((site, latency))
        else:
            blocked_sites.append((site, status, error))

    # Display working sites
    if working_sites:
        console.print(f"\n[green]✓ {len(working_sites)} site(s) accessible:[/green]")
        for site, latency in working_sites[:5]:  # Show first 5
            console.print(f"  • {site} ({latency:.0f}ms)")
        if len(working_sites) > 5:
            console.print(f"  ... and {len(working_sites) - 5} more")

    # Display blocked sites
    if blocked_sites:
        console.print(f"\n[red]✗ {len(blocked_sites)} site(s) blocked:[/red]")
        for site, status, error in blocked_sites[:5]:  # Show first 5
            error_msg = f" - {error}" if error else ""
            console.print(f"  • {site} [{status}]{error_msg}")
        if len(blocked_sites) > 5:
            console.print(f"  ... and {len(blocked_sites) - 5} more")

    return [site for site, _, _ in blocked_sites]


def print_blocked_sites_summary(blocked_sites: List[str], total_sites: int, console=None):
    """
    Display a summary of blocked vs accessible sites.

    Args:
        blocked_sites: List of blocked site URLs
        total_sites: Total number of sites tested
        console: Rich Console instance for output

    Returns:
        None

    Example:
        print_blocked_sites_summary(blocked_sites, len(dm.domains), console)
    """
    if console is None:
        return

    blocked_count = len(blocked_sites)
    accessible_count = total_sites - blocked_count

    if blocked_count == 0:
        console.print("\n[bold green]✓ All sites are accessible! No bypass needed.[/bold green]")
    else:
        console.print(
            f"\n[yellow]Found {blocked_count}/{total_sites} blocked site(s) "
            f"({accessible_count} accessible)[/yellow]"
        )


def print_fingerprint_result(hostname: str, fingerprint, console=None):
    """
    Display DPI fingerprint result for a single host.

    Args:
        hostname: Target hostname
        fingerprint: Fingerprint object with dpi_type and other attributes
        console: Rich Console instance for output

    Returns:
        None

    Example:
        print_fingerprint_result("example.com", fp, console)
    """
    if console is None or not fingerprint:
        return

    try:
        # Try to get DPI type value
        dpi_value = getattr(
            fingerprint.dpi_type,
            "value",
            str(getattr(fingerprint.dpi_type, "name", "unknown")),
        )

        # Try to get reliability score
        reliability = getattr(fingerprint, "reliability_score", None)

        if reliability is not None:
            console.print(
                f"  • {hostname}: [cyan]{dpi_value}[/cyan] " f"(reliability: {reliability:.2f})"
            )
        else:
            console.print(f"  • {hostname}: [cyan]{dpi_value}[/cyan]")

    except Exception:
        # Fallback for simple fingerprints
        dpi_type = getattr(fingerprint, "dpi_type", "unknown")
        blocking_method = getattr(fingerprint, "blocking_method", "")
        if blocking_method:
            console.print(f"  • {hostname}: [cyan]{dpi_type}[/cyan] ({blocking_method})")
        else:
            console.print(f"  • {hostname}: [cyan]{dpi_type}[/cyan]")


def print_strategy_test_summary(test_results: List[dict], console=None):
    """
    Display summary of strategy testing results.

    Shows total strategies tested, working strategies, and best performers.

    Args:
        test_results: List of strategy test result dictionaries
        console: Rich Console instance for output

    Returns:
        Tuple of (working_strategies, best_strategy)

    Example:
        working, best = print_strategy_test_summary(test_results, console)
    """
    if console is None or not test_results:
        return [], None

    working_strategies = [r for r in test_results if r.get("success_rate", 0) > 0]
    total_tested = len(test_results)

    console.print(
        f"\n[bold]Strategy Testing Results:[/bold] "
        f"{len(working_strategies)}/{total_tested} strategies working"
    )

    if not working_strategies:
        console.print("[red]✗ No working strategies found[/red]")
        return [], None

    # Sort by success rate, then by latency
    working_strategies.sort(
        key=lambda x: (-x.get("success_rate", 0), x.get("avg_latency_ms", 999999))
    )

    best_strategy = working_strategies[0]

    # Display top 3 strategies
    console.print("\n[green]✓ Top working strategies:[/green]")
    for i, result in enumerate(working_strategies[:3], 1):
        strategy = result.get("strategy", "unknown")
        success_rate = result.get("success_rate", 0)
        latency = result.get("avg_latency_ms", 0)
        console.print(
            f"  {i}. {strategy[:60]}... "
            f"[green]{success_rate:.0%}[/green] success, "
            f"{latency:.1f}ms avg"
        )

    if len(working_strategies) > 3:
        console.print(f"  ... and {len(working_strategies) - 3} more working strategies")

    return working_strategies, best_strategy


def print_domain_optimization_results(all_results: dict, console=None):
    """
    Display per-domain optimization results.

    Shows which domains have working strategies and which don't.

    Args:
        all_results: Dict mapping domain names to strategy results (or None if failed)
        console: Rich Console instance for output

    Returns:
        Tuple of (successful_domains, failed_domains)

    Example:
        successful, failed = print_domain_optimization_results(all_results, console)
    """
    if console is None or not all_results:
        return [], []

    successful_domains = [d for d, r in all_results.items() if r is not None]
    failed_domains = [d for d, r in all_results.items() if r is None]

    console.print(
        f"\n[bold]Per-Domain Optimization Results:[/bold] "
        f"[green]{len(successful_domains)}/{len(all_results)}[/green] domains optimized"
    )

    # Display successful domains
    if successful_domains:
        console.print("\n[green]✓ Domains with optimal strategies:[/green]")
        for domain in successful_domains[:10]:  # Show first 10
            result = all_results[domain]
            success_rate = result.get("success_rate", 0)
            latency = result.get("avg_latency_ms", 0)
            console.print(f"  • {domain}: {success_rate:.0%} success, {latency:.1f}ms")
        if len(successful_domains) > 10:
            console.print(f"  ... and {len(successful_domains) - 10} more")

    # Display failed domains
    if failed_domains:
        console.print("\n[red]✗ Domains without working strategies:[/red]")
        for domain in failed_domains[:10]:  # Show first 10
            console.print(f"  • {domain}")
        if len(failed_domains) > 10:
            console.print(f"  ... and {len(failed_domains) - 10} more")

    return successful_domains, failed_domains


def print_statistics_table(stats: dict, console=None):
    """
    Display statistics in a formatted table.

    Args:
        stats: Dictionary with statistics (total_domains, avg_success_rate, etc.)
        console: Rich Console instance for output

    Returns:
        None

    Example:
        print_statistics_table(strategy_manager.get_statistics(), console)
    """
    if console is None or not stats:
        return

    try:
        from rich.table import Table

        table = Table(title="Strategy Statistics", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        # Add rows for each statistic
        if "total_domains" in stats:
            table.add_row("Total Domains", str(stats["total_domains"]))

        if "avg_success_rate" in stats:
            table.add_row("Avg Success Rate", f"{stats['avg_success_rate']:.1%}")

        if "avg_latency" in stats:
            table.add_row("Avg Latency", f"{stats['avg_latency']:.1f}ms")

        if "best_domain" in stats and "best_success_rate" in stats:
            table.add_row(
                "Best Domain", f"{stats['best_domain']} ({stats['best_success_rate']:.1%})"
            )

        console.print(table)

    except ImportError:
        # Fallback without Table
        console.print("\n[bold]Strategy Statistics:[/bold]")
        if "total_domains" in stats:
            console.print(f"  Total domains: {stats['total_domains']}")
        if "avg_success_rate" in stats:
            console.print(f"  Average success rate: {stats['avg_success_rate']:.1%}")
        if "avg_latency" in stats:
            console.print(f"  Average latency: {stats['avg_latency']:.1f}ms")
        if "best_domain" in stats and "best_success_rate" in stats:
            console.print(
                f"  Best performing domain: {stats['best_domain']} "
                f"({stats['best_success_rate']:.1%})"
            )


def print_error_message(message: str, console=None):
    """
    Display a formatted error message.

    Args:
        message: Error message text
        console: Rich Console instance for output

    Returns:
        None

    Example:
        print_error_message("No domains to test", console)
    """
    if console is None:
        return
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_success_message(message: str, console=None):
    """
    Display a formatted success message.

    Args:
        message: Success message text
        console: Rich Console instance for output

    Returns:
        None

    Example:
        print_success_message("All strategies saved successfully", console)
    """
    if console is None:
        return
    console.print(f"[bold green]✓[/bold green] {message}")


def print_warning_message(message: str, console=None):
    """
    Display a formatted warning message.

    Args:
        message: Warning message text
        console: Rich Console instance for output

    Returns:
        None

    Example:
        print_warning_message("Advanced fingerprinting not available", console)
    """
    if console is None:
        return
    console.print(f"[yellow]⚠[/yellow] {message}")


def print_info_message(message: str, console=None):
    """
    Display a formatted info message.

    Args:
        message: Info message text
        console: Rich Console instance for output

    Returns:
        None

    Example:
        print_info_message("Loading configuration...", console)
    """
    if console is None:
        return
    console.print(f"[dim]{message}[/dim]")
