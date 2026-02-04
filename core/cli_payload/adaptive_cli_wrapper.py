"""
CLI Wrapper for AdaptiveEngine - Ultimate Edition

Provides enhanced CLI integration for AdaptiveEngine with:
- Rich output formatting with graceful degradation
- Comprehensive error handling
- Parameter validation and processing
- Multiple output formats (console, JSON, legacy)
- Metrics collection and caching
- Batch processing support
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)

LOG = logging.getLogger("AdaptiveCLIWrapper")


# ============================================================================
# IMPORTS FROM SUBMODULES
# ============================================================================

# Import enums and data models
from .data_models import AnalysisMode  # noqa: E402

# Import Unicode utilities
from .unicode_utils import (
    UnicodeReplacements,
    UnicodeSupport,
    safe_console_print,
)  # noqa: E402, F401


# ============================================================================
# CONSTANTS
# ============================================================================


# ============================================================================
# EXCEPTIONS
# ============================================================================


class CLIWrapperError(Exception):
    """Base exception for CLI wrapper errors."""

    pass


# Import from domain_validation module for backward compatibility
from .domain_validation import DomainValidationError  # noqa: E402


class ConfigurationError(CLIWrapperError):
    """Configuration creation failed."""

    pass


class EngineInitializationError(CLIWrapperError):
    """Engine initialization failed."""

    pass


class AnalysisError(CLIWrapperError):
    """Analysis execution failed."""

    pass


class TimeoutError(CLIWrapperError):
    """Operation timed out."""

    pass


class ExportError(CLIWrapperError):
    """Export operation failed."""

    pass


# ============================================================================
# IMPORTS WITH FALLBACKS
# ============================================================================

# Rich imports
RICH_AVAILABLE = False
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TimeElapsedColumn,
    )

    RICH_AVAILABLE = True
    LOG.debug("Rich library imported successfully")
except ImportError:
    LOG.info("Rich library not available, using fallback console")


# AdaptiveEngine imports
ADAPTIVE_ENGINE_AVAILABLE = False
try:
    from core.adaptive_refactored.facade import AdaptiveEngine, AdaptiveConfig, StrategyResult

    ADAPTIVE_ENGINE_AVAILABLE = True
    LOG.debug("AdaptiveEngine imported successfully")
except ImportError:
    LOG.warning("AdaptiveEngine not available")


# Error handler imports (prefer local module in this package)
ERROR_HANDLER_AVAILABLE = False
try:
    from .error_handler import (
        CLIErrorHandler,
        ErrorSeverity,
        ErrorContext,
        handle_cli_error,
    )

    ERROR_HANDLER_AVAILABLE = True
except ImportError:
    try:
        from core.cli.error_handler import (  # type: ignore
            CLIErrorHandler,
            ErrorSeverity,
            ErrorContext,
            handle_cli_error,
        )

        ERROR_HANDLER_AVAILABLE = True
    except ImportError:
        LOG.debug("CLIErrorHandler not available")

    # Fallback error handling
    def handle_cli_error(error, *args, **kwargs):
        LOG.error(f"Error: {error}")
        return False


# ============================================================================
# FALLBACK CLASSES
# ============================================================================

# Import from fallback_compat module for backward compatibility
from .fallback_compat import (  # noqa: E402
    FallbackConsole,
    FallbackPanel,
    FallbackProgress,
    FallbackAdaptiveEngine,
    FallbackAdaptiveConfig,
    FallbackStrategyResult,
)

# Set fallbacks if imports failed
if not RICH_AVAILABLE:
    Console = FallbackConsole
    Panel = FallbackPanel
    Progress = FallbackProgress

if not ADAPTIVE_ENGINE_AVAILABLE:
    AdaptiveEngine = FallbackAdaptiveEngine
    AdaptiveConfig = FallbackAdaptiveConfig
    StrategyResult = FallbackStrategyResult


# ============================================================================
# DATA CLASSES
# ============================================================================

# Import from data_models module for backward compatibility
from .data_models import (  # noqa: E402
    CLIConfig,
    AnalysisMetrics,
    BatchSummary,
)


# ============================================================================
# VALIDATION
# ============================================================================

# Import from domain_validation module for backward compatibility
from .domain_validation import DomainValidator  # noqa: E402


class ArgumentValidator:
    """Validate CLI arguments."""

    @classmethod
    def validate_timeout(cls, timeout: float) -> float:
        """Validate timeout value."""
        if timeout <= 0:
            raise ConfigurationError(f"Timeout must be positive: {timeout}")
        if timeout > 3600:
            LOG.warning(f"Very long timeout specified: {timeout}s")
        return timeout

    @classmethod
    def validate_max_trials(cls, max_trials: int) -> int:
        """Validate max_trials value."""
        if max_trials < 1:
            raise ConfigurationError(f"max_trials must be at least 1: {max_trials}")
        if max_trials > 100:
            LOG.warning(f"Very high max_trials specified: {max_trials}")
        return max_trials


# ============================================================================
# OUTPUT STRATEGIES
# ============================================================================
# OUTPUT STRATEGIES
# ============================================================================

# Import from output_strategies module for backward compatibility
from .output_strategies import (  # noqa: E402
    OutputStrategy,
    RichOutputStrategy,
    PlainOutputStrategy,
    QuietOutputStrategy,
)


# ============================================================================
# STRATEGY SAVER
# ============================================================================

# Import from strategy_persistence module for backward compatibility
from .strategy_persistence import StrategySaver  # noqa: E402


# ============================================================================
# BATCH ANALYSIS
# ============================================================================

# Import from batch_analysis module for backward compatibility
from .batch_analysis import BatchAnalyzer  # noqa: E402


# ============================================================================
# DISCOVERY MODE
# ============================================================================

# Import from discovery_mode module for backward compatibility
from .discovery_mode import DiscoveryModeCoordinator  # noqa: E402


# ============================================================================
# PCAP SETUP
# ============================================================================

# Import from pcap_setup module for backward compatibility
from .pcap_setup import PCAPCaptureManager  # noqa: E402


# ============================================================================
# RESULTS EXPORTER
# ============================================================================


class ResultsExporter:
    """Export analysis results in various formats."""

    def __init__(self, console: Any, quiet: bool = False):
        self.console = console
        self.quiet = quiet

    def export_to_json(
        self,
        domain: str,
        result: Any,
        execution_time: float,
        stats: Dict[str, Any],
        export_file: str,
        progress_messages: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """
        Export results to JSON file.

        Returns:
            bool: True if export successful
        """
        try:
            run_id = None
            try:
                run_id = (stats or {}).get("_run_id") or (stats or {}).get("run_id")
            except Exception:
                run_id = None

            export_data = {
                "run_id": run_id,
                "timestamp": datetime.now().isoformat(),
                "domain": domain,
                "result": {
                    "success": result.success,
                    "message": result.message,
                    "execution_time": execution_time,
                    "trials_count": getattr(result, "trials_count", 0),
                    "fingerprint_updated": getattr(result, "fingerprint_updated", False),
                    "run_id": run_id,
                },
                "statistics": stats,
                "progress_log": progress_messages or [],
            }

            # Add strategy details
            if result.success and hasattr(result, "strategy") and result.strategy:
                export_data["result"]["strategy"] = {
                    "name": result.strategy.name,
                    "attack_name": getattr(result.strategy, "attack_name", None),
                    "parameters": getattr(result.strategy, "parameters", {}),
                }

                if hasattr(result.strategy, "attack_combination"):
                    export_data["result"]["strategy"]["attack_combination"] = [
                        a for a in result.strategy.attack_combination if a
                    ]

            with open(export_file, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

            if not self.quiet:
                self.console.print(f"[green]✓ Results exported to: {export_file}[/green]")

            return True

        except Exception as e:
            LOG.error(f"Failed to export results: {e}")
            if not self.quiet:
                self.console.print(f"[yellow]Warning: Failed to export results: {e}[/yellow]")
            return False

    def export_batch_summary(
        self,
        summary: BatchSummary,
        filename: Optional[str] = None,
    ) -> bool:
        """Export batch summary to JSON file."""
        try:
            if not filename:
                filename = f"batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

            summary_data = {
                "timestamp": datetime.now().isoformat(),
                "total_domains": summary.total_domains,
                "successful_domains": summary.successful_domains,
                "failed_domains": summary.failed_domains,
                "success_rate": summary.success_rate,
                "total_time": summary.total_time,
                "per_domain_results": {
                    domain: {
                        "success": result.success,
                        "strategy": result.strategy_name,
                        "error": result.error,
                        "execution_time": result.execution_time,
                    }
                    for domain, result in summary.results.items()
                },
            }

            with open(filename, "w", encoding="utf-8") as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)

            if not self.quiet:
                self.console.print(f"[dim]Summary report saved to: {filename}[/dim]")

            return True

        except Exception as e:
            LOG.warning(f"Failed to save batch summary: {e}")
            return False


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_monotonic_time() -> float:
    """Get monotonic time for performance measurement."""
    return time.monotonic()


def create_config_from_args(args: Any) -> FallbackAdaptiveConfig:
    """
    Create AdaptiveConfig from CLI arguments.

    Args:
        args: CLI arguments object

    Returns:
        AdaptiveConfig instance
    """
    config = FallbackAdaptiveConfig() if not ADAPTIVE_ENGINE_AVAILABLE else AdaptiveConfig()

    # Mode and trials
    mode = getattr(args, "mode", "balanced")
    config.mode = mode

    if hasattr(args, "max_trials") and args.max_trials:
        config.max_trials = ArgumentValidator.validate_max_trials(int(args.max_trials))
    else:
        try:
            config.max_trials = AnalysisMode(mode).max_trials
        except ValueError:
            config.max_trials = 10

    # Feature flags
    if hasattr(args, "no_fingerprinting"):
        config.enable_fingerprinting = not args.no_fingerprinting

    if hasattr(args, "no_failure_analysis"):
        config.enable_failure_analysis = not args.no_failure_analysis

    # Timeouts
    config.strategy_timeout = ArgumentValidator.validate_timeout(
        float(getattr(args, "tls_timeout", 30.0))
    )
    config.connection_timeout = ArgumentValidator.validate_timeout(
        float(getattr(args, "connect_timeout", 5.0))
    )

    # Verification mode
    config.verify_with_pcap = getattr(args, "verify_with_pcap", False)

    LOG.info(f"Created config: mode={config.mode}, max_trials={config.max_trials}")
    return config


# ============================================================================
# ADAPTIVE CLI WRAPPER
# ============================================================================


class AdaptiveCLIWrapper:
    """
    Enhanced CLI wrapper for AdaptiveEngine with Rich output and error handling.

    Features:
    - Beautiful Rich-based progress display with fallback
    - Comprehensive error handling with graceful degradation
    - Parameter validation and normalization
    - Multiple output formats (console, JSON, legacy)
    - Timeout handling and cancellation support
    - Batch processing support
    - Metrics collection
    """

    def __init__(self, cli_config: Optional[CLIConfig] = None):
        """
        Initialize CLI wrapper.

        Args:
            cli_config: CLI configuration options
        """
        self.cli_config = cli_config or CLIConfig()

        # Setup Unicode support
        UnicodeSupport.setup(self.cli_config)

        # Initialize console
        self.console = self._create_console()

        # Initialize output strategy
        self.output_strategy = self._create_output_strategy()

        # Initialize error handler
        self.error_handler = None
        if ERROR_HANDLER_AVAILABLE:
            self.error_handler = CLIErrorHandler(
                self.console,
                self.cli_config.verbose,
            )

        # Initialize components
        self.strategy_saver = StrategySaver(
            self.console, self.cli_config.quiet, engine=None
        )  # Engine will be set later
        self.exporter = ResultsExporter(self.console, self.cli_config.quiet)

        # Engine state
        self.engine = None
        self.engine_available = ADAPTIVE_ENGINE_AVAILABLE
        self.config = None

        # Progress tracking
        self.progress_messages: List[Dict[str, Any]] = []

        # Metrics
        self._metrics: Optional[AnalysisMetrics] = None

        # Original domain tracking (for wildcards)
        self._original_domain: Optional[str] = None

        # Discovery system integration
        self._discovery_controller = None
        self._discovery_session_id: Optional[str] = None
        self._batch_discovery_mode = False
        self._discovery_mode = DiscoveryModeCoordinator(
            console=self.console,
            cli_config=self.cli_config,
            output_strategy=self.output_strategy,
            error_handler=self.error_handler,
        )

        # PCAP manager (initialized when engine+config are ready)
        self._pcap_manager: Optional[PCAPCaptureManager] = None

        # Run correlation ID (per analysis call)
        self._run_id: Optional[str] = None

    @staticmethod
    def _generate_run_id() -> str:
        # short, stable for logs/exports
        return str(uuid.uuid4())[:8]

    def _rid(self) -> str:
        return self._run_id or "--------"

    def _print(self, *args: Any, **kwargs: Any) -> None:
        """
        Unicode-safe print to current console.
        Keeps existing console interface.
        """
        safe_console_print(self.console, *args, **kwargs)

    def _create_console(self) -> Any:
        """Create console with appropriate settings."""
        if not RICH_AVAILABLE or self.cli_config.no_colors:
            LOG.info("Using fallback console")
            return FallbackConsole()

        try:
            console = Console(
                highlight=False,
                force_terminal=not self.cli_config.quiet,
                width=None if sys.stdout.isatty() else 120,
                file=sys.stdout,
                legacy_windows=True,
                safe_box=True,
            )

            # Test Unicode support
            try:
                console.print("✓", end="")
                LOG.debug("Rich console with Unicode support created")
                return console
            except UnicodeEncodeError:
                LOG.warning("Unicode not supported, using fallback")
                self.cli_config.no_colors = True
                return FallbackConsole()

        except Exception as e:
            LOG.warning(f"Failed to create Rich console: {e}")
            return FallbackConsole()

    def _create_output_strategy(self) -> OutputStrategy:
        """Create appropriate output strategy based on config."""
        if self.cli_config.quiet:
            return QuietOutputStrategy()

        if self.cli_config.no_colors or not RICH_AVAILABLE:
            return PlainOutputStrategy(self.console)

        return RichOutputStrategy(self.console)

    def _progress_callback(self, message: str) -> None:
        """Progress callback for AdaptiveEngine."""
        # Normalize message for unicode safety and consistent logs
        safe_msg = UnicodeReplacements.make_safe(message)
        self.progress_messages.append(
            {
                "timestamp": datetime.now(),
                "message": safe_msg,
                "run_id": self._rid(),
                "monotonic": get_monotonic_time(),
            }
        )

        if not self.cli_config.quiet:
            self.output_strategy.display_progress(safe_msg)

    async def run_adaptive_analysis(self, domain: str, args: Any) -> bool:
        """
        Run adaptive analysis with enhanced CLI integration and discovery system support.

        Args:
            domain: Target domain name
            args: CLI arguments object

        Returns:
            bool: True if analysis was successful
        """
        # New run correlation id
        self._run_id = self._generate_run_id()
        self.progress_messages = []

        LOG.info("[RID:%s] Starting analysis for domain=%s", self._rid(), domain)

        # Initialize metrics
        self._metrics = AnalysisMetrics(
            start_time=get_monotonic_time(),
            domain=domain,
        )

        # Enable reasoning logger if requested
        if getattr(args, "debug_reasoning", False):
            try:
                from core.diagnostics.strategy_reasoning_logger import enable_reasoning_logging

                _ = enable_reasoning_logging("data/reasoning_logs")
                if not self.cli_config.quiet:
                    self._print("[green]✓ Strategy reasoning logging enabled[/green]")
                    self._print("[dim]Reasoning logs will be saved to: data/reasoning_logs/[/dim]")
            except Exception as e:
                if not self.cli_config.quiet:
                    self.console.print(
                        f"[yellow]Warning: Could not enable reasoning logging: {e}[/yellow]"
                    )
                if getattr(args, "debug", False):
                    import traceback

                    traceback.print_exc()

        try:
            # Validate domain
            domain, self._original_domain = DomainValidator.validate_and_normalize(
                domain, self.console, self.cli_config.quiet
            )

        except DomainValidationError as e:
            self._handle_error(
                e, "domain_validation", ErrorSeverity.ERROR if ERROR_HANDLER_AVAILABLE else None
            )
            return False

        # Check if discovery mode should be enabled
        use_discovery_mode = self._should_use_discovery_mode(args)

        if use_discovery_mode:
            return await self._run_discovery_mode_analysis(domain, args)
        else:
            return await self._run_standard_analysis(domain, args)

    def _initialize_engine(self, args: Any) -> Any:
        """Initialize AdaptiveEngine with proper configuration."""
        engine = AdaptiveEngine(self.config)

        if hasattr(engine, "bypass_engine"):
            if not self.cli_config.quiet:
                self.console.print(
                    "[green]✓ AdaptiveEngine initialized with capture support[/green]"
                )

            # Enable verbose logging if requested
            if getattr(args, "verbose_strategy", False):
                self._enable_verbose_logging(engine)
        else:
            if not self.cli_config.quiet:
                self.console.print(
                    "[yellow]⚠ AdaptiveEngine initialized without capture support[/yellow]"
                )

        return engine

    def _check_engine_availability(self) -> bool:
        """
        Check if AdaptiveEngine is available.

        Returns:
            bool: True if engine is available
        """
        if not self.engine_available:
            error = EngineInitializationError("AdaptiveEngine components not available")
            self._handle_error(
                error,
                "adaptive_engine_initialization",
                ErrorSeverity.CRITICAL if ERROR_HANDLER_AVAILABLE else None,
                suggestions=[
                    "Check if core.adaptive_engine module is installed",
                    "Verify all dependencies are available",
                    "Try running in legacy mode",
                ],
            )
            return False
        return True

    def _create_config_safe(self, args: Any) -> bool:
        """
        Create configuration from args with error handling.

        Args:
            args: CLI arguments

        Returns:
            bool: True if config created successfully
        """
        try:
            self.config = create_config_from_args(args)
            self._metrics.mode = self.config.mode
            return True
        except Exception as e:
            error = ConfigurationError(f"Failed to create configuration: {e}")
            self._handle_error(error, "configuration_creation")
            return False

    def _initialize_engine_safe(self, args: Any, domain: str) -> bool:
        """
        Initialize engine with error handling and domain setup.

        Args:
            args: CLI arguments
            domain: Target domain

        Returns:
            bool: True if engine initialized successfully
        """
        try:
            self.engine = self._initialize_engine(args)

            # CRITICAL FIX: Set target domain in engine for discovery mode
            if hasattr(self.engine, "bypass_engine") and self.engine.bypass_engine:
                if hasattr(self.engine.bypass_engine, "set_target_domain"):
                    self.engine.bypass_engine.set_target_domain(domain)
                    if not self.cli_config.quiet:
                        self.console.print(
                            f"[green]🎯 Target domain set in bypass engine: {domain}[/green]"
                        )

            # Update StrategySaver with engine reference for TestResultCoordinator access
            self.strategy_saver.engine = self.engine
            return True
        except Exception as e:
            self._handle_error(e, "adaptive_engine_initialization")
            return False

    def _stop_pcap_capture_safe(self, pcap_capturer: Any) -> None:
        """
        Stop PCAP capture with error handling.

        Args:
            pcap_capturer: PCAP capturer instance or None
        """
        if self._pcap_manager:
            self._pcap_manager.stop_pcap_capture_safe(pcap_capturer)
            return
        # Fallback to old behavior
        if pcap_capturer:
            try:
                pcap_capturer.stop_capture()
            except (AttributeError, RuntimeError) as e:
                LOG.debug(f"Error stopping PCAP capture: {e}")
            except Exception as e:
                LOG.error(f"Unexpected error stopping PCAP capture: {e}", exc_info=True)

    def _get_engine_stats_safe(self) -> Dict[str, Any]:
        """
        Get engine statistics with error handling.

        Returns:
            Dict with engine stats or empty dict
        """
        stats = {}
        if self.engine:
            try:
                stats = self.engine.get_stats()
            except (AttributeError, TypeError) as e:
                LOG.warning(f"Failed to get engine stats (attribute/type error): {e}")
            except Exception as e:
                LOG.error(f"Unexpected error getting engine stats: {e}", exc_info=True)
        return stats

    def _enable_verbose_logging(self, engine: Any) -> None:
        """Enable verbose strategy logging."""
        try:
            bypass_engine = engine.bypass_engine
            if hasattr(bypass_engine, "engine"):
                bypass_engine = bypass_engine.engine

            if hasattr(bypass_engine, "_domain_strategy_engine"):
                domain_engine = bypass_engine._domain_strategy_engine
                if domain_engine and hasattr(domain_engine, "set_verbose_mode"):
                    log_file = f"verbose_strategy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                    domain_engine.set_verbose_mode(True, log_file)
                    self.console.print("[green]✅ Verbose strategy logging enabled[/green]")
                    self.console.print(f"[dim]Logs will be written to: {log_file}[/dim]")
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not enable verbose logging: {e}[/yellow]")

    def _setup_pcap_capture(self, domain: str) -> Tuple[Any, Optional[Path]]:
        """Setup PCAP capture if enabled with discovery mode filtering."""
        if not self.config or not self.engine:
            return None, None

        # Initialize PCAP manager lazily
        self._pcap_manager = PCAPCaptureManager(
            console=self.console,
            config=self.config,
            engine=self.engine,
            quiet=self.cli_config.quiet,
        )
        return self._pcap_manager.setup_pcap_capture(domain)

    def _should_use_discovery_mode(self, args: Any) -> bool:
        """
        Determine if discovery mode should be used based on CLI arguments.

        Discovery mode is enabled when:
        - Auto-discovery flag is set, OR
        - Mode is comprehensive or deep, OR
        - Max trials is high (>= 20)

        Args:
            args: CLI arguments

        Returns:
            bool: True if discovery mode should be used
        """
        # Delegate to coordinator to keep logic in one place
        try:
            return self._discovery_mode.should_use_discovery_mode(args)
        except Exception:
            # Fallback to conservative behavior
            return bool(getattr(args, "auto_discovery", False))

    async def _run_discovery_mode_analysis(self, domain: str, args: Any) -> bool:
        """
        Run analysis using the discovery system for enhanced strategy diversity and domain filtering.

        Args:
            domain: Target domain name
            args: CLI arguments object

        Returns:
            bool: True if analysis was successful
        """
        # Delegate discovery session orchestration to DiscoveryModeCoordinator.
        # IMPORTANT: We intentionally re-use existing wrapper analysis functions to preserve
        # export/save behavior and minimize regression risk.
        try:
            # Let coordinator manage: pre-check + start_discovery + stop_discovery
            # Use _run_standard_analysis as "discovery-enhanced" analysis function:
            # discovery system may influence strategy generation while standard analysis runs.
            return await self._discovery_mode.run_discovery_mode_analysis(
                domain=domain,
                args=args,
                engine=self.engine,
                config=self.config,
                metrics=self._metrics,
                handle_error_func=self._handle_error,
                run_standard_analysis_func=self._run_standard_analysis,
                run_discovery_enhanced_analysis_func=getattr(
                    self, "_run_discovery_enhanced_analysis", self._run_standard_analysis
                ),
            )
        except Exception as e:
            LOG.error(
                "[RID:%s] Discovery mode delegation failed: %s", self._rid(), e, exc_info=True
            )
            # Fallback to standard analysis
            return await self._run_standard_analysis(domain, args)

    async def _run_standard_analysis(self, domain: str, args: Any) -> bool:
        """
        Run standard analysis without discovery system.

        Args:
            domain: Target domain name
            args: CLI arguments object

        Returns:
            bool: True if analysis was successful
        """
        # Check engine availability
        if not self._check_engine_availability():
            return False

        # Create configuration
        if not self._create_config_safe(args):
            return False

        # Display banner
        if not self.cli_config.quiet:
            self.output_strategy.display_banner(domain, self.config)

        # Initialize engine
        if not self._initialize_engine_safe(args, domain):
            return False

        # Setup PCAP capture if enabled
        pcap_capturer, shared_pcap_file = self._setup_pcap_capture(domain)

        # Run analysis
        try:
            result = await self._run_analysis_with_timeout(domain, shared_pcap_file)

            # IMPORTANT: Add delay to ensure PCAP captures strategy testing traffic
            if pcap_capturer and getattr(self.config, "verify_with_pcap", False):
                LOG.info("⏳ Waiting additional time to capture strategy testing traffic...")
                await asyncio.sleep(3.0)  # Give time for strategy testing to complete

        except asyncio.TimeoutError:
            error = TimeoutError(f"Analysis timed out after {self.cli_config.timeout}s")
            self._handle_error(
                error,
                "adaptive_analysis",
                suggestions=[
                    "Try with --mode quick for faster analysis",
                    "Increase timeout or reduce --max-trials",
                    "Check network connectivity",
                ],
            )
            return False
        except Exception as e:
            self._handle_error(e, "adaptive_analysis")
            return False
        finally:
            # Stop PCAP capture
            self._stop_pcap_capture_safe(pcap_capturer)

        # Calculate execution time
        self._metrics.end_time = get_monotonic_time()
        self._metrics.execution_time = self._metrics.duration

        # Get engine stats
        stats = self._get_engine_stats_safe()

        # Display and export results
        return self._finalize_results(domain, result, stats, args)

    def _configure_bypass_engine_pcap(self, pcap_file: Path) -> None:
        """Configure bypass engine to write to shared PCAP file."""
        # Configure bypass engine to write to shared PCAP
        # AdaptiveEngine.bypass_engine -> UnifiedBypassEngine
        # UnifiedBypassEngine.engine -> WindowsBypassEngine
        bypass_engine = None
        if hasattr(self.engine, "bypass_engine"):
            bypass_engine = self.engine.bypass_engine
            # If it's UnifiedBypassEngine, get the inner engine
            if hasattr(bypass_engine, "engine"):
                bypass_engine = bypass_engine.engine

        if bypass_engine and hasattr(bypass_engine, "set_shared_pcap_file"):
            try:
                bypass_engine.set_shared_pcap_file(str(pcap_file))
                LOG.info(f"📝 Bypass engine configured to write to shared PCAP: {pcap_file}")
            except Exception as e:
                LOG.warning(f"⚠️ Failed to set shared PCAP file: {e}")

    async def _run_analysis_with_timeout(
        self,
        domain: str,
        shared_pcap_file: Optional[Path],
    ) -> Any:
        """Run analysis with timeout and progress display."""
        # Check if we can use Rich Progress
        can_use_progress = (
            RICH_AVAILABLE
            and self.cli_config.show_progress
            and not self.cli_config.quiet
            and not isinstance(self.console, FallbackConsole)
        )

        if can_use_progress:
            try:
                return await self._run_with_rich_progress(domain, shared_pcap_file)
            except Exception as e:
                LOG.debug(f"Rich Progress failed: {e}, falling back")

        # Fallback without progress
        if not self.cli_config.quiet:
            self.console.print("Running adaptive analysis...")

        return await asyncio.wait_for(
            self.engine.find_best_strategy(
                domain,
                self._progress_callback,
                shared_pcap_file=shared_pcap_file,
            ),
            timeout=self.cli_config.timeout or 300.0,
        )

    async def _run_with_rich_progress(
        self,
        domain: str,
        shared_pcap_file: Optional[Path],
    ) -> Any:
        """Run analysis with Rich progress display."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Running adaptive analysis...", total=None)

            result = await asyncio.wait_for(
                self.engine.find_best_strategy(
                    domain,
                    self._progress_callback,
                    shared_pcap_file=shared_pcap_file,
                ),
                timeout=self.cli_config.timeout or 300.0,
            )

            progress.update(task, completed=True)
            return result

    def _finalize_results(
        self,
        domain: str,
        result: Any,
        stats: Dict[str, Any],
        args: Any,
    ) -> bool:
        """Display results and export if needed."""
        if not result:
            error = AnalysisError("No result returned from analysis")
            self._handle_error(error, "adaptive_analysis")
            return False

        # Update metrics
        self._metrics.success = result.success
        self._metrics.trials_count = getattr(result, "trials_count", 0)
        self._metrics.fingerprint_updated = getattr(result, "fingerprint_updated", False)

        # Display results
        self.output_strategy.display_results(result, self._metrics.execution_time, stats)

        # Export if requested
        if self.cli_config.export_file:
            # inject run_id for exporter without changing signature
            try:
                stats = dict(stats or {})
                stats["_run_id"] = self._rid()
            except Exception:  # nosec B110 - Intentional: non-critical metadata injection
                pass
            self.exporter.export_to_json(
                domain,
                result,
                self._metrics.execution_time,
                stats,
                self.cli_config.export_file,
                self.progress_messages,
            )

        # Save legacy strategy
        if self.cli_config.save_legacy:
            self.strategy_saver.save_legacy_strategy(domain, result, self._original_domain)

        # Display error summary
        if self.error_handler:
            self.error_handler.display_summary()

        # Export diagnostics if requested
        if getattr(args, "export_diagnostics", False) and self.engine:
            self._export_diagnostics(domain)

        return result.success

    def _export_diagnostics(self, domain: str) -> None:
        """Export diagnostics to file."""
        try:
            diag_file = f"diagnostics_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            if self.engine.export_diagnostics(diag_file):
                self.console.print(f"[green]✓ Diagnostics exported to: {diag_file}[/green]")
        except Exception as e:
            LOG.warning(f"Failed to export diagnostics: {e}")

    def _handle_error(
        self,
        error: Exception,
        context: str,
        severity: Any = None,
        suggestions: List[str] = None,
    ) -> None:
        """Handle error with appropriate output."""
        if self.error_handler and severity:
            self.error_handler.handle_error(
                error,
                severity,
                ErrorContext(
                    operation=context,
                    component="AdaptiveCLIWrapper",
                    user_action=f"during {context}",
                    debug_info={"run_id": self._rid()},
                    suggestions=suggestions,
                ),
            )
        else:
            self.output_strategy.display_error(error, context)
            if self.cli_config.verbose:
                traceback.print_exc()

    # --------------------------------------------------------------------
    # Discovery callbacks (BACKWARD COMPATIBILITY)
    # Some legacy discovery-mode code paths (or older DiscoveryController API)
    # may still reference these methods on AdaptiveCLIWrapper.
    # Keep them to avoid runtime AttributeError.
    # --------------------------------------------------------------------

    def _discovery_strategy_callback(self, strategy: Any) -> bool:
        """
        Callback for discovery system strategy testing.
        Backward-compatible wrapper around coordinator behavior.
        """
        try:
            if not self.cli_config.quiet:
                name = getattr(strategy, "name", "unknown")
                self._print(f"[dim]🧪 Testing discovery strategy: {name}[/dim]")
            return True
        except Exception as e:
            LOG.warning("[RID:%s] Error in discovery strategy callback: %s", self._rid(), e)
            return False

    def _discovery_progress_callback(self, progress_data: Dict[str, Any]) -> None:
        """
        Callback for discovery system progress updates.
        Backward-compatible wrapper.
        """
        try:
            if self.cli_config.quiet:
                return
            strategies_tested = progress_data.get("strategies_tested", 0)
            max_strategies = progress_data.get("max_strategies", 0)
            progress_percent = progress_data.get("progress_percent", 0.0)
            current_strategy = progress_data.get("current_strategy")

            if current_strategy:
                self._print(
                    f"[dim]🔍 Discovery progress: {strategies_tested}/{max_strategies} "
                    f"({progress_percent:.1f}%) - {current_strategy}[/dim]"
                )
            else:
                self._print(
                    f"[dim]🔍 Discovery progress: {strategies_tested}/{max_strategies} "
                    f"({progress_percent:.1f}%)[/dim]"
                )
        except Exception as e:
            LOG.debug("[RID:%s] discovery progress callback failed: %s", self._rid(), e)

    async def _run_discovery_enhanced_analysis(self, domain: str, args: Any) -> bool:
        """
        Optional hook: if DiscoveryModeCoordinator calls this method.
        Keep as fallback to standard analysis to preserve behavior.
        """
        return await self._run_standard_analysis(domain, args)

    # ========================================================================
    # BATCH PROCESSING
    # ========================================================================

    async def run_batch_adaptive_analysis(
        self,
        domains: List[str],
        args: Any,
    ) -> Dict[str, bool]:
        """
        Run batch adaptive analysis using BatchAnalyzer.

        Args:
            domains: List of domains to analyze
            args: CLI arguments

        Returns:
            Dict mapping domains to success status
        """
        cfg = create_config_from_args(args)
        # Create batch analyzer
        batch_analyzer = BatchAnalyzer(
            console=self.console,
            engine=self.engine or AdaptiveEngine(cfg),
            config=cfg,
            quiet=self.cli_config.quiet,
        )

        # Run batch analysis
        results = await batch_analyzer.run_batch_analysis(domains, get_monotonic_time)

        # Export summary
        # Note: BatchAnalyzer handles summary display internally
        # Export is done via exporter if needed
        return results


# ============================================================================
# FACTORY FUNCTION
# ============================================================================


def create_cli_wrapper_from_args(args: Any) -> AdaptiveCLIWrapper:
    """
    Create AdaptiveCLIWrapper from CLI arguments.

    Args:
        args: CLI arguments object

    Returns:
        Configured AdaptiveCLIWrapper
    """
    cli_config = CLIConfig(
        verbose=getattr(args, "debug", False),
        quiet=getattr(args, "quiet", False),
        no_colors=not RICH_AVAILABLE,
        export_file=getattr(args, "export_results", None),
        save_legacy=True,
        show_progress=True,
        timeout=300.0,
    )

    return AdaptiveCLIWrapper(cli_config)
