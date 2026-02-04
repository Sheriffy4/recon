"""
Discovery mode integration for AdaptiveCLIWrapper.

This module provides enhanced strategy discovery with domain filtering,
integrating the discovery system for improved strategy diversity and testing.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG = logging.getLogger("AdaptiveCLIWrapper.DiscoveryMode")


# ============================================================================
# DISCOVERY MODE COORDINATOR
# ============================================================================


class DiscoveryModeCoordinator:
    """
    Coordinates discovery mode analysis with enhanced strategy diversity.

    Features:
    - Domain accessibility pre-check
    - Discovery system integration
    - Strategy diversity optimization
    - Domain filtering for PCAP capture
    """

    def __init__(
        self,
        console: Any,
        cli_config: Any,
        output_strategy: Any,
        error_handler: Any = None,
    ):
        """
        Initialize discovery mode coordinator.

        Args:
            console: Console for output
            cli_config: CLI configuration
            output_strategy: Output strategy for display
            error_handler: Optional error handler
        """
        self.console = console
        self.cli_config = cli_config
        self.output_strategy = output_strategy
        self.error_handler = error_handler

        # Discovery system state
        self._discovery_controller = None
        self._discovery_session_id: Optional[str] = None
        self._batch_discovery_mode = False

    def should_use_discovery_mode(self, args: Any) -> bool:
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
        # Check for explicit discovery flag
        if getattr(args, "auto_discovery", False):
            return True

        # Check for comprehensive modes that benefit from discovery
        mode = getattr(args, "mode", "balanced")
        if mode in ["comprehensive", "deep"]:
            return True

        # Check for high trial counts that suggest thorough testing
        max_trials = getattr(args, "max_trials", None)
        if max_trials and max_trials >= 20:
            return True

        # Check if optimization mode is enabled
        if getattr(args, "optimize", False):
            return True

        return False

    async def run_discovery_mode_analysis(
        self,
        domain: str,
        args: Any,
        engine: Any,
        config: Any,
        metrics: Any,
        handle_error_func: callable,
        run_standard_analysis_func: callable,
        run_discovery_enhanced_analysis_func: callable,
    ) -> bool:
        """
        Run analysis using the discovery system for enhanced strategy diversity.

        Args:
            domain: Target domain name
            args: CLI arguments object
            engine: AdaptiveEngine instance
            config: Analysis configuration
            metrics: Analysis metrics
            handle_error_func: Error handling function
            run_standard_analysis_func: Fallback to standard analysis
            run_discovery_enhanced_analysis_func: Run discovery-enhanced analysis

        Returns:
            bool: True if analysis was successful
        """
        if not self.cli_config.quiet:
            self.console.print("[bold blue]🔍 Discovery Mode Enabled[/bold blue]")
            self.console.print("[dim]Using advanced strategy discovery with domain filtering[/dim]")

        # Pre-check domain accessibility
        if not await self._check_domain_accessibility(domain, engine):
            # Domain is accessible, skip discovery
            return True

        try:
            # Import discovery system components
            from core.discovery_controller import DiscoveryController, create_discovery_config

            # Initialize discovery controller
            self._discovery_controller = DiscoveryController()

            # Create discovery configuration
            max_strategies = self._calculate_max_strategies(args, config)

            # Ensure timeout is not None
            timeout_value = self.cli_config.timeout
            if timeout_value is None:
                timeout_value = 300.0
                LOG.warning(f"⚠️ CLI timeout was None, using default: {timeout_value}s")

            discovery_config = create_discovery_config(
                target_domain=domain,
                max_strategies=max_strategies,
                max_duration_seconds=int(timeout_value),
                pcap_enabled=(
                    getattr(config, "verify_with_pcap", False) if config is not None else False
                ),
                prefer_untested=True,
                override_domain_rules=True,
                restore_rules_on_completion=True,
            )

            # Start discovery session
            self._discovery_session_id = self._discovery_controller.start_discovery(
                discovery_config,
                strategy_callback=self._discovery_strategy_callback,
                progress_callback=self._discovery_progress_callback,
            )

            if not self.cli_config.quiet:
                self.console.print(
                    f"[green]✓ Discovery session started: {self._discovery_session_id}[/green]"
                )
                self.console.print(
                    f"[dim]Max strategies: {max_strategies}, Timeout: {self.cli_config.timeout}s[/dim]"
                )

            # Run discovery-enhanced analysis
            result = await run_discovery_enhanced_analysis_func(domain, args)

            return result

        except ImportError as e:
            if not self.cli_config.quiet:
                self.console.print(f"[yellow]⚠️ Discovery system not available: {e}[/yellow]")
                self.console.print("[yellow]Falling back to standard analysis mode[/yellow]")

            # Fallback to standard analysis
            return await run_standard_analysis_func(domain, args)

        except (ValueError, TypeError) as e:
            LOG.error(f"Configuration error in discovery mode: {e}")
            handle_error_func(e, "discovery_mode_configuration")

            # Fallback to standard analysis
            if not self.cli_config.quiet:
                self.console.print("[yellow]Falling back to standard analysis mode[/yellow]")
            return await run_standard_analysis_func(domain, args)

        except Exception as e:
            LOG.error(f"Unexpected error in discovery mode initialization: {e}", exc_info=True)
            handle_error_func(e, "discovery_mode_initialization")

            # Fallback to standard analysis
            if not self.cli_config.quiet:
                self.console.print("[yellow]Falling back to standard analysis mode[/yellow]")
            return await run_standard_analysis_func(domain, args)

        finally:
            # Clean up discovery session
            self._cleanup_discovery_session()

    async def _check_domain_accessibility(self, domain: str, engine: Any) -> bool:
        """
        Check if domain is accessible before running discovery.

        Returns:
            bool: True if domain needs bypass (should continue with discovery)
        """
        if not self.cli_config.quiet:
            self.console.print(
                "[cyan]🔍 Checking domain accessibility before strategy discovery...[/cyan]"
            )

        try:
            # Create temporary engine for accessibility check
            from core.adaptive_refactored.facade import AdaptiveConfig, AdaptiveEngine

            temp_config = AdaptiveConfig()
            temp_engine = AdaptiveEngine(temp_config)

            # Check domain accessibility
            is_accessible = await temp_engine._is_domain_accessible(domain)

            # Known domains that need bypass check even if accessible
            known_subdomain_domains = [
                "googlevideo.com",
                "ytimg.com",
                "ggpht.com",
                "youtube.com",
                "ytimg.l.google.com",
            ]

            domain_needs_bypass_check = any(
                subdomain_domain in domain for subdomain_domain in known_subdomain_domains
            )

            if is_accessible and not domain_needs_bypass_check:
                if not self.cli_config.quiet:
                    self.console.print(
                        "[green]✅ Domain is accessible without bypass - skipping strategy discovery[/green]"
                    )
                return False  # Don't need discovery

            elif is_accessible and domain_needs_bypass_check:
                if not self.cli_config.quiet:
                    self.console.print(
                        "[yellow]ℹ️ Domain accessible but requires bypass testing for subdomains[/yellow]"
                    )
            else:
                if not self.cli_config.quiet:
                    self.console.print(
                        "[red]🚫 Domain blocked - proceeding with strategy discovery[/red]"
                    )

            return True  # Need discovery

        except Exception as e:
            LOG.warning(f"Domain accessibility check failed: {e}")
            if not self.cli_config.quiet:
                self.console.print(f"[yellow]⚠️ Could not check domain accessibility: {e}[/yellow]")
                self.console.print("[yellow]Proceeding with strategy discovery...[/yellow]")
            return True  # Assume need discovery on error

    def _calculate_max_strategies(self, args: Any, config: Any) -> int:
        """Calculate maximum strategies for discovery mode."""
        max_strategies = getattr(args, "max_trials", None)
        if not max_strategies:
            from .data_models import AnalysisMode

            mode = getattr(args, "mode", "balanced")
            max_strategies = AnalysisMode(mode).max_trials

        # Increase strategy count for discovery mode
        max_strategies = min(max_strategies * 2, 100)  # Double strategies but cap at 100
        return max_strategies

    def _cleanup_discovery_session(self) -> None:
        """Clean up discovery session."""
        if self._discovery_controller and self._discovery_session_id:
            try:
                report = self._discovery_controller.stop_discovery(
                    self._discovery_session_id, "Analysis completed"
                )

                if not self.cli_config.quiet:
                    self.console.print(
                        f"[dim]Discovery session completed. Strategies tested: {report.aggregated_stats.total_tests}[/dim]"
                    )

            except (AttributeError, KeyError) as e:
                LOG.warning(f"Error accessing discovery report: {e}")
            except Exception as e:
                LOG.error(f"Unexpected error stopping discovery session: {e}", exc_info=True)

    def _discovery_strategy_callback(self, strategy) -> bool:
        """
        Callback for discovery system strategy testing.

        Args:
            strategy: Strategy variation to test

        Returns:
            bool: True if strategy should continue to be tested
        """
        try:
            if not self.cli_config.quiet:
                self.console.print(f"[dim]🧪 Testing discovery strategy: {strategy.name}[/dim]")
            return True
        except Exception as e:
            LOG.warning(f"Error in discovery strategy callback: {e}")
            return False

    def _discovery_progress_callback(self, progress_data: Dict[str, Any]) -> None:
        """
        Callback for discovery system progress updates.

        Args:
            progress_data: Progress information from discovery system
        """
        try:
            if not self.cli_config.quiet:
                _ = progress_data.get("session_id", "unknown")
                strategies_tested = progress_data.get("strategies_tested", 0)
                max_strategies = progress_data.get("max_strategies", 0)
                current_strategy = progress_data.get("current_strategy")
                progress_percent = progress_data.get("progress_percent", 0)

                if current_strategy:
                    self.console.print(
                        f"[dim]🔍 Discovery progress: {strategies_tested}/{max_strategies} ({progress_percent:.1f}%) - {current_strategy}[/dim]"
                    )
                else:
                    self.console.print(
                        f"[dim]🔍 Discovery progress: {strategies_tested}/{max_strategies} ({progress_percent:.1f}%)[/dim]"
                    )

        except Exception as e:
            LOG.warning(f"Error in discovery progress callback: {e}")

    def set_discovery_controller(self, controller) -> None:
        """
        Set the discovery controller for enhanced strategy discovery.

        Args:
            controller: DiscoveryController instance
        """
        self._discovery_controller = controller
        LOG.info("Discovery controller configured for CLI wrapper")

    def set_batch_discovery_mode(self, enabled: bool) -> None:
        """
        Enable or disable discovery mode for batch processing.

        Args:
            enabled: Whether to enable discovery mode for batch processing
        """
        self._batch_discovery_mode = enabled
        if enabled:
            LOG.info("Batch discovery mode enabled")
        else:
            LOG.info("Batch discovery mode disabled")

    @property
    def discovery_controller(self):
        """Get discovery controller."""
        return self._discovery_controller

    @property
    def discovery_session_id(self):
        """Get discovery session ID."""
        return self._discovery_session_id


# ============================================================================
# DISCOVERY STRATEGY TESTER
# ============================================================================


class DiscoveryStrategyTester:
    """
    Tests strategies provided by the discovery system.

    Handles strategy conversion, testing, and result reporting back to
    the discovery system.
    """

    def __init__(
        self,
        console: Any,
        cli_config: Any,
        engine: Any,
        discovery_coordinator: DiscoveryModeCoordinator,
    ):
        """
        Initialize discovery strategy tester.

        Args:
            console: Console for output
            cli_config: CLI configuration
            engine: AdaptiveEngine instance
            discovery_coordinator: Discovery mode coordinator
        """
        self.console = console
        self.cli_config = cli_config
        self.engine = engine
        self.discovery_coordinator = discovery_coordinator

    async def test_discovery_strategies(
        self, domain: str, strategies: List[Any], shared_pcap_file: Optional[Path], config: Any
    ) -> Any:
        """
        Test strategies provided by the discovery system.

        Args:
            domain: Target domain
            strategies: List of strategy variations from discovery system
            shared_pcap_file: Optional shared PCAP file path
            config: Analysis configuration

        Returns:
            Analysis result
        """
        best_result = None
        best_success_rate = 0.0

        for i, strategy in enumerate(strategies, 1):
            if not self.cli_config.quiet:
                self.console.print(
                    f"[cyan]🧪 Testing strategy {i}/{len(strategies)}: {strategy.name}[/cyan]"
                )

            try:
                # Convert discovery strategy to engine format
                engine_strategy = self._convert_discovery_strategy(strategy)

                # Test the strategy
                result = await self.engine.test_single_strategy(
                    domain, engine_strategy, shared_pcap_file=shared_pcap_file
                )

                # Mark strategy as tested in discovery system
                self._mark_strategy_tested(domain, strategy, result)

                # Track best result
                if result.success:
                    current_success_rate = getattr(result, "success_rate", 1.0)
                    if current_success_rate > best_success_rate:
                        best_result = result
                        best_success_rate = current_success_rate

                    if not self.cli_config.quiet:
                        self.console.print(f"[green]✓ Strategy succeeded: {strategy.name}[/green]")

                    # Stop on first success if configured
                    if config.stop_on_success:
                        break
                else:
                    if not self.cli_config.quiet:
                        self.console.print(f"[red]✗ Strategy failed: {strategy.name}[/red]")

            except Exception as e:
                LOG.warning(f"Error testing discovery strategy {strategy.name}: {e}")
                if not self.cli_config.quiet:
                    self.console.print(f"[yellow]⚠️ Error testing {strategy.name}: {e}[/yellow]")
                continue

        # Return best result or create failure result
        if best_result:
            return best_result
        else:
            # Create a failure result
            from .fallback_compat import FallbackStrategyResult

            failure_result = FallbackStrategyResult()
            failure_result.success = False
            failure_result.message = f"All {len(strategies)} discovery strategies failed"
            failure_result.trials_count = len(strategies)
            return failure_result

    def _mark_strategy_tested(self, domain: str, strategy: Any, result: Any) -> None:
        """Mark strategy as tested in discovery system."""
        controller = self.discovery_coordinator.discovery_controller
        session_id = self.discovery_coordinator.discovery_session_id

        if controller and session_id:
            success_rate = getattr(result, "success_rate", 0.0) if result.success else 0.0
            test_results = {
                "domain": domain,
                "strategy_name": strategy.name,
                "success": result.success,
                "success_rate": success_rate,
                "message": result.message,
            }

            controller.mark_strategy_tested(session_id, strategy, success_rate, test_results)

    def _convert_discovery_strategy(self, discovery_strategy: Any) -> Any:
        """
        Convert a discovery system strategy to engine format.

        Args:
            discovery_strategy: Strategy variation from discovery system

        Returns:
            Strategy in engine format
        """
        try:
            # Extract strategy information
            strategy_name = discovery_strategy.name
            attack_types = getattr(discovery_strategy, "attack_types", [])
            parameters = getattr(discovery_strategy, "parameters", {})

            # Create engine-compatible strategy
            if hasattr(self.engine, "create_strategy"):
                return self.engine.create_strategy(
                    name=strategy_name, attack_types=attack_types, parameters=parameters
                )
            else:
                # Fallback: create a simple strategy object
                class SimpleStrategy:
                    def __init__(self, name, attack_types, parameters):
                        self.name = name
                        self.attack_combination = attack_types
                        self.parameters = parameters
                        self.type = attack_types[0] if attack_types else "unknown"

                return SimpleStrategy(strategy_name, attack_types, parameters)

        except Exception as e:
            LOG.warning(f"Error converting discovery strategy: {e}")

            # Return a fallback strategy
            class FallbackStrategy:
                def __init__(self):
                    self.name = "fallback"
                    self.attack_combination = ["fake"]
                    self.parameters = {"ttl": 3}
                    self.type = "fake"

            return FallbackStrategy()
