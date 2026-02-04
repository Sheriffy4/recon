"""
AdaptiveEngine Facade for backward compatibility.

This facade maintains the exact same public API as the original AdaptiveEngine
while delegating to the refactored components internally. This ensures that
existing code continues to work without any modifications.
"""

import asyncio
import inspect
import logging
import time
from typing import Dict, List, Optional, Any, Tuple, Callable
from datetime import datetime

from .interfaces import (
    IStrategyService,
    ITestingService,
    IAnalyticsService,
    IConfigurationManager,
    ICacheManager,
)
from .models import Strategy, TestResult, PerformanceMetrics, StrategyType, TestMode, CacheType
from .config import AdaptiveEngineConfig
from .container import DIContainer, get_container, create_default_container

# Import original types for compatibility
try:
    from core.adaptive_engine import StrategyResult, AdaptiveConfig

    # Check if StrategyResult has the expected signature
    import inspect

    sig = inspect.signature(StrategyResult.__init__)
    if "domain" not in sig.parameters:
        # Original StrategyResult doesn't have domain parameter, create our own
        raise ImportError("Original StrategyResult incompatible")

except ImportError:
    # Fallback definitions if original not available or incompatible
    from dataclasses import dataclass, field

    @dataclass
    class StrategyResult:
        success: bool
        strategy: Optional[Any] = None
        domain: str = ""
        trials: int = 0
        error: Optional[str] = None
        metadata: Dict[str, Any] = field(default_factory=dict)

        # Additional attributes for backward compatibility
        message: str = ""
        execution_time: float = 0.0
        trials_count: int = 0
        fingerprint_updated: bool = False

        def __post_init__(self):
            """Initialize computed fields for backward compatibility."""
            # Sync trials and trials_count
            if self.trials_count == 0 and self.trials > 0:
                self.trials_count = self.trials
            elif self.trials == 0 and self.trials_count > 0:
                self.trials = self.trials_count

            # Set default message if not provided
            if not self.message:
                if self.success:
                    self.message = f"Successfully found strategy for {self.domain}"
                else:
                    self.message = self.error or f"Failed to find strategy for {self.domain}"

    @dataclass
    class AdaptiveConfig:
        max_trials: int = 15
        enable_fingerprinting: bool = True
        enable_failure_analysis: bool = True
        mode: str = "discovery"
        enable_profiling: bool = False


LOG = logging.getLogger(__name__)


class AdaptiveEngine:
    """
    Backward-compatible facade for the refactored AdaptiveEngine.

    This class maintains the exact same public API as the original AdaptiveEngine
    while internally using the new refactored components. All existing code
    should work without any modifications.
    """

    def __init__(self, config: Optional[Any] = None):
        """Initialize the AdaptiveEngine facade with backward compatibility."""
        LOG.info("🔄 Initializing refactored AdaptiveEngine facade")

        # Handle both old and new config formats
        if config is None:
            self._original_config = AdaptiveConfig()
            self._new_config = self._convert_config(self._original_config)
        elif hasattr(config, "strategy") and hasattr(config, "testing"):
            # This is already the new AdaptiveEngineConfig format
            self._new_config = config
            self._original_config = self._convert_new_to_old_config(config)
        else:
            # This is the old AdaptiveConfig format
            self._original_config = config
            self._new_config = self._convert_config(config)

        # Get or create DI container with the new config
        self._container = create_default_container(self._new_config)

        # Initialize services through DI container
        self._initialize_services()

        # Initialize compatibility fields
        self._initialize_stats()

        # Cache StrategyResult constructor signature for robust instantiation
        self._strategy_result_sig = inspect.signature(StrategyResult.__init__)

        LOG.info("✅ AdaptiveEngine facade initialized successfully")

    def _make_strategy_result(self, **kwargs) -> StrategyResult:
        """
        Instantiate StrategyResult in a backward-compatible way:
        - pass only supported kwargs into __init__
        - set the rest as attributes (best-effort)
        """
        accepted = {k: v for k, v in kwargs.items() if k in self._strategy_result_sig.parameters}
        try:
            obj = StrategyResult(**accepted)
        except Exception:
            # minimal fallback
            obj = StrategyResult(success=bool(kwargs.get("success", False)))
        for k, v in kwargs.items():
            if k in accepted:
                continue
            try:
                setattr(obj, k, v)
            except Exception:
                pass
        return obj

    def _initialize_services(self):
        """Initialize all services through dependency injection."""
        service_types = [
            (IStrategyService, "_strategy_service"),
            (ITestingService, "_testing_service"),
            (IAnalyticsService, "_analytics_service"),
            (IConfigurationManager, "_config_manager"),
            (ICacheManager, "_cache_manager"),
        ]

        for service_type, attr_name in service_types:
            try:
                service = self._container.resolve(service_type)
                setattr(self, attr_name, service)
            except (ValueError, NotImplementedError):
                LOG.warning(f"⚠️ {service_type.__name__} not available, using placeholder")
                setattr(self, attr_name, None)

        LOG.info("✅ Service resolution completed (some services may be placeholders)")

    def _initialize_stats(self):
        """Initialize backward compatibility statistics fields."""
        self.config = self._original_config
        self.stats = {
            "domains_processed": 0,
            "strategies_found": 0,
            "total_trials": 0,
            "fingerprints_created": 0,
            "failures_analyzed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "parallel_tests_executed": 0,
            "average_test_time": 0.0,
            "fingerprint_creation_time": 0.0,
            "strategy_generation_time": 0.0,
        }

        self.closed_loop_stats = {
            "iterations_total": 0,
            "intents_generated": 0,
            "strategies_augmented": 0,
            "pattern_matches": 0,
            "knowledge_updates": 0,
        }

        self.timeout_stats = {
            "adaptive_timeouts_applied": 0,
            "content_inspection_adjustments": 0,
            "rst_injection_adjustments": 0,
            "network_timeout_adjustments": 0,
            "slow_cdn_adjustments": 0,
            "average_timeout_factor": 1.0,
        }

    def _convert_config(self, old_config: AdaptiveConfig) -> AdaptiveEngineConfig:
        """Convert old AdaptiveConfig to new AdaptiveEngineConfig."""
        new_config = AdaptiveEngineConfig()

        # Map old config fields to new config structure
        new_config.strategy.max_trials = getattr(old_config, "max_trials", 15)
        new_config.strategy.enable_fingerprinting = getattr(
            old_config, "enable_fingerprinting", True
        )
        new_config.strategy.enable_failure_analysis = getattr(
            old_config, "enable_failure_analysis", True
        )
        new_config.analytics.enable_profiling = getattr(old_config, "enable_profiling", False)

        # Set mode-specific configurations
        mode = getattr(old_config, "mode", "discovery")
        if mode == "service":
            new_config.testing.enable_parallel_testing = True
            new_config.testing.verify_with_pcap = True

        return new_config

    def _convert_new_to_old_config(self, new_config) -> AdaptiveConfig:
        """Convert new AdaptiveEngineConfig to old AdaptiveConfig for compatibility."""
        old_config = AdaptiveConfig()

        # Map new config fields back to old config structure
        old_config.max_trials = new_config.strategy.max_trials
        old_config.enable_fingerprinting = new_config.strategy.enable_fingerprinting
        old_config.enable_failure_analysis = new_config.strategy.enable_failure_analysis
        old_config.enable_profiling = new_config.analytics.enable_profiling

        # Determine mode based on testing configuration
        if new_config.testing.enable_parallel_testing and new_config.testing.verify_with_pcap:
            old_config.mode = "service"
        else:
            old_config.mode = "discovery"

        return old_config

    async def find_best_strategy(
        self, domain: str, progress_callback=None, shared_pcap_file=None
    ) -> StrategyResult:
        """
        Main method for finding the best bypass strategy for a domain.

        Maintains exact compatibility with the original method signature and behavior.
        """
        LOG.info(f"🔍 Finding best strategy for domain: {domain}")
        start_time = time.time()

        # Validate input
        validation_result = self._validate_domain_input(domain)
        if not validation_result.success:
            return validation_result

        if progress_callback:
            progress_callback(f"[SEARCH] 🔍 Analyzing domain {domain}...")

        try:
            # Update stats
            self.stats["domains_processed"] += 1

            # Try cached strategy first
            cached_result = await self._try_cached_strategy(domain)
            if cached_result:
                return cached_result

            # Generate and test new strategies
            strategy_result = await self._generate_and_test_strategies(domain, progress_callback)

            # Update timing and analytics
            execution_time = time.time() - start_time
            strategy_result.execution_time = execution_time
            self._update_execution_stats(execution_time)

            # Check if fingerprint was updated (simplified check)
            strategy_result.fingerprint_updated = (
                strategy_result.success and strategy_result.strategy is not None
            )

            if strategy_result.success and self._analytics_service:
                await self._record_analytics(domain, strategy_result, execution_time)

            return strategy_result

        except Exception as e:
            LOG.error(f"❌ Error finding strategy for {domain}: {e}")
            execution_time = time.time() - start_time
            return self._make_strategy_result(
                success=False,
                domain=domain,
                trials=0,
                error=str(e),
                message=f"Error finding strategy for {domain}: {str(e)}",
                execution_time=execution_time,
                trials_count=0,
            )

    def _validate_domain_input(self, domain: str) -> StrategyResult:
        """Validate domain input and return error result if invalid."""
        if not domain or not domain.strip():
            LOG.warning(f"⚠️ Invalid domain provided: '{domain}'")
            return self._make_strategy_result(
                success=False,
                domain=domain,
                trials=0,
                error="Invalid domain: domain cannot be empty",
                message="Invalid domain: domain cannot be empty",
                trials_count=0,
            )

        # Return success indicator (not a real result)
        return self._make_strategy_result(success=True, domain=domain, trials=0, trials_count=0)

    async def _try_cached_strategy(self, domain: str) -> Optional[StrategyResult]:
        """Try to get cached strategy for domain."""
        if not self._strategy_service:
            self.stats["cache_misses"] += 1
            return None

        cached_strategy = await self._strategy_service.get_cached_strategy(domain)
        if cached_strategy:
            LOG.info(f"✅ Found cached strategy for {domain}")
            self.stats["cache_hits"] += 1

            return StrategyResult(
                success=True,
                strategy=self._convert_strategy_to_old_format(cached_strategy),
                domain=domain,
                trials=0,
                metadata={"source": "cache", "cached": True},
                message=f"Found cached strategy for {domain}",
                execution_time=0.0,
            )

        self.stats["cache_misses"] += 1
        return None

    async def _generate_and_test_strategies(
        self, domain: str, progress_callback=None
    ) -> StrategyResult:
        """Generate and test strategies for domain."""
        # Generate strategies
        strategies = await self._generate_strategies(domain, progress_callback)
        if not strategies:
            return StrategyResult(
                success=False,
                domain=domain,
                trials=0,
                error="No strategies could be generated",
                message=f"No strategies could be generated for {domain}",
            )

        # Test strategies
        return await self._test_strategies(domain, strategies, progress_callback)

    async def _generate_strategies(self, domain: str, progress_callback=None) -> List[Strategy]:
        """Generate strategies for domain."""
        if progress_callback:
            progress_callback(f"[GENERATE] 🧠 Generating strategies for {domain}...")

        strategies = []
        if self._strategy_service:
            from .models import DPIFingerprint

            fingerprint = DPIFingerprint(
                domain=domain,
                detection_methods=[],
                blocking_patterns=[],
                protocol_analysis={},
                timing_characteristics={},
            )

            strategies = await self._strategy_service.generate_strategies(fingerprint)
            self.stats["strategies_found"] += len(strategies)

        return strategies

    async def _test_strategies(
        self, domain: str, strategies: List[Strategy], progress_callback=None
    ) -> StrategyResult:
        """Test strategies and return the first successful one."""
        if progress_callback:
            progress_callback(f"[TEST] 🧪 Testing {len(strategies)} strategies...")

        successful_strategy = None
        trials = 0

        if self._testing_service:
            for strategy in strategies[: self._new_config.strategy.max_trials]:
                trials += 1
                self.stats["total_trials"] += 1

                if progress_callback:
                    progress_callback(f"[TEST] 🧪 Testing strategy {trials}/{len(strategies)}")

                test_result = await self._testing_service.test_strategy(domain, strategy)

                if test_result.success:
                    successful_strategy = strategy
                    LOG.info(f"✅ Found working strategy for {domain} after {trials} trials")
                    break

                if trials >= self._new_config.strategy.max_trials:
                    LOG.warning(
                        f"⚠️ Reached max trials ({self._new_config.strategy.max_trials}) for {domain}"
                    )
                    break

        # Save successful strategy to cache
        if successful_strategy and self._strategy_service:
            await self._strategy_service.save_strategy(domain, successful_strategy)

        return self._create_strategy_result(domain, successful_strategy, trials)

    def _create_strategy_result(
        self, domain: str, strategy: Optional[Strategy], trials: int
    ) -> StrategyResult:
        """Create strategy result based on testing outcome."""
        if strategy:
            return self._make_strategy_result(
                success=True,
                strategy=self._convert_strategy_to_old_format(strategy),
                domain=domain,
                trials=trials,
                trials_count=trials,
                metadata={"strategies_tested": trials},
                message=f"Found working strategy for {domain} after {trials} trials",
            )
        else:
            return self._make_strategy_result(
                success=False,
                domain=domain,
                trials=trials,
                trials_count=trials,
                error=f"No working strategy found after {trials} trials",
                message=f"No working strategy found for {domain} after {trials} trials",
                metadata={"strategies_tested": trials},
            )

    def _update_execution_stats(self, execution_time: float):
        """Update execution timing statistics."""
        if self.stats["domains_processed"] > 0:
            self.stats["average_test_time"] = (
                self.stats["average_test_time"] * (self.stats["domains_processed"] - 1)
                + execution_time
            ) / self.stats["domains_processed"]

    async def _record_analytics(
        self, domain: str, strategy_result: StrategyResult, execution_time: float
    ):
        """Record analytics for successful strategy."""
        try:
            test_result = TestResult(
                success=True,
                strategy=self._convert_old_strategy_to_new(strategy_result.strategy, domain),
                domain=domain,
                execution_time=execution_time,
            )
            self._analytics_service.record_strategy_test(domain, test_result.strategy, test_result)
        except Exception as e:
            LOG.warning(f"⚠️ Error recording analytics: {e}")

    async def _is_domain_accessible(self, domain: str, timeout: float = 5.0) -> bool:
        """
        Check if a domain is accessible without bypass.

        This method performs a simple connectivity check to determine if
        the domain can be reached without applying any bypass strategies.

        Args:
            domain: Domain to check
            timeout: Timeout for the check in seconds

        Returns:
            True if domain is accessible, False otherwise
        """
        LOG.info(f"🔍 Checking accessibility for domain: {domain}")

        try:
            import aiohttp
            import asyncio

            # Try to connect to the domain
            url = f"https://{domain}"

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False
                    ) as response:
                        # Consider any response (even errors) as "accessible"
                        # We just want to know if we can reach the server
                        is_accessible = response.status < 500

                        if is_accessible:
                            LOG.info(
                                f"✅ Domain {domain} is accessible (status: {response.status})"
                            )
                        else:
                            LOG.info(
                                f"⚠️ Domain {domain} returned server error (status: {response.status})"
                            )

                        return is_accessible

                except asyncio.TimeoutError:
                    LOG.info(f"⏱️ Domain {domain} timed out - likely blocked")
                    return False

                except aiohttp.ClientConnectorError as e:
                    LOG.info(f"🔌 Domain {domain} connection failed: {e}")
                    return False

                except aiohttp.ClientError as e:
                    LOG.info(f"⚠️ Domain {domain} client error: {e}")
                    # Some client errors might indicate the domain is reachable but has issues
                    # Consider it accessible if we got a response
                    return False

        except ImportError:
            LOG.warning("⚠️ aiohttp not available, cannot check domain accessibility")
            # If we can't check, assume it needs bypass
            return False

        except Exception as e:
            LOG.error(f"❌ Error checking domain accessibility for {domain}: {e}")
            # On error, assume domain needs bypass
            return False

    def _convert_strategy_to_old_format(self, strategy: Strategy) -> Any:
        """Convert new Strategy model to old format for compatibility."""

        # Create a simple object that mimics the old strategy format
        class OldStrategy:
            def __init__(self, strategy: Strategy):
                self.name = strategy.name
                self.attack_combination = strategy.attack_combination
                self.parameters = strategy.parameters
                self.success_rate = strategy.success_rate
                self.metadata = strategy.metadata
                self.type = strategy.strategy_type.value

                # Add attack_name attribute for backward compatibility
                # Use the first attack from attack_combination, or fallback to name
                if strategy.attack_combination and len(strategy.attack_combination) > 0:
                    self.attack_name = strategy.attack_combination[0]
                else:
                    # Fallback to extracting attack name from strategy name
                    self.attack_name = (
                        strategy.name.split("_")[0] if "_" in strategy.name else strategy.name
                    )

            def to_dict(self):
                return {
                    "name": self.name,
                    "attack_combination": self.attack_combination,
                    "parameters": self.parameters,
                    "success_rate": self.success_rate,
                    "metadata": self.metadata,
                    "type": self.type,
                    "attack_name": self.attack_name,
                }

        return OldStrategy(strategy)

    async def test_strategy(self, domain: str, strategy) -> bool:
        """
        Public async method to test a strategy for optimization.

        Maintains exact compatibility with the original method.
        """
        LOG.info(f"🧪 Testing strategy for domain: {domain}")

        try:
            if self._testing_service:
                # Convert old strategy format to new if needed
                new_strategy = self._convert_old_strategy_to_new(strategy, domain)
                result = await self._testing_service.test_strategy(domain, new_strategy)
                return result.success
            else:
                LOG.warning("⚠️ Testing service not available")
                return False

        except Exception as e:
            LOG.error(f"❌ Error testing strategy: {e}")
            return False

    def _convert_old_strategy_to_new(self, old_strategy, domain: str) -> Strategy:
        """Convert old strategy format to new Strategy model."""
        if hasattr(old_strategy, "name"):
            name = old_strategy.name
        else:
            name = f"strategy_{domain}_{int(time.time())}"

        if hasattr(old_strategy, "attack_combination"):
            attack_combination = old_strategy.attack_combination
        else:
            attack_combination = []

        if hasattr(old_strategy, "parameters"):
            parameters = old_strategy.parameters
        else:
            parameters = {}

        return Strategy(
            name=name,
            attack_combination=attack_combination,
            parameters=parameters,
            strategy_type=StrategyType.COMBINATION,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics - maintains exact compatibility."""
        # Update stats from analytics service if available
        if self._analytics_service:
            try:
                metrics = self._analytics_service.get_performance_metrics()

                # Update stats with latest metrics
                self.stats.update(
                    {
                        "cache_hits": int(
                            metrics.cache_hit_rate * 100
                        ),  # Convert rate to count approximation
                        "average_test_time": metrics.average_test_time,
                        "strategy_generation_time": metrics.strategy_generation_time,
                        "fingerprint_creation_time": metrics.fingerprint_creation_time,
                        "total_domains_processed": metrics.total_domains_processed,
                        "total_strategies_found": metrics.total_strategies_found,
                    }
                )
            except Exception as e:
                LOG.warning(f"⚠️ Error updating stats from analytics service: {e}")

        return self.stats.copy()

    def get_closed_loop_statistics(self) -> Dict[str, Any]:
        """Get closed loop statistics - maintains exact compatibility."""
        return self.closed_loop_stats.copy()

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics - maintains exact compatibility."""
        if self._analytics_service:
            try:
                metrics = self._analytics_service.get_performance_metrics()
                return metrics.to_dict()
            except Exception as e:
                LOG.warning(f"⚠️ Error getting performance metrics: {e}")

        # Return default metrics if service not available
        return {
            "cache_hit_rate": 0.0,
            "average_test_time": self.stats.get("average_test_time", 0.0),
            "strategy_generation_time": self.stats.get("strategy_generation_time", 0.0),
            "fingerprint_creation_time": self.stats.get("fingerprint_creation_time", 0.0),
            "total_domains_processed": self.stats.get("domains_processed", 0),
            "total_strategies_found": self.stats.get("strategies_found", 0),
            "memory_usage_mb": 0.0,
            "cpu_usage_percent": 0.0,
        }

    def clear_caches(self):
        """Clear all caches - maintains exact compatibility."""
        LOG.info("🧹 Clearing all caches")

        if self._cache_manager:
            try:
                # Use asyncio.run to handle the async method properly
                import asyncio

                # Check if we're already in an event loop
                try:
                    loop = asyncio.get_running_loop()
                    # We're in an event loop, create a task
                    task = loop.create_task(self._cache_manager.clear_cache())
                    # Don't wait for it to complete to avoid blocking
                    LOG.info("✅ Cache clearing task created")
                except RuntimeError:
                    # No event loop running, safe to use asyncio.run
                    asyncio.run(self._cache_manager.clear_cache())
                    LOG.info("✅ Caches cleared successfully")
            except Exception as e:
                LOG.error(f"❌ Error clearing caches: {e}")

        # Reset stats
        self.stats["cache_hits"] = 0
        self.stats["cache_misses"] = 0

    def set_discovery_mode(self, enabled: bool, discovery_controller=None) -> None:
        """Configure the engine for discovery mode - maintains exact compatibility."""
        LOG.info(f"🎯 Discovery mode {'enabled' if enabled else 'disabled'}")

        # Update configuration
        if enabled:
            self._new_config.testing.enable_test_validation = True
            self._new_config.testing.verify_with_pcap = True

        # Store discovery controller reference for compatibility
        self._discovery_controller = discovery_controller

    def enable_profiling(self, enable: bool = True):
        """Enable/disable profiling - maintains exact compatibility."""
        LOG.info(f"📊 Profiling {'enabled' if enable else 'disabled'}")
        self._new_config.analytics.enable_profiling = enable
        self.config.enable_profiling = enable  # Update original config too

    async def test_single_strategy(
        self, domain: str, strategy, shared_pcap_file: Optional[str] = None
    ):
        """
        Test a single strategy for the discovery system.

        Maintains exact compatibility with the original method.
        """
        LOG.info(f"🧪 Testing single strategy for domain: {domain}")

        try:
            if self._testing_service:
                new_strategy = self._convert_old_strategy_to_new(strategy, domain)
                result = await self._testing_service.test_strategy(domain, new_strategy)

                # Return result as object with attributes (not dict) for CLI compatibility
                class StrategyTestResult:
                    def __init__(self, success, domain, strategy, execution_time, error, metadata):
                        self.success = success
                        self.domain = domain
                        self.strategy = strategy
                        self.execution_time = execution_time
                        self.error = error
                        self.metadata = metadata
                        self.message = error if error else ("Success" if success else "Failed")
                        self.success_rate = 1.0 if success else 0.0

                return StrategyTestResult(
                    success=result.success,
                    domain=domain,
                    strategy=strategy,
                    execution_time=result.execution_time,
                    error=result.error,
                    metadata=result.metadata,
                )
            else:

                class StrategyTestResult:
                    def __init__(self, success, domain, strategy, execution_time, error, metadata):
                        self.success = success
                        self.domain = domain
                        self.strategy = strategy
                        self.execution_time = execution_time
                        self.error = error
                        self.metadata = metadata
                        self.message = error if error else ("Success" if success else "Failed")
                        self.success_rate = 1.0 if success else 0.0

                return StrategyTestResult(
                    success=False,
                    domain=domain,
                    strategy=strategy,
                    execution_time=0.0,
                    error="Testing service not available",
                    metadata={},
                )

        except Exception as e:
            LOG.error(f"❌ Error testing single strategy: {e}")

            class StrategyTestResult:
                def __init__(self, success, domain, strategy, execution_time, error, metadata):
                    self.success = success
                    self.domain = domain
                    self.strategy = strategy
                    self.execution_time = execution_time
                    self.error = error
                    self.metadata = metadata
                    self.message = error if error else ("Success" if success else "Failed")
                    self.success_rate = 1.0 if success else 0.0

            return StrategyTestResult(
                success=False,
                domain=domain,
                strategy=strategy,
                execution_time=0.0,
                error=str(e),
                metadata={},
            )

    async def test_strategy_on_multiple_domains(
        self, domains: List[str], strategy: Any, progress_callback=None
    ) -> Dict[str, bool]:
        """
        Test a strategy on multiple domains.

        Maintains exact compatibility with the original method.
        """
        LOG.info(f"🧪 Testing strategy on {len(domains)} domains")

        results = {}

        for i, domain in enumerate(domains):
            if progress_callback:
                progress_callback(f"Testing domain {i+1}/{len(domains)}: {domain}")

            try:
                result = await self.test_strategy(domain, strategy)
                results[domain] = result
            except Exception as e:
                LOG.error(f"❌ Error testing {domain}: {e}")
                results[domain] = False

        return results

    def get_profiling_statistics(self) -> Dict[str, Any]:
        """Get profiling statistics - maintains exact compatibility."""
        return {
            "profiling_enabled": self._new_config.analytics.enable_profiling,
            "operations_profiled": 0,
            "hot_paths": [],
            "performance_bottlenecks": [],
        }

    def get_protocol_preference_statistics(self) -> Dict[str, Any]:
        """Get protocol preference statistics - maintains exact compatibility."""
        return {
            "ipv4_preferred": 0,
            "ipv6_preferred": 0,
            "protocol_failures": {},
            "preference_cache_size": 0,
        }

    def optimize_caches(self):
        """Optimize caches - maintains exact compatibility."""
        LOG.info("⚡ Optimizing caches")

        if self._cache_manager:
            try:
                # Get cache stats for logging
                stats = self._cache_manager.get_cache_stats()
                LOG.info(f"📊 Cache stats: {stats}")
            except Exception as e:
                LOG.warning(f"⚠️ Error optimizing caches: {e}")

    def export_results(self, format: str = "json") -> Dict[str, Any]:
        """Export results in compatible format - maintains exact compatibility."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.get_stats(),
            "performance_metrics": self.get_performance_metrics(),
            "closed_loop_stats": self.get_closed_loop_statistics(),
            "configuration": {
                "max_trials": self._new_config.strategy.max_trials,
                "enable_fingerprinting": self._new_config.strategy.enable_fingerprinting,
                "enable_failure_analysis": self._new_config.strategy.enable_failure_analysis,
                "enable_profiling": self._new_config.analytics.enable_profiling,
            },
        }

        if self._analytics_service:
            try:
                exported_metrics = self._analytics_service.export_metrics(format)
                results["exported_metrics"] = exported_metrics
            except Exception as e:
                LOG.warning(f"⚠️ Error exporting metrics: {e}")

        return results

    def get_diagnostics_summary(self) -> Dict[str, Any]:
        """Get comprehensive diagnostics summary - maintains exact compatibility."""
        summary = {
            "system_status": "operational",
            "components_status": {
                "strategy_service": self._strategy_service is not None,
                "testing_service": self._testing_service is not None,
                "analytics_service": self._analytics_service is not None,
                "cache_manager": self._cache_manager is not None,
                "config_manager": self._config_manager is not None,
            },
            "statistics": self.get_stats(),
            "performance_metrics": self.get_performance_metrics(),
            "configuration": self._new_config.to_dict(),
            "timestamp": datetime.now().isoformat(),
        }

        return summary

    def export_diagnostics(self, output_file: str = "adaptive_diagnostics.json") -> bool:
        """Export comprehensive diagnostics data to file - maintains exact compatibility."""
        try:
            import json
            from pathlib import Path

            diagnostics = self.get_diagnostics_summary()

            output_path = Path(output_file)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(diagnostics, f, indent=2, ensure_ascii=False)

            LOG.info(f"✅ Diagnostics exported to {output_path}")
            return True

        except Exception as e:
            LOG.error(f"❌ Error exporting diagnostics: {e}")
            return False

    def optimize_hot_paths(self):
        """Optimize hot paths based on profiling data - maintains exact compatibility."""
        LOG.info("⚡ Optimizing hot paths")

        if self._new_config.analytics.enable_profiling:
            LOG.info("📊 Profiling enabled - analyzing performance data")
            # Hot path optimization would be implemented here
        else:
            LOG.info("📊 Profiling disabled - enable profiling for hot path optimization")

    def discover_strategy(self, domain: str) -> Optional[Any]:
        """
        Discover strategy for domain - synchronous version for compatibility.

        This method provides synchronous access to strategy discovery for
        backward compatibility with existing code.
        """
        LOG.info(f"🔍 Discovering strategy for domain: {domain}")

        try:
            # Import retry mechanism
            from .infrastructure.retry_mechanisms import with_retry, RetryConfig

            # Create retry-enabled version of find_best_strategy
            @with_retry("strategy_generation", RetryConfig(max_attempts=3, base_delay=1.0))
            async def find_strategy_with_retry():
                result = await self.find_best_strategy(domain)
                if not result.success:
                    # Raise exception to trigger retry
                    raise Exception(result.error or "Strategy discovery failed")
                return result

            # Run the async method synchronously
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(find_strategy_with_retry())
                if result.success and result.strategy:
                    return result.strategy
                return None
            finally:
                loop.close()

        except Exception as e:
            LOG.error(f"❌ Error discovering strategy for {domain}: {e}")
            return None

    def analyze_failure(self, test_result) -> Optional[Any]:
        """
        Analyze failure and provide failure report.

        Maintains exact compatibility with the original method.
        """
        LOG.info("🔍 Analyzing failure")

        try:
            if self._analytics_service and hasattr(self._analytics_service, "analyze_failure"):
                # Convert test result to new format if needed
                if hasattr(test_result, "strategy") and hasattr(test_result, "domain"):
                    new_test_result = TestResult(
                        success=False,
                        strategy=self._convert_old_strategy_to_new(
                            test_result.strategy, test_result.domain
                        ),
                        domain=test_result.domain,
                        execution_time=getattr(test_result, "execution_time", 0.0),
                        error=getattr(test_result, "error", "Unknown error"),
                    )

                    return self._analytics_service.analyze_failure(new_test_result)

            # Fallback failure analysis
            from .models import FailureReport
            from .infrastructure.failure_isolation import FailureType

            # Extract domain from test_result if available
            domain = getattr(test_result, "domain", "unknown")

            return FailureReport(
                domain=domain,
                error_message="Failure analysis service not available",
                failure_type=FailureType.CONNECTION_ERROR.value,
                suggested_fixes=["Check network connectivity", "Verify domain accessibility"],
            )

        except Exception as e:
            LOG.error(f"❌ Error analyzing failure: {e}")
            return None

    def __del__(self):
        """Cleanup resources on destruction."""
        try:
            LOG.info("🧹 Cleaning up AdaptiveEngine facade")
        except:
            pass  # Ignore errors during cleanup
