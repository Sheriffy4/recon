"""
Core interfaces for the refactored Adaptive Engine components.

These interfaces define the contracts for all major components,
enabling dependency injection and loose coupling.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from .models import (
    Strategy,
    TestResult,
    PerformanceMetrics,
    DPIFingerprint,
    FailureReport,
    TestVerdict,
    CacheType,
    ValidationError,
)
from .config import StrategyConfig, TestingConfig, CacheConfig, AnalyticsConfig, NetworkingConfig


class IStrategyService(ABC):
    """Service for managing strategy operations including generation, caching, and management."""

    @abstractmethod
    async def generate_strategies(self, fingerprint: DPIFingerprint) -> List[Strategy]:
        """Generate strategies based on DPI fingerprint."""
        pass

    @abstractmethod
    async def get_cached_strategy(self, domain: str) -> Optional[Strategy]:
        """Retrieve cached strategy for domain."""
        pass

    @abstractmethod
    async def save_strategy(self, domain: str, strategy: Strategy) -> None:
        """Save strategy to cache."""
        pass

    @abstractmethod
    async def invalidate_strategy_cache(self, domain: str) -> None:
        """Invalidate cached strategy for domain."""
        pass

    @abstractmethod
    async def get_strategy_statistics(self) -> Dict[str, Any]:
        """Get statistics about cached strategies and strategy service operations."""
        pass

    @abstractmethod
    async def get_strategy_recommendations(
        self, domain: str, fingerprint: DPIFingerprint
    ) -> List[Strategy]:
        """Get strategy recommendations based on domain and fingerprint."""
        pass

    @abstractmethod
    async def update_strategy_success_rate(
        self, domain: str, strategy_name: str, success: bool
    ) -> None:
        """Update success rate for a strategy."""
        pass

    @abstractmethod
    async def cleanup_expired_strategies(self) -> int:
        """Clean up expired strategy cache entries."""
        pass


class ITestingService(ABC):
    """Service for coordinating strategy testing operations."""

    @abstractmethod
    async def test_strategy(
        self, domain: str, strategy: Strategy, shared_pcap_file: Optional[str] = None
    ) -> TestResult:
        """Test a single strategy against a domain."""
        pass

    @abstractmethod
    async def test_multiple_strategies(
        self, domain: str, strategies: List[Strategy], shared_pcap_file: Optional[str] = None
    ) -> List[TestResult]:
        """Test multiple strategies against a domain."""
        pass

    @abstractmethod
    async def validate_test_result(self, result: TestResult) -> bool:
        """Validate that a test result is accurate."""
        pass

    @abstractmethod
    async def coordinate_pcap_capture(self, domain: str, duration: float) -> Optional[str]:
        """Coordinate PCAP capture for a domain."""
        pass

    @abstractmethod
    async def finalize_test_session(self, session_id: str) -> TestVerdict:
        """Finalize a test session and get the verdict."""
        pass

    @abstractmethod
    def should_save_strategy(self, session_id: str) -> bool:
        """Determine if a strategy should be saved based on test session results."""
        pass

    @abstractmethod
    async def validate_test_environment(self) -> bool:
        """Validate that the test environment is properly configured and ready for testing."""
        pass

    @abstractmethod
    async def cleanup_test_artifacts(self, domain: str) -> None:
        """Clean up test artifacts and temporary files for a domain."""
        pass

    @abstractmethod
    def get_test_stats(self) -> Dict[str, Any]:
        """Get comprehensive testing statistics and metrics."""
        pass


class IAnalyticsService(ABC):
    """Service for managing metrics collection, performance monitoring, and analytics."""

    @abstractmethod
    def record_strategy_test(self, domain: str, strategy: Strategy, result: TestResult) -> None:
        """Record the result of a strategy test."""
        pass

    @abstractmethod
    def get_performance_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics."""
        pass

    @abstractmethod
    def export_metrics(self, format: str = "json") -> str:
        """Export metrics in specified format."""
        pass

    @abstractmethod
    def reset_metrics(self) -> None:
        """Reset all collected metrics."""
        pass

    @abstractmethod
    def get_closed_loop_analytics(self) -> Dict[str, Any]:
        """Get closed-loop learning analytics."""
        pass

    @abstractmethod
    def get_timeout_analytics(self) -> Dict[str, Any]:
        """Get adaptive timeout analytics."""
        pass

    @abstractmethod
    def get_comprehensive_analytics(self) -> Dict[str, Any]:
        """Get comprehensive analytics combining all metrics."""
        pass


class IStrategyGenerator(ABC):
    """Component responsible for generating new bypass strategies."""

    @abstractmethod
    async def generate_strategies(
        self, fingerprint: DPIFingerprint, max_count: int = 10
    ) -> List[Strategy]:
        """Generate strategies based on DPI fingerprint."""
        pass

    @abstractmethod
    async def generate_from_failure(self, failure_report: FailureReport) -> List[Strategy]:
        """Generate strategies based on failure analysis."""
        pass

    @abstractmethod
    def set_generation_timeout(self, timeout: float) -> None:
        """Set timeout for strategy generation."""
        pass


class ITestCoordinator(ABC):
    """Component that manages test execution, PCAP capture, and result validation."""

    @abstractmethod
    async def execute_test(self, domain: str, strategy: Strategy) -> TestResult:
        """Execute a single strategy test."""
        pass

    @abstractmethod
    def start_test_session(
        self, domain: str, strategy_name: str, pcap_file: Optional[str] = None
    ) -> str:
        """Start a new test session and return session ID."""
        pass

    @abstractmethod
    def finalize_test_session(self, session_id: str) -> TestVerdict:
        """Finalize test session and return verdict."""
        pass

    @abstractmethod
    async def capture_pcap(self, domain: str, duration: float) -> Optional[str]:
        """Capture PCAP for specified domain and duration."""
        pass

    @abstractmethod
    def record_response(
        self,
        session_id: str,
        success: bool = False,
        timeout: bool = False,
        error: Optional[str] = None,
        response_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a response/result for the test session."""
        pass

    @abstractmethod
    def should_save_strategy(self, session_id: str) -> bool:
        """Determine if a strategy should be saved based on test session results."""
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data for a given session ID."""
        pass

    @abstractmethod
    def get_pcap_analysis(self, pcap_file: str) -> Optional[Dict[str, Any]]:
        """Get PCAP analysis for a file, with caching support."""
        pass

    @abstractmethod
    def update_session_pcap_path(self, session_id: str, actual_pcap_path: str) -> None:
        """Update the PCAP file path for a session."""
        pass

    @abstractmethod
    def add_test_result_to_session(self, session_id: str, test_result: TestResult) -> None:
        """Add a test result to a session for tracking."""
        pass

    @abstractmethod
    def get_active_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Get information about active test sessions."""
        pass


class ICacheManager(ABC):
    """Component that handles all caching operations with configurable TTL and size limits."""

    @abstractmethod
    async def get(self, key: str, cache_type: CacheType) -> Optional[Any]:
        """Get value from cache."""
        pass

    @abstractmethod
    async def set(
        self, key: str, value: Any, cache_type: CacheType, ttl: Optional[int] = None
    ) -> None:
        """Set value in cache with optional TTL."""
        pass

    @abstractmethod
    async def invalidate(self, key: str, cache_type: CacheType) -> None:
        """Invalidate specific cache entry."""
        pass

    @abstractmethod
    async def clear_cache(self, cache_type: Optional[CacheType] = None) -> None:
        """Clear entire cache or specific cache type."""
        pass

    @abstractmethod
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        pass

    @abstractmethod
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get performance-focused cache metrics."""
        pass

    @abstractmethod
    def set_eviction_policy(self, policy: str) -> None:
        """Set the eviction policy for all caches."""
        pass

    @abstractmethod
    def get_eviction_policy(self) -> str:
        """Get the current eviction policy."""
        pass

    @abstractmethod
    async def optimize_cache(self, cache_type: Optional[CacheType] = None) -> Dict[str, int]:
        """Optimize cache by removing expired entries and compacting."""
        pass


class IConfigurationManager(ABC):
    """Component that manages all configuration aspects with validation and type safety."""

    @abstractmethod
    def get_strategy_config(self) -> StrategyConfig:
        """Get strategy configuration."""
        pass

    @abstractmethod
    def get_testing_config(self) -> TestingConfig:
        """Get testing configuration."""
        pass

    @abstractmethod
    def get_cache_config(self) -> CacheConfig:
        """Get cache configuration."""
        pass

    @abstractmethod
    def get_analytics_config(self) -> AnalyticsConfig:
        """Get analytics configuration."""
        pass

    @abstractmethod
    def get_networking_config(self) -> NetworkingConfig:
        """Get networking configuration."""
        pass

    @abstractmethod
    def validate_configuration(self) -> List[ValidationError]:
        """Validate all configuration and return any errors."""
        pass

    @abstractmethod
    def reload_configuration(self) -> None:
        """Reload configuration from source."""
        pass


class IFailureAnalyzer(ABC):
    """Component that analyzes failed strategy attempts to improve future attempts."""

    @abstractmethod
    async def analyze_failure(self, test_result) -> FailureReport:
        """Analyze a strategy failure and generate report."""
        pass

    @abstractmethod
    def categorize_failure(self, error_message: str) -> str:
        """Categorize the type of failure based on error message."""
        pass

    @abstractmethod
    async def analyze_pcap_failure(
        self, pcap_file: str, domain: str, strategy: Strategy
    ) -> FailureReport:
        """Analyze failure using PCAP file directly."""
        pass

    @abstractmethod
    async def learn_from_failure(self, failure_report: FailureReport) -> None:
        """Learn from failure to improve future strategy generation."""
        pass

    @abstractmethod
    def get_failure_patterns(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """Get identified failure patterns."""
        pass

    @abstractmethod
    def is_pcap_analysis_available(self) -> bool:
        """Check if PCAP analysis capabilities are available."""
        pass

    @abstractmethod
    async def generate_strategies_from_failure(
        self, failure_report: FailureReport
    ) -> List[Dict[str, Any]]:
        """Generate strategy suggestions based on failure analysis."""
        pass


class IMetricsCollector(ABC):
    """Component that collects and manages performance and success metrics."""

    @abstractmethod
    def record_operation_time(self, operation: str, duration: float) -> None:
        """Record timing for an operation."""
        pass

    @abstractmethod
    def record_success_rate(self, operation: str, success: bool) -> None:
        """Record success/failure for an operation."""
        pass

    @abstractmethod
    def record_cache_hit(self, cache_type: CacheType) -> None:
        """Record cache hit."""
        pass

    @abstractmethod
    def record_cache_miss(self, cache_type: CacheType) -> None:
        """Record cache miss."""
        pass

    @abstractmethod
    def record_domain_processed(self, domain: str) -> None:
        """Record that a domain has been processed."""
        pass

    @abstractmethod
    def record_strategy_found(self, strategy_name: str) -> None:
        """Record that a strategy was found/generated."""
        pass

    @abstractmethod
    def record_fingerprint_created(self) -> None:
        """Record that a fingerprint was created."""
        pass

    @abstractmethod
    def record_failure_analyzed(self) -> None:
        """Record that a failure was analyzed."""
        pass

    @abstractmethod
    def record_parallel_test(self) -> None:
        """Record that a parallel test was executed."""
        pass

    @abstractmethod
    def record_closed_loop_iteration(self) -> None:
        """Record a closed-loop learning iteration."""
        pass

    @abstractmethod
    def record_intent_generated(self) -> None:
        """Record that an intent was generated."""
        pass

    @abstractmethod
    def record_strategy_augmented(self) -> None:
        """Record that a strategy was augmented."""
        pass

    @abstractmethod
    def record_pattern_match(self) -> None:
        """Record that a pattern was matched."""
        pass

    @abstractmethod
    def record_knowledge_update(self) -> None:
        """Record that knowledge was updated."""
        pass

    @abstractmethod
    def record_adaptive_timeout(self, timeout_type: str, factor: float) -> None:
        """Record an adaptive timeout adjustment."""
        pass

    @abstractmethod
    def record_strategy_test(
        self, domain: str, strategy_name: str, success: bool, duration: float
    ) -> None:
        """Record the result of a strategy test."""
        pass

    @abstractmethod
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all collected metrics."""
        pass

    @abstractmethod
    def get_closed_loop_stats(self) -> Dict[str, Any]:
        """Get closed-loop learning statistics."""
        pass

    @abstractmethod
    def get_timeout_stats(self) -> Dict[str, Any]:
        """Get adaptive timeout statistics."""
        pass

    @abstractmethod
    def get_performance_metrics(self) -> PerformanceMetrics:
        """Get performance metrics as a PerformanceMetrics object."""
        pass

    @abstractmethod
    def reset_metrics(self) -> None:
        """Reset all collected metrics."""
        pass


class IPerformanceMonitor(ABC):
    """Component that provides performance monitoring and profiling capabilities."""

    @abstractmethod
    def start_profiling(self, operation: str) -> str:
        """Start profiling an operation and return profile ID."""
        pass

    @abstractmethod
    def stop_profiling(self, profile_id: str) -> Dict[str, Any]:
        """Stop profiling and return performance data."""
        pass

    @abstractmethod
    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics."""
        pass

    @abstractmethod
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        pass

    @abstractmethod
    def get_system_performance(self) -> Dict[str, Any]:
        """Get comprehensive system performance metrics."""
        pass

    @abstractmethod
    def start_operation(self, operation: str) -> str:
        """Start operation timing tracking and return operation ID."""
        pass

    @abstractmethod
    def end_operation(self, operation_id: str) -> float:
        """End operation timing tracking and return duration."""
        pass

    @abstractmethod
    def get_performance_alerts(self) -> List[Dict[str, Any]]:
        """Get performance alerts based on configured thresholds."""
        pass

    @abstractmethod
    def optimize_memory_usage(self) -> Dict[str, Any]:
        """Optimize memory usage and return optimization results."""
        pass

    @abstractmethod
    def get_memory_optimization_stats(self) -> Dict[str, Any]:
        """Get memory optimization statistics."""
        pass

    @abstractmethod
    def set_performance_baseline(self, operation: str, baseline_metrics: Dict[str, float]) -> None:
        """Set performance baseline for an operation."""
        pass

    @abstractmethod
    def compare_with_baseline(
        self, operation: str, current_metrics: Dict[str, float]
    ) -> Dict[str, Any]:
        """Compare current performance with baseline."""
        pass

    @abstractmethod
    def get_performance_trends(self, operation: str, hours: int = 24) -> Dict[str, Any]:
        """Get performance trends for an operation over time."""
        pass


class IBypassEngine(ABC):
    """Interface for bypass engine implementations."""

    @abstractmethod
    async def test_strategy(self, domain: str, strategy: Strategy) -> TestResult:
        """Test a strategy against a domain."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if bypass engine is available."""
        pass

    @abstractmethod
    def set_domain_filter(self, domain: Optional[str]) -> None:
        """Устанавливает жесткий фильтр: обрабатывать пакеты ТОЛЬКО этого домена."""
        pass

    @abstractmethod
    def enable_discovery_mode(self) -> None:
        """Отключает загрузку существующих правил (Fixed strategies) на время теста."""
        pass

    @abstractmethod
    def disable_discovery_mode(self) -> None:
        """Возвращает движок в режим Production (использование domain_rules.json)."""
        pass


class IPCAPAnalyzer(ABC):
    """Interface for PCAP analysis implementations."""

    @abstractmethod
    async def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze PCAP file and return results."""
        pass

    @abstractmethod
    def validate_pcap(self, pcap_path: str) -> bool:
        """Validate PCAP file format and content."""
        pass


class IStrategyValidator(ABC):
    """Interface for strategy validation implementations."""

    @abstractmethod
    async def validate_strategy(self, strategy: Strategy) -> bool:
        """Validate strategy configuration."""
        pass

    @abstractmethod
    def get_validation_errors(self, strategy: Strategy) -> List[str]:
        """Get validation errors for strategy."""
        pass
