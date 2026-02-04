# Adaptive Engine API Documentation

This document provides comprehensive API documentation for all public interfaces and classes in the refactored Adaptive Engine.

## Table of Contents

1. [Core Interfaces](#core-interfaces)
2. [Data Models](#data-models)
3. [Configuration Classes](#configuration-classes)
4. [Service APIs](#service-apis)
5. [Component APIs](#component-apis)
6. [Infrastructure APIs](#infrastructure-apis)
7. [Utility Functions](#utility-functions)
8. [Error Handling](#error-handling)

## Core Interfaces

### IStrategyService

Interface for strategy-related operations.

```python
class IStrategyService(ABC):
    @abstractmethod
    async def generate_strategies(self, fingerprint: DPIFingerprint) -> List[Strategy]:
        """
        Generate strategies based on DPI fingerprint.
        
        Args:
            fingerprint: DPI fingerprint containing domain and detection information
            
        Returns:
            List of generated strategies
            
        Raises:
            StrategyGenerationError: If strategy generation fails
        """
        pass
    
    @abstractmethod
    async def get_cached_strategy(self, domain: str) -> Optional[Strategy]:
        """
        Retrieve cached strategy for domain.
        
        Args:
            domain: Domain name to look up
            
        Returns:
            Cached strategy if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def save_strategy(self, domain: str, strategy: Strategy) -> None:
        """
        Save strategy to cache.
        
        Args:
            domain: Domain name
            strategy: Strategy to cache
            
        Raises:
            CacheError: If caching fails
        """
        pass
```

### ITestingService

Interface for testing operations.

```python
class ITestingService(ABC):
    @abstractmethod
    async def test_strategy(self, domain: str, strategy: Strategy) -> TestResult:
        """
        Test a strategy against a domain.
        
        Args:
            domain: Target domain
            strategy: Strategy to test
            
        Returns:
            Test result with success status and metadata
            
        Raises:
            TestingError: If testing fails
        """
        pass
    
    @abstractmethod
    async def test_multiple_strategies(self, domain: str, strategies: List[Strategy]) -> List[TestResult]:
        """
        Test multiple strategies against a domain.
        
        Args:
            domain: Target domain
            strategies: List of strategies to test
            
        Returns:
            List of test results
        """
        pass
```

### IAnalyticsService

Interface for analytics and metrics operations.

```python
class IAnalyticsService(ABC):
    @abstractmethod
    def record_strategy_test(self, domain: str, strategy: Strategy, result: TestResult) -> None:
        """
        Record a strategy test result for analytics.
        
        Args:
            domain: Domain that was tested
            strategy: Strategy that was tested
            result: Test result
        """
        pass
    
    @abstractmethod
    def get_performance_metrics(self) -> PerformanceMetrics:
        """
        Get current performance metrics.
        
        Returns:
            Performance metrics object
        """
        pass
    
    @abstractmethod
    def export_metrics(self, format: str = "json") -> Dict[str, Any]:
        """
        Export metrics in specified format.
        
        Args:
            format: Export format ("json", "csv", "prometheus")
            
        Returns:
            Exported metrics data
        """
        pass
```

### ICacheManager

Interface for cache operations.

```python
class ICacheManager(ABC):
    @abstractmethod
    async def get(self, key: str, cache_type: CacheType) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            cache_type: Type of cache to query
            
        Returns:
            Cached value if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Any, cache_type: CacheType, ttl: Optional[int] = None) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            cache_type: Type of cache to use
            ttl: Time to live in seconds (optional)
        """
        pass
    
    @abstractmethod
    async def invalidate(self, key: str, cache_type: CacheType) -> None:
        """
        Invalidate cache entry.
        
        Args:
            key: Cache key to invalidate
            cache_type: Type of cache
        """
        pass
```

## Data Models

### Strategy

Represents a bypass strategy.

```python
@dataclass
class Strategy:
    name: str                           # Strategy name
    attack_combination: List[str]       # List of attack techniques
    parameters: Dict[str, Any]          # Strategy parameters
    strategy_type: StrategyType         # Type of strategy
    confidence_score: float = 0.0       # Confidence in strategy (0.0-1.0)
    success_rate: float = 0.0          # Historical success rate
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional metadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert strategy to dictionary representation."""
        pass
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Strategy':
        """Create strategy from dictionary representation."""
        pass
```

### TestResult

Represents the result of a strategy test.

```python
@dataclass
class TestResult:
    success: bool                       # Whether test was successful
    strategy: Strategy                  # Strategy that was tested
    domain: str                        # Domain that was tested
    execution_time: float              # Test execution time in seconds
    error: Optional[str] = None        # Error message if test failed
    artifacts: Optional[TestArtifacts] = None  # Test artifacts (PCAP, logs, etc.)
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional metadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary representation."""
        pass
```

### DPIFingerprint

Represents DPI system characteristics.

```python
@dataclass
class DPIFingerprint:
    domain: str                                    # Target domain
    detection_methods: List[str]                   # Detected DPI methods
    blocking_patterns: List[str]                   # Identified blocking patterns
    protocol_analysis: Dict[str, Any]              # Protocol-specific analysis
    timing_characteristics: Dict[str, float]       # Timing-based characteristics
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional metadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert fingerprint to dictionary representation."""
        pass
```

### PerformanceMetrics

Performance and operational metrics.

```python
@dataclass
class PerformanceMetrics:
    cache_hit_rate: float                    # Cache hit rate (0.0-1.0)
    average_test_time: float                 # Average test time in seconds
    strategy_generation_time: float          # Average strategy generation time
    fingerprint_creation_time: float         # Average fingerprint creation time
    total_domains_processed: int             # Total domains processed
    total_strategies_found: int              # Total strategies found
    memory_usage_mb: float = 0.0            # Memory usage in MB
    cpu_usage_percent: float = 0.0          # CPU usage percentage
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary representation."""
        pass
```

## Configuration Classes

### AdaptiveEngineConfig

Main configuration class.

```python
@dataclass
class AdaptiveEngineConfig:
    strategy: StrategyConfig                 # Strategy configuration
    testing: TestingConfig                   # Testing configuration
    caching: CacheConfig                     # Caching configuration
    analytics: AnalyticsConfig               # Analytics configuration
    networking: NetworkingConfig             # Networking configuration
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        pass
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AdaptiveEngineConfig':
        """Create configuration from dictionary."""
        pass
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        pass
```

### StrategyConfig

Strategy generation configuration.

```python
@dataclass
class StrategyConfig:
    max_trials: int = 15                     # Maximum strategy trials
    generation_timeout: float = 30.0        # Strategy generation timeout
    enable_failure_analysis: bool = True     # Enable failure analysis
    enable_fingerprinting: bool = True      # Enable DPI fingerprinting
    max_strategies_per_domain: int = 10     # Max strategies per domain
    confidence_threshold: float = 0.5       # Minimum confidence threshold
    strategy_ttl_hours: int = 24            # Strategy cache TTL
    enable_learning: bool = True            # Enable learning from results
```

### TestingConfig

Testing configuration.

```python
@dataclass
class TestingConfig:
    strategy_timeout: float = 30.0          # Strategy test timeout
    connection_timeout: float = 5.0         # Connection timeout
    enable_parallel_testing: bool = False   # Enable parallel testing
    max_parallel_workers: int = 5           # Max parallel workers
    verify_with_pcap: bool = False          # Verify results with PCAP
    enable_test_validation: bool = True     # Enable test validation
    retry_failed_tests: bool = True         # Retry failed tests
    max_test_retries: int = 3               # Maximum test retries
```

## Service APIs

### AdaptiveEngine (Facade)

Main facade class maintaining backward compatibility.

```python
class AdaptiveEngine:
    def __init__(self, config: Optional[AdaptiveConfig] = None):
        """
        Initialize AdaptiveEngine with optional configuration.
        
        Args:
            config: Optional configuration (for backward compatibility)
        """
        pass
    
    async def find_best_strategy(self, domain: str, progress_callback=None, shared_pcap_file=None) -> StrategyResult:
        """
        Find the best bypass strategy for a domain.
        
        Args:
            domain: Target domain
            progress_callback: Optional progress callback function
            shared_pcap_file: Optional shared PCAP file path
            
        Returns:
            Strategy result with success status and strategy
            
        Raises:
            ValueError: If domain is invalid
            StrategyError: If strategy generation/testing fails
        """
        pass
    
    async def test_strategy(self, domain: str, strategy) -> bool:
        """
        Test a specific strategy against a domain.
        
        Args:
            domain: Target domain
            strategy: Strategy to test
            
        Returns:
            True if strategy works, False otherwise
        """
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current engine statistics.
        
        Returns:
            Dictionary containing various statistics
        """
        pass
    
    def clear_caches(self):
        """Clear all caches."""
        pass
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get performance metrics.
        
        Returns:
            Dictionary containing performance metrics
        """
        pass
```

## Component APIs

### StrategyGenerator

Strategy generation component.

```python
class StrategyGenerator(IStrategyGenerator):
    def __init__(self, config: StrategyConfig, failure_analyzer: Optional[IFailureAnalyzer] = None):
        """
        Initialize strategy generator.
        
        Args:
            config: Strategy configuration
            failure_analyzer: Optional failure analyzer
        """
        pass
    
    async def generate_strategies(self, fingerprint: DPIFingerprint, max_count: int = 10) -> List[Strategy]:
        """
        Generate strategies based on DPI fingerprint.
        
        Args:
            fingerprint: DPI fingerprint
            max_count: Maximum number of strategies to generate
            
        Returns:
            List of generated strategies
        """
        pass
    
    async def generate_from_failure(self, failure_report: FailureReport) -> List[Strategy]:
        """
        Generate strategies based on failure analysis.
        
        Args:
            failure_report: Failure analysis report
            
        Returns:
            List of recovery strategies
        """
        pass
    
    def set_generation_timeout(self, timeout: float) -> None:
        """
        Set timeout for strategy generation.
        
        Args:
            timeout: Timeout in seconds
        """
        pass
```

### TestCoordinator

Test coordination component.

```python
class TestCoordinator(ITestCoordinator):
    def __init__(self, config: TestingConfig):
        """
        Initialize test coordinator.
        
        Args:
            config: Testing configuration
        """
        pass
    
    async def execute_test(self, domain: str, strategy: Strategy) -> TestResult:
        """
        Execute a strategy test.
        
        Args:
            domain: Target domain
            strategy: Strategy to test
            
        Returns:
            Test result
        """
        pass
    
    def start_test_session(self, domain: str, strategy_name: str) -> str:
        """
        Start a test session.
        
        Args:
            domain: Target domain
            strategy_name: Name of strategy being tested
            
        Returns:
            Session ID
        """
        pass
    
    def finalize_test_session(self, session_id: str) -> TestVerdict:
        """
        Finalize a test session.
        
        Args:
            session_id: Session ID to finalize
            
        Returns:
            Test verdict
        """
        pass
```

## Infrastructure APIs

### CacheManager

Cache management implementation.

```python
class CacheManager(ICacheManager):
    def __init__(self, config: CacheConfig):
        """
        Initialize cache manager.
        
        Args:
            config: Cache configuration
        """
        pass
    
    async def get(self, key: str, cache_type: CacheType) -> Optional[Any]:
        """Get value from cache."""
        pass
    
    async def set(self, key: str, value: Any, cache_type: CacheType, ttl: Optional[int] = None) -> None:
        """Set value in cache."""
        pass
    
    async def invalidate(self, key: str, cache_type: CacheType) -> None:
        """Invalidate cache entry."""
        pass
    
    async def clear_cache(self, cache_type: Optional[CacheType] = None) -> None:
        """
        Clear cache entries.
        
        Args:
            cache_type: Specific cache type to clear, or None for all caches
        """
        pass
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary containing cache statistics
        """
        pass
```

### MetricsCollector

Metrics collection implementation.

```python
class MetricsCollector(IMetricsCollector):
    def __init__(self, config: AnalyticsConfig):
        """
        Initialize metrics collector.
        
        Args:
            config: Analytics configuration
        """
        pass
    
    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Record a metric value.
        
        Args:
            name: Metric name
            value: Metric value
            tags: Optional tags for the metric
        """
        pass
    
    def increment_counter(self, name: str, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Increment a counter metric.
        
        Args:
            name: Counter name
            tags: Optional tags
        """
        pass
    
    def record_timing(self, name: str, duration: float, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Record a timing metric.
        
        Args:
            name: Timing metric name
            duration: Duration in seconds
            tags: Optional tags
        """
        pass
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get summary of all metrics.
        
        Returns:
            Dictionary containing metrics summary
        """
        pass
```

## Utility Functions

### Error Handling Utilities

```python
def handle_exceptions(default_return=None, log_level="error", reraise=False, operation_name=None):
    """
    Decorator for consistent exception handling.
    
    Args:
        default_return: Value to return on exception
        log_level: Logging level for exceptions
        reraise: Whether to reraise after logging
        operation_name: Name for logging context
    """
    pass

@contextmanager
def log_operation(operation_name: str, log_level: str = "info"):
    """
    Context manager for operation logging.
    
    Args:
        operation_name: Name of the operation
        log_level: Logging level
    """
    pass

def format_error_message(operation: str, error: Exception, context: Optional[dict] = None) -> str:
    """
    Format consistent error messages.
    
    Args:
        operation: Operation that failed
        error: Exception that occurred
        context: Additional context
        
    Returns:
        Formatted error message
    """
    pass
```

### Configuration Utilities

```python
def validate_config_field(config: dict, field_name: str, field_type: type, default=None):
    """
    Validate configuration field with type checking.
    
    Args:
        config: Configuration dictionary
        field_name: Field name to validate
        field_type: Expected field type
        default: Default value
        
    Returns:
        Validated field value
    """
    pass

def safe_dict_get(dictionary: dict, key: str, default=None):
    """
    Safely get dictionary value with error handling.
    
    Args:
        dictionary: Dictionary to query
        key: Key to look up
        default: Default value
        
    Returns:
        Dictionary value or default
    """
    pass
```

## Error Handling

### Exception Classes

```python
class AdaptiveEngineError(Exception):
    """Base exception for Adaptive Engine errors."""
    pass

class StrategyGenerationError(AdaptiveEngineError):
    """Raised when strategy generation fails."""
    pass

class TestingError(AdaptiveEngineError):
    """Raised when strategy testing fails."""
    pass

class CacheError(AdaptiveEngineError):
    """Raised when cache operations fail."""
    pass

class ConfigurationError(AdaptiveEngineError):
    """Raised when configuration is invalid."""
    pass
```

### Error Context

All errors include structured context information:

```python
{
    "operation": "strategy_generation",
    "domain": "example.com",
    "timestamp": "2024-01-01T12:00:00Z",
    "component": "StrategyGenerator",
    "error_type": "timeout",
    "details": {...}
}
```

## Usage Examples

### Basic Usage

```python
from core.adaptive_refactored import AdaptiveEngine

# Initialize engine
engine = AdaptiveEngine()

# Find best strategy
result = await engine.find_best_strategy("example.com")
if result.success:
    print(f"Found strategy: {result.strategy.name}")
else:
    print(f"Failed: {result.error}")
```

### Advanced Usage

```python
from core.adaptive_refactored import get_container
from core.adaptive_refactored.interfaces import IStrategyService, ITestingService

# Get container and resolve services
container = get_container()
strategy_service = container.resolve(IStrategyService)
testing_service = container.resolve(ITestingService)

# Generate strategies
fingerprint = DPIFingerprint(domain="example.com", ...)
strategies = await strategy_service.generate_strategies(fingerprint)

# Test strategies
for strategy in strategies:
    result = await testing_service.test_strategy("example.com", strategy)
    if result.success:
        print(f"Strategy {strategy.name} works!")
        break
```

### Configuration

```python
from core.adaptive_refactored.config import AdaptiveEngineConfig, StrategyConfig

# Create custom configuration
config = AdaptiveEngineConfig(
    strategy=StrategyConfig(
        max_trials=20,
        generation_timeout=60.0,
        enable_failure_analysis=True
    )
)

# Initialize with custom config
engine = AdaptiveEngine(config)
```

This API documentation provides comprehensive coverage of all public interfaces and usage patterns for the refactored Adaptive Engine system.