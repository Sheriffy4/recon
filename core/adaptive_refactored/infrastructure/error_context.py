"""
Error context and recovery suggestion system.

Provides detailed error analysis, context collection, and intelligent
recovery suggestions for the adaptive engine system.
"""

import traceback
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Type, Union
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Severity levels for errors."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Categories of errors for better classification."""

    NETWORK = "network"
    CONFIGURATION = "configuration"
    RESOURCE = "resource"
    AUTHENTICATION = "authentication"
    VALIDATION = "validation"
    DEPENDENCY = "dependency"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@dataclass
class SystemContext:
    """System context at the time of error."""

    timestamp: datetime = field(default_factory=datetime.now)
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    disk_usage_percent: Optional[float] = None
    active_connections: Optional[int] = None
    system_load: Optional[float] = None
    python_version: str = field(default_factory=lambda: sys.version)

    def to_dict(self) -> Dict[str, Any]:
        """Convert system context to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "memory_usage_mb": self.memory_usage_mb,
            "cpu_usage_percent": self.cpu_usage_percent,
            "disk_usage_percent": self.disk_usage_percent,
            "active_connections": self.active_connections,
            "system_load": self.system_load,
            "python_version": self.python_version,
        }


@dataclass
class OperationContext:
    """Context about the operation that failed."""

    operation_name: str
    component_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    execution_time: Optional[float] = None
    memory_used: Optional[float] = None
    dependencies_used: List[str] = field(default_factory=list)
    configuration_used: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert operation context to dictionary."""
        return {
            "operation_name": self.operation_name,
            "component_name": self.component_name,
            "parameters": self.parameters,
            "execution_time": self.execution_time,
            "memory_used": self.memory_used,
            "dependencies_used": self.dependencies_used,
            "configuration_used": self.configuration_used,
        }


@dataclass
class ErrorDetails:
    """Detailed information about an error."""

    exception_type: str
    exception_message: str
    stack_trace: str
    cause_chain: List[str] = field(default_factory=list)
    error_code: Optional[str] = None

    @classmethod
    def from_exception(cls, exception: Exception) -> "ErrorDetails":
        """Create ErrorDetails from an exception."""
        # Get the full stack trace
        stack_trace = "".join(
            traceback.format_exception(type(exception), exception, exception.__traceback__)
        )

        # Build cause chain
        cause_chain = []
        current = exception
        while current:
            cause_chain.append(f"{type(current).__name__}: {str(current)}")
            current = getattr(current, "__cause__", None)

        return cls(
            exception_type=type(exception).__name__,
            exception_message=str(exception),
            stack_trace=stack_trace,
            cause_chain=cause_chain,
            error_code=getattr(exception, "code", None),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert error details to dictionary."""
        return {
            "exception_type": self.exception_type,
            "exception_message": self.exception_message,
            "stack_trace": self.stack_trace,
            "cause_chain": self.cause_chain,
            "error_code": self.error_code,
        }


@dataclass
class RecoverySuggestion:
    """A specific recovery suggestion with priority and rationale."""

    suggestion: str
    priority: int  # 1 = highest priority
    rationale: str
    category: str
    estimated_effort: str  # "low", "medium", "high"
    success_probability: float  # 0.0 to 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert recovery suggestion to dictionary."""
        return {
            "suggestion": self.suggestion,
            "priority": self.priority,
            "rationale": self.rationale,
            "category": self.category,
            "estimated_effort": self.estimated_effort,
            "success_probability": self.success_probability,
        }


@dataclass
class EnhancedErrorContext:
    """
    Comprehensive error context with system state, operation details,
    and intelligent recovery suggestions.
    """

    error_details: ErrorDetails
    operation_context: OperationContext
    system_context: SystemContext
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    category: ErrorCategory = ErrorCategory.UNKNOWN
    recovery_suggestions: List[RecoverySuggestion] = field(default_factory=list)
    related_errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert enhanced error context to dictionary."""
        return {
            "error_details": self.error_details.to_dict(),
            "operation_context": self.operation_context.to_dict(),
            "system_context": self.system_context.to_dict(),
            "severity": self.severity.value,
            "category": self.category.value,
            "recovery_suggestions": [s.to_dict() for s in self.recovery_suggestions],
            "related_errors": self.related_errors,
            "metadata": self.metadata,
        }

    def get_top_suggestions(self, limit: int = 3) -> List[RecoverySuggestion]:
        """Get top recovery suggestions by priority and success probability."""
        sorted_suggestions = sorted(
            self.recovery_suggestions, key=lambda s: (s.priority, -s.success_probability)
        )
        return sorted_suggestions[:limit]


class ErrorContextBuilder:
    """
    Builder for creating comprehensive error contexts with intelligent analysis.
    """

    def __init__(self):
        self._error_patterns: Dict[str, List[RecoverySuggestion]] = {}
        self._setup_default_patterns()

    def build_context(
        self, exception: Exception, operation_name: str, component_name: str, **kwargs
    ) -> EnhancedErrorContext:
        """
        Build comprehensive error context from exception and operation details.

        Args:
            exception: The exception that occurred
            operation_name: Name of the operation that failed
            component_name: Name of the component where error occurred
            **kwargs: Additional context parameters

        Returns:
            Enhanced error context with analysis and suggestions
        """
        # Create error details
        error_details = ErrorDetails.from_exception(exception)

        # Create operation context
        operation_context = OperationContext(
            operation_name=operation_name,
            component_name=component_name,
            parameters=kwargs.get("parameters", {}),
            execution_time=kwargs.get("execution_time"),
            memory_used=kwargs.get("memory_used"),
            dependencies_used=kwargs.get("dependencies_used", []),
            configuration_used=kwargs.get("configuration_used", {}),
        )

        # Create system context
        system_context = self._collect_system_context()

        # Classify error
        severity = self._classify_severity(exception, operation_context)
        category = self._classify_category(exception)

        # Generate recovery suggestions
        recovery_suggestions = self._generate_recovery_suggestions(
            exception, operation_context, system_context
        )

        # Find related errors
        related_errors = self._find_related_errors(exception, component_name)

        return EnhancedErrorContext(
            error_details=error_details,
            operation_context=operation_context,
            system_context=system_context,
            severity=severity,
            category=category,
            recovery_suggestions=recovery_suggestions,
            related_errors=related_errors,
            metadata=kwargs.get("metadata", {}),
        )

    def _collect_system_context(self) -> SystemContext:
        """Collect current system context."""
        context = SystemContext()

        try:
            import psutil

            # Memory usage
            memory = psutil.virtual_memory()
            context.memory_usage_mb = memory.used / (1024 * 1024)

            # CPU usage
            context.cpu_usage_percent = psutil.cpu_percent(interval=0.1)

            # Disk usage
            disk = psutil.disk_usage("/")
            context.disk_usage_percent = (disk.used / disk.total) * 100

            # System load
            context.system_load = psutil.getloadavg()[0] if hasattr(psutil, "getloadavg") else None

            # Network connections
            context.active_connections = len(psutil.net_connections())

        except ImportError:
            logger.debug("psutil not available, system context will be limited")
        except Exception as e:
            logger.warning(f"Error collecting system context: {e}")

        return context

    def _classify_severity(
        self, exception: Exception, operation_context: OperationContext
    ) -> ErrorSeverity:
        """Classify error severity based on exception type and context."""
        # Critical errors
        critical_exceptions = [MemoryError, SystemExit, KeyboardInterrupt]
        if any(isinstance(exception, exc) for exc in critical_exceptions):
            return ErrorSeverity.CRITICAL

        # High severity errors
        high_severity_exceptions = [
            ConnectionError,
            OSError,
            PermissionError,
            ImportError,
            AttributeError,
        ]
        if any(isinstance(exception, exc) for exc in high_severity_exceptions):
            return ErrorSeverity.HIGH

        # Medium severity errors
        medium_severity_exceptions = [ValueError, TypeError, KeyError, IndexError]
        if any(isinstance(exception, exc) for exc in medium_severity_exceptions):
            return ErrorSeverity.MEDIUM

        # Check operation context for severity hints
        if operation_context.component_name in ["cache_manager", "configuration_manager"]:
            return ErrorSeverity.HIGH

        return ErrorSeverity.LOW

    def _classify_category(self, exception: Exception) -> ErrorCategory:
        """Classify error into category based on exception type."""
        category_mapping = {
            ConnectionError: ErrorCategory.NETWORK,
            OSError: ErrorCategory.SYSTEM,
            PermissionError: ErrorCategory.AUTHENTICATION,
            MemoryError: ErrorCategory.RESOURCE,
            ValueError: ErrorCategory.VALIDATION,
            TypeError: ErrorCategory.VALIDATION,
            ImportError: ErrorCategory.DEPENDENCY,
            AttributeError: ErrorCategory.CONFIGURATION,
        }

        for exc_type, category in category_mapping.items():
            if isinstance(exception, exc_type):
                return category

        return ErrorCategory.UNKNOWN

    def _generate_recovery_suggestions(
        self,
        exception: Exception,
        operation_context: OperationContext,
        system_context: SystemContext,
    ) -> List[RecoverySuggestion]:
        """Generate intelligent recovery suggestions based on error analysis."""
        suggestions = []

        # Get pattern-based suggestions
        exception_type = type(exception).__name__
        if exception_type in self._error_patterns:
            suggestions.extend(self._error_patterns[exception_type])

        # Context-specific suggestions
        suggestions.extend(
            self._generate_context_specific_suggestions(
                exception, operation_context, system_context
            )
        )

        # Component-specific suggestions
        suggestions.extend(
            self._generate_component_specific_suggestions(exception, operation_context)
        )

        # Remove duplicates and sort by priority
        unique_suggestions = {}
        for suggestion in suggestions:
            key = suggestion.suggestion
            if (
                key not in unique_suggestions
                or suggestion.priority < unique_suggestions[key].priority
            ):
                unique_suggestions[key] = suggestion

        return list(unique_suggestions.values())

    def _generate_context_specific_suggestions(
        self,
        exception: Exception,
        operation_context: OperationContext,
        system_context: SystemContext,
    ) -> List[RecoverySuggestion]:
        """Generate suggestions based on system and operation context."""
        suggestions = []

        # Memory-related suggestions
        if system_context.memory_usage_mb and system_context.memory_usage_mb > 1000:  # > 1GB
            suggestions.append(
                RecoverySuggestion(
                    suggestion="High memory usage detected - consider memory optimization",
                    priority=2,
                    rationale="System memory usage is high, which may contribute to failures",
                    category="resource",
                    estimated_effort="medium",
                    success_probability=0.7,
                )
            )

        # CPU-related suggestions
        if system_context.cpu_usage_percent and system_context.cpu_usage_percent > 80:
            suggestions.append(
                RecoverySuggestion(
                    suggestion="High CPU usage detected - consider load balancing or optimization",
                    priority=3,
                    rationale="High CPU usage may cause timeouts and performance issues",
                    category="resource",
                    estimated_effort="high",
                    success_probability=0.6,
                )
            )

        # Execution time suggestions
        if operation_context.execution_time and operation_context.execution_time > 30:
            suggestions.append(
                RecoverySuggestion(
                    suggestion="Long execution time - consider timeout adjustments or async processing",
                    priority=2,
                    rationale="Operation took longer than expected, may need optimization",
                    category="performance",
                    estimated_effort="medium",
                    success_probability=0.8,
                )
            )

        return suggestions

    def _generate_component_specific_suggestions(
        self, exception: Exception, operation_context: OperationContext
    ) -> List[RecoverySuggestion]:
        """Generate suggestions specific to the component that failed."""
        suggestions = []
        component = operation_context.component_name

        if component == "cache_manager":
            suggestions.extend(
                [
                    RecoverySuggestion(
                        suggestion="Clear cache and restart cache manager",
                        priority=1,
                        rationale="Cache corruption or memory issues may be resolved by clearing",
                        category="cache",
                        estimated_effort="low",
                        success_probability=0.8,
                    ),
                    RecoverySuggestion(
                        suggestion="Check cache configuration and size limits",
                        priority=2,
                        rationale="Cache configuration may need adjustment for current workload",
                        category="configuration",
                        estimated_effort="low",
                        success_probability=0.7,
                    ),
                ]
            )

        elif component == "strategy_generator":
            suggestions.extend(
                [
                    RecoverySuggestion(
                        suggestion="Reduce strategy generation complexity or timeout",
                        priority=1,
                        rationale="Strategy generation may be too complex for current resources",
                        category="configuration",
                        estimated_effort="low",
                        success_probability=0.8,
                    ),
                    RecoverySuggestion(
                        suggestion="Check DPI fingerprint quality and completeness",
                        priority=2,
                        rationale="Poor fingerprint data may cause generation failures",
                        category="data",
                        estimated_effort="medium",
                        success_probability=0.6,
                    ),
                ]
            )

        elif component == "test_coordinator":
            suggestions.extend(
                [
                    RecoverySuggestion(
                        suggestion="Check network connectivity and target domain accessibility",
                        priority=1,
                        rationale="Network issues may prevent successful strategy testing",
                        category="network",
                        estimated_effort="low",
                        success_probability=0.9,
                    ),
                    RecoverySuggestion(
                        suggestion="Verify PCAP capture permissions and disk space",
                        priority=2,
                        rationale="PCAP operations require proper permissions and storage",
                        category="system",
                        estimated_effort="low",
                        success_probability=0.8,
                    ),
                ]
            )

        return suggestions

    def _find_related_errors(self, exception: Exception, component_name: str) -> List[str]:
        """Find related errors that might be connected to this failure."""
        # This is a simplified implementation - in practice, you'd maintain
        # an error correlation database
        related = []

        if isinstance(exception, ConnectionError):
            related.extend(
                [
                    "Network connectivity issues",
                    "DNS resolution failures",
                    "Firewall blocking connections",
                ]
            )

        elif isinstance(exception, MemoryError):
            related.extend(
                [
                    "Memory leaks in application",
                    "Large data processing operations",
                    "Insufficient system memory",
                ]
            )

        elif isinstance(exception, PermissionError):
            related.extend(
                [
                    "File system permission issues",
                    "Authentication failures",
                    "Security policy restrictions",
                ]
            )

        return related

    def _setup_default_patterns(self) -> None:
        """Setup default error patterns and recovery suggestions."""
        self._error_patterns = {
            "ConnectionError": [
                RecoverySuggestion(
                    suggestion="Check network connectivity and retry",
                    priority=1,
                    rationale="Connection errors are often transient network issues",
                    category="network",
                    estimated_effort="low",
                    success_probability=0.8,
                ),
                RecoverySuggestion(
                    suggestion="Verify target service is running and accessible",
                    priority=2,
                    rationale="Service may be down or unreachable",
                    category="dependency",
                    estimated_effort="medium",
                    success_probability=0.7,
                ),
            ],
            "TimeoutError": [
                RecoverySuggestion(
                    suggestion="Increase timeout values and retry",
                    priority=1,
                    rationale="Operation may need more time to complete",
                    category="configuration",
                    estimated_effort="low",
                    success_probability=0.9,
                ),
                RecoverySuggestion(
                    suggestion="Check system performance and resource availability",
                    priority=2,
                    rationale="System may be under high load causing delays",
                    category="resource",
                    estimated_effort="medium",
                    success_probability=0.6,
                ),
            ],
            "MemoryError": [
                RecoverySuggestion(
                    suggestion="Reduce memory usage or increase available memory",
                    priority=1,
                    rationale="Operation requires more memory than available",
                    category="resource",
                    estimated_effort="high",
                    success_probability=0.8,
                ),
                RecoverySuggestion(
                    suggestion="Implement data streaming or chunking",
                    priority=2,
                    rationale="Processing smaller chunks may reduce memory requirements",
                    category="optimization",
                    estimated_effort="high",
                    success_probability=0.7,
                ),
            ],
            "ValueError": [
                RecoverySuggestion(
                    suggestion="Validate input parameters and data formats",
                    priority=1,
                    rationale="Invalid input data is causing processing errors",
                    category="validation",
                    estimated_effort="low",
                    success_probability=0.9,
                ),
                RecoverySuggestion(
                    suggestion="Review data transformation and parsing logic",
                    priority=2,
                    rationale="Data processing logic may need adjustment",
                    category="code",
                    estimated_effort="medium",
                    success_probability=0.7,
                ),
            ],
        }


# Global error context builder instance
error_context_builder = ErrorContextBuilder()
