"""
Attack error logging system with stack traces and categorization.

Provides detailed error logging with automatic categorization,
stack trace capture, and error frequency tracking.
"""

import logging
import traceback
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, Optional, List
from enum import Enum
from collections import defaultdict


class ErrorCategory(Enum):
    """Categories of errors that can occur during attack execution."""
    PARAMETER_ERROR = "parameter_error"
    EXECUTION_ERROR = "execution_error"
    NETWORK_ERROR = "network_error"
    TIMEOUT_ERROR = "timeout_error"
    VALIDATION_ERROR = "validation_error"
    RESOURCE_ERROR = "resource_error"
    UNKNOWN_ERROR = "unknown_error"


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorLogEntry:
    """Structured log entry for errors."""
    
    timestamp: datetime
    attack_type: str
    attack_name: str
    error_category: ErrorCategory
    error_severity: ErrorSeverity
    error_type: str
    error_message: str
    stack_trace: str
    parameters: Dict[str, Any]
    connection_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['error_category'] = self.error_category.value
        data['error_severity'] = self.error_severity.value
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class AttackErrorLogger:
    """
    Logger for attack errors with categorization and tracking.
    
    Features:
    - Automatic error categorization
    - Stack trace capture
    - Error frequency tracking
    - Severity assessment
    - Error pattern detection
    """
    
    def __init__(
        self,
        logger_name: str = "attack_errors",
        structured_format: bool = True
    ):
        """
        Initialize error logger.
        
        Args:
            logger_name: Name for the logger
            structured_format: Use structured JSON format
        """
        self.logger = logging.getLogger(logger_name)
        self.structured_format = structured_format
        self._error_history: List[ErrorLogEntry] = []
        self._error_frequency: Dict[str, int] = defaultdict(int)
        self._error_by_category: Dict[ErrorCategory, int] = defaultdict(int)
        
        # Configure logger
        self._configure_logger()
    
    def _configure_logger(self):
        """Configure the underlying logger."""
        self.logger.setLevel(logging.ERROR)
        
        # Add handler if not already present
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            if self.structured_format:
                formatter = logging.Formatter(
                    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                    '"logger": "%(name)s", "message": %(message)s}'
                )
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def log_error(
        self,
        attack_type: str,
        attack_name: str,
        exception: Exception,
        parameters: Dict[str, Any],
        connection_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Log an error with automatic categorization.
        
        Args:
            attack_type: Type/category of attack
            attack_name: Specific attack name
            exception: The exception that occurred
            parameters: Attack parameters
            connection_id: Optional connection identifier
            context: Optional additional context
        """
        # Categorize error
        category = self._categorize_error(exception)
        severity = self._assess_severity(exception, category)
        
        # Capture stack trace
        stack_trace = ''.join(traceback.format_exception(
            type(exception), exception, exception.__traceback__
        ))
        
        # Create log entry
        entry = ErrorLogEntry(
            timestamp=datetime.now(),
            attack_type=attack_type,
            attack_name=attack_name,
            error_category=category,
            error_severity=severity,
            error_type=type(exception).__name__,
            error_message=str(exception),
            stack_trace=stack_trace,
            parameters=parameters,
            connection_id=connection_id,
            context=context or {}
        )
        
        # Store in history
        self._error_history.append(entry)
        
        # Update frequency tracking
        error_key = f"{attack_name}:{type(exception).__name__}"
        self._error_frequency[error_key] += 1
        self._error_by_category[category] += 1
        
        # Log the error
        if self.structured_format:
            self.logger.error(entry.to_json())
        else:
            severity_emoji = {
                ErrorSeverity.LOW: "⚠️",
                ErrorSeverity.MEDIUM: "❌",
                ErrorSeverity.HIGH: "🔥",
                ErrorSeverity.CRITICAL: "💥"
            }
            emoji = severity_emoji.get(severity, "❓")
            
            self.logger.error(
                f"{emoji} Error in {attack_name}: {type(exception).__name__}"
            )
            self.logger.error(f"❌ Message: {exception}")
            self.logger.error(f"📋 Category: {category.value}")
            self.logger.error(f"📊 Severity: {severity.value}")
            self.logger.debug(f"📋 Stack trace:\n{stack_trace}")
    
    def _categorize_error(self, exception: Exception) -> ErrorCategory:
        """
        Automatically categorize an error based on exception type.
        
        Args:
            exception: The exception to categorize
        
        Returns:
            Error category
        """
        exception_type = type(exception).__name__
        exception_msg = str(exception).lower()
        
        # Parameter errors
        if exception_type in ('ValueError', 'TypeError', 'KeyError'):
            if 'parameter' in exception_msg or 'param' in exception_msg:
                return ErrorCategory.PARAMETER_ERROR
        
        # Validation errors
        if 'validation' in exception_msg or 'invalid' in exception_msg:
            return ErrorCategory.VALIDATION_ERROR
        
        # Network errors
        if exception_type in ('ConnectionError', 'TimeoutError', 'OSError'):
            return ErrorCategory.NETWORK_ERROR
        
        # Timeout errors
        if 'timeout' in exception_msg or exception_type == 'TimeoutError':
            return ErrorCategory.TIMEOUT_ERROR
        
        # Resource errors
        if exception_type in ('MemoryError', 'ResourceWarning'):
            return ErrorCategory.RESOURCE_ERROR
        
        # Execution errors
        if exception_type in ('RuntimeError', 'AssertionError'):
            return ErrorCategory.EXECUTION_ERROR
        
        return ErrorCategory.UNKNOWN_ERROR
    
    def _assess_severity(
        self,
        exception: Exception,
        category: ErrorCategory
    ) -> ErrorSeverity:
        """
        Assess the severity of an error.
        
        Args:
            exception: The exception
            category: Error category
        
        Returns:
            Error severity
        """
        # Critical errors
        if isinstance(exception, (MemoryError, SystemError)):
            return ErrorSeverity.CRITICAL
        
        # High severity
        if category in (ErrorCategory.RESOURCE_ERROR, ErrorCategory.NETWORK_ERROR):
            return ErrorSeverity.HIGH
        
        # Medium severity
        if category in (ErrorCategory.EXECUTION_ERROR, ErrorCategory.TIMEOUT_ERROR):
            return ErrorSeverity.MEDIUM
        
        # Low severity
        return ErrorSeverity.LOW
    
    def get_error_history(
        self,
        attack_type: Optional[str] = None,
        category: Optional[ErrorCategory] = None,
        severity: Optional[ErrorSeverity] = None,
        limit: Optional[int] = None
    ) -> List[ErrorLogEntry]:
        """
        Get error history with optional filtering.
        
        Args:
            attack_type: Filter by attack type
            category: Filter by error category
            severity: Filter by error severity
            limit: Maximum number of entries to return
        
        Returns:
            List of error log entries
        """
        filtered = self._error_history
        
        if attack_type:
            filtered = [e for e in filtered if e.attack_type == attack_type]
        
        if category:
            filtered = [e for e in filtered if e.error_category == category]
        
        if severity:
            filtered = [e for e in filtered if e.error_severity == severity]
        
        if limit:
            filtered = filtered[-limit:]
        
        return filtered
    
    def get_error_frequency(
        self,
        top_n: Optional[int] = None
    ) -> Dict[str, int]:
        """
        Get error frequency statistics.
        
        Args:
            top_n: Return only top N most frequent errors
        
        Returns:
            Dictionary of error frequencies
        """
        if top_n:
            sorted_errors = sorted(
                self._error_frequency.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return dict(sorted_errors[:top_n])
        
        return dict(self._error_frequency)
    
    def get_category_distribution(self) -> Dict[str, int]:
        """
        Get distribution of errors by category.
        
        Returns:
            Dictionary of category counts
        """
        return {
            category.value: count
            for category, count in self._error_by_category.items()
        }
    
    def get_error_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics for errors.
        
        Returns:
            Dictionary with error summary
        """
        if not self._error_history:
            return {
                "total_errors": 0,
                "by_category": {},
                "by_severity": {},
                "most_frequent": []
            }
        
        # Count by severity
        by_severity = defaultdict(int)
        for entry in self._error_history:
            by_severity[entry.error_severity.value] += 1
        
        # Get most frequent errors
        most_frequent = sorted(
            self._error_frequency.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            "total_errors": len(self._error_history),
            "by_category": self.get_category_distribution(),
            "by_severity": dict(by_severity),
            "most_frequent": [
                {"error": error, "count": count}
                for error, count in most_frequent
            ]
        }
    
    def clear_history(self):
        """Clear error history and frequency tracking."""
        self._error_history.clear()
        self._error_frequency.clear()
        self._error_by_category.clear()
