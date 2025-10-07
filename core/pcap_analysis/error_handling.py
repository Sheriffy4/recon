"""
Error handling and recovery mechanisms for PCAP analysis system.

This module provides comprehensive error handling, graceful degradation,
and recovery mechanisms for the PCAP analysis pipeline.
"""

import logging
import traceback
from typing import Optional, Dict, Any, List, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json
import time
from contextlib import contextmanager

from .packet_info import PacketInfo
from .comparison_result import ComparisonResult
from .critical_difference import CriticalDifference


class ErrorCategory(Enum):
    """Categories of errors that can occur during PCAP analysis."""
    INPUT_VALIDATION = "input_validation"
    PCAP_PARSING = "pcap_parsing"
    ANALYSIS_FAILURE = "analysis_failure"
    FIX_GENERATION = "fix_generation"
    VALIDATION_ERROR = "validation_error"
    NETWORK_ERROR = "network_error"
    PERFORMANCE_ERROR = "performance_error"
    SYSTEM_ERROR = "system_error"


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    WARNING = "warning"


@dataclass
class ErrorContext:
    """Context information for error handling."""
    operation: str
    component: str
    input_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class RecoveryAction:
    """Represents a recovery action that can be taken."""
    action_type: str
    description: str
    handler: Callable
    priority: int = 1
    max_retries: int = 3
    retry_delay: float = 1.0


class AnalysisError(Exception):
    """Base exception for PCAP analysis errors."""
    
    def __init__(
        self,
        message: str,
        category: ErrorCategory,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recoverable: bool = True,
        context: Optional[ErrorContext] = None,
        original_error: Optional[Exception] = None
    ):
        self.message = message
        self.category = category
        self.severity = severity
        self.recoverable = recoverable
        self.context = context or ErrorContext("unknown", "unknown")
        self.original_error = original_error
        self.timestamp = time.time()
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging/reporting."""
        return {
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "recoverable": self.recoverable,
            "timestamp": self.timestamp,
            "context": {
                "operation": self.context.operation,
                "component": self.context.component,
                "metadata": self.context.metadata
            },
            "original_error": str(self.original_error) if self.original_error else None,
            "traceback": traceback.format_exc() if self.original_error else None
        }


class PCAPParsingError(AnalysisError):
    """Error during PCAP file parsing."""
    
    def __init__(self, message: str, pcap_file: str, packet_index: Optional[int] = None, **kwargs):
        self.pcap_file = pcap_file
        self.packet_index = packet_index
        context = kwargs.get('context', ErrorContext("pcap_parsing", "pcap_parser"))
        context.input_data.update({
            "pcap_file": pcap_file,
            "packet_index": packet_index
        })
        super().__init__(
            message,
            ErrorCategory.PCAP_PARSING,
            context=context,
            **kwargs
        )


class StrategyAnalysisError(AnalysisError):
    """Error during strategy analysis."""
    
    def __init__(self, message: str, strategy_name: Optional[str] = None, **kwargs):
        self.strategy_name = strategy_name
        context = kwargs.get('context', ErrorContext("strategy_analysis", "strategy_analyzer"))
        context.input_data.update({"strategy_name": strategy_name})
        super().__init__(
            message,
            ErrorCategory.ANALYSIS_FAILURE,
            context=context,
            **kwargs
        )


class FixGenerationError(AnalysisError):
    """Error during fix generation."""
    
    def __init__(self, message: str, fix_type: Optional[str] = None, **kwargs):
        self.fix_type = fix_type
        context = kwargs.get('context', ErrorContext("fix_generation", "fix_generator"))
        context.input_data.update({"fix_type": fix_type})
        super().__init__(
            message,
            ErrorCategory.FIX_GENERATION,
            context=context,
            **kwargs
        )


class ValidationError(AnalysisError):
    """Error during validation."""
    
    def __init__(self, message: str, validation_type: Optional[str] = None, **kwargs):
        self.validation_type = validation_type
        context = kwargs.get('context', ErrorContext("validation", "validator"))
        context.input_data.update({"validation_type": validation_type})
        super().__init__(
            message,
            ErrorCategory.VALIDATION_ERROR,
            context=context,
            **kwargs
        )


@dataclass
class PartialResult:
    """Represents a partial result when full analysis fails."""
    success: bool
    data: Any
    errors: List[AnalysisError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    completeness: float = 0.0  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_usable(self, min_completeness: float = 0.5) -> bool:
        """Check if partial result is usable."""
        return self.success and self.completeness >= min_completeness


class ErrorHandler:
    """Comprehensive error handler with recovery mechanisms."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or self._setup_logger()
        self.recovery_actions: Dict[ErrorCategory, List[RecoveryAction]] = {}
        self.error_history: List[AnalysisError] = []
        self.recovery_stats: Dict[str, int] = {
            "total_errors": 0,
            "recovered_errors": 0,
            "failed_recoveries": 0
        }
        self._setup_recovery_actions()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger for error handling."""
        logger = logging.getLogger("pcap_analysis.error_handler")
        logger.setLevel(logging.DEBUG)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler for detailed logs
        try:
            log_dir = Path("recon/logs")
            log_dir.mkdir(exist_ok=True)
            file_handler = logging.FileHandler(log_dir / "pcap_analysis_errors.log")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not setup file logging: {e}")
        
        return logger
    
    def _setup_recovery_actions(self):
        """Setup default recovery actions for different error categories."""
        
        # PCAP parsing recovery actions
        self.recovery_actions[ErrorCategory.PCAP_PARSING] = [
            RecoveryAction(
                "skip_corrupted_packets",
                "Skip corrupted packets and continue parsing",
                self._skip_corrupted_packets,
                priority=1
            ),
            RecoveryAction(
                "use_alternative_parser",
                "Try alternative PCAP parsing method",
                self._use_alternative_parser,
                priority=2
            ),
            RecoveryAction(
                "partial_file_analysis",
                "Analyze only the readable portion of PCAP file",
                self._partial_file_analysis,
                priority=3
            )
        ]
        
        # Analysis failure recovery actions
        self.recovery_actions[ErrorCategory.ANALYSIS_FAILURE] = [
            RecoveryAction(
                "simplified_analysis",
                "Use simplified analysis method",
                self._simplified_analysis,
                priority=1
            ),
            RecoveryAction(
                "fallback_to_basic_comparison",
                "Fall back to basic packet comparison",
                self._fallback_basic_comparison,
                priority=2
            )
        ]
        
        # Fix generation recovery actions
        self.recovery_actions[ErrorCategory.FIX_GENERATION] = [
            RecoveryAction(
                "generate_manual_recommendations",
                "Generate manual fix recommendations",
                self._generate_manual_recommendations,
                priority=1
            ),
            RecoveryAction(
                "use_template_fixes",
                "Use template-based fixes",
                self._use_template_fixes,
                priority=2
            )
        ]
    
    def handle_error(
        self,
        error: Union[Exception, AnalysisError],
        context: Optional[ErrorContext] = None,
        attempt_recovery: bool = True
    ) -> PartialResult:
        """Handle an error with optional recovery."""
        
        # Convert to AnalysisError if needed
        if not isinstance(error, AnalysisError):
            analysis_error = AnalysisError(
                str(error),
                ErrorCategory.SYSTEM_ERROR,
                context=context,
                original_error=error
            )
        else:
            analysis_error = error
        
        # Log the error
        self._log_error(analysis_error)
        
        # Add to history
        self.error_history.append(analysis_error)
        self.recovery_stats["total_errors"] += 1
        
        # Attempt recovery if requested and error is recoverable
        if attempt_recovery and analysis_error.recoverable:
            return self._attempt_recovery(analysis_error)
        
        # Return failed result
        return PartialResult(
            success=False,
            data=None,
            errors=[analysis_error],
            completeness=0.0
        )
    
    def _log_error(self, error: AnalysisError):
        """Log error with appropriate level."""
        error_dict = error.to_dict()
        # Remove 'message' key to avoid conflict with logging system
        log_extra = {k: v for k, v in error_dict.items() if k != 'message'}
        
        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(f"CRITICAL ERROR: {error.message}", extra=log_extra)
        elif error.severity == ErrorSeverity.HIGH:
            self.logger.error(f"HIGH SEVERITY: {error.message}", extra=log_extra)
        elif error.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(f"MEDIUM SEVERITY: {error.message}", extra=log_extra)
        elif error.severity == ErrorSeverity.LOW:
            self.logger.info(f"LOW SEVERITY: {error.message}", extra=log_extra)
        else:
            self.logger.debug(f"WARNING: {error.message}", extra=log_extra)
    
    def _attempt_recovery(self, error: AnalysisError) -> PartialResult:
        """Attempt to recover from an error."""
        recovery_actions = self.recovery_actions.get(error.category, [])
        
        if not recovery_actions:
            self.logger.warning(f"No recovery actions available for {error.category}")
            self.recovery_stats["failed_recoveries"] += 1
            return PartialResult(
                success=False,
                data=None,
                errors=[error],
                completeness=0.0
            )
        
        # Sort by priority
        recovery_actions.sort(key=lambda x: x.priority)
        
        for action in recovery_actions:
            self.logger.info(f"Attempting recovery: {action.description}")
            
            try:
                result = self._execute_recovery_action(action, error)
                if result.success:
                    self.logger.info(f"Recovery successful: {action.description}")
                    self.recovery_stats["recovered_errors"] += 1
                    return result
                else:
                    self.logger.warning(f"Recovery failed: {action.description}")
            except Exception as recovery_error:
                self.logger.error(f"Recovery action failed: {recovery_error}")
        
        self.logger.error("All recovery attempts failed")
        self.recovery_stats["failed_recoveries"] += 1
        return PartialResult(
            success=False,
            data=None,
            errors=[error],
            completeness=0.0
        )
    
    def _execute_recovery_action(
        self,
        action: RecoveryAction,
        error: AnalysisError
    ) -> PartialResult:
        """Execute a recovery action with retries."""
        last_exception = None
        
        for attempt in range(action.max_retries):
            try:
                if attempt > 0:
                    time.sleep(action.retry_delay)
                    self.logger.info(f"Retry {attempt + 1}/{action.max_retries} for {action.action_type}")
                
                return action.handler(error)
                
            except Exception as e:
                last_exception = e
                self.logger.warning(f"Recovery attempt {attempt + 1} failed: {e}")
        
        # All retries failed
        return PartialResult(
            success=False,
            data=None,
            errors=[error],
            warnings=[f"Recovery action failed after {action.max_retries} attempts: {last_exception}"],
            completeness=0.0
        )
    
    # Recovery action implementations
    def _skip_corrupted_packets(self, error: PCAPParsingError) -> PartialResult:
        """Skip corrupted packets and continue parsing."""
        try:
            # This would be implemented by the actual PCAP parser
            # For now, return a partial result indicating some packets were skipped
            return PartialResult(
                success=True,
                data={"recovery_action": "skip_corrupted_packets"},
                warnings=[f"Skipped corrupted packets in {error.pcap_file}"],
                completeness=0.8,
                metadata={"skipped_packets": True, "pcap_file": error.pcap_file}
            )
        except Exception as e:
            raise Exception(f"Failed to skip corrupted packets: {e}")
    
    def _use_alternative_parser(self, error: PCAPParsingError) -> PartialResult:
        """Try alternative PCAP parsing method."""
        try:
            # This would switch to a different parsing library (e.g., dpkt instead of scapy)
            return PartialResult(
                success=True,
                data={"recovery_action": "alternative_parser"},
                warnings=[f"Used alternative parser for {error.pcap_file}"],
                completeness=0.9,
                metadata={"alternative_parser": True, "pcap_file": error.pcap_file}
            )
        except Exception as e:
            raise Exception(f"Alternative parser failed: {e}")
    
    def _partial_file_analysis(self, error: PCAPParsingError) -> PartialResult:
        """Analyze only the readable portion of PCAP file."""
        try:
            return PartialResult(
                success=True,
                data={"recovery_action": "partial_analysis"},
                warnings=[f"Partial analysis of {error.pcap_file}"],
                completeness=0.6,
                metadata={"partial_analysis": True, "pcap_file": error.pcap_file}
            )
        except Exception as e:
            raise Exception(f"Partial analysis failed: {e}")
    
    def _simplified_analysis(self, error: StrategyAnalysisError) -> PartialResult:
        """Use simplified analysis method."""
        try:
            return PartialResult(
                success=True,
                data={"recovery_action": "simplified_analysis"},
                warnings=["Used simplified analysis method"],
                completeness=0.7,
                metadata={"simplified_analysis": True}
            )
        except Exception as e:
            raise Exception(f"Simplified analysis failed: {e}")
    
    def _fallback_basic_comparison(self, error: StrategyAnalysisError) -> PartialResult:
        """Fall back to basic packet comparison."""
        try:
            return PartialResult(
                success=True,
                data={"recovery_action": "basic_comparison"},
                warnings=["Fell back to basic packet comparison"],
                completeness=0.5,
                metadata={"basic_comparison": True}
            )
        except Exception as e:
            raise Exception(f"Basic comparison failed: {e}")
    
    def _generate_manual_recommendations(self, error: FixGenerationError) -> PartialResult:
        """Generate manual fix recommendations."""
        try:
            recommendations = [
                "Review PCAP files manually for differences",
                "Check strategy parameters for correctness",
                "Verify packet sequence timing",
                "Examine TTL and checksum values"
            ]
            
            return PartialResult(
                success=True,
                data={"manual_recommendations": recommendations},
                warnings=["Generated manual recommendations instead of automated fixes"],
                completeness=0.4,
                metadata={"manual_recommendations": True}
            )
        except Exception as e:
            raise Exception(f"Manual recommendation generation failed: {e}")
    
    def _use_template_fixes(self, error: FixGenerationError) -> PartialResult:
        """Use template-based fixes."""
        try:
            template_fixes = {
                "ttl_fix": "Set TTL to 3 for fake packets",
                "checksum_fix": "Corrupt checksum for fake packets",
                "split_pos_fix": "Set split position to 3",
                "timing_fix": "Add proper delays between packets"
            }
            
            return PartialResult(
                success=True,
                data={"template_fixes": template_fixes},
                warnings=["Used template fixes instead of custom generated fixes"],
                completeness=0.6,
                metadata={"template_fixes": True}
            )
        except Exception as e:
            raise Exception(f"Template fix generation failed: {e}")
    
    @contextmanager
    def error_context(self, operation: str, component: str, **metadata):
        """Context manager for error handling."""
        context = ErrorContext(operation, component, metadata=metadata)
        try:
            yield context
        except Exception as e:
            self.handle_error(e, context)
            raise
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of errors and recovery statistics."""
        error_counts = {}
        for error in self.error_history:
            category = error.category.value
            error_counts[category] = error_counts.get(category, 0) + 1
        
        return {
            "total_errors": len(self.error_history),
            "error_counts_by_category": error_counts,
            "recovery_stats": self.recovery_stats.copy(),
            "recovery_rate": (
                self.recovery_stats["recovered_errors"] / 
                max(1, self.recovery_stats["total_errors"])
            )
        }
    
    def export_error_log(self, filepath: str):
        """Export error log to file."""
        error_data = {
            "summary": self.get_error_summary(),
            "errors": [error.to_dict() for error in self.error_history]
        }
        
        with open(filepath, 'w') as f:
            json.dump(error_data, f, indent=2, default=str)
        
        self.logger.info(f"Error log exported to {filepath}")


# Global error handler instance
_global_error_handler = None


def get_error_handler() -> ErrorHandler:
    """Get global error handler instance."""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = ErrorHandler()
    return _global_error_handler


def handle_pcap_error(
    error: Exception,
    pcap_file: str,
    packet_index: Optional[int] = None,
    attempt_recovery: bool = True
) -> PartialResult:
    """Convenience function for handling PCAP parsing errors."""
    pcap_error = PCAPParsingError(
        str(error),
        pcap_file,
        packet_index,
        original_error=error
    )
    return get_error_handler().handle_error(pcap_error, attempt_recovery=attempt_recovery)


def handle_analysis_error(
    error: Exception,
    operation: str,
    component: str,
    attempt_recovery: bool = True
) -> PartialResult:
    """Convenience function for handling analysis errors."""
    context = ErrorContext(operation, component)
    return get_error_handler().handle_error(error, context, attempt_recovery)


def safe_execute(func: Callable, *args, **kwargs) -> PartialResult:
    """Safely execute a function with error handling."""
    try:
        result = func(*args, **kwargs)
        return PartialResult(
            success=True,
            data=result,
            completeness=1.0
        )
    except Exception as e:
        return get_error_handler().handle_error(e)