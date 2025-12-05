"""
Structured Logger for Adaptive Monitoring System - Task 7.4 Implementation

Provides structured logging capabilities for detailed diagnostics and problem analysis.
Implements JSON-based logging with contextual information for each testing phase.
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
import threading
import uuid
from contextlib import contextmanager


class LogLevel(Enum):
    """Log levels for structured logging"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogCategory(Enum):
    """Categories for structured logging"""
    SYSTEM = "system"
    STRATEGY_TEST = "strategy_test"
    DPI_ANALYSIS = "dpi_analysis"
    FINGERPRINTING = "fingerprinting"
    PERFORMANCE = "performance"
    VALIDATION = "validation"
    ENGINE_OPERATION = "engine_operation"
    NETWORK = "network"
    ERROR_ANALYSIS = "error_analysis"


@dataclass
class LogContext:
    """Context information for structured logging"""
    session_id: str
    domain: str
    operation: str
    component: str
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceMetrics:
    """Performance metrics for logging"""
    operation_name: str
    start_time: float
    end_time: float
    duration_ms: float
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    network_bytes_sent: Optional[int] = None
    network_bytes_received: Optional[int] = None
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class StrategyTestLog:
    """Structured log entry for strategy testing"""
    strategy_name: str
    domain: str
    test_phase: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None
    network_metrics: Dict[str, Any] = field(default_factory=dict)
    strategy_parameters: Dict[str, Any] = field(default_factory=dict)
    validation_results: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)


class StructuredLogger:
    """
    Structured logger for adaptive monitoring system with JSON output.
    
    Features:
    - JSON-based structured logging
    - Performance metrics tracking
    - Contextual information preservation
    - Thread-safe operation
    - File rotation and retention
    - Real-time log streaming
    """
    
    def __init__(self, 
                 log_file: str = "adaptive_monitoring_structured.log",
                 max_file_size_mb: int = 100,
                 backup_count: int = 5,
                 enable_console: bool = True,
                 log_level: LogLevel = LogLevel.INFO):
        
        self.log_file = Path(log_file)
        self.max_file_size_mb = max_file_size_mb
        self.backup_count = backup_count
        self.enable_console = enable_console
        self.log_level = log_level
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Session tracking
        self.session_id = str(uuid.uuid4())[:8]
        self.session_start = datetime.now()
        
        # Performance tracking
        self._active_operations = {}
        self._performance_history = []
        
        # Statistics
        self.stats = {
            "total_logs": 0,
            "logs_by_level": {level.value: 0 for level in LogLevel},
            "logs_by_category": {cat.value: 0 for cat in LogCategory},
            "errors_count": 0,
            "warnings_count": 0,
            "session_start": self.session_start.isoformat(),
            "session_id": self.session_id
        }
        
        # Initialize logging
        self._setup_logging()
        
        # Log session start
        self.log_system_event("structured_logger_initialized", {
            "session_id": self.session_id,
            "log_file": str(self.log_file),
            "log_level": self.log_level.value
        })
    
    def _setup_logging(self):
        """Setup logging configuration with rotation"""
        try:
            from logging.handlers import RotatingFileHandler
            
            # Create log directory if needed
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Setup file handler with rotation
            self.file_handler = RotatingFileHandler(
                self.log_file,
                maxBytes=self.max_file_size_mb * 1024 * 1024,
                backupCount=self.backup_count,
                encoding='utf-8'
            )
            
            # Setup console handler if enabled
            if self.enable_console:
                self.console_handler = logging.StreamHandler()
            else:
                self.console_handler = None
                
        except Exception as e:
            print(f"Warning: Failed to setup structured logging: {e}")
            self.file_handler = None
            self.console_handler = None
    
    def _write_log_entry(self, entry: Dict[str, Any]):
        """Write structured log entry to file and console"""
        with self._lock:
            try:
                # Convert to JSON
                json_entry = json.dumps(entry, default=str, ensure_ascii=False)
                
                # Write to file
                if self.file_handler:
                    self.file_handler.emit(logging.LogRecord(
                        name="StructuredLogger",
                        level=logging.INFO,
                        pathname="",
                        lineno=0,
                        msg=json_entry,
                        args=(),
                        exc_info=None
                    ))
                
                # Write to console if enabled and appropriate level
                if (self.enable_console and 
                    self.console_handler and 
                    entry.get("level") in ["error", "critical", "warning"]):
                    
                    # Format for console readability
                    console_msg = self._format_for_console(entry)
                    print(console_msg)
                
                # Update statistics
                self.stats["total_logs"] += 1
                level = entry.get("level", "info")
                if level in self.stats["logs_by_level"]:
                    self.stats["logs_by_level"][level] += 1
                
                category = entry.get("category", "system")
                if category in self.stats["logs_by_category"]:
                    self.stats["logs_by_category"][category] += 1
                
                if level in ["error", "critical"]:
                    self.stats["errors_count"] += 1
                elif level == "warning":
                    self.stats["warnings_count"] += 1
                    
            except Exception as e:
                print(f"Error writing structured log: {e}")
    
    def _format_for_console(self, entry: Dict[str, Any]) -> str:
        """Format log entry for console output"""
        timestamp = entry.get("timestamp", "")
        level = entry.get("level", "").upper()
        category = entry.get("category", "")
        message = entry.get("message", "")
        
        # Color coding for different levels
        colors = {
            "ERROR": "\033[91m",    # Red
            "CRITICAL": "\033[95m", # Magenta
            "WARNING": "\033[93m",  # Yellow
            "INFO": "\033[92m",     # Green
            "DEBUG": "\033[94m"     # Blue
        }
        reset_color = "\033[0m"
        
        color = colors.get(level, "")
        
        return f"{color}[{timestamp}] {level} [{category}] {message}{reset_color}"
    
    def log_structured(self, 
                      level: LogLevel,
                      category: LogCategory,
                      message: str,
                      context: Optional[LogContext] = None,
                      data: Optional[Dict[str, Any]] = None):
        """Log structured entry with full context"""
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level.value,
            "category": category.value,
            "message": message,
            "session_id": self.session_id
        }
        
        # Add context information
        if context:
            entry.update({
                "domain": context.domain,
                "operation": context.operation,
                "component": context.component,
                "correlation_id": context.correlation_id,
                "metadata": context.metadata
            })
        
        # Add additional data
        if data:
            entry["data"] = data
        
        self._write_log_entry(entry)
    
    def log_system_event(self, event_name: str, data: Dict[str, Any]):
        """Log system-level events"""
        self.log_structured(
            LogLevel.INFO,
            LogCategory.SYSTEM,
            f"System event: {event_name}",
            data=data
        )
    
    def log_strategy_test_start(self, 
                               strategy_name: str,
                               domain: str,
                               parameters: Dict[str, Any]) -> str:
        """Log start of strategy testing and return operation ID"""
        
        operation_id = str(uuid.uuid4())[:8]
        
        test_log = StrategyTestLog(
            strategy_name=strategy_name,
            domain=domain,
            test_phase="start",
            start_time=datetime.now(),
            strategy_parameters=parameters
        )
        
        # Store for completion tracking
        with self._lock:
            self._active_operations[operation_id] = test_log
        
        self.log_structured(
            LogLevel.INFO,
            LogCategory.STRATEGY_TEST,
            f"Starting strategy test: {strategy_name} for {domain}",
            data={
                "operation_id": operation_id,
                "strategy_name": strategy_name,
                "domain": domain,
                "parameters": parameters,
                "phase": "start"
            }
        )
        
        return operation_id
    
    def log_strategy_test_end(self,
                             operation_id: str,
                             success: bool,
                             error_message: Optional[str] = None,
                             network_metrics: Optional[Dict[str, Any]] = None,
                             validation_results: Optional[Dict[str, Any]] = None):
        """Log end of strategy testing"""
        
        with self._lock:
            if operation_id not in self._active_operations:
                self.log_structured(
                    LogLevel.WARNING,
                    LogCategory.STRATEGY_TEST,
                    f"Unknown operation ID for test completion: {operation_id}"
                )
                return
            
            test_log = self._active_operations[operation_id]
            test_log.end_time = datetime.now()
            test_log.success = success
            test_log.error_message = error_message
            test_log.test_phase = "complete"
            
            if test_log.start_time:
                duration = (test_log.end_time - test_log.start_time).total_seconds() * 1000
                test_log.duration_ms = duration
            
            if network_metrics:
                test_log.network_metrics = network_metrics
            
            if validation_results:
                test_log.validation_results = validation_results
            
            # Remove from active operations
            del self._active_operations[operation_id]
        
        level = LogLevel.INFO if success else LogLevel.ERROR
        message = f"Strategy test {'completed successfully' if success else 'failed'}: {test_log.strategy_name}"
        
        self.log_structured(
            level,
            LogCategory.STRATEGY_TEST,
            message,
            data={
                "operation_id": operation_id,
                "strategy_name": test_log.strategy_name,
                "domain": test_log.domain,
                "success": success,
                "duration_ms": test_log.duration_ms,
                "error_message": error_message,
                "network_metrics": network_metrics or {},
                "validation_results": validation_results or {},
                "phase": "complete"
            }
        )
    
    @contextmanager
    def performance_context(self, operation_name: str, metadata: Optional[Dict[str, Any]] = None):
        """Context manager for performance tracking"""
        
        start_time = time.time()
        operation_id = str(uuid.uuid4())[:8]
        
        # Log operation start
        self.log_structured(
            LogLevel.DEBUG,
            LogCategory.PERFORMANCE,
            f"Performance tracking started: {operation_name}",
            data={
                "operation_id": operation_id,
                "operation_name": operation_name,
                "metadata": metadata or {}
            }
        )
        
        try:
            yield operation_id
            
        except Exception as e:
            # Log performance data even on exception
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            
            metrics = PerformanceMetrics(
                operation_name=operation_name,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                success=False,
                error_message=str(e)
            )
            
            self._record_performance_metrics(operation_id, metrics, metadata)
            raise
            
        else:
            # Log successful completion
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            
            metrics = PerformanceMetrics(
                operation_name=operation_name,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                success=True
            )
            
            self._record_performance_metrics(operation_id, metrics, metadata)
    
    def _record_performance_metrics(self, 
                                   operation_id: str,
                                   metrics: PerformanceMetrics,
                                   metadata: Optional[Dict[str, Any]] = None):
        """Record performance metrics"""
        
        with self._lock:
            self._performance_history.append(metrics)
            
            # Keep only last 1000 entries
            if len(self._performance_history) > 1000:
                self._performance_history = self._performance_history[-1000:]
        
        self.log_structured(
            LogLevel.INFO,
            LogCategory.PERFORMANCE,
            f"Performance metrics: {metrics.operation_name}",
            data={
                "operation_id": operation_id,
                "operation_name": metrics.operation_name,
                "duration_ms": metrics.duration_ms,
                "success": metrics.success,
                "error_message": metrics.error_message,
                "memory_usage_mb": metrics.memory_usage_mb,
                "cpu_usage_percent": metrics.cpu_usage_percent,
                "metadata": metadata or {}
            }
        )
    
    def log_validation_result(self,
                             validation_type: str,
                             target: str,
                             success: bool,
                             details: Dict[str, Any]):
        """Log validation results"""
        
        level = LogLevel.INFO if success else LogLevel.WARNING
        
        self.log_structured(
            level,
            LogCategory.VALIDATION,
            f"Validation {validation_type}: {'PASS' if success else 'FAIL'} for {target}",
            data={
                "validation_type": validation_type,
                "target": target,
                "success": success,
                "details": details
            }
        )
    
    def log_dpi_analysis(self,
                        domain: str,
                        analysis_type: str,
                        results: Dict[str, Any],
                        confidence: float):
        """Log DPI analysis results"""
        
        self.log_structured(
            LogLevel.INFO,
            LogCategory.DPI_ANALYSIS,
            f"DPI analysis completed: {analysis_type} for {domain}",
            data={
                "domain": domain,
                "analysis_type": analysis_type,
                "results": results,
                "confidence": confidence
            }
        )
    
    def log_network_event(self,
                         event_type: str,
                         domain: str,
                         details: Dict[str, Any]):
        """Log network-related events"""
        
        self.log_structured(
            LogLevel.INFO,
            LogCategory.NETWORK,
            f"Network event: {event_type} for {domain}",
            data={
                "event_type": event_type,
                "domain": domain,
                "details": details
            }
        )
    
    def log_error_analysis(self,
                          error_type: str,
                          component: str,
                          error_details: Dict[str, Any],
                          suggested_actions: List[str]):
        """Log error analysis results"""
        
        self.log_structured(
            LogLevel.ERROR,
            LogCategory.ERROR_ANALYSIS,
            f"Error analysis: {error_type} in {component}",
            data={
                "error_type": error_type,
                "component": component,
                "error_details": error_details,
                "suggested_actions": suggested_actions
            }
        )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance metrics summary"""
        
        with self._lock:
            if not self._performance_history:
                return {"message": "No performance data available"}
            
            # Calculate statistics
            durations = [m.duration_ms for m in self._performance_history]
            successful_ops = [m for m in self._performance_history if m.success]
            failed_ops = [m for m in self._performance_history if not m.success]
            
            return {
                "total_operations": len(self._performance_history),
                "successful_operations": len(successful_ops),
                "failed_operations": len(failed_ops),
                "success_rate": len(successful_ops) / len(self._performance_history) if self._performance_history else 0,
                "average_duration_ms": sum(durations) / len(durations) if durations else 0,
                "min_duration_ms": min(durations) if durations else 0,
                "max_duration_ms": max(durations) if durations else 0,
                "operations_by_name": self._get_operations_by_name()
            }
    
    def _get_operations_by_name(self) -> Dict[str, Dict[str, Any]]:
        """Get performance statistics grouped by operation name"""
        
        operations = {}
        
        for metrics in self._performance_history:
            name = metrics.operation_name
            
            if name not in operations:
                operations[name] = {
                    "count": 0,
                    "successful": 0,
                    "failed": 0,
                    "total_duration_ms": 0,
                    "min_duration_ms": float('inf'),
                    "max_duration_ms": 0
                }
            
            op_stats = operations[name]
            op_stats["count"] += 1
            op_stats["total_duration_ms"] += metrics.duration_ms
            op_stats["min_duration_ms"] = min(op_stats["min_duration_ms"], metrics.duration_ms)
            op_stats["max_duration_ms"] = max(op_stats["max_duration_ms"], metrics.duration_ms)
            
            if metrics.success:
                op_stats["successful"] += 1
            else:
                op_stats["failed"] += 1
        
        # Calculate averages
        for name, stats in operations.items():
            if stats["count"] > 0:
                stats["average_duration_ms"] = stats["total_duration_ms"] / stats["count"]
                stats["success_rate"] = stats["successful"] / stats["count"]
        
        return operations
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive logging statistics"""
        
        return {
            **self.stats,
            "performance_summary": self.get_performance_summary(),
            "active_operations": len(self._active_operations),
            "session_duration_minutes": (datetime.now() - self.session_start).total_seconds() / 60
        }
    
    def export_logs(self, 
                   output_file: str,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   categories: Optional[List[LogCategory]] = None) -> bool:
        """Export logs to file with filtering"""
        
        try:
            # This is a simplified implementation
            # In a full implementation, you would read from the log file and filter
            
            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "session_id": self.session_id,
                "statistics": self.get_statistics(),
                "filters": {
                    "start_time": start_time.isoformat() if start_time else None,
                    "end_time": end_time.isoformat() if end_time else None,
                    "categories": [cat.value for cat in categories] if categories else None
                }
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            self.log_system_event("logs_exported", {
                "output_file": output_file,
                "filters_applied": bool(start_time or end_time or categories)
            })
            
            return True
            
        except Exception as e:
            self.log_structured(
                LogLevel.ERROR,
                LogCategory.SYSTEM,
                f"Failed to export logs: {e}",
                data={"output_file": output_file, "error": str(e)}
            )
            return False
    
    def close(self):
        """Close logger and cleanup resources"""
        
        self.log_system_event("structured_logger_closing", {
            "session_duration_minutes": (datetime.now() - self.session_start).total_seconds() / 60,
            "total_logs": self.stats["total_logs"]
        })
        
        if self.file_handler:
            self.file_handler.close()


# Global structured logger instance
_structured_logger: Optional[StructuredLogger] = None


def get_structured_logger() -> StructuredLogger:
    """Get global structured logger instance"""
    global _structured_logger
    
    if _structured_logger is None:
        _structured_logger = StructuredLogger()
    
    return _structured_logger


def initialize_structured_logging(log_file: str = "adaptive_monitoring_structured.log",
                                 enable_console: bool = True,
                                 log_level: LogLevel = LogLevel.INFO) -> StructuredLogger:
    """Initialize global structured logging"""
    global _structured_logger
    
    _structured_logger = StructuredLogger(
        log_file=log_file,
        enable_console=enable_console,
        log_level=log_level
    )
    
    return _structured_logger