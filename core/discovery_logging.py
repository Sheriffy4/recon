"""
Discovery Logging and Monitoring System

This module implements structured logging and monitoring for auto strategy discovery operations,
providing comprehensive logging, metrics collection, and debugging support for discovery sessions.

Requirements: 1.3 from auto-strategy-discovery spec
"""

import logging
import json
import time
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter
from pathlib import Path
import threading
import queue


class LogLevel(Enum):
    """Discovery-specific log levels"""

    TRACE = "TRACE"  # Detailed packet-level tracing
    DEBUG = "DEBUG"  # Debug information
    INFO = "INFO"  # General information
    WARNING = "WARNING"  # Warning messages
    ERROR = "ERROR"  # Error messages
    CRITICAL = "CRITICAL"  # Critical errors


class DiscoveryEventType(Enum):
    """Types of discovery events for structured logging"""

    SESSION_START = "session_start"
    SESSION_END = "session_end"
    STRATEGY_GENERATED = "strategy_generated"
    STRATEGY_TESTED = "strategy_tested"
    DOMAIN_FILTERED = "domain_filtered"
    PACKET_PROCESSED = "packet_processed"
    RESULT_COLLECTED = "result_collected"
    ERROR_OCCURRED = "error_occurred"
    PERFORMANCE_METRIC = "performance_metric"
    DISCOVERY_MILESTONE = "discovery_milestone"


@dataclass
class DiscoveryLogEntry:
    """Structured log entry for discovery operations"""

    timestamp: datetime
    session_id: str
    event_type: DiscoveryEventType
    level: LogLevel
    message: str
    target_domain: str

    # Event-specific data
    event_data: Dict[str, Any] = field(default_factory=dict)

    # Context information
    strategy_name: Optional[str] = None
    component: Optional[str] = None
    thread_id: Optional[int] = None

    # Performance data
    duration_ms: Optional[float] = None
    memory_usage_mb: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary for JSON serialization"""
        return {
            "timestamp": self.timestamp.isoformat(),
            "session_id": self.session_id,
            "event_type": self.event_type.value,
            "level": self.level.value,
            "message": self.message,
            "target_domain": self.target_domain,
            "event_data": self.event_data,
            "strategy_name": self.strategy_name,
            "component": self.component,
            "thread_id": self.thread_id,
            "duration_ms": self.duration_ms,
            "memory_usage_mb": self.memory_usage_mb,
        }

    def to_json(self) -> str:
        """Convert log entry to JSON string"""
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


@dataclass
class DiscoveryMetrics:
    """Metrics for discovery effectiveness monitoring"""

    session_id: str
    target_domain: str
    start_time: datetime

    # Strategy metrics
    strategies_generated: int = 0
    strategies_tested: int = 0
    successful_strategies: int = 0
    failed_strategies: int = 0

    # Domain filtering metrics
    total_packets: int = 0
    filtered_packets: int = 0
    target_domain_packets: int = 0
    background_packets: int = 0

    # Performance metrics
    avg_strategy_test_time_ms: float = 0.0
    min_strategy_test_time_ms: float = float("inf")
    max_strategy_test_time_ms: float = 0.0

    # Result collection metrics
    results_collected: int = 0
    results_filtered: int = 0

    # Error metrics
    errors_count: int = 0
    warnings_count: int = 0

    # Diversity metrics
    unique_attack_types: Set[str] = field(default_factory=set)
    parameter_variations: Dict[str, Set[Any]] = field(default_factory=lambda: defaultdict(set))

    # Time tracking
    last_update: datetime = field(default_factory=datetime.now)

    @property
    def success_rate(self) -> float:
        """Calculate strategy success rate"""
        return (
            self.successful_strategies / self.strategies_tested
            if self.strategies_tested > 0
            else 0.0
        )

    @property
    def filter_effectiveness(self) -> float:
        """Calculate filtering effectiveness (target packets / total packets)"""
        return self.target_domain_packets / self.total_packets if self.total_packets > 0 else 0.0

    @property
    def discovery_efficiency(self) -> float:
        """Calculate overall discovery efficiency score"""
        # Combine success rate, filter effectiveness, and diversity
        diversity_score = len(self.unique_attack_types) / 10.0  # Normalize to 0-1
        return self.success_rate * 0.4 + self.filter_effectiveness * 0.3 + diversity_score * 0.3

    def update_strategy_test(
        self, success: bool, duration_ms: float, attack_types: List[str]
    ) -> None:
        """Update metrics after a strategy test"""
        self.strategies_tested += 1
        if success:
            self.successful_strategies += 1
        else:
            self.failed_strategies += 1

        # Update timing metrics
        if duration_ms < self.min_strategy_test_time_ms:
            self.min_strategy_test_time_ms = duration_ms
        if duration_ms > self.max_strategy_test_time_ms:
            self.max_strategy_test_time_ms = duration_ms

        # Update average (running average)
        if self.strategies_tested == 1:
            self.avg_strategy_test_time_ms = duration_ms
        else:
            self.avg_strategy_test_time_ms = (
                self.avg_strategy_test_time_ms * (self.strategies_tested - 1) + duration_ms
            ) / self.strategies_tested

        # Update diversity metrics
        for attack_type in attack_types:
            self.unique_attack_types.add(attack_type)

        self.last_update = datetime.now()

    def update_filtering(self, total: int, filtered: int, target: int, background: int) -> None:
        """Update filtering metrics"""
        self.total_packets += total
        self.filtered_packets += filtered
        self.target_domain_packets += target
        self.background_packets += background
        self.last_update = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        return {
            "session_id": self.session_id,
            "target_domain": self.target_domain,
            "start_time": self.start_time.isoformat(),
            "strategies_generated": self.strategies_generated,
            "strategies_tested": self.strategies_tested,
            "successful_strategies": self.successful_strategies,
            "failed_strategies": self.failed_strategies,
            "success_rate": self.success_rate,
            "total_packets": self.total_packets,
            "filtered_packets": self.filtered_packets,
            "target_domain_packets": self.target_domain_packets,
            "background_packets": self.background_packets,
            "filter_effectiveness": self.filter_effectiveness,
            "avg_strategy_test_time_ms": self.avg_strategy_test_time_ms,
            "min_strategy_test_time_ms": (
                self.min_strategy_test_time_ms
                if self.min_strategy_test_time_ms != float("inf")
                else 0.0
            ),
            "max_strategy_test_time_ms": self.max_strategy_test_time_ms,
            "results_collected": self.results_collected,
            "results_filtered": self.results_filtered,
            "errors_count": self.errors_count,
            "warnings_count": self.warnings_count,
            "unique_attack_types": list(self.unique_attack_types),
            "parameter_variations": {k: list(v) for k, v in self.parameter_variations.items()},
            "discovery_efficiency": self.discovery_efficiency,
            "last_update": self.last_update.isoformat(),
        }


class DiscoveryLogger:
    """
    Structured logger for discovery operations with target domain filtering.

    Provides comprehensive logging for discovery sessions while ensuring
    that only target domain related log entries are recorded, filtering
    out unrelated domain information.

    Key features:
    - Structured logging with JSON output support
    - Domain-based log filtering for target domain isolation
    - Performance metrics integration
    - Debugging support with detailed tracing
    - Thread-safe operation for concurrent discovery sessions

    Requirements: 1.3 (target domain log filtering)
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        enable_console: bool = True,
        enable_json_output: bool = True,
        max_log_entries: int = 10000,
    ):
        """
        Initialize the discovery logger.

        Args:
            log_file: Optional file path for log output
            enable_console: Whether to enable console logging
            enable_json_output: Whether to enable JSON structured output
            max_log_entries: Maximum number of log entries to keep in memory
        """
        self.log_file = log_file
        self.enable_console = enable_console
        self.enable_json_output = enable_json_output
        self.max_log_entries = max_log_entries

        # Log storage
        self.log_entries: List[DiscoveryLogEntry] = []
        self.log_lock = threading.Lock()

        # Session tracking
        self.active_sessions: Dict[str, str] = {}  # session_id -> target_domain
        self.session_filters: Dict[str, str] = {}  # session_id -> target_domain filter

        # Setup standard logger
        self.logger = logging.getLogger("discovery_logger")
        self._setup_logger()

        # Async logging queue for performance
        self.log_queue = queue.Queue()
        self.log_thread = threading.Thread(target=self._log_worker, daemon=True)
        self.log_thread.start()

        self.logger.info("DiscoveryLogger initialized")

    def _setup_logger(self) -> None:
        """Setup the underlying logging infrastructure"""
        self.logger.setLevel(logging.DEBUG)

        # Create formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        # Console handler
        if self.enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # File handler
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def _log_worker(self) -> None:
        """Background worker for async log processing"""
        while True:
            try:
                log_entry = self.log_queue.get(timeout=1.0)
                if log_entry is None:  # Shutdown signal
                    break

                self._process_log_entry(log_entry)
                self.log_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                # Fallback to standard logger to avoid infinite recursion
                logging.getLogger("discovery_logger_worker").error(
                    f"Error processing log entry: {e}"
                )

    def _process_log_entry(self, entry: DiscoveryLogEntry) -> None:
        """Process a single log entry"""
        with self.log_lock:
            # Add to memory storage
            self.log_entries.append(entry)

            # Maintain size limit
            if len(self.log_entries) > self.max_log_entries:
                self.log_entries = self.log_entries[-self.max_log_entries :]

        # Log to standard logger
        # Map custom TRACE level to DEBUG for standard logging
        if entry.level == LogLevel.TRACE:
            log_level = logging.DEBUG
        else:
            log_level = getattr(logging, entry.level.value)
        self.logger.log(log_level, f"[{entry.session_id}] {entry.message}")

        # JSON output if enabled
        if self.enable_json_output and self.log_file:
            json_file = self.log_file.replace(".log", "_structured.jsonl")
            try:
                with open(json_file, "a", encoding="utf-8") as f:
                    f.write(entry.to_json() + "\n")
            except Exception as e:
                self.logger.error(f"Failed to write JSON log: {e}")

    def start_session_logging(self, session_id: str, target_domain: str) -> None:
        """
        Start logging for a discovery session with target domain filtering.

        Args:
            session_id: Unique session identifier
            target_domain: Target domain for filtering logs

        Requirements: 1.3 (target domain log filtering)
        """
        self.active_sessions[session_id] = target_domain
        self.session_filters[session_id] = target_domain.lower().strip()

        self.log_discovery_event(
            session_id=session_id,
            event_type=DiscoveryEventType.SESSION_START,
            level=LogLevel.INFO,
            message=f"Started discovery session for target domain: {target_domain}",
            target_domain=target_domain,
            event_data={"session_start_time": datetime.now().isoformat()},
        )

    def end_session_logging(self, session_id: str) -> None:
        """
        End logging for a discovery session.

        Args:
            session_id: Session identifier to end
        """
        target_domain = self.active_sessions.get(session_id, "unknown")

        self.log_discovery_event(
            session_id=session_id,
            event_type=DiscoveryEventType.SESSION_END,
            level=LogLevel.INFO,
            message=f"Ended discovery session for target domain: {target_domain}",
            target_domain=target_domain,
            event_data={"session_end_time": datetime.now().isoformat()},
        )

        # Clean up session tracking
        self.active_sessions.pop(session_id, None)
        self.session_filters.pop(session_id, None)

    def log_discovery_event(
        self,
        session_id: str,
        event_type: DiscoveryEventType,
        level: LogLevel,
        message: str,
        target_domain: str,
        event_data: Optional[Dict[str, Any]] = None,
        strategy_name: Optional[str] = None,
        component: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        """
        Log a discovery event with target domain filtering.

        Only logs events related to the target domain, filtering out
        unrelated domain information.

        Args:
            session_id: Discovery session ID
            event_type: Type of discovery event
            level: Log level
            message: Log message
            target_domain: Target domain for the event
            event_data: Optional event-specific data
            strategy_name: Optional strategy name
            component: Optional component name
            duration_ms: Optional duration in milliseconds

        Requirements: 1.3 (target domain log filtering)
        """
        # Check if this event should be logged based on domain filtering
        if not self._should_log_for_domain(session_id, target_domain):
            return

        # Create log entry
        entry = DiscoveryLogEntry(
            timestamp=datetime.now(),
            session_id=session_id,
            event_type=event_type,
            level=level,
            message=message,
            target_domain=target_domain,
            event_data=event_data or {},
            strategy_name=strategy_name,
            component=component,
            thread_id=threading.get_ident(),
            duration_ms=duration_ms,
        )

        # Queue for async processing
        self.log_queue.put(entry)

    def _should_log_for_domain(self, session_id: str, event_domain: str) -> bool:
        """
        Check if an event should be logged based on domain filtering.

        Args:
            session_id: Session ID
            event_domain: Domain associated with the event

        Returns:
            True if event should be logged, False if filtered out

        Requirements: 1.3 (target domain log filtering)
        """
        # If no session filter is set, log everything
        if session_id not in self.session_filters:
            return True

        target_domain = self.session_filters[session_id]
        event_domain_normalized = event_domain.lower().strip()

        # Exact match
        if event_domain_normalized == target_domain:
            return True

        # Subdomain match (e.g., "www.mail.ru" matches "mail.ru")
        if event_domain_normalized.endswith(f".{target_domain}"):
            return True

        return False

    def log_strategy_generated(
        self,
        session_id: str,
        target_domain: str,
        strategy_name: str,
        attack_types: List[str],
        parameters: Dict[str, Any],
    ) -> None:
        """Log strategy generation event"""
        self.log_discovery_event(
            session_id=session_id,
            event_type=DiscoveryEventType.STRATEGY_GENERATED,
            level=LogLevel.INFO,
            message=f"Generated strategy: {strategy_name}",
            target_domain=target_domain,
            strategy_name=strategy_name,
            component="strategy_diversifier",
            event_data={
                "attack_types": attack_types,
                "parameters": parameters,
                "generation_time": datetime.now().isoformat(),
            },
        )

    def log_strategy_tested(
        self,
        session_id: str,
        target_domain: str,
        strategy_name: str,
        success: bool,
        duration_ms: float,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log strategy testing event"""
        self.log_discovery_event(
            session_id=session_id,
            event_type=DiscoveryEventType.STRATEGY_TESTED,
            level=LogLevel.INFO if success else LogLevel.WARNING,
            message=f"Strategy {strategy_name} {'succeeded' if success else 'failed'} in {duration_ms:.1f}ms",
            target_domain=target_domain,
            strategy_name=strategy_name,
            component="strategy_tester",
            duration_ms=duration_ms,
            event_data={
                "success": success,
                "test_duration_ms": duration_ms,
                "result_data": result_data or {},
                "test_time": datetime.now().isoformat(),
            },
        )

    def log_domain_filtering(
        self, session_id: str, target_domain: str, filtered_domain: str, action: str, reason: str
    ) -> None:
        """Log domain filtering event"""
        # Only log if the filtered domain is NOT the target domain (i.e., it was actually filtered)
        if filtered_domain.lower().strip() != target_domain.lower().strip():
            self.log_discovery_event(
                session_id=session_id,
                event_type=DiscoveryEventType.DOMAIN_FILTERED,
                level=LogLevel.DEBUG,
                message=f"Filtered {action} for domain {filtered_domain}: {reason}",
                target_domain=target_domain,
                component="domain_filter",
                event_data={
                    "filtered_domain": filtered_domain,
                    "action": action,
                    "reason": reason,
                    "filter_time": datetime.now().isoformat(),
                },
            )

    def log_packet_processed(
        self, session_id: str, target_domain: str, packet_domain: str, processed: bool, reason: str
    ) -> None:
        """Log packet processing event"""
        self.log_discovery_event(
            session_id=session_id,
            event_type=DiscoveryEventType.PACKET_PROCESSED,
            level=LogLevel.TRACE,
            message=f"Packet for {packet_domain} {'processed' if processed else 'filtered'}: {reason}",
            target_domain=target_domain,
            component="packet_processor",
            event_data={
                "packet_domain": packet_domain,
                "processed": processed,
                "reason": reason,
                "process_time": datetime.now().isoformat(),
            },
        )

    def log_result_collected(
        self, session_id: str, target_domain: str, result_type: str, collected: bool, reason: str
    ) -> None:
        """Log result collection event"""
        self.log_discovery_event(
            session_id=session_id,
            event_type=DiscoveryEventType.RESULT_COLLECTED,
            level=LogLevel.DEBUG,
            message=f"Result {result_type} {'collected' if collected else 'filtered'}: {reason}",
            target_domain=target_domain,
            component="results_collector",
            event_data={
                "result_type": result_type,
                "collected": collected,
                "reason": reason,
                "collection_time": datetime.now().isoformat(),
            },
        )

    def log_error(
        self,
        session_id: str,
        target_domain: str,
        error_message: str,
        component: str,
        exception: Optional[Exception] = None,
    ) -> None:
        """Log error event"""
        event_data = {"error_message": error_message, "error_time": datetime.now().isoformat()}

        if exception:
            event_data.update(
                {"exception_type": type(exception).__name__, "exception_message": str(exception)}
            )

        self.log_discovery_event(
            session_id=session_id,
            event_type=DiscoveryEventType.ERROR_OCCURRED,
            level=LogLevel.ERROR,
            message=f"Error in {component}: {error_message}",
            target_domain=target_domain,
            component=component,
            event_data=event_data,
        )

    def log_performance_metric(
        self,
        session_id: str,
        target_domain: str,
        metric_name: str,
        metric_value: float,
        metric_unit: str,
        component: str,
    ) -> None:
        """Log performance metric"""
        self.log_discovery_event(
            session_id=session_id,
            event_type=DiscoveryEventType.PERFORMANCE_METRIC,
            level=LogLevel.DEBUG,
            message=f"Performance metric {metric_name}: {metric_value} {metric_unit}",
            target_domain=target_domain,
            component=component,
            event_data={
                "metric_name": metric_name,
                "metric_value": metric_value,
                "metric_unit": metric_unit,
                "measurement_time": datetime.now().isoformat(),
            },
        )

    def get_session_logs(self, session_id: str) -> List[DiscoveryLogEntry]:
        """Get all log entries for a specific session"""
        with self.log_lock:
            return [entry for entry in self.log_entries if entry.session_id == session_id]

    def get_logs_by_domain(self, target_domain: str) -> List[DiscoveryLogEntry]:
        """Get all log entries for a specific target domain"""
        with self.log_lock:
            return [entry for entry in self.log_entries if entry.target_domain == target_domain]

    def get_logs_by_event_type(self, event_type: DiscoveryEventType) -> List[DiscoveryLogEntry]:
        """Get all log entries of a specific event type"""
        with self.log_lock:
            return [entry for entry in self.log_entries if entry.event_type == event_type]

    def export_session_logs(self, session_id: str, filename: Optional[str] = None) -> str:
        """Export logs for a specific session to JSON file"""
        session_logs = self.get_session_logs(session_id)

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"discovery_logs_{session_id}_{timestamp}.json"

        export_data = {
            "session_id": session_id,
            "export_time": datetime.now().isoformat(),
            "log_count": len(session_logs),
            "logs": [entry.to_dict() for entry in session_logs],
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

        self.logger.info(f"Exported {len(session_logs)} log entries to: {filename}")
        return filename

    def clear_logs(self, older_than_hours: Optional[int] = None) -> int:
        """Clear log entries, optionally only those older than specified hours"""
        with self.log_lock:
            if older_than_hours is None:
                count = len(self.log_entries)
                self.log_entries.clear()
                return count

            cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
            original_count = len(self.log_entries)
            self.log_entries = [
                entry for entry in self.log_entries if entry.timestamp > cutoff_time
            ]
            return original_count - len(self.log_entries)

    def shutdown(self) -> None:
        """Shutdown the logger and cleanup resources"""
        try:
            # Signal worker thread to stop
            self.log_queue.put(None)

            # Wait for worker thread to finish
            if self.log_thread.is_alive():
                self.log_thread.join(timeout=2.0)

                # Force terminate if still alive
                if self.log_thread.is_alive():
                    self.logger.warning("Log worker thread did not shutdown gracefully")

            self.logger.info("DiscoveryLogger shutdown complete")
        except Exception as e:
            # Fallback logging to avoid infinite recursion
            print(f"Error during DiscoveryLogger shutdown: {e}")


class DiscoveryMetricsCollector:
    """
    Metrics collector for discovery effectiveness monitoring.

    Collects and aggregates metrics about discovery session effectiveness,
    strategy performance, and system behavior during discovery operations.

    Key features:
    - Real-time metrics collection and aggregation
    - Discovery effectiveness scoring
    - Performance trend analysis
    - Integration with discovery logger
    - Thread-safe operation
    """

    def __init__(self, logger: Optional[DiscoveryLogger] = None):
        """
        Initialize the metrics collector.

        Args:
            logger: Optional DiscoveryLogger for integration
        """
        self.logger = logger
        self.metrics: Dict[str, DiscoveryMetrics] = {}
        self.metrics_lock = threading.Lock()

        # Global metrics across all sessions
        self.global_metrics = {
            "total_sessions": 0,
            "successful_sessions": 0,
            "total_strategies_tested": 0,
            "total_successful_strategies": 0,
            "avg_session_duration_minutes": 0.0,
            "most_effective_attack_types": Counter(),
            "domain_success_rates": defaultdict(list),
        }

        self.standard_logger = logging.getLogger("discovery_metrics")
        self.standard_logger.info("DiscoveryMetricsCollector initialized")

    def start_session_metrics(self, session_id: str, target_domain: str) -> None:
        """Start metrics collection for a discovery session"""
        with self.metrics_lock:
            self.metrics[session_id] = DiscoveryMetrics(
                session_id=session_id, target_domain=target_domain, start_time=datetime.now()
            )

            self.global_metrics["total_sessions"] += 1

        if self.logger:
            self.logger.log_discovery_event(
                session_id=session_id,
                event_type=DiscoveryEventType.DISCOVERY_MILESTONE,
                level=LogLevel.INFO,
                message=f"Started metrics collection for session {session_id}",
                target_domain=target_domain,
                component="metrics_collector",
            )

    def record_strategy_generation(self, session_id: str, attack_types: List[str]) -> None:
        """Record strategy generation metrics"""
        with self.metrics_lock:
            if session_id in self.metrics:
                self.metrics[session_id].strategies_generated += 1

                # Update diversity tracking
                for attack_type in attack_types:
                    self.metrics[session_id].unique_attack_types.add(attack_type)

    def record_strategy_test(
        self,
        session_id: str,
        success: bool,
        duration_ms: float,
        attack_types: List[str],
        parameters: Dict[str, Any],
    ) -> None:
        """Record strategy test results and update metrics"""
        with self.metrics_lock:
            if session_id in self.metrics:
                metrics = self.metrics[session_id]
                metrics.update_strategy_test(success, duration_ms, attack_types)

                # Update parameter diversity
                for param, value in parameters.items():
                    # Convert unhashable types to hashable ones
                    if isinstance(value, (list, dict)):
                        hashable_value = str(value)
                    else:
                        hashable_value = value
                    metrics.parameter_variations[param].add(hashable_value)

                # Update global metrics
                self.global_metrics["total_strategies_tested"] += 1
                if success:
                    self.global_metrics["total_successful_strategies"] += 1
                    for attack_type in attack_types:
                        self.global_metrics["most_effective_attack_types"][attack_type] += 1

        # Log performance metric
        if self.logger:
            self.logger.log_performance_metric(
                session_id=session_id,
                target_domain=self.get_session_target_domain(session_id),
                metric_name="strategy_test_duration",
                metric_value=duration_ms,
                metric_unit="ms",
                component="strategy_tester",
            )

    def record_filtering_metrics(
        self, session_id: str, total: int, filtered: int, target: int, background: int
    ) -> None:
        """Record domain filtering metrics"""
        with self.metrics_lock:
            if session_id in self.metrics:
                self.metrics[session_id].update_filtering(total, filtered, target, background)

    def record_result_collection(self, session_id: str, collected: bool) -> None:
        """Record result collection metrics"""
        with self.metrics_lock:
            if session_id in self.metrics:
                if collected:
                    self.metrics[session_id].results_collected += 1
                else:
                    self.metrics[session_id].results_filtered += 1

    def record_error(self, session_id: str, error_type: str) -> None:
        """Record error occurrence"""
        with self.metrics_lock:
            if session_id in self.metrics:
                if error_type.lower() in ["error", "critical"]:
                    self.metrics[session_id].errors_count += 1
                elif error_type.lower() == "warning":
                    self.metrics[session_id].warnings_count += 1

    def end_session_metrics(self, session_id: str, successful: bool) -> DiscoveryMetrics:
        """End metrics collection for a session and return final metrics"""
        with self.metrics_lock:
            if session_id not in self.metrics:
                raise ValueError(f"No metrics found for session {session_id}")

            metrics = self.metrics[session_id]

            # Update global metrics
            if successful:
                self.global_metrics["successful_sessions"] += 1

            # Calculate session duration
            session_duration_minutes = (datetime.now() - metrics.start_time).total_seconds() / 60.0

            # Update average session duration (running average)
            total_sessions = self.global_metrics["total_sessions"]
            current_avg = self.global_metrics["avg_session_duration_minutes"]
            self.global_metrics["avg_session_duration_minutes"] = (
                current_avg * (total_sessions - 1) + session_duration_minutes
            ) / total_sessions

            # Record domain success rate
            self.global_metrics["domain_success_rates"][metrics.target_domain].append(
                metrics.success_rate
            )

            return metrics

    def get_session_metrics(self, session_id: str) -> Optional[DiscoveryMetrics]:
        """Get current metrics for a session"""
        with self.metrics_lock:
            return self.metrics.get(session_id)

    def get_session_target_domain(self, session_id: str) -> str:
        """Get target domain for a session"""
        with self.metrics_lock:
            metrics = self.metrics.get(session_id)
            return metrics.target_domain if metrics else "unknown"

    def get_global_metrics(self) -> Dict[str, Any]:
        """Get global metrics across all sessions"""
        with self.metrics_lock:
            # Calculate derived metrics
            total_sessions = self.global_metrics["total_sessions"]
            successful_sessions = self.global_metrics["successful_sessions"]

            global_success_rate = (
                successful_sessions / total_sessions if total_sessions > 0 else 0.0
            )

            strategy_success_rate = (
                self.global_metrics["total_successful_strategies"]
                / self.global_metrics["total_strategies_tested"]
                if self.global_metrics["total_strategies_tested"] > 0
                else 0.0
            )

            # Calculate average domain success rates
            avg_domain_success_rates = {}
            for domain, rates in self.global_metrics["domain_success_rates"].items():
                avg_domain_success_rates[domain] = sum(rates) / len(rates) if rates else 0.0

            return {
                "total_sessions": total_sessions,
                "successful_sessions": successful_sessions,
                "global_success_rate": global_success_rate,
                "total_strategies_tested": self.global_metrics["total_strategies_tested"],
                "total_successful_strategies": self.global_metrics["total_successful_strategies"],
                "strategy_success_rate": strategy_success_rate,
                "avg_session_duration_minutes": self.global_metrics["avg_session_duration_minutes"],
                "most_effective_attack_types": dict(
                    self.global_metrics["most_effective_attack_types"].most_common(10)
                ),
                "avg_domain_success_rates": avg_domain_success_rates,
                "active_sessions": len(self.metrics),
            }

    def generate_effectiveness_report(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate discovery effectiveness report"""
        if session_id:
            # Session-specific report
            metrics = self.get_session_metrics(session_id)
            if not metrics:
                return {"error": f"No metrics found for session {session_id}"}

            return {
                "session_id": session_id,
                "target_domain": metrics.target_domain,
                "report_type": "session_specific",
                "metrics": metrics.to_dict(),
                "effectiveness_score": metrics.discovery_efficiency,
                "recommendations": self._generate_session_recommendations(metrics),
            }
        else:
            # Global report
            global_metrics = self.get_global_metrics()

            return {
                "report_type": "global",
                "global_metrics": global_metrics,
                "recommendations": self._generate_global_recommendations(global_metrics),
            }

    def _generate_session_recommendations(self, metrics: DiscoveryMetrics) -> List[str]:
        """Generate recommendations based on session metrics"""
        recommendations = []

        if metrics.success_rate < 0.3:
            recommendations.append(
                "Low success rate - consider trying more diverse attack strategies"
            )

        if metrics.filter_effectiveness < 0.8:
            recommendations.append(
                "Poor filtering effectiveness - check domain filtering configuration"
            )

        if metrics.avg_strategy_test_time_ms > 5000:
            recommendations.append("High strategy test times - consider optimizing test parameters")

        if len(metrics.unique_attack_types) < 3:
            recommendations.append("Limited attack type diversity - enable more attack types")

        if metrics.errors_count > metrics.strategies_tested * 0.1:
            recommendations.append("High error rate - investigate system stability issues")

        return recommendations

    def _generate_global_recommendations(self, global_metrics: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on global metrics"""
        recommendations = []

        if global_metrics["global_success_rate"] < 0.5:
            recommendations.append(
                "Overall low success rate - review discovery strategy configuration"
            )

        if global_metrics["strategy_success_rate"] < 0.4:
            recommendations.append(
                "Poor strategy effectiveness - consider updating attack templates"
            )

        if global_metrics["avg_session_duration_minutes"] > 30:
            recommendations.append(
                "Long session durations - consider reducing max strategies or duration limits"
            )

        # Analyze most effective attack types
        most_effective = global_metrics.get("most_effective_attack_types", {})
        if most_effective:
            top_attack = max(most_effective.items(), key=lambda x: x[1])
            recommendations.append(
                f"Most effective attack type: {top_attack[0]} - prioritize in future sessions"
            )

        return recommendations

    def export_metrics(self, filename: Optional[str] = None) -> str:
        """Export all metrics to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"discovery_metrics_{timestamp}.json"

        export_data = {
            "export_time": datetime.now().isoformat(),
            "global_metrics": self.get_global_metrics(),
            "session_metrics": {
                session_id: metrics.to_dict() for session_id, metrics in self.metrics.items()
            },
            "effectiveness_report": self.generate_effectiveness_report(),
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

        self.standard_logger.info(f"Exported metrics to: {filename}")
        return filename


# Global instances for easy access
_global_logger: Optional[DiscoveryLogger] = None
_global_metrics_collector: Optional[DiscoveryMetricsCollector] = None


def get_discovery_logger() -> DiscoveryLogger:
    """Get or create global discovery logger instance"""
    global _global_logger
    if _global_logger is None:
        log_file = f"discovery_logs_{datetime.now().strftime('%Y%m%d')}.log"
        _global_logger = DiscoveryLogger(log_file=log_file)
    return _global_logger


def get_metrics_collector() -> DiscoveryMetricsCollector:
    """Get or create global metrics collector instance"""
    global _global_metrics_collector
    if _global_metrics_collector is None:
        _global_metrics_collector = DiscoveryMetricsCollector(logger=get_discovery_logger())
    return _global_metrics_collector


# Example usage and testing
if __name__ == "__main__":
    # Create logger and metrics collector
    logger = DiscoveryLogger(log_file="test_discovery.log")
    metrics = DiscoveryMetricsCollector(logger)

    # Simulate discovery session
    session_id = "test_session_001"
    target_domain = "example.com"

    print("Testing discovery logging and monitoring...")

    # Start session
    logger.start_session_logging(session_id, target_domain)
    metrics.start_session_metrics(session_id, target_domain)

    # Simulate strategy generation and testing
    for i in range(5):
        strategy_name = f"test_strategy_{i+1}"
        attack_types = ["fragmentation", "disorder"]
        parameters = {"split_pos": i + 1, "ttl": 2}

        # Log strategy generation
        logger.log_strategy_generated(
            session_id, target_domain, strategy_name, attack_types, parameters
        )
        metrics.record_strategy_generation(session_id, attack_types)

        # Simulate strategy testing
        import random

        success = random.choice([True, False])
        duration_ms = random.uniform(100, 2000)

        logger.log_strategy_tested(session_id, target_domain, strategy_name, success, duration_ms)
        metrics.record_strategy_test(session_id, success, duration_ms, attack_types, parameters)

        # Simulate some filtering
        metrics.record_filtering_metrics(session_id, 100, 20, 80, 20)

        print(f"  Tested strategy {i+1}: {'✓' if success else '✗'} ({duration_ms:.1f}ms)")

    # End session
    final_metrics = metrics.end_session_metrics(session_id, True)
    logger.end_session_logging(session_id)

    # Generate reports
    effectiveness_report = metrics.generate_effectiveness_report(session_id)

    print(f"\nSession Results:")
    print(f"  Success rate: {final_metrics.success_rate:.1%}")
    print(f"  Filter effectiveness: {final_metrics.filter_effectiveness:.1%}")
    print(f"  Discovery efficiency: {final_metrics.discovery_efficiency:.3f}")
    print(f"  Unique attack types: {len(final_metrics.unique_attack_types)}")

    # Export data
    log_file = logger.export_session_logs(session_id)
    metrics_file = metrics.export_metrics()

    print(f"\nExported:")
    print(f"  Logs: {log_file}")
    print(f"  Metrics: {metrics_file}")

    # Cleanup
    logger.shutdown()

    print("Discovery logging and monitoring test completed successfully!")
