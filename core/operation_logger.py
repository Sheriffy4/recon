# path: core/operation_logger.py
"""
Operation Logger for Strategy Validation

This module provides logging of DPI bypass operations for validation purposes.
Each operation is logged with a unique ID, type, parameters, and segment number
to enable offline PCAP validation against expected operations.

Requirements: 1.2 - Log operations for validation
"""

import logging
import uuid
import json
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path


@dataclass
class Operation:
    """
    Represents a single DPI bypass operation.

    Attributes:
        operation_id: Unique identifier for this operation
        type: Operation type (split, fake, disorder, fooling, etc.)
        parameters: Operation-specific parameters
        segment_number: TCP segment number this operation applies to
        timestamp: When the operation was logged
        correlation_id: ID linking operations from the same strategy test
    """

    operation_id: str
    type: str
    parameters: Dict[str, Any]
    segment_number: int
    timestamp: str
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert operation to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class StrategyLog:
    """
    Log of all operations for a strategy test.

    Attributes:
        strategy_id: Unique identifier for this strategy test
        strategy_name: Name of the strategy being tested
        domain: Target domain
        timestamp: When the strategy test started
        operations: List of operations performed
        metadata: Additional metadata (target IP, port, etc.)
    """

    strategy_id: str
    strategy_name: str
    domain: str
    timestamp: str
    operations: List[Operation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert strategy log to dictionary for JSON serialization."""
        return {
            "strategy_id": self.strategy_id,
            "strategy_name": self.strategy_name,
            "domain": self.domain,
            "timestamp": self.timestamp,
            "operations": [op.to_dict() for op in self.operations],
            "metadata": self.metadata,
        }


class OperationLogger:
    """
    Logger for DPI bypass operations.

    This class provides thread-safe logging of operations for validation purposes.
    Operations are logged with unique IDs and can be saved to JSON files for
    offline analysis and PCAP validation.
    """

    def __init__(self, log_dir: Optional[Path] = None):
        """
        Initialize operation logger.

        Args:
            log_dir: Directory to save operation logs (default: data/operation_logs)
        """
        self.logger = logging.getLogger("OperationLogger")
        self.log_dir = log_dir or Path("data/operation_logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Thread-safe storage for current strategy logs
        self._lock = threading.RLock()
        self._current_logs: Dict[str, StrategyLog] = {}

        # Global operation counter for debugging
        self._operation_count = 0

        self.logger.info(f"✅ OperationLogger initialized, log_dir={self.log_dir}")

    def start_strategy_log(
        self, strategy_name: str, domain: str, metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Start logging operations for a strategy test.

        Args:
            strategy_name: Name of the strategy being tested
            domain: Target domain
            metadata: Additional metadata (target IP, port, etc.)

        Returns:
            strategy_id: Unique identifier for this strategy test
        """
        strategy_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        strategy_log = StrategyLog(
            strategy_id=strategy_id,
            strategy_name=strategy_name,
            domain=domain,
            timestamp=timestamp,
            metadata=metadata or {},
        )

        with self._lock:
            self._current_logs[strategy_id] = strategy_log

        self.logger.info(
            f"📝 Started strategy log: id={strategy_id[:8]}, "
            f"strategy={strategy_name}, domain={domain}"
        )

        return strategy_id

    def log_operation(
        self,
        strategy_id: str,
        operation_type: str,
        parameters: Dict[str, Any],
        segment_number: int,
        correlation_id: Optional[str] = None,
    ) -> str:
        """
        Log a single operation.

        Args:
            strategy_id: Strategy test identifier
            operation_type: Type of operation (split, fake, disorder, etc.)
            parameters: Operation-specific parameters
            segment_number: TCP segment number
            correlation_id: Optional correlation ID for tracing

        Returns:
            operation_id: Unique identifier for this operation
        """
        operation_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        operation = Operation(
            operation_id=operation_id,
            type=operation_type,
            parameters=parameters,
            segment_number=segment_number,
            timestamp=timestamp,
            correlation_id=correlation_id,
        )

        with self._lock:
            if strategy_id in self._current_logs:
                self._current_logs[strategy_id].operations.append(operation)
                self._operation_count += 1

                self.logger.debug(
                    f"📝 Logged operation: id={operation_id[:8]}, "
                    f"type={operation_type}, segment={segment_number}, "
                    f"params={parameters}"
                )
            else:
                self.logger.warning(
                    f"⚠️ Strategy ID not found: {strategy_id[:8]}, " f"operation not logged"
                )

        return operation_id

    def end_strategy_log(
        self, strategy_id: str, save_to_file: bool = True
    ) -> Optional[StrategyLog]:
        """
        End logging for a strategy test and optionally save to file.

        Args:
            strategy_id: Strategy test identifier
            save_to_file: Whether to save the log to a JSON file

        Returns:
            StrategyLog if found, None otherwise
        """
        with self._lock:
            strategy_log = self._current_logs.pop(strategy_id, None)

        if strategy_log is None:
            self.logger.warning(f"⚠️ Strategy ID not found: {strategy_id[:8]}")
            return None

        self.logger.info(
            f"📝 Ended strategy log: id={strategy_id[:8]}, "
            f"operations={len(strategy_log.operations)}"
        )

        if save_to_file:
            self._save_log_to_file(strategy_log)

        return strategy_log

    def _save_log_to_file(self, strategy_log: StrategyLog):
        """
        Save strategy log to JSON file.

        Args:
            strategy_log: Strategy log to save
        """
        try:
            # Create filename with timestamp and domain
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain_safe = strategy_log.domain.replace(".", "_")
            filename = f"{timestamp}_{domain_safe}_{strategy_log.strategy_id[:8]}.json"
            filepath = self.log_dir / filename

            # Save to JSON
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(strategy_log.to_dict(), f, indent=2, ensure_ascii=False)

            self.logger.info(f"💾 Saved operation log: {filepath}")

        except Exception as e:
            self.logger.error(f"❌ Failed to save operation log: {e}", exc_info=True)

    def get_strategy_log(self, strategy_id: str) -> Optional[StrategyLog]:
        """
        Get current strategy log without ending it.

        Args:
            strategy_id: Strategy test identifier

        Returns:
            StrategyLog if found, None otherwise
        """
        with self._lock:
            return self._current_logs.get(strategy_id)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about operation logging.

        Returns:
            Dictionary with statistics
        """
        with self._lock:
            active_logs = len(self._current_logs)
            total_operations = sum(len(log.operations) for log in self._current_logs.values())

        return {
            "active_strategy_logs": active_logs,
            "total_operations_logged": self._operation_count,
            "operations_in_active_logs": total_operations,
            "log_directory": str(self.log_dir),
        }


# Global operation logger instance
_operation_logger: Optional[OperationLogger] = None
_logger_lock = threading.Lock()


def get_operation_logger() -> OperationLogger:
    """
    Get the global operation logger instance (singleton).

    Returns:
        OperationLogger instance
    """
    global _operation_logger

    if _operation_logger is None:
        with _logger_lock:
            if _operation_logger is None:
                _operation_logger = OperationLogger()

    return _operation_logger


def log_operation(
    strategy_id: str,
    operation_type: str,
    parameters: Dict[str, Any],
    segment_number: int,
    correlation_id: Optional[str] = None,
) -> str:
    """
    Convenience function to log an operation using the global logger.

    Args:
        strategy_id: Strategy test identifier
        operation_type: Type of operation
        parameters: Operation parameters
        segment_number: TCP segment number
        correlation_id: Optional correlation ID

    Returns:
        operation_id: Unique identifier for this operation
    """
    logger = get_operation_logger()
    return logger.log_operation(
        strategy_id, operation_type, parameters, segment_number, correlation_id
    )
