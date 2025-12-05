"""
Attack execution logging system.

Provides structured logging for attack execution with configurable
log levels and formats.
"""

import logging
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, Optional
from enum import Enum


class LogLevel(Enum):
    """Log levels for execution logging."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class ExecutionStatus(Enum):
    """Status of attack execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class ExecutionLogEntry:
    """Structured log entry for attack execution."""
    
    timestamp: datetime
    attack_type: str
    attack_name: str
    parameters: Dict[str, Any]
    execution_time_ms: float
    status: ExecutionStatus
    segments_generated: int
    payload_size: int
    connection_id: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['status'] = self.status.value
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class AttackExecutionLogger:
    """
    Logger for attack execution with structured logging support.
    
    Features:
    - Structured log format with JSON support
    - Configurable log levels
    - Automatic timing measurement
    - Context-aware logging
    - Log aggregation and filtering
    """
    
    def __init__(
        self,
        logger_name: str = "attack_execution",
        log_level: LogLevel = LogLevel.INFO,
        structured_format: bool = True
    ):
        """
        Initialize execution logger.
        
        Args:
            logger_name: Name for the logger
            log_level: Minimum log level to record
            structured_format: Use structured JSON format
        """
        self.logger = logging.getLogger(logger_name)
        self.log_level = log_level
        self.structured_format = structured_format
        self._execution_history: list[ExecutionLogEntry] = []
        
        # Configure logger
        self._configure_logger()
    
    def _configure_logger(self):
        """Configure the underlying logger."""
        # Set log level
        level_map = {
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ERROR: logging.ERROR,
        }
        self.logger.setLevel(level_map[self.log_level])
        
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
    
    def log_execution_start(
        self,
        attack_type: str,
        attack_name: str,
        parameters: Dict[str, Any],
        payload_size: int,
        connection_id: Optional[str] = None
    ):
        """
        Log the start of attack execution.
        
        Args:
            attack_type: Type/category of attack
            attack_name: Specific attack name
            parameters: Attack parameters
            payload_size: Size of payload in bytes
            connection_id: Optional connection identifier
        """
        if self.structured_format:
            log_data = {
                "event": "execution_start",
                "attack_type": attack_type,
                "attack_name": attack_name,
                "parameters": parameters,
                "payload_size": payload_size,
                "connection_id": connection_id
            }
            self.logger.info(json.dumps(log_data))
        else:
            self.logger.info(
                f"🎯 Starting attack execution: {attack_name} "
                f"(type={attack_type}, payload_size={payload_size})"
            )
            self.logger.debug(f"📋 Parameters: {parameters}")
    
    def log_execution_complete(
        self,
        attack_type: str,
        attack_name: str,
        parameters: Dict[str, Any],
        execution_time_ms: float,
        status: ExecutionStatus,
        segments_generated: int,
        payload_size: int,
        connection_id: Optional[str] = None,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log the completion of attack execution.
        
        Args:
            attack_type: Type/category of attack
            attack_name: Specific attack name
            parameters: Attack parameters
            execution_time_ms: Execution time in milliseconds
            status: Execution status
            segments_generated: Number of segments generated
            payload_size: Size of payload in bytes
            connection_id: Optional connection identifier
            error_message: Optional error message
            metadata: Optional additional metadata
        """
        # Create log entry
        entry = ExecutionLogEntry(
            timestamp=datetime.now(),
            attack_type=attack_type,
            attack_name=attack_name,
            parameters=parameters,
            execution_time_ms=execution_time_ms,
            status=status,
            segments_generated=segments_generated,
            payload_size=payload_size,
            connection_id=connection_id,
            error_message=error_message,
            metadata=metadata or {}
        )
        
        # Store in history
        self._execution_history.append(entry)
        
        # Log based on status
        if self.structured_format:
            self.logger.info(entry.to_json())
        else:
            status_emoji = {
                ExecutionStatus.SUCCESS: "✅",
                ExecutionStatus.FAILURE: "❌",
                ExecutionStatus.ERROR: "💥",
                ExecutionStatus.TIMEOUT: "⏱️"
            }
            emoji = status_emoji.get(status, "❓")
            
            self.logger.info(
                f"{emoji} Attack {attack_name} completed: "
                f"status={status.value}, time={execution_time_ms:.2f}ms, "
                f"segments={segments_generated}"
            )
            
            if error_message:
                self.logger.error(f"❌ Error: {error_message}")
    
    def get_execution_history(
        self,
        attack_type: Optional[str] = None,
        status: Optional[ExecutionStatus] = None,
        limit: Optional[int] = None
    ) -> list[ExecutionLogEntry]:
        """
        Get execution history with optional filtering.
        
        Args:
            attack_type: Filter by attack type
            status: Filter by execution status
            limit: Maximum number of entries to return
        
        Returns:
            List of execution log entries
        """
        filtered = self._execution_history
        
        if attack_type:
            filtered = [e for e in filtered if e.attack_type == attack_type]
        
        if status:
            filtered = [e for e in filtered if e.status == status]
        
        if limit:
            filtered = filtered[-limit:]
        
        return filtered
    
    def clear_history(self):
        """Clear execution history."""
        self._execution_history.clear()
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """
        Get summary statistics from execution history.
        
        Returns:
            Dictionary with summary statistics
        """
        if not self._execution_history:
            return {
                "total_executions": 0,
                "success_count": 0,
                "failure_count": 0,
                "error_count": 0,
                "avg_execution_time_ms": 0.0
            }
        
        success_count = sum(
            1 for e in self._execution_history 
            if e.status == ExecutionStatus.SUCCESS
        )
        failure_count = sum(
            1 for e in self._execution_history 
            if e.status == ExecutionStatus.FAILURE
        )
        error_count = sum(
            1 for e in self._execution_history 
            if e.status == ExecutionStatus.ERROR
        )
        
        avg_time = sum(
            e.execution_time_ms for e in self._execution_history
        ) / len(self._execution_history)
        
        return {
            "total_executions": len(self._execution_history),
            "success_count": success_count,
            "failure_count": failure_count,
            "error_count": error_count,
            "success_rate": success_count / len(self._execution_history),
            "avg_execution_time_ms": avg_time
        }
