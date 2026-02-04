"""
Telemetry collection interfaces for UnifiedBypassEngine refactoring.

This module defines the abstract interfaces for telemetry collection
components.

Feature: unified-engine-refactoring
Requirements: 6.1, 6.2, 6.4
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class ITelemetryCollector(ABC):
    """
    Interface for telemetry collection from bypass engines.

    This interface defines the contract for collecting, aggregating,
    and managing telemetry data from bypass engine operations.

    Requirements:
    - 6.1: Accurate ClientHello/ServerHello counting
    - 6.2: Retransmission tracking and rate calculation
    - 6.4: Structured, machine-readable metrics
    """

    @abstractmethod
    def collect_metrics(self, engine: Any) -> Dict[str, Any]:
        """
        Collect metrics from bypass engine.

        This method extracts telemetry data from the bypass engine
        and returns it in a structured format.

        Args:
            engine: The bypass engine instance to collect metrics from

        Returns:
            Dictionary containing structured telemetry metrics

        Requirement 6.4: Structured, machine-readable metrics
        """
        pass

    @abstractmethod
    def reset_metrics(self, engine: Any) -> None:
        """
        Reset engine metrics for new test.

        This method clears all telemetry counters in the engine
        to prepare for a fresh test run.

        Args:
            engine: The bypass engine instance to reset

        Requirement 6.4: Telemetry reset capabilities
        """
        pass

    @abstractmethod
    def aggregate_metrics(self, metrics_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate multiple metric snapshots.

        This method combines multiple telemetry snapshots into
        a single aggregated view for analysis.

        Args:
            metrics_list: List of telemetry snapshots to aggregate

        Returns:
            Dictionary containing aggregated metrics

        Requirement 6.4: Structured, machine-readable metrics
        """
        pass

    @abstractmethod
    def calculate_retransmission_rate(self, metrics: Dict[str, Any]) -> float:
        """
        Calculate retransmission rate from metrics.

        This method computes the percentage of retransmissions
        relative to total packets for validation purposes.

        Args:
            metrics: Telemetry metrics containing packet counts

        Returns:
            Retransmission rate as a percentage (0.0 to 100.0)

        Requirement 6.2: Retransmission tracking and rate calculation
        """
        pass
