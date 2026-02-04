"""
Telemetry collector implementation for UnifiedBypassEngine refactoring.

This module provides the concrete implementation of telemetry collection
for bypass engine operations.

Feature: unified-engine-refactoring
Requirements: 6.1, 6.2, 6.4
"""

import time
import logging
from typing import Dict, Any, List, Optional
from dataclasses import asdict

from core.unified_engine_models import TelemetrySnapshot, BypassDefaults
from .interfaces import ITelemetryCollector


class TelemetryCollector(ITelemetryCollector):
    """
    Concrete implementation of telemetry collection.

    This class provides structured metric collection, aggregation,
    and validation for bypass engine operations.

    Requirements:
    - 6.1: Accurate ClientHello/ServerHello counting
    - 6.2: Retransmission tracking and rate calculation
    - 6.4: Structured, machine-readable metrics
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize telemetry collector.

        Args:
            logger: Optional logger instance for telemetry operations
        """
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._collection_count = 0
        self._last_collection_time = 0.0

    def collect_metrics(self, engine: Any) -> Dict[str, Any]:
        """
        Collect metrics from bypass engine.

        This method extracts telemetry data from the bypass engine
        and returns it in a structured format using TelemetrySnapshot.

        Args:
            engine: The bypass engine instance to collect metrics from

        Returns:
            Dictionary containing structured telemetry metrics

        Requirement 6.4: Structured, machine-readable metrics
        """
        try:
            self._collection_count += 1
            self._last_collection_time = time.time()

            # Extract telemetry data from engine
            raw_telemetry = self._extract_engine_telemetry(engine)

            # Create structured telemetry snapshot
            snapshot = TelemetrySnapshot(
                timestamp=time.time(),
                client_hellos=raw_telemetry.get("client_hellos", 0),
                server_hellos=raw_telemetry.get("server_hellos", 0),
                retransmissions=raw_telemetry.get("retransmissions", 0),
                total_packets=raw_telemetry.get("total_packets", 0),
                fake_packets_sent=raw_telemetry.get("fake_packets_sent", 0),
                bytes_processed=raw_telemetry.get("bytes_processed", 0),
                connection_attempts=raw_telemetry.get("connection_attempts", 0),
                successful_connections=raw_telemetry.get("successful_connections", 0),
            )

            # Convert to dictionary format
            metrics = snapshot.to_dict()

            # Add collection metadata
            metrics["collection_id"] = self._collection_count
            metrics["collector_timestamp"] = self._last_collection_time

            # Add derived metrics
            metrics["retransmission_rate"] = self.calculate_retransmission_rate(metrics)
            metrics["handshake_ratio"] = self._calculate_handshake_ratio(metrics)
            metrics["packet_efficiency"] = self._calculate_packet_efficiency(metrics)

            self.logger.debug(
                f"Collected telemetry: {metrics['total_packets']} packets, "
                f"{metrics['client_hellos']} ClientHellos, "
                f"{metrics['server_hellos']} ServerHellos, "
                f"{metrics['retransmissions']} retransmissions"
            )

            return metrics

        except Exception as e:
            self.logger.error(f"Failed to collect metrics from engine: {e}")
            # Return empty metrics on failure
            return self._create_empty_metrics()

    def reset_metrics(self, engine: Any) -> None:
        """
        Reset engine metrics for new test.

        This method clears all telemetry counters in the engine
        to prepare for a fresh test run.

        Args:
            engine: The bypass engine instance to reset

        Requirement 6.4: Telemetry reset capabilities
        """
        try:
            # Check if engine has reset method
            if hasattr(engine, "reset_telemetry"):
                engine.reset_telemetry()
                self.logger.debug("Engine telemetry reset via reset_telemetry method")
            elif hasattr(engine, "_init_telemetry") and hasattr(engine, "_telemetry"):
                # Direct reset for engines with _telemetry attribute
                if hasattr(engine, "_tlock"):
                    with engine._tlock:
                        engine._telemetry = engine._init_telemetry()
                else:
                    engine._telemetry = engine._init_telemetry()
                self.logger.debug("Engine telemetry reset via direct _telemetry initialization")
            else:
                self.logger.warning("Engine does not support telemetry reset")

        except Exception as e:
            self.logger.error(f"Failed to reset engine metrics: {e}")

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
        if not metrics_list:
            return self._create_empty_metrics()

        try:
            # Initialize aggregated metrics
            aggregated = {
                "timestamp": time.time(),
                "client_hellos": 0,
                "server_hellos": 0,
                "retransmissions": 0,
                "total_packets": 0,
                "fake_packets_sent": 0,
                "bytes_processed": 0,
                "connection_attempts": 0,
                "successful_connections": 0,
                "snapshot_count": len(metrics_list),
                "time_span": 0.0,
                "retransmission_rate": 0.0,
                "handshake_ratio": 0.0,
                "packet_efficiency": 0.0,
            }

            # Track time span
            timestamps = []
            for m in metrics_list:
                if isinstance(m, dict) and "timestamp" in m:
                    try:
                        ts = float(m["timestamp"])
                        timestamps.append(ts)
                    except (ValueError, TypeError):
                        continue
            if len(timestamps) > 1:
                aggregated["time_span"] = max(timestamps) - min(timestamps)
                aggregated["earliest_timestamp"] = min(timestamps)
                aggregated["latest_timestamp"] = max(timestamps)
            elif len(timestamps) == 1:
                aggregated["time_span"] = 0.0
                aggregated["earliest_timestamp"] = timestamps[0]
                aggregated["latest_timestamp"] = timestamps[0]

            # Sum up all metrics
            for metrics in metrics_list:
                if not isinstance(metrics, dict):
                    continue

                # Use safe integer conversion for all fields
                aggregated["client_hellos"] += self._safe_int(metrics.get("client_hellos", 0))
                aggregated["server_hellos"] += self._safe_int(metrics.get("server_hellos", 0))
                aggregated["retransmissions"] += self._safe_int(metrics.get("retransmissions", 0))
                aggregated["total_packets"] += self._safe_int(metrics.get("total_packets", 0))
                aggregated["fake_packets_sent"] += self._safe_int(
                    metrics.get("fake_packets_sent", 0)
                )
                aggregated["bytes_processed"] += self._safe_int(metrics.get("bytes_processed", 0))
                aggregated["connection_attempts"] += self._safe_int(
                    metrics.get("connection_attempts", 0)
                )
                aggregated["successful_connections"] += self._safe_int(
                    metrics.get("successful_connections", 0)
                )

            # Calculate derived metrics
            aggregated["retransmission_rate"] = self.calculate_retransmission_rate(aggregated)
            aggregated["handshake_ratio"] = self._calculate_handshake_ratio(aggregated)
            aggregated["packet_efficiency"] = self._calculate_packet_efficiency(aggregated)

            self.logger.debug(
                f"Aggregated {len(metrics_list)} snapshots: "
                f"{aggregated['total_packets']} total packets, "
                f"{aggregated['retransmission_rate']:.2f}% retransmission rate"
            )

            return aggregated

        except Exception as e:
            self.logger.error(f"Failed to aggregate metrics: {e}")
            return self._create_empty_metrics()

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
        try:
            retransmissions = metrics.get("retransmissions", 0)
            total_packets = metrics.get("total_packets", 0)

            if total_packets == 0:
                return 0.0

            rate = (retransmissions / total_packets) * 100.0

            # Ensure rate is within valid bounds
            return max(0.0, min(100.0, rate))

        except (TypeError, ZeroDivisionError, ValueError) as e:
            self.logger.warning(f"Failed to calculate retransmission rate: {e}")
            return 0.0

    def validate_tls_handshake_counts(self, metrics: Dict[str, Any]) -> bool:
        """
        Validate TLS handshake counts for accuracy.

        This method validates that handshake counts are consistent
        and follow expected TLS handshake patterns.

        Args:
            metrics: Telemetry metrics containing handshake counts

        Returns:
            True if handshake counts are valid, False otherwise

        Requirement 6.1: Accurate ClientHello/ServerHello counting
        """
        try:
            client_hellos = self._safe_int(metrics.get("client_hellos", 0))
            server_hellos = self._safe_int(metrics.get("server_hellos", 0))

            # Basic validation rules:
            # 1. Both counts must be non-negative
            if client_hellos < 0 or server_hellos < 0:
                return False

            # 2. ServerHellos should not exceed ClientHellos
            # (each ServerHello should correspond to a ClientHello)
            if server_hellos > client_hellos:
                return False

            # 3. If there are no ClientHellos, there should be no ServerHellos
            if client_hellos == 0 and server_hellos > 0:
                return False

            return True

        except (TypeError, ValueError) as e:
            self.logger.warning(f"Failed to validate TLS handshake counts: {e}")
            return False

    def get_telemetry_snapshot(self, engine: Any) -> Dict[str, Any]:
        """
        Get telemetry snapshot from bypass engine.

        This method is an alias for collect_metrics to maintain
        interface compatibility.

        Args:
            engine: The bypass engine instance to collect metrics from

        Returns:
            Dictionary containing structured telemetry metrics
        """
        return self.collect_metrics(engine)

    def get_snapshot(self) -> "TelemetrySnapshot":
        """
        Get telemetry snapshot without engine (for testing).

        Returns:
            TelemetrySnapshot instance with default values
        """
        from core.unified_engine_models import TelemetrySnapshot

        return TelemetrySnapshot(
            timestamp=time.time(),
            client_hellos=0,
            server_hellos=0,
            retransmissions=0,
            total_packets=0,
            fake_packets_sent=0,
            bytes_processed=0,
            connection_attempts=0,
            successful_connections=0,
        )

    def _calculate_handshake_ratio(self, metrics: Dict[str, Any]) -> float:
        """
        Calculate the ratio of ServerHellos to ClientHellos.

        Args:
            metrics: Telemetry metrics containing handshake counts

        Returns:
            Ratio of ServerHellos to ClientHellos (0.0 to 1.0)
        """
        try:
            client_hellos = metrics.get("client_hellos", 0)
            server_hellos = metrics.get("server_hellos", 0)

            if client_hellos == 0:
                return 0.0

            ratio = server_hellos / client_hellos
            return max(0.0, min(1.0, ratio))

        except (TypeError, ZeroDivisionError, ValueError):
            return 0.0

    def _calculate_packet_efficiency(self, metrics: Dict[str, Any]) -> float:
        """
        Calculate packet efficiency (successful connections per packet).

        Args:
            metrics: Telemetry metrics containing packet and connection counts

        Returns:
            Packet efficiency ratio (0.0 to 1.0)
        """
        try:
            total_packets = metrics.get("total_packets", 0)
            successful_connections = metrics.get("successful_connections", 0)

            if total_packets == 0:
                return 0.0

            efficiency = successful_connections / total_packets
            return max(0.0, min(1.0, efficiency))

        except (TypeError, ZeroDivisionError, ValueError):
            return 0.0

    def _create_empty_metrics(self) -> Dict[str, Any]:
        """
        Create empty metrics dictionary with default values.

        Returns:
            Dictionary with zero values for all metrics
        """
        return {
            "timestamp": time.time(),
            "client_hellos": 0,
            "server_hellos": 0,
            "retransmissions": 0,
            "total_packets": 0,
            "fake_packets_sent": 0,
            "bytes_processed": 0,
            "connection_attempts": 0,
            "successful_connections": 0,
            "collection_id": self._collection_count,
            "collector_timestamp": self._last_collection_time,
            "retransmission_rate": 0.0,
            "handshake_ratio": 0.0,
            "packet_efficiency": 0.0,
            "snapshot_count": 0,
            "time_span": 0.0,
        }

    def get_collection_stats(self) -> Dict[str, Any]:
        """
        Get statistics about telemetry collection operations.

        Returns:
            Dictionary containing collection statistics
        """
        return {
            "total_collections": self._collection_count,
            "last_collection_time": self._last_collection_time,
            "collector_uptime": time.time() - (self._last_collection_time or time.time()),
        }

    def _extract_engine_telemetry(self, engine: Any) -> Dict[str, Any]:
        """
        Extract telemetry data from engine in a normalized format.

        This method handles different engine telemetry formats and normalizes
        them to a consistent structure for TelemetrySnapshot creation.

        Args:
            engine: The bypass engine instance

        Returns:
            Dictionary with normalized telemetry data
        """
        try:
            # Try get_telemetry_snapshot first (WindowsBypassEngine format)
            if hasattr(engine, "get_telemetry_snapshot"):
                raw_data = engine.get_telemetry_snapshot()
                if isinstance(raw_data, dict):
                    return self._normalize_windows_engine_telemetry(raw_data)

            # Try get_telemetry method (alternative format)
            if hasattr(engine, "get_telemetry"):
                raw_data = engine.get_telemetry()
                if isinstance(raw_data, dict):
                    return self._normalize_generic_telemetry(raw_data)

            # No telemetry available
            return self._get_default_telemetry()

        except Exception as e:
            self.logger.warning(f"Failed to extract engine telemetry: {e}")
            return self._get_default_telemetry()

    def _normalize_windows_engine_telemetry(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize WindowsBypassEngine telemetry format.

        WindowsBypassEngine uses format like:
        - clienthellos, serverhellos (lowercase)
        - total_retransmissions_detected
        - packets_captured
        - aggregate.fake_packets_sent
        """
        try:
            aggregate = raw_data.get("aggregate", {})

            # Calculate bytes processed from packet count (estimate)
            packets_captured = self._safe_int(raw_data.get("packets_captured", 0))
            bytes_processed = packets_captured * 1500  # Estimate 1500 bytes per packet

            return {
                "client_hellos": self._safe_int(raw_data.get("clienthellos", 0)),
                "server_hellos": self._safe_int(raw_data.get("serverhellos", 0)),
                "retransmissions": self._safe_int(
                    raw_data.get("total_retransmissions_detected", 0)
                ),
                "total_packets": packets_captured,
                "fake_packets_sent": self._safe_int(aggregate.get("fake_packets_sent", 0)),
                "bytes_processed": bytes_processed,
                "connection_attempts": self._safe_int(aggregate.get("segments_sent", 0)),
                "successful_connections": self._safe_int(
                    raw_data.get("serverhellos", 0)
                ),  # ServerHellos indicate successful connections
            }
        except Exception as e:
            self.logger.warning(f"Failed to normalize Windows engine telemetry: {e}")
            return self._get_default_telemetry()

    def _normalize_generic_telemetry(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize generic telemetry format.

        Handles standard format with expected field names.
        """
        try:
            return {
                "client_hellos": self._safe_int(raw_data.get("client_hellos", 0)),
                "server_hellos": self._safe_int(raw_data.get("server_hellos", 0)),
                "retransmissions": self._safe_int(raw_data.get("retransmissions", 0)),
                "total_packets": self._safe_int(raw_data.get("total_packets", 0)),
                "fake_packets_sent": self._safe_int(raw_data.get("fake_packets_sent", 0)),
                "bytes_processed": self._safe_int(raw_data.get("bytes_processed", 0)),
                "connection_attempts": self._safe_int(raw_data.get("connection_attempts", 0)),
                "successful_connections": self._safe_int(raw_data.get("successful_connections", 0)),
            }
        except Exception as e:
            self.logger.warning(f"Failed to normalize generic telemetry: {e}")
            return self._get_default_telemetry()

    def _safe_int(self, value: Any) -> int:
        """
        Safely convert value to integer.

        Args:
            value: Value to convert

        Returns:
            Integer value or 0 if conversion fails
        """
        try:
            if isinstance(value, (int, float)):
                return max(0, int(value))
            elif isinstance(value, str):
                return max(0, int(float(value)))
            else:
                return 0
        except (ValueError, TypeError):
            return 0

    def _get_default_telemetry(self) -> Dict[str, Any]:
        """
        Get default telemetry values when no engine telemetry is available.

        Returns:
            Dictionary with zero values for all telemetry fields
        """
        return {
            "client_hellos": 0,
            "server_hellos": 0,
            "retransmissions": 0,
            "total_packets": 0,
            "fake_packets_sent": 0,
            "bytes_processed": 0,
            "connection_attempts": 0,
            "successful_connections": 0,
        }
