"""
Metrics export system with Prometheus and JSON support.

Provides endpoints for exporting metrics in various formats
including Prometheus-compatible format and JSON.
"""

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime

from .metrics_collector import AttackMetricsCollector, MetricsSnapshot


class MetricsExporter(ABC):
    """Base class for metrics exporters."""
    
    @abstractmethod
    def export(self, snapshot: MetricsSnapshot) -> str:
        """
        Export metrics snapshot to string format.
        
        Args:
            snapshot: Metrics snapshot to export
        
        Returns:
            Formatted metrics string
        """
        pass
    
    @abstractmethod
    def get_content_type(self) -> str:
        """
        Get content type for HTTP response.
        
        Returns:
            Content type string
        """
        pass


class PrometheusExporter(MetricsExporter):
    """
    Exporter for Prometheus-compatible metrics format.
    
    Exports metrics in Prometheus text exposition format:
    https://prometheus.io/docs/instrumenting/exposition_formats/
    """
    
    def __init__(self, namespace: str = "attack"):
        """
        Initialize Prometheus exporter.
        
        Args:
            namespace: Namespace prefix for metrics
        """
        self.namespace = namespace
    
    def export(self, snapshot: MetricsSnapshot) -> str:
        """
        Export metrics in Prometheus format.
        
        Args:
            snapshot: Metrics snapshot to export
        
        Returns:
            Prometheus-formatted metrics
        """
        lines = []
        
        # Add timestamp comment
        lines.append(f"# Metrics snapshot at {snapshot.timestamp.isoformat()}")
        lines.append("")
        
        # Export attack metrics
        for attack_name, metrics in snapshot.attack_metrics.items():
            safe_name = self._sanitize_name(attack_name)
            
            # Total executions
            lines.append(
                f"# HELP {self.namespace}_executions_total "
                f"Total number of attack executions"
            )
            lines.append(f"# TYPE {self.namespace}_executions_total counter")
            lines.append(
                f'{self.namespace}_executions_total{{attack="{safe_name}"}} '
                f'{metrics.total_executions}'
            )
            lines.append("")
            
            # Successful executions
            lines.append(
                f"# HELP {self.namespace}_executions_successful "
                f"Number of successful attack executions"
            )
            lines.append(f"# TYPE {self.namespace}_executions_successful counter")
            lines.append(
                f'{self.namespace}_executions_successful{{attack="{safe_name}"}} '
                f'{metrics.successful_executions}'
            )
            lines.append("")
            
            # Failed executions
            lines.append(
                f"# HELP {self.namespace}_executions_failed "
                f"Number of failed attack executions"
            )
            lines.append(f"# TYPE {self.namespace}_executions_failed counter")
            lines.append(
                f'{self.namespace}_executions_failed{{attack="{safe_name}"}} '
                f'{metrics.failed_executions}'
            )
            lines.append("")
            
            # Error executions
            lines.append(
                f"# HELP {self.namespace}_executions_error "
                f"Number of error attack executions"
            )
            lines.append(f"# TYPE {self.namespace}_executions_error counter")
            lines.append(
                f'{self.namespace}_executions_error{{attack="{safe_name}"}} '
                f'{metrics.error_executions}'
            )
            lines.append("")
            
            # Success rate
            lines.append(
                f"# HELP {self.namespace}_success_rate "
                f"Success rate of attack executions"
            )
            lines.append(f"# TYPE {self.namespace}_success_rate gauge")
            lines.append(
                f'{self.namespace}_success_rate{{attack="{safe_name}"}} '
                f'{metrics.success_rate:.4f}'
            )
            lines.append("")
            
            # Average execution time
            lines.append(
                f"# HELP {self.namespace}_execution_time_ms "
                f"Average execution time in milliseconds"
            )
            lines.append(f"# TYPE {self.namespace}_execution_time_ms gauge")
            lines.append(
                f'{self.namespace}_execution_time_ms{{attack="{safe_name}"}} '
                f'{metrics.avg_execution_time_ms:.2f}'
            )
            lines.append("")
            
            # Min execution time
            lines.append(
                f"# HELP {self.namespace}_execution_time_min_ms "
                f"Minimum execution time in milliseconds"
            )
            lines.append(f"# TYPE {self.namespace}_execution_time_min_ms gauge")
            lines.append(
                f'{self.namespace}_execution_time_min_ms{{attack="{safe_name}"}} '
                f'{metrics.min_execution_time_ms:.2f}'
            )
            lines.append("")
            
            # Max execution time
            lines.append(
                f"# HELP {self.namespace}_execution_time_max_ms "
                f"Maximum execution time in milliseconds"
            )
            lines.append(f"# TYPE {self.namespace}_execution_time_max_ms gauge")
            lines.append(
                f'{self.namespace}_execution_time_max_ms{{attack="{safe_name}"}} '
                f'{metrics.max_execution_time_ms:.2f}'
            )
            lines.append("")
            
            # Segments generated
            lines.append(
                f"# HELP {self.namespace}_segments_total "
                f"Total number of segments generated"
            )
            lines.append(f"# TYPE {self.namespace}_segments_total counter")
            lines.append(
                f'{self.namespace}_segments_total{{attack="{safe_name}"}} '
                f'{metrics.total_segments_generated}'
            )
            lines.append("")
            
            # Fallback count
            lines.append(
                f"# HELP {self.namespace}_fallback_total "
                f"Total number of fallback executions"
            )
            lines.append(f"# TYPE {self.namespace}_fallback_total counter")
            lines.append(
                f'{self.namespace}_fallback_total{{attack="{safe_name}"}} '
                f'{metrics.fallback_count}'
            )
            lines.append("")
            
            # Fallback rate
            lines.append(
                f"# HELP {self.namespace}_fallback_rate "
                f"Rate of fallback executions"
            )
            lines.append(f"# TYPE {self.namespace}_fallback_rate gauge")
            lines.append(
                f'{self.namespace}_fallback_rate{{attack="{safe_name}"}} '
                f'{metrics.fallback_rate:.4f}'
            )
            lines.append("")
        
        # Export throughput metrics
        throughput = snapshot.throughput_metrics
        
        lines.append(
            f"# HELP {self.namespace}_throughput_packets_per_second "
            f"Throughput in packets per second"
        )
        lines.append(f"# TYPE {self.namespace}_throughput_packets_per_second gauge")
        lines.append(
            f'{self.namespace}_throughput_packets_per_second '
            f'{throughput.packets_per_second:.2f}'
        )
        lines.append("")
        
        lines.append(
            f"# HELP {self.namespace}_throughput_bytes_per_second "
            f"Throughput in bytes per second"
        )
        lines.append(f"# TYPE {self.namespace}_throughput_bytes_per_second gauge")
        lines.append(
            f'{self.namespace}_throughput_bytes_per_second '
            f'{throughput.bytes_per_second:.2f}'
        )
        lines.append("")
        
        # Export global stats
        global_stats = snapshot.global_stats
        
        lines.append(
            f"# HELP {self.namespace}_global_executions_total "
            f"Total number of all attack executions"
        )
        lines.append(f"# TYPE {self.namespace}_global_executions_total counter")
        lines.append(
            f'{self.namespace}_global_executions_total '
            f'{global_stats.get("total_executions", 0)}'
        )
        lines.append("")
        
        lines.append(
            f"# HELP {self.namespace}_global_success_rate "
            f"Global success rate across all attacks"
        )
        lines.append(f"# TYPE {self.namespace}_global_success_rate gauge")
        lines.append(
            f'{self.namespace}_global_success_rate '
            f'{global_stats.get("global_success_rate", 0):.4f}'
        )
        lines.append("")
        
        lines.append(
            f"# HELP {self.namespace}_unique_attacks "
            f"Number of unique attack types"
        )
        lines.append(f"# TYPE {self.namespace}_unique_attacks gauge")
        lines.append(
            f'{self.namespace}_unique_attacks '
            f'{global_stats.get("unique_attacks", 0)}'
        )
        lines.append("")
        
        return "\n".join(lines)
    
    def get_content_type(self) -> str:
        """Get Prometheus content type."""
        return "text/plain; version=0.0.4"
    
    def _sanitize_name(self, name: str) -> str:
        """
        Sanitize metric name for Prometheus.
        
        Args:
            name: Original name
        
        Returns:
            Sanitized name
        """
        # Replace invalid characters with underscores
        return name.replace("-", "_").replace(".", "_").replace(" ", "_")


class JSONExporter(MetricsExporter):
    """
    Exporter for JSON format metrics.
    
    Exports metrics as structured JSON for easy consumption
    by web dashboards and other tools.
    """
    
    def __init__(self, pretty: bool = True):
        """
        Initialize JSON exporter.
        
        Args:
            pretty: Use pretty-printed JSON
        """
        self.pretty = pretty
    
    def export(self, snapshot: MetricsSnapshot) -> str:
        """
        Export metrics in JSON format.
        
        Args:
            snapshot: Metrics snapshot to export
        
        Returns:
            JSON-formatted metrics
        """
        data = snapshot.to_dict()
        
        if self.pretty:
            return json.dumps(data, indent=2)
        else:
            return json.dumps(data)
    
    def get_content_type(self) -> str:
        """Get JSON content type."""
        return "application/json"


class MetricsAggregator:
    """
    Aggregates metrics from multiple collectors.
    
    Useful for combining metrics from different sources
    or time periods.
    """
    
    def __init__(self):
        """Initialize metrics aggregator."""
        self._snapshots: List[MetricsSnapshot] = []
    
    def add_snapshot(self, snapshot: MetricsSnapshot):
        """
        Add a snapshot to the aggregator.
        
        Args:
            snapshot: Metrics snapshot to add
        """
        self._snapshots.append(snapshot)
    
    def aggregate(self) -> MetricsSnapshot:
        """
        Aggregate all snapshots into a single snapshot.
        
        Returns:
            Aggregated metrics snapshot
        """
        if not self._snapshots:
            # Return empty snapshot
            from .metrics_collector import ThroughputMetrics
            return MetricsSnapshot(
                timestamp=datetime.now(),
                attack_metrics={},
                throughput_metrics=ThroughputMetrics(
                    window_start=datetime.now(),
                    window_end=datetime.now()
                ),
                global_stats={}
            )
        
        # Aggregate attack metrics
        from .metrics_collector import AttackMetrics, ThroughputMetrics
        
        aggregated_attacks = {}
        
        for snapshot in self._snapshots:
            for attack_name, metrics in snapshot.attack_metrics.items():
                if attack_name not in aggregated_attacks:
                    aggregated_attacks[attack_name] = AttackMetrics(
                        attack_name=attack_name
                    )
                
                agg = aggregated_attacks[attack_name]
                agg.total_executions += metrics.total_executions
                agg.successful_executions += metrics.successful_executions
                agg.failed_executions += metrics.failed_executions
                agg.error_executions += metrics.error_executions
                agg.total_execution_time_ms += metrics.total_execution_time_ms
                agg.min_execution_time_ms = min(
                    agg.min_execution_time_ms,
                    metrics.min_execution_time_ms
                )
                agg.max_execution_time_ms = max(
                    agg.max_execution_time_ms,
                    metrics.max_execution_time_ms
                )
                agg.total_segments_generated += metrics.total_segments_generated
                agg.fallback_count += metrics.fallback_count
        
        # Aggregate throughput
        total_packets = sum(
            s.throughput_metrics.total_packets for s in self._snapshots
        )
        total_bytes = sum(
            s.throughput_metrics.total_bytes for s in self._snapshots
        )
        
        window_start = min(s.throughput_metrics.window_start for s in self._snapshots)
        window_end = max(s.throughput_metrics.window_end for s in self._snapshots)
        
        aggregated_throughput = ThroughputMetrics(
            window_start=window_start,
            window_end=window_end,
            total_packets=total_packets,
            total_bytes=total_bytes
        )
        
        # Calculate global stats
        total_executions = sum(m.total_executions for m in aggregated_attacks.values())
        total_successful = sum(m.successful_executions for m in aggregated_attacks.values())
        
        global_stats = {
            'total_executions': total_executions,
            'total_successful': total_successful,
            'global_success_rate': total_successful / total_executions if total_executions > 0 else 0.0,
            'unique_attacks': len(aggregated_attacks)
        }
        
        return MetricsSnapshot(
            timestamp=datetime.now(),
            attack_metrics=aggregated_attacks,
            throughput_metrics=aggregated_throughput,
            global_stats=global_stats
        )
    
    def clear(self):
        """Clear all snapshots."""
        self._snapshots.clear()


class MetricsFilter:
    """
    Filters metrics based on criteria.
    
    Useful for exporting only specific metrics or
    filtering by time range.
    """
    
    def __init__(
        self,
        attack_names: Optional[List[str]] = None,
        min_executions: Optional[int] = None,
        min_success_rate: Optional[float] = None
    ):
        """
        Initialize metrics filter.
        
        Args:
            attack_names: Filter by specific attack names
            min_executions: Minimum number of executions
            min_success_rate: Minimum success rate
        """
        self.attack_names = attack_names
        self.min_executions = min_executions
        self.min_success_rate = min_success_rate
    
    def filter(self, snapshot: MetricsSnapshot) -> MetricsSnapshot:
        """
        Filter a metrics snapshot.
        
        Args:
            snapshot: Snapshot to filter
        
        Returns:
            Filtered snapshot
        """
        filtered_attacks = {}
        
        for attack_name, metrics in snapshot.attack_metrics.items():
            # Apply filters
            if self.attack_names and attack_name not in self.attack_names:
                continue
            
            if self.min_executions and metrics.total_executions < self.min_executions:
                continue
            
            if self.min_success_rate and metrics.success_rate < self.min_success_rate:
                continue
            
            filtered_attacks[attack_name] = metrics
        
        # Recalculate global stats
        total_executions = sum(m.total_executions for m in filtered_attacks.values())
        total_successful = sum(m.successful_executions for m in filtered_attacks.values())
        
        global_stats = {
            'total_executions': total_executions,
            'total_successful': total_successful,
            'global_success_rate': total_successful / total_executions if total_executions > 0 else 0.0,
            'unique_attacks': len(filtered_attacks)
        }
        
        return MetricsSnapshot(
            timestamp=snapshot.timestamp,
            attack_metrics=filtered_attacks,
            throughput_metrics=snapshot.throughput_metrics,
            global_stats=global_stats
        )
