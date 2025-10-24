"""
Visualization helper for PCAP analysis reporting.

This module provides utilities for creating visualizations of packet sequences,
timing differences, and analysis results for inclusion in reports.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
import json
import statistics
from pathlib import Path

from .packet_info import PacketInfo
from .critical_difference import CriticalDifference
from .fix_generator import CodeFix, RiskLevel


@dataclass
class VisualizationData:
    """Data structure for visualization information."""

    viz_type: str
    title: str
    data: Dict[str, Any]
    config: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "type": self.viz_type,
            "title": self.title,
            "description": self.description,
            "data": self.data,
            "config": self.config,
        }


class VisualizationHelper:
    """
    Helper class for creating visualizations for PCAP analysis reports.

    Provides methods to generate visualization data that can be rendered
    by various charting libraries or converted to different formats.
    """

    def __init__(self):
        """Initialize the visualization helper."""
        self.color_schemes = {
            "default": ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"],
            "severity": {
                "CRITICAL": "#d32f2f",
                "HIGH": "#f57c00",
                "MEDIUM": "#fbc02d",
                "LOW": "#388e3c",
            },
            "comparison": ["#2196F3", "#FF5722"],
        }

    def create_packet_sequence_timeline(
        self,
        recon_packets: List[PacketInfo],
        zapret_packets: List[PacketInfo],
        max_packets: int = 50,
    ) -> VisualizationData:
        """
        Create a timeline visualization of packet sequences.

        Args:
            recon_packets: Packets from recon capture
            zapret_packets: Packets from zapret capture
            max_packets: Maximum number of packets to include

        Returns:
            VisualizationData: Timeline visualization data
        """

        # Limit packets for visualization
        recon_subset = recon_packets[:max_packets]
        zapret_subset = zapret_packets[:max_packets]

        # Create timeline data
        timeline_data = {
            "recon": [
                {
                    "index": i,
                    "timestamp": p.timestamp,
                    "ttl": p.ttl,
                    "flags": p.flags,
                    "payload_length": p.payload_length,
                    "sequence_num": p.sequence_num,
                    "is_fake": p.ttl <= 5,  # Heuristic for fake packets
                    "checksum_valid": p.checksum_valid,
                }
                for i, p in enumerate(recon_subset)
            ],
            "zapret": [
                {
                    "index": i,
                    "timestamp": p.timestamp,
                    "ttl": p.ttl,
                    "flags": p.flags,
                    "payload_length": p.payload_length,
                    "sequence_num": p.sequence_num,
                    "is_fake": p.ttl <= 5,  # Heuristic for fake packets
                    "checksum_valid": p.checksum_valid,
                }
                for i, p in enumerate(zapret_subset)
            ],
        }

        # Calculate timing statistics
        if recon_subset and zapret_subset:
            recon_duration = recon_subset[-1].timestamp - recon_subset[0].timestamp
            zapret_duration = zapret_subset[-1].timestamp - zapret_subset[0].timestamp

            config = {
                "chart_type": "timeline",
                "x_axis": "Packet Index",
                "y_axis": "Timestamp (relative)",
                "color_by": "ttl",
                "colors": self.color_schemes["comparison"],
                "statistics": {
                    "recon_duration": recon_duration,
                    "zapret_duration": zapret_duration,
                    "recon_packet_count": len(recon_subset),
                    "zapret_packet_count": len(zapret_subset),
                },
            }
        else:
            config = {"chart_type": "timeline"}

        return VisualizationData(
            viz_type="packet_sequence_timeline",
            title="Packet Sequence Timeline Comparison",
            description=f"Timeline showing first {max_packets} packets from each capture",
            data=timeline_data,
            config=config,
        )

    def create_ttl_pattern_analysis(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> VisualizationData:
        """
        Create TTL pattern analysis visualization.

        Args:
            recon_packets: Packets from recon capture
            zapret_packets: Packets from zapret capture

        Returns:
            VisualizationData: TTL pattern visualization data
        """

        # Extract TTL patterns
        recon_ttls = [p.ttl for p in recon_packets]
        zapret_ttls = [p.ttl for p in zapret_packets]

        # Create TTL distribution
        recon_ttl_dist = {}
        zapret_ttl_dist = {}

        for ttl in recon_ttls:
            recon_ttl_dist[ttl] = recon_ttl_dist.get(ttl, 0) + 1

        for ttl in zapret_ttls:
            zapret_ttl_dist[ttl] = zapret_ttl_dist.get(ttl, 0) + 1

        # Create comparison data
        all_ttls = sorted(set(recon_ttls + zapret_ttls))

        comparison_data = {
            "ttl_values": all_ttls,
            "recon_counts": [recon_ttl_dist.get(ttl, 0) for ttl in all_ttls],
            "zapret_counts": [zapret_ttl_dist.get(ttl, 0) for ttl in all_ttls],
            "differences": [
                abs(recon_ttl_dist.get(ttl, 0) - zapret_ttl_dist.get(ttl, 0))
                for ttl in all_ttls
            ],
        }

        # Identify fake packet TTLs (typically 3-5)
        fake_ttls = [ttl for ttl in all_ttls if ttl <= 5]

        config = {
            "chart_type": "grouped_bar",
            "x_axis": "TTL Value",
            "y_axis": "Packet Count",
            "colors": self.color_schemes["comparison"],
            "highlight_ttls": fake_ttls,
            "statistics": {
                "recon_unique_ttls": len(set(recon_ttls)),
                "zapret_unique_ttls": len(set(zapret_ttls)),
                "common_ttls": len(set(recon_ttls) & set(zapret_ttls)),
                "fake_packet_ttls": fake_ttls,
            },
        }

        return VisualizationData(
            viz_type="ttl_pattern_analysis",
            title="TTL Pattern Analysis",
            description="Comparison of TTL values used in recon vs zapret packets",
            data=comparison_data,
            config=config,
        )

    def create_timing_difference_chart(
        self, timing_differences: List[Dict[str, Any]]
    ) -> VisualizationData:
        """
        Create timing difference visualization.

        Args:
            timing_differences: List of timing differences from comparison

        Returns:
            VisualizationData: Timing difference visualization data
        """

        if not timing_differences:
            return VisualizationData(
                viz_type="timing_differences",
                title="Timing Differences",
                description="No timing differences found",
                data={"message": "No timing differences detected"},
                config={},
            )

        # Extract timing data
        timing_data = {
            "descriptions": [
                d.get("description", "Unknown") for d in timing_differences
            ],
            "recon_timings": [d.get("recon_timing", 0) for d in timing_differences],
            "zapret_timings": [d.get("zapret_timing", 0) for d in timing_differences],
            "differences": [d.get("difference", 0) for d in timing_differences],
            "impacts": [d.get("impact", "medium") for d in timing_differences],
        }

        # Calculate statistics
        avg_difference = (
            statistics.mean(timing_data["differences"])
            if timing_data["differences"]
            else 0
        )
        max_difference = (
            max(timing_data["differences"]) if timing_data["differences"] else 0
        )

        config = {
            "chart_type": "scatter",
            "x_axis": "Recon Timing (ms)",
            "y_axis": "Zapret Timing (ms)",
            "color_by": "impact",
            "colors": self.color_schemes["severity"],
            "statistics": {
                "total_differences": len(timing_differences),
                "average_difference": avg_difference,
                "max_difference": max_difference,
            },
        }

        return VisualizationData(
            viz_type="timing_differences",
            title="Timing Differences Analysis",
            description=f"Analysis of {len(timing_differences)} timing differences",
            data=timing_data,
            config=config,
        )

    def create_fix_priority_matrix(self, fixes: List[CodeFix]) -> VisualizationData:
        """
        Create fix priority matrix visualization.

        Args:
            fixes: List of generated code fixes

        Returns:
            VisualizationData: Fix priority matrix visualization data
        """

        if not fixes:
            return VisualizationData(
                viz_type="fix_priority_matrix",
                title="Fix Priority Matrix",
                description="No fixes generated",
                data={"message": "No fixes available"},
                config={},
            )

        # Create matrix data
        matrix_data = {
            "fixes": [
                {
                    "id": f.fix_id,
                    "description": (
                        f.description[:50] + "..."
                        if len(f.description) > 50
                        else f.description
                    ),
                    "confidence": f.confidence,
                    "risk_level": f.risk_level.value,
                    "fix_type": f.fix_type.value,
                    "risk_score": self._calculate_risk_score(f.risk_level),
                    "priority_score": f.confidence
                    * (1.0 - self._calculate_risk_score(f.risk_level)),
                }
                for f in fixes
            ]
        }

        # Group by fix type
        fix_type_counts = {}
        for fix in fixes:
            fix_type = fix.fix_type.value
            fix_type_counts[fix_type] = fix_type_counts.get(fix_type, 0) + 1

        config = {
            "chart_type": "bubble",
            "x_axis": "Risk Level",
            "y_axis": "Confidence",
            "size_by": "priority_score",
            "color_by": "fix_type",
            "colors": self.color_schemes["default"],
            "statistics": {
                "total_fixes": len(fixes),
                "fix_types": fix_type_counts,
                "high_confidence_fixes": len([f for f in fixes if f.confidence >= 0.8]),
                "low_risk_fixes": len(
                    [f for f in fixes if f.risk_level == RiskLevel.LOW]
                ),
            },
        }

        return VisualizationData(
            viz_type="fix_priority_matrix",
            title="Fix Priority Matrix",
            description=f"Priority matrix for {len(fixes)} generated fixes",
            data=matrix_data,
            config=config,
        )

    def create_difference_category_breakdown(
        self, differences: List[CriticalDifference]
    ) -> VisualizationData:
        """
        Create breakdown of differences by category.

        Args:
            differences: List of critical differences

        Returns:
            VisualizationData: Category breakdown visualization data
        """

        if not differences:
            return VisualizationData(
                viz_type="difference_breakdown",
                title="Difference Category Breakdown",
                description="No differences found",
                data={"message": "No differences detected"},
                config={},
            )

        # Group by category and impact level
        category_data = {}
        impact_data = {}

        for diff in differences:
            category = diff.category.value
            impact = diff.impact_level.value

            if category not in category_data:
                category_data[category] = {"total": 0, "by_impact": {}}

            category_data[category]["total"] += 1
            category_data[category]["by_impact"][impact] = (
                category_data[category]["by_impact"].get(impact, 0) + 1
            )

            impact_data[impact] = impact_data.get(impact, 0) + 1

        # Create visualization data
        breakdown_data = {
            "categories": list(category_data.keys()),
            "category_totals": [
                category_data[cat]["total"] for cat in category_data.keys()
            ],
            "impact_levels": list(impact_data.keys()),
            "impact_totals": [impact_data[impact] for impact in impact_data.keys()],
            "category_breakdown": category_data,
        }

        config = {
            "chart_type": "stacked_bar",
            "x_axis": "Category",
            "y_axis": "Count",
            "stack_by": "impact_level",
            "colors": self.color_schemes["severity"],
            "statistics": {
                "total_differences": len(differences),
                "categories_affected": len(category_data),
                "most_common_category": max(
                    category_data.keys(), key=lambda k: category_data[k]["total"]
                ),
                "most_common_impact": max(
                    impact_data.keys(), key=lambda k: impact_data[k]
                ),
            },
        }

        return VisualizationData(
            viz_type="difference_breakdown",
            title="Difference Category Breakdown",
            description=f"Breakdown of {len(differences)} differences by category and impact",
            data=breakdown_data,
            config=config,
        )

    def create_checksum_analysis_chart(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> VisualizationData:
        """
        Create checksum analysis visualization.

        Args:
            recon_packets: Packets from recon capture
            zapret_packets: Packets from zapret capture

        Returns:
            VisualizationData: Checksum analysis visualization data
        """

        # Analyze checksum validity patterns
        recon_checksum_data = [
            {
                "index": i,
                "ttl": p.ttl,
                "checksum_valid": p.checksum_valid,
                "is_fake": p.ttl <= 5,
                "payload_length": p.payload_length,
            }
            for i, p in enumerate(recon_packets)
        ]

        zapret_checksum_data = [
            {
                "index": i,
                "ttl": p.ttl,
                "checksum_valid": p.checksum_valid,
                "is_fake": p.ttl <= 5,
                "payload_length": p.payload_length,
            }
            for i, p in enumerate(zapret_packets)
        ]

        # Calculate statistics
        recon_invalid_checksums = len(
            [p for p in recon_packets if not p.checksum_valid]
        )
        zapret_invalid_checksums = len(
            [p for p in zapret_packets if not p.checksum_valid]
        )

        recon_fake_invalid = len(
            [p for p in recon_packets if not p.checksum_valid and p.ttl <= 5]
        )
        zapret_fake_invalid = len(
            [p for p in zapret_packets if not p.checksum_valid and p.ttl <= 5]
        )

        checksum_data = {
            "recon_data": recon_checksum_data,
            "zapret_data": zapret_checksum_data,
            "summary": {
                "recon_invalid_total": recon_invalid_checksums,
                "zapret_invalid_total": zapret_invalid_checksums,
                "recon_fake_invalid": recon_fake_invalid,
                "zapret_fake_invalid": zapret_fake_invalid,
            },
        }

        config = {
            "chart_type": "scatter",
            "x_axis": "Packet Index",
            "y_axis": "TTL",
            "color_by": "checksum_valid",
            "shape_by": "is_fake",
            "colors": {"valid": "#2ca02c", "invalid": "#d62728"},
            "statistics": {
                "recon_total_packets": len(recon_packets),
                "zapret_total_packets": len(zapret_packets),
                "checksum_difference": abs(
                    recon_invalid_checksums - zapret_invalid_checksums
                ),
            },
        }

        return VisualizationData(
            viz_type="checksum_analysis",
            title="Checksum Validity Analysis",
            description="Analysis of checksum validity patterns in fake vs real packets",
            data=checksum_data,
            config=config,
        )

    def create_strategy_comparison_chart(
        self, recon_strategy: Dict[str, Any], zapret_strategy: Dict[str, Any]
    ) -> VisualizationData:
        """
        Create strategy parameter comparison visualization.

        Args:
            recon_strategy: Recon strategy parameters
            zapret_strategy: Zapret strategy parameters

        Returns:
            VisualizationData: Strategy comparison visualization data
        """

        # Extract comparable parameters
        common_params = set(recon_strategy.keys()) & set(zapret_strategy.keys())

        comparison_data = {
            "parameters": list(common_params),
            "recon_values": [
                str(recon_strategy.get(param, "N/A")) for param in common_params
            ],
            "zapret_values": [
                str(zapret_strategy.get(param, "N/A")) for param in common_params
            ],
            "matches": [
                recon_strategy.get(param) == zapret_strategy.get(param)
                for param in common_params
            ],
        }

        # Calculate match statistics
        total_params = len(common_params)
        matching_params = sum(comparison_data["matches"])
        match_percentage = (
            (matching_params / total_params * 100) if total_params > 0 else 0
        )

        config = {
            "chart_type": "comparison_table",
            "colors": {"match": "#2ca02c", "mismatch": "#d62728"},
            "statistics": {
                "total_parameters": total_params,
                "matching_parameters": matching_params,
                "match_percentage": match_percentage,
                "recon_only_params": list(set(recon_strategy.keys()) - common_params),
                "zapret_only_params": list(set(zapret_strategy.keys()) - common_params),
            },
        }

        return VisualizationData(
            viz_type="strategy_comparison",
            title="Strategy Parameter Comparison",
            description=f"Comparison of {total_params} strategy parameters",
            data=comparison_data,
            config=config,
        )

    def _calculate_risk_score(self, risk_level: RiskLevel) -> float:
        """Calculate numerical risk score from risk level."""
        risk_scores = {
            RiskLevel.LOW: 0.1,
            RiskLevel.MEDIUM: 0.4,
            RiskLevel.HIGH: 0.7,
            RiskLevel.CRITICAL: 1.0,
        }
        return risk_scores.get(risk_level, 0.5)

    def export_visualization_data(
        self,
        visualizations: List[VisualizationData],
        output_path: str,
        format: str = "json",
    ) -> str:
        """
        Export visualization data to file.

        Args:
            visualizations: List of visualization data
            output_path: Output file path
            format: Export format ('json', 'csv')

        Returns:
            str: Path to exported file
        """

        output_file = Path(output_path)

        if format == "json":
            viz_data = {
                "visualizations": [viz.to_dict() for viz in visualizations],
                "metadata": {
                    "total_visualizations": len(visualizations),
                    "types": list(set(viz.viz_type for viz in visualizations)),
                },
            }

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(viz_data, f, indent=2, ensure_ascii=False)

        elif format == "csv":
            # Export as CSV (simplified format)
            import csv

            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "Title", "Description", "Data_Keys"])

                for viz in visualizations:
                    data_keys = (
                        list(viz.data.keys()) if isinstance(viz.data, dict) else []
                    )
                    writer.writerow(
                        [viz.viz_type, viz.title, viz.description, ", ".join(data_keys)]
                    )

        return str(output_file)

    def create_summary_dashboard_data(
        self,
        recon_packets: List[PacketInfo],
        zapret_packets: List[PacketInfo],
        differences: List[CriticalDifference],
        fixes: List[CodeFix],
    ) -> Dict[str, VisualizationData]:
        """
        Create a complete set of visualizations for a summary dashboard.

        Args:
            recon_packets: Packets from recon capture
            zapret_packets: Packets from zapret capture
            differences: List of critical differences
            fixes: List of generated fixes

        Returns:
            Dict[str, VisualizationData]: Dictionary of visualizations
        """

        dashboard_vizs = {}

        # Packet sequence timeline
        if recon_packets and zapret_packets:
            dashboard_vizs["packet_timeline"] = self.create_packet_sequence_timeline(
                recon_packets, zapret_packets
            )

        # TTL pattern analysis
        if recon_packets and zapret_packets:
            dashboard_vizs["ttl_patterns"] = self.create_ttl_pattern_analysis(
                recon_packets, zapret_packets
            )

        # Checksum analysis
        if recon_packets and zapret_packets:
            dashboard_vizs["checksum_analysis"] = self.create_checksum_analysis_chart(
                recon_packets, zapret_packets
            )

        # Difference breakdown
        if differences:
            dashboard_vizs["difference_breakdown"] = (
                self.create_difference_category_breakdown(differences)
            )

        # Fix priority matrix
        if fixes:
            dashboard_vizs["fix_priority"] = self.create_fix_priority_matrix(fixes)

        return dashboard_vizs
