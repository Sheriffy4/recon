"""
Strategy comparison report generation.

This module provides report formatting for strategy and packet comparisons,
delegating to ReportFormatter for consistent output.
"""

from typing import List, Any, Dict
from core.utils.report_formatter import ReportFormatter


class StrategyComparisonReporter:
    """Generates formatted reports for strategy and packet comparisons."""

    @staticmethod
    def format_strategy_diff(comparison: Any) -> str:
        """
        Generate a human-readable report of strategy differences.

        Args:
            comparison: StrategyComparison object

        Returns:
            Formatted string report
        """
        sections: List[List[str]] = []

        sections.append(
            ReportFormatter.create_key_value_section(
                "METADATA:",
                {"Timestamp": comparison.timestamp},
            )
        )

        sections.append(
            [
                "Discovery Mode Strategy:",
                f"  {comparison.discovery_strategy}",
                "",
                "Service Mode Strategy:",
                f"  {comparison.service_strategy}",
                "",
            ]
        )

        if comparison.strategies_match:
            sections.append([f"RESULT: ✓ Strategies match perfectly!", ""])
        else:
            sections.append([f"RESULT: ✗ Found {len(comparison.differences)} differences", ""])

            critical = [d.to_dict() for d in comparison.differences if d.is_critical]
            other = [d.to_dict() for d in comparison.differences if not d.is_critical]

            if critical:
                sections.append(
                    ReportFormatter.create_difference_section(
                        "CRITICAL DIFFERENCES:", critical, critical_only=False
                    )
                )
            if other:
                sections.append(
                    ReportFormatter.create_difference_section(
                        "OTHER DIFFERENCES:", other, critical_only=False
                    )
                )

        return ReportFormatter.create_full_report(
            f"STRATEGY COMPARISON REPORT: {comparison.domain}",
            sections,
            width=80,
        )

    @staticmethod
    def format_packet_diff(comparison: Any) -> str:
        """
        Generate a human-readable report of packet differences.

        Args:
            comparison: PacketComparison object

        Returns:
            Formatted string report
        """
        sections: List[List[str]] = []

        sections.append(
            ReportFormatter.create_key_value_section(
                "METADATA:",
                {"Timestamp": comparison.timestamp},
            )
        )

        sections.append(
            [
                "CAPTURES:",
                f"  Discovery PCAP: {comparison.discovery_pcap}",
                f"  Discovery packets: {comparison.discovery_packet_count}",
                f"  Service PCAP:   {comparison.service_pcap}",
                f"  Service packets:   {comparison.service_packet_count}",
                "",
            ]
        )

        if comparison.packets_match:
            sections.append([f"RESULT: ✓ Packets match perfectly!", ""])
        else:
            sections.append(
                [f"RESULT: ✗ Found {len(comparison.differences)} packet differences", ""]
            )

            critical = [d for d in comparison.differences if d.is_critical]
            other = [d for d in comparison.differences if not d.is_critical]

            if critical:
                items = [
                    f"Packet {d.packet_index}, {d.field}: discovery={d.discovery_value} service={d.service_value}"
                    for d in critical
                ]
                sections.append(
                    ReportFormatter.create_section("CRITICAL PACKET DIFFERENCES:", items)
                )

            if other:
                items = [
                    f"Packet {d.packet_index}, {d.field}: discovery={d.discovery_value} service={d.service_value}"
                    for d in other
                ]
                sections.append(ReportFormatter.create_section("OTHER PACKET DIFFERENCES:", items))

        if comparison.timing_differences:
            timing_items = [f"{k}: {v:.2f}" for k, v in comparison.timing_differences.items()]
            sections.append(ReportFormatter.create_section("TIMING ANALYSIS:", timing_items))

        return ReportFormatter.create_full_report(
            f"PACKET COMPARISON REPORT: {comparison.domain}",
            sections,
            width=80,
        )

    @staticmethod
    def format_root_cause(analysis: Any) -> str:
        """
        Generate a human-readable root cause analysis report.

        Args:
            analysis: RootCauseAnalysis object

        Returns:
            Formatted string report
        """
        sections: List[List[str]] = []

        sections.append(
            ReportFormatter.create_key_value_section(
                "METADATA:",
                {
                    "Domain": analysis.domain,
                    "Timestamp": analysis.timestamp,
                    "Has Strategy Differences": str(analysis.has_strategy_differences),
                    "Has Packet Differences": str(analysis.has_packet_differences),
                },
            )
        )

        if analysis.root_causes:
            sections.append(ReportFormatter.create_section("ROOT CAUSES:", analysis.root_causes))

        if analysis.code_locations:
            sections.append(
                ReportFormatter.create_section("CODE LOCATIONS:", analysis.code_locations)
            )

        if analysis.fix_recommendations:
            sections.append(
                ReportFormatter.create_section("FIX RECOMMENDATIONS:", analysis.fix_recommendations)
            )

        return ReportFormatter.create_full_report(
            f"ROOT CAUSE ANALYSIS: {analysis.domain}",
            sections,
            width=80,
        )
