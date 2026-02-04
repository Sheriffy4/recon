"""
Visualization builders for PCAP analysis reports.

This module contains builders for generating visualization data structures
used in analysis reports.
"""

from typing import List, Dict, Any

from .packet_info import PacketInfo
from .critical_difference import CriticalDifference, DifferenceCategory
from .fix_generator import CodeFix


class VisualizationBuilder:
    """Builds visualization data structures for reports."""

    def create_packet_sequence_viz(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> Dict[str, Any]:
        """Create packet sequence visualization data."""
        return {
            "type": "packet_sequence",
            "data": {
                "recon_sequence": [
                    {
                        "index": i,
                        "timestamp": p.timestamp,
                        "ttl": p.ttl,
                        "flags": p.flags,
                        "payload_length": p.payload_length,
                        "sequence_num": p.sequence_num,
                    }
                    for i, p in enumerate(recon_packets[:50])
                ],
                "zapret_sequence": [
                    {
                        "index": i,
                        "timestamp": p.timestamp,
                        "ttl": p.ttl,
                        "flags": p.flags,
                        "payload_length": p.payload_length,
                        "sequence_num": p.sequence_num,
                    }
                    for i, p in enumerate(zapret_packets[:50])
                ],
            },
            "config": {
                "title": "Packet Sequence Comparison",
                "x_axis": "Packet Index",
                "y_axis": "Timestamp",
                "color_by": "ttl",
            },
        }

    def create_ttl_pattern_viz(self, ttl_differences: List[CriticalDifference]) -> Dict[str, Any]:
        """Create TTL pattern visualization data."""
        return {
            "type": "ttl_pattern",
            "data": {
                "differences": [
                    {
                        "description": d.description,
                        "recon_ttl": d.recon_value,
                        "zapret_ttl": d.zapret_value,
                        "confidence": d.confidence,
                        "impact": d.impact_level.value,
                    }
                    for d in ttl_differences
                ]
            },
            "config": {"title": "TTL Pattern Analysis", "chart_type": "comparison_bar"},
        }

    def create_fix_priority_matrix(self, fixes: List[CodeFix]) -> Dict[str, Any]:
        """Create fix priority matrix visualization."""
        return {
            "type": "fix_priority_matrix",
            "data": {
                "fixes": [
                    {
                        "id": f.fix_id,
                        "description": f.description,
                        "risk_level": f.risk_level.value,
                        "confidence": f.confidence,
                        "fix_type": f.fix_type.value,
                    }
                    for f in fixes
                ]
            },
            "config": {
                "title": "Fix Priority Matrix",
                "x_axis": "Risk Level",
                "y_axis": "Confidence",
                "size_by": "impact",
            },
        }

    def generate_visualizations(
        self,
        comparison_result,
        critical_differences: List[CriticalDifference],
        generated_fixes: List[CodeFix],
    ) -> Dict[str, Any]:
        """Generate all visualizations for the report."""
        visualizations = {}

        # Packet sequence visualization
        if (
            comparison_result
            and comparison_result.recon_packets
            and comparison_result.zapret_packets
        ):
            visualizations["packet_sequence"] = self.create_packet_sequence_viz(
                comparison_result.recon_packets,
                comparison_result.zapret_packets,
            )

        # TTL pattern visualization
        if critical_differences:
            ttl_diffs = [d for d in critical_differences if d.category == DifferenceCategory.TTL]
            if ttl_diffs:
                visualizations["ttl_pattern"] = self.create_ttl_pattern_viz(ttl_diffs)

        # Fix priority matrix
        if generated_fixes:
            visualizations["fix_priority_matrix"] = self.create_fix_priority_matrix(generated_fixes)

        return visualizations
