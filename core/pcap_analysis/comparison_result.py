"""
Comparison result data structures for PCAP analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from .packet_info import PacketInfo


@dataclass
class ComparisonResult:
    """Result of PCAP comparison between recon and zapret."""

    # Source data
    recon_packets: List[PacketInfo] = field(default_factory=list)
    zapret_packets: List[PacketInfo] = field(default_factory=list)

    # Analysis metadata
    recon_file: str = ""
    zapret_file: str = ""
    analysis_timestamp: float = 0.0

    # High-level metrics
    similarity_score: float = 0.0
    packet_count_diff: int = 0
    timing_correlation: float = 0.0

    # Detailed analysis
    sequence_differences: List[Dict[str, Any]] = field(default_factory=list)
    timing_differences: List[Dict[str, Any]] = field(default_factory=list)
    parameter_differences: List[Dict[str, Any]] = field(default_factory=list)

    # Connection analysis
    recon_connections: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    zapret_connections: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Strategy analysis
    detected_strategies: Dict[str, Any] = field(default_factory=dict)
    strategy_effectiveness: Dict[str, float] = field(default_factory=dict)

    # Issues and recommendations
    critical_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def add_sequence_difference(
        self,
        recon_packet: PacketInfo,
        zapret_packet: PacketInfo,
        difference_type: str,
        description: str,
        severity: str = "medium",
    ):
        """Add a sequence difference to the analysis."""
        diff = {
            "type": difference_type,
            "description": description,
            "severity": severity,
            "recon_packet": {
                "timestamp": recon_packet.timestamp,
                "sequence_num": recon_packet.sequence_num,
                "ttl": recon_packet.ttl,
                "flags": recon_packet.flags,
                "payload_length": recon_packet.payload_length,
            },
            "zapret_packet": {
                "timestamp": zapret_packet.timestamp,
                "sequence_num": zapret_packet.sequence_num,
                "ttl": zapret_packet.ttl,
                "flags": zapret_packet.flags,
                "payload_length": zapret_packet.payload_length,
            },
        }
        self.sequence_differences.append(diff)

    def add_timing_difference(
        self,
        description: str,
        recon_timing: float,
        zapret_timing: float,
        impact: str = "medium",
    ):
        """Add a timing difference to the analysis."""
        diff = {
            "description": description,
            "recon_timing": recon_timing,
            "zapret_timing": zapret_timing,
            "difference": abs(recon_timing - zapret_timing),
            "impact": impact,
        }
        self.timing_differences.append(diff)

    def add_parameter_difference(
        self,
        parameter: str,
        recon_value: Any,
        zapret_value: Any,
        impact: str = "medium",
    ):
        """Add a parameter difference to the analysis."""
        diff = {
            "parameter": parameter,
            "recon_value": recon_value,
            "zapret_value": zapret_value,
            "impact": impact,
        }
        self.parameter_differences.append(diff)

    def add_critical_issue(self, issue: str):
        """Add a critical issue that needs immediate attention."""
        if issue not in self.critical_issues:
            self.critical_issues.append(issue)

    def add_recommendation(self, recommendation: str):
        """Add a recommendation for fixing issues."""
        if recommendation not in self.recommendations:
            self.recommendations.append(recommendation)

    def calculate_similarity_score(self) -> float:
        """Calculate overall similarity score between recon and zapret."""
        if not self.recon_packets or not self.zapret_packets:
            self.similarity_score = 0.0
            return self.similarity_score

        # Factors for similarity calculation
        factors = []

        # Packet count similarity
        recon_count = len(self.recon_packets)
        zapret_count = len(self.zapret_packets)
        count_similarity = 1.0 - abs(recon_count - zapret_count) / max(recon_count, zapret_count)
        factors.append(count_similarity * 0.2)  # 20% weight

        # Sequence similarity (based on differences found)
        if recon_count > 0:
            sequence_similarity = 1.0 - len(self.sequence_differences) / recon_count
            factors.append(max(0.0, sequence_similarity) * 0.3)  # 30% weight

        # Timing similarity
        timing_similarity = 1.0 - len(self.timing_differences) / max(recon_count, 1)
        factors.append(max(0.0, timing_similarity) * 0.2)  # 20% weight

        # Parameter similarity
        param_similarity = (
            1.0 - len(self.parameter_differences) / 10
        )  # Normalize by expected params
        factors.append(max(0.0, param_similarity) * 0.3)  # 30% weight

        self.similarity_score = sum(factors)
        return self.similarity_score

    def get_critical_differences(self) -> List[Dict[str, Any]]:
        """Get all critical differences that need immediate attention."""
        critical = []

        # Critical sequence differences
        for diff in self.sequence_differences:
            if diff.get("severity") == "critical":
                critical.append(diff)

        # Critical timing differences
        for diff in self.timing_differences:
            if diff.get("impact") == "critical":
                critical.append(diff)

        # Critical parameter differences
        for diff in self.parameter_differences:
            if diff.get("impact") == "critical":
                critical.append(diff)

        return critical

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the comparison results."""
        return {
            "files_compared": {"recon": self.recon_file, "zapret": self.zapret_file},
            "packet_counts": {
                "recon": len(self.recon_packets),
                "zapret": len(self.zapret_packets),
                "difference": self.packet_count_diff,
            },
            "similarity_score": self.similarity_score,
            "differences_found": {
                "sequence": len(self.sequence_differences),
                "timing": len(self.timing_differences),
                "parameters": len(self.parameter_differences),
            },
            "critical_issues": len(self.critical_issues),
            "recommendations": len(self.recommendations),
            "connections": {
                "recon": len(self.recon_connections),
                "zapret": len(self.zapret_connections),
            },
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "summary": self.get_summary(),
            "similarity_score": self.similarity_score,
            "sequence_differences": self.sequence_differences,
            "timing_differences": self.timing_differences,
            "parameter_differences": self.parameter_differences,
            "critical_issues": self.critical_issues,
            "recommendations": self.recommendations,
            "detected_strategies": self.detected_strategies,
            "strategy_effectiveness": self.strategy_effectiveness,
            "analysis_metadata": {
                "timestamp": self.analysis_timestamp,
                "recon_file": self.recon_file,
                "zapret_file": self.zapret_file,
            },
        }
