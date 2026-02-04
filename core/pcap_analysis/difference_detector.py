from __future__ import annotations

"""
DifferenceDetector for identifying critical differences between recon and zapret PCAP files.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
import statistics
from statistics import StatisticsError
from collections import defaultdict
from collections import Counter

from .packet_info import PacketInfo
from .comparison_result import ComparisonResult
from .critical_difference import (
    CriticalDifference,
    DifferenceCategory,
    ImpactLevel,
    FixComplexity,
    DifferenceGroup,
)


@dataclass
class DetectionConfig:
    """Configuration for difference detection algorithms."""

    # Thresholds for different types of differences
    timing_threshold_ms: float = 10.0  # Milliseconds
    sequence_gap_threshold: int = 1000
    ttl_difference_threshold: int = 1
    checksum_mismatch_threshold: float = 0.1  # Percentage

    # Confidence calculation parameters
    min_evidence_count: int = 2
    confidence_decay_factor: float = 0.9

    # Impact assessment parameters
    critical_packet_types: Optional[Set[str]] = field(default=None)
    high_impact_categories: Optional[Set[DifferenceCategory]] = field(default=None)

    def __post_init__(self):
        """Initialize default sets."""
        if self.critical_packet_types is None:
            self.critical_packet_types = {
                "ClientHello",
                "fake_packet",
                "disorder_packet",
            }

        if self.high_impact_categories is None:
            self.high_impact_categories = {
                DifferenceCategory.SEQUENCE,
                DifferenceCategory.TTL,
                DifferenceCategory.STRATEGY,
            }


class DifferenceDetector:
    """
    Detects and prioritizes critical differences between recon and zapret packet sequences.

    This class implements sophisticated algorithms to identify differences that are likely
    to cause bypass failures and prioritizes them for fixing.
    """

    @staticmethod
    def _safe_mode(values: List[Any]) -> Optional[Any]:
        if not values:
            return None
        try:
            return statistics.mode(values)
        except StatisticsError:
            return Counter(values).most_common(1)[0][0]

    def __init__(self, config: Optional[DetectionConfig] = None):
        """Initialize the difference detector."""
        self.config = config or DetectionConfig()
        self.logger = logging.getLogger(__name__)

        # Detection statistics
        self.detection_stats = {
            "total_comparisons": 0,
            "differences_found": 0,
            "critical_differences": 0,
            "categories_detected": defaultdict(int),
        }

    def detect_critical_differences(self, comparison: ComparisonResult) -> List[CriticalDifference]:
        """
        Main entry point for detecting critical differences.

        Args:
            comparison: ComparisonResult containing recon and zapret packet data

        Returns:
            List of CriticalDifference objects prioritized by severity
        """
        self.logger.info("Starting critical difference detection")
        self.detection_stats["total_comparisons"] += 1

        differences = []

        # Detect different types of differences
        differences.extend(self._detect_sequence_differences(comparison))
        differences.extend(self._detect_timing_differences(comparison))
        differences.extend(self._detect_checksum_differences(comparison))
        differences.extend(self._detect_ttl_differences(comparison))
        differences.extend(self._detect_strategy_differences(comparison))
        differences.extend(self._detect_payload_differences(comparison))
        differences.extend(self._detect_flag_differences(comparison))
        differences.extend(self._detect_ordering_differences(comparison))

        # Update statistics
        self.detection_stats["differences_found"] += len(differences)
        for diff in differences:
            self.detection_stats["categories_detected"][diff.category.value] += 1
            if diff.impact_level == ImpactLevel.CRITICAL:
                self.detection_stats["critical_differences"] += 1

        # Prioritize differences
        prioritized = self.prioritize_differences(differences)

        self.logger.info(
            f"Detected {len(differences)} differences, "
            f"{len([d for d in differences if d.impact_level == ImpactLevel.CRITICAL])} critical"
        )

        return prioritized

    def _detect_sequence_differences(
        self, comparison: ComparisonResult
    ) -> List[CriticalDifference]:
        """Detect differences in packet sequence numbers and ordering."""
        differences = []

        recon_packets = comparison.recon_packets
        zapret_packets = comparison.zapret_packets

        if not recon_packets or not zapret_packets:
            return differences

        # Group packets by connection
        recon_connections = self._group_by_connection(recon_packets)
        zapret_connections = self._group_by_connection(zapret_packets)

        # Compare sequence patterns for each connection
        for conn_key in recon_connections:
            if conn_key not in zapret_connections:
                continue

            recon_conn_packets = recon_connections[conn_key]
            zapret_conn_packets = zapret_connections[conn_key]

            # Detect sequence number gaps
            seq_diff = self._detect_sequence_gaps(recon_conn_packets, zapret_conn_packets, conn_key)
            if seq_diff:
                differences.append(seq_diff)

            # Detect fake packet sequence issues
            fake_diff = self._detect_fake_packet_sequence_issues(
                recon_conn_packets, zapret_conn_packets, conn_key
            )
            if fake_diff:
                differences.append(fake_diff)

        return differences

    def _detect_timing_differences(self, comparison: ComparisonResult) -> List[CriticalDifference]:
        """Detect critical timing differences between packet sequences."""
        differences = []

        recon_packets = comparison.recon_packets
        zapret_packets = comparison.zapret_packets

        if len(recon_packets) < 2 or len(zapret_packets) < 2:
            return differences

        # Calculate inter-packet delays
        recon_delays = self._calculate_inter_packet_delays(recon_packets)
        zapret_delays = self._calculate_inter_packet_delays(zapret_packets)

        # Compare delay patterns
        if len(recon_delays) > 0 and len(zapret_delays) > 0:
            avg_recon_delay = statistics.mean(recon_delays)
            avg_zapret_delay = statistics.mean(zapret_delays)

            delay_diff_ms = abs(avg_recon_delay - avg_zapret_delay) * 1000

            if delay_diff_ms > self.config.timing_threshold_ms:
                confidence = min(1.0, delay_diff_ms / (self.config.timing_threshold_ms * 10))

                diff = CriticalDifference(
                    category=DifferenceCategory.TIMING,
                    description=f"Significant timing difference in packet delays: "
                    f"{delay_diff_ms:.2f}ms average difference",
                    recon_value=f"{avg_recon_delay*1000:.2f}ms",
                    zapret_value=f"{avg_zapret_delay*1000:.2f}ms",
                    impact_level=self._assess_timing_impact(delay_diff_ms),
                    confidence=confidence,
                    fix_priority=self._calculate_timing_priority(delay_diff_ms),
                    fix_complexity=FixComplexity.MODERATE,
                    suggested_fix="Adjust packet sending delays in bypass engine",
                    code_location="core/bypass/packet/sender.py",
                )

                diff.add_evidence(
                    "timing_analysis",
                    f"Inter-packet delay analysis across {len(recon_delays)} packet pairs",
                    {
                        "recon_delays_ms": [d * 1000 for d in recon_delays[:10]],  # First 10
                        "zapret_delays_ms": [d * 1000 for d in zapret_delays[:10]],
                        "difference_ms": delay_diff_ms,
                    },
                )

                differences.append(diff)

        return differences

    def _detect_checksum_differences(
        self, comparison: ComparisonResult
    ) -> List[CriticalDifference]:
        """Detect differences in checksum handling."""
        differences = []

        recon_packets = comparison.recon_packets
        zapret_packets = comparison.zapret_packets

        # Analyze checksum patterns
        recon_bad_checksums = [p for p in recon_packets if not p.checksum_valid]
        zapret_bad_checksums = [p for p in zapret_packets if not p.checksum_valid]

        recon_bad_ratio = len(recon_bad_checksums) / max(1, len(recon_packets))
        zapret_bad_ratio = len(zapret_bad_checksums) / max(1, len(zapret_packets))

        ratio_diff = abs(recon_bad_ratio - zapret_bad_ratio)

        if ratio_diff > self.config.checksum_mismatch_threshold:
            confidence = min(1.0, ratio_diff / 0.5)  # Scale to 0-1

            diff = CriticalDifference(
                category=DifferenceCategory.CHECKSUM,
                description=f"Checksum corruption pattern mismatch: "
                f"{ratio_diff:.1%} difference in bad checksum ratio",
                recon_value=f"{recon_bad_ratio:.1%} bad checksums",
                zapret_value=f"{zapret_bad_ratio:.1%} bad checksums",
                impact_level=(ImpactLevel.HIGH if ratio_diff > 0.3 else ImpactLevel.MEDIUM),
                confidence=confidence,
                fix_priority=2 if ratio_diff > 0.3 else 4,
                fix_complexity=FixComplexity.MODERATE,
                suggested_fix="Fix checksum corruption in fake packet generation",
                code_location="core/bypass/packet/builder.py",
            )

            diff.add_evidence(
                "checksum_analysis",
                f"Checksum pattern analysis across {len(recon_packets)} recon and {len(zapret_packets)} zapret packets",
                {
                    "recon_bad_count": len(recon_bad_checksums),
                    "zapret_bad_count": len(zapret_bad_checksums),
                    "recon_total": len(recon_packets),
                    "zapret_total": len(zapret_packets),
                },
            )

            differences.append(diff)

        return differences

    def _detect_ttl_differences(self, comparison: ComparisonResult) -> List[CriticalDifference]:
        """Detect critical TTL differences."""
        differences = []

        recon_packets = comparison.recon_packets
        zapret_packets = comparison.zapret_packets

        # Analyze TTL patterns
        recon_ttls = [p.ttl for p in recon_packets]
        zapret_ttls = [p.ttl for p in zapret_packets]

        if not recon_ttls or not zapret_ttls:
            return differences

        # Check for fake packet TTL differences (most critical)
        recon_fake_ttls = [p.ttl for p in recon_packets if p.is_fake_packet()]
        zapret_fake_ttls = [p.ttl for p in zapret_packets if p.is_fake_packet()]

        if recon_fake_ttls and zapret_fake_ttls:
            recon_fake_ttl = self._safe_mode(recon_fake_ttls)
            zapret_fake_ttl = self._safe_mode(zapret_fake_ttls)

            if (
                recon_fake_ttl is not None
                and zapret_fake_ttl is not None
                and abs(recon_fake_ttl - zapret_fake_ttl) >= self.config.ttl_difference_threshold
            ):
                diff = CriticalDifference(
                    category=DifferenceCategory.TTL,
                    description=f"Critical TTL mismatch in fake packets: "
                    f"recon uses TTL={recon_fake_ttl}, zapret uses TTL={zapret_fake_ttl}",
                    recon_value=recon_fake_ttl,
                    zapret_value=zapret_fake_ttl,
                    impact_level=ImpactLevel.CRITICAL,
                    confidence=0.95,
                    fix_priority=1,
                    fix_complexity=FixComplexity.SIMPLE,
                    suggested_fix=f"Set fake packet TTL to {zapret_fake_ttl} in strategy configuration",
                    code_location="core/bypass/attacks/tcp/fake_disorder_attack.py",
                )

                diff.add_evidence(
                    "ttl_analysis",
                    "Fake packet TTL analysis",
                    {
                        "recon_fake_ttls": recon_fake_ttls,
                        "zapret_fake_ttls": zapret_fake_ttls,
                        "recon_mode": recon_fake_ttl,
                        "zapret_mode": zapret_fake_ttl,
                    },
                )

                differences.append(diff)

        return differences

    def _detect_strategy_differences(
        self, comparison: ComparisonResult
    ) -> List[CriticalDifference]:
        """Detect strategy-level differences."""
        differences = []

        # Analyze strategy patterns from packet sequences
        recon_strategy = self._infer_strategy_from_packets(comparison.recon_packets)
        zapret_strategy = self._infer_strategy_from_packets(comparison.zapret_packets)

        # Compare inferred strategies
        strategy_diffs = self._compare_strategies(recon_strategy, zapret_strategy)

        for param, (recon_val, zapret_val) in strategy_diffs.items():
            diff = CriticalDifference(
                category=DifferenceCategory.STRATEGY,
                description=f"Strategy parameter mismatch: {param}",
                recon_value=recon_val,
                zapret_value=zapret_val,
                impact_level=self._assess_strategy_param_impact(param),
                confidence=0.8,
                fix_priority=self._calculate_strategy_priority(param),
                fix_complexity=FixComplexity.MODERATE,
                suggested_fix=f"Update {param} parameter to match zapret behavior",
                code_location="core/strategy/",
            )

            diff.add_evidence(
                "strategy_inference",
                "Strategy parameter inferred from packet analysis",
                {
                    "parameter": param,
                    "recon_inferred": recon_val,
                    "zapret_inferred": zapret_val,
                },
            )

            differences.append(diff)

        return differences

    def _detect_payload_differences(self, comparison: ComparisonResult) -> List[CriticalDifference]:
        """Detect payload-related differences."""
        differences = []

        recon_packets = comparison.recon_packets
        zapret_packets = comparison.zapret_packets

        # Compare ClientHello payloads
        recon_client_hellos = [p for p in recon_packets if p.is_client_hello]
        zapret_client_hellos = [p for p in zapret_packets if p.is_client_hello]

        if recon_client_hellos and zapret_client_hellos:
            # Compare payload sizes
            recon_sizes = [p.payload_length for p in recon_client_hellos]
            zapret_sizes = [p.payload_length for p in zapret_client_hellos]

            if recon_sizes and zapret_sizes:
                avg_recon_size = statistics.mean(recon_sizes)
                avg_zapret_size = statistics.mean(zapret_sizes)

                size_diff = abs(avg_recon_size - avg_zapret_size)

                if size_diff > 50:  # Significant payload size difference
                    diff = CriticalDifference(
                        category=DifferenceCategory.PAYLOAD,
                        description=f"ClientHello payload size difference: {size_diff:.0f} bytes",
                        recon_value=f"{avg_recon_size:.0f} bytes",
                        zapret_value=f"{avg_zapret_size:.0f} bytes",
                        impact_level=ImpactLevel.MEDIUM,
                        confidence=0.7,
                        fix_priority=5,
                        fix_complexity=FixComplexity.COMPLEX,
                        suggested_fix="Investigate TLS handshake differences",
                    )

                    differences.append(diff)

        return differences

    def _detect_flag_differences(self, comparison: ComparisonResult) -> List[CriticalDifference]:
        """Detect TCP flag differences."""
        differences = []

        recon_packets = comparison.recon_packets
        zapret_packets = comparison.zapret_packets

        # Analyze flag patterns
        recon_flag_patterns = self._analyze_flag_patterns(recon_packets)
        zapret_flag_patterns = self._analyze_flag_patterns(zapret_packets)

        # Compare patterns
        for flag_combo in sorted(
            set(recon_flag_patterns.keys()) | set(zapret_flag_patterns.keys())
        ):
            recon_count = recon_flag_patterns.get(flag_combo, 0)
            zapret_count = zapret_flag_patterns.get(flag_combo, 0)

            if abs(recon_count - zapret_count) > 2:  # Significant difference
                diff = CriticalDifference(
                    category=DifferenceCategory.FLAGS,
                    description=f"TCP flag pattern difference: {flag_combo}",
                    recon_value=f"{recon_count} packets",
                    zapret_value=f"{zapret_count} packets",
                    impact_level=ImpactLevel.LOW,
                    confidence=0.6,
                    fix_priority=7,
                    fix_complexity=FixComplexity.MODERATE,
                )

                differences.append(diff)

        return differences

    def _detect_ordering_differences(
        self, comparison: ComparisonResult
    ) -> List[CriticalDifference]:
        """Detect packet ordering differences."""
        differences = []

        recon_packets = comparison.recon_packets
        zapret_packets = comparison.zapret_packets

        if len(recon_packets) != len(zapret_packets):
            diff = CriticalDifference(
                category=DifferenceCategory.ORDERING,
                description="Packet count mismatch",
                recon_value=f"{len(recon_packets)} packets",
                zapret_value=f"{len(zapret_packets)} packets",
                impact_level=ImpactLevel.HIGH,
                confidence=1.0,
                fix_priority=2,
                fix_complexity=FixComplexity.COMPLEX,
                suggested_fix="Investigate missing or extra packets in sequence",
            )

            differences.append(diff)

        return differences

    def prioritize_differences(
        self, differences: List[CriticalDifference]
    ) -> List[CriticalDifference]:
        """
        Prioritize differences by severity and impact.

        Args:
            differences: List of detected differences

        Returns:
            List of differences sorted by priority (most critical first)
        """
        # Sort by severity score (descending) and fix priority (ascending)
        prioritized = sorted(
            differences,
            key=lambda d: (
                -d.calculate_severity_score(),
                d.fix_priority,
                -d.confidence,
            ),
        )

        return prioritized

    def categorize_differences(
        self, differences: List[CriticalDifference]
    ) -> Dict[DifferenceCategory, List[CriticalDifference]]:
        """
        Categorize differences by type.

        Args:
            differences: List of differences to categorize

        Returns:
            Dictionary mapping categories to lists of differences
        """
        categorized = defaultdict(list)

        for diff in differences:
            categorized[diff.category].append(diff)

        return dict(categorized)

    def assess_impact(self, difference: CriticalDifference) -> Dict[str, Any]:
        """
        Assess the impact of a specific difference.

        Args:
            difference: The difference to assess

        Returns:
            Dictionary containing impact assessment details
        """
        assessment = {
            "severity_score": difference.calculate_severity_score(),
            "is_blocking": difference.is_blocking(),
            "fix_urgency": difference.get_fix_urgency(),
            "estimated_fix_time": self._estimate_fix_time(difference),
            "risk_level": self._assess_fix_risk(difference),
            "dependencies": self._identify_dependencies(difference),
        }

        return assessment

    def group_related_differences(
        self, differences: List[CriticalDifference]
    ) -> List[DifferenceGroup]:
        """Group related differences for batch fixing."""
        groups = []

        # Group by category and connection
        category_groups = defaultdict(list)
        for diff in differences:
            key = f"{diff.category.value}_{diff.connection_key or 'global'}"
            category_groups[key].append(diff)

        # Create groups
        for group_key, group_diffs in category_groups.items():
            if len(group_diffs) > 1:
                group = DifferenceGroup(name=group_key, differences=group_diffs)
                groups.append(group)

        return groups

    # Helper methods

    def _group_by_connection(self, packets: List[PacketInfo]) -> Dict[str, List[PacketInfo]]:
        """Group packets by connection key."""
        connections = defaultdict(list)
        for packet in packets:
            key = packet.get_connection_key()
            connections[key].append(packet)
        return dict(connections)

    def _detect_sequence_gaps(
        self,
        recon_packets: List[PacketInfo],
        zapret_packets: List[PacketInfo],
        conn_key: str,
    ) -> Optional[CriticalDifference]:
        """Detect sequence number gaps between recon and zapret."""
        if not recon_packets or not zapret_packets:
            return None

        # Calculate sequence ranges
        recon_seqs = [p.sequence_num for p in recon_packets if p.sequence_num > 0]
        zapret_seqs = [p.sequence_num for p in zapret_packets if p.sequence_num > 0]

        if not recon_seqs or not zapret_seqs:
            return None

        recon_range = max(recon_seqs) - min(recon_seqs)
        zapret_range = max(zapret_seqs) - min(zapret_seqs)

        range_diff = abs(recon_range - zapret_range)

        if range_diff > self.config.sequence_gap_threshold:
            return CriticalDifference(
                category=DifferenceCategory.SEQUENCE,
                description=f"Sequence number range mismatch in connection {conn_key}",
                recon_value=f"range: {recon_range}",
                zapret_value=f"range: {zapret_range}",
                impact_level=ImpactLevel.HIGH,
                confidence=0.8,
                fix_priority=3,
                connection_key=conn_key,
            )

        return None

    def _detect_fake_packet_sequence_issues(
        self,
        recon_packets: List[PacketInfo],
        zapret_packets: List[PacketInfo],
        conn_key: str,
    ) -> Optional[CriticalDifference]:
        """Detect issues with fake packet sequences."""
        recon_fake = [p for p in recon_packets if p.is_fake_packet()]
        zapret_fake = [p for p in zapret_packets if p.is_fake_packet()]

        if len(recon_fake) != len(zapret_fake):
            return CriticalDifference(
                category=DifferenceCategory.SEQUENCE,
                description=f"Fake packet count mismatch in connection {conn_key}",
                recon_value=f"{len(recon_fake)} fake packets",
                zapret_value=f"{len(zapret_fake)} fake packets",
                impact_level=ImpactLevel.CRITICAL,
                confidence=0.9,
                fix_priority=1,
                connection_key=conn_key,
            )

        return None

    def _calculate_inter_packet_delays(self, packets: List[PacketInfo]) -> List[float]:
        """Calculate delays between consecutive packets."""
        if len(packets) < 2:
            return []

        delays = []
        for i in range(1, len(packets)):
            delay = packets[i].timestamp - packets[i - 1].timestamp
            delays.append(delay)

        return delays

    def _assess_timing_impact(self, delay_diff_ms: float) -> ImpactLevel:
        """Assess impact level based on timing difference."""
        if delay_diff_ms > 100:
            return ImpactLevel.CRITICAL
        elif delay_diff_ms > 50:
            return ImpactLevel.HIGH
        elif delay_diff_ms > 20:
            return ImpactLevel.MEDIUM
        else:
            return ImpactLevel.LOW

    def _calculate_timing_priority(self, delay_diff_ms: float) -> int:
        """Calculate fix priority based on timing difference."""
        if delay_diff_ms > 100:
            return 1
        elif delay_diff_ms > 50:
            return 2
        elif delay_diff_ms > 20:
            return 4
        else:
            return 6

    def _infer_strategy_from_packets(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """Infer strategy parameters from packet analysis."""
        strategy = {}

        fake_packets = [p for p in packets if p.is_fake_packet()]
        if fake_packets:
            # Infer TTL setting
            ttls = [p.ttl for p in fake_packets]
            if ttls:
                strategy["ttl"] = self._safe_mode(ttls)

        # Infer split position from ClientHello analysis
        client_hellos = [p for p in packets if p.is_client_hello]
        if client_hellos and len(packets) > len(client_hellos):
            # Look for split patterns
            strategy["split_detected"] = True

        return strategy

    def _compare_strategies(
        self, recon_strategy: Dict[str, Any], zapret_strategy: Dict[str, Any]
    ) -> Dict[str, Tuple[Any, Any]]:
        """Compare inferred strategies."""
        differences = {}

        all_params = sorted(set(recon_strategy.keys()) | set(zapret_strategy.keys()))

        for param in all_params:
            recon_val = recon_strategy.get(param)
            zapret_val = zapret_strategy.get(param)

            if recon_val != zapret_val:
                differences[param] = (recon_val, zapret_val)

        return differences

    def _assess_strategy_param_impact(self, param: str) -> ImpactLevel:
        """Assess impact of strategy parameter differences."""
        critical_params = {"ttl", "split_pos", "fooling"}
        high_params = {"split_seqovl", "fake_tls"}

        if param in critical_params:
            return ImpactLevel.CRITICAL
        elif param in high_params:
            return ImpactLevel.HIGH
        else:
            return ImpactLevel.MEDIUM

    def _calculate_strategy_priority(self, param: str) -> int:
        """Calculate fix priority for strategy parameters."""
        priority_map = {
            "ttl": 1,
            "split_pos": 2,
            "fooling": 2,
            "split_seqovl": 3,
            "fake_tls": 4,
        }

        return priority_map.get(param, 5)

    def _analyze_flag_patterns(self, packets: List[PacketInfo]) -> Dict[str, int]:
        """Analyze TCP flag patterns."""
        patterns = defaultdict(int)

        for packet in packets:
            flag_combo = ",".join(sorted(packet.flags))
            patterns[flag_combo] += 1

        return dict(patterns)

    def _estimate_fix_time(self, difference: CriticalDifference) -> str:
        """Estimate time required to fix the difference."""
        complexity_times = {
            FixComplexity.SIMPLE: "1-2 hours",
            FixComplexity.MODERATE: "4-8 hours",
            FixComplexity.COMPLEX: "1-3 days",
        }

        return complexity_times[difference.fix_complexity]

    def _assess_fix_risk(self, difference: CriticalDifference) -> str:
        """Assess risk level of applying the fix."""
        if difference.category in [
            DifferenceCategory.STRATEGY,
            DifferenceCategory.SEQUENCE,
        ]:
            return "MEDIUM"
        elif difference.fix_complexity == FixComplexity.COMPLEX:
            return "HIGH"
        else:
            return "LOW"

    def _identify_dependencies(self, difference: CriticalDifference) -> List[str]:
        """Identify dependencies for fixing the difference."""
        dependencies = []

        if difference.category == DifferenceCategory.STRATEGY:
            dependencies.append("Strategy configuration update")

        if difference.category == DifferenceCategory.SEQUENCE:
            dependencies.append("Packet sequence engine modification")

        return dependencies

    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection statistics."""
        return dict(self.detection_stats)
