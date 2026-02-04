"""
Helper functions for root cause analysis.

This module contains utility functions for determining affected components,
calculating impacts, generating fixes, and identifying code locations.
"""

from typing import List, Dict, Any
from .models import RootCauseType
from .critical_difference import CriticalDifference, ImpactLevel
from .pattern_recognizer import Anomaly


class CauseHelpers:
    """Helper functions for root cause creation and analysis."""

    @staticmethod
    def determine_affected_components(cause_type: RootCauseType) -> List[str]:
        """Determine which components are affected by a cause type."""
        component_mapping = {
            RootCauseType.MISSING_FAKE_PACKETS: [
                "fake_packet_generator",
                "attack_engine",
                "packet_sender",
            ],
            RootCauseType.INCORRECT_TTL: ["packet_builder", "fake_packet_generator"],
            RootCauseType.WRONG_SPLIT_POSITION: [
                "payload_splitter",
                "segment_generator",
            ],
            RootCauseType.MISSING_FOOLING_METHOD: [
                "checksum_corruptor",
                "sequence_manipulator",
            ],
            RootCauseType.SEQUENCE_OVERLAP_ERROR: [
                "sequence_calculator",
                "segment_generator",
            ],
            RootCauseType.TIMING_ISSUES: ["packet_scheduler", "timing_controller"],
            RootCauseType.CHECKSUM_VALIDATION_ERROR: [
                "checksum_calculator",
                "packet_validator",
            ],
            RootCauseType.PACKET_ORDER_ERROR: ["packet_scheduler", "sequence_manager"],
            RootCauseType.STRATEGY_PARAMETER_MISMATCH: [
                "strategy_parser",
                "parameter_validator",
            ],
            RootCauseType.ENGINE_TELEMETRY_ANOMALY: [
                "telemetry_collector",
                "metrics_reporter",
            ],
        }

        return component_mapping.get(cause_type, ["unknown_component"])

    @staticmethod
    def calculate_impact_from_difference(diff: CriticalDifference) -> float:
        """Calculate impact on success from a critical difference."""
        impact_mapping = {
            ImpactLevel.CRITICAL: 0.9,
            ImpactLevel.HIGH: 0.7,
            ImpactLevel.MEDIUM: 0.5,
            ImpactLevel.LOW: 0.3,
        }

        base_impact = impact_mapping.get(diff.impact_level, 0.5)

        # Adjust by confidence
        return base_impact * diff.confidence

    @staticmethod
    def calculate_impact_from_anomaly(anomaly: Anomaly) -> float:
        """Calculate impact on success from an anomaly."""
        severity_mapping = {"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3}

        base_impact = severity_mapping.get(anomaly.severity, 0.5)

        # Adjust by confidence
        return base_impact * anomaly.confidence

    @staticmethod
    def generate_fixes_for_cause_type(
        cause_type: RootCauseType, diff: CriticalDifference
    ) -> List[str]:
        """Generate suggested fixes for a cause type."""
        fix_templates = {
            RootCauseType.MISSING_FAKE_PACKETS: [
                "Implement fake packet generation in attack engine",
                "Add fake packet injection before real segments",
                "Ensure fake packets have correct TTL and corrupted checksums",
            ],
            RootCauseType.INCORRECT_TTL: [
                f"Set fake packet TTL to {diff.zapret_value} to match zapret",
                "Update TTL configuration in packet builder",
                "Validate TTL values in fake packet generation",
            ],
            RootCauseType.WRONG_SPLIT_POSITION: [
                f"Adjust split position to {diff.zapret_value}",
                "Fix payload splitting algorithm",
                "Validate split position calculation",
            ],
            RootCauseType.MISSING_FOOLING_METHOD: [
                "Implement badsum fooling method",
                "Implement badseq fooling method",
                "Add checksum corruption to fake packets",
            ],
            RootCauseType.SEQUENCE_OVERLAP_ERROR: [
                "Fix sequence number overlap calculation",
                "Ensure proper sequence number progression",
                "Validate segment sequence numbers",
            ],
        }

        return fix_templates.get(cause_type, ["Fix implementation to match zapret behavior"])

    @staticmethod
    def identify_code_locations(cause_type: RootCauseType) -> List[str]:
        """Identify likely code locations for a cause type."""
        location_mapping = {
            RootCauseType.MISSING_FAKE_PACKETS: [
                "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
                "recon/core/packet/packet_builder.py",
            ],
            RootCauseType.INCORRECT_TTL: [
                "recon/core/packet/packet_builder.py",
                "recon/core/bypass/packet/builder.py",
            ],
            RootCauseType.WRONG_SPLIT_POSITION: [
                "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
                "recon/core/packet/packet_builder.py",
            ],
            RootCauseType.MISSING_FOOLING_METHOD: [
                "recon/core/bypass/techniques/primitives.py",
                "recon/core/packet/packet_builder.py",
            ],
        }

        return location_mapping.get(cause_type, ["unknown_location"])

    @staticmethod
    def generate_test_requirements(cause_type: RootCauseType) -> List[str]:
        """Generate test requirements for a cause type."""
        test_templates = {
            RootCauseType.MISSING_FAKE_PACKETS: [
                "Test fake packet generation",
                "Verify fake packet count in telemetry",
                "Compare PCAP with zapret",
            ],
            RootCauseType.INCORRECT_TTL: [
                "Test TTL values in fake packets",
                "Verify TTL matches zapret configuration",
                "Test TTL impact on bypass success",
            ],
            RootCauseType.WRONG_SPLIT_POSITION: [
                "Test split position calculation",
                "Verify segment sizes match zapret",
                "Test split position impact on bypass",
            ],
        }

        return test_templates.get(cause_type, ["Test fix implementation"])
