"""
Hypothesis generation for root causes.

This module contains the HypothesisGenerator class that generates
testable hypotheses from identified root causes.
"""

from typing import List, Dict, Optional
import statistics
from .models import RootCause, Hypothesis, RootCauseType


class HypothesisGenerator:
    """Generator for creating testable hypotheses from root causes."""

    def group_causes_by_type(self, causes: List[RootCause]) -> Dict[RootCauseType, List[RootCause]]:
        """Group root causes by type."""
        groups = {}
        for cause in causes:
            if cause.cause_type not in groups:
                groups[cause.cause_type] = []
            groups[cause.cause_type].append(cause)
        return groups

    def generate_hypothesis_for_group(
        self, cause_type: RootCauseType, causes: List[RootCause]
    ) -> Optional[Hypothesis]:
        """Generate hypothesis for a group of similar causes."""
        if not causes:
            return None

        # Calculate group confidence
        group_confidence = statistics.mean([c.confidence for c in causes])

        # Generate hypothesis based on cause type
        hypothesis_templates = {
            RootCauseType.MISSING_FAKE_PACKETS: {
                "description": "Recon is not generating fake packets as expected by the fakeddisorder strategy",
                "predicted_fix": "Implement fake packet generation with correct TTL and checksum corruption",
                "testable_predictions": [
                    "Adding fake packet generation will increase fake_packets_sent telemetry",
                    "Fake packets should have TTL=3 and invalid checksums",
                    "Fake packets should be sent before real segments",
                ],
                "validation_criteria": [
                    "PCAP shows fake packets with TTL=3",
                    "Engine telemetry shows fake_packets_sent > 0",
                    "Fake packets have corrupted checksums",
                ],
            },
            RootCauseType.INCORRECT_TTL: {
                "description": "TTL values in fake packets do not match zapret behavior",
                "predicted_fix": "Set fake packet TTL to 3 to match zapret configuration",
                "testable_predictions": [
                    "Setting TTL=3 will make fake packets identical to zapret",
                    "DPI will ignore fake packets with low TTL",
                ],
                "validation_criteria": [
                    "All fake packets have TTL=3",
                    "TTL matches zapret PCAP exactly",
                ],
            },
            RootCauseType.WRONG_SPLIT_POSITION: {
                "description": "Payload split position does not match zapret implementation",
                "predicted_fix": "Adjust split position to match zapret (likely position 3)",
                "testable_predictions": [
                    "Correct split position will create identical segment sizes",
                    "Split segments will have proper sequence overlap",
                ],
                "validation_criteria": [
                    "Split position matches zapret PCAP",
                    "Segment sizes are identical to zapret",
                ],
            },
        }

        template = hypothesis_templates.get(cause_type)
        if not template:
            return None

        hypothesis = Hypothesis(
            description=template["description"],
            root_causes=causes,
            predicted_fix=template["predicted_fix"],
            confidence=group_confidence,
            testable_predictions=template["testable_predictions"],
            validation_criteria=template["validation_criteria"],
        )

        return hypothesis

    def generate_combined_hypotheses(self, causes: List[RootCause]) -> List[Hypothesis]:
        """Generate hypotheses that combine multiple related causes."""
        combined_hypotheses = []

        # Look for fakeddisorder-specific combination
        fake_packet_causes = [
            c for c in causes if c.cause_type == RootCauseType.MISSING_FAKE_PACKETS
        ]
        ttl_causes = [c for c in causes if c.cause_type == RootCauseType.INCORRECT_TTL]
        split_causes = [c for c in causes if c.cause_type == RootCauseType.WRONG_SPLIT_POSITION]

        if len(fake_packet_causes) + len(ttl_causes) + len(split_causes) >= 2:
            combined_causes = fake_packet_causes + ttl_causes + split_causes
            avg_confidence = statistics.mean([c.confidence for c in combined_causes])

            hypothesis = Hypothesis(
                description="Recon's fakeddisorder implementation has multiple issues preventing successful bypass",
                root_causes=combined_causes,
                predicted_fix="Comprehensive fakeddisorder fix: implement fake packets with TTL=3, correct split position, and proper sequence overlap",
                confidence=avg_confidence,
                testable_predictions=[
                    "Complete fakeddisorder fix will match zapret behavior exactly",
                    "All telemetry metrics will match zapret patterns",
                    "Success rate will improve significantly",
                ],
                validation_criteria=[
                    "PCAP comparison shows identical packet sequences",
                    "All strategy parameters match zapret",
                    "Domain bypass success matches zapret",
                ],
            )

            combined_hypotheses.append(hypothesis)

        return combined_hypotheses
