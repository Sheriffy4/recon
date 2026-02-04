"""
Hypothesis validation against PCAP and historical data.

This module contains the HypothesisValidator class that validates
hypotheses using evidence from PCAP analysis and historical data.
"""

from typing import List, Dict, Any
import statistics
from .models import (
    Hypothesis,
    ValidatedHypothesis,
    Evidence,
    RootCause,
)
from .packet_info import PacketInfo


class HypothesisValidator:
    """Validator for testing hypotheses against evidence."""

    def __init__(self, historical_data=None):
        """Initialize validator with optional historical data."""
        self._historical_data = historical_data

    def set_historical_data(self, data: Dict[str, Any]):
        """Set historical data for validation."""
        self._historical_data = data

    def validate_single_hypothesis(
        self,
        hypothesis: Hypothesis,
        recon_packets: List[PacketInfo] = None,
        zapret_packets: List[PacketInfo] = None,
    ) -> ValidatedHypothesis:
        """Validate a single hypothesis against available evidence."""
        validation = ValidatedHypothesis(hypothesis=hypothesis, validation_score=0.0)

        # Validate against PCAP evidence if available
        if recon_packets and zapret_packets:
            pcap_validation = self._validate_against_pcap(hypothesis, recon_packets, zapret_packets)
            validation.supporting_evidence.extend(pcap_validation["supporting"])
            validation.contradicting_evidence.extend(pcap_validation["contradicting"])

        # Validate against historical data
        if self._historical_data:
            historical_validation = self._validate_against_historical_data(hypothesis)
            validation.supporting_evidence.extend(historical_validation["supporting"])
            validation.contradicting_evidence.extend(historical_validation["contradicting"])

        # Calculate validation score
        support_score = sum(e.confidence for e in validation.supporting_evidence)
        contradict_score = sum(e.confidence for e in validation.contradicting_evidence)

        total_evidence = len(validation.supporting_evidence) + len(
            validation.contradicting_evidence
        )
        if total_evidence > 0:
            validation.validation_score = (support_score - contradict_score) / total_evidence
            validation.validation_score = max(0.0, min(1.0, validation.validation_score))
        else:
            validation.validation_score = hypothesis.confidence * 0.5  # Default to half confidence

        # Recalculate validated flag AFTER evidence/score are populated.
        validation.is_validated = (
            support_score > contradict_score and validation.validation_score >= 0.7
        )

        return validation

    def _validate_against_pcap(
        self,
        hypothesis: Hypothesis,
        recon_packets: List[PacketInfo],
        zapret_packets: List[PacketInfo],
    ) -> Dict[str, List[Evidence]]:
        """Validate hypothesis against PCAP evidence."""
        supporting = []
        contradicting = []

        # Check for fake packet evidence
        if any("fake packet" in rc.description.lower() for rc in hypothesis.root_causes):
            recon_fake_count = sum(1 for p in recon_packets if p.ttl <= 5)
            zapret_fake_count = sum(1 for p in zapret_packets if p.ttl <= 5)

            if recon_fake_count < zapret_fake_count:
                supporting.append(
                    Evidence(
                        type="pcap_validation",
                        description=f"PCAP confirms missing fake packets: recon={recon_fake_count}, zapret={zapret_fake_count}",
                        confidence=0.9,
                        source="pcap_comparison",
                    )
                )
            else:
                contradicting.append(
                    Evidence(
                        type="pcap_validation",
                        description=f"PCAP shows adequate fake packets: recon={recon_fake_count}, zapret={zapret_fake_count}",
                        confidence=0.7,
                        source="pcap_comparison",
                    )
                )

        # Check for TTL evidence
        if any("ttl" in rc.description.lower() for rc in hypothesis.root_causes):
            recon_ttls = [p.ttl for p in recon_packets if p.ttl <= 10]
            zapret_ttls = [p.ttl for p in zapret_packets if p.ttl <= 10]

            if recon_ttls and zapret_ttls:
                recon_avg_ttl = statistics.mean(recon_ttls)
                zapret_avg_ttl = statistics.mean(zapret_ttls)

                if abs(recon_avg_ttl - zapret_avg_ttl) > 1:
                    supporting.append(
                        Evidence(
                            type="pcap_validation",
                            description=f"PCAP confirms TTL mismatch: recon avg={recon_avg_ttl:.1f}, zapret avg={zapret_avg_ttl:.1f}",
                            confidence=0.8,
                            source="pcap_comparison",
                        )
                    )

        return {"supporting": supporting, "contradicting": contradicting}

    def _validate_against_historical_data(
        self, hypothesis: Hypothesis
    ) -> Dict[str, List[Evidence]]:
        """Validate hypothesis against historical data."""
        supporting = []
        contradicting = []

        if not self._historical_data:
            return {"supporting": supporting, "contradicting": contradicting}

        # Check telemetry data
        failing_strategies = self._historical_data.get("strategy_effectiveness", {}).get(
            "top_failing", []
        )

        for strategy in failing_strategies:
            telemetry = strategy.get("engine_telemetry", {})

            # Check for fake packet hypothesis
            if any("fake packet" in rc.description.lower() for rc in hypothesis.root_causes):
                if telemetry.get("fake_packets_sent", 0) == 0:
                    supporting.append(
                        Evidence(
                            type="historical_validation",
                            description=f"Historical data confirms no fake packets sent in strategy: {strategy.get('strategy', 'unknown')}",
                            confidence=0.8,
                            source="historical_analysis",
                        )
                    )

        return {"supporting": supporting, "contradicting": contradicting}

    def deduplicate_causes(self, causes: List[RootCause]) -> List[RootCause]:
        """Remove duplicate or very similar root causes."""
        if not causes:
            return causes

        deduplicated = []
        seen_types = set()

        for cause in causes:
            # Simple deduplication by cause type
            if cause.cause_type not in seen_types:
                deduplicated.append(cause)
                seen_types.add(cause.cause_type)
            else:
                # Merge evidence into existing cause of same type
                existing = next(c for c in deduplicated if c.cause_type == cause.cause_type)
                existing.evidence.extend(cause.evidence)
                # Prefer worst-case (max) impact across duplicates.
                existing.impact_on_success = max(
                    existing.impact_on_success, cause.impact_on_success
                )
                existing.recalculate_blocking_severity()
                # Update confidence to average
                if existing.evidence:
                    existing.confidence = max(
                        0.0,
                        min(
                            1.0,
                            statistics.mean([e.confidence for e in existing.evidence]),
                        ),
                    )

        return deduplicated
