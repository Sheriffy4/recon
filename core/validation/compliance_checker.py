"""
ComplianceChecker - Strategy validation and compliance checking.

This module implements compliance checking between PCAP captures and expected strategies:
- Compare PCAP vs expected strategy from domain_rules.json
- Match expected vs detected attacks
- Calculate compliance scores
- Generate patches for domain_rules.json updates
- Provide detailed compliance reports

Requirements: 3.2, 3.6, 9.1, 9.2
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .pcap_validator import PCAPValidator
from .attack_detector import DetectedAttacks
from ..strategy.loader import Strategy

try:
    from ..metrics.attack_parity_metrics import get_metrics_collector

    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ComplianceReport:
    """
    Compliance report comparing expected strategy vs detected attacks.

    Requirements: 9.2
    """

    domain: str
    expected_strategy: Strategy
    detected_attacks: DetectedAttacks
    score: int
    max_score: int
    issues: List[str] = field(default_factory=list)
    verdicts: Dict[str, bool] = field(default_factory=dict)
    proposed_patch: Optional[Dict] = None

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance as percentage."""
        if self.max_score == 0:
            return 100.0
        return (self.score / self.max_score) * 100.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "expected_strategy": {
                "type": self.expected_strategy.type,
                "attacks": self.expected_strategy.attacks,
                "params": self.expected_strategy.params,
                "metadata": self.expected_strategy.metadata,
            },
            "detected_attacks": {
                "fake": self.detected_attacks.fake,
                "fake_count": self.detected_attacks.fake_count,
                "fake_ttl": self.detected_attacks.fake_ttl,
                "split": self.detected_attacks.split,
                "fragment_count": self.detected_attacks.fragment_count,
                "split_near_sni": self.detected_attacks.split_near_sni,
                "split_positions": self.detected_attacks.split_positions,
                "disorder": self.detected_attacks.disorder,
                "disorder_type": self.detected_attacks.disorder_type,
                "badsum": self.detected_attacks.badsum,
                "badseq": self.detected_attacks.badseq,
            },
            "score": self.score,
            "max_score": self.max_score,
            "compliance_percentage": self.compliance_percentage,
            "issues": self.issues,
            "verdicts": self.verdicts,
            "proposed_patch": self.proposed_patch,
        }


class ComplianceChecker:
    """
    Compliance checker for validating strategy application.

    Compares PCAP captures against expected strategies to ensure:
    - All expected attacks are present
    - Attack parameters match expectations
    - No unexpected attacks are present

    Requirements: 3.2, 3.6, 9.1, 9.2
    """

    def __init__(self):
        """Initialize compliance checker."""
        self.validator = PCAPValidator()

    def check_compliance(
        self,
        pcap_path: str,
        domain: str,
        expected_strategy: Strategy,
        target_ip: Optional[str] = None,
    ) -> ComplianceReport:
        """
        Check if PCAP matches expected strategy.

        Args:
            pcap_path: Path to PCAP file
            domain: Domain name being tested
            expected_strategy: Expected strategy from domain_rules.json
            target_ip: Optional target IP to filter streams

        Returns:
            ComplianceReport with score and list of issues

        Requirements: 3.2, 3.6, 9.1, 9.2
        """
        logger.info(f"Checking compliance for {domain} against {pcap_path}")

        # Load and analyze PCAP
        try:
            packets = self.validator.load_pcap(pcap_path)
            if not packets:
                return self._create_error_report(
                    domain, expected_strategy, "No packets found in PCAP file"
                )

            streams = self.validator.find_streams(packets, target_ip)
            if not streams:
                return self._create_error_report(
                    domain, expected_strategy, "No TCP streams found in PCAP"
                )

            # Find stream with ClientHello
            clienthello_stream = None
            sni_offset = None

            for stream in streams:
                ch_data = self.validator.reassemble_clienthello(stream)
                if ch_data:
                    clienthello_stream = stream

                    # Parse ClientHello to get SNI offset
                    ch_info = self.validator.parse_clienthello(ch_data)
                    if ch_info.sni_offset is not None:
                        sni_offset = ch_info.sni_offset
                    break

            if not clienthello_stream:
                return self._create_error_report(
                    domain, expected_strategy, "No ClientHello found in PCAP"
                )

            # Detect attacks
            detected = self.validator.detect_attacks(clienthello_stream, sni_offset)

        except Exception as e:
            logger.error(f"Error analyzing PCAP: {e}")
            return self._create_error_report(
                domain, expected_strategy, f"Error analyzing PCAP: {str(e)}"
            )

        # Compare expected vs detected
        verdicts = self.compare_attacks(expected_strategy.attacks, detected)
        score, max_score, issues = self.calculate_score(expected_strategy, detected, verdicts)

        # Generate patch if needed
        proposed_patch = None
        if score < max_score:
            proposed_patch = self.generate_patch(domain, detected)

        report = ComplianceReport(
            domain=domain,
            expected_strategy=expected_strategy,
            detected_attacks=detected,
            score=score,
            max_score=max_score,
            issues=issues,
            verdicts=verdicts,
            proposed_patch=proposed_patch,
        )

        # Record compliance metric
        if METRICS_AVAILABLE:
            try:
                collector = get_metrics_collector()
                detected_attack_list = []
                if detected.fake:
                    detected_attack_list.append("fake")
                if detected.split:
                    detected_attack_list.append(
                        "multisplit" if detected.fragment_count > 2 else "split"
                    )
                if detected.disorder:
                    detected_attack_list.append("disorder")

                collector.record_compliance(
                    domain=domain,
                    score=score,
                    max_score=max_score,
                    issues_count=len(issues),
                    expected_attacks=expected_strategy.attacks,
                    detected_attacks=detected_attack_list,
                    mode="production",
                )
            except Exception as e:
                logger.warning(f"Failed to record compliance metric: {e}")

        return report

    def compare_attacks(self, expected: List[str], detected: DetectedAttacks) -> Dict[str, bool]:
        """
        Compare expected vs detected attacks.

        Args:
            expected: List of expected attack names
            detected: DetectedAttacks object from PCAP analysis

        Returns:
            Dictionary mapping attack name to match status (True if matched)

        Requirements: 3.2, 9.1
        """
        verdicts = {}

        for attack in expected:
            if attack == "fake" or attack == "fakeddisorder":
                verdicts[attack] = detected.fake
            elif attack == "split":
                verdicts[attack] = detected.split and detected.fragment_count == 2
            elif attack == "multisplit":
                verdicts[attack] = detected.split and detected.fragment_count > 2
            elif attack == "disorder" or attack == "disorder_short_ttl_decoy":
                verdicts[attack] = detected.disorder
            else:
                # Unknown attack type
                verdicts[attack] = False
                logger.warning(f"Unknown attack type in expected: {attack}")

        return verdicts

    def calculate_score(
        self, expected_strategy: Strategy, detected: DetectedAttacks, verdicts: Dict[str, bool]
    ) -> tuple[int, int, List[str]]:
        """
        Calculate compliance score.

        Scoring:
        - Each expected attack that is detected: +10 points
        - Each expected attack that is missing: 0 points, issue added
        - Parameter mismatches: -2 points per mismatch, issue added

        Args:
            expected_strategy: Expected strategy
            detected: Detected attacks
            verdicts: Attack match verdicts

        Returns:
            Tuple of (score, max_score, issues)

        Requirements: 9.1, 9.2
        """
        score = 0
        max_score = len(expected_strategy.attacks) * 10
        issues = []

        # Check each expected attack
        for attack in expected_strategy.attacks:
            if verdicts.get(attack, False):
                score += 10
                logger.debug(f"Attack '{attack}' detected: +10 points")
            else:
                issues.append(f"Expected attack '{attack}' not detected in PCAP")
                logger.debug(f"Attack '{attack}' missing: 0 points")

        # Check parameter compliance
        params = expected_strategy.params

        # Check fake parameters
        if "fake" in expected_strategy.attacks or "fakeddisorder" in expected_strategy.attacks:
            if detected.fake:
                # Check TTL
                expected_ttl = params.get("ttl")
                if expected_ttl is not None:
                    if abs(detected.fake_ttl - expected_ttl) > 1:
                        score = max(0, score - 2)
                        issues.append(
                            f"TTL mismatch: expected {expected_ttl}, "
                            f"detected {detected.fake_ttl:.1f}"
                        )

        # Check split parameters
        if "split" in expected_strategy.attacks or "multisplit" in expected_strategy.attacks:
            if detected.split:
                # Check split_count for multisplit
                if "multisplit" in expected_strategy.attacks:
                    expected_count = params.get("split_count", 2)
                    if detected.fragment_count != expected_count:
                        score = max(0, score - 2)
                        issues.append(
                            f"Fragment count mismatch: expected {expected_count}, "
                            f"detected {detected.fragment_count}"
                        )

                # Check split_pos="sni"
                split_pos = params.get("split_pos")
                if split_pos == "sni":
                    if not detected.split_near_sni:
                        score = max(0, score - 2)
                        issues.append("Split position not near SNI as expected")

        # Check disorder parameters
        if "disorder" in expected_strategy.attacks or "fakeddisorder" in expected_strategy.attacks:
            if detected.disorder:
                expected_method = params.get("disorder_method")
                if expected_method:
                    # Map disorder_method to disorder_type
                    if expected_method == "reverse" and detected.disorder_type != "out-of-order":
                        score = max(0, score - 2)
                        issues.append(
                            f"Disorder method mismatch: expected {expected_method}, "
                            f"detected {detected.disorder_type}"
                        )

        return score, max_score, issues

    def generate_patch(self, domain: str, detected: DetectedAttacks) -> Dict[str, Any]:
        """
        Generate JSON patch for domain_rules.json updates.

        Creates a patch that updates the domain rule to match detected attacks.

        Args:
            domain: Domain name
            detected: Detected attacks from PCAP

        Returns:
            Dictionary representing JSON patch

        Requirements: 9.2
        """
        # Build attacks list from detected
        attacks = []
        params = {}

        if detected.fake:
            attacks.append("fake")
            if detected.fake_ttl > 0:
                params["ttl"] = int(detected.fake_ttl)

        if detected.split:
            if detected.fragment_count == 2:
                attacks.append("split")
            elif detected.fragment_count > 2:
                attacks.append("multisplit")
                params["split_count"] = detected.fragment_count

            # Add split_pos if near SNI
            if detected.split_near_sni:
                params["split_pos"] = "sni"
            elif detected.split_positions:
                params["split_pos"] = detected.split_positions[0]

        if detected.disorder:
            attacks.append("disorder")
            if detected.disorder_type == "out-of-order":
                params["disorder_method"] = "reverse"
            elif detected.disorder_type == "overlap":
                params["disorder_method"] = "overlap"

        # Create patch
        patch = {
            "domain": domain,
            "operation": "update",
            "path": f"/domain_rules/{domain}",
            "value": {
                "type": attacks[0] if attacks else "none",
                "attacks": attacks,
                "params": params,
                "metadata": {"auto_generated": True, "source": "compliance_checker"},
            },
        }

        return patch

    def _create_error_report(
        self, domain: str, expected_strategy: Strategy, error_message: str
    ) -> ComplianceReport:
        """Create error report when PCAP analysis fails."""
        return ComplianceReport(
            domain=domain,
            expected_strategy=expected_strategy,
            detected_attacks=DetectedAttacks(),
            score=0,
            max_score=len(expected_strategy.attacks) * 10,
            issues=[error_message],
            verdicts={},
            proposed_patch=None,
        )
