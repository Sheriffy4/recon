"""
PacketValidator - Validates generated packets against attack specifications.

This module provides comprehensive validation of DPI bypass attack packets,
ensuring they match expected behavior for sequence numbers, checksums, TTL,
packet counts, and other critical parameters.
"""

import struct
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Import validation utilities
from core.validation.checksum_utils import calculate_tcp_checksum, validate_tcp_checksum
from core.validation.pcap_parser import PacketData, parse_pcap_file, parse_single_packet
from core.validation.rule_evaluators import (
    evaluate_checksum_rule,
    evaluate_ttl_rule,
    evaluate_seq_rule,
    extract_expected_count,
)

# Import spec loader
try:
    from core.attack_spec_loader import get_spec_loader, AttackSpec, ValidationRule
except ImportError:
    # Fallback for different import paths
    try:
        from recon.core.attack_spec_loader import (
            get_spec_loader,
            AttackSpec,
            ValidationRule,
        )
    except ImportError:
        get_spec_loader = None
        AttackSpec = None
        ValidationRule = None


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationDetail:
    """Details of a specific validation check."""

    aspect: str
    passed: bool
    expected: Any = None
    actual: Any = None
    message: str = ""
    severity: ValidationSeverity = ValidationSeverity.ERROR
    packet_index: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "aspect": self.aspect,
            "passed": self.passed,
            "expected": str(self.expected) if self.expected is not None else None,
            "actual": str(self.actual) if self.actual is not None else None,
            "message": self.message,
            "severity": self.severity.value,
            "packet_index": self.packet_index,
        }


@dataclass
class ValidationResult:
    """Result of packet validation."""

    attack_name: str
    params: Dict[str, Any]
    passed: bool = False
    details: List[ValidationDetail] = field(default_factory=list)
    packet_count: int = 0
    error: Optional[str] = None

    def add_detail(self, detail: ValidationDetail):
        """Add validation detail."""
        self.details.append(detail)
        if not detail.passed and detail.severity in [
            ValidationSeverity.ERROR,
            ValidationSeverity.CRITICAL,
        ]:
            self.passed = False

    def get_critical_issues(self) -> List[ValidationDetail]:
        """Get all critical validation issues."""
        return [
            d for d in self.details if d.severity == ValidationSeverity.CRITICAL and not d.passed
        ]

    def get_errors(self) -> List[ValidationDetail]:
        """Get all error-level issues."""
        return [d for d in self.details if d.severity == ValidationSeverity.ERROR and not d.passed]

    def get_warnings(self) -> List[ValidationDetail]:
        """Get all warnings."""
        return [
            d for d in self.details if d.severity == ValidationSeverity.WARNING and not d.passed
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "attack_name": self.attack_name,
            "params": self.params,
            "passed": self.passed,
            "packet_count": self.packet_count,
            "error": self.error,
            "details": [d.to_dict() for d in self.details],
            "critical_issues": len(self.get_critical_issues()),
            "errors": len(self.get_errors()),
            "warnings": len(self.get_warnings()),
        }


class PacketValidator:
    """
    Validates generated packets against attack specifications.

    This class provides comprehensive validation including:
    - Sequence number validation
    - Checksum validation
    - TTL validation
    - Packet count validation
    - Visual diff generation
    """

    def __init__(self, debug_mode: bool = False):
        """
        Initialize PacketValidator.

        Args:
            debug_mode: Enable debug output
        """
        self.debug_mode = debug_mode
        self.max_packets = 10000
        self.spec_loader = get_spec_loader() if get_spec_loader else None

        # Initialize validators
        from core.validation.sequence_validator import SequenceValidator
        from core.validation.checksum_validator import ChecksumValidator
        from core.validation.ttl_validator import TTLValidator
        from core.validation.packet_count_validator import PacketCountValidator
        from core.validation.attack_validator import AttackValidator
        from core.validation.diff_generator import DiffGenerator
        from core.validation.spec_validator import SpecValidator

        self._sequence_validator = SequenceValidator(ValidationDetail, ValidationSeverity)
        self._checksum_validator = ChecksumValidator(ValidationDetail, ValidationSeverity)
        self._ttl_validator = TTLValidator(ValidationDetail, ValidationSeverity)
        self._packet_count_validator = PacketCountValidator(ValidationDetail, ValidationSeverity)
        self._attack_validator = AttackValidator(ValidationDetail, ValidationSeverity)
        self._diff_generator = DiffGenerator(debug_mode)
        self._spec_validator = SpecValidator(self.spec_loader, ValidationDetail, ValidationSeverity)

    @staticmethod
    def _normalize_params_for_validation(params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runtime often uses slightly different names.
        We normalize for validators/specs without breaking caller interfaces.
        """
        p = dict(params or {})
        if "fooling" not in p and "fooling_methods" in p:
            p["fooling"] = p.get("fooling_methods")
        if "split_pos" not in p and "split_position" in p:
            p["split_pos"] = p.get("split_position")
        return p

    def _apply_fake_classification(
        self, packets: List[PacketData], attack_name: str, params: Dict[str, Any]
    ) -> None:
        """
        Apply params-aware fake/real classification without changing PacketData interface.
        Sets PacketData._fake_override (dynamic attribute) for validators that rely on is_fake_packet().
        """
        # Clear previous overrides (in case packets reused)
        for p in packets:
            if hasattr(p, "_fake_override"):
                try:
                    delattr(p, "_fake_override")
                except Exception:
                    pass

        if attack_name not in ["fake", "fakeddisorder"]:
            return

        autottl = params.get("autottl")
        if isinstance(autottl, (int, float)) and autottl is not None:
            autottl = int(autottl)

        expected_fake_ttl = params.get("fake_ttl", params.get("ttl"))
        payload_packets = [p for p in packets if p.payload_length > 0]
        candidates = payload_packets or packets

        fake_idxs = set()

        # TTL-based classification (primary)
        if expected_fake_ttl is not None:
            # Prefer payload packets with exact fake TTL
            ttl_matches = [p for p in candidates if p.ttl == expected_fake_ttl]
            if ttl_matches:
                # choose the earliest in send order to avoid "multiple fake" misclassifications
                first = min(ttl_matches, key=lambda p: p.index)
                fake_idxs.add(first.index)

        # autottl: if requested, pick the smallest ttl within [1..autottl] if nothing else chosen
        if not fake_idxs and autottl:
            within = [p for p in candidates if 1 <= p.ttl <= autottl]
            if within:
                chosen = min(within, key=lambda p: (p.ttl, p.index))
                fake_idxs.add(chosen.index)

        # Fallback heuristic if ttl param missing or not found
        if not fake_idxs:
            low = [p for p in candidates if p.ttl <= 3]
            if low:
                chosen = min(low, key=lambda p: p.index)
                fake_idxs.add(chosen.index)

        # If badsum fooling enabled, allow checksum-invalid packets as fake,
        # but keep a TTL guard to reduce offload/capture false positives.
        fooling = params.get("fooling", [])
        has_badsum = ("badsum" in fooling) if isinstance(fooling, list) else (fooling == "badsum")
        if has_badsum:
            for p in candidates:
                # only promote to fake if we don't already have one, or if it's the same one
                if fake_idxs and p.index not in fake_idxs:
                    continue
                if (not p.checksum_valid) and (
                    p.ttl <= 10 or (expected_fake_ttl is not None and p.ttl == expected_fake_ttl)
                ):
                    fake_idxs.add(p.index)

        for p in packets:
            p._fake_override = p.index in fake_idxs

    def validate_attack(
        self, attack_name: str, params: Dict[str, Any], pcap_file: str
    ) -> ValidationResult:
        """
        Validate that attack generated correct packets.

        Args:
            attack_name: Name of attack (e.g., 'fake', 'split', 'fakeddisorder')
            params: Attack parameters
            pcap_file: Path to PCAP file

        Returns:
            ValidationResult with pass/fail and details
        """
        result = ValidationResult(
            attack_name=attack_name,
            params=params,
            passed=True,  # Assume pass until proven otherwise
        )

        try:
            # Parse PCAP file
            packets = self.parse_pcap(pcap_file)
            result.packet_count = len(packets)

            if not packets:
                result.passed = False
                result.error = "No packets found in PCAP file"
                return result

            # Apply params-aware fake classification before any validators rely on it
            self._apply_fake_classification(packets, attack_name, params)

            # Validate based on attack type
            if attack_name in ["fake", "fakeddisorder"]:
                self._validate_fake_attack(packets, params, result)

            if attack_name in ["split", "fakeddisorder", "disorder"]:
                self._validate_split_attack(packets, params, result)

            if attack_name in ["fakeddisorder", "disorder", "multidisorder"]:
                self._validate_disorder_attack(packets, params, result)

            # Common validations for all attacks
            self._validate_sequence_numbers(packets, params, result)
            self._validate_checksums(packets, params, result)
            self._validate_ttl(packets, params, result)
            self._validate_packet_count(packets, params, result)

        except (FileNotFoundError, OSError) as e:
            result.passed = False
            result.error = f"PCAP file error: {str(e)}"
            if self.debug_mode:
                import traceback

                result.error += f"\n{traceback.format_exc()}"
        except (struct.error, ValueError) as e:
            result.passed = False
            result.error = f"Packet parsing error: {str(e)}"
            if self.debug_mode:
                import traceback

                result.error += f"\n{traceback.format_exc()}"
        except Exception as e:
            result.passed = False
            result.error = f"Validation failed: {str(e)}"
            if self.debug_mode:
                import traceback

                result.error += f"\n{traceback.format_exc()}"

        return result

    def validate_attack_with_spec(
        self, attack_name: str, params: Dict[str, Any], pcap_file: str
    ) -> ValidationResult:
        """
        Validate attack using YAML specification.

        Args:
            attack_name: Name of attack
            params: Attack parameters
            pcap_file: Path to PCAP file

        Returns:
            ValidationResult with spec-based validation
        """
        result = ValidationResult(attack_name=attack_name, params=params, passed=True)

        try:
            # Parse PCAP file
            packets = self.parse_pcap(pcap_file)
            result.packet_count = len(packets)

            if not packets:
                result.passed = False
                result.error = "No packets found in PCAP file"
                return result

            # Keep fake classification consistent for spec rules too
            self._apply_fake_classification(packets, attack_name, params)

            # Validate using spec
            self._spec_validator.validate_with_spec(attack_name, params, packets, result)

        except (FileNotFoundError, OSError) as e:
            result.passed = False
            result.error = f"PCAP file error: {str(e)}"
            if self.debug_mode:
                import traceback

                result.error += f"\n{traceback.format_exc()}"
        except (struct.error, ValueError) as e:
            result.passed = False
            result.error = f"Packet parsing error: {str(e)}"
            if self.debug_mode:
                import traceback

                result.error += f"\n{traceback.format_exc()}"
        except Exception as e:
            result.passed = False
            result.error = f"Spec-based validation failed: {str(e)}"
            if self.debug_mode:
                import traceback

                result.error += f"\n{traceback.format_exc()}"

        return result

    def validate_raw_packets_with_spec(
        self,
        attack_name: str,
        params: Dict[str, Any],
        raw_packets: List[bytes],
    ) -> ValidationResult:
        """
        Validate already-built raw packets (IP/TCP bytes) using YAML spec.
        This enables "pre-send" validation without PCAP capture.

        Args:
            attack_name: Name of attack
            params: Attack parameters (runtime may contain fooling_methods etc)
            raw_packets: List of raw packets bytes (WinDivert-style IP packets)
        """
        from core.validation.pcap_parser import parse_network_packet

        params_n = self._normalize_params_for_validation(params)
        result = ValidationResult(attack_name=attack_name, params=params_n, passed=True)

        packets: List[PacketData] = []
        import time

        t0 = time.time()
        for i, b in enumerate(raw_packets or []):
            pkt = parse_network_packet(b, i, t0 + (i * 1e-6), debug=self.debug_mode)
            if pkt:
                packets.append(pkt)

        result.packet_count = len(packets)
        if not packets:
            result.passed = False
            result.error = "No packets could be parsed from raw bytes"
            return result

        self._apply_fake_classification(packets, attack_name, params_n)
        self._spec_validator.validate_with_spec(attack_name, params_n, packets, result)
        return result

    def validate_raw_packets(
        self,
        attack_name: str,
        params: Dict[str, Any],
        raw_packets: List[bytes],
    ) -> ValidationResult:
        """
        Validate already-built raw packets (IP/TCP bytes) with built-in validators
        (sequence/checksum/ttl/count) without YAML.
        """
        from core.validation.pcap_parser import parse_network_packet

        params_n = self._normalize_params_for_validation(params)
        result = ValidationResult(attack_name=attack_name, params=params_n, passed=True)

        packets: List[PacketData] = []
        import time

        t0 = time.time()
        for i, b in enumerate(raw_packets or []):
            pkt = parse_network_packet(b, i, t0 + (i * 1e-6), debug=self.debug_mode)
            if pkt:
                packets.append(pkt)

        result.packet_count = len(packets)
        if not packets:
            result.passed = False
            result.error = "No packets could be parsed from raw bytes"
            return result

        self._apply_fake_classification(packets, attack_name, params_n)
        # Reuse existing validation pipeline
        if attack_name in ["fake", "fakeddisorder"]:
            self._validate_fake_attack(packets, params_n, result)
        if attack_name in ["split", "fakeddisorder", "disorder"]:
            self._validate_split_attack(packets, params_n, result)
        if attack_name in ["fakeddisorder", "disorder", "multidisorder"]:
            self._validate_disorder_attack(packets, params_n, result)

        self._validate_sequence_numbers(packets, params_n, result)
        self._validate_checksums(packets, params_n, result)
        self._validate_ttl(packets, params_n, result)
        self._validate_packet_count(packets, params_n, result)

        return result

    def _apply_spec_validation_rules(
        self,
        spec: "AttackSpec",
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """
        Apply validation rules from spec to packets (delegated to spec_validator).

        Args:
            spec: Attack specification
            packets: Parsed packets
            params: Attack parameters
            result: ValidationResult to update
        """
        self._spec_validator.apply_spec_validation_rules(spec, packets, params, result)

    def _evaluate_validation_rule(
        self,
        rule: "ValidationRule",
        packets: List[PacketData],
        params: Dict[str, Any],
        spec: "AttackSpec",
    ) -> bool:
        """
        Evaluate a single validation rule (delegated to spec_validator).

        Args:
            rule: Validation rule to evaluate
            packets: Parsed packets
            params: Attack parameters
            spec: Attack specification

        Returns:
            True if rule passes, False otherwise
        """
        return self._spec_validator._evaluate_validation_rule(rule, packets, params, spec)

    def _extract_expected_count(
        self, rule_str: str, params: Dict[str, Any], spec: "AttackSpec"
    ) -> int:
        """Extract expected packet count from spec (delegated to rule_evaluators)."""
        return extract_expected_count(rule_str, params, spec)

    def _evaluate_checksum_rule(
        self, rule_str: str, packets: List[PacketData], params: Dict[str, Any]
    ) -> bool:
        """Evaluate checksum validation rule (delegated to rule_evaluators)."""
        return evaluate_checksum_rule(rule_str, packets)

    def _evaluate_ttl_rule(
        self, rule_str: str, packets: List[PacketData], params: Dict[str, Any]
    ) -> bool:
        """Evaluate TTL validation rule (delegated to rule_evaluators)."""
        return evaluate_ttl_rule(rule_str, packets, params)

    def _evaluate_seq_rule(
        self, rule_str: str, packets: List[PacketData], params: Dict[str, Any]
    ) -> bool:
        """Evaluate sequence number validation rule (delegated to rule_evaluators)."""
        return evaluate_seq_rule(rule_str, packets)

    def parse_pcap(self, pcap_file: str) -> List[PacketData]:
        """
        Parse PCAP file and extract packet data (delegated to pcap_parser).

        Args:
            pcap_file: Path to PCAP file

        Returns:
            List of PacketData objects
        """
        return parse_pcap_file(pcap_file, self.max_packets, self.debug_mode)

    def _parse_packet(self, raw_data: bytes, index: int, timestamp: float) -> Optional[PacketData]:
        """
        Parse raw packet data into PacketData object (delegated to pcap_parser).

        Args:
            raw_data: Raw packet bytes
            index: Packet index in sequence
            timestamp: Packet timestamp

        Returns:
            PacketData object or None if parsing fails
        """
        return parse_single_packet(raw_data, index, timestamp, self.debug_mode)

    def _validate_tcp_checksum(self, ip_header: bytes, tcp_header: bytes, payload: bytes) -> bool:
        """
        Validate TCP checksum (delegated to checksum_utils).

        Args:
            ip_header: IP header bytes
            tcp_header: TCP header bytes
            payload: TCP payload bytes

        Returns:
            True if checksum is valid
        """
        return validate_tcp_checksum(ip_header, tcp_header, payload)

    def _calculate_checksum(self, data: bytes) -> int:
        """
        Calculate Internet checksum (delegated to checksum_utils).

        Args:
            data: Data to checksum

        Returns:
            Checksum value
        """
        return calculate_tcp_checksum(data)

    def _validate_sequence_numbers(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """
        Validate sequence numbers (delegated to sequence_validator).

        Args:
            packets: List of parsed packets
            params: Attack parameters
            result: ValidationResult to update
        """
        self._sequence_validator.validate_sequence_numbers(
            packets, params, result, result.attack_name
        )

    def _validate_fakeddisorder_sequence(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate fakeddisorder sequence (delegated to sequence_validator)."""
        self._sequence_validator.validate_fakeddisorder_sequence(packets, params, result)

    def _validate_split_sequence(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate split sequence (delegated to sequence_validator)."""
        self._sequence_validator.validate_split_sequence(packets, result)

    def _validate_generic_sequence(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate generic sequence (delegated to sequence_validator)."""
        self._sequence_validator.validate_generic_sequence(packets, result)

    def _validate_overlap(
        self, packets: List[PacketData], overlap_size: int, result: ValidationResult
    ):
        """Validate overlap (delegated to sequence_validator)."""
        self._sequence_validator.validate_overlap(packets, overlap_size, result)

    def _validate_checksums(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate checksums (delegated to checksum_validator)."""
        self._checksum_validator.validate_checksums(packets, params, result)

    def _validate_all_good_checksums(self, packets: List[PacketData], result: ValidationResult):
        """Validate all good checksums (delegated to checksum_validator)."""
        self._checksum_validator.validate_all_good_checksums(packets, result)

    def _detect_windivert_recalculation(self, packets: List[PacketData], result: ValidationResult):
        """Detect WinDivert recalculation (delegated to checksum_validator)."""
        self._checksum_validator.detect_windivert_recalculation(packets, result)

    def _validate_ttl(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate TTL values (delegated to ttl_validator)."""
        self._ttl_validator.validate_ttl(packets, params, result, result.attack_name)

    def _validate_fake_attack_ttl(
        self,
        packets: List[PacketData],
        expected_fake_ttl: Optional[int],
        result: ValidationResult,
    ):
        """Validate fake attack TTL (delegated to ttl_validator)."""
        self._ttl_validator.validate_fake_attack_ttl(packets, expected_fake_ttl, result)

    def _validate_generic_ttl(self, packets: List[PacketData], result: ValidationResult):
        """Validate generic TTL (delegated to ttl_validator)."""
        self._ttl_validator.validate_generic_ttl(packets, result)

    def _validate_packet_count(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate packet count (delegated to packet_count_validator)."""
        self._packet_count_validator.validate_packet_count(
            packets, params, result, result.attack_name
        )
        # Also validate order and sizes
        self._packet_count_validator.validate_packet_order(packets, result.attack_name, result)
        self._packet_count_validator.validate_packet_sizes(packets, params, result)

    def _get_expected_packet_count(
        self, attack_name: str, params: Dict[str, Any]
    ) -> Optional[int | Tuple[int, int]]:
        """Get expected packet count (delegated to packet_count_validator)."""
        return self._packet_count_validator.get_expected_packet_count(attack_name, params)

    def _validate_packet_order(
        self, packets: List[PacketData], attack_name: str, result: ValidationResult
    ):
        """Validate packet order (delegated to packet_count_validator)."""
        self._packet_count_validator.validate_packet_order(packets, attack_name, result)

    def _validate_packet_sizes(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate packet sizes (delegated to packet_count_validator)."""
        self._packet_count_validator.validate_packet_sizes(packets, params, result)

    def _validate_fake_attack(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate fake attack specific requirements (delegated to attack_validator)."""
        self._attack_validator.validate_fake_attack(packets, result)

    def _validate_split_attack(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate split attack specific requirements (delegated to attack_validator)."""
        split_pos = params.get("split_pos")
        self._attack_validator.validate_split_attack(packets, split_pos, result)

    def _validate_disorder_attack(
        self,
        packets: List[PacketData],
        params: Dict[str, Any],
        result: ValidationResult,
    ):
        """Validate disorder attack specific requirements (delegated to attack_validator)."""
        self._attack_validator.validate_disorder_attack(packets, result)

    def generate_visual_diff(
        self,
        expected_packets: List[Dict[str, Any]],
        actual_packets: List[PacketData],
        output_format: str = "text",
    ) -> str:
        """
        Generate visual diff between expected and actual packets (delegated to diff_generator).

        Args:
            expected_packets: List of expected packet specifications
            actual_packets: List of actual parsed packets
            output_format: Output format ('text' or 'html')

        Returns:
            Visual diff as string
        """
        return self._diff_generator.generate_visual_diff(
            expected_packets, actual_packets, output_format
        )

    def _generate_text_diff(
        self, expected_packets: List[Dict[str, Any]], actual_packets: List[PacketData]
    ) -> str:
        """Generate text-based visual diff (delegated to diff_generator)."""
        return self._diff_generator.generate_text_diff(expected_packets, actual_packets)

    def _generate_html_diff(
        self, expected_packets: List[Dict[str, Any]], actual_packets: List[PacketData]
    ) -> str:
        """Generate HTML-based visual diff (delegated to diff_generator)."""
        return self._diff_generator.generate_html_diff(expected_packets, actual_packets)

    def export_diff(self, diff: str, output_file: str):
        """
        Export visual diff to file (delegated to diff_generator).

        Args:
            diff: Visual diff string
            output_file: Output file path
        """
        self._diff_generator.export_diff(diff, output_file)


# Convenience functions for common use cases


def validate_pcap(
    attack_name: str, params: Dict[str, Any], pcap_file: str, debug: bool = False
) -> ValidationResult:
    """
    Convenience function to validate a PCAP file.

    Args:
        attack_name: Name of attack
        params: Attack parameters
        pcap_file: Path to PCAP file
        debug: Enable debug mode

    Returns:
        ValidationResult
    """
    validator = PacketValidator(debug_mode=debug)
    return validator.validate_attack(attack_name, params, pcap_file)


def generate_diff_report(
    expected: List[Dict[str, Any]],
    actual: List[PacketData],
    output_file: str,
    format: str = "html",
) -> str:
    """
    Generate and export diff report.

    Args:
        expected: Expected packet specifications
        actual: Actual parsed packets
        output_file: Output file path
        format: Output format ('text' or 'html')

    Returns:
        Diff string
    """
    validator = PacketValidator()
    diff = validator.generate_visual_diff(expected, actual, format)
    validator.export_diff(diff, output_file)
    return diff
