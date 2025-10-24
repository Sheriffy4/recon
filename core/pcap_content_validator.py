"""
PCAP Content Validator

This module provides comprehensive validation of PCAP file contents,
including packet count, sequence numbers, checksums, TTL values, and TCP flags.

Part of the Attack Validation Production Readiness suite.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import logging

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.packet import Packet

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    TCP = IP = Raw = Packet = None


logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    """Represents a validation issue found in PCAP."""

    severity: str  # 'error', 'warning', 'info'
    category: str  # 'packet_count', 'sequence', 'checksum', 'ttl', 'flags'
    packet_index: int
    description: str
    expected: Any
    actual: Any

    def __str__(self) -> str:
        return (
            f"[{self.severity.upper()}] {self.category} at packet {self.packet_index}: "
            f"{self.description} (expected: {self.expected}, actual: {self.actual})"
        )


@dataclass
class PCAPValidationResult:
    """Result of PCAP validation."""

    passed: bool
    pcap_file: Path
    packet_count: int
    expected_packet_count: Optional[int] = None
    issues: List[ValidationIssue] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def add_issue(self, issue: ValidationIssue):
        """Add a validation issue."""
        self.issues.append(issue)
        if issue.severity == "error":
            self.passed = False

    def add_warning(self, warning: str):
        """Add a warning."""
        self.warnings.append(warning)

    def get_summary(self) -> str:
        """Get a summary of validation results."""
        errors = [i for i in self.issues if i.severity == "error"]
        warnings_issues = [i for i in self.issues if i.severity == "warning"]

        summary = f"PCAP Validation: {'PASSED' if self.passed else 'FAILED'}\n"
        summary += f"File: {self.pcap_file}\n"
        summary += f"Packets: {self.packet_count}"
        if self.expected_packet_count:
            summary += f" (expected: {self.expected_packet_count})"
        summary += f"\nErrors: {len(errors)}, Warnings: {len(warnings_issues)}\n"

        if errors:
            summary += "\nErrors:\n"
            for err in errors[:5]:  # Show first 5 errors
                summary += f"  - {err}\n"
            if len(errors) > 5:
                summary += f"  ... and {len(errors) - 5} more errors\n"

        return summary


class PCAPContentValidator:
    """
    Validates PCAP file contents against expected packet structure.

    Performs validation of:
    - Packet count
    - TCP sequence numbers
    - Checksums (good/bad as expected)
    - TTL values
    - TCP flags
    """

    def __init__(self):
        """Initialize the PCAP content validator."""
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "Scapy is required for PCAP validation. Install with: pip install scapy"
            )

        self.logger = logging.getLogger(__name__)

    def validate_pcap(
        self, pcap_file: Path, attack_spec: Optional[Dict[str, Any]] = None
    ) -> PCAPValidationResult:
        """
        Validate a PCAP file against expected specifications.

        Args:
            pcap_file: Path to PCAP file
            attack_spec: Optional attack specification with expected values
                {
                    'expected_packet_count': int,
                    'expected_bad_checksums': bool,
                    'expected_ttl': int,
                    'expected_flags': List[str],
                    'validate_sequence': bool
                }

        Returns:
            PCAPValidationResult with validation results
        """
        pcap_file = Path(pcap_file)

        if not pcap_file.exists():
            result = PCAPValidationResult(
                passed=False, pcap_file=pcap_file, packet_count=0
            )
            result.add_issue(
                ValidationIssue(
                    severity="error",
                    category="file",
                    packet_index=-1,
                    description="PCAP file does not exist",
                    expected="file exists",
                    actual="file not found",
                )
            )
            return result

        # Load packets
        try:
            packets = rdpcap(str(pcap_file))
        except Exception as e:
            result = PCAPValidationResult(
                passed=False, pcap_file=pcap_file, packet_count=0
            )
            result.add_issue(
                ValidationIssue(
                    severity="error",
                    category="file",
                    packet_index=-1,
                    description=f"Failed to read PCAP file: {e}",
                    expected="valid PCAP",
                    actual="read error",
                )
            )
            return result

        # Initialize result
        attack_spec = attack_spec or {}
        result = PCAPValidationResult(
            passed=True,
            pcap_file=pcap_file,
            packet_count=len(packets),
            expected_packet_count=attack_spec.get("expected_packet_count"),
        )

        # Run validations
        self._validate_packet_count(packets, result, attack_spec)

        if attack_spec.get("validate_sequence", True):
            self._validate_sequence_numbers(packets, result)

        if "expected_bad_checksums" in attack_spec:
            self._validate_checksums(packets, result, attack_spec)

        if "expected_ttl" in attack_spec:
            self._validate_ttl(packets, result, attack_spec)

        if "expected_flags" in attack_spec or attack_spec.get(
            "validate_flag_combinations"
        ):
            self._validate_tcp_flags(packets, result, attack_spec)

        # Add packet details
        result.details["tcp_packets"] = sum(1 for p in packets if TCP in p)
        result.details["ip_packets"] = sum(1 for p in packets if IP in p)

        self.logger.info(f"Validation complete: {result.get_summary()}")

        return result

    def _validate_packet_count(
        self,
        packets: List[Packet],
        result: PCAPValidationResult,
        attack_spec: Dict[str, Any],
    ):
        """
        Validate packet count matches expected count.

        Implements subtask 2.1: Implement packet count validation
        """
        expected_count = attack_spec.get("expected_packet_count")

        if expected_count is None:
            result.add_warning(
                "No expected packet count specified, skipping validation"
            )
            return

        actual_count = len(packets)

        if actual_count != expected_count:
            result.add_issue(
                ValidationIssue(
                    severity="error",
                    category="packet_count",
                    packet_index=-1,
                    description="Packet count mismatch",
                    expected=expected_count,
                    actual=actual_count,
                )
            )
        else:
            self.logger.debug(f"Packet count validation passed: {actual_count} packets")

    def _validate_sequence_numbers(
        self, packets: List[Packet], result: PCAPValidationResult
    ):
        """
        Validate TCP sequence number progression.

        Implements subtask 2.2: Implement sequence number validation
        """
        tcp_packets = [p for p in packets if TCP in p and IP in p]

        if not tcp_packets:
            result.add_warning("No TCP packets found for sequence validation")
            return

        # Group packets by connection (src_ip, dst_ip, src_port, dst_port)
        connections: Dict[Tuple, List[Tuple[int, Packet]]] = {}

        for idx, pkt in enumerate(tcp_packets):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            conn_key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)

            if conn_key not in connections:
                connections[conn_key] = []

            connections[conn_key].append((idx, pkt))

        # Validate sequence progression for each connection
        for conn_key, conn_packets in connections.items():
            self._validate_connection_sequences(conn_packets, result)

    def _validate_connection_sequences(
        self, conn_packets: List[Tuple[int, Packet]], result: PCAPValidationResult
    ):
        """Validate sequence numbers for a single connection."""
        if len(conn_packets) < 2:
            return

        prev_seq = None
        prev_idx = None

        for idx, pkt in conn_packets:
            tcp_layer = pkt[TCP]
            current_seq = tcp_layer.seq

            # Check for sequence number anomalies
            if prev_seq is not None:
                # Allow for retransmissions and out-of-order packets
                # Flag only if sequence goes backwards significantly
                if current_seq < prev_seq - 100000:  # Likely wrapped around
                    result.add_issue(
                        ValidationIssue(
                            severity="warning",
                            category="sequence",
                            packet_index=idx,
                            description="Sequence number wrapped around",
                            expected=f"seq >= {prev_seq}",
                            actual=current_seq,
                        )
                    )
                elif current_seq == prev_seq and len(pkt[TCP].payload) > 0:
                    # Retransmission
                    result.add_issue(
                        ValidationIssue(
                            severity="info",
                            category="sequence",
                            packet_index=idx,
                            description="Possible retransmission detected",
                            expected="new sequence",
                            actual=current_seq,
                        )
                    )

            prev_seq = current_seq
            prev_idx = idx

    def _validate_checksums(
        self,
        packets: List[Packet],
        result: PCAPValidationResult,
        attack_spec: Dict[str, Any],
    ):
        """
        Validate packet checksums (good/bad as expected).

        Implements subtask 2.3: Implement checksum validation

        This method:
        - Extracts packet checksums from TCP and IP layers
        - Validates good/bad checksums as expected
        - Detects checksum anomalies (zero checksums, incorrect checksums)
        - Reports issues with detailed information
        """
        expected_bad = attack_spec.get("expected_bad_checksums", False)

        tcp_packets = [
            (idx, p) for idx, p in enumerate(packets) if TCP in p and IP in p
        ]

        if not tcp_packets:
            result.add_warning("No TCP packets found for checksum validation")
            return

        bad_tcp_checksum_count = 0
        bad_ip_checksum_count = 0
        zero_tcp_checksums = []
        zero_ip_checksums = []
        invalid_tcp_checksums = []
        invalid_ip_checksums = []

        for idx, pkt in tcp_packets:
            tcp_layer = pkt[TCP]
            ip_layer = pkt[IP]

            # Extract checksums
            tcp_chksum = tcp_layer.chksum
            ip_chksum = ip_layer.chksum

            # Check for zero checksums (explicitly bad)
            if tcp_chksum == 0:
                bad_tcp_checksum_count += 1
                zero_tcp_checksums.append(idx)

                if not expected_bad:
                    result.add_issue(
                        ValidationIssue(
                            severity="warning",
                            category="checksum",
                            packet_index=idx,
                            description="TCP checksum is zero (bad checksum)",
                            expected="valid checksum",
                            actual="0x0000",
                        )
                    )

            if ip_chksum == 0:
                bad_ip_checksum_count += 1
                zero_ip_checksums.append(idx)

                if not expected_bad:
                    result.add_issue(
                        ValidationIssue(
                            severity="warning",
                            category="checksum",
                            packet_index=idx,
                            description="IP checksum is zero (bad checksum)",
                            expected="valid checksum",
                            actual="0x0000",
                        )
                    )

            # Verify checksum correctness by recalculating
            # Note: Scapy automatically recalculates checksums when building packets
            # We can detect incorrect checksums by comparing with recalculated values
            # Only do this if checksums are not zero (zero means intentionally bad)
            if tcp_chksum != 0 or ip_chksum != 0:
                try:
                    # Create a copy of the packet for recalculation
                    pkt_copy = pkt.copy()

                    # Delete checksums to force recalculation
                    if hasattr(pkt_copy[IP], "chksum"):
                        del pkt_copy[IP].chksum
                    if hasattr(pkt_copy[TCP], "chksum"):
                        del pkt_copy[TCP].chksum

                    # Recalculate by rebuilding the packet
                    pkt_copy = pkt_copy.__class__(bytes(pkt_copy))

                    recalc_tcp_chksum = (
                        pkt_copy[TCP].chksum if hasattr(pkt_copy[TCP], "chksum") else 0
                    )
                    recalc_ip_chksum = (
                        pkt_copy[IP].chksum if hasattr(pkt_copy[IP], "chksum") else 0
                    )

                    # Compare with original (if not zero)
                    if tcp_chksum != 0 and tcp_chksum != recalc_tcp_chksum:
                        invalid_tcp_checksums.append(
                            (idx, tcp_chksum, recalc_tcp_chksum)
                        )

                        result.add_issue(
                            ValidationIssue(
                                severity="info",
                                category="checksum",
                                packet_index=idx,
                                description="TCP checksum mismatch (possibly intentional)",
                                expected=f"0x{recalc_tcp_chksum:04x}",
                                actual=f"0x{tcp_chksum:04x}",
                            )
                        )

                    if ip_chksum != 0 and ip_chksum != recalc_ip_chksum:
                        invalid_ip_checksums.append((idx, ip_chksum, recalc_ip_chksum))

                        result.add_issue(
                            ValidationIssue(
                                severity="info",
                                category="checksum",
                                packet_index=idx,
                                description="IP checksum mismatch (possibly intentional)",
                                expected=f"0x{recalc_ip_chksum:04x}",
                                actual=f"0x{ip_chksum:04x}",
                            )
                        )

                except Exception as e:
                    # If recalculation fails, log but don't fail validation
                    self.logger.debug(
                        f"Could not recalculate checksum for packet {idx}: {e}"
                    )

        # Check if we expected bad checksums but didn't find any
        if expected_bad and bad_tcp_checksum_count == 0 and bad_ip_checksum_count == 0:
            result.add_issue(
                ValidationIssue(
                    severity="error",
                    category="checksum",
                    packet_index=-1,
                    description="Expected bad checksums but all checksums are valid",
                    expected="some bad checksums",
                    actual="all valid checksums",
                )
            )

        # Check if we found bad checksums when we didn't expect them
        if not expected_bad and (
            bad_tcp_checksum_count > 0 or bad_ip_checksum_count > 0
        ):
            result.add_issue(
                ValidationIssue(
                    severity="warning",
                    category="checksum",
                    packet_index=-1,
                    description=f"Found {bad_tcp_checksum_count} bad TCP and {bad_ip_checksum_count} bad IP checksums",
                    expected="all valid checksums",
                    actual=f"{bad_tcp_checksum_count} bad TCP, {bad_ip_checksum_count} bad IP",
                )
            )

        # Store detailed checksum information
        result.details["bad_tcp_checksum_count"] = bad_tcp_checksum_count
        result.details["bad_ip_checksum_count"] = bad_ip_checksum_count
        result.details["total_tcp_packets"] = len(tcp_packets)
        result.details["zero_tcp_checksums"] = zero_tcp_checksums
        result.details["zero_ip_checksums"] = zero_ip_checksums
        result.details["invalid_tcp_checksums"] = len(invalid_tcp_checksums)
        result.details["invalid_ip_checksums"] = len(invalid_ip_checksums)

        self.logger.debug(
            f"Checksum validation: {bad_tcp_checksum_count} bad TCP, "
            f"{bad_ip_checksum_count} bad IP out of {len(tcp_packets)} packets"
        )

    def _validate_ttl(
        self,
        packets: List[Packet],
        result: PCAPValidationResult,
        attack_spec: Dict[str, Any],
    ):
        """
        Validate TTL values match expected values.

        Implements subtask 2.4: Implement TTL validation
        """
        expected_ttl = attack_spec.get("expected_ttl")

        if expected_ttl is None:
            result.add_warning("No expected TTL specified, skipping validation")
            return

        ip_packets = [p for p in packets if IP in p]

        if not ip_packets:
            result.add_warning("No IP packets found for TTL validation")
            return

        ttl_mismatches = []

        for idx, pkt in enumerate(ip_packets):
            ip_layer = pkt[IP]
            actual_ttl = ip_layer.ttl

            if actual_ttl != expected_ttl:
                ttl_mismatches.append((idx, actual_ttl))

                result.add_issue(
                    ValidationIssue(
                        severity="warning",
                        category="ttl",
                        packet_index=idx,
                        description="TTL value mismatch",
                        expected=expected_ttl,
                        actual=actual_ttl,
                    )
                )

        result.details["ttl_mismatches"] = len(ttl_mismatches)
        result.details["expected_ttl"] = expected_ttl

    def _validate_tcp_flags(
        self,
        packets: List[Packet],
        result: PCAPValidationResult,
        attack_spec: Dict[str, Any],
    ):
        """
        Validate TCP flags are set correctly.

        Implements subtask 2.5: Implement TCP flags validation

        This method:
        - Extracts TCP flags from all TCP packets
        - Validates flag combinations (e.g., SYN+ACK, FIN+ACK)
        - Detects flag anomalies (invalid combinations, unexpected flags)
        - Reports issues with detailed information
        """
        expected_flags = attack_spec.get("expected_flags", [])
        validate_combinations = attack_spec.get("validate_flag_combinations", True)

        tcp_packets = [(idx, p) for idx, p in enumerate(packets) if TCP in p]

        if not tcp_packets:
            result.add_warning("No TCP packets found for flags validation")
            return

        # TCP flag definitions
        flag_map = {
            "F": "FIN",
            "S": "SYN",
            "R": "RST",
            "P": "PSH",
            "A": "ACK",
            "U": "URG",
            "E": "ECE",
            "C": "CWR",
            "N": "NS",  # ECN-nonce concealment protection
        }

        # Track flag statistics
        flag_counts = {flag: 0 for flag in flag_map.values()}
        flag_combinations = {}
        invalid_combinations = []

        for idx, pkt in tcp_packets:
            tcp_layer = pkt[TCP]

            # Get flags as string (e.g., "SA" for SYN+ACK)
            flags_str = str(tcp_layer.flags)

            # Count individual flags
            for flag_letter, flag_name in flag_map.items():
                if flag_letter in flags_str:
                    flag_counts[flag_name] += 1

            # Track flag combinations
            if flags_str not in flag_combinations:
                flag_combinations[flags_str] = []
            flag_combinations[flags_str].append(idx)

            # Validate expected flags if specified
            if expected_flags:
                for expected_flag in expected_flags:
                    flag_letter = expected_flag[0].upper()

                    if flag_letter not in flags_str:
                        result.add_issue(
                            ValidationIssue(
                                severity="warning",
                                category="flags",
                                packet_index=idx,
                                description=f"Expected flag {flag_map.get(flag_letter, flag_letter)} not found",
                                expected=expected_flag,
                                actual=flags_str,
                            )
                        )

            # Validate flag combinations for anomalies
            if validate_combinations:
                anomaly = self._check_flag_anomalies(flags_str, idx)
                if anomaly:
                    invalid_combinations.append((idx, flags_str, anomaly))
                    result.add_issue(
                        ValidationIssue(
                            severity="warning",
                            category="flags",
                            packet_index=idx,
                            description=f"Flag anomaly detected: {anomaly}",
                            expected="valid flag combination",
                            actual=flags_str,
                        )
                    )

        # Store detailed flag information
        result.details["tcp_packet_count"] = len(tcp_packets)
        result.details["flag_counts"] = flag_counts
        result.details["flag_combinations"] = {
            combo: len(indices) for combo, indices in flag_combinations.items()
        }
        result.details["invalid_flag_combinations"] = len(invalid_combinations)

        # Log summary
        self.logger.debug(
            f"TCP flags validation: {len(tcp_packets)} packets, "
            f"{len(flag_combinations)} unique combinations, "
            f"{len(invalid_combinations)} anomalies"
        )

    def _check_flag_anomalies(self, flags_str: str, packet_idx: int) -> Optional[str]:
        """
        Check for TCP flag anomalies and invalid combinations.

        Returns:
            Description of anomaly if found, None otherwise
        """
        # Invalid flag combinations that should be flagged

        # 1. SYN+FIN combination (Christmas tree attack indicator)
        if "S" in flags_str and "F" in flags_str:
            return "SYN+FIN combination (invalid, possible attack)"

        # 2. SYN+RST combination (invalid)
        if "S" in flags_str and "R" in flags_str:
            return "SYN+RST combination (invalid)"

        # 3. FIN+RST combination (unusual)
        if "F" in flags_str and "R" in flags_str:
            return "FIN+RST combination (unusual)"

        # 4. No flags set (NULL scan)
        if not flags_str or flags_str == "":
            return "No flags set (NULL scan indicator)"

        # 5. All flags set (XMAS scan)
        if all(flag in flags_str for flag in ["F", "S", "R", "P", "A", "U"]):
            return "All flags set (XMAS scan indicator)"

        # 6. FIN without ACK (unusual in normal traffic)
        if "F" in flags_str and "A" not in flags_str:
            return "FIN without ACK (unusual)"

        # 7. RST with other flags besides ACK (unusual)
        if "R" in flags_str and len(flags_str) > 2:
            # RST+ACK is valid, but RST with other flags is unusual
            if not (len(flags_str) == 2 and "A" in flags_str):
                return "RST with unexpected additional flags"

        # 8. URG flag without urgent pointer (would need to check tcp.urgptr)
        # This is a more advanced check that could be added

        return None
        return None

    def validate_attack_pcap(
        self,
        pcap_file: Path,
        attack_name: str,
        attack_params: Optional[Dict[str, Any]] = None,
    ) -> PCAPValidationResult:
        """
        Validate PCAP for a specific attack type.

        Args:
            pcap_file: Path to PCAP file
            attack_name: Name of the attack
            attack_params: Parameters used for the attack

        Returns:
            PCAPValidationResult
        """
        # Build attack spec based on attack type
        attack_spec = self._build_attack_spec(attack_name, attack_params or {})

        return self.validate_pcap(pcap_file, attack_spec)

    def _build_attack_spec(
        self, attack_name: str, attack_params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build attack specification for validation."""
        spec: Dict[str, Any] = {"validate_sequence": True}

        # Attack-specific specifications
        if "badsum" in attack_name.lower():
            spec["expected_bad_checksums"] = True

        if "ttl" in attack_params:
            spec["expected_ttl"] = attack_params["ttl"]

        if "fake_ttl" in attack_params:
            spec["expected_ttl"] = attack_params["fake_ttl"]

        # Estimate packet count based on attack type
        if "split" in attack_name.lower():
            split_count = attack_params.get("split_count", 2)
            spec["expected_packet_count"] = split_count + 2  # splits + handshake

        return spec


# Convenience function
def validate_pcap_file(
    pcap_file: Path, attack_spec: Optional[Dict[str, Any]] = None
) -> PCAPValidationResult:
    """
    Convenience function to validate a PCAP file.

    Args:
        pcap_file: Path to PCAP file
        attack_spec: Optional attack specification

    Returns:
        PCAPValidationResult
    """
    validator = PCAPContentValidator()
    return validator.validate_pcap(pcap_file, attack_spec)
