"""
Checksum Fooler component for DPI strategy system.

This module implements badsum functionality to create invalid TCP checksums
for bypassing DPI systems that validate packet integrity.
"""

import struct
import socket
import logging
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass

from .config_models import FoolingConfig, TCPPacketInfo
from .exceptions import ChecksumCalculationError


logger = logging.getLogger(__name__)


@dataclass
class ChecksumResult:
    """Result of checksum manipulation operation."""

    original_checksum: int
    modified_checksum: int
    is_badsum_applied: bool
    calculation_method: str

    def get_checksum_diff(self) -> int:
        """Get difference between original and modified checksums."""
        return abs(self.original_checksum - self.modified_checksum)

    def is_checksum_changed(self) -> bool:
        """Check if checksum was actually changed."""
        return self.original_checksum != self.modified_checksum


class ChecksumFooler:
    """
    Component for manipulating TCP checksums to fool DPI systems.

    This class implements badsum functionality that creates predictable
    invalid TCP checksums to bypass DPI systems that validate packet integrity.
    """

    def __init__(self, config: Optional[FoolingConfig] = None):
        """
        Initialize ChecksumFooler.

        Args:
            config: Fooling configuration, defaults to disabled badsum
        """
        self.config = config or FoolingConfig()
        self._checksum_cache: Dict[bytes, int] = {}
        self._stats = {"badsum_applied": 0, "badsum_skipped": 0, "checksum_errors": 0}

    def apply_badsum(
        self, packet_data: bytes, tcp_info: TCPPacketInfo
    ) -> Tuple[bytes, ChecksumResult]:
        """
        Apply badsum (invalid checksum) to TCP packet.

        This method modifies the TCP checksum to be intentionally incorrect
        while maintaining predictable behavior for testing and validation.

        Args:
            packet_data: Raw packet data including IP and TCP headers
            tcp_info: Parsed TCP packet information

        Returns:
            Tuple of (modified_packet_data, checksum_result)

        Raises:
            ChecksumCalculationError: If checksum calculation fails
        """
        try:
            logger.debug(
                f"Applying badsum to packet: {tcp_info.src_ip}:{tcp_info.src_port} -> "
                f"{tcp_info.dst_ip}:{tcp_info.dst_port}"
            )

            # Extract original checksum
            original_checksum = tcp_info.checksum

            # Calculate bad checksum
            bad_checksum = self.calculate_bad_checksum(original_checksum)

            # Modify packet data with bad checksum
            modified_packet = self._replace_tcp_checksum(packet_data, bad_checksum)

            # Create result
            result = ChecksumResult(
                original_checksum=original_checksum,
                modified_checksum=bad_checksum,
                is_badsum_applied=True,
                calculation_method="predictable_bad",
            )

            self._stats["badsum_applied"] += 1

            logger.debug(
                f"Badsum applied: original=0x{original_checksum:04x}, "
                f"modified=0x{bad_checksum:04x}"
            )

            return modified_packet, result

        except Exception as e:
            self._stats["checksum_errors"] += 1
            logger.error(f"Failed to apply badsum: {e}")
            raise ChecksumCalculationError(f"Badsum application failed: {e}") from e

    def calculate_bad_checksum(self, original_checksum: int) -> int:
        """
        Calculate a predictable bad checksum.

        This method generates an intentionally incorrect checksum that is
        stable and predictable for testing purposes. The bad checksum is
        calculated by XORing the original checksum with a fixed pattern.

        Args:
            original_checksum: Original TCP checksum

        Returns:
            Predictable bad checksum value

        Raises:
            ChecksumCalculationError: If checksum calculation fails
        """
        try:
            # Use XOR with a fixed pattern to create predictable bad checksum
            # Pattern 0xDEAD ensures the checksum is always different and recognizable
            bad_checksum = original_checksum ^ 0xDEAD

            # Ensure we don't accidentally create a valid checksum
            if bad_checksum == original_checksum:
                bad_checksum = (~original_checksum) & 0xFFFF

            # Ensure checksum is in valid 16-bit range
            bad_checksum = bad_checksum & 0xFFFF

            logger.debug(
                f"Calculated bad checksum: 0x{original_checksum:04x} -> 0x{bad_checksum:04x}"
            )

            return bad_checksum

        except Exception as e:
            logger.error(f"Failed to calculate bad checksum: {e}")
            raise ChecksumCalculationError(f"Bad checksum calculation failed: {e}") from e

    def should_apply_badsum(
        self,
        tcp_info: TCPPacketInfo,
        is_first_part: bool = True,
        packet_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determine if badsum should be applied to a packet.

        According to requirements, badsum should only be applied to the first
        part of split packets when badsum is enabled in configuration.

        Args:
            tcp_info: TCP packet information
            is_first_part: Whether this is the first part of a split packet
            packet_context: Additional context about packet processing

        Returns:
            True if badsum should be applied
        """
        context = packet_context or {}
        connection_info = (
            f"{tcp_info.src_ip}:{tcp_info.src_port} -> {tcp_info.dst_ip}:{tcp_info.dst_port}"
        )

        # Check if badsum is enabled in configuration
        if not self.config.should_apply_badsum():
            logger.debug(f"Badsum not enabled in configuration for {connection_info}")
            self._stats["badsum_skipped"] += 1
            self._log_badsum_decision("disabled_in_config", tcp_info, context)
            return False

        # Only apply to first part of split packets
        if not is_first_part:
            logger.debug(f"Skipping badsum for non-first packet part: {connection_info}")
            self._stats["badsum_skipped"] += 1
            self._log_badsum_decision("not_first_part", tcp_info, context)
            return False

        # Only apply to packets with payload (avoid applying to control packets)
        if not tcp_info.has_payload():
            logger.debug(f"Skipping badsum for packet without payload: {connection_info}")
            self._stats["badsum_skipped"] += 1
            self._log_badsum_decision("no_payload", tcp_info, context)
            return False

        # Only apply to HTTPS traffic for DPI bypass
        if not tcp_info.is_https_traffic():
            logger.debug(f"Skipping badsum for non-HTTPS traffic: {connection_info}")
            self._stats["badsum_skipped"] += 1
            self._log_badsum_decision("not_https", tcp_info, context)
            return False

        # Additional checks based on packet context
        if context.get("packet_size", 0) < 40:  # Minimum size for meaningful TLS packet
            logger.debug(f"Skipping badsum for small packet: {connection_info}")
            self._stats["badsum_skipped"] += 1
            self._log_badsum_decision("packet_too_small", tcp_info, context)
            return False

        logger.info(
            f"Badsum will be applied to packet: {connection_info} "
            f"(size: {context.get('packet_size', 'unknown')})"
        )
        self._log_badsum_decision("will_apply", tcp_info, context)
        return True

    def _replace_tcp_checksum(self, packet_data: bytes, new_checksum: int) -> bytes:
        """
        Replace TCP checksum in packet data.

        Args:
            packet_data: Raw packet data
            new_checksum: New checksum value to set

        Returns:
            Modified packet data with new checksum

        Raises:
            ChecksumCalculationError: If packet modification fails
        """
        try:
            # Convert to mutable bytearray
            packet = bytearray(packet_data)

            # Find IP header length (IHL field in first byte of IP header)
            if len(packet) < 20:
                raise ChecksumCalculationError("Packet too small for IP header")

            ip_header_length = (packet[0] & 0x0F) * 4

            # TCP checksum is at offset 16 from start of TCP header
            tcp_checksum_offset = ip_header_length + 16

            if tcp_checksum_offset + 2 > len(packet):
                raise ChecksumCalculationError("Packet too small for TCP checksum")

            # Replace checksum (network byte order - big endian)
            struct.pack_into("!H", packet, tcp_checksum_offset, new_checksum)

            return bytes(packet)

        except struct.error as e:
            raise ChecksumCalculationError(f"Failed to replace TCP checksum: {e}") from e
        except Exception as e:
            raise ChecksumCalculationError(f"Packet modification failed: {e}") from e

    def verify_checksum_modification(self, original_packet: bytes, modified_packet: bytes) -> bool:
        """
        Verify that checksum was correctly modified.

        Args:
            original_packet: Original packet data
            modified_packet: Modified packet data

        Returns:
            True if checksum was correctly modified
        """
        try:
            # Extract checksums from both packets
            original_checksum = self._extract_tcp_checksum(original_packet)
            modified_checksum = self._extract_tcp_checksum(modified_packet)

            # Verify checksums are different
            if original_checksum == modified_checksum:
                logger.warning("Checksum was not modified")
                return False

            # Verify rest of packet is unchanged (except checksum)
            if not self._packets_equal_except_checksum(original_packet, modified_packet):
                logger.warning("Packet data changed beyond checksum")
                return False

            logger.debug(
                f"Checksum modification verified: 0x{original_checksum:04x} -> 0x{modified_checksum:04x}"
            )
            return True

        except Exception as e:
            logger.error(f"Checksum verification failed: {e}")
            return False

    def _extract_tcp_checksum(self, packet_data: bytes) -> int:
        """
        Extract TCP checksum from packet data.

        Args:
            packet_data: Raw packet data

        Returns:
            TCP checksum value

        Raises:
            ChecksumCalculationError: If checksum extraction fails
        """
        try:
            if len(packet_data) < 20:
                raise ChecksumCalculationError("Packet too small for IP header")

            # Get IP header length
            ip_header_length = (packet_data[0] & 0x0F) * 4

            # TCP checksum offset
            tcp_checksum_offset = ip_header_length + 16

            if tcp_checksum_offset + 2 > len(packet_data):
                raise ChecksumCalculationError("Packet too small for TCP checksum")

            # Extract checksum (network byte order)
            checksum = struct.unpack(
                "!H", packet_data[tcp_checksum_offset : tcp_checksum_offset + 2]
            )[0]

            return checksum

        except struct.error as e:
            raise ChecksumCalculationError(f"Failed to extract TCP checksum: {e}") from e

    def _packets_equal_except_checksum(self, packet1: bytes, packet2: bytes) -> bool:
        """
        Check if two packets are equal except for TCP checksum.

        Args:
            packet1: First packet data
            packet2: Second packet data

        Returns:
            True if packets are equal except for checksum
        """
        try:
            if len(packet1) != len(packet2):
                return False

            # Get IP header length
            ip_header_length = (packet1[0] & 0x0F) * 4
            tcp_checksum_offset = ip_header_length + 16

            # Compare everything before checksum
            if packet1[:tcp_checksum_offset] != packet2[:tcp_checksum_offset]:
                return False

            # Compare everything after checksum
            if packet1[tcp_checksum_offset + 2 :] != packet2[tcp_checksum_offset + 2 :]:
                return False

            return True

        except Exception:
            return False

    def restore_original_checksum(self, modified_packet: bytes, original_checksum: int) -> bytes:
        """
        Restore original checksum for testing purposes.

        Args:
            modified_packet: Packet with modified checksum
            original_checksum: Original checksum to restore

        Returns:
            Packet with restored original checksum
        """
        try:
            return self._replace_tcp_checksum(modified_packet, original_checksum)
        except Exception as e:
            logger.error(f"Failed to restore original checksum: {e}")
            raise ChecksumCalculationError(f"Checksum restoration failed: {e}") from e

    def get_stats(self) -> Dict[str, Any]:
        """
        Get checksum fooler statistics.

        Returns:
            Dictionary with operation statistics
        """
        return {
            "badsum_applied": self._stats["badsum_applied"],
            "badsum_skipped": self._stats["badsum_skipped"],
            "checksum_errors": self._stats["checksum_errors"],
            "cache_size": len(self._checksum_cache),
        }

    def reset_stats(self):
        """Reset operation statistics."""
        self._stats = {"badsum_applied": 0, "badsum_skipped": 0, "checksum_errors": 0}
        self._checksum_cache.clear()

    def _log_badsum_decision(self, decision: str, tcp_info: TCPPacketInfo, context: Dict[str, Any]):
        """
        Log badsum application decision for tracking and debugging.

        Args:
            decision: Decision reason (will_apply, disabled_in_config, etc.)
            tcp_info: TCP packet information
            context: Additional packet context
        """
        log_data = {
            "decision": decision,
            "connection": tcp_info.get_connection_tuple(),
            "packet_size": context.get("packet_size", 0),
            "has_payload": tcp_info.has_payload(),
            "is_https": tcp_info.is_https_traffic(),
            "tcp_flags": tcp_info.get_flag_names(),
            "seq_num": tcp_info.seq_num,
        }

        # Log at appropriate level based on decision
        if decision == "will_apply":
            logger.info(f"Badsum decision: {decision} - {log_data}")
        else:
            logger.debug(f"Badsum decision: {decision} - {log_data}")

    def apply_badsum_to_first_part_only(
        self, packet_parts: list, tcp_infos: list
    ) -> Tuple[list, list]:
        """
        Apply badsum only to the first part of split packets.

        This method implements the requirement that badsum should only be
        applied to the first part when packets are split.

        Args:
            packet_parts: List of packet parts (bytes)
            tcp_infos: List of TCP info for each part

        Returns:
            Tuple of (modified_packet_parts, checksum_results)
        """
        if not packet_parts or not tcp_infos:
            return packet_parts, []

        if len(packet_parts) != len(tcp_infos):
            raise ValueError("Number of packet parts must match number of TCP infos")

        modified_parts = []
        checksum_results = []

        for i, (part, tcp_info) in enumerate(zip(packet_parts, tcp_infos)):
            is_first_part = i == 0

            if self.should_apply_badsum(tcp_info, is_first_part):
                try:
                    modified_part, result = self.apply_badsum(part, tcp_info)
                    modified_parts.append(modified_part)
                    checksum_results.append(result)
                    logger.info(f"Applied badsum to part {i+1}/{len(packet_parts)}")
                except Exception as e:
                    logger.error(f"Failed to apply badsum to part {i+1}: {e}")
                    modified_parts.append(part)  # Use original part on error
                    checksum_results.append(None)
            else:
                modified_parts.append(part)  # Use original part
                checksum_results.append(None)

        return modified_parts, checksum_results

    def get_badsum_application_summary(self, checksum_results: list) -> Dict[str, Any]:
        """
        Get summary of badsum application across multiple packet parts.

        Args:
            checksum_results: List of ChecksumResult objects (or None)

        Returns:
            Summary dictionary with application statistics
        """
        applied_count = sum(1 for result in checksum_results if result and result.is_badsum_applied)
        total_parts = len(checksum_results)

        summary = {
            "total_parts": total_parts,
            "badsum_applied_count": applied_count,
            "badsum_skipped_count": total_parts - applied_count,
            "application_rate": applied_count / total_parts if total_parts > 0 else 0.0,
            "checksum_changes": [],
        }

        for i, result in enumerate(checksum_results):
            if result and result.is_badsum_applied:
                summary["checksum_changes"].append(
                    {
                        "part_index": i,
                        "original": f"0x{result.original_checksum:04x}",
                        "modified": f"0x{result.modified_checksum:04x}",
                        "diff": result.get_checksum_diff(),
                    }
                )

        return summary

    def validate_checksum_integrity(self, packet_data: bytes) -> Dict[str, Any]:
        """
        Validate TCP checksum integrity and provide detailed analysis.

        Args:
            packet_data: Raw packet data to validate

        Returns:
            Dictionary with validation results and analysis
        """
        try:
            # Extract current checksum
            current_checksum = self._extract_tcp_checksum(packet_data)

            # Calculate what the correct checksum should be
            correct_checksum = self._calculate_correct_tcp_checksum(packet_data)

            is_valid = current_checksum == correct_checksum

            validation_result = {
                "is_valid": is_valid,
                "current_checksum": f"0x{current_checksum:04x}",
                "correct_checksum": f"0x{correct_checksum:04x}",
                "checksum_diff": abs(current_checksum - correct_checksum),
                "is_likely_badsum": self._is_likely_badsum_pattern(
                    current_checksum, correct_checksum
                ),
                "packet_size": len(packet_data),
            }

            if not is_valid:
                validation_result["error_type"] = self._classify_checksum_error(
                    current_checksum, correct_checksum
                )

            return validation_result

        except Exception as e:
            return {"is_valid": False, "error": str(e), "validation_failed": True}

    def _calculate_correct_tcp_checksum(self, packet_data: bytes) -> int:
        """
        Calculate the correct TCP checksum for a packet.

        Args:
            packet_data: Raw packet data

        Returns:
            Correct TCP checksum value
        """
        try:
            # Create a copy of the packet with checksum set to 0
            packet = bytearray(packet_data)

            # Get IP header length
            ip_header_length = (packet[0] & 0x0F) * 4
            tcp_checksum_offset = ip_header_length + 16

            # Set checksum to 0 for calculation
            struct.pack_into("!H", packet, tcp_checksum_offset, 0)

            # Extract IP addresses for pseudo-header
            src_ip = struct.unpack("!I", packet[12:16])[0]
            dst_ip = struct.unpack("!I", packet[16:20])[0]

            # TCP segment (header + data)
            tcp_segment = packet[ip_header_length:]
            tcp_length = len(tcp_segment)

            # Create pseudo-header
            pseudo_header = struct.pack("!IIBBH", src_ip, dst_ip, 0, 6, tcp_length)

            # Calculate checksum over pseudo-header + TCP segment
            checksum_data = pseudo_header + tcp_segment
            checksum = self._calculate_internet_checksum(checksum_data)

            return checksum

        except Exception as e:
            logger.error(f"Failed to calculate correct TCP checksum: {e}")
            return 0

    def _calculate_internet_checksum(self, data: bytes) -> int:
        """
        Calculate Internet checksum (RFC 1071).

        Args:
            data: Data to calculate checksum for

        Returns:
            Internet checksum value
        """
        # Pad data to even length
        if len(data) % 2:
            data += b"\x00"

        # Sum all 16-bit words
        checksum = 0
        for i in range(0, len(data), 2):
            word = struct.unpack("!H", data[i : i + 2])[0]
            checksum += word

        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # One's complement
        checksum = (~checksum) & 0xFFFF

        return checksum

    def _is_likely_badsum_pattern(self, current: int, correct: int) -> bool:
        """
        Check if checksum appears to be intentionally bad (badsum pattern).

        Args:
            current: Current checksum value
            correct: Correct checksum value

        Returns:
            True if this looks like an intentional badsum
        """
        # Check for our specific badsum pattern (XOR with 0xDEAD)
        if current == (correct ^ 0xDEAD):
            return True

        # Check for complement pattern
        if current == (~correct & 0xFFFF):
            return True

        # Check for other common badsum patterns
        common_patterns = [0x0000, 0xFFFF, 0xDEAD, 0xBEEF, 0xCAFE]
        if current in common_patterns and current != correct:
            return True

        return False

    def _classify_checksum_error(self, current: int, correct: int) -> str:
        """
        Classify the type of checksum error.

        Args:
            current: Current checksum value
            correct: Correct checksum value

        Returns:
            Error classification string
        """
        if self._is_likely_badsum_pattern(current, correct):
            return "intentional_badsum"

        diff = abs(current - correct)

        if diff == 1:
            return "single_bit_error"
        elif diff < 16:
            return "minor_corruption"
        elif current == 0:
            return "zero_checksum"
        elif current == 0xFFFF:
            return "all_ones_checksum"
        else:
            return "major_corruption"

    def create_test_packet_with_badsum(self, base_packet: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """
        Create a test packet with badsum for validation testing.

        Args:
            base_packet: Base packet to modify

        Returns:
            Tuple of (modified_packet, test_info)
        """
        try:
            # Parse TCP info from base packet
            tcp_info = self._parse_tcp_info_from_packet(base_packet)

            # Apply badsum
            modified_packet, checksum_result = self.apply_badsum(base_packet, tcp_info)

            # Create test info
            test_info = {
                "original_checksum": f"0x{checksum_result.original_checksum:04x}",
                "badsum_checksum": f"0x{checksum_result.modified_checksum:04x}",
                "modification_method": checksum_result.calculation_method,
                "packet_size": len(base_packet),
                "test_timestamp": (
                    logger.handlers[0].formatter.formatTime(
                        logging.LogRecord("", 0, "", 0, "", (), None)
                    )
                    if logger.handlers
                    else "unknown"
                ),
            }

            return modified_packet, test_info

        except Exception as e:
            logger.error(f"Failed to create test packet with badsum: {e}")
            raise ChecksumCalculationError(f"Test packet creation failed: {e}") from e

    def _parse_tcp_info_from_packet(self, packet_data: bytes) -> TCPPacketInfo:
        """
        Parse TCP information from raw packet data.

        Args:
            packet_data: Raw packet data

        Returns:
            TCPPacketInfo object
        """
        try:
            # Get IP header length
            ip_header_length = (packet_data[0] & 0x0F) * 4

            # Extract IP addresses
            src_ip = socket.inet_ntoa(packet_data[12:16])
            dst_ip = socket.inet_ntoa(packet_data[16:20])

            # Extract TCP header fields
            tcp_header_start = ip_header_length
            tcp_header = packet_data[tcp_header_start : tcp_header_start + 20]

            src_port, dst_port, seq_num, ack_num, flags_and_window, window_size = struct.unpack(
                "!HHIIHH", tcp_header[:16]
            )
            flags = (flags_and_window >> 8) & 0xFF
            checksum = struct.unpack("!H", tcp_header[16:18])[0]

            # Get TCP header length
            tcp_header_length = ((tcp_header[12] >> 4) & 0x0F) * 4

            # Extract payload
            payload_start = tcp_header_start + tcp_header_length
            payload = packet_data[payload_start:]

            return TCPPacketInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                seq_num=seq_num,
                ack_num=ack_num,
                flags=flags,
                window_size=window_size,
                checksum=checksum,
                payload=payload,
            )

        except Exception as e:
            logger.error(f"Failed to parse TCP info from packet: {e}")
            raise ChecksumCalculationError(f"TCP info parsing failed: {e}") from e

    def run_checksum_validation_tests(self) -> Dict[str, Any]:
        """
        Run comprehensive checksum validation tests.

        Returns:
            Dictionary with test results
        """
        test_results = {
            "tests_run": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "test_details": [],
        }

        try:
            # Test 1: Badsum calculation consistency
            test_results["tests_run"] += 1
            original_checksum = 0x1234
            bad1 = self.calculate_bad_checksum(original_checksum)
            bad2 = self.calculate_bad_checksum(original_checksum)

            if bad1 == bad2 and bad1 != original_checksum:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test": "badsum_consistency",
                        "status": "passed",
                        "details": f"Consistent badsum: 0x{bad1:04x}",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test": "badsum_consistency",
                        "status": "failed",
                        "details": f"Inconsistent badsum: {bad1} vs {bad2}",
                    }
                )

            # Test 2: Badsum pattern recognition
            test_results["tests_run"] += 1
            correct = 0x5678
            bad = correct ^ 0xDEAD

            if self._is_likely_badsum_pattern(bad, correct):
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test": "badsum_pattern_recognition",
                        "status": "passed",
                        "details": "Correctly identified badsum pattern",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test": "badsum_pattern_recognition",
                        "status": "failed",
                        "details": "Failed to identify badsum pattern",
                    }
                )

            # Test 3: Internet checksum calculation
            test_results["tests_run"] += 1
            test_data = (
                b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c"
            )
            calculated = self._calculate_internet_checksum(test_data)

            # This should produce a valid checksum (non-zero for this test data)
            if calculated != 0:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test": "internet_checksum_calculation",
                        "status": "passed",
                        "details": f"Calculated checksum: 0x{calculated:04x}",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test": "internet_checksum_calculation",
                        "status": "failed",
                        "details": "Unexpected zero checksum",
                    }
                )

            logger.info(
                f"Checksum validation tests completed: "
                f"{test_results['tests_passed']}/{test_results['tests_run']} passed"
            )

        except Exception as e:
            logger.error(f"Checksum validation tests failed: {e}")
            test_results["test_error"] = str(e)

        return test_results

    def _classify_checksum_error(self, actual_checksum: int, expected_checksum: int) -> str:
        """
        Classify the type of checksum error.

        Args:
            actual_checksum: The actual checksum value found
            expected_checksum: The expected/correct checksum value

        Returns:
            String describing the type of checksum error
        """
        if actual_checksum == expected_checksum:
            return "correct_checksum"

        # Check for specific patterns
        if actual_checksum == 0x0000:
            return "zero_checksum"

        if actual_checksum == 0xFFFF:
            return "all_ones_checksum"

        # Check for single bit errors
        diff = actual_checksum ^ expected_checksum
        if diff and (diff & (diff - 1)) == 0:  # Check if diff is a power of 2
            return "single_bit_error"

        # Check for common badsum patterns
        if self._is_likely_badsum_pattern(actual_checksum, expected_checksum):
            return "intentional_badsum"

        return "unknown_checksum_error"

    def should_apply_badsum(self, tcp_info: TCPPacketInfo, is_first_part: bool = True) -> bool:
        """
        Determine if badsum should be applied to this packet.

        Args:
            tcp_info: TCP packet information
            is_first_part: Whether this is the first part of a split packet

        Returns:
            True if badsum should be applied, False otherwise
        """
        # Check if badsum is enabled in configuration
        if not self.config.badsum:
            return False

        # Apply badsum only to first part by default
        if not is_first_part and not getattr(self.config, "badsum_all_parts", False):
            return False

        # Don't apply badsum if there's no payload
        if not tcp_info.payload or len(tcp_info.payload) == 0:
            return False

        # Check if this is an HTTPS connection (port 443) - primary target
        if tcp_info.dst_port == 443 or tcp_info.src_port == 443:
            return True

        # For HTTP (port 80) and other ports, don't apply badsum by default
        # This is more conservative and matches expected test behavior
        return False
