#!/usr/bin/env python3
"""
Comprehensive audit and validation of attack primitives.

This module performs a thorough analysis of all attack primitives in primitives.py
to ensure their theoretical and practical correctness.
"""

import sys
import struct
import logging
from typing import Dict, Any
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    from scapy.all import rdpcap, IP, TCP, wrpcap, Packet

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. PCAP analysis will be limited.")

from core.bypass.techniques.primitives import BypassTechniques

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PrimitivesAuditor:
    """Auditor for attack primitives validation."""

    def __init__(self):
        self.results = {}
        self.test_payload = (
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        )
        self.tls_payload = (
            b"\x16\x03\x01\x00\xf4"  # TLS Record Header (Content Type: Handshake, Version: TLS 1.0, Length: 244)
            b"\x01\x00\x00\xf0"  # Handshake Header (Type: Client Hello, Length: 240)
            b"\x03\x03"  # Version: TLS 1.2
            + b"\x00" * 32  # Random (32 bytes)
            + b"\x00"  # Session ID Length
            + b"\x00\x02\x13\x01"  # Cipher Suites Length + Cipher Suites
            + b"\x01\x00"  # Compression Methods
            + b"\x00\x00"  # Extensions Length
        )

    def audit_fakeddisorder(self) -> Dict[str, Any]:
        """Deep analysis of fakeddisorder attack."""
        logger.info("🔍 Auditing fakeddisorder attack...")

        results = {"test_cases": [], "issues": [], "pcap_comparison": None}

        # Test Case 1: Basic fakeddisorder without overlap
        test1 = self._test_fakeddisorder_no_overlap()
        results["test_cases"].append(test1)

        # Test Case 2: fakeddisorder with overlap
        test2 = self._test_fakeddisorder_with_overlap()
        results["test_cases"].append(test2)

        # Test Case 3: fakeddisorder with fooling methods
        test3 = self._test_fakeddisorder_with_fooling()
        results["test_cases"].append(test3)

        # Test Case 4: Edge cases
        test4 = self._test_fakeddisorder_edge_cases()
        results["test_cases"].append(test4)

        # PCAP comparison if available
        if SCAPY_AVAILABLE:
            pcap_result = self._compare_fakeddisorder_pcap()
            results["pcap_comparison"] = pcap_result

        return results

    def _test_fakeddisorder_no_overlap(self) -> Dict[str, Any]:
        """Test fakeddisorder without overlap."""
        test_name = "fakeddisorder_no_overlap"
        logger.info(f"  Testing {test_name}...")

        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=10,
            overlap_size=0,
            fake_ttl=64,
            fooling_methods=[],
        )

        issues = []

        # Validate segment count
        if len(segments) != 2:
            issues.append(f"Expected 2 segments, got {len(segments)}")

        # Validate fake segment
        if len(segments) >= 1:
            fake_payload, fake_offset, fake_opts = segments[0]
            if not fake_opts.get("is_fake", False):
                issues.append("First segment should be fake")
            if fake_opts.get("ttl") != 64:
                issues.append(f"Expected TTL=64, got {fake_opts.get('ttl')}")
            if fake_offset != 0:
                issues.append(f"Expected fake offset=0, got {fake_offset}")
            if fake_payload != self.test_payload[:10]:
                issues.append("Fake payload doesn't match expected content")

        # Validate real segment
        if len(segments) >= 2:
            real_payload, real_offset, real_opts = segments[1]
            if real_opts.get("is_fake", True):
                issues.append("Second segment should be real")
            if real_offset != 10:
                issues.append(f"Expected real offset=10, got {real_offset}")
            if real_payload != self.test_payload[10:]:
                issues.append("Real payload doesn't match expected content")

        return {
            "name": test_name,
            "segments": len(segments),
            "issues": issues,
            "passed": len(issues) == 0,
        }

    def _test_fakeddisorder_with_overlap(self) -> Dict[str, Any]:
        """Test fakeddisorder with overlap."""
        test_name = "fakeddisorder_with_overlap"
        logger.info(f"  Testing {test_name}...")

        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=20,
            overlap_size=5,
            fake_ttl=1,
            fooling_methods=[],
        )

        issues = []

        # Validate segment count
        if len(segments) != 2:
            issues.append(f"Expected 2 segments, got {len(segments)}")

        # Validate overlap logic
        if len(segments) >= 2:
            fake_payload, fake_offset, fake_opts = segments[0]
            real_payload, real_offset, real_opts = segments[1]

            # Check offsets for overlap
            expected_fake_offset = 20 - 5  # split_pos - overlap_size
            expected_real_offset = 20

            if fake_offset != expected_fake_offset:
                issues.append(
                    f"Expected fake offset={expected_fake_offset}, got {fake_offset}"
                )
            if real_offset != expected_real_offset:
                issues.append(
                    f"Expected real offset={expected_real_offset}, got {real_offset}"
                )

        return {
            "name": test_name,
            "segments": len(segments),
            "issues": issues,
            "passed": len(issues) == 0,
        }

    def _test_fakeddisorder_with_fooling(self) -> Dict[str, Any]:
        """Test fakeddisorder with fooling methods."""
        test_name = "fakeddisorder_with_fooling"
        logger.info(f"  Testing {test_name}...")

        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=15,
            overlap_size=0,
            fake_ttl=64,
            fooling_methods=["badsum", "md5sig", "badseq"],
        )

        issues = []

        if len(segments) >= 1:
            fake_payload, fake_offset, fake_opts = segments[0]

            # Check fooling options
            if not fake_opts.get("corrupt_tcp_checksum", False):
                issues.append("badsum fooling not applied")
            if not fake_opts.get("add_md5sig_option", False):
                issues.append("md5sig fooling not applied")
            if not fake_opts.get("corrupt_sequence", False):
                issues.append("badseq fooling not applied")

        return {
            "name": test_name,
            "segments": len(segments),
            "issues": issues,
            "passed": len(issues) == 0,
        }

    def _test_fakeddisorder_edge_cases(self) -> Dict[str, Any]:
        """Test fakeddisorder edge cases."""
        test_name = "fakeddisorder_edge_cases"
        logger.info(f"  Testing {test_name}...")

        issues = []

        # Test 1: split_pos >= payload length
        segments1 = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=len(self.test_payload) + 10,
            overlap_size=0,
            fake_ttl=64,
        )

        if len(segments1) != 1:
            issues.append(
                "Should return single segment when split_pos >= payload length"
            )
        elif segments1[0][2].get("is_fake", True):
            issues.append(
                "Single segment should not be fake when split_pos >= payload length"
            )

        # Test 2: overlap_size > split_pos
        segments2 = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=10,
            overlap_size=15,  # > split_pos
            fake_ttl=64,
        )

        if len(segments2) >= 1:
            fake_offset = segments2[0][1]
            # Should clamp overlap to split_pos, so offset should be 0
            if fake_offset != 0:
                issues.append(
                    f"Overlap clamping failed: expected offset=0, got {fake_offset}"
                )

        # Test 3: negative overlap_size
        segments3 = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload, split_pos=10, overlap_size=-5, fake_ttl=64
        )

        if len(segments3) >= 1:
            fake_offset = segments3[0][1]
            # Should clamp to 0
            if fake_offset != 0:
                issues.append(
                    f"Negative overlap handling failed: expected offset=0, got {fake_offset}"
                )

        return {"name": test_name, "issues": issues, "passed": len(issues) == 0}

    def _compare_fakeddisorder_pcap(self) -> Dict[str, Any]:
        """Compare fakeddisorder implementation with zapret PCAP."""
        logger.info("  Comparing with zapret PCAP...")

        zapret_pcap = Path("zapret.pcap")
        recon_pcap = Path("out2.pcap")

        if not zapret_pcap.exists():
            return {"error": "zapret.pcap not found"}

        if not recon_pcap.exists():
            return {"error": "out2.pcap not found"}

        try:
            zapret_packets = rdpcap(str(zapret_pcap))
            recon_packets = rdpcap(str(recon_pcap))

            # Analyze packet structure differences
            analysis = self._analyze_packet_differences(zapret_packets, recon_packets)
            return analysis

        except Exception as e:
            return {"error": f"PCAP analysis failed: {str(e)}"}

    def _analyze_packet_differences(
        self, zapret_packets, recon_packets
    ) -> Dict[str, Any]:
        """Analyze differences between zapret and recon packets."""
        differences = {
            "ip_header_diffs": [],
            "tcp_header_diffs": [],
            "tcp_options_diffs": [],
            "timing_diffs": [],
            "checksum_diffs": [],
        }

        # Find TLS handshake packets for comparison
        zapret_tls = [p for p in zapret_packets if TCP in p and p[TCP].dport == 443]
        recon_tls = [p for p in recon_packets if TCP in p and p[TCP].dport == 443]

        if not zapret_tls or not recon_tls:
            return {"error": "No TLS packets found for comparison"}

        # Compare first few packets
        for i in range(min(3, len(zapret_tls), len(recon_tls))):
            z_pkt = zapret_tls[i]
            r_pkt = recon_tls[i]

            # IP header comparison
            if IP in z_pkt and IP in r_pkt:
                z_ip = z_pkt[IP]
                r_ip = r_pkt[IP]

                if z_ip.id != r_ip.id:
                    differences["ip_header_diffs"].append(
                        f"Packet {i}: IP ID differs (zapret: {z_ip.id}, recon: {r_ip.id})"
                    )

                if z_ip.flags != r_ip.flags:
                    differences["ip_header_diffs"].append(
                        f"Packet {i}: IP flags differ (zapret: {z_ip.flags}, recon: {r_ip.flags})"
                    )

                if z_ip.ttl != r_ip.ttl:
                    differences["ip_header_diffs"].append(
                        f"Packet {i}: TTL differs (zapret: {z_ip.ttl}, recon: {r_ip.ttl})"
                    )

            # TCP header comparison
            if TCP in z_pkt and TCP in r_pkt:
                z_tcp = z_pkt[TCP]
                r_tcp = r_pkt[TCP]

                if z_tcp.window != r_tcp.window:
                    differences["tcp_header_diffs"].append(
                        f"Packet {i}: Window size differs (zapret: {z_tcp.window}, recon: {r_tcp.window})"
                    )

                if z_tcp.flags != r_tcp.flags:
                    differences["tcp_header_diffs"].append(
                        f"Packet {i}: TCP flags differ (zapret: {z_tcp.flags}, recon: {r_tcp.flags})"
                    )

                # TCP options comparison
                z_options = getattr(z_tcp, "options", [])
                r_options = getattr(r_tcp, "options", [])

                if len(z_options) != len(r_options):
                    differences["tcp_options_diffs"].append(
                        f"Packet {i}: TCP options count differs (zapret: {len(z_options)}, recon: {len(r_options)})"
                    )

        return differences

    def audit_multisplit_seqovl(self) -> Dict[str, Any]:
        """Validate multisplit and seqovl attacks."""
        logger.info("🔍 Auditing multisplit & seqovl attacks...")

        results = {"multisplit_tests": [], "seqovl_tests": [], "issues": []}

        # Test multisplit
        multisplit_result = self._test_multisplit()
        results["multisplit_tests"].append(multisplit_result)

        # Test seqovl
        seqovl_result = self._test_seqovl()
        results["seqovl_tests"].append(seqovl_result)

        return results

    def _test_multisplit(self) -> Dict[str, Any]:
        """Test multisplit attack."""
        logger.info("  Testing multisplit...")

        issues = []

        # Test 1: Basic multisplit
        segments = BypassTechniques.apply_multisplit(self.test_payload, [10, 20, 30])

        if (
            len(segments) != 4
        ):  # Should create 4 segments: [0:10], [10:20], [20:30], [30:]
            issues.append(f"Expected 4 segments, got {len(segments)}")

        # Validate segment boundaries
        expected_segments = [
            (self.test_payload[0:10], 0),
            (self.test_payload[10:20], 10),
            (self.test_payload[20:30], 20),
            (self.test_payload[30:], 30),
        ]

        for i, (expected_payload, expected_offset) in enumerate(expected_segments):
            if i < len(segments):
                actual_payload, actual_offset = segments[i]
                if actual_payload != expected_payload:
                    issues.append(f"Segment {i} payload mismatch")
                if actual_offset != expected_offset:
                    issues.append(
                        f"Segment {i} offset mismatch: expected {expected_offset}, got {actual_offset}"
                    )

        # Test 2: Empty positions
        segments_empty = BypassTechniques.apply_multisplit(self.test_payload, [])
        if len(segments_empty) != 1:
            issues.append("Empty positions should return single segment")

        # Test 3: Out of bounds positions
        segments_oob = BypassTechniques.apply_multisplit(
            self.test_payload, [5, len(self.test_payload) + 10]
        )
        # Should ignore out of bounds positions

        return {"name": "multisplit", "issues": issues, "passed": len(issues) == 0}

    def _test_seqovl(self) -> Dict[str, Any]:
        """Test seqovl attack."""
        logger.info("  Testing seqovl...")

        issues = []

        segments = BypassTechniques.apply_seqovl(
            self.test_payload, split_pos=10, overlap_size=5
        )

        if len(segments) != 2:
            issues.append(f"Expected 2 segments, got {len(segments)}")

        if len(segments) >= 2:
            # First segment should be part2 at split_pos
            part2_payload, part2_offset = segments[0]
            if part2_payload != self.test_payload[10:]:
                issues.append("First segment (part2) payload mismatch")
            if part2_offset != 10:
                issues.append(f"First segment offset should be 10, got {part2_offset}")

            # Second segment should be overlap + part1 at negative offset
            part1_payload, part1_offset = segments[1]
            expected_part1 = b"\x00" * 5 + self.test_payload[:10]  # overlap + part1
            if part1_payload != expected_part1:
                issues.append("Second segment (part1 with overlap) payload mismatch")
            if part1_offset != -5:
                issues.append(f"Second segment offset should be -5, got {part1_offset}")

        return {"name": "seqovl", "issues": issues, "passed": len(issues) == 0}

    def audit_fooling_methods(self) -> Dict[str, Any]:
        """Audit fooling methods (badsum, md5sig)."""
        logger.info("🔍 Auditing fooling methods...")

        results = {"badsum_test": None, "md5sig_test": None, "issues": []}

        # Create a mock packet for testing
        mock_packet = self._create_mock_tcp_packet()

        # Test badsum fooling
        badsum_result = self._test_badsum_fooling(mock_packet.copy())
        results["badsum_test"] = badsum_result

        # Test md5sig fooling
        md5sig_result = self._test_md5sig_fooling(mock_packet.copy())
        results["md5sig_test"] = md5sig_result

        return results

    def _create_mock_tcp_packet(self) -> bytearray:
        """Create a mock TCP packet for testing."""
        # Simplified IP + TCP header
        ip_header = bytearray(
            [
                0x45,  # Version + IHL
                0x00,  # ToS
                0x00,
                0x3C,  # Total Length
                0x00,
                0x00,  # ID
                0x40,
                0x00,  # Flags + Fragment Offset
                0x40,  # TTL
                0x06,  # Protocol (TCP)
                0x00,
                0x00,  # Header Checksum
                0xC0,
                0xA8,
                0x01,
                0x01,  # Source IP
                0xC0,
                0xA8,
                0x01,
                0x02,  # Dest IP
            ]
        )

        tcp_header = bytearray(
            [
                0x04,
                0xD2,  # Source Port
                0x01,
                0xBB,  # Dest Port
                0x00,
                0x00,
                0x00,
                0x01,  # Seq Number
                0x00,
                0x00,
                0x00,
                0x00,  # Ack Number
                0x50,
                0x18,  # Data Offset + Flags
                0x20,
                0x00,  # Window Size
                0x00,
                0x00,  # Checksum (will be modified)
                0x00,
                0x00,  # Urgent Pointer
            ]
        )

        return ip_header + tcp_header

    def _test_badsum_fooling(self, packet: bytearray) -> Dict[str, Any]:
        """Test badsum fooling method."""
        logger.info("  Testing badsum fooling...")

        original_checksum = struct.unpack("!H", packet[36:38])[
            0
        ]  # TCP checksum position

        modified_packet = BypassTechniques.apply_badsum_fooling(packet)
        new_checksum = struct.unpack("!H", modified_packet[36:38])[0]

        issues = []
        if new_checksum != 0xDEAD:
            issues.append(f"Expected checksum 0xDEAD, got 0x{new_checksum:04X}")

        return {
            "name": "badsum_fooling",
            "original_checksum": f"0x{original_checksum:04X}",
            "new_checksum": f"0x{new_checksum:04X}",
            "issues": issues,
            "passed": len(issues) == 0,
        }

    def _test_md5sig_fooling(self, packet: bytearray) -> Dict[str, Any]:
        """Test md5sig fooling method."""
        logger.info("  Testing md5sig fooling...")

        original_checksum = struct.unpack("!H", packet[36:38])[0]

        modified_packet = BypassTechniques.apply_md5sig_fooling(packet)
        new_checksum = struct.unpack("!H", modified_packet[36:38])[0]

        issues = []
        if new_checksum != 0xBEEF:
            issues.append(f"Expected checksum 0xBEEF, got 0x{new_checksum:04X}")

        return {
            "name": "md5sig_fooling",
            "original_checksum": f"0x{original_checksum:04X}",
            "new_checksum": f"0x{new_checksum:04X}",
            "issues": issues,
            "passed": len(issues) == 0,
        }

    def audit_other_attacks(self) -> Dict[str, Any]:
        """Audit other attacks (tlsrec_split, wssize_limit)."""
        logger.info("🔍 Auditing other attacks...")

        results = {"tlsrec_split_test": None, "wssize_limit_test": None, "issues": []}

        # Test tlsrec_split
        tlsrec_result = self._test_tlsrec_split()
        results["tlsrec_split_test"] = tlsrec_result

        # Test wssize_limit
        wssize_result = self._test_wssize_limit()
        results["wssize_limit_test"] = wssize_result

        return results

    def _test_tlsrec_split(self) -> Dict[str, Any]:
        """Test TLS record split attack."""
        logger.info("  Testing tlsrec_split...")

        issues = []

        # Test with valid TLS record
        result = BypassTechniques.apply_tlsrec_split(self.tls_payload, split_pos=10)

        # Should return modified payload with split TLS records
        if result == self.tls_payload:
            issues.append("TLS record was not split")

        # Test with invalid payload (should return unchanged)
        invalid_payload = b"Not a TLS record"
        result_invalid = BypassTechniques.apply_tlsrec_split(
            invalid_payload, split_pos=5
        )

        if result_invalid != invalid_payload:
            issues.append("Invalid payload should be returned unchanged")

        # Test edge cases
        result_empty = BypassTechniques.apply_tlsrec_split(b"", split_pos=5)
        if result_empty != b"":
            issues.append("Empty payload should be returned unchanged")

        return {"name": "tlsrec_split", "issues": issues, "passed": len(issues) == 0}

    def _test_wssize_limit(self) -> Dict[str, Any]:
        """Test window size limit attack."""
        logger.info("  Testing wssize_limit...")

        issues = []

        # Test with window size 10
        segments = BypassTechniques.apply_wssize_limit(
            self.test_payload, window_size=10
        )

        expected_segments = len(self.test_payload) // 10
        if len(self.test_payload) % 10 != 0:
            expected_segments += 1

        if len(segments) != expected_segments:
            issues.append(f"Expected {expected_segments} segments, got {len(segments)}")

        # Validate segment sizes
        for i, (chunk, offset) in enumerate(segments):
            expected_size = min(10, len(self.test_payload) - i * 10)
            if len(chunk) != expected_size:
                issues.append(
                    f"Segment {i} size mismatch: expected {expected_size}, got {len(chunk)}"
                )

            if offset != i * 10:
                issues.append(
                    f"Segment {i} offset mismatch: expected {i * 10}, got {offset}"
                )

        # Test with window size 1
        segments_1 = BypassTechniques.apply_wssize_limit(
            self.test_payload, window_size=1
        )
        if len(segments_1) != len(self.test_payload):
            issues.append(
                f"Window size 1 should create {len(self.test_payload)} segments, got {len(segments_1)}"
            )

        return {"name": "wssize_limit", "issues": issues, "passed": len(issues) == 0}

    def generate_test_pcaps(self) -> Dict[str, Any]:
        """Generate PCAP files for visual inspection."""
        logger.info("🔍 Generating test PCAP files...")

        if not SCAPY_AVAILABLE:
            return {"error": "Scapy not available for PCAP generation"}

        results = {}

        try:
            # Generate fakeddisorder PCAP
            fakeddisorder_pcap = self._generate_fakeddisorder_pcap()
            results["fakeddisorder_pcap"] = fakeddisorder_pcap

            # Generate multisplit PCAP
            multisplit_pcap = self._generate_multisplit_pcap()
            results["multisplit_pcap"] = multisplit_pcap

            # Generate seqovl PCAP
            seqovl_pcap = self._generate_seqovl_pcap()
            results["seqovl_pcap"] = seqovl_pcap

        except Exception as e:
            results["error"] = f"PCAP generation failed: {str(e)}"

        return results

    def _generate_fakeddisorder_pcap(self) -> str:
        """Generate PCAP demonstrating fakeddisorder attack."""
        from scapy.all import IP, TCP, wrpcap

        packets = []

        # Simulate fakeddisorder attack
        segments = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload,
            split_pos=20,
            overlap_size=5,
            fake_ttl=1,
            fooling_methods=["badsum"],
        )

        base_seq = 1000

        for i, (payload, offset, opts) in enumerate(segments):
            pkt = (
                IP(dst="192.168.1.100", ttl=opts.get("ttl", 64))
                / TCP(
                    dport=443, seq=base_seq + offset, flags=opts.get("tcp_flags", 0x18)
                )
                / payload
            )

            # Apply fooling if specified
            if opts.get("corrupt_tcp_checksum"):
                pkt[TCP].chksum = 0xDEAD

            packets.append(pkt)

        pcap_path = "test_fakeddisorder.pcap"
        wrpcap(pcap_path, packets)

        return pcap_path

    def _generate_multisplit_pcap(self) -> str:
        """Generate PCAP demonstrating multisplit attack."""
        from scapy.all import IP, TCP, wrpcap

        packets = []

        segments = BypassTechniques.apply_multisplit(self.test_payload, [10, 20, 30])

        base_seq = 2000

        for payload, offset in segments:
            pkt = (
                IP(dst="192.168.1.100")
                / TCP(dport=443, seq=base_seq + offset, flags=0x18)
                / payload
            )

            packets.append(pkt)

        pcap_path = "test_multisplit.pcap"
        wrpcap(pcap_path, packets)

        return pcap_path

    def _generate_seqovl_pcap(self) -> str:
        """Generate PCAP demonstrating seqovl attack."""
        from scapy.all import IP, TCP, wrpcap

        packets = []

        segments = BypassTechniques.apply_seqovl(
            self.test_payload, split_pos=15, overlap_size=5
        )

        base_seq = 3000

        for payload, offset in segments:
            pkt = (
                IP(dst="192.168.1.100")
                / TCP(dport=443, seq=base_seq + offset, flags=0x18)
                / payload
            )

            packets.append(pkt)

        pcap_path = "test_seqovl.pcap"
        wrpcap(pcap_path, packets)

        return pcap_path

    def run_full_audit(self) -> Dict[str, Any]:
        """Run complete audit of all primitives."""
        logger.info("🚀 Starting full primitives audit...")

        audit_results = {
            "timestamp": str(Path(__file__).stat().st_mtime),
            "fakeddisorder": self.audit_fakeddisorder(),
            "multisplit_seqovl": self.audit_multisplit_seqovl(),
            "fooling_methods": self.audit_fooling_methods(),
            "other_attacks": self.audit_other_attacks(),
            "test_pcaps": self.generate_test_pcaps(),
            "summary": {},
        }

        # Generate summary
        total_tests = 0
        passed_tests = 0
        all_issues = []

        for category, results in audit_results.items():
            if category in ["timestamp", "summary"]:
                continue

            if isinstance(results, dict):
                for test_name, test_result in results.items():
                    if isinstance(test_result, dict) and "passed" in test_result:
                        total_tests += 1
                        if test_result["passed"]:
                            passed_tests += 1
                        if "issues" in test_result:
                            all_issues.extend(test_result["issues"])
                    elif isinstance(test_result, list):
                        for item in test_result:
                            if isinstance(item, dict) and "passed" in item:
                                total_tests += 1
                                if item["passed"]:
                                    passed_tests += 1
                                if "issues" in item:
                                    all_issues.extend(item["issues"])

        audit_results["summary"] = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "success_rate": (
                f"{(passed_tests/total_tests*100):.1f}%" if total_tests > 0 else "0%"
            ),
            "total_issues": len(all_issues),
            "critical_issues": [
                issue for issue in all_issues if "TTL" in issue or "checksum" in issue
            ],
        }

        logger.info(f"✅ Audit completed: {passed_tests}/{total_tests} tests passed")

        return audit_results


def main():
    """Main function to run the audit."""
    auditor = PrimitivesAuditor()
    results = auditor.run_full_audit()

    # Save results to file
    import json

    output_file = "primitives_audit_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print("\n📊 Audit Results Summary:")
    print(f"Total Tests: {results['summary']['total_tests']}")
    print(f"Passed: {results['summary']['passed_tests']}")
    print(f"Failed: {results['summary']['failed_tests']}")
    print(f"Success Rate: {results['summary']['success_rate']}")
    print(f"Total Issues: {results['summary']['total_issues']}")
    print(f"Critical Issues: {len(results['summary']['critical_issues'])}")

    if results["summary"]["critical_issues"]:
        print("\n🚨 Critical Issues Found:")
        for issue in results["summary"]["critical_issues"]:
            print(f"  - {issue}")

    print(f"\n📄 Full results saved to: {output_file}")

    return results


if __name__ == "__main__":
    main()
