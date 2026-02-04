#!/usr/bin/env python3
"""
Comprehensive audit and validation of attack primitives.

This module performs a thorough analysis of all attack primitives in primitives.py
to ensure their theoretical and practical correctness.
"""

import sys
import logging
from typing import Dict, Any
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    import scapy.all  # noqa: F401

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. PCAP analysis will be limited.")

from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.techniques.primitives_validators import (
    validate_segment_count,
    validate_fake_segment,
    validate_real_segment,
    validate_overlap_offsets,
    validate_fooling_options,
)
from core.bypass.techniques.pcap_analyzer import compare_pcap_files
from core.bypass.techniques.fooling_testers import (
    create_mock_tcp_packet,
    test_badsum_fooling,
    test_md5sig_fooling,
)
from core.bypass.techniques.pcap_generator import generate_test_pcaps

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class PrimitivesAuditor:
    """Orchestrates attack primitives validation."""

    def __init__(self):
        self.results = {}
        self.test_payload = (
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        )
        self.tls_payload = (
            b"\x16\x03\x01\x00\xf4"  # TLS Record Header
            b"\x01\x00\x00\xf0"  # Handshake Header
            b"\x03\x03"  # Version: TLS 1.2
            + b"\x00" * 32  # Random
            + b"\x00"  # Session ID Length
            + b"\x00\x02\x13\x01"  # Cipher Suites
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
            pcap_result = compare_pcap_files()
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
        issues.extend(validate_segment_count(segments, 2))

        # Validate fake segment
        if len(segments) >= 1:
            issues.extend(
                validate_fake_segment(
                    segments[0],
                    expected_ttl=64,
                    expected_offset=0,
                    expected_payload=self.test_payload[:10],
                )
            )

        # Validate real segment
        if len(segments) >= 2:
            issues.extend(
                validate_real_segment(
                    segments[1], expected_offset=10, expected_payload=self.test_payload[10:]
                )
            )

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
        issues.extend(validate_segment_count(segments, 2))

        # Validate overlap logic
        if len(segments) >= 2:
            issues.extend(
                validate_overlap_offsets(segments[0], segments[1], split_pos=20, overlap_size=5)
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
            _, _, fake_opts = segments[0]
            issues.extend(validate_fooling_options(fake_opts, ["badsum", "md5sig", "badseq"]))

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
            issues.append("Should return single segment when split_pos >= payload length")
        elif segments1[0][2].get("is_fake", True):
            issues.append("Single segment should not be fake when split_pos >= payload length")

        # Test 2: overlap_size > split_pos
        segments2 = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload, split_pos=10, overlap_size=15, fake_ttl=64
        )

        if len(segments2) >= 1:
            fake_offset = segments2[0][1]
            if fake_offset != 0:
                issues.append(f"Overlap clamping failed: expected offset=0, got {fake_offset}")

        # Test 3: negative overlap_size
        segments3 = BypassTechniques.apply_fakeddisorder(
            payload=self.test_payload, split_pos=10, overlap_size=-5, fake_ttl=64
        )

        if len(segments3) >= 1:
            fake_offset = segments3[0][1]
            if fake_offset != 0:
                issues.append(
                    f"Negative overlap handling failed: expected offset=0, got {fake_offset}"
                )

        return {"name": test_name, "issues": issues, "passed": len(issues) == 0}

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

        if len(segments) != 4:  # Should create 4 segments
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

        return {"name": "multisplit", "issues": issues, "passed": len(issues) == 0}

    def _test_seqovl(self) -> Dict[str, Any]:
        """Test seqovl attack."""
        logger.info("  Testing seqovl...")

        issues = []

        segments = BypassTechniques.apply_seqovl(self.test_payload, split_pos=10, overlap_size=5)

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
            expected_part1 = b"\x00" * 5 + self.test_payload[:10]
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
        mock_packet = create_mock_tcp_packet()

        # Test badsum fooling
        badsum_result = test_badsum_fooling(mock_packet.copy())
        results["badsum_test"] = badsum_result

        # Test md5sig fooling
        md5sig_result = test_md5sig_fooling(mock_packet.copy())
        results["md5sig_test"] = md5sig_result

        return results

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

        if result == self.tls_payload:
            issues.append("TLS record was not split")

        # Test with invalid payload (should return unchanged)
        invalid_payload = b"Not a TLS record"
        result_invalid = BypassTechniques.apply_tlsrec_split(invalid_payload, split_pos=5)

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
        segments = BypassTechniques.apply_wssize_limit(self.test_payload, window_size=10)

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
                issues.append(f"Segment {i} offset mismatch: expected {i * 10}, got {offset}")

        # Test with window size 1
        segments_1 = BypassTechniques.apply_wssize_limit(self.test_payload, window_size=1)
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

        return generate_test_pcaps(self.test_payload)

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
        summary = self._generate_summary(audit_results)
        audit_results["summary"] = summary

        logger.info(
            f"✅ Audit completed: {summary['passed_tests']}/{summary['total_tests']} tests passed"
        )

        return audit_results

    def _generate_summary(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics from audit results."""
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

        return {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "success_rate": f"{(passed_tests/total_tests*100):.1f}%" if total_tests > 0 else "0%",
            "total_issues": len(all_issues),
            "critical_issues": [
                issue for issue in all_issues if "TTL" in issue or "checksum" in issue
            ],
        }


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
    print(f"Total: {results['summary']['total_tests']}")
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
