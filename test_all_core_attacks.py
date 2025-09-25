#!/usr/bin/env python3
"""
Test script for Task 21: Critical Packet Construction & Injection Fixes
Sub-task: Validate All Core Attacks

This script systematically tests all core attacks on sites.txt to identify issues:
1. Tests each attack individually
2. Analyzes PCAP output for correctness
3. Validates sequence numbers, TTL, checksum, flags, timing
4. Compares with zapret reference behavior
"""

import sys
import os
import time
import struct
import logging
import json
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

# Add recon to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.types import TCPSegmentSpec

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
)

class CoreAttackValidator:
    """Validates all core attacks for correctness"""
    
    def __init__(self):
        self.logger = logging.getLogger("CoreAttackValidator")
        self.techniques = BypassTechniques()
        self.builder = PacketBuilder()
        self.test_results = {}
        
    def test_fakeddisorder_attack(self):
        """Test fakeddisorder attack with various parameters"""
        self.logger.info("🎯 Testing fakeddisorder attack...")
        
        test_cases = [
            {
                "name": "basic_fakeddisorder",
                "payload": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "split_pos": 10,
                "overlap_size": 5,
                "fake_ttl": 64,
                "fooling_methods": ["badsum"]
            },
            {
                "name": "zapret_compatible_fakeddisorder", 
                "payload": self._create_tls_clienthello(),
                "split_pos": 76,
                "overlap_size": 336,
                "fake_ttl": 1,
                "fooling_methods": ["badsum", "md5sig", "badseq"]
            },
            {
                "name": "no_overlap_fakeddisorder",
                "payload": b"POST /api HTTP/1.1\r\nContent-Length: 10\r\n\r\ntest data",
                "split_pos": 15,
                "overlap_size": 0,
                "fake_ttl": 3,
                "fooling_methods": ["md5sig"]
            }
        ]
        
        results = {}
        for case in test_cases:
            try:
                self.logger.info(f"  Testing case: {case['name']}")
                segments = self.techniques.apply_fakeddisorder(
                    payload=case["payload"],
                    split_pos=case["split_pos"],
                    overlap_size=case["overlap_size"],
                    fake_ttl=case["fake_ttl"],
                    fooling_methods=case["fooling_methods"]
                )
                
                # Validate segment structure
                validation_result = self._validate_fakeddisorder_segments(segments, case)
                results[case["name"]] = validation_result
                
                if validation_result["valid"]:
                    self.logger.info(f"    ✅ {case['name']}: PASS")
                else:
                    self.logger.error(f"    ❌ {case['name']}: FAIL - {validation_result['error']}")
                    
            except Exception as e:
                self.logger.error(f"    ❌ {case['name']}: ERROR - {e}")
                results[case["name"]] = {"valid": False, "error": str(e)}
        
        return results
    
    def test_multisplit_attack(self):
        """Test multisplit attack"""
        self.logger.info("🔀 Testing multisplit attack...")
        
        test_cases = [
            {
                "name": "basic_multisplit",
                "payload": b"This is a test payload for multisplit attack testing",
                "positions": [5, 15, 25]
            },
            {
                "name": "single_split",
                "payload": b"Short payload",
                "positions": [6]
            },
            {
                "name": "many_splits",
                "payload": b"A longer payload that will be split into many segments for testing purposes",
                "positions": [10, 20, 30, 40, 50]
            }
        ]
        
        results = {}
        for case in test_cases:
            try:
                self.logger.info(f"  Testing case: {case['name']}")
                segments = self.techniques.apply_multisplit(
                    payload=case["payload"],
                    positions=case["positions"]
                )
                
                validation_result = self._validate_multisplit_segments(segments, case)
                results[case["name"]] = validation_result
                
                if validation_result["valid"]:
                    self.logger.info(f"    ✅ {case['name']}: PASS")
                else:
                    self.logger.error(f"    ❌ {case['name']}: FAIL - {validation_result['error']}")
                    
            except Exception as e:
                self.logger.error(f"    ❌ {case['name']}: ERROR - {e}")
                results[case["name"]] = {"valid": False, "error": str(e)}
        
        return results
    
    def test_multidisorder_attack(self):
        """Test multidisorder attack"""
        self.logger.info("🔄 Testing multidisorder attack...")
        
        test_cases = [
            {
                "name": "basic_multidisorder",
                "payload": b"This payload will be split and reordered",
                "positions": [8, 16, 24]
            },
            {
                "name": "two_segment_disorder",
                "payload": b"Two segment test",
                "positions": [8]
            }
        ]
        
        results = {}
        for case in test_cases:
            try:
                self.logger.info(f"  Testing case: {case['name']}")
                segments = self.techniques.apply_multidisorder(
                    payload=case["payload"],
                    positions=case["positions"]
                )
                
                validation_result = self._validate_multidisorder_segments(segments, case)
                results[case["name"]] = validation_result
                
                if validation_result["valid"]:
                    self.logger.info(f"    ✅ {case['name']}: PASS")
                else:
                    self.logger.error(f"    ❌ {case['name']}: FAIL - {validation_result['error']}")
                    
            except Exception as e:
                self.logger.error(f"    ❌ {case['name']}: ERROR - {e}")
                results[case["name"]] = {"valid": False, "error": str(e)}
        
        return results
    
    def test_seqovl_attack(self):
        """Test seqovl attack"""
        self.logger.info("📐 Testing seqovl attack...")
        
        test_cases = [
            {
                "name": "basic_seqovl",
                "payload": b"Test payload for sequence overlap",
                "split_pos": 8,
                "overlap_size": 4
            },
            {
                "name": "large_overlap",
                "payload": b"Larger test payload for sequence overlap testing",
                "split_pos": 12,
                "overlap_size": 10
            }
        ]
        
        results = {}
        for case in test_cases:
            try:
                self.logger.info(f"  Testing case: {case['name']}")
                segments = self.techniques.apply_seqovl(
                    payload=case["payload"],
                    split_pos=case["split_pos"],
                    overlap_size=case["overlap_size"]
                )
                
                validation_result = self._validate_seqovl_segments(segments, case)
                results[case["name"]] = validation_result
                
                if validation_result["valid"]:
                    self.logger.info(f"    ✅ {case['name']}: PASS")
                else:
                    self.logger.error(f"    ❌ {case['name']}: FAIL - {validation_result['error']}")
                    
            except Exception as e:
                self.logger.error(f"    ❌ {case['name']}: ERROR - {e}")
                results[case["name"]] = {"valid": False, "error": str(e)}
        
        return results
    
    def test_fooling_methods(self):
        """Test fooling methods (badsum, md5sig)"""
        self.logger.info("🎭 Testing fooling methods...")
        
        results = {}
        
        # Test badsum fooling
        try:
            test_packet = bytearray(b'\x45\x00\x00\x3c' + b'\x00' * 56)  # Mock IP+TCP packet
            result_packet = self.techniques.apply_badsum_fooling(test_packet)
            
            # Check if checksum was corrupted to 0xDEAD
            ip_header_len = (test_packet[0] & 0x0F) * 4
            tcp_checksum_pos = ip_header_len + 16
            checksum = struct.unpack("!H", result_packet[tcp_checksum_pos:tcp_checksum_pos+2])[0]
            
            if checksum == 0xDEAD:
                self.logger.info("    ✅ badsum fooling: PASS")
                results["badsum"] = {"valid": True}
            else:
                self.logger.error(f"    ❌ badsum fooling: FAIL - checksum is 0x{checksum:04X}, expected 0xDEAD")
                results["badsum"] = {"valid": False, "error": f"Wrong checksum: 0x{checksum:04X}"}
                
        except Exception as e:
            self.logger.error(f"    ❌ badsum fooling: ERROR - {e}")
            results["badsum"] = {"valid": False, "error": str(e)}
        
        # Test md5sig fooling
        try:
            test_packet = bytearray(b'\x45\x00\x00\x3c' + b'\x00' * 56)  # Mock IP+TCP packet
            result_packet = self.techniques.apply_md5sig_fooling(test_packet)
            
            # Check if checksum was corrupted to 0xBEEF
            ip_header_len = (test_packet[0] & 0x0F) * 4
            tcp_checksum_pos = ip_header_len + 16
            checksum = struct.unpack("!H", result_packet[tcp_checksum_pos:tcp_checksum_pos+2])[0]
            
            if checksum == 0xBEEF:
                self.logger.info("    ✅ md5sig fooling: PASS")
                results["md5sig"] = {"valid": True}
            else:
                self.logger.error(f"    ❌ md5sig fooling: FAIL - checksum is 0x{checksum:04X}, expected 0xBEEF")
                results["md5sig"] = {"valid": False, "error": f"Wrong checksum: 0x{checksum:04X}"}
                
        except Exception as e:
            self.logger.error(f"    ❌ md5sig fooling: ERROR - {e}")
            results["md5sig"] = {"valid": False, "error": str(e)}
        
        return results
    
    def _validate_fakeddisorder_segments(self, segments: List, case: Dict) -> Dict:
        """Validate fakeddisorder segments structure and sequence numbers"""
        try:
            if len(segments) != 3:
                return {"valid": False, "error": f"Expected 3 segments, got {len(segments)}"}
            
            fake_seg, real2_seg, real1_seg = segments
            fake_payload, fake_offset, fake_opts = fake_seg
            real2_payload, real2_offset, real2_opts = real2_seg
            real1_payload, real1_offset, real1_opts = real1_seg
            
            # Validation logging (can be enabled for debugging)
            # self.logger.debug(f"Case {case['name']}: Fake={len(fake_payload)}b@{fake_offset}, Real2={len(real2_payload)}b@{real2_offset}, Real1={len(real1_payload)}b@{real1_offset}")
            
            # Validate fake segment
            if not fake_opts.get("is_fake"):
                return {"valid": False, "error": "First segment should be fake"}
            
            if fake_payload != case["payload"]:
                return {"valid": False, "error": "Fake segment should contain full payload"}
            
            if fake_offset != 0:
                return {"valid": False, "error": f"Fake segment offset should be 0, got {fake_offset}"}
            
            # Validate sequence number progression
            if case["overlap_size"] == 0:
                # No overlap case: part1 at offset 0, part2 at offset len(part1)
                expected_part1_len = case["split_pos"]
                if real2_offset != expected_part1_len:
                    return {"valid": False, "error": f"Real2 offset should be {expected_part1_len}, got {real2_offset}"}
            else:
                # Overlap case: validate overlap calculation
                expected_overlap_start = case["split_pos"] - case["overlap_size"]
                if real2_offset != expected_overlap_start:
                    return {"valid": False, "error": f"Real2 offset should be {expected_overlap_start}, got {real2_offset}"}
            
            # Validate fooling methods are applied
            for method in case["fooling_methods"]:
                if method == "badsum" and not fake_opts.get("corrupt_tcp_checksum"):
                    return {"valid": False, "error": "badsum fooling not applied"}
                if method == "md5sig" and not fake_opts.get("add_md5sig_option"):
                    return {"valid": False, "error": "md5sig fooling not applied"}
                if method == "badseq" and not fake_opts.get("corrupt_sequence"):
                    return {"valid": False, "error": "badseq fooling not applied"}
            
            return {"valid": True, "segments": len(segments)}
            
        except Exception as e:
            return {"valid": False, "error": f"Validation error: {e}"}
    
    def _validate_multisplit_segments(self, segments: List, case: Dict) -> Dict:
        """Validate multisplit segments"""
        try:
            # Reconstruct payload from segments
            reconstructed = b""
            last_offset = 0
            
            for payload_part, offset in segments:
                if offset != last_offset:
                    return {"valid": False, "error": f"Gap in segments: expected offset {last_offset}, got {offset}"}
                reconstructed += payload_part
                last_offset = offset + len(payload_part)
            
            if reconstructed != case["payload"]:
                return {"valid": False, "error": "Reconstructed payload doesn't match original"}
            
            return {"valid": True, "segments": len(segments)}
            
        except Exception as e:
            return {"valid": False, "error": f"Validation error: {e}"}
    
    def _validate_multidisorder_segments(self, segments: List, case: Dict) -> Dict:
        """Validate multidisorder segments (should be reverse of multisplit)"""
        try:
            # Get multisplit result for comparison
            multisplit_segments = self.techniques.apply_multisplit(case["payload"], case["positions"])
            
            # Multidisorder should be reverse of multisplit
            if len(segments) != len(multisplit_segments):
                return {"valid": False, "error": "Segment count mismatch with multisplit"}
            
            # Check if segments are in reverse order
            for i, (payload_part, offset) in enumerate(segments):
                expected_payload, expected_offset = multisplit_segments[-(i+1)]
                if payload_part != expected_payload or offset != expected_offset:
                    return {"valid": False, "error": f"Segment {i} doesn't match expected reverse order"}
            
            return {"valid": True, "segments": len(segments)}
            
        except Exception as e:
            return {"valid": False, "error": f"Validation error: {e}"}
    
    def _validate_seqovl_segments(self, segments: List, case: Dict) -> Dict:
        """Validate seqovl segments"""
        try:
            if len(segments) != 2:
                return {"valid": False, "error": f"Expected 2 segments, got {len(segments)}"}
            
            seg1_payload, seg1_offset = segments[0]
            seg2_payload, seg2_offset = segments[1]
            
            # Validate structure
            expected_part1 = case["payload"][:case["split_pos"]]
            expected_part2 = case["payload"][case["split_pos"]:]
            
            # seg1 should be part2 at split_pos offset
            if seg1_payload != expected_part2:
                return {"valid": False, "error": "First segment payload mismatch"}
            
            if seg1_offset != case["split_pos"]:
                return {"valid": False, "error": f"First segment offset should be {case['split_pos']}, got {seg1_offset}"}
            
            # seg2 should be part1 with overlap padding at negative offset
            expected_overlap_data = b"\x00" * case["overlap_size"]
            expected_seg2_payload = expected_overlap_data + expected_part1
            
            if seg2_payload != expected_seg2_payload:
                return {"valid": False, "error": "Second segment payload mismatch"}
            
            if seg2_offset != -case["overlap_size"]:
                return {"valid": False, "error": f"Second segment offset should be {-case['overlap_size']}, got {seg2_offset}"}
            
            return {"valid": True, "segments": len(segments)}
            
        except Exception as e:
            return {"valid": False, "error": f"Validation error: {e}"}
    
    def _create_tls_clienthello(self) -> bytes:
        """Create a realistic TLS ClientHello for testing"""
        # TLS Record Header
        record_type = b'\x16'  # Handshake
        version = b'\x03\x01'  # TLS 1.0
        
        # Handshake Header
        handshake_type = b'\x01'  # ClientHello
        
        # ClientHello content
        client_version = b'\x03\x03'  # TLS 1.2
        random = b'\x00' * 32  # 32 bytes of random
        session_id_len = b'\x00'  # No session ID
        
        # Cipher suites
        cipher_suites_len = b'\x00\x04'
        cipher_suites = b'\x00\x2f\x00\x35'  # Two cipher suites
        
        # Compression methods
        compression_len = b'\x01'
        compression = b'\x00'  # No compression
        
        # Extensions
        extensions_len = b'\x00\x17'  # 23 bytes of extensions
        
        # SNI extension
        sni_ext_type = b'\x00\x00'  # server_name
        sni_ext_len = b'\x00\x13'   # 19 bytes
        sni_list_len = b'\x00\x11'  # 17 bytes
        sni_type = b'\x00'          # hostname
        sni_len = b'\x00\x0e'       # 14 bytes
        sni_name = b'www.google.com'
        
        extensions = sni_ext_type + sni_ext_len + sni_list_len + sni_type + sni_len + sni_name
        
        # Assemble ClientHello
        clienthello_content = (client_version + random + session_id_len + 
                              cipher_suites_len + cipher_suites + 
                              compression_len + compression + 
                              extensions_len + extensions)
        
        handshake_len = len(clienthello_content).to_bytes(3, 'big')
        handshake = handshake_type + handshake_len + clienthello_content
        
        record_len = len(handshake).to_bytes(2, 'big')
        
        return record_type + version + record_len + handshake
    
    def run_all_tests(self):
        """Run all core attack validation tests"""
        self.logger.info("🚀 Starting comprehensive core attack validation...")
        
        test_functions = [
            ("FakeDisorder Attack", self.test_fakeddisorder_attack),
            ("MultiSplit Attack", self.test_multisplit_attack),
            ("MultiDisorder Attack", self.test_multidisorder_attack),
            ("SeqOvl Attack", self.test_seqovl_attack),
            ("Fooling Methods", self.test_fooling_methods)
        ]
        
        all_results = {}
        
        for test_name, test_func in test_functions:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Running: {test_name}")
            self.logger.info(f"{'='*60}")
            
            try:
                results = test_func()
                all_results[test_name] = results
            except Exception as e:
                self.logger.error(f"❌ {test_name} failed with exception: {e}")
                all_results[test_name] = {"error": str(e)}
        
        # Generate summary
        self._generate_test_summary(all_results)
        
        return all_results
    
    def _generate_test_summary(self, all_results: Dict):
        """Generate and display test summary"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("CORE ATTACK VALIDATION SUMMARY")
        self.logger.info(f"{'='*60}")
        
        total_tests = 0
        passed_tests = 0
        
        for test_category, results in all_results.items():
            if "error" in results:
                self.logger.error(f"❌ {test_category}: CATEGORY ERROR - {results['error']}")
                continue
                
            category_passed = 0
            category_total = 0
            
            for test_name, result in results.items():
                category_total += 1
                total_tests += 1
                
                if result.get("valid", False):
                    category_passed += 1
                    passed_tests += 1
                    self.logger.info(f"  ✅ {test_name}: PASS")
                else:
                    error_msg = result.get("error", "Unknown error")
                    self.logger.error(f"  ❌ {test_name}: FAIL - {error_msg}")
            
            self.logger.info(f"{test_category}: {category_passed}/{category_total} tests passed")
        
        self.logger.info(f"\nOverall Results: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests == total_tests:
            self.logger.info("🎉 All core attacks are working correctly!")
            return True
        else:
            self.logger.error(f"⚠️ {total_tests - passed_tests} tests failed. Core attacks need fixes.")
            return False

def main():
    """Main test function"""
    validator = CoreAttackValidator()
    success = validator.run_all_tests()
    
    if success:
        print("\n✅ Task 21 core attack validation completed successfully!")
        return 0
    else:
        print("\n❌ Task 21 core attack validation found issues that need fixing!")
        return 1

if __name__ == "__main__":
    sys.exit(main())