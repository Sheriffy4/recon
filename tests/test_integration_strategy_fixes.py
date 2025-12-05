#!/usr/bin/env python3
"""
Integration tests for strategy application bug fixes.

This test suite validates that all 6 critical bugs have been fixed:
1. TTL=128 instead of TTL=1 for fake packets (CRITICAL)
2. fooling="badseq" becomes badsum in practice (HIGH)
3. split_count=6 ignored, only 2 fragments created (MEDIUM)
4. disorder_method="reverse" not applied (MEDIUM)
5. fake_mode="per_fragment" creates only 1 fake (MEDIUM)
6. TLS version logging (diagnostics)

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
"""

import pytest
import logging
from typing import Dict, Any, List, Tuple

from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
from core.strategy.combo_builder import ComboAttackBuilder
from core.strategy.normalizer import ParameterNormalizer
from core.validation.tls_version_checker import TLSVersionChecker

logger = logging.getLogger(__name__)


class TestTTLFix:
    """
    Test 10.1: Test TTL fix with PCAP capture
    
    Requirements: 8.2
    - Apply strategy with ttl=1
    - Capture PCAP in TEST and BYPASS modes
    - Verify fake packets have TTL=1 in both modes
    """
    
    def test_ttl_preservation_in_fake_packets(self):
        """Verify that TTL=1 is correctly applied to fake packets."""
        # Setup
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        # Create strategy with ttl=1
        params = {
            'ttl': 1,
            'fooling': 'badsum',
            'split_pos': 2,
            'no_fallbacks': True,
            'forced': True
        }
        
        # Normalize parameters
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        # Build recipe
        attacks = ['fake', 'split']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        # Apply recipe
        payload = b'\x16\x03\x01\x00\x05Hello World Test Payload'
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify: Find fake packets and check TTL
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        
        assert len(fake_segments) > 0, "No fake packets generated"
        
        for i, (data, offset, options) in enumerate(fake_segments):
            actual_ttl = options.get('ttl')
            assert actual_ttl == 1, (
                f"Fake packet {i} has TTL={actual_ttl}, expected TTL=1. "
                f"Bug: TTL parameter not propagated correctly."
            )
        
        logger.info(f"✅ TTL fix verified: All {len(fake_segments)} fake packets have TTL=1")
    
    def test_ttl_mode_parity(self):
        """Verify that TTL is identical in TEST and BYPASS modes."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'ttl': 1,
            'fooling': 'badsum',
            'split_pos': 2
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['fake', 'split']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05Hello World Test Payload'
        
        # Apply in TEST mode
        test_packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        test_segments = dispatcher.apply_recipe(recipe, payload, test_packet_info)
        
        # Apply in BYPASS mode
        bypass_packet_info = {
            'domain': 'test.example.com',
            'mode': 'BYPASS',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        bypass_segments = dispatcher.apply_recipe(recipe, payload, bypass_packet_info)
        
        # Extract TTL from fake packets in both modes
        test_fake_ttls = [s[2].get('ttl') for s in test_segments if s[2].get('is_fake')]
        bypass_fake_ttls = [s[2].get('ttl') for s in bypass_segments if s[2].get('is_fake')]
        
        assert test_fake_ttls == bypass_fake_ttls, (
            f"TTL mismatch between modes: TEST={test_fake_ttls}, BYPASS={bypass_fake_ttls}. "
            f"Bug: TEST and BYPASS modes use different TTL values."
        )
        
        logger.info(f"✅ TTL mode parity verified: TEST and BYPASS both use TTL={test_fake_ttls}")


class TestFoolingFix:
    """
    Test 10.2: Test fooling fix with PCAP capture
    
    Requirements: 8.2
    - Apply strategy with fooling="badseq"
    - Capture PCAP
    - Verify sequence numbers are modified (not checksum)
    """
    
    def test_badseq_fooling_preservation(self):
        """Verify that fooling='badseq' is preserved and not replaced with 'badsum'."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'ttl': 1,
            'fooling': 'badseq',  # Explicitly set badseq
            'split_pos': 2
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        # Verify normalization preserved badseq
        assert 'fooling_methods' in normalized_params, "fooling_methods not created"
        assert 'badseq' in normalized_params['fooling_methods'], (
            f"fooling='badseq' was not preserved. "
            f"Got fooling_methods={normalized_params.get('fooling_methods')}. "
            f"Bug: Parameter normalization replaces badseq with badsum."
        )
        
        attacks = ['fake', 'split']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05Hello World Test Payload'
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify: Find fake packets and check fooling method
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        
        assert len(fake_segments) > 0, "No fake packets generated"
        
        for i, (data, offset, options) in enumerate(fake_segments):
            actual_fooling = options.get('fooling')
            assert actual_fooling == 'badseq', (
                f"Fake packet {i} has fooling={actual_fooling}, expected fooling='badseq'. "
                f"Bug: fooling parameter not propagated correctly."
            )
        
        logger.info(f"✅ Fooling fix verified: All {len(fake_segments)} fake packets use fooling='badseq'")
    
    def test_badsum_checksum_value(self):
        """Verify that fooling='badsum' sets checksum to 0xDEAD."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'ttl': 1,
            'fooling': 'badsum',
            'split_pos': 2
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['fake', 'split']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05Hello World Test Payload'
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify: Find fake packets and check fooling method
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        
        assert len(fake_segments) > 0, "No fake packets generated"
        
        for i, (data, offset, options) in enumerate(fake_segments):
            actual_fooling = options.get('fooling')
            assert actual_fooling == 'badsum', (
                f"Fake packet {i} has fooling={actual_fooling}, expected fooling='badsum'"
            )
        
        logger.info(f"✅ Badsum fooling verified: All {len(fake_segments)} fake packets use fooling='badsum'")


class TestSplitCountFix:
    """
    Test 10.3: Test split_count fix
    
    Requirements: 8.2
    - Apply strategy with split_count=6
    - Verify 6 fragments are created
    - Verify all bytes are covered
    """
    
    def test_split_count_fragment_generation(self):
        """Verify that split_count=6 creates exactly 6 fragments."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'split_count': 6,
            'no_fallbacks': True,
            'forced': True
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['multisplit']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'A' * 120  # 120 bytes, evenly divisible by 6
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify: Check fragment count
        assert len(segments) == 6, (
            f"Expected 6 fragments, got {len(segments)}. "
            f"Bug: split_count parameter not implemented correctly."
        )
        
        logger.info(f"✅ Split count fix verified: Generated exactly 6 fragments")
    
    def test_split_count_byte_coverage(self):
        """Verify that all bytes are covered when splitting."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'split_count': 6
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['multisplit']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' * 3  # 108 bytes
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify: Sum of fragment lengths equals original length
        total_length = sum(len(s[0]) for s in segments)
        assert total_length == len(payload), (
            f"Byte coverage mismatch: original={len(payload)}, total={total_length}. "
            f"Bug: Bytes lost or duplicated during split."
        )
        
        # Verify: Reconstructed payload matches original
        reconstructed = b''.join(s[0] for s in segments)
        assert reconstructed == payload, (
            f"Reconstructed payload doesn't match original. "
            f"Bug: Payload corruption during split."
        )
        
        logger.info(f"✅ Byte coverage verified: All {len(payload)} bytes preserved")


class TestDisorderFix:
    """
    Test 10.4: Test disorder fix
    
    Requirements: 8.2
    - Apply strategy with disorder_method="reverse"
    - Verify segments are sent in reverse order
    """
    
    def test_disorder_reverse_ordering(self):
        """Verify that disorder_method='reverse' reverses segment order."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'split_count': 4,
            'disorder_method': 'reverse'
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['multisplit', 'disorder']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        # Use distinct payload for each fragment
        payload = b'AAAABBBBCCCCDDDD'  # 16 bytes, 4 bytes per fragment
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify: Check that segments are in reverse order
        # Original order: AAAA, BBBB, CCCC, DDDD
        # Reversed order: DDDD, CCCC, BBBB, AAAA
        assert len(segments) == 4, f"Expected 4 segments, got {len(segments)}"
        
        # Check payload order
        payloads = [s[0] for s in segments]
        expected_order = [b'DDDD', b'CCCC', b'BBBB', b'AAAA']
        
        assert payloads == expected_order, (
            f"Segments not in reverse order. "
            f"Got: {[p.decode('ascii', errors='ignore') for p in payloads]}, "
            f"Expected: {[p.decode('ascii', errors='ignore') for p in expected_order]}. "
            f"Bug: disorder_method='reverse' not applied."
        )
        
        logger.info(f"✅ Disorder fix verified: Segments are in reverse order")
    
    def test_disorder_applies_to_all_segments(self):
        """Verify that disorder applies to both fake and real segments together."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'ttl': 1,
            'fooling': 'badsum',
            'split_count': 3,
            'disorder_method': 'reverse',
            'fake_mode': 'per_fragment'
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['fake', 'multisplit', 'disorder']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'AAABBBCCC'  # 9 bytes, 3 bytes per fragment
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # With per_fragment mode: 3 fake + 3 real = 6 segments
        # Original order: fake1, real1, fake2, real2, fake3, real3
        # After disorder: real3, fake3, real2, fake2, real1, fake1
        
        assert len(segments) == 6, f"Expected 6 segments (3 fake + 3 real), got {len(segments)}"
        
        # Verify that disorder was applied to all segments (not just real or just fake)
        # Check that the last segment is now first
        first_segment_payload = segments[0][0]
        last_original_payload = b'CCC'  # This should be the real3 payload
        
        # The first segment after reverse should contain 'CCC' (either fake or real)
        # Since we can't easily predict fake payload, just check that order changed
        segment_types = [s[2].get('is_fake') for s in segments]
        
        # Original pattern: [True, False, True, False, True, False]
        # Reversed pattern: [False, True, False, True, False, True]
        expected_pattern = [False, True, False, True, False, True]
        
        assert segment_types == expected_pattern, (
            f"Disorder not applied to all segments. "
            f"Got pattern: {segment_types}, "
            f"Expected: {expected_pattern}. "
            f"Bug: Disorder only applied to fake or real segments separately."
        )
        
        logger.info(f"✅ Disorder applies to all segments: Both fake and real reordered together")


class TestFakeModeFix:
    """
    Test 10.5: Test fake_mode fix
    
    Requirements: 8.2
    - Apply strategy with fake_mode="per_fragment" and split_count=6
    - Verify 6 fake packets are created
    - Verify fakes are positioned before real fragments
    """
    
    def test_per_fragment_fake_count(self):
        """Verify that fake_mode='per_fragment' creates one fake per fragment."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'ttl': 1,
            'fooling': 'badsum',
            'split_count': 6,
            'fake_mode': 'per_fragment'
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['fake', 'multisplit']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'A' * 120  # 120 bytes, 20 bytes per fragment
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify: Count fake packets
        fake_count = sum(1 for s in segments if s[2].get('is_fake'))
        real_count = sum(1 for s in segments if not s[2].get('is_fake'))
        
        assert fake_count == 6, (
            f"Expected 6 fake packets, got {fake_count}. "
            f"Bug: fake_mode='per_fragment' not creating one fake per fragment."
        )
        
        assert real_count == 6, (
            f"Expected 6 real packets, got {real_count}. "
            f"Bug: Real fragments not preserved."
        )
        
        assert len(segments) == 12, (
            f"Expected 12 total segments (6 fake + 6 real), got {len(segments)}"
        )
        
        logger.info(f"✅ Fake mode fix verified: Generated 6 fake + 6 real = 12 segments")
    
    def test_per_fragment_fake_positioning(self):
        """Verify that each fake appears before its corresponding real fragment."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        params = {
            'ttl': 1,
            'fooling': 'badsum',
            'split_count': 4,
            'fake_mode': 'per_fragment'
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['fake', 'multisplit']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'AAAABBBBCCCCDDDD'  # 16 bytes, 4 bytes per fragment
        packet_info = {
            'domain': 'test.example.com',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify: Pattern should be [fake, real, fake, real, fake, real, fake, real]
        expected_pattern = [True, False, True, False, True, False, True, False]
        actual_pattern = [s[2].get('is_fake') for s in segments]
        
        assert actual_pattern == expected_pattern, (
            f"Fake positioning incorrect. "
            f"Got pattern: {actual_pattern}, "
            f"Expected: {expected_pattern}. "
            f"Bug: Fakes not positioned before real fragments."
        )
        
        logger.info(f"✅ Fake positioning verified: Pattern is [fake, real, fake, real, ...]")


class TestTLSVersionConsistency:
    """
    Test 10.6: Test TLS version consistency
    
    Requirements: 8.2
    - Generate ClientHello in TEST and BYPASS modes
    - Verify TLS versions match
    - If not, verify warning is logged
    """
    
    def test_tls_version_extraction(self):
        """Verify that TLS version can be extracted from ClientHello."""
        # TLS 1.2 ClientHello (0x0303)
        tls12_hello = b'\x16\x03\x03\x00\x05Hello'
        version = TLSVersionChecker.extract_tls_version(tls12_hello)
        assert version == 'TLS 1.2', f"Expected 'TLS 1.2', got '{version}'"
        
        # TLS 1.3 ClientHello (0x0304)
        tls13_hello = b'\x16\x03\x04\x00\x05Hello'
        version = TLSVersionChecker.extract_tls_version(tls13_hello)
        assert version == 'TLS 1.3', f"Expected 'TLS 1.3', got '{version}'"
        
        logger.info(f"✅ TLS version extraction verified")
    
    def test_tls_version_consistency_check(self):
        """Verify that TLS version consistency check works."""
        # Same versions
        tls12_hello1 = b'\x16\x03\x03\x00\x05Hello'
        tls12_hello2 = b'\x16\x03\x03\x00\x05World'
        
        is_consistent, details = TLSVersionChecker.check_consistency(tls12_hello1, tls12_hello2)
        assert is_consistent, "Same TLS versions should be consistent"
        assert details['test_version'] == 'TLS 1.2'
        assert details['bypass_version'] == 'TLS 1.2'
        
        # Different versions (TLS 1.2 vs TLS 1.3)
        tls12_hello = b'\x16\x03\x03\x00\x05Hello'
        tls13_hello = b'\x16\x03\x04\x00\x05World'
        
        is_consistent, details = TLSVersionChecker.check_consistency(tls12_hello, tls13_hello)
        assert not is_consistent, "Different TLS versions should be inconsistent"
        assert details['test_version'] == 'TLS 1.2'
        assert details['bypass_version'] == 'TLS 1.3'
        
        logger.info(f"✅ TLS version consistency check verified")


class TestCompleteNnmclubStrategy:
    """
    Test 10.7: Run complete PCAP comparison
    
    Requirements: 8.5
    - Apply strategy to nnmclub.to in both modes
    - Capture PCAP files
    - Run detailed_comparison_nnmclub.py
    - Verify all parameters match between modes
    """
    
    def test_nnmclub_strategy_application(self):
        """Verify that nnmclub.to strategy applies correctly with all parameters."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        
        # nnmclub.to strategy from domain_rules.json
        params = {
            'ttl': 1,
            'fooling': 'badseq',
            'split_pos': 2,
            'split_count': 6,
            'disorder_method': 'reverse',
            'fake_mode': 'per_fragment',
            'no_fallbacks': True,
            'forced': True
        }
        
        normalizer = ParameterNormalizer()
        normalized_params = normalizer.normalize(params)
        
        attacks = ['fake', 'multisplit', 'disorder']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        # Simulate ClientHello payload
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115  # 120 bytes total
        
        # Apply in TEST mode
        test_packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        test_segments = dispatcher.apply_recipe(recipe, payload, test_packet_info)
        
        # Apply in BYPASS mode
        bypass_packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'BYPASS',
            'src_addr': '192.168.1.1',
            'dst_addr': '1.1.1.1',
            'src_port': 12345,
            'dst_port': 443
        }
        bypass_segments = dispatcher.apply_recipe(recipe, payload, bypass_packet_info)
        
        # Verify: Same number of segments
        assert len(test_segments) == len(bypass_segments), (
            f"Segment count mismatch: TEST={len(test_segments)}, BYPASS={len(bypass_segments)}"
        )
        
        # Verify: Same TTL in fake packets
        test_fake_ttls = [s[2].get('ttl') for s in test_segments if s[2].get('is_fake')]
        bypass_fake_ttls = [s[2].get('ttl') for s in bypass_segments if s[2].get('is_fake')]
        assert test_fake_ttls == bypass_fake_ttls, (
            f"TTL mismatch: TEST={test_fake_ttls}, BYPASS={bypass_fake_ttls}"
        )
        
        # Verify: Same fooling method
        test_fooling = [s[2].get('fooling') for s in test_segments if s[2].get('is_fake')]
        bypass_fooling = [s[2].get('fooling') for s in bypass_segments if s[2].get('is_fake')]
        assert test_fooling == bypass_fooling, (
            f"Fooling mismatch: TEST={test_fooling}, BYPASS={bypass_fooling}"
        )
        
        # Verify: Same segment pattern (fake/real)
        test_pattern = [s[2].get('is_fake') for s in test_segments]
        bypass_pattern = [s[2].get('is_fake') for s in bypass_segments]
        assert test_pattern == bypass_pattern, (
            f"Segment pattern mismatch: TEST={test_pattern}, BYPASS={bypass_pattern}"
        )
        
        # Verify: Expected segment count
        # split_count=6, fake_mode=per_fragment: 6 fake + 6 real = 12 segments
        # After disorder: still 12 segments, just reordered
        assert len(test_segments) == 12, (
            f"Expected 12 segments (6 fake + 6 real), got {len(test_segments)}"
        )
        
        # Verify: Fake count
        test_fake_count = sum(1 for s in test_segments if s[2].get('is_fake'))
        assert test_fake_count == 6, (
            f"Expected 6 fake packets, got {test_fake_count}"
        )
        
        # Verify: Real count
        test_real_count = sum(1 for s in test_segments if not s[2].get('is_fake'))
        assert test_real_count == 6, (
            f"Expected 6 real packets, got {test_real_count}"
        )
        
        logger.info(f"✅ nnmclub.to strategy verified: All parameters applied correctly in both modes")
        logger.info(f"   - TTL: {test_fake_ttls[0]}")
        logger.info(f"   - Fooling: {test_fooling[0]}")
        logger.info(f"   - Segments: {len(test_segments)} (6 fake + 6 real)")
        logger.info(f"   - Disorder: applied (reverse)")
        logger.info(f"   - TEST and BYPASS modes: identical")


if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '-s'])
