#!/usr/bin/env python3
"""
Task 11: Validate nnmclub.to strategy after fixes

This test suite validates the complete nnmclub.to strategy with all parameters:
- ttl=1
- fooling=badseq
- split_pos=2
- split_count=6
- disorder_method=reverse
- fake_mode=per_fragment

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
"""

import pytest
import logging
import json
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass

from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
from core.strategy.combo_builder import ComboAttackBuilder
from core.strategy.normalizer import ParameterNormalizer
from core.strategy.loader import StrategyLoader
from core.validation.tls_version_checker import TLSVersionChecker

logger = logging.getLogger(__name__)


# ============================================================================
# Task 11.1: Test complete nnmclub.to strategy
# ============================================================================

class TestNnmclubStrategyComplete:
    """
    Task 11.1: Test complete nnmclub.to strategy
    
    Requirements: 7.1, 7.2
    - Test with all parameters: ttl=1, fooling=badseq, split_pos=2, split_count=6, 
      disorder_method=reverse, fake_mode=per_fragment
    - Verify all parameters are applied correctly
    - Capture PCAP and analyze
    """
    
    # Expected strategy configuration from domain_rules.json
    NNMCLUB_STRATEGY = {
        'ttl': 1,
        'fooling': 'badseq',
        'split_pos': 2,
        'split_count': 6,
        'disorder_method': 'reverse',
        'fake_mode': 'per_fragment',
        'no_fallbacks': True,
        'forced': True
    }
    
    NNMCLUB_ATTACKS = ['fake', 'multisplit', 'disorder']
    
    def test_strategy_loads_from_domain_rules(self):
        """Verify nnmclub.to strategy loads correctly from domain_rules.json."""
        loader = StrategyLoader()
        loader.load_rules()
        strategy = loader.find_strategy('nnmclub.to')
        
        assert strategy is not None, "nnmclub.to strategy not found in domain_rules.json"
        
        # Strategy is a dataclass, access attributes directly
        params = strategy.params if hasattr(strategy, 'params') else strategy.get('params', {})
        attacks = strategy.attacks if hasattr(strategy, 'attacks') else strategy.get('attacks', [])
        
        # Verify key parameters exist
        assert params.get('ttl') == 1, f"Expected ttl=1, got {params.get('ttl')}"
        assert params.get('fooling') == 'badseq', f"Expected fooling=badseq, got {params.get('fooling')}"
        assert params.get('split_count') == 6, f"Expected split_count=6, got {params.get('split_count')}"
        assert params.get('disorder_method') == 'reverse', f"Expected disorder_method=reverse, got {params.get('disorder_method')}"
        assert params.get('fake_mode') == 'per_fragment', f"Expected fake_mode=per_fragment, got {params.get('fake_mode')}"
        
        # Verify attacks
        assert 'fake' in attacks, "fake attack not in attacks list"
        assert 'multisplit' in attacks, "multisplit attack not in attacks list"
        assert 'disorder' in attacks, "disorder attack not in attacks list"
        
        logger.info("✅ nnmclub.to strategy loaded correctly from domain_rules.json")
    
    def test_ttl_parameter_applied(self):
        """Verify TTL=1 is applied to all fake packets."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        normalized_params = normalizer.normalize(self.NNMCLUB_STRATEGY)
        recipe = combo_builder.build_recipe(self.NNMCLUB_ATTACKS, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115  # 120 bytes TLS-like payload
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        
        assert len(fake_segments) > 0, "No fake packets generated"
        
        for i, (data, offset, options) in enumerate(fake_segments):
            actual_ttl = options.get('ttl')
            assert actual_ttl == 1, (
                f"Fake packet {i} has TTL={actual_ttl}, expected TTL=1"
            )
        
        logger.info(f"✅ TTL=1 verified for all {len(fake_segments)} fake packets")
    
    def test_fooling_badseq_applied(self):
        """Verify fooling=badseq is applied to all fake packets."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        normalized_params = normalizer.normalize(self.NNMCLUB_STRATEGY)
        recipe = combo_builder.build_recipe(self.NNMCLUB_ATTACKS, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        
        for i, (data, offset, options) in enumerate(fake_segments):
            actual_fooling = options.get('fooling')
            assert actual_fooling == 'badseq', (
                f"Fake packet {i} has fooling={actual_fooling}, expected fooling=badseq"
            )
        
        logger.info(f"✅ fooling=badseq verified for all {len(fake_segments)} fake packets")
    
    def test_split_count_6_fragments(self):
        """Verify split_count=6 creates exactly 6 real fragments."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        normalized_params = normalizer.normalize(self.NNMCLUB_STRATEGY)
        recipe = combo_builder.build_recipe(self.NNMCLUB_ATTACKS, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115  # 120 bytes
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        real_segments = [s for s in segments if not s[2].get('is_fake')]
        
        assert len(real_segments) == 6, (
            f"Expected 6 real fragments, got {len(real_segments)}"
        )
        
        # Verify all bytes are covered
        total_bytes = sum(len(s[0]) for s in real_segments)
        assert total_bytes == len(payload), (
            f"Byte coverage mismatch: expected {len(payload)}, got {total_bytes}"
        )
        
        logger.info(f"✅ split_count=6 verified: {len(real_segments)} real fragments, {total_bytes} bytes")
    
    def test_fake_mode_per_fragment(self):
        """Verify fake_mode=per_fragment creates 6 fake packets for 6 fragments."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        normalized_params = normalizer.normalize(self.NNMCLUB_STRATEGY)
        recipe = combo_builder.build_recipe(self.NNMCLUB_ATTACKS, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        real_segments = [s for s in segments if not s[2].get('is_fake')]
        
        assert len(fake_segments) == 6, (
            f"Expected 6 fake packets (per_fragment mode), got {len(fake_segments)}"
        )
        assert len(real_segments) == 6, (
            f"Expected 6 real packets, got {len(real_segments)}"
        )
        assert len(segments) == 12, (
            f"Expected 12 total segments (6 fake + 6 real), got {len(segments)}"
        )
        
        logger.info(f"✅ fake_mode=per_fragment verified: 6 fake + 6 real = 12 segments")
    
    def test_disorder_reverse_applied(self):
        """Verify disorder_method=reverse reorders segments correctly."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        # Use a simpler strategy without disorder first to get original order
        params_no_disorder = {
            'ttl': 1,
            'fooling': 'badseq',
            'split_count': 4,
            'fake_mode': 'per_fragment'
        }
        normalized_no_disorder = normalizer.normalize(params_no_disorder)
        recipe_no_disorder = combo_builder.build_recipe(['fake', 'multisplit'], normalized_no_disorder)
        
        payload = b'AAAABBBBCCCCDDDD'  # 16 bytes, 4 bytes per fragment
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments_no_disorder = dispatcher.apply_recipe(recipe_no_disorder, payload, packet_info)
        
        # Now with disorder
        params_with_disorder = {
            'ttl': 1,
            'fooling': 'badseq',
            'split_count': 4,
            'disorder_method': 'reverse',
            'fake_mode': 'per_fragment'
        }
        normalized_with_disorder = normalizer.normalize(params_with_disorder)
        recipe_with_disorder = combo_builder.build_recipe(['fake', 'multisplit', 'disorder'], normalized_with_disorder)
        
        segments_with_disorder = dispatcher.apply_recipe(recipe_with_disorder, payload, packet_info)
        
        # Verify disorder was applied (segments should be reversed)
        assert len(segments_with_disorder) == len(segments_no_disorder), (
            "Segment count changed after disorder"
        )
        
        # Check that the pattern is reversed
        # Original: [fake, real, fake, real, fake, real, fake, real]
        # Reversed: [real, fake, real, fake, real, fake, real, fake]
        original_pattern = [s[2].get('is_fake') for s in segments_no_disorder]
        reversed_pattern = [s[2].get('is_fake') for s in segments_with_disorder]
        
        assert reversed_pattern == list(reversed(original_pattern)), (
            f"Disorder not applied correctly. "
            f"Original: {original_pattern}, "
            f"After disorder: {reversed_pattern}, "
            f"Expected: {list(reversed(original_pattern))}"
        )
        
        logger.info(f"✅ disorder_method=reverse verified: segments are reversed")
    
    def test_test_bypass_mode_parity(self):
        """Verify TEST and BYPASS modes produce identical results."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        normalized_params = normalizer.normalize(self.NNMCLUB_STRATEGY)
        recipe = combo_builder.build_recipe(self.NNMCLUB_ATTACKS, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115
        
        # TEST mode
        test_packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        test_segments = dispatcher.apply_recipe(recipe, payload, test_packet_info)
        
        # BYPASS mode
        bypass_packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'BYPASS',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        bypass_segments = dispatcher.apply_recipe(recipe, payload, bypass_packet_info)
        
        # Compare segment counts
        assert len(test_segments) == len(bypass_segments), (
            f"Segment count mismatch: TEST={len(test_segments)}, BYPASS={len(bypass_segments)}"
        )
        
        # Compare TTL values
        test_ttls = [s[2].get('ttl') for s in test_segments if s[2].get('is_fake')]
        bypass_ttls = [s[2].get('ttl') for s in bypass_segments if s[2].get('is_fake')]
        assert test_ttls == bypass_ttls, (
            f"TTL mismatch: TEST={test_ttls}, BYPASS={bypass_ttls}"
        )
        
        # Compare fooling methods
        test_fooling = [s[2].get('fooling') for s in test_segments if s[2].get('is_fake')]
        bypass_fooling = [s[2].get('fooling') for s in bypass_segments if s[2].get('is_fake')]
        assert test_fooling == bypass_fooling, (
            f"Fooling mismatch: TEST={test_fooling}, BYPASS={bypass_fooling}"
        )
        
        # Compare segment patterns
        test_pattern = [s[2].get('is_fake') for s in test_segments]
        bypass_pattern = [s[2].get('is_fake') for s in bypass_segments]
        assert test_pattern == bypass_pattern, (
            f"Pattern mismatch: TEST={test_pattern}, BYPASS={bypass_pattern}"
        )
        
        logger.info("✅ TEST and BYPASS modes produce identical results")




# ============================================================================
# Task 11.2: Document actual strategy behavior
# ============================================================================

class TestNnmclubStrategyDocumentation:
    """
    Task 11.2: Document actual strategy behavior
    
    Requirements: 7.4
    - Document what each parameter does in practice
    - Document expected PCAP output (packet count, order, TTL, fooling)
    - Add troubleshooting notes
    """
    
    def test_document_strategy_behavior(self):
        """
        Document the complete nnmclub.to strategy behavior.
        
        This test generates a detailed report of what the strategy does.
        """
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
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
        
        normalized_params = normalizer.normalize(params)
        attacks = ['fake', 'multisplit', 'disorder']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        # Use a realistic ClientHello-like payload
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115  # 120 bytes
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Generate documentation
        doc = []
        doc.append("=" * 80)
        doc.append("NNMCLUB.TO STRATEGY BEHAVIOR DOCUMENTATION")
        doc.append("=" * 80)
        doc.append("")
        doc.append("## Strategy Configuration")
        doc.append(f"  Domain: nnmclub.to")
        doc.append(f"  Attacks: {attacks}")
        doc.append(f"  Parameters:")
        for key, value in params.items():
            doc.append(f"    - {key}: {value}")
        doc.append("")
        
        doc.append("## Parameter Effects")
        doc.append("")
        doc.append("### ttl=1")
        doc.append("  - Sets IP TTL field to 1 in all fake packets")
        doc.append("  - Fake packets expire after 1 hop (before reaching DPI)")
        doc.append("  - Real packets use normal TTL (64 or 128)")
        doc.append("")
        
        doc.append("### fooling=badseq")
        doc.append("  - Modifies TCP sequence number in fake packets")
        doc.append("  - Sequence number is offset by 0x10000000")
        doc.append("  - DPI sees invalid sequence, ignores fake packet")
        doc.append("  - Alternative: badsum sets checksum to 0xDEAD")
        doc.append("")
        
        doc.append("### split_count=6")
        doc.append("  - Divides payload into 6 equal fragments")
        doc.append(f"  - For {len(payload)} byte payload: ~{len(payload)//6} bytes per fragment")
        doc.append("  - Fragments are sent as separate TCP segments")
        doc.append("  - DPI must reassemble to see full content")
        doc.append("")
        
        doc.append("### fake_mode=per_fragment")
        doc.append("  - Creates one fake packet before each real fragment")
        doc.append("  - Total: 6 fake + 6 real = 12 packets")
        doc.append("  - Pattern: [fake1, real1, fake2, real2, ...]")
        doc.append("  - Each fake has same TTL and fooling as configured")
        doc.append("")
        
        doc.append("### disorder_method=reverse")
        doc.append("  - Reverses the order of all segments")
        doc.append("  - Original: [fake1, real1, fake2, real2, ...]")
        doc.append("  - Reversed: [..., real2, fake2, real1, fake1]")
        doc.append("  - DPI sees packets out of order")
        doc.append("")
        
        doc.append("## Expected PCAP Output")
        doc.append("")
        doc.append(f"  Total packets: {len(segments)}")
        
        fake_count = sum(1 for s in segments if s[2].get('is_fake'))
        real_count = sum(1 for s in segments if not s[2].get('is_fake'))
        doc.append(f"  Fake packets: {fake_count}")
        doc.append(f"  Real packets: {real_count}")
        doc.append("")
        
        doc.append("  Packet sequence (after disorder):")
        for i, (data, offset, options) in enumerate(segments):
            pkt_type = "FAKE" if options.get('is_fake') else "REAL"
            ttl = options.get('ttl', 'default')
            fooling = options.get('fooling', 'none')
            doc.append(f"    {i+1}. [{pkt_type}] len={len(data)}, ttl={ttl}, fooling={fooling}")
        doc.append("")
        
        doc.append("## Troubleshooting Notes")
        doc.append("")
        doc.append("### If strategy fails:")
        doc.append("  1. Check PCAP to verify all parameters are applied")
        doc.append("  2. Verify TTL=1 in fake packets (not 128 or 64)")
        doc.append("  3. Verify fooling=badseq (sequence modified, not checksum)")
        doc.append("  4. Verify 6 fragments created (not 2)")
        doc.append("  5. Verify 6 fake packets (not 1)")
        doc.append("  6. Verify disorder applied (packets reversed)")
        doc.append("")
        
        doc.append("### Common issues:")
        doc.append("  - TTL=128: Hardcoded default not removed")
        doc.append("  - fooling=badsum: Parameter normalization bug")
        doc.append("  - 2 fragments: split_count ignored, using split_pos")
        doc.append("  - 1 fake: fake_mode not implemented")
        doc.append("  - No disorder: apply_disorder() not called in combo")
        doc.append("")
        
        doc.append("### TLS version mismatch:")
        doc.append("  - TEST mode may use TLS 1.2 (562 bytes ClientHello)")
        doc.append("  - BYPASS mode may use TLS 1.3 (1893 bytes ClientHello)")
        doc.append("  - This causes different TCP segmentation")
        doc.append("  - Solution: Configure TEST mode to use same TLS version")
        doc.append("")
        
        doc.append("=" * 80)
        
        # Print documentation
        documentation = "\n".join(doc)
        print(documentation)
        
        # Verify expected behavior
        assert len(segments) == 12, f"Expected 12 segments, got {len(segments)}"
        assert fake_count == 6, f"Expected 6 fake packets, got {fake_count}"
        assert real_count == 6, f"Expected 6 real packets, got {real_count}"
        
        logger.info("✅ Strategy behavior documented successfully")


# ============================================================================
# Task 11.3: Validate strategy effectiveness
# ============================================================================

class TestNnmclubStrategyEffectiveness:
    """
    Task 11.3: Validate strategy effectiveness
    
    Requirements: 7.5
    - Test connection to nnmclub.to
    - Verify no retransmissions
    - Verify connection succeeds
    - Compare with baseline (no strategy)
    
    Note: These tests validate the strategy logic, not actual network connectivity.
    Real network tests require a live environment with DPI.
    """
    
    def test_strategy_produces_valid_segments(self):
        """Verify strategy produces valid TCP segments."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        params = {
            'ttl': 1,
            'fooling': 'badseq',
            'split_count': 6,
            'disorder_method': 'reverse',
            'fake_mode': 'per_fragment'
        }
        
        normalized_params = normalizer.normalize(params)
        attacks = ['fake', 'multisplit', 'disorder']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Verify all segments have valid data
        for i, (data, offset, options) in enumerate(segments):
            assert data is not None, f"Segment {i} has None data"
            assert len(data) > 0, f"Segment {i} has empty data"
            assert isinstance(offset, int), f"Segment {i} has invalid offset type"
            assert isinstance(options, dict), f"Segment {i} has invalid options type"
        
        # Verify real segments reconstruct original payload
        real_segments = [(data, offset, options) for data, offset, options in segments 
                        if not options.get('is_fake')]
        
        # Sort by offset to reconstruct
        real_segments_sorted = sorted(real_segments, key=lambda x: x[1])
        reconstructed = b''.join(data for data, offset, options in real_segments_sorted)
        
        assert reconstructed == payload, (
            f"Reconstructed payload doesn't match original. "
            f"Original: {len(payload)} bytes, Reconstructed: {len(reconstructed)} bytes"
        )
        
        logger.info("✅ Strategy produces valid segments that reconstruct original payload")
    
    def test_fake_packets_have_correct_properties(self):
        """Verify fake packets have properties that make them invalid to DPI."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        params = {
            'ttl': 1,
            'fooling': 'badseq',
            'split_count': 6,
            'fake_mode': 'per_fragment'
        }
        
        normalized_params = normalizer.normalize(params)
        attacks = ['fake', 'multisplit']
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        
        for i, (data, offset, options) in enumerate(fake_segments):
            # Verify TTL is low (will expire before reaching destination)
            ttl = options.get('ttl')
            assert ttl is not None, f"Fake packet {i} has no TTL"
            assert ttl <= 3, f"Fake packet {i} has TTL={ttl}, should be ≤3"
            
            # Verify fooling method is set
            fooling = options.get('fooling')
            assert fooling is not None, f"Fake packet {i} has no fooling method"
            assert fooling in ['badseq', 'badsum', 'md5sig', 'none'], (
                f"Fake packet {i} has invalid fooling={fooling}"
            )
        
        logger.info(f"✅ All {len(fake_segments)} fake packets have correct properties")
    
    def test_strategy_vs_baseline_comparison(self):
        """Compare strategy output with baseline (no strategy)."""
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Baseline: simple split only (minimal strategy)
        baseline_params = {'split_pos': 2}
        baseline_normalized = normalizer.normalize(baseline_params)
        baseline_recipe = combo_builder.build_recipe(['split'], baseline_normalized)
        baseline_segments = dispatcher.apply_recipe(baseline_recipe, payload, packet_info)
        
        # With strategy
        strategy_params = {
            'ttl': 1,
            'fooling': 'badseq',
            'split_count': 6,
            'disorder_method': 'reverse',
            'fake_mode': 'per_fragment'
        }
        strategy_normalized = normalizer.normalize(strategy_params)
        strategy_attacks = ['fake', 'multisplit', 'disorder']
        strategy_recipe = combo_builder.build_recipe(strategy_attacks, strategy_normalized)
        strategy_segments = dispatcher.apply_recipe(strategy_recipe, payload, packet_info)
        
        # Compare
        print("\n" + "=" * 60)
        print("BASELINE vs STRATEGY COMPARISON")
        print("=" * 60)
        print(f"\nBaseline (no strategy):")
        print(f"  Segments: {len(baseline_segments)}")
        print(f"  Total bytes: {sum(len(s[0]) for s in baseline_segments)}")
        
        print(f"\nWith strategy:")
        print(f"  Segments: {len(strategy_segments)}")
        print(f"  Fake packets: {sum(1 for s in strategy_segments if s[2].get('is_fake'))}")
        print(f"  Real packets: {sum(1 for s in strategy_segments if not s[2].get('is_fake'))}")
        print(f"  Total bytes (real): {sum(len(s[0]) for s in strategy_segments if not s[2].get('is_fake'))}")
        
        print(f"\nStrategy effects:")
        print(f"  - Payload split into 6 fragments")
        print(f"  - 6 fake packets added (one per fragment)")
        print(f"  - All packets sent in reverse order")
        print(f"  - Fake packets have TTL=1 and badseq fooling")
        print("=" * 60)
        
        # Verify strategy adds complexity
        assert len(strategy_segments) > len(baseline_segments), (
            "Strategy should produce more segments than baseline"
        )
        
        # Verify fake packets are added
        fake_count = sum(1 for s in strategy_segments if s[2].get('is_fake'))
        assert fake_count > 0, "Strategy should add fake packets"
        
        logger.info("✅ Strategy comparison with baseline completed")


# ============================================================================
# Summary test that runs all validations
# ============================================================================

class TestNnmclubStrategySummary:
    """Summary test that validates all aspects of the nnmclub.to strategy."""
    
    def test_complete_strategy_validation(self):
        """
        Complete validation of nnmclub.to strategy.
        
        This test validates:
        1. Strategy loads correctly from domain_rules.json
        2. All parameters are applied correctly
        3. TEST and BYPASS modes produce identical results
        4. Strategy produces valid segments
        5. Fake packets have correct properties
        """
        dispatcher = UnifiedAttackDispatcher()
        combo_builder = ComboAttackBuilder()
        normalizer = ParameterNormalizer()
        loader = StrategyLoader()
        
        # 1. Load strategy from domain_rules.json
        loader.load_rules()
        strategy = loader.find_strategy('nnmclub.to')
        assert strategy is not None, "Strategy not found"
        
        params = strategy.params if hasattr(strategy, 'params') else strategy.get('params', {})
        attacks = strategy.attacks if hasattr(strategy, 'attacks') else strategy.get('attacks', [])
        
        # 2. Normalize and build recipe
        normalized_params = normalizer.normalize(params)
        recipe = combo_builder.build_recipe(attacks, normalized_params)
        
        # 3. Apply strategy
        payload = b'\x16\x03\x01\x00\x05' + b'A' * 115
        packet_info = {
            'domain': 'nnmclub.to',
            'mode': 'TEST',
            'src_addr': '192.168.1.1',
            'dst_addr': '104.21.112.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # 4. Validate results
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        real_segments = [s for s in segments if not s[2].get('is_fake')]
        
        # Print summary
        strategy_type = strategy.type if hasattr(strategy, 'type') else strategy.get('type', 'unknown')
        
        print("\n" + "=" * 60)
        print("NNMCLUB.TO STRATEGY VALIDATION SUMMARY")
        print("=" * 60)
        print(f"\nStrategy loaded: ✅")
        print(f"  Type: {strategy_type}")
        print(f"  Attacks: {attacks}")
        print(f"\nParameters applied:")
        print(f"  TTL: {params.get('ttl')} ✅" if params.get('ttl') == 1 else f"  TTL: {params.get('ttl')} ❌")
        print(f"  Fooling: {params.get('fooling')} ✅" if params.get('fooling') == 'badseq' else f"  Fooling: {params.get('fooling')} ❌")
        print(f"  Split count: {params.get('split_count')} ✅" if params.get('split_count') == 6 else f"  Split count: {params.get('split_count')} ❌")
        print(f"  Fake mode: {params.get('fake_mode')} ✅" if params.get('fake_mode') == 'per_fragment' else f"  Fake mode: {params.get('fake_mode')} ❌")
        print(f"  Disorder: {params.get('disorder_method')} ✅" if params.get('disorder_method') == 'reverse' else f"  Disorder: {params.get('disorder_method')} ❌")
        print(f"\nSegments generated:")
        print(f"  Total: {len(segments)}")
        print(f"  Fake: {len(fake_segments)}")
        print(f"  Real: {len(real_segments)}")
        print(f"\nValidation:")
        
        # Validate TTL
        ttl_ok = all(s[2].get('ttl') == 1 for s in fake_segments)
        print(f"  TTL=1 in fake packets: {'✅' if ttl_ok else '❌'}")
        
        # Validate fooling
        fooling_ok = all(s[2].get('fooling') == 'badseq' for s in fake_segments)
        print(f"  Fooling=badseq in fake packets: {'✅' if fooling_ok else '❌'}")
        
        # Validate segment counts
        count_ok = len(fake_segments) == 6 and len(real_segments) == 6
        print(f"  6 fake + 6 real segments: {'✅' if count_ok else '❌'}")
        
        # Validate byte coverage
        total_bytes = sum(len(s[0]) for s in real_segments)
        bytes_ok = total_bytes == len(payload)
        print(f"  All bytes covered: {'✅' if bytes_ok else '❌'}")
        
        print("=" * 60)
        
        # Assert all validations pass
        assert ttl_ok, "TTL validation failed"
        assert fooling_ok, "Fooling validation failed"
        assert count_ok, "Segment count validation failed"
        assert bytes_ok, "Byte coverage validation failed"
        
        logger.info("✅ Complete nnmclub.to strategy validation passed")


if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '-s'])
