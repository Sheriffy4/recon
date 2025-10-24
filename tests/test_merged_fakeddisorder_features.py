#!/usr/bin/env python3
"""
Tests for Merged FakedDisorderAttack Features

This test suite validates the unified FakedDisorderAttack class in primitives.py
that combines unique features from all three fake_disorder_attack variants:

1. fake_disorder_attack.py (Current/Fixed) - Special position handling, X.COM TTL fix
2. fake_disorder_attack_original.py (Comprehensive) - AutoTTL, multiple payloads, monitoring
3. fake_disorder_attack_fixed.py (Zapret-Compatible) - Zapret defaults, enhanced TLS

Tests cover:
- Configuration validation and parameter handling
- Special position resolution (sni, cipher, midsld)
- X.COM TTL fix (CRITICAL optimization)
- Comprehensive AutoTTL testing
- Multiple fake payload types (TLS, HTTP, QUIC, WireGuard, DHT)
- Zapret compatibility mode
- Repeats functionality
- Factory methods for domain optimization
- Error handling and edge cases
"""

import pytest
from unittest.mock import patch

from core.bypass.techniques.primitives import BypassTechniques


class TestFakedDisorderAttackConfiguration:
    """Test configuration validation and initialization"""

    def test_default_configuration(self):
        """Test default configuration values match zapret defaults"""
        attack = FakedDisorderAttack()

        assert attack.split_pos == 76  # Zapret default
        assert attack.split_seqovl == 336  # Zapret default
        assert attack.ttl == 1  # Zapret default
        assert attack.autottl is None
        assert attack.repeats == 1
        assert attack.fooling_methods == ["badsum", "badseq"]
        assert attack.fake_payload_type == "PAYLOADTLS"

    def test_custom_configuration(self):
        """Test custom configuration parameters"""
        attack = FakedDisorderAttack(
            split_pos="sni",
            split_seqovl=400,
            ttl=3,
            autottl=5,
            repeats=2,
            fooling_methods=["badsum", "badseq", "md5sig"],
            fake_payload_type="HTTP",
        )

        assert attack.split_pos == "sni"
        assert attack.split_seqovl == 400
        assert attack.ttl == 3
        assert attack.autottl == 5
        assert attack.repeats == 2
        assert attack.fooling_methods == ["badsum", "badseq", "md5sig"]
        assert attack.fake_payload_type == "HTTP"

    def test_configuration_validation(self):
        """Test configuration validation with invalid parameters"""
        # Invalid split_seqovl
        with pytest.raises(ValueError, match="split_seqovl must be non-negative"):
            FakedDisorderAttack(split_seqovl=-1)

        # Invalid TTL
        with pytest.raises(ValueError, match="ttl must be between 1 and 255"):
            FakedDisorderAttack(ttl=0)

        with pytest.raises(ValueError, match="ttl must be between 1 and 255"):
            FakedDisorderAttack(ttl=256)

        # Invalid autottl
        with pytest.raises(ValueError, match="autottl must be between 1 and 10"):
            FakedDisorderAttack(autottl=0)

        with pytest.raises(ValueError, match="autottl must be between 1 and 10"):
            FakedDisorderAttack(autottl=11)

        # Invalid repeats
        with pytest.raises(ValueError, match="repeats must be >= 1"):
            FakedDisorderAttack(repeats=0)

        # Invalid fooling method
        with pytest.raises(ValueError, match="Invalid fooling method"):
            FakedDisorderAttack(fooling_methods=["invalid_method"])


class TestSpecialPositionResolution:
    """Test special position handling (from Current version)"""

    def test_sni_position_resolution(self):
        """Test SNI special position resolution"""
        attack = FakedDisorderAttack(split_pos="sni")

        # Long payload - should use position 43
        long_payload = b"A" * 100
        pos = attack._resolve_split_position(long_payload)
        assert pos == 43

        # Short payload - should use middle
        short_payload = b"A" * 20
        pos = attack._resolve_split_position(short_payload)
        assert pos == 10  # Middle of 20-byte payload

    def test_cipher_position_resolution(self):
        """Test cipher special position resolution"""
        attack = FakedDisorderAttack(split_pos="cipher")

        # Long payload - should use position 11
        long_payload = b"A" * 100
        pos = attack._resolve_split_position(long_payload)
        assert pos == 11

        # Short payload - should use middle
        short_payload = b"A" * 8
        pos = attack._resolve_split_position(short_payload)
        assert pos == 4  # Middle of 8-byte payload

    def test_midsld_position_resolution(self):
        """Test midsld special position resolution"""
        attack = FakedDisorderAttack(split_pos="midsld")

        payload = b"A" * 50
        pos = attack._resolve_split_position(payload)
        assert pos == 25  # Middle of 50-byte payload

    def test_numeric_position_resolution(self):
        """Test numeric position resolution with validation"""
        attack = FakedDisorderAttack(split_pos=10)

        # Valid position
        payload = b"A" * 50
        pos = attack._resolve_split_position(payload)
        assert pos == 10

        # Position too large - should use middle
        attack.split_pos = 100
        pos = attack._resolve_split_position(payload)
        assert pos == 25  # Middle of 50-byte payload

    def test_unknown_special_position(self):
        """Test handling of unknown special position"""
        attack = FakedDisorderAttack(split_pos="unknown")

        payload = b"A" * 40
        pos = attack._resolve_split_position(payload)
        assert pos == 20  # Should fall back to middle


class TestXComTtlFix:
    """Test X.COM TTL fix (CRITICAL optimization from Current version)"""

    def test_ttl_limitation_for_fakeddisorder(self):
        """Test TTL is limited to 3 for maximum effectiveness"""
        # TTL > 3 should be limited
        attack = FakedDisorderAttack(ttl=10)
        effective_ttl = attack._calculate_effective_ttl()
        assert effective_ttl == 3  # Limited to 3

        # TTL <= 3 should remain unchanged
        attack = FakedDisorderAttack(ttl=2)
        effective_ttl = attack._calculate_effective_ttl()
        assert effective_ttl == 2

        attack = FakedDisorderAttack(ttl=3)
        effective_ttl = attack._calculate_effective_ttl()
        assert effective_ttl == 3

    def test_autottl_effective_range(self):
        """Test AutoTTL uses effective range with TTL limitation"""
        # AutoTTL > 3 should be limited to 3
        attack = FakedDisorderAttack(ttl=1, autottl=10)
        effective_ttl = attack._calculate_effective_ttl()
        assert effective_ttl == 3  # Limited to 3 even with autottl=10

        # AutoTTL <= 3 should use autottl value
        attack = FakedDisorderAttack(ttl=1, autottl=2)
        effective_ttl = attack._calculate_effective_ttl()
        assert effective_ttl == 2


class TestFakePayloadGeneration:
    """Test multiple fake payload types (from Original version)"""

    def test_enhanced_tls_payload_generation(self):
        """Test enhanced TLS ClientHello generation"""
        attack = FakedDisorderAttack(fake_payload_type="PAYLOADTLS")

        fake_payload = attack._generate_enhanced_tls_payload()

        # Validate TLS structure
        assert len(fake_payload) > 50  # Should be substantial
        assert fake_payload[0] == 0x16  # TLS Handshake record type
        assert fake_payload[1] == 0x03  # TLS version major
        assert fake_payload[2] in [0x01, 0x02, 0x03]  # TLS version minor

        # Should contain SNI extension (google.com)
        assert b"google.com" in fake_payload

    def test_enhanced_http_payload_generation(self):
        """Test enhanced HTTP payload generation"""
        attack = FakedDisorderAttack(fake_payload_type="HTTP")

        fake_payload = attack._generate_enhanced_http_payload()

        # Validate HTTP structure
        assert len(fake_payload) > 20
        assert (
            fake_payload.startswith(b"GET ")
            or fake_payload.startswith(b"POST ")
            or fake_payload.startswith(b"HEAD ")
        )
        assert b"HTTP/1.1" in fake_payload
        assert b"Host: " in fake_payload
        assert b"\r\n\r\n" in fake_payload  # HTTP header terminator

    def test_quic_payload_generation(self):
        """Test QUIC payload generation"""
        attack = FakedDisorderAttack(fake_payload_type="QUIC")

        fake_payload = attack._generate_quic_payload()

        # Validate QUIC structure
        assert len(fake_payload) > 20
        assert fake_payload[0] & 0x80 == 0x80  # Long header bit
        # Version should be QUIC v1
        assert fake_payload[1:5] == b"\x00\x00\x00\x01"

    def test_wireguard_payload_generation(self):
        """Test WireGuard payload generation"""
        attack = FakedDisorderAttack(fake_payload_type="WIREGUARD")

        fake_payload = attack._generate_wireguard_payload()

        # Validate WireGuard structure
        assert len(fake_payload) > 100  # WireGuard handshake is substantial
        assert fake_payload[0] == 1  # Handshake Initiation message type
        assert fake_payload[1:4] == b"\x00\x00\x00"  # Reserved bytes

    def test_dht_payload_generation(self):
        """Test DHT payload generation"""
        attack = FakedDisorderAttack(fake_payload_type="DHT")

        fake_payload = attack._generate_dht_payload()

        # Validate DHT structure
        assert len(fake_payload) > 10
        # Should contain bencode structure
        assert b"d1:ad2:id20:" in fake_payload  # DHT query structure
        assert b"1:q4:ping" in fake_payload  # Ping query

    def test_custom_fake_payload(self):
        """Test custom fake payload"""
        custom_payload = b"CUSTOM_FAKE_DATA"
        attack = FakedDisorderAttack(custom_fake_payload=custom_payload)

        original_payload = b"GET / HTTP/1.1\r\n\r\n"
        fake_payload = attack._generate_fake_payload(original_payload)

        assert fake_payload == custom_payload

    def test_protocol_detection(self):
        """Test automatic protocol detection"""
        attack = FakedDisorderAttack()

        # TLS payload should generate TLS fake
        tls_payload = b"\x16\x03\x01\x00\x05hello"
        assert attack._detect_tls(tls_payload) is True
        assert attack._detect_http(tls_payload) is False

        # HTTP payload should generate HTTP fake
        http_payload = b"GET / HTTP/1.1\r\n\r\n"
        assert attack._detect_http(http_payload) is True
        assert attack._detect_tls(http_payload) is False


class TestUnifiedSegmentCreation:
    """Test unified segment creation algorithm"""

    def test_basic_segment_creation(self):
        """Test basic segment creation without overlap"""
        attack = FakedDisorderAttack(split_seqovl=0)

        payload = b"Hello, World! This is a test payload."
        fake_payload = b"FAKE_DATA"
        split_pos = 10
        ttl = 3

        segments = attack._create_unified_segments(
            payload, fake_payload, split_pos, ttl
        )

        # Should have 3 segments: fake + part2 + part1
        assert len(segments) == 3

        # Validate fake segment
        fake_data, fake_seq, fake_opts = segments[0]
        assert fake_data == fake_payload
        assert fake_seq == 0
        assert fake_opts["is_fake"] is True
        assert fake_opts["ttl"] == ttl

        # Validate part2 segment
        part2_data, part2_seq, part2_opts = segments[1]
        assert part2_data == payload[split_pos:]
        assert part2_seq == split_pos
        assert part2_opts["is_fake"] is False

        # Validate part1 segment
        part1_data, part1_seq, part1_opts = segments[2]
        assert part1_data == payload[:split_pos]
        assert part1_seq == 0
        assert part1_opts["is_fake"] is False

    def test_segment_creation_with_overlap(self):
        """Test segment creation with sequence overlap"""
        attack = FakedDisorderAttack(split_seqovl=5)

        payload = b"Hello, World! This is a test payload."
        fake_payload = b"FAKE_DATA"
        split_pos = 10
        ttl = 3

        segments = attack._create_unified_segments(
            payload, fake_payload, split_pos, ttl
        )

        # Should have 3 segments with overlap
        assert len(segments) == 3

        # Validate overlap calculation
        part2_data, part2_seq, part2_opts = segments[1]
        expected_overlap_start = split_pos - 5  # split_pos - split_seqovl
        assert part2_seq == expected_overlap_start

    def test_fooling_methods_in_segments(self):
        """Test fooling methods are applied to fake segments"""
        attack = FakedDisorderAttack(fooling_methods=["badsum", "badseq", "md5sig"])

        payload = b"Test payload"
        fake_payload = b"FAKE"

        segments = attack._create_unified_segments(payload, fake_payload, 5, 3)

        # Check fake segment has fooling methods
        fake_data, fake_seq, fake_opts = segments[0]
        assert fake_opts["is_fake"] is True
        # The fooling methods should be applied via shared helper


class TestAutoTtlTesting:
    """Test comprehensive AutoTTL testing (from Original version)"""

    def test_autottl_range_testing(self):
        """Test AutoTTL tests range of TTL values"""
        attack = FakedDisorderAttack(ttl=1, autottl=5)

        payload = b"Test payload for AutoTTL"
        fake_payload = b"FAKE_DATA"
        split_pos = 5

        # Mock the effectiveness evaluation to return predictable results
        with patch.object(attack, "_evaluate_ttl_effectiveness") as mock_eval:
            # Make TTL 3 highly effective to stop testing
            mock_eval.side_effect = lambda ttl, segments: 0.95 if ttl == 3 else 0.5

            segments = attack._execute_with_autottl(payload, fake_payload, split_pos)

            # Should have called evaluation for TTLs 1, 2, 3 (stops at 3 due to high effectiveness)
            assert mock_eval.call_count >= 3

            # Verify TTL values tested
            tested_ttls = [call[0][0] for call in mock_eval.call_args_list]
            assert 1 in tested_ttls
            assert 2 in tested_ttls
            assert 3 in tested_ttls

    def test_ttl_effectiveness_evaluation(self):
        """Test TTL effectiveness evaluation logic"""
        attack = FakedDisorderAttack()

        # Lower TTL should have higher effectiveness
        segments = []  # Mock segments

        low_ttl_eff = attack._evaluate_ttl_effectiveness(1, segments)
        mid_ttl_eff = attack._evaluate_ttl_effectiveness(5, segments)
        high_ttl_eff = attack._evaluate_ttl_effectiveness(10, segments)

        assert low_ttl_eff > mid_ttl_eff > high_ttl_eff

        # TTL <= 3 should have base effectiveness of 0.8
        ttl_3_eff = attack._evaluate_ttl_effectiveness(3, segments)
        assert ttl_3_eff >= 0.8

    def test_autottl_stops_on_high_effectiveness(self):
        """Test AutoTTL stops when highly effective TTL is found"""
        attack = FakedDisorderAttack(ttl=1, autottl=10)

        payload = b"Test payload"
        fake_payload = b"FAKE"
        split_pos = 5

        with patch.object(attack, "_evaluate_ttl_effectiveness") as mock_eval:
            # Make TTL 2 highly effective (>= 0.9)
            mock_eval.side_effect = lambda ttl, segments: 0.95 if ttl == 2 else 0.3

            segments = attack._execute_with_autottl(payload, fake_payload, split_pos)

            # Should stop at TTL 2, not test all the way to 10
            tested_ttls = [call[0][0] for call in mock_eval.call_args_list]
            assert 1 in tested_ttls
            assert 2 in tested_ttls
            # Should not test TTL 3-10 due to early stopping
            assert len(tested_ttls) <= 3


class TestRepeatsFunction:
    """Test repeats functionality (from Original version)"""

    def test_single_repeat(self):
        """Test single repeat (no additional segments)"""
        attack = FakedDisorderAttack(repeats=1)

        original_segments = [
            (b"fake", 0, {"is_fake": True}),
            (b"part2", 10, {"is_fake": False}),
            (b"part1", 0, {"is_fake": False}),
        ]

        repeated_segments = attack._apply_repeats(original_segments)

        # Should be unchanged
        assert len(repeated_segments) == 3
        assert repeated_segments == original_segments

    def test_multiple_repeats(self):
        """Test multiple repeats with minimal delays"""
        attack = FakedDisorderAttack(repeats=3)

        original_segments = [
            (b"fake", 0, {"is_fake": True, "delay_ms_after": 0}),
            (b"part2", 10, {"is_fake": False, "delay_ms_after": 1}),
            (b"part1", 0, {"is_fake": False, "delay_ms_after": 0}),
        ]

        repeated_segments = attack._apply_repeats(original_segments)

        # Should have 3 * 3 = 9 segments
        assert len(repeated_segments) == 9

        # Check repeat metadata
        repeat_segments = repeated_segments[3:]  # Skip original segments
        for i, (data, seq, opts) in enumerate(repeat_segments):
            if i < 3:  # First repeat
                assert opts["repeat_num"] == 1
                assert opts["is_repeat"] is True
                assert opts["delay_ms_after"] >= 1.0  # Should have additional delay
            elif i < 6:  # Second repeat
                assert opts["repeat_num"] == 2
                assert opts["delay_ms_after"] >= 2.0  # Should have more delay


class TestFactoryMethods:
    """Test factory methods for domain optimization"""

    def test_zapret_compatible_factory(self):
        """Test zapret-compatible factory method"""
        attack = FakedDisorderAttack.create_zapret_compatible()

        assert attack.split_pos == 76  # Zapret default
        assert attack.split_seqovl == 336  # Zapret default
        assert attack.ttl == 1  # Zapret default
        assert attack.autottl == 2
        assert attack.fooling_methods == ["badsum", "badseq"]
        assert attack.fake_payload_type == "PAYLOADTLS"

    def test_x_com_optimized_factory(self):
        """Test X.COM optimized factory method"""
        attack = FakedDisorderAttack.create_x_com_optimized()

        assert attack.split_pos == "sni"  # SNI position for TLS
        assert attack.split_seqovl == 400  # Higher overlap for X.COM
        assert attack.ttl == 3  # X.COM TTL fix
        assert attack.autottl == 3
        assert attack.repeats == 2  # More attempts for stubborn DPI
        assert attack.fooling_methods == ["badsum", "badseq"]
        assert attack.fake_payload_type == "PAYLOADTLS"

    def test_instagram_optimized_factory(self):
        """Test Instagram optimized factory method"""
        attack = FakedDisorderAttack.create_instagram_optimized()

        assert attack.split_pos == 60
        assert attack.split_seqovl == 250
        assert attack.ttl == 1
        assert attack.autottl == 2
        assert attack.repeats == 1
        assert attack.fooling_methods == ["badsum", "badseq"]
        assert attack.fake_payload_type == "PAYLOADTLS"


class TestExecutionIntegration:
    """Test full execution integration"""

    def test_basic_execution(self):
        """Test basic attack execution"""
        attack = FakedDisorderAttack()

        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

        segments = attack.execute(payload)

        # Should return list of segments
        assert isinstance(segments, list)
        assert len(segments) >= 3  # At least fake + part2 + part1

        # Validate segment structure
        for data, seq_offset, options in segments:
            assert isinstance(data, bytes)
            assert isinstance(seq_offset, int)
            assert isinstance(options, dict)

    def test_execution_with_autottl(self):
        """Test execution with AutoTTL enabled"""
        attack = FakedDisorderAttack(autottl=3)

        payload = b"Test payload for AutoTTL execution"

        with patch.object(attack, "_evaluate_ttl_effectiveness") as mock_eval:
            mock_eval.return_value = 0.7  # Moderate effectiveness

            segments = attack.execute(payload)

            assert isinstance(segments, list)
            assert len(segments) >= 3
            # AutoTTL should have been tested
            assert mock_eval.called

    def test_execution_with_repeats(self):
        """Test execution with repeats"""
        attack = FakedDisorderAttack(repeats=2)

        payload = b"Test payload for repeats"

        segments = attack.execute(payload)

        # Should have double the segments due to repeats
        assert len(segments) == 6  # 3 original + 3 repeated

        # Check for repeat metadata
        repeat_segments = segments[3:]
        for data, seq, opts in repeat_segments:
            assert opts.get("is_repeat") is True
            assert opts.get("repeat_num") == 1

    def test_execution_error_handling(self):
        """Test execution error handling"""
        attack = FakedDisorderAttack()

        # Empty payload should raise error
        with pytest.raises(ValueError, match="Empty payload"):
            attack.execute(b"")

    def test_execution_with_special_positions(self):
        """Test execution with special position values"""
        # Test SNI position
        attack = FakedDisorderAttack(split_pos="sni")
        payload = b"A" * 100

        segments = attack.execute(payload)
        assert len(segments) >= 3

        # Test cipher position
        attack = FakedDisorderAttack(split_pos="cipher")
        segments = attack.execute(payload)
        assert len(segments) >= 3

        # Test midsld position
        attack = FakedDisorderAttack(split_pos="midsld")
        segments = attack.execute(payload)
        assert len(segments) >= 3


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_very_short_payload(self):
        """Test handling of very short payloads"""
        attack = FakedDisorderAttack(split_pos=10)

        short_payload = b"Hi"
        segments = attack.execute(short_payload)

        # Should handle gracefully
        assert isinstance(segments, list)
        assert len(segments) >= 1

    def test_split_position_larger_than_payload(self):
        """Test split position larger than payload"""
        attack = FakedDisorderAttack(split_pos=100)

        payload = b"Short payload"
        pos = attack._resolve_split_position(payload)

        # Should fall back to middle
        assert pos == len(payload) // 2

    def test_zero_split_seqovl(self):
        """Test zero sequence overlap"""
        attack = FakedDisorderAttack(split_seqovl=0)

        payload = b"Test payload without overlap"
        segments = attack.execute(payload)

        # Should work without overlap
        assert len(segments) >= 3

        # Part2 should start at split_pos (no overlap)
        part2_data, part2_seq, part2_opts = segments[1]
        # The exact sequence depends on split position resolution
        assert isinstance(part2_seq, int)

    def test_single_byte_payload(self):
        """Test single byte payload"""
        attack = FakedDisorderAttack()

        payload = b"A"
        segments = attack.execute(payload)

        # Should handle gracefully
        assert isinstance(segments, list)
        # May have fewer segments due to inability to split effectively


class TestBackwardCompatibility:
    """Test backward compatibility with existing code"""

    def test_primitives_integration(self):
        """Test integration with BypassTechniques primitives"""
        # The new class should work alongside existing primitives
        payload = b"Test payload for primitives integration"

        # Test that shared helpers work
        part1, part2 = BypassTechniques._split_payload(payload, 5)
        assert part1 == payload[:5]
        assert part2 == payload[5:]

        # Test segment options creation
        opts = BypassTechniques._create_segment_options(
            is_fake=True, ttl=3, fooling_methods=["badsum"]
        )
        assert opts["is_fake"] is True
        assert opts["ttl"] == 3

    def test_existing_primitive_still_works(self):
        """Test that existing apply_fakeddisorder primitive still works"""
        payload = b"Test payload for primitive compatibility"

        segments = BypassTechniques.apply_fakeddisorder(
            payload=payload, split_pos=5, fake_ttl=3, fooling_methods=["badsum"]
        )

        # Should return segments in expected format
        assert isinstance(segments, list)
        assert len(segments) == 3  # fake + part2 + part1

        for data, seq, opts in segments:
            assert isinstance(data, bytes)
            assert isinstance(seq, int)
            assert isinstance(opts, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
