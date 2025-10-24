#!/usr/bin/env python3
"""
Tests for Unified FakedDisorder Attack

Tests Task 10.1 implementation requirements:
- Configuration validation
- Special position handling
- AutoTTL testing
- Zapret compatibility mode
- Fake payload generation
- Segment creation
"""

import pytest

from core.bypass.attacks.tcp.fakeddisorder_attack import (
    FakedDisorderAttack,
    FakedDisorderConfig,
)
from core.bypass.attacks.base import AttackContext, AttackStatus


class TestFakedDisorderConfig:
    """Test configuration validation and normalization"""

    def test_default_config(self):
        """Test default configuration values"""
        config = FakedDisorderConfig()

        assert config.split_pos == 3
        assert config.ttl == 3
        assert config.fooling_methods == ["badsum"]
        assert config.zapret_compatibility is True
        assert config.split_seqovl == 0

    def test_fooling_methods_normalization(self):
        """Test fooling methods are normalized to list"""
        # String input
        config = FakedDisorderConfig(fooling_methods="badsum")
        assert config.fooling_methods == ["badsum"]

        # List input
        config = FakedDisorderConfig(fooling_methods=["badsum", "badseq"])
        assert config.fooling_methods == ["badsum", "badseq"]

        # None input
        config = FakedDisorderConfig(fooling_methods=None)
        assert config.fooling_methods == ["badsum"]

    def test_ttl_validation(self):
        """Test TTL validation and clamping"""
        # Valid TTL
        config = FakedDisorderConfig(ttl=64)
        assert config.ttl == 64

        # TTL too low (clamped)
        config = FakedDisorderConfig(ttl=0, strict_mode=False)
        assert config.ttl == 1

        # TTL too high (clamped)
        config = FakedDisorderConfig(ttl=300, strict_mode=False)
        assert config.ttl == 255

        # Strict mode raises error
        with pytest.raises(ValueError):
            FakedDisorderConfig(ttl=0, strict_mode=True)

    def test_split_pos_validation(self):
        """Test split_pos validation"""
        # Valid numeric position
        config = FakedDisorderConfig(split_pos=10)
        assert config.split_pos == 10

        # Valid special position
        config = FakedDisorderConfig(split_pos="sni")
        assert config.split_pos == "sni"

        # Invalid special position (non-strict)
        config = FakedDisorderConfig(split_pos="invalid", strict_mode=False)
        assert config.split_pos == 3  # Falls back to default

        # Invalid numeric position (clamped)
        config = FakedDisorderConfig(split_pos=0, strict_mode=False)
        assert config.split_pos == 1

    def test_split_seqovl_validation(self):
        """Test split_seqovl validation"""
        # Valid overlap
        config = FakedDisorderConfig(split_seqovl=336)
        assert config.split_seqovl == 336

        # Zero overlap (valid)
        config = FakedDisorderConfig(split_seqovl=0)
        assert config.split_seqovl == 0

        # Negative overlap (clamped)
        config = FakedDisorderConfig(split_seqovl=-10, strict_mode=False)
        assert config.split_seqovl == 0


class TestFakedDisorderAttack:
    """Test unified attack implementation"""

    @pytest.fixture
    def attack(self):
        """Create attack instance for testing"""
        config = FakedDisorderConfig()
        return FakedDisorderAttack(config=config)

    @pytest.fixture
    def context(self):
        """Create attack context for testing"""
        return AttackContext(
            connection_id="test_conn",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            src_port=12345,
            dst_port=443,
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_window_size=65535,
        )

    @pytest.mark.asyncio
    async def test_basic_execution(self, attack, context):
        """Test basic attack execution"""
        result = await attack.execute(context)

        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent > 0
        assert len(result.segments) > 0
        assert result.metadata["attack_type"] == "unified_fakeddisorder"

    @pytest.mark.asyncio
    async def test_empty_payload(self, attack):
        """Test handling of empty payload"""
        context = AttackContext(
            connection_id="test_conn",
            payload=b"",
            dst_ip="93.184.216.34",
            dst_port=443,
        )

        result = await attack.execute(context)

        assert result.status == AttackStatus.FAILURE
        assert "Empty payload" in result.error_message

    def test_split_position_calculation(self, attack):
        """Test split position calculation"""
        # Numeric position
        payload = b"A" * 100
        pos = attack._calculate_split_position(payload)
        assert pos == 3  # Default config

        # Special position: SNI
        attack.config.split_pos = "sni"
        pos = attack._calculate_split_position(payload)
        assert pos == 43  # SNI position

        # Special position: cipher
        attack.config.split_pos = "cipher"
        pos = attack._calculate_split_position(payload)
        assert pos == 11  # Cipher position

        # Special position: midsld
        attack.config.split_pos = "midsld"
        pos = attack._calculate_split_position(payload)
        assert pos == 50  # Middle of 100-byte payload

        # Short payload
        attack.config.split_pos = 200
        short_payload = b"A" * 10
        pos = attack._calculate_split_position(short_payload)
        assert pos == 5  # Falls back to middle

    @pytest.mark.asyncio
    async def test_fake_payload_generation(self, attack, context):
        """Test fake payload generation"""
        # TLS payload
        tls_payload = b"\x16\x03\x01\x00\x05hello"
        fake = await attack._generate_fake_payload(tls_payload, context)
        assert len(fake) > 0
        assert fake[0] == 0x16  # TLS record type

        # HTTP payload
        http_payload = b"GET / HTTP/1.1\r\n"
        fake = await attack._generate_fake_payload(http_payload, context)
        assert len(fake) > 0
        assert b"GET" in fake or b"HTTP" in fake

        # Custom payload
        attack.config.custom_fake_payload = b"CUSTOM"
        fake = await attack._generate_fake_payload(b"anything", context)
        assert fake == b"CUSTOM"

    @pytest.mark.asyncio
    async def test_zapret_mode_segments(self, attack, context):
        """Test segment creation in Zapret mode"""
        attack.config.zapret_compatibility = True
        attack.config.split_seqovl = 10

        segments = await attack._create_segments(context.payload, context)

        # Should have 3 segments: fake + part2 + part1
        assert len(segments) == 3

        # First segment is fake
        fake_data, fake_seq, fake_opts = segments[0]
        assert fake_opts["is_fake"] is True
        assert fake_opts["ttl"] == attack.config.fake_ttl

        # Second segment is part2 (with overlap)
        part2_data, part2_seq, part2_opts = segments[1]
        assert part2_opts.get("is_real") is True

        # Third segment is part1
        part1_data, part1_seq, part1_opts = segments[2]
        assert part1_opts.get("is_real") is True
        assert part1_seq == 0  # Part1 starts at 0

    @pytest.mark.asyncio
    async def test_standard_mode_segments(self, attack, context):
        """Test segment creation in standard mode"""
        attack.config.zapret_compatibility = False

        segments = await attack._create_segments(context.payload, context)

        # Should have 3 segments: fake + part2 + part1
        assert len(segments) == 3

        # Verify segment structure
        for data, seq, opts in segments:
            assert isinstance(data, bytes)
            assert isinstance(seq, int)
            assert isinstance(opts, dict)

    def test_fooling_methods_application(self, attack):
        """Test fooling methods are applied correctly"""
        # badsum
        attack.config.fooling_methods = ["badsum"]
        opts = attack._apply_fooling_methods()
        assert opts.get("corrupt_tcp_checksum") is True

        # badseq
        attack.config.fooling_methods = ["badseq"]
        opts = attack._apply_fooling_methods()
        assert opts.get("corrupt_sequence") is True
        assert opts.get("seq_offset") == -10000

        # md5sig
        attack.config.fooling_methods = ["md5sig"]
        opts = attack._apply_fooling_methods()
        assert opts.get("add_md5sig_option") is True

        # Multiple methods
        attack.config.fooling_methods = ["badsum", "badseq", "md5sig"]
        opts = attack._apply_fooling_methods()
        assert opts.get("corrupt_tcp_checksum") is True
        assert opts.get("corrupt_sequence") is True
        assert opts.get("add_md5sig_option") is True

    @pytest.mark.asyncio
    async def test_autottl_execution(self, attack, context):
        """Test AutoTTL testing"""
        attack.config.autottl_enabled = True
        attack.config.autottl_range = (1, 5)

        result = await attack.execute(context)

        assert result.status == AttackStatus.SUCCESS
        assert result.metadata.get("autottl_tested") is True
        assert "best_ttl" in result.metadata
        assert 1 <= result.metadata["best_ttl"] <= 5

    def test_ttl_effectiveness_evaluation(self, attack):
        """Test TTL effectiveness evaluation"""
        from core.bypass.attacks.base import AttackResult

        # Successful result
        success_result = AttackResult(status=AttackStatus.SUCCESS)
        effectiveness = attack._evaluate_ttl_effectiveness(3, success_result)
        assert effectiveness >= 0.8

        # Blocked result
        blocked_result = AttackResult(status=AttackStatus.BLOCKED)
        effectiveness = attack._evaluate_ttl_effectiveness(3, blocked_result)
        assert effectiveness < 0.5

        # Lower TTL should have higher bonus
        low_ttl_eff = attack._evaluate_ttl_effectiveness(1, success_result)
        high_ttl_eff = attack._evaluate_ttl_effectiveness(10, success_result)
        assert low_ttl_eff > high_ttl_eff


class TestLegacyConfigConversion:
    """Test conversion from legacy configurations"""

    def test_basic_legacy_config(self):
        """Test basic legacy config conversion"""
        legacy_config = {
            "split_pos": 76,
            "ttl": 1,
            "fooling": ["md5sig", "badsum"],
        }

        attack = create_from_legacy_config(legacy_config)

        assert attack.config.split_pos == 76
        assert attack.config.ttl == 1
        assert attack.config.fooling_methods == ["md5sig", "badsum"]

    def test_autottl_legacy_config(self):
        """Test legacy config with autottl"""
        legacy_config = {
            "split_pos": 3,
            "ttl": 3,
            "autottl": 10,
            "fooling": ["badsum"],
        }

        attack = create_from_legacy_config(legacy_config)

        assert attack.config.autottl_enabled is True
        assert attack.config.autottl_range == (1, 10)

    def test_zapret_legacy_config(self):
        """Test legacy config with Zapret parameters"""
        legacy_config = {
            "split_pos": 76,
            "split_seqovl": 336,
            "ttl": 1,
            "zapret_compatibility": True,
            "fooling": ["md5sig", "badsum", "badseq"],
        }

        attack = create_from_legacy_config(legacy_config)

        assert attack.config.split_seqovl == 336
        assert attack.config.zapret_compatibility is True


class TestProtocolDetection:
    """Test protocol detection for fake payload generation"""

    @pytest.fixture
    def attack(self):
        config = FakedDisorderConfig()
        return FakedDisorderAttack(config=config)

    def test_tls_detection(self, attack):
        """Test TLS payload detection"""
        tls_payload = b"\x16\x03\x01\x00\x05hello"
        assert attack._is_tls_payload(tls_payload) is True

        non_tls = b"GET / HTTP/1.1"
        assert attack._is_tls_payload(non_tls) is False

    def test_http_detection(self, attack):
        """Test HTTP payload detection"""
        http_get = b"GET / HTTP/1.1\r\n"
        assert attack._is_http_payload(http_get) is True

        http_post = b"POST /api HTTP/1.1\r\n"
        assert attack._is_http_payload(http_post) is True

        non_http = b"\x16\x03\x01\x00\x05"
        assert attack._is_http_payload(non_http) is False

    def test_tls_fake_generation(self, attack):
        """Test TLS fake payload generation"""
        fake = attack._generate_tls_fake()

        assert len(fake) > 0
        assert fake[0] == 0x16  # TLS Handshake
        assert fake[1] == 0x03  # TLS version major

    def test_http_fake_generation(self, attack):
        """Test HTTP fake payload generation"""
        fake = attack._generate_http_fake()

        assert len(fake) > 0
        assert b"GET" in fake or b"HTTP" in fake
        assert b"\r\n" in fake

    def test_quic_fake_generation(self, attack):
        """Test QUIC fake payload generation"""
        fake = attack._generate_quic_fake()

        assert len(fake) > 0
        assert fake[0] == 0xC0  # QUIC long header


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
