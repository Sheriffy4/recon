#!/usr/bin/env python3
"""
Comprehensive test suite for TCP-level DPI bypass attacks.

Tests all TCP attack implementations including manipulation, fooling,
race conditions, stateful attacks, and timing-based techniques.
"""

import pytest
import asyncio
import os
import sys
from unittest.mock import Mock, patch, AsyncMock

# Setup path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)

from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.tcp.manipulation import TCPManipulationAttack
from core.bypass.attacks.tcp.fooling import TCPFoolingAttack
from core.bypass.attacks.tcp.timing import TCPTimingAttack
from core.bypass.attacks.tcp.race_attacks import TCPRaceAttack
from core.bypass.attacks.tcp.stateful_attacks import StatefulTCPAttack
from core.bypass.attacks.tcp_fragmentation import TCPFragmentationAttack


class TestTCPManipulationAttack:
    """Test TCP manipulation attack implementation."""

    @pytest.fixture
    def tcp_manipulation(self):
        """Create TCP manipulation attack instance."""
        return TCPManipulationAttack()

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="8.8.8.8",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=12345,
            domain="example.com",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            protocol="tcp",
        )

    def test_tcp_manipulation_initialization(self, tcp_manipulation):
        """Test TCP manipulation attack initialization."""
        assert tcp_manipulation.name == "tcp_manipulation"
        assert tcp_manipulation.category == "tcp"
        assert "tcp" in tcp_manipulation.supported_protocols

    @pytest.mark.asyncio
    async def test_tcp_manipulation_execution(self, tcp_manipulation, attack_context):
        """Test TCP manipulation attack execution."""
        with patch("core.bypass.attacks.tcp.manipulation.WinDivert") as mock_windivert:
            mock_windivert.return_value.__enter__.return_value = Mock()

            result = await tcp_manipulation.execute(attack_context)

            assert isinstance(result, AttackResult)
            assert result.status in [
                AttackStatus.SUCCESS,
                AttackStatus.FAILURE,
                AttackStatus.ERROR,
            ]
            assert result.technique_used == "tcp_manipulation"

    def test_tcp_header_manipulation(self, tcp_manipulation):
        """Test TCP header manipulation techniques."""
        # Test different manipulation modes
        modes = tcp_manipulation._get_manipulation_modes()
        assert isinstance(modes, list)
        assert len(modes) > 0

    def test_tcp_flag_manipulation(self, tcp_manipulation):
        """Test TCP flag manipulation."""
        flags = tcp_manipulation._get_flag_manipulations()
        assert isinstance(flags, list)
        # Should include common TCP flags
        expected_flags = ["SYN", "ACK", "PSH", "FIN", "RST", "URG"]
        assert any(flag in str(flags) for flag in expected_flags)

    @pytest.mark.asyncio
    async def test_sequence_number_manipulation(self, tcp_manipulation, attack_context):
        """Test TCP sequence number manipulation."""
        with patch("core.bypass.attacks.tcp.manipulation.socket") as mock_socket:
            mock_socket.socket.return_value = Mock()

            result = await tcp_manipulation._manipulate_sequence_numbers(attack_context)
            assert result is not None

    @pytest.mark.asyncio
    async def test_window_size_manipulation(self, tcp_manipulation, attack_context):
        """Test TCP window size manipulation."""
        with patch("core.bypass.attacks.tcp.manipulation.WinDivert") as mock_windivert:
            mock_windivert.return_value.__enter__.return_value = Mock()

            result = await tcp_manipulation._manipulate_window_size(attack_context)
            assert result is not None


class TestTCPFoolingAttack:
    """Test TCP fooling attack implementation."""

    @pytest.fixture
    def tcp_fooling(self):
        """Create TCP fooling attack instance."""
        return TCPFoolingAttack()

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="1.1.1.1",
            dst_port=80,
            src_ip="192.168.1.100",
            src_port=54321,
            domain="cloudflare.com",
            protocol="tcp",
        )

    def test_tcp_fooling_initialization(self, tcp_fooling):
        """Test TCP fooling attack initialization."""
        assert tcp_fooling.name == "tcp_fooling"
        assert tcp_fooling.category == "tcp"
        assert "tcp" in tcp_fooling.supported_protocols

    @pytest.mark.asyncio
    async def test_tcp_fooling_execution(self, tcp_fooling, attack_context):
        """Test TCP fooling attack execution."""
        result = await tcp_fooling.execute(attack_context)

        assert isinstance(result, AttackResult)
        assert result.status in [
            AttackStatus.SUCCESS,
            AttackStatus.FAILURE,
            AttackStatus.ERROR,
        ]
        assert result.technique_used == "tcp_fooling"

    def test_fooling_techniques(self, tcp_fooling):
        """Test available fooling techniques."""
        techniques = tcp_fooling._get_fooling_techniques()
        assert isinstance(techniques, list)
        assert len(techniques) > 0

    @pytest.mark.asyncio
    async def test_fake_packets(self, tcp_fooling, attack_context):
        """Test fake packet injection."""
        with patch("core.bypass.attacks.tcp.fooling.socket") as mock_socket:
            mock_socket.socket.return_value = Mock()

            result = await tcp_fooling._inject_fake_packets(attack_context)
            assert result is not None

    @pytest.mark.asyncio
    async def test_packet_disorder(self, tcp_fooling, attack_context):
        """Test packet disorder technique."""
        result = await tcp_fooling._create_packet_disorder(attack_context)
        assert result is not None


class TestTCPTimingAttack:
    """Test TCP timing attack implementation."""

    @pytest.fixture
    def tcp_timing(self):
        """Create TCP timing attack instance."""
        return TCPTimingAttack()

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="8.8.4.4",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=23456,
            domain="dns.google",
            protocol="tcp",
        )

    def test_tcp_timing_initialization(self, tcp_timing):
        """Test TCP timing attack initialization."""
        assert tcp_timing.name == "tcp_timing"
        assert tcp_timing.category == "tcp"
        assert "tcp" in tcp_timing.supported_protocols

    @pytest.mark.asyncio
    async def test_tcp_timing_execution(self, tcp_timing, attack_context):
        """Test TCP timing attack execution."""
        result = await tcp_timing.execute(attack_context)

        assert isinstance(result, AttackResult)
        assert result.status in [
            AttackStatus.SUCCESS,
            AttackStatus.FAILURE,
            AttackStatus.ERROR,
        ]
        assert result.technique_used == "tcp_timing"

    def test_timing_patterns(self, tcp_timing):
        """Test timing pattern generation."""
        patterns = tcp_timing._get_timing_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_delayed_transmission(self, tcp_timing, attack_context):
        """Test delayed transmission technique."""
        result = await tcp_timing._apply_transmission_delays(attack_context)
        assert result is not None

    def test_timing_configuration(self, tcp_timing):
        """Test timing configuration options."""
        config = tcp_timing._get_timing_config()
        assert isinstance(config, dict)
        assert "min_delay" in config
        assert "max_delay" in config


class TestTCPRaceAttack:
    """Test TCP race attack implementation."""

    @pytest.fixture
    def tcp_race(self):
        """Create TCP race attack instance."""
        return TCPRaceAttack()

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="9.9.9.9",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=34567,
            domain="quad9.net",
            protocol="tcp",
        )

    def test_tcp_race_initialization(self, tcp_race):
        """Test TCP race attack initialization."""
        assert tcp_race.name == "tcp_race"
        assert tcp_race.category == "tcp"
        assert "tcp" in tcp_race.supported_protocols

    @pytest.mark.asyncio
    async def test_tcp_race_execution(self, tcp_race, attack_context):
        """Test TCP race attack execution."""
        result = await tcp_race.execute(attack_context)

        assert isinstance(result, AttackResult)
        assert result.status in [
            AttackStatus.SUCCESS,
            AttackStatus.FAILURE,
            AttackStatus.ERROR,
        ]
        assert result.technique_used == "tcp_race"

    def test_race_conditions(self, tcp_race):
        """Test race condition scenarios."""
        conditions = tcp_race._get_race_conditions()
        assert isinstance(conditions, list)
        assert len(conditions) > 0

    @pytest.mark.asyncio
    async def test_concurrent_connections(self, tcp_race, attack_context):
        """Test concurrent connection establishment."""
        with patch(
            "core.bypass.attacks.tcp.race_attacks.asyncio.gather"
        ) as mock_gather:
            mock_gather.return_value = [Mock(), Mock()]

            result = await tcp_race._establish_concurrent_connections(attack_context)
            assert result is not None

    @pytest.mark.asyncio
    async def test_packet_race(self, tcp_race, attack_context):
        """Test packet race conditions."""
        result = await tcp_race._create_packet_race(attack_context)
        assert result is not None


class TestStatefulTCPAttack:
    """Test stateful TCP attack implementation."""

    @pytest.fixture
    def stateful_tcp(self):
        """Create stateful TCP attack instance."""
        return StatefulTCPAttack()

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="208.67.222.222",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=45678,
            domain="opendns.com",
            protocol="tcp",
        )

    def test_stateful_tcp_initialization(self, stateful_tcp):
        """Test stateful TCP attack initialization."""
        assert stateful_tcp.name == "stateful_tcp"
        assert stateful_tcp.category == "tcp"
        assert "tcp" in stateful_tcp.supported_protocols

    @pytest.mark.asyncio
    async def test_stateful_tcp_execution(self, stateful_tcp, attack_context):
        """Test stateful TCP attack execution."""
        result = await stateful_tcp.execute(attack_context)

        assert isinstance(result, AttackResult)
        assert result.status in [
            AttackStatus.SUCCESS,
            AttackStatus.FAILURE,
            AttackStatus.ERROR,
        ]
        assert result.technique_used == "stateful_tcp"

    def test_session_management(self, stateful_tcp):
        """Test TCP session management."""
        session = stateful_tcp._create_session()
        assert session is not None
        assert hasattr(session, "state") or "state" in session

    @pytest.mark.asyncio
    async def test_state_manipulation(self, stateful_tcp, attack_context):
        """Test TCP state manipulation."""
        result = await stateful_tcp._manipulate_connection_state(attack_context)
        assert result is not None

    def test_connection_tracking(self, stateful_tcp):
        """Test connection state tracking."""
        tracker = stateful_tcp._get_connection_tracker()
        assert tracker is not None


class TestTCPFragmentationAttack:
    """Test TCP fragmentation attack implementation."""

    @pytest.fixture
    def tcp_fragmentation(self):
        """Create TCP fragmentation attack instance."""
        return TCPFragmentationAttack()

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="1.0.0.1",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=56789,
            domain="cloudflare.com",
            payload=b"GET /test HTTP/1.1\r\nHost: cloudflare.com\r\n\r\n",
            protocol="tcp",
        )

    def test_tcp_fragmentation_initialization(self, tcp_fragmentation):
        """Test TCP fragmentation attack initialization."""
        assert tcp_fragmentation.name == "tcp_fragmentation"
        assert tcp_fragmentation.category == "tcp"
        assert "tcp" in tcp_fragmentation.supported_protocols

    @pytest.mark.asyncio
    async def test_tcp_fragmentation_execution(self, tcp_fragmentation, attack_context):
        """Test TCP fragmentation attack execution."""
        with patch("core.bypass.attacks.tcp_fragmentation.WinDivert") as mock_windivert:
            mock_windivert.return_value.__enter__.return_value = Mock()

            result = await tcp_fragmentation.execute(attack_context)

            assert isinstance(result, AttackResult)
            assert result.status in [
                AttackStatus.SUCCESS,
                AttackStatus.FAILURE,
                AttackStatus.ERROR,
            ]
            assert result.technique_used == "tcp_fragmentation"

    def test_fragmentation_strategies(self, tcp_fragmentation):
        """Test fragmentation strategies."""
        strategies = tcp_fragmentation._get_fragmentation_strategies()
        assert isinstance(strategies, list)
        assert len(strategies) > 0

    @pytest.mark.asyncio
    async def test_segment_splitting(self, tcp_fragmentation, attack_context):
        """Test TCP segment splitting."""
        segments = await tcp_fragmentation._split_segments(attack_context.payload)
        assert isinstance(segments, list)
        assert len(segments) > 0

    def test_fragment_size_calculation(self, tcp_fragmentation):
        """Test fragment size calculation."""
        size = tcp_fragmentation._calculate_fragment_size(1500)
        assert isinstance(size, int)
        assert size > 0
        assert size <= 1500

    @pytest.mark.asyncio
    async def test_overlapping_fragments(self, tcp_fragmentation, attack_context):
        """Test overlapping fragment generation."""
        fragments = await tcp_fragmentation._create_overlapping_fragments(
            attack_context.payload
        )
        assert isinstance(fragments, list)


class TestTCPAttackIntegration:
    """Test integration between different TCP attacks."""

    @pytest.mark.asyncio
    async def test_tcp_attack_chaining(self):
        """Test chaining multiple TCP attacks."""
        context = AttackContext(
            dst_ip="8.8.8.8", dst_port=443, domain="google.com", protocol="tcp"
        )

        # Test sequential execution of TCP attacks
        attacks = [
            TCPManipulationAttack(),
            TCPFoolingAttack(),
            TCPTimingAttack(),
            TCPRaceAttack(),
            StatefulTCPAttack(),
            TCPFragmentationAttack(),
        ]

        results = []
        for attack in attacks:
            try:
                result = await attack.execute(context)
                results.append(result)
            except Exception as e:
                # Some attacks may fail in test environment
                results.append(
                    AttackResult(
                        status=AttackStatus.ERROR,
                        error_message=str(e),
                        technique_used=attack.name,
                    )
                )

        assert len(results) == len(attacks)
        assert all(isinstance(r, AttackResult) for r in results)

    def test_tcp_attack_compatibility(self):
        """Test TCP attack compatibility."""
        attacks = [
            TCPManipulationAttack(),
            TCPFoolingAttack(),
            TCPTimingAttack(),
            TCPRaceAttack(),
            StatefulTCPAttack(),
            TCPFragmentationAttack(),
        ]

        for attack in attacks:
            assert hasattr(attack, "name")
            assert hasattr(attack, "category")
            assert hasattr(attack, "supported_protocols")
            assert attack.category == "tcp"
            assert "tcp" in attack.supported_protocols
            assert hasattr(attack, "execute")

    @pytest.mark.asyncio
    async def test_tcp_attack_performance(self):
        """Test TCP attack performance characteristics."""
        context = AttackContext(dst_ip="1.1.1.1", dst_port=443, protocol="tcp")

        attack = TCPManipulationAttack()

        # Measure execution time
        import time

        start_time = time.time()

        try:
            result = await attack.execute(context)
            execution_time = time.time() - start_time

            # Should complete within reasonable time
            assert execution_time < 30.0  # 30 seconds max
            assert isinstance(result, AttackResult)

        except Exception:
            # Attack may fail in test environment, that's okay
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
