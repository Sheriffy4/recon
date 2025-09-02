"""
Comprehensive tests for the MultiPortHandler implementation.
Tests all aspects of multi-port and protocol support functionality.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from core.bypass.protocols.multi_port_handler import (
    MultiPortHandler,
    ProtocolFamily,
    PortStrategy,
    PortTestResult,
    BypassResult,
)
from core.bypass.types import BlockType
from core.bypass.attacks.attack_definition import (
    AttackDefinition,
    AttackCategory,
    AttackComplexity,
    AttackStability,
)


class TestMultiPortHandler:
    """Test suite for MultiPortHandler functionality."""

    @pytest.fixture
    def handler(self):
        """Create a MultiPortHandler instance for testing."""
        return MultiPortHandler()

    @pytest.fixture
    def sample_attacks(self):
        """Create sample attack definitions for testing."""
        attacks = []
        http_attack = AttackDefinition(
            id="http_host_header_case",
            name="HTTP Host Header Case Manipulation",
            description="Manipulate case of HTTP Host header",
            category=AttackCategory.HTTP_MANIPULATION,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
            supported_protocols=["tcp"],
            supported_ports=[80, 443],
            effectiveness_score=0.8,
        )
        attacks.append(http_attack)
        tls_attack = AttackDefinition(
            id="tls_sni_fragmentation",
            name="TLS SNI Fragmentation",
            description="Fragment TLS SNI extension",
            category=AttackCategory.TLS_EVASION,
            complexity=AttackComplexity.MODERATE,
            stability=AttackStability.STABLE,
            supported_protocols=["tcp"],
            supported_ports=[443],
            effectiveness_score=0.9,
        )
        attacks.append(tls_attack)
        dns_attack = AttackDefinition(
            id="dns_fragmentation",
            name="DNS Query Fragmentation",
            description="Fragment DNS queries",
            category=AttackCategory.DNS_TUNNELING,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
            supported_protocols=["udp"],
            supported_ports=[53],
            effectiveness_score=0.7,
        )
        attacks.append(dns_attack)
        return attacks

    def test_initialization(self, handler):
        """Test MultiPortHandler initialization."""
        assert handler is not None
        assert len(handler.port_strategies) >= 3
        assert 80 in handler.port_strategies
        assert 443 in handler.port_strategies
        assert 53 in handler.port_strategies
        assert ProtocolFamily.HTTP_FAMILY in handler.protocol_attacks
        assert ProtocolFamily.SECURE_FAMILY in handler.protocol_attacks
        assert ProtocolFamily.DNS_FAMILY in handler.protocol_attacks
        assert handler.stats["ports_tested"] == 0
        assert handler.stats["strategies_applied"] == 0

    def test_port_strategy_configuration(self, handler):
        """Test port strategy configurations."""
        http_strategy = handler.get_port_strategy(80)
        assert http_strategy.port == 80
        assert http_strategy.protocol_family == ProtocolFamily.HTTP_FAMILY
        assert not http_strategy.requires_tls
        assert not http_strategy.supports_sni
        assert http_strategy.validation_method == "http_response"
        https_strategy = handler.get_port_strategy(443)
        assert https_strategy.port == 443
        assert https_strategy.protocol_family == ProtocolFamily.SECURE_FAMILY
        assert https_strategy.requires_tls
        assert https_strategy.supports_sni
        assert https_strategy.validation_method == "tls_handshake"
        dns_strategy = handler.get_port_strategy(53)
        assert dns_strategy.port == 53
        assert dns_strategy.protocol_family == ProtocolFamily.DNS_FAMILY
        assert dns_strategy.validation_method == "dns_query"

    def test_unknown_port_strategy(self, handler):
        """Test strategy creation for unknown ports."""
        system_port_strategy = handler.get_port_strategy(22)
        assert system_port_strategy.port == 22
        assert system_port_strategy.protocol_family == ProtocolFamily.SECURE_FAMILY
        user_port_strategy = handler.get_port_strategy(8080)
        assert user_port_strategy.port == 8080
        assert user_port_strategy.protocol_family == ProtocolFamily.PLAIN_FAMILY

    def test_add_remove_port_strategy(self, handler):
        """Test adding and removing port strategies."""
        custom_strategy = PortStrategy(
            port=8443,
            protocol_family=ProtocolFamily.SECURE_FAMILY,
            preferred_attacks=["custom_attack"],
            requires_tls=True,
        )
        handler.add_port_strategy(8443, custom_strategy)
        assert 8443 in handler.port_strategies
        assert handler.get_port_strategy(8443) == custom_strategy
        removed = handler.remove_port_strategy(8443)
        assert removed is True
        assert 8443 not in handler.port_strategies
        removed = handler.remove_port_strategy(9999)
        assert removed is False

    @pytest.mark.asyncio
    async def test_http_port_testing(self, handler):
        """Test HTTP port accessibility testing."""
        with patch("asyncio.open_connection") as mock_connect:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_reader.read.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
            mock_connect.return_value = (mock_reader, mock_writer)
            result = await handler._test_http_port("example.com", 80)
            assert result.port == 80
            assert result.accessible is True
            assert result.protocol_detected == "http"
            assert result.server_header == "nginx"
            assert result.block_type == BlockType.NONE

    @pytest.mark.asyncio
    async def test_https_port_testing(self, handler):
        """Test HTTPS port accessibility testing."""
        with patch("asyncio.open_connection") as mock_connect:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_ssl_object = MagicMock()
            mock_ssl_object.version.return_value = "TLSv1.3"
            mock_writer.get_extra_info.return_value = mock_ssl_object
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            result = await handler._test_https_port("example.com", 443)
            assert result.port == 443
            assert result.accessible is True
            assert result.protocol_detected == "https"
            assert result.tls_version == "TLSv1.3"
            assert result.block_type == BlockType.NONE

    @pytest.mark.asyncio
    async def test_connection_timeout(self, handler):
        """Test connection timeout handling."""
        with patch("asyncio.open_connection") as mock_connect:
            mock_connect.side_effect = asyncio.TimeoutError()
            result = await handler._test_http_port("blocked.example.com", 80)
            assert result.port == 80
            assert result.accessible is False
            assert result.error_message == "Connection timeout"
            assert result.block_type == BlockType.TIMEOUT

    @pytest.mark.asyncio
    async def test_connection_refused(self, handler):
        """Test connection refused handling."""
        with patch("asyncio.open_connection") as mock_connect:
            mock_connect.side_effect = ConnectionRefusedError()
            result = await handler._test_http_port("refused.example.com", 80)
            assert result.port == 80
            assert result.accessible is False
            assert result.error_message == "Connection refused"
            assert result.block_type == BlockType.CONNECTION_REFUSED

    @pytest.mark.asyncio
    async def test_domain_accessibility_testing(self, handler):
        """Test comprehensive domain accessibility testing."""
        with patch.object(handler, "_test_single_port") as mock_test:
            mock_test.side_effect = [
                PortTestResult(
                    port=80,
                    accessible=True,
                    response_time_ms=100.0,
                    block_type=BlockType.NONE,
                ),
                PortTestResult(
                    port=443,
                    accessible=False,
                    response_time_ms=5000.0,
                    block_type=BlockType.TIMEOUT,
                ),
            ]
            results = await handler.test_domain_accessibility("example.com", [80, 443])
            assert len(results) == 2
            assert results[80].accessible is True
            assert results[443].accessible is False
            assert handler.stats["ports_tested"] == 2

    def test_attack_selection_for_port(self, handler, sample_attacks):
        """Test attack selection based on port and protocol."""
        http_attacks = handler._select_attacks_for_port(80, sample_attacks)
        http_attack_ids = [attack.id for attack in http_attacks]
        assert "http_host_header_case" in http_attack_ids
        assert "tls_sni_fragmentation" not in http_attack_ids
        https_attacks = handler._select_attacks_for_port(443, sample_attacks)
        https_attack_ids = [attack.id for attack in https_attacks]
        assert "tls_sni_fragmentation" in https_attack_ids
        assert "http_host_header_case" in https_attack_ids
        dns_attacks = handler._select_attacks_for_port(53, sample_attacks)
        dns_attack_ids = [attack.id for attack in dns_attacks]
        assert "dns_fragmentation" in dns_attack_ids
        assert "http_host_header_case" not in dns_attack_ids

    @pytest.mark.asyncio
    async def test_port_specific_strategy_application(self, handler, sample_attacks):
        """Test application of port-specific bypass strategies."""
        with patch.object(handler, "_test_single_port") as mock_test:
            mock_test.return_value = PortTestResult(
                port=443,
                accessible=True,
                response_time_ms=200.0,
                block_type=BlockType.NONE,
            )
            result = await handler.apply_port_specific_strategy(
                "example.com", 443, "test_strategy", sample_attacks
            )
            assert result.success is True
            assert result.port == 443
            assert result.strategy_used == "test_strategy"
            assert len(result.attacks_applied) > 0
            assert handler.stats["strategies_applied"] == 1
            assert handler.stats["successful_bypasses"] == 1

    @pytest.mark.asyncio
    async def test_strategy_application_failure(self, handler, sample_attacks):
        """Test strategy application when bypass fails."""
        with patch.object(handler, "_test_single_port") as mock_test:
            mock_test.return_value = PortTestResult(
                port=80,
                accessible=False,
                response_time_ms=5000.0,
                block_type=BlockType.TIMEOUT,
            )
            result = await handler.apply_port_specific_strategy(
                "blocked.example.com", 80, "test_strategy", sample_attacks
            )
            assert result.success is False
            assert result.port == 80
            assert result.strategy_used == "test_strategy"
            assert handler.stats["strategies_applied"] == 1
            assert handler.stats["successful_bypasses"] == 0

    def test_optimal_port_selection(self, handler):
        """Test optimal port selection for domains."""
        test_results = {
            80: PortTestResult(port=80, accessible=True, response_time_ms=100.0),
            443: PortTestResult(port=443, accessible=True, response_time_ms=150.0),
        }
        optimal_port = handler.get_optimal_port_for_domain("example.com", test_results)
        assert optimal_port == 443
        test_results = {
            80: PortTestResult(port=80, accessible=True, response_time_ms=100.0),
            443: PortTestResult(port=443, accessible=False, response_time_ms=5000.0),
        }
        optimal_port = handler.get_optimal_port_for_domain("example.com", test_results)
        assert optimal_port == 80
        test_results = {
            80: PortTestResult(port=80, accessible=False, response_time_ms=5000.0),
            443: PortTestResult(port=443, accessible=False, response_time_ms=5000.0),
        }
        optimal_port = handler.get_optimal_port_for_domain("example.com", test_results)
        assert optimal_port == 443

    def test_protocol_requirements_detection(self, handler):
        """Test protocol requirements detection."""
        test_results = {
            80: PortTestResult(port=80, accessible=True, response_time_ms=100.0),
            443: PortTestResult(port=443, accessible=True, response_time_ms=150.0),
            53: PortTestResult(port=53, accessible=False, response_time_ms=1000.0),
        }
        required_ports = handler.detect_protocol_requirements(
            "example.com", test_results
        )
        assert 80 in required_ports
        assert 443 in required_ports
        assert 53 not in required_ports
        test_results = {
            80: PortTestResult(
                port=80,
                accessible=False,
                response_time_ms=5000.0,
                block_type=BlockType.TIMEOUT,
            ),
            443: PortTestResult(
                port=443,
                accessible=False,
                response_time_ms=5000.0,
                block_type=BlockType.RST_INJECTION,
            ),
        }
        required_ports = handler.detect_protocol_requirements(
            "example.com", test_results
        )
        assert 80 in required_ports
        assert 443 in required_ports

    def test_cache_functionality(self, handler):
        """Test port test result caching."""
        test_result = PortTestResult(
            port=80, accessible=True, response_time_ms=100.0, block_type=BlockType.NONE
        )
        cache_key = "example.com:80"
        handler.port_test_cache[cache_key] = test_result
        assert cache_key in handler.port_test_cache
        assert handler.port_test_cache[cache_key] == test_result
        handler.clear_cache()
        assert len(handler.port_test_cache) == 0

    def test_statistics_tracking(self, handler):
        """Test statistics tracking functionality."""
        initial_stats = handler.get_stats()
        assert initial_stats["ports_tested"] == 0
        assert initial_stats["strategies_applied"] == 0
        assert initial_stats["successful_bypasses"] == 0
        assert initial_stats["success_rate"] == 0.0
        handler.stats["ports_tested"] = 10
        handler.stats["strategies_applied"] = 5
        handler.stats["successful_bypasses"] = 3
        updated_stats = handler.get_stats()
        assert updated_stats["ports_tested"] == 10
        assert updated_stats["strategies_applied"] == 5
        assert updated_stats["successful_bypasses"] == 3
        assert updated_stats["success_rate"] == 0.6
        handler.reset_stats()
        reset_stats = handler.get_stats()
        assert reset_stats["ports_tested"] == 0
        assert reset_stats["strategies_applied"] == 0
        assert reset_stats["successful_bypasses"] == 0

    def test_supported_ports_management(self, handler):
        """Test supported ports management."""
        initial_ports = handler.get_supported_ports()
        assert 80 in initial_ports
        assert 443 in initial_ports
        assert 53 in initial_ports
        custom_strategy = PortStrategy(
            port=8080, protocol_family=ProtocolFamily.HTTP_FAMILY
        )
        handler.add_port_strategy(8080, custom_strategy)
        updated_ports = handler.get_supported_ports()
        assert 8080 in updated_ports
        handler.remove_port_strategy(8080)
        final_ports = handler.get_supported_ports()
        assert 8080 not in final_ports


class TestPortStrategy:
    """Test suite for PortStrategy functionality."""

    def test_port_strategy_initialization(self):
        """Test PortStrategy initialization and post-init logic."""
        https_strategy = PortStrategy(
            port=443, protocol_family=ProtocolFamily.SECURE_FAMILY
        )
        assert https_strategy.requires_tls is True
        assert https_strategy.supports_sni is True
        assert https_strategy.validation_method == "tls_handshake"
        http_strategy = PortStrategy(
            port=80, protocol_family=ProtocolFamily.HTTP_FAMILY
        )
        assert http_strategy.requires_tls is False
        assert http_strategy.supports_sni is False
        assert http_strategy.validation_method == "http_response"
        dns_strategy = PortStrategy(port=53, protocol_family=ProtocolFamily.DNS_FAMILY)
        assert dns_strategy.validation_method == "dns_query"

    def test_port_strategy_custom_configuration(self):
        """Test custom PortStrategy configuration."""
        custom_strategy = PortStrategy(
            port=8443,
            protocol_family=ProtocolFamily.SECURE_FAMILY,
            preferred_attacks=["custom_tls_attack"],
            blocked_attacks=["unsafe_attack"],
            default_timeout=60,
            custom_headers={"X-Custom": "value"},
        )
        assert custom_strategy.port == 8443
        assert "custom_tls_attack" in custom_strategy.preferred_attacks
        assert "unsafe_attack" in custom_strategy.blocked_attacks
        assert custom_strategy.default_timeout == 60
        assert custom_strategy.custom_headers["X-Custom"] == "value"


class TestPortTestResult:
    """Test suite for PortTestResult functionality."""

    def test_port_test_result_initialization(self):
        """Test PortTestResult initialization."""
        result = PortTestResult(
            port=443,
            accessible=True,
            response_time_ms=150.0,
            protocol_detected="https",
            tls_version="TLSv1.3",
        )
        assert result.port == 443
        assert result.accessible is True
        assert result.response_time_ms == 150.0
        assert result.protocol_detected == "https"
        assert result.tls_version == "TLSv1.3"
        assert result.block_type == BlockType.NONE

    def test_port_test_result_with_block_type(self):
        """Test PortTestResult with explicit block type."""
        result = PortTestResult(
            port=80,
            accessible=False,
            response_time_ms=5000.0,
            block_type=BlockType.TIMEOUT,
            error_message="Connection timed out",
        )
        assert result.port == 80
        assert result.accessible is False
        assert result.block_type == BlockType.TIMEOUT
        assert result.error_message == "Connection timed out"


class TestBypassResult:
    """Test suite for BypassResult functionality."""

    def test_bypass_result_success(self):
        """Test successful BypassResult."""
        result = BypassResult(
            success=True,
            port=443,
            strategy_used="tls_fragmentation",
            execution_time_ms=250.0,
            attacks_applied=["tls_sni_fragmentation", "tcp_window_scaling"],
            metadata={"test_key": "test_value"},
        )
        assert result.success is True
        assert result.port == 443
        assert result.strategy_used == "tls_fragmentation"
        assert result.execution_time_ms == 250.0
        assert len(result.attacks_applied) == 2
        assert "tls_sni_fragmentation" in result.attacks_applied
        assert result.metadata["test_key"] == "test_value"

    def test_bypass_result_failure(self):
        """Test failed BypassResult."""
        result = BypassResult(
            success=False,
            port=80,
            strategy_used="http_manipulation",
            execution_time_ms=100.0,
            error_message="No suitable attacks found",
        )
        assert result.success is False
        assert result.port == 80
        assert result.error_message == "No suitable attacks found"
        assert len(result.attacks_applied) == 0


@pytest.mark.asyncio
async def test_integration_multi_port_workflow():
    """Integration test for complete multi-port workflow."""
    handler = MultiPortHandler()
    attacks = [
        AttackDefinition(
            id="http_test_attack",
            name="HTTP Test Attack",
            description="Test HTTP attack",
            category=AttackCategory.HTTP_MANIPULATION,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
            supported_protocols=["tcp"],
            supported_ports=[80, 443],
            effectiveness_score=0.8,
        ),
        AttackDefinition(
            id="tls_test_attack",
            name="TLS Test Attack",
            description="Test TLS attack",
            category=AttackCategory.TLS_EVASION,
            complexity=AttackComplexity.MODERATE,
            stability=AttackStability.STABLE,
            supported_protocols=["tcp"],
            supported_ports=[443],
            effectiveness_score=0.9,
        ),
    ]
    with patch.object(handler, "_test_single_port") as mock_test:
        mock_test.side_effect = [
            PortTestResult(
                port=80,
                accessible=True,
                response_time_ms=100.0,
                block_type=BlockType.NONE,
            ),
            PortTestResult(
                port=443,
                accessible=True,
                response_time_ms=150.0,
                block_type=BlockType.NONE,
            ),
            PortTestResult(
                port=443,
                accessible=True,
                response_time_ms=120.0,
                block_type=BlockType.NONE,
            ),
        ]
        accessibility_results = await handler.test_domain_accessibility(
            "example.com", [80, 443]
        )
        assert len(accessibility_results) == 2
        assert accessibility_results[80].accessible is True
        assert accessibility_results[443].accessible is True
        optimal_port = handler.get_optimal_port_for_domain(
            "example.com", accessibility_results
        )
        assert optimal_port == 443
        bypass_result = await handler.apply_port_specific_strategy(
            "example.com", optimal_port, "integration_test_strategy", attacks
        )
        assert bypass_result.success is True
        assert bypass_result.port == 443
        assert len(bypass_result.attacks_applied) > 0
        stats = handler.get_stats()
        assert stats["ports_tested"] == 2
        assert stats["strategies_applied"] == 1
        assert stats["successful_bypasses"] == 1
        assert stats["success_rate"] == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
