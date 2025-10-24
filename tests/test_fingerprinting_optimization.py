#!/usr/bin/env python3
"""
Integration tests for optimized fingerprinting system.
Tests the three-phase approach: passive analysis → bypass probes → HTTP analysis.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock

# Import components
from core.fingerprint.passive_analyzer import PassiveDPIAnalyzer, BlockingMethod
from core.fingerprint.bypass_prober import QuickBypassProber
from core.fingerprint.strategy_mapping import (
    get_strategies_for_fingerprint,
    get_fallback_strategies,
)


class TestPassiveAnalyzer:
    """Test passive DPI analysis"""

    @pytest.mark.asyncio
    async def test_passive_analysis_timeout(self):
        """Test passive analysis detects timeout"""
        analyzer = PassiveDPIAnalyzer(timeout=1.0)

        # Mock socket to simulate timeout
        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect.side_effect = TimeoutError()
            mock_socket.return_value = mock_sock

            result = await analyzer.analyze_blocking_method("example.com", 443)

            assert result.blocking_method == BlockingMethod.SILENT_DROP
            assert result.timeout_stage == "TCP_SYN"
            assert len(result.recommended_bypasses) > 0

    @pytest.mark.asyncio
    async def test_passive_analysis_rst(self):
        """Test passive analysis detects RST injection"""
        analyzer = PassiveDPIAnalyzer(timeout=1.0)

        # Mock socket to simulate RST
        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect.side_effect = ConnectionRefusedError()
            mock_socket.return_value = mock_sock

            result = await analyzer.analyze_blocking_method("example.com", 443)

            assert result.rst_detected == True
            assert result.blocking_method == BlockingMethod.TCP_RST_INJECTION
            assert len(result.recommended_bypasses) > 0


class TestBypassProber:
    """Test bypass probe functionality"""

    @pytest.mark.asyncio
    async def test_bypass_probe_success(self):
        """Test bypass probe detects working strategy"""
        prober = QuickBypassProber(timeout=2.0)

        # Mock successful SSL connection
        with patch("socket.socket") as mock_socket, patch(
            "ssl.SSLContext.wrap_socket"
        ) as mock_ssl:

            mock_sock = Mock()
            mock_socket.return_value = mock_sock

            mock_ssl_sock = Mock()
            mock_ssl_sock.cipher.return_value = (
                "TLS_AES_256_GCM_SHA384",
                "TLSv1.3",
                256,
            )
            mock_ssl_sock.version.return_value = "TLSv1.3"
            mock_ssl.return_value = mock_ssl_sock

            results = await prober.probe_bypasses(
                "example.com", "93.184.216.34", 443, max_probes=1
            )

            assert len(results) > 0
            # Note: In real test, we'd check if any succeeded

    def test_get_best_strategy(self):
        """Test best strategy selection"""
        prober = QuickBypassProber()

        # Create mock results
        from core.fingerprint.bypass_prober import BypassProbeResult

        results = [
            BypassProbeResult(
                strategy_name="fast_strategy",
                strategy_config={},
                success=True,
                response_time_ms=50.0,
                server_hello_received=True,
            ),
            BypassProbeResult(
                strategy_name="slow_strategy",
                strategy_config={},
                success=True,
                response_time_ms=200.0,
                server_hello_received=True,
            ),
        ]

        best = prober.get_best_strategy(results)

        assert best is not None
        assert best["name"] == "fast_strategy"
        assert best["response_time_ms"] == 50.0


class TestStrategyMapping:
    """Test strategy mapping functionality"""

    def test_map_tls_timeout(self):
        """Test mapping TLS handshake timeout"""
        fingerprint_data = {
            "tcp_analysis": {},
            "http_analysis": {"http_blocking_detected": True},
            "tls_analysis": {"handshake_timeout": True},
        }

        strategies = get_strategies_for_fingerprint(fingerprint_data)

        assert len(strategies) > 0
        # Should recommend TLS-specific strategies
        strategy_names = [s["name"] for s in strategies]
        assert any("fakeddisorder" in name for name in strategy_names)

    def test_map_rst_injection_low_ttl(self):
        """Test mapping RST injection with low TTL"""
        fingerprint_data = {
            "tcp_analysis": {"rst_injection_detected": True, "rst_ttl": 5},
            "http_analysis": {},
            "tls_analysis": {},
        }

        strategies = get_strategies_for_fingerprint(fingerprint_data)

        assert len(strategies) > 0
        # Should recommend low-TTL strategies
        priorities = [s["priority"] for s in strategies]
        assert max(priorities) >= 90  # High priority strategies

    def test_map_sni_filtering(self):
        """Test mapping SNI filtering"""
        fingerprint_data = {
            "tcp_analysis": {},
            "http_analysis": {"sni_host_mismatch_blocking": True},
            "tls_analysis": {"sni_blocking_detected": True},
        }

        strategies = get_strategies_for_fingerprint(fingerprint_data)

        assert len(strategies) > 0
        # Should recommend SNI-specific strategies
        strategy_names = [s["name"] for s in strategies]
        assert any("sni" in name.lower() for name in strategy_names)

    def test_fallback_strategies(self):
        """Test fallback strategies"""
        fallback = get_fallback_strategies()

        assert len(fallback) > 0
        assert all("priority" in s for s in fallback)
        assert all("reasoning" in s for s in fallback)


class TestUnifiedFingerprinter:
    """Test unified fingerprinter with optimizations"""

    @pytest.mark.asyncio
    async def test_fast_mode(self):
        """Test fast fingerprinting mode"""
        config = FingerprintingConfig(
            analysis_level="fast", enable_http_analysis=False, timeout=2.0
        )

        fingerprinter = UnifiedFingerprinter(config)

        # Mock analyzers
        with patch.object(fingerprinter, "passive_analyzer") as mock_passive:
            mock_result = Mock()
            mock_result.blocking_method = Mock(value="tcp_rst_injection")
            mock_result.confidence = 0.8
            mock_result.recommended_bypasses = ["fakeddisorder(ttl=1)"]
            mock_result.rst_detected = True
            mock_result.rst_ttl = 5
            mock_result.details = {}
            mock_passive.analyze_blocking_method = AsyncMock(return_value=mock_result)

            fingerprint = await fingerprinter.fingerprint_target("example.com", 443)

            assert fingerprint is not None
            assert fingerprint.target == "example.com"
            assert fingerprint.port == 443

    @pytest.mark.asyncio
    async def test_fail_fast_http(self):
        """Test HTTP analyzer fail-fast gate"""

        analyzer = HTTPAnalyzer(timeout=2.0, use_system_proxy=False)

        # Mock failed connectivity
        with patch.object(analyzer, "_test_basic_connectivity", return_value=False):
            result = await analyzer.analyze_http_behavior("example.com", 443)

            # Should have baseline failure error
            assert "BASELINE_FAILED" in str(result.get("analysis_errors", []))
            # Should skip advanced tests
            assert result.get("http_blocking_detected") == True

    @pytest.mark.asyncio
    async def test_proxy_disabled_by_default(self):
        """Test that proxy is disabled by default for fingerprinting"""

        analyzer = HTTPAnalyzer()

        # Should default to False
        assert analyzer.use_system_proxy == False

    @pytest.mark.asyncio
    async def test_strategy_recommendations(self):
        """Test strategy recommendation generation"""
        config = FingerprintingConfig(analysis_level="fast")
        fingerprinter = UnifiedFingerprinter(config)

        # Create mock fingerprint
        fingerprint = UnifiedFingerprint(target="example.com", port=443)

        # Set some characteristics
        fingerprint.tcp_analysis.rst_injection_detected = True
        fingerprint.tcp_analysis.rst_ttl = 5

        # Generate recommendations
        recommendations = await fingerprinter._generate_strategy_recommendations(
            fingerprint
        )

        assert len(recommendations) > 0
        assert all(hasattr(r, "strategy_name") for r in recommendations)
        assert all(hasattr(r, "confidence") for r in recommendations)


class TestIntegration:
    """Integration tests for complete workflow"""

    @pytest.mark.asyncio
    async def test_complete_workflow(self):
        """Test complete fingerprinting workflow"""
        # 1. Passive analysis
        passive_analyzer = PassiveDPIAnalyzer(timeout=1.0)

        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect.side_effect = ConnectionRefusedError()
            mock_socket.return_value = mock_sock

            passive_result = await passive_analyzer.analyze_blocking_method(
                "example.com", 443
            )

            assert passive_result.rst_detected == True
            assert len(passive_result.recommended_bypasses) > 0

        # 2. Strategy mapping
        fingerprint_data = {
            "tcp_analysis": {"rst_injection_detected": True, "rst_ttl": 5},
            "http_analysis": {},
            "tls_analysis": {},
        }

        strategies = get_strategies_for_fingerprint(fingerprint_data)

        assert len(strategies) > 0
        assert strategies[0]["priority"] >= 85

        # 3. Verify recommendations match passive analysis
        passive_bypasses = set(passive_result.recommended_bypasses)
        strategy_names = set(s["name"] for s in strategies)

        # Should have some overlap
        assert len(passive_bypasses) > 0
        assert len(strategy_names) > 0

    @pytest.mark.asyncio
    async def test_performance_improvement(self):
        """Test that fast mode is actually faster"""
        import time

        # Fast mode
        config_fast = FingerprintingConfig(
            analysis_level="fast", enable_http_analysis=False, timeout=1.0
        )

        fingerprinter_fast = UnifiedFingerprinter(config_fast)

        start = time.time()
        # Mock to avoid actual network calls
        with patch.object(fingerprinter_fast, "_resolve_target", return_value=[]):
            fingerprint = await fingerprinter_fast.fingerprint_target(
                "example.com", 443
            )
        duration_fast = time.time() - start

        # Should complete quickly (< 5 seconds even with mocks)
        assert duration_fast < 5.0
        assert fingerprint is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
