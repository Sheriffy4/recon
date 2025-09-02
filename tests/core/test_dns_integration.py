"""
Integration tests for DNS Behavior Analyzer - Task 6 Implementation
Tests real-world DNS analysis scenarios and integration with other components.
"""

import pytest
import time
import logging
from unittest.mock import Mock, patch, AsyncMock
from core.fingerprint.dns_analyzer import (
    DNSAnalyzer,
    DNSResponse,
    DNSQuery,
    DNSRecordType,
)

logging.basicConfig(level=logging.DEBUG)


class TestDNSIntegration:
    """Integration tests for DNS analyzer with other components"""

    @pytest.fixture
    def analyzer(self):
        """Create DNSAnalyzer instance for integration testing"""
        return DNSAnalyzer(timeout=5.0, max_retries=2)

    @pytest.mark.asyncio
    async def test_dns_analysis_with_metrics_collector(self, analyzer):
        """Test DNS analysis integration with metrics collector"""
        target = "test.com"
        with patch.object(
            analyzer, "_detect_dns_hijacking", new_callable=AsyncMock
        ) as mock_hijacking, patch.object(
            analyzer, "_detect_response_modification", new_callable=AsyncMock
        ) as mock_modification, patch.object(
            analyzer, "_test_doh_blocking", new_callable=AsyncMock
        ) as mock_doh, patch.object(
            analyzer, "_test_dot_blocking", new_callable=AsyncMock
        ) as mock_dot, patch.object(
            analyzer, "_detect_cache_poisoning", new_callable=AsyncMock
        ) as mock_poisoning, patch.object(
            analyzer, "_test_edns_support", new_callable=AsyncMock
        ) as mock_edns, patch.object(
            analyzer, "_test_dns_over_tcp", new_callable=AsyncMock
        ) as mock_tcp, patch.object(
            analyzer, "_test_recursive_resolver_blocking", new_callable=AsyncMock
        ) as mock_resolver, patch.object(
            analyzer, "_detect_timeout_manipulation", new_callable=AsyncMock
        ) as mock_timeout:
            mock_hijacking.return_value = {
                "dns_hijacking_detected": True,
                "hijacking_details": {
                    "conflicting_resolvers": ["8.8.8.8", "1.1.1.1"],
                    "responses": {"8.8.8.8": ["1.2.3.4"], "1.1.1.1": ["5.6.7.8"]},
                },
            }
            mock_modification.return_value = {
                "dns_response_modification": True,
                "modification_details": [
                    {"record_type": "A", "suspicious_patterns": ["null_ip_response"]}
                ],
            }
            mock_doh.return_value = {
                "doh_blocking": True,
                "doh_details": {
                    "blocked_servers": ["cloudflare", "google"],
                    "working_servers": [],
                },
            }
            mock_dot.return_value = {
                "dot_blocking": True,
                "dot_details": {
                    "blocked_servers": ["cloudflare", "google"],
                    "working_servers": [],
                },
            }
            mock_poisoning.return_value = {
                "dns_cache_poisoning": True,
                "poisoning_details": {
                    "inconsistent_responses": [["1.2.3.4"], ["5.6.7.8"]]
                },
            }
            mock_edns.return_value = {"edns_support": False, "edns_details": {}}
            mock_tcp.return_value = {
                "dns_over_tcp_blocking": True,
                "tcp_details": {"tcp_successful": False, "udp_successful": True},
            }
            mock_resolver.return_value = {
                "recursive_resolver_blocking": True,
                "resolver_details": {
                    "blocked_resolvers": ["8.8.8.8", "1.1.1.1"],
                    "working_resolvers": [],
                },
            }
            mock_timeout.return_value = {
                "dns_timeout_manipulation": True,
                "timeout_details": {"8.8.8.8": 5.0, "1.1.1.1": 0.1},
            }
            dns_results = await analyzer.analyze_dns_behavior(target)
            assert dns_results["dns_hijacking_detected"] is True
            assert dns_results["dns_response_modification"] is True
            assert dns_results["doh_blocking"] is True
            assert dns_results["dot_blocking"] is True
            assert dns_results["dns_cache_poisoning"] is True
            assert dns_results["dns_over_tcp_blocking"] is True
            assert dns_results["recursive_resolver_blocking"] is True
            assert dns_results["dns_timeout_manipulation"] is True
            assert dns_results["edns_support"] is False
            assert "analysis_duration" in dns_results
            assert dns_results["analysis_duration"] > 0

    @pytest.mark.asyncio
    async def test_dns_analysis_clean_environment(self, analyzer):
        """Test DNS analysis in clean environment (no blocking)"""
        target = "google.com"
        with patch.object(
            analyzer, "_detect_dns_hijacking", new_callable=AsyncMock
        ) as mock_hijacking, patch.object(
            analyzer, "_detect_response_modification", new_callable=AsyncMock
        ) as mock_modification, patch.object(
            analyzer, "_test_doh_blocking", new_callable=AsyncMock
        ) as mock_doh, patch.object(
            analyzer, "_test_dot_blocking", new_callable=AsyncMock
        ) as mock_dot, patch.object(
            analyzer, "_detect_cache_poisoning", new_callable=AsyncMock
        ) as mock_poisoning, patch.object(
            analyzer, "_test_edns_support", new_callable=AsyncMock
        ) as mock_edns, patch.object(
            analyzer, "_test_dns_over_tcp", new_callable=AsyncMock
        ) as mock_tcp, patch.object(
            analyzer, "_test_recursive_resolver_blocking", new_callable=AsyncMock
        ) as mock_resolver, patch.object(
            analyzer, "_detect_timeout_manipulation", new_callable=AsyncMock
        ) as mock_timeout:
            mock_hijacking.return_value = {"dns_hijacking_detected": False}
            mock_modification.return_value = {"dns_response_modification": False}
            mock_doh.return_value = {
                "doh_blocking": False,
                "doh_details": {
                    "blocked_servers": [],
                    "working_servers": ["cloudflare", "google"],
                },
            }
            mock_dot.return_value = {
                "dot_blocking": False,
                "dot_details": {
                    "blocked_servers": [],
                    "working_servers": ["cloudflare", "google"],
                },
            }
            mock_poisoning.return_value = {"dns_cache_poisoning": False}
            mock_edns.return_value = {
                "edns_support": True,
                "edns_details": {"edns_version": 0},
            }
            mock_tcp.return_value = {
                "dns_over_tcp_blocking": False,
                "tcp_details": {"tcp_successful": True, "udp_successful": True},
            }
            mock_resolver.return_value = {
                "recursive_resolver_blocking": False,
                "resolver_details": {
                    "blocked_resolvers": [],
                    "working_resolvers": ["8.8.8.8", "1.1.1.1"],
                },
            }
            mock_timeout.return_value = {
                "dns_timeout_manipulation": False,
                "timeout_details": {"8.8.8.8": 0.1, "1.1.1.1": 0.1},
            }
            dns_results = await analyzer.analyze_dns_behavior(target)
            assert dns_results["dns_hijacking_detected"] is False
            assert dns_results["dns_response_modification"] is False
            assert dns_results["doh_blocking"] is False
            assert dns_results["dot_blocking"] is False
            assert dns_results["dns_cache_poisoning"] is False
            assert dns_results["dns_over_tcp_blocking"] is False
            assert dns_results["recursive_resolver_blocking"] is False
            assert dns_results["dns_timeout_manipulation"] is False
            assert dns_results["edns_support"] is True

    @pytest.mark.asyncio
    async def test_dns_analysis_partial_blocking(self, analyzer):
        """Test DNS analysis with partial blocking (some methods blocked, others not)"""
        target = "facebook.com"
        with patch.object(
            analyzer, "_detect_dns_hijacking", new_callable=AsyncMock
        ) as mock_hijacking, patch.object(
            analyzer, "_detect_response_modification", new_callable=AsyncMock
        ) as mock_modification, patch.object(
            analyzer, "_test_doh_blocking", new_callable=AsyncMock
        ) as mock_doh, patch.object(
            analyzer, "_test_dot_blocking", new_callable=AsyncMock
        ) as mock_dot, patch.object(
            analyzer, "_detect_cache_poisoning", new_callable=AsyncMock
        ) as mock_poisoning, patch.object(
            analyzer, "_test_edns_support", new_callable=AsyncMock
        ) as mock_edns, patch.object(
            analyzer, "_test_dns_over_tcp", new_callable=AsyncMock
        ) as mock_tcp, patch.object(
            analyzer, "_test_recursive_resolver_blocking", new_callable=AsyncMock
        ) as mock_resolver, patch.object(
            analyzer, "_detect_timeout_manipulation", new_callable=AsyncMock
        ) as mock_timeout:
            mock_hijacking.return_value = {"dns_hijacking_detected": False}
            mock_modification.return_value = {"dns_response_modification": False}
            mock_doh.return_value = {
                "doh_blocking": True,
                "doh_details": {
                    "blocked_servers": ["cloudflare"],
                    "working_servers": ["google"],
                },
            }
            mock_dot.return_value = {
                "dot_blocking": False,
                "dot_details": {
                    "blocked_servers": [],
                    "working_servers": ["cloudflare", "google"],
                },
            }
            mock_poisoning.return_value = {"dns_cache_poisoning": False}
            mock_edns.return_value = {"edns_support": True}
            mock_tcp.return_value = {
                "dns_over_tcp_blocking": True,
                "tcp_details": {"tcp_successful": False, "udp_successful": True},
            }
            mock_resolver.return_value = {
                "recursive_resolver_blocking": False,
                "resolver_details": {
                    "blocked_resolvers": [],
                    "working_resolvers": ["8.8.8.8", "1.1.1.1"],
                },
            }
            mock_timeout.return_value = {"dns_timeout_manipulation": False}
            dns_results = await analyzer.analyze_dns_behavior(target)
            assert dns_results["doh_blocking"] is True
            assert dns_results["dot_blocking"] is False
            assert dns_results["dns_over_tcp_blocking"] is True
            assert dns_results["dns_hijacking_detected"] is False
            assert dns_results["recursive_resolver_blocking"] is False

    @pytest.mark.asyncio
    async def test_dns_analysis_error_handling(self, analyzer):
        """Test DNS analysis error handling and graceful degradation"""
        target = "error-test.com"
        with patch.object(
            analyzer, "_detect_dns_hijacking", new_callable=AsyncMock
        ) as mock_hijacking, patch.object(
            analyzer, "_detect_response_modification", new_callable=AsyncMock
        ) as mock_modification, patch.object(
            analyzer, "_test_doh_blocking", new_callable=AsyncMock
        ) as mock_doh:
            mock_hijacking.side_effect = Exception("Network error")
            mock_modification.return_value = {"dns_response_modification": False}
            mock_doh.side_effect = Exception("DoH server unreachable")
            dns_results = await analyzer.analyze_dns_behavior(target)
            assert isinstance(dns_results, dict)
            assert "analysis_duration" in dns_results
            assert (
                "analysis_error" in dns_results
                or "dns_response_modification" in dns_results
            )

    @pytest.mark.asyncio
    async def test_dns_query_methods_integration(self, analyzer):
        """Test integration of different DNS query methods"""
        target = "integration-test.com"
        with patch("socket.gethostbyname_ex") as mock_resolve:
            mock_resolve.return_value = ("integration-test.com", [], ["1.2.3.4"])
            udp_result = await analyzer._query_dns_udp(target, "8.8.8.8")
            assert udp_result is not None
            assert isinstance(udp_result, DNSResponse)
            assert udp_result.answers == ["1.2.3.4"]
            assert udp_result.query.protocol == "udp"
        with patch("socket.socket") as mock_socket, patch.object(
            analyzer, "_query_dns_udp", new_callable=AsyncMock
        ) as mock_udp:
            mock_sock = Mock()
            mock_sock.connect_ex.return_value = 0
            mock_socket.return_value = mock_sock
            mock_udp.return_value = DNSResponse(
                timestamp=time.time(),
                query=Mock(),
                response_time=0.1,
                status_code=0,
                answers=["1.2.3.4"],
            )
            tcp_result = await analyzer._query_dns_tcp(target, "8.8.8.8")
            assert tcp_result is not None
            mock_sock.close.assert_called()

    @pytest.mark.asyncio
    async def test_dns_blocking_pattern_analysis(self, analyzer):
        """Test DNS blocking pattern analysis and classification"""
        query = DNSQuery(
            timestamp=time.time(),
            domain="blocked-site.com",
            record_type=DNSRecordType.A,
            query_id=12345,
            resolver="8.8.8.8",
        )
        blocking_response = DNSResponse(
            timestamp=time.time(),
            query=query,
            response_time=0.1,
            status_code=0,
            answers=["0.0.0.0"],
            flags={"qr": True, "aa": False},
        )
        assert analyzer._is_suspicious_response(blocking_response) is True
        patterns = analyzer._analyze_response_patterns(blocking_response)
        assert "null_ip_response" in patterns
        normal_response = DNSResponse(
            timestamp=time.time(),
            query=query,
            response_time=0.1,
            status_code=0,
            answers=["8.8.8.8"],
            flags={"qr": True, "aa": False},
        )
        assert analyzer._is_suspicious_response(normal_response) is False
        private_response = DNSResponse(
            timestamp=time.time(),
            query=query,
            response_time=0.1,
            status_code=0,
            answers=["192.168.1.1"],
            flags={"qr": True, "aa": False},
        )
        patterns = analyzer._analyze_response_patterns(private_response)
        assert "private_ip_response" in patterns

    @pytest.mark.asyncio
    async def test_dns_analyzer_configuration(self, analyzer):
        """Test DNS analyzer configuration and customization"""
        assert analyzer.timeout == 5.0
        assert analyzer.max_retries == 2
        assert len(analyzer.test_domains) > 0
        assert len(analyzer.blocked_domains) > 0
        assert "google.com" in analyzer.test_domains
        assert len(analyzer.doh_servers) > 0
        assert len(analyzer.dot_servers) > 0
        assert len(analyzer.public_resolvers) > 0
        assert "cloudflare" in analyzer.doh_servers
        assert "google" in analyzer.doh_servers
        assert "8.8.8.8" in analyzer.public_resolvers
        assert "1.1.1.1" in analyzer.public_resolvers

    @pytest.mark.asyncio
    async def test_dns_analysis_performance(self, analyzer):
        """Test DNS analysis performance and timing"""
        target = "performance-test.com"
        with patch.object(
            analyzer, "_detect_dns_hijacking", new_callable=AsyncMock
        ) as mock_hijacking, patch.object(
            analyzer, "_detect_response_modification", new_callable=AsyncMock
        ) as mock_modification, patch.object(
            analyzer, "_test_doh_blocking", new_callable=AsyncMock
        ) as mock_doh, patch.object(
            analyzer, "_test_dot_blocking", new_callable=AsyncMock
        ) as mock_dot, patch.object(
            analyzer, "_detect_cache_poisoning", new_callable=AsyncMock
        ) as mock_poisoning, patch.object(
            analyzer, "_test_edns_support", new_callable=AsyncMock
        ) as mock_edns, patch.object(
            analyzer, "_test_dns_over_tcp", new_callable=AsyncMock
        ) as mock_tcp, patch.object(
            analyzer, "_test_recursive_resolver_blocking", new_callable=AsyncMock
        ) as mock_resolver, patch.object(
            analyzer, "_detect_timeout_manipulation", new_callable=AsyncMock
        ) as mock_timeout:
            mock_hijacking.return_value = {"dns_hijacking_detected": False}
            mock_modification.return_value = {"dns_response_modification": False}
            mock_doh.return_value = {"doh_blocking": False}
            mock_dot.return_value = {"dot_blocking": False}
            mock_poisoning.return_value = {"dns_cache_poisoning": False}
            mock_edns.return_value = {"edns_support": True}
            mock_tcp.return_value = {"dns_over_tcp_blocking": False}
            mock_resolver.return_value = {"recursive_resolver_blocking": False}
            mock_timeout.return_value = {"dns_timeout_manipulation": False}
            start_time = time.time()
            dns_results = await analyzer.analyze_dns_behavior(target)
            end_time = time.time()
            actual_duration = end_time - start_time
            reported_duration = dns_results["analysis_duration"]
            assert actual_duration < 1.0
            assert reported_duration >= 0
            mock_hijacking.assert_called_once()
            mock_modification.assert_called_once()
            mock_doh.assert_called_once()
            mock_dot.assert_called_once()
            mock_poisoning.assert_called_once()
            mock_edns.assert_called_once()
            mock_tcp.assert_called_once()
            mock_resolver.assert_called_once()
            mock_timeout.assert_called_once()


class TestDNSRealWorldScenarios:
    """Test DNS analyzer with real-world blocking scenarios"""

    @pytest.fixture
    def analyzer(self):
        """Create DNSAnalyzer instance for real-world testing"""
        return DNSAnalyzer(timeout=3.0, max_retries=1)

    @pytest.mark.asyncio
    async def test_government_censorship_scenario(self, analyzer):
        """Test DNS analysis for government censorship scenario"""
        target = "censored-site.gov"
        with patch.object(
            analyzer, "_detect_dns_hijacking", new_callable=AsyncMock
        ) as mock_hijacking, patch.object(
            analyzer, "_detect_response_modification", new_callable=AsyncMock
        ) as mock_modification, patch.object(
            analyzer, "_test_doh_blocking", new_callable=AsyncMock
        ) as mock_doh, patch.object(
            analyzer, "_test_dot_blocking", new_callable=AsyncMock
        ) as mock_dot, patch.object(
            analyzer, "_detect_cache_poisoning", new_callable=AsyncMock
        ) as mock_poisoning, patch.object(
            analyzer, "_test_edns_support", new_callable=AsyncMock
        ) as mock_edns, patch.object(
            analyzer, "_test_dns_over_tcp", new_callable=AsyncMock
        ) as mock_tcp, patch.object(
            analyzer, "_test_recursive_resolver_blocking", new_callable=AsyncMock
        ) as mock_resolver, patch.object(
            analyzer, "_detect_timeout_manipulation", new_callable=AsyncMock
        ) as mock_timeout:
            mock_hijacking.return_value = {
                "dns_hijacking_detected": True,
                "hijacking_details": {"conflicting_resolvers": ["8.8.8.8", "1.1.1.1"]},
            }
            mock_modification.return_value = {
                "dns_response_modification": True,
                "modification_details": [{"suspicious_patterns": ["null_ip_response"]}],
            }
            mock_doh.return_value = {"doh_blocking": True}
            mock_dot.return_value = {"dot_blocking": True}
            mock_poisoning.return_value = {"dns_cache_poisoning": True}
            mock_edns.return_value = {"edns_support": False}
            mock_tcp.return_value = {"dns_over_tcp_blocking": True}
            mock_resolver.return_value = {"recursive_resolver_blocking": True}
            mock_timeout.return_value = {"dns_timeout_manipulation": True}
            dns_results = await analyzer.analyze_dns_behavior(target)
            blocking_indicators = [
                dns_results["dns_hijacking_detected"],
                dns_results["dns_response_modification"],
                dns_results["doh_blocking"],
                dns_results["dot_blocking"],
                dns_results["dns_cache_poisoning"],
                dns_results["dns_over_tcp_blocking"],
                dns_results["recursive_resolver_blocking"],
                dns_results["dns_timeout_manipulation"],
            ]
            assert sum(blocking_indicators) >= 6

    @pytest.mark.asyncio
    async def test_isp_transparent_proxy_scenario(self, analyzer):
        """Test DNS analysis for ISP transparent proxy scenario"""
        target = "social-media.com"
        with patch.object(
            analyzer, "_detect_dns_hijacking", new_callable=AsyncMock
        ) as mock_hijacking, patch.object(
            analyzer, "_detect_response_modification", new_callable=AsyncMock
        ) as mock_modification, patch.object(
            analyzer, "_test_doh_blocking", new_callable=AsyncMock
        ) as mock_doh, patch.object(
            analyzer, "_test_dot_blocking", new_callable=AsyncMock
        ) as mock_dot, patch.object(
            analyzer, "_detect_cache_poisoning", new_callable=AsyncMock
        ) as mock_poisoning, patch.object(
            analyzer, "_test_edns_support", new_callable=AsyncMock
        ) as mock_edns, patch.object(
            analyzer, "_test_dns_over_tcp", new_callable=AsyncMock
        ) as mock_tcp, patch.object(
            analyzer, "_test_recursive_resolver_blocking", new_callable=AsyncMock
        ) as mock_resolver, patch.object(
            analyzer, "_detect_timeout_manipulation", new_callable=AsyncMock
        ) as mock_timeout:
            mock_hijacking.return_value = {"dns_hijacking_detected": False}
            mock_modification.return_value = {
                "dns_response_modification": True,
                "modification_details": [
                    {"suspicious_patterns": ["private_ip_response"]}
                ],
            }
            mock_doh.return_value = {"doh_blocking": False}
            mock_dot.return_value = {"dot_blocking": False}
            mock_poisoning.return_value = {"dns_cache_poisoning": False}
            mock_edns.return_value = {"edns_support": True}
            mock_tcp.return_value = {"dns_over_tcp_blocking": False}
            mock_resolver.return_value = {"recursive_resolver_blocking": False}
            mock_timeout.return_value = {"dns_timeout_manipulation": False}
            dns_results = await analyzer.analyze_dns_behavior(target)
            assert dns_results["dns_response_modification"] is True
            assert dns_results["doh_blocking"] is False
            assert dns_results["dot_blocking"] is False
            assert dns_results["dns_hijacking_detected"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
