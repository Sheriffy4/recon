"""
Comprehensive unit tests for Ultimate AdvancedFingerprinter
Tests all functionality including new features from the ultimate version
"""

import pytest
import asyncio
import tempfile
import time
import ssl
import socket
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Import the module under test
from core.fingerprint.advanced_fingerprinter import (
    AdvancedFingerprinter,
    FingerprintingConfig,
    BlockingEvent,
    ConnectivityResult,
    DPIBehaviorProfile,
)
from core.fingerprint.advanced_models import DPIFingerprint, DPIType


class TestAdvancedFingerprinterCore:
    """Core functionality tests"""

    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return FingerprintingConfig(
            cache_ttl=300,
            enable_ml=False,  # Disable ML for most tests
            enable_cache=True,
            max_concurrent_probes=3,
            timeout=5.0,
            enable_tcp_analysis=True,
            enable_http_analysis=True,
            enable_dns_analysis=True,
            fallback_on_error=True,
            min_confidence_threshold=0.6,
            retry_attempts=2,
            retry_delay=1.0,
            enable_behavior_analysis=True,
            enable_attack_recommendations=True,
            enable_extended_metrics=False,  # Disable to avoid RealEffectivenessTester dependency
            enable_targeted_probes=True,
            enable_sni_probing=True,
            enable_ml_refinement=False,
            enable_attack_history=True,
        )

    @pytest.fixture
    def temp_cache_file(self):
        """Create temporary cache file"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            yield f.name

    @pytest.fixture
    async def fingerprinter(self, config, temp_cache_file):
        """Create AdvancedFingerprinter instance"""
        fp = AdvancedFingerprinter(config=config, cache_file=temp_cache_file)
        yield fp
        # Cleanup
        if hasattr(fp, 'executor'):
            fp.executor.shutdown(wait=False)

    def test_initialization_success(self, config, temp_cache_file):
        """Test successful initialization"""
        fingerprinter = AdvancedFingerprinter(config=config, cache_file=temp_cache_file)
        
        assert fingerprinter.config == config
        assert fingerprinter.cache is not None
        assert fingerprinter.metrics_collector is not None
        assert fingerprinter.tcp_analyzer is not None
        assert fingerprinter.http_analyzer is not None
        assert fingerprinter.dns_analyzer is not None
        assert fingerprinter.behavior_profiles == {}
        assert fingerprinter.stats["fingerprints_created"] == 0

    def test_initialization_with_disabled_components(self, temp_cache_file):
        """Test initialization with disabled components"""
        config = FingerprintingConfig(
            enable_cache=False,
            enable_tcp_analysis=False,
            enable_http_analysis=False,
            enable_dns_analysis=False,
            enable_ml=False,
        )
        
        fingerprinter = AdvancedFingerprinter(config=config, cache_file=temp_cache_file)
        
        assert fingerprinter.cache is None
        assert fingerprinter.tcp_analyzer is None
        assert fingerprinter.http_analyzer is None
        assert fingerprinter.dns_analyzer is None
        assert fingerprinter.ml_classifier is None

    @pytest.mark.asyncio
    async def test_fingerprint_target_basic(self, fingerprinter):
        """Test basic fingerprinting workflow"""
        target = "example.com"
        port = 443
        
        # Mock the shallow probe
        with patch.object(fingerprinter, '_run_shallow_probe', new_callable=AsyncMock) as mock_probe:
            mock_fp = DPIFingerprint(target=f"{target}:{port}")
            mock_fp.rst_ttl = 64
            mock_fp.block_type = "connection_reset"
            mock_probe.return_value = mock_fp
            
            # Mock comprehensive analysis
            with patch.object(fingerprinter, '_perform_comprehensive_analysis', new_callable=AsyncMock) as mock_analysis:
                analysis_fp = DPIFingerprint(
                    target=f"{target}:{port}",
                    dpi_type=DPIType.ROSKOMNADZOR_TSPU,
                    confidence=0.85,
                    reliability_score=0.9
                )
                mock_analysis.return_value = analysis_fp
                
                # Disable behavior analysis for this test
                result = await fingerprinter.fingerprint_target(
                    target, port, 
                    include_behavior_analysis=False,
                    include_extended_metrics=False
                )
                
                assert result is not None
                assert result.dpi_type == DPIType.ROSKOMNADZOR_TSPU
                assert result.confidence == 0.85
                assert result.rst_ttl == 64  # From shallow probe
                assert fingerprinter.stats["fingerprints_created"] == 1

    @pytest.mark.asyncio
    async def test_fingerprint_with_cache_hit(self, fingerprinter):
        """Test fingerprinting with cache hit"""
        target = "cached.com"
        port = 443
        
        # Create and cache a fingerprint
        cached_fp = DPIFingerprint(
            target=f"{target}:{port}",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.9,
            reliability_score=0.85
        )
        
        # Mock shallow probe to return consistent hash
        with patch.object(fingerprinter, '_run_shallow_probe', new_callable=AsyncMock) as mock_probe:
            mock_fp = DPIFingerprint(target=f"{target}:{port}")
            mock_probe.return_value = mock_fp
            
            # Manually insert into cache
            if fingerprinter.cache:
                fingerprinter.cache.set(mock_fp.short_hash(), cached_fp)
            
            result = await fingerprinter.fingerprint_target(target, port)
            
            assert result.dpi_type == DPIType.COMMERCIAL_DPI
            assert fingerprinter.stats["cache_hits"] == 1

    @pytest.mark.asyncio
    async def test_error_handling_with_fallback(self, fingerprinter):
        """Test error handling with fallback"""
        target = "error.com"
        port = 443
        
        with patch.object(fingerprinter, '_run_shallow_probe', new_callable=AsyncMock) as mock_probe:
            mock_probe.side_effect = Exception("Network error")
            
            result = await fingerprinter.fingerprint_target(target, port)
            
            assert result is not None
            assert result.reliability_score == 0.0
            assert "fallback" in result.analysis_methods_used
            assert fingerprinter.stats["errors"] == 1

    @pytest.mark.asyncio
    async def test_behavior_analysis(self, fingerprinter):
        """Test DPI behavior analysis"""
        domain = "test.com"
        
        test_fp = DPIFingerprint(
            target=f"{domain}:443",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.8,
            rst_injection_detected=True,
            tcp_window_manipulation=True
        )
        
        # Mock timing analysis
        with patch.object(fingerprinter, '_analyze_timing_sensitivity_detailed', new_callable=AsyncMock) as mock_timing:
            mock_timing.return_value = {"connection_delay": 0.7}
            
            # Mock burst tolerance
            with patch.object(fingerprinter, '_analyze_burst_tolerance', new_callable=AsyncMock) as mock_burst:
                mock_burst.return_value = 0.4
                
                profile = await fingerprinter.analyze_dpi_behavior(domain, test_fp)
                
                assert profile is not None
                assert profile.signature_based_detection == True
                assert profile.behavioral_analysis == True
                assert profile.burst_tolerance == 0.4
                assert len(profile.identified_weaknesses) > 0
                assert fingerprinter.stats["behavior_profiles_created"] == 1

    def test_recommend_bypass_strategies(self, fingerprinter):
        """Test bypass strategy recommendations"""
        test_fp = DPIFingerprint(
            target="test.com:443",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
            rst_injection_detected=True,
            dns_hijacking_detected=True
        )
        
        test_fp.raw_metrics = {
            "strategy_hints": ["split_tls_sni", "disable_quic"],
            "quic_probe": {"blocked": True}
        }
        
        recommendations = fingerprinter.recommend_bypass_strategies(test_fp)
        
        assert len(recommendations) > 0
        assert recommendations[0]["execution_order"] == 1
        assert "tcp_multisplit" in [r["technique"] for r in recommendations]
        assert all("score" in r for r in recommendations)
        assert all("reasoning" in r for r in recommendations)

    @pytest.mark.asyncio
    async def test_extended_metrics_collection(self, fingerprinter):
        """Test extended metrics collection (when available)"""
        target = "metrics.com"
        port = 443
        
        # This test only runs if RealEffectivenessTester is available
        if not fingerprinter.effectiveness_tester:
            pytest.skip("RealEffectivenessTester not available")
        
        with patch.object(fingerprinter.effectiveness_tester, 'collect_extended_metrics', new_callable=AsyncMock) as mock_collect:
            mock_collect.return_value = {
                "baseline_block_type": "RST",
                "rst_ttl_distance": 5,
                "http2_support": True
            }
            
            metrics = await fingerprinter.collect_extended_fingerprint_metrics(target, port)
            
            assert "baseline_block_type" in metrics
            assert metrics["rst_ttl_distance"] == 5

    @pytest.mark.asyncio
    async def test_ml_classification_refinement(self, fingerprinter):
        """Test ML classification refinement"""
        test_fp = DPIFingerprint(
            target="ml-test.com:443",
            dpi_type=DPIType.UNKNOWN,
            confidence=0.5
        )
        
        if fingerprinter.ml_classifier:
            with patch.object(fingerprinter.ml_classifier, 'predict') as mock_predict:
                mock_predict.return_value = {
                    "dpi_type": "ROSKOMNADZOR_TSPU",
                    "confidence": 0.9
                }
                
                await fingerprinter._classify_with_ml(test_fp)
                
                assert test_fp.dpi_type == DPIType.ROSKOMNADZOR_TSPU
                assert test_fp.confidence == 0.9
                assert "ml_classification" in test_fp.analysis_methods_used
        else:
            # If ML not available, should not crash
            await fingerprinter._classify_with_ml(test_fp)
            assert test_fp.dpi_type == DPIType.UNKNOWN

    @pytest.mark.asyncio
    async def test_targeted_probes(self, fingerprinter):
        """Test targeted probes execution"""
        target = "probe.com"
        port = 443
        
        test_fp = DPIFingerprint(
            target=f"{target}:{port}",
            confidence=0.4  # Low confidence to trigger probes
        )
        
        with patch.object(fingerprinter, '_probe_sni_sensitivity_detailed', new_callable=AsyncMock) as mock_sni:
            mock_sni.return_value = {
                "sni_sensitive": True,
                "sni_validation_type": "strict_domain"
            }
            
            with patch.object(fingerprinter, '_probe_timing_sensitivity', new_callable=AsyncMock) as mock_timing:
                mock_timing.return_value = {"timing_sensitive": True}
                
                results = await fingerprinter._run_targeted_probes(target, port, test_fp)
                
                assert "sni_probe_detailed" in results
                assert results["sni_probe_detailed"]["sni_sensitive"] == True
                assert "timing_probe" in results

    def test_get_extended_stats(self, fingerprinter):
        """Test extended statistics collection"""
        # Populate some stats
        fingerprinter.stats["fingerprints_created"] = 10
        fingerprinter.stats["cache_hits"] = 5
        fingerprinter.stats["total_analysis_time"] = 50.0
        
        # Add some tracking data
        fingerprinter.technique_effectiveness["test.com"]["tcp_multisplit"] = [0.8, 0.9, 0.7]
        
        stats = fingerprinter.get_extended_stats()
        
        assert stats["fingerprints_created"] == 10
        assert stats["cache_hits"] == 5
        assert stats["avg_analysis_time"] == 5.0
        assert stats["domains_tracked"] == 1
        assert "avg_attack_effectiveness" in stats

    @pytest.mark.asyncio
    async def test_concurrent_fingerprinting(self, fingerprinter):
        """Test concurrent fingerprinting"""
        targets = [f"concurrent{i}.com" for i in range(3)]
        
        with patch.object(fingerprinter, 'fingerprint_target', new_callable=AsyncMock) as mock_fp:
            mock_fp.return_value = DPIFingerprint(
                target="test:443",
                dpi_type=DPIType.COMMERCIAL_DPI,
                confidence=0.8
            )
            
            tasks = [fingerprinter.fingerprint_target(t, 443) for t in targets]
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 3
            assert all(r.dpi_type == DPIType.COMMERCIAL_DPI for r in results)


class TestProbesAndAnalysis:
    """Test probing and analysis methods"""

    @pytest.fixture
    async def fingerprinter(self):
        """Create fingerprinter for probe tests"""
        config = FingerprintingConfig(
            enable_ml=False,
            enable_cache=False,
            enable_extended_metrics=False
        )
        fp = AdvancedFingerprinter(config=config, cache_file="test.pkl")
        yield fp
        if hasattr(fp, 'executor'):
            fp.executor.shutdown(wait=False)

    @pytest.mark.asyncio
    async def test_probe_quic_initial(self, fingerprinter):
        """Test QUIC initial probe"""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            mock_socket.sendto.return_value = None
            mock_socket.recvfrom.side_effect = socket.timeout()
            
            result = await fingerprinter._probe_quic_initial("test.com", 443)
            
            assert result["attempted"] == True
            assert "error" in result or "blocked" in result

    @pytest.mark.asyncio
    async def test_probe_tls_capabilities(self, fingerprinter):
        """Test TLS capabilities probe"""
        with patch('socket.create_connection') as mock_connect:
            mock_socket = Mock()
            mock_connect.return_value = mock_socket
            
            with patch('ssl.SSLContext') as mock_ssl_context:
                mock_ctx = Mock()
                mock_ssl_context.return_value = mock_ctx
                mock_ssock = Mock()
                mock_ssock.version.return_value = "TLSv1.3"
                mock_ssock.selected_alpn_protocol.return_value = "h2"
                mock_ctx.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssock)
                mock_ctx.wrap_socket.return_value.__exit__ = Mock()
                
                result = await fingerprinter._probe_tls_capabilities("test.com", 443)
                
                assert "tls13_supported" in result
                assert "alpn_h2_supported" in result

    @pytest.mark.asyncio
    async def test_probe_sni_sensitivity(self, fingerprinter):
        """Test SNI sensitivity probe"""
        async def mock_handshake(server_hostname):
            if server_hostname == "test.com":
                return {"ok": True, "latency_ms": 50}
            elif server_hostname == "TEST.COM":
                return {"ok": False, "error": "Failed"}
            else:  # No SNI
                return {"ok": False, "error": "No SNI"}
        
        with patch.object(fingerprinter.executor, 'submit') as mock_submit:
            # Create futures for each call
            futures = []
            for sni in ["test.com", "TEST.COM", None]:
                future = asyncio.Future()
                if sni == "test.com":
                    future.set_result({"ok": True, "latency_ms": 50})
                else:
                    future.set_result({"ok": False, "error": "Failed"})
                futures.append(future)
            
            mock_submit.side_effect = futures
            
            # Need to also patch the run_in_executor since we're using it
            with patch('asyncio.get_event_loop') as mock_get_loop:
                loop = Mock()
                mock_get_loop.return_value = loop
                
                async def run_in_executor_side_effect(executor, func, *args):
                    if args[0] == "test.com":
                        return {"ok": True, "latency_ms": 50}
                    else:
                        return {"ok": False, "error": "Failed"}
                
                loop.run_in_executor = AsyncMock(side_effect=run_in_executor_side_effect)
                
                result = await fingerprinter._probe_sni_sensitivity("test.com", 443)
                
                assert "sni_sensitive" in result
                assert result["sni_sensitive"] == True

    @pytest.mark.asyncio
    async def test_probe_behavioral_patterns(self, fingerprinter):
        """Test behavioral pattern probing"""
        with patch.object(fingerprinter, '_probe_packet_reordering_detailed', new_callable=AsyncMock) as mock_reorder:
            mock_reorder.return_value = {"tolerates_reordering": True, "max_reorder_distance": 4}
            
            with patch.object(fingerprinter, '_probe_fragmentation_detailed', new_callable=AsyncMock) as mock_frag:
                mock_frag.return_value = {"supports_ip_fragmentation": True, "min_fragment_size": 8}
                
                with patch.object(fingerprinter, '_analyze_timing_patterns', new_callable=AsyncMock) as mock_timing:
                    mock_timing.return_value = {"connect_time_ms": 100}
                    
                    with patch.object(fingerprinter, '_probe_packet_size_limits', new_callable=AsyncMock) as mock_size:
                        mock_size.return_value = {"max_tcp_payload": 1460}
                        
                        with patch.object(fingerprinter, '_probe_protocol_detection', new_callable=AsyncMock) as mock_proto:
                            mock_proto.return_value = {"https_detected": True}
                            
                            result = await fingerprinter._probe_dpi_behavioral_patterns("test.com", 443)
                            
                            assert result["reordering_tolerance"]["tolerates_reordering"] == True
                            assert result["fragmentation_handling"]["supports_ip_fragmentation"] == True
                            assert result["timing_patterns"]["connect_time_ms"] == 100

    def test_compute_ja3(self, fingerprinter):
        """Test JA3 computation"""
        test_bytes = b"test_client_hello_bytes"
        result = fingerprinter._compute_ja3(test_bytes)
        
        assert "ja3_hash" in result
        assert result["ja3_hash"] is not None
        assert len(result["ja3_hash"]) == 32  # MD5 hash length

    def test_analyze_rst_ttl_stats(self, fingerprinter):
        """Test RST TTL statistics analysis"""
        test_fp = DPIFingerprint(target="test:443")
        
        # Test with low TTL
        test_fp.rst_ttl = 50
        result = fingerprinter._analyze_rst_ttl_stats(test_fp)
        assert result["rst_ttl_level"] == "low"
        
        # Test with mid TTL
        test_fp.rst_ttl = 100
        result = fingerprinter._analyze_rst_ttl_stats(test_fp)
        assert result["rst_ttl_level"] == "mid"
        
        # Test with high TTL
        test_fp.rst_ttl = 200
        result = fingerprinter._analyze_rst_ttl_stats(test_fp)
        assert result["rst_ttl_level"] == "high"

    def test_heuristic_classification(self, fingerprinter):
        """Test heuristic DPI classification"""
        test_fp = DPIFingerprint(target="test:443")
        
        # Test TSPU detection
        test_fp.rst_injection_detected = True
        test_fp.dns_hijacking_detected = True
        test_fp.http_header_filtering = True
        test_fp.raw_metrics = {"rst_ttl_stats": {"rst_ttl_level": "low"}}
        
        dpi_type, confidence = fingerprinter._heuristic_classification(test_fp)
        
        assert dpi_type == DPIType.ROSKOMNADZOR_TSPU
        assert confidence > 0.5

    def test_calculate_reliability_score(self, fingerprinter):
        """Test reliability score calculation"""
        test_fp = DPIFingerprint(
            target="test:443",
            confidence=0.8,
            rst_injection_detected=True,
            tcp_window_manipulation=True,
            dns_hijacking_detected=True
        )
        test_fp.analysis_methods_used = ["heuristic", "ml", "behavioral"]
        
        score = fingerprinter._calculate_reliability_score(test_fp)
        
        assert score > 0.5
        assert score <= 1.0


class TestAttackHistoryAndEffectiveness:
    """Test attack history and effectiveness tracking"""

    @pytest.fixture
    def fingerprinter(self):
        """Create fingerprinter for tracking tests"""
        config = FingerprintingConfig(enable_attack_history=True)
        return AdvancedFingerprinter(config=config, cache_file="test.pkl")

    def test_update_with_attack_results(self, fingerprinter):
        """Test updating with attack results"""
        domain = "test.com"
        
        # Create mock attack results
        attack_results = [
            Mock(technique_used="tcp_multisplit", effectiveness=0.9),
            Mock(technique_used="tcp_multisplit", effectiveness=0.8),
            Mock(technique_used="dns_over_https", effectiveness=0.6)
        ]
        
        fingerprinter.update_with_attack_results(domain, attack_results)
        
        assert len(fingerprinter.technique_effectiveness[domain]) == 2
        assert len(fingerprinter.technique_effectiveness[domain]["tcp_multisplit"]) == 2
        assert fingerprinter.technique_effectiveness[domain]["tcp_multisplit"][0] == 0.9

    @pytest.mark.asyncio
    async def test_refine_fingerprint(self, fingerprinter):
        """Test fingerprint refinement"""
        current_fp = DPIFingerprint(
            target="test.com:443",
            dpi_type=DPIType.UNKNOWN,
            confidence=0.5
        )
        
        # Create test results
        test_results = [
            Mock(technique_used="tcp_multisplit", effectiveness=0.9),
            Mock(technique_used="dns_over_https", effectiveness=0.7)
        ]
        
        learning_insights = {
            "successful_patterns": ["pattern1", "pattern2"],
            "optimal_parameters": {"split_pos": 3}
        }
        
        refined = await fingerprinter.refine_fingerprint(
            current_fp, test_results, learning_insights
        )
        
        assert "successful_patterns" in refined.raw_metrics
        assert "optimal_parameters" in refined.raw_metrics
        assert hasattr(refined, 'technique_success_rates')


class TestIntegrationScenarios:
    """Integration test scenarios"""

    @pytest.mark.asyncio
    async def test_full_fingerprinting_workflow(self):
        """Test complete fingerprinting workflow"""
        config = FingerprintingConfig(
            enable_ml=False,
            enable_cache=True,
            enable_behavior_analysis=True,
            enable_attack_recommendations=True,
            enable_extended_metrics=False
        )
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            cache_file = f.name
        
        fingerprinter = AdvancedFingerprinter(config=config, cache_file=cache_file)
        
        try:
            # Mock all network operations
            with patch.object(fingerprinter, '_run_shallow_probe', new_callable=AsyncMock) as mock_probe:
                shallow_fp = DPIFingerprint(target="test.com:443")
                shallow_fp.rst_ttl = 64
                mock_probe.return_value = shallow_fp
                
                with patch.object(fingerprinter, '_perform_comprehensive_analysis', new_callable=AsyncMock) as mock_analysis:
                    comprehensive_fp = DPIFingerprint(
                        target="test.com:443",
                        dpi_type=DPIType.ROSKOMNADZOR_TSPU,
                        confidence=0.85,
                        reliability_score=0.9,
                        rst_injection_detected=True
                    )
                    comprehensive_fp.raw_metrics = {"strategy_hints": ["split_tls_sni"]}
                    mock_analysis.return_value = comprehensive_fp
                    
                    # Mock behavior analysis components
                    with patch.object(fingerprinter, '_analyze_timing_sensitivity_detailed', new_callable=AsyncMock) as mock_timing:
                        mock_timing.return_value = {"connection_delay": 0.5}
                        
                        with patch.object(fingerprinter, '_analyze_burst_tolerance', new_callable=AsyncMock) as mock_burst:
                            mock_burst.return_value = 0.6
                            
                            # Run full workflow
                            result = await fingerprinter.fingerprint_target(
                                "test.com", 443,
                                include_behavior_analysis=True
                            )
                            
                            assert result is not None
                            assert result.dpi_type == DPIType.ROSKOMNADZOR_TSPU
                            assert "behavior_profile" in result.raw_metrics
                            assert "recommendations" in result.raw_metrics
                            assert len(result.raw_metrics["recommendations"]) > 0
                            
                            # Check stats
                            stats = fingerprinter.get_extended_stats()
                            assert stats["fingerprints_created"] == 1
                            assert stats["behavior_profiles_created"] == 1
                            assert stats["attacks_recommended"] == 1
                            
        finally:
            if hasattr(fingerprinter, 'executor'):
                fingerprinter.executor.shutdown(wait=False)

    @pytest.mark.asyncio
    async def test_error_recovery_workflow(self):
        """Test error recovery in fingerprinting workflow"""
        config = FingerprintingConfig(
            fallback_on_error=True,
            enable_ml=False,
            enable_extended_metrics=False
        )
        
        fingerprinter = AdvancedFingerprinter(config=config, cache_file="test.pkl")
        
        try:
            # Simulate network error in shallow probe
            with patch.object(fingerprinter, '_run_shallow_probe', new_callable=AsyncMock) as mock_probe:
                mock_probe.side_effect = Exception("Network unreachable")
                
                result = await fingerprinter.fingerprint_target("unreachable.com", 443)
                
                assert result is not None
                assert result.reliability_score == 0.0
                assert "fallback" in result.analysis_methods_used
                assert fingerprinter.stats["errors"] == 1
                
        finally:
            if hasattr(fingerprinter, 'executor'):
                fingerprinter.executor.shutdown(wait=False)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
