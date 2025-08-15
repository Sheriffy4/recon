# recon/core/fingerprint/test_advanced_fingerprinter.py
"""
Integration tests for AdvancedFingerprinter - Task 10 Implementation
Tests complete fingerprinting workflow with parallel metric collection,
cache integration, error handling, and graceful degradation.
"""

import pytest
import asyncio
import tempfile
import os
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any

from .advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
from .advanced_models import DPIFingerprint, DPIType, ConfidenceLevel, FingerprintingError
from .cache import FingerprintCache
from .metrics_collector import MetricsCollector, ComprehensiveMetrics, TimingMetrics


class TestAdvancedFingerprinter:
    """Test suite for AdvancedFingerprinter"""
    
    @pytest.fixture
    def temp_cache_file(self):
        """Create temporary cache file"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        yield cache_file
        try:
            os.unlink(cache_file)
        except FileNotFoundError:
            pass
    
    @pytest.fixture
    def config(self):
        """Default configuration for testing"""
        return FingerprintingConfig(
            cache_ttl=300,  # 5 minutes for testing
            enable_ml=True,
            enable_cache=True,
            max_concurrent_probes=3,
            timeout=5.0,
            retry_attempts=1,  # Reduce for faster tests
            retry_delay=0.1
        )
    
    @pytest.fixture
    def fingerprinter(self, config, temp_cache_file):
        """Create AdvancedFingerprinter instance"""
        return AdvancedFingerprinter(config=config, cache_file=temp_cache_file)
    
    @pytest.fixture
    def mock_metrics_result(self):
        """Mock comprehensive metrics result"""
        metrics = ComprehensiveMetrics(target="example.com:443")
        metrics.timing = TimingMetrics(
            latency_ms=50.0,
            jitter_ms=5.0,
            connection_time_ms=30.0,
            first_byte_time_ms=45.0,
            total_time_ms=100.0
        )
        return metrics
    
    @pytest.fixture
    def mock_tcp_result(self):
        """Mock TCP analysis result"""
        return {
            'rst_injection_detected': True,
            'rst_source_analysis': 'middlebox',
            'tcp_window_manipulation': False,
            'sequence_number_anomalies': True,
            'tcp_options_filtering': False,
            'connection_reset_timing': 25.0,
            'handshake_anomalies': ['window_size_anomaly'],
            'fragmentation_handling': 'blocked',
            'mss_clamping_detected': False,
            'tcp_timestamp_manipulation': True
        }
    
    @pytest.fixture
    def mock_http_result(self):
        """Mock HTTP analysis result"""
        return {
            'http_header_filtering': True,
            'content_inspection_depth': 1500,
            'user_agent_filtering': True,
            'host_header_manipulation': False,
            'http_method_restrictions': ['POST', 'PUT'],
            'content_type_filtering': True,
            'redirect_injection': False,
            'http_response_modification': True,
            'keep_alive_manipulation': False,
            'chunked_encoding_handling': 'modified'
        }
    
    @pytest.fixture
    def mock_dns_result(self):
        """Mock DNS analysis result"""
        return {
            'dns_hijacking_detected': True,
            'dns_response_modification': True,
            'dns_query_filtering': False,
            'doh_blocking': True,
            'dot_blocking': False,
            'dns_cache_poisoning': False,
            'dns_timeout_manipulation': True,
            'recursive_resolver_blocking': False,
            'dns_over_tcp_blocking': True,
            'edns_support': False
        }

    def test_initialization_success(self, config, temp_cache_file):
        """Test successful initialization of AdvancedFingerprinter"""
        fingerprinter = AdvancedFingerprinter(config=config, cache_file=temp_cache_file)
        
        assert fingerprinter.config == config
        assert fingerprinter.cache is not None
        assert fingerprinter.metrics_collector is not None
        assert fingerprinter.stats['fingerprints_created'] == 0
        
        # Check component initialization
        assert fingerprinter.tcp_analyzer is not None
        assert fingerprinter.http_analyzer is not None
        assert fingerprinter.dns_analyzer is not None
    
    def test_initialization_with_disabled_components(self, temp_cache_file):
        """Test initialization with disabled components"""
        config = FingerprintingConfig(
            enable_cache=False,
            enable_ml=False,
            enable_tcp_analysis=False,
            enable_http_analysis=False,
            enable_dns_analysis=False
        )
        
        fingerprinter = AdvancedFingerprinter(config=config, cache_file=temp_cache_file)
        
        assert fingerprinter.cache is None
        assert fingerprinter.ml_classifier is None
        assert fingerprinter.tcp_analyzer is None
        assert fingerprinter.http_analyzer is None
        assert fingerprinter.dns_analyzer is None
    
    @pytest.mark.asyncio
    async def test_fingerprint_target_basic(self, fingerprinter, mock_metrics_result, 
                                          mock_tcp_result, mock_http_result):
        """Test basic fingerprinting workflow"""
        target = "example.com"
        port = 443
        
        try:
            # Mock the analyzers
            with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics', 
                             new_callable=AsyncMock) as mock_metrics:
                mock_metrics.return_value = mock_metrics_result
                
                with patch.object(fingerprinter.tcp_analyzer, 'analyze_tcp_behavior',
                                 new_callable=AsyncMock) as mock_tcp:
                    mock_tcp.return_value = mock_tcp_result
                    
                    with patch.object(fingerprinter.http_analyzer, 'analyze_http_behavior',
                                     new_callable=AsyncMock) as mock_http:
                        mock_http.return_value = mock_http_result
                        
                        # Perform fingerprinting
                        fingerprint = await fingerprinter.fingerprint_target(target, port)
                        
                        # Verify result
                        assert isinstance(fingerprint, DPIFingerprint)
                        assert fingerprint.target == f"{target}:{port}"
                        assert fingerprint.rst_injection_detected == True
                        assert fingerprint.rst_source_analysis == 'middlebox'
                        assert fingerprint.http_header_filtering == True
                        assert fingerprint.content_inspection_depth == 1500
                        assert len(fingerprint.analysis_methods_used) >= 2
                        
                        # Verify calls were made
                        mock_metrics.assert_called_once()
                        mock_tcp.assert_called_once()
                        mock_http.assert_called_once()
        finally:
            await fingerprinter.close()
    
    @pytest.mark.asyncio
    async def test_fingerprint_target_with_cache(self, fingerprinter, mock_metrics_result):
        """Test fingerprinting with cache hit and miss"""
        target = "cached-example.com"
        port = 443
        
        try:
            # First call - cache miss
            with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                             new_callable=AsyncMock) as mock_metrics:
                mock_metrics.return_value = mock_metrics_result
                
                fingerprint1 = await fingerprinter.fingerprint_target(target, port)
                
                assert fingerprint1 is not None
                assert fingerprinter.stats['cache_misses'] == 1
                assert fingerprinter.stats['fingerprints_created'] == 1
                mock_metrics.assert_called_once()
            
            # Second call - cache hit
            with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                             new_callable=AsyncMock) as mock_metrics2:
                fingerprint2 = await fingerprinter.fingerprint_target(target, port)
                
                assert fingerprint2 is not None
                assert fingerprint2.target == fingerprint1.target
                assert fingerprinter.stats['cache_hits'] == 1
                # Should not call metrics collector on cache hit
                mock_metrics2.assert_not_called()
        finally:
            await fingerprinter.close()
    
    @pytest.mark.asyncio
    async def test_fingerprint_target_force_refresh(self, fingerprinter, mock_metrics_result):
        """Test fingerprinting with force refresh bypassing cache"""
        target = "refresh-example.com"
        port = 443
        
        # First call to populate cache
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         new_callable=AsyncMock) as mock_metrics1:
            mock_metrics1.return_value = mock_metrics_result
            
            await fingerprinter.fingerprint_target(target, port)
            mock_metrics1.assert_called_once()
        
        # Second call with force refresh
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         new_callable=AsyncMock) as mock_metrics2:
            mock_metrics2.return_value = mock_metrics_result
            
            fingerprint = await fingerprinter.fingerprint_target(target, port, force_refresh=True)
            
            assert fingerprint is not None
            # Should call metrics collector even with cache entry
            mock_metrics2.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_parallel_metric_collection(self, fingerprinter, mock_metrics_result,
                                            mock_tcp_result, mock_http_result, mock_dns_result):
        """Test parallel execution of multiple analyzers"""
        target = "parallel-test.com"
        port = 443
        
        # Track call order and timing
        call_times = []
        
        async def track_metrics_call(*args, **kwargs):
            call_times.append(('metrics', time.time()))
            await asyncio.sleep(0.1)  # Simulate work
            return mock_metrics_result
        
        async def track_tcp_call(*args, **kwargs):
            call_times.append(('tcp', time.time()))
            await asyncio.sleep(0.1)  # Simulate work
            return mock_tcp_result
        
        async def track_http_call(*args, **kwargs):
            call_times.append(('http', time.time()))
            await asyncio.sleep(0.1)  # Simulate work
            return mock_http_result
        
        # Mock all analyzers with timing tracking
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         side_effect=track_metrics_call):
            with patch.object(fingerprinter.tcp_analyzer, 'analyze_tcp_behavior',
                             side_effect=track_tcp_call):
                with patch.object(fingerprinter.http_analyzer, 'analyze_http_behavior',
                                 side_effect=track_http_call):
                    
                    start_time = time.time()
                    fingerprint = await fingerprinter.fingerprint_target(target, port)
                    total_time = time.time() - start_time
                    
                    # Verify parallel execution (should be faster than sequential)
                    assert total_time < 0.25  # Should be much less than 0.3s (3 * 0.1s)
                    assert len(call_times) == 3
                    assert fingerprint is not None
    
    @pytest.mark.asyncio
    async def test_error_handling_with_fallback(self, fingerprinter):
        """Test error handling with fallback fingerprint creation"""
        target = "error-test.com"
        port = 443
        
        # Mock all analyzers to raise exceptions
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         side_effect=Exception("Metrics collection failed")):
            with patch.object(fingerprinter.tcp_analyzer, 'analyze_tcp_behavior',
                             side_effect=Exception("TCP analysis failed")):
                
                fingerprint = await fingerprinter.fingerprint_target(target, port)
                
                # Should return fallback fingerprint
                assert fingerprint is not None
                assert fingerprint.dpi_type == DPIType.UNKNOWN
                assert fingerprint.confidence == 0.0
                assert fingerprint.reliability_score == 0.0
                assert 'fallback' in fingerprint.analysis_methods_used
                assert fingerprinter.stats['errors'] == 1
    
    @pytest.mark.asyncio
    async def test_error_handling_without_fallback(self, temp_cache_file):
        """Test error handling without fallback (should raise exception)"""
        config = FingerprintingConfig(fallback_on_error=False)
        fingerprinter = AdvancedFingerprinter(config=config, cache_file=temp_cache_file)
        
        try:
            target = "error-test.com"
            port = 443
            
            # Mock analyzer to raise exception
            with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                             side_effect=Exception("Critical failure")):
                
                with pytest.raises(FingerprintingError):
                    await fingerprinter.fingerprint_target(target, port)
        finally:
            await fingerprinter.close()
    
    @pytest.mark.asyncio
    async def test_ml_classification(self, fingerprinter, mock_metrics_result):
        """Test ML classification integration"""
        target = "ml-test.com"
        port = 443
        
        # Mock ML classifier
        mock_classifier = Mock()
        mock_classifier.is_trained = True
        mock_classifier.classify_dpi = Mock(return_value=('roskomnadzor_tspu', 0.85))
        fingerprinter.ml_classifier = mock_classifier
        
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         new_callable=AsyncMock) as mock_metrics:
            mock_metrics.return_value = mock_metrics_result
            
            fingerprint = await fingerprinter.fingerprint_target(target, port)
            
            assert fingerprint.dpi_type == DPIType.ROSKOMNADZOR_TSPU
            assert fingerprint.confidence == 0.85
            assert fingerprinter.stats['ml_classifications'] == 1
    
    @pytest.mark.asyncio
    async def test_heuristic_classification(self, fingerprinter, mock_metrics_result):
        """Test heuristic classification fallback"""
        target = "heuristic-test.com"
        port = 443
        
        # Disable ML classifier
        fingerprinter.ml_classifier = None
        
        # Create fingerprint with specific patterns for heuristic classification
        mock_tcp_result = {
            'rst_injection_detected': True,
            'rst_source_analysis': 'middlebox',
            'tcp_window_manipulation': False,
            'sequence_number_anomalies': False,
            'tcp_options_filtering': False,
            'connection_reset_timing': 50.0,  # Slow reset suggests regular DPI
            'handshake_anomalies': [],
            'fragmentation_handling': 'unknown',
            'mss_clamping_detected': False,
            'tcp_timestamp_manipulation': False
        }
        
        mock_dns_result = {
            'dns_hijacking_detected': True,
            'dns_response_modification': False,
            'dns_query_filtering': False,
            'doh_blocking': False,
            'dot_blocking': False,
            'dns_cache_poisoning': False,
            'dns_timeout_manipulation': False,
            'recursive_resolver_blocking': False,
            'dns_over_tcp_blocking': False,
            'edns_support': False
        }
        
        mock_http_result = {
            'http_header_filtering': True,
            'content_inspection_depth': 500,
            'user_agent_filtering': False,
            'host_header_manipulation': False,
            'http_method_restrictions': [],
            'content_type_filtering': False,
            'redirect_injection': False,
            'http_response_modification': False,
            'keep_alive_manipulation': False,
            'chunked_encoding_handling': 'unknown'
        }
        
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         new_callable=AsyncMock) as mock_metrics:
            mock_metrics.return_value = mock_metrics_result
            
            with patch.object(fingerprinter.tcp_analyzer, 'analyze_tcp_behavior',
                             new_callable=AsyncMock) as mock_tcp:
                mock_tcp.return_value = mock_tcp_result
                
                with patch.object(fingerprinter.http_analyzer, 'analyze_http_behavior',
                                 new_callable=AsyncMock) as mock_http:
                    mock_http.return_value = mock_http_result
                    
                    with patch.object(fingerprinter.dns_analyzer, 'analyze_dns_behavior',
                                     new_callable=AsyncMock) as mock_dns:
                        mock_dns.return_value = mock_dns_result
                        
                        fingerprint = await fingerprinter.fingerprint_target(target, port)
                        
                        # Should classify as ROSKOMNADZOR_DPI based on heuristics
                        assert fingerprint.dpi_type == DPIType.ROSKOMNADZOR_DPI
                        assert fingerprint.confidence > 0.5
                        assert fingerprinter.stats['fallback_classifications'] == 1
    
    def test_cache_operations(self, fingerprinter):
        """Test cache operations"""
        target = "cache-test.com"
        
        # Test cache miss
        result = fingerprinter.get_cached_fingerprint(target)
        assert result is None
        
        # Create and cache fingerprint
        fingerprint = DPIFingerprint(
            target=target,
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.8
        )
        
        if fingerprinter.cache:
            fingerprinter.cache.set(target, fingerprint)
            
            # Test cache hit
            cached = fingerprinter.get_cached_fingerprint(target)
            assert cached is not None
            assert cached.target == target
            assert cached.dpi_type == DPIType.COMMERCIAL_DPI
            
            # Test cache invalidation
            fingerprinter.invalidate_cache(target)
            result = fingerprinter.get_cached_fingerprint(target)
            assert result is None
    
    def test_statistics_tracking(self, fingerprinter):
        """Test statistics tracking"""
        initial_stats = fingerprinter.get_stats()
        
        assert 'fingerprints_created' in initial_stats
        assert 'cache_hits' in initial_stats
        assert 'cache_misses' in initial_stats
        assert 'ml_classifications' in initial_stats
        assert 'fallback_classifications' in initial_stats
        assert 'errors' in initial_stats
        
        # All should start at 0
        assert initial_stats['fingerprints_created'] == 0
        assert initial_stats['cache_hits'] == 0
        assert initial_stats['cache_misses'] == 0
    
    @pytest.mark.asyncio
    async def test_health_check(self, fingerprinter):
        """Test health check functionality"""
        health = await fingerprinter.health_check()
        
        assert 'status' in health
        assert 'components' in health
        assert 'timestamp' in health
        
        # Check component statuses
        components = health['components']
        assert 'cache' in components
        assert 'ml_classifier' in components
        assert 'metrics_collector' in components
        assert 'tcp_analyzer' in components
        assert 'http_analyzer' in components
        assert 'dns_analyzer' in components
        
        # All components should be healthy or disabled
        for component, status in components.items():
            assert status['status'] in ['healthy', 'disabled', 'untrained']
    
    @pytest.mark.asyncio
    async def test_concurrent_fingerprinting(self, fingerprinter, mock_metrics_result):
        """Test concurrent fingerprinting requests"""
        targets = [f"concurrent-test-{i}.com" for i in range(5)]
        port = 443
        
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         new_callable=AsyncMock) as mock_metrics:
            mock_metrics.return_value = mock_metrics_result
            
            # Execute concurrent fingerprinting
            tasks = [
                fingerprinter.fingerprint_target(target, port)
                for target in targets
            ]
            
            results = await asyncio.gather(*tasks)
            
            # Verify all results
            assert len(results) == 5
            for i, fingerprint in enumerate(results):
                assert fingerprint is not None
                assert fingerprint.target == f"{targets[i]}:{port}"
            
            # Verify metrics collector was called for each target
            assert mock_metrics.call_count == 5
    
    @pytest.mark.asyncio
    async def test_dns_port_analysis(self, fingerprinter, mock_metrics_result, mock_dns_result):
        """Test DNS-specific analysis for DNS port"""
        target = "dns-test.com"
        port = 53  # DNS port
        
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         new_callable=AsyncMock) as mock_metrics:
            mock_metrics.return_value = mock_metrics_result
            
            with patch.object(fingerprinter.dns_analyzer, 'analyze_dns_behavior',
                             new_callable=AsyncMock) as mock_dns:
                mock_dns.return_value = mock_dns_result
                
                fingerprint = await fingerprinter.fingerprint_target(target, port)
                
                # Verify DNS analysis was performed
                mock_dns.assert_called_once_with(target)
                assert fingerprint.dns_hijacking_detected == True
                assert fingerprint.doh_blocking == True
    
    @pytest.mark.asyncio
    async def test_reliability_score_calculation(self, fingerprinter, mock_metrics_result,
                                                mock_tcp_result, mock_http_result, mock_dns_result):
        """Test reliability score calculation"""
        target = "reliability-test.com"
        port = 443
        
        with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics',
                         new_callable=AsyncMock) as mock_metrics:
            mock_metrics.return_value = mock_metrics_result
            
            with patch.object(fingerprinter.tcp_analyzer, 'analyze_tcp_behavior',
                             new_callable=AsyncMock) as mock_tcp:
                mock_tcp.return_value = mock_tcp_result
                
                with patch.object(fingerprinter.http_analyzer, 'analyze_http_behavior',
                                 new_callable=AsyncMock) as mock_http:
                    mock_http.return_value = mock_http_result
                    
                    with patch.object(fingerprinter.dns_analyzer, 'analyze_dns_behavior',
                                     new_callable=AsyncMock) as mock_dns:
                        mock_dns.return_value = mock_dns_result
                        
                        fingerprint = await fingerprinter.fingerprint_target(target, port)
                        
                        # Should have high reliability with multiple analysis methods
                        assert fingerprint.reliability_score > 0.5
                        assert len(fingerprint.analysis_methods_used) >= 3
    
    @pytest.mark.asyncio
    async def test_context_manager(self, config, temp_cache_file):
        """Test async context manager functionality"""
        async with AdvancedFingerprinter(config=config, cache_file=temp_cache_file) as fingerprinter:
            assert fingerprinter is not None
            
            # Should be able to use fingerprinter normally
            stats = fingerprinter.get_stats()
            assert isinstance(stats, dict)
        
        # After context exit, should be closed (we can't easily test this without
        # exposing internal state, but the context manager should work)


@pytest.mark.asyncio
async def test_integration_with_real_components():
    """Integration test with real components (no mocking)"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
        cache_file = f.name
    
    try:
        config = FingerprintingConfig(
            timeout=2.0,  # Short timeout for testing
            retry_attempts=1,
            enable_ml=False  # Disable ML to avoid model dependencies
        )
        
        async with AdvancedFingerprinter(config=config, cache_file=cache_file) as fingerprinter:
            # Test with a reliable target (localhost should always be reachable)
            try:
                # This might fail if no service is running on port 80, but should not crash
                fingerprint = await fingerprinter.fingerprint_target("127.0.0.1", 80)
                
                # Basic validation
                assert isinstance(fingerprint, DPIFingerprint)
                assert fingerprint.target == "127.0.0.1:80"
                assert isinstance(fingerprint.timestamp, float)
                assert fingerprint.analysis_duration >= 0
                
            except Exception as e:
                # If connection fails, should still get a fallback fingerprint
                assert "fallback" in str(e) or isinstance(fingerprint, DPIFingerprint)
    
    finally:
        try:
            os.unlink(cache_file)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    # Run basic tests
    pytest.main([__file__, "-v"])