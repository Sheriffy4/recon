"""
Simple integration tests for AdvancedFingerprinter - Task 10 Implementation
Focused tests for core functionality without complex mocking.
"""
import pytest
import tempfile
import os
from unittest.mock import Mock, AsyncMock, patch
from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
from core.fingerprint.advanced_models import DPIFingerprint, DPIType

class TestAdvancedFingerprinteSimple:
    """Simple test suite for AdvancedFingerprinter core functionality"""

    def test_initialization_default_config(self):
        """Test initialization with default configuration"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            fingerprinter = AdvancedFingerprinter(cache_file=cache_file)
            assert fingerprinter is not None
            assert fingerprinter.config is not None
            assert fingerprinter.stats is not None
            assert fingerprinter.executor is not None
            assert fingerprinter.stats['fingerprints_created'] == 0
            assert fingerprinter.stats['cache_hits'] == 0
            assert fingerprinter.stats['cache_misses'] == 0
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    def test_initialization_custom_config(self):
        """Test initialization with custom configuration"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            config = FingerprintingConfig(cache_ttl=1800, enable_ml=False, enable_cache=False, timeout=15.0)
            fingerprinter = AdvancedFingerprinter(config=config, cache_file=cache_file)
            assert fingerprinter.config == config
            assert fingerprinter.config.cache_ttl == 1800
            assert fingerprinter.config.enable_ml == False
            assert fingerprinter.config.timeout == 15.0
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    def test_get_stats(self):
        """Test statistics retrieval"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            fingerprinter = AdvancedFingerprinter(cache_file=cache_file)
            stats = fingerprinter.get_stats()
            required_fields = ['fingerprints_created', 'cache_hits', 'cache_misses', 'ml_classifications', 'fallback_classifications', 'errors', 'total_analysis_time', 'cache_hit_rate', 'avg_analysis_time']
            for field in required_fields:
                assert field in stats
                assert isinstance(stats[field], (int, float))
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check functionality"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            fingerprinter = AdvancedFingerprinter(cache_file=cache_file)
            health = await fingerprinter.health_check()
            assert 'status' in health
            assert 'components' in health
            assert 'timestamp' in health
            components = health['components']
            expected_components = ['cache', 'ml_classifier', 'metrics_collector', 'tcp_analyzer', 'http_analyzer', 'dns_analyzer']
            for component in expected_components:
                assert component in components
                assert 'status' in components[component]
                assert components[component]['status'] in ['healthy', 'disabled', 'unhealthy', 'untrained']
            await fingerprinter.close()
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    def test_heuristic_classification_patterns(self):
        """Test heuristic classification patterns"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            fingerprinter = AdvancedFingerprinter(cache_file=cache_file)
            fingerprint1 = DPIFingerprint(target='test1.com:443', rst_injection_detected=True, dns_hijacking_detected=True, http_header_filtering=True, connection_reset_timing=50.0)
            dpi_type, confidence = fingerprinter._heuristic_classification(fingerprint1)
            assert dpi_type == DPIType.ROSKOMNADZOR_TSPU
            assert confidence > 0.5
            fingerprint2 = DPIFingerprint(target='test2.com:443', content_inspection_depth=1500, user_agent_filtering=True, content_type_filtering=True)
            dpi_type, confidence = fingerprinter._heuristic_classification(fingerprint2)
            assert dpi_type == DPIType.COMMERCIAL_DPI
            assert confidence > 0.5
            fingerprint3 = DPIFingerprint(target='test3.com:443', redirect_injection=True, http_response_modification=True, rst_injection_detected=False)
            dpi_type, confidence = fingerprinter._heuristic_classification(fingerprint3)
            assert dpi_type == DPIType.ISP_TRANSPARENT_PROXY
            assert confidence > 0.5
            fingerprint4 = DPIFingerprint(target='test4.com:443')
            dpi_type, confidence = fingerprinter._heuristic_classification(fingerprint4)
            assert dpi_type == DPIType.UNKNOWN
            assert confidence < 0.5
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    def test_extract_ml_features(self):
        """Test ML feature extraction"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            fingerprinter = AdvancedFingerprinter(cache_file=cache_file)
            fingerprint = DPIFingerprint(target='test.com:443', rst_injection_detected=True, tcp_window_manipulation=False, content_inspection_depth=1000, http_header_filtering=True, dns_hijacking_detected=True, handshake_anomalies=['anomaly1', 'anomaly2'], http_method_restrictions=['POST'], protocol_whitelist=['http', 'https'], packet_size_limitations=1400, analysis_duration=2.5)
            features = fingerprinter._extract_ml_features(fingerprint)
            assert isinstance(features, dict)
            assert features['rst_injection_detected'] == 1
            assert features['tcp_window_manipulation'] == 0
            assert features['content_inspection_depth'] == 1000
            assert features['http_header_filtering'] == 1
            assert features['dns_hijacking_detected'] == 1
            assert features['handshake_anomalies_count'] == 2
            assert features['http_method_restrictions_count'] == 1
            assert features['protocol_whitelist_count'] == 2
            assert features['packet_size_limitations'] == 1400
            assert features['analysis_duration'] == 2.5
            expected_features = ['rst_injection_detected', 'tcp_window_manipulation', 'sequence_number_anomalies', 'tcp_options_filtering', 'connection_reset_timing', 'handshake_anomalies_count', 'mss_clamping_detected', 'tcp_timestamp_manipulation', 'http_header_filtering', 'content_inspection_depth', 'user_agent_filtering', 'host_header_manipulation', 'http_method_restrictions_count', 'content_type_filtering', 'redirect_injection', 'http_response_modification', 'keep_alive_manipulation', 'dns_hijacking_detected', 'dns_response_modification', 'dns_query_filtering', 'doh_blocking', 'dot_blocking', 'dns_cache_poisoning', 'dns_timeout_manipulation', 'recursive_resolver_blocking', 'dns_over_tcp_blocking', 'edns_support', 'supports_ipv6', 'geographic_restrictions', 'time_based_filtering', 'packet_size_limitations', 'protocol_whitelist_count', 'analysis_duration']
            for feature in expected_features:
                assert feature in features
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    def test_calculate_reliability_score(self):
        """Test reliability score calculation"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            fingerprinter = AdvancedFingerprinter(cache_file=cache_file)
            fingerprint1 = DPIFingerprint(target='test1.com:443', confidence=0.9, analysis_methods_used=['tcp_analysis', 'http_analysis', 'dns_analysis'], rst_injection_detected=True, tcp_window_manipulation=True, sequence_number_anomalies=True, tcp_options_filtering=True, mss_clamping_detected=True, http_header_filtering=True, user_agent_filtering=True, host_header_manipulation=True, content_type_filtering=True, redirect_injection=True, dns_hijacking_detected=True, dns_response_modification=True, dns_query_filtering=True, doh_blocking=True, dot_blocking=True)
            reliability1 = fingerprinter._calculate_reliability_score(fingerprint1)
            assert reliability1 > 0.8
            fingerprint2 = DPIFingerprint(target='test2.com:443', confidence=0.2, analysis_methods_used=['fallback'])
            reliability2 = fingerprinter._calculate_reliability_score(fingerprint2)
            assert reliability2 < 0.3
            fingerprint3 = DPIFingerprint(target='test3.com:443', confidence=0.6, analysis_methods_used=['tcp_analysis', 'http_analysis'], rst_injection_detected=True, http_header_filtering=True, dns_hijacking_detected=True)
            reliability3 = fingerprinter._calculate_reliability_score(fingerprint3)
            assert 0.3 < reliability3 < 0.8
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    def test_create_fallback_fingerprint(self):
        """Test fallback fingerprint creation"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            fingerprinter = AdvancedFingerprinter(cache_file=cache_file)
            target = 'error-test.com'
            error_msg = 'Network connection failed'
            fallback = fingerprinter._create_fallback_fingerprint(target, error_msg)
            assert isinstance(fallback, DPIFingerprint)
            assert fallback.target == target
            assert fallback.dpi_type == DPIType.UNKNOWN
            assert fallback.confidence == 0.0
            assert fallback.reliability_score == 0.0
            assert fallback.analysis_duration == 0.0
            assert 'fallback' in fallback.analysis_methods_used
            assert fallback.raw_metrics['error'] == error_msg
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            async with AdvancedFingerprinter(cache_file=cache_file) as fingerprinter:
                assert fingerprinter is not None
                stats = fingerprinter.get_stats()
                assert isinstance(stats, dict)
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    def test_string_representation(self):
        """Test string representation"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            fingerprinter = AdvancedFingerprinter(cache_file=cache_file)
            repr_str = repr(fingerprinter)
            assert 'AdvancedFingerprinter' in repr_str
            assert 'cache=' in repr_str
            assert 'ml=' in repr_str
            assert 'analyzers=' in repr_str
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass

    @pytest.mark.asyncio
    async def test_fingerprint_with_mocked_analyzers(self):
        """Test fingerprinting with mocked analyzers for controlled testing"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
            cache_file = f.name
        try:
            config = FingerprintingConfig(enable_cache=False, enable_ml=False, timeout=1.0)
            fingerprinter = AdvancedFingerprinter(config=config, cache_file=cache_file)
            mock_metrics_result = Mock()
            mock_metrics_result.to_dict.return_value = {'test': 'data'}
            mock_tcp_result = {'rst_injection_detected': True, 'rst_source_analysis': 'middlebox', 'tcp_window_manipulation': False, 'sequence_number_anomalies': True, 'tcp_options_filtering': False, 'connection_reset_timing': 25.0, 'handshake_anomalies': ['test_anomaly'], 'fragmentation_handling': 'blocked', 'mss_clamping_detected': False, 'tcp_timestamp_manipulation': True}
            with patch.object(fingerprinter.metrics_collector, 'collect_comprehensive_metrics', new_callable=AsyncMock) as mock_metrics:
                mock_metrics.return_value = mock_metrics_result
                with patch.object(fingerprinter.tcp_analyzer, 'analyze_tcp_behavior', new_callable=AsyncMock) as mock_tcp:
                    mock_tcp.return_value = mock_tcp_result
                    fingerprint = await fingerprinter.fingerprint_target('test.com', 443)
                    assert isinstance(fingerprint, DPIFingerprint)
                    assert fingerprint.target == 'test.com:443'
                    assert fingerprint.rst_injection_detected == True
                    assert fingerprint.rst_source_analysis == 'middlebox'
                    assert fingerprint.sequence_number_anomalies == True
                    assert len(fingerprint.handshake_anomalies) == 1
                    assert fingerprint.handshake_anomalies[0] == 'test_anomaly'
                    mock_metrics.assert_called_once()
                    mock_tcp.assert_called_once()
            await fingerprinter.close()
        finally:
            try:
                os.unlink(cache_file)
            except FileNotFoundError:
                pass
if __name__ == '__main__':
    pytest.main([__file__, '-v'])