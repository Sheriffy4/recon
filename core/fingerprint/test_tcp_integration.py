# recon/core/fingerprint/test_tcp_integration.py
"""
Integration test for TCP Analyzer with the existing fingerprinting system
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock

from .tcp_analyzer import TCPAnalyzer
from . import TCPAnalyzer as ImportedTCPAnalyzer


class TestTCPAnalyzerIntegration:
    """Integration tests for TCP Analyzer"""
    
    def test_tcp_analyzer_import(self):
        """Test that TCP analyzer can be imported from the module"""
        assert TCPAnalyzer is not None
        assert ImportedTCPAnalyzer is not None
        assert TCPAnalyzer == ImportedTCPAnalyzer
    
    def test_tcp_analyzer_initialization(self):
        """Test TCP analyzer can be initialized"""
        analyzer = TCPAnalyzer(timeout=5.0, max_attempts=3)
        assert analyzer.timeout == 5.0
        assert analyzer.max_attempts == 3
        assert analyzer.rst_timing_threshold_ms == 100
    
    @pytest.mark.asyncio
    async def test_tcp_analyzer_basic_functionality(self):
        """Test basic TCP analyzer functionality with mocked network"""
        analyzer = TCPAnalyzer(timeout=2.0, max_attempts=2)
        
        # Mock the DNS resolution and analysis methods
        with patch.object(analyzer, '_resolve_target', return_value="127.0.0.1") as mock_resolve, \
             patch.object(analyzer, '_analyze_basic_connections') as mock_basic, \
             patch.object(analyzer, '_analyze_rst_injection') as mock_rst, \
             patch.object(analyzer, '_analyze_window_manipulation') as mock_window, \
             patch.object(analyzer, '_analyze_sequence_numbers') as mock_seq, \
             patch.object(analyzer, '_analyze_fragmentation_handling') as mock_frag, \
             patch.object(analyzer, '_analyze_tcp_options') as mock_options:
            
            # Configure mocks to modify the result object
            def mock_basic_analysis(result, target_ip, port):
                result.rst_injection_detected = True
                result.rst_source_analysis = "middlebox"
            
            def mock_rst_analysis(result, target_ip, port):
                result.rst_timing_patterns = [45.0, 50.0, 48.0]
            
            def mock_window_analysis(result, target_ip, port):
                result.tcp_window_manipulation = True
                result.window_size_variations = [1024, 8192, 16384]
            
            def mock_seq_analysis(result, target_ip, port):
                result.sequence_number_anomalies = False
                result.seq_prediction_difficulty = 0.7
            
            def mock_frag_analysis(result, target_ip, port):
                result.fragmentation_handling = "blocked"
                result.mss_clamping_detected = True
            
            def mock_options_analysis(result, target_ip, port):
                result.tcp_options_filtering = ["WScale", "SAckOK"]
                result.syn_flood_protection = True
            
            mock_basic.side_effect = mock_basic_analysis
            mock_rst.side_effect = mock_rst_analysis
            mock_window.side_effect = mock_window_analysis
            mock_seq.side_effect = mock_seq_analysis
            mock_frag.side_effect = mock_frag_analysis
            mock_options.side_effect = mock_options_analysis
            
            # Run the analysis
            result = await analyzer.analyze_tcp_behavior("test.example.com", 443)
            
            # Verify the result structure and content
            assert isinstance(result, dict)
            assert result['target'] == "test.example.com"
            assert result['rst_injection_detected'] == True
            assert result['rst_source_analysis'] == "middlebox"
            assert result['tcp_window_manipulation'] == True
            assert result['fragmentation_handling'] == "blocked"
            assert result['mss_clamping_detected'] == True
            assert result['syn_flood_protection'] == True
            assert len(result['rst_timing_patterns']) == 3
            assert len(result['window_size_variations']) == 3
            assert len(result['tcp_options_filtering']) == 2
            assert 0.0 <= result['reliability_score'] <= 1.0
            
            # Verify all analysis methods were called
            mock_resolve.assert_called_once_with("test.example.com")
            mock_basic.assert_called_once()
            mock_rst.assert_called_once()
            mock_window.assert_called_once()
            mock_seq.assert_called_once()
            mock_frag.assert_called_once()
            mock_options.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_tcp_analyzer_error_handling(self):
        """Test TCP analyzer error handling"""
        analyzer = TCPAnalyzer(timeout=1.0, max_attempts=1)
        
        # Mock DNS resolution to fail
        with patch.object(analyzer, '_resolve_target', side_effect=Exception("DNS failed")):
            
            with pytest.raises(Exception):
                await analyzer.analyze_tcp_behavior("invalid.domain", 443)
    
    def test_tcp_analysis_result_serialization(self):
        """Test that TCP analysis results can be serialized"""
        from .tcp_analyzer import TCPAnalysisResult
        
        result = TCPAnalysisResult(target="test.com")
        result.rst_injection_detected = True
        result.rst_source_analysis = "middlebox"
        result.tcp_window_manipulation = True
        result.reliability_score = 0.85
        
        # Test to_dict conversion
        result_dict = result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert result_dict['target'] == "test.com"
        assert result_dict['rst_injection_detected'] == True
        assert result_dict['rst_source_analysis'] == "middlebox"
        assert result_dict['tcp_window_manipulation'] == True
        assert result_dict['reliability_score'] == 0.85
        
        # Verify all expected fields are present
        expected_fields = [
            'target', 'timestamp', 'rst_injection_detected', 'rst_source_analysis',
            'rst_timing_patterns', 'rst_ttl_analysis', 'tcp_window_manipulation',
            'window_size_variations', 'window_scaling_blocked', 'sequence_number_anomalies',
            'seq_prediction_difficulty', 'ack_number_manipulation', 'fragmentation_handling',
            'mss_clamping_detected', 'fragment_timeout_ms', 'tcp_options_filtering',
            'tcp_timestamp_manipulation', 'connection_state_tracking', 'syn_flood_protection',
            'reliability_score', 'analysis_errors'
        ]
        
        for field in expected_fields:
            assert field in result_dict, f"Missing field: {field}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])