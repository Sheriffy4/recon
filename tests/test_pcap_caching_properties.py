"""
Property-based tests for PCAP analysis caching.

Feature: strategy-testing-production-parity, Property 8: PCAP is analyzed exactly once per test
Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5

For any test session with a PCAP file, the PCAP must be analyzed exactly once,
with results cached and reused by all components that need them.
"""

import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, MagicMock, call
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.test_result_coordinator import TestResultCoordinator
from core.test_result_models import PCAPAnalysisResult
from core.pcap.analyzer import StrategyAnalysisResult


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_domain(draw):
    """Generate valid domain names."""
    tld = draw(st.sampled_from(['com', 'org', 'net', 'io', 'ru']))
    domain_name = draw(st.text(
        alphabet='abcdefghijklmnopqrstuvwxyz0123456789-',
        min_size=3,
        max_size=20
    ).filter(lambda x: not x.startswith('-') and not x.endswith('-')))
    
    return f"{domain_name}.{tld}"


@st.composite
def valid_strategy_name(draw):
    """Generate valid strategy names."""
    return draw(st.text(
        alphabet='abcdefghijklmnopqrstuvwxyz_',
        min_size=3,
        max_size=30
    ))


@st.composite
def pcap_analysis_request(draw):
    """Generate a PCAP analysis request with domain, strategy, and file path."""
    domain = draw(valid_domain())
    strategy = draw(valid_strategy_name())
    
    # Generate a unique PCAP file path
    pcap_id = draw(st.text(min_size=8, max_size=16, alphabet='abcdefghijklmnopqrstuvwxyz0123456789'))
    pcap_file = f"/tmp/test_{pcap_id}.pcap"
    
    return {
        'domain': domain,
        'strategy': strategy,
        'pcap_file': pcap_file
    }


# ============================================================================
# Helper Functions
# ============================================================================

def create_mock_pcap_analyzer():
    """Create a mock PCAP analyzer that tracks analysis calls."""
    mock_analyzer = Mock()
    
    # Track how many times analyze_pcap is called
    call_count = {'count': 0}
    
    def mock_analyze(pcap_file):
        call_count['count'] += 1
        
        # Return a mock PCAPAnalysisResult (Task 3.4: structured result format)
        return PCAPAnalysisResult(
            pcap_file=pcap_file,
            packet_count=10,
            detected_attacks=['split'],
            parameters={'split_pos': 3},
            split_positions=[3, 5],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version='1.0'
        )
    
    mock_analyzer.analyze_pcap = Mock(side_effect=mock_analyze)
    mock_analyzer.call_count = call_count
    
    return mock_analyzer


def create_temp_pcap_file():
    """Create a temporary PCAP file for testing."""
    temp_file = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    temp_file.write(b'\x00' * 100)  # Write some dummy data
    temp_file.close()
    return temp_file.name


# ============================================================================
# Property Tests for PCAP Caching
# ============================================================================

class TestPCAPCachingProperty:
    """
    **Feature: strategy-testing-production-parity, Property 8: PCAP is analyzed exactly once per test**
    **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**
    
    Property: For any test session with a PCAP file, the PCAP must be analyzed exactly once,
    with results cached and reused by all components that need them.
    """
    
    @given(request=pcap_analysis_request())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_pcap_analyzed_exactly_once_per_file(self, request):
        """
        Test that each PCAP file is analyzed exactly once.
        
        For any PCAP file, regardless of how many times analysis is requested,
        the actual analysis should only occur once, with subsequent requests
        returning cached results.
        
        Validates: Requirements 6.1, 6.2, 6.3
        """
        # Create mock analyzer
        mock_analyzer = create_mock_pcap_analyzer()
        
        # Create coordinator with mock analyzer
        coordinator = TestResultCoordinator(pcap_analyzer=mock_analyzer)
        
        # Create a temporary PCAP file
        pcap_file = create_temp_pcap_file()
        
        try:
            # Request analysis multiple times (2-5 times)
            num_requests = 3
            results = []
            
            for i in range(num_requests):
                result = coordinator.get_pcap_analysis(pcap_file)
                results.append(result)
            
            # Verify analysis was called exactly once
            assert mock_analyzer.call_count['count'] == 1, \
                f"PCAP analysis should be called exactly once, but was called {mock_analyzer.call_count['count']} times"
            
            # Verify all results are identical (same object from cache)
            for i in range(1, len(results)):
                assert results[i] is results[0], \
                    f"All analysis results should be the same cached object"
        
        finally:
            # Clean up temp file
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        request1=pcap_analysis_request(),
        request2=pcap_analysis_request()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_different_pcap_files_analyzed_separately(self, request1, request2):
        """
        Test that different PCAP files are analyzed separately.
        
        For any two different PCAP files, each should be analyzed once,
        and their results should be cached independently.
        
        Validates: Requirements 6.1, 6.2
        """
        # Ensure we have different PCAP files
        assume(request1['pcap_file'] != request2['pcap_file'])
        
        # Create mock analyzer
        mock_analyzer = create_mock_pcap_analyzer()
        
        # Create coordinator with mock analyzer
        coordinator = TestResultCoordinator(pcap_analyzer=mock_analyzer)
        
        # Create two temporary PCAP files
        pcap_file1 = create_temp_pcap_file()
        pcap_file2 = create_temp_pcap_file()
        
        try:
            # Analyze first file twice
            result1a = coordinator.get_pcap_analysis(pcap_file1)
            result1b = coordinator.get_pcap_analysis(pcap_file1)
            
            # Analyze second file twice
            result2a = coordinator.get_pcap_analysis(pcap_file2)
            result2b = coordinator.get_pcap_analysis(pcap_file2)
            
            # Verify analysis was called exactly twice (once per file)
            assert mock_analyzer.call_count['count'] == 2, \
                f"PCAP analysis should be called twice (once per file), but was called {mock_analyzer.call_count['count']} times"
            
            # Verify results for same file are identical
            assert result1a is result1b, "Results for same file should be cached"
            assert result2a is result2b, "Results for same file should be cached"
            
            # Verify results for different files are different
            assert result1a is not result2a, "Results for different files should be different"
        
        finally:
            # Clean up temp files
            Path(pcap_file1).unlink(missing_ok=True)
            Path(pcap_file2).unlink(missing_ok=True)
    
    @given(request=pcap_analysis_request())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_cache_persists_across_multiple_sessions(self, request):
        """
        Test that PCAP cache persists across multiple test sessions.
        
        For any PCAP file used by multiple test sessions, the analysis
        should only occur once, with all sessions using the cached result.
        
        Validates: Requirements 6.2, 6.3
        """
        # Create mock analyzer
        mock_analyzer = create_mock_pcap_analyzer()
        
        # Create coordinator with mock analyzer
        coordinator = TestResultCoordinator(pcap_analyzer=mock_analyzer)
        
        # Create a temporary PCAP file
        pcap_file = create_temp_pcap_file()
        
        try:
            # Start multiple test sessions using the same PCAP file
            num_sessions = 3
            session_ids = []
            
            for i in range(num_sessions):
                session_id = coordinator.start_test(
                    domain=f"{request['domain']}{i}",
                    strategy_name=request['strategy'],
                    pcap_file=pcap_file
                )
                session_ids.append(session_id)
            
            # Request PCAP analysis for each session
            results = []
            for session_id in session_ids:
                result = coordinator.get_pcap_analysis(pcap_file)
                results.append(result)
            
            # Verify analysis was called exactly once
            assert mock_analyzer.call_count['count'] == 1, \
                f"PCAP analysis should be called exactly once across all sessions, but was called {mock_analyzer.call_count['count']} times"
            
            # Verify all sessions got the same cached result
            for i in range(1, len(results)):
                assert results[i] is results[0], \
                    f"All sessions should receive the same cached PCAP analysis result"
        
        finally:
            # Clean up temp file
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(request=pcap_analysis_request())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_missing_pcap_file_returns_none_without_caching(self, request):
        """
        Test that missing PCAP files return None and are not cached.
        
        For any non-existent PCAP file, the analysis should return None
        and should not cache the None result (allowing retry if file appears later).
        
        Validates: Requirements 6.1
        """
        # Create mock analyzer
        mock_analyzer = create_mock_pcap_analyzer()
        
        # Create coordinator with mock analyzer
        coordinator = TestResultCoordinator(pcap_analyzer=mock_analyzer)
        
        # Use a non-existent PCAP file
        pcap_file = "/tmp/nonexistent_file_12345.pcap"
        
        # Ensure file doesn't exist
        Path(pcap_file).unlink(missing_ok=True)
        
        # Request analysis multiple times
        result1 = coordinator.get_pcap_analysis(pcap_file)
        result2 = coordinator.get_pcap_analysis(pcap_file)
        
        # Verify both results are None
        assert result1 is None, "Missing PCAP file should return None"
        assert result2 is None, "Missing PCAP file should return None"
        
        # Verify analyzer was never called (file doesn't exist)
        assert mock_analyzer.call_count['count'] == 0, \
            f"Analyzer should not be called for missing file, but was called {mock_analyzer.call_count['count']} times"
    
    @given(request=pcap_analysis_request())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_cache_clear_allows_reanalysis(self, request):
        """
        Test that clearing the cache allows PCAP to be reanalyzed.
        
        For any PCAP file, after clearing the cache, the next analysis
        request should trigger a new analysis (not use cached result).
        
        Validates: Requirements 6.2
        """
        # Create mock analyzer
        mock_analyzer = create_mock_pcap_analyzer()
        
        # Create coordinator with mock analyzer
        coordinator = TestResultCoordinator(pcap_analyzer=mock_analyzer)
        
        # Create a temporary PCAP file
        pcap_file = create_temp_pcap_file()
        
        try:
            # First analysis
            result1 = coordinator.get_pcap_analysis(pcap_file)
            
            # Verify analysis was called once
            assert mock_analyzer.call_count['count'] == 1, \
                f"First analysis should call analyzer once"
            
            # Clear cache
            coordinator.clear_pcap_cache()
            
            # Second analysis (should trigger new analysis)
            result2 = coordinator.get_pcap_analysis(pcap_file)
            
            # Verify analysis was called twice (once before clear, once after)
            assert mock_analyzer.call_count['count'] == 2, \
                f"After cache clear, analysis should be called again, total calls: {mock_analyzer.call_count['count']}"
            
            # Results should be different objects (not cached)
            assert result1 is not result2, \
                "After cache clear, new analysis should produce new result object"
        
        finally:
            # Clean up temp file
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        num_requests=st.integers(min_value=2, max_value=10)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_concurrent_requests_result_in_single_analysis(self, num_requests):
        """
        Test that concurrent requests for the same PCAP result in single analysis.
        
        For any number of concurrent requests for the same PCAP file,
        the analysis should only occur once.
        
        Validates: Requirements 6.1, 6.2, 6.3
        """
        # Create mock analyzer
        mock_analyzer = create_mock_pcap_analyzer()
        
        # Create coordinator with mock analyzer
        coordinator = TestResultCoordinator(pcap_analyzer=mock_analyzer)
        
        # Create a temporary PCAP file
        pcap_file = create_temp_pcap_file()
        
        try:
            # Request analysis multiple times
            results = []
            for i in range(num_requests):
                result = coordinator.get_pcap_analysis(pcap_file)
                results.append(result)
            
            # Verify analysis was called exactly once
            assert mock_analyzer.call_count['count'] == 1, \
                f"PCAP analysis should be called exactly once for {num_requests} requests, " \
                f"but was called {mock_analyzer.call_count['count']} times"
            
            # Verify all results are the same cached object
            for i in range(1, len(results)):
                assert results[i] is results[0], \
                    f"Request {i} should return the same cached result as request 0"
        
        finally:
            # Clean up temp file
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(request=pcap_analysis_request())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_cache_key_is_based_on_file_path(self, request):
        """
        Test that cache key is based on file path.
        
        For any PCAP file, the cache key should be the file path,
        so that the same file path always returns the same cached result.
        
        Validates: Requirements 6.2
        """
        # Create mock analyzer
        mock_analyzer = create_mock_pcap_analyzer()
        
        # Create coordinator with mock analyzer
        coordinator = TestResultCoordinator(pcap_analyzer=mock_analyzer)
        
        # Create a temporary PCAP file
        pcap_file = create_temp_pcap_file()
        
        try:
            # First analysis
            result1 = coordinator.get_pcap_analysis(pcap_file)
            
            # Verify result is in cache with file path as key
            assert pcap_file in coordinator.pcap_cache, \
                "PCAP file path should be in cache"
            
            # Verify cached result matches returned result
            assert coordinator.pcap_cache[pcap_file] is result1, \
                "Cached result should match returned result"
            
            # Second analysis should return cached result
            result2 = coordinator.get_pcap_analysis(pcap_file)
            
            # Verify it's the same object from cache
            assert result2 is result1, \
                "Second analysis should return cached result"
            assert result2 is coordinator.pcap_cache[pcap_file], \
                "Returned result should be the cached object"
        
        finally:
            # Clean up temp file
            Path(pcap_file).unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
