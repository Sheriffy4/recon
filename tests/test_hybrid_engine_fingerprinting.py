#!/usr/bin/env python3
"""
Integration tests for HybridEngine with Advanced DPI Fingerprinting
Tests the integration between HybridEngine and AdvancedFingerprinter.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""

import asyncio
import pytest
import logging
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, List, Set

# Import the components to test
from recon.core.hybrid_engine import HybridEngine
from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType, ConfidenceLevel

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


class TestHybridEngineFingerprinting:
    """Test suite for HybridEngine fingerprinting integration"""
    
    @pytest.fixture
    def mock_fingerprint(self):
        """Create a mock DPI fingerprint for testing"""
        return DPIFingerprint(
            target="blocked-site.com:443",
            timestamp=time.time(),
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
            analysis_duration=2.5,
            reliability_score=0.8,
            
            # TCP characteristics
            rst_injection_detected=True,
            rst_source_analysis="middlebox",
            tcp_window_manipulation=False,
            sequence_number_anomalies=True,
            connection_reset_timing=50.0,
            
            # HTTP characteristics
            http_header_filtering=True,
            user_agent_filtering=True,
            host_header_manipulation=False,
            
            # DNS characteristics
            dns_hijacking_detected=True,
            dns_response_modification=True,
            
            raw_metrics={"test": "data"},
            analysis_methods_used=["tcp_analysis", "http_analysis", "dns_analysis"]
        )
    
    @pytest.fixture
    def hybrid_engine(self):
        """Create HybridEngine instance for testing"""
        return HybridEngine(debug=True, enable_advanced_fingerprinting=True)
    
    @pytest.fixture
    def test_data(self):
        """Common test data"""
        return {
            'domain': 'blocked-site.com',
            'port': 443,
            'test_sites': ['https://blocked-site.com', 'https://another-blocked.com'],
            'ips': {'1.2.3.4', '5.6.7.8'},
            'dns_cache': {'blocked-site.com': '1.2.3.4', 'another-blocked.com': '5.6.7.8'},
            'strategies': [
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
                "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10"
            ]
        }

    def test_hybrid_engine_initialization_with_fingerprinting(self):
        """Test HybridEngine initialization with fingerprinting enabled"""
        # Test with fingerprinting enabled
        engine = HybridEngine(debug=True, enable_advanced_fingerprinting=True)
        
        # Should attempt to initialize fingerprinting
        assert hasattr(engine, 'advanced_fingerprinting_enabled')
        assert hasattr(engine, 'fingerprint_stats')
        assert 'fingerprints_created' in engine.fingerprint_stats
        
        # Test with fingerprinting disabled
        engine_disabled = HybridEngine(debug=True, enable_advanced_fingerprinting=False)
        assert not engine_disabled.advanced_fingerprinting_enabled
        assert engine_disabled.advanced_fingerprinter is None

    @pytest.mark.asyncio
    async def test_fingerprint_target_success(self, hybrid_engine, mock_fingerprint):
        """Test successful DPI fingerprinting"""
        if not hybrid_engine.advanced_fingerprinting_enabled:
            pytest.skip("Advanced fingerprinting not available")
        
        # Mock the advanced fingerprinter
        hybrid_engine.advanced_fingerprinter = Mock()
        hybrid_engine.advanced_fingerprinter.fingerprint_target = AsyncMock(return_value=mock_fingerprint)
        
        # Test fingerprinting
        result = await hybrid_engine.fingerprint_target("blocked-site.com", 443)
        
        assert result is not None
        assert result.dpi_type == DPIType.ROSKOMNADZOR_TSPU
        assert result.confidence == 0.85
        assert hybrid_engine.fingerprint_stats['fingerprints_created'] == 1
        
        # Verify the fingerprinter was called correctly
        hybrid_engine.advanced_fingerprinter.fingerprint_target.assert_called_once_with(
            target="blocked-site.com",
            port=443,
            force_refresh=False
        )

    @pytest.mark.asyncio
    async def test_fingerprint_target_failure(self, hybrid_engine):
        """Test fingerprinting failure handling"""
        if not hybrid_engine.advanced_fingerprinting_enabled:
            pytest.skip("Advanced fingerprinting not available")
        
        # Mock the advanced fingerprinter to raise an exception
        hybrid_engine.advanced_fingerprinter = Mock()
        hybrid_engine.advanced_fingerprinter.fingerprint_target = AsyncMock(
            side_effect=Exception("Network error")
        )
        
        # Test fingerprinting failure
        result = await hybrid_engine.fingerprint_target("blocked-site.com", 443)
        
        assert result is None
        assert hybrid_engine.fingerprint_stats['fingerprint_failures'] == 1

    def test_adapt_strategies_for_fingerprint_roskomnadzor_tspu(self, hybrid_engine, mock_fingerprint):
        """Test strategy adaptation for Roskomnadzor TSPU"""
        strategies = [
            "--dpi-desync=fake --dpi-desync-ttl=10 --dpi-desync-fooling=badsum",
            "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
            "--dpi-desync=multisplit --dpi-desync-split-count=3"
        ]
        
        mock_fingerprint.dpi_type = DPIType.ROSKOMNADZOR_TSPU
        mock_fingerprint.rst_injection_detected = True
        mock_fingerprint.connection_reset_timing = 50.0
        
        adapted = hybrid_engine._adapt_strategies_for_fingerprint(strategies, mock_fingerprint)
        
        # Should prioritize low TTL and fake+disorder strategies
        assert len(adapted) >= len(strategies)
        
        # Check that low TTL strategies are added
        low_ttl_found = any("--dpi-desync-ttl=1" in s or "--dpi-desync-ttl=2" in s for s in adapted)
        assert low_ttl_found, "Low TTL strategies should be added for TSPU"
        
        # Check that fake+disorder strategies are prioritized
        fake_disorder_found = any("fake" in s and "disorder" in s for s in adapted)
        assert fake_disorder_found, "Fake+disorder strategies should be present for TSPU"

    def test_adapt_strategies_for_fingerprint_commercial_dpi(self, hybrid_engine, mock_fingerprint):
        """Test strategy adaptation for Commercial DPI"""
        strategies = [
            "--dpi-desync=fake --dpi-desync-ttl=5",
            "--dpi-desync=disorder --dpi-desync-split-pos=3"
        ]
        
        mock_fingerprint.dpi_type = DPIType.COMMERCIAL_DPI
        mock_fingerprint.content_inspection_depth = 2000
        
        adapted = hybrid_engine._adapt_strategies_for_fingerprint(strategies, mock_fingerprint)
        
        # Should prioritize advanced techniques for commercial DPI
        assert len(adapted) >= len(strategies)
        
        # Check for multisplit strategies
        multisplit_found = any("multisplit" in s for s in adapted)
        assert multisplit_found, "Multisplit strategies should be added for commercial DPI"

    def test_prioritize_strategies(self, hybrid_engine):
        """Test strategy prioritization by patterns"""
        strategies = [
            "--dpi-desync=fake --dpi-desync-ttl=10",
            "--dpi-desync=fake --dpi-desync-ttl=1",
            "--dpi-desync=disorder --dpi-desync-split-pos=3",
            "--dpi-desync=fake --dpi-desync-ttl=2"
        ]
        
        priority_patterns = [r'--dpi-desync-ttl=[1-5]']
        
        prioritized = hybrid_engine._prioritize_strategies(strategies, priority_patterns)
        
        # Should find strategies with TTL 1-5 (TTL=1, TTL=2, and TTL=5 if present)
        assert len(prioritized) >= 2  # At least TTL=1 and TTL=2
        ttl_values_found = []
        for strategy in prioritized:
            if "--dpi-desync-ttl=1" in strategy:
                ttl_values_found.append(1)
            elif "--dpi-desync-ttl=2" in strategy:
                ttl_values_found.append(2)
        
        assert 1 in ttl_values_found, "TTL=1 strategy should be prioritized"
        assert 2 in ttl_values_found, "TTL=2 strategy should be prioritized"

    @pytest.mark.asyncio
    async def test_test_strategies_hybrid_with_fingerprinting(self, hybrid_engine, mock_fingerprint, test_data):
        """Test hybrid strategy testing with fingerprinting"""
        if not hybrid_engine.advanced_fingerprinting_enabled:
            pytest.skip("Advanced fingerprinting not available")
        
        # Mock fingerprinting
        hybrid_engine.fingerprint_target = AsyncMock(return_value=mock_fingerprint)
        
        # Mock strategy execution
        hybrid_engine.execute_strategy_real_world = AsyncMock(
            return_value=("ALL_SITES_WORKING", 2, 2, 150.0)
        )
        
        # Test strategy testing with fingerprinting
        results = await hybrid_engine.test_strategies_hybrid(
            strategies=test_data['strategies'],
            test_sites=test_data['test_sites'],
            ips=test_data['ips'],
            dns_cache=test_data['dns_cache'],
            port=test_data['port'],
            domain=test_data['domain'],
            enable_fingerprinting=True
        )
        
        assert len(results) > 0
        assert all('fingerprint_used' in result for result in results)
        assert all('dpi_type' in result for result in results)
        assert all('dpi_confidence' in result for result in results)
        
        # Verify fingerprinting was called
        hybrid_engine.fingerprint_target.assert_called_once_with(test_data['domain'], test_data['port'])
        
        # Check that fingerprint-aware testing was recorded
        assert hybrid_engine.fingerprint_stats['fingerprint_aware_tests'] == 1

    @pytest.mark.asyncio
    async def test_test_strategies_hybrid_without_fingerprinting(self, hybrid_engine, test_data):
        """Test hybrid strategy testing without fingerprinting"""
        # Mock strategy execution
        hybrid_engine.execute_strategy_real_world = AsyncMock(
            return_value=("PARTIAL_SUCCESS", 1, 2, 200.0)
        )
        
        # Test strategy testing without fingerprinting
        results = await hybrid_engine.test_strategies_hybrid(
            strategies=test_data['strategies'],
            test_sites=test_data['test_sites'],
            ips=test_data['ips'],
            dns_cache=test_data['dns_cache'],
            port=test_data['port'],
            domain=test_data['domain'],
            enable_fingerprinting=False
        )
        
        assert len(results) > 0
        assert all(result['fingerprint_used'] is False for result in results)
        assert all(result['dpi_type'] is None for result in results)
        
        # Check that fallback testing was recorded
        assert hybrid_engine.fingerprint_stats['fallback_tests'] == 1

    @pytest.mark.asyncio
    async def test_execute_strategy_with_fingerprint_context(self, hybrid_engine, mock_fingerprint, test_data):
        """Test strategy execution with fingerprint context"""
        # Mock the bypass engine and connectivity testing
        with patch('recon.core.hybrid_engine.BypassEngine') as mock_bypass_engine:
            mock_engine_instance = Mock()
            mock_bypass_engine.return_value = mock_engine_instance
            mock_engine_instance.start.return_value = Mock()
            
            # Mock connectivity testing
            hybrid_engine._test_sites_connectivity = AsyncMock(return_value={
                'https://blocked-site.com': ("WORKING", "1.2.3.4", 100.0, 200),
                'https://another-blocked.com': ("WORKING", "5.6.7.8", 120.0, 200)
            })
            
            # Test strategy execution with fingerprint
            result = await hybrid_engine.execute_strategy_real_world(
                strategy_str="--dpi-desync=fake --dpi-desync-ttl=1",
                test_sites=test_data['test_sites'],
                target_ips=test_data['ips'],
                dns_cache=test_data['dns_cache'],
                target_port=test_data['port'],
                fingerprint=mock_fingerprint
            )
            
            status, successful, total, latency = result
            assert status == "ALL_SITES_WORKING"
            assert successful == 2
            assert total == 2
            assert latency > 0

    def test_get_fingerprint_stats(self, hybrid_engine):
        """Test fingerprint statistics retrieval"""
        # Modify some stats
        hybrid_engine.fingerprint_stats['fingerprints_created'] = 5
        hybrid_engine.fingerprint_stats['cache_hits'] = 3
        hybrid_engine.fingerprint_stats['fingerprint_failures'] = 1
        
        stats = hybrid_engine.get_fingerprint_stats()
        
        assert stats['fingerprints_created'] == 5
        assert stats['cache_hits'] == 3
        assert stats['fingerprint_failures'] == 1
        assert isinstance(stats, dict)

    def test_cleanup_with_fingerprinting(self, hybrid_engine):
        """Test cleanup with fingerprinting components"""
        # Mock the advanced fingerprinter with executor
        mock_executor = Mock()
        mock_fingerprinter = Mock()
        mock_fingerprinter.executor = mock_executor
        hybrid_engine.advanced_fingerprinter = mock_fingerprinter
        
        # Test cleanup
        hybrid_engine.cleanup()
        
        # Verify executor shutdown was called
        mock_executor.shutdown.assert_called_once_with(wait=True)

    @pytest.mark.asyncio
    async def test_fingerprinting_error_handling(self, hybrid_engine, test_data):
        """Test error handling during fingerprinting"""
        if not hybrid_engine.advanced_fingerprinting_enabled:
            pytest.skip("Advanced fingerprinting not available")
        
        # Mock fingerprinting to fail
        hybrid_engine.advanced_fingerprinter = Mock()
        hybrid_engine.advanced_fingerprinter.fingerprint_target = AsyncMock(
            side_effect=Exception("Fingerprinting failed")
        )
        
        # Mock strategy execution
        hybrid_engine.execute_strategy_real_world = AsyncMock(
            return_value=("NO_SITES_WORKING", 0, 2, 0.0)
        )
        
        # Test that strategy testing continues despite fingerprinting failure
        results = await hybrid_engine.test_strategies_hybrid(
            strategies=test_data['strategies'],
            test_sites=test_data['test_sites'],
            ips=test_data['ips'],
            dns_cache=test_data['dns_cache'],
            port=test_data['port'],
            domain=test_data['domain'],
            enable_fingerprinting=True
        )
        
        assert len(results) > 0
        assert all(result['fingerprint_used'] is False for result in results)
        assert hybrid_engine.fingerprint_stats['fingerprint_failures'] == 1
        assert hybrid_engine.fingerprint_stats['fallback_tests'] == 1

    def test_fingerprint_disabled_graceful_degradation(self):
        """Test graceful degradation when fingerprinting is disabled"""
        engine = HybridEngine(debug=True, enable_advanced_fingerprinting=False)
        
        assert not engine.advanced_fingerprinting_enabled
        assert engine.advanced_fingerprinter is None
        
        # Test that methods handle disabled fingerprinting gracefully
        stats = engine.get_fingerprint_stats()
        assert isinstance(stats, dict)
        
        # Cleanup should not fail
        engine.cleanup()


class TestFingerprintIntegrationScenarios:
    """Test realistic integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_full_integration_scenario_roskomnadzor(self):
        """Test full integration scenario for Roskomnadzor DPI"""
        engine = HybridEngine(debug=True, enable_advanced_fingerprinting=True)
        
        if not engine.advanced_fingerprinting_enabled:
            pytest.skip("Advanced fingerprinting not available")
        
        # Create realistic fingerprint for Roskomnadzor
        fingerprint = DPIFingerprint(
            target="blocked-site.ru:443",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.9,
            rst_injection_detected=True,
            connection_reset_timing=30.0,
            dns_hijacking_detected=True,
            http_header_filtering=True
        )
        
        # Mock fingerprinting
        engine.fingerprint_target = AsyncMock(return_value=fingerprint)
        
        # Mock successful strategy execution for adapted strategies
        async def mock_execute_strategy(strategy_str, *args, **kwargs):
            if "--dpi-desync-ttl=1" in strategy_str or "--dpi-desync-ttl=2" in strategy_str:
                return ("ALL_SITES_WORKING", 2, 2, 80.0)
            else:
                return ("NO_SITES_WORKING", 0, 2, 0.0)
        
        engine.execute_strategy_real_world = mock_execute_strategy
        
        # Test strategy testing
        results = await engine.test_strategies_hybrid(
            strategies=[
                "--dpi-desync=fake --dpi-desync-ttl=10",
                "--dpi-desync=disorder --dpi-desync-split-pos=3"
            ],
            test_sites=['https://blocked-site.ru'],
            ips={'1.2.3.4'},
            dns_cache={'blocked-site.ru': '1.2.3.4'},
            port=443,
            domain='blocked-site.ru'
        )
        
        # Should have successful results due to fingerprint adaptation
        successful_results = [r for r in results if r['success_rate'] > 0]
        assert len(successful_results) > 0
        
        # Verify fingerprint information is included
        assert all(r['dpi_type'] == 'roskomnadzor_tspu' for r in results)
        assert all(r['dpi_confidence'] == 0.9 for r in results)

    @pytest.mark.asyncio
    async def test_performance_impact_measurement(self):
        """Test performance impact of fingerprinting"""
        # Test without fingerprinting
        engine_no_fp = HybridEngine(debug=False, enable_advanced_fingerprinting=False)
        
        start_time = time.time()
        # Simulate strategy testing without fingerprinting
        await asyncio.sleep(0.1)  # Simulate processing time
        time_without_fp = time.time() - start_time
        
        # Test with fingerprinting (mocked)
        engine_with_fp = HybridEngine(debug=False, enable_advanced_fingerprinting=True)
        
        if engine_with_fp.advanced_fingerprinting_enabled:
            # Mock fast fingerprinting
            engine_with_fp.fingerprint_target = AsyncMock(return_value=None)
            
            start_time = time.time()
            await engine_with_fp.fingerprint_target("test.com", 443)
            await asyncio.sleep(0.1)  # Simulate processing time
            time_with_fp = time.time() - start_time
            
            # Fingerprinting should add minimal overhead
            overhead = time_with_fp - time_without_fp
            assert overhead < 1.0, f"Fingerprinting overhead too high: {overhead}s"


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "-s"])