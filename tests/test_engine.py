import asyncio
import pytest
import time
from unittest.mock import Mock, AsyncMock, patch
from core.hybrid_engine import HybridEngine
from core.bypass.strategies.pool_management import BypassStrategy
from core.fingerprint.advanced_models import DPIFingerprint
import logging

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


class TestHybridEngine:
    """Test suite for HybridEngine core functionality"""

    @pytest.fixture
    def hybrid_engine(self):
        """Create HybridEngine instance for testing"""
        return HybridEngine(
            debug=True, enable_advanced_fingerprinting=False, enable_modern_bypass=False
        )

    @pytest.fixture
    def test_data(self):
        """Common test data"""
        return {
            "domain": "test-domain.com",
            "port": 443,
            "test_sites": ["https://test-domain.com", "https://another-site.com"],
            "ips": {"1.1.1.1", "2.2.2.2"},
            "dns_cache": {"test-domain.com": "1.1.1.1", "another-site.com": "2.2.2.2"},
            "strategy_str": "--dpi-desync=fake --dpi-desync-ttl=2",
            "strategy_dict": {"name": "fakedisorder", "params": {"split_pos": 3}},
        }

    def test_hybrid_engine_initialization(self, hybrid_engine):
        """Test basic HybridEngine initialization"""
        assert hybrid_engine.debug is True
        assert hybrid_engine.advanced_fingerprinting_enabled is False
        assert hybrid_engine.modern_bypass_enabled is False
        assert hybrid_engine.advanced_fingerprinter is None
        assert hybrid_engine.pool_manager is None

    @pytest.mark.asyncio
    @patch("aiohttp.ClientSession")
    async def test_connectivity_success(self, mock_session, hybrid_engine, test_data):
        """Test _test_sites_connectivity for a successful connection."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.content.readexactly.return_value = b"OK"
        mock_session.return_value.__aenter__.return_value.get.return_value = (
            mock_response
        )
        results = await hybrid_engine._test_sites_connectivity(
            sites=test_data["test_sites"], dns_cache=test_data["dns_cache"]
        )
        assert len(results) == len(test_data["test_sites"])
        for site in test_data["test_sites"]:
            assert site in results
            status, ip, latency, response_status = results[site]
            assert status == "WORKING"
            assert ip == test_data["dns_cache"][site.split("://")[1]]
            assert latency > 0
            assert response_status == 200

    @pytest.mark.asyncio
    @patch("aiohttp.ClientSession")
    async def test_connectivity_failure_timeout(
        self, mock_session, hybrid_engine, test_data
    ):
        """Test _test_sites_connectivity for a failed connection due to timeout."""
        mock_session.return_value.__aenter__.return_value.get.side_effect = (
            asyncio.TimeoutError
        )
        results = await hybrid_engine._test_sites_connectivity(
            sites=test_data["test_sites"], dns_cache=test_data["dns_cache"]
        )
        assert len(results) == len(test_data["test_sites"])
        for site in test_data["test_sites"]:
            assert site in results
            status, ip, latency, response_status = results[site]
            assert status == "TIMEOUT"
            assert ip == test_data["dns_cache"][site.split("://")[1]]
            assert latency > 0
            assert response_status == 0

    @pytest.mark.asyncio
    @patch("core.hybrid_engine.BypassEngine")
    async def test_execute_strategy_real_world_success(
        self, mock_bypass_engine, hybrid_engine, test_data
    ):
        """Test execute_strategy_real_world with successful connectivity."""
        mock_engine_instance = Mock()
        mock_engine_instance.start.return_value = Mock()
        mock_bypass_engine.return_value = mock_engine_instance
        hybrid_engine._test_sites_connectivity = AsyncMock(
            return_value={
                site: ("WORKING", "1.1.1.1", 100.0, 200)
                for site in test_data["test_sites"]
            }
        )
        result_status, successful_count, total_count, avg_latency = (
            await hybrid_engine.execute_strategy_real_world(
                strategy_str=test_data["strategy_str"],
                test_sites=test_data["test_sites"],
                target_ips=test_data["ips"],
                dns_cache=test_data["dns_cache"],
            )
        )
        assert result_status == "ALL_SITES_WORKING"
        assert successful_count == len(test_data["test_sites"])
        assert total_count == len(test_data["test_sites"])
        assert avg_latency > 0
        mock_bypass_engine.assert_called_once()
        mock_engine_instance.start.assert_called_once()
        mock_engine_instance.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_strategies_hybrid_logic(self, hybrid_engine, test_data):
        """Test the high-level logic of test_strategies_hybrid."""
        strategies_to_test = [
            {"name": "fakedisorder", "params": {"split_pos": 3}},
            {"name": "multisplit", "params": {"positions": [1, 5]}},
        ]

        async def mock_execute_strategy(strategy_dict, *args, **kwargs):
            if strategy_dict["name"] == "fakedisorder":
                return ("ALL_SITES_WORKING", 2, 2, 120.0)
            else:
                return ("NO_SITES_WORKING", 0, 2, 0.0)

        hybrid_engine.execute_strategy_real_world_from_dict = AsyncMock(
            side_effect=mock_execute_strategy
        )
        hybrid_engine.fingerprint_target = AsyncMock(return_value=None)
        results = await hybrid_engine.test_strategies_hybrid(
            strategies=strategies_to_test,
            test_sites=test_data["test_sites"],
            ips=test_data["ips"],
            dns_cache=test_data["dns_cache"],
            port=test_data["port"],
            domain=test_data["domain"],
            enable_fingerprinting=False,
        )
        assert len(results) == 2
        assert results[0]["strategy_dict"]["name"] == "fakedisorder"
        assert results[0]["success_rate"] == 1.0
        assert results[1]["strategy_dict"]["name"] == "multisplit"
        assert results[1]["success_rate"] == 0.0
        assert hybrid_engine.execute_strategy_real_world_from_dict.call_count == 2

    @pytest.mark.asyncio
    @patch("core.hybrid_engine.BypassEngine")
    async def test_execute_strategy_real_world_failure(
        self, mock_bypass_engine, hybrid_engine, test_data
    ):
        """Test execute_strategy_real_world with failed connectivity."""
        mock_engine_instance = Mock()
        mock_engine_instance.start.return_value = Mock()
        mock_bypass_engine.return_value = mock_engine_instance
        hybrid_engine._test_sites_connectivity = AsyncMock(
            return_value={
                site: ("TIMEOUT", "1.1.1.1", 5000.0, 0)
                for site in test_data["test_sites"]
            }
        )
        result_status, successful_count, total_count, avg_latency = (
            await hybrid_engine.execute_strategy_real_world(
                strategy_str=test_data["strategy_str"],
                test_sites=test_data["test_sites"],
                target_ips=test_data["ips"],
                dns_cache=test_data["dns_cache"],
            )
        )
        assert result_status == "NO_SITES_WORKING"
        assert successful_count == 0
        assert total_count == len(test_data["test_sites"])
        assert avg_latency == 0
        mock_bypass_engine.assert_called_once()
        mock_engine_instance.start.assert_called_once()
        mock_engine_instance.stop.assert_called_once()
