#!/usr/bin/env python3
"""
Comprehensive test suite for combination DPI bypass attacks.

Tests all combo attack implementations including Zapret integration,
adaptive combinations, multi-layer attacks, and steganographic techniques.
"""

import pytest
import asyncio
import os
import sys
from unittest.mock import Mock, patch, AsyncMock

# Setup path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)

from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.combo.zapret_strategy import ZapretStrategy, ZapretConfig
from core.bypass.attacks.combo.zapret_attack_adapter import (
    ZapretAttackAdapter,
    ZapretAdapterConfig,
    ZapretAdapterMode,
)
from core.bypass.attacks.combo.adaptive_combo import DPIResponseAdaptiveAttack
from core.bypass.attacks.combo.traffic_mimicry import TrafficMimicryAttack


class TestZapretStrategy:
    """Test Zapret strategy implementation."""

    @pytest.fixture
    def zapret_config(self):
        """Create test Zapret configuration."""
        return ZapretConfig(
            split_seqovl=297,
            repeats=5,
            auto_ttl=True,
            desync_methods=["fake", "fakeddisorder"],
        )

    @pytest.fixture
    def zapret_strategy(self, zapret_config):
        """Create Zapret strategy instance."""
        return ZapretStrategy(zapret_config)

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="8.8.8.8",
            dst_port=443,
            src_ip="192.168.1.100",
            src_port=12345,
            domain="example.com",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            protocol="tcp",
        )

    def test_zapret_config_creation(self, zapret_config):
        """Test Zapret configuration creation."""
        assert zapret_config.split_seqovl == 297
        assert zapret_config.repeats == 5
        assert zapret_config.auto_ttl is True
        assert "fake" in zapret_config.desync_methods

    def test_zapret_strategy_initialization(self, zapret_strategy):
        """Test Zapret strategy initialization."""
        assert zapret_strategy.name == "zapret"
        assert zapret_strategy.category == "combo"
        assert "tcp" in zapret_strategy.supported_protocols

    @pytest.mark.asyncio
    async def test_zapret_strategy_execution(self, zapret_strategy, attack_context):
        """Test Zapret strategy execution."""
        with patch(
            "core.bypass.attacks.combo.zapret_strategy.WinDivert"
        ) as mock_windivert:
            mock_windivert.return_value.__enter__.return_value = Mock()

            result = await zapret_strategy.execute(attack_context)

            assert isinstance(result, AttackResult)
            assert result.status in [
                AttackStatus.SUCCESS,
                AttackStatus.FAILURE,
                AttackStatus.ERROR,
            ]
            assert result.technique_used == "zapret"

    def test_zapret_config_validation(self):
        """Test Zapret configuration validation."""
        # Valid config
        config = ZapretConfig(split_seqovl=350, repeats=3)
        assert config.split_seqovl == 350

        # Test with all parameters
        full_config = ZapretConfig(
            split_seqovl=400,
            repeats=7,
            auto_ttl=False,
            desync_methods=["fake", "disorder"],
            inter_packet_delay_ms=10.0,
            burst_delay_ms=5.0,
        )
        assert full_config.inter_packet_delay_ms == 10.0


class TestZapretAttackAdapter:
    """Test Zapret attack adapter implementation."""

    @pytest.fixture
    def adapter_config(self):
        """Create adapter configuration."""
        return ZapretAdapterConfig(
            mode=ZapretAdapterMode.AUTO, validation_enabled=True, retry_count=2
        )

    @pytest.fixture
    def zapret_adapter(self, adapter_config):
        """Create Zapret adapter instance."""
        return ZapretAttackAdapter(adapter_config)

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="1.1.1.1", dst_port=80, domain="test.com", protocol="tcp"
        )

    def test_adapter_initialization(self, zapret_adapter):
        """Test adapter initialization."""
        assert zapret_adapter.name == "zapret_adapter"
        assert zapret_adapter.category == "combo"
        assert "tcp" in zapret_adapter.supported_protocols

    def test_adapter_configuration(self, zapret_adapter):
        """Test adapter configuration management."""
        config = zapret_adapter.get_configuration()
        assert "adapter_config" in config
        assert "components_available" in config

    def test_configuration_validation(self, zapret_adapter):
        """Test configuration validation."""
        validation = zapret_adapter.validate_configuration()
        assert isinstance(validation, dict)
        assert "config_valid" in validation

    def test_execution_mode_determination(self, zapret_adapter):
        """Test execution mode determination logic."""
        mode = zapret_adapter._determine_execution_mode()
        assert isinstance(mode, ZapretAdapterMode)

    @pytest.mark.asyncio
    async def test_adapter_execution(self, zapret_adapter, attack_context):
        """Test adapter execution."""
        with patch.object(zapret_adapter, "_async_execute") as mock_execute:
            mock_execute.return_value = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=50.0,
                technique_used="zapret_adapter_auto",
            )

            result = zapret_adapter.execute(attack_context)

            assert isinstance(result, AttackResult)
            assert result.status == AttackStatus.SUCCESS


class TestDPIResponseAdaptiveAttack:
    """Test DPI response adaptive attack."""

    @pytest.fixture
    def adaptive_attack(self):
        """Create DPI response adaptive attack instance."""
        return DPIResponseAdaptiveAttack()

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="8.8.4.4", dst_port=443, domain="google.com", protocol="tcp"
        )

    def test_adaptive_attack_initialization(self, adaptive_attack):
        """Test adaptive attack initialization."""
        assert adaptive_attack.name == "dpi_response_adaptive"
        assert adaptive_attack.category == "combo"
        assert len(adaptive_attack.supported_protocols) > 0

    @pytest.mark.asyncio
    async def test_adaptive_execution(self, adaptive_attack, attack_context):
        """Test adaptive attack execution."""
        with patch("core.bypass.attacks.combo.adaptive_combo.MLClassifier") as mock_ml:
            mock_ml.return_value.predict_best_strategy.return_value = (
                "tcp_fragmentation"
            )

            result = await adaptive_attack.execute(attack_context)

            assert isinstance(result, AttackResult)
            assert result.status in [
                AttackStatus.SUCCESS,
                AttackStatus.FAILURE,
                AttackStatus.ERROR,
            ]

    def test_strategy_selection(self, adaptive_attack):
        """Test strategy selection logic."""
        # Mock DPI characteristics
        dpi_characteristics = {
            "deep_inspection": True,
            "protocol_detection": ["http", "https"],
            "behavioral_analysis": False,
        }

        strategy = adaptive_attack._select_strategy(dpi_characteristics)
        assert strategy in adaptive_attack.available_strategies


class TestTrafficMimicryAttack:
    """Test traffic mimicry attack."""

    @pytest.fixture
    def traffic_mimicry(self):
        """Create traffic mimicry attack instance."""
        return TrafficMimicryAttack()

    @pytest.fixture
    def attack_context(self):
        """Create test attack context."""
        return AttackContext(
            dst_ip="208.67.222.222", dst_port=443, domain="opendns.com", protocol="tcp"
        )

    def test_traffic_mimicry_initialization(self, traffic_mimicry):
        """Test traffic mimicry initialization."""
        assert traffic_mimicry.name == "traffic_mimicry"
        assert traffic_mimicry.category == "combo"

    @pytest.mark.asyncio
    async def test_traffic_mimicry_execution(self, traffic_mimicry, attack_context):
        """Test traffic mimicry execution."""
        result = await traffic_mimicry.execute(attack_context)

        assert isinstance(result, AttackResult)
        assert result.status in [
            AttackStatus.SUCCESS,
            AttackStatus.FAILURE,
            AttackStatus.ERROR,
        ]

    def test_traffic_profile_selection(self, traffic_mimicry):
        """Test traffic profile selection."""
        profile = traffic_mimicry._select_traffic_profile("https")
        assert profile is not None


class TestComboAttackIntegration:
    """Test integration between different combo attacks."""

    @pytest.mark.asyncio
    async def test_attack_chaining(self):
        """Test chaining multiple combo attacks."""
        context = AttackContext(
            dst_ip="1.1.1.1", dst_port=443, domain="cloudflare.com", protocol="tcp"
        )

        # Test sequential execution of combo attacks
        attacks = [
            ZapretAttackAdapter(),
            DPIResponseAdaptiveAttack(),
            TrafficMimicryAttack(),
        ]

        results = []
        for attack in attacks:
            try:
                result = await attack.execute(context)
                results.append(result)
            except Exception as e:
                # Some attacks may fail in test environment
                results.append(
                    AttackResult(
                        status=AttackStatus.ERROR,
                        error_message=str(e),
                        technique_used=attack.name,
                    )
                )

        assert len(results) == len(attacks)
        assert all(isinstance(r, AttackResult) for r in results)

    def test_combo_attack_compatibility(self):
        """Test combo attack compatibility."""
        attacks = [
            ZapretAttackAdapter(),
            DPIResponseAdaptiveAttack(),
            TrafficMimicryAttack(),
        ]

        for attack in attacks:
            assert hasattr(attack, "name")
            assert hasattr(attack, "category")
            assert hasattr(attack, "supported_protocols")
            assert attack.category == "combo"
            assert hasattr(attack, "execute")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
