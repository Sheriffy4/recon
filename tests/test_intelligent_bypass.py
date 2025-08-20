# tests/test_intelligent_bypass.py

import pytest
from unittest.mock import Mock, patch, AsyncMock

from core.fingerprint.advanced_models import DPIFingerprint
from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
from core.bypass.strategies.generator import StrategyGenerator
from core.bypass.attacks.modern_registry import get_modern_registry, ModernAttackRegistry

@pytest.fixture
def mock_attack_registry():
    # Create a mock registry to avoid dependency on the full registry content
    registry = ModernAttackRegistry()

    # Create mock attack definitions for the rules we want to test
    mock_tcp_multisplit = Mock()
    mock_tcp_multisplit.name = 'tcp_multisplit'

    mock_ip_frag = Mock()
    mock_ip_frag.name = 'ip_fragmentation_disorder'

    mock_sni = Mock()
    mock_sni.name = 'sni_manipulation'

    mock_badsum = Mock()
    mock_badsum.name = 'badsum_race'

    mock_faked = Mock()
    mock_faked.name = 'faked_disorder'

    mock_seqovl = Mock()
    mock_seqovl.name = 'seqovl'

    mock_dynamic_combo = Mock()
    mock_dynamic_combo.name = 'dynamic_combo'

    # Register mock attacks
    registry.register(mock_tcp_multisplit)
    registry.register(mock_ip_frag)
    registry.register(mock_sni)
    registry.register(mock_badsum)
    registry.register(mock_faked)
    registry.register(mock_seqovl)
    registry.register(mock_dynamic_combo)

    return registry

def test_dpi_fingerprint_short_hash():
    """Tests the generation of the short_hash."""
    fp = DPIFingerprint(target="test.com:443")
    fp.block_type = "rst"
    fp.rst_injection_detected = True
    fp.rst_ttl = 64
    fp.tcp_options_filtering = False

    hash1 = fp.short_hash()
    hash2 = fp.short_hash()
    assert hash1 == hash2
    assert len(hash1) == 12

    fp.rst_ttl = 128
    hash3 = fp.short_hash()
    assert hash1 != hash3

@pytest.mark.asyncio
async def test_advanced_fingerprinter_caching():
    """Tests the new cache-accelerated workflow in AdvancedFingerprinter."""
    config = FingerprintingConfig(enable_cache=True)

    with patch('core.fingerprint.advanced_fingerprinter.FingerprintCache') as MockCache:
        mock_cache_instance = MockCache.return_value
        mock_cache_instance.get.return_value = None

        fingerprinter = AdvancedFingerprinter(config=config)
        fingerprinter.cache = mock_cache_instance

        shallow_fp = DPIFingerprint(target="test.com:443", rst_ttl=64, block_type='rst')
        full_fp = DPIFingerprint(target="test.com:443", rst_ttl=64, block_type='rst', reliability_score=0.9)

        fingerprinter._run_shallow_probe = AsyncMock(return_value=shallow_fp)
        fingerprinter._perform_comprehensive_analysis = AsyncMock(return_value=full_fp)

        # 1. Cache Miss
        result1 = await fingerprinter.fingerprint_target("test.com", 443)

        fingerprinter._run_shallow_probe.assert_called_once_with("test.com", 443)
        mock_cache_instance.get.assert_called_once_with(shallow_fp.short_hash())
        fingerprinter._perform_comprehensive_analysis.assert_called_once()
        mock_cache_instance.set.assert_called_once_with(shallow_fp.short_hash(), full_fp)
        assert result1 == full_fp

        # 2. Cache Hit
        mock_cache_instance.get.return_value = full_fp
        fingerprinter._run_shallow_probe.reset_mock()
        fingerprinter._perform_comprehensive_analysis.reset_mock()

        result2 = await fingerprinter.fingerprint_target("test.com", 443)

        fingerprinter._run_shallow_probe.assert_called_once_with("test.com", 443)
        assert fingerprinter._perform_comprehensive_analysis.call_count == 0
        assert result2 == full_fp

def test_strategy_generator_rule_based(mock_attack_registry):
    """Tests the rule-based strategy generation."""
    generator = StrategyGenerator(attack_registry=mock_attack_registry, learning_cache=None)

    fp = DPIFingerprint(target="test.com:443")
    fp.vulnerable_to_fragmentation = True

    strategies = generator.generate_strategies(fp)

    assert len(strategies) >= 2
    strategy_names = [s['name'] for s in strategies]
    assert "tcp_multisplit" in strategy_names
    assert "ip_fragmentation_disorder" in strategy_names

    fp.vulnerable_to_fragmentation = False
    fp.is_stateful = True
    fp.rst_injection_detected = True

    strategies = generator.generate_strategies(fp)
    strategy_names = [s['name'] for s in strategies]
    assert "faked_disorder" in strategy_names
    assert "seqovl" in strategy_names

def test_strategy_generator_combo(mock_attack_registry):
    """Tests combo strategy generation."""
    generator = StrategyGenerator(attack_registry=mock_attack_registry, learning_cache=None)

    best_singles = [
        {"name": "sni_manipulation", "estimated_score": 0.95},
        {"name": "tcp_multisplit", "estimated_score": 0.9},
    ]

    fp = DPIFingerprint(target="test.com:443")
    combo_strategies = generator.generate_combo_strategies(fp, best_singles)

    assert len(combo_strategies) == 1
    combo = combo_strategies[0]
    assert combo['name'] == 'dynamic_combo'
    assert len(combo['params']['layers']) == 2
    assert combo['params']['layers'][0]['name'] == 'sni_manipulation'
