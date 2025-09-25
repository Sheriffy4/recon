"""
Unit tests for Strategy Generation Logic Overhaul (Task 10).
Tests rule engine, combinator, and validator components.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any, List

# Import the modules we're testing
try:
    from core.strategy_rule_engine import StrategyRuleEngine, StrategyRule, create_default_rule_engine
    from core.strategy_combinator import StrategyCombinator, AttackComponent, create_default_combinator
    from core.strategy_validator import StrategyValidator, StrategyTestResult, ValidationReport, create_default_validator
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False


class TestStrategyRuleEngine:
    """Test cases for StrategyRuleEngine"""
    
    def setup_method(self):
        """Setup for each test method"""
        if not MODULES_AVAILABLE:
            pytest.skip("Strategy generation modules not available")
            
        self.engine = StrategyRuleEngine()
        
        # Create test fingerprints with correct structure
        self.roskomnadzor_fingerprint = DPIFingerprint(
            target='test1.com',
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            vulnerable_to_bad_checksum_race=True,
            tcp_options_filtering=True,
            content_inspection_depth=30,
            rst_ttl=1,
            vulnerable_to_fragmentation=True
        )
        
        self.commercial_fingerprint = DPIFingerprint(
            target='test2.com',
            dpi_type=DPIType.COMMERCIAL_DPI,
            vulnerable_to_bad_checksum_race=True,
            tcp_options_filtering=False,
            content_inspection_depth=50,
            rst_ttl=64,
            vulnerable_to_fragmentation=True
        )
    
    def test_rule_engine_initialization(self):
        """Test that rule engine initializes with default rules"""
        assert len(self.engine.rules) > 0
        assert any(rule.name == "roskomnadzor_tspu_optimized" for rule in self.engine.rules)
        assert any(rule.name == "commercial_dpi_bypass" for rule in self.engine.rules)
    
    def test_generate_strategy_roskomnadzor(self):
        """Test strategy generation for Roskomnadzor TSPU"""
        strategy = self.engine.generate_strategy(self.roskomnadzor_fingerprint)
        
        assert strategy is not None
        assert strategy["type"] == "fakeddisorder"
        assert "params" in strategy
        
        params = strategy["params"]
        assert "ttl" in params
        assert "fooling" in params


class TestStrategyCombinator:
    """Test cases for StrategyCombinator"""
    
    def setup_method(self):
        """Setup for each test method"""
        if not MODULES_AVAILABLE:
            pytest.skip("Strategy generation modules not available")
            
        self.combinator = StrategyCombinator()
        
        # Create test fingerprint
        self.test_fingerprint = DPIFingerprint(
            target='test.com',
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            vulnerable_to_bad_checksum_race=True,
            tcp_options_filtering=True,
            rst_ttl=1
        )
    
    def test_combinator_initialization(self):
        """Test that combinator initializes with components and rules"""
        assert len(self.combinator.attack_components) > 0
        assert len(self.combinator.combination_rules) > 0
        
        # Check for key components
        assert "fakeddisorder_base" in self.combinator.attack_components
        assert "badsum_fooling" in self.combinator.attack_components
        assert "low_ttl" in self.combinator.attack_components
    
    def test_combine_compatible_components(self):
        """Test combining compatible components"""
        components = ["fakeddisorder_base", "badsum_fooling", "high_ttl"]
        strategy = self.combinator.combine_components(components)
        
        assert strategy is not None
        assert strategy["type"] == "fakeddisorder"
        assert "params" in strategy
        
        params = strategy["params"]
        assert params["ttl"] == 64  # From high_ttl component
        assert "fooling" in params
        assert "badsum" in params["fooling"]


class TestStrategyValidator:
    """Test cases for StrategyValidator"""
    
    def setup_method(self):
        """Setup for each test method"""
        if not MODULES_AVAILABLE:
            pytest.skip("Strategy generation modules not available")
            
        # Create mock rule engine and combinator
        self.mock_rule_engine = Mock()
        self.mock_combinator = Mock()
        
        self.validator = StrategyValidator(
            rule_engine=self.mock_rule_engine,
            combinator=self.mock_combinator
        )
        
        # Create test data
        self.test_fingerprint = DPIFingerprint(
            target='test.com',
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            vulnerable_to_bad_checksum_race=True,
            tcp_options_filtering=True
        )
        
        self.test_sites = ['x.com', 'youtube.com', 'instagram.com']
        
        self.test_strategy = {
            "type": "fakeddisorder",
            "params": {
                "ttl": 64,
                "split_pos": 76,
                "fooling": ["badsum"]
            }
        }
    
    def test_validator_initialization(self):
        """Test validator initialization"""
        assert self.validator.rule_engine is not None
        assert self.validator.combinator is not None
        assert len(self.validator.manual_strategies_db) > 0


class TestIntegration:
    """Integration tests for the complete strategy generation system"""
    
    def setup_method(self):
        """Setup for integration tests"""
        if not MODULES_AVAILABLE:
            pytest.skip("Strategy generation modules not available")
            
        self.rule_engine = create_default_rule_engine()
        self.combinator = create_default_combinator()
        self.validator = create_default_validator()
        
        self.test_fingerprint = DPIFingerprint(
            target='test.com',
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            vulnerable_to_bad_checksum_race=True,
            tcp_options_filtering=True,
            content_inspection_depth=30,
            rst_ttl=1,
            vulnerable_to_fragmentation=True
        )
    
    def test_end_to_end_strategy_generation(self):
        """Test complete strategy generation workflow"""
        # Generate strategy using rule engine
        strategy = self.rule_engine.generate_strategy(self.test_fingerprint)
        
        assert strategy is not None
        assert "type" in strategy
        assert "params" in strategy
        
        # Get combinations from combinator
        suggestions = self.combinator.suggest_combinations_for_fingerprint(self.test_fingerprint)
        
        assert len(suggestions) > 0
        
        # Validate that all suggestions are valid strategies
        for name, suggested_strategy in suggestions:
            assert suggested_strategy is not None
            assert "type" in suggested_strategy
            assert "params" in suggested_strategy


if __name__ == "__main__":
    pytest.main([__file__, "-v"])