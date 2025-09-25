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
    # Don't skip at module level, handle in individual tests


if MODULES_AVAILABLE:
    class TestStrategyRuleEngine:
    """Test cases for StrategyRuleEngine"""
    
    def setup_method(self):
        """Setup for each test method"""
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
        
        self.unknown_fingerprint = DPIFingerprint(
            target='test3.com',
            dpi_type=DPIType.UNKNOWN,
            vulnerable_to_bad_checksum_race=False,
            tcp_options_filtering=False,
            content_inspection_depth=0,
            rst_ttl=None,
            vulnerable_to_fragmentation=False
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
        assert "badsum" in params["fooling"] or "md5sig" in params["fooling"]
    
    def test_generate_strategy_commercial_dpi(self):
        """Test strategy generation for commercial DPI"""
        strategy = self.engine.generate_strategy(self.commercial_fingerprint)
        
        assert strategy is not None
        assert strategy["type"] in ["multisplit", "fakeddisorder"]
        assert "params" in strategy
    
    def test_generate_multiple_strategies(self):
        """Test generation of multiple alternative strategies"""
        strategies = self.engine.generate_multiple_strategies(self.roskomnadzor_fingerprint, count=3)
        
        assert len(strategies) == 3
        assert all("type" in strategy for strategy in strategies)
        assert all("params" in strategy for strategy in strategies)
        
        # Should have different variations
        ttl_values = [strategy["params"].get("ttl") for strategy in strategies]
        assert len(set(ttl_values)) > 1  # Should have different TTL values
    
    def test_explain_strategy(self):
        """Test strategy explanation generation"""
        explanation = self.engine.explain_strategy(self.roskomnadzor_fingerprint)
        
        assert isinstance(explanation, str)
        assert len(explanation) > 0
        assert "rule" in explanation.lower()
    
    def test_add_custom_rule(self):
        """Test adding custom rules"""
        initial_count = len(self.engine.rules)
        
        custom_rule = StrategyRule(
            name="test_custom_rule",
            condition="Test condition",
            priority=100,
            attack_type="fakeddisorder",
            parameters={"ttl": 128}
        )
        
        self.engine.add_rule(custom_rule)
        
        assert len(self.engine.rules) == initial_count + 1
        assert self.engine.rules[0].name == "test_custom_rule"  # Should be first due to high priority


class TestStrategyCombinator:
    """Test cases for StrategyCombinator"""
    
    def setup_method(self):
        """Setup for each test method"""
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
    
    def test_combine_incompatible_components(self):
        """Test that incompatible components are rejected"""
        # Try to combine conflicting TTL components
        components = ["fakeddisorder_base", "low_ttl", "high_ttl"]
        strategy = self.combinator.combine_components(components)
        
        assert strategy is None  # Should fail due to TTL conflict
    
    def test_predefined_combinations(self):
        """Test predefined combination retrieval"""
        strategy = self.combinator.get_predefined_combination("roskomnadzor_aggressive")
        
        assert strategy is not None
        assert strategy["type"] == "fakeddisorder"
        assert "params" in strategy
        
        params = strategy["params"]
        assert "fooling" in params
        assert len(params["fooling"]) > 1  # Should have multiple fooling methods
    
    def test_suggest_combinations_for_fingerprint(self):
        """Test fingerprint-based combination suggestions"""
        suggestions = self.combinator.suggest_combinations_for_fingerprint(self.test_fingerprint)
        
        assert len(suggestions) > 0
        assert all(isinstance(item, tuple) and len(item) == 2 for item in suggestions)
        
        # Check that suggestions are valid
        for name, strategy in suggestions:
            assert isinstance(name, str)
            assert strategy is not None
            assert "type" in strategy
            assert "params" in strategy
    
    def test_create_custom_combination(self):
        """Test custom combination creation"""
        strategy = self.combinator.create_custom_combination(
            "fakeddisorder",
            ttl=64,
            fooling=["badsum", "md5sig"]
        )
        
        assert strategy is not None
        assert strategy["type"] == "fakeddisorder"
        
        params = strategy["params"]
        assert params["ttl"] == 64
        assert "fooling" in params
        assert "badsum" in params["fooling"]
        assert "md5sig" in params["fooling"]
    
    def test_list_available_items(self):
        """Test listing available combinations and components"""
        combinations = self.combinator.list_available_combinations()
        components = self.combinator.list_available_components()
        
        assert len(combinations) > 0
        assert len(components) > 0
        assert "roskomnadzor_aggressive" in combinations
        assert "fakeddisorder_base" in components


class TestStrategyValidator:
    """Test cases for StrategyValidator"""
    
    def setup_method(self):
        """Setup for each test method"""
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
    
    def test_add_manual_strategy(self):
        """Test adding manual strategies"""
        initial_count = len(self.validator.manual_strategies_db)
        
        self.validator.add_manual_strategy(
            "test_manual",
            self.test_strategy,
            0.85,
            "Test manual strategy"
        )
        
        assert len(self.validator.manual_strategies_db) == initial_count + 1
        assert "test_manual" in self.validator.manual_strategies_db
    
    @pytest.mark.asyncio
    async def test_strategy_effectiveness_simulation(self):
        """Test strategy effectiveness testing with simulation"""
        result = await self.validator.test_strategy_effectiveness(
            self.test_strategy,
            self.test_sites,
            hybrid_engine=None  # Use simulation
        )
        
        assert isinstance(result, StrategyTestResult)
        assert result.strategy == self.test_strategy
        assert result.total_count == len(self.test_sites)
        assert 0 <= result.success_rate <= 1.0
        assert result.avg_latency > 0
    
    @pytest.mark.asyncio
    async def test_validate_generated_strategies(self):
        """Test full validation workflow"""
        # Setup mocks
        self.mock_rule_engine.generate_strategy.return_value = self.test_strategy
        self.mock_rule_engine.generate_multiple_strategies.return_value = [self.test_strategy]
        self.mock_combinator.suggest_combinations_for_fingerprint.return_value = [
            ("test_combo", self.test_strategy)
        ]
        
        report = await self.validator.validate_generated_strategies(
            self.test_fingerprint,
            self.test_sites,
            hybrid_engine=None
        )
        
        assert isinstance(report, ValidationReport)
        assert len(report.generated_strategies) > 0
        assert len(report.manual_strategies) > 0
        assert report.best_generated is not None
        assert report.best_manual is not None
        assert isinstance(report.improvement_suggestions, list)
        assert isinstance(report.performance_comparison, dict)


class TestIntegration:
    """Integration tests for the complete strategy generation system"""
    
    def setup_method(self):
        """Setup for integration tests"""
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
    
    @pytest.mark.asyncio
    async def test_full_validation_workflow(self):
        """Test complete validation workflow"""
        test_sites = ["x.com", "youtube.com"]
        
        report = await self.validator.validate_generated_strategies(
            self.test_fingerprint,
            test_sites,
            hybrid_engine=None
        )
        
        assert isinstance(report, ValidationReport)
        assert len(report.generated_strategies) > 0
        assert len(report.manual_strategies) > 0
        
        # Check that performance comparison makes sense
        comparison = report.performance_comparison
        assert "avg_generated_success_rate" in comparison
        assert "avg_manual_success_rate" in comparison
    
    def test_factory_functions(self):
        """Test that factory functions work correctly"""
        rule_engine = create_default_rule_engine()
        combinator = create_default_combinator()
        validator = create_default_validator()
        
        assert isinstance(rule_engine, StrategyRuleEngine)
        assert isinstance(combinator, StrategyCombinator)
        assert isinstance(validator, StrategyValidator)
        
        # Test that they have the expected components
        assert len(rule_engine.rules) > 0
        assert len(combinator.attack_components) > 0
        assert len(validator.manual_strategies_db) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
        assert isinstance(explanation, str)
        assert len(explanation) > 0
        assert "rule" in explanation.lower()
    
    def test_add_custom_rule(self):
        """Test adding custom rules"""
        initial_count = len(self.engine.rules)
        
        custom_rule = StrategyRule(
            name="test_custom_rule",
            condition="Test condition",
            priority=100,
            attack_type="fakeddisorder",
            parameters={"ttl": 128}
        )
        
        self.engine.add_rule(custom_rule)
        
        assert len(self.engine.rules) == initial_count + 1
        assert self.engine.rules[0].name == "test_custom_rule"  # Should be first due to high priority


class TestStrategyCombinator:
    """Test cases for StrategyCombinator"""
    
    def setup_method(self):
        """Setup for each test method"""
        self.combinator = StrategyCombinator()
        
        # Create test fingerprint
        self.test_fingerprint = DPIFingerprint(
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            allows_badsum=True,
            allows_md5sig=True,
            requires_low_ttl=True
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
    
    def test_combine_incompatible_components(self):
        """Test that incompatible components are rejected"""
        # Try to combine conflicting TTL components
        components = ["fakeddisorder_base", "low_ttl", "high_ttl"]
        strategy = self.combinator.combine_components(components)
        
        assert strategy is None  # Should fail due to TTL conflict
    
    def test_predefined_combinations(self):
        """Test predefined combination retrieval"""
        strategy = self.combinator.get_predefined_combination("roskomnadzor_aggressive")
        
        assert strategy is not None
        assert strategy["type"] == "fakeddisorder"
        assert "params" in strategy
        
        params = strategy["params"]
        assert "fooling" in params
        assert len(params["fooling"]) > 1  # Should have multiple fooling methods
    
    def test_suggest_combinations_for_fingerprint(self):
        """Test fingerprint-based combination suggestions"""
        suggestions = self.combinator.suggest_combinations_for_fingerprint(self.test_fingerprint)
        
        assert len(suggestions) > 0
        assert all(isinstance(item, tuple) and len(item) == 2 for item in suggestions)
        
        # Check that suggestions are valid
        for name, strategy in suggestions:
            assert isinstance(name, str)
            assert strategy is not None
            assert "type" in strategy
            assert "params" in strategy
    
    def test_create_custom_combination(self):
        """Test custom combination creation"""
        strategy = self.combinator.create_custom_combination(
            "fakeddisorder",
            ttl=64,
            fooling=["badsum", "md5sig"]
        )
        
        assert strategy is not None
        assert strategy["type"] == "fakeddisorder"
        
        params = strategy["params"]
        assert params["ttl"] == 64
        assert "fooling" in params
        assert "badsum" in params["fooling"]
        assert "md5sig" in params["fooling"]
    
    def test_list_available_items(self):
        """Test listing available combinations and components"""
        combinations = self.combinator.list_available_combinations()
        components = self.combinator.list_available_components()
        
        assert len(combinations) > 0
        assert len(components) > 0
        assert "roskomnadzor_aggressive" in combinations
        assert "fakeddisorder_base" in components


class TestStrategyValidator:
    """Test cases for StrategyValidator"""
    
    def setup_method(self):
        """Setup for each test method"""
        # Create mock rule engine and combinator
        self.mock_rule_engine = Mock()
        self.mock_combinator = Mock()
        
        self.validator = StrategyValidator(
            rule_engine=self.mock_rule_engine,
            combinator=self.mock_combinator
        )
        
        # Create test data
        self.test_fingerprint = DPIFingerprint(
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            allows_badsum=True,
            allows_md5sig=True
        )
        
        self.test_sites = ["x.com", "youtube.com", "instagram.com"]
        
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
    
    def test_add_manual_strategy(self):
        """Test adding manual strategies"""
        initial_count = len(self.validator.manual_strategies_db)
        
        self.validator.add_manual_strategy(
            "test_manual",
            self.test_strategy,
            0.85,
            "Test manual strategy"
        )
        
        assert len(self.validator.manual_strategies_db) == initial_count + 1
        assert "test_manual" in self.validator.manual_strategies_db
    
    @pytest.mark.asyncio
    async def test_strategy_effectiveness_simulation(self):
        """Test strategy effectiveness testing with simulation"""
        result = await self.validator.test_strategy_effectiveness(
            self.test_strategy,
            self.test_sites,
            hybrid_engine=None  # Use simulation
        )
        
        assert isinstance(result, StrategyTestResult)
        assert result.strategy == self.test_strategy
        assert result.total_count == len(self.test_sites)
        assert 0 <= result.success_rate <= 1.0
        assert result.avg_latency > 0
    
    @pytest.mark.asyncio
    async def test_validate_generated_strategies(self):
        """Test full validation workflow"""
        # Setup mocks
        self.mock_rule_engine.generate_strategy.return_value = self.test_strategy
        self.mock_rule_engine.generate_multiple_strategies.return_value = [self.test_strategy]
        self.mock_combinator.suggest_combinations_for_fingerprint.return_value = [
            ("test_combo", self.test_strategy)
        ]
        
        report = await self.validator.validate_generated_strategies(
            self.test_fingerprint,
            self.test_sites,
            hybrid_engine=None
        )
        
        assert isinstance(report, ValidationReport)
        assert len(report.generated_strategies) > 0
        assert len(report.manual_strategies) > 0
        assert report.best_generated is not None
        assert report.best_manual is not None
        assert isinstance(report.improvement_suggestions, list)
        assert isinstance(report.performance_comparison, dict)


class TestIntegration:
    """Integration tests for the complete strategy generation system"""
    
    def setup_method(self):
        """Setup for integration tests"""
        self.rule_engine = create_default_rule_engine()
        self.combinator = create_default_combinator()
        self.validator = create_default_validator()
        
        self.test_fingerprint = DPIFingerprint(
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            allows_badsum=True,
            allows_md5sig=True,
            tls_alert_on_split_pos=30,
            requires_low_ttl=True,
            supports_fragmentation=True
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
    
    @pytest.mark.asyncio
    async def test_full_validation_workflow(self):
        """Test complete validation workflow"""
        test_sites = ["x.com", "youtube.com"]
        
        report = await self.validator.validate_generated_strategies(
            self.test_fingerprint,
            test_sites,
            hybrid_engine=None
        )
        
        assert isinstance(report, ValidationReport)
        assert len(report.generated_strategies) > 0
        assert len(report.manual_strategies) > 0
        
        # Check that performance comparison makes sense
        comparison = report.performance_comparison
        assert "avg_generated_success_rate" in comparison
        assert "avg_manual_success_rate" in comparison
    
    def test_factory_functions(self):
        """Test that factory functions work correctly"""
        rule_engine = create_default_rule_engine()
        combinator = create_default_combinator()
        validator = create_default_validator()
        
        assert isinstance(rule_engine, StrategyRuleEngine)
        assert isinstance(combinator, StrategyCombinator)
        assert isinstance(validator, StrategyValidator)
        
        # Test that they have the expected components
        assert len(rule_engine.rules) > 0
        assert len(combinator.attack_components) > 0
        assert len(validator.manual_strategies_db) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])