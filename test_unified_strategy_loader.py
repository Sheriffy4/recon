#!/usr/bin/env python3
"""
Unit tests for UnifiedStrategyLoader

Tests all functionality of the unified strategy loading system:
1. Strategy loading from various formats
2. Parameter normalization
3. Forced override creation
4. Strategy validation
5. Error handling

Requirements tested:
- 1.1: Unified strategy loading across modes
- 1.2: Forced override creation for identical behavior
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

# Import the module under test
from core.unified_strategy_loader import (
    UnifiedStrategyLoader,
    NormalizedStrategy,
    StrategyLoadError,
    StrategyValidationError,
    load_strategy,
    create_forced_override,
    load_strategies_from_file
)


class TestNormalizedStrategy:
    """Test the NormalizedStrategy dataclass."""
    
    def test_normalized_strategy_creation(self):
        """Test creating a NormalizedStrategy instance."""
        strategy = NormalizedStrategy(
            type='fakeddisorder',
            params={'ttl': 8, 'fooling': 'badsum'},
            no_fallbacks=True,
            forced=True,
            raw_string='fakeddisorder(ttl=8, fooling=badsum)',
            source_format='function'
        )
        
        assert strategy.type == 'fakeddisorder'
        assert strategy.params == {'ttl': 8, 'fooling': 'badsum'}
        assert strategy.no_fallbacks is True
        assert strategy.forced is True
        assert strategy.raw_string == 'fakeddisorder(ttl=8, fooling=badsum)'
        assert strategy.source_format == 'function'
    
    def test_to_engine_format(self):
        """Test conversion to engine format."""
        strategy = NormalizedStrategy(
            type='multisplit',
            params={'split_pos': 2},
            no_fallbacks=True,
            forced=True
        )
        
        engine_format = strategy.to_engine_format()
        expected = {
            'type': 'multisplit',
            'params': {'split_pos': 2},
            'no_fallbacks': True,
            'forced': True
        }
        
        assert engine_format == expected
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        strategy = NormalizedStrategy(
            type='fake',
            params={'ttl': 5},
            no_fallbacks=True,
            forced=True,
            raw_string='fake(ttl=5)',
            source_format='function'
        )
        
        strategy_dict = strategy.to_dict()
        
        assert strategy_dict['type'] == 'fake'
        assert strategy_dict['params'] == {'ttl': 5}
        assert strategy_dict['no_fallbacks'] is True
        assert strategy_dict['forced'] is True
        assert strategy_dict['raw_string'] == 'fake(ttl=5)'
        assert strategy_dict['source_format'] == 'function'


class TestUnifiedStrategyLoader:
    """Test the UnifiedStrategyLoader class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.loader = UnifiedStrategyLoader(debug=True)
    
    def test_loader_initialization(self):
        """Test loader initialization."""
        loader = UnifiedStrategyLoader(debug=False)
        assert loader.debug is False
        assert loader.known_attacks == {
            'fake', 'split', 'disorder', 'disorder2', 'multisplit', 
            'multidisorder', 'fakeddisorder', 'seqovl'
        }
        assert 'fakeddisorder' in loader.required_params
    
    def test_load_strategy_from_dict(self):
        """Test loading strategy from dictionary format."""
        strategy_dict = {
            'type': 'fakeddisorder',
            'params': {'ttl': 8, 'fooling': 'badsum'}
        }
        
        strategy = self.loader.load_strategy(strategy_dict)
        
        assert isinstance(strategy, NormalizedStrategy)
        assert strategy.type == 'fakeddisorder'
        assert strategy.params == {'ttl': 8, 'fooling': 'badsum'}
        assert strategy.no_fallbacks is True  # CRITICAL: Always forced
        assert strategy.forced is True
        assert strategy.source_format == 'dict'
    
    def test_load_strategy_from_zapret_style(self):
        """Test loading strategy from Zapret command-line style."""
        zapret_strategy = "--dpi-desync=fakeddisorder --dpi-desync-ttl=8 --dpi-desync-fooling=badsum"
        
        strategy = self.loader.load_strategy(zapret_strategy)
        
        assert isinstance(strategy, NormalizedStrategy)
        assert strategy.type == 'fakeddisorder'
        assert strategy.params['ttl'] == 8
        assert strategy.params['fooling'] == 'badsum'
        assert strategy.no_fallbacks is True  # CRITICAL: Always forced
        assert strategy.forced is True
        assert strategy.source_format == 'zapret'
        assert strategy.raw_string == zapret_strategy
    
    def test_load_strategy_from_function_style(self):
        """Test loading strategy from function call style."""
        function_strategy = "multisplit(split_pos=2, repeats=3)"
        
        strategy = self.loader.load_strategy(function_strategy)
        
        assert isinstance(strategy, NormalizedStrategy)
        assert strategy.type == 'multisplit'
        assert strategy.params['split_pos'] == 2
        assert strategy.params['repeats'] == 3
        assert strategy.no_fallbacks is True  # CRITICAL: Always forced
        assert strategy.forced is True
        assert strategy.source_format == 'function'
        assert strategy.raw_string == function_strategy
    
    def test_load_strategy_empty_string_error(self):
        """Test that empty string raises error."""
        with pytest.raises(StrategyLoadError, match="Empty strategy string"):
            self.loader.load_strategy("")
    
    def test_load_strategy_invalid_type_error(self):
        """Test that invalid input type raises error."""
        with pytest.raises(StrategyLoadError, match="Unsupported strategy input type"):
            self.loader.load_strategy(123)
    
    def test_load_strategy_dict_missing_type_error(self):
        """Test that dict without type raises error."""
        with pytest.raises(StrategyLoadError, match="Strategy dict missing 'type' field"):
            self.loader.load_strategy({'params': {'ttl': 8}})
    
    def test_parse_zapret_style_complex(self):
        """Test parsing complex Zapret-style strategy."""
        zapret_strategy = (
            "--dpi-desync=multidisorder --dpi-desync-ttl=6 --dpi-desync-autottl=2 "
            "--dpi-desync-fooling=badseq --dpi-desync-split-pos=1 --dpi-desync-repeats=2"
        )
        
        strategy = self.loader.load_strategy(zapret_strategy)
        
        assert strategy.type == 'multidisorder'
        assert strategy.params['ttl'] == 6
        assert strategy.params['autottl'] == 2
        assert strategy.params['fooling'] == 'badseq'
        assert strategy.params['split_pos'] == 1
        assert strategy.params['repeats'] == 2
    
    def test_parse_function_style_complex(self):
        """Test parsing complex function-style strategy."""
        function_strategy = "seqovl(overlap_size=4, ttl=7, fooling='md5sig')"
        
        strategy = self.loader.load_strategy(function_strategy)
        
        assert strategy.type == 'seqovl'
        assert strategy.params['overlap_size'] == 4
        assert strategy.params['ttl'] == 7
        assert strategy.params['fooling'] == 'md5sig'
    
    def test_parse_function_style_no_params(self):
        """Test parsing function-style strategy with no parameters."""
        function_strategy = "disorder()"
        
        strategy = self.loader.load_strategy(function_strategy)
        
        assert strategy.type == 'disorder'
        assert strategy.params == {}
    
    def test_parse_function_style_boolean_params(self):
        """Test parsing function-style strategy with boolean parameters."""
        function_strategy = "fake(ttl=5, enabled=true, debug=false)"
        
        strategy = self.loader.load_strategy(function_strategy)
        
        assert strategy.type == 'fake'
        assert strategy.params['ttl'] == 5
        assert strategy.params['enabled'] is True
        assert strategy.params['debug'] is False
    
    def test_create_forced_override_from_strategy(self):
        """Test creating forced override from NormalizedStrategy."""
        strategy = NormalizedStrategy(
            type='fakeddisorder',
            params={'ttl': 8},
            no_fallbacks=True,
            forced=True
        )
        
        forced_config = self.loader.create_forced_override(strategy)
        
        expected = {
            'type': 'fakeddisorder',
            'params': {'ttl': 8},
            'no_fallbacks': True,  # CRITICAL: Always True
            'forced': True,        # CRITICAL: Always True
            'override_mode': True
        }
        
        assert forced_config == expected
    
    def test_create_forced_override_from_dict(self):
        """Test creating forced override from dictionary."""
        strategy_dict = {
            'type': 'multisplit',
            'params': {'split_pos': 2}
        }
        
        forced_config = self.loader.create_forced_override(strategy_dict)
        
        expected = {
            'type': 'multisplit',
            'params': {'split_pos': 2},
            'no_fallbacks': True,  # CRITICAL: Always True
            'forced': True,        # CRITICAL: Always True
            'override_mode': True
        }
        
        assert forced_config == expected
    
    def test_create_forced_override_invalid_type_error(self):
        """Test that invalid type for forced override raises error."""
        with pytest.raises(StrategyLoadError, match="Invalid strategy type for forced override"):
            self.loader.create_forced_override("invalid_string")
    
    def test_validate_strategy_valid(self):
        """Test validating a valid strategy."""
        strategy = NormalizedStrategy(
            type='fakeddisorder',
            params={'ttl': 8, 'fooling': 'badsum'},
            no_fallbacks=True,
            forced=True
        )
        
        result = self.loader.validate_strategy(strategy)
        assert result is True
    
    def test_validate_strategy_missing_required_params(self):
        """Test validation fails for missing required parameters."""
        strategy = NormalizedStrategy(
            type='multisplit',
            params={},  # Missing required split_pos
            no_fallbacks=True,
            forced=True
        )
        
        with pytest.raises(StrategyValidationError, match="missing required parameters"):
            self.loader.validate_strategy(strategy)
    
    def test_validate_strategy_invalid_ttl(self):
        """Test validation fails for invalid TTL value."""
        strategy = NormalizedStrategy(
            type='fake',
            params={'ttl': 300},  # Invalid TTL > 255
            no_fallbacks=True,
            forced=True
        )
        
        with pytest.raises(StrategyValidationError, match="Invalid TTL value"):
            self.loader.validate_strategy(strategy)
    
    def test_validate_strategy_invalid_fooling(self):
        """Test validation fails for invalid fooling method."""
        strategy = NormalizedStrategy(
            type='fakeddisorder',
            params={'fooling': 'invalid_method'},
            no_fallbacks=True,
            forced=True
        )
        
        with pytest.raises(StrategyValidationError, match="Invalid fooling method"):
            self.loader.validate_strategy(strategy)
    
    def test_validate_strategy_unknown_attack_type_warning(self):
        """Test validation warns for unknown attack type but doesn't fail."""
        strategy = NormalizedStrategy(
            type='unknown_attack',
            params={},
            no_fallbacks=True,
            forced=True
        )
        
        # Should not raise exception, just warn
        result = self.loader.validate_strategy(strategy)
        assert result is True
    
    def test_normalize_strategy_dict_parsed_format(self):
        """Test normalizing ParsedStrategy-like dictionary."""
        strategy_dict = {
            'attack_type': 'fakeddisorder',
            'params': {'ttl': 8},
            'raw_string': 'fakeddisorder(ttl=8)',
            'syntax_type': 'function'
        }
        
        strategy = self.loader.normalize_strategy_dict(strategy_dict)
        
        assert strategy.type == 'fakeddisorder'
        assert strategy.params == {'ttl': 8}
        assert strategy.no_fallbacks is True
        assert strategy.forced is True
        assert strategy.raw_string == 'fakeddisorder(ttl=8)'
        assert strategy.source_format == 'function'
    
    def test_normalize_strategy_dict_direct_format(self):
        """Test normalizing direct dictionary format."""
        strategy_dict = {
            'type': 'multisplit',
            'params': {'split_pos': 2}
        }
        
        strategy = self.loader.normalize_strategy_dict(strategy_dict)
        
        assert strategy.type == 'multisplit'
        assert strategy.params == {'split_pos': 2}
        assert strategy.no_fallbacks is True
        assert strategy.forced is True
        assert strategy.source_format == 'dict'
    
    def test_normalize_strategy_dict_invalid_format_error(self):
        """Test that invalid dict format raises error."""
        strategy_dict = {
            'invalid_field': 'value'
        }
        
        with pytest.raises(StrategyLoadError, match="Invalid strategy dict format"):
            self.loader.normalize_strategy_dict(strategy_dict)


class TestUnifiedStrategyLoaderFileOperations:
    """Test file loading operations."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.loader = UnifiedStrategyLoader(debug=True)
    
    def test_load_strategies_from_file_simple_format(self):
        """Test loading strategies from simple JSON format."""
        strategies_data = {
            "youtube.com": "fakeddisorder(ttl=8, fooling=badsum)",
            "rutracker.org": "--dpi-desync=multisplit --dpi-desync-split-pos=2",
            "x.com": {
                "type": "disorder",
                "params": {"repeats": 2}
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(strategies_data, f)
            temp_path = f.name
        
        try:
            strategies = self.loader.load_strategies_from_file(temp_path)
            
            assert len(strategies) == 3
            
            # Check youtube.com strategy
            youtube_strategy = strategies["youtube.com"]
            assert youtube_strategy.type == 'fakeddisorder'
            assert youtube_strategy.params['ttl'] == 8
            assert youtube_strategy.params['fooling'] == 'badsum'
            assert youtube_strategy.no_fallbacks is True
            
            # Check rutracker.org strategy
            rutracker_strategy = strategies["rutracker.org"]
            assert rutracker_strategy.type == 'multisplit'
            assert rutracker_strategy.params['split_pos'] == 2
            assert rutracker_strategy.no_fallbacks is True
            
            # Check x.com strategy
            x_strategy = strategies["x.com"]
            assert x_strategy.type == 'disorder'
            assert x_strategy.params['repeats'] == 2
            assert x_strategy.no_fallbacks is True
            
        finally:
            Path(temp_path).unlink()
    
    def test_load_strategies_from_file_nested_format(self):
        """Test loading strategies from nested JSON format."""
        strategies_data = {
            "instagram.com": {
                "strategy": "fake(ttl=5)",
                "priority": 1
            },
            "facebook.com": {
                "strategy": "--dpi-desync=seqovl --dpi-desync-split-seqovl=4",
                "enabled": True
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(strategies_data, f)
            temp_path = f.name
        
        try:
            strategies = self.loader.load_strategies_from_file(temp_path)
            
            assert len(strategies) == 2
            
            # Check instagram.com strategy
            instagram_strategy = strategies["instagram.com"]
            assert instagram_strategy.type == 'fake'
            assert instagram_strategy.params['ttl'] == 5
            assert instagram_strategy.no_fallbacks is True
            
            # Check facebook.com strategy
            facebook_strategy = strategies["facebook.com"]
            assert facebook_strategy.type == 'seqovl'
            assert facebook_strategy.params['overlap_size'] == 4
            assert facebook_strategy.no_fallbacks is True
            
        finally:
            Path(temp_path).unlink()
    
    def test_load_strategies_from_file_not_found_error(self):
        """Test that non-existent file raises error."""
        with pytest.raises(StrategyLoadError, match="Strategy file not found"):
            self.loader.load_strategies_from_file("/non/existent/file.json")
    
    def test_load_strategies_from_file_invalid_json_error(self):
        """Test that invalid JSON raises error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content")
            temp_path = f.name
        
        try:
            with pytest.raises(StrategyLoadError, match="Failed to read strategy file"):
                self.loader.load_strategies_from_file(temp_path)
        finally:
            Path(temp_path).unlink()
    
    def test_load_strategies_from_file_partial_failure(self):
        """Test that partial failures don't stop loading other strategies."""
        strategies_data = {
            "valid.com": "fakeddisorder(ttl=8)",
            "invalid.com": "invalid_format_that_will_fail",
            "another_valid.com": "split(split_pos=1)"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(strategies_data, f)
            temp_path = f.name
        
        try:
            strategies = self.loader.load_strategies_from_file(temp_path)
            
            # Should load valid strategies despite one failure
            assert len(strategies) == 2
            assert "valid.com" in strategies
            assert "another_valid.com" in strategies
            assert "invalid.com" not in strategies
            
        finally:
            Path(temp_path).unlink()


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_load_strategy_convenience_function(self):
        """Test the convenience load_strategy function."""
        strategy = load_strategy("fakeddisorder(ttl=8)", debug=True)
        
        assert isinstance(strategy, NormalizedStrategy)
        assert strategy.type == 'fakeddisorder'
        assert strategy.params['ttl'] == 8
        assert strategy.no_fallbacks is True
        assert strategy.forced is True
    
    def test_create_forced_override_convenience_function(self):
        """Test the convenience create_forced_override function."""
        strategy_dict = {
            'type': 'multisplit',
            'params': {'split_pos': 2}
        }
        
        forced_config = create_forced_override(strategy_dict, debug=True)
        
        expected = {
            'type': 'multisplit',
            'params': {'split_pos': 2},
            'no_fallbacks': True,
            'forced': True,
            'override_mode': True
        }
        
        assert forced_config == expected
    
    def test_load_strategies_from_file_convenience_function(self):
        """Test the convenience load_strategies_from_file function."""
        strategies_data = {
            "test.com": "disorder()"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(strategies_data, f)
            temp_path = f.name
        
        try:
            strategies = load_strategies_from_file(temp_path, debug=True)
            
            assert len(strategies) == 1
            assert "test.com" in strategies
            assert strategies["test.com"].type == 'disorder'
            assert strategies["test.com"].no_fallbacks is True
            
        finally:
            Path(temp_path).unlink()


class TestParameterNormalization:
    """Test parameter normalization functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.loader = UnifiedStrategyLoader(debug=True)
    
    def test_normalize_parser_v2_params_string_conversion(self):
        """Test normalization of StrategyParserV2 parameters."""
        params = {
            'ttl': 8,
            'fooling': ['badsum'],  # Single-item list should become string
            'fake_sni': ['example.com'],  # Single-item list should become string
            'repeats': 2
        }
        
        normalized = self.loader._normalize_parser_v2_params(params)
        
        assert normalized['ttl'] == 8
        assert normalized['fooling'] == 'badsum'  # Converted from list
        assert normalized['fake_sni'] == 'example.com'  # Converted from list
        assert normalized['repeats'] == 2
    
    def test_normalize_parser_v2_params_multiple_values(self):
        """Test normalization keeps multiple values as lists."""
        params = {
            'fooling': ['badsum', 'badseq'],  # Multiple values should stay as list
            'fake_sni': ['example.com', 'test.com']
        }
        
        normalized = self.loader._normalize_parser_v2_params(params)
        
        assert normalized['fooling'] == ['badsum', 'badseq']
        assert normalized['fake_sni'] == ['example.com', 'test.com']
    
    def test_normalize_parser_v2_params_empty_list_removal(self):
        """Test normalization removes empty lists."""
        params = {
            'ttl': 8,
            'fooling': [],  # Empty list should be removed
            'fake_sni': []
        }
        
        normalized = self.loader._normalize_parser_v2_params(params)
        
        assert normalized['ttl'] == 8
        assert 'fooling' not in normalized
        assert 'fake_sni' not in normalized


class TestCriticalBehavior:
    """Test critical behavior requirements."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.loader = UnifiedStrategyLoader(debug=True)
    
    def test_forced_override_always_enabled(self):
        """Test that forced override is ALWAYS enabled (Requirement 1.2)."""
        test_strategies = [
            "fakeddisorder(ttl=8)",
            "--dpi-desync=multisplit --dpi-desync-split-pos=2",
            {"type": "disorder", "params": {"repeats": 2}}
        ]
        
        for strategy_input in test_strategies:
            strategy = self.loader.load_strategy(strategy_input)
            
            # CRITICAL: These must ALWAYS be True
            assert strategy.no_fallbacks is True, f"no_fallbacks not True for {strategy_input}"
            assert strategy.forced is True, f"forced not True for {strategy_input}"
            
            # Test forced override creation
            forced_config = self.loader.create_forced_override(strategy)
            assert forced_config['no_fallbacks'] is True
            assert forced_config['forced'] is True
            assert forced_config['override_mode'] is True
    
    def test_identical_behavior_across_formats(self):
        """Test that different formats produce identical behavior (Requirement 1.1)."""
        # Same strategy in different formats
        zapret_format = "--dpi-desync=fakeddisorder --dpi-desync-ttl=8 --dpi-desync-fooling=badsum"
        function_format = "fakeddisorder(ttl=8, fooling=badsum)"
        dict_format = {
            "type": "fakeddisorder",
            "params": {"ttl": 8, "fooling": "badsum"}
        }
        
        strategies = [
            self.loader.load_strategy(zapret_format),
            self.loader.load_strategy(function_format),
            self.loader.load_strategy(dict_format)
        ]
        
        # All should produce identical engine format
        engine_formats = [s.to_engine_format() for s in strategies]
        
        # Compare the essential parts (type, params, forced behavior)
        for engine_format in engine_formats:
            assert engine_format['type'] == 'fakeddisorder'
            assert engine_format['params']['ttl'] == 8
            assert engine_format['params']['fooling'] == 'badsum'
            assert engine_format['no_fallbacks'] is True
            assert engine_format['forced'] is True
    
    def test_validation_preserves_forced_override(self):
        """Test that validation doesn't change forced override behavior."""
        strategy = NormalizedStrategy(
            type='fakeddisorder',
            params={'ttl': 8},
            no_fallbacks=True,
            forced=True
        )
        
        # Validation should not modify the strategy
        original_no_fallbacks = strategy.no_fallbacks
        original_forced = strategy.forced
        
        self.loader.validate_strategy(strategy)
        
        assert strategy.no_fallbacks == original_no_fallbacks
        assert strategy.forced == original_forced


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])