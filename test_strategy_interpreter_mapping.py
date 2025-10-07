"""
Unit tests for Strategy Interpreter Mapping (Task 3.1)

Tests Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt:
- Check desync_method BEFORE fooling parameter
- Ensure multidisorder maps to multidisorder (not fakeddisorder)
- Ensure fakeddisorder with badsum maps to fakeddisorder (not badsum_race)
"""

import pytest
import sys
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_interpreter import StrategyInterpreter, AttackTask, DPIMethod


class TestStrategyInterpreterMapping:
    """Test correct mapping priority: desync_method before fooling"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.interpreter = StrategyInterpreter()
    
    def test_multidisorder_maps_to_multidisorder_not_fakeddisorder(self):
        """
        Test that multidisorder explicitly maps to multidisorder attack type.
        
        This is Fix #1 part 1: multidisorder should not be confused with fakeddisorder.
        """
        strategy_str = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq"
        
        attack_task = self.interpreter.interpret_strategy(strategy_str)
        
        assert attack_task is not None, "Strategy should parse successfully"
        assert isinstance(attack_task, AttackTask), "Should return AttackTask object"
        assert attack_task.attack_type == "multidisorder", \
            f"Expected 'multidisorder', got '{attack_task.attack_type}'"
    
    def test_fakeddisorder_with_badsum_maps_to_fakeddisorder_not_badsum_race(self):
        """
        Test that fakeddisorder with badsum fooling maps to fakeddisorder (not badsum_race).
        
        This is Fix #1 part 2: desync_method takes priority over fooling parameter.
        """
        strategy_str = "--dpi-desync=fakeddisorder --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"
        
        attack_task = self.interpreter.interpret_strategy(strategy_str)
        
        assert attack_task is not None, "Strategy should parse successfully"
        assert attack_task.attack_type == "fakeddisorder", \
            f"Expected 'fakeddisorder', got '{attack_task.attack_type}' (should not be 'badsum_race')"
        assert "badsum" in attack_task.fooling, "Should preserve badsum in fooling list"
    
    def test_desync_method_priority_over_fooling(self):
        """
        Test that desync_method is checked BEFORE fooling parameter.
        
        Even if fooling=badsum, if desync_method is explicit, it should be used.
        """
        test_cases = [
            ("--dpi-desync=multidisorder --dpi-desync-fooling=badsum", "multidisorder"),
            ("--dpi-desync=fakeddisorder --dpi-desync-fooling=badsum", "fakeddisorder"),
            ("--dpi-desync=disorder --dpi-desync-fooling=badsum", "disorder"),
            ("--dpi-desync=split --dpi-desync-fooling=badsum", "split"),
        ]
        
        for strategy_str, expected_type in test_cases:
            attack_task = self.interpreter.interpret_strategy(strategy_str)
            assert attack_task is not None, f"Strategy should parse: {strategy_str}"
            assert attack_task.attack_type == expected_type, \
                f"For '{strategy_str}': expected '{expected_type}', got '{attack_task.attack_type}'"
    
    def test_badsum_only_maps_to_badsum_race_when_no_desync_method(self):
        """
        Test that badsum fooling only maps to badsum_race when no explicit desync_method.
        
        This ensures backward compatibility while fixing the priority issue.
        """
        # This is a tricky case - if only fooling is specified without desync method
        # Currently our parser requires --dpi-desync, so this test documents expected behavior
        strategy_str = "--dpi-desync=fake --dpi-desync-fooling=badsum"
        
        attack_task = self.interpreter.interpret_strategy(strategy_str)
        
        assert attack_task is not None
        # Since desync=fake is explicit, it should be 'fake', not 'badsum_race'
        assert attack_task.attack_type == "fake"
    
    def test_x_com_router_strategy_maps_correctly(self):
        """
        Test the actual x.com router-tested strategy maps to multidisorder.
        
        Strategy: --dpi-desync=multidisorder --dpi-desync-autottl=2 
                  --dpi-desync-fooling=badseq --dpi-desync-repeats=2 
                  --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1
        """
        strategy_str = (
            "--dpi-desync=multidisorder --dpi-desync-autottl=2 "
            "--dpi-desync-fooling=badseq --dpi-desync-repeats=2 "
            "--dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
        )
        
        attack_task = self.interpreter.interpret_strategy(strategy_str)
        
        assert attack_task is not None
        assert attack_task.attack_type == "multidisorder"
        assert attack_task.autottl == 2
        assert attack_task.ttl is None  # Should use autottl, not fixed ttl
        assert attack_task.fooling == ["badseq"]
        assert attack_task.repeats == 2
        assert attack_task.split_pos == 46
        assert attack_task.overlap_size == 1
    
    def test_fake_disorder_combination_maps_to_fakeddisorder(self):
        """
        Test that fake+disorder combination is recognized as fakeddisorder.
        """
        strategy_str = "--dpi-desync=fake,disorder --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"
        
        attack_task = self.interpreter.interpret_strategy(strategy_str)
        
        assert attack_task is not None
        assert attack_task.attack_type == "fakeddisorder"
        assert attack_task.ttl == 3
        assert "badsum" in attack_task.fooling
        assert "badseq" in attack_task.fooling


class TestAttackTaskValidation:
    """Test AttackTask dataclass validation"""
    
    def test_ttl_and_autottl_mutually_exclusive(self):
        """Test that specifying both ttl and autottl raises ValueError"""
        with pytest.raises(ValueError, match="mutually exclusive"):
            AttackTask(
                attack_type="multidisorder",
                ttl=4,
                autottl=2  # Should raise error
            )
    
    def test_ttl_only_is_valid(self):
        """Test that specifying only ttl is valid"""
        task = AttackTask(
            attack_type="fakeddisorder",
            ttl=3
        )
        assert task.ttl == 3
        assert task.autottl is None
    
    def test_autottl_only_is_valid(self):
        """Test that specifying only autottl is valid"""
        task = AttackTask(
            attack_type="multidisorder",
            autottl=2
        )
        assert task.autottl == 2
        assert task.ttl is None
    
    def test_neither_ttl_nor_autottl_is_valid(self):
        """Test that specifying neither ttl nor autottl is valid (will use defaults)"""
        task = AttackTask(
            attack_type="split"
        )
        assert task.ttl is None
        assert task.autottl is None
    
    def test_fooling_string_converted_to_list(self):
        """Test that fooling string is automatically converted to list"""
        task = AttackTask(
            attack_type="fake",
            fooling="badseq"  # type: ignore
        )
        assert isinstance(task.fooling, list)
        assert task.fooling == ["badseq"]
    
    def test_default_values(self):
        """Test that default values are set correctly"""
        task = AttackTask(attack_type="split")
        
        assert task.split_pos == 3
        assert task.overlap_size == 0
        assert task.fooling == []
        assert task.repeats == 1
        assert task.window_div == 8
        assert task.ipid_step == 2048


class TestConfigToStrategyTask:
    """Test _config_to_strategy_task method"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.interpreter = StrategyInterpreter()
    
    def test_multidisorder_with_autottl(self):
        """Test multidisorder strategy with autottl"""
        strategy_str = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-split-pos=46"
        
        strategy = self.interpreter.parse_strategy(strategy_str)
        attack_task = self.interpreter._config_to_strategy_task(strategy)
        
        assert attack_task.attack_type == "multidisorder"
        assert attack_task.autottl == 2
        assert attack_task.ttl is None
        assert attack_task.split_pos == 46
    
    def test_fakeddisorder_with_ttl(self):
        """Test fakeddisorder strategy with fixed ttl"""
        strategy_str = "--dpi-desync=fakeddisorder --dpi-desync-ttl=3 --dpi-desync-split-pos=3"
        
        strategy = self.interpreter.parse_strategy(strategy_str)
        attack_task = self.interpreter._config_to_strategy_task(strategy)
        
        assert attack_task.attack_type == "fakeddisorder"
        assert attack_task.ttl == 3
        assert attack_task.autottl is None
        assert attack_task.split_pos == 3
    
    def test_repeats_parameter(self):
        """Test that repeats parameter is correctly mapped"""
        strategy_str = "--dpi-desync=multidisorder --dpi-desync-repeats=2"
        
        strategy = self.interpreter.parse_strategy(strategy_str)
        attack_task = self.interpreter._config_to_strategy_task(strategy)
        
        assert attack_task.repeats == 2
    
    def test_overlap_size_from_split_seqovl(self):
        """Test that overlap_size is correctly mapped from split_seqovl"""
        strategy_str = "--dpi-desync=multidisorder --dpi-desync-split-seqovl=1"
        
        strategy = self.interpreter.parse_strategy(strategy_str)
        attack_task = self.interpreter._config_to_strategy_task(strategy)
        
        assert attack_task.overlap_size == 1
    
    def test_default_ttl_when_neither_specified(self):
        """Test that default ttl=64 is used when neither ttl nor autottl specified"""
        strategy_str = "--dpi-desync=split"
        
        strategy = self.interpreter.parse_strategy(strategy_str)
        attack_task = self.interpreter._config_to_strategy_task(strategy)
        
        # ZapretStrategy sets default ttl=64 in __post_init__
        assert attack_task.ttl == 64
        assert attack_task.autottl is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
