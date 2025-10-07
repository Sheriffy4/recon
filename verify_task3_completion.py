"""
Verification script for Task 3: Fix Strategy Interpreter Mapping

This script demonstrates that all requirements are met:
1. Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt is applied
2. AttackTask dataclass with autottl, repeats, overlap_size
3. Correct mapping priority: desync_method before fooling
"""

import sys
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_interpreter import StrategyInterpreter, AttackTask


def print_section(title):
    """Print a section header"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def verify_fix_1():
    """Verify Fix #1: desync_method checked before fooling"""
    print_section("Verifying Fix #1: Desync Method Priority")
    
    interpreter = StrategyInterpreter()
    
    # Test 1: multidisorder should map to multidisorder (not fakeddisorder)
    print("Test 1: multidisorder with badseq fooling")
    strategy = "--dpi-desync=multidisorder --dpi-desync-fooling=badseq"
    task = interpreter.interpret_strategy(strategy)
    print(f"  Strategy: {strategy}")
    print(f"  Result: attack_type='{task.attack_type}'")
    assert task.attack_type == "multidisorder", "FAILED: Should be multidisorder"
    print("  ✅ PASS: Correctly mapped to multidisorder\n")
    
    # Test 2: fakeddisorder with badsum should map to fakeddisorder (not badsum_race)
    print("Test 2: fakeddisorder with badsum fooling")
    strategy = "--dpi-desync=fakeddisorder --dpi-desync-fooling=badsum,badseq"
    task = interpreter.interpret_strategy(strategy)
    print(f"  Strategy: {strategy}")
    print(f"  Result: attack_type='{task.attack_type}'")
    assert task.attack_type == "fakeddisorder", "FAILED: Should be fakeddisorder"
    print("  ✅ PASS: Correctly mapped to fakeddisorder (not badsum_race)\n")


def verify_autottl_support():
    """Verify autottl support in AttackTask"""
    print_section("Verifying AutoTTL Support")
    
    interpreter = StrategyInterpreter()
    
    # Test with autottl
    print("Test 1: Strategy with autottl=2")
    strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2"
    task = interpreter.interpret_strategy(strategy)
    print(f"  Strategy: {strategy}")
    print(f"  Result: autottl={task.autottl}, ttl={task.ttl}")
    assert task.autottl == 2, "FAILED: autottl should be 2"
    assert task.ttl is None, "FAILED: ttl should be None when autottl is set"
    print("  ✅ PASS: AutoTTL correctly set\n")
    
    # Test mutual exclusivity
    print("Test 2: TTL and AutoTTL are mutually exclusive")
    try:
        task = AttackTask(attack_type="test", ttl=4, autottl=2)
        print("  ❌ FAIL: Should have raised ValueError")
    except ValueError as e:
        print(f"  ✅ PASS: Correctly raised ValueError: {e}\n")


def verify_repeats_support():
    """Verify repeats support in AttackTask"""
    print_section("Verifying Repeats Support")
    
    interpreter = StrategyInterpreter()
    
    print("Test: Strategy with repeats=2")
    strategy = "--dpi-desync=multidisorder --dpi-desync-repeats=2"
    task = interpreter.interpret_strategy(strategy)
    print(f"  Strategy: {strategy}")
    print(f"  Result: repeats={task.repeats}")
    assert task.repeats == 2, "FAILED: repeats should be 2"
    print("  ✅ PASS: Repeats correctly set\n")
    
    print("Test: Default repeats=1")
    strategy = "--dpi-desync=split"
    task = interpreter.interpret_strategy(strategy)
    print(f"  Strategy: {strategy}")
    print(f"  Result: repeats={task.repeats}")
    assert task.repeats == 1, "FAILED: default repeats should be 1"
    print("  ✅ PASS: Default repeats correctly set\n")


def verify_overlap_size_support():
    """Verify overlap_size support in AttackTask"""
    print_section("Verifying Overlap Size Support")
    
    interpreter = StrategyInterpreter()
    
    print("Test: Strategy with split-seqovl=1")
    strategy = "--dpi-desync=multidisorder --dpi-desync-split-seqovl=1"
    task = interpreter.interpret_strategy(strategy)
    print(f"  Strategy: {strategy}")
    print(f"  Result: overlap_size={task.overlap_size}")
    assert task.overlap_size == 1, "FAILED: overlap_size should be 1"
    print("  ✅ PASS: Overlap size correctly mapped from split-seqovl\n")


def verify_x_com_strategy():
    """Verify the actual x.com router-tested strategy"""
    print_section("Verifying X.com Router-Tested Strategy")
    
    interpreter = StrategyInterpreter()
    
    strategy = (
        "--dpi-desync=multidisorder --dpi-desync-autottl=2 "
        "--dpi-desync-fooling=badseq --dpi-desync-repeats=2 "
        "--dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
    )
    
    print(f"Strategy: {strategy}\n")
    task = interpreter.interpret_strategy(strategy)
    
    print("Results:")
    print(f"  attack_type: {task.attack_type}")
    print(f"  autottl: {task.autottl}")
    print(f"  ttl: {task.ttl}")
    print(f"  fooling: {task.fooling}")
    print(f"  repeats: {task.repeats}")
    print(f"  split_pos: {task.split_pos}")
    print(f"  overlap_size: {task.overlap_size}")
    
    # Verify all parameters
    assert task.attack_type == "multidisorder", "FAILED: attack_type"
    assert task.autottl == 2, "FAILED: autottl"
    assert task.ttl is None, "FAILED: ttl should be None"
    assert task.fooling == ["badseq"], "FAILED: fooling"
    assert task.repeats == 2, "FAILED: repeats"
    assert task.split_pos == 46, "FAILED: split_pos"
    assert task.overlap_size == 1, "FAILED: overlap_size"
    
    print("\n  ✅ ALL PARAMETERS CORRECT!")


def main():
    """Run all verification tests"""
    print("\n" + "="*70)
    print("  TASK 3 VERIFICATION: Fix Strategy Interpreter Mapping")
    print("="*70)
    
    try:
        verify_fix_1()
        verify_autottl_support()
        verify_repeats_support()
        verify_overlap_size_support()
        verify_x_com_strategy()
        
        print("\n" + "="*70)
        print("  ✅ ALL VERIFICATIONS PASSED!")
        print("  Task 3 is complete and working correctly.")
        print("="*70 + "\n")
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ VERIFICATION FAILED: {e}\n")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
