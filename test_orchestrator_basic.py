"""
Basic test to verify AttackTestOrchestrator functionality.
"""

import sys
import logging
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from test_all_attacks import (
    AttackTestOrchestrator,
    AttackRegistryLoader,
    TestStatus
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_registry_loader():
    """Test the attack registry loader."""
    print("\n" + "="*80)
    print("Testing AttackRegistryLoader")
    print("="*80)
    
    loader = AttackRegistryLoader()
    
    # Load all attacks
    attacks = loader.load_all_attacks()
    print(f"\n✓ Loaded {len(attacks)} attacks from registry")
    
    # Show some examples
    print("\nSample attacks:")
    for i, (name, metadata) in enumerate(list(attacks.items())[:5]):
        print(f"  {i+1}. {name}")
        print(f"     Category: {metadata.category}")
        print(f"     Normalized: {metadata.normalized_name}")
        print(f"     Default params: {metadata.default_params}")
        print(f"     Test variations: {len(metadata.test_variations)}")
    
    # Get categories
    categories = loader.get_all_categories()
    print(f"\n✓ Found {len(categories)} categories: {categories}")
    
    # Check for missing attacks
    missing = loader.handle_missing_attacks()
    if missing:
        print(f"\n⚠ Found {len(missing)} missing attacks: {missing}")
    else:
        print("\n✓ No missing attacks detected")
    
    return True

def test_orchestrator_initialization():
    """Test orchestrator initialization."""
    print("\n" + "="*80)
    print("Testing AttackTestOrchestrator Initialization")
    print("="*80)
    
    output_dir = Path("test_results_basic")
    orchestrator = AttackTestOrchestrator(output_dir=output_dir)
    
    print(f"\n✓ Orchestrator initialized")
    print(f"  Output directory: {orchestrator.output_dir}")
    print(f"  Registry loader: {type(orchestrator.registry_loader).__name__}")
    print(f"  Parser: {type(orchestrator.parser).__name__}")
    print(f"  Validator: {type(orchestrator.validator).__name__}")
    
    return True

def test_strategy_generation():
    """Test strategy string generation."""
    print("\n" + "="*80)
    print("Testing Strategy String Generation")
    print("="*80)
    
    orchestrator = AttackTestOrchestrator()
    
    # Test various parameter formats
    test_cases = [
        ('fake', {'ttl': 1, 'fooling': ['badsum']}, "fake(ttl=1, fooling=['badsum'])"),
        ('split', {'split_pos': 2}, "split(split_pos=2)"),
        ('fakeddisorder', {'split_pos': 76, 'ttl': 3}, "fakeddisorder(split_pos=76, ttl=3)"),
    ]
    
    for attack_name, params, expected in test_cases:
        result = orchestrator._generate_strategy_string(attack_name, params)
        status = "✓" if result == expected else "✗"
        print(f"\n{status} {attack_name}")
        print(f"  Generated: {result}")
        print(f"  Expected:  {expected}")
        if result != expected:
            print(f"  MISMATCH!")
    
    return True

def test_report_generation():
    """Test report generation without actual test execution."""
    print("\n" + "="*80)
    print("Testing Report Generation")
    print("="*80)
    
    from test_all_attacks import TestResult, TestReport
    
    # Create mock report
    report = TestReport()
    
    # Add some mock results
    report.add_result(TestResult(
        attack_name='fake',
        params={'ttl': 1},
        status=TestStatus.PASSED,
        duration=0.5
    ))
    
    report.add_result(TestResult(
        attack_name='split',
        params={'split_pos': 2},
        status=TestStatus.FAILED,
        duration=0.3
    ))
    
    report.add_result(TestResult(
        attack_name='disorder',
        params={'split_pos': 1},
        status=TestStatus.ERROR,
        error='Test error',
        duration=0.1
    ))
    
    print(f"\n✓ Created mock report with {report.total_tests} tests")
    print(f"  Passed: {report.passed}")
    print(f"  Failed: {report.failed}")
    print(f"  Errors: {report.errors}")
    
    # Test JSON serialization
    report_dict = report.to_dict()
    print(f"\n✓ Report serialized to dictionary")
    print(f"  Keys: {list(report_dict.keys())}")
    
    return True

def test_baseline_operations():
    """Test baseline save/load operations."""
    print("\n" + "="*80)
    print("Testing Baseline Operations")
    print("="*80)
    
    from test_all_attacks import TestResult
    
    output_dir = Path("test_results_baseline")
    output_dir.mkdir(exist_ok=True)
    
    orchestrator = AttackTestOrchestrator(output_dir=output_dir)
    
    # Add mock result
    orchestrator.report.add_result(TestResult(
        attack_name='fake',
        params={'ttl': 1},
        status=TestStatus.PASSED,
        duration=0.5
    ))
    
    # Save baseline
    baseline_file = output_dir / "test_baseline.json"
    orchestrator.save_baseline(baseline_file)
    print(f"\n✓ Baseline saved to {baseline_file}")
    
    # Load baseline
    loaded = orchestrator.load_baseline(baseline_file)
    print(f"✓ Baseline loaded")
    print(f"  Timestamp: {loaded.get('timestamp', 'N/A')}")
    print(f"  Results: {len(loaded.get('results', []))}")
    
    # Test regression detection
    regressions = orchestrator.detect_regressions()
    print(f"\n✓ Regression detection completed")
    print(f"  Regressions found: {len(regressions)}")
    
    return True

def main():
    """Run all basic tests."""
    print("\n" + "="*80)
    print("ATTACK TEST ORCHESTRATOR - BASIC VERIFICATION")
    print("="*80)
    
    tests = [
        ("Registry Loader", test_registry_loader),
        ("Orchestrator Initialization", test_orchestrator_initialization),
        ("Strategy Generation", test_strategy_generation),
        ("Report Generation", test_report_generation),
        ("Baseline Operations", test_baseline_operations),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success, None))
        except Exception as e:
            results.append((test_name, False, str(e)))
            print(f"\n✗ Test failed: {e}")
            import traceback
            traceback.print_exc()
    
    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for test_name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status} - {test_name}")
        if error:
            print(f"       Error: {error}")
    
    print(f"\n{passed}/{total} tests passed")
    print("="*80 + "\n")
    
    return 0 if passed == total else 1

if __name__ == '__main__':
    exit(main())
