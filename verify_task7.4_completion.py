#!/usr/bin/env python3
"""
Verification Script for Task 7.4: JSON Report Generation

This script verifies that Task 7.4 has been successfully completed by checking:
1. All required report fields are present
2. JSON serialization works correctly
3. File saving functionality works
4. Report structure matches requirements

Requirements from Task 7.4:
- Output tested_strategies count
- List successful strategies with metrics
- List failed strategies
- Include recommendations
"""

import json
import os
import sys
import tempfile

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from enhanced_find_rst_triggers import (
    DPIFingerprintAnalyzer,
    StrategyTestConfig,
    TestResult
)


def verify_requirement_1():
    """Verify: Output tested_strategies count"""
    print("\n[1/4] Verifying: Output tested_strategies count")
    
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    # Add test results
    for i in range(3):
        config = StrategyTestConfig(split_pos=46+i, autottl=2, fooling="badseq")
        analyzer.results.append(TestResult(
            config=config,
            success=True,
            rst_count=0,
            latency_ms=45.0
        ))
    
    report = analyzer.analyze_results()
    
    # Verify tested_strategies field exists
    assert 'tested_strategies' in report, "Missing 'tested_strategies' field"
    assert isinstance(report['tested_strategies'], int), "tested_strategies must be integer"
    assert report['tested_strategies'] == 3, f"Expected 3 strategies, got {report['tested_strategies']}"
    
    print(f"  ✓ tested_strategies count: {report['tested_strategies']}")
    print("  ✓ Requirement 1: PASSED")
    return True


def verify_requirement_2():
    """Verify: List successful strategies with metrics"""
    print("\n[2/4] Verifying: List successful strategies with metrics")
    
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    # Add successful strategy
    config = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=46,
        autottl=2,
        fooling="badseq",
        overlap_size=1,
        repeats=2
    )
    analyzer.results.append(TestResult(
        config=config,
        success=True,
        rst_count=0,
        latency_ms=45.5
    ))
    
    report = analyzer.analyze_results()
    
    # Verify successful_strategies field
    assert 'successful_strategies' in report, "Missing 'successful_strategies' field"
    assert isinstance(report['successful_strategies'], list), "successful_strategies must be list"
    assert len(report['successful_strategies']) > 0, "No successful strategies found"
    
    # Verify metrics
    strategy = report['successful_strategies'][0]
    required_metrics = ['strategy', 'description', 'success_rate', 'avg_latency_ms', 'rst_count', 'tests_run']
    
    for metric in required_metrics:
        assert metric in strategy, f"Missing metric: {metric}"
        print(f"  ✓ Metric present: {metric}")
    
    # Verify metric values
    assert strategy['success_rate'] == 1.0, "Success rate should be 1.0"
    assert strategy['avg_latency_ms'] == 45.5, "Latency should be 45.5ms"
    assert strategy['rst_count'] == 0, "RST count should be 0"
    
    print("  ✓ All required metrics present and valid")
    print("  ✓ Requirement 2: PASSED")
    return True


def verify_requirement_3():
    """Verify: List failed strategies"""
    print("\n[3/4] Verifying: List failed strategies")
    
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    # Add failed strategy
    config = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=1,
        ttl=1,
        fooling="badsum"
    )
    analyzer.results.append(TestResult(
        config=config,
        success=False,
        rst_count=5,
        latency_ms=0.0
    ))
    
    report = analyzer.analyze_results()
    
    # Verify failed_strategies field
    assert 'failed_strategies' in report, "Missing 'failed_strategies' field"
    assert isinstance(report['failed_strategies'], list), "failed_strategies must be list"
    assert len(report['failed_strategies']) > 0, "No failed strategies found"
    
    # Verify failed strategy structure
    failed = report['failed_strategies'][0]
    required_fields = ['strategy', 'description', 'success_rate', 'rst_count', 'tests_run']
    
    for field in required_fields:
        assert field in failed, f"Missing field: {field}"
        print(f"  ✓ Field present: {field}")
    
    # Verify values
    assert failed['success_rate'] == 0.0, "Failed strategy should have 0.0 success rate"
    assert failed['rst_count'] == 5, "RST count should be 5"
    
    print("  ✓ Failed strategies properly tracked")
    print("  ✓ Requirement 3: PASSED")
    return True


def verify_requirement_4():
    """Verify: Include recommendations"""
    print("\n[4/4] Verifying: Include recommendations")
    
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    # Add successful strategy to generate recommendations
    config = StrategyTestConfig(split_pos=46, autottl=2, fooling="badseq", repeats=2)
    analyzer.results.append(TestResult(
        config=config,
        success=True,
        rst_count=0,
        latency_ms=45.0
    ))
    
    report = analyzer.analyze_results()
    
    # Verify recommendations field
    assert 'recommendations' in report, "Missing 'recommendations' field"
    assert isinstance(report['recommendations'], list), "recommendations must be list"
    assert len(report['recommendations']) > 0, "No recommendations generated"
    
    # Verify recommendation structure
    rec = report['recommendations'][0]
    required_fields = ['priority', 'title', 'description']
    
    for field in required_fields:
        assert field in rec, f"Missing field: {field}"
        print(f"  ✓ Field present: {field}")
    
    # Verify priority values
    valid_priorities = ['HIGH', 'MEDIUM', 'LOW']
    assert rec['priority'] in valid_priorities, f"Invalid priority: {rec['priority']}"
    
    print(f"  ✓ Recommendation priority: {rec['priority']}")
    print(f"  ✓ Recommendation title: {rec['title']}")
    print("  ✓ Recommendations properly generated")
    print("  ✓ Requirement 4: PASSED")
    return True


def verify_json_serialization():
    """Verify JSON serialization works"""
    print("\n[BONUS] Verifying: JSON serialization")
    
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    config = StrategyTestConfig(split_pos=46, autottl=2, fooling="badseq")
    analyzer.results.append(TestResult(
        config=config,
        success=True,
        rst_count=0,
        latency_ms=45.0
    ))
    
    report = analyzer.analyze_results()
    
    # Test serialization
    try:
        json_str = json.dumps(report, indent=2, ensure_ascii=False)
        print(f"  ✓ Report serialized to JSON ({len(json_str)} bytes)")
        
        # Test deserialization
        parsed = json.loads(json_str)
        assert parsed['domain'] == 'test.com', "Domain mismatch"
        print("  ✓ Report deserialized successfully")
        
    except Exception as e:
        print(f"  ✗ JSON serialization failed: {e}")
        return False
    
    return True


def verify_file_saving():
    """Verify file saving works"""
    print("\n[BONUS] Verifying: File saving")
    
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    config = StrategyTestConfig(split_pos=46, autottl=2, fooling="badseq")
    analyzer.results.append(TestResult(
        config=config,
        success=True,
        rst_count=0,
        latency_ms=45.0
    ))
    
    # Save to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_file = f.name
    
    try:
        output_file = analyzer.save_results(temp_file)
        assert output_file == temp_file, "Output file path mismatch"
        assert os.path.exists(output_file), "File not created"
        
        # Verify file content
        with open(output_file, 'r', encoding='utf-8') as f:
            loaded = json.load(f)
        
        assert 'tested_strategies' in loaded, "Missing field in saved file"
        print(f"  ✓ Report saved to: {output_file}")
        print(f"  ✓ File size: {os.path.getsize(output_file)} bytes")
        print("  ✓ File content valid")
        
        return True
        
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def main():
    """Run all verification checks"""
    print("="*80)
    print("TASK 7.4 COMPLETION VERIFICATION")
    print("="*80)
    print("\nVerifying all requirements from Task 7.4:")
    print("  1. Output tested_strategies count")
    print("  2. List successful strategies with metrics")
    print("  3. List failed strategies")
    print("  4. Include recommendations")
    
    try:
        # Verify all requirements
        results = []
        results.append(verify_requirement_1())
        results.append(verify_requirement_2())
        results.append(verify_requirement_3())
        results.append(verify_requirement_4())
        
        # Bonus verifications
        results.append(verify_json_serialization())
        results.append(verify_file_saving())
        
        # Summary
        print("\n" + "="*80)
        if all(results):
            print("✓ ALL VERIFICATIONS PASSED")
            print("="*80)
            print("\nTask 7.4: JSON Report Generation - COMPLETE ✅")
            print("\nAll requirements have been successfully implemented:")
            print("  ✓ Output tested_strategies count")
            print("  ✓ List successful strategies with metrics")
            print("  ✓ List failed strategies")
            print("  ✓ Include recommendations")
            print("\nBonus features verified:")
            print("  ✓ JSON serialization/deserialization")
            print("  ✓ File saving functionality")
            print("\nImplementation files:")
            print("  - enhanced_find_rst_triggers.py (main implementation)")
            print("  - test_json_report_generation.py (test suite)")
            print("  - demo_json_report_generation.py (demonstration)")
            print("  - TASK7.4_JSON_REPORT_GENERATION_COMPLETE.md (documentation)")
            return 0
        else:
            print("✗ SOME VERIFICATIONS FAILED")
            print("="*80)
            return 1
            
    except Exception as e:
        print(f"\n✗ VERIFICATION ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
