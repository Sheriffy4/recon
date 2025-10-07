#!/usr/bin/env python3
"""
Test JSON Report Generation for DPI Fingerprinting Analysis Tool

This test verifies that the enhanced_find_rst_triggers.py tool correctly generates
JSON reports with all required elements as specified in task 7.4.

Requirements verified:
- Output tested_strategies count
- List successful strategies with metrics
- List failed strategies
- Include recommendations
"""

import json
import os
import sys
import tempfile
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from enhanced_find_rst_triggers import (
    DPIFingerprintAnalyzer,
    StrategyTestConfig,
    TestResult
)


def test_json_report_structure():
    """Test that JSON report contains all required elements"""
    print("Testing JSON report structure...")
    
    # Create analyzer with test domain
    analyzer = DPIFingerprintAnalyzer(domain="example.com", test_count=1)
    
    # Create mock test results
    # Successful strategy
    success_config = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=46,
        autottl=2,
        fooling="badseq",
        overlap_size=1,
        repeats=2
    )
    
    analyzer.results.append(TestResult(
        config=success_config,
        success=True,
        rst_count=0,
        latency_ms=45.5
    ))
    
    # Failed strategy
    fail_config = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=1,
        ttl=1,
        fooling="badsum",
        overlap_size=0,
        repeats=1
    )
    
    analyzer.results.append(TestResult(
        config=fail_config,
        success=False,
        rst_count=5,
        latency_ms=0.0
    ))
    
    # Generate report
    report = analyzer.analyze_results()
    
    # Verify required fields
    assert 'tested_strategies' in report, "Missing 'tested_strategies' count"
    assert 'successful_strategies' in report, "Missing 'successful_strategies' list"
    assert 'failed_strategies' in report, "Missing 'failed_strategies' list"
    assert 'recommendations' in report, "Missing 'recommendations' list"
    
    print("✓ All required fields present in report")
    
    # Verify tested_strategies count
    assert isinstance(report['tested_strategies'], int), "tested_strategies should be an integer"
    assert report['tested_strategies'] > 0, "tested_strategies count should be > 0"
    print(f"✓ tested_strategies count: {report['tested_strategies']}")
    
    # Verify successful strategies structure
    assert isinstance(report['successful_strategies'], list), "successful_strategies should be a list"
    if report['successful_strategies']:
        success_strategy = report['successful_strategies'][0]
        assert 'strategy' in success_strategy, "Missing 'strategy' field"
        assert 'success_rate' in success_strategy, "Missing 'success_rate' metric"
        assert 'avg_latency_ms' in success_strategy, "Missing 'avg_latency_ms' metric"
        assert 'rst_count' in success_strategy, "Missing 'rst_count' metric"
        print(f"✓ Successful strategies have required metrics")
    
    # Verify failed strategies structure
    assert isinstance(report['failed_strategies'], list), "failed_strategies should be a list"
    if report['failed_strategies']:
        fail_strategy = report['failed_strategies'][0]
        assert 'strategy' in fail_strategy, "Missing 'strategy' field"
        assert 'rst_count' in fail_strategy, "Missing 'rst_count' metric"
        print(f"✓ Failed strategies have required metrics")
    
    # Verify recommendations structure
    assert isinstance(report['recommendations'], list), "recommendations should be a list"
    if report['recommendations']:
        recommendation = report['recommendations'][0]
        assert 'priority' in recommendation, "Missing 'priority' field"
        assert 'title' in recommendation, "Missing 'title' field"
        assert 'description' in recommendation, "Missing 'description' field"
        print(f"✓ Recommendations have required fields")
    
    print("✓ JSON report structure validation passed")
    return report


def test_json_serialization():
    """Test that report can be serialized to JSON"""
    print("\nTesting JSON serialization...")
    
    # Create analyzer
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    # Add test result
    config = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=46,
        autottl=2,
        fooling="badseq"
    )
    
    analyzer.results.append(TestResult(
        config=config,
        success=True,
        rst_count=0,
        latency_ms=50.0
    ))
    
    # Generate report
    report = analyzer.analyze_results()
    
    # Try to serialize to JSON
    try:
        json_str = json.dumps(report, indent=2, ensure_ascii=False)
        print(f"✓ Report serialized to JSON ({len(json_str)} bytes)")
        
        # Verify it can be deserialized
        parsed = json.loads(json_str)
        assert parsed['domain'] == 'test.com', "Domain mismatch after deserialization"
        print("✓ Report can be deserialized from JSON")
        
    except Exception as e:
        print(f"✗ JSON serialization failed: {e}")
        raise
    
    return json_str


def test_save_to_file():
    """Test saving report to JSON file"""
    print("\nTesting save to file...")
    
    # Create analyzer
    analyzer = DPIFingerprintAnalyzer(domain="save-test.com", test_count=1)
    
    # Add test result
    config = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=46,
        autottl=2,
        fooling="badseq"
    )
    
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
        # Save results
        output_file = analyzer.save_results(temp_file)
        assert output_file == temp_file, "Output file path mismatch"
        print(f"✓ Report saved to: {output_file}")
        
        # Verify file exists and is valid JSON
        assert os.path.exists(output_file), "Output file not created"
        
        with open(output_file, 'r', encoding='utf-8') as f:
            loaded_report = json.load(f)
        
        # Verify content
        assert loaded_report['domain'] == 'save-test.com', "Domain mismatch in saved file"
        assert 'tested_strategies' in loaded_report, "Missing tested_strategies in saved file"
        assert 'successful_strategies' in loaded_report, "Missing successful_strategies in saved file"
        assert 'failed_strategies' in loaded_report, "Missing failed_strategies in saved file"
        assert 'recommendations' in loaded_report, "Missing recommendations in saved file"
        
        print("✓ Saved file contains all required fields")
        
        # Print sample of saved content
        print("\nSample of saved JSON:")
        print(f"  Domain: {loaded_report['domain']}")
        print(f"  Tested strategies: {loaded_report['tested_strategies']}")
        print(f"  Successful: {len(loaded_report['successful_strategies'])}")
        print(f"  Failed: {len(loaded_report['failed_strategies'])}")
        print(f"  Recommendations: {len(loaded_report['recommendations'])}")
        
    finally:
        # Cleanup
        if os.path.exists(temp_file):
            os.remove(temp_file)
            print(f"✓ Cleaned up temporary file")


def test_report_completeness():
    """Test that report includes all metrics and details"""
    print("\nTesting report completeness...")
    
    analyzer = DPIFingerprintAnalyzer(domain="complete-test.com", test_count=2)
    
    # Add multiple test results with different outcomes
    configs = [
        StrategyTestConfig(desync_method="multidisorder", split_pos=46, autottl=2, fooling="badseq", repeats=2),
        StrategyTestConfig(desync_method="multidisorder", split_pos=3, ttl=1, fooling="badsum", repeats=1),
        StrategyTestConfig(desync_method="multidisorder", split_pos=50, autottl=3, fooling="md5sig", repeats=1),
    ]
    
    # Add successful results
    for config in configs[:2]:
        analyzer.results.append(TestResult(
            config=config,
            success=True,
            rst_count=0,
            latency_ms=45.0 + (configs.index(config) * 10)
        ))
    
    # Add failed result
    analyzer.results.append(TestResult(
        config=configs[2],
        success=False,
        rst_count=3,
        latency_ms=0.0
    ))
    
    # Generate report
    report = analyzer.analyze_results()
    
    # Verify summary section
    assert 'summary' in report, "Missing summary section"
    summary = report['summary']
    assert 'total_tests' in summary, "Missing total_tests in summary"
    assert 'success_rate' in summary, "Missing success_rate in summary"
    assert 'avg_latency_ms' in summary, "Missing avg_latency_ms in summary"
    print("✓ Summary section complete")
    
    # Verify timestamp
    assert 'timestamp' in report, "Missing timestamp"
    try:
        datetime.fromisoformat(report['timestamp'])
        print("✓ Timestamp is valid ISO format")
    except:
        print("✗ Invalid timestamp format")
        raise
    
    # Verify domain and target_ip
    assert 'domain' in report, "Missing domain"
    assert 'target_ip' in report, "Missing target_ip"
    print("✓ Domain and target_ip present")
    
    # Verify ranked strategies (from task 7.3)
    if 'ranked_strategies' in report and report['ranked_strategies']:
        ranked = report['ranked_strategies'][0]
        assert 'rank' in ranked, "Missing rank in ranked strategy"
        assert 'composite_score' in ranked, "Missing composite_score"
        assert 'rank_category' in ranked, "Missing rank_category"
        print("✓ Ranked strategies include ranking details")
    
    print("✓ Report completeness validation passed")
    
    return report


def print_sample_report(report):
    """Print a sample of the generated report"""
    print("\n" + "="*80)
    print("SAMPLE JSON REPORT")
    print("="*80)
    
    # Print formatted JSON sample
    sample = {
        'domain': report['domain'],
        'tested_strategies': report['tested_strategies'],
        'successful_strategies_count': len(report['successful_strategies']),
        'failed_strategies_count': len(report['failed_strategies']),
        'recommendations_count': len(report['recommendations']),
        'summary': report['summary']
    }
    
    if report['successful_strategies']:
        sample['sample_successful_strategy'] = report['successful_strategies'][0]
    
    if report['recommendations']:
        sample['sample_recommendation'] = report['recommendations'][0]
    
    print(json.dumps(sample, indent=2))
    print("="*80)


def main():
    """Run all tests"""
    print("="*80)
    print("JSON REPORT GENERATION TEST SUITE")
    print("Task 7.4: Generate JSON report")
    print("="*80)
    
    try:
        # Test 1: Report structure
        report1 = test_json_report_structure()
        
        # Test 2: JSON serialization
        test_json_serialization()
        
        # Test 3: Save to file
        test_save_to_file()
        
        # Test 4: Report completeness
        report4 = test_report_completeness()
        
        # Print sample report
        print_sample_report(report4)
        
        print("\n" + "="*80)
        print("✓ ALL TESTS PASSED")
        print("="*80)
        print("\nTask 7.4 Requirements Verified:")
        print("  ✓ Output tested_strategies count")
        print("  ✓ List successful strategies with metrics")
        print("  ✓ List failed strategies")
        print("  ✓ Include recommendations")
        print("\nJSON report generation is fully functional!")
        
        return 0
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
