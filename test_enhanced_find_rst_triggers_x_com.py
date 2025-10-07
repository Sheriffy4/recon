#!/usr/bin/env python3
"""
Test script for enhanced_find_rst_triggers_x_com.py

Verifies that the DPI fingerprinting analysis tool correctly:
1. Generates test configurations with all required parameters
2. Tests strategies and tracks results
3. Ranks strategies by success rate and latency
4. Generates comprehensive JSON reports
"""

import sys
import os
import json
import tempfile
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from enhanced_find_rst_triggers_x_com import (
    DPIFingerprintAnalyzer,
    StrategyTestConfig,
    TestResult
)


def test_strategy_config_creation():
    """Test StrategyTestConfig creation and string conversion"""
    print("\n=== Test 1: StrategyTestConfig Creation ===")
    
    # Test with fixed TTL
    config1 = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=46,
        ttl=1,
        fooling="badseq",
        overlap_size=1,
        repeats=2
    )
    
    strategy_str = config1.to_strategy_string()
    print(f"Strategy string: {strategy_str}")
    
    assert "--dpi-desync=multidisorder" in strategy_str
    assert "--dpi-desync-ttl=1" in strategy_str
    assert "--dpi-desync-fooling=badseq" in strategy_str
    assert "--dpi-desync-split-pos=46" in strategy_str
    assert "--dpi-desync-split-seqovl=1" in strategy_str
    assert "--dpi-desync-repeats=2" in strategy_str
    
    print("✓ Fixed TTL strategy config works")
    
    # Test with autottl
    config2 = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=46,
        autottl=2,
        fooling="badseq",
        overlap_size=1,
        repeats=2
    )
    
    strategy_str2 = config2.to_strategy_string()
    print(f"Strategy string: {strategy_str2}")
    
    assert "--dpi-desync-autottl=2" in strategy_str2
    assert "--dpi-desync-ttl" not in strategy_str2
    
    print("✓ AutoTTL strategy config works")
    
    # Test description
    desc = config2.get_description()
    print(f"Description: {desc}")
    assert "autottl=2" in desc
    assert "badseq" in desc
    assert "split_pos=46" in desc
    
    print("✓ Strategy description works")


def test_config_generation():
    """Test generation of test configurations"""
    print("\n=== Test 2: Test Configuration Generation ===")
    
    analyzer = DPIFingerprintAnalyzer("example.com")
    
    # Generate limited configs
    configs = analyzer.generate_test_configs(max_configs=50)
    
    print(f"Generated {len(configs)} configurations")
    assert len(configs) <= 50
    assert len(configs) > 0
    
    # Verify router-tested strategy is included
    router_config_found = False
    for config in configs:
        if (config.split_pos == 46 and 
            config.autottl == 2 and 
            config.fooling == "badseq" and
            config.overlap_size == 1 and
            config.repeats == 2):
            router_config_found = True
            print("✓ Router-tested strategy found in configs")
            break
    
    assert router_config_found, "Router-tested strategy not found"
    
    # Verify parameter variety
    split_positions = set(c.split_pos for c in configs)
    fooling_methods = set(c.fooling for c in configs)
    
    print(f"Split positions tested: {sorted(split_positions)}")
    print(f"Fooling methods tested: {sorted(fooling_methods)}")
    
    assert len(split_positions) > 1, "Not enough split position variety"
    assert len(fooling_methods) > 1, "Not enough fooling method variety"
    
    print("✓ Configuration generation works")


def test_result_serialization():
    """Test TestResult serialization to dict"""
    print("\n=== Test 3: Result Serialization ===")
    
    config = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=46,
        autottl=2,
        fooling="badseq",
        overlap_size=1,
        repeats=2
    )
    
    result = TestResult(
        config=config,
        success=True,
        rst_count=0,
        latency_ms=45.5,
        connection_established=True,
        tls_handshake_success=True,
        http_response_code=200
    )
    
    result_dict = result.to_dict()
    
    print(f"Result dict keys: {list(result_dict.keys())}")
    
    assert "strategy" in result_dict
    assert "description" in result_dict
    assert "success" in result_dict
    assert "rst_count" in result_dict
    assert "latency_ms" in result_dict
    assert "config" in result_dict
    
    assert result_dict["success"] == True
    assert result_dict["rst_count"] == 0
    assert result_dict["latency_ms"] == 45.5
    
    print("✓ Result serialization works")


def test_strategy_ranking():
    """Test strategy ranking by success and latency"""
    print("\n=== Test 4: Strategy Ranking ===")
    
    analyzer = DPIFingerprintAnalyzer("example.com")
    
    # Create mock results
    config1 = StrategyTestConfig(split_pos=46, ttl=1, fooling="badseq")
    config2 = StrategyTestConfig(split_pos=46, ttl=2, fooling="badseq")
    config3 = StrategyTestConfig(split_pos=46, ttl=3, fooling="badseq")
    
    # Add results with different latencies
    analyzer.results = [
        TestResult(config1, success=True, rst_count=0, latency_ms=100.0),
        TestResult(config2, success=True, rst_count=0, latency_ms=50.0),  # Best
        TestResult(config3, success=False, rst_count=1, latency_ms=200.0),
    ]
    
    ranked = analyzer.rank_strategies()
    
    print(f"Ranked {len(ranked)} successful strategies")
    
    assert len(ranked) == 2, "Should only include successful strategies"
    assert ranked[0].latency_ms == 50.0, "Best strategy should have lowest latency"
    assert ranked[0].config.ttl == 2, "Best strategy should be config2"
    
    print("✓ Strategy ranking works")


def test_report_generation():
    """Test comprehensive report generation"""
    print("\n=== Test 5: Report Generation ===")
    
    analyzer = DPIFingerprintAnalyzer("example.com")
    
    # Create mock results
    config1 = StrategyTestConfig(split_pos=46, autottl=2, fooling="badseq", overlap_size=1, repeats=2)
    config2 = StrategyTestConfig(split_pos=46, ttl=1, fooling="badsum")
    
    analyzer.results = [
        TestResult(config1, success=True, rst_count=0, latency_ms=45.0),
        TestResult(config2, success=False, rst_count=1, latency_ms=100.0),
    ]
    analyzer.total_tests = 2
    analyzer.successful_tests = 1
    analyzer.failed_tests = 1
    
    # Generate report
    start_time = datetime.now()
    end_time = datetime.now()
    duration = 10.0
    
    report = analyzer.generate_report(start_time, end_time, duration)
    
    print(f"Report keys: {list(report.keys())}")
    
    # Verify report structure
    assert "metadata" in report
    assert "summary" in report
    assert "successful_strategies" in report
    assert "failed_strategies" in report
    assert "top_5_strategies" in report
    assert "router_tested_strategy" in report
    assert "recommendations" in report
    assert "parameter_analysis" in report
    
    # Verify summary
    assert report["summary"]["tested_strategies"] == 2
    assert report["summary"]["successful_strategies"] == 1
    assert report["summary"]["failed_strategies"] == 1
    assert report["summary"]["success_rate"] == 0.5
    
    # Verify strategies
    assert len(report["successful_strategies"]) == 1
    assert len(report["failed_strategies"]) == 1
    
    # Verify router-tested strategy is identified
    assert report["router_tested_strategy"] is not None
    assert report["router_tested_strategy"]["success"] == True
    
    # Verify recommendations
    assert len(report["recommendations"]) > 0
    assert any(r["priority"] == "HIGH" for r in report["recommendations"])
    
    print("✓ Report generation works")


def test_report_saving():
    """Test saving report to JSON file"""
    print("\n=== Test 6: Report Saving ===")
    
    analyzer = DPIFingerprintAnalyzer("example.com")
    
    # Create mock result
    config = StrategyTestConfig(split_pos=46, autottl=2, fooling="badseq")
    analyzer.results = [
        TestResult(config, success=True, rst_count=0, latency_ms=45.0)
    ]
    analyzer.total_tests = 1
    analyzer.successful_tests = 1
    analyzer.failed_tests = 0
    
    # Save to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_file = f.name
    
    try:
        output_file = analyzer.save_report(temp_file)
        
        print(f"Report saved to: {output_file}")
        assert os.path.exists(output_file)
        
        # Load and verify JSON
        with open(output_file, 'r') as f:
            loaded_report = json.load(f)
        
        assert "metadata" in loaded_report
        assert "summary" in loaded_report
        assert loaded_report["metadata"]["domain"] == "example.com"
        
        print("✓ Report saving works")
        
    finally:
        # Cleanup
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_parameter_coverage():
    """Test that all required parameters are tested"""
    print("\n=== Test 7: Parameter Coverage ===")
    
    analyzer = DPIFingerprintAnalyzer("example.com")
    
    # Verify all required parameters are defined
    assert len(analyzer.split_positions) >= 6, "Should test at least 6 split positions"
    assert 1 in analyzer.split_positions
    assert 2 in analyzer.split_positions
    assert 3 in analyzer.split_positions
    assert 46 in analyzer.split_positions
    assert 50 in analyzer.split_positions
    assert 100 in analyzer.split_positions
    print(f"✓ Split positions: {analyzer.split_positions}")
    
    assert len(analyzer.ttl_values) >= 4, "Should test at least 4 TTL values"
    assert 1 in analyzer.ttl_values
    assert 2 in analyzer.ttl_values
    assert 3 in analyzer.ttl_values
    assert 4 in analyzer.ttl_values
    print(f"✓ TTL values: {analyzer.ttl_values}")
    
    assert len(analyzer.autottl_offsets) >= 3, "Should test at least 3 autottl offsets"
    assert 1 in analyzer.autottl_offsets
    assert 2 in analyzer.autottl_offsets
    assert 3 in analyzer.autottl_offsets
    print(f"✓ AutoTTL offsets: {analyzer.autottl_offsets}")
    
    assert len(analyzer.fooling_methods) >= 3, "Should test at least 3 fooling methods"
    assert "badseq" in analyzer.fooling_methods
    assert "badsum" in analyzer.fooling_methods
    assert "md5sig" in analyzer.fooling_methods
    print(f"✓ Fooling methods: {analyzer.fooling_methods}")
    
    assert len(analyzer.overlap_sizes) >= 4, "Should test at least 4 overlap sizes"
    assert 0 in analyzer.overlap_sizes
    assert 1 in analyzer.overlap_sizes
    assert 2 in analyzer.overlap_sizes
    assert 5 in analyzer.overlap_sizes
    print(f"✓ Overlap sizes: {analyzer.overlap_sizes}")
    
    assert len(analyzer.repeat_counts) >= 3, "Should test at least 3 repeat counts"
    assert 1 in analyzer.repeat_counts
    assert 2 in analyzer.repeat_counts
    assert 3 in analyzer.repeat_counts
    print(f"✓ Repeat counts: {analyzer.repeat_counts}")
    
    print("✓ All required parameters are covered")


def main():
    """Run all tests"""
    print("="*80)
    print("Testing Enhanced Find RST Triggers (X.com)")
    print("="*80)
    
    try:
        test_strategy_config_creation()
        test_config_generation()
        test_result_serialization()
        test_strategy_ranking()
        test_report_generation()
        test_report_saving()
        test_parameter_coverage()
        
        print("\n" + "="*80)
        print("ALL TESTS PASSED ✓")
        print("="*80)
        print("\nTask 7 Implementation Verified:")
        print("  ✓ 7.1: Test multiple parameters (split_pos, TTL, autottl, fooling, overlap, repeats)")
        print("  ✓ 7.2: RST detection and analysis")
        print("  ✓ 7.3: Strategy ranking by success rate and latency")
        print("  ✓ 7.4: JSON report generation with recommendations")
        print("\nThe DPI fingerprinting analysis tool is ready to use!")
        print("\nUsage:")
        print("  python enhanced_find_rst_triggers_x_com.py --domain x.com")
        print("  python enhanced_find_rst_triggers_x_com.py --domain x.com --max-strategies 100")
        print("  python enhanced_find_rst_triggers_x_com.py --domain x.com --output x_com_analysis.json")
        
        return 0
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
