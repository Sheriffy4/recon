#!/usr/bin/env python3
"""
Demonstration: JSON Report Generation for DPI Fingerprinting

This script demonstrates how to use the enhanced_find_rst_triggers.py tool
to generate comprehensive JSON reports for DPI fingerprinting analysis.

Task 7.4 Implementation: Generate JSON report
- Output tested_strategies count
- List successful strategies with metrics
- List failed strategies
- Include recommendations
"""

import json
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from enhanced_find_rst_triggers import (
    DPIFingerprintAnalyzer,
    StrategyTestConfig,
    TestResult
)


def demo_basic_report():
    """Demonstrate basic JSON report generation"""
    print("="*80)
    print("DEMO 1: Basic JSON Report Generation")
    print("="*80)
    
    # Create analyzer for a test domain
    analyzer = DPIFingerprintAnalyzer(domain="example.com", test_count=1)
    
    # Simulate some test results
    print("\nSimulating strategy tests...")
    
    # Successful strategy 1
    config1 = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=46,
        autottl=2,
        fooling="badseq",
        overlap_size=1,
        repeats=2
    )
    analyzer.results.append(TestResult(
        config=config1,
        success=True,
        rst_count=0,
        latency_ms=45.5
    ))
    print(f"  ✓ Tested: {config1.get_description()}")
    
    # Successful strategy 2
    config2 = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=50,
        autottl=3,
        fooling="badseq",
        overlap_size=2,
        repeats=1
    )
    analyzer.results.append(TestResult(
        config=config2,
        success=True,
        rst_count=0,
        latency_ms=52.3
    ))
    print(f"  ✓ Tested: {config2.get_description()}")
    
    # Failed strategy
    config3 = StrategyTestConfig(
        desync_method="multidisorder",
        split_pos=1,
        ttl=1,
        fooling="badsum",
        overlap_size=0,
        repeats=1
    )
    analyzer.results.append(TestResult(
        config=config3,
        success=False,
        rst_count=5,
        latency_ms=0.0
    ))
    print(f"  ✗ Tested: {config3.get_description()}")
    
    # Generate report
    print("\nGenerating JSON report...")
    report = analyzer.analyze_results()
    
    # Display key metrics
    print("\nReport Summary:")
    print(f"  Domain: {report['domain']}")
    print(f"  Tested Strategies: {report['tested_strategies']}")
    print(f"  Successful: {len(report['successful_strategies'])}")
    print(f"  Failed: {len(report['failed_strategies'])}")
    print(f"  Recommendations: {len(report['recommendations'])}")
    
    return report


def demo_report_structure(report):
    """Demonstrate the structure of the JSON report"""
    print("\n" + "="*80)
    print("DEMO 2: JSON Report Structure")
    print("="*80)
    
    print("\nTop-level fields:")
    for key in report.keys():
        print(f"  - {key}")
    
    print("\nSuccessful Strategy Example:")
    if report['successful_strategies']:
        strategy = report['successful_strategies'][0]
        print(json.dumps(strategy, indent=2))
    
    print("\nFailed Strategy Example:")
    if report['failed_strategies']:
        strategy = report['failed_strategies'][0]
        print(json.dumps(strategy, indent=2))
    
    print("\nRecommendation Example:")
    if report['recommendations']:
        rec = report['recommendations'][0]
        print(json.dumps(rec, indent=2))


def demo_save_report(analyzer):
    """Demonstrate saving report to file"""
    print("\n" + "="*80)
    print("DEMO 3: Saving Report to File")
    print("="*80)
    
    # Save with auto-generated filename
    print("\nSaving report with auto-generated filename...")
    output_file = analyzer.save_results()
    
    if output_file:
        print(f"✓ Report saved to: {output_file}")
        
        # Show file size
        file_size = os.path.getsize(output_file)
        print(f"  File size: {file_size} bytes")
        
        # Verify it can be loaded
        print("\nVerifying saved file...")
        with open(output_file, 'r', encoding='utf-8') as f:
            loaded_report = json.load(f)
        
        print(f"✓ File loaded successfully")
        print(f"  Domain: {loaded_report['domain']}")
        print(f"  Tested strategies: {loaded_report['tested_strategies']}")
        
        return output_file
    else:
        print("✗ Failed to save report")
        return None


def demo_custom_filename(analyzer):
    """Demonstrate saving with custom filename"""
    print("\n" + "="*80)
    print("DEMO 4: Custom Filename")
    print("="*80)
    
    custom_file = "demo_dpi_analysis_report.json"
    print(f"\nSaving report to custom file: {custom_file}")
    
    output_file = analyzer.save_results(custom_file)
    
    if output_file:
        print(f"✓ Report saved to: {output_file}")
        return output_file
    else:
        print("✗ Failed to save report")
        return None


def demo_report_usage():
    """Demonstrate how to use the report data"""
    print("\n" + "="*80)
    print("DEMO 5: Using Report Data")
    print("="*80)
    
    # Create analyzer with more test data
    analyzer = DPIFingerprintAnalyzer(domain="test.com", test_count=1)
    
    # Add various test results
    test_configs = [
        (StrategyTestConfig(split_pos=46, autottl=2, fooling="badseq", repeats=2), True, 0, 45.0),
        (StrategyTestConfig(split_pos=50, autottl=3, fooling="badseq", repeats=1), True, 0, 52.0),
        (StrategyTestConfig(split_pos=3, ttl=1, fooling="badsum", repeats=1), False, 5, 0.0),
        (StrategyTestConfig(split_pos=100, autottl=1, fooling="md5sig", repeats=3), True, 0, 48.0),
    ]
    
    for config, success, rst_count, latency in test_configs:
        analyzer.results.append(TestResult(
            config=config,
            success=success,
            rst_count=rst_count,
            latency_ms=latency
        ))
    
    # Generate report
    report = analyzer.analyze_results()
    
    # Example 1: Find best strategy
    print("\nExample 1: Finding the best strategy")
    if report['ranked_strategies']:
        best = report['ranked_strategies'][0]
        print(f"  Best strategy: {best['description']}")
        print(f"  Success rate: {best['success_rate']:.1%}")
        print(f"  Latency: {best['avg_latency_ms']:.1f}ms")
        print(f"  Rank: #{best['rank']} ({best['rank_category']})")
    
    # Example 2: Filter by success rate
    print("\nExample 2: Strategies with >90% success rate")
    high_success = [s for s in report['successful_strategies'] if s['success_rate'] > 0.9]
    for strategy in high_success:
        print(f"  - {strategy['description']}: {strategy['success_rate']:.1%}")
    
    # Example 3: Find low-latency strategies
    print("\nExample 3: Strategies with <50ms latency")
    low_latency = [s for s in report['successful_strategies'] if s['avg_latency_ms'] < 50]
    for strategy in low_latency:
        print(f"  - {strategy['description']}: {strategy['avg_latency_ms']:.1f}ms")
    
    # Example 4: Check recommendations
    print("\nExample 4: High-priority recommendations")
    high_priority = [r for r in report['recommendations'] if r['priority'] == 'HIGH']
    for rec in high_priority:
        print(f"  - {rec['title']}")
        print(f"    {rec['description']}")
        if 'action' in rec:
            print(f"    Action: {rec['action']}")


def demo_report_comparison():
    """Demonstrate comparing multiple reports"""
    print("\n" + "="*80)
    print("DEMO 6: Report Comparison")
    print("="*80)
    
    print("\nThis demonstrates how you could compare reports from different domains")
    print("or different time periods to track DPI behavior changes.")
    
    # Example structure for comparison
    comparison = {
        "domains_tested": ["x.com", "example.com", "test.com"],
        "comparison_date": "2025-10-06",
        "findings": {
            "common_successful_strategies": [
                "multidisorder autottl=2 badseq split_pos=46"
            ],
            "domain_specific_strategies": {
                "x.com": "split_pos=46 works best",
                "example.com": "split_pos=50 works best"
            },
            "dpi_behavior_changes": [
                "No significant changes detected in last 7 days"
            ]
        }
    }
    
    print("\nExample comparison structure:")
    print(json.dumps(comparison, indent=2))


def main():
    """Run all demonstrations"""
    print("\n" + "="*80)
    print("JSON REPORT GENERATION DEMONSTRATION")
    print("Task 7.4: Generate JSON report")
    print("="*80)
    print("\nThis demonstrates the JSON report generation feature")
    print("implemented in enhanced_find_rst_triggers.py")
    
    try:
        # Demo 1: Basic report generation
        report = demo_basic_report()
        
        # Demo 2: Report structure
        demo_report_structure(report)
        
        # Create analyzer for file demos
        analyzer = DPIFingerprintAnalyzer(domain="demo.com", test_count=1)
        analyzer.results.append(TestResult(
            config=StrategyTestConfig(split_pos=46, autottl=2, fooling="badseq"),
            success=True,
            rst_count=0,
            latency_ms=45.0
        ))
        
        # Demo 3: Save to file
        auto_file = demo_save_report(analyzer)
        
        # Demo 4: Custom filename
        custom_file = demo_custom_filename(analyzer)
        
        # Demo 5: Using report data
        demo_report_usage()
        
        # Demo 6: Report comparison
        demo_report_comparison()
        
        # Summary
        print("\n" + "="*80)
        print("DEMONSTRATION COMPLETE")
        print("="*80)
        print("\nKey Features Demonstrated:")
        print("  ✓ Generate comprehensive JSON reports")
        print("  ✓ Include tested_strategies count")
        print("  ✓ List successful strategies with metrics")
        print("  ✓ List failed strategies")
        print("  ✓ Include actionable recommendations")
        print("  ✓ Save reports to files")
        print("  ✓ Use report data for analysis")
        
        print("\nUsage Example:")
        print("  python enhanced_find_rst_triggers.py --domain x.com --output x_com_report.json")
        
        # Cleanup demo files
        print("\nCleaning up demo files...")
        for file in [auto_file, custom_file]:
            if file and os.path.exists(file):
                os.remove(file)
                print(f"  Removed: {file}")
        
        return 0
        
    except Exception as e:
        print(f"\n✗ DEMO FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
