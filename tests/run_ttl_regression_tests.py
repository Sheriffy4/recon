#!/usr/bin/env python3
"""
TTL Regression Test Runner

This script runs comprehensive TTL regression tests to prevent future TTL-related issues.
It can be used in CI/CD pipelines or for manual testing.

Usage:
    python run_ttl_regression_tests.py [options]

Options:
    --verbose       Enable verbose output
    --baseline      Create new baseline file
    --compare       Compare against existing baseline
    --report        Generate detailed HTML report
    --critical-only Run only critical regression tests
"""

import sys
import os
import argparse
import json
import time
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add recon directory to path
recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

# Import test modules
from tests.test_ttl_regression import (
    TestTTLParameterPreservation,
    TestZapretCompatibilityRegression,
    TestTTLScenarioRegression,
    TestTTLDocumentationRegression,
    TestTTLRegressionSuite,
    run_ttl_regression_tests
)

from tests.test_ttl_parameter_parsing import (
    TestTTLParameterParsing,
    TestTTLParameterIntegration
)

import unittest


class TTLRegressionTestRunner:
    """Comprehensive TTL regression test runner."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results = {}
        self.start_time = None
        self.end_time = None
        
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all TTL regression tests."""
        
        print("🔍 Starting TTL Regression Test Suite")
        print("=" * 60)
        
        self.start_time = time.time()
        
        # Test categories to run
        test_categories = [
            {
                "name": "TTL Parameter Parsing Tests",
                "classes": [TestTTLParameterParsing, TestTTLParameterIntegration],
                "critical": True
            },
            {
                "name": "TTL Parameter Preservation Tests", 
                "classes": [TestTTLParameterPreservation],
                "critical": True
            },
            {
                "name": "Zapret Compatibility Tests",
                "classes": [TestZapretCompatibilityRegression],
                "critical": True
            },
            {
                "name": "TTL Scenario Tests",
                "classes": [TestTTLScenarioRegression],
                "critical": False
            },
            {
                "name": "TTL Documentation Tests",
                "classes": [TestTTLDocumentationRegression],
                "critical": False
            },
            {
                "name": "TTL Master Regression Suite",
                "classes": [TestTTLRegressionSuite],
                "critical": True
            }
        ]
        
        overall_success = True
        
        for category in test_categories:
            print(f"\n📋 Running {category['name']}")
            print("-" * 40)
            
            category_result = self._run_test_category(category)
            self.results[category['name']] = category_result
            
            if not category_result['success'] and category['critical']:
                overall_success = False
                print(f"❌ Critical test category failed: {category['name']}")
            elif category_result['success']:
                print(f"✅ {category['name']} passed")
            else:
                print(f"⚠️  {category['name']} failed (non-critical)")
        
        self.end_time = time.time()
        
        # Generate summary
        summary = self._generate_summary(overall_success)
        self.results['summary'] = summary
        
        return self.results
    
    def _run_test_category(self, category: Dict[str, Any]) -> Dict[str, Any]:
        """Run a specific test category."""
        
        suite = unittest.TestSuite()
        
        # Add all test classes in category
        for test_class in category['classes']:
            tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
            suite.addTests(tests)
        
        # Run tests
        stream = unittest.StringIO() if not self.verbose else sys.stdout
        runner = unittest.TextTestRunner(
            stream=stream,
            verbosity=2 if self.verbose else 1
        )
        
        result = runner.run(suite)
        
        # Collect results
        category_result = {
            'success': result.wasSuccessful(),
            'tests_run': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'success_rate': ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100) if result.testsRun > 0 else 0,
            'critical': category['critical'],
            'failure_details': [
                {'test': str(test), 'traceback': traceback}
                for test, traceback in result.failures
            ],
            'error_details': [
                {'test': str(test), 'traceback': traceback}
                for test, traceback in result.errors
            ]
        }
        
        if not self.verbose and not result.wasSuccessful():
            # Print failures for non-verbose mode
            if result.failures:
                print("Failures:")
                for test, traceback in result.failures:
                    print(f"  - {test}")
            if result.errors:
                print("Errors:")
                for test, traceback in result.errors:
                    print(f"  - {test}")
        
        return category_result
    
    def _generate_summary(self, overall_success: bool) -> Dict[str, Any]:
        """Generate test run summary."""
        
        total_tests = sum(cat['tests_run'] for cat in self.results.values() if isinstance(cat, dict) and 'tests_run' in cat)
        total_failures = sum(cat['failures'] for cat in self.results.values() if isinstance(cat, dict) and 'failures' in cat)
        total_errors = sum(cat['errors'] for cat in self.results.values() if isinstance(cat, dict) and 'errors' in cat)
        
        duration = self.end_time - self.start_time if self.start_time and self.end_time else 0
        
        summary = {
            'overall_success': overall_success,
            'total_tests': total_tests,
            'successful_tests': total_tests - total_failures - total_errors,
            'failed_tests': total_failures,
            'error_tests': total_errors,
            'success_rate': ((total_tests - total_failures - total_errors) / total_tests * 100) if total_tests > 0 else 0,
            'duration_seconds': duration,
            'timestamp': datetime.now().isoformat(),
            'critical_failures': [
                cat_name for cat_name, cat_result in self.results.items()
                if isinstance(cat_result, dict) and not cat_result.get('success', True) and cat_result.get('critical', False)
            ]
        }
        
        return summary
    
    def create_baseline(self, baseline_file: Path) -> bool:
        """Create a new regression test baseline."""
        
        print(f"📝 Creating TTL regression baseline: {baseline_file}")
        
        # Import strategy interpreter for baseline creation
        from core.strategy_interpreter import interpret_strategy
        
        # Define baseline test cases
        baseline_cases = [
            {
                "name": "Original failing command",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64",
                "critical": True
            },
            {
                "name": "Simple fake with TTL=32",
                "strategy": "--dpi-desync=fake --dpi-desync-ttl=32",
                "critical": True
            },
            {
                "name": "Fakeddisorder with TTL=1",
                "strategy": "--dpi-desync=fakeddisorder --dpi-desync-ttl=1",
                "critical": True
            },
            {
                "name": "Maximum TTL test",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=255",
                "critical": False
            },
            {
                "name": "TTL with AutoTTL",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64 --dpi-desync-autottl=2",
                "critical": False
            }
        ]
        
        baseline_data = {
            "version": "1.0",
            "created_date": datetime.now().isoformat(),
            "description": "TTL parameter handling regression baseline",
            "test_cases": []
        }
        
        for case in baseline_cases:
            try:
                result = interpret_strategy(case["strategy"])
                
                baseline_case = {
                    "name": case["name"],
                    "strategy": case["strategy"],
                    "expected_result": {
                        "ttl": result['params'].get('ttl'),
                        "type": result.get('type'),
                        "has_error": 'error' in result,
                        "params_keys": sorted(result['params'].keys()) if 'params' in result else []
                    },
                    "critical": case["critical"]
                }
                
                baseline_data["test_cases"].append(baseline_case)
                print(f"✅ Baseline case added: {case['name']}")
                
            except Exception as e:
                print(f"❌ Failed to create baseline for {case['name']}: {e}")
                return False
        
        # Save baseline
        try:
            baseline_file.parent.mkdir(parents=True, exist_ok=True)
            with open(baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            
            print(f"✅ Baseline created successfully: {baseline_file}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to save baseline: {e}")
            return False
    
    def compare_with_baseline(self, baseline_file: Path) -> Dict[str, Any]:
        """Compare current results with baseline."""
        
        print(f"📊 Comparing with baseline: {baseline_file}")
        
        if not baseline_file.exists():
            print(f"❌ Baseline file not found: {baseline_file}")
            return {"success": False, "error": "Baseline file not found"}
        
        # Load baseline
        try:
            with open(baseline_file, 'r') as f:
                baseline_data = json.load(f)
        except Exception as e:
            print(f"❌ Failed to load baseline: {e}")
            return {"success": False, "error": f"Failed to load baseline: {e}"}
        
        # Import strategy interpreter
        from core.strategy_interpreter import interpret_strategy
        
        comparison_results = {
            "baseline_version": baseline_data.get("version"),
            "baseline_date": baseline_data.get("created_date"),
            "comparison_date": datetime.now().isoformat(),
            "test_cases": [],
            "summary": {
                "total_cases": 0,
                "passed_cases": 0,
                "failed_cases": 0,
                "critical_failures": []
            }
        }
        
        for baseline_case in baseline_data["test_cases"]:
            case_name = baseline_case["name"]
            strategy = baseline_case["strategy"]
            expected = baseline_case["expected_result"]
            is_critical = baseline_case.get("critical", False)
            
            try:
                # Run current implementation
                current_result = interpret_strategy(strategy)
                
                # Compare results
                current_data = {
                    "ttl": current_result['params'].get('ttl'),
                    "type": current_result.get('type'),
                    "has_error": 'error' in current_result,
                    "params_keys": sorted(current_result['params'].keys()) if 'params' in current_result else []
                }
                
                # Check for differences
                differences = []
                if current_data["ttl"] != expected["ttl"]:
                    differences.append(f"TTL: expected {expected['ttl']}, got {current_data['ttl']}")
                
                if current_data["type"] != expected["type"]:
                    differences.append(f"Type: expected {expected['type']}, got {current_data['type']}")
                
                if current_data["has_error"] != expected["has_error"]:
                    differences.append(f"Error status: expected {expected['has_error']}, got {current_data['has_error']}")
                
                case_passed = len(differences) == 0
                
                case_result = {
                    "name": case_name,
                    "strategy": strategy,
                    "passed": case_passed,
                    "critical": is_critical,
                    "expected": expected,
                    "current": current_data,
                    "differences": differences
                }
                
                comparison_results["test_cases"].append(case_result)
                comparison_results["summary"]["total_cases"] += 1
                
                if case_passed:
                    comparison_results["summary"]["passed_cases"] += 1
                    print(f"✅ {case_name}")
                else:
                    comparison_results["summary"]["failed_cases"] += 1
                    if is_critical:
                        comparison_results["summary"]["critical_failures"].append(case_name)
                    print(f"❌ {case_name}: {', '.join(differences)}")
                
            except Exception as e:
                case_result = {
                    "name": case_name,
                    "strategy": strategy,
                    "passed": False,
                    "critical": is_critical,
                    "error": str(e)
                }
                
                comparison_results["test_cases"].append(case_result)
                comparison_results["summary"]["total_cases"] += 1
                comparison_results["summary"]["failed_cases"] += 1
                
                if is_critical:
                    comparison_results["summary"]["critical_failures"].append(case_name)
                
                print(f"❌ {case_name}: Exception - {e}")
        
        # Overall success
        comparison_results["success"] = len(comparison_results["summary"]["critical_failures"]) == 0
        
        return comparison_results
    
    def generate_html_report(self, output_file: Path) -> bool:
        """Generate detailed HTML report."""
        
        print(f"📄 Generating HTML report: {output_file}")
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>TTL Regression Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #e8f5e8; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .failure {{ background-color: #ffe8e8; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .category {{ margin: 20px 0; }}
        .test-case {{ margin: 10px 0; padding: 10px; border-left: 3px solid #ccc; }}
        .success {{ border-left-color: #4CAF50; }}
        .fail {{ border-left-color: #f44336; }}
        .critical {{ font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>TTL Regression Test Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
"""
        
        if 'summary' in self.results:
            summary = self.results['summary']
            
            if summary['overall_success']:
                html_content += f"""
    <div class="summary">
        <h2>✅ Overall Result: SUCCESS</h2>
        <p>All critical tests passed successfully.</p>
    </div>
"""
            else:
                html_content += f"""
    <div class="failure">
        <h2>❌ Overall Result: FAILURE</h2>
        <p>Critical test failures detected.</p>
    </div>
"""
            
            html_content += f"""
    <h2>Summary Statistics</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Tests</td><td>{summary['total_tests']}</td></tr>
        <tr><td>Successful Tests</td><td>{summary['successful_tests']}</td></tr>
        <tr><td>Failed Tests</td><td>{summary['failed_tests']}</td></tr>
        <tr><td>Error Tests</td><td>{summary['error_tests']}</td></tr>
        <tr><td>Success Rate</td><td>{summary['success_rate']:.1f}%</td></tr>
        <tr><td>Duration</td><td>{summary['duration_seconds']:.2f} seconds</td></tr>
    </table>
"""
        
        # Add category details
        html_content += "<h2>Test Categories</h2>"
        
        for cat_name, cat_result in self.results.items():
            if cat_name == 'summary' or not isinstance(cat_result, dict):
                continue
            
            status_class = "success" if cat_result.get('success', False) else "fail"
            critical_text = " (CRITICAL)" if cat_result.get('critical', False) else ""
            
            html_content += f"""
    <div class="category">
        <div class="test-case {status_class}">
            <h3>{cat_name}{critical_text}</h3>
            <p>Tests: {cat_result.get('tests_run', 0)} | 
               Success Rate: {cat_result.get('success_rate', 0):.1f}% | 
               Failures: {cat_result.get('failures', 0)} | 
               Errors: {cat_result.get('errors', 0)}</p>
        </div>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(html_content)
            
            print(f"✅ HTML report generated: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to generate HTML report: {e}")
            return False


def main():
    """Main entry point for TTL regression test runner."""
    
    parser = argparse.ArgumentParser(
        description="Run TTL regression tests for Recon DPI bypass system"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Create new baseline file at specified path"
    )
    
    parser.add_argument(
        "--compare",
        type=Path,
        help="Compare against existing baseline file"
    )
    
    parser.add_argument(
        "--report",
        type=Path,
        help="Generate detailed HTML report at specified path"
    )
    
    parser.add_argument(
        "--critical-only",
        action="store_true",
        help="Run only critical regression tests"
    )
    
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("test_results"),
        help="Output directory for reports and baselines"
    )
    
    args = parser.parse_args()
    
    # Create test runner
    runner = TTLRegressionTestRunner(verbose=args.verbose)
    
    # Handle baseline creation
    if args.baseline:
        baseline_file = args.output_dir / args.baseline
        success = runner.create_baseline(baseline_file)
        return 0 if success else 1
    
    # Handle baseline comparison
    if args.compare:
        comparison_result = runner.compare_with_baseline(args.compare)
        
        if comparison_result["success"]:
            print("\n✅ All baseline comparisons passed!")
        else:
            print(f"\n❌ Baseline comparison failed!")
            if "critical_failures" in comparison_result.get("summary", {}):
                critical_failures = comparison_result["summary"]["critical_failures"]
                if critical_failures:
                    print(f"Critical failures: {critical_failures}")
        
        return 0 if comparison_result["success"] else 1
    
    # Run regression tests
    results = runner.run_all_tests()
    
    # Generate HTML report if requested
    if args.report:
        report_file = args.output_dir / args.report
        runner.generate_html_report(report_file)
    
    # Print final summary
    print("\n" + "=" * 60)
    print("📊 TTL Regression Test Summary")
    print("=" * 60)
    
    if 'summary' in results:
        summary = results['summary']
        
        print(f"Total tests: {summary['total_tests']}")
        print(f"Successful: {summary['successful_tests']}")
        print(f"Failed: {summary['failed_tests']}")
        print(f"Errors: {summary['error_tests']}")
        print(f"Success rate: {summary['success_rate']:.1f}%")
        print(f"Duration: {summary['duration_seconds']:.2f} seconds")
        
        if summary['overall_success']:
            print("\n✅ All TTL regression tests passed!")
            print("✅ TTL parameter preservation verified")
            print("✅ Zapret compatibility maintained")
            print("✅ No regressions detected")
        else:
            print(f"\n❌ TTL regression tests failed!")
            if summary['critical_failures']:
                print(f"Critical failures: {summary['critical_failures']}")
        
        return 0 if summary['overall_success'] else 1
    else:
        print("❌ No test results available")
        return 1


if __name__ == '__main__':
    sys.exit(main())