#!/usr/bin/env python3
"""
Test runner for DPI strategy implementation tests.

This script provides a convenient way to run different categories of tests
with various options and configurations.
"""

import sys
import os
import argparse
import subprocess
import time
from typing import List, Dict, Any

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests import TEST_CATEGORIES, TEST_CONFIG


class TestRunner:
    """Test runner for DPI strategy tests."""
    
    def __init__(self):
        self.test_dir = os.path.dirname(__file__)
        self.project_root = os.path.dirname(self.test_dir)
        self.results = {}
    
    def run_category(self, category: str, verbose: bool = False, fail_fast: bool = False) -> Dict[str, Any]:
        """Run tests for a specific category."""
        if category not in TEST_CATEGORIES:
            raise ValueError(f"Unknown test category: {category}")
        
        test_modules = TEST_CATEGORIES[category]
        results = {
            'category': category,
            'modules': {},
            'summary': {
                'total_modules': len(test_modules),
                'passed_modules': 0,
                'failed_modules': 0,
                'total_time': 0
            }
        }
        
        print(f"\n{'='*60}")
        print(f"Running {category.upper()} tests")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        for module in test_modules:
            print(f"\nRunning {module}...")
            module_result = self._run_module(module, verbose, fail_fast)
            results['modules'][module] = module_result
            
            if module_result['success']:
                results['summary']['passed_modules'] += 1
                print(f"✓ {module} PASSED")
            else:
                results['summary']['failed_modules'] += 1
                print(f"✗ {module} FAILED")
                
                if fail_fast:
                    print("Stopping due to --fail-fast")
                    break
        
        end_time = time.time()
        results['summary']['total_time'] = end_time - start_time
        
        return results
    
    def run_all(self, verbose: bool = False, fail_fast: bool = False) -> Dict[str, Any]:
        """Run all test categories."""
        all_results = {
            'categories': {},
            'summary': {
                'total_categories': len(TEST_CATEGORIES),
                'passed_categories': 0,
                'failed_categories': 0,
                'total_time': 0
            }
        }
        
        print(f"\n{'='*60}")
        print("Running ALL DPI Strategy Tests")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        for category in TEST_CATEGORIES.keys():
            category_result = self.run_category(category, verbose, fail_fast)
            all_results['categories'][category] = category_result
            
            if category_result['summary']['failed_modules'] == 0:
                all_results['summary']['passed_categories'] += 1
            else:
                all_results['summary']['failed_categories'] += 1
                
                if fail_fast and category_result['summary']['failed_modules'] > 0:
                    print("Stopping due to --fail-fast")
                    break
        
        end_time = time.time()
        all_results['summary']['total_time'] = end_time - start_time
        
        return all_results
    
    def run_specific_tests(self, test_patterns: List[str], verbose: bool = False) -> Dict[str, Any]:
        """Run specific tests matching patterns."""
        cmd = ['python', '-m', 'pytest']
        
        # Add test patterns
        for pattern in test_patterns:
            if not pattern.startswith('tests/'):
                pattern = f'tests/{pattern}'
            cmd.append(pattern)
        
        # Add options
        if verbose:
            cmd.extend(['-v', '-s'])
        else:
            cmd.append('-q')
        
        cmd.extend(['--tb=short', '--no-header'])
        
        print(f"\nRunning specific tests: {' '.join(test_patterns)}")
        print(f"Command: {' '.join(cmd)}")
        
        start_time = time.time()
        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        end_time = time.time()
        
        return {
            'patterns': test_patterns,
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'duration': end_time - start_time,
            'return_code': result.returncode
        }
    
    def _run_module(self, module: str, verbose: bool = False, fail_fast: bool = False) -> Dict[str, Any]:
        """Run a specific test module."""
        cmd = ['python', '-m', 'pytest', f'tests/{module}.py']
        
        # Add options
        if verbose:
            cmd.extend(['-v', '-s'])
        else:
            cmd.append('-q')
        
        if fail_fast:
            cmd.append('-x')
        
        cmd.extend(['--tb=short', '--no-header'])
        
        start_time = time.time()
        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        end_time = time.time()
        
        return {
            'module': module,
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'duration': end_time - start_time,
            'return_code': result.returncode
        }
    
    def print_summary(self, results: Dict[str, Any]):
        """Print test results summary."""
        print(f"\n{'='*60}")
        print("TEST SUMMARY")
        print(f"{'='*60}")
        
        if 'categories' in results:
            # All tests summary
            summary = results['summary']
            print(f"Total Categories: {summary['total_categories']}")
            print(f"Passed Categories: {summary['passed_categories']}")
            print(f"Failed Categories: {summary['failed_categories']}")
            print(f"Total Time: {summary['total_time']:.2f}s")
            
            print(f"\nCategory Details:")
            for category, category_result in results['categories'].items():
                cat_summary = category_result['summary']
                status = "PASS" if cat_summary['failed_modules'] == 0 else "FAIL"
                print(f"  {category}: {status} ({cat_summary['passed_modules']}/{cat_summary['total_modules']} modules)")
        
        elif 'category' in results:
            # Single category summary
            summary = results['summary']
            print(f"Category: {results['category']}")
            print(f"Total Modules: {summary['total_modules']}")
            print(f"Passed Modules: {summary['passed_modules']}")
            print(f"Failed Modules: {summary['failed_modules']}")
            print(f"Total Time: {summary['total_time']:.2f}s")
            
            print(f"\nModule Details:")
            for module, module_result in results['modules'].items():
                status = "PASS" if module_result['success'] else "FAIL"
                print(f"  {module}: {status} ({module_result['duration']:.2f}s)")
        
        elif 'patterns' in results:
            # Specific tests summary
            status = "PASS" if results['success'] else "FAIL"
            print(f"Specific Tests: {status}")
            print(f"Patterns: {', '.join(results['patterns'])}")
            print(f"Duration: {results['duration']:.2f}s")
            print(f"Return Code: {results['return_code']}")
    
    def print_failures(self, results: Dict[str, Any]):
        """Print detailed failure information."""
        failures = []
        
        if 'categories' in results:
            for category, category_result in results['categories'].items():
                for module, module_result in category_result['modules'].items():
                    if not module_result['success']:
                        failures.append((f"{category}/{module}", module_result))
        
        elif 'modules' in results:
            for module, module_result in results['modules'].items():
                if not module_result['success']:
                    failures.append((module, module_result))
        
        elif not results.get('success', True):
            failures.append(("specific_tests", results))
        
        if failures:
            print(f"\n{'='*60}")
            print("FAILURE DETAILS")
            print(f"{'='*60}")
            
            for name, result in failures:
                print(f"\n{'-'*40}")
                print(f"FAILED: {name}")
                print(f"{'-'*40}")
                
                if result.get('stderr'):
                    print("STDERR:")
                    print(result['stderr'])
                
                if result.get('stdout'):
                    print("STDOUT:")
                    print(result['stdout'])


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Run DPI strategy tests')
    
    parser.add_argument(
        'category',
        nargs='?',
        choices=['unit', 'integration', 'pcap_validation', 'all'],
        default='all',
        help='Test category to run (default: all)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '-f', '--fail-fast',
        action='store_true',
        help='Stop on first failure'
    )
    
    parser.add_argument(
        '-s', '--specific',
        nargs='+',
        help='Run specific test files or patterns'
    )
    
    parser.add_argument(
        '--no-summary',
        action='store_true',
        help='Skip summary output'
    )
    
    parser.add_argument(
        '--failures-only',
        action='store_true',
        help='Only show failure details'
    )
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    try:
        if args.specific:
            # Run specific tests
            results = runner.run_specific_tests(args.specific, args.verbose)
        elif args.category == 'all':
            # Run all categories
            results = runner.run_all(args.verbose, args.fail_fast)
        else:
            # Run specific category
            results = runner.run_category(args.category, args.verbose, args.fail_fast)
        
        # Print results
        if not args.no_summary:
            runner.print_summary(results)
        
        if args.failures_only or (not args.no_summary and not _all_passed(results)):
            runner.print_failures(results)
        
        # Exit with appropriate code
        if _all_passed(results):
            print(f"\n🎉 All tests PASSED!")
            sys.exit(0)
        else:
            print(f"\n❌ Some tests FAILED!")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print(f"\n\nTest run interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        print(f"\nError running tests: {e}")
        sys.exit(1)


def _all_passed(results: Dict[str, Any]) -> bool:
    """Check if all tests passed."""
    if 'categories' in results:
        return results['summary']['failed_categories'] == 0
    elif 'category' in results:
        return results['summary']['failed_modules'] == 0
    elif 'success' in results:
        return results['success']
    else:
        return False


if __name__ == '__main__':
    main()