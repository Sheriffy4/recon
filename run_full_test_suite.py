"""
Full Test Suite Runner - QS-7

This script runs the complete attack validation test suite, testing all registered
attacks with their default parameters and variations.

Usage:
    python run_full_test_suite.py [--categories CATEGORY1,CATEGORY2] [--output-dir DIR]
"""

import sys
import logging
import argparse
from pathlib import Path
from datetime import datetime

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from test_all_attacks import AttackTestOrchestrator, TestStatus


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('full_test_suite.log')
        ]
    )


def print_summary(report):
    """Print a summary of test results."""
    print("\n" + "=" * 80)
    print("FULL TEST SUITE RESULTS")
    print("=" * 80)
    print(f"\nTotal Tests:   {report.total_tests}")
    print(f"Passed:        {report.passed} ({report.passed/report.total_tests*100:.1f}%)" if report.total_tests > 0 else "Passed:        0")
    print(f"Failed:        {report.failed}")
    print(f"Errors:        {report.errors}")
    print(f"Skipped:       {report.skipped}")
    print(f"Duration:      {report.duration:.2f}s")
    print(f"Timestamp:     {report.timestamp}")
    
    # Attack summary
    print("\n" + "-" * 80)
    print("ATTACK SUMMARY")
    print("-" * 80)
    print(f"{'Attack':<25} {'Total':>6} {'Passed':>6} {'Failed':>6} {'Success':>8}")
    print("-" * 80)
    
    for attack_name, stats in sorted(report.attack_summary.items()):
        if attack_name == 'failure_patterns':
            continue
        
        print(
            f"{attack_name:<25} "
            f"{stats['total']:>6} "
            f"{stats['passed']:>6} "
            f"{stats['failed']:>6} "
            f"{stats['success_rate']:>7.1f}%"
        )
    
    # Failure patterns
    if 'failure_patterns' in report.attack_summary:
        patterns = report.attack_summary['failure_patterns']
        total_failures = sum(patterns.values())
        
        if total_failures > 0:
            print("\n" + "-" * 80)
            print("FAILURE PATTERNS")
            print("-" * 80)
            for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    print(f"{pattern:<35} {count:>6}")
    
    print("\n" + "=" * 80)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Run full attack validation test suite'
    )
    parser.add_argument(
        '--categories',
        type=str,
        help='Comma-separated list of attack categories to test (default: all)'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('test_results'),
        help='Directory for test outputs (default: test_results)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--html',
        action='store_true',
        help='Generate HTML report'
    )
    parser.add_argument(
        '--text',
        action='store_true',
        help='Generate text report'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Generate JSON report'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Parse categories
    categories = None
    if args.categories:
        categories = [c.strip() for c in args.categories.split(',')]
        logger.info(f"Testing categories: {categories}")
    
    # Create output directory
    args.output_dir.mkdir(exist_ok=True, parents=True)
    
    # Load all attack modules
    logger.info("Loading attack modules...")
    try:
        from load_all_attacks import load_all_attacks
        stats = load_all_attacks()
        logger.info(f"Loaded {stats['total_attacks']} attacks in {len(stats['categories'])} categories")
    except Exception as e:
        logger.error(f"Failed to load attacks: {e}")
        print(f"\n[ERROR] Failed to load attack modules: {e}")
        return 2
    
    # Initialize orchestrator
    logger.info("Initializing test orchestrator...")
    orchestrator = AttackTestOrchestrator(output_dir=args.output_dir)
    
    # Run tests
    logger.info("Starting full test suite...")
    print("\n" + "=" * 80)
    print("RUNNING FULL ATTACK VALIDATION TEST SUITE")
    print("=" * 80)
    print(f"Output directory: {args.output_dir}")
    if categories:
        print(f"Testing categories: {', '.join(categories)}")
    else:
        print("Testing all attacks")
    print("=" * 80 + "\n")
    
    try:
        report = orchestrator.test_all_attacks(categories=categories)
        
        # Print summary
        print_summary(report)
        
        # Generate reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if args.html or not (args.text or args.json):
            # Generate HTML by default
            html_file = orchestrator.generate_html_report()
            print(f"\n[OK] HTML report: {html_file}")
        
        if args.text:
            text_file = orchestrator.generate_text_report()
            print(f"[OK] Text report: {text_file}")
        
        if args.json:
            json_file = args.output_dir / f"attack_test_report_{timestamp}.json"
            import json
            json_file.write_text(
                json.dumps(report.to_dict(), indent=2),
                encoding='utf-8'
            )
            print(f"[OK] JSON report: {json_file}")
        
        # Exit code based on results
        if report.failed > 0 or report.errors > 0:
            logger.warning("Test suite completed with failures")
            return 1
        else:
            logger.info("Test suite completed successfully")
            return 0
    
    except Exception as e:
        logger.error(f"Test suite failed: {e}", exc_info=True)
        print(f"\n[ERROR] {e}")
        return 2


if __name__ == '__main__':
    sys.exit(main())
