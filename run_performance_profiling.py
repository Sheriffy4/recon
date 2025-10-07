"""
Comprehensive Performance Profiling Script

This script runs all performance profiling tests for the Attack Validation Suite
and generates a comprehensive report with optimization recommendations.

Part of Task 8: Profile and optimize baseline manager, real domain tester, and CLI validation
"""

import sys
import logging
import subprocess
from pathlib import Path
from datetime import datetime


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_profiling_script(script_name: str) -> bool:
    """
    Run a profiling script and return success status.
    
    Args:
        script_name: Name of the profiling script to run
    
    Returns:
        True if successful, False otherwise
    """
    logger.info(f"\n{'=' * 70}")
    logger.info(f"Running {script_name}...")
    logger.info(f"{'=' * 70}\n")
    
    try:
        result = subprocess.run(
            [sys.executable, script_name],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        # Print output
        if result.stdout:
            print(result.stdout)
        
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        
        if result.returncode == 0:
            logger.info(f"✓ {script_name} completed successfully")
            return True
        else:
            logger.error(f"✗ {script_name} failed with return code {result.returncode}")
            return False
    
    except subprocess.TimeoutExpired:
        logger.error(f"✗ {script_name} timed out after 5 minutes")
        return False
    
    except Exception as e:
        logger.error(f"✗ {script_name} failed with error: {e}")
        return False


def generate_summary_report(results: dict):
    """Generate summary report of all profiling results."""
    logger.info("\n" + "=" * 70)
    logger.info("COMPREHENSIVE PROFILING SUMMARY")
    logger.info("=" * 70)
    
    total_tests = len(results)
    passed_tests = sum(1 for success in results.values() if success)
    failed_tests = total_tests - passed_tests
    
    logger.info(f"\nTotal profiling scripts: {total_tests}")
    logger.info(f"Successful: {passed_tests}")
    logger.info(f"Failed: {failed_tests}")
    
    logger.info("\nResults by component:")
    for script, success in results.items():
        status = "✓ PASSED" if success else "✗ FAILED"
        logger.info(f"  {status} - {script}")
    
    # Check for profiling results
    profiling_dir = Path("profiling_results")
    if profiling_dir.exists():
        report_files = list(profiling_dir.glob("*.json"))
        logger.info(f"\nGenerated {len(report_files)} profiling reports:")
        for report_file in sorted(report_files):
            logger.info(f"  - {report_file.name}")
    
    logger.info("\n" + "=" * 70)
    
    # Overall status
    if failed_tests == 0:
        logger.info("✓ ALL PROFILING TESTS PASSED")
    else:
        logger.warning(f"✗ {failed_tests} PROFILING TEST(S) FAILED")
    
    logger.info("=" * 70)


def main():
    """Main function to run all profiling scripts."""
    logger.info("Starting comprehensive performance profiling...")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    
    # Define profiling scripts to run
    profiling_scripts = [
        "profile_baseline_manager.py",
        "profile_real_domain_tester.py",
        "profile_cli_validation.py"
    ]
    
    # Run each profiling script
    results = {}
    
    for script in profiling_scripts:
        script_path = Path(__file__).parent / script
        
        if not script_path.exists():
            logger.error(f"Script not found: {script}")
            results[script] = False
            continue
        
        success = run_profiling_script(str(script_path))
        results[script] = success
    
    # Generate summary report
    generate_summary_report(results)
    
    # Exit with appropriate code
    if all(results.values()):
        logger.info("\n✓ Performance profiling completed successfully")
        sys.exit(0)
    else:
        logger.error("\n✗ Performance profiling completed with failures")
        sys.exit(1)


if __name__ == "__main__":
    main()
