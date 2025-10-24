#!/usr/bin/env python3
"""
Automated PCAP Comparison Workflow - Main Entry Point

This script provides a simple command-line interface for running the automated
PCAP comparison workflow with various options and presets.

Usage examples:
    # Quick analysis
    python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap

    # Full analysis with custom domains
    python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap --full --domains x.com twitter.com

    # Safe analysis with backups
    python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap --safe

    # Batch processing
    python automated_pcap_workflow.py --batch pcap_directory/

    # Schedule daily analysis
    python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap --schedule daily --hour 2
"""

import argparse
import asyncio
import json
import logging
import os
import sys

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pcap_analysis.workflow_integration import (
    WorkflowIntegration,
    run_quick_analysis,
    run_full_analysis,
    run_safe_analysis,
)
from core.pcap_analysis.workflow_config_manager import WorkflowConfigManager
from core.pcap_analysis.logging_config import setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="Automated PCAP Comparison Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Input files
    parser.add_argument("recon_pcap", nargs="?", help="Path to recon PCAP file")
    parser.add_argument("zapret_pcap", nargs="?", help="Path to zapret PCAP file")

    # Analysis modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--quick",
        action="store_true",
        help="Run quick analysis (no fixes or validation)",
    )
    mode_group.add_argument(
        "--full",
        action="store_true",
        help="Run full analysis with fixes and validation",
    )
    mode_group.add_argument(
        "--safe",
        action="store_true",
        help="Run safe analysis with backups and rollbacks",
    )
    mode_group.add_argument(
        "--batch",
        type=str,
        metavar="DIRECTORY",
        help="Run batch analysis on PCAP directory",
    )

    # Target domains
    parser.add_argument(
        "--domains",
        nargs="+",
        default=["x.com"],
        help="Target domains for validation (default: x.com)",
    )

    # Scheduling options
    parser.add_argument(
        "--schedule",
        choices=["daily", "weekly", "interval"],
        help="Schedule periodic analysis",
    )
    parser.add_argument(
        "--hour",
        type=int,
        default=2,
        help="Hour for daily/weekly schedule (default: 2)",
    )
    parser.add_argument(
        "--minute",
        type=int,
        default=0,
        help="Minute for daily/weekly schedule (default: 0)",
    )
    parser.add_argument(
        "--weekday",
        type=int,
        default=0,
        help="Weekday for weekly schedule (0=Monday, default: 0)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Interval in minutes for interval schedule (default: 60)",
    )

    # Output options
    parser.add_argument(
        "--output",
        type=str,
        default="workflow_results",
        help="Output directory (default: workflow_results)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate comprehensive integration report",
    )

    # Workflow options
    parser.add_argument(
        "--auto-fix", action="store_true", help="Enable automatic fix application"
    )
    parser.add_argument(
        "--no-validation", action="store_true", help="Disable fix validation"
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=3,
        help="Maximum concurrent workflows for batch processing (default: 3)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Validation timeout in seconds (default: 300)",
    )

    # Logging options
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-error output"
    )
    parser.add_argument("--log-file", type=str, help="Log to file instead of console")

    # Utility options
    parser.add_argument(
        "--list-presets",
        action="store_true",
        help="List available configuration presets",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate fixes against domains (no PCAP analysis)",
    )

    return parser


def validate_inputs(args: argparse.Namespace) -> bool:
    """Validate command-line arguments"""
    errors = []

    # Check for required inputs based on mode
    if args.batch:
        if not os.path.isdir(args.batch):
            errors.append(f"Batch directory not found: {args.batch}")
    elif not args.list_presets and not args.report and not args.validate_only:
        if not args.recon_pcap or not args.zapret_pcap:
            errors.append("Both recon_pcap and zapret_pcap are required")
        else:
            if not os.path.exists(args.recon_pcap):
                errors.append(f"Recon PCAP file not found: {args.recon_pcap}")
            if not os.path.exists(args.zapret_pcap):
                errors.append(f"Zapret PCAP file not found: {args.zapret_pcap}")

    # Validate scheduling parameters
    if args.schedule:
        if args.schedule == "daily" and (args.hour < 0 or args.hour > 23):
            errors.append("Hour must be between 0 and 23")
        if args.schedule == "weekly" and (args.weekday < 0 or args.weekday > 6):
            errors.append("Weekday must be between 0 (Monday) and 6 (Sunday)")
        if args.schedule == "interval" and args.interval < 1:
            errors.append("Interval must be at least 1 minute")

    # Validate numeric parameters
    if args.max_concurrent < 1:
        errors.append("max_concurrent must be at least 1")
    if args.timeout < 10:
        errors.append("timeout must be at least 10 seconds")

    if errors:
        print("Input validation errors:")
        for error in errors:
            print(f"  - {error}")
        return False

    return True


def print_results(result, json_output: bool = False) -> None:
    """Print workflow results"""
    if json_output:
        result_dict = {
            "success": result.success,
            "execution_time": result.execution_time,
            "fixes_applied": result.fixes_applied,
            "validation_results": result.validation_results,
            "recommendations": result.recommendations,
            "error_details": result.error_details,
        }
        print(json.dumps(result_dict, indent=2))
    else:
        print("\n" + "=" * 60)
        print("WORKFLOW RESULTS")
        print("=" * 60)

        status = "SUCCESS" if result.success else "FAILED"
        print(f"Status: {status}")
        print(f"Execution time: {result.execution_time:.2f} seconds")

        if result.fixes_applied:
            print(f"\nFixes applied ({len(result.fixes_applied)}):")
            for fix in result.fixes_applied:
                print(f"  - {fix}")

        if result.validation_results:
            print("\nValidation results:")
            for domain, validation in result.validation_results.items():
                if isinstance(validation, dict):
                    status = "PASS" if validation.get("success", False) else "FAIL"
                    print(f"  - {domain}: {status}")
                    if "success_rate" in validation:
                        print(f"    Success rate: {validation['success_rate']:.1%}")

        if result.recommendations:
            print(f"\nRecommendations ({len(result.recommendations)}):")
            for rec in result.recommendations:
                print(f"  - {rec}")

        if result.error_details:
            print(f"\nError: {result.error_details}")


async def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    log_level = "DEBUG" if args.verbose else "ERROR" if args.quiet else "INFO"
    setup_logging(log_level=log_level)

    logger = logging.getLogger(__name__)

    try:
        # Handle utility commands
        if args.list_presets:
            config_manager = WorkflowConfigManager()
            config_manager.print_preset_summary()
            return

        # Validate inputs
        if not validate_inputs(args):
            sys.exit(1)

        # Create integration instance
        integration_config = {
            "auto_apply_fixes": args.auto_fix,
            "notifications": False,  # Could be enabled based on config
        }
        integration = WorkflowIntegration(integration_config)

        # Handle different modes
        if args.report:
            # Generate integration report
            if not args.quiet:
                print("Generating integration report...")

            report = await integration.generate_integration_report()

            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print("\n" + "=" * 60)
                print("INTEGRATION REPORT")
                print("=" * 60)

                summary = report.get("summary", {})
                print(f"Total workflows: {summary.get('total_workflows', 0)}")
                print(f"Success rate: {summary.get('success_rate', 0):.1%}")
                print(f"Fixes applied: {summary.get('total_fixes_applied', 0)}")
                print(f"Domains tested: {summary.get('domains_tested', 0)}")

                recommendations = report.get("recommendations", [])
                if recommendations:
                    print("\nRecommendations:")
                    for rec in recommendations:
                        print(f"  - {rec}")

        elif args.validate_only:
            # Validation only mode
            if not args.quiet:
                print(f"Validating fixes against {len(args.domains)} domains...")

            validation_result = await integration.validate_fix_effectiveness(
                args.domains, args.timeout
            )

            if args.json:
                print(json.dumps(validation_result, indent=2))
            else:
                print("\nValidation Results:")
                print(f"Success rate: {validation_result.get('success_rate', 0):.1%}")
                print(
                    f"Successful domains: {validation_result.get('successful_domains', 0)}"
                )
                print(f"Total domains: {validation_result.get('total_domains', 0)}")

        elif args.batch:
            # Batch processing mode
            if not args.quiet:
                print(f"Starting batch analysis in {args.batch}...")

            results = await integration.run_batch_analysis(
                args.batch, args.domains, args.max_concurrent
            )

            if args.json:
                results_data = [
                    {
                        "success": r.success,
                        "execution_time": r.execution_time,
                        "fixes_applied": len(r.fixes_applied),
                        "error": r.error_details,
                    }
                    for r in results
                ]
                print(json.dumps(results_data, indent=2))
            else:
                success_count = sum(1 for r in results if r.success)
                print(f"\nBatch Results: {success_count}/{len(results)} successful")

                for i, result in enumerate(results):
                    status = "SUCCESS" if result.success else "FAILED"
                    print(f"  {i+1}: {status} ({result.execution_time:.1f}s)")

        elif args.schedule:
            # Scheduling mode
            if not args.quiet:
                print(f"Scheduling {args.schedule} analysis...")

            schedule_params = {}
            if args.schedule == "daily":
                schedule_params = {"hour": args.hour, "minute": args.minute}
            elif args.schedule == "weekly":
                schedule_params = {
                    "weekday": args.weekday,
                    "hour": args.hour,
                    "minute": args.minute,
                }
            elif args.schedule == "interval":
                schedule_params = {"interval_minutes": args.interval}

            job_id = await integration.schedule_periodic_analysis(
                args.recon_pcap, args.zapret_pcap, args.schedule, **schedule_params
            )

            print(f"Scheduled job created: {job_id}")
            print("Scheduler is now running. Press Ctrl+C to stop.")

            # Keep running until interrupted
            try:
                while True:
                    await asyncio.sleep(60)
            except KeyboardInterrupt:
                print("\nStopping scheduler...")
                await integration.scheduler.stop_scheduler()

        else:
            # Regular analysis mode
            if not args.quiet:
                mode = "full" if args.full else "safe" if args.safe else "quick"
                print(f"Starting {mode} PCAP analysis...")

            # Choose analysis function based on mode
            if args.quick:
                result = await run_quick_analysis(args.recon_pcap, args.zapret_pcap)
            elif args.full:
                result = await run_full_analysis(
                    args.recon_pcap, args.zapret_pcap, args.domains
                )
            elif args.safe:
                result = await run_safe_analysis(args.recon_pcap, args.zapret_pcap)
            else:
                # Default to comprehensive analysis
                result = await integration.run_comprehensive_analysis(
                    args.recon_pcap, args.zapret_pcap, args.domains
                )

            # Print results
            if not args.quiet:
                print_results(result, args.json)

            # Exit with appropriate code
            sys.exit(0 if result.success else 1)

    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
