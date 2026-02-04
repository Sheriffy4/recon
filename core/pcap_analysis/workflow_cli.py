#!/usr/bin/env python3
"""
Command-line interface for automated PCAP comparison workflow

This module provides a user-friendly CLI for running the automated workflow
with various configuration options and interactive features.
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from .automated_workflow import (
    WorkflowConfig,
    run_automated_workflow,
)
from .logging_config import setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="Automated PCAP Comparison Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic comparison
  python workflow_cli.py recon_x.pcap zapret_x.pcap

  # With target domains
  python workflow_cli.py recon_x.pcap zapret_x.pcap --domains x.com twitter.com

  # Disable auto-fix
  python workflow_cli.py recon_x.pcap zapret_x.pcap --no-auto-fix

  # Custom output directory
  python workflow_cli.py recon_x.pcap zapret_x.pcap --output results_2024

  # Load configuration from file
  python workflow_cli.py --config workflow_config.json
        """,
    )

    # Input files
    parser.add_argument("recon_pcap", nargs="?", help="Path to recon PCAP file")
    parser.add_argument("zapret_pcap", nargs="?", help="Path to zapret PCAP file")

    # Configuration options
    parser.add_argument("--config", type=str, help="Load configuration from JSON file")

    parser.add_argument(
        "--domains",
        nargs="+",
        default=["x.com"],
        help="Target domains for validation (default: x.com)",
    )

    parser.add_argument(
        "--output",
        type=str,
        default="workflow_results",
        help="Output directory for results (default: workflow_results)",
    )

    # Workflow control
    parser.add_argument(
        "--no-auto-fix", action="store_true", help="Disable automatic fix application"
    )

    parser.add_argument("--no-validation", action="store_true", help="Disable fix validation")

    parser.add_argument(
        "--max-fix-attempts",
        type=int,
        default=3,
        help="Maximum fix attempts (default: 3)",
    )

    parser.add_argument(
        "--validation-timeout",
        type=int,
        default=300,
        help="Validation timeout in seconds (default: 300)",
    )

    parser.add_argument("--no-parallel", action="store_true", help="Disable parallel validation")

    parser.add_argument("--no-backup", action="store_true", help="Disable file backup before fixes")

    parser.add_argument(
        "--no-rollback", action="store_true", help="Disable rollback on fix failure"
    )

    # Output options
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error output")

    parser.add_argument("--json-output", action="store_true", help="Output results in JSON format")

    # Interactive mode
    parser.add_argument("--interactive", "-i", action="store_true", help="Run in interactive mode")

    return parser


def load_config_from_file(config_path: str) -> WorkflowConfig:
    """Load workflow configuration from JSON file"""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        return WorkflowConfig(**config_data)

    except Exception as e:
        print(f"Error loading configuration from {config_path}: {e}")
        sys.exit(1)


def create_config_from_args(args: argparse.Namespace) -> WorkflowConfig:
    """Create workflow configuration from command-line arguments"""
    if args.config:
        return load_config_from_file(args.config)

    if not args.recon_pcap or not args.zapret_pcap:
        print("Error: Both recon_pcap and zapret_pcap are required when not using --config")
        sys.exit(1)

    return WorkflowConfig(
        recon_pcap_path=args.recon_pcap,
        zapret_pcap_path=args.zapret_pcap,
        target_domains=args.domains,
        output_dir=args.output,
        enable_auto_fix=not args.no_auto_fix,
        enable_validation=not args.no_validation,
        max_fix_attempts=args.max_fix_attempts,
        validation_timeout=args.validation_timeout,
        parallel_validation=not args.no_parallel,
        backup_before_fix=not args.no_backup,
        rollback_on_failure=not args.no_rollback,
    )


def validate_inputs(config: WorkflowConfig) -> bool:
    """Validate input files and configuration"""
    errors = []

    # Check PCAP files exist
    if not os.path.exists(config.recon_pcap_path):
        errors.append(f"Recon PCAP file not found: {config.recon_pcap_path}")

    if not os.path.exists(config.zapret_pcap_path):
        errors.append(f"Zapret PCAP file not found: {config.zapret_pcap_path}")

    # Check output directory is writable
    try:
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
        test_file = os.path.join(config.output_dir, ".write_test")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
    except Exception as e:
        errors.append(f"Output directory not writable: {config.output_dir} ({e})")

    # Validate configuration values
    if config.max_fix_attempts < 1:
        errors.append("max_fix_attempts must be at least 1")

    if config.validation_timeout < 10:
        errors.append("validation_timeout must be at least 10 seconds")

    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"  - {error}")
        return False

    return True


def print_config_summary(config: WorkflowConfig) -> None:
    """Print configuration summary"""
    print("Workflow Configuration:")
    print(f"  Recon PCAP: {config.recon_pcap_path}")
    print(f"  Zapret PCAP: {config.zapret_pcap_path}")
    print(f"  Target domains: {', '.join(config.target_domains)}")
    print(f"  Output directory: {config.output_dir}")
    print(f"  Auto-fix enabled: {config.enable_auto_fix}")
    print(f"  Validation enabled: {config.enable_validation}")
    print(f"  Max fix attempts: {config.max_fix_attempts}")
    print(f"  Validation timeout: {config.validation_timeout}s")
    print(f"  Parallel validation: {config.parallel_validation}")
    print(f"  Backup before fix: {config.backup_before_fix}")
    print(f"  Rollback on failure: {config.rollback_on_failure}")
    print()


def print_results_summary(result, json_output: bool = False) -> None:
    """Print workflow results summary"""
    if json_output:
        # Output as JSON
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
        # Human-readable output
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
                    if validation.get("error"):
                        print(f"    Error: {validation['error']}")

        if result.recommendations:
            print(f"\nRecommendations ({len(result.recommendations)}):")
            for rec in result.recommendations:
                print(f"  - {rec}")

        if result.error_details:
            print("\nError details:")
            print(f"  {result.error_details}")

        print("\n" + "=" * 60)


def interactive_mode() -> WorkflowConfig:
    """Run in interactive mode to collect configuration"""
    print("Interactive Workflow Configuration")
    print("=" * 40)

    # Get PCAP files
    recon_pcap = input("Recon PCAP file path: ").strip()
    while not os.path.exists(recon_pcap):
        print(f"File not found: {recon_pcap}")
        recon_pcap = input("Recon PCAP file path: ").strip()

    zapret_pcap = input("Zapret PCAP file path: ").strip()
    while not os.path.exists(zapret_pcap):
        print(f"File not found: {zapret_pcap}")
        zapret_pcap = input("Zapret PCAP file path: ").strip()

    # Get target domains
    domains_input = input("Target domains (comma-separated, default: x.com): ").strip()
    if domains_input:
        domains = [d.strip() for d in domains_input.split(",")]
    else:
        domains = ["x.com"]

    # Get output directory
    output_dir = input("Output directory (default: workflow_results): ").strip()
    if not output_dir:
        output_dir = "workflow_results"

    # Get workflow options
    enable_auto_fix = input("Enable auto-fix? (Y/n): ").strip().lower() != "n"
    enable_validation = input("Enable validation? (Y/n): ").strip().lower() != "n"

    return WorkflowConfig(
        recon_pcap_path=recon_pcap,
        zapret_pcap_path=zapret_pcap,
        target_domains=domains,
        output_dir=output_dir,
        enable_auto_fix=enable_auto_fix,
        enable_validation=enable_validation,
    )


async def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        setup_logging(level="DEBUG")
    elif args.quiet:
        setup_logging(level="ERROR")
    else:
        setup_logging(level="INFO")

    try:
        # Get configuration
        if args.interactive:
            config = interactive_mode()
        else:
            config = create_config_from_args(args)

        # Validate inputs
        if not validate_inputs(config):
            sys.exit(1)

        # Print configuration summary
        if not args.quiet and not args.json_output:
            print_config_summary(config)

        # Run workflow
        if not args.quiet and not args.json_output:
            print("Starting automated PCAP comparison workflow...")
            print("This may take several minutes depending on PCAP size and validation domains.")
            print()

        result = await run_automated_workflow(config)

        # Print results
        if not args.quiet:
            print_results_summary(result, args.json_output)

        # Exit with appropriate code
        sys.exit(0 if result.success else 1)

    except KeyboardInterrupt:
        print("\nWorkflow interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
