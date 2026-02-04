#!/usr/bin/env python3
"""
Command-line interface for attack parity analysis tool.

This module provides a CLI tool to run analysis on provided log and PCAP file pairs,
supporting configuration options for timing tolerance and analysis depth, including
combination analysis and connection integrity validation.
"""

import argparse
import sys
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from .analyzer import AttackParityAnalyzer, AnalysisConfiguration
from .combination_registry import build_combination_registry, validate_all_combinations
from .models import ExecutionMode


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO

    # Create formatter
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="Attack Application Parity Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full parity analysis
  %(prog)s parity --discovery-log discovery.log --service-log service.log \\
                  --discovery-pcap discovery.pcap --service-pcap service.pcap \\
                  --output report.json

  # Correlation analysis only
  %(prog)s correlate --log discovery.log --pcap discovery.pcap --mode discovery

  # Timing validation
  %(prog)s timing --log service.log --pcap service.pcap --detailed

  # Combination registry analysis
  %(prog)s combinations --knowledge data/adaptive_knowledge.json --validate
        """,
    )

    # Global options
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    parser.add_argument("--log-file", type=str, help="Log file path for detailed logging")

    parser.add_argument("--config", type=str, help="Configuration file path (JSON format)")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Parity analysis command
    parity_parser = subparsers.add_parser(
        "parity", help="Perform comprehensive parity analysis between discovery and service modes"
    )
    add_parity_arguments(parity_parser)

    # Correlation analysis command
    correlate_parser = subparsers.add_parser(
        "correlate", help="Perform correlation analysis between logs and PCAP"
    )
    add_correlate_arguments(correlate_parser)

    # Timing validation command
    timing_parser = subparsers.add_parser("timing", help="Perform timing consistency validation")
    add_timing_arguments(timing_parser)

    # Combination analysis command
    combo_parser = subparsers.add_parser(
        "combinations", help="Analyze attack combinations from adaptive knowledge"
    )
    add_combination_arguments(combo_parser)

    return parser


def add_parity_arguments(parser: argparse.ArgumentParser):
    """Add arguments for parity analysis command."""
    parser.add_argument("--discovery-log", type=str, help="Path to discovery mode log file")

    parser.add_argument("--service-log", type=str, help="Path to service mode log file")

    parser.add_argument("--discovery-pcap", type=str, help="Path to discovery mode PCAP file")

    parser.add_argument("--service-pcap", type=str, help="Path to service mode PCAP file")

    parser.add_argument("--output", "-o", type=str, required=True, help="Output report file path")

    parser.add_argument(
        "--timing-tolerance",
        type=float,
        default=0.1,
        help="Timing tolerance in seconds (default: 0.1)",
    )

    parser.add_argument(
        "--format",
        choices=["json", "html", "text"],
        default="json",
        help="Output format (default: json)",
    )


def add_correlate_arguments(parser: argparse.ArgumentParser):
    """Add arguments for correlation analysis command."""
    parser.add_argument("--log", type=str, required=True, help="Path to log file")

    parser.add_argument("--pcap", type=str, required=True, help="Path to PCAP file")

    parser.add_argument(
        "--mode",
        choices=["discovery", "service"],
        default="discovery",
        help="Execution mode (default: discovery)",
    )

    parser.add_argument("--output", "-o", type=str, help="Output file path for correlation results")

    parser.add_argument(
        "--timing-tolerance",
        type=float,
        default=0.1,
        help="Timing tolerance in seconds (default: 0.1)",
    )


def add_timing_arguments(parser: argparse.ArgumentParser):
    """Add arguments for timing validation command."""
    parser.add_argument("--log", type=str, required=True, help="Path to log file")

    parser.add_argument("--pcap", type=str, required=True, help="Path to PCAP file")

    parser.add_argument("--detailed", action="store_true", help="Perform detailed timing analysis")

    parser.add_argument("--output", "-o", type=str, help="Output file path for timing results")

    parser.add_argument(
        "--tolerance", type=float, default=0.1, help="Timing tolerance in seconds (default: 0.1)"
    )


def add_combination_arguments(parser: argparse.ArgumentParser):
    """Add arguments for combination analysis command."""
    parser.add_argument(
        "--knowledge",
        type=str,
        default="data/adaptive_knowledge.json",
        help="Path to adaptive knowledge file (default: data/adaptive_knowledge.json)",
    )

    parser.add_argument("--validate", action="store_true", help="Validate combination logic")

    parser.add_argument(
        "--output", "-o", type=str, help="Output file path for combination analysis"
    )

    parser.add_argument(
        "--list-combinations", action="store_true", help="List all discovered combinations"
    )


def load_configuration(config_path: str) -> AnalysisConfiguration:
    """Load configuration from file."""
    try:
        return AnalysisConfiguration.from_file(config_path)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        sys.exit(1)


def validate_file_paths(*file_paths: Optional[str]) -> bool:
    """Validate that all provided file paths exist."""
    for file_path in file_paths:
        if file_path and not Path(file_path).exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            return False
    return True


def handle_parity_command(args: argparse.Namespace) -> int:
    """Handle parity analysis command."""
    # Validate required files
    required_files = []
    if args.discovery_log:
        required_files.append(args.discovery_log)
    if args.service_log:
        required_files.append(args.service_log)
    if args.discovery_pcap:
        required_files.append(args.discovery_pcap)
    if args.service_pcap:
        required_files.append(args.service_pcap)

    if not required_files:
        print("Error: At least one log or PCAP file must be provided", file=sys.stderr)
        return 1

    if not validate_file_paths(*required_files):
        return 1

    # Load configuration
    config = None
    if args.config:
        config = load_configuration(args.config)
    else:
        config = AnalysisConfiguration(
            timing_tolerance=args.timing_tolerance, report_format=args.format
        )

    # Create analyzer
    analyzer = AttackParityAnalyzer(timing_tolerance=config.timing_tolerance)

    try:
        # Perform analysis
        print("Starting comprehensive parity analysis...")
        results = analyzer.analyze_parity(
            discovery_log_path=args.discovery_log,
            service_log_path=args.service_log,
            discovery_pcap_path=args.discovery_pcap,
            service_pcap_path=args.service_pcap,
            output_report_path=args.output,
            analysis_config=config.to_dict(),
        )

        if results.get("success", True):
            print(f"Analysis completed successfully. Report saved to: {args.output}")

            # Print summary
            summary = analyzer.get_analysis_summary()
            if summary:
                print("\nAnalysis Summary:")
                print(f"  Semantic Accuracy: {summary['semantic_accuracy']:.1%}")
                print(f"  Truth Consistency: {summary['truth_consistency']:.1%}")
                print(f"  Parity Score: {summary['parity_score']:.1%}")
                print(f"  Total Attacks: {summary['total_attacks_analyzed']}")

                if summary["critical_issues"]:
                    print("\nCritical Issues:")
                    for issue in summary["critical_issues"]:
                        print(f"  - {issue}")

            return 0
        else:
            print(f"Analysis failed: {results.get('error', 'Unknown error')}", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Analysis failed: {e}", file=sys.stderr)
        return 1


def handle_correlate_command(args: argparse.Namespace) -> int:
    """Handle correlation analysis command."""
    if not validate_file_paths(args.log, args.pcap):
        return 1

    # Create analyzer
    analyzer = AttackParityAnalyzer(timing_tolerance=args.timing_tolerance)

    try:
        # Perform correlation analysis
        print("Starting correlation analysis...")
        mode = ExecutionMode.DISCOVERY if args.mode == "discovery" else ExecutionMode.SERVICE

        result = analyzer.analyze_correlation_only(args.log, args.pcap, mode)

        print(f"Correlation analysis completed.")
        print(f"  Semantic Accuracy: {result.semantic_accuracy:.1%}")
        print(f"  Truth Consistency: {result.truth_consistency_score:.1%}")
        print(f"  Correct Attacks: {len(result.semantically_correct_attacks)}")
        print(f"  Incorrect Attacks: {len(result.semantically_incorrect_attacks)}")
        print(f"  Truth Violations: {len(result.truth_consistency_violations)}")
        print(f"  Orphaned Modifications: {len(result.orphaned_modifications)}")

        # Save results if output specified
        if args.output:
            result_dict = {
                "semantic_accuracy": result.semantic_accuracy,
                "truth_consistency_score": result.truth_consistency_score,
                "summary": result.get_summary(),
                "violations": [
                    {
                        "type": v.violation_type,
                        "description": v.description,
                        "attack_type": v.attack_event.attack_type,
                        "timestamp": v.attack_event.timestamp.isoformat(),
                    }
                    for v in result.truth_consistency_violations
                ],
            }

            with open(args.output, "w") as f:
                json.dump(result_dict, f, indent=2)
            print(f"Results saved to: {args.output}")

        return 0

    except Exception as e:
        print(f"Correlation analysis failed: {e}", file=sys.stderr)
        return 1


def handle_timing_command(args: argparse.Namespace) -> int:
    """Handle timing validation command."""
    if not validate_file_paths(args.log, args.pcap):
        return 1

    # Create analyzer
    analyzer = AttackParityAnalyzer(timing_tolerance=args.tolerance)

    try:
        # Perform timing validation
        print("Starting timing validation...")

        results = analyzer.validate_timing_consistency(
            args.log, args.pcap, detailed_analysis=args.detailed
        )

        print("Timing validation completed.")

        if "consistency_score" in results:
            print(f"  Consistency Score: {results['consistency_score']:.1%}")

        if "alignment_score" in results:
            print(f"  Alignment Score: {results['alignment_score']:.1%}")

        if "aligned_pairs" in results:
            print(f"  Aligned Pairs: {len(results['aligned_pairs'])}")

        if "misaligned_pairs" in results:
            print(f"  Misaligned Pairs: {len(results['misaligned_pairs'])}")

        if "recommendations" in results and results["recommendations"]:
            print("\nRecommendations:")
            for rec in results["recommendations"]:
                print(f"  - {rec}")

        # Save results if output specified
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(f"Results saved to: {args.output}")

        return 0

    except Exception as e:
        print(f"Timing validation failed: {e}", file=sys.stderr)
        return 1


def handle_combinations_command(args: argparse.Namespace) -> int:
    """Handle combination analysis command."""
    if not validate_file_paths(args.knowledge):
        return 1

    try:
        print("Building attack combination registry...")

        # Build combination registry
        combinations = build_combination_registry(args.knowledge)

        print(f"Found {len(combinations)} attack combinations.")

        # List combinations if requested
        if args.list_combinations:
            print("\nDiscovered Combinations:")
            for name, combo in combinations.items():
                print(f"  {name}: {' -> '.join(combo.attack_sequence)}")

        # Validate combinations if requested
        validation_results = None
        if args.validate:
            print("\nValidating combination logic...")
            validation_results = validate_all_combinations(combinations)

            safe_count = sum(
                1 for r in validation_results.values() if r["connection_safety"] == "safe"
            )
            risky_count = sum(
                1 for r in validation_results.values() if r["connection_safety"] == "risky"
            )
            unsafe_count = sum(
                1 for r in validation_results.values() if r["connection_safety"] == "unsafe"
            )

            print(f"  Safe combinations: {safe_count}")
            print(f"  Risky combinations: {risky_count}")
            print(f"  Unsafe combinations: {unsafe_count}")

            # Show unsafe combinations
            if unsafe_count > 0:
                print("\nUnsafe Combinations:")
                for name, result in validation_results.items():
                    if result["connection_safety"] == "unsafe":
                        print(f"  {name}: {', '.join(result['errors'])}")

        # Save results if output specified
        if args.output:
            output_data = {
                "combinations": {
                    name: {
                        "attack_sequence": combo.attack_sequence,
                        "interaction_rules_count": len(combo.interaction_rules),
                        "expected_modifications_count": len(combo.expected_combined_modifications),
                        "connection_preservation_rules": combo.connection_preservation_rules,
                        "failure_conditions": combo.failure_conditions,
                    }
                    for name, combo in combinations.items()
                },
                "validation_results": validation_results,
            }

            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2)
            print(f"Results saved to: {args.output}")

        return 0

    except Exception as e:
        print(f"Combination analysis failed: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    # Set up logging
    setup_logging(args.verbose, args.log_file)

    # Handle commands
    if args.command == "parity":
        return handle_parity_command(args)
    elif args.command == "correlate":
        return handle_correlate_command(args)
    elif args.command == "timing":
        return handle_timing_command(args)
    elif args.command == "combinations":
        return handle_combinations_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
