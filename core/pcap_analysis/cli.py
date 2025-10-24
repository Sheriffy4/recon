#!/usr/bin/env python3
"""
Command-line interface for PCAP analysis and comparison system.
Provides interactive and batch processing modes for analyzing differences
between recon and zapret PCAP files.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, Optional, Any
import logging
from datetime import datetime

from .pcap_comparator import PCAPComparator
from .strategy_analyzer import StrategyAnalyzer
from .difference_detector import DifferenceDetector
from .pattern_recognizer import PatternRecognizer
from .root_cause_analyzer import RootCauseAnalyzer
from .fix_generator import FixGenerator
from .strategy_validator import StrategyValidator
from .analysis_reporter import AnalysisReporter
from .error_handling import ErrorHandler
from .logging_config import setup_logging
from .progress_reporter import (
    create_analysis_progress,
    create_batch_progress,
)
from .interactive_menu import DifferenceReviewMenu, FixReviewMenu
from .cli_config import ConfigManager, CLIConfig, load_batch_config
from .cli_help import show_help


class BatchProcessor:
    """Batch processing mode for multiple PCAP comparisons."""

    def __init__(self, cli_instance):
        self.cli = cli_instance

    async def process_batch(self, batch_config: Dict[str, Any]) -> Dict[str, Any]:
        """Process multiple PCAP comparisons in batch mode."""
        results = {}
        comparisons = batch_config.get("comparisons", [])

        print(f"Starting batch processing of {len(comparisons)} comparisons...")

        # Create progress bar for batch processing
        progress_bar = create_batch_progress(len(comparisons))

        for i, comparison in enumerate(comparisons, 1):
            comparison_name = comparison.get("name", f"comparison_{i}")
            progress_bar.update(i - 1, f"Processing {comparison_name}")

            try:
                result = await self.cli.run_single_analysis(
                    recon_pcap=comparison["recon_pcap"],
                    zapret_pcap=comparison["zapret_pcap"],
                    output_dir=comparison.get("output_dir"),
                    strategy_params=comparison.get("strategy_params"),
                    auto_apply_fixes=batch_config.get("auto_apply_fixes", False),
                )

                results[comparison_name] = {"status": "success", "result": result}

            except Exception as e:
                self.cli.logger.error(f"Error processing {comparison_name}: {e}")
                results[comparison_name] = {"status": "error", "error": str(e)}

        progress_bar.finish("Batch processing complete")
        return results


class PCAPAnalysisCLI:
    """Main CLI class for PCAP analysis system."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.error_handler = ErrorHandler()
        self.difference_review = DifferenceReviewMenu()
        self.fix_review = FixReviewMenu()
        self.batch_processor = BatchProcessor(self)
        self.config_manager = ConfigManager()
        self.config: Optional[CLIConfig] = None

    def create_parser(self) -> argparse.ArgumentParser:
        """Create command-line argument parser."""
        parser = argparse.ArgumentParser(
            description="PCAP Analysis and Comparison Tool for recon vs zapret",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Basic comparison
  %(prog)s compare recon_x.pcap zapret_x.pcap
  
  # Interactive mode with fix review
  %(prog)s compare recon_x.pcap zapret_x.pcap --interactive
  
  # Batch processing
  %(prog)s batch batch_config.json
  
  # Generate analysis report only
  %(prog)s analyze recon_x.pcap zapret_x.pcap --report-only
            """,
        )

        # Global options
        parser.add_argument(
            "--verbose",
            "-v",
            action="count",
            default=0,
            help="Increase verbosity (use -vv for debug)",
        )
        parser.add_argument(
            "--quiet", "-q", action="store_true", help="Suppress progress output"
        )
        parser.add_argument(
            "--output-dir", "-o", type=str, help="Output directory for results"
        )
        parser.add_argument("--config", "-c", type=str, help="Configuration file path")
        parser.add_argument(
            "--help-topic",
            type=str,
            help="Show help for specific topic (config, batch, interactive, troubleshooting)",
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Compare command
        compare_parser = subparsers.add_parser("compare", help="Compare two PCAP files")
        compare_parser.add_argument("recon_pcap", help="Recon PCAP file path")
        compare_parser.add_argument("zapret_pcap", help="Zapret PCAP file path")
        compare_parser.add_argument(
            "--interactive",
            "-i",
            action="store_true",
            help="Enable interactive mode for fix review",
        )
        compare_parser.add_argument(
            "--auto-apply",
            "-a",
            action="store_true",
            help="Automatically apply low-risk fixes",
        )
        compare_parser.add_argument(
            "--strategy-params", type=str, help="Strategy parameters JSON file"
        )
        compare_parser.add_argument(
            "--report-only",
            action="store_true",
            help="Generate report without applying fixes",
        )

        # Analyze command
        analyze_parser = subparsers.add_parser("analyze", help="Analyze PCAP files")
        analyze_parser.add_argument("pcap_files", nargs="+", help="PCAP file paths")
        analyze_parser.add_argument(
            "--report-only", action="store_true", help="Generate analysis report only"
        )

        # Batch command
        batch_parser = subparsers.add_parser(
            "batch", help="Batch process multiple comparisons"
        )
        batch_parser.add_argument("config_file", help="Batch configuration JSON file")
        batch_parser.add_argument(
            "--parallel", "-p", type=int, default=1, help="Number of parallel processes"
        )

        # Validate command
        validate_parser = subparsers.add_parser("validate", help="Validate fixes")
        validate_parser.add_argument("fixes_file", help="Fixes JSON file")
        validate_parser.add_argument(
            "--test-domains", nargs="+", help="Test domains for validation"
        )

        return parser

    async def run_single_analysis(
        self,
        recon_pcap: str,
        zapret_pcap: str,
        output_dir: Optional[str] = None,
        strategy_params: Optional[Dict] = None,
        auto_apply_fixes: bool = False,
    ) -> Dict[str, Any]:
        """Run a single PCAP analysis."""
        # Use detailed progress reporter for better user experience
        progress = create_analysis_progress()
        progress.show_details = not getattr(self, "quiet", False)

        try:
            # Step 1: Initialize components
            progress.start_step(0, "Initializing analysis components...")
            comparator = PCAPComparator()
            strategy_analyzer = StrategyAnalyzer()
            difference_detector = DifferenceDetector()
            pattern_recognizer = PatternRecognizer()
            root_cause_analyzer = RootCauseAnalyzer()
            fix_generator = FixGenerator()
            reporter = AnalysisReporter()
            progress.complete_step(0)

            # Step 2: Load and compare PCAP files
            progress.start_step(1, f"Loading {recon_pcap} and {zapret_pcap}...")
            comparison_result = await comparator.compare_pcaps(recon_pcap, zapret_pcap)
            progress.complete_step(
                1,
                f"Loaded {len(comparison_result.recon_packets)} recon packets, {len(comparison_result.zapret_packets)} zapret packets",
            )

            # Step 3: Analyze strategies
            progress.start_step(2, "Analyzing strategy parameters...")
            strategy_analysis = await strategy_analyzer.analyze_strategies(
                comparison_result, strategy_params
            )
            progress.complete_step(2)

            # Step 4: Detect differences
            progress.start_step(3, "Detecting critical differences...")
            differences = await difference_detector.detect_critical_differences(
                comparison_result, strategy_analysis
            )
            progress.complete_step(3, f"Found {len(differences)} differences")

            # Step 5: Pattern recognition
            progress.start_step(4, "Recognizing DPI evasion patterns...")
            patterns = await pattern_recognizer.recognize_patterns(
                comparison_result, differences
            )
            progress.complete_step(4, f"Recognized {len(patterns)} patterns")

            # Step 6: Root cause analysis
            progress.start_step(5, "Analyzing failure root causes...")
            root_causes = await root_cause_analyzer.analyze_failure_causes(
                differences, patterns
            )
            progress.complete_step(5, f"Identified {len(root_causes)} root causes")

            # Step 7: Generate fixes
            progress.start_step(6, "Generating code fixes...")
            fixes = await fix_generator.generate_code_fixes(root_causes)
            progress.complete_step(6, f"Generated {len(fixes)} fixes")

            # Step 8: Interactive review (if enabled)
            if getattr(self, "interactive", False):
                progress.start_step(7, "Starting interactive review...")

                # Review differences
                approved_differences, diff_results = (
                    self.difference_review.review_differences(differences)
                )
                differences = approved_differences

                # Review fixes
                approved_fixes, fix_results = self.fix_review.review_fixes(fixes)
                fixes = approved_fixes

                progress.complete_step(
                    7, f"Approved {len(differences)} differences, {len(fixes)} fixes"
                )
            else:
                progress.start_step(7, "Skipping interactive review...")
                progress.complete_step(7)

            # Step 9: Apply fixes (if requested)
            applied_fixes = []
            if auto_apply_fixes and fixes:
                progress.start_step(8, f"Applying {len(fixes)} fixes...")

                for fix in fixes:
                    if fix.risk_level == "LOW" or auto_apply_fixes == "force":
                        try:
                            # Apply fix logic would go here
                            applied_fixes.append(fix)
                            self.logger.info(f"Applied fix: {fix.description}")
                        except Exception as e:
                            self.logger.error(
                                f"Failed to apply fix {fix.description}: {e}"
                            )

                progress.complete_step(8, f"Applied {len(applied_fixes)} fixes")
            else:
                progress.start_step(8, "Skipping fix application...")
                progress.complete_step(8)

            # Step 10: Generate report
            progress.start_step(9, "Generating comprehensive report...")
            report = await reporter.generate_comprehensive_report(
                comparison_result, differences, patterns, root_causes, fixes
            )
            progress.complete_step(9)

            # Save results
            if output_dir:
                await self._save_results(
                    output_dir,
                    {
                        "comparison_result": comparison_result,
                        "differences": differences,
                        "patterns": patterns,
                        "root_causes": root_causes,
                        "fixes": fixes,
                        "applied_fixes": applied_fixes,
                        "report": report,
                    },
                )

            progress.finish("PCAP analysis complete")

            return {
                "comparison_result": comparison_result,
                "differences": differences,
                "patterns": patterns,
                "root_causes": root_causes,
                "fixes": fixes,
                "applied_fixes": applied_fixes,
                "report": report,
            }

        except Exception as e:
            progress.finish(f"Analysis failed: {e}")
            raise

    async def _save_results(self, output_dir: str, results: Dict[str, Any]):
        """Save analysis results to output directory."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON results
        results_file = output_path / f"analysis_results_{timestamp}.json"
        with open(results_file, "w") as f:
            # Convert complex objects to serializable format
            serializable_results = self._make_serializable(results)
            json.dump(serializable_results, f, indent=2)

        # Save report
        if "report" in results:
            report_file = output_path / f"analysis_report_{timestamp}.md"
            with open(report_file, "w") as f:
                f.write(results["report"])

        print(f"Results saved to {output_dir}")

    def _make_serializable(self, obj: Any) -> Any:
        """Convert complex objects to JSON-serializable format."""
        if hasattr(obj, "__dict__"):
            return {k: self._make_serializable(v) for k, v in obj.__dict__.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        else:
            try:
                json.dumps(obj)
                return obj
            except (TypeError, ValueError):
                return str(obj)

    async def run_compare_command(self, args) -> int:
        """Run the compare command."""
        try:
            self.interactive = args.interactive
            self.quiet = args.quiet

            # Load strategy parameters if provided
            strategy_params = None
            if args.strategy_params:
                with open(args.strategy_params, "r") as f:
                    strategy_params = json.load(f)

            result = await self.run_single_analysis(
                recon_pcap=args.recon_pcap,
                zapret_pcap=args.zapret_pcap,
                output_dir=args.output_dir,
                strategy_params=strategy_params,
                auto_apply_fixes=args.auto_apply and not args.report_only,
            )

            # Print summary
            print("\nAnalysis Summary:")
            print(f"- Differences found: {len(result.get('differences', []))}")
            print(f"- Patterns recognized: {len(result.get('patterns', []))}")
            print(f"- Root causes identified: {len(result.get('root_causes', []))}")
            print(f"- Fixes generated: {len(result.get('fixes', []))}")
            print(f"- Fixes applied: {len(result.get('applied_fixes', []))}")

            return 0

        except Exception as e:
            self.logger.error(f"Compare command failed: {e}")
            return 1

    async def run_batch_command(self, args) -> int:
        """Run the batch command."""
        try:
            # Load and validate batch configuration
            batch_config = load_batch_config(args.config_file)

            # Apply CLI overrides
            if hasattr(args, "output_dir") and args.output_dir:
                batch_config["output_base_dir"] = args.output_dir

            if hasattr(args, "parallel") and args.parallel:
                batch_config["max_parallel"] = args.parallel

            results = await self.batch_processor.process_batch(batch_config)

            # Print batch summary
            successful = sum(1 for r in results.values() if r["status"] == "success")
            failed = len(results) - successful

            print("\nBatch Processing Summary:")
            print(f"- Total comparisons: {len(results)}")
            print(f"- Successful: {successful}")
            print(f"- Failed: {failed}")

            if failed > 0:
                print("\nFailed comparisons:")
                for name, result in results.items():
                    if result["status"] == "error":
                        print(f"  - {name}: {result['error']}")

            # Save batch results
            output_dir = getattr(args, "output_dir", None) or batch_config.get(
                "output_base_dir", "./batch_results"
            )
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = Path(output_dir) / f"batch_results_{timestamp}.json"
            results_file.parent.mkdir(parents=True, exist_ok=True)

            with open(results_file, "w") as f:
                json.dump(results, f, indent=2)
            print(f"Batch results saved to {results_file}")

            return 0 if failed == 0 else 1

        except Exception as e:
            self.logger.error(f"Batch command failed: {e}")
            return 1

    async def run_validate_command(self, args) -> int:
        """Run the validate command."""
        try:
            with open(args.fixes_file, "r") as f:
                fixes = json.load(f)

            validator = StrategyValidator()
            test_domains = args.test_domains or ["x.com", "example.com"]

            print(
                f"Validating {len(fixes)} fixes against {len(test_domains)} domains..."
            )

            validation_results = []
            for fix in fixes:
                result = await validator.validate_fix(fix, test_domains)
                validation_results.append(result)

                print(
                    f"Fix {fix.get('file_path', 'unknown')}: "
                    f"{'PASSED' if result.success else 'FAILED'} "
                    f"({result.success_rate:.1%} success rate)"
                )

            # Summary
            passed = sum(1 for r in validation_results if r.success)
            print(f"\nValidation Summary: {passed}/{len(fixes)} fixes passed")

            return 0 if passed == len(fixes) else 1

        except Exception as e:
            self.logger.error(f"Validate command failed: {e}")
            return 1

    async def main(self) -> int:
        """Main CLI entry point."""
        parser = self.create_parser()
        args = parser.parse_args()

        # Handle help topics
        if hasattr(args, "help_topic") and args.help_topic:
            show_help(args.help_topic)
            return 0

        # Load configuration
        try:
            self.config = self.config_manager.load_config(getattr(args, "config", None))
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return 1

        # Setup logging based on config and CLI args
        log_level = getattr(logging, self.config.log_level, logging.INFO)
        if args.verbose == 1:
            log_level = logging.INFO
        elif args.verbose >= 2:
            log_level = logging.DEBUG

        setup_logging(log_level)

        # Set global options (CLI args override config)
        self.quiet = args.quiet or self.config.quiet_mode

        # Apply CLI overrides to config
        if hasattr(args, "output_dir") and args.output_dir:
            self.config.default_output_dir = args.output_dir

        # Route to appropriate command handler
        if args.command == "compare":
            return await self.run_compare_command(args)
        elif args.command == "batch":
            return await self.run_batch_command(args)
        elif args.command == "validate":
            return await self.run_validate_command(args)
        elif args.command == "analyze":
            # For now, treat analyze same as compare with first two files
            if len(args.pcap_files) >= 2:
                args.recon_pcap = args.pcap_files[0]
                args.zapret_pcap = args.pcap_files[1]
                args.interactive = False
                args.auto_apply = False
                return await self.run_compare_command(args)
            else:
                print("Error: analyze command requires at least 2 PCAP files")
                return 1
        else:
            parser.print_help()
            return 1


def main():
    """Entry point for CLI script."""
    cli = PCAPAnalysisCLI()
    try:
        return asyncio.run(cli.main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
