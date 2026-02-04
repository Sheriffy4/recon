#!/usr/bin/env python3
"""
Script to run comprehensive attack audit and generate report.

This script executes the AttackAuditor to analyze all registered attacks,
identify missing implementations, and generate a detailed report.

Usage:
    python -m core.bypass.attacks.audit.run_audit [--output FILENAME] [--no-logs]
"""

import argparse
import logging
import sys
from pathlib import Path

from .attack_auditor import AttackAuditor


def setup_logging(verbose: bool = False):
    """Configure logging for the audit script."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    """Main entry point for the audit script."""
    parser = argparse.ArgumentParser(description="Run comprehensive attack implementation audit")
    parser.add_argument(
        "--output",
        "-o",
        default="ATTACK_AUDIT_REPORT.md",
        help="Output filename for the audit report (default: ATTACK_AUDIT_REPORT.md)",
    )
    parser.add_argument(
        "--no-logs", action="store_true", help="Skip log file analysis (only analyze registry)"
    )
    parser.add_argument(
        "--log-paths", nargs="+", help="Specific log files to analyze (default: auto-discover)"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info("=" * 70)
    logger.info("ATTACK IMPLEMENTATION AUDIT")
    logger.info("=" * 70)

    try:
        # Create auditor
        logger.info("Initializing AttackAuditor...")
        auditor = AttackAuditor()

        # Generate comprehensive report
        logger.info("Generating comprehensive audit report...")
        report = auditor.generate_comprehensive_report(
            include_log_analysis=not args.no_logs, log_paths=args.log_paths
        )

        # Get report summary
        summary = report.get_summary()

        # Print to console
        print("\n" + summary)

        # Save to file
        output_path = Path(args.output)
        logger.info(f"Saving report to {output_path}...")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(summary)

            # Add additional sections
            f.write("\n\n## Detailed Attack List\n\n")

            # Advanced attacks
            f.write("### Advanced Implementations\n\n")
            for attack in sorted(report.advanced_attacks):
                f.write(f"- ✅ {attack}\n")

            # Primitive attacks
            f.write("\n### Primitive Implementations (Need Advanced Version)\n\n")
            for attack in sorted(report.primitive_attacks):
                fallback_count = report.fallback_frequency.get(attack, 0)
                if fallback_count > 0:
                    f.write(f"- ⚠️ {attack} (fallback count: {fallback_count})\n")
                else:
                    f.write(f"- ⚠️ {attack}\n")

            # Priority ranking
            if report.missing_implementations:
                f.write("\n\n## Implementation Priority Ranking\n\n")
                f.write(
                    "Attacks ranked by implementation priority (based on fallback frequency and category):\n\n"
                )

                priority_ranking = auditor.rank_attacks_by_priority(report)
                for i, (attack, score) in enumerate(priority_ranking[:20], 1):
                    fallback_count = report.fallback_frequency.get(attack, 0)
                    f.write(
                        f"{i}. **{attack}** (priority score: {score}, fallbacks: {fallback_count})\n"
                    )

                if len(priority_ranking) > 20:
                    f.write(f"\n... and {len(priority_ranking) - 20} more attacks\n")

        logger.info(f"✅ Report saved to {output_path}")
        logger.info("=" * 70)
        logger.info("AUDIT COMPLETE")
        logger.info("=" * 70)

        # Exit with appropriate code
        if report.missing_implementations:
            logger.warning(
                f"Found {len(report.missing_implementations)} attacks needing advanced implementations"
            )
            return 1
        else:
            logger.info("All attacks have advanced implementations!")
            return 0

    except Exception as e:
        logger.error(f"❌ Audit failed: {e}", exc_info=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
