"""
Automated validation runner for attack implementations.

Discovers and validates all attack implementations, generating
comprehensive validation reports.
"""

import logging
from pathlib import Path
from typing import Dict, List, Type
from datetime import datetime
from core.bypass.attacks.base import BaseAttack
from core.bypass.attacks.validation.attack_validator import AttackValidator, ValidationReport


logger = logging.getLogger(__name__)


class ValidationRunner:
    """
    Automated runner for attack validation.

    Discovers all attack implementations and runs comprehensive
    validation on each one.
    """

    def __init__(self):
        """Initialize the validation runner."""
        self.validator = AttackValidator()
        self.reports: Dict[str, ValidationReport] = {}

    async def run_all_validations(
        self, attack_classes: List[Type[BaseAttack]]
    ) -> Dict[str, ValidationReport]:
        """
        Run validation on all provided attack classes.

        Args:
            attack_classes: List of attack classes to validate

        Returns:
            Dictionary mapping attack names to validation reports
        """
        logger.info(f"Starting validation for {len(attack_classes)} attacks")

        for attack_class in attack_classes:
            attack_name = getattr(attack_class, "__name__", str(attack_class))
            logger.info(f"Validating {attack_name}...")

            try:
                report = await self.validator.validate_attack(attack_class)
                self.reports[attack_name] = report

                if report.failed_checks == 0:
                    logger.info(f"✅ {attack_name} validation passed")
                else:
                    logger.warning(
                        f"❌ {attack_name} validation failed: "
                        f"{report.failed_checks} checks failed"
                    )
            except Exception as e:
                logger.error(f"Failed to validate {attack_name}: {str(e)}")

        logger.info(f"Validation complete for {len(self.reports)} attacks")
        return self.reports

    def generate_summary_report(self) -> str:
        """
        Generate a summary report of all validations.

        Returns:
            Human-readable summary report
        """
        total_attacks = len(self.reports)
        passed_attacks = sum(1 for r in self.reports.values() if r.failed_checks == 0)
        failed_attacks = total_attacks - passed_attacks

        total_checks = sum(r.total_checks for r in self.reports.values())
        total_passed = sum(r.passed_checks for r in self.reports.values())
        total_failed = sum(r.failed_checks for r in self.reports.values())
        total_warnings = sum(r.warnings for r in self.reports.values())

        attacks_pass_rate = (passed_attacks / total_attacks * 100.0) if total_attacks else 0.0
        attacks_fail_rate = (failed_attacks / total_attacks * 100.0) if total_attacks else 0.0
        checks_pass_rate = (total_passed / total_checks * 100.0) if total_checks else 0.0

        summary = f"""
Attack Validation Summary Report
{'=' * 80}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Overall Statistics:
  Total Attacks Validated: {total_attacks}
  Attacks Passed: {passed_attacks} ({attacks_pass_rate:.1f}%)
  Attacks Failed: {failed_attacks} ({attacks_fail_rate:.1f}%)
  
  Total Checks: {total_checks}
  Checks Passed: {total_passed} ({checks_pass_rate:.1f}%)
  Checks Failed: {total_failed}
  Warnings: {total_warnings}

"""

        if failed_attacks > 0:
            summary += "Failed Attacks:\n"
            for name, report in self.reports.items():
                if report.failed_checks > 0:
                    summary += f"  ❌ {name}: {report.failed_checks} checks failed\n"
            summary += "\n"

        if passed_attacks > 0:
            summary += "Passed Attacks:\n"
            for name, report in self.reports.items():
                if report.failed_checks == 0:
                    summary += f"  ✅ {name}: All checks passed"
                    if report.warnings > 0:
                        summary += f" ({report.warnings} warnings)"
                    summary += "\n"

        return summary

    def save_reports(self, output_dir: Path):
        """
        Save individual validation reports to files.

        Args:
            output_dir: Directory to save reports to
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save individual reports
        for name, report in self.reports.items():
            report_file = output_dir / f"{name}_validation.txt"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report.get_summary())

        # Save summary report
        summary_file = output_dir / "validation_summary.txt"
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write(self.generate_summary_report())

        logger.info(f"Saved {len(self.reports)} validation reports to {output_dir}")
