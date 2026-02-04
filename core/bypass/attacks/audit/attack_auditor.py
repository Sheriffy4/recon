"""
AttackAuditor for analyzing attack registrations and identifying missing implementations.

This module provides comprehensive analysis of the attack registry to identify:
- Attacks using primitive implementations (CORE priority)
- Attacks with advanced implementations (HIGH priority)
- Missing attack implementations
- Fallback frequency analysis from logs
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..attack_registry import get_attack_registry
from ..metadata import RegistrationPriority, AttackCategories

logger = logging.getLogger(__name__)


@dataclass
class AttackAuditReport:
    """Report of attack implementation audit."""

    # Basic statistics
    total_attacks: int = 0
    advanced_attacks: List[str] = field(default_factory=list)
    primitive_attacks: List[str] = field(default_factory=list)

    # Categorized analysis
    attacks_by_category: Dict[str, List[str]] = field(default_factory=dict)
    attacks_by_priority: Dict[str, List[str]] = field(default_factory=dict)

    # Fallback analysis
    fallback_frequency: Dict[str, int] = field(default_factory=dict)
    fallback_warnings: List[str] = field(default_factory=list)

    # Missing implementations
    missing_implementations: List[str] = field(default_factory=list)

    # Metadata
    audit_time: datetime = field(default_factory=datetime.now)
    log_files_analyzed: List[str] = field(default_factory=list)

    def _safe_pct(self, value: int, total: int) -> float:
        if total <= 0:
            return 0.0
        return (value / total) * 100.0

    def get_summary(self) -> str:
        """Get human-readable summary of the audit."""
        total = int(self.total_attacks or 0)
        return f"""
Attack Implementation Audit Report
==================================
Generated: {self.audit_time.strftime('%Y-%m-%d %H:%M:%S')}

OVERVIEW
--------
Total Attacks: {self.total_attacks}
Advanced Implementations: {len(self.advanced_attacks)} ({self._safe_pct(len(self.advanced_attacks), total):.1f}%)
Primitive Only: {len(self.primitive_attacks)} ({self._safe_pct(len(self.primitive_attacks), total):.1f}%)

PRIORITY BREAKDOWN
------------------
{self._format_priority_breakdown()}

CATEGORY BREAKDOWN
------------------
{self._format_category_breakdown()}

FALLBACK ANALYSIS
-----------------
Total Fallback Occurrences: {sum(self.fallback_frequency.values())}
Attacks with Fallbacks: {len(self.fallback_frequency)}
{self._format_fallback_analysis()}

MISSING IMPLEMENTATIONS (Priority for Development)
--------------------------------------------------
{self._format_missing_implementations()}

LOG ANALYSIS
------------
Log Files Analyzed: {len(self.log_files_analyzed)}
{chr(10).join(f'  - {log_file}' for log_file in self.log_files_analyzed)}
"""

    def _format_priority_breakdown(self) -> str:
        """Format priority breakdown section."""
        lines = []
        for priority, attacks in self.attacks_by_priority.items():
            lines.append(f"{priority}: {len(attacks)} attacks")
            if len(attacks) <= 10:  # Show all if few
                for attack in sorted(attacks):
                    lines.append(f"  - {attack}")
            else:  # Show top 10 if many
                for attack in sorted(attacks)[:10]:
                    lines.append(f"  - {attack}")
                lines.append(f"  ... and {len(attacks) - 10} more")
        return chr(10).join(lines)

    def _format_category_breakdown(self) -> str:
        """Format category breakdown section."""
        lines = []
        for category, attacks in self.attacks_by_category.items():
            lines.append(f"{category}: {len(attacks)} attacks")
            for attack in sorted(attacks)[:5]:  # Show top 5 per category
                lines.append(f"  - {attack}")
            if len(attacks) > 5:
                lines.append(f"  ... and {len(attacks) - 5} more")
        return chr(10).join(lines)

    def _format_fallback_analysis(self) -> str:
        """Format fallback analysis section."""
        if not self.fallback_frequency:
            return "No fallback occurrences found in logs."

        lines = []
        # Sort by frequency (descending)
        sorted_fallbacks = sorted(self.fallback_frequency.items(), key=lambda x: x[1], reverse=True)

        lines.append("Most Frequent Fallbacks:")
        for attack, count in sorted_fallbacks[:10]:  # Top 10
            lines.append(f"  - {attack}: {count} occurrences")

        if len(sorted_fallbacks) > 10:
            lines.append(f"  ... and {len(sorted_fallbacks) - 10} more")

        return chr(10).join(lines)

    def _format_missing_implementations(self) -> str:
        """Format missing implementations section."""
        if not self.missing_implementations:
            return "All attacks have advanced implementations! 🎉"

        lines = []
        lines.append(f"Total Missing: {len(self.missing_implementations)}")
        lines.append("")
        lines.append("Attacks needing advanced implementation:")

        for attack in sorted(self.missing_implementations):
            fallback_count = self.fallback_frequency.get(attack, 0)
            if fallback_count > 0:
                lines.append(f"  - {attack} (fallback count: {fallback_count})")
            else:
                lines.append(f"  - {attack}")

        return chr(10).join(lines)


class AttackAuditor:
    """Tool for auditing attack implementations and identifying gaps."""

    def __init__(self):
        """Initialize the auditor."""
        self.registry = get_attack_registry()

    def audit_registrations(self) -> AttackAuditReport:
        """
        Audit all registered attacks to identify implementation status.

        Analyzes the attack registry to categorize attacks by:
        - Priority level (HIGH=advanced, CORE=primitive)
        - Category (IP, TCP, HTTP, TLS, DNS, UDP)
        - Implementation status

        Returns:
            AttackAuditReport with comprehensive analysis
        """
        logger.info("🔍 Starting attack registration audit")

        report = AttackAuditReport()
        all_attacks = self.registry.list_attacks()
        report.total_attacks = len(all_attacks)

        # Initialize category tracking
        report.attacks_by_category = {
            category: []
            for category in AttackCategories.__dict__.values()
            if isinstance(category, str) and not category.startswith("_")
        }
        report.attacks_by_priority = {}

        logger.info(f"📊 Analyzing {report.total_attacks} registered attacks")

        for attack_name in all_attacks:
            entry = self.registry.attacks.get(attack_name)
            if not entry:
                logger.warning(f"⚠️ Attack '{attack_name}' found in list but not in registry")
                continue

            # Categorize by priority
            priority_name = entry.priority.name
            if priority_name not in report.attacks_by_priority:
                report.attacks_by_priority[priority_name] = []
            report.attacks_by_priority[priority_name].append(attack_name)

            # Categorize by implementation level
            if entry.priority == RegistrationPriority.HIGH:
                report.advanced_attacks.append(attack_name)
                logger.debug(f"✅ Advanced: {attack_name} (priority: {priority_name})")
            else:
                report.primitive_attacks.append(attack_name)
                report.missing_implementations.append(attack_name)
                logger.debug(f"⚠️ Primitive: {attack_name} (priority: {priority_name})")

            # Categorize by attack category
            category = entry.metadata.category
            if category in report.attacks_by_category:
                report.attacks_by_category[category].append(attack_name)
            else:
                # Handle unknown categories
                if "UNKNOWN" not in report.attacks_by_category:
                    report.attacks_by_category["UNKNOWN"] = []
                report.attacks_by_category["UNKNOWN"].append(attack_name)
                logger.warning(f"⚠️ Unknown category '{category}' for attack '{attack_name}'")

        # Remove empty categories
        report.attacks_by_category = {k: v for k, v in report.attacks_by_category.items() if v}

        logger.info("✅ Registration audit complete:")
        logger.info(f"   - Advanced implementations: {len(report.advanced_attacks)}")
        logger.info(f"   - Primitive implementations: {len(report.primitive_attacks)}")
        logger.info(f"   - Categories found: {len(report.attacks_by_category)}")
        logger.info(f"   - Priority levels: {len(report.attacks_by_priority)}")

        return report

    def analyze_log_fallbacks(self, log_paths: Optional[List[str]] = None) -> Dict[str, int]:
        """
        Parse application logs for "falling back to primitives" warnings.

        Searches for log messages indicating attacks fell back to primitive
        implementations and counts frequency per attack.

        Args:
            log_paths: List of log file paths to analyze. If None, searches common locations.

        Returns:
            Dictionary mapping attack names to fallback frequency counts
        """
        logger.info("📋 Starting log fallback analysis")

        if log_paths is None:
            log_paths = self._find_log_files()

        fallback_frequency = {}
        fallback_patterns = [
            # Pattern for "No advanced attack available for 'X', falling back to primitives"
            r"No advanced attack available for ['\"]([^'\"]+)['\"], falling back to primitives",
            # Pattern for "falling back to primitives" with attack name
            r"falling back to primitives.*['\"]([^'\"]+)['\"]",
            # Pattern for "Attack 'X' dispatch failed" (indicates fallback attempt)
            r"Attack ['\"]([^'\"]+)['\"] dispatch failed",
            # Pattern for primitive attack execution
            r"Executing primitive attack handler for ['\"]([^'\"]+)['\"]",
        ]

        total_lines_processed = 0
        total_fallbacks_found = 0

        for log_path in log_paths:
            if not Path(log_path).exists():
                logger.warning(f"⚠️ Log file not found: {log_path}")
                continue

            logger.info(f"📄 Analyzing log file: {log_path}")
            lines_in_file = 0
            fallbacks_in_file = 0

            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        lines_in_file += 1
                        total_lines_processed += 1

                        # Check each pattern
                        for pattern in fallback_patterns:
                            matches = re.findall(pattern, line, re.IGNORECASE)
                            for attack_name in matches:
                                # Normalize attack name
                                attack_name = attack_name.lower().strip()

                                if attack_name not in fallback_frequency:
                                    fallback_frequency[attack_name] = 0
                                fallback_frequency[attack_name] += 1
                                fallbacks_in_file += 1
                                total_fallbacks_found += 1

                                logger.debug(f"🔍 Found fallback: {attack_name} in {log_path}")

            except Exception as e:
                logger.error(f"❌ Error reading log file {log_path}: {e}")
                continue

            logger.info(f"📊 {log_path}: {lines_in_file} lines, {fallbacks_in_file} fallbacks")

        logger.info("✅ Log analysis complete:")
        logger.info(f"   - Files processed: {len([p for p in log_paths if Path(p).exists()])}")
        logger.info(f"   - Lines processed: {total_lines_processed}")
        logger.info(f"   - Fallbacks found: {total_fallbacks_found}")
        logger.info(f"   - Unique attacks with fallbacks: {len(fallback_frequency)}")

        return fallback_frequency

    def _find_log_files(self) -> List[str]:
        """
        Find common log file locations.

        Returns:
            List of potential log file paths
        """
        potential_paths = [
            # Current directory logs
            "recon.log",
            "bypass.log",
            "attack.log",
            "debug.log",
            # Logs directory
            "logs/recon.log",
            "logs/bypass.log",
            "logs/attack.log",
            "logs/debug.log",
            # System logs (if accessible)
            "/var/log/recon.log",
            "/tmp/recon.log",
            # Windows logs
            "C:\\temp\\recon.log",
            "C:\\logs\\recon.log",
        ]

        # Also search for any .log files in current directory
        try:
            current_dir = Path(".")
            for log_file in current_dir.glob("*.log"):
                potential_paths.append(str(log_file))
        except Exception as e:
            logger.debug(f"Error searching for log files: {e}")

        # Filter to existing files
        existing_paths = [path for path in potential_paths if Path(path).exists()]

        logger.info(f"🔍 Found {len(existing_paths)} log files to analyze")
        for path in existing_paths:
            logger.debug(f"   - {path}")

        return existing_paths

    def generate_comprehensive_report(
        self, include_log_analysis: bool = True, log_paths: Optional[List[str]] = None
    ) -> AttackAuditReport:
        """
        Generate a comprehensive audit report combining registration and log analysis.

        Args:
            include_log_analysis: Whether to include log fallback analysis
            log_paths: Custom log file paths (if None, auto-discovers)

        Returns:
            Complete AttackAuditReport with all findings
        """
        logger.info("🚀 Generating comprehensive attack audit report")

        # Start with registration audit
        report = self.audit_registrations()

        # Add log analysis if requested
        if include_log_analysis:
            logger.info("📋 Adding log fallback analysis to report")
            try:
                fallback_frequency = self.analyze_log_fallbacks(log_paths)
                report.fallback_frequency = fallback_frequency

                # Update log files analyzed
                if log_paths:
                    report.log_files_analyzed = [p for p in log_paths if Path(p).exists()]
                else:
                    report.log_files_analyzed = self._find_log_files()

                # Generate fallback warnings for high-frequency attacks
                high_frequency_threshold = 10
                for attack, count in fallback_frequency.items():
                    if count >= high_frequency_threshold:
                        warning = f"Attack '{attack}' has {count} fallback occurrences - high priority for implementation"
                        report.fallback_warnings.append(warning)
                        logger.warning(f"⚠️ {warning}")

            except Exception as e:
                logger.error(f"❌ Log analysis failed: {e}")
                report.fallback_warnings.append(f"Log analysis failed: {e}")

        logger.info("✅ Comprehensive audit report generated")
        logger.info(f"   - Total attacks analyzed: {report.total_attacks}")
        logger.info(f"   - Missing implementations: {len(report.missing_implementations)}")
        logger.info(f"   - Fallback occurrences: {sum(report.fallback_frequency.values())}")
        logger.info(f"   - High-priority warnings: {len(report.fallback_warnings)}")

        return report

    def rank_attacks_by_priority(self, report: AttackAuditReport) -> List[Tuple[str, int]]:
        """
        Rank attacks by implementation priority based on fallback frequency.

        Args:
            report: AttackAuditReport with fallback data

        Returns:
            List of (attack_name, priority_score) tuples, sorted by priority (descending)
        """
        priority_scores = []

        for attack in report.missing_implementations:
            # Base score for missing implementation
            score = 100

            # Add fallback frequency bonus
            fallback_count = report.fallback_frequency.get(attack, 0)
            score += fallback_count * 10  # 10 points per fallback occurrence

            # Category bonus (some categories are more critical)
            category_bonuses = {
                AttackCategories.FAKE: 50,  # Fake attacks are critical
                AttackCategories.DISORDER: 40,  # Disorder attacks are important
                AttackCategories.SPLIT: 30,  # Split attacks are common
                AttackCategories.OVERLAP: 20,  # Overlap attacks are specialized
                AttackCategories.TIMING: 10,  # Timing attacks are advanced
            }

            # Find attack category
            for category, attacks in report.attacks_by_category.items():
                if attack in attacks:
                    bonus = category_bonuses.get(category, 0)
                    score += bonus
                    break

            priority_scores.append((attack, score))

        # Sort by score (descending)
        priority_scores.sort(key=lambda x: x[1], reverse=True)

        logger.info(f"📊 Ranked {len(priority_scores)} attacks by implementation priority")
        for i, (attack, score) in enumerate(priority_scores[:5]):
            logger.info(f"   {i+1}. {attack} (score: {score})")

        return priority_scores
