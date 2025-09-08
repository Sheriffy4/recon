"""
Backward Compatibility Manager for Native Attack Orchestration.

This module ensures that existing attacks continue to work with the new
segment-based architecture while providing migration utilities.
"""

import logging
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum
from core.bypass.attacks.base import (
    BaseAttack,
    AttackResult,
    AttackContext,
    AttackStatus,
)


class CompatibilityMode(Enum):
    """Compatibility modes for attack execution."""

    LEGACY_ONLY = "legacy_only"
    SEGMENTS_ONLY = "segments_only"
    HYBRID = "hybrid"
    AUTO_DETECT = "auto_detect"


@dataclass
class CompatibilityReport:
    """Report on attack compatibility status."""

    attack_name: str
    has_segments_support: bool
    has_legacy_support: bool
    recommended_mode: CompatibilityMode
    migration_required: bool
    migration_complexity: str
    issues: List[str]
    recommendations: List[str]


class BackwardCompatibilityManager:
    """
    Manages backward compatibility for attacks in the segment-based system.

    Provides:
    - Compatibility checking for existing attacks
    - Fallback mechanisms for legacy attacks
    - Migration utilities and validation
    - Performance monitoring for compatibility overhead
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._compatibility_cache: Dict[str, CompatibilityReport] = {}
        self._fallback_stats: Dict[str, Dict[str, int]] = {}

    def check_attack_compatibility(self, attack: BaseAttack) -> CompatibilityReport:
        """
        Check compatibility of an attack with the segment-based system.

        Args:
            attack: Attack instance to check

        Returns:
            CompatibilityReport with detailed compatibility information
        """
        attack_name = attack.__class__.__name__
        if attack_name in self._compatibility_cache:
            return self._compatibility_cache[attack_name]
        report = self._analyze_attack_compatibility(attack)
        self._compatibility_cache[attack_name] = report
        return report

    def _analyze_attack_compatibility(self, attack: BaseAttack) -> CompatibilityReport:
        """Analyze attack for compatibility with segment system."""
        attack_name = attack.__class__.__name__
        issues = []
        recommendations = []
        has_segments_support = self._check_segments_support(attack)
        has_legacy_support = self._check_legacy_support(attack)
        migration_required = not has_segments_support
        migration_complexity = self._assess_migration_complexity(attack)
        if not has_segments_support:
            if has_legacy_support:
                recommendations.append(
                    "Consider migrating to segments for better performance"
                )
                recommendations.append(
                    "Current legacy implementation will continue to work"
                )
            else:
                issues.append("Attack has no segments or legacy support")
                recommendations.append(
                    "Urgent migration required to segments architecture"
                )
        if has_segments_support and has_legacy_support:
            recommendations.append(
                "Attack supports both modes - consider removing legacy code"
            )
        if has_segments_support and has_legacy_support:
            recommended_mode = CompatibilityMode.HYBRID
        elif has_segments_support:
            recommended_mode = CompatibilityMode.SEGMENTS_ONLY
        elif has_legacy_support:
            recommended_mode = CompatibilityMode.LEGACY_ONLY
        else:
            recommended_mode = CompatibilityMode.AUTO_DETECT
            issues.append("Attack has no clear execution mode")
        return CompatibilityReport(
            attack_name=attack_name,
            has_segments_support=has_segments_support,
            has_legacy_support=has_legacy_support,
            recommended_mode=recommended_mode,
            migration_required=migration_required,
            migration_complexity=migration_complexity,
            issues=issues,
            recommendations=recommendations,
        )

    def _check_segments_support(self, attack: BaseAttack) -> bool:
        """Check if attack supports segments architecture."""
        try:
            test_context = AttackContext(
                dst_ip="127.0.0.1",
                dst_port=80,
                payload=b"test",
                connection_id="compatibility_test",
            )
            result = attack.execute(test_context)
            if hasattr(result, "_segments") and result._segments:
                return True
            if result.metadata.get("supports_segments", False):
                return True
            return False
        except Exception as e:
            self.logger.debug(
                f"Segments support check failed for {attack.__class__.__name__}: {e}"
            )
            return False

    def _check_legacy_support(self, attack: BaseAttack) -> bool:
        """Check if attack supports legacy modified_payload approach."""
        try:
            test_context = AttackContext(
                dst_ip="127.0.0.1",
                dst_port=80,
                payload=b"test",
                connection_id="compatibility_test",
            )
            result = attack.execute(test_context)
            if hasattr(result, "modified_payload") and result.modified_payload:
                return True
            if result.metadata.get("supports_legacy", False):
                return True
            return False
        except Exception as e:
            self.logger.debug(
                f"Legacy support check failed for {attack.__class__.__name__}: {e}"
            )
            return False

    def _assess_migration_complexity(self, attack: BaseAttack) -> str:
        """Assess the complexity of migrating an attack to segments."""
        attack_name = attack.__class__.__name__.lower()
        simple_patterns = ["simple", "basic", "payload", "header"]
        if any((pattern in attack_name for pattern in simple_patterns)):
            return "simple"
        complex_patterns = ["timing", "state", "multi", "combo", "adaptive"]
        if any((pattern in attack_name for pattern in complex_patterns)):
            return "complex"
        return "moderate"

    def execute_with_fallback(
        self,
        attack: BaseAttack,
        context: AttackContext,
        preferred_mode: CompatibilityMode = CompatibilityMode.AUTO_DETECT,
    ) -> AttackResult:
        """
        Execute attack with fallback compatibility support.

        Args:
            attack: Attack to execute
            context: Attack context
            preferred_mode: Preferred execution mode

        Returns:
            AttackResult from successful execution
        """
        attack_name = attack.__class__.__name__
        if attack_name not in self._fallback_stats:
            self._fallback_stats[attack_name] = {
                "segments_attempts": 0,
                "segments_successes": 0,
                "legacy_attempts": 0,
                "legacy_successes": 0,
                "fallback_used": 0,
            }
        stats = self._fallback_stats[attack_name]
        report = self.check_attack_compatibility(attack)
        if preferred_mode == CompatibilityMode.AUTO_DETECT:
            execution_mode = report.recommended_mode
        else:
            execution_mode = preferred_mode
        if execution_mode == CompatibilityMode.SEGMENTS_ONLY:
            return self._execute_segments_mode(attack, context, stats)
        elif execution_mode == CompatibilityMode.LEGACY_ONLY:
            return self._execute_legacy_mode(attack, context, stats)
        elif execution_mode == CompatibilityMode.HYBRID:
            return self._execute_hybrid_mode(attack, context, stats, report)
        elif report.has_segments_support:
            return self._execute_segments_mode(attack, context, stats)
        elif report.has_legacy_support:
            return self._execute_legacy_mode(attack, context, stats)
        else:
            raise RuntimeError(f"Attack {attack_name} has no compatible execution mode")

    def _execute_segments_mode(
        self, attack: BaseAttack, context: AttackContext, stats: Dict[str, int]
    ) -> AttackResult:
        """Execute attack in segments-only mode."""
        stats["segments_attempts"] += 1
        try:
            result = attack.execute(context)
            if not hasattr(result, "_segments") or not result._segments:
                raise RuntimeError(
                    "Attack claimed segments support but returned no segments"
                )
            stats["segments_successes"] += 1
            return result
        except Exception as e:
            self.logger.error(f"Segments execution failed: {e}")
            raise

    def _execute_legacy_mode(
        self, attack: BaseAttack, context: AttackContext, stats: Dict[str, int]
    ) -> AttackResult:
        """Execute attack in legacy-only mode."""
        stats["legacy_attempts"] += 1
        try:
            result = attack.execute(context)
            if not hasattr(result, "_segments") or not result._segments:
                if hasattr(result, "modified_payload") and result.modified_payload:
                    result._segments = [(result.modified_payload, 0, {})]
                else:
                    result._segments = [(context.payload, 0, {})]
            stats["legacy_successes"] += 1
            return result
        except Exception as e:
            self.logger.error(f"Legacy execution failed: {e}")
            raise

    def _execute_hybrid_mode(
        self,
        attack: BaseAttack,
        context: AttackContext,
        stats: Dict[str, int],
        report: CompatibilityReport,
    ) -> AttackResult:
        """Execute attack in hybrid mode with fallback."""
        if report.has_segments_support:
            try:
                return self._execute_segments_mode(attack, context, stats)
            except Exception as e:
                self.logger.warning(
                    f"Segments execution failed, falling back to legacy: {e}"
                )
                stats["fallback_used"] += 1
        if report.has_legacy_support:
            return self._execute_legacy_mode(attack, context, stats)
        raise RuntimeError(
            f"No compatible execution mode available for {attack.__class__.__name__}"
        )

    def get_compatibility_stats(self) -> Dict[str, Any]:
        """Get compatibility and fallback statistics."""
        total_attacks = len(self._compatibility_cache)
        segments_supported = sum(
            (
                1
                for report in self._compatibility_cache.values()
                if report.has_segments_support
            )
        )
        legacy_supported = sum(
            (
                1
                for report in self._compatibility_cache.values()
                if report.has_legacy_support
            )
        )
        migration_required = sum(
            (
                1
                for report in self._compatibility_cache.values()
                if report.migration_required
            )
        )
        return {
            "total_attacks_analyzed": total_attacks,
            "segments_supported": segments_supported,
            "legacy_supported": legacy_supported,
            "migration_required": migration_required,
            "compatibility_percentage": (
                segments_supported / total_attacks * 100 if total_attacks > 0 else 0
            ),
            "fallback_stats": dict(self._fallback_stats),
        }

    def generate_migration_plan(self, attacks: List[BaseAttack]) -> Dict[str, Any]:
        """
        Generate a migration plan for a list of attacks.

        Args:
            attacks: List of attacks to analyze

        Returns:
            Migration plan with priorities and recommendations
        """
        migration_plan = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "no_migration": [],
            "summary": {},
        }
        for attack in attacks:
            report = self.check_attack_compatibility(attack)
            attack_info = {
                "name": report.attack_name,
                "complexity": report.migration_complexity,
                "issues": report.issues,
                "recommendations": report.recommendations,
            }
            if not report.has_segments_support and (not report.has_legacy_support):
                migration_plan["high_priority"].append(attack_info)
            elif report.migration_required and report.migration_complexity == "simple":
                migration_plan["medium_priority"].append(attack_info)
            elif report.migration_required:
                migration_plan["low_priority"].append(attack_info)
            else:
                migration_plan["no_migration"].append(attack_info)
        migration_plan["summary"] = {
            "total_attacks": len(attacks),
            "high_priority_count": len(migration_plan["high_priority"]),
            "medium_priority_count": len(migration_plan["medium_priority"]),
            "low_priority_count": len(migration_plan["low_priority"]),
            "no_migration_count": len(migration_plan["no_migration"]),
            "estimated_effort": self._estimate_migration_effort(migration_plan),
        }
        return migration_plan

    def _estimate_migration_effort(self, migration_plan: Dict[str, Any]) -> str:
        """Estimate overall migration effort."""
        high_count = len(migration_plan["high_priority"])
        medium_count = len(migration_plan["medium_priority"])
        low_count = len(migration_plan["low_priority"])
        total_effort = high_count * 3 + medium_count * 2 + low_count * 1
        if total_effort == 0:
            return "No migration needed"
        elif total_effort <= 5:
            return "Low effort (1-2 days)"
        elif total_effort <= 15:
            return "Medium effort (1-2 weeks)"
        else:
            return "High effort (2+ weeks)"

    def validate_migration(
        self, attack: BaseAttack, test_contexts: List[AttackContext]
    ) -> Dict[str, Any]:
        """
        Validate that a migrated attack works correctly.

        Args:
            attack: Migrated attack to validate
            test_contexts: List of test contexts to validate against

        Returns:
            Validation results
        """
        validation_results = {
            "attack_name": attack.__class__.__name__,
            "test_count": len(test_contexts),
            "passed_tests": 0,
            "failed_tests": 0,
            "errors": [],
            "warnings": [],
            "performance_metrics": {},
        }
        for i, context in enumerate(test_contexts):
            try:
                import time

                start_time = time.time()
                result = attack.execute(context)
                execution_time = time.time() - start_time
                if result.status != AttackStatus.SUCCESS:
                    validation_results["errors"].append(
                        f"Test {i}: Attack failed with status {result.status}"
                    )
                    validation_results["failed_tests"] += 1
                    continue
                if not hasattr(result, "_segments") or not result._segments:
                    validation_results["warnings"].append(
                        f"Test {i}: No segments generated"
                    )
                if execution_time > 0.1:
                    validation_results["warnings"].append(
                        f"Test {i}: Slow execution ({execution_time:.3f}s)"
                    )
                validation_results["passed_tests"] += 1
                validation_results["performance_metrics"][
                    f"test_{i}_time"
                ] = execution_time
            except Exception as e:
                validation_results["errors"].append(f"Test {i}: Exception - {str(e)}")
                validation_results["failed_tests"] += 1
        validation_results["success_rate"] = (
            validation_results["passed_tests"] / validation_results["test_count"] * 100
            if validation_results["test_count"] > 0
            else 0
        )
        return validation_results


compatibility_manager = BackwardCompatibilityManager()


def ensure_backward_compatibility(
    attack: BaseAttack, context: AttackContext
) -> AttackResult:
    """
    Convenience function to execute attack with backward compatibility.

    Args:
        attack: Attack to execute
        context: Attack context

    Returns:
        AttackResult with compatibility handling
    """
    return compatibility_manager.execute_with_fallback(attack, context)


def check_attack_compatibility(attack: BaseAttack) -> CompatibilityReport:
    """
    Convenience function to check attack compatibility.

    Args:
        attack: Attack to check

    Returns:
        CompatibilityReport
    """
    return compatibility_manager.check_attack_compatibility(attack)
