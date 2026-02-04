#!/usr/bin/env python3
"""
Advanced Reporting Integration for Phase 2 Advanced Attacks.
Integrates advanced attack metrics with existing reporting systems.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import asdict

from core.integration.reporting_models import (
    AdvancedAttackReport,
    SystemPerformanceReport,
)
from core.integration.reporting_analysis import (
    analyze_performance_trends,
    analyze_attack_trend,
    calculate_average_effectiveness,
)
from core.integration.reporting_discovery import (
    identify_top_performing_attacks,
    identify_problematic_targets,
)
from core.integration.reporting_recommendations import (
    generate_attack_recommendations,
    generate_system_recommendations,
    generate_attack_improvement_recommendations,
    generate_target_specific_recommendations,
)
from core.integration.reporting_ml_insights import generate_ml_insights
from core.integration.reporting_helpers import (
    calculate_dpi_analysis,
    calculate_attack_analysis,
    create_summary_report,
    filter_recent_reports,
    calculate_performance_summary,
)

# Setup logging
LOG = logging.getLogger(__name__)


class AdvancedReportingIntegration:
    """Integration with existing reporting systems for advanced attacks."""

    def __init__(self):
        self.report_history = []
        self.performance_monitor = None
        self.existing_reporter = None

        LOG.info("Advanced Reporting Integration initialized")

    async def initialize(self) -> bool:
        """Initialize the reporting integration."""

        try:
            # Initialize performance monitor
            from core.integration.advanced_performance_monitor import (
                get_performance_monitor,
            )

            self.performance_monitor = get_performance_monitor()

            # Try to integrate with existing reporter
            try:
                from core.reporting.enhanced_reporter import EnhancedReporter

                self.existing_reporter = EnhancedReporter()
                LOG.info("Integrated with existing enhanced reporter")
            except ImportError:
                LOG.warning("Enhanced reporter not available, using standalone reporting")

            LOG.info("Advanced reporting integration initialized successfully")
            return True

        except Exception as e:
            LOG.error(f"Failed to initialize advanced reporting integration: {e}")
            return False

    async def generate_attack_report(
        self, attack_name: str, target_domain: str, execution_result: Dict[str, Any]
    ) -> AdvancedAttackReport:
        """Generate comprehensive report for an attack execution."""

        try:
            # Get performance metrics
            performance_metrics = {}
            if self.performance_monitor:
                attack_summary = await self.performance_monitor.get_attack_performance_summary(
                    attack_name
                )
                performance_metrics = attack_summary

            # Generate ML insights
            ml_insights = generate_ml_insights(attack_name, execution_result)

            # Generate recommendations
            recommendations = generate_attack_recommendations(
                attack_name, execution_result, performance_metrics
            )

            # Create report
            report = AdvancedAttackReport(
                attack_name=attack_name,
                target_domain=target_domain,
                dpi_type=execution_result.get("dpi_type", "unknown"),
                execution_time_ms=execution_result.get("execution_time_ms", 0.0),
                success=execution_result.get("success", False),
                effectiveness_score=execution_result.get("effectiveness_score", 0.0),
                timestamp=datetime.now(),
                performance_metrics=performance_metrics,
                ml_insights=ml_insights,
                recommendations=recommendations,
            )

            # Store report
            self.report_history.append(report)

            # Integrate with existing reporting system
            if self.existing_reporter:
                await self._integrate_with_existing_reporter(report)

            LOG.info(f"Generated advanced attack report for {attack_name} on {target_domain}")
            return report

        except Exception as e:
            LOG.error(f"Failed to generate attack report: {e}")
            return None

    async def generate_system_performance_report(
        self, period_hours: int = 24
    ) -> SystemPerformanceReport:
        """Generate system-wide performance report."""

        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=period_hours)

            # Get performance data
            performance_data = {}
            if self.performance_monitor:
                performance_data = await self.performance_monitor.export_performance_data(
                    start_time, end_time
                )

            # Analyze performance trends
            performance_trends = analyze_performance_trends(performance_data)

            # Identify top performing attacks
            top_performing_attacks = identify_top_performing_attacks(performance_data)

            # Identify problematic targets
            problematic_targets = identify_problematic_targets(performance_data)

            # Get system health score
            system_health_score = 0.0
            if self.performance_monitor:
                health_report = await self.performance_monitor.get_system_health_report()
                system_health_score = health_report.get("system_health_score", 0.0)

            # Generate system recommendations
            recommendations = generate_system_recommendations(
                performance_data, performance_trends, system_health_score
            )

            # Create system report
            report = SystemPerformanceReport(
                report_period=f"{period_hours} hours",
                total_attacks=len(performance_data.get("attack_metrics", [])),
                successful_attacks=sum(
                    1 for m in performance_data.get("attack_metrics", []) if m.get("success", False)
                ),
                average_effectiveness=calculate_average_effectiveness(performance_data),
                performance_trends=performance_trends,
                top_performing_attacks=top_performing_attacks,
                problematic_targets=problematic_targets,
                system_health_score=system_health_score,
                recommendations=recommendations,
            )

            LOG.info(f"Generated system performance report for {period_hours} hour period")
            return report

        except Exception as e:
            LOG.error(f"Failed to generate system performance report: {e}")
            return None

    async def export_comprehensive_report(
        self, format_type: str = "json", include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """Export comprehensive report in specified format."""

        try:
            # Generate system report
            system_report = await self.generate_system_performance_report()

            # Get recent attack reports using helper
            recent_reports = filter_recent_reports(self.report_history, hours=24)

            # Get performance data
            performance_data = {}
            if self.performance_monitor:
                performance_data = await self.performance_monitor.export_performance_data()

            # Create comprehensive report
            comprehensive_report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "format": format_type,
                    "includes_raw_data": include_raw_data,
                },
                "system_performance": asdict(system_report) if system_report else {},
                "recent_attack_reports": [asdict(r) for r in recent_reports],
                "performance_summary": calculate_performance_summary(recent_reports),
            }

            # Include raw data if requested
            if include_raw_data:
                comprehensive_report["raw_performance_data"] = performance_data

            # Format-specific processing
            if format_type == "json":
                return comprehensive_report
            elif format_type == "summary":
                return create_summary_report(comprehensive_report)
            else:
                return comprehensive_report

        except Exception as e:
            LOG.error(f"Failed to export comprehensive report: {e}")
            return {"error": str(e)}

    async def get_attack_effectiveness_analysis(self, attack_name: str) -> Dict[str, Any]:
        """Get detailed effectiveness analysis for specific attack."""
        try:
            # Get attack reports
            attack_reports = [r for r in self.report_history if r.attack_name == attack_name]

            if not attack_reports:
                return {
                    "attack_name": attack_name,
                    "message": "No reports available for this attack",
                }

            # Calculate effectiveness metrics
            total_executions = len(attack_reports)
            successful_executions = sum(1 for r in attack_reports if r.success)
            success_rate = (successful_executions / total_executions) * 100

            effectiveness_scores = [r.effectiveness_score for r in attack_reports]
            avg_effectiveness = sum(effectiveness_scores) / len(effectiveness_scores)

            # Analyze by DPI type using helper
            dpi_analysis = calculate_dpi_analysis(attack_reports)

            # Performance trends
            recent_reports = sorted(attack_reports, key=lambda x: x.timestamp)[-10:]
            trend_analysis = analyze_attack_trend(recent_reports)

            analysis = {
                "attack_name": attack_name,
                "overall_metrics": {
                    "total_executions": total_executions,
                    "success_rate_percent": success_rate,
                    "average_effectiveness": avg_effectiveness,
                    "best_effectiveness": max(effectiveness_scores),
                    "worst_effectiveness": min(effectiveness_scores),
                },
                "dpi_type_analysis": dpi_analysis,
                "performance_trend": trend_analysis,
                "recommendations": generate_attack_improvement_recommendations(attack_reports),
            }

            return analysis

        except Exception as e:
            LOG.error(f"Failed to analyze attack effectiveness for {attack_name}: {e}")
            return {"error": str(e)}

    async def get_target_analysis_report(self, target_domain: str) -> Dict[str, Any]:
        """Get analysis report for specific target domain."""

        try:
            # Get target reports
            target_reports = [r for r in self.report_history if r.target_domain == target_domain]

            if not target_reports:
                return {
                    "target_domain": target_domain,
                    "message": "No reports available for this target",
                }

            # Analyze attack effectiveness by type using helper
            attack_analysis = calculate_attack_analysis(target_reports)

            # Identify best attack for this target
            best_attack = (
                max(attack_analysis.items(), key=lambda x: x[1]["success_rate"])[0]
                if attack_analysis
                else None
            )

            # DPI analysis
            dpi_types = list(set(r.dpi_type for r in target_reports))

            analysis = {
                "target_domain": target_domain,
                "total_attacks": len(target_reports),
                "unique_attack_types": len(attack_analysis),
                "detected_dpi_types": dpi_types,
                "attack_effectiveness": attack_analysis,
                "best_attack": best_attack,
                "overall_success_rate": (
                    sum(1 for r in target_reports if r.success) / len(target_reports)
                )
                * 100,
                "recommendations": generate_target_specific_recommendations(target_reports),
            }

            return analysis

        except Exception as e:
            LOG.error(f"Failed to analyze target {target_domain}: {e}")
            return {"error": str(e)}

    # Private helper methods

    async def _integrate_with_existing_reporter(self, report: AdvancedAttackReport) -> None:
        """Integrate report with existing reporting system."""

        try:
            if self.existing_reporter and hasattr(self.existing_reporter, "add_attack_result"):
                # Convert to format expected by existing reporter
                result_data = {
                    "attack_type": report.attack_name,
                    "target": report.target_domain,
                    "success": report.success,
                    "execution_time": report.execution_time_ms / 1000,  # Convert to seconds
                    "effectiveness": report.effectiveness_score,
                    "timestamp": report.timestamp,
                    "advanced_metrics": report.performance_metrics,
                }

                await self.existing_reporter.add_attack_result(result_data)
                LOG.debug("Integrated report with existing reporter")

        except Exception as e:
            LOG.error(f"Failed to integrate with existing reporter: {e}")


# Global reporting integration instance
_reporting_integration = None


def get_reporting_integration() -> AdvancedReportingIntegration:
    """Get the global reporting integration instance."""
    global _reporting_integration
    if _reporting_integration is None:
        _reporting_integration = AdvancedReportingIntegration()
    return _reporting_integration


async def initialize_advanced_reporting() -> bool:
    """Initialize the advanced reporting integration."""
    try:
        integration = get_reporting_integration()
        return await integration.initialize()
    except Exception as e:
        LOG.error(f"Failed to initialize advanced reporting: {e}")
        return False
