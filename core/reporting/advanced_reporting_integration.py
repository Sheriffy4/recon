#!/usr/bin/env python3
"""
Advanced Reporting Integration for Phase 2 Advanced Attacks.
Integrates advanced attack metrics with existing reporting systems.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass, asdict

# Setup logging
LOG = logging.getLogger(__name__)


@dataclass
class AdvancedAttackReport:
    """Report for advanced attack execution."""

    attack_name: str
    target_domain: str
    dpi_type: str
    execution_time_ms: float
    success: bool
    effectiveness_score: float
    timestamp: datetime
    performance_metrics: Dict[str, Any]
    ml_insights: Dict[str, Any]
    recommendations: List[str]


@dataclass
class SystemPerformanceReport:
    """System-wide performance report."""

    report_period: str
    total_attacks: int
    successful_attacks: int
    average_effectiveness: float
    performance_trends: Dict[str, Any]
    top_performing_attacks: List[str]
    problematic_targets: List[str]
    system_health_score: float
    recommendations: List[str]


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
                LOG.warning(
                    "Enhanced reporter not available, using standalone reporting"
                )

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
                attack_summary = (
                    await self.performance_monitor.get_attack_performance_summary(
                        attack_name
                    )
                )
                performance_metrics = attack_summary

            # Generate ML insights
            ml_insights = await self._generate_ml_insights(
                attack_name, execution_result
            )

            # Generate recommendations
            recommendations = await self._generate_attack_recommendations(
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

            LOG.info(
                f"Generated advanced attack report for {attack_name} on {target_domain}"
            )
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
                performance_data = (
                    await self.performance_monitor.export_performance_data(
                        start_time, end_time
                    )
                )

            # Analyze performance trends
            performance_trends = await self._analyze_performance_trends(
                performance_data
            )

            # Identify top performing attacks
            top_performing_attacks = await self._identify_top_performing_attacks(
                performance_data
            )

            # Identify problematic targets
            problematic_targets = await self._identify_problematic_targets(
                performance_data
            )

            # Get system health score
            system_health_score = 0.0
            if self.performance_monitor:
                health_report = (
                    await self.performance_monitor.get_system_health_report()
                )
                system_health_score = health_report.get("system_health_score", 0.0)

            # Generate system recommendations
            recommendations = await self._generate_system_recommendations(
                performance_data, performance_trends, system_health_score
            )

            # Create system report
            report = SystemPerformanceReport(
                report_period=f"{period_hours} hours",
                total_attacks=len(performance_data.get("attack_metrics", [])),
                successful_attacks=sum(
                    1
                    for m in performance_data.get("attack_metrics", [])
                    if m.get("success", False)
                ),
                average_effectiveness=self._calculate_average_effectiveness(
                    performance_data
                ),
                performance_trends=performance_trends,
                top_performing_attacks=top_performing_attacks,
                problematic_targets=problematic_targets,
                system_health_score=system_health_score,
                recommendations=recommendations,
            )

            LOG.info(
                f"Generated system performance report for {period_hours} hour period"
            )
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

            # Get recent attack reports
            recent_reports = [
                r
                for r in self.report_history
                if (datetime.now() - r.timestamp) < timedelta(hours=24)
            ]

            # Get performance data
            performance_data = {}
            if self.performance_monitor:
                performance_data = (
                    await self.performance_monitor.export_performance_data()
                )

            # Create comprehensive report
            comprehensive_report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "format": format_type,
                    "includes_raw_data": include_raw_data,
                },
                "system_performance": asdict(system_report) if system_report else {},
                "recent_attack_reports": [asdict(r) for r in recent_reports],
                "performance_summary": {
                    "total_attacks_24h": len(recent_reports),
                    "success_rate_24h": (
                        (
                            sum(1 for r in recent_reports if r.success)
                            / len(recent_reports)
                            * 100
                        )
                        if recent_reports
                        else 0
                    ),
                    "average_effectiveness_24h": (
                        sum(r.effectiveness_score for r in recent_reports)
                        / len(recent_reports)
                        if recent_reports
                        else 0
                    ),
                    "unique_targets_24h": len(
                        set(r.target_domain for r in recent_reports)
                    ),
                    "unique_attacks_used": len(
                        set(r.attack_name for r in recent_reports)
                    ),
                },
            }

            # Include raw data if requested
            if include_raw_data:
                comprehensive_report["raw_performance_data"] = performance_data

            # Format-specific processing
            if format_type == "json":
                return comprehensive_report
            elif format_type == "summary":
                return await self._create_summary_report(comprehensive_report)
            else:
                return comprehensive_report

        except Exception as e:
            LOG.error(f"Failed to export comprehensive report: {e}")
            return {"error": str(e)}

    async def get_attack_effectiveness_analysis(
        self, attack_name: str
    ) -> Dict[str, Any]:
        """Get detailed effectiveness analysis for specific attack."""

        try:
            # Get attack reports
            attack_reports = [
                r for r in self.report_history if r.attack_name == attack_name
            ]

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

            # Analyze by DPI type
            dpi_analysis = {}
            for report in attack_reports:
                dpi_type = report.dpi_type
                if dpi_type not in dpi_analysis:
                    dpi_analysis[dpi_type] = {
                        "total": 0,
                        "successful": 0,
                        "effectiveness_scores": [],
                    }

                dpi_analysis[dpi_type]["total"] += 1
                if report.success:
                    dpi_analysis[dpi_type]["successful"] += 1
                dpi_analysis[dpi_type]["effectiveness_scores"].append(
                    report.effectiveness_score
                )

            # Calculate DPI-specific metrics
            for dpi_type, data in dpi_analysis.items():
                data["success_rate"] = (data["successful"] / data["total"]) * 100
                data["avg_effectiveness"] = sum(data["effectiveness_scores"]) / len(
                    data["effectiveness_scores"]
                )

            # Performance trends
            recent_reports = sorted(attack_reports, key=lambda x: x.timestamp)[-10:]
            trend_analysis = await self._analyze_attack_trend(recent_reports)

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
                "recommendations": await self._generate_attack_improvement_recommendations(
                    attack_reports
                ),
            }

            return analysis

        except Exception as e:
            LOG.error(f"Failed to analyze attack effectiveness for {attack_name}: {e}")
            return {"error": str(e)}

    async def get_target_analysis_report(self, target_domain: str) -> Dict[str, Any]:
        """Get analysis report for specific target domain."""

        try:
            # Get target reports
            target_reports = [
                r for r in self.report_history if r.target_domain == target_domain
            ]

            if not target_reports:
                return {
                    "target_domain": target_domain,
                    "message": "No reports available for this target",
                }

            # Analyze attack effectiveness by type
            attack_analysis = {}
            for report in target_reports:
                attack_name = report.attack_name
                if attack_name not in attack_analysis:
                    attack_analysis[attack_name] = {
                        "executions": 0,
                        "successes": 0,
                        "effectiveness_scores": [],
                    }

                attack_analysis[attack_name]["executions"] += 1
                if report.success:
                    attack_analysis[attack_name]["successes"] += 1
                attack_analysis[attack_name]["effectiveness_scores"].append(
                    report.effectiveness_score
                )

            # Calculate metrics for each attack
            for attack_name, data in attack_analysis.items():
                data["success_rate"] = (data["successes"] / data["executions"]) * 100
                data["avg_effectiveness"] = sum(data["effectiveness_scores"]) / len(
                    data["effectiveness_scores"]
                )

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
                "recommendations": await self._generate_target_specific_recommendations(
                    target_reports
                ),
            }

            return analysis

        except Exception as e:
            LOG.error(f"Failed to analyze target {target_domain}: {e}")
            return {"error": str(e)}

    # Private helper methods

    async def _generate_ml_insights(
        self, attack_name: str, execution_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate ML-based insights for attack execution."""

        try:
            insights = {
                "prediction_accuracy": "unknown",
                "learning_opportunities": [],
                "optimization_suggestions": [],
            }

            # Try to get ML prediction accuracy
            if "ml_prediction" in execution_result:
                predicted_success = execution_result["ml_prediction"].get(
                    "success_probability", 0.5
                )
                actual_success = execution_result.get("success", False)

                if (predicted_success > 0.5 and actual_success) or (
                    predicted_success <= 0.5 and not actual_success
                ):
                    insights["prediction_accuracy"] = "accurate"
                else:
                    insights["prediction_accuracy"] = "inaccurate"
                    insights["learning_opportunities"].append(
                        "Update ML model with this result"
                    )

            # Generate optimization suggestions
            if execution_result.get("execution_time_ms", 0) > 3000:
                insights["optimization_suggestions"].append(
                    "Consider parameter optimization for faster execution"
                )

            if execution_result.get("effectiveness_score", 0) < 0.5:
                insights["optimization_suggestions"].append(
                    "Review attack configuration for better effectiveness"
                )

            return insights

        except Exception as e:
            LOG.error(f"Failed to generate ML insights: {e}")
            return {"error": str(e)}

    async def _generate_attack_recommendations(
        self,
        attack_name: str,
        execution_result: Dict[str, Any],
        performance_metrics: Dict[str, Any],
    ) -> List[str]:
        """Generate recommendations for attack improvement."""

        recommendations = []

        try:
            # Success-based recommendations
            if not execution_result.get("success", False):
                recommendations.append(
                    "Consider alternative attack parameters or different attack type"
                )

            # Performance-based recommendations
            if execution_result.get("execution_time_ms", 0) > 5000:
                recommendations.append(
                    "Optimize attack execution time or increase timeout thresholds"
                )

            # Effectiveness-based recommendations
            effectiveness = execution_result.get("effectiveness_score", 0)
            if effectiveness < 0.3:
                recommendations.append(
                    "Review attack configuration and target compatibility"
                )
            elif effectiveness < 0.7:
                recommendations.append(
                    "Fine-tune attack parameters for better effectiveness"
                )

            # Performance metrics recommendations
            if performance_metrics and "performance_grade" in performance_metrics:
                grade = performance_metrics["performance_grade"]
                if grade in ["D", "F"]:
                    recommendations.append(
                        "Consider replacing this attack with better-performing alternatives"
                    )
                elif grade == "C":
                    recommendations.append(
                        "Monitor performance and consider optimization"
                    )

            if not recommendations:
                recommendations.append(
                    "Attack performance is within acceptable parameters"
                )

        except Exception as e:
            recommendations.append(f"Unable to generate recommendations: {e}")

        return recommendations

    async def _integrate_with_existing_reporter(
        self, report: AdvancedAttackReport
    ) -> None:
        """Integrate report with existing reporting system."""

        try:
            if self.existing_reporter and hasattr(
                self.existing_reporter, "add_attack_result"
            ):
                # Convert to format expected by existing reporter
                result_data = {
                    "attack_type": report.attack_name,
                    "target": report.target_domain,
                    "success": report.success,
                    "execution_time": report.execution_time_ms
                    / 1000,  # Convert to seconds
                    "effectiveness": report.effectiveness_score,
                    "timestamp": report.timestamp,
                    "advanced_metrics": report.performance_metrics,
                }

                await self.existing_reporter.add_attack_result(result_data)
                LOG.debug("Integrated report with existing reporter")

        except Exception as e:
            LOG.error(f"Failed to integrate with existing reporter: {e}")

    async def _analyze_performance_trends(
        self, performance_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze performance trends from data."""

        try:
            attack_metrics = performance_data.get("attack_metrics", [])

            if not attack_metrics:
                return {"message": "No performance data available"}

            # Group by time periods
            hourly_performance = {}
            for metric in attack_metrics:
                timestamp = datetime.fromisoformat(
                    metric["timestamp"].replace("Z", "+00:00")
                )
                hour_key = timestamp.strftime("%Y-%m-%d %H:00")

                if hour_key not in hourly_performance:
                    hourly_performance[hour_key] = {
                        "total": 0,
                        "successful": 0,
                        "effectiveness_scores": [],
                    }

                hourly_performance[hour_key]["total"] += 1
                if metric["success"]:
                    hourly_performance[hour_key]["successful"] += 1
                hourly_performance[hour_key]["effectiveness_scores"].append(
                    metric["effectiveness_score"]
                )

            # Calculate trends
            trends = {}
            for hour, data in hourly_performance.items():
                success_rate = (data["successful"] / data["total"]) * 100
                avg_effectiveness = sum(data["effectiveness_scores"]) / len(
                    data["effectiveness_scores"]
                )

                trends[hour] = {
                    "success_rate": success_rate,
                    "average_effectiveness": avg_effectiveness,
                    "total_attacks": data["total"],
                }

            return trends

        except Exception as e:
            LOG.error(f"Failed to analyze performance trends: {e}")
            return {"error": str(e)}

    async def _identify_top_performing_attacks(
        self, performance_data: Dict[str, Any]
    ) -> List[str]:
        """Identify top performing attacks from data."""

        try:
            attack_metrics = performance_data.get("attack_metrics", [])

            # Group by attack type
            attack_performance = {}
            for metric in attack_metrics:
                attack_name = metric["attack_name"]
                if attack_name not in attack_performance:
                    attack_performance[attack_name] = {
                        "total": 0,
                        "successful": 0,
                        "effectiveness_scores": [],
                    }

                attack_performance[attack_name]["total"] += 1
                if metric["success"]:
                    attack_performance[attack_name]["successful"] += 1
                attack_performance[attack_name]["effectiveness_scores"].append(
                    metric["effectiveness_score"]
                )

            # Calculate performance scores
            attack_scores = {}
            for attack_name, data in attack_performance.items():
                success_rate = (data["successful"] / data["total"]) * 100
                avg_effectiveness = sum(data["effectiveness_scores"]) / len(
                    data["effectiveness_scores"]
                )

                # Combined score (success rate 60%, effectiveness 40%)
                combined_score = (success_rate * 0.6) + (avg_effectiveness * 100 * 0.4)
                attack_scores[attack_name] = combined_score

            # Return top 3 attacks
            top_attacks = sorted(
                attack_scores.items(), key=lambda x: x[1], reverse=True
            )[:3]
            return [attack[0] for attack in top_attacks]

        except Exception as e:
            LOG.error(f"Failed to identify top performing attacks: {e}")
            return []

    async def _identify_problematic_targets(
        self, performance_data: Dict[str, Any]
    ) -> List[str]:
        """Identify problematic targets from data."""

        try:
            attack_metrics = performance_data.get("attack_metrics", [])

            # Group by target domain
            target_performance = {}
            for metric in attack_metrics:
                target = metric["target_domain"]
                if target not in target_performance:
                    target_performance[target] = {"total": 0, "successful": 0}

                target_performance[target]["total"] += 1
                if metric["success"]:
                    target_performance[target]["successful"] += 1

            # Identify targets with low success rates
            problematic_targets = []
            for target, data in target_performance.items():
                success_rate = (data["successful"] / data["total"]) * 100
                if (
                    success_rate < 50 and data["total"] >= 3
                ):  # At least 3 attempts with <50% success
                    problematic_targets.append(target)

            return problematic_targets[:5]  # Return top 5 problematic targets

        except Exception as e:
            LOG.error(f"Failed to identify problematic targets: {e}")
            return []

    def _calculate_average_effectiveness(
        self, performance_data: Dict[str, Any]
    ) -> float:
        """Calculate average effectiveness from performance data."""

        try:
            attack_metrics = performance_data.get("attack_metrics", [])
            if not attack_metrics:
                return 0.0

            effectiveness_scores = [m["effectiveness_score"] for m in attack_metrics]
            return sum(effectiveness_scores) / len(effectiveness_scores)

        except Exception:
            return 0.0

    async def _generate_system_recommendations(
        self,
        performance_data: Dict[str, Any],
        performance_trends: Dict[str, Any],
        system_health_score: float,
    ) -> List[str]:
        """Generate system-level recommendations."""

        recommendations = []

        try:
            # Health score recommendations
            if system_health_score < 60:
                recommendations.append(
                    "System health is critical - immediate attention required"
                )
            elif system_health_score < 80:
                recommendations.append(
                    "System health needs improvement - review performance metrics"
                )

            # Performance data recommendations
            attack_metrics = performance_data.get("attack_metrics", [])
            if attack_metrics:
                success_rate = (
                    sum(1 for m in attack_metrics if m["success"])
                    / len(attack_metrics)
                    * 100
                )
                if success_rate < 70:
                    recommendations.append(
                        "Overall success rate is low - review attack selection and configuration"
                    )

            # Trend-based recommendations
            if performance_trends and len(performance_trends) > 1:
                recent_trends = list(performance_trends.values())[-3:]
                if len(recent_trends) >= 2:
                    recent_success = [t["success_rate"] for t in recent_trends]
                    if all(
                        recent_success[i] < recent_success[i - 1]
                        for i in range(1, len(recent_success))
                    ):
                        recommendations.append(
                            "Success rate is declining - investigate recent changes"
                        )

            if not recommendations:
                recommendations.append(
                    "System performance is within acceptable parameters"
                )

        except Exception as e:
            recommendations.append(f"Unable to generate system recommendations: {e}")

        return recommendations

    async def _create_summary_report(
        self, comprehensive_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create summary version of comprehensive report."""

        try:
            summary = {
                "report_summary": {
                    "generated_at": comprehensive_report["report_metadata"][
                        "generated_at"
                    ],
                    "period": "24 hours",
                },
                "key_metrics": comprehensive_report["performance_summary"],
                "system_health": {
                    "score": comprehensive_report["system_performance"].get(
                        "system_health_score", 0
                    ),
                    "status": (
                        "good"
                        if comprehensive_report["system_performance"].get(
                            "system_health_score", 0
                        )
                        > 80
                        else "needs_attention"
                    ),
                },
                "top_recommendations": comprehensive_report["system_performance"].get(
                    "recommendations", []
                )[:3],
            }

            return summary

        except Exception as e:
            LOG.error(f"Failed to create summary report: {e}")
            return {"error": str(e)}

    async def _analyze_attack_trend(
        self, recent_reports: List[AdvancedAttackReport]
    ) -> Dict[str, Any]:
        """Analyze trend for specific attack."""

        try:
            if len(recent_reports) < 3:
                return {"trend": "insufficient_data"}

            # Calculate success rate trend
            success_rates = []
            for i in range(len(recent_reports) - 2):
                batch = recent_reports[i : i + 3]
                success_rate = sum(1 for r in batch if r.success) / len(batch)
                success_rates.append(success_rate)

            if len(success_rates) < 2:
                return {"trend": "stable"}

            # Determine trend
            recent_rate = success_rates[-1]
            older_rate = success_rates[0]

            if recent_rate > older_rate + 0.1:
                trend = "improving"
            elif recent_rate < older_rate - 0.1:
                trend = "declining"
            else:
                trend = "stable"

            return {
                "trend": trend,
                "recent_success_rate": recent_rate,
                "change_from_baseline": recent_rate - older_rate,
            }

        except Exception as e:
            LOG.error(f"Failed to analyze attack trend: {e}")
            return {"trend": "unknown", "error": str(e)}

    async def _generate_attack_improvement_recommendations(
        self, attack_reports: List[AdvancedAttackReport]
    ) -> List[str]:
        """Generate improvement recommendations for specific attack."""

        recommendations = []

        try:
            if not attack_reports:
                return ["No data available for recommendations"]

            # Success rate analysis
            success_rate = (
                sum(1 for r in attack_reports if r.success) / len(attack_reports) * 100
            )
            if success_rate < 70:
                recommendations.append(
                    "Consider reviewing attack parameters and target selection"
                )

            # Effectiveness analysis
            avg_effectiveness = sum(
                r.effectiveness_score for r in attack_reports
            ) / len(attack_reports)
            if avg_effectiveness < 0.6:
                recommendations.append(
                    "Optimize attack configuration for better effectiveness"
                )

            # Performance analysis
            avg_execution_time = sum(r.execution_time_ms for r in attack_reports) / len(
                attack_reports
            )
            if avg_execution_time > 3000:
                recommendations.append(
                    "Consider performance optimization to reduce execution time"
                )

            # DPI-specific analysis
            dpi_performance = {}
            for report in attack_reports:
                dpi_type = report.dpi_type
                if dpi_type not in dpi_performance:
                    dpi_performance[dpi_type] = []
                dpi_performance[dpi_type].append(report.success)

            for dpi_type, successes in dpi_performance.items():
                success_rate = sum(successes) / len(successes) * 100
                if success_rate < 50:
                    recommendations.append(
                        f"Poor performance against {dpi_type} - consider alternative approaches"
                    )

            if not recommendations:
                recommendations.append("Attack performance is satisfactory")

        except Exception as e:
            recommendations.append(
                f"Unable to generate improvement recommendations: {e}"
            )

        return recommendations

    async def _generate_target_specific_recommendations(
        self, target_reports: List[AdvancedAttackReport]
    ) -> List[str]:
        """Generate recommendations specific to a target."""

        recommendations = []

        try:
            if not target_reports:
                return ["No data available for recommendations"]

            # Overall success analysis
            overall_success = (
                sum(1 for r in target_reports if r.success) / len(target_reports) * 100
            )
            if overall_success < 50:
                recommendations.append(
                    "This target appears to be well-protected - consider advanced attack strategies"
                )

            # Attack type analysis
            attack_success = {}
            for report in target_reports:
                attack_name = report.attack_name
                if attack_name not in attack_success:
                    attack_success[attack_name] = []
                attack_success[attack_name].append(report.success)

            # Find best performing attack
            best_attack = None
            best_success_rate = 0
            for attack_name, successes in attack_success.items():
                success_rate = sum(successes) / len(successes) * 100
                if success_rate > best_success_rate:
                    best_success_rate = success_rate
                    best_attack = attack_name

            if best_attack and best_success_rate > 70:
                recommendations.append(
                    f"Use {best_attack} for best results against this target"
                )

            # DPI analysis
            dpi_types = list(set(r.dpi_type for r in target_reports))
            if len(dpi_types) == 1 and dpi_types[0] != "unknown":
                recommendations.append(
                    f"Target uses {dpi_types[0]} - optimize attacks for this DPI type"
                )

            if not recommendations:
                recommendations.append("Continue monitoring target performance")

        except Exception as e:
            recommendations.append(f"Unable to generate target recommendations: {e}")

        return recommendations


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
