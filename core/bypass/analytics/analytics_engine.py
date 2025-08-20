"""
Main analytics engine that coordinates all analytics components
"""

import asyncio
from typing import Dict, List, Optional, Any

from .metrics_collector import MetricsCollector
from .performance_tracker import PerformanceTracker
from .ml_predictor import MLPredictor
from .reporting_dashboard import ReportingDashboard
from .analytics_models import MetricType, AnalyticsReport


class AnalyticsEngine:
    """Main analytics engine for bypass engine modernization"""

    def __init__(self, db_path: str = "analytics.db", model_dir: str = "ml_models"):
        self.metrics_collector = MetricsCollector(db_path)
        self.performance_tracker = PerformanceTracker(self.metrics_collector)
        self.ml_predictor = MLPredictor(self.metrics_collector, model_dir)
        self.reporting_dashboard = ReportingDashboard(
            self.metrics_collector, self.performance_tracker, self.ml_predictor
        )

        self._running = False
        self._tasks = []

    async def initialize(self):
        """Initialize the analytics engine"""
        print("Initializing Analytics Engine...")

        # Load existing ML models
        await self.ml_predictor.load_models()

        # Start performance tracking
        await self.performance_tracker.start_tracking()

        # Schedule periodic tasks
        self._schedule_periodic_tasks()

        self._running = True
        print("Analytics Engine initialized successfully")

    async def shutdown(self):
        """Shutdown the analytics engine"""
        print("Shutting down Analytics Engine...")

        self._running = False

        # Cancel periodic tasks
        for task in self._tasks:
            task.cancel()

        # Stop performance tracking
        await self.performance_tracker.stop_tracking()

        print("Analytics Engine shutdown complete")

    def _schedule_periodic_tasks(self):
        """Schedule periodic maintenance tasks"""
        # Train ML models every 6 hours
        self._tasks.append(asyncio.create_task(self._periodic_ml_training()))

        # Generate reports every hour
        self._tasks.append(asyncio.create_task(self._periodic_reporting()))

        # Cleanup old data daily
        self._tasks.append(asyncio.create_task(self._periodic_cleanup()))

    async def _periodic_ml_training(self):
        """Periodic ML model training"""
        while self._running:
            try:
                await asyncio.sleep(6 * 3600)  # 6 hours
                if self._running:
                    print("Starting periodic ML model training...")
                    await self.ml_predictor.train_models()
                    print("Periodic ML training completed")
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in periodic ML training: {e}")

    async def _periodic_reporting(self):
        """Periodic report generation"""
        while self._running:
            try:
                await asyncio.sleep(3600)  # 1 hour
                if self._running:
                    print("Generating periodic analytics report...")
                    await self.reporting_dashboard.generate_comprehensive_report(
                        1
                    )  # Last hour
                    print("Periodic report generated")
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in periodic reporting: {e}")

    async def _periodic_cleanup(self):
        """Periodic data cleanup"""
        while self._running:
            try:
                await asyncio.sleep(24 * 3600)  # 24 hours
                if self._running:
                    print("Starting periodic data cleanup...")
                    await self.metrics_collector.cleanup_old_data(30)  # 30 days
                    await self.reporting_dashboard.cleanup_old_reports(30)
                    print("Periodic cleanup completed")
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in periodic cleanup: {e}")

    # Public API methods

    async def record_attack_result(
        self, attack_id: str, success: bool, response_time: float, domain: str = None
    ):
        """Record attack execution result"""
        await self.metrics_collector.record_attack_result(
            attack_id, success, response_time, domain
        )

    async def record_strategy_result(
        self, strategy_id: str, domain: str, success: bool, effectiveness: float
    ):
        """Record strategy application result"""
        await self.metrics_collector.record_strategy_result(
            strategy_id, domain, success, effectiveness
        )

    async def get_attack_analytics(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive analytics for specific attack"""
        metrics = await self.metrics_collector.get_attack_metrics(attack_id)
        if not metrics:
            return None

        # Get performance summary
        performance = await self.performance_tracker.get_performance_summary(attack_id)

        # Get predictions
        success_prediction = await self.ml_predictor.predict_success_rate(attack_id)
        response_prediction = await self.ml_predictor.predict_response_time(attack_id)

        return {
            "attack_id": attack_id,
            "metrics": {
                "success_rate": metrics.success_rate,
                "total_attempts": metrics.total_attempts,
                "avg_response_time": metrics.avg_response_time,
                "reliability_score": metrics.reliability_score,
                "last_success": (
                    metrics.last_success.isoformat() if metrics.last_success else None
                ),
                "last_failure": (
                    metrics.last_failure.isoformat() if metrics.last_failure else None
                ),
            },
            "performance": performance,
            "predictions": {
                "success_rate": {
                    "value": (
                        success_prediction.predicted_value
                        if success_prediction
                        else None
                    ),
                    "confidence": (
                        success_prediction.confidence if success_prediction else None
                    ),
                },
                "response_time": {
                    "value": (
                        response_prediction.predicted_value
                        if response_prediction
                        else None
                    ),
                    "confidence": (
                        response_prediction.confidence if response_prediction else None
                    ),
                },
            },
        }

    async def get_strategy_analytics(
        self, strategy_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get comprehensive analytics for specific strategy"""
        metrics = await self.metrics_collector.get_strategy_metrics(strategy_id)
        if not metrics:
            return None

        # Get performance summary
        performance = await self.performance_tracker.get_performance_summary(
            strategy_id
        )

        # Get prediction
        effectiveness_prediction = (
            await self.ml_predictor.predict_strategy_effectiveness(strategy_id)
        )

        return {
            "strategy_id": strategy_id,
            "metrics": {
                "success_rate": metrics.success_rate,
                "domain_count": metrics.domain_count,
                "successful_domains": metrics.successful_domains,
                "failed_domains": metrics.failed_domains,
                "avg_effectiveness": metrics.avg_effectiveness,
                "trend_direction": metrics.trend_direction.value,
                "last_updated": metrics.last_updated.isoformat(),
            },
            "performance": performance,
            "prediction": {
                "effectiveness": {
                    "value": (
                        effectiveness_prediction.predicted_value
                        if effectiveness_prediction
                        else None
                    ),
                    "confidence": (
                        effectiveness_prediction.confidence
                        if effectiveness_prediction
                        else None
                    ),
                }
            },
        }

    async def get_system_overview(self) -> Dict[str, Any]:
        """Get system-wide analytics overview"""
        realtime_metrics = await self.metrics_collector.get_realtime_metrics()

        # Get top performers
        top_attacks = await self.performance_tracker.get_top_performers(
            MetricType.SUCCESS_RATE, 5
        )
        top_strategies = await self.performance_tracker.get_top_performers(
            MetricType.STRATEGY_PERFORMANCE, 5
        )

        # Get system health trends
        performance_report = (
            await self.performance_tracker.generate_performance_report()
        )

        return {
            "timestamp": realtime_metrics.timestamp.isoformat(),
            "system_metrics": {
                "active_attacks": realtime_metrics.active_attacks,
                "active_strategies": realtime_metrics.active_strategies,
                "overall_success_rate": realtime_metrics.overall_success_rate,
                "avg_response_time": realtime_metrics.avg_response_time,
                "system_health": realtime_metrics.system_health,
            },
            "top_performers": {"attacks": top_attacks, "strategies": top_strategies},
            "recent_issues": {
                "failures": realtime_metrics.recent_failures,
                "declining_entities": performance_report["declining_entities"],
                "volatile_entities": performance_report["volatile_entities"],
            },
            "recommendations": performance_report["recommendations"],
        }

    async def generate_full_report(self, hours: int = 24) -> AnalyticsReport:
        """Generate comprehensive analytics report"""
        return await self.reporting_dashboard.generate_comprehensive_report(hours)

    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get real-time dashboard data"""
        return await self.reporting_dashboard.get_realtime_dashboard_data()

    async def get_trend_analysis(
        self, entity_id: str, metric_type: MetricType, hours: int = 168
    ) -> Dict[str, Any]:
        """Get detailed trend analysis for entity"""
        return await self.reporting_dashboard.generate_trend_report(
            entity_id, metric_type, hours
        )

    async def train_ml_models(self, min_data_points: int = 50):
        """Manually trigger ML model training"""
        await self.ml_predictor.train_models(min_data_points)

    async def get_prediction(
        self, entity_id: str, metric_type: MetricType, hours_ahead: int = 1
    ) -> Optional[Dict[str, Any]]:
        """Get prediction for specific entity and metric"""
        if metric_type == MetricType.SUCCESS_RATE:
            prediction = await self.ml_predictor.predict_success_rate(
                entity_id, hours_ahead
            )
        elif metric_type == MetricType.RESPONSE_TIME:
            prediction = await self.ml_predictor.predict_response_time(
                entity_id, hours_ahead
            )
        elif metric_type == MetricType.STRATEGY_PERFORMANCE:
            prediction = await self.ml_predictor.predict_strategy_effectiveness(
                entity_id, hours_ahead
            )
        else:
            return None

        if prediction:
            return {
                "entity_id": prediction.entity_id,
                "metric_type": prediction.metric_type.value,
                "predicted_value": prediction.predicted_value,
                "confidence": prediction.confidence,
                "prediction_horizon": prediction.prediction_horizon,
                "created_at": prediction.created_at.isoformat(),
            }

        return None

    async def export_analytics_data(self, filepath: str, format: str = "json"):
        """Export analytics data to file"""
        await self.reporting_dashboard.export_dashboard_data(filepath, format)

    async def get_historical_data(
        self, entity_id: str, metric_type: MetricType, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get historical metric data"""
        return await self.metrics_collector.get_metric_history(
            entity_id, metric_type, hours
        )

    async def get_analytics_summary(self) -> Dict[str, Any]:
        """Get high-level analytics summary"""
        system_overview = await self.get_system_overview()

        # Calculate additional summary metrics
        total_entities = (
            system_overview["system_metrics"]["active_attacks"]
            + system_overview["system_metrics"]["active_strategies"]
        )

        health_status = "excellent"
        if system_overview["system_metrics"]["system_health"] < 0.8:
            health_status = "good"
        if system_overview["system_metrics"]["system_health"] < 0.6:
            health_status = "fair"
        if system_overview["system_metrics"]["system_health"] < 0.4:
            health_status = "poor"

        return {
            "summary": {
                "total_entities_monitored": total_entities,
                "overall_success_rate": system_overview["system_metrics"][
                    "overall_success_rate"
                ],
                "system_health_status": health_status,
                "active_issues": len(system_overview["recent_issues"]["failures"]),
                "recommendations_count": len(system_overview["recommendations"]),
            },
            "key_metrics": {
                "success_rate": system_overview["system_metrics"][
                    "overall_success_rate"
                ],
                "avg_response_time": system_overview["system_metrics"][
                    "avg_response_time"
                ],
                "system_health": system_overview["system_metrics"]["system_health"],
            },
            "status": {
                "analytics_engine_running": self._running,
                "ml_models_trained": len(self.ml_predictor.trained_models),
                "performance_tracking_active": self.performance_tracker._running,
            },
        }
