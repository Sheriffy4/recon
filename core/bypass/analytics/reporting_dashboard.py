"""
Comprehensive reporting dashboard for bypass engine analytics
"""

import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from .analytics_models import (
    AnalyticsReport, RealtimeMetrics, MetricType, TrendDirection
)
from .metrics_collector import MetricsCollector
from .performance_tracker import PerformanceTracker
from .ml_predictor import MLPredictor


class ReportingDashboard:
    """Comprehensive reporting and dashboard system"""
    
    def __init__(self, metrics_collector: MetricsCollector, 
                 performance_tracker: PerformanceTracker,
                 ml_predictor: MLPredictor):
        self.metrics_collector = metrics_collector
        self.performance_tracker = performance_tracker
        self.ml_predictor = ml_predictor
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    async def generate_comprehensive_report(self, 
                                         time_period_hours: int = 24) -> AnalyticsReport:
        """Generate comprehensive analytics report"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time_period_hours)
        
        report_id = f"analytics_report_{end_time.strftime('%Y%m%d_%H%M%S')}"
        
        print(f"Generating comprehensive report for period: {start_time} to {end_time}")
        
        # Collect attack analytics
        attack_analytics = {}
        for attack_id, metrics in self.metrics_collector.attack_metrics.items():
            if metrics.total_attempts > 0:
                attack_analytics[attack_id] = metrics
        
        # Collect strategy analytics
        strategy_analytics = {}
        for strategy_id, metrics in self.metrics_collector.strategy_metrics.items():
            if metrics.domain_count > 0:
                strategy_analytics[strategy_id] = metrics
        
        # Collect domain analytics
        domain_analytics = {}
        for key, analytics in self.metrics_collector.domain_analytics.items():
            if analytics.last_tested:
                domain_analytics[key] = analytics
        
        # Get performance trends
        performance_trends = []
        for trend in self.performance_tracker.trends.values():
            if len(trend.values) > 0:
                performance_trends.append(trend)
        
        # Generate predictions
        predictions = []
        for attack_id in list(attack_analytics.keys())[:10]:  # Top 10 attacks
            pred = await self.ml_predictor.predict_success_rate(attack_id)
            if pred:
                predictions.append(pred)
        
        # Calculate summary statistics
        summary_stats = await self._calculate_summary_stats(
            attack_analytics, strategy_analytics, domain_analytics
        )
        
        # Generate recommendations
        recommendations = await self._generate_recommendations(
            attack_analytics, strategy_analytics, performance_trends
        )
        
        report = AnalyticsReport(
            report_id=report_id,
            generated_at=end_time,
            time_period={'start': start_time, 'end': end_time},
            attack_analytics=attack_analytics,
            strategy_analytics=strategy_analytics,
            domain_analytics=domain_analytics,
            performance_trends=performance_trends,
            predictions=predictions,
            summary_stats=summary_stats,
            recommendations=recommendations
        )
        
        # Save report
        await self._save_report(report)
        
        return report
    
    async def _calculate_summary_stats(self, attack_analytics: Dict, 
                                     strategy_analytics: Dict,
                                     domain_analytics: Dict) -> Dict[str, Any]:
        """Calculate summary statistics"""
        stats = {
            'total_attacks': len(attack_analytics),
            'total_strategies': len(strategy_analytics),
            'total_domains': len(domain_analytics),
            'overall_success_rate': 0.0,
            'avg_response_time': 0.0,
            'most_successful_attack': None,
            'most_successful_strategy': None,
            'most_problematic_domain': None,
            'system_health_score': 0.0
        }
        
        if attack_analytics:
            # Calculate overall success rate
            total_successes = sum(m.success_count for m in attack_analytics.values())
            total_attempts = sum(m.total_attempts for m in attack_analytics.values())
            stats['overall_success_rate'] = total_successes / total_attempts if total_attempts > 0 else 0.0
            
            # Calculate average response time
            response_times = [m.avg_response_time for m in attack_analytics.values() if m.avg_response_time > 0]
            stats['avg_response_time'] = sum(response_times) / len(response_times) if response_times else 0.0
            
            # Find most successful attack
            best_attack = max(attack_analytics.items(), key=lambda x: x[1].success_rate)
            stats['most_successful_attack'] = {
                'id': best_attack[0],
                'success_rate': best_attack[1].success_rate
            }
        
        if strategy_analytics:
            # Find most successful strategy
            best_strategy = max(strategy_analytics.items(), key=lambda x: x[1].success_rate)
            stats['most_successful_strategy'] = {
                'id': best_strategy[0],
                'success_rate': best_strategy[1].success_rate
            }
        
        if domain_analytics:
            # Find most problematic domain (lowest success rate)
            worst_domain = min(domain_analytics.items(), key=lambda x: x[1].avg_success_rate)
            stats['most_problematic_domain'] = {
                'domain': worst_domain[1].domain,
                'success_rate': worst_domain[1].avg_success_rate
            }
        
        # Calculate system health score
        health_factors = [
            stats['overall_success_rate'],
            min(1.0, 1.0 / max(stats['avg_response_time'], 0.1)) if stats['avg_response_time'] > 0 else 1.0,
            min(1.0, len(attack_analytics) / 50.0),  # Normalize by expected attack count
        ]
        stats['system_health_score'] = sum(health_factors) / len(health_factors)
        
        return stats
    
    async def _generate_recommendations(self, attack_analytics: Dict,
                                      strategy_analytics: Dict,
                                      performance_trends: List) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Analyze attack performance
        if attack_analytics:
            low_performing_attacks = [
                (attack_id, metrics) for attack_id, metrics in attack_analytics.items()
                if metrics.success_rate < 0.5 and metrics.total_attempts > 10
            ]
            
            if low_performing_attacks:
                recommendations.append(
                    f"Review configuration for {len(low_performing_attacks)} low-performing attacks"
                )
            
            # Check for attacks with high response times
            slow_attacks = [
                attack_id for attack_id, metrics in attack_analytics.items()
                if metrics.avg_response_time > 5.0
            ]
            
            if slow_attacks:
                recommendations.append(
                    f"Optimize {len(slow_attacks)} attacks with high response times"
                )
        
        # Analyze strategy performance
        if strategy_analytics:
            ineffective_strategies = [
                strategy_id for strategy_id, metrics in strategy_analytics.items()
                if metrics.success_rate < 0.3 and metrics.domain_count > 5
            ]
            
            if ineffective_strategies:
                recommendations.append(
                    f"Replace or improve {len(ineffective_strategies)} ineffective strategies"
                )
        
        # Analyze performance trends
        declining_trends = [
            trend for trend in performance_trends
            if trend.trend_direction == TrendDirection.DECLINING and trend.trend_strength > 0.5
        ]
        
        if declining_trends:
            recommendations.append(
                f"Investigate {len(declining_trends)} entities with declining performance"
            )
        
        # General recommendations
        if not recommendations:
            recommendations.append("System performance is stable - continue monitoring")
        
        return recommendations
    
    async def _save_report(self, report: AnalyticsReport):
        """Save report to file"""
        report_file = self.reports_dir / f"{report.report_id}.json"
        
        # Convert report to serializable format
        report_data = {
            'report_id': report.report_id,
            'generated_at': report.generated_at.isoformat(),
            'time_period': {
                'start': report.time_period['start'].isoformat(),
                'end': report.time_period['end'].isoformat()
            },
            'attack_analytics': {
                attack_id: {
                    'success_rate': metrics.success_rate,
                    'total_attempts': metrics.total_attempts,
                    'avg_response_time': metrics.avg_response_time,
                    'reliability_score': metrics.reliability_score
                }
                for attack_id, metrics in report.attack_analytics.items()
            },
            'strategy_analytics': {
                strategy_id: {
                    'success_rate': metrics.success_rate,
                    'domain_count': metrics.domain_count,
                    'avg_effectiveness': metrics.avg_effectiveness
                }
                for strategy_id, metrics in report.strategy_analytics.items()
            },
            'domain_analytics': {
                key: {
                    'domain': analytics.domain,
                    'avg_success_rate': analytics.avg_success_rate,
                    'best_strategy': analytics.best_strategy,
                    'successful_strategies_count': len(analytics.successful_strategies)
                }
                for key, analytics in report.domain_analytics.items()
            },
            'performance_trends': [
                {
                    'entity_id': trend.entity_id,
                    'metric_type': trend.metric_type.value,
                    'trend_direction': trend.trend_direction.value,
                    'trend_strength': trend.trend_strength,
                    'data_points': len(trend.values)
                }
                for trend in report.performance_trends
            ],
            'predictions': [
                {
                    'entity_id': pred.entity_id,
                    'metric_type': pred.metric_type.value,
                    'predicted_value': pred.predicted_value,
                    'confidence': pred.confidence,
                    'prediction_horizon': pred.prediction_horizon
                }
                for pred in report.predictions
            ],
            'summary_stats': report.summary_stats,
            'recommendations': report.recommendations
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"Report saved to {report_file}")
    
    async def get_realtime_dashboard_data(self) -> Dict[str, Any]:
        """Get real-time data for dashboard display"""
        realtime_metrics = await self.metrics_collector.get_realtime_metrics()
        
        # Get recent performance data
        recent_trends = {}
        for metric_type in MetricType:
            top_performers = await self.performance_tracker.get_top_performers(metric_type, 5)
            recent_trends[metric_type.value] = top_performers
        
        # Get recent predictions
        recent_predictions = []
        attack_ids = list(self.metrics_collector.attack_metrics.keys())[:5]
        for attack_id in attack_ids:
            pred = await self.ml_predictor.predict_success_rate(attack_id)
            if pred:
                recent_predictions.append({
                    'entity_id': pred.entity_id,
                    'predicted_value': pred.predicted_value,
                    'confidence': pred.confidence
                })
        
        dashboard_data = {
            'timestamp': realtime_metrics.timestamp.isoformat(),
            'system_overview': {
                'active_attacks': realtime_metrics.active_attacks,
                'active_strategies': realtime_metrics.active_strategies,
                'overall_success_rate': realtime_metrics.overall_success_rate,
                'avg_response_time': realtime_metrics.avg_response_time,
                'system_health': realtime_metrics.system_health
            },
            'top_performers': {
                'attacks': realtime_metrics.top_performing_attacks,
                'strategies': realtime_metrics.top_performing_strategies
            },
            'recent_issues': {
                'failures': realtime_metrics.recent_failures
            },
            'performance_trends': recent_trends,
            'predictions': recent_predictions,
            'alerts': await self._generate_alerts(realtime_metrics)
        }
        
        return dashboard_data
    
    async def _generate_alerts(self, metrics: RealtimeMetrics) -> List[Dict[str, Any]]:
        """Generate alerts based on current metrics"""
        alerts = []
        
        # System health alert
        if metrics.system_health < 0.7:
            alerts.append({
                'type': 'warning',
                'message': f"System health is low: {metrics.system_health:.2f}",
                'severity': 'high' if metrics.system_health < 0.5 else 'medium'
            })
        
        # Success rate alert
        if metrics.overall_success_rate < 0.6:
            alerts.append({
                'type': 'error',
                'message': f"Overall success rate is low: {metrics.overall_success_rate:.2f}",
                'severity': 'high'
            })
        
        # Response time alert
        if metrics.avg_response_time > 10.0:
            alerts.append({
                'type': 'warning',
                'message': f"Average response time is high: {metrics.avg_response_time:.2f}s",
                'severity': 'medium'
            })
        
        # Recent failures alert
        if len(metrics.recent_failures) > 5:
            alerts.append({
                'type': 'warning',
                'message': f"High number of recent failures: {len(metrics.recent_failures)}",
                'severity': 'medium'
            })
        
        return alerts
    
    async def export_dashboard_data(self, filepath: str, format: str = 'json'):
        """Export dashboard data to file"""
        dashboard_data = await self.get_realtime_dashboard_data()
        
        if format.lower() == 'json':
            with open(filepath, 'w') as f:
                json.dump(dashboard_data, f, indent=2)
        elif format.lower() == 'csv':
            await self._export_to_csv(dashboard_data, filepath)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    async def _export_to_csv(self, data: Dict[str, Any], filepath: str):
        """Export data to CSV format"""
        import csv
        
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write system overview
            writer.writerow(['Metric', 'Value'])
            for key, value in data['system_overview'].items():
                writer.writerow([key, value])
            
            writer.writerow([])  # Empty row
            
            # Write top performers
            writer.writerow(['Top Performing Attacks'])
            for attack in data['top_performers']['attacks']:
                writer.writerow([attack])
            
            writer.writerow([])
            writer.writerow(['Top Performing Strategies'])
            for strategy in data['top_performers']['strategies']:
                writer.writerow([strategy])
    
    async def generate_trend_report(self, entity_id: str, 
                                  metric_type: MetricType,
                                  hours: int = 168) -> Dict[str, Any]:
        """Generate detailed trend report for specific entity"""
        trend = await self.performance_tracker.get_trend_data(entity_id, metric_type, hours)
        
        if not trend:
            return {'error': f'No trend data available for {entity_id}'}
        
        # Get predictions
        if metric_type == MetricType.SUCCESS_RATE:
            prediction = await self.ml_predictor.predict_success_rate(entity_id)
        elif metric_type == MetricType.RESPONSE_TIME:
            prediction = await self.ml_predictor.predict_response_time(entity_id)
        else:
            prediction = None
        
        report = {
            'entity_id': entity_id,
            'metric_type': metric_type.value,
            'time_period_hours': hours,
            'trend_analysis': {
                'direction': trend.trend_direction.value,
                'strength': trend.trend_strength,
                'data_points': len(trend.values),
                'current_value': trend.values[-1] if trend.values else None,
                'min_value': min(trend.values) if trend.values else None,
                'max_value': max(trend.values) if trend.values else None,
                'avg_value': sum(trend.values) / len(trend.values) if trend.values else None
            },
            'prediction': {
                'predicted_value': prediction.predicted_value if prediction else None,
                'confidence': prediction.confidence if prediction else None,
                'horizon_hours': prediction.prediction_horizon if prediction else None
            } if prediction else None,
            'recommendations': await self._generate_entity_recommendations(entity_id, trend)
        }
        
        return report
    
    async def _generate_entity_recommendations(self, entity_id: str, 
                                            trend: 'PerformanceTrend') -> List[str]:
        """Generate recommendations for specific entity"""
        recommendations = []
        
        if trend.trend_direction == TrendDirection.DECLINING:
            if trend.metric_type == MetricType.SUCCESS_RATE:
                recommendations.append(f"Success rate declining for {entity_id} - review configuration")
            elif trend.metric_type == MetricType.RESPONSE_TIME:
                recommendations.append(f"Response time increasing for {entity_id} - check performance")
        
        elif trend.trend_direction == TrendDirection.VOLATILE:
            recommendations.append(f"Performance is unstable for {entity_id} - investigate stability")
        
        elif trend.trend_direction == TrendDirection.IMPROVING:
            recommendations.append(f"Performance improving for {entity_id} - maintain current configuration")
        
        else:
            recommendations.append(f"Performance stable for {entity_id} - continue monitoring")
        
        return recommendations
    
    async def cleanup_old_reports(self, days: int = 30):
        """Clean up old report files"""
        cutoff = datetime.now() - timedelta(days=days)
        
        for report_file in self.reports_dir.glob("*.json"):
            if report_file.stat().st_mtime < cutoff.timestamp():
                report_file.unlink()
                print(f"Deleted old report: {report_file}")
    
    async def get_report_list(self) -> List[Dict[str, Any]]:
        """Get list of available reports"""
        reports = []
        
        for report_file in self.reports_dir.glob("*.json"):
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                
                reports.append({
                    'filename': report_file.name,
                    'report_id': report_data.get('report_id'),
                    'generated_at': report_data.get('generated_at'),
                    'size_kb': report_file.stat().st_size / 1024
                })
            except Exception as e:
                print(f"Error reading report {report_file}: {e}")
        
        # Sort by generation time (newest first)
        reports.sort(key=lambda x: x['generated_at'], reverse=True)
        
        return reports