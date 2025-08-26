"""
Performance tracking and trend analysis for bypass engine
"""
import asyncio
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict, deque
from core.bypass.analytics.analytics_models import PerformanceTrend, MetricType, TrendDirection
from core.bypass.analytics.metrics_collector import MetricsCollector

class PerformanceTracker:
    """Tracks performance trends and analyzes patterns"""

    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.trends: Dict[str, PerformanceTrend] = {}
        self.trend_cache = defaultdict(lambda: deque(maxlen=100))
        self.analysis_interval = 300
        self._running = False

    async def start_tracking(self):
        """Start continuous performance tracking"""
        self._running = True
        asyncio.create_task(self._tracking_loop())

    async def stop_tracking(self):
        """Stop performance tracking"""
        self._running = False

    async def _tracking_loop(self):
        """Main tracking loop"""
        while self._running:
            try:
                await self._collect_performance_data()
                await self._analyze_trends()
                await asyncio.sleep(self.analysis_interval)
            except Exception as e:
                print(f'Error in performance tracking: {e}')
                await asyncio.sleep(60)

    async def _collect_performance_data(self):
        """Collect current performance data"""
        now = datetime.now()
        for attack_id, metrics in self.metrics_collector.attack_metrics.items():
            if metrics.total_attempts > 0:
                trend_key = f'attack_{attack_id}_success_rate'
                if trend_key not in self.trends:
                    self.trends[trend_key] = PerformanceTrend(metric_type=MetricType.SUCCESS_RATE, entity_id=attack_id)
                self.trends[trend_key].add_data_point(now, metrics.success_rate)
                if metrics.avg_response_time > 0:
                    trend_key = f'attack_{attack_id}_response_time'
                    if trend_key not in self.trends:
                        self.trends[trend_key] = PerformanceTrend(metric_type=MetricType.RESPONSE_TIME, entity_id=attack_id)
                    self.trends[trend_key].add_data_point(now, metrics.avg_response_time)
        for strategy_id, metrics in self.metrics_collector.strategy_metrics.items():
            if metrics.domain_count > 0:
                trend_key = f'strategy_{strategy_id}_performance'
                if trend_key not in self.trends:
                    self.trends[trend_key] = PerformanceTrend(metric_type=MetricType.STRATEGY_PERFORMANCE, entity_id=strategy_id)
                self.trends[trend_key].add_data_point(now, metrics.success_rate)

    async def _analyze_trends(self):
        """Analyze performance trends and detect patterns"""
        for trend_key, trend in self.trends.items():
            if len(trend.values) >= 3:
                await self._detect_anomalies(trend)
                await self._analyze_trend_patterns(trend)

    async def _detect_anomalies(self, trend: PerformanceTrend):
        """Detect performance anomalies"""
        if len(trend.values) < 10:
            return
        values = np.array(trend.values[-20:])
        mean = np.mean(values)
        std = np.std(values)
        current_value = values[-1]
        if abs(current_value - mean) > 2 * std:
            await self._handle_anomaly(trend, current_value, mean, std)

    async def _handle_anomaly(self, trend: PerformanceTrend, value: float, mean: float, std: float):
        """Handle detected performance anomaly"""
        anomaly_info = {'entity_id': trend.entity_id, 'metric_type': trend.metric_type.value, 'current_value': value, 'expected_range': (mean - 2 * std, mean + 2 * std), 'severity': 'high' if abs(value - mean) > 3 * std else 'medium', 'timestamp': datetime.now().isoformat()}
        print(f'Performance anomaly detected: {anomaly_info}')

    async def _analyze_trend_patterns(self, trend: PerformanceTrend):
        """Analyze trend patterns for insights"""
        if len(trend.values) < 5:
            return
        values = trend.values[-10:]
        if self._is_declining_pattern(values):
            await self._handle_declining_performance(trend)
        if self._is_volatile_pattern(values):
            await self._handle_volatile_performance(trend)

    def _is_declining_pattern(self, values: List[float]) -> bool:
        """Check if values show consistent decline"""
        if len(values) < 3:
            return False
        declines = 0
        for i in range(1, len(values)):
            if values[i] < values[i - 1]:
                declines += 1
        return declines >= len(values) * 0.7

    def _is_volatile_pattern(self, values: List[float]) -> bool:
        """Check if values show high volatility"""
        if len(values) < 3:
            return False
        mean = np.mean(values)
        std = np.std(values)
        return std > 0.3 * mean if mean > 0 else False

    async def _handle_declining_performance(self, trend: PerformanceTrend):
        """Handle declining performance pattern"""
        print(f'Declining performance detected for {trend.entity_id} ({trend.metric_type.value})')

    async def _handle_volatile_performance(self, trend: PerformanceTrend):
        """Handle volatile performance pattern"""
        print(f'Volatile performance detected for {trend.entity_id} ({trend.metric_type.value})')

    async def get_performance_summary(self, entity_id: str) -> Dict[str, any]:
        """Get performance summary for entity"""
        summary = {'entity_id': entity_id, 'trends': {}, 'current_status': 'unknown', 'recommendations': []}
        entity_trends = {key: trend for key, trend in self.trends.items() if trend.entity_id == entity_id}
        if not entity_trends:
            return summary
        for trend_key, trend in entity_trends.items():
            if len(trend.values) > 0:
                summary['trends'][trend.metric_type.value] = {'direction': trend.trend_direction.value, 'strength': trend.trend_strength, 'current_value': trend.values[-1], 'data_points': len(trend.values)}
        summary['current_status'] = self._determine_overall_status(entity_trends)
        summary['recommendations'] = self._generate_recommendations(entity_trends)
        return summary

    def _determine_overall_status(self, trends: Dict[str, PerformanceTrend]) -> str:
        """Determine overall performance status"""
        if not trends:
            return 'unknown'
        declining_count = sum((1 for t in trends.values() if t.trend_direction == TrendDirection.DECLINING))
        improving_count = sum((1 for t in trends.values() if t.trend_direction == TrendDirection.IMPROVING))
        if declining_count > improving_count:
            return 'declining'
        elif improving_count > declining_count:
            return 'improving'
        else:
            return 'stable'

    def _generate_recommendations(self, trends: Dict[str, PerformanceTrend]) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []
        for trend in trends.values():
            if trend.trend_direction == TrendDirection.DECLINING:
                if trend.metric_type == MetricType.SUCCESS_RATE:
                    recommendations.append(f'Consider reviewing {trend.entity_id} configuration - success rate declining')
                elif trend.metric_type == MetricType.RESPONSE_TIME:
                    recommendations.append(f'Investigate {trend.entity_id} performance - response time increasing')
            elif trend.trend_direction == TrendDirection.VOLATILE:
                recommendations.append(f'Stabilize {trend.entity_id} - performance is volatile')
        return recommendations

    async def get_top_performers(self, metric_type: MetricType, limit: int=10) -> List[Dict[str, any]]:
        """Get top performing entities for specific metric"""
        performers = []
        for trend in self.trends.values():
            if trend.metric_type == metric_type and len(trend.values) > 0:
                current_value = trend.values[-1]
                performers.append({'entity_id': trend.entity_id, 'current_value': current_value, 'trend_direction': trend.trend_direction.value, 'trend_strength': trend.trend_strength})
        reverse_sort = metric_type != MetricType.RESPONSE_TIME
        performers.sort(key=lambda x: x['current_value'], reverse=reverse_sort)
        return performers[:limit]

    async def get_trend_data(self, entity_id: str, metric_type: MetricType, hours: int=24) -> Optional[PerformanceTrend]:
        """Get trend data for specific entity and metric"""
        trend_key = f'{entity_id}_{metric_type.value}'
        for key, trend in self.trends.items():
            if trend.entity_id == entity_id and trend.metric_type == metric_type:
                cutoff = datetime.now() - timedelta(hours=hours)
                filtered_trend = PerformanceTrend(metric_type=trend.metric_type, entity_id=trend.entity_id)
                for i, timestamp in enumerate(trend.timestamps):
                    if timestamp >= cutoff:
                        filtered_trend.timestamps.append(timestamp)
                        filtered_trend.values.append(trend.values[i])
                filtered_trend._calculate_trend()
                return filtered_trend
        return None

    async def export_trends(self, filepath: str):
        """Export trend data to file"""
        import json
        export_data = {}
        for key, trend in self.trends.items():
            export_data[key] = {'entity_id': trend.entity_id, 'metric_type': trend.metric_type.value, 'trend_direction': trend.trend_direction.value, 'trend_strength': trend.trend_strength, 'data_points': len(trend.values), 'timestamps': [t.isoformat() for t in trend.timestamps], 'values': trend.values}
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)

    async def generate_performance_report(self) -> Dict[str, any]:
        """Generate comprehensive performance report"""
        report = {'generated_at': datetime.now().isoformat(), 'summary': {'total_entities_tracked': len(set((t.entity_id for t in self.trends.values()))), 'total_trends': len(self.trends), 'active_trends': len([t for t in self.trends.values() if len(t.values) > 0])}, 'top_performers': {}, 'declining_entities': [], 'volatile_entities': [], 'recommendations': []}
        for metric_type in MetricType:
            performers = await self.get_top_performers(metric_type, 5)
            report['top_performers'][metric_type.value] = performers
        for trend in self.trends.values():
            if trend.trend_direction == TrendDirection.DECLINING:
                report['declining_entities'].append({'entity_id': trend.entity_id, 'metric_type': trend.metric_type.value, 'trend_strength': trend.trend_strength})
            elif trend.trend_direction == TrendDirection.VOLATILE:
                report['volatile_entities'].append({'entity_id': trend.entity_id, 'metric_type': trend.metric_type.value, 'trend_strength': trend.trend_strength})
        if report['declining_entities']:
            report['recommendations'].append('Review configuration for declining entities')
        if report['volatile_entities']:
            report['recommendations'].append('Investigate stability issues for volatile entities')
        return report