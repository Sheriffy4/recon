"""
Strategy selection algorithm optimizer.
"""
import logging
import numpy as np
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict, deque
from recon.core.bypass.performance.performance_models import OptimizationLevel

class StrategyOptimizer:
    """Optimizes strategy selection algorithms for maximum effectiveness."""

    def __init__(self, optimization_level: OptimizationLevel=OptimizationLevel.BALANCED):
        self.optimization_level = optimization_level
        self.strategy_stats = defaultdict(lambda: {'success_count': 0, 'failure_count': 0, 'total_time': 0.0, 'last_used': None, 'effectiveness_history': deque(maxlen=100)})
        self.domain_strategy_mapping = {}
        self.optimization_weights = self._get_optimization_weights()
        self.logger = logging.getLogger(__name__)

    def _get_optimization_weights(self) -> Dict[str, float]:
        """Get optimization weights based on optimization level."""
        weights = {OptimizationLevel.CONSERVATIVE: {'success_rate': 0.5, 'execution_time': 0.2, 'stability': 0.3}, OptimizationLevel.BALANCED: {'success_rate': 0.4, 'execution_time': 0.3, 'stability': 0.3}, OptimizationLevel.AGGRESSIVE: {'success_rate': 0.6, 'execution_time': 0.3, 'stability': 0.1}, OptimizationLevel.MAXIMUM: {'success_rate': 0.7, 'execution_time': 0.3, 'stability': 0.0}}
        return weights[self.optimization_level]

    async def optimize_strategy_selection(self, domain: str, available_strategies: List[str]) -> str:
        """Optimize strategy selection for a specific domain."""
        try:
            if not available_strategies:
                raise ValueError('No strategies available for optimization')
            strategy_scores = {}
            for strategy_id in available_strategies:
                score = await self._calculate_strategy_score(strategy_id, domain)
                strategy_scores[strategy_id] = score
            best_strategy = max(strategy_scores.items(), key=lambda x: x[1])
            self.logger.debug(f'Selected strategy {best_strategy[0]} for domain {domain} with score {best_strategy[1]:.3f}')
            return best_strategy[0]
        except Exception as e:
            self.logger.error(f'Error optimizing strategy selection: {e}')
            return available_strategies[0] if available_strategies else None

    async def _calculate_strategy_score(self, strategy_id: str, domain: str) -> float:
        """Calculate effectiveness score for a strategy."""
        try:
            stats = self.strategy_stats[strategy_id]
            total_attempts = stats['success_count'] + stats['failure_count']
            success_rate = stats['success_count'] / max(total_attempts, 1)
            avg_time = stats['total_time'] / max(total_attempts, 1)
            time_score = 1.0 / (1.0 + avg_time)
            stability_score = self._calculate_stability_score(stats['effectiveness_history'])
            domain_bonus = self._get_domain_specific_bonus(strategy_id, domain)
            recency_bonus = self._get_recency_bonus(stats['last_used'])
            score = success_rate * self.optimization_weights['success_rate'] + time_score * self.optimization_weights['execution_time'] + stability_score * self.optimization_weights['stability'] + domain_bonus * 0.1 + recency_bonus * 0.05
            return score
        except Exception as e:
            self.logger.error(f'Error calculating strategy score for {strategy_id}: {e}')
            return 0.0

    def _calculate_stability_score(self, effectiveness_history: deque) -> float:
        """Calculate stability score based on effectiveness history."""
        if len(effectiveness_history) < 2:
            return 0.5
        try:
            values = list(effectiveness_history)
            mean_val = np.mean(values)
            std_val = np.std(values)
            if mean_val == 0:
                return 0.0
            cv = std_val / mean_val
            stability_score = 1.0 / (1.0 + cv)
            return stability_score
        except Exception:
            return 0.5

    def _get_domain_specific_bonus(self, strategy_id: str, domain: str) -> float:
        """Get domain-specific bonus for strategy."""
        domain_key = f'{domain}:{strategy_id}'
        if domain_key in self.domain_strategy_mapping:
            mapping_data = self.domain_strategy_mapping[domain_key]
            return mapping_data.get('success_rate', 0.0) * 0.2
        return 0.0

    def _get_recency_bonus(self, last_used: Optional[datetime]) -> float:
        """Get recency bonus for recently used strategies."""
        if not last_used:
            return 0.0
        time_diff = datetime.now() - last_used
        hours_ago = time_diff.total_seconds() / 3600
        if hours_ago < 1:
            return 0.3
        elif hours_ago < 6:
            return 0.2
        elif hours_ago < 24:
            return 0.1
        else:
            return 0.0

    async def update_strategy_performance(self, strategy_id: str, domain: str, success: bool, execution_time: float, effectiveness_score: float) -> None:
        """Update strategy performance statistics."""
        try:
            stats = self.strategy_stats[strategy_id]
            if success:
                stats['success_count'] += 1
            else:
                stats['failure_count'] += 1
            stats['total_time'] += execution_time
            stats['last_used'] = datetime.now()
            stats['effectiveness_history'].append(effectiveness_score)
            domain_key = f'{domain}:{strategy_id}'
            if domain_key not in self.domain_strategy_mapping:
                self.domain_strategy_mapping[domain_key] = {'success_count': 0, 'failure_count': 0, 'success_rate': 0.0}
            domain_stats = self.domain_strategy_mapping[domain_key]
            if success:
                domain_stats['success_count'] += 1
            else:
                domain_stats['failure_count'] += 1
            total = domain_stats['success_count'] + domain_stats['failure_count']
            domain_stats['success_rate'] = domain_stats['success_count'] / max(total, 1)
            self.logger.debug(f'Updated performance for strategy {strategy_id} on domain {domain}')
        except Exception as e:
            self.logger.error(f'Error updating strategy performance: {e}')

    async def get_strategy_recommendations(self, domain: str) -> List[Dict[str, Any]]:
        """Get strategy recommendations for a domain."""
        try:
            recommendations = []
            all_strategies = list(self.strategy_stats.keys())
            for strategy_id in all_strategies:
                stats = self.strategy_stats[strategy_id]
                total_attempts = stats['success_count'] + stats['failure_count']
                if total_attempts > 0:
                    success_rate = stats['success_count'] / total_attempts
                    avg_time = stats['total_time'] / total_attempts
                    recommendation = {'strategy_id': strategy_id, 'success_rate': success_rate, 'average_time': avg_time, 'total_uses': total_attempts, 'last_used': stats['last_used'], 'effectiveness_score': await self._calculate_strategy_score(strategy_id, domain)}
                    recommendations.append(recommendation)
            recommendations.sort(key=lambda x: x['effectiveness_score'], reverse=True)
            return recommendations
        except Exception as e:
            self.logger.error(f'Error getting strategy recommendations: {e}')
            return []

    async def optimize_algorithm_parameters(self) -> Dict[str, Any]:
        """Optimize algorithm parameters based on historical performance."""
        try:
            optimization_results = {}
            level_performance = {}
            for level in OptimizationLevel:
                temp_weights = {OptimizationLevel.CONSERVATIVE: {'success_rate': 0.5, 'execution_time': 0.2, 'stability': 0.3}, OptimizationLevel.BALANCED: {'success_rate': 0.4, 'execution_time': 0.3, 'stability': 0.3}, OptimizationLevel.AGGRESSIVE: {'success_rate': 0.6, 'execution_time': 0.3, 'stability': 0.1}, OptimizationLevel.MAXIMUM: {'success_rate': 0.7, 'execution_time': 0.3, 'stability': 0.0}}[level]
                avg_success_rate = self._calculate_average_success_rate()
                avg_execution_time = self._calculate_average_execution_time()
                theoretical_score = avg_success_rate * temp_weights['success_rate'] + 1.0 / (1.0 + avg_execution_time) * temp_weights['execution_time'] + 0.7 * temp_weights['stability']
                level_performance[level.value] = theoretical_score
            optimal_level = max(level_performance.items(), key=lambda x: x[1])
            optimization_results = {'recommended_optimization_level': optimal_level[0], 'level_scores': level_performance, 'current_level': self.optimization_level.value, 'improvement_potential': optimal_level[1] - level_performance[self.optimization_level.value], 'parameter_recommendations': self._generate_parameter_recommendations()}
            return optimization_results
        except Exception as e:
            self.logger.error(f'Error optimizing algorithm parameters: {e}')
            return {}

    def _calculate_average_success_rate(self) -> float:
        """Calculate average success rate across all strategies."""
        if not self.strategy_stats:
            return 0.8
        total_success = sum((stats['success_count'] for stats in self.strategy_stats.values()))
        total_attempts = sum((stats['success_count'] + stats['failure_count'] for stats in self.strategy_stats.values()))
        return total_success / max(total_attempts, 1)

    def _calculate_average_execution_time(self) -> float:
        """Calculate average execution time across all strategies."""
        if not self.strategy_stats:
            return 1.0
        total_time = sum((stats['total_time'] for stats in self.strategy_stats.values()))
        total_attempts = sum((stats['success_count'] + stats['failure_count'] for stats in self.strategy_stats.values()))
        return total_time / max(total_attempts, 1)

    def _generate_parameter_recommendations(self) -> List[str]:
        """Generate parameter optimization recommendations."""
        recommendations = []
        avg_success_rate = self._calculate_average_success_rate()
        avg_execution_time = self._calculate_average_execution_time()
        if avg_success_rate < 0.7:
            recommendations.append('Increase success_rate weight in optimization')
        if avg_execution_time > 2.0:
            recommendations.append('Increase execution_time weight to prioritize faster strategies')
        if len(self.strategy_stats) > 50:
            recommendations.append('Consider pruning underperforming strategies')
        return recommendations

    async def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary for all strategies."""
        try:
            summary = {'total_strategies': len(self.strategy_stats), 'optimization_level': self.optimization_level.value, 'average_success_rate': self._calculate_average_success_rate(), 'average_execution_time': self._calculate_average_execution_time(), 'top_strategies': [], 'underperforming_strategies': []}
            strategy_performances = []
            for strategy_id, stats in self.strategy_stats.items():
                total_attempts = stats['success_count'] + stats['failure_count']
                if total_attempts > 0:
                    success_rate = stats['success_count'] / total_attempts
                    avg_time = stats['total_time'] / total_attempts
                    strategy_performances.append({'strategy_id': strategy_id, 'success_rate': success_rate, 'average_time': avg_time, 'total_uses': total_attempts})
            strategy_performances.sort(key=lambda x: x['success_rate'], reverse=True)
            summary['top_strategies'] = strategy_performances[:5]
            summary['underperforming_strategies'] = strategy_performances[-5:]
            return summary
        except Exception as e:
            self.logger.error(f'Error getting performance summary: {e}')
            return {}