"""
Data models for analytics and reporting system
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class MetricType(Enum):
    SUCCESS_RATE = "success_rate"
    RESPONSE_TIME = "response_time"
    RELIABILITY_SCORE = "reliability_score"
    ATTACK_EFFECTIVENESS = "attack_effectiveness"
    STRATEGY_PERFORMANCE = "strategy_performance"


class TrendDirection(Enum):
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    VOLATILE = "volatile"


@dataclass
class AttackMetrics:
    """Metrics for individual attack performance"""
    attack_id: str
    success_count: int = 0
    failure_count: int = 0
    total_attempts: int = 0
    avg_response_time: float = 0.0
    reliability_score: float = 0.0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    
    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.success_count / self.total_attempts
    
    def update_metrics(self, success: bool, response_time: float):
        """Update metrics with new test result"""
        self.total_attempts += 1
        if success:
            self.success_count += 1
            self.last_success = datetime.now()
        else:
            self.failure_count += 1
            self.last_failure = datetime.now()
        
        # Update average response time
        self.avg_response_time = (
            (self.avg_response_time * (self.total_attempts - 1) + response_time) 
            / self.total_attempts
        )


@dataclass
class StrategyMetrics:
    """Metrics for strategy performance"""
    strategy_id: str
    domain_count: int = 0
    successful_domains: int = 0
    failed_domains: int = 0
    avg_effectiveness: float = 0.0
    trend_direction: TrendDirection = TrendDirection.STABLE
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        if self.domain_count == 0:
            return 0.0
        return self.successful_domains / self.domain_count


@dataclass
class DomainAnalytics:
    """Analytics data for specific domain"""
    domain: str
    port: int
    successful_strategies: List[str] = field(default_factory=list)
    failed_strategies: List[str] = field(default_factory=list)
    best_strategy: Optional[str] = None
    avg_success_rate: float = 0.0
    last_tested: Optional[datetime] = None
    test_history: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PerformanceTrend:
    """Performance trend data over time"""
    metric_type: MetricType
    entity_id: str  # attack_id, strategy_id, or domain
    timestamps: List[datetime] = field(default_factory=list)
    values: List[float] = field(default_factory=list)
    trend_direction: TrendDirection = TrendDirection.STABLE
    trend_strength: float = 0.0  # 0-1, how strong the trend is
    
    def add_data_point(self, timestamp: datetime, value: float):
        """Add new data point to trend"""
        self.timestamps.append(timestamp)
        self.values.append(value)
        self._calculate_trend()
    
    def _calculate_trend(self):
        """Calculate trend direction and strength"""
        if len(self.values) < 3:
            return
        
        # Simple linear trend calculation
        recent_values = self.values[-10:]  # Last 10 points
        if len(recent_values) < 3:
            return
        
        # Calculate slope
        x = list(range(len(recent_values)))
        y = recent_values
        n = len(x)
        
        slope = (n * sum(x[i] * y[i] for i in range(n)) - sum(x) * sum(y)) / (n * sum(x[i]**2 for i in range(n)) - sum(x)**2)
        
        # Determine trend direction
        if abs(slope) < 0.01:
            self.trend_direction = TrendDirection.STABLE
        elif slope > 0:
            self.trend_direction = TrendDirection.IMPROVING
        else:
            self.trend_direction = TrendDirection.DECLINING
        
        # Calculate trend strength (normalized)
        self.trend_strength = min(abs(slope) * 10, 1.0)


@dataclass
class PredictionResult:
    """ML prediction result"""
    entity_id: str
    metric_type: MetricType
    predicted_value: float
    confidence: float
    prediction_horizon: int  # hours into future
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class AnalyticsReport:
    """Comprehensive analytics report"""
    report_id: str
    generated_at: datetime
    time_period: Dict[str, datetime]  # start, end
    attack_analytics: Dict[str, AttackMetrics]
    strategy_analytics: Dict[str, StrategyMetrics]
    domain_analytics: Dict[str, DomainAnalytics]
    performance_trends: List[PerformanceTrend]
    predictions: List[PredictionResult]
    summary_stats: Dict[str, Any]
    recommendations: List[str]


@dataclass
class RealtimeMetrics:
    """Real-time metrics for dashboard"""
    timestamp: datetime
    active_attacks: int
    active_strategies: int
    overall_success_rate: float
    avg_response_time: float
    system_health: float  # 0-1 score
    recent_failures: List[Dict[str, Any]]
    top_performing_attacks: List[str]
    top_performing_strategies: List[str]