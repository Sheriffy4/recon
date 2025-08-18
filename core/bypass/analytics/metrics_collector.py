"""
Metrics collection system for bypass engine analytics
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import asdict

from .analytics_models import (
    AttackMetrics, StrategyMetrics, DomainAnalytics,
    MetricType, TrendDirection, RealtimeMetrics
)


class MetricsCollector:
    """Collects and stores metrics for analytics"""
    
    def __init__(self, db_path: str = "analytics.db"):
        self.db_path = db_path
        self.attack_metrics: Dict[str, AttackMetrics] = {}
        self.strategy_metrics: Dict[str, StrategyMetrics] = {}
        self.domain_analytics: Dict[str, DomainAnalytics] = {}
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for metrics storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_metrics (
                attack_id TEXT PRIMARY KEY,
                success_count INTEGER,
                failure_count INTEGER,
                total_attempts INTEGER,
                avg_response_time REAL,
                reliability_score REAL,
                last_success TEXT,
                last_failure TEXT,
                updated_at TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS strategy_metrics (
                strategy_id TEXT PRIMARY KEY,
                domain_count INTEGER,
                successful_domains INTEGER,
                failed_domains INTEGER,
                avg_effectiveness REAL,
                trend_direction TEXT,
                last_updated TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_analytics (
                domain TEXT,
                port INTEGER,
                successful_strategies TEXT,
                failed_strategies TEXT,
                best_strategy TEXT,
                avg_success_rate REAL,
                last_tested TEXT,
                test_history TEXT,
                PRIMARY KEY (domain, port)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metric_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id TEXT,
                metric_type TEXT,
                value REAL,
                timestamp TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def record_attack_result(self, attack_id: str, success: bool, 
                                 response_time: float, domain: str = None):
        """Record result of attack execution"""
        if attack_id not in self.attack_metrics:
            self.attack_metrics[attack_id] = AttackMetrics(attack_id=attack_id)
        
        metrics = self.attack_metrics[attack_id]
        metrics.update_metrics(success, response_time)
        
        # Store in database
        await self._store_attack_metrics(attack_id, metrics)
        
        # Record in history
        await self._record_metric_history(
            attack_id, MetricType.SUCCESS_RATE, metrics.success_rate
        )
        await self._record_metric_history(
            attack_id, MetricType.RESPONSE_TIME, response_time
        )
    
    async def record_strategy_result(self, strategy_id: str, domain: str, 
                                   success: bool, effectiveness: float):
        """Record result of strategy application"""
        if strategy_id not in self.strategy_metrics:
            self.strategy_metrics[strategy_id] = StrategyMetrics(strategy_id=strategy_id)
        
        metrics = self.strategy_metrics[strategy_id]
        metrics.domain_count += 1
        if success:
            metrics.successful_domains += 1
        else:
            metrics.failed_domains += 1
        
        # Update average effectiveness
        metrics.avg_effectiveness = (
            (metrics.avg_effectiveness * (metrics.domain_count - 1) + effectiveness)
            / metrics.domain_count
        )
        metrics.last_updated = datetime.now()
        
        # Store in database
        await self._store_strategy_metrics(strategy_id, metrics)
        
        # Record domain analytics
        await self._update_domain_analytics(domain, strategy_id, success, effectiveness)
    
    async def _update_domain_analytics(self, domain: str, strategy_id: str, 
                                     success: bool, effectiveness: float):
        """Update analytics for specific domain"""
        key = f"{domain}:443"  # Default to HTTPS port
        if key not in self.domain_analytics:
            self.domain_analytics[key] = DomainAnalytics(domain=domain, port=443)
        
        analytics = self.domain_analytics[key]
        
        if success:
            if strategy_id not in analytics.successful_strategies:
                analytics.successful_strategies.append(strategy_id)
            # Update best strategy if this one is better
            if not analytics.best_strategy or effectiveness > analytics.avg_success_rate:
                analytics.best_strategy = strategy_id
        else:
            if strategy_id not in analytics.failed_strategies:
                analytics.failed_strategies.append(strategy_id)
        
        # Update average success rate
        total_tests = len(analytics.successful_strategies) + len(analytics.failed_strategies)
        if total_tests > 0:
            analytics.avg_success_rate = len(analytics.successful_strategies) / total_tests
        
        analytics.last_tested = datetime.now()
        
        # Add to test history
        analytics.test_history.append({
            'timestamp': datetime.now().isoformat(),
            'strategy_id': strategy_id,
            'success': success,
            'effectiveness': effectiveness
        })
        
        # Keep only last 100 test results
        if len(analytics.test_history) > 100:
            analytics.test_history = analytics.test_history[-100:]
        
        # Store in database
        await self._store_domain_analytics(key, analytics)
    
    async def _store_attack_metrics(self, attack_id: str, metrics: AttackMetrics):
        """Store attack metrics in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO attack_metrics 
            (attack_id, success_count, failure_count, total_attempts, 
             avg_response_time, reliability_score, last_success, last_failure, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            attack_id, metrics.success_count, metrics.failure_count,
            metrics.total_attempts, metrics.avg_response_time, metrics.reliability_score,
            metrics.last_success.isoformat() if metrics.last_success else None,
            metrics.last_failure.isoformat() if metrics.last_failure else None,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _store_strategy_metrics(self, strategy_id: str, metrics: StrategyMetrics):
        """Store strategy metrics in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO strategy_metrics 
            (strategy_id, domain_count, successful_domains, failed_domains,
             avg_effectiveness, trend_direction, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            strategy_id, metrics.domain_count, metrics.successful_domains,
            metrics.failed_domains, metrics.avg_effectiveness,
            metrics.trend_direction.value, metrics.last_updated.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _store_domain_analytics(self, key: str, analytics: DomainAnalytics):
        """Store domain analytics in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO domain_analytics 
            (domain, port, successful_strategies, failed_strategies, best_strategy,
             avg_success_rate, last_tested, test_history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analytics.domain, analytics.port,
            json.dumps(analytics.successful_strategies),
            json.dumps(analytics.failed_strategies),
            analytics.best_strategy, analytics.avg_success_rate,
            analytics.last_tested.isoformat() if analytics.last_tested else None,
            json.dumps(analytics.test_history)
        ))
        
        conn.commit()
        conn.close()
    
    async def _record_metric_history(self, entity_id: str, metric_type: MetricType, value: float):
        """Record metric value in history table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO metric_history (entity_id, metric_type, value, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (entity_id, metric_type.value, value, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    async def get_attack_metrics(self, attack_id: str) -> Optional[AttackMetrics]:
        """Get metrics for specific attack"""
        if attack_id in self.attack_metrics:
            return self.attack_metrics[attack_id]
        
        # Load from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT * FROM attack_metrics WHERE attack_id = ?', (attack_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            metrics = AttackMetrics(
                attack_id=row[0],
                success_count=row[1],
                failure_count=row[2],
                total_attempts=row[3],
                avg_response_time=row[4],
                reliability_score=row[5],
                last_success=datetime.fromisoformat(row[6]) if row[6] else None,
                last_failure=datetime.fromisoformat(row[7]) if row[7] else None
            )
            self.attack_metrics[attack_id] = metrics
            return metrics
        
        return None
    
    async def get_strategy_metrics(self, strategy_id: str) -> Optional[StrategyMetrics]:
        """Get metrics for specific strategy"""
        if strategy_id in self.strategy_metrics:
            return self.strategy_metrics[strategy_id]
        
        # Load from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT * FROM strategy_metrics WHERE strategy_id = ?', (strategy_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            metrics = StrategyMetrics(
                strategy_id=row[0],
                domain_count=row[1],
                successful_domains=row[2],
                failed_domains=row[3],
                avg_effectiveness=row[4],
                trend_direction=TrendDirection(row[5]),
                last_updated=datetime.fromisoformat(row[6])
            )
            self.strategy_metrics[strategy_id] = metrics
            return metrics
        
        return None
    
    async def get_realtime_metrics(self) -> RealtimeMetrics:
        """Get current real-time metrics"""
        now = datetime.now()
        
        # Calculate overall statistics
        total_attacks = len(self.attack_metrics)
        total_strategies = len(self.strategy_metrics)
        
        # Calculate overall success rate
        total_successes = sum(m.success_count for m in self.attack_metrics.values())
        total_attempts = sum(m.total_attempts for m in self.attack_metrics.values())
        overall_success_rate = total_successes / total_attempts if total_attempts > 0 else 0.0
        
        # Calculate average response time
        response_times = [m.avg_response_time for m in self.attack_metrics.values() if m.avg_response_time > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0.0
        
        # Calculate system health (simplified)
        system_health = min(overall_success_rate * 1.2, 1.0)
        
        # Get recent failures
        recent_failures = []
        for attack_id, metrics in self.attack_metrics.items():
            if metrics.last_failure and (now - metrics.last_failure).seconds < 3600:  # Last hour
                recent_failures.append({
                    'attack_id': attack_id,
                    'timestamp': metrics.last_failure.isoformat(),
                    'failure_rate': metrics.failure_count / metrics.total_attempts if metrics.total_attempts > 0 else 0
                })
        
        # Get top performing attacks and strategies
        top_attacks = sorted(
            self.attack_metrics.items(),
            key=lambda x: x[1].success_rate,
            reverse=True
        )[:5]
        
        top_strategies = sorted(
            self.strategy_metrics.items(),
            key=lambda x: x[1].success_rate,
            reverse=True
        )[:5]
        
        return RealtimeMetrics(
            timestamp=now,
            active_attacks=total_attacks,
            active_strategies=total_strategies,
            overall_success_rate=overall_success_rate,
            avg_response_time=avg_response_time,
            system_health=system_health,
            recent_failures=recent_failures[:10],  # Last 10 failures
            top_performing_attacks=[attack_id for attack_id, _ in top_attacks],
            top_performing_strategies=[strategy_id for strategy_id, _ in top_strategies]
        )
    
    async def get_metric_history(self, entity_id: str, metric_type: MetricType, 
                               hours: int = 24) -> List[Dict[str, Any]]:
        """Get historical data for specific metric"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        
        cursor.execute('''
            SELECT value, timestamp FROM metric_history 
            WHERE entity_id = ? AND metric_type = ? AND timestamp > ?
            ORDER BY timestamp
        ''', (entity_id, metric_type.value, since.isoformat()))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {'value': row[0], 'timestamp': row[1]}
            for row in rows
        ]
    
    async def cleanup_old_data(self, days: int = 30):
        """Clean up old metric data"""
        cutoff = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'DELETE FROM metric_history WHERE timestamp < ?',
            (cutoff.isoformat(),)
        )
        
        conn.commit()
        conn.close()