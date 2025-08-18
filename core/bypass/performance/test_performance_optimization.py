"""
Test suite for performance optimization and production readiness features.
"""

import asyncio
import pytest
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

from .performance_optimizer import PerformanceOptimizer
from .strategy_optimizer import StrategyOptimizer
from .production_monitor import ProductionMonitor
from .alerting_system import AlertingSystem
from .performance_models import (
    OptimizationLevel, ProductionConfig, AlertSeverity,
    PerformanceMetrics, SystemHealth, Alert
)


class TestPerformanceOptimizer:
    """Test cases for PerformanceOptimizer."""
    
    @pytest.fixture
    def optimizer(self):
        return PerformanceOptimizer(OptimizationLevel.BALANCED)
    
    @pytest.mark.asyncio
    async def test_collect_performance_metrics(self, optimizer):
        """Test performance metrics collection."""
        with patch('psutil.cpu_percent', return_value=50.0), \
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.net_io_counters') as mock_network:
            
            mock_memory.return_value.percent = 60.0
            mock_network.return_value = Mock()
            
            metrics = await optimizer.collect_performance_metrics()
            
            assert isinstance(metrics, PerformanceMetrics)
            assert metrics.cpu_usage == 50.0
            assert metrics.memory_usage == 60.0
            assert metrics.attack_execution_time >= 0
            assert metrics.strategy_selection_time >= 0
    
    @pytest.mark.asyncio
    async def test_optimize_performance(self, optimizer):
        """Test performance optimization."""
        # Create metrics that need optimization
        metrics = PerformanceMetrics(
            attack_execution_time=2.0,
            strategy_selection_time=0.2,
            validation_time=1.0,
            memory_usage=80.0,  # High memory usage
            cpu_usage=85.0,     # High CPU usage
            success_rate=60.0,  # Low success rate
            throughput=5.0,
            latency=6.0         # High latency
        )
        
        result = await optimizer.optimize_performance(metrics)
        
        assert isinstance(result, type(result))
        assert len(result.optimization_actions) > 0
        assert result.improvement_percentage >= 0
    
    @pytest.mark.asyncio
    async def test_get_system_health(self, optimizer):
        """Test system health retrieval."""
        with patch('psutil.cpu_percent', return_value=45.0), \
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.disk_usage') as mock_disk, \
             patch('time.time', return_value=1000000), \
             patch('psutil.boot_time', return_value=999000):
            
            mock_memory.return_value.percent = 55.0
            mock_disk.return_value.percent = 30.0
            
            health = await optimizer.get_system_health()
            
            assert isinstance(health, SystemHealth)
            assert health.cpu_usage == 45.0
            assert health.memory_usage == 55.0
            assert health.disk_usage == 30.0
            assert health.uptime == 1000.0


class TestStrategyOptimizer:
    """Test cases for StrategyOptimizer."""
    
    @pytest.fixture
    def optimizer(self):
        return StrategyOptimizer(OptimizationLevel.BALANCED)
    
    @pytest.mark.asyncio
    async def test_optimize_strategy_selection(self, optimizer):
        """Test strategy selection optimization."""
        domain = "example.com"
        strategies = ["tcp_fragmentation", "http_manipulation", "tls_evasion"]
        
        # Add some performance data
        await optimizer.update_strategy_performance(
            "tcp_fragmentation", domain, True, 1.0, 0.8
        )
        await optimizer.update_strategy_performance(
            "http_manipulation", domain, True, 0.5, 0.9
        )
        
        selected = await optimizer.optimize_strategy_selection(domain, strategies)
        
        assert selected in strategies
    
    @pytest.mark.asyncio
    async def test_update_strategy_performance(self, optimizer):
        """Test strategy performance updates."""
        strategy_id = "test_strategy"
        domain = "test.com"
        
        await optimizer.update_strategy_performance(
            strategy_id, domain, True, 1.5, 0.85
        )
        
        stats = optimizer.strategy_stats[strategy_id]
        assert stats['success_count'] == 1
        assert stats['failure_count'] == 0
        assert stats['total_time'] == 1.5
        assert len(stats['effectiveness_history']) == 1
    
    @pytest.mark.asyncio
    async def test_get_strategy_recommendations(self, optimizer):
        """Test strategy recommendations."""
        domain = "example.com"
        
        # Add performance data for multiple strategies
        strategies = ["strategy1", "strategy2", "strategy3"]
        for i, strategy in enumerate(strategies):
            await optimizer.update_strategy_performance(
                strategy, domain, True, 1.0 + i * 0.5, 0.8 + i * 0.05
            )
        
        recommendations = await optimizer.get_strategy_recommendations(domain)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) == len(strategies)
        
        # Check that recommendations are sorted by effectiveness
        if len(recommendations) > 1:
            assert (recommendations[0]['effectiveness_score'] >= 
                   recommendations[1]['effectiveness_score'])
    
    @pytest.mark.asyncio
    async def test_optimize_algorithm_parameters(self, optimizer):
        """Test algorithm parameter optimization."""
        # Add some performance data
        await optimizer.update_strategy_performance(
            "test_strategy", "test.com", True, 1.0, 0.8
        )
        
        result = await optimizer.optimize_algorithm_parameters()
        
        assert isinstance(result, dict)
        assert 'recommended_optimization_level' in result
        assert 'level_scores' in result
        assert 'current_level' in result


class TestProductionMonitor:
    """Test cases for ProductionMonitor."""
    
    @pytest.fixture
    def config(self):
        return ProductionConfig(
            optimization_level=OptimizationLevel.BALANCED,
            max_concurrent_attacks=10,
            resource_limits={'max_cpu_usage': 70.0},
            monitoring_interval=1,  # Short interval for testing
            alert_thresholds={
                'cpu_critical': 90.0,
                'memory_critical': 85.0
            },
            auto_scaling_enabled=False,
            backup_enabled=False,
            logging_level='INFO',
            performance_targets={}
        )
    
    @pytest.fixture
    def monitor(self, config):
        return ProductionMonitor(config)
    
    @pytest.mark.asyncio
    async def test_create_alert(self, monitor):
        """Test alert creation."""
        await monitor._create_alert(
            AlertSeverity.WARNING,
            "Test Alert",
            "This is a test alert",
            "test_component",
            {"test_metric": 100}
        )
        
        assert len(monitor.alerts) == 1
        alert = monitor.alerts[0]
        assert alert.severity == AlertSeverity.WARNING
        assert alert.title == "Test Alert"
        assert alert.component == "test_component"
    
    @pytest.mark.asyncio
    async def test_get_active_alerts(self, monitor):
        """Test getting active alerts."""
        # Create test alert
        await monitor._create_alert(
            AlertSeverity.ERROR,
            "Active Alert",
            "This is an active alert",
            "test",
            {}
        )
        
        active_alerts = await monitor.get_active_alerts()
        
        assert len(active_alerts) == 1
        assert active_alerts[0].title == "Active Alert"
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert(self, monitor):
        """Test alert acknowledgment."""
        # Create test alert
        await monitor._create_alert(
            AlertSeverity.INFO,
            "Test Alert",
            "Test message",
            "test",
            {}
        )
        
        alert_id = monitor.alerts[0].id
        result = await monitor.acknowledge_alert(alert_id)
        
        assert result is True
        assert monitor.alerts[0].acknowledged is True
    
    @pytest.mark.asyncio
    async def test_resolve_alert(self, monitor):
        """Test alert resolution."""
        # Create test alert
        await monitor._create_alert(
            AlertSeverity.WARNING,
            "Resolvable Alert",
            "Test message",
            "test",
            {}
        )
        
        alert_id = monitor.alerts[0].id
        result = await monitor.resolve_alert(alert_id)
        
        assert result is True
        assert monitor.alerts[0].resolved is True


class TestAlertingSystem:
    """Test cases for AlertingSystem."""
    
    @pytest.fixture
    def temp_log_file(self):
        """Create temporary log file for testing."""
        fd, path = tempfile.mkstemp(suffix='.log')
        os.close(fd)
        yield path
        os.unlink(path)
    
    @pytest.fixture
    def alerting_config(self, temp_log_file):
        return {
            'email': {'enabled': False},
            'webhook': {'enabled': False},
            'file': {
                'enabled': True,
                'log_file': temp_log_file
            }
        }
    
    @pytest.fixture
    def alerting_system(self, alerting_config):
        return AlertingSystem(alerting_config)
    
    @pytest.mark.asyncio
    async def test_send_alert(self, alerting_system, temp_log_file):
        """Test alert sending."""
        alert = Alert(
            id="test_alert",
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="This is a test alert",
            component="test",
            metrics={"test": True}
        )
        
        await alerting_system.send_alert(alert)
        
        # Check that alert was logged to file
        with open(temp_log_file, 'r') as f:
            content = f.read()
            assert "Test Alert" in content
            assert "WARNING" in content
    
    def test_add_suppression_rule(self, alerting_system):
        """Test adding suppression rules."""
        rule = {
            'component': 'test',
            'severity': 'warning'
        }
        
        alerting_system.add_suppression_rule('test_rule', rule)
        
        assert 'test_rule' in alerting_system.suppression_rules
        assert alerting_system.suppression_rules['test_rule'] == rule
    
    def test_add_escalation_rule(self, alerting_system):
        """Test adding escalation rules."""
        rule = {
            'severity': 'warning',
            'title_prefix': '[ESCALATED]'
        }
        
        alerting_system.add_escalation_rule('escalation_rule', rule)
        
        assert 'escalation_rule' in alerting_system.escalation_rules
        assert alerting_system.escalation_rules['escalation_rule'] == rule
    
    @pytest.mark.asyncio
    async def test_log_to_file(self, alerting_system, temp_log_file):
        """Test file logging functionality."""
        alert = Alert(
            id="file_test",
            severity=AlertSeverity.ERROR,
            title="File Test Alert",
            message="Testing file logging",
            component="file_test",
            metrics={"file_test": True}
        )
        
        await alerting_system._log_to_file(alert)
        
        # Verify file content
        with open(temp_log_file, 'r') as f:
            content = f.read()
            assert "File Test Alert" in content
            assert "ERROR" in content
            assert "file_test" in content
    
    @pytest.mark.asyncio
    async def test_test_notifications(self, alerting_system):
        """Test notification channel testing."""
        results = await alerting_system.test_notifications()
        
        assert isinstance(results, dict)
        assert 'file' in results  # File logging should be enabled
        assert results['file'] is True  # Should succeed
    
    def test_get_configuration(self, alerting_system):
        """Test configuration retrieval."""
        config = alerting_system.get_configuration()
        
        assert isinstance(config, dict)
        assert 'config' in config
        assert 'suppression_rules' in config
        assert 'escalation_rules' in config
        assert 'notification_channels' in config


class TestIntegration:
    """Integration tests for performance optimization components."""
    
    @pytest.mark.asyncio
    async def test_full_optimization_workflow(self):
        """Test complete optimization workflow."""
        # Initialize components
        optimizer = PerformanceOptimizer(OptimizationLevel.BALANCED)
        strategy_optimizer = StrategyOptimizer(OptimizationLevel.BALANCED)
        
        # Collect metrics
        metrics = await optimizer.collect_performance_metrics()
        assert isinstance(metrics, PerformanceMetrics)
        
        # Optimize performance
        result = await optimizer.optimize_performance(metrics)
        assert result.improvement_percentage >= 0
        
        # Optimize strategy selection
        strategies = ["tcp_fragmentation", "http_manipulation"]
        selected = await strategy_optimizer.optimize_strategy_selection(
            "example.com", strategies
        )
        assert selected in strategies
    
    @pytest.mark.asyncio
    async def test_monitoring_and_alerting_integration(self):
        """Test monitoring and alerting integration."""
        # Setup configuration
        config = ProductionConfig(
            optimization_level=OptimizationLevel.BALANCED,
            max_concurrent_attacks=5,
            resource_limits={},
            monitoring_interval=1,
            alert_thresholds={'cpu_critical': 90.0},
            auto_scaling_enabled=False,
            backup_enabled=False,
            logging_level='INFO',
            performance_targets={}
        )
        
        # Create temporary log file
        fd, temp_log = tempfile.mkstemp(suffix='.log')
        os.close(fd)
        
        try:
            # Initialize components
            monitor = ProductionMonitor(config)
            alerting_config = {
                'file': {'enabled': True, 'log_file': temp_log}
            }
            alerting_system = AlertingSystem(alerting_config)
            
            # Setup alert callback
            async def alert_callback(alert):
                await alerting_system.send_alert(alert)
            
            monitor.add_alert_callback(alert_callback)
            
            # Create test alert
            await monitor._create_alert(
                AlertSeverity.WARNING,
                "Integration Test",
                "Testing integration",
                "integration_test",
                {}
            )
            
            # Verify alert was processed
            assert len(monitor.alerts) == 1
            
            # Check file logging
            with open(temp_log, 'r') as f:
                content = f.read()
                assert "Integration Test" in content
        
        finally:
            os.unlink(temp_log)


# Test runner
if __name__ == "__main__":
    pytest.main([__file__, "-v"])