"""
Simple test script for performance optimization features.
"""

import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

from recon.core.bypass.performance.performance_optimizer import PerformanceOptimizer
from recon.core.bypass.performance.strategy_optimizer import StrategyOptimizer
from recon.core.bypass.performance.production_monitor import ProductionMonitor
from recon.core.bypass.performance.alerting_system import AlertingSystem
from recon.core.bypass.performance.performance_models import (
    OptimizationLevel, ProductionConfig, AlertSeverity, Alert
)


async def test_performance_optimizer():
    """Test performance optimizer functionality."""
    print("Testing Performance Optimizer...")
    
    try:
        optimizer = PerformanceOptimizer(OptimizationLevel.BALANCED)
        
        # Test metrics collection
        metrics = await optimizer.collect_performance_metrics()
        print(f"✅ Metrics collected: CPU {metrics.cpu_usage:.1f}%, Memory {metrics.memory_usage:.1f}%")
        
        # Test optimization
        result = await optimizer.optimize_performance(metrics)
        print(f"✅ Optimization completed: {result.improvement_percentage:.2f}% improvement")
        
        # Test system health
        health = await optimizer.get_system_health()
        print(f"✅ System health: Load {health.system_load:.2f}, Uptime {health.uptime/3600:.1f}h")
        
        return True
        
    except Exception as e:
        print(f"❌ Performance Optimizer test failed: {e}")
        return False


async def test_strategy_optimizer():
    """Test strategy optimizer functionality."""
    print("\nTesting Strategy Optimizer...")
    
    try:
        optimizer = StrategyOptimizer(OptimizationLevel.BALANCED)
        
        # Add test data
        await optimizer.update_strategy_performance(
            "test_strategy", "example.com", True, 1.0, 0.8
        )
        print("✅ Strategy performance updated")
        
        # Test strategy selection
        strategies = ["tcp_fragmentation", "http_manipulation", "tls_evasion"]
        selected = await optimizer.optimize_strategy_selection("example.com", strategies)
        print(f"✅ Strategy selected: {selected}")
        
        # Test recommendations
        recommendations = await optimizer.get_strategy_recommendations("example.com")
        print(f"✅ Got {len(recommendations)} strategy recommendations")
        
        # Test parameter optimization
        params = await optimizer.optimize_algorithm_parameters()
        print(f"✅ Algorithm parameters optimized: {params.get('current_level', 'unknown')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Strategy Optimizer test failed: {e}")
        return False


async def test_production_monitor():
    """Test production monitor functionality."""
    print("\nTesting Production Monitor...")
    
    try:
        config = ProductionConfig(
            optimization_level=OptimizationLevel.BALANCED,
            max_concurrent_attacks=10,
            resource_limits={'max_cpu_usage': 70.0},
            monitoring_interval=60,
            alert_thresholds={'cpu_critical': 90.0},
            auto_scaling_enabled=False,
            backup_enabled=False,
            logging_level='INFO',
            performance_targets={}
        )
        
        monitor = ProductionMonitor(config)
        
        # Test alert creation
        await monitor._create_alert(
            AlertSeverity.INFO,
            "Test Alert",
            "This is a test alert",
            "test_component",
            {"test": True}
        )
        print("✅ Alert created successfully")
        
        # Test alert retrieval
        alerts = await monitor.get_active_alerts()
        print(f"✅ Retrieved {len(alerts)} active alerts")
        
        # Test monitoring status
        status = await monitor.get_monitoring_status()
        print(f"✅ Monitoring status: {len(status)} status items")
        
        return True
        
    except Exception as e:
        print(f"❌ Production Monitor test failed: {e}")
        return False


async def test_alerting_system():
    """Test alerting system functionality."""
    print("\nTesting Alerting System...")
    
    try:
        # Create temporary log file
        import tempfile
        fd, temp_log = tempfile.mkstemp(suffix='.log')
        os.close(fd)
        
        try:
            config = {
                'email': {'enabled': False},
                'webhook': {'enabled': False},
                'file': {'enabled': True, 'log_file': temp_log}
            }
            
            alerting = AlertingSystem(config)
            
            # Test alert sending
            alert = Alert(
                id="test_alert",
                severity=AlertSeverity.WARNING,
                title="Test Alert",
                message="This is a test alert",
                component="test",
                metrics={"test": True}
            )
            
            await alerting.send_alert(alert)
            print("✅ Alert sent successfully")
            
            # Test notification channels
            results = await alerting.test_notifications()
            print(f"✅ Notification test results: {results}")
            
            # Test configuration
            config_info = alerting.get_configuration()
            print(f"✅ Configuration retrieved: {len(config_info)} items")
            
            return True
            
        finally:
            os.unlink(temp_log)
        
    except Exception as e:
        print(f"❌ Alerting System test failed: {e}")
        return False


async def main():
    """Run all tests."""
    print("🚀 Starting Performance Optimization Simple Tests")
    print("=" * 60)
    
    tests = [
        test_performance_optimizer,
        test_strategy_optimizer,
        test_production_monitor,
        test_alerting_system
    ]
    
    results = []
    for test in tests:
        result = await test()
        results.append(result)
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary:")
    
    passed = sum(results)
    total = len(results)
    
    print(f"✅ Passed: {passed}/{total}")
    print(f"❌ Failed: {total - passed}/{total}")
    
    if all(results):
        print("\n🎉 All tests passed! Performance optimization system is working correctly.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please check the implementation.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)