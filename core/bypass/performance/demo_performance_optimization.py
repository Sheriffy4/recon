"""
Demo script for performance optimization and production readiness features.
"""

import asyncio
import logging
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

from core.bypass.performance.performance_optimizer import PerformanceOptimizer
from core.bypass.performance.strategy_optimizer import StrategyOptimizer
from core.bypass.performance.production_monitor import ProductionMonitor
from core.bypass.performance.alerting_system import AlertingSystem
from core.bypass.performance.performance_models import (
    OptimizationLevel,
    ProductionConfig,
    AlertSeverity,
    Alert,
)


class PerformanceOptimizationDemo:
    """Demo class for performance optimization features."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.setup_logging()

        # Initialize components
        self.performance_optimizer = PerformanceOptimizer(OptimizationLevel.BALANCED)
        self.strategy_optimizer = StrategyOptimizer(OptimizationLevel.BALANCED)

        # Production configuration
        self.production_config = ProductionConfig(
            optimization_level=OptimizationLevel.BALANCED,
            max_concurrent_attacks=20,
            resource_limits={
                "max_cpu_usage": 70.0,
                "max_memory_usage": 75.0,
                "max_execution_time": 30.0,
            },
            monitoring_interval=60,
            alert_thresholds={
                "cpu_warning": 75.0,
                "cpu_critical": 90.0,
                "memory_warning": 70.0,
                "memory_critical": 85.0,
                "success_rate_warning": 70.0,
                "success_rate_critical": 50.0,
            },
            auto_scaling_enabled=True,
            backup_enabled=True,
            logging_level="INFO",
            performance_targets={
                "max_latency": 2.0,
                "min_success_rate": 80.0,
                "max_cpu_usage": 70.0,
            },
        )

        self.production_monitor = ProductionMonitor(self.production_config)

        # Alerting configuration
        alerting_config = {
            "email": {
                "enabled": False,  # Disabled for demo
                "smtp_server": "localhost",
                "smtp_port": 587,
                "from_address": "alerts@bypass-engine.local",
                "to_addresses": ["admin@bypass-engine.local"],
            },
            "webhook": {
                "enabled": False,  # Disabled for demo
                "urls": ["http://localhost:8080/webhook"],
            },
            "file": {"enabled": True, "log_file": "recon/logs/alerts.log"},
        }

        self.alerting_system = AlertingSystem(alerting_config)

    def setup_logging(self):
        """Setup logging for demo."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

    async def run_demo(self):
        """Run comprehensive performance optimization demo."""
        print("🚀 Starting Performance Optimization and Production Readiness Demo")
        print("=" * 70)

        try:
            # Demo sections
            await self.demo_performance_optimization()
            await self.demo_strategy_optimization()
            await self.demo_production_monitoring()
            await self.demo_alerting_system()
            await self.demo_production_readiness()

            print("\n✅ Performance Optimization Demo completed successfully!")

        except Exception as e:
            print(f"\n❌ Demo failed: {e}")
            self.logger.error(f"Demo failed: {e}")

    async def demo_performance_optimization(self):
        """Demo performance optimization features."""
        print("\n📊 Performance Optimization Demo")
        print("-" * 40)

        # Collect baseline metrics
        print("1. Collecting baseline performance metrics...")
        baseline_metrics = (
            await self.performance_optimizer.collect_performance_metrics()
        )

        print(f"   CPU Usage: {baseline_metrics.cpu_usage:.1f}%")
        print(f"   Memory Usage: {baseline_metrics.memory_usage:.1f}%")
        print(f"   Latency: {baseline_metrics.latency:.2f}s")
        print(f"   Success Rate: {baseline_metrics.success_rate:.1f}%")
        print(f"   Throughput: {baseline_metrics.throughput:.1f} ops/min")

        # Simulate performance optimization
        print("\n2. Running performance optimization...")
        optimization_result = await self.performance_optimizer.optimize_performance(
            baseline_metrics
        )

        print(
            f"   Optimization Actions: {len(optimization_result.optimization_actions)}"
        )
        for action in optimization_result.optimization_actions:
            print(f"     - {action}")

        print(
            f"   Performance Improvement: {optimization_result.improvement_percentage:.2f}%"
        )

        # Show recommendations
        if optimization_result.recommendations:
            print("\n3. Optimization Recommendations:")
            for rec in optimization_result.recommendations:
                print(f"     - {rec}")

        # Get system health
        print("\n4. System Health Status:")
        health = await self.performance_optimizer.get_system_health()
        print(f"   System Load: {health.system_load:.2f}")
        print(f"   Uptime: {health.uptime/3600:.1f} hours")
        print(f"   Active Attacks: {health.active_attacks}")

    async def demo_strategy_optimization(self):
        """Demo strategy optimization features."""
        print("\n🎯 Strategy Optimization Demo")
        print("-" * 40)

        # Simulate strategy performance data
        await self._simulate_strategy_data()

        # Demo strategy selection optimization
        print("1. Optimizing strategy selection...")
        test_domain = "example.com"
        available_strategies = ["tcp_fragmentation", "http_manipulation", "tls_evasion"]

        optimal_strategy = await self.strategy_optimizer.optimize_strategy_selection(
            test_domain, available_strategies
        )
        print(f"   Optimal strategy for {test_domain}: {optimal_strategy}")

        # Get strategy recommendations
        print("\n2. Strategy Recommendations:")
        recommendations = await self.strategy_optimizer.get_strategy_recommendations(
            test_domain
        )

        for i, rec in enumerate(recommendations[:3], 1):
            print(f"   {i}. {rec['strategy_id']}")
            print(f"      Success Rate: {rec['success_rate']:.1%}")
            print(f"      Average Time: {rec['average_time']:.2f}s")
            print(f"      Effectiveness Score: {rec['effectiveness_score']:.3f}")

        # Algorithm parameter optimization
        print("\n3. Algorithm Parameter Optimization:")
        param_optimization = (
            await self.strategy_optimizer.optimize_algorithm_parameters()
        )

        print(f"   Current Level: {param_optimization.get('current_level', 'unknown')}")
        print(
            f"   Recommended Level: {param_optimization.get('recommended_optimization_level', 'unknown')}"
        )
        print(
            f"   Improvement Potential: {param_optimization.get('improvement_potential', 0):.3f}"
        )

        # Performance summary
        print("\n4. Strategy Performance Summary:")
        summary = await self.strategy_optimizer.get_performance_summary()
        print(f"   Total Strategies: {summary.get('total_strategies', 0)}")
        print(f"   Average Success Rate: {summary.get('average_success_rate', 0):.1%}")
        print(
            f"   Average Execution Time: {summary.get('average_execution_time', 0):.2f}s"
        )

    async def demo_production_monitoring(self):
        """Demo production monitoring features."""
        print("\n📈 Production Monitoring Demo")
        print("-" * 40)

        # Setup alert callback for demo
        async def demo_alert_callback(alert: Alert):
            print(f"   🚨 Alert: {alert.title} ({alert.severity.value})")

        self.production_monitor.add_alert_callback(demo_alert_callback)

        # Start monitoring (brief demo)
        print("1. Starting production monitoring...")

        # Simulate monitoring for a short period
        monitoring_task = asyncio.create_task(self._demo_monitoring_cycle())

        try:
            await asyncio.wait_for(monitoring_task, timeout=10.0)
        except asyncio.TimeoutError:
            print("   Monitoring demo completed (timeout)")

        # Get monitoring status
        print("\n2. Monitoring Status:")
        status = await self.production_monitor.get_monitoring_status()

        print(f"   Monitoring Active: {status.get('monitoring_active', False)}")
        print(f"   Health Records: {status.get('health_records', 0)}")
        print(f"   Active Alerts: {status.get('active_alerts', 0)}")
        print(f"   Critical Alerts: {status.get('critical_alerts', 0)}")
        print(f"   Warning Alerts: {status.get('warning_alerts', 0)}")

        # Show current health if available
        current_health = await self.production_monitor.get_current_health()
        if current_health:
            print("\n3. Current System Health:")
            print(f"   CPU: {current_health.cpu_usage:.1f}%")
            print(f"   Memory: {current_health.memory_usage:.1f}%")
            print(f"   Disk: {current_health.disk_usage:.1f}%")

        # Stop monitoring
        await self.production_monitor.stop_monitoring()

    async def demo_alerting_system(self):
        """Demo alerting system features."""
        print("\n🔔 Alerting System Demo")
        print("-" * 40)

        # Test notification channels
        print("1. Testing notification channels...")
        test_results = await self.alerting_system.test_notifications()

        for channel, success in test_results.items():
            status = "✅" if success else "❌"
            print(f"   {status} {channel}: {'Working' if success else 'Failed'}")

        # Create demo alerts
        print("\n2. Creating demo alerts...")

        demo_alerts = [
            Alert(
                id="demo_warning",
                severity=AlertSeverity.WARNING,
                title="High CPU Usage",
                message="CPU usage is 78% (warning threshold: 75%)",
                component="system_health",
                metrics={"cpu_usage": 78.0},
            ),
            Alert(
                id="demo_critical",
                severity=AlertSeverity.CRITICAL,
                title="Low Success Rate",
                message="Success rate is 45% (critical threshold: 50%)",
                component="performance",
                metrics={"success_rate": 45.0},
            ),
        ]

        for alert in demo_alerts:
            await self.alerting_system.send_alert(alert)
            print(f"   📤 Sent {alert.severity.value} alert: {alert.title}")

        # Demo alert rules
        print("\n3. Configuring alert rules...")

        # Add suppression rule
        self.alerting_system.add_suppression_rule(
            "demo_suppression", {"component": "demo", "time_window": 300}  # 5 minutes
        )

        # Add escalation rule
        self.alerting_system.add_escalation_rule(
            "demo_escalation", {"severity": "warning", "title_prefix": "[ESCALATED]"}
        )

        print("   ✅ Alert rules configured")

        # Show configuration
        config = self.alerting_system.get_configuration()
        print(f"   Suppression Rules: {len(config['suppression_rules'])}")
        print(f"   Escalation Rules: {len(config['escalation_rules'])}")
        print(f"   Notification Channels: {config['notification_channels']}")

    async def demo_production_readiness(self):
        """Demo production readiness features."""
        print("\n🏭 Production Readiness Demo")
        print("-" * 40)

        # Simulate production deployment checklist
        print("1. Production Deployment Checklist:")

        checklist_items = [
            ("System Requirements", True),
            ("Dependencies Installed", True),
            ("Configuration Validated", True),
            ("Security Checks", True),
            ("Performance Tests", True),
            ("Monitoring Configured", True),
            ("Backup Configured", True),
            ("Documentation Complete", True),
            ("Team Training", False),  # Simulate one incomplete item
        ]

        for item, completed in checklist_items:
            status = "✅" if completed else "❌"
            print(f"   {status} {item}")

        # Production configuration validation
        print("\n2. Production Configuration:")
        print(
            f"   Optimization Level: {self.production_config.optimization_level.value}"
        )
        print(
            f"   Max Concurrent Attacks: {self.production_config.max_concurrent_attacks}"
        )
        print(f"   Monitoring Interval: {self.production_config.monitoring_interval}s")
        print(f"   Auto Scaling: {self.production_config.auto_scaling_enabled}")
        print(f"   Backup Enabled: {self.production_config.backup_enabled}")

        # Resource limits
        print("\n3. Resource Limits:")
        for resource, limit in self.production_config.resource_limits.items():
            print(f"   {resource}: {limit}")

        # Performance targets
        print("\n4. Performance Targets:")
        for target, value in self.production_config.performance_targets.items():
            print(f"   {target}: {value}")

        # Alert thresholds
        print("\n5. Alert Thresholds:")
        for threshold, value in self.production_config.alert_thresholds.items():
            print(f"   {threshold}: {value}")

    async def _simulate_strategy_data(self):
        """Simulate strategy performance data for demo."""
        strategies = [
            "tcp_fragmentation",
            "http_manipulation",
            "tls_evasion",
            "dns_tunneling",
        ]
        domains = ["example.com", "google.com", "youtube.com", "twitter.com"]

        for strategy in strategies:
            for domain in domains:
                # Simulate random performance data
                import random

                success = random.choice([True, False, True, True])  # 75% success rate
                execution_time = random.uniform(0.5, 3.0)
                effectiveness_score = random.uniform(0.6, 0.95)

                await self.strategy_optimizer.update_strategy_performance(
                    strategy, domain, success, execution_time, effectiveness_score
                )

    async def _demo_monitoring_cycle(self):
        """Run a brief monitoring cycle for demo."""
        # Simulate monitoring for a few cycles
        for i in range(3):
            # Simulate health check
            await asyncio.sleep(2)

            # Create a demo alert if needed
            if i == 1:  # Second cycle
                demo_alert = Alert(
                    id=f"demo_monitor_{i}",
                    severity=AlertSeverity.INFO,
                    title="Monitoring Demo Alert",
                    message="This is a demo alert from the monitoring system",
                    component="monitoring_demo",
                    metrics={"cycle": i},
                )

                # Simulate alert creation
                await self.production_monitor._create_alert(
                    demo_alert.severity,
                    demo_alert.title,
                    demo_alert.message,
                    demo_alert.component,
                    demo_alert.metrics,
                )


async def main():
    """Main demo function."""
    demo = PerformanceOptimizationDemo()
    await demo.run_demo()


if __name__ == "__main__":
    asyncio.run(main())
