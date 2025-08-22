"""
Demo script for DPI Behavior Monitoring System - Task 11 Implementation

This script demonstrates:
- Background monitoring for DPI behavior changes
- Automatic fingerprint updates when behavior changes detected
- Alert system for unknown DPI behavior patterns
- Performance-aware monitoring with adaptive frequency

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""
import asyncio
import logging
from typing import List
from recon.core.fingerprint.dpi_behavior_monitor import DPIBehaviorMonitor, MonitoringConfig, MonitoringAlert, AlertSeverity
from recon.core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DPIMonitoringDemo:
    """Demo class for DPI behavior monitoring"""

    def __init__(self):
        self.alerts_received: List[MonitoringAlert] = []
        self.setup_components()

    def setup_components(self):
        """Set up monitoring components"""
        logger.info('Setting up DPI monitoring demo components...')
        fingerprint_config = FingerprintingConfig(cache_ttl=300, enable_ml=True, enable_cache=True, timeout=10.0, retry_attempts=1)
        self.fingerprinter = AdvancedFingerprinter(config=fingerprint_config, cache_file='demo_fingerprint_cache.pkl')
        monitoring_config = MonitoringConfig(check_interval_seconds=30, min_check_interval=15, max_check_interval=120, max_concurrent_monitors=3, enable_adaptive_frequency=True, performance_threshold_cpu=70.0, performance_threshold_memory=80.0, fingerprint_similarity_threshold=0.8, behavior_change_confidence_threshold=0.6, unknown_pattern_threshold=0.4, enable_alerts=True, alert_retention_days=1, max_alerts_per_target=3, enable_strategy_testing=True, strategy_test_timeout=5.0, max_strategies_to_test=2, save_behavior_changes=True, behavior_log_file='demo_behavior_changes.json', alerts_file='demo_alerts.json')
        self.monitor = DPIBehaviorMonitor(fingerprinter=self.fingerprinter, config=monitoring_config, alert_callback=self.handle_alert)
        logger.info('Demo components initialized successfully')

    def handle_alert(self, alert: MonitoringAlert):
        """Handle monitoring alerts"""
        self.alerts_received.append(alert)
        severity_emoji = {AlertSeverity.LOW: '🟡', AlertSeverity.MEDIUM: '🟠', AlertSeverity.HIGH: '🔴', AlertSeverity.CRITICAL: '🚨'}
        emoji = severity_emoji.get(alert.severity, '⚠️')
        logger.warning(f'{emoji} ALERT: {alert.title}')
        logger.warning(f'   Target: {alert.target}')
        logger.warning(f'   Severity: {alert.severity.value.upper()}')
        logger.warning(f'   Description: {alert.description}')
        if alert.suggested_actions:
            logger.warning('   Suggested actions:')
            for action in alert.suggested_actions:
                logger.warning(f'   - {action}')

    async def demo_basic_monitoring(self):
        """Demonstrate basic monitoring functionality"""
        logger.info('=== Demo: Basic DPI Behavior Monitoring ===')
        test_targets = [('example.com', 443), ('httpbin.org', 443), ('google.com', 443)]
        logger.info('Adding targets for monitoring...')
        for domain, port in test_targets:
            self.monitor.add_target(domain, port)
            logger.info(f'  Added: {domain}:{port}')
        logger.info('Starting monitoring system...')
        await self.monitor.start_monitoring()
        logger.info('Monitoring running... (will run for 2 minutes)')
        await asyncio.sleep(120)
        status = self.monitor.get_monitoring_status()
        logger.info(f"Monitoring status: {status['state']}")
        logger.info(f"Monitored targets: {status['monitored_targets']}")
        logger.info(f"Behavior changes detected: {status['behavior_changes']}")
        logger.info(f"Alerts generated: {status['total_alerts']}")
        logger.info('Stopping monitoring system...')
        await self.monitor.stop_monitoring()
        logger.info('Basic monitoring demo completed')

    async def demo_force_checks(self):
        """Demonstrate force check functionality"""
        logger.info('=== Demo: Force Check Functionality ===')
        test_targets = [('httpbin.org', 443), ('example.com', 443)]
        for domain, port in test_targets:
            logger.info(f'Force checking {domain}:{port}...')
            try:
                change = await self.monitor.force_check(domain, port)
                if change:
                    logger.info(f'  Behavior change detected: {change.change_type}')
                    logger.info(f'  Confidence: {change.confidence:.2f}')
                    logger.info(f'  DPI Type: {change.new_fingerprint.dpi_type.value}')
                else:
                    logger.info('  No significant behavior change detected')
                target_status = self.monitor.get_target_status(domain, port)
                if target_status:
                    logger.info(f"  Target status: {target_status['behavior_changes']} changes, {target_status['active_alerts']} active alerts")
            except Exception as e:
                logger.error(f'  Error checking {domain}:{port}: {e}')
        logger.info('Force check demo completed')

    async def demo_alert_management(self):
        """Demonstrate alert management"""
        logger.info('=== Demo: Alert Management ===')
        all_alerts = self.monitor.get_alerts()
        logger.info(f'Total alerts: {len(all_alerts)}')
        if all_alerts:
            for alert in all_alerts[:3]:
                logger.info(f'Alert {alert.id}:')
                logger.info(f'  Target: {alert.target}')
                logger.info(f'  Severity: {alert.severity.value}')
                logger.info(f'  Title: {alert.title}')
                logger.info(f'  Acknowledged: {alert.acknowledged}')
                logger.info(f'  Resolved: {alert.resolved}')
            first_alert = all_alerts[0]
            if not first_alert.acknowledged:
                logger.info(f'Acknowledging alert {first_alert.id}...')
                success = self.monitor.acknowledge_alert(first_alert.id)
                logger.info(f"  Acknowledgment {('successful' if success else 'failed')}")
            if not first_alert.resolved:
                logger.info(f'Resolving alert {first_alert.id}...')
                success = self.monitor.resolve_alert(first_alert.id)
                logger.info(f"  Resolution {('successful' if success else 'failed')}")
        high_alerts = self.monitor.get_alerts(severity=AlertSeverity.HIGH)
        logger.info(f'High severity alerts: {len(high_alerts)}')
        unresolved_alerts = self.monitor.get_alerts(unresolved_only=True)
        logger.info(f'Unresolved alerts: {len(unresolved_alerts)}')
        logger.info('Alert management demo completed')

    async def demo_performance_monitoring(self):
        """Demonstrate performance-aware monitoring"""
        logger.info('=== Demo: Performance-Aware Monitoring ===')
        perf_monitor = self.monitor.performance_monitor
        cpu_usage = perf_monitor.get_cpu_usage()
        memory_usage = perf_monitor.get_memory_usage()
        logger.info(f'Current CPU usage: {cpu_usage:.1f}%')
        logger.info(f'Current memory usage: {memory_usage:.1f}%')
        base_interval = 60
        min_interval = 30
        max_interval = 300
        cpu_threshold = 80.0
        memory_threshold = 85.0
        adaptive_interval = perf_monitor.get_adaptive_interval(base_interval, min_interval, max_interval, cpu_threshold, memory_threshold)
        logger.info(f'Base monitoring interval: {base_interval}s')
        logger.info(f'Adaptive interval: {adaptive_interval}s')
        is_overloaded = perf_monitor.is_system_overloaded(cpu_threshold, memory_threshold)
        logger.info(f'System overloaded: {is_overloaded}')
        if is_overloaded:
            logger.info('  System is under high load - monitoring frequency will be reduced')
        else:
            logger.info('  System load is normal - monitoring at regular frequency')
        logger.info('Performance monitoring demo completed')

    async def demo_monitoring_statistics(self):
        """Demonstrate monitoring statistics"""
        logger.info('=== Demo: Monitoring Statistics ===')
        status = self.monitor.get_monitoring_status()
        stats = status['stats']
        logger.info('Monitoring Statistics:')
        logger.info(f"  Monitoring cycles: {stats['monitoring_cycles']}")
        logger.info(f"  Behavior changes detected: {stats['behavior_changes_detected']}")
        logger.info(f"  Alerts generated: {stats['alerts_generated']}")
        logger.info(f"  Fingerprints updated: {stats['fingerprints_updated']}")
        logger.info(f"  Strategy tests performed: {stats['strategy_tests_performed']}")
        logger.info(f"  Total monitoring time: {stats['total_monitoring_time']:.2f}s")
        if stats['monitoring_cycles'] > 0:
            avg_cycle_time = stats['total_monitoring_time'] / stats['monitoring_cycles']
            logger.info(f'  Average cycle time: {avg_cycle_time:.2f}s')
        logger.info(f"  Last cycle time: {stats['last_cycle_time']:.2f}s")
        try:
            fp_stats = self.fingerprinter.get_stats()
            logger.info('Fingerprinter Statistics:')
            logger.info(f"  Fingerprints created: {fp_stats['fingerprints_created']}")
            logger.info(f"  Cache hits: {fp_stats['cache_hits']}")
            logger.info(f"  Cache misses: {fp_stats['cache_misses']}")
            logger.info(f"  Cache hit rate: {fp_stats.get('cache_hit_rate', 0):.2%}")
            logger.info(f"  ML classifications: {fp_stats['ml_classifications']}")
            logger.info(f"  Fallback classifications: {fp_stats['fallback_classifications']}")
            logger.info(f"  Errors: {fp_stats['errors']}")
        except Exception as e:
            logger.warning(f'Could not get fingerprinter stats: {e}')
        logger.info('Statistics demo completed')

    async def run_full_demo(self):
        """Run complete monitoring demo"""
        logger.info('🚀 Starting DPI Behavior Monitoring Demo')
        logger.info('=' * 50)
        try:
            await self.demo_force_checks()
            await asyncio.sleep(2)
            await self.demo_performance_monitoring()
            await asyncio.sleep(2)
            await self.demo_basic_monitoring()
            await asyncio.sleep(2)
            await self.demo_alert_management()
            await asyncio.sleep(2)
            await self.demo_monitoring_statistics()
        except KeyboardInterrupt:
            logger.info('Demo interrupted by user')
        except Exception as e:
            logger.error(f'Demo error: {e}')
        finally:
            if self.monitor.state.value != 'stopped':
                await self.monitor.stop_monitoring()
        logger.info('=' * 50)
        logger.info('🏁 DPI Behavior Monitoring Demo Completed')
        logger.info(f'Total alerts received during demo: {len(self.alerts_received)}')
        if self.alerts_received:
            severity_counts = {}
            for alert in self.alerts_received:
                severity_counts[alert.severity.value] = severity_counts.get(alert.severity.value, 0) + 1
            logger.info('Alert breakdown by severity:')
            for severity, count in severity_counts.items():
                logger.info(f'  {severity}: {count}')

async def main():
    """Main demo function"""
    demo = DPIMonitoringDemo()
    await demo.run_full_demo()
if __name__ == '__main__':
    asyncio.run(main())