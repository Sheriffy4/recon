#!/usr/bin/env python3
"""
Production Monitoring System Example.

This example demonstrates how to use the comprehensive production monitoring
system for the segment-based attack orchestration in real production environments.
"""

import asyncio
import logging
import json
import time
from pathlib import Path

# Import monitoring system
from monitoring.production_monitoring_system import (
    ProductionMonitoringSystem,
    MonitoringConfig,
)


async def basic_monitoring_example():
    """Basic monitoring system usage example."""

    print("🔍 Production Monitoring System - Basic Example")
    print("=" * 60)

    # Configure monitoring for production
    config = MonitoringConfig(
        monitoring_data_dir="./production_monitoring_data",
        metrics_collection_interval=10,  # Collect metrics every 10 seconds
        performance_check_interval=30,  # Check performance every 30 seconds
        health_check_interval=60,  # Health check every minute
        # Production thresholds
        failure_rate_threshold=0.10,  # 10% failure rate threshold
        response_time_threshold_ms=300.0,  # 300ms response time threshold
        memory_usage_threshold_mb=200.0,  # 200MB memory threshold
        cpu_usage_threshold_percent=75.0,  # 75% CPU threshold
        # Enable real-time dashboard
        enable_real_time_dashboard=True,
        # Alert settings
        alert_cooldown_minutes=10,  # 10 minute cooldown between similar alerts
        metrics_retention_hours=48,  # Keep metrics for 48 hours
        alert_retention_days=14,  # Keep alerts for 14 days
    )

    # Create monitoring system
    monitoring = ProductionMonitoringSystem(config)

    try:
        print("🚀 Starting production monitoring...")
        await monitoring.start_monitoring()

        # Let monitoring run and collect data
        print("📊 Collecting metrics for 2 minutes...")
        await asyncio.sleep(120)

        # Check current status
        print("\n📈 Current Monitoring Status:")
        status = monitoring.get_current_status()
        print(json.dumps(status, indent=2))

        # Get metrics summary
        print("\n📊 Metrics Summary (Last Hour):")
        summary = monitoring.get_metrics_summary(hours=1)
        print(json.dumps(summary, indent=2))

        # Get alert summary
        print("\n🚨 Alert Summary:")
        alerts = monitoring.get_alert_summary()
        print(json.dumps(alerts, indent=2))

    finally:
        print("\n🛑 Stopping monitoring...")
        await monitoring.stop_monitoring()
        print("✅ Monitoring stopped")


async def advanced_monitoring_example():
    """Advanced monitoring with custom thresholds and alerting."""

    print("\n🔍 Production Monitoring System - Advanced Example")
    print("=" * 60)

    # Configure monitoring with strict thresholds for high-performance environment
    config = MonitoringConfig(
        monitoring_data_dir="./advanced_monitoring_data",
        metrics_collection_interval=5,  # Very frequent collection
        performance_check_interval=15,  # Frequent performance checks
        health_check_interval=30,  # Regular health checks
        # Strict production thresholds
        failure_rate_threshold=0.05,  # 5% failure rate threshold
        response_time_threshold_ms=150.0,  # 150ms response time threshold
        memory_usage_threshold_mb=100.0,  # 100MB memory threshold
        cpu_usage_threshold_percent=60.0,  # 60% CPU threshold
        # Advanced features
        enable_real_time_dashboard=True,
        enable_prometheus_metrics=False,  # Could be enabled for Prometheus integration
        # Tight alert settings
        alert_cooldown_minutes=5,  # Short cooldown for rapid response
        metrics_retention_hours=72,  # Keep more historical data
        alert_retention_days=30,  # Keep alerts longer for analysis
    )

    # Create monitoring system
    monitoring = ProductionMonitoringSystem(config)

    try:
        print("🚀 Starting advanced monitoring...")
        await monitoring.start_monitoring()

        # Simulate monitoring during different load conditions
        print("📊 Monitoring during normal operations...")
        await asyncio.sleep(30)

        # Check status during normal operations
        print("\n📈 Status During Normal Operations:")
        status = monitoring.get_current_status()
        print(f"System Status: {status.get('status', 'unknown')}")
        print(f"Active Alerts: {status.get('active_alerts', 0)}")
        print(f"Metrics Collected: {status.get('metrics_count', 0)}")

        if status.get("latest_metrics"):
            latest = status["latest_metrics"]
            print(f"Attacks/min: {latest.get('attacks_per_minute', 0):.1f}")
            print(f"Success Rate: {latest.get('success_rate', 0):.1%}")
            print(f"Avg Response: {latest.get('average_response_time_ms', 0):.1f}ms")
            print(f"Memory Usage: {latest.get('memory_usage_mb', 0):.1f}MB")

        # Continue monitoring
        print("\n📊 Continuing monitoring for performance analysis...")
        await asyncio.sleep(60)

        # Get detailed metrics analysis
        print("\n📊 Detailed Metrics Analysis:")
        summary = monitoring.get_metrics_summary(hours=1)
        if "error" not in summary:
            print(f"Metrics Collected: {summary['metrics_count']}")
            print(f"Avg Attacks/min: {summary['avg_attacks_per_minute']:.1f}")
            print(f"Avg Success Rate: {summary['avg_success_rate']:.1%}")
            print(f"Avg Response Time: {summary['avg_response_time_ms']:.1f}ms")
            print(f"Max Response Time: {summary['max_response_time_ms']:.1f}ms")
            print(f"Avg Memory Usage: {summary['avg_memory_usage_mb']:.1f}MB")
            print(f"Max Memory Usage: {summary['max_memory_usage_mb']:.1f}MB")
            print(f"Total Errors: {summary['total_errors']}")

        # Check for any alerts
        alerts = monitoring.get_alert_summary()
        if alerts["active_alerts"] > 0:
            print(f"\n🚨 Active Alerts: {alerts['active_alerts']}")
            print(f"Critical: {alerts['critical_alerts']}")
            print(f"Warnings: {alerts['warning_alerts']}")

            print("\nRecent Alerts:")
            for alert in alerts["recent_alerts"][-3:]:  # Show last 3 alerts
                print(f"- [{alert['severity'].upper()}] {alert['title']}")
                print(
                    f"  Type: {alert['type']}, Time: {time.ctime(alert['timestamp'])}"
                )
        else:
            print("\n✅ No active alerts - system running smoothly")

    finally:
        print("\n🛑 Stopping advanced monitoring...")
        await monitoring.stop_monitoring()
        print("✅ Advanced monitoring stopped")


async def monitoring_data_analysis_example():
    """Example of analyzing monitoring data."""

    print("\n📊 Production Monitoring Data Analysis Example")
    print("=" * 60)

    # Configure monitoring for data collection
    config = MonitoringConfig(
        monitoring_data_dir="./monitoring_analysis_data",
        metrics_collection_interval=3,
        enable_real_time_dashboard=True,
    )

    monitoring = ProductionMonitoringSystem(config)

    try:
        print("🚀 Starting monitoring for data analysis...")
        await monitoring.start_monitoring()

        # Collect data for analysis
        print("📊 Collecting data for 90 seconds...")
        await asyncio.sleep(90)

        # Analyze different time periods
        print("\n📈 Performance Analysis:")

        # Last 15 minutes
        summary_15m = monitoring.get_metrics_summary(hours=0.25)  # 15 minutes
        if "error" not in summary_15m:
            print("\nLast 15 minutes:")
            print(f"  Metrics: {summary_15m['metrics_count']}")
            print(f"  Avg Success Rate: {summary_15m['avg_success_rate']:.1%}")
            print(f"  Avg Response Time: {summary_15m['avg_response_time_ms']:.1f}ms")

        # Last hour
        summary_1h = monitoring.get_metrics_summary(hours=1)
        if "error" not in summary_1h:
            print("\nLast hour:")
            print(f"  Metrics: {summary_1h['metrics_count']}")
            print(f"  Avg Success Rate: {summary_1h['avg_success_rate']:.1%}")
            print(f"  Avg Response Time: {summary_1h['avg_response_time_ms']:.1f}ms")

        # Check monitoring data files
        monitoring_dir = Path(config.monitoring_data_dir)
        if monitoring_dir.exists():
            print(f"\n📁 Monitoring Data Directory: {monitoring_dir}")

            # Check metrics files
            metrics_dir = monitoring_dir / "metrics"
            if metrics_dir.exists():
                metrics_files = list(metrics_dir.glob("metrics_*.json"))
                print(f"  Metrics files: {len(metrics_files)}")

                if metrics_files:
                    # Show sample of latest metrics file
                    latest_file = max(metrics_files, key=lambda f: f.stat().st_mtime)
                    print(f"  Latest metrics file: {latest_file.name}")

                    try:
                        with open(latest_file, "r") as f:
                            sample_data = json.load(f)
                        print(f"  Sample data: {json.dumps(sample_data, indent=4)}")
                    except Exception as e:
                        print(f"  Error reading file: {e}")

            # Check dashboard file
            dashboard_file = monitoring_dir / "dashboard.json"
            if dashboard_file.exists():
                print(f"  Dashboard file: {dashboard_file.name}")

                try:
                    with open(dashboard_file, "r") as f:
                        dashboard_data = json.load(f)
                    print(
                        f"  Dashboard status: {dashboard_data.get('system_status', 'unknown')}"
                    )
                    print(
                        f"  Active alerts: {dashboard_data.get('active_alerts_count', 0)}"
                    )
                except Exception as e:
                    print(f"  Error reading dashboard: {e}")

            # Check alerts directory
            alerts_dir = monitoring_dir / "alerts"
            if alerts_dir.exists():
                alert_files = list(alerts_dir.glob("alert_*.json"))
                print(f"  Alert files: {len(alert_files)}")

    finally:
        print("\n🛑 Stopping monitoring...")
        await monitoring.stop_monitoring()
        print("✅ Data analysis monitoring stopped")


async def production_deployment_monitoring_example():
    """Example of monitoring during production deployment."""

    print("\n🚀 Production Deployment Monitoring Example")
    print("=" * 60)

    # Configure monitoring for deployment scenario
    config = MonitoringConfig(
        monitoring_data_dir="./deployment_monitoring_data",
        metrics_collection_interval=2,  # Very frequent during deployment
        performance_check_interval=10,  # Quick performance checks
        health_check_interval=20,  # Regular health monitoring
        # Conservative thresholds during deployment
        failure_rate_threshold=0.08,  # 8% failure rate threshold
        response_time_threshold_ms=250.0,  # 250ms response time threshold
        memory_usage_threshold_mb=150.0,  # 150MB memory threshold
        cpu_usage_threshold_percent=70.0,  # 70% CPU threshold
        # Deployment-specific settings
        enable_real_time_dashboard=True,
        alert_cooldown_minutes=3,  # Quick alerts during deployment
        metrics_retention_hours=24,  # Keep deployment metrics
        alert_retention_days=7,  # Keep deployment alerts
    )

    monitoring = ProductionMonitoringSystem(config)

    try:
        print("🚀 Starting deployment monitoring...")
        await monitoring.start_monitoring()

        # Simulate pre-deployment monitoring
        print("📊 Pre-deployment baseline monitoring...")
        await asyncio.sleep(30)

        baseline_status = monitoring.get_current_status()
        print(f"Pre-deployment status: {baseline_status.get('status', 'unknown')}")

        # Simulate deployment phase
        print("\n🔄 Simulating deployment phase...")
        await asyncio.sleep(45)

        deployment_status = monitoring.get_current_status()
        print(f"During deployment status: {deployment_status.get('status', 'unknown')}")

        # Simulate post-deployment monitoring
        print("\n✅ Post-deployment monitoring...")
        await asyncio.sleep(60)

        final_status = monitoring.get_current_status()
        print(f"Post-deployment status: {final_status.get('status', 'unknown')}")

        # Generate deployment report
        print("\n📋 Deployment Monitoring Report:")
        print("-" * 40)

        deployment_summary = monitoring.get_metrics_summary(hours=1)
        if "error" not in deployment_summary:
            print(f"Total metrics collected: {deployment_summary['metrics_count']}")
            print(f"Average success rate: {deployment_summary['avg_success_rate']:.1%}")
            print(
                f"Average response time: {deployment_summary['avg_response_time_ms']:.1f}ms"
            )
            print(
                f"Maximum response time: {deployment_summary['max_response_time_ms']:.1f}ms"
            )
            print(
                f"Average memory usage: {deployment_summary['avg_memory_usage_mb']:.1f}MB"
            )
            print(
                f"Maximum memory usage: {deployment_summary['max_memory_usage_mb']:.1f}MB"
            )
            print(f"Total errors detected: {deployment_summary['total_errors']}")

        alert_summary = monitoring.get_alert_summary()
        print("\nDeployment alerts:")
        print(f"  Active alerts: {alert_summary['active_alerts']}")
        print(f"  Critical alerts: {alert_summary['critical_alerts']}")
        print(f"  Warning alerts: {alert_summary['warning_alerts']}")
        print(f"  Total alerts today: {alert_summary['total_alerts_today']}")

        if alert_summary["recent_alerts"]:
            print("\nRecent alerts during deployment:")
            for alert in alert_summary["recent_alerts"][-5:]:
                status = "RESOLVED" if alert["resolved"] else "ACTIVE"
                print(f"  [{status}] {alert['title']} ({alert['severity']})")

        # Deployment success assessment
        if (
            alert_summary["critical_alerts"] == 0
            and deployment_summary.get("avg_success_rate", 0) > 0.9
        ):
            print("\n✅ DEPLOYMENT SUCCESS: No critical issues detected")
        elif alert_summary["critical_alerts"] > 0:
            print("\n❌ DEPLOYMENT CONCERN: Critical alerts detected")
        else:
            print("\n⚠️ DEPLOYMENT WARNING: Performance degradation detected")

    finally:
        print("\n🛑 Stopping deployment monitoring...")
        await monitoring.stop_monitoring()
        print("✅ Deployment monitoring completed")


async def main():
    """Run all monitoring examples."""

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("🔍 Production Monitoring System Examples")
    print("=" * 80)

    try:
        # Run basic example
        await basic_monitoring_example()

        # Wait between examples
        await asyncio.sleep(2)

        # Run advanced example
        await advanced_monitoring_example()

        # Wait between examples
        await asyncio.sleep(2)

        # Run data analysis example
        await monitoring_data_analysis_example()

        # Wait between examples
        await asyncio.sleep(2)

        # Run deployment monitoring example
        await production_deployment_monitoring_example()

    except KeyboardInterrupt:
        print("\n⚠️ Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback

        traceback.print_exc()

    print("\n✅ All monitoring examples completed!")


if __name__ == "__main__":
    asyncio.run(main())
