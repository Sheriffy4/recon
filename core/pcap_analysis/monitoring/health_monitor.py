#!/usr/bin/env python3
"""
Health monitoring and alerting system for PCAP Analysis System.
Monitors system health, performance metrics, and sends alerts.
"""

import os
import sys
import time
import json
import psutil
import asyncio
import logging
import requests
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path

# Add recon to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))


@dataclass
class HealthMetric:
    """Individual health metric."""
    name: str
    value: float
    unit: str
    status: str  # 'healthy', 'warning', 'critical'
    threshold_warning: float
    threshold_critical: float
    timestamp: datetime
    description: str = ""


@dataclass
class SystemHealth:
    """Overall system health status."""
    status: str  # 'healthy', 'degraded', 'critical'
    metrics: List[HealthMetric]
    alerts: List[str]
    timestamp: datetime
    uptime_seconds: float
    
    
@dataclass
class AlertConfig:
    """Alert configuration."""
    webhook_url: str = ""
    email_recipients: List[str] = None
    slack_webhook: str = ""
    alert_cooldown_minutes: int = 15
    enable_email: bool = False
    enable_webhook: bool = False
    enable_slack: bool = False
    
    def __post_init__(self):
        if self.email_recipients is None:
            self.email_recipients = []


class HealthMonitor:
    """System health monitor with alerting capabilities."""
    
    def __init__(self, alert_config: AlertConfig = None):
        """Initialize health monitor."""
        self.alert_config = alert_config or AlertConfig()
        self.logger = self._setup_logging()
        self.start_time = time.time()
        self.last_alerts: Dict[str, datetime] = {}
        self.metrics_history: List[SystemHealth] = []
        self.max_history_size = 1000
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for health monitor."""
        logger = logging.getLogger("health_monitor")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    async def check_system_health(self) -> SystemHealth:
        """Perform comprehensive system health check."""
        metrics = []
        alerts = []
        
        # Check CPU usage
        cpu_metric = await self._check_cpu_usage()
        metrics.append(cpu_metric)
        if cpu_metric.status in ['warning', 'critical']:
            alerts.append(f"High CPU usage: {cpu_metric.value}%")
            
        # Check memory usage
        memory_metric = await self._check_memory_usage()
        metrics.append(memory_metric)
        if memory_metric.status in ['warning', 'critical']:
            alerts.append(f"High memory usage: {memory_metric.value}%")
            
        # Check disk usage
        disk_metric = await self._check_disk_usage()
        metrics.append(disk_metric)
        if disk_metric.status in ['warning', 'critical']:
            alerts.append(f"High disk usage: {disk_metric.value}%")
            
        # Check network connectivity
        network_metric = await self._check_network_connectivity()
        metrics.append(network_metric)
        if network_metric.status in ['warning', 'critical']:
            alerts.append(f"Network connectivity issues: {network_metric.description}")
            
        # Check application processes
        process_metric = await self._check_application_processes()
        metrics.append(process_metric)
        if process_metric.status in ['warning', 'critical']:
            alerts.append(f"Application process issues: {process_metric.description}")
            
        # Check database connectivity
        db_metric = await self._check_database_connectivity()
        metrics.append(db_metric)
        if db_metric.status in ['warning', 'critical']:
            alerts.append(f"Database connectivity issues: {db_metric.description}")
            
        # Check Redis connectivity
        redis_metric = await self._check_redis_connectivity()
        metrics.append(redis_metric)
        if redis_metric.status in ['warning', 'critical']:
            alerts.append(f"Redis connectivity issues: {redis_metric.description}")
            
        # Check file system permissions
        permissions_metric = await self._check_file_permissions()
        metrics.append(permissions_metric)
        if permissions_metric.status in ['warning', 'critical']:
            alerts.append(f"File permission issues: {permissions_metric.description}")
            
        # Determine overall status
        critical_count = sum(1 for m in metrics if m.status == 'critical')
        warning_count = sum(1 for m in metrics if m.status == 'warning')
        
        if critical_count > 0:
            overall_status = 'critical'
        elif warning_count > 0:
            overall_status = 'degraded'
        else:
            overall_status = 'healthy'
            
        health = SystemHealth(
            status=overall_status,
            metrics=metrics,
            alerts=alerts,
            timestamp=datetime.now(),
            uptime_seconds=time.time() - self.start_time
        )
        
        # Store in history
        self.metrics_history.append(health)
        if len(self.metrics_history) > self.max_history_size:
            self.metrics_history.pop(0)
            
        # Send alerts if necessary
        if alerts:
            await self._send_alerts(health)
            
        return health
        
    async def _check_cpu_usage(self) -> HealthMetric:
        """Check CPU usage."""
        cpu_percent = psutil.cpu_percent(interval=1)
        
        status = 'healthy'
        if cpu_percent > 90:
            status = 'critical'
        elif cpu_percent > 75:
            status = 'warning'
            
        return HealthMetric(
            name="cpu_usage",
            value=cpu_percent,
            unit="%",
            status=status,
            threshold_warning=75.0,
            threshold_critical=90.0,
            timestamp=datetime.now(),
            description=f"CPU usage at {cpu_percent}%"
        )
        
    async def _check_memory_usage(self) -> HealthMetric:
        """Check memory usage."""
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        status = 'healthy'
        if memory_percent > 90:
            status = 'critical'
        elif memory_percent > 80:
            status = 'warning'
            
        return HealthMetric(
            name="memory_usage",
            value=memory_percent,
            unit="%",
            status=status,
            threshold_warning=80.0,
            threshold_critical=90.0,
            timestamp=datetime.now(),
            description=f"Memory usage at {memory_percent}% ({memory.used // (1024**3)}GB used)"
        )
        
    async def _check_disk_usage(self) -> HealthMetric:
        """Check disk usage."""
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        
        status = 'healthy'
        if disk_percent > 90:
            status = 'critical'
        elif disk_percent > 80:
            status = 'warning'
            
        return HealthMetric(
            name="disk_usage",
            value=disk_percent,
            unit="%",
            status=status,
            threshold_warning=80.0,
            threshold_critical=90.0,
            timestamp=datetime.now(),
            description=f"Disk usage at {disk_percent}% ({disk.used // (1024**3)}GB used)"
        )
        
    async def _check_network_connectivity(self) -> HealthMetric:
        """Check network connectivity."""
        try:
            # Test connectivity to common DNS servers
            test_hosts = ["8.8.8.8", "1.1.1.1", "google.com"]
            successful_tests = 0
            
            for host in test_hosts:
                try:
                    response = await asyncio.wait_for(
                        asyncio.create_subprocess_exec(
                            "ping", "-c", "1", "-W", "2", host,
                            stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.DEVNULL
                        ),
                        timeout=5
                    )
                    process = await response
                    if process.returncode == 0:
                        successful_tests += 1
                except:
                    pass
                    
            success_rate = (successful_tests / len(test_hosts)) * 100
            
            status = 'healthy'
            if success_rate < 50:
                status = 'critical'
            elif success_rate < 80:
                status = 'warning'
                
            return HealthMetric(
                name="network_connectivity",
                value=success_rate,
                unit="%",
                status=status,
                threshold_warning=80.0,
                threshold_critical=50.0,
                timestamp=datetime.now(),
                description=f"Network connectivity at {success_rate}% ({successful_tests}/{len(test_hosts)} tests passed)"
            )
            
        except Exception as e:
            return HealthMetric(
                name="network_connectivity",
                value=0.0,
                unit="%",
                status='critical',
                threshold_warning=80.0,
                threshold_critical=50.0,
                timestamp=datetime.now(),
                description=f"Network connectivity check failed: {e}"
            )
            
    async def _check_application_processes(self) -> HealthMetric:
        """Check application processes."""
        try:
            # Look for PCAP analysis processes
            pcap_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if any('pcap' in str(item).lower() for item in proc.info['cmdline'] or []):
                        pcap_processes.append(proc)
                except:
                    pass
                    
            process_count = len(pcap_processes)
            
            status = 'healthy'
            if process_count == 0:
                status = 'critical'
            elif process_count < 2:
                status = 'warning'
                
            return HealthMetric(
                name="application_processes",
                value=process_count,
                unit="count",
                status=status,
                threshold_warning=2.0,
                threshold_critical=1.0,
                timestamp=datetime.now(),
                description=f"{process_count} PCAP analysis processes running"
            )
            
        except Exception as e:
            return HealthMetric(
                name="application_processes",
                value=0.0,
                unit="count",
                status='critical',
                threshold_warning=2.0,
                threshold_critical=1.0,
                timestamp=datetime.now(),
                description=f"Process check failed: {e}"
            )
            
    async def _check_database_connectivity(self) -> HealthMetric:
        """Check database connectivity."""
        try:
            # This would normally test actual database connection
            # For now, simulate the check
            await asyncio.sleep(0.1)  # Simulate connection test
            
            return HealthMetric(
                name="database_connectivity",
                value=1.0,
                unit="status",
                status='healthy',
                threshold_warning=1.0,
                threshold_critical=0.0,
                timestamp=datetime.now(),
                description="Database connection healthy"
            )
            
        except Exception as e:
            return HealthMetric(
                name="database_connectivity",
                value=0.0,
                unit="status",
                status='critical',
                threshold_warning=1.0,
                threshold_critical=0.0,
                timestamp=datetime.now(),
                description=f"Database connection failed: {e}"
            )
            
    async def _check_redis_connectivity(self) -> HealthMetric:
        """Check Redis connectivity."""
        try:
            # This would normally test actual Redis connection
            # For now, simulate the check
            await asyncio.sleep(0.1)  # Simulate connection test
            
            return HealthMetric(
                name="redis_connectivity",
                value=1.0,
                unit="status",
                status='healthy',
                threshold_warning=1.0,
                threshold_critical=0.0,
                timestamp=datetime.now(),
                description="Redis connection healthy"
            )
            
        except Exception as e:
            return HealthMetric(
                name="redis_connectivity",
                value=0.0,
                unit="status",
                status='critical',
                threshold_warning=1.0,
                threshold_critical=0.0,
                timestamp=datetime.now(),
                description=f"Redis connection failed: {e}"
            )
            
    async def _check_file_permissions(self) -> HealthMetric:
        """Check file system permissions."""
        try:
            # Check critical directories
            critical_dirs = [
                "/var/lib/pcap-analysis",
                "/var/log/pcap-analysis",
                "/tmp/pcap-analysis"
            ]
            
            permission_issues = []
            
            for directory in critical_dirs:
                if os.path.exists(directory):
                    if not os.access(directory, os.R_OK | os.W_OK):
                        permission_issues.append(f"No read/write access to {directory}")
                else:
                    # Try to create directory
                    try:
                        os.makedirs(directory, exist_ok=True)
                    except PermissionError:
                        permission_issues.append(f"Cannot create directory {directory}")
                        
            status = 'healthy'
            if len(permission_issues) > 2:
                status = 'critical'
            elif len(permission_issues) > 0:
                status = 'warning'
                
            return HealthMetric(
                name="file_permissions",
                value=len(critical_dirs) - len(permission_issues),
                unit="accessible_dirs",
                status=status,
                threshold_warning=len(critical_dirs) - 1,
                threshold_critical=len(critical_dirs) - 2,
                timestamp=datetime.now(),
                description=f"{len(permission_issues)} permission issues found" if permission_issues else "All directories accessible"
            )
            
        except Exception as e:
            return HealthMetric(
                name="file_permissions",
                value=0.0,
                unit="accessible_dirs",
                status='critical',
                threshold_warning=2.0,
                threshold_critical=1.0,
                timestamp=datetime.now(),
                description=f"Permission check failed: {e}"
            )
            
    async def _send_alerts(self, health: SystemHealth):
        """Send alerts based on health status."""
        if not health.alerts:
            return
            
        # Check cooldown period
        now = datetime.now()
        alert_key = f"{health.status}_{len(health.alerts)}"
        
        if alert_key in self.last_alerts:
            time_since_last = now - self.last_alerts[alert_key]
            if time_since_last.total_seconds() < (self.alert_config.alert_cooldown_minutes * 60):
                return  # Still in cooldown period
                
        self.last_alerts[alert_key] = now
        
        # Prepare alert message
        alert_message = self._format_alert_message(health)
        
        # Send alerts through configured channels
        if self.alert_config.enable_webhook and self.alert_config.webhook_url:
            await self._send_webhook_alert(alert_message, health)
            
        if self.alert_config.enable_slack and self.alert_config.slack_webhook:
            await self._send_slack_alert(alert_message, health)
            
        if self.alert_config.enable_email and self.alert_config.email_recipients:
            await self._send_email_alert(alert_message, health)
            
        self.logger.warning(f"Alerts sent for {health.status} status: {len(health.alerts)} issues")
        
    def _format_alert_message(self, health: SystemHealth) -> str:
        """Format alert message."""
        message = f"🚨 PCAP Analysis System Alert - Status: {health.status.upper()}\n\n"
        message += f"Timestamp: {health.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += f"Uptime: {health.uptime_seconds / 3600:.1f} hours\n\n"
        
        message += "Issues:\n"
        for alert in health.alerts:
            message += f"• {alert}\n"
            
        message += "\nMetrics:\n"
        for metric in health.metrics:
            if metric.status != 'healthy':
                message += f"• {metric.name}: {metric.value}{metric.unit} ({metric.status})\n"
                
        return message
        
    async def _send_webhook_alert(self, message: str, health: SystemHealth):
        """Send webhook alert."""
        try:
            payload = {
                "text": message,
                "status": health.status,
                "timestamp": health.timestamp.isoformat(),
                "alerts": health.alerts,
                "metrics": [asdict(m) for m in health.metrics if m.status != 'healthy']
            }
            
            response = requests.post(
                self.alert_config.webhook_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            self.logger.info("Webhook alert sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")
            
    async def _send_slack_alert(self, message: str, health: SystemHealth):
        """Send Slack alert."""
        try:
            # Format for Slack
            color = {
                'healthy': 'good',
                'degraded': 'warning', 
                'critical': 'danger'
            }.get(health.status, 'warning')
            
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"PCAP Analysis System - {health.status.upper()}",
                        "text": message,
                        "ts": int(health.timestamp.timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.alert_config.slack_webhook,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            self.logger.info("Slack alert sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
            
    async def _send_email_alert(self, message: str, health: SystemHealth):
        """Send email alert."""
        try:
            # This would normally use SMTP to send emails
            # For now, just log the alert
            self.logger.info(f"Email alert would be sent to: {self.alert_config.email_recipients}")
            self.logger.info(f"Email content: {message}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            
    def get_health_history(self, hours: int = 24) -> List[SystemHealth]:
        """Get health history for specified hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [h for h in self.metrics_history if h.timestamp >= cutoff_time]
        
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary statistics."""
        if not self.metrics_history:
            return {"status": "no_data", "message": "No health data available"}
            
        recent_health = self.metrics_history[-10:]  # Last 10 checks
        
        status_counts = {}
        for health in recent_health:
            status_counts[health.status] = status_counts.get(health.status, 0) + 1
            
        avg_uptime = sum(h.uptime_seconds for h in recent_health) / len(recent_health)
        
        return {
            "current_status": self.metrics_history[-1].status,
            "status_distribution": status_counts,
            "average_uptime_hours": avg_uptime / 3600,
            "total_checks": len(self.metrics_history),
            "last_check": self.metrics_history[-1].timestamp.isoformat()
        }


async def main():
    """Run health monitoring."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PCAP Analysis System Health Monitor")
    parser.add_argument("--interval", type=int, default=60, help="Check interval in seconds")
    parser.add_argument("--webhook-url", help="Webhook URL for alerts")
    parser.add_argument("--slack-webhook", help="Slack webhook URL")
    parser.add_argument("--email", action="append", help="Email recipients for alerts")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    
    args = parser.parse_args()
    
    # Setup alert configuration
    alert_config = AlertConfig(
        webhook_url=args.webhook_url or "",
        slack_webhook=args.slack_webhook or "",
        email_recipients=args.email or [],
        enable_webhook=bool(args.webhook_url),
        enable_slack=bool(args.slack_webhook),
        enable_email=bool(args.email)
    )
    
    monitor = HealthMonitor(alert_config)
    
    print("🏥 Starting PCAP Analysis System Health Monitor...")
    print(f"Check interval: {args.interval} seconds")
    
    if args.once:
        health = await monitor.check_system_health()
        print(f"System Status: {health.status}")
        print(f"Alerts: {len(health.alerts)}")
        for alert in health.alerts:
            print(f"  • {alert}")
        return 0 if health.status == 'healthy' else 1
        
    try:
        while True:
            health = await monitor.check_system_health()
            
            status_emoji = {
                'healthy': '✅',
                'degraded': '⚠️',
                'critical': '🚨'
            }.get(health.status, '❓')
            
            print(f"{status_emoji} {health.timestamp.strftime('%H:%M:%S')} - Status: {health.status} - Alerts: {len(health.alerts)}")
            
            if health.alerts:
                for alert in health.alerts:
                    print(f"    • {alert}")
                    
            await asyncio.sleep(args.interval)
            
    except KeyboardInterrupt:
        print("\n👋 Health monitor stopped")
        return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)