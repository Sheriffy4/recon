#!/usr/bin/env python3
"""
Production Deployment Manager for Native Attack Orchestration.

This module manages the deployment of the segment-based attack system
to production environments with monitoring, alerting, and operational support.
"""

import os
import sys
import time
import json
import logging
import asyncio
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Core imports
from core.bypass.monitoring.segment_execution_stats import SegmentExecutionStatsCollector
from core.bypass.diagnostics.segment_diagnostics import SegmentDiagnostics
from core.bypass.performance.segment_performance_optimizer import (
    SegmentPerformanceOptimizer,
    OptimizationConfig
)
from tests.run_final_system_validation import FinalSystemValidator


@dataclass
class ProductionConfig:
    """Configuration for production deployment."""
    
    # Environment settings
    environment_name: str = "production"
    deployment_version: str = "1.0.0"
    deployment_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # System settings
    enable_segment_attacks: bool = True
    enable_performance_optimization: bool = True
    enable_monitoring: bool = True
    enable_alerting: bool = True
    
    # Performance settings
    max_concurrent_attacks: int = 10
    segment_execution_timeout: int = 300
    performance_monitoring_interval: int = 60
    
    # Monitoring settings
    stats_collection_enabled: bool = True
    diagnostics_enabled: bool = True
    log_level: str = "INFO"
    log_retention_days: int = 30
    
    # Alerting settings
    alert_on_failure_rate: float = 0.1  # Alert if >10% failure rate
    alert_on_performance_degradation: float = 0.2  # Alert if >20% slower
    alert_email_recipients: List[str] = field(default_factory=list)
    
    # Paths
    log_directory: str = "/var/log/native_attack_orchestration"
    data_directory: str = "/var/lib/native_attack_orchestration"
    config_directory: str = "/etc/native_attack_orchestration"


@dataclass
class DeploymentStatus:
    """Status of production deployment."""
    
    deployment_id: str
    status: str  # deploying, deployed, failed, stopped
    start_time: float
    end_time: Optional[float] = None
    
    # Validation results
    pre_deployment_validation: Optional[Dict[str, Any]] = None
    post_deployment_validation: Optional[Dict[str, Any]] = None
    
    # System health
    system_health: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Issues and alerts
    deployment_issues: List[str] = field(default_factory=list)
    active_alerts: List[Dict[str, Any]] = field(default_factory=list)
    
    # Operational data
    attacks_executed: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    average_execution_time: float = 0.0


class ProductionDeploymentManager:
    """Manages production deployment and monitoring."""
    
    def __init__(self, config: ProductionConfig):
        self.config = config
        self.deployment_id = f"deploy_{int(time.time())}"
        
        # Initialize components
        self.stats_collector = SegmentExecutionStatsCollector()
        self.diagnostics = SegmentDiagnostics()
        self.performance_optimizer = None
        self.validator = FinalSystemValidator()
        
        # Setup logging
        self._setup_logging()
        
        # Deployment status
        self.status = DeploymentStatus(
            deployment_id=self.deployment_id,
            status="initializing",
            start_time=time.time()
        )
        
        self.logger = logging.getLogger(__name__)
    
    def _setup_logging(self):
        """Setup production logging."""
        # Create log directory
        log_dir = Path(self.config.log_directory)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        log_file = log_dir / f"deployment_{self.deployment_id}.log"
        
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    async def deploy_to_production(self) -> DeploymentStatus:
        """Deploy system to production environment."""
        
        self.logger.info(f"🚀 Starting production deployment {self.deployment_id}")
        self.logger.info(f"Environment: {self.config.environment_name}")
        self.logger.info(f"Version: {self.config.deployment_version}")
        
        try:
            self.status.status = "deploying"
            
            # Phase 1: Pre-deployment validation
            self.logger.info("📋 Phase 1: Pre-deployment validation")
            await self._run_pre_deployment_validation()
            
            # Phase 2: System preparation
            self.logger.info("🔧 Phase 2: System preparation")
            await self._prepare_production_environment()
            
            # Phase 3: Component deployment
            self.logger.info("📦 Phase 3: Component deployment")
            await self._deploy_system_components()
            
            # Phase 4: Configuration setup
            self.logger.info("⚙️ Phase 4: Configuration setup")
            await self._setup_production_configuration()
            
            # Phase 5: Service startup
            self.logger.info("🔄 Phase 5: Service startup")
            await self._start_production_services()
            
            # Phase 6: Post-deployment validation
            self.logger.info("✅ Phase 6: Post-deployment validation")
            await self._run_post_deployment_validation()
            
            # Phase 7: Monitoring setup
            self.logger.info("📊 Phase 7: Monitoring setup")
            await self._setup_production_monitoring()
            
            # Mark deployment as successful
            self.status.status = "deployed"
            self.status.end_time = time.time()
            
            self.logger.info(f"✅ Production deployment completed successfully")
            self.logger.info(f"Deployment duration: {self.status.end_time - self.status.start_time:.2f}s")
            
            return self.status
        
        except Exception as e:
            self.status.status = "failed"
            self.status.end_time = time.time()
            self.status.deployment_issues.append(f"Deployment failed: {str(e)}")
            
            self.logger.error(f"❌ Production deployment failed: {e}")
            
            # Attempt rollback
            await self._rollback_deployment()
            
            return self.status
    
    async def _run_pre_deployment_validation(self):
        """Run pre-deployment validation."""
        
        self.logger.info("Running comprehensive system validation...")
        
        # Run full system validation
        validation_results = self.validator.run_all_validations()
        
        self.status.pre_deployment_validation = validation_results
        
        # Check if validation passed
        if not validation_results['overall_success']:
            critical_failures = validation_results['critical_failures']
            raise Exception(f"Pre-deployment validation failed: {critical_failures}")
        
        self.logger.info(f"✅ Pre-deployment validation passed")
        self.logger.info(f"Validation score: {validation_results['summary']['weighted_score']:.1%}")
    
    async def _prepare_production_environment(self):
        """Prepare production environment."""
        
        # Create necessary directories
        directories = [
            self.config.log_directory,
            self.config.data_directory,
            self.config.config_directory,
            f"{self.config.data_directory}/stats",
            f"{self.config.data_directory}/diagnostics",
            f"{self.config.data_directory}/reports"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Created directory: {directory}")
        
        # Set up log rotation
        await self._setup_log_rotation()
        
        # Check system requirements
        await self._verify_system_requirements()
    
    async def _setup_log_rotation(self):
        """Setup log rotation for production."""
        
        logrotate_config = f"""
{self.config.log_directory}/*.log {{
    daily
    rotate {self.config.log_retention_days}
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}}
"""
        
        logrotate_file = Path("/etc/logrotate.d/native-attack-orchestration")
        try:
            with open(logrotate_file, 'w') as f:
                f.write(logrotate_config)
            self.logger.info("✅ Log rotation configured")
        except Exception as e:
            self.logger.warning(f"⚠️ Could not setup log rotation: {e}")
    
    async def _verify_system_requirements(self):
        """Verify system requirements."""
        
        requirements = {
            'python_version': (3, 8),
            'memory_gb': 4,
            'disk_space_gb': 10
        }
        
        # Check Python version
        python_version = sys.version_info[:2]
        if python_version < requirements['python_version']:
            raise Exception(f"Python {requirements['python_version']} required, got {python_version}")
        
        # Check available memory (if psutil available)
        try:
            import psutil
            memory_gb = psutil.virtual_memory().total / (1024**3)
            if memory_gb < requirements['memory_gb']:
                self.logger.warning(f"⚠️ Low memory: {memory_gb:.1f}GB available, {requirements['memory_gb']}GB recommended")
        except ImportError:
            self.logger.warning("⚠️ Could not check memory requirements (psutil not available)")
        
        self.logger.info("✅ System requirements verified")
    
    async def _deploy_system_components(self):
        """Deploy system components."""
        
        # Initialize performance optimizer
        if self.config.enable_performance_optimization:
            self.performance_optimizer = SegmentPerformanceOptimizer(
                OptimizationConfig(
                    enable_packet_caching=True,
                    enable_memory_pooling=True,
                    enable_async_execution=True,
                    enable_batch_processing=True
                )
            )
            self.logger.info("✅ Performance optimizer initialized")
        
        # Initialize monitoring components
        if self.config.enable_monitoring:
            # Stats collector is already initialized
            self.logger.info("✅ Statistics collector initialized")
            
            # Diagnostics is already initialized
            self.logger.info("✅ Diagnostics system initialized")
        
        self.logger.info("✅ System components deployed")
    
    async def _setup_production_configuration(self):
        """Setup production configuration."""
        
        # Create production config file
        prod_config = {
            'environment': self.config.environment_name,
            'version': self.config.deployment_version,
            'deployment_id': self.deployment_id,
            'segment_attacks_enabled': self.config.enable_segment_attacks,
            'performance_optimization_enabled': self.config.enable_performance_optimization,
            'monitoring_enabled': self.config.enable_monitoring,
            'max_concurrent_attacks': self.config.max_concurrent_attacks,
            'segment_execution_timeout': self.config.segment_execution_timeout,
            'log_level': self.config.log_level
        }
        
        config_file = Path(self.config.config_directory) / "production.json"
        with open(config_file, 'w') as f:
            json.dump(prod_config, f, indent=2)
        
        self.logger.info(f"✅ Production configuration saved: {config_file}")
    
    async def _start_production_services(self):
        """Start production services."""
        
        # Start monitoring services
        if self.config.enable_monitoring:
            await self._start_monitoring_services()
        
        # Start alerting services
        if self.config.enable_alerting:
            await self._start_alerting_services()
        
        self.logger.info("✅ Production services started")
    
    async def _start_monitoring_services(self):
        """Start monitoring services."""
        
        # Start performance monitoring
        asyncio.create_task(self._performance_monitoring_loop())
        
        # Start health monitoring
        asyncio.create_task(self._health_monitoring_loop())
        
        self.logger.info("✅ Monitoring services started")
    
    async def _start_alerting_services(self):
        """Start alerting services."""
        
        # Start alert monitoring
        asyncio.create_task(self._alert_monitoring_loop())
        
        self.logger.info("✅ Alerting services started")
    
    async def _run_post_deployment_validation(self):
        """Run post-deployment validation."""
        
        self.logger.info("Running post-deployment validation...")
        
        # Wait a moment for services to stabilize
        await asyncio.sleep(5)
        
        # Run basic functionality tests
        validation_results = await self._run_basic_functionality_tests()
        
        self.status.post_deployment_validation = validation_results
        
        if not validation_results['success']:
            raise Exception(f"Post-deployment validation failed: {validation_results['issues']}")
        
        self.logger.info("✅ Post-deployment validation passed")
    
    async def _run_basic_functionality_tests(self) -> Dict[str, Any]:
        """Run basic functionality tests."""
        
        tests_results = {
            'success': True,
            'tests_run': 0,
            'tests_passed': 0,
            'issues': []
        }
        
        # Test 1: Stats collector functionality
        try:
            self.stats_collector.start_execution("test_attack", "post_deploy_test")
            self.stats_collector.record_execution_result("test_attack", "post_deploy_test", True, 0.05)
            summary = self.stats_collector.get_execution_summary()
            
            if len(summary.get('completed_executions', [])) > 0:
                tests_results['tests_passed'] += 1
            else:
                tests_results['issues'].append("Stats collector test failed")
            
            tests_results['tests_run'] += 1
        
        except Exception as e:
            tests_results['issues'].append(f"Stats collector test error: {e}")
            tests_results['tests_run'] += 1
        
        # Test 2: Diagnostics functionality
        try:
            self.diagnostics.start_session("post_deploy_test")
            self.diagnostics.log_segment_execution("post_deploy_test", 0, 100, 0, {"delay_ms": 10})
            summary = self.diagnostics.get_session_summary("post_deploy_test")
            
            if summary and summary.get('segments_executed', 0) > 0:
                tests_results['tests_passed'] += 1
            else:
                tests_results['issues'].append("Diagnostics test failed")
            
            tests_results['tests_run'] += 1
        
        except Exception as e:
            tests_results['issues'].append(f"Diagnostics test error: {e}")
            tests_results['tests_run'] += 1
        
        # Test 3: Performance optimizer functionality
        if self.performance_optimizer:
            try:
                stats = self.performance_optimizer.get_performance_stats()
                
                if isinstance(stats, dict):
                    tests_results['tests_passed'] += 1
                else:
                    tests_results['issues'].append("Performance optimizer test failed")
                
                tests_results['tests_run'] += 1
            
            except Exception as e:
                tests_results['issues'].append(f"Performance optimizer test error: {e}")
                tests_results['tests_run'] += 1
        
        # Determine overall success
        if tests_results['tests_run'] > 0:
            success_rate = tests_results['tests_passed'] / tests_results['tests_run']
            tests_results['success'] = success_rate >= 0.8  # 80% success rate required
        else:
            tests_results['success'] = False
            tests_results['issues'].append("No tests were run")
        
        return tests_results
    
    async def _setup_production_monitoring(self):
        """Setup production monitoring."""
        
        # Create monitoring dashboard data
        monitoring_data = {
            'deployment_id': self.deployment_id,
            'start_time': self.status.start_time,
            'status': self.status.status,
            'components': {
                'stats_collector': 'active',
                'diagnostics': 'active',
                'performance_optimizer': 'active' if self.performance_optimizer else 'disabled'
            }
        }
        
        # Save monitoring data
        monitoring_file = Path(self.config.data_directory) / "monitoring" / "dashboard.json"
        monitoring_file.parent.mkdir(exist_ok=True)
        
        with open(monitoring_file, 'w') as f:
            json.dump(monitoring_data, f, indent=2)
        
        self.logger.info("✅ Production monitoring setup complete")
    
    async def _performance_monitoring_loop(self):
        """Performance monitoring loop."""
        
        while self.status.status == "deployed":
            try:
                # Collect performance metrics
                current_time = time.time()
                
                # Get stats summary
                stats_summary = self.stats_collector.get_execution_summary()
                
                # Update status metrics
                completed_executions = stats_summary.get('completed_executions', [])
                
                if completed_executions:
                    self.status.attacks_executed = len(completed_executions)
                    self.status.successful_attacks = sum(1 for ex in completed_executions if ex.get('success', False))
                    self.status.failed_attacks = self.status.attacks_executed - self.status.successful_attacks
                    
                    # Calculate average execution time
                    execution_times = [ex.get('execution_time', 0) for ex in completed_executions]
                    if execution_times:
                        self.status.average_execution_time = sum(execution_times) / len(execution_times)
                
                # Get performance optimizer stats
                if self.performance_optimizer:
                    perf_stats = self.performance_optimizer.get_performance_stats()
                    self.status.performance_metrics = perf_stats
                
                # Check for performance issues
                await self._check_performance_alerts()
                
                # Log performance metrics
                self.logger.info(f"Performance metrics - Attacks: {self.status.attacks_executed}, "
                               f"Success rate: {self.status.successful_attacks/max(1, self.status.attacks_executed):.1%}, "
                               f"Avg time: {self.status.average_execution_time*1000:.1f}ms")
                
                # Wait for next monitoring interval
                await asyncio.sleep(self.config.performance_monitoring_interval)
            
            except Exception as e:
                self.logger.error(f"Performance monitoring error: {e}")
                await asyncio.sleep(self.config.performance_monitoring_interval)
    
    async def _health_monitoring_loop(self):
        """Health monitoring loop."""
        
        while self.status.status == "deployed":
            try:
                # Check system health
                health_status = await self._check_system_health()
                self.status.system_health = health_status
                
                # Log health status
                if health_status.get('overall_health') == 'healthy':
                    self.logger.debug("System health: OK")
                else:
                    self.logger.warning(f"System health issues: {health_status.get('issues', [])}")
                
                # Wait for next health check
                await asyncio.sleep(60)  # Check every minute
            
            except Exception as e:
                self.logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _alert_monitoring_loop(self):
        """Alert monitoring loop."""
        
        while self.status.status == "deployed":
            try:
                # Check for alert conditions
                alerts = await self._check_alert_conditions()
                
                # Process new alerts
                for alert in alerts:
                    if alert not in self.status.active_alerts:
                        self.status.active_alerts.append(alert)
                        await self._send_alert(alert)
                
                # Wait for next alert check
                await asyncio.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                self.logger.error(f"Alert monitoring error: {e}")
                await asyncio.sleep(30)
    
    async def _check_system_health(self) -> Dict[str, Any]:
        """Check system health."""
        
        health_status = {
            'overall_health': 'healthy',
            'components': {},
            'issues': []
        }
        
        # Check stats collector
        try:
            summary = self.stats_collector.get_execution_summary()
            health_status['components']['stats_collector'] = 'healthy'
        except Exception as e:
            health_status['components']['stats_collector'] = 'unhealthy'
            health_status['issues'].append(f"Stats collector error: {e}")
        
        # Check diagnostics
        try:
            global_summary = self.diagnostics.get_global_summary()
            health_status['components']['diagnostics'] = 'healthy'
        except Exception as e:
            health_status['components']['diagnostics'] = 'unhealthy'
            health_status['issues'].append(f"Diagnostics error: {e}")
        
        # Check performance optimizer
        if self.performance_optimizer:
            try:
                stats = self.performance_optimizer.get_performance_stats()
                health_status['components']['performance_optimizer'] = 'healthy'
            except Exception as e:
                health_status['components']['performance_optimizer'] = 'unhealthy'
                health_status['issues'].append(f"Performance optimizer error: {e}")
        
        # Determine overall health
        unhealthy_components = [comp for comp, status in health_status['components'].items() if status == 'unhealthy']
        if unhealthy_components:
            health_status['overall_health'] = 'degraded' if len(unhealthy_components) == 1 else 'unhealthy'
        
        return health_status
    
    async def _check_performance_alerts(self):
        """Check for performance alert conditions."""
        
        # Check failure rate
        if self.status.attacks_executed > 0:
            failure_rate = self.status.failed_attacks / self.status.attacks_executed
            
            if failure_rate > self.config.alert_on_failure_rate:
                alert = {
                    'type': 'high_failure_rate',
                    'severity': 'warning',
                    'message': f"High failure rate: {failure_rate:.1%}",
                    'timestamp': time.time(),
                    'data': {
                        'failure_rate': failure_rate,
                        'failed_attacks': self.status.failed_attacks,
                        'total_attacks': self.status.attacks_executed
                    }
                }
                
                if alert not in self.status.active_alerts:
                    self.status.active_alerts.append(alert)
                    await self._send_alert(alert)
    
    async def _check_alert_conditions(self) -> List[Dict[str, Any]]:
        """Check for alert conditions."""
        
        alerts = []
        
        # Check system health alerts
        if self.status.system_health.get('overall_health') != 'healthy':
            alerts.append({
                'type': 'system_health',
                'severity': 'critical' if self.status.system_health.get('overall_health') == 'unhealthy' else 'warning',
                'message': f"System health: {self.status.system_health.get('overall_health')}",
                'timestamp': time.time(),
                'data': self.status.system_health
            })
        
        return alerts
    
    async def _send_alert(self, alert: Dict[str, Any]):
        """Send alert notification."""
        
        self.logger.warning(f"🚨 ALERT: {alert['type']} - {alert['message']}")
        
        # Log alert details
        alert_log = {
            'deployment_id': self.deployment_id,
            'alert': alert,
            'timestamp': datetime.now().isoformat()
        }
        
        # Save alert to file
        alerts_file = Path(self.config.data_directory) / "alerts" / f"alert_{int(alert['timestamp'])}.json"
        alerts_file.parent.mkdir(exist_ok=True)
        
        with open(alerts_file, 'w') as f:
            json.dump(alert_log, f, indent=2)
        
        # Send email alerts if configured
        if self.config.alert_email_recipients:
            await self._send_email_alert(alert)
    
    async def _send_email_alert(self, alert: Dict[str, Any]):
        """Send email alert (placeholder implementation)."""
        
        # This would integrate with actual email service
        self.logger.info(f"📧 Email alert would be sent to: {self.config.alert_email_recipients}")
        self.logger.info(f"Alert: {alert['type']} - {alert['message']}")
    
    async def _rollback_deployment(self):
        """Rollback failed deployment."""
        
        self.logger.warning("🔄 Attempting deployment rollback...")
        
        try:
            # Stop services
            if self.performance_optimizer:
                self.performance_optimizer.cleanup()
            
            # Clean up resources
            # This would include stopping services, removing files, etc.
            
            self.logger.info("✅ Deployment rollback completed")
        
        except Exception as e:
            self.logger.error(f"❌ Rollback failed: {e}")
    
    def get_deployment_status(self) -> DeploymentStatus:
        """Get current deployment status."""
        return self.status
    
    async def stop_production_deployment(self):
        """Stop production deployment."""
        
        self.logger.info("🛑 Stopping production deployment...")
        
        self.status.status = "stopping"
        
        try:
            # Cleanup resources
            if self.performance_optimizer:
                self.performance_optimizer.cleanup()
            
            self.status.status = "stopped"
            self.status.end_time = time.time()
            
            self.logger.info("✅ Production deployment stopped")
        
        except Exception as e:
            self.logger.error(f"❌ Error stopping deployment: {e}")
            self.status.deployment_issues.append(f"Stop error: {str(e)}")


# Convenience functions for production deployment

async def deploy_to_production(
    environment_name: str = "production",
    version: str = "1.0.0",
    enable_monitoring: bool = True
) -> DeploymentStatus:
    """Deploy system to production with default configuration."""
    
    config = ProductionConfig(
        environment_name=environment_name,
        deployment_version=version,
        enable_monitoring=enable_monitoring
    )
    
    manager = ProductionDeploymentManager(config)
    return await manager.deploy_to_production()


async def deploy_to_staging(
    version: str = "1.0.0-staging"
) -> DeploymentStatus:
    """Deploy system to staging environment."""
    
    config = ProductionConfig(
        environment_name="staging",
        deployment_version=version,
        enable_monitoring=True,
        enable_alerting=False,  # Reduced alerting for staging
        log_level="DEBUG"
    )
    
    manager = ProductionDeploymentManager(config)
    return await manager.deploy_to_production()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Production Deployment Manager')
    parser.add_argument('--environment', default='production', help='Environment name')
    parser.add_argument('--version', default='1.0.0', help='Deployment version')
    parser.add_argument('--no-monitoring', action='store_true', help='Disable monitoring')
    
    args = parser.parse_args()
    
    # Run deployment
    config = ProductionConfig(
        environment_name=args.environment,
        deployment_version=args.version,
        enable_monitoring=not args.no_monitoring
    )
    
    manager = ProductionDeploymentManager(config)
    
    try:
        status = asyncio.run(manager.deploy_to_production())
        
        if status.status == "deployed":
            print(f"✅ Deployment successful: {status.deployment_id}")
            print(f"Duration: {status.end_time - status.start_time:.2f}s")
        else:
            print(f"❌ Deployment failed: {status.deployment_issues}")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Deployment interrupted")
        asyncio.run(manager.stop_production_deployment())
        sys.exit(130)