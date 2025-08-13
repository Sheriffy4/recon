#!/usr/bin/env python3
"""
Advanced Diagnostics and Optimization Recommendations for Phase 2.
Provides intelligent diagnostics and optimization suggestions.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# Setup logging
LOG = logging.getLogger(__name__)

class DiagnosticSeverity(Enum):
    """Diagnostic issue severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class OptimizationCategory(Enum):
    """Optimization recommendation categories."""
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    EFFECTIVENESS = "effectiveness"
    RESOURCE_USAGE = "resource_usage"
    CONFIGURATION = "configuration"

@dataclass
class DiagnosticIssue:
    """Diagnostic issue found in the system."""
    issue_id: str
    severity: DiagnosticSeverity
    category: str
    title: str
    description: str
    affected_components: List[str]
    impact_assessment: str
    timestamp: datetime
    metrics: Dict[str, Any]
    recommendations: List[str]

@dataclass
class OptimizationRecommendation:
    """Optimization recommendation for system improvement."""
    recommendation_id: str
    category: OptimizationCategory
    priority: int  # 1-10, 10 being highest
    title: str
    description: str
    expected_improvement: str
    implementation_effort: str  # 'low', 'medium', 'high'
    affected_systems: List[str]
    implementation_steps: List[str]
    success_metrics: List[str]

@dataclass
class SystemDiagnosticReport:
    """Comprehensive system diagnostic report."""
    report_id: str
    timestamp: datetime
    system_health_score: float
    total_issues: int
    critical_issues: int
    warning_issues: int
    issues: List[DiagnosticIssue]
    recommendations: List[OptimizationRecommendation]
    system_metrics: Dict[str, Any]

class AdvancedDiagnostics:
    """Advanced diagnostics and optimization system."""
    
    def __init__(self):
        self.diagnostic_history = []
        self.performance_monitor = None
        self.reporting_integration = None
        self.attack_manager = None
        
        # Diagnostic thresholds
        self.thresholds = {
            'critical_success_rate': 30.0,
            'warning_success_rate': 60.0,
            'critical_execution_time_ms': 10000.0,
            'warning_execution_time_ms': 5000.0,
            'critical_memory_usage_mb': 1000.0,
            'warning_memory_usage_mb': 500.0,
            'critical_error_rate': 50.0,
            'warning_error_rate': 20.0,
            'critical_health_score': 40.0,
            'warning_health_score': 70.0
        }
        
        LOG.info("Advanced Diagnostics system initialized")
    
    async def initialize(self) -> bool:
        """Initialize the diagnostics system."""
        
        try:
            # Initialize dependencies
            from core.integration.advanced_performance_monitor import get_performance_monitor
            self.performance_monitor = get_performance_monitor()
            
            from core.integration.advanced_reporting_integration import get_reporting_integration
            self.reporting_integration = get_reporting_integration()
            
            from core.integration.advanced_attack_manager import get_advanced_attack_manager
            self.attack_manager = get_advanced_attack_manager()
            
            LOG.info("Advanced diagnostics initialized successfully")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to initialize advanced diagnostics: {e}")
            return False
    
    async def run_comprehensive_diagnostics(self) -> SystemDiagnosticReport:
        """Run comprehensive system diagnostics."""
        
        try:
            report_id = f"diag_{int(time.time())}"
            timestamp = datetime.now()
            
            LOG.info("Starting comprehensive system diagnostics")
            
            # Collect system metrics
            system_metrics = await self._collect_system_metrics()
            
            # Run diagnostic checks
            issues = []
            
            # Performance diagnostics
            performance_issues = await self._diagnose_performance_issues()
            issues.extend(performance_issues)
            
            # Attack system diagnostics
            attack_issues = await self._diagnose_attack_system_issues()
            issues.extend(attack_issues)
            
            # Resource usage diagnostics
            resource_issues = await self._diagnose_resource_usage_issues()
            issues.extend(resource_issues)
            
            # Integration diagnostics
            integration_issues = await self._diagnose_integration_issues()
            issues.extend(integration_issues)
            
            # Configuration diagnostics
            config_issues = await self._diagnose_configuration_issues()
            issues.extend(config_issues)
            
            # Calculate system health score
            system_health_score = await self._calculate_system_health_score(issues, system_metrics)
            
            # Generate optimization recommendations
            recommendations = await self._generate_optimization_recommendations(issues, system_metrics)
            
            # Count issues by severity
            critical_issues = len([i for i in issues if i.severity == DiagnosticSeverity.CRITICAL])
            warning_issues = len([i for i in issues if i.severity == DiagnosticSeverity.WARNING])
            
            # Create diagnostic report
            report = SystemDiagnosticReport(
                report_id=report_id,
                timestamp=timestamp,
                system_health_score=system_health_score,
                total_issues=len(issues),
                critical_issues=critical_issues,
                warning_issues=warning_issues,
                issues=issues,
                recommendations=recommendations,
                system_metrics=system_metrics
            )
            
            # Store report
            self.diagnostic_history.append(report)
            
            LOG.info(f"Comprehensive diagnostics completed: {len(issues)} issues found, "
                    f"health score: {system_health_score:.1f}")
            
            return report
            
        except Exception as e:
            LOG.error(f"Failed to run comprehensive diagnostics: {e}")
            return None
    
    async def diagnose_attack_performance(self, attack_name: str) -> List[DiagnosticIssue]:
        """Diagnose performance issues for specific attack."""
        
        try:
            issues = []
            
            if not self.performance_monitor:
                return issues
            
            # Get attack performance summary
            performance_summary = await self.performance_monitor.get_attack_performance_summary(attack_name)
            
            if 'error' in performance_summary:
                return issues
            
            # Check success rate
            success_rate = performance_summary.get('success_rate_percent', 0)
            if success_rate < self.thresholds['critical_success_rate']:
                issue = DiagnosticIssue(
                    issue_id=f"attack_success_critical_{attack_name}",
                    severity=DiagnosticSeverity.CRITICAL,
                    category="attack_performance",
                    title=f"Critical Success Rate for {attack_name}",
                    description=f"Attack {attack_name} has critically low success rate: {success_rate:.1f}%",
                    affected_components=[attack_name],
                    impact_assessment="Severely impacts bypass effectiveness",
                    timestamp=datetime.now(),
                    metrics={'success_rate_percent': success_rate},
                    recommendations=[
                        "Review attack configuration and parameters",
                        "Analyze target compatibility",
                        "Consider alternative attack strategies"
                    ]
                )
                issues.append(issue)
            elif success_rate < self.thresholds['warning_success_rate']:
                issue = DiagnosticIssue(
                    issue_id=f"attack_success_warning_{attack_name}",
                    severity=DiagnosticSeverity.WARNING,
                    category="attack_performance",
                    title=f"Low Success Rate for {attack_name}",
                    description=f"Attack {attack_name} has low success rate: {success_rate:.1f}%",
                    affected_components=[attack_name],
                    impact_assessment="Reduces overall bypass effectiveness",
                    timestamp=datetime.now(),
                    metrics={'success_rate_percent': success_rate},
                    recommendations=[
                        "Monitor performance trends",
                        "Consider parameter optimization",
                        "Review recent failures"
                    ]
                )
                issues.append(issue)
            
            # Check execution time
            execution_stats = performance_summary.get('execution_time_stats', {})
            mean_time = execution_stats.get('mean_ms', 0)
            
            if mean_time > self.thresholds['critical_execution_time_ms']:
                issue = DiagnosticIssue(
                    issue_id=f"attack_time_critical_{attack_name}",
                    severity=DiagnosticSeverity.CRITICAL,
                    category="attack_performance",
                    title=f"Critical Execution Time for {attack_name}",
                    description=f"Attack {attack_name} has critically high execution time: {mean_time:.1f}ms",
                    affected_components=[attack_name],
                    impact_assessment="Severely impacts system responsiveness",
                    timestamp=datetime.now(),
                    metrics={'mean_execution_time_ms': mean_time},
                    recommendations=[
                        "Optimize attack implementation",
                        "Review timeout configurations",
                        "Consider performance profiling"
                    ]
                )
                issues.append(issue)
            elif mean_time > self.thresholds['warning_execution_time_ms']:
                issue = DiagnosticIssue(
                    issue_id=f"attack_time_warning_{attack_name}",
                    severity=DiagnosticSeverity.WARNING,
                    category="attack_performance",
                    title=f"High Execution Time for {attack_name}",
                    description=f"Attack {attack_name} has high execution time: {mean_time:.1f}ms",
                    affected_components=[attack_name],
                    impact_assessment="May impact system responsiveness",
                    timestamp=datetime.now(),
                    metrics={'mean_execution_time_ms': mean_time},
                    recommendations=[
                        "Monitor execution time trends",
                        "Consider parameter optimization",
                        "Review network conditions"
                    ]
                )
                issues.append(issue)
            
            # Check effectiveness
            effectiveness_stats = performance_summary.get('effectiveness_stats', {})
            mean_effectiveness = effectiveness_stats.get('mean_score', 0)
            
            if mean_effectiveness < 0.3:
                issue = DiagnosticIssue(
                    issue_id=f"attack_effectiveness_low_{attack_name}",
                    severity=DiagnosticSeverity.ERROR,
                    category="attack_effectiveness",
                    title=f"Low Effectiveness for {attack_name}",
                    description=f"Attack {attack_name} has low effectiveness: {mean_effectiveness:.2f}",
                    affected_components=[attack_name],
                    impact_assessment="Reduces bypass success probability",
                    timestamp=datetime.now(),
                    metrics={'mean_effectiveness': mean_effectiveness},
                    recommendations=[
                        "Review attack configuration",
                        "Analyze target characteristics",
                        "Consider attack replacement"
                    ]
                )
                issues.append(issue)
            
            return issues
            
        except Exception as e:
            LOG.error(f"Failed to diagnose attack performance for {attack_name}: {e}")
            return []
    
    async def get_optimization_recommendations(self, 
                                            category: Optional[OptimizationCategory] = None,
                                            min_priority: int = 1) -> List[OptimizationRecommendation]:
        """Get optimization recommendations."""
        
        try:
            # Run diagnostics if needed
            if not self.diagnostic_history:
                await self.run_comprehensive_diagnostics()
            
            if not self.diagnostic_history:
                return []
            
            # Get latest recommendations
            latest_report = self.diagnostic_history[-1]
            recommendations = latest_report.recommendations
            
            # Filter by category if specified
            if category:
                recommendations = [r for r in recommendations if r.category == category]
            
            # Filter by priority
            recommendations = [r for r in recommendations if r.priority >= min_priority]
            
            # Sort by priority (highest first)
            recommendations.sort(key=lambda x: x.priority, reverse=True)
            
            return recommendations
            
        except Exception as e:
            LOG.error(f"Failed to get optimization recommendations: {e}")
            return []
    
    async def get_system_health_summary(self) -> Dict[str, Any]:
        """Get system health summary."""
        
        try:
            # Run diagnostics if needed
            if not self.diagnostic_history:
                await self.run_comprehensive_diagnostics()
            
            if not self.diagnostic_history:
                return {'error': 'No diagnostic data available'}
            
            latest_report = self.diagnostic_history[-1]
            
            # Categorize issues
            issue_categories = {}
            for issue in latest_report.issues:
                category = issue.category
                if category not in issue_categories:
                    issue_categories[category] = {'critical': 0, 'error': 0, 'warning': 0, 'info': 0}
                
                issue_categories[category][issue.severity.value] += 1
            
            # Get health status
            health_score = latest_report.system_health_score
            if health_score >= 90:
                health_status = 'excellent'
            elif health_score >= 80:
                health_status = 'good'
            elif health_score >= 70:
                health_status = 'fair'
            elif health_score >= 60:
                health_status = 'poor'
            else:
                health_status = 'critical'
            
            # Get top recommendations
            top_recommendations = sorted(latest_report.recommendations, 
                                       key=lambda x: x.priority, reverse=True)[:5]
            
            summary = {
                'health_score': health_score,
                'health_status': health_status,
                'total_issues': latest_report.total_issues,
                'critical_issues': latest_report.critical_issues,
                'warning_issues': latest_report.warning_issues,
                'issue_categories': issue_categories,
                'top_recommendations': [
                    {
                        'title': r.title,
                        'priority': r.priority,
                        'category': r.category.value,
                        'expected_improvement': r.expected_improvement
                    } for r in top_recommendations
                ],
                'last_diagnostic_run': latest_report.timestamp.isoformat()
            }
            
            return summary
            
        except Exception as e:
            LOG.error(f"Failed to get system health summary: {e}")
            return {'error': str(e)}
    
    # Private diagnostic methods
    
    async def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system metrics."""
        
        metrics = {}
        
        try:
            # Performance metrics
            if self.performance_monitor:
                health_report = await self.performance_monitor.get_system_health_report()
                metrics['performance'] = health_report
            
            # Attack manager metrics
            if self.attack_manager:
                registered_attacks = self.attack_manager.get_registered_attacks()
                performance_metrics = await self.attack_manager.get_performance_metrics()
                
                metrics['attack_manager'] = {
                    'registered_attacks': len(registered_attacks),
                    'attack_names': list(registered_attacks.keys()),
                    'performance_metrics': performance_metrics
                }
            
            # System resource metrics
            try:
                import psutil
                import os
                
                process = psutil.Process(os.getpid())
                metrics['system_resources'] = {
                    'memory_usage_mb': process.memory_info().rss / 1024 / 1024,
                    'cpu_percent': psutil.cpu_percent(interval=0.1),
                    'open_files': len(process.open_files()),
                    'connections': len(process.connections())
                }
            except ImportError:
                metrics['system_resources'] = {'error': 'psutil not available'}
            
            return metrics
            
        except Exception as e:
            LOG.error(f"Failed to collect system metrics: {e}")
            return {'error': str(e)}
    
    async def _diagnose_performance_issues(self) -> List[DiagnosticIssue]:
        """Diagnose performance-related issues."""
        
        issues = []
        
        try:
            if not self.performance_monitor:
                return issues
            
            # Get system health report
            health_report = await self.performance_monitor.get_system_health_report()
            
            if 'error' in health_report:
                return issues
            
            # Check system health score
            health_score = health_report.get('system_health_score', 100)
            if health_score < self.thresholds['critical_health_score']:
                issue = DiagnosticIssue(
                    issue_id="system_health_critical",
                    severity=DiagnosticSeverity.CRITICAL,
                    category="system_performance",
                    title="Critical System Health",
                    description=f"System health score is critically low: {health_score:.1f}",
                    affected_components=["system"],
                    impact_assessment="System may be unreliable or ineffective",
                    timestamp=datetime.now(),
                    metrics={'health_score': health_score},
                    recommendations=[
                        "Immediate investigation required",
                        "Review all system components",
                        "Check for resource constraints"
                    ]
                )
                issues.append(issue)
            elif health_score < self.thresholds['warning_health_score']:
                issue = DiagnosticIssue(
                    issue_id="system_health_warning",
                    severity=DiagnosticSeverity.WARNING,
                    category="system_performance",
                    title="Low System Health",
                    description=f"System health score is low: {health_score:.1f}",
                    affected_components=["system"],
                    impact_assessment="System performance may be degraded",
                    timestamp=datetime.now(),
                    metrics={'health_score': health_score},
                    recommendations=[
                        "Monitor system performance",
                        "Review recent changes",
                        "Consider optimization"
                    ]
                )
                issues.append(issue)
            
            # Check performance alerts
            alerts = await self.performance_monitor.get_performance_alerts()
            critical_alerts = [a for a in alerts if a.get('severity') == 'critical']
            
            if critical_alerts:
                issue = DiagnosticIssue(
                    issue_id="performance_alerts_critical",
                    severity=DiagnosticSeverity.CRITICAL,
                    category="performance_alerts",
                    title="Critical Performance Alerts",
                    description=f"System has {len(critical_alerts)} critical performance alerts",
                    affected_components=["performance_monitor"],
                    impact_assessment="System performance is severely impacted",
                    timestamp=datetime.now(),
                    metrics={'critical_alerts': len(critical_alerts)},
                    recommendations=[
                        "Address critical alerts immediately",
                        "Review alert details",
                        "Implement corrective actions"
                    ]
                )
                issues.append(issue)
            
            return issues
            
        except Exception as e:
            LOG.error(f"Failed to diagnose performance issues: {e}")
            return []
    
    async def _diagnose_attack_system_issues(self) -> List[DiagnosticIssue]:
        """Diagnose attack system issues."""
        
        issues = []
        
        try:
            if not self.attack_manager:
                return issues
            
            # Check registered attacks
            registered_attacks = self.attack_manager.get_registered_attacks()
            
            if len(registered_attacks) == 0:
                issue = DiagnosticIssue(
                    issue_id="no_attacks_registered",
                    severity=DiagnosticSeverity.CRITICAL,
                    category="attack_system",
                    title="No Attacks Registered",
                    description="No advanced attacks are registered in the system",
                    affected_components=["attack_manager"],
                    impact_assessment="System cannot perform any bypass operations",
                    timestamp=datetime.now(),
                    metrics={'registered_attacks': 0},
                    recommendations=[
                        "Initialize attack registration",
                        "Check attack module imports",
                        "Verify system configuration"
                    ]
                )
                issues.append(issue)
            elif len(registered_attacks) < 3:
                issue = DiagnosticIssue(
                    issue_id="few_attacks_registered",
                    severity=DiagnosticSeverity.WARNING,
                    category="attack_system",
                    title="Few Attacks Registered",
                    description=f"Only {len(registered_attacks)} attacks registered, limited bypass options",
                    affected_components=["attack_manager"],
                    impact_assessment="Reduced bypass effectiveness and flexibility",
                    timestamp=datetime.now(),
                    metrics={'registered_attacks': len(registered_attacks)},
                    recommendations=[
                        "Register additional attack types",
                        "Check for missing attack modules",
                        "Review attack initialization"
                    ]
                )
                issues.append(issue)
            
            # Diagnose individual attacks
            for attack_name in registered_attacks.keys():
                attack_issues = await self.diagnose_attack_performance(attack_name)
                issues.extend(attack_issues)
            
            return issues
            
        except Exception as e:
            LOG.error(f"Failed to diagnose attack system issues: {e}")
            return []
    
    async def _diagnose_resource_usage_issues(self) -> List[DiagnosticIssue]:
        """Diagnose resource usage issues."""
        
        issues = []
        
        try:
            # Check memory usage
            try:
                import psutil
                import os
                
                process = psutil.Process(os.getpid())
                memory_usage_mb = process.memory_info().rss / 1024 / 1024
                
                if memory_usage_mb > self.thresholds['critical_memory_usage_mb']:
                    issue = DiagnosticIssue(
                        issue_id="memory_usage_critical",
                        severity=DiagnosticSeverity.CRITICAL,
                        category="resource_usage",
                        title="Critical Memory Usage",
                        description=f"Memory usage is critically high: {memory_usage_mb:.1f}MB",
                        affected_components=["system"],
                        impact_assessment="System may become unstable or crash",
                        timestamp=datetime.now(),
                        metrics={'memory_usage_mb': memory_usage_mb},
                        recommendations=[
                            "Investigate memory leaks",
                            "Optimize memory usage",
                            "Consider system restart"
                        ]
                    )
                    issues.append(issue)
                elif memory_usage_mb > self.thresholds['warning_memory_usage_mb']:
                    issue = DiagnosticIssue(
                        issue_id="memory_usage_warning",
                        severity=DiagnosticSeverity.WARNING,
                        category="resource_usage",
                        title="High Memory Usage",
                        description=f"Memory usage is high: {memory_usage_mb:.1f}MB",
                        affected_components=["system"],
                        impact_assessment="System performance may be degraded",
                        timestamp=datetime.now(),
                        metrics={'memory_usage_mb': memory_usage_mb},
                        recommendations=[
                            "Monitor memory usage trends",
                            "Consider memory optimization",
                            "Review resource-intensive operations"
                        ]
                    )
                    issues.append(issue)
                
                # Check CPU usage
                cpu_percent = psutil.cpu_percent(interval=0.1)
                if cpu_percent > 90:
                    issue = DiagnosticIssue(
                        issue_id="cpu_usage_high",
                        severity=DiagnosticSeverity.WARNING,
                        category="resource_usage",
                        title="High CPU Usage",
                        description=f"CPU usage is high: {cpu_percent:.1f}%",
                        affected_components=["system"],
                        impact_assessment="System responsiveness may be reduced",
                        timestamp=datetime.now(),
                        metrics={'cpu_percent': cpu_percent},
                        recommendations=[
                            "Monitor CPU usage patterns",
                            "Optimize CPU-intensive operations",
                            "Consider load balancing"
                        ]
                    )
                    issues.append(issue)
                
            except ImportError:
                issue = DiagnosticIssue(
                    issue_id="resource_monitoring_unavailable",
                    severity=DiagnosticSeverity.INFO,
                    category="resource_usage",
                    title="Resource Monitoring Unavailable",
                    description="psutil not available for resource monitoring",
                    affected_components=["diagnostics"],
                    impact_assessment="Cannot monitor system resource usage",
                    timestamp=datetime.now(),
                    metrics={},
                    recommendations=[
                        "Install psutil for resource monitoring",
                        "Consider alternative monitoring solutions"
                    ]
                )
                issues.append(issue)
            
            return issues
            
        except Exception as e:
            LOG.error(f"Failed to diagnose resource usage issues: {e}")
            return []
    
    async def _diagnose_integration_issues(self) -> List[DiagnosticIssue]:
        """Diagnose integration issues."""
        
        issues = []
        
        try:
            # Check Phase 1 integrations
            phase1_integrations = [
                ("Strategy Prediction", "core.integration.strategy_prediction_integration"),
                ("Fingerprint Engine", "core.integration.fingerprint_integration"),
                ("Performance Monitor", "core.integration.performance_integration"),
                ("Evolutionary Optimizer", "core.integration.evolutionary_optimization_integration")
            ]
            
            failed_integrations = []
            for name, module_path in phase1_integrations:
                try:
                    __import__(module_path)
                except ImportError:
                    failed_integrations.append(name)
            
            if failed_integrations:
                issue = DiagnosticIssue(
                    issue_id="phase1_integration_failures",
                    severity=DiagnosticSeverity.ERROR,
                    category="integration",
                    title="Phase 1 Integration Failures",
                    description=f"Failed integrations: {', '.join(failed_integrations)}",
                    affected_components=failed_integrations,
                    impact_assessment="Reduced system functionality and effectiveness",
                    timestamp=datetime.now(),
                    metrics={'failed_integrations': len(failed_integrations)},
                    recommendations=[
                        "Check Phase 1 module availability",
                        "Review integration configurations",
                        "Verify dependencies"
                    ]
                )
                issues.append(issue)
            
            return issues
            
        except Exception as e:
            LOG.error(f"Failed to diagnose integration issues: {e}")
            return []
    
    async def _diagnose_configuration_issues(self) -> List[DiagnosticIssue]:
        """Diagnose configuration issues."""
        
        issues = []
        
        try:
            # Check for missing configuration files
            config_files = [
                "config/engine_config.json",
                "config/engine_config_production.json"
            ]
            
            missing_configs = []
            for config_file in config_files:
                try:
                    with open(config_file, 'r') as f:
                        pass
                except FileNotFoundError:
                    missing_configs.append(config_file)
            
            if missing_configs:
                issue = DiagnosticIssue(
                    issue_id="missing_config_files",
                    severity=DiagnosticSeverity.WARNING,
                    category="configuration",
                    title="Missing Configuration Files",
                    description=f"Missing config files: {', '.join(missing_configs)}",
                    affected_components=["configuration"],
                    impact_assessment="System may use default configurations",
                    timestamp=datetime.now(),
                    metrics={'missing_configs': len(missing_configs)},
                    recommendations=[
                        "Create missing configuration files",
                        "Review configuration templates",
                        "Verify configuration paths"
                    ]
                )
                issues.append(issue)
            
            return issues
            
        except Exception as e:
            LOG.error(f"Failed to diagnose configuration issues: {e}")
            return []
    
    async def _calculate_system_health_score(self, 
                                           issues: List[DiagnosticIssue],
                                           system_metrics: Dict[str, Any]) -> float:
        """Calculate overall system health score."""
        
        try:
            base_score = 100.0
            
            # Deduct points for issues
            for issue in issues:
                if issue.severity == DiagnosticSeverity.CRITICAL:
                    base_score -= 20.0
                elif issue.severity == DiagnosticSeverity.ERROR:
                    base_score -= 10.0
                elif issue.severity == DiagnosticSeverity.WARNING:
                    base_score -= 5.0
                elif issue.severity == DiagnosticSeverity.INFO:
                    base_score -= 1.0
            
            # Consider performance metrics if available
            if 'performance' in system_metrics:
                perf_health = system_metrics['performance'].get('system_health_score', 100)
                base_score = (base_score + perf_health) / 2
            
            return max(0.0, min(100.0, base_score))
            
        except Exception as e:
            LOG.error(f"Failed to calculate system health score: {e}")
            return 50.0  # Default neutral score
    
    async def _generate_optimization_recommendations(self, 
                                                   issues: List[DiagnosticIssue],
                                                   system_metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations based on issues and metrics."""
        
        recommendations = []
        
        try:
            # Performance optimization recommendations
            performance_issues = [i for i in issues if 'performance' in i.category]
            if performance_issues:
                rec = OptimizationRecommendation(
                    recommendation_id="optimize_performance",
                    category=OptimizationCategory.PERFORMANCE,
                    priority=8,
                    title="Optimize System Performance",
                    description="Address performance issues to improve system responsiveness",
                    expected_improvement="20-30% improvement in execution times",
                    implementation_effort="medium",
                    affected_systems=["performance_monitor", "attack_system"],
                    implementation_steps=[
                        "Identify performance bottlenecks",
                        "Optimize critical code paths",
                        "Implement caching where appropriate",
                        "Monitor performance improvements"
                    ],
                    success_metrics=[
                        "Reduced average execution time",
                        "Improved system health score",
                        "Fewer performance alerts"
                    ]
                )
                recommendations.append(rec)
            
            # Attack effectiveness recommendations
            attack_issues = [i for i in issues if 'attack' in i.category]
            if attack_issues:
                rec = OptimizationRecommendation(
                    recommendation_id="improve_attack_effectiveness",
                    category=OptimizationCategory.EFFECTIVENESS,
                    priority=9,
                    title="Improve Attack Effectiveness",
                    description="Optimize attack configurations and selection algorithms",
                    expected_improvement="15-25% improvement in success rates",
                    implementation_effort="medium",
                    affected_systems=["attack_manager", "ml_systems"],
                    implementation_steps=[
                        "Analyze attack failure patterns",
                        "Optimize attack parameters",
                        "Improve target detection",
                        "Enhance ML prediction accuracy"
                    ],
                    success_metrics=[
                        "Increased attack success rates",
                        "Better effectiveness scores",
                        "Reduced attack failures"
                    ]
                )
                recommendations.append(rec)
            
            # Resource usage recommendations
            resource_issues = [i for i in issues if 'resource' in i.category]
            if resource_issues:
                rec = OptimizationRecommendation(
                    recommendation_id="optimize_resource_usage",
                    category=OptimizationCategory.RESOURCE_USAGE,
                    priority=6,
                    title="Optimize Resource Usage",
                    description="Reduce memory and CPU usage for better system stability",
                    expected_improvement="20-40% reduction in resource usage",
                    implementation_effort="high",
                    affected_systems=["system", "attack_system"],
                    implementation_steps=[
                        "Profile resource usage patterns",
                        "Implement memory optimization",
                        "Optimize CPU-intensive operations",
                        "Add resource monitoring"
                    ],
                    success_metrics=[
                        "Reduced memory usage",
                        "Lower CPU utilization",
                        "Improved system stability"
                    ]
                )
                recommendations.append(rec)
            
            # Integration recommendations
            integration_issues = [i for i in issues if 'integration' in i.category]
            if integration_issues:
                rec = OptimizationRecommendation(
                    recommendation_id="fix_integrations",
                    category=OptimizationCategory.RELIABILITY,
                    priority=7,
                    title="Fix Integration Issues",
                    description="Resolve integration problems to restore full functionality",
                    expected_improvement="Restored system functionality",
                    implementation_effort="low",
                    affected_systems=["integration_layer"],
                    implementation_steps=[
                        "Identify failed integrations",
                        "Check dependency availability",
                        "Fix import issues",
                        "Test integration functionality"
                    ],
                    success_metrics=[
                        "All integrations working",
                        "No integration errors",
                        "Full system functionality"
                    ]
                )
                recommendations.append(rec)
            
            # Configuration recommendations
            config_issues = [i for i in issues if 'configuration' in i.category]
            if config_issues:
                rec = OptimizationRecommendation(
                    recommendation_id="improve_configuration",
                    category=OptimizationCategory.CONFIGURATION,
                    priority=5,
                    title="Improve System Configuration",
                    description="Create and optimize system configuration files",
                    expected_improvement="Better system reliability and performance",
                    implementation_effort="low",
                    affected_systems=["configuration"],
                    implementation_steps=[
                        "Create missing configuration files",
                        "Review and optimize settings",
                        "Document configuration options",
                        "Implement configuration validation"
                    ],
                    success_metrics=[
                        "All configuration files present",
                        "Optimized system settings",
                        "No configuration warnings"
                    ]
                )
                recommendations.append(rec)
            
            # Sort by priority
            recommendations.sort(key=lambda x: x.priority, reverse=True)
            
            return recommendations
            
        except Exception as e:
            LOG.error(f"Failed to generate optimization recommendations: {e}")
            return []

# Global diagnostics instance
_diagnostics = None

def get_diagnostics() -> AdvancedDiagnostics:
    """Get the global diagnostics instance."""
    global _diagnostics
    if _diagnostics is None:
        _diagnostics = AdvancedDiagnostics()
    return _diagnostics

async def initialize_advanced_diagnostics() -> bool:
    """Initialize the advanced diagnostics system."""
    try:
        diagnostics = get_diagnostics()
        return await diagnostics.initialize()
    except Exception as e:
        LOG.error(f"Failed to initialize advanced diagnostics: {e}")
        return False