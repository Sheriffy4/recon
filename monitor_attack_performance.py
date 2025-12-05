"""
Attack Performance Monitoring and Optimization Tool.

Monitors attack execution metrics, analyzes performance data,
identifies optimization opportunities, and prepares for production deployment.

This script implements task 15.5: Monitor and optimize.
"""

import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import sys
from pathlib import Path

# Add core to path
sys.path.insert(0, str(Path(__file__).parent))

from core.bypass.attacks.telemetry.telemetry_system import (
    get_telemetry_system,
    initialize_telemetry
)
from core.bypass.attacks.telemetry.metrics_endpoint import (
    start_metrics_endpoint,
    get_metrics_endpoint
)
from core.bypass.attacks.telemetry.performance_monitor import (
    DegradationType,
    DegradationSeverity
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class OptimizationOpportunity:
    """Represents an optimization opportunity."""
    
    attack_name: str
    opportunity_type: str
    severity: str
    description: str
    current_value: float
    target_value: float
    potential_improvement: float
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class PerformanceReport:
    """Comprehensive performance report."""
    
    timestamp: datetime
    total_attacks_monitored: int
    total_executions: int
    global_success_rate: float
    global_avg_execution_time_ms: float
    degradations_detected: int
    optimization_opportunities: List[OptimizationOpportunity]
    top_performers: List[Dict[str, Any]]
    underperformers: List[Dict[str, Any]]
    recommendations: List[str]
    ready_for_production: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['optimization_opportunities'] = [
            opp.to_dict() for opp in self.optimization_opportunities
        ]
        return data


class AttackPerformanceMonitor:
    """
    Comprehensive attack performance monitoring and optimization tool.
    
    Features:
    - Real-time metrics monitoring
    - Performance degradation detection
    - Optimization opportunity identification
    - Production readiness assessment
    - Automated recommendations
    """
    
    def __init__(self):
        """Initialize performance monitor."""
        self.logger = logging.getLogger("attack_performance_monitor")
        
        # Initialize telemetry system
        self.telemetry = initialize_telemetry(
            structured_logging=True,
            enable_performance_monitoring=True
        )
        
        # Performance thresholds
        self.thresholds = {
            'min_success_rate': 0.95,  # 95% success rate
            'max_avg_execution_time_ms': 100,  # 100ms average
            'max_error_rate': 0.05,  # 5% error rate
            'max_fallback_rate': 0.10,  # 10% fallback rate
            'min_throughput_pps': 1000  # 1000 packets/second
        }
        
        self.logger.info("✅ Attack Performance Monitor initialized")
    
    def start_monitoring(self, duration_seconds: int = 60):
        """
        Start monitoring for a specified duration.
        
        Args:
            duration_seconds: Duration to monitor in seconds
        """
        self.logger.info(f"🔍 Starting performance monitoring for {duration_seconds} seconds...")
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        # Start metrics endpoint
        try:
            metrics_server = start_metrics_endpoint(host='127.0.0.1', port=9090)
            self.logger.info(f"📊 Metrics endpoint available at {metrics_server.get_url()}/metrics")
        except Exception as e:
            self.logger.warning(f"Could not start metrics endpoint: {e}")
        
        # Monitor loop
        sample_count = 0
        while time.time() < end_time:
            sample_count += 1
            
            # Get current metrics
            snapshot = self.telemetry.get_metrics_snapshot()
            
            # Log summary
            self.logger.info(
                f"📈 Sample {sample_count}: "
                f"{len(snapshot.attack_metrics)} attacks, "
                f"{snapshot.global_stats.get('total_executions', 0)} executions, "
                f"{snapshot.global_stats.get('global_success_rate', 0):.1%} success rate"
            )
            
            # Check for degradations
            degradations = self.telemetry.get_recent_degradations(limit=5)
            if degradations:
                self.logger.warning(f"⚠️ {len(degradations)} performance degradations detected")
            
            # Wait before next sample
            time.sleep(10)
        
        self.logger.info("✅ Monitoring period complete")
    
    def analyze_performance(self) -> PerformanceReport:
        """
        Analyze current performance and generate comprehensive report.
        
        Returns:
            Performance report with analysis and recommendations
        """
        self.logger.info("🔍 Analyzing attack performance...")
        
        # Get metrics snapshot
        snapshot = self.telemetry.get_metrics_snapshot()
        
        # Get performance baselines
        baselines = self.telemetry.get_performance_baselines()
        
        # Get degradations
        degradations = self.telemetry.get_recent_degradations()
        
        # Analyze each attack
        optimization_opportunities = []
        top_performers = []
        underperformers = []
        
        for attack_name, metrics in snapshot.attack_metrics.items():
            # Check success rate
            if metrics.success_rate < self.thresholds['min_success_rate']:
                opportunity = OptimizationOpportunity(
                    attack_name=attack_name,
                    opportunity_type='success_rate',
                    severity='high' if metrics.success_rate < 0.80 else 'medium',
                    description=f"Success rate ({metrics.success_rate:.1%}) below threshold ({self.thresholds['min_success_rate']:.1%})",
                    current_value=metrics.success_rate,
                    target_value=self.thresholds['min_success_rate'],
                    potential_improvement=(self.thresholds['min_success_rate'] - metrics.success_rate) * 100,
                    recommendations=[
                        "Review error logs for common failure patterns",
                        "Validate attack parameters are correct",
                        "Check for protocol compliance issues",
                        "Consider adding retry logic for transient failures"
                    ]
                )
                optimization_opportunities.append(opportunity)
                underperformers.append({
                    'attack_name': attack_name,
                    'reason': 'low_success_rate',
                    'value': metrics.success_rate
                })
            
            # Check execution time
            if metrics.avg_execution_time_ms > self.thresholds['max_avg_execution_time_ms']:
                opportunity = OptimizationOpportunity(
                    attack_name=attack_name,
                    opportunity_type='execution_time',
                    severity='high' if metrics.avg_execution_time_ms > 200 else 'medium',
                    description=f"Average execution time ({metrics.avg_execution_time_ms:.1f}ms) exceeds threshold ({self.thresholds['max_avg_execution_time_ms']}ms)",
                    current_value=metrics.avg_execution_time_ms,
                    target_value=self.thresholds['max_avg_execution_time_ms'],
                    potential_improvement=((metrics.avg_execution_time_ms - self.thresholds['max_avg_execution_time_ms']) / metrics.avg_execution_time_ms) * 100,
                    recommendations=[
                        "Profile attack execution to identify bottlenecks",
                        "Consider caching frequently computed values",
                        "Optimize buffer allocations and reuse",
                        "Use hardware acceleration if available",
                        "Review algorithm complexity"
                    ]
                )
                optimization_opportunities.append(opportunity)
                underperformers.append({
                    'attack_name': attack_name,
                    'reason': 'slow_execution',
                    'value': metrics.avg_execution_time_ms
                })
            
            # Check error rate
            if metrics.error_rate > self.thresholds['max_error_rate']:
                opportunity = OptimizationOpportunity(
                    attack_name=attack_name,
                    opportunity_type='error_rate',
                    severity='critical' if metrics.error_rate > 0.20 else 'high',
                    description=f"Error rate ({metrics.error_rate:.1%}) exceeds threshold ({self.thresholds['max_error_rate']:.1%})",
                    current_value=metrics.error_rate,
                    target_value=self.thresholds['max_error_rate'],
                    potential_improvement=(metrics.error_rate - self.thresholds['max_error_rate']) * 100,
                    recommendations=[
                        "Review error logs for root causes",
                        "Add input validation and error handling",
                        "Check for resource exhaustion issues",
                        "Validate dependencies are available",
                        "Add defensive programming checks"
                    ]
                )
                optimization_opportunities.append(opportunity)
                underperformers.append({
                    'attack_name': attack_name,
                    'reason': 'high_error_rate',
                    'value': metrics.error_rate
                })
            
            # Check fallback rate
            if metrics.fallback_rate > self.thresholds['max_fallback_rate']:
                opportunity = OptimizationOpportunity(
                    attack_name=attack_name,
                    opportunity_type='fallback_rate',
                    severity='medium',
                    description=f"Fallback rate ({metrics.fallback_rate:.1%}) exceeds threshold ({self.thresholds['max_fallback_rate']:.1%})",
                    current_value=metrics.fallback_rate,
                    target_value=self.thresholds['max_fallback_rate'],
                    potential_improvement=(metrics.fallback_rate - self.thresholds['max_fallback_rate']) * 100,
                    recommendations=[
                        "Verify advanced attack implementation is registered",
                        "Check attack priority in registration",
                        "Review conditions that trigger fallback",
                        "Ensure attack parameters are compatible"
                    ]
                )
                optimization_opportunities.append(opportunity)
            
            # Identify top performers
            if (metrics.success_rate >= self.thresholds['min_success_rate'] and
                metrics.avg_execution_time_ms <= self.thresholds['max_avg_execution_time_ms'] and
                metrics.error_rate <= self.thresholds['max_error_rate']):
                top_performers.append({
                    'attack_name': attack_name,
                    'success_rate': metrics.success_rate,
                    'avg_execution_time_ms': metrics.avg_execution_time_ms,
                    'total_executions': metrics.total_executions
                })
        
        # Sort top performers by success rate
        top_performers.sort(key=lambda x: x['success_rate'], reverse=True)
        
        # Calculate global metrics
        total_executions = snapshot.global_stats.get('total_executions', 0)
        global_success_rate = snapshot.global_stats.get('global_success_rate', 0.0)
        
        # Calculate global average execution time
        total_time = sum(m.total_execution_time_ms for m in snapshot.attack_metrics.values())
        global_avg_time = total_time / total_executions if total_executions > 0 else 0.0
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            snapshot,
            optimization_opportunities,
            degradations
        )
        
        # Assess production readiness
        ready_for_production = self._assess_production_readiness(
            snapshot,
            optimization_opportunities,
            degradations
        )
        
        # Create report
        report = PerformanceReport(
            timestamp=datetime.now(),
            total_attacks_monitored=len(snapshot.attack_metrics),
            total_executions=total_executions,
            global_success_rate=global_success_rate,
            global_avg_execution_time_ms=global_avg_time,
            degradations_detected=len(degradations),
            optimization_opportunities=optimization_opportunities,
            top_performers=top_performers[:10],
            underperformers=underperformers,
            recommendations=recommendations,
            ready_for_production=ready_for_production
        )
        
        self.logger.info("✅ Performance analysis complete")
        
        return report
    
    def _generate_recommendations(
        self,
        snapshot,
        opportunities: List[OptimizationOpportunity],
        degradations: List
    ) -> List[str]:
        """
        Generate actionable recommendations.
        
        Args:
            snapshot: Metrics snapshot
            opportunities: Optimization opportunities
            degradations: Performance degradations
        
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Global recommendations
        if snapshot.global_stats.get('global_success_rate', 0) < 0.95:
            recommendations.append(
                "🎯 PRIORITY: Global success rate is below 95%. "
                "Focus on improving reliability of underperforming attacks."
            )
        
        if len(degradations) > 5:
            recommendations.append(
                "⚠️ Multiple performance degradations detected. "
                "Review system resources and recent changes."
            )
        
        # Opportunity-specific recommendations
        critical_opportunities = [o for o in opportunities if o.severity == 'critical']
        if critical_opportunities:
            recommendations.append(
                f"🔥 CRITICAL: {len(critical_opportunities)} attacks have critical issues. "
                "Address these before production deployment."
            )
        
        high_opportunities = [o for o in opportunities if o.severity == 'high']
        if high_opportunities:
            recommendations.append(
                f"⚠️ HIGH: {len(high_opportunities)} attacks need optimization. "
                "Review and address high-priority issues."
            )
        
        # Fallback recommendations
        high_fallback_attacks = [
            name for name, metrics in snapshot.attack_metrics.items()
            if metrics.fallback_rate > 0.10
        ]
        if high_fallback_attacks:
            recommendations.append(
                f"📋 {len(high_fallback_attacks)} attacks have high fallback rates. "
                "Verify advanced implementations are properly registered."
            )
        
        # Performance recommendations
        slow_attacks = [
            name for name, metrics in snapshot.attack_metrics.items()
            if metrics.avg_execution_time_ms > 100
        ]
        if slow_attacks:
            recommendations.append(
                f"⏱️ {len(slow_attacks)} attacks exceed 100ms average execution time. "
                "Profile and optimize these attacks."
            )
        
        # Positive feedback
        if not opportunities and not degradations:
            recommendations.append(
                "✅ All attacks are performing within acceptable thresholds. "
                "System is ready for production deployment."
            )
        
        return recommendations
    
    def _assess_production_readiness(
        self,
        snapshot,
        opportunities: List[OptimizationOpportunity],
        degradations: List
    ) -> bool:
        """
        Assess if system is ready for production deployment.
        
        Args:
            snapshot: Metrics snapshot
            opportunities: Optimization opportunities
            degradations: Performance degradations
        
        Returns:
            True if ready for production
        """
        # Check for critical issues
        critical_opportunities = [o for o in opportunities if o.severity == 'critical']
        if critical_opportunities:
            self.logger.warning(
                f"❌ Not ready for production: {len(critical_opportunities)} critical issues"
            )
            return False
        
        # Check global success rate
        if snapshot.global_stats.get('global_success_rate', 0) < 0.90:
            self.logger.warning(
                "❌ Not ready for production: Global success rate below 90%"
            )
            return False
        
        # Check for severe degradations
        severe_degradations = [
            d for d in degradations
            if hasattr(d, 'severity') and d.severity in [
                DegradationSeverity.SEVERE,
                DegradationSeverity.CRITICAL
            ]
        ]
        if severe_degradations:
            self.logger.warning(
                f"❌ Not ready for production: {len(severe_degradations)} severe degradations"
            )
            return False
        
        # Check minimum execution count
        if snapshot.global_stats.get('total_executions', 0) < 100:
            self.logger.warning(
                "⚠️ Limited data: Less than 100 executions recorded. "
                "Consider longer monitoring period."
            )
        
        self.logger.info("✅ System meets production readiness criteria")
        return True
    
    def export_report(self, report: PerformanceReport, output_file: str):
        """
        Export performance report to file.
        
        Args:
            report: Performance report
            output_file: Output file path
        """
        self.logger.info(f"📝 Exporting report to {output_file}...")
        
        with open(output_file, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)
        
        self.logger.info("✅ Report exported successfully")
    
    def print_report_summary(self, report: PerformanceReport):
        """
        Print human-readable report summary.
        
        Args:
            report: Performance report
        """
        print("\n" + "=" * 80)
        print("ATTACK PERFORMANCE MONITORING REPORT")
        print("=" * 80)
        print(f"\nTimestamp: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nGlobal Metrics:")
        print(f"  • Total Attacks Monitored: {report.total_attacks_monitored}")
        print(f"  • Total Executions: {report.total_executions}")
        print(f"  • Global Success Rate: {report.global_success_rate:.1%}")
        print(f"  • Global Avg Execution Time: {report.global_avg_execution_time_ms:.2f}ms")
        print(f"  • Degradations Detected: {report.degradations_detected}")
        
        print(f"\nTop Performers ({len(report.top_performers)}):")
        for i, performer in enumerate(report.top_performers[:5], 1):
            print(
                f"  {i}. {performer['attack_name']}: "
                f"{performer['success_rate']:.1%} success, "
                f"{performer['avg_execution_time_ms']:.1f}ms avg"
            )
        
        if report.underperformers:
            print(f"\nUnderperformers ({len(report.underperformers)}):")
            for i, underperformer in enumerate(report.underperformers[:5], 1):
                print(
                    f"  {i}. {underperformer['attack_name']}: "
                    f"{underperformer['reason']} ({underperformer['value']:.2f})"
                )
        
        if report.optimization_opportunities:
            print(f"\nOptimization Opportunities ({len(report.optimization_opportunities)}):")
            for i, opp in enumerate(report.optimization_opportunities[:5], 1):
                print(f"  {i}. [{opp.severity.upper()}] {opp.attack_name}")
                print(f"     {opp.description}")
                print(f"     Potential improvement: {opp.potential_improvement:.1f}%")
        
        print(f"\nRecommendations:")
        for i, rec in enumerate(report.recommendations, 1):
            print(f"  {i}. {rec}")
        
        print(f"\nProduction Readiness: {'✅ READY' if report.ready_for_production else '❌ NOT READY'}")
        print("\n" + "=" * 80 + "\n")


def main():
    """Main entry point."""
    print("🚀 Attack Performance Monitoring and Optimization Tool")
    print("=" * 80)
    
    # Create monitor
    monitor = AttackPerformanceMonitor()
    
    # Option 1: Analyze current metrics (if system has been running)
    print("\n📊 Analyzing current performance metrics...")
    report = monitor.analyze_performance()
    
    # Print summary
    monitor.print_report_summary(report)
    
    # Export detailed report
    output_file = f"attack_performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    monitor.export_report(report, output_file)
    
    print(f"\n✅ Detailed report saved to: {output_file}")
    
    # Option 2: Start live monitoring (commented out by default)
    # print("\n🔍 Starting live monitoring for 60 seconds...")
    # monitor.start_monitoring(duration_seconds=60)
    # 
    # print("\n📊 Analyzing performance after monitoring...")
    # report = monitor.analyze_performance()
    # monitor.print_report_summary(report)
    
    print("\n✅ Monitoring and optimization complete!")
    print("\nNext steps:")
    print("  1. Review optimization opportunities and address high-priority issues")
    print("  2. Implement recommended optimizations")
    print("  3. Re-run monitoring to validate improvements")
    print("  4. Once all critical issues are resolved, proceed with production deployment")


if __name__ == '__main__':
    main()
