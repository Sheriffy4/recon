#!/usr/bin/env python3
"""
Deployment monitoring script.

Monitors attack system metrics and logs after deployment to identify issues
and optimization opportunities.
"""

import sys
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict


class DeploymentMonitor:
    """Monitors deployment health and performance."""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.metrics_history = []
        self.errors = []
        self.warnings = []
    
    def log(self, message: str, level: str = "INFO"):
        """Log monitoring message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def collect_attack_metrics(self) -> Dict[str, Any]:
        """Collect attack execution metrics."""
        try:
            from core.bypass.attacks.attack_registry import get_attack_registry
            
            registry = get_attack_registry()
            all_attacks = registry.list_attacks()
            
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "total_attacks_registered": len(all_attacks),
                "attacks_by_category": defaultdict(int)
            }
            
            # Count attacks by category
            for attack_name in all_attacks:
                entry = registry.attacks.get(attack_name)
                if entry and hasattr(entry, 'metadata') and hasattr(entry.metadata, 'category'):
                    metrics["attacks_by_category"][entry.metadata.category] += 1
            
            return metrics
        
        except Exception as e:
            self.log(f"Failed to collect attack metrics: {e}", "ERROR")
            self.errors.append(str(e))
            return {}
    
    def collect_telemetry_metrics(self) -> Dict[str, Any]:
        """Collect telemetry metrics."""
        try:
            # In actual deployment, this would query the metrics endpoint
            # For now, return simulated metrics
            
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "attack_executions_total": 0,
                "attack_success_rate": 0.0,
                "attack_fallback_total": 0,
                "attack_errors_total": 0,
                "avg_execution_time_ms": 0.0
            }
            
            # In actual deployment:
            # import requests
            # response = requests.get("http://localhost:8080/metrics")
            # Parse Prometheus metrics format
            
            return metrics
        
        except Exception as e:
            self.log(f"Failed to collect telemetry metrics: {e}", "ERROR")
            self.errors.append(str(e))
            return {}
    
    def analyze_logs(self, log_file: str = "logs/attack_system.log") -> Dict[str, Any]:
        """Analyze log files for errors and warnings."""
        try:
            from pathlib import Path
            
            log_path = Path(log_file)
            if not log_path.exists():
                self.log(f"Log file not found: {log_file}", "WARNING")
                return {}
            
            error_count = 0
            warning_count = 0
            recent_errors = []
            
            # Read last 1000 lines
            with open(log_path, 'r') as f:
                lines = f.readlines()[-1000:]
            
            for line in lines:
                if "ERROR" in line:
                    error_count += 1
                    if len(recent_errors) < 10:
                        recent_errors.append(line.strip())
                elif "WARNING" in line:
                    warning_count += 1
            
            return {
                "timestamp": datetime.now().isoformat(),
                "error_count": error_count,
                "warning_count": warning_count,
                "recent_errors": recent_errors
            }
        
        except Exception as e:
            self.log(f"Failed to analyze logs: {e}", "ERROR")
            self.errors.append(str(e))
            return {}
    
    def check_system_health(self) -> Dict[str, Any]:
        """Check overall system health."""
        health = {
            "timestamp": datetime.now().isoformat(),
            "status": "healthy",
            "issues": []
        }
        
        # Check attack registry
        try:
            from core.bypass.attacks.attack_registry import get_attack_registry
            registry = get_attack_registry()
            attack_count = len(registry.list_attacks())
            
            if attack_count < 50:
                health["issues"].append(f"Low attack count: {attack_count}")
                health["status"] = "degraded"
        
        except Exception as e:
            health["issues"].append(f"Attack registry error: {e}")
            health["status"] = "unhealthy"
        
        # Check for recent errors
        if len(self.errors) > 10:
            health["issues"].append(f"High error count: {len(self.errors)}")
            health["status"] = "degraded"
        
        return health
    
    def identify_optimization_opportunities(self) -> List[str]:
        """Identify optimization opportunities based on metrics."""
        opportunities = []
        
        if not self.metrics_history:
            return opportunities
        
        latest_metrics = self.metrics_history[-1]
        
        # Check execution time
        if "telemetry" in latest_metrics:
            avg_time = latest_metrics["telemetry"].get("avg_execution_time_ms", 0)
            if avg_time > 100:
                opportunities.append(
                    f"High average execution time ({avg_time:.1f}ms). "
                    "Consider enabling caching or optimizing attack implementations."
                )
        
        # Check fallback rate
        if "telemetry" in latest_metrics:
            fallbacks = latest_metrics["telemetry"].get("attack_fallback_total", 0)
            executions = latest_metrics["telemetry"].get("attack_executions_total", 1)
            fallback_rate = fallbacks / executions if executions > 0 else 0
            
            if fallback_rate > 0.1:  # More than 10% fallbacks
                opportunities.append(
                    f"High fallback rate ({fallback_rate:.1%}). "
                    "Some attacks may be missing advanced implementations."
                )
        
        # Check error rate
        if "telemetry" in latest_metrics:
            errors = latest_metrics["telemetry"].get("attack_errors_total", 0)
            executions = latest_metrics["telemetry"].get("attack_executions_total", 1)
            error_rate = errors / executions if executions > 0 else 0
            
            if error_rate > 0.05:  # More than 5% errors
                opportunities.append(
                    f"High error rate ({error_rate:.1%}). "
                    "Review error logs and improve error handling."
                )
        
        return opportunities
    
    def generate_report(self) -> str:
        """Generate monitoring report."""
        report = []
        report.append("="*80)
        report.append("DEPLOYMENT MONITORING REPORT")
        report.append("="*80)
        report.append(f"\nMonitoring Duration: {datetime.now() - self.start_time}")
        report.append(f"Report Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # System health
        health = self.check_system_health()
        report.append(f"\nSystem Health: {health['status'].upper()}")
        if health['issues']:
            report.append("\nIssues:")
            for issue in health['issues']:
                report.append(f"  - {issue}")
        
        # Metrics summary
        if self.metrics_history:
            latest = self.metrics_history[-1]
            report.append("\nLatest Metrics:")
            
            if "attacks" in latest:
                report.append(f"  Attacks Registered: {latest['attacks'].get('total_attacks_registered', 0)}")
            
            if "telemetry" in latest:
                telemetry = latest["telemetry"]
                report.append(f"  Total Executions: {telemetry.get('attack_executions_total', 0)}")
                report.append(f"  Success Rate: {telemetry.get('attack_success_rate', 0):.1%}")
                report.append(f"  Avg Execution Time: {telemetry.get('avg_execution_time_ms', 0):.1f}ms")
                report.append(f"  Total Errors: {telemetry.get('attack_errors_total', 0)}")
        
        # Errors and warnings
        if self.errors:
            report.append(f"\nErrors Detected: {len(self.errors)}")
            report.append("Recent Errors:")
            for error in self.errors[-5:]:
                report.append(f"  - {error}")
        
        if self.warnings:
            report.append(f"\nWarnings: {len(self.warnings)}")
        
        # Optimization opportunities
        opportunities = self.identify_optimization_opportunities()
        if opportunities:
            report.append("\nOptimization Opportunities:")
            for opp in opportunities:
                report.append(f"  - {opp}")
        
        report.append("\n" + "="*80)
        
        return "\n".join(report)
    
    def monitor(self, duration_minutes: int = 60, interval_seconds: int = 60):
        """Monitor deployment for specified duration."""
        self.log("="*80)
        self.log("STARTING DEPLOYMENT MONITORING")
        self.log("="*80)
        self.log(f"Duration: {duration_minutes} minutes")
        self.log(f"Interval: {interval_seconds} seconds")
        
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        iteration = 0
        
        try:
            while datetime.now() < end_time:
                iteration += 1
                self.log(f"\n--- Monitoring Iteration {iteration} ---")
                
                # Collect metrics
                metrics = {
                    "iteration": iteration,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.log("Collecting attack metrics...")
                metrics["attacks"] = self.collect_attack_metrics()
                
                self.log("Collecting telemetry metrics...")
                metrics["telemetry"] = self.collect_telemetry_metrics()
                
                self.log("Analyzing logs...")
                metrics["logs"] = self.analyze_logs()
                
                # Store metrics
                self.metrics_history.append(metrics)
                
                # Check health
                health = self.check_system_health()
                self.log(f"System Health: {health['status']}")
                
                if health['issues']:
                    for issue in health['issues']:
                        self.log(f"  Issue: {issue}", "WARNING")
                        self.warnings.append(issue)
                
                # Wait for next iteration
                if datetime.now() < end_time:
                    self.log(f"Waiting {interval_seconds}s until next check...")
                    time.sleep(interval_seconds)
            
            # Generate final report
            self.log("\n" + "="*80)
            self.log("MONITORING COMPLETE")
            self.log("="*80)
            
            report = self.generate_report()
            print("\n" + report)
            
            # Save report
            report_file = f"monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_file, 'w') as f:
                f.write(report)
            
            self.log(f"\nReport saved to: {report_file}")
            
            # Save metrics
            metrics_file = f"monitoring_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(metrics_file, 'w') as f:
                json.dump(self.metrics_history, f, indent=2)
            
            self.log(f"Metrics saved to: {metrics_file}")
            
            return True
        
        except KeyboardInterrupt:
            self.log("\nMonitoring interrupted by user", "WARNING")
            report = self.generate_report()
            print("\n" + report)
            return False
        
        except Exception as e:
            self.log(f"Monitoring failed: {e}", "ERROR")
            return False


def main():
    """Main monitoring function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Monitor deployment health and performance")
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Monitoring duration in minutes (default: 60)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Check interval in seconds (default: 60)"
    )
    
    args = parser.parse_args()
    
    print("="*80)
    print("ATTACK SYSTEM DEPLOYMENT MONITORING")
    print("="*80)
    print(f"\nDuration: {args.duration} minutes")
    print(f"Interval: {args.interval} seconds")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n" + "="*80)
    
    monitor = DeploymentMonitor()
    success = monitor.monitor(
        duration_minutes=args.duration,
        interval_seconds=args.interval
    )
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
