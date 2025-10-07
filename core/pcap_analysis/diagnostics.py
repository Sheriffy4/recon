"""
Diagnostics and debugging utilities for PCAP analysis system.

This module provides comprehensive debugging capabilities, system health checks,
and diagnostic tools for troubleshooting PCAP analysis issues.
"""

import logging
import sys
import traceback
import psutil
import time
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from contextlib import contextmanager
import threading
import queue
from datetime import datetime, timedelta

from .error_handling import AnalysisError, ErrorCategory, ErrorSeverity


@dataclass
class SystemMetrics:
    """System performance metrics."""
    cpu_percent: float
    memory_percent: float
    memory_available: int
    disk_usage_percent: float
    network_io: Dict[str, int]
    process_count: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class PerformanceProfile:
    """Performance profiling data."""
    operation: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    memory_before: int = 0
    memory_after: int = 0
    memory_peak: int = 0
    cpu_percent: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def finish(self):
        """Mark the operation as finished and calculate duration."""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.memory_after = psutil.Process().memory_info().rss


@dataclass
class DiagnosticResult:
    """Result of a diagnostic check."""
    check_name: str
    status: str  # 'PASS', 'FAIL', 'WARNING'
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class PerformanceMonitor:
    """Monitor system performance during PCAP analysis."""
    
    def __init__(self, sample_interval: float = 1.0):
        self.sample_interval = sample_interval
        self.metrics_history: List[SystemMetrics] = []
        self.performance_profiles: List[PerformanceProfile] = []
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.metrics_queue = queue.Queue()
        self.logger = logging.getLogger("pcap_analysis.performance_monitor")
    
    def start_monitoring(self):
        """Start performance monitoring."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring."""
        if not self.monitoring:
            return
        
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        self.logger.info("Performance monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Keep only last 1000 samples
                if len(self.metrics_history) > 1000:
                    self.metrics_history = self.metrics_history[-1000:]
                
                time.sleep(self.sample_interval)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
    
    def _collect_metrics(self) -> SystemMetrics:
        """Collect current system metrics."""
        try:
            process = psutil.Process()
            
            # CPU and memory
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            
            # Disk usage for current directory
            disk_usage = psutil.disk_usage('.')
            
            # Network I/O
            net_io = psutil.net_io_counters()
            network_io = {
                'bytes_sent': net_io.bytes_sent if net_io else 0,
                'bytes_recv': net_io.bytes_recv if net_io else 0
            }
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_available=memory.available,
                disk_usage_percent=(disk_usage.used / disk_usage.total) * 100,
                network_io=network_io,
                process_count=len(psutil.pids())
            )
        except Exception as e:
            self.logger.error(f"Failed to collect metrics: {e}")
            return SystemMetrics(0, 0, 0, 0, {}, 0)
    
    @contextmanager
    def profile_operation(self, operation_name: str, **metadata):
        """Context manager for profiling operations."""
        profile = PerformanceProfile(
            operation=operation_name,
            start_time=time.time(),
            memory_before=psutil.Process().memory_info().rss,
            metadata=metadata
        )
        
        try:
            yield profile
        finally:
            profile.finish()
            self.performance_profiles.append(profile)
            
            # Log performance info
            self.logger.info(
                f"Operation '{operation_name}' completed in {profile.duration:.2f}s, "
                f"memory delta: {(profile.memory_after - profile.memory_before) / 1024 / 1024:.1f}MB"
            )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        if not self.metrics_history:
            return {"error": "No metrics collected"}
        
        recent_metrics = self.metrics_history[-10:]  # Last 10 samples
        
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        
        operation_stats = {}
        for profile in self.performance_profiles:
            op_name = profile.operation
            if op_name not in operation_stats:
                operation_stats[op_name] = {
                    'count': 0,
                    'total_duration': 0,
                    'avg_duration': 0,
                    'max_duration': 0,
                    'total_memory_delta': 0
                }
            
            stats = operation_stats[op_name]
            stats['count'] += 1
            stats['total_duration'] += profile.duration or 0
            stats['max_duration'] = max(stats['max_duration'], profile.duration or 0)
            stats['total_memory_delta'] += (profile.memory_after - profile.memory_before)
            stats['avg_duration'] = stats['total_duration'] / stats['count']
        
        return {
            "current_metrics": {
                "cpu_percent": avg_cpu,
                "memory_percent": avg_memory,
                "samples_count": len(recent_metrics)
            },
            "operation_stats": operation_stats,
            "total_operations": len(self.performance_profiles)
        }


class DiagnosticChecker:
    """Perform diagnostic checks on the PCAP analysis system."""
    
    def __init__(self):
        self.logger = logging.getLogger("pcap_analysis.diagnostics")
        self.checks: List[DiagnosticResult] = []
    
    def run_all_checks(self) -> List[DiagnosticResult]:
        """Run all diagnostic checks."""
        self.checks.clear()
        
        # System checks
        self.checks.append(self._check_system_resources())
        self.checks.append(self._check_python_environment())
        self.checks.append(self._check_dependencies())
        
        # File system checks
        self.checks.append(self._check_file_permissions())
        self.checks.append(self._check_disk_space())
        
        # PCAP analysis specific checks
        self.checks.append(self._check_pcap_files())
        self.checks.append(self._check_log_directories())
        
        return self.checks
    
    def _check_system_resources(self) -> DiagnosticResult:
        """Check system resource availability."""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('.')
            
            issues = []
            recommendations = []
            
            # Check memory
            if memory.percent > 90:
                issues.append(f"High memory usage: {memory.percent:.1f}%")
                recommendations.append("Close unnecessary applications to free memory")
            
            # Check disk space
            if (disk.used / disk.total) * 100 > 90:
                issues.append(f"Low disk space: {((disk.used / disk.total) * 100):.1f}% used")
                recommendations.append("Free up disk space before running analysis")
            
            # Check CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 95:
                issues.append(f"High CPU usage: {cpu_percent:.1f}%")
                recommendations.append("Wait for CPU usage to decrease")
            
            status = "FAIL" if issues else "PASS"
            message = "; ".join(issues) if issues else "System resources are adequate"
            
            return DiagnosticResult(
                check_name="system_resources",
                status=status,
                message=message,
                details={
                    "memory_percent": memory.percent,
                    "disk_percent": (disk.used / disk.total) * 100,
                    "cpu_percent": cpu_percent
                },
                recommendations=recommendations
            )
        except Exception as e:
            return DiagnosticResult(
                check_name="system_resources",
                status="FAIL",
                message=f"Failed to check system resources: {e}",
                recommendations=["Check system health manually"]
            )
    
    def _check_python_environment(self) -> DiagnosticResult:
        """Check Python environment."""
        try:
            python_version = sys.version_info
            issues = []
            recommendations = []
            
            # Check Python version
            if python_version < (3, 8):
                issues.append(f"Python version {python_version.major}.{python_version.minor} is too old")
                recommendations.append("Upgrade to Python 3.8 or newer")
            
            # Check if running in virtual environment
            in_venv = hasattr(sys, 'real_prefix') or (
                hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
            )
            
            if not in_venv:
                issues.append("Not running in virtual environment")
                recommendations.append("Use virtual environment to avoid dependency conflicts")
            
            status = "WARNING" if issues and not any("too old" in issue for issue in issues) else "FAIL" if issues else "PASS"
            message = "; ".join(issues) if issues else "Python environment is suitable"
            
            return DiagnosticResult(
                check_name="python_environment",
                status=status,
                message=message,
                details={
                    "python_version": f"{python_version.major}.{python_version.minor}.{python_version.micro}",
                    "in_virtual_env": in_venv,
                    "executable": sys.executable
                },
                recommendations=recommendations
            )
        except Exception as e:
            return DiagnosticResult(
                check_name="python_environment",
                status="FAIL",
                message=f"Failed to check Python environment: {e}"
            )
    
    def _check_dependencies(self) -> DiagnosticResult:
        """Check required dependencies."""
        required_packages = [
            'scapy',
            'dpkt',
            'psutil',
            'numpy'
        ]
        
        missing_packages = []
        version_info = {}
        
        for package in required_packages:
            try:
                module = __import__(package)
                version = getattr(module, '__version__', 'unknown')
                version_info[package] = version
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            return DiagnosticResult(
                check_name="dependencies",
                status="FAIL",
                message=f"Missing required packages: {', '.join(missing_packages)}",
                details={"missing_packages": missing_packages, "installed_versions": version_info},
                recommendations=[f"Install missing packages: pip install {' '.join(missing_packages)}"]
            )
        
        return DiagnosticResult(
            check_name="dependencies",
            status="PASS",
            message="All required dependencies are installed",
            details={"installed_versions": version_info}
        )
    
    def _check_file_permissions(self) -> DiagnosticResult:
        """Check file system permissions."""
        try:
            test_dirs = [
                Path("recon/logs"),
                Path("recon/core/pcap_analysis"),
                Path(".")
            ]
            
            issues = []
            for test_dir in test_dirs:
                if test_dir.exists():
                    # Test write permission
                    test_file = test_dir / ".permission_test"
                    try:
                        test_file.write_text("test")
                        test_file.unlink()
                    except Exception as e:
                        issues.append(f"No write permission in {test_dir}: {e}")
                else:
                    try:
                        test_dir.mkdir(parents=True, exist_ok=True)
                    except Exception as e:
                        issues.append(f"Cannot create directory {test_dir}: {e}")
            
            status = "FAIL" if issues else "PASS"
            message = "; ".join(issues) if issues else "File permissions are adequate"
            
            return DiagnosticResult(
                check_name="file_permissions",
                status=status,
                message=message,
                recommendations=["Fix file permissions" if issues else ""]
            )
        except Exception as e:
            return DiagnosticResult(
                check_name="file_permissions",
                status="FAIL",
                message=f"Failed to check file permissions: {e}"
            )
    
    def _check_disk_space(self) -> DiagnosticResult:
        """Check available disk space."""
        try:
            disk_usage = psutil.disk_usage('.')
            available_gb = disk_usage.free / (1024**3)
            
            if available_gb < 1.0:
                return DiagnosticResult(
                    check_name="disk_space",
                    status="FAIL",
                    message=f"Insufficient disk space: {available_gb:.1f}GB available",
                    details={"available_gb": available_gb},
                    recommendations=["Free up at least 1GB of disk space"]
                )
            elif available_gb < 5.0:
                return DiagnosticResult(
                    check_name="disk_space",
                    status="WARNING",
                    message=f"Low disk space: {available_gb:.1f}GB available",
                    details={"available_gb": available_gb},
                    recommendations=["Consider freeing up more disk space for large PCAP files"]
                )
            
            return DiagnosticResult(
                check_name="disk_space",
                status="PASS",
                message=f"Adequate disk space: {available_gb:.1f}GB available",
                details={"available_gb": available_gb}
            )
        except Exception as e:
            return DiagnosticResult(
                check_name="disk_space",
                status="FAIL",
                message=f"Failed to check disk space: {e}"
            )
    
    def _check_pcap_files(self) -> DiagnosticResult:
        """Check for common PCAP file issues."""
        try:
            pcap_files = list(Path("recon").glob("*.pcap"))
            
            if not pcap_files:
                return DiagnosticResult(
                    check_name="pcap_files",
                    status="WARNING",
                    message="No PCAP files found in recon directory",
                    recommendations=["Ensure PCAP files are available for analysis"]
                )
            
            issues = []
            file_info = {}
            
            for pcap_file in pcap_files[:10]:  # Check first 10 files
                try:
                    size = pcap_file.stat().st_size
                    file_info[str(pcap_file)] = {"size_bytes": size}
                    
                    if size == 0:
                        issues.append(f"Empty PCAP file: {pcap_file}")
                    elif size < 100:
                        issues.append(f"Suspiciously small PCAP file: {pcap_file} ({size} bytes)")
                except Exception as e:
                    issues.append(f"Cannot access {pcap_file}: {e}")
            
            status = "WARNING" if issues else "PASS"
            message = "; ".join(issues) if issues else f"Found {len(pcap_files)} PCAP files"
            
            return DiagnosticResult(
                check_name="pcap_files",
                status=status,
                message=message,
                details={"pcap_count": len(pcap_files), "file_info": file_info},
                recommendations=["Check PCAP file integrity" if issues else ""]
            )
        except Exception as e:
            return DiagnosticResult(
                check_name="pcap_files",
                status="FAIL",
                message=f"Failed to check PCAP files: {e}"
            )
    
    def _check_log_directories(self) -> DiagnosticResult:
        """Check log directory setup."""
        try:
            log_dir = Path("recon/logs")
            
            if not log_dir.exists():
                try:
                    log_dir.mkdir(parents=True, exist_ok=True)
                    return DiagnosticResult(
                        check_name="log_directories",
                        status="PASS",
                        message="Created log directory",
                        details={"log_dir": str(log_dir)}
                    )
                except Exception as e:
                    return DiagnosticResult(
                        check_name="log_directories",
                        status="FAIL",
                        message=f"Cannot create log directory: {e}",
                        recommendations=["Create log directory manually or fix permissions"]
                    )
            
            # Check if we can write to log directory
            test_log = log_dir / ".test_log"
            try:
                test_log.write_text("test")
                test_log.unlink()
            except Exception as e:
                return DiagnosticResult(
                    check_name="log_directories",
                    status="FAIL",
                    message=f"Cannot write to log directory: {e}",
                    recommendations=["Fix log directory permissions"]
                )
            
            return DiagnosticResult(
                check_name="log_directories",
                status="PASS",
                message="Log directory is accessible",
                details={"log_dir": str(log_dir)}
            )
        except Exception as e:
            return DiagnosticResult(
                check_name="log_directories",
                status="FAIL",
                message=f"Failed to check log directories: {e}"
            )
    
    def generate_report(self) -> str:
        """Generate a diagnostic report."""
        if not self.checks:
            self.run_all_checks()
        
        report_lines = [
            "PCAP Analysis System Diagnostic Report",
            "=" * 50,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]
        
        # Summary
        pass_count = sum(1 for check in self.checks if check.status == "PASS")
        warning_count = sum(1 for check in self.checks if check.status == "WARNING")
        fail_count = sum(1 for check in self.checks if check.status == "FAIL")
        
        report_lines.extend([
            "SUMMARY:",
            f"  PASS: {pass_count}",
            f"  WARNING: {warning_count}",
            f"  FAIL: {fail_count}",
            ""
        ])
        
        # Detailed results
        report_lines.append("DETAILED RESULTS:")
        for check in self.checks:
            report_lines.extend([
                f"  {check.check_name.upper()}: {check.status}",
                f"    Message: {check.message}",
            ])
            
            if check.recommendations:
                report_lines.append("    Recommendations:")
                for rec in check.recommendations:
                    if rec:  # Skip empty recommendations
                        report_lines.append(f"      - {rec}")
            
            report_lines.append("")
        
        return "\n".join(report_lines)


class DebugLogger:
    """Enhanced logging for debugging PCAP analysis issues."""
    
    def __init__(self, name: str = "pcap_analysis.debug"):
        self.logger = logging.getLogger(name)
        self.debug_data: Dict[str, Any] = {}
        self.operation_stack: List[str] = []
        
        # Setup debug logging
        self._setup_debug_logging()
    
    def _setup_debug_logging(self):
        """Setup debug logging configuration."""
        self.logger.setLevel(logging.DEBUG)
        
        # Create detailed formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        
        # Debug file handler
        try:
            log_dir = Path("recon/logs")
            log_dir.mkdir(exist_ok=True)
            
            debug_handler = logging.FileHandler(log_dir / "debug.log")
            debug_handler.setLevel(logging.DEBUG)
            debug_handler.setFormatter(formatter)
            self.logger.addHandler(debug_handler)
        except Exception as e:
            print(f"Warning: Could not setup debug file logging: {e}")
    
    def start_operation(self, operation: str, **context):
        """Start tracking an operation."""
        self.operation_stack.append(operation)
        self.logger.debug(f"Starting operation: {operation}", extra=context)
        
        # Store operation context
        self.debug_data[f"{operation}_start"] = {
            "timestamp": time.time(),
            "context": context
        }
    
    def end_operation(self, operation: str, **results):
        """End tracking an operation."""
        if self.operation_stack and self.operation_stack[-1] == operation:
            self.operation_stack.pop()
        
        start_data = self.debug_data.get(f"{operation}_start", {})
        start_time = start_data.get("timestamp", time.time())
        duration = time.time() - start_time
        
        self.logger.debug(
            f"Completed operation: {operation} (duration: {duration:.2f}s)",
            extra={"duration": duration, "results": results}
        )
    
    def log_packet_info(self, packet_info: Dict[str, Any], context: str = ""):
        """Log detailed packet information."""
        self.logger.debug(
            f"Packet info {context}: {packet_info}",
            extra={"packet_info": packet_info, "context": context}
        )
    
    def log_comparison_result(self, result: Dict[str, Any]):
        """Log comparison result details."""
        self.logger.debug(
            f"Comparison result: {result}",
            extra={"comparison_result": result}
        )
    
    def log_error_details(self, error: Exception, context: str = ""):
        """Log detailed error information."""
        self.logger.error(
            f"Error in {context}: {error}",
            extra={
                "error_type": type(error).__name__,
                "error_message": str(error),
                "traceback": traceback.format_exc(),
                "context": context,
                "operation_stack": self.operation_stack.copy()
            }
        )
    
    def dump_debug_data(self, filepath: str):
        """Dump all debug data to file."""
        debug_dump = {
            "timestamp": datetime.now().isoformat(),
            "operation_stack": self.operation_stack.copy(),
            "debug_data": self.debug_data.copy()
        }
        
        with open(filepath, 'w') as f:
            json.dump(debug_dump, f, indent=2, default=str)
        
        self.logger.info(f"Debug data dumped to {filepath}")


# Global instances
_performance_monitor = None
_diagnostic_checker = None
_debug_logger = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


def get_diagnostic_checker() -> DiagnosticChecker:
    """Get global diagnostic checker instance."""
    global _diagnostic_checker
    if _diagnostic_checker is None:
        _diagnostic_checker = DiagnosticChecker()
    return _diagnostic_checker


def get_debug_logger() -> DebugLogger:
    """Get global debug logger instance."""
    global _debug_logger
    if _debug_logger is None:
        _debug_logger = DebugLogger()
    return _debug_logger


def run_system_diagnostics() -> str:
    """Run complete system diagnostics and return report."""
    checker = get_diagnostic_checker()
    return checker.generate_report()


@contextmanager
def debug_operation(operation_name: str, **context):
    """Context manager for debugging operations."""
    debug_logger = get_debug_logger()
    debug_logger.start_operation(operation_name, **context)
    try:
        yield debug_logger
    except Exception as e:
        debug_logger.log_error_details(e, operation_name)
        raise
    finally:
        debug_logger.end_operation(operation_name)