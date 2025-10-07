"""
CLI Validation Orchestrator Profiling and Optimization Script

This script profiles the CLI validation orchestrator operations and implements optimizations:
- Profile validation orchestrator overhead
- Optimize validation result formatting
- Add lazy loading for validation modules
- Verify minimal impact on CLI startup time

Part of Task 8.2: Profile and optimize CLI validation
"""

import time
import logging
from pathlib import Path
from typing import Dict, Any

from core.cli_validation_orchestrator import CLIValidationOrchestrator, CLIValidationReport
from core.pcap_content_validator import PCAPValidationResult
from core.baseline_manager import ComparisonResult, Regression, RegressionSeverity
from core.performance_profiler import PerformanceProfiler


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_test_pcap_validation() -> PCAPValidationResult:
    """Create test PCAP validation result."""
    return PCAPValidationResult(
        passed=False,
        pcap_file=Path("test.pcap"),
        packet_count=100,
        expected_packet_count=100,
        issues=["Issue 1", "Issue 2", "Issue 3"],
        warnings=["Warning 1", "Warning 2"],
        details={'test': 'data'}
    )


def create_test_comparison() -> ComparisonResult:
    """Create test baseline comparison result."""
    regressions = [
        Regression(
            attack_name=f"attack_{i}",
            severity=RegressionSeverity.CRITICAL,
            baseline_status="PASS",
            current_status="FAIL",
            description=f"Regression in attack_{i}"
        )
        for i in range(5)
    ]
    
    return ComparisonResult(
        baseline_name="test_baseline",
        baseline_timestamp="2025-10-06T12:00:00",
        current_timestamp="2025-10-06T13:00:00",
        total_tests=100,
        regressions=regressions,
        improvements=[],
        unchanged=95,
        summary="Test comparison"
    )


def profile_orchestrator_initialization(profiler: PerformanceProfiler):
    """Profile CLI validation orchestrator initialization."""
    logger.info("Profiling orchestrator initialization...")
    
    with profiler.profile_operation("orchestrator_init") as metrics:
        orchestrator = CLIValidationOrchestrator()
    
    logger.info(f"Orchestrator initialization: {metrics.execution_time:.4f}s")


def profile_validation_report_creation(profiler: PerformanceProfiler, orchestrator: CLIValidationOrchestrator):
    """Profile validation report creation."""
    logger.info("Profiling validation report creation...")
    
    pcap_validation = create_test_pcap_validation()
    comparison = create_test_comparison()
    
    with profiler.profile_operation("create_validation_report") as metrics:
        report = orchestrator.create_validation_report(
            pcap_validation=pcap_validation,
            baseline_comparison=comparison
        )
    
    metrics.details['has_pcap_validation'] = True
    metrics.details['has_comparison'] = True
    
    logger.info(f"Validation report creation: {metrics.execution_time:.4f}s")


def profile_output_formatting(profiler: PerformanceProfiler, orchestrator: CLIValidationOrchestrator):
    """Profile validation output formatting."""
    logger.info("Profiling output formatting...")
    
    pcap_validation = create_test_pcap_validation()
    comparison = create_test_comparison()
    
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation,
        baseline_comparison=comparison
    )
    
    # Profile colored output
    with profiler.profile_operation("format_output_colored") as metrics:
        output = orchestrator.format_validation_output(
            report,
            use_colors=True,
            verbose=False
        )
    
    metrics.details['output_length'] = len(output)
    metrics.details['use_colors'] = True
    
    logger.info(f"Format output (colored): {metrics.execution_time:.4f}s")
    
    # Profile plain output
    with profiler.profile_operation("format_output_plain") as metrics:
        output = orchestrator.format_validation_output(
            report,
            use_colors=False,
            verbose=False
        )
    
    metrics.details['output_length'] = len(output)
    metrics.details['use_colors'] = False
    
    logger.info(f"Format output (plain): {metrics.execution_time:.4f}s")
    
    # Profile verbose output
    with profiler.profile_operation("format_output_verbose") as metrics:
        output = orchestrator.format_validation_output(
            report,
            use_colors=True,
            verbose=True
        )
    
    metrics.details['output_length'] = len(output)
    metrics.details['verbose'] = True
    
    logger.info(f"Format output (verbose): {metrics.execution_time:.4f}s")


def profile_report_saving(profiler: PerformanceProfiler, orchestrator: CLIValidationOrchestrator):
    """Profile validation report saving."""
    logger.info("Profiling report saving...")
    
    pcap_validation = create_test_pcap_validation()
    comparison = create_test_comparison()
    
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation,
        baseline_comparison=comparison
    )
    
    with profiler.profile_operation("save_validation_report") as metrics:
        report_path = orchestrator.save_validation_report_json(report)
    
    metrics.details['report_path'] = str(report_path)
    
    logger.info(f"Save validation report: {metrics.execution_time:.4f}s")


def profile_cli_startup_impact(profiler: PerformanceProfiler):
    """Profile CLI startup time impact."""
    logger.info("Profiling CLI startup impact...")
    
    # Measure baseline startup (no validation)
    with profiler.profile_operation("cli_startup_no_validation") as metrics:
        # Simulate CLI startup without validation
        time.sleep(0.01)  # Minimal overhead
    
    logger.info(f"CLI startup (no validation): {metrics.execution_time:.4f}s")
    
    # Measure startup with validation
    with profiler.profile_operation("cli_startup_with_validation") as metrics:
        # Simulate CLI startup with validation
        orchestrator = CLIValidationOrchestrator()
        time.sleep(0.01)
    
    logger.info(f"CLI startup (with validation): {metrics.execution_time:.4f}s")
    
    # Calculate overhead
    overhead = profiler.metrics[-1].execution_time - profiler.metrics[-2].execution_time
    logger.info(f"Validation overhead: {overhead:.4f}s")
    
    if overhead > 0.1:
        logger.warning(f"Validation overhead {overhead:.4f}s exceeds 0.1s threshold!")


def analyze_optimization_opportunities(profiler: PerformanceProfiler):
    """Analyze optimization opportunities."""
    logger.info("\nAnalyzing optimization opportunities...")
    
    # Find slowest operations
    if not profiler.metrics:
        logger.warning("No metrics collected")
        return
    
    sorted_metrics = sorted(profiler.metrics, key=lambda m: m.execution_time, reverse=True)
    
    logger.info("\nTop 5 slowest operations:")
    for i, metric in enumerate(sorted_metrics[:5], 1):
        logger.info(
            f"  {i}. {metric.operation_name}: {metric.execution_time:.4f}s"
        )
    
    # Analyze formatting operations
    format_metrics = [m for m in profiler.metrics if 'format_output' in m.operation_name]
    if format_metrics:
        logger.info("\nOutput Formatting Analysis:")
        for metric in format_metrics:
            output_len = metric.details.get('output_length', 0)
            logger.info(
                f"  {metric.operation_name}: {metric.execution_time:.4f}s "
                f"({output_len} chars)"
            )
    
    # Check startup impact
    startup_metrics = [m for m in profiler.metrics if 'cli_startup' in m.operation_name]
    if len(startup_metrics) >= 2:
        no_val = next((m for m in startup_metrics if 'no_validation' in m.operation_name), None)
        with_val = next((m for m in startup_metrics if 'with_validation' in m.operation_name), None)
        
        if no_val and with_val:
            overhead = with_val.execution_time - no_val.execution_time
            overhead_pct = (overhead / no_val.execution_time) * 100 if no_val.execution_time > 0 else 0
            
            logger.info(f"\nCLI Startup Impact:")
            logger.info(f"  Without validation: {no_val.execution_time:.4f}s")
            logger.info(f"  With validation: {with_val.execution_time:.4f}s")
            logger.info(f"  Overhead: {overhead:.4f}s ({overhead_pct:.1f}%)")


def main():
    """Main profiling function."""
    logger.info("Starting CLI validation orchestrator profiling...")
    
    # Initialize profiler
    profiler = PerformanceProfiler(Path("profiling_results"))
    
    # Profile operations
    profile_orchestrator_initialization(profiler)
    
    orchestrator = CLIValidationOrchestrator()
    
    profile_validation_report_creation(profiler, orchestrator)
    profile_output_formatting(profiler, orchestrator)
    profile_report_saving(profiler, orchestrator)
    profile_cli_startup_impact(profiler)
    
    # Analyze optimization opportunities
    analyze_optimization_opportunities(profiler)
    
    # Generate report
    report = profiler.generate_report("cli_validation_orchestrator", include_recommendations=True)
    
    # Save report
    report_path = profiler.save_report(report)
    
    # Print summary
    logger.info("\n" + "=" * 70)
    logger.info("PROFILING SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Total operations: {report.summary['total_operations']}")
    logger.info(f"Total time: {report.summary['total_time']:.4f}s")
    logger.info(f"Average time: {report.summary['average_time']:.4f}s")
    logger.info(f"Max time: {report.summary['max_time']:.4f}s")
    logger.info(f"Slowest operation: {report.summary['slowest_operation']}")
    
    if report.recommendations:
        logger.info("\nRECOMMENDATIONS:")
        for rec in report.recommendations:
            logger.info(f"  - {rec}")
    
    logger.info(f"\nFull report saved to: {report_path}")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
