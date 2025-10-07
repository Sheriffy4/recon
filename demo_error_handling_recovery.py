"""
Demonstration of error handling and recovery mechanisms for PCAP analysis.

This script demonstrates how to use the comprehensive error handling,
graceful degradation, and recovery mechanisms in real scenarios.
"""

import sys
import tempfile
import time
from pathlib import Path
import struct

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_analysis.error_handling import (
    get_error_handler, handle_pcap_error, safe_execute,
    PCAPParsingError, AnalysisError, ErrorCategory, ErrorSeverity
)
from core.pcap_analysis.graceful_degradation import (
    get_graceful_parser, parse_pcap_with_fallback
)
from core.pcap_analysis.diagnostics import (
    get_diagnostic_checker, get_performance_monitor, get_debug_logger,
    run_system_diagnostics, debug_operation
)
from core.pcap_analysis.logging_config import (
    setup_logging, get_logger, get_contextual_logger,
    log_operation_start, log_operation_end, log_error_with_context
)


def create_test_files():
    """Create test PCAP files for demonstration."""
    print("Creating test files...")
    
    # Create a valid PCAP file
    valid_pcap = "demo_valid.pcap"
    with open(valid_pcap, 'wb') as f:
        # Write PCAP global header
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        # Write a simple packet record
        f.write(struct.pack('<IIII', int(time.time()), 0, 64, 64))  # Packet header
        f.write(b'x' * 64)  # Dummy packet data
    
    # Create a corrupted PCAP file
    corrupted_pcap = "demo_corrupted.pcap"
    with open(corrupted_pcap, 'wb') as f:
        f.write(b'This is not a valid PCAP file content')
    
    # Create an empty file
    empty_pcap = "demo_empty.pcap"
    with open(empty_pcap, 'wb') as f:
        pass  # Empty file
    
    return valid_pcap, corrupted_pcap, empty_pcap


def demo_basic_error_handling():
    """Demonstrate basic error handling."""
    print("\n" + "="*60)
    print("DEMO: Basic Error Handling")
    print("="*60)
    
    error_handler = get_error_handler()
    
    # Example 1: Handle a simple exception
    print("\n1. Handling a simple exception:")
    try:
        raise ValueError("This is a test error")
    except Exception as e:
        result = error_handler.handle_error(e)
        print(f"   Error handled: success={result.success}")
        print(f"   Completeness: {result.completeness}")
        print(f"   Errors: {len(result.errors)}")
    
    # Example 2: Handle a PCAP parsing error with recovery
    print("\n2. Handling PCAP parsing error with recovery:")
    pcap_error = PCAPParsingError(
        "Corrupted packet at position 42",
        "test.pcap",
        packet_index=42,
        recoverable=True
    )
    result = error_handler.handle_error(pcap_error, attempt_recovery=True)
    print(f"   Recovery attempted: success={result.success}")
    print(f"   Completeness: {result.completeness}")
    if result.warnings:
        print(f"   Warnings: {result.warnings}")
    
    # Example 3: Safe execution
    print("\n3. Safe execution wrapper:")
    
    def risky_function():
        if time.time() % 2 < 1:  # Randomly fail
            raise RuntimeError("Random failure")
        return "Success!"
    
    result = safe_execute(risky_function)
    print(f"   Safe execution result: success={result.success}")
    if result.success:
        print(f"   Data: {result.data}")
    else:
        print(f"   Errors: {len(result.errors)}")
    
    # Show error summary
    print("\n4. Error summary:")
    summary = error_handler.get_error_summary()
    print(f"   Total errors: {summary['total_errors']}")
    print(f"   Recovery rate: {summary['recovery_rate']:.2%}")
    print(f"   Error categories: {list(summary['error_counts_by_category'].keys())}")


def demo_graceful_degradation():
    """Demonstrate graceful degradation with PCAP files."""
    print("\n" + "="*60)
    print("DEMO: Graceful Degradation")
    print("="*60)
    
    valid_pcap, corrupted_pcap, empty_pcap = create_test_files()
    parser = get_graceful_parser()
    
    test_files = [
        ("Valid PCAP", valid_pcap),
        ("Corrupted PCAP", corrupted_pcap),
        ("Empty PCAP", empty_pcap),
        ("Non-existent PCAP", "nonexistent.pcap")
    ]
    
    for description, filepath in test_files:
        print(f"\n{description} ({filepath}):")
        
        # Analyze file first
        file_info = parser.analyze_pcap_file(filepath)
        print(f"   File size: {file_info.size_bytes} bytes")
        print(f"   Readable: {file_info.is_readable}")
        print(f"   Header valid: {file_info.header_valid}")
        print(f"   Corruption detected: {file_info.corruption_detected}")
        if file_info.corruption_details:
            print(f"   Issues: {', '.join(file_info.corruption_details)}")
        
        # Try parsing with degradation
        result = parse_pcap_with_fallback(filepath, min_success_rate=0.3)
        print(f"   Parsing result: success={result.success}")
        print(f"   Completeness: {result.completeness:.2%}")
        if result.warnings:
            print(f"   Warnings: {result.warnings[0]}")
        if result.metadata and "parsing_method" in result.metadata:
            print(f"   Method used: {result.metadata['parsing_method']}")
    
    # Show parsing statistics
    print("\nParsing Statistics:")
    stats = parser.get_parsing_statistics()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"   {key}: {value:.2%}")
        else:
            print(f"   {key}: {value}")
    
    # Cleanup
    for _, filepath in test_files[:-1]:  # Skip non-existent file
        try:
            Path(filepath).unlink()
        except:
            pass


def demo_diagnostics():
    """Demonstrate diagnostic capabilities."""
    print("\n" + "="*60)
    print("DEMO: System Diagnostics")
    print("="*60)
    
    # Run diagnostic checks
    print("Running diagnostic checks...")
    checker = get_diagnostic_checker()
    results = checker.run_all_checks()
    
    print(f"\nCompleted {len(results)} diagnostic checks:")
    for result in results:
        status_symbol = "✓" if result.status == "PASS" else "⚠" if result.status == "WARNING" else "✗"
        print(f"   {status_symbol} {result.check_name}: {result.status}")
        if result.status != "PASS":
            print(f"     {result.message}")
    
    # Generate full report
    print("\nGenerating diagnostic report...")
    report = run_system_diagnostics()
    print("\nDiagnostic Report Preview:")
    print("-" * 40)
    # Show first few lines of report
    report_lines = report.split('\n')
    for line in report_lines[:15]:
        print(line)
    if len(report_lines) > 15:
        print("... (truncated)")


def demo_performance_monitoring():
    """Demonstrate performance monitoring."""
    print("\n" + "="*60)
    print("DEMO: Performance Monitoring")
    print("="*60)
    
    monitor = get_performance_monitor()
    
    # Start monitoring
    print("Starting performance monitoring...")
    monitor.start_monitoring()
    
    # Simulate some operations
    operations = [
        ("pcap_parsing", 0.5),
        ("strategy_analysis", 0.3),
        ("difference_detection", 0.2),
        ("fix_generation", 0.4)
    ]
    
    for op_name, duration in operations:
        print(f"Simulating {op_name}...")
        with monitor.profile_operation(op_name, test_param="demo") as profile:
            time.sleep(duration)  # Simulate work
        print(f"   Completed in {profile.duration:.2f}s")
    
    # Stop monitoring
    monitor.stop_monitoring()
    
    # Show performance summary
    print("\nPerformance Summary:")
    summary = monitor.get_performance_summary()
    
    if "operation_stats" in summary:
        for op_name, stats in summary["operation_stats"].items():
            print(f"   {op_name}:")
            print(f"     Count: {stats['count']}")
            print(f"     Avg Duration: {stats['avg_duration']:.2f}s")
            print(f"     Max Duration: {stats['max_duration']:.2f}s")


def demo_debug_logging():
    """Demonstrate debug logging capabilities."""
    print("\n" + "="*60)
    print("DEMO: Debug Logging")
    print("="*60)
    
    # Setup logging
    with tempfile.TemporaryDirectory() as log_dir:
        print(f"Setting up logging in: {log_dir}")
        setup_logging(log_dir, log_level="DEBUG")
        
        # Get loggers
        logger = get_logger("demo")
        contextual_logger = get_contextual_logger("demo")
        debug_logger = get_debug_logger()
        
        # Demonstrate different logging levels
        print("\n1. Basic logging:")
        logger.debug("This is a debug message")
        logger.info("This is an info message")
        logger.warning("This is a warning message")
        logger.error("This is an error message")
        
        # Demonstrate contextual logging
        print("\n2. Contextual logging:")
        contextual_logger.set_context(operation="demo_operation", user="demo_user")
        contextual_logger.info("Operation started")
        contextual_logger.warning("Something might be wrong")
        contextual_logger.clear_context()
        
        # Demonstrate operation logging
        print("\n3. Operation logging:")
        log_operation_start("demo_analysis", pcap_file="demo.pcap")
        time.sleep(0.1)  # Simulate work
        log_operation_end("demo_analysis", 0.1, packets_processed=100)
        
        # Demonstrate error logging
        print("\n4. Error logging:")
        try:
            raise ValueError("Demo error for logging")
        except Exception as e:
            log_error_with_context(e, "demo_function", extra_info="demo_value")
        
        # Demonstrate debug operation tracking
        print("\n5. Debug operation tracking:")
        with debug_operation("complex_analysis", input_file="demo.pcap") as debug_ctx:
            debug_ctx.log_packet_info({"src_ip": "192.168.1.1", "dst_ip": "8.8.8.8"})
            time.sleep(0.1)  # Simulate work
        
        print(f"\nLog files created in: {log_dir}")
        log_files = list(Path(log_dir).glob("*.log"))
        for log_file in log_files:
            print(f"   {log_file.name}: {log_file.stat().st_size} bytes")
        
        # Close all handlers to release file locks
        logger_config = setup_logging.__globals__.get('_pcap_logger')
        if logger_config:
            logger_config.close_all_handlers()


def demo_integrated_workflow():
    """Demonstrate integrated error handling workflow."""
    print("\n" + "="*60)
    print("DEMO: Integrated Workflow")
    print("="*60)
    
    # Setup logging
    with tempfile.TemporaryDirectory() as log_dir:
        setup_logging(log_dir)
        logger = get_logger("workflow")
        
        print("Simulating complete PCAP analysis workflow with error handling...")
        
        # Create test files
        valid_pcap, corrupted_pcap, empty_pcap = create_test_files()
        
        # Simulate workflow steps
        workflow_steps = [
            ("File validation", lambda f: Path(f).exists()),
            ("PCAP parsing", lambda f: parse_pcap_with_fallback(f)),
            ("Strategy analysis", lambda f: {"strategy": "fake,fakeddisorder"}),
            ("Difference detection", lambda f: []),
            ("Fix generation", lambda f: {"fixes": ["ttl_fix", "checksum_fix"]})
        ]
        
        test_files = [valid_pcap, corrupted_pcap, empty_pcap]
        
        for pcap_file in test_files:
            print(f"\nProcessing: {pcap_file}")
            
            workflow_success = True
            results = {}
            
            for step_name, step_func in workflow_steps:
                print(f"   {step_name}...", end=" ")
                
                try:
                    with debug_operation(step_name, file=pcap_file):
                        result = safe_execute(step_func, pcap_file)
                        
                        if result.success:
                            print("✓")
                            results[step_name] = result.data
                        else:
                            print("✗")
                            logger.warning(f"{step_name} failed for {pcap_file}")
                            workflow_success = False
                            
                            # Try to continue with partial results
                            if result.completeness > 0.5:
                                print(f"     Continuing with partial results ({result.completeness:.1%})")
                                results[step_name] = result.data
                            else:
                                print("     Stopping workflow due to insufficient data")
                                break
                                
                except Exception as e:
                    print("✗")
                    log_error_with_context(e, step_name, file=pcap_file)
                    workflow_success = False
                    break
            
            if workflow_success:
                print(f"   Workflow completed successfully!")
            else:
                print(f"   Workflow completed with errors/warnings")
            
            print(f"   Results: {len(results)} steps completed")
        
        # Show final statistics
        print("\nFinal Statistics:")
        error_handler = get_error_handler()
        summary = error_handler.get_error_summary()
        print(f"   Total errors handled: {summary['total_errors']}")
        print(f"   Recovery rate: {summary['recovery_rate']:.2%}")
        
        parser = get_graceful_parser()
        parse_stats = parser.get_parsing_statistics()
        if parse_stats.get("total_files", 0) > 0:
            print(f"   Files parsed: {parse_stats['total_files']}")
            print(f"   Success rate: {parse_stats.get('success_rate', 0):.2%}")
        
        # Cleanup
        for pcap_file in test_files:
            try:
                Path(pcap_file).unlink()
            except:
                pass


def main():
    """Run all demonstrations."""
    print("PCAP Analysis Error Handling and Recovery Demonstration")
    print("=" * 60)
    
    try:
        demo_basic_error_handling()
        demo_graceful_degradation()
        demo_diagnostics()
        demo_performance_monitoring()
        demo_debug_logging()
        demo_integrated_workflow()
        
        print("\n" + "="*60)
        print("All demonstrations completed successfully!")
        print("="*60)
        
    except Exception as e:
        print(f"\nDemo failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())