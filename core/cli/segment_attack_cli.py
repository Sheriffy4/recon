#!/usr/bin/env python3
"""
Segment-based Attack CLI Integration.

This module extends the existing CLI system to support segment-based attacks
with enhanced monitoring, statistics, and workflow integration.
"""

import argparse
import asyncio
import json
import sys
import time
from typing import Dict, Any, List, Optional

# Core imports
from core.bypass.attacks.base import AttackContext, AttackStatus
from core.integration.attack_adapter import AttackAdapter
from core.bypass.monitoring.segment_execution_stats import (
    SegmentExecutionStatsCollector,
)
from core.bypass.diagnostics.segment_diagnostics import SegmentDiagnostics
from core.bypass.performance.segment_performance_optimizer import (
    SegmentPerformanceOptimizer,
    OptimizationConfig,
)

# Reference attacks
from core.bypass.attacks.reference.tcp_timing_manipulation_attack import (
    create_tcp_timing_attack,
)
from core.bypass.attacks.reference.multisplit_attack import create_multisplit_attack
from core.bypass.attacks.reference.faked_disorder_attack import (
    create_faked_disorder_attack,
)
from core.bypass.attacks.reference.payload_obfuscation_attack import (
    create_payload_obfuscation_attack,
)
from core.bypass.attacks.reference.urgent_pointer_manipulation_attack import (
    create_urgent_pointer_attack,
)
from core.bypass.attacks.reference.window_scaling_attack import (
    create_window_scaling_attack,
)


class SegmentAttackCLI:
    """Enhanced CLI for segment-based attack execution."""

    def __init__(self):
        self.attack_adapter = AttackAdapter()
        self.stats_collector = SegmentExecutionStatsCollector()
        self.diagnostics = SegmentDiagnostics()
        self.performance_optimizer = None

        # Available segment-based attacks
        self.segment_attacks = {
            "tcp-timing": {
                "factory": create_tcp_timing_attack,
                "description": "TCP timing manipulation with variable delays",
                "params": ["delay_ms", "jitter_ms", "burst_count"],
            },
            "multisplit": {
                "factory": create_multisplit_attack,
                "description": "Multi-segment payload splitting with overlap",
                "params": ["split_count", "overlap_size", "delay_between_ms"],
            },
            "faked-disorder": {
                "factory": create_faked_disorder_attack,
                "description": "Fake packet disorder technique (zapret-style)",
                "params": ["split_pos", "fake_ttl", "disorder_delay_ms"],
            },
            "payload-obfuscation": {
                "factory": create_payload_obfuscation_attack,
                "description": "Payload obfuscation with encoding segments",
                "params": ["encoding_type", "chunk_size", "obfuscation_level"],
            },
            "urgent-pointer": {
                "factory": create_urgent_pointer_attack,
                "description": "TCP urgent pointer manipulation",
                "params": ["urgent_offset", "urgent_data_size"],
            },
            "window-scaling": {
                "factory": create_window_scaling_attack,
                "description": "TCP window scaling manipulation",
                "params": ["window_size", "scale_factor", "dynamic_scaling"],
            },
        }

    def create_parser(self) -> argparse.ArgumentParser:
        """Create CLI argument parser."""
        parser = argparse.ArgumentParser(
            description="Native Attack Orchestration CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self._get_examples_text(),
        )

        # Main command
        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Execute attack command
        execute_parser = subparsers.add_parser(
            "execute", help="Execute segment-based attack"
        )
        execute_parser.add_argument(
            "attack",
            choices=list(self.segment_attacks.keys()),
            help="Attack type to execute",
        )
        execute_parser.add_argument("--target", required=True, help="Target IP address")
        execute_parser.add_argument(
            "--port", type=int, default=80, help="Target port (default: 80)"
        )
        execute_parser.add_argument(
            "--payload", help="Custom payload (default: HTTP GET)"
        )
        execute_parser.add_argument("--payload-file", help="Load payload from file")
        execute_parser.add_argument(
            "--params", action="append", help="Attack parameters (key=value)"
        )
        execute_parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simulate execution without sending packets",
        )
        execute_parser.add_argument(
            "--verbose", "-v", action="store_true", help="Enable verbose output"
        )
        execute_parser.add_argument(
            "--stats", action="store_true", help="Show detailed execution statistics"
        )
        execute_parser.add_argument(
            "--optimize", action="store_true", help="Enable performance optimizations"
        )
        execute_parser.add_argument("--output", "-o", help="Save results to JSON file")

        # List attacks command
        list_parser = subparsers.add_parser("list", help="List available attacks")
        list_parser.add_argument(
            "--detailed", action="store_true", help="Show detailed attack information"
        )

        # Benchmark command
        benchmark_parser = subparsers.add_parser(
            "benchmark", help="Benchmark attack performance"
        )
        benchmark_parser.add_argument(
            "attack",
            choices=list(self.segment_attacks.keys()),
            help="Attack type to benchmark",
        )
        benchmark_parser.add_argument(
            "--iterations",
            type=int,
            default=100,
            help="Number of iterations (default: 100)",
        )
        benchmark_parser.add_argument(
            "--target", default="127.0.0.1", help="Target IP for benchmarking"
        )
        benchmark_parser.add_argument(
            "--output", "-o", help="Save benchmark results to file"
        )

        # Validate command
        validate_parser = subparsers.add_parser(
            "validate", help="Validate attack configuration"
        )
        validate_parser.add_argument(
            "attack",
            choices=list(self.segment_attacks.keys()),
            help="Attack type to validate",
        )
        validate_parser.add_argument(
            "--params", action="append", help="Attack parameters to validate"
        )

        # Monitor command
        monitor_parser = subparsers.add_parser(
            "monitor", help="Monitor attack execution"
        )
        monitor_parser.add_argument(
            "--duration", type=int, default=60, help="Monitoring duration in seconds"
        )
        monitor_parser.add_argument(
            "--output", "-o", help="Save monitoring data to file"
        )

        return parser

    def _get_examples_text(self) -> str:
        """Get CLI usage examples."""
        return """
Examples:
  # Execute faked-disorder attack
  python -m core.cli.segment_attack_cli execute faked-disorder --target 192.168.1.1 --port 80
  
  # Execute with custom parameters
  python -m core.cli.segment_attack_cli execute multisplit --target 10.0.0.1 --params split_count=5 --params overlap_size=20
  
  # Dry run with verbose output
  python -m core.cli.segment_attack_cli execute tcp-timing --target 127.0.0.1 --dry-run --verbose
  
  # Benchmark attack performance
  python -m core.cli.segment_attack_cli benchmark faked-disorder --iterations 200 --output benchmark.json
  
  # List all available attacks
  python -m core.cli.segment_attack_cli list --detailed
  
  # Monitor execution statistics
  python -m core.cli.segment_attack_cli monitor --duration 120 --output monitoring.json
        """

    async def execute_attack(self, args) -> Dict[str, Any]:
        """Execute segment-based attack."""
        print(f"Executing {args.attack} attack against {args.target}:{args.port}")

        # Setup performance optimization if requested
        if args.optimize:
            self.performance_optimizer = SegmentPerformanceOptimizer(
                OptimizationConfig(
                    enable_packet_caching=True,
                    enable_memory_pooling=True,
                    enable_async_execution=True,
                    enable_batch_processing=True,
                )
            )

        # Prepare payload
        payload = self._prepare_payload(args)

        # Parse parameters
        params = self._parse_parameters(args.params or [])

        # Create attack context
        context = AttackContext(
            dst_ip=args.target,
            dst_port=args.port,
            payload=payload,
            connection_id=f"cli_{int(time.time())}",
            debug=args.verbose,
            params=params,
        )

        # Create attack instance
        attack_info = self.segment_attacks[args.attack]
        attack = attack_info["factory"]()

        # Start statistics collection
        self.stats_collector.start_execution(args.attack, context.connection_id)

        # Start diagnostics if verbose
        if args.verbose:
            self.diagnostics.start_session(context.connection_id)

        try:
            start_time = time.perf_counter()

            if args.dry_run:
                print("🔍 DRY RUN MODE - No packets will be sent")
                result = await self._execute_dry_run(attack, context)
            else:
                result = attack.execute(context)

            execution_time = time.perf_counter() - start_time

            # Record execution result
            self.stats_collector.record_execution_result(
                args.attack,
                context.connection_id,
                result.status == AttackStatus.SUCCESS,
                execution_time,
            )

            # Collect execution statistics
            execution_stats = self.stats_collector.get_execution_summary()

            # Prepare result data
            result_data = {
                "attack_type": args.attack,
                "target": f"{args.target}:{args.port}",
                "execution_time_ms": execution_time * 1000,
                "status": result.status.value,
                "technique_used": result.technique_used,
                "packets_sent": result.packets_sent,
                "bytes_sent": result.bytes_sent,
                "dry_run": args.dry_run,
                "segments_info": self._extract_segments_info(result),
                "execution_stats": execution_stats if args.stats else None,
                "diagnostics": (
                    self.diagnostics.get_session_summary(context.connection_id)
                    if args.verbose
                    else None
                ),
                "performance_metrics": (
                    self.performance_optimizer.get_performance_stats()
                    if self.performance_optimizer
                    else None
                ),
            }

            # Print results
            self._print_execution_results(result_data, args.verbose)

            # Save to file if requested
            if args.output:
                self._save_results_to_file(result_data, args.output)

            return result_data

        except Exception as e:
            error_data = {
                "attack_type": args.attack,
                "target": f"{args.target}:{args.port}",
                "status": "ERROR",
                "error": str(e),
                "dry_run": args.dry_run,
            }

            print(f"❌ Attack execution failed: {e}")

            if args.output:
                self._save_results_to_file(error_data, args.output)

            return error_data

        finally:
            if self.performance_optimizer:
                self.performance_optimizer.cleanup()

    async def _execute_dry_run(self, attack, context: AttackContext) -> Any:
        """Execute attack in dry run mode."""
        # Execute attack logic without network transmission
        result = attack.execute(context)

        # Log what would be executed
        if result.segments:
            print("📋 Execution Plan:")
            print(f"   Segments: {len(result.segments)}")

            total_delay = 0
            for i, (payload_data, seq_offset, options) in enumerate(result.segments):
                delay = options.get("delay_ms", 0)
                total_delay += delay

                print(f"   Segment {i+1}:")
                print(f"     Payload size: {len(payload_data)} bytes")
                print(f"     Sequence offset: {seq_offset}")
                print(f"     Options: {options}")

                if delay > 0:
                    print(f"     Delay: {delay}ms")

            print(f"   Total execution time: ~{total_delay}ms")

        return result

    def _prepare_payload(self, args) -> bytes:
        """Prepare attack payload."""
        if args.payload_file:
            with open(args.payload_file, "rb") as f:
                return f.read()
        elif args.payload:
            return args.payload.encode("utf-8")
        else:
            # Default HTTP GET payload
            return f"GET / HTTP/1.1\r\nHost: {args.target}\r\nConnection: close\r\n\r\n".encode(
                "utf-8"
            )

    def _parse_parameters(self, param_list: List[str]) -> Dict[str, Any]:
        """Parse parameter key=value pairs."""
        params = {}
        for param in param_list:
            if "=" not in param:
                continue

            key, value = param.split("=", 1)

            # Try to convert to appropriate type
            try:
                if value.lower() in ("true", "false"):
                    params[key] = value.lower() == "true"
                elif value.isdigit():
                    params[key] = int(value)
                elif "." in value and value.replace(".", "").isdigit():
                    params[key] = float(value)
                else:
                    params[key] = value
            except ValueError:
                params[key] = value

        return params

    def _extract_segments_info(self, result) -> Optional[Dict[str, Any]]:
        """Extract segments information from attack result."""
        if not result.segments:
            return None

        segments_info = {
            "count": len(result.segments),
            "total_payload_size": sum(len(seg[0]) for seg in result.segments),
            "sequence_offsets": [seg[1] for seg in result.segments],
            "options_summary": {},
        }

        # Analyze options
        for _, _, options in result.segments:
            for key, value in options.items():
                if key not in segments_info["options_summary"]:
                    segments_info["options_summary"][key] = []
                segments_info["options_summary"][key].append(value)

        return segments_info

    def _print_execution_results(self, result_data: Dict[str, Any], verbose: bool):
        """Print execution results to console."""
        status_emoji = "✅" if result_data["status"] == "SUCCESS" else "❌"

        print(f"\n{status_emoji} Attack Execution Results:")
        print(f"   Attack Type: {result_data['attack_type']}")
        print(f"   Target: {result_data['target']}")
        print(f"   Status: {result_data['status']}")
        print(f"   Execution Time: {result_data['execution_time_ms']:.2f}ms")

        if result_data.get("technique_used"):
            print(f"   Technique: {result_data['technique_used']}")

        if result_data.get("packets_sent"):
            print(f"   Packets Sent: {result_data['packets_sent']}")

        if result_data.get("bytes_sent"):
            print(f"   Bytes Sent: {result_data['bytes_sent']}")

        # Segments information
        segments_info = result_data.get("segments_info")
        if segments_info:
            print("\n📦 Segments Information:")
            print(f"   Count: {segments_info['count']}")
            print(f"   Total Payload Size: {segments_info['total_payload_size']} bytes")

            if verbose and segments_info.get("options_summary"):
                print("   Options Used:")
                for option, values in segments_info["options_summary"].items():
                    unique_values = list(set(values))
                    print(f"     {option}: {unique_values}")

        # Performance metrics
        if verbose and result_data.get("performance_metrics"):
            metrics = result_data["performance_metrics"]
            print("\n⚡ Performance Metrics:")
            for key, value in metrics.items():
                print(f"   {key}: {value}")

        # Diagnostics
        if verbose and result_data.get("diagnostics"):
            diagnostics = result_data["diagnostics"]
            print("\n🔍 Diagnostics:")
            for key, value in diagnostics.items():
                print(f"   {key}: {value}")

    def _save_results_to_file(self, result_data: Dict[str, Any], filename: str):
        """Save results to JSON file."""
        try:
            with open(filename, "w") as f:
                json.dump(result_data, f, indent=2, default=str)
            print(f"📄 Results saved to: {filename}")
        except Exception as e:
            print(f"⚠️ Failed to save results: {e}")

    def list_attacks(self, detailed: bool = False):
        """List available segment-based attacks."""
        print("Available Segment-based Attacks:")
        print("=" * 50)

        for name, info in self.segment_attacks.items():
            print(f"\n🎯 {name}")
            print(f"   Description: {info['description']}")

            if detailed:
                print(f"   Parameters: {', '.join(info['params'])}")

                # Show example usage
                example_params = []
                for param in info["params"][:2]:  # Show first 2 params as example
                    if "delay" in param:
                        example_params.append(f"{param}=10")
                    elif "count" in param or "size" in param:
                        example_params.append(f"{param}=5")
                    elif "ttl" in param:
                        example_params.append(f"{param}=2")
                    else:
                        example_params.append(f"{param}=value")

                if example_params:
                    params_str = " ".join(f"--params {p}" for p in example_params)
                    print(
                        f"   Example: execute {name} --target 192.168.1.1 {params_str}"
                    )

    async def benchmark_attack(self, args) -> Dict[str, Any]:
        """Benchmark attack performance."""
        print(f"Benchmarking {args.attack} attack ({args.iterations} iterations)")

        attack_info = self.segment_attacks[args.attack]
        execution_times = []
        success_count = 0

        # Default payload for benchmarking
        payload = f"GET / HTTP/1.1\r\nHost: {args.target}\r\nConnection: close\r\n\r\n".encode(
            "utf-8"
        )

        for i in range(args.iterations):
            context = AttackContext(
                dst_ip=args.target,
                dst_port=80,
                payload=payload,
                connection_id=f"benchmark_{i}",
                debug=False,
            )

            attack = attack_info["factory"]()

            start_time = time.perf_counter()
            try:
                result = attack.execute(context)
                execution_time = time.perf_counter() - start_time
                execution_times.append(execution_time)

                if result.status == AttackStatus.SUCCESS:
                    success_count += 1

            except Exception:
                execution_time = time.perf_counter() - start_time
                execution_times.append(execution_time)

            if (i + 1) % 10 == 0:
                print(f"   Progress: {i + 1}/{args.iterations}")

        # Calculate statistics
        avg_time = sum(execution_times) / len(execution_times)
        min_time = min(execution_times)
        max_time = max(execution_times)
        success_rate = success_count / args.iterations

        benchmark_results = {
            "attack_type": args.attack,
            "iterations": args.iterations,
            "success_rate": success_rate,
            "avg_execution_time_ms": avg_time * 1000,
            "min_execution_time_ms": min_time * 1000,
            "max_execution_time_ms": max_time * 1000,
            "throughput_ops_per_sec": 1.0 / avg_time if avg_time > 0 else 0,
        }

        # Print results
        print("\n📊 Benchmark Results:")
        print(f"   Attack: {args.attack}")
        print(f"   Iterations: {args.iterations}")
        print(f"   Success Rate: {success_rate:.1%}")
        print(f"   Average Time: {avg_time * 1000:.2f}ms")
        print(f"   Min Time: {min_time * 1000:.2f}ms")
        print(f"   Max Time: {max_time * 1000:.2f}ms")
        print(
            f"   Throughput: {benchmark_results['throughput_ops_per_sec']:.1f} ops/sec"
        )

        # Save results if requested
        if args.output:
            self._save_results_to_file(benchmark_results, args.output)

        return benchmark_results

    def validate_attack(self, args) -> Dict[str, Any]:
        """Validate attack configuration."""
        print(f"Validating {args.attack} attack configuration")

        attack_info = self.segment_attacks[args.attack]
        params = self._parse_parameters(args.params or [])

        # Create test context
        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=80,
            payload=b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            connection_id="validation_test",
            params=params,
        )

        validation_results = {
            "attack_type": args.attack,
            "parameters": params,
            "validation_status": "UNKNOWN",
            "issues": [],
            "recommendations": [],
        }

        try:
            # Create attack instance
            attack = attack_info["factory"]()

            # Test parameter validation
            if hasattr(attack, "validate_parameters"):
                param_validation = attack.validate_parameters(params)
                if not param_validation.get("valid", True):
                    validation_results["issues"].extend(
                        param_validation.get("issues", [])
                    )

            # Test execution (dry run)
            result = attack.execute(context)

            if result.status == AttackStatus.SUCCESS:
                validation_results["validation_status"] = "VALID"

                # Analyze segments if present
                if result.segments:
                    segments_analysis = self._analyze_segments(result.segments)
                    validation_results["segments_analysis"] = segments_analysis

                    if segments_analysis.get("issues"):
                        validation_results["issues"].extend(segments_analysis["issues"])

            else:
                validation_results["validation_status"] = "INVALID"
                validation_results["issues"].append(
                    f"Attack execution failed: {result.error}"
                )

        except Exception as e:
            validation_results["validation_status"] = "ERROR"
            validation_results["issues"].append(f"Validation error: {str(e)}")

        # Print validation results
        status_emoji = (
            "✅" if validation_results["validation_status"] == "VALID" else "❌"
        )
        print(f"\n{status_emoji} Validation Results:")
        print(f"   Attack: {args.attack}")
        print(f"   Status: {validation_results['validation_status']}")

        if validation_results["issues"]:
            print("   Issues:")
            for issue in validation_results["issues"]:
                print(f"     - {issue}")

        if validation_results["recommendations"]:
            print("   Recommendations:")
            for rec in validation_results["recommendations"]:
                print(f"     - {rec}")

        return validation_results

    def _analyze_segments(self, segments) -> Dict[str, Any]:
        """Analyze segments for potential issues."""
        analysis = {
            "segment_count": len(segments),
            "total_payload_size": sum(len(seg[0]) for seg in segments),
            "issues": [],
            "warnings": [],
        }

        # Check for common issues
        sequence_offsets = [seg[1] for seg in segments]
        if len(set(sequence_offsets)) != len(sequence_offsets):
            analysis["issues"].append("Duplicate sequence offsets detected")

        # Check timing
        total_delay = sum(seg[2].get("delay_ms", 0) for seg in segments)
        if total_delay > 5000:  # 5 seconds
            analysis["warnings"].append(f"Total delay is high: {total_delay}ms")

        # Check TTL values
        ttl_values = [seg[2].get("ttl") for seg in segments if "ttl" in seg[2]]
        if any(ttl < 1 for ttl in ttl_values if ttl is not None):
            analysis["issues"].append("TTL values below 1 detected")

        return analysis

    async def monitor_execution(self, args) -> Dict[str, Any]:
        """Monitor attack execution statistics."""
        print(f"Monitoring attack execution for {args.duration} seconds...")

        monitoring_data = {
            "duration_seconds": args.duration,
            "start_time": time.time(),
            "samples": [],
            "summary": {},
        }

        start_time = time.time()
        sample_interval = 5  # Sample every 5 seconds

        while time.time() - start_time < args.duration:
            # Collect current statistics
            current_stats = self.stats_collector.get_execution_summary()

            sample = {"timestamp": time.time(), "stats": current_stats}
            monitoring_data["samples"].append(sample)

            # Print current status
            print(
                f"   Time: {int(time.time() - start_time)}s - Active executions: {len(current_stats.get('active_executions', []))}"
            )

            await asyncio.sleep(sample_interval)

        # Calculate summary
        monitoring_data["end_time"] = time.time()
        monitoring_data["summary"] = self._calculate_monitoring_summary(
            monitoring_data["samples"]
        )

        # Print summary
        print("\n📈 Monitoring Summary:")
        summary = monitoring_data["summary"]
        for key, value in summary.items():
            print(f"   {key}: {value}")

        # Save results if requested
        if args.output:
            self._save_results_to_file(monitoring_data, args.output)

        return monitoring_data

    def _calculate_monitoring_summary(
        self, samples: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate monitoring summary from samples."""
        if not samples:
            return {}

        # Extract metrics from samples
        total_executions = []
        success_rates = []

        for sample in samples:
            stats = sample.get("stats", {})
            total_executions.append(len(stats.get("completed_executions", [])))

            completed = len(stats.get("completed_executions", []))
            successful = len(
                [
                    e
                    for e in stats.get("completed_executions", [])
                    if e.get("success", False)
                ]
            )
            success_rate = successful / completed if completed > 0 else 0
            success_rates.append(success_rate)

        return {
            "total_samples": len(samples),
            "max_concurrent_executions": max(
                len(s.get("stats", {}).get("active_executions", [])) for s in samples
            ),
            "total_executions_trend": (
                f"{total_executions[0]} -> {total_executions[-1]}"
                if len(total_executions) >= 2
                else str(total_executions[0] if total_executions else 0)
            ),
            "average_success_rate": (
                sum(success_rates) / len(success_rates) if success_rates else 0
            ),
        }


async def main():
    """Main CLI entry point."""
    cli = SegmentAttackCLI()
    parser = cli.create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "execute":
            await cli.execute_attack(args)
        elif args.command == "list":
            cli.list_attacks(args.detailed)
        elif args.command == "benchmark":
            await cli.benchmark_attack(args)
        elif args.command == "validate":
            cli.validate_attack(args)
        elif args.command == "monitor":
            await cli.monitor_execution(args)
        else:
            print(f"Unknown command: {args.command}")
            return 1

        return 0

    except KeyboardInterrupt:
        print("\n⚠️ Operation interrupted by user")
        return 130

    except Exception as e:
        print(f"❌ CLI error: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
