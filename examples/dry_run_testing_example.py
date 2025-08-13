#!/usr/bin/env python3
"""
Example demonstrating dry run testing mode.

Shows how to use dry run mode to test segment-based attacks
without actual network transmission.
"""

import asyncio
import logging
import time
from typing import Dict, Any

from core.integration.attack_adapter import AttackAdapter
from core.integration.integration_config import IntegrationConfig
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus, BaseAttack


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ExampleSegmentAttack(BaseAttack):
    """Example attack that generates segments for demonstration."""
    
    def __init__(self):
        super().__init__()
        self.name = "example_segment_attack"
        self.category = "tcp"
        self.supported_protocols = ["tcp"]
        self.description = "Example attack demonstrating segment-based DPI evasion"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Execute example attack with segments."""
        logger.info(f"Executing {self.name} with context: {context.dst_ip}:{context.dst_port}")
        
        # Check if running in dry run mode
        is_dry_run = context.params.get("dry_run", False)
        if is_dry_run:
            logger.info("Running in DRY RUN mode - no network transmission")
        
        # Create segments for fake disorder attack pattern
        segments = [
            # Fake packet with low TTL (will be dropped by intermediate routers)
            (b"fake_decoy_data", 0, {
                "ttl": 1,
                "delay_ms": 15,
                "flags": 0x18  # PSH+ACK
            }),
            
            # Real packet part 1 with checksum corruption
            (context.payload[:len(context.payload)//2], 0, {
                "ttl": 64,
                "bad_checksum": True,
                "delay_ms": 5
            }),
            
            # Real packet part 2 with normal settings
            (context.payload[len(context.payload)//2:], len(context.payload)//2, {
                "ttl": 64,
                "delay_ms": 2,
                "window_size": 32768
            })
        ]
        
        # Simulate processing time
        time.sleep(0.01)  # 10ms processing
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            latency_ms=15.0,
            metadata={
                "attack_type": "fake_disorder",
                "segments_generated": len(segments),
                "total_payload_size": len(context.payload)
            }
        )
        
        # Set segments
        result._segments = segments
        result.metadata["segments"] = segments
        
        logger.info(f"Generated {len(segments)} segments for {self.name}")
        
        return result


class ExamplePayloadAttack(BaseAttack):
    """Example attack that modifies payload."""
    
    def __init__(self):
        super().__init__()
        self.name = "example_payload_attack"
        self.category = "http"
        self.supported_protocols = ["tcp", "http"]
        self.description = "Example attack demonstrating payload modification"
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Execute example payload modification attack."""
        logger.info(f"Executing {self.name} with payload size: {len(context.payload)}")
        
        # Check if running in dry run mode
        is_dry_run = context.params.get("dry_run", False)
        if is_dry_run:
            logger.info("Running in DRY RUN mode - simulating payload modification")
        
        # Modify payload by adding obfuscation
        original_payload = context.payload
        modified_payload = original_payload.replace(b"Host:", b"X-Real-Host:")
        
        # Add some padding to confuse DPI
        modified_payload += b"\r\nX-Padding: " + b"A" * 50 + b"\r\n"
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            modified_payload=modified_payload,
            latency_ms=8.0,
            metadata={
                "attack_type": "payload_modification",
                "original_size": len(original_payload),
                "modified_size": len(modified_payload),
                "modifications": ["host_header_obfuscation", "padding_injection"]
            }
        )
        
        logger.info(f"Modified payload from {len(original_payload)} to {len(modified_payload)} bytes")
        
        return result


class DryRunTestingDemo:
    """Demonstration of dry run testing capabilities."""
    
    def __init__(self):
        """Initialize demo components."""
        self.config = IntegrationConfig(
            debug_mode=True,
            cache_attack_results=False,
            attack_timeout_seconds=30
        )
        
        self.adapter = AttackAdapter(self.config)
        
        # Register example attacks
        self.adapter.registry.register("example_segment_attack", ExampleSegmentAttack)
        self.adapter.registry.register("example_payload_attack", ExamplePayloadAttack)
        
        logger.info("Dry run testing demo initialized")
    
    def create_test_context(self, target_ip: str = "1.2.3.4", target_port: int = 443) -> AttackContext:
        """Create test attack context."""
        return AttackContext(
            dst_ip=target_ip,
            dst_port=target_port,
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            protocol="tcp",
            domain="example.com",
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,
            tcp_window_size=65535,
            connection_id=f"demo_connection_{int(time.time())}"
        )
    
    async def demonstrate_segment_attack_dry_run(self):
        """Demonstrate dry run of segment-based attack."""
        logger.info("=== Segment Attack Dry Run Demo ===")
        
        context = self.create_test_context()
        
        # Execute in dry run mode
        logger.info("Executing segment attack in DRY RUN mode...")
        dry_result = await self.adapter.execute_attack_by_name(
            "example_segment_attack", context, dry_run=True
        )
        
        # Analyze dry run results
        logger.info(f"Dry run status: {dry_result.status.value}")
        logger.info(f"Simulation time: {dry_result.metadata.get('simulation_time_ms', 0):.3f}ms")
        
        if "segment_analysis" in dry_result.metadata:
            analysis = dry_result.metadata["segment_analysis"]
            logger.info(f"Segments analyzed: {analysis.get('total_segments', 0)}")
            logger.info(f"TTL modifications: {analysis.get('ttl_modifications', 0)}")
            logger.info(f"Checksum corruptions: {analysis.get('checksum_corruptions', 0)}")
            logger.info(f"Timing delays: {analysis.get('timing_delays', 0)}")
        
        if "validation_errors" in dry_result.metadata:
            errors = dry_result.metadata["validation_errors"]
            if errors:
                logger.warning(f"Validation errors found: {len(errors)}")
                for error in errors:
                    logger.warning(f"  - {error}")
            else:
                logger.info("✓ All segments passed validation")
        
        logger.info("Segment attack dry run completed\n")
        return dry_result
    
    async def demonstrate_payload_attack_dry_run(self):
        """Demonstrate dry run of payload modification attack."""
        logger.info("=== Payload Attack Dry Run Demo ===")
        
        context = self.create_test_context(target_port=80)
        
        # Execute in dry run mode
        logger.info("Executing payload attack in DRY RUN mode...")
        dry_result = await self.adapter.execute_attack_by_name(
            "example_payload_attack", context, dry_run=True
        )
        
        # Analyze dry run results
        logger.info(f"Dry run status: {dry_result.status.value}")
        logger.info(f"Simulation time: {dry_result.metadata.get('simulation_time_ms', 0):.3f}ms")
        
        if dry_result.metadata.get("payload_modified"):
            logger.info(f"Original payload size: {dry_result.metadata.get('original_payload_size', 0)} bytes")
            logger.info(f"Modified payload size: {dry_result.metadata.get('modified_payload_size', 0)} bytes")
            
            if dry_result.modified_payload:
                logger.info("✓ Modified payload generated successfully")
                logger.info(f"Preview: {dry_result.modified_payload[:100]}...")
        
        logger.info("Payload attack dry run completed\n")
        return dry_result
    
    async def demonstrate_comparison_dry_vs_real(self):
        """Demonstrate comparison between dry run and real execution."""
        logger.info("=== Dry Run vs Real Execution Comparison ===")
        
        context = self.create_test_context()
        
        # Execute in dry run mode
        logger.info("Executing in DRY RUN mode...")
        dry_start = time.time()
        dry_result = await self.adapter.execute_attack_by_name(
            "example_segment_attack", context, dry_run=True
        )
        dry_time = (time.time() - dry_start) * 1000
        
        # Execute in real mode (but without actual network transmission)
        logger.info("Executing in REAL mode...")
        real_start = time.time()
        real_result = await self.adapter.execute_attack_by_name(
            "example_segment_attack", context, dry_run=False
        )
        real_time = (time.time() - real_start) * 1000
        
        # Compare results
        logger.info("Comparison Results:")
        logger.info(f"  Dry run time: {dry_time:.3f}ms")
        logger.info(f"  Real execution time: {real_time:.3f}ms")
        logger.info(f"  Both successful: {dry_result.status == real_result.status == AttackStatus.SUCCESS}")
        
        # Compare segments
        dry_segments = len(dry_result._segments) if hasattr(dry_result, '_segments') else 0
        real_segments = len(real_result._segments) if hasattr(real_result, '_segments') else 0
        logger.info(f"  Segments generated: dry={dry_segments}, real={real_segments}")
        
        # Dry run specific features
        logger.info(f"  Dry run validation: {'✓' if dry_result.metadata.get('segments_valid') else '✗'}")
        logger.info(f"  Dry run analysis: {'✓' if 'segment_analysis' in dry_result.metadata else '✗'}")
        
        logger.info("Comparison completed\n")
    
    async def demonstrate_validation_testing(self):
        """Demonstrate validation testing with dry run."""
        logger.info("=== Validation Testing Demo ===")
        
        # Create context with various scenarios
        test_scenarios = [
            {
                "name": "Normal HTTPS",
                "context": self.create_test_context("1.2.3.4", 443),
                "expected": "success"
            },
            {
                "name": "HTTP with large payload",
                "context": AttackContext(
                    dst_ip="5.6.7.8",
                    dst_port=80,
                    payload=b"GET / HTTP/1.1\r\n" + b"X-Large-Header: " + b"A" * 1000 + b"\r\n\r\n",
                    protocol="tcp"
                ),
                "expected": "success"
            },
            {
                "name": "Invalid IP",
                "context": AttackContext(
                    dst_ip="invalid_ip",
                    dst_port=443,
                    payload=b"test",
                    protocol="tcp"
                ),
                "expected": "validation_error"
            }
        ]
        
        for scenario in test_scenarios:
            logger.info(f"Testing scenario: {scenario['name']}")
            
            try:
                result = await self.adapter.execute_attack_by_name(
                    "example_segment_attack", scenario["context"], dry_run=True
                )
                
                logger.info(f"  Status: {result.status.value}")
                logger.info(f"  Validation: {'✓' if result.metadata.get('segments_valid', True) else '✗'}")
                
                if result.metadata.get("validation_errors"):
                    logger.info(f"  Errors: {len(result.metadata['validation_errors'])}")
                
            except Exception as e:
                logger.info(f"  Exception: {e}")
        
        logger.info("Validation testing completed\n")
    
    async def demonstrate_performance_analysis(self):
        """Demonstrate performance analysis with dry run."""
        logger.info("=== Performance Analysis Demo ===")
        
        context = self.create_test_context()
        
        # Run multiple dry runs to collect statistics
        num_runs = 5
        logger.info(f"Running {num_runs} dry run iterations...")
        
        results = []
        for i in range(num_runs):
            result = await self.adapter.execute_attack_by_name(
                "example_segment_attack", context, dry_run=True
            )
            results.append(result)
            logger.info(f"  Run {i+1}: {result.metadata.get('simulation_time_ms', 0):.3f}ms")
        
        # Analyze performance
        simulation_times = [r.metadata.get('simulation_time_ms', 0) for r in results]
        avg_time = sum(simulation_times) / len(simulation_times)
        min_time = min(simulation_times)
        max_time = max(simulation_times)
        
        logger.info(f"Performance Analysis:")
        logger.info(f"  Average simulation time: {avg_time:.3f}ms")
        logger.info(f"  Min simulation time: {min_time:.3f}ms")
        logger.info(f"  Max simulation time: {max_time:.3f}ms")
        logger.info(f"  Time variance: {max_time - min_time:.3f}ms")
        
        # Get adapter statistics
        dry_run_stats = self.adapter.get_dry_run_stats()
        logger.info(f"Adapter Statistics:")
        logger.info(f"  Total dry runs: {dry_run_stats['total_dry_runs']}")
        logger.info(f"  Segments simulated: {dry_run_stats['segments_simulated']}")
        logger.info(f"  Average segments per run: {dry_run_stats['average_segments_per_run']:.1f}")
        logger.info(f"  Validation error rate: {dry_run_stats['validation_error_rate']:.2%}")
        
        logger.info("Performance analysis completed\n")
    
    async def run_all_demos(self):
        """Run all dry run demonstration scenarios."""
        logger.info("Starting Dry Run Testing Mode Demonstration")
        logger.info("=" * 60)
        
        try:
            await self.demonstrate_segment_attack_dry_run()
            await self.demonstrate_payload_attack_dry_run()
            await self.demonstrate_comparison_dry_vs_real()
            await self.demonstrate_validation_testing()
            await self.demonstrate_performance_analysis()
            
            logger.info("All dry run demonstrations completed successfully!")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise


async def main():
    """Main demo function."""
    demo = DryRunTestingDemo()
    await demo.run_all_demos()


if __name__ == "__main__":
    asyncio.run(main())