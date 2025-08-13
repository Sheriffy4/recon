#!/usr/bin/env python3
"""
Example demonstrating engine dry run testing.

Shows how to use dry run mode with NativePyDivertEngine
to test attacks without network transmission.
"""

import asyncio
import logging
import time
from typing import List, Tuple

from core.bypass.engines.native_pydivert_engine import NativePydivertEngine
from core.bypass.engines.base import EngineConfig
from core.bypass.attacks.base import AttackContext, AttackStatus


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EngineDryRunDemo:
    """Demonstration of engine dry run testing capabilities."""
    
    def __init__(self):
        """Initialize demo components."""
        self.config = EngineConfig(
            debug=True,
            timeout=30.0,
            packet_buffer_size=65535,
            log_packets=True
        )
        
        self.engine = NativePydivertEngine(self.config)
        
        logger.info("Engine dry run demo initialized")
    
    def create_test_contexts(self) -> List[Tuple[str, AttackContext]]:
        """Create various test contexts for different scenarios."""
        contexts = []
        
        # HTTPS scenario
        https_context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x50" + b"A" * 75,  # TLS ClientHello-like
            protocol="tcp",
            domain="example.com",
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,
            tcp_window_size=65535,
            connection_id="https_test_connection"
        )
        contexts.append(("fake_disorder_attack", https_context))
        
        # HTTP scenario
        http_context = AttackContext(
            dst_ip="5.6.7.8",
            dst_port=80,
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            protocol="tcp",
            tcp_seq=2000,
            tcp_ack=3000,
            tcp_flags=0x18,
            tcp_window_size=32768,
            connection_id="http_test_connection"
        )
        contexts.append(("multisplit_attack", http_context))
        
        # Large payload scenario
        large_context = AttackContext(
            dst_ip="9.10.11.12",
            dst_port=443,
            payload=b"POST /api/data HTTP/1.1\r\n" + b"X-Large-Data: " + b"B" * 500 + b"\r\n\r\n",
            protocol="tcp",
            tcp_seq=5000,
            tcp_ack=6000,
            tcp_flags=0x18,
            tcp_window_size=65535,
            connection_id="large_payload_connection"
        )
        contexts.append(("tcp_manipulation_attack", large_context))
        
        return contexts
    
    async def demonstrate_single_attack_dry_run(self):
        """Demonstrate dry run testing of a single attack."""
        logger.info("=== Single Attack Dry Run Demo ===")
        
        # Create test context
        context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            payload=b"test_payload_for_single_attack",
            protocol="tcp",
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,
            tcp_window_size=65535,
            connection_id="single_attack_test"
        )
        
        # Execute dry run test
        logger.info("Executing single attack dry run test...")
        result = await self.engine.execute_dry_run_test("fake_disorder_attack", context)
        
        # Analyze results
        logger.info(f"Dry run result: {result.status.value}")
        
        if result.status == AttackStatus.SUCCESS:
            logger.info("✓ Attack dry run completed successfully")
            
            # Show simulation details
            if "simulation_time_ms" in result.metadata:
                logger.info(f"Simulation time: {result.metadata['simulation_time_ms']:.3f}ms")
            
            # Show segment analysis
            if "segment_analysis" in result.metadata:
                analysis = result.metadata["segment_analysis"]
                logger.info(f"Segments generated: {analysis.get('total_segments', 0)}")
                logger.info(f"TTL modifications: {analysis.get('ttl_modifications', 0)}")
                logger.info(f"Checksum corruptions: {analysis.get('checksum_corruptions', 0)}")
                logger.info(f"Timing delays: {analysis.get('timing_delays', 0)}")
            
            # Show validation results
            if result.metadata.get("segments_valid"):
                logger.info("✓ All segments passed validation")
            else:
                logger.warning("✗ Segment validation issues found")
                for error in result.metadata.get("validation_errors", []):
                    logger.warning(f"  - {error}")
        
        else:
            logger.error(f"✗ Attack dry run failed: {result.error_message}")
        
        logger.info("Single attack dry run demo completed\n")
        return result
    
    def demonstrate_multiple_attack_scenarios(self):
        """Demonstrate testing multiple attack scenarios."""
        logger.info("=== Multiple Attack Scenarios Demo ===")
        
        # Create test scenarios
        scenarios = self.create_test_contexts()
        
        logger.info(f"Testing {len(scenarios)} attack scenarios...")
        
        # Execute scenario testing
        results = self.engine.test_attack_scenarios(scenarios)
        
        # Analyze results
        logger.info("Scenario Testing Results:")
        logger.info(f"Total scenarios: {results['total_scenarios']}")
        logger.info(f"Successful: {results['successful_scenarios']}")
        logger.info(f"Failed: {results['failed_scenarios']}")
        logger.info(f"Success rate: {results['success_rate']:.1f}%")
        
        # Show individual results
        for scenario_key, scenario_result in results["results"].items():
            attack_name = scenario_result["attack_name"]
            status = scenario_result["status"]
            success = "✓" if scenario_result["success"] else "✗"
            
            logger.info(f"  {success} {attack_name}: {status}")
            
            if scenario_result.get("simulation_time_ms"):
                logger.info(f"    Simulation time: {scenario_result['simulation_time_ms']:.3f}ms")
            
            if not scenario_result["success"] and scenario_result.get("error_message"):
                logger.info(f"    Error: {scenario_result['error_message']}")
        
        logger.info("Multiple attack scenarios demo completed\n")
        return results
    
    async def demonstrate_performance_analysis(self):
        """Demonstrate performance analysis using dry run."""
        logger.info("=== Performance Analysis Demo ===")
        
        context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            payload=b"performance_test_payload",
            protocol="tcp",
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,
            tcp_window_size=65535,
            connection_id="performance_test"
        )
        
        # Run multiple iterations for performance analysis
        num_iterations = 5
        attack_name = "fake_disorder_attack"
        
        logger.info(f"Running {num_iterations} iterations for performance analysis...")
        
        results = []
        total_start_time = time.time()
        
        for i in range(num_iterations):
            iteration_start = time.time()
            
            result = await self.engine.execute_dry_run_test(attack_name, context)
            
            iteration_time = (time.time() - iteration_start) * 1000
            
            results.append({
                "iteration": i + 1,
                "status": result.status.value,
                "simulation_time_ms": result.metadata.get("simulation_time_ms", 0),
                "total_time_ms": iteration_time,
                "segments_valid": result.metadata.get("segments_valid", True)
            })
            
            logger.info(f"  Iteration {i+1}: {result.status.value} ({iteration_time:.3f}ms total)")
        
        total_time = (time.time() - total_start_time) * 1000
        
        # Analyze performance
        simulation_times = [r["simulation_time_ms"] for r in results]
        total_times = [r["total_time_ms"] for r in results]
        
        logger.info("Performance Analysis Results:")
        logger.info(f"Total execution time: {total_time:.3f}ms")
        logger.info(f"Average simulation time: {sum(simulation_times) / len(simulation_times):.3f}ms")
        logger.info(f"Average total time: {sum(total_times) / len(total_times):.3f}ms")
        logger.info(f"Min simulation time: {min(simulation_times):.3f}ms")
        logger.info(f"Max simulation time: {max(simulation_times):.3f}ms")
        logger.info(f"Simulation time variance: {max(simulation_times) - min(simulation_times):.3f}ms")
        
        # Check consistency
        successful_runs = sum(1 for r in results if r["status"] == "success")
        logger.info(f"Consistency: {successful_runs}/{num_iterations} successful runs")
        
        logger.info("Performance analysis demo completed\n")
        return results
    
    async def demonstrate_validation_testing(self):
        """Demonstrate validation testing with various scenarios."""
        logger.info("=== Validation Testing Demo ===")
        
        # Test scenarios with different validation outcomes
        test_scenarios = [
            {
                "name": "Valid HTTPS context",
                "context": AttackContext(
                    dst_ip="1.2.3.4",
                    dst_port=443,
                    payload=b"\x16\x03\x01\x00\x50" + b"valid_tls_data",
                    protocol="tcp",
                    tcp_seq=1000,
                    tcp_ack=2000,
                    tcp_flags=0x18,
                    tcp_window_size=65535
                ),
                "expected": "success"
            },
            {
                "name": "Large payload context",
                "context": AttackContext(
                    dst_ip="5.6.7.8",
                    dst_port=80,
                    payload=b"GET / HTTP/1.1\r\n" + b"X-Large-Header: " + b"A" * 1000 + b"\r\n\r\n",
                    protocol="tcp",
                    tcp_seq=2000,
                    tcp_ack=3000,
                    tcp_flags=0x18,
                    tcp_window_size=32768
                ),
                "expected": "success"
            },
            {
                "name": "Edge case - minimal payload",
                "context": AttackContext(
                    dst_ip="9.10.11.12",
                    dst_port=443,
                    payload=b"X",  # Minimal payload
                    protocol="tcp",
                    tcp_seq=3000,
                    tcp_ack=4000,
                    tcp_flags=0x18,
                    tcp_window_size=1024
                ),
                "expected": "success"
            }
        ]
        
        validation_results = []
        
        for scenario in test_scenarios:
            logger.info(f"Testing: {scenario['name']}")
            
            try:
                result = await self.engine.execute_dry_run_test(
                    "fake_disorder_attack", scenario["context"]
                )
                
                validation_result = {
                    "name": scenario["name"],
                    "status": result.status.value,
                    "expected": scenario["expected"],
                    "success": result.status == AttackStatus.SUCCESS,
                    "segments_valid": result.metadata.get("segments_valid", True),
                    "validation_errors": result.metadata.get("validation_errors", []),
                    "simulation_time_ms": result.metadata.get("simulation_time_ms", 0)
                }
                
                validation_results.append(validation_result)
                
                # Log result
                status_icon = "✓" if validation_result["success"] else "✗"
                logger.info(f"  {status_icon} Status: {validation_result['status']}")
                logger.info(f"  Validation: {'✓' if validation_result['segments_valid'] else '✗'}")
                
                if validation_result["validation_errors"]:
                    logger.info(f"  Errors: {len(validation_result['validation_errors'])}")
                
            except Exception as e:
                logger.error(f"  Exception: {e}")
                validation_results.append({
                    "name": scenario["name"],
                    "status": "ERROR",
                    "success": False,
                    "error": str(e)
                })
        
        # Summary
        successful_validations = sum(1 for r in validation_results if r.get("success", False))
        logger.info(f"Validation testing summary: {successful_validations}/{len(test_scenarios)} scenarios passed")
        
        logger.info("Validation testing demo completed\n")
        return validation_results
    
    async def demonstrate_engine_integration(self):
        """Demonstrate engine-specific dry run features."""
        logger.info("=== Engine Integration Demo ===")
        
        context = AttackContext(
            dst_ip="1.2.3.4",
            dst_port=443,
            payload=b"engine_integration_test",
            protocol="tcp",
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,
            tcp_window_size=65535,
            connection_id="engine_integration_test"
        )
        
        # Execute dry run with engine
        result = await self.engine.execute_dry_run_test("fake_disorder_attack", context)
        
        # Show engine-specific metadata
        logger.info("Engine Integration Features:")
        logger.info(f"Engine dry run: {result.metadata.get('engine_dry_run', False)}")
        logger.info(f"Engine type: {result.metadata.get('engine_type', 'unknown')}")
        
        # Show engine statistics integration
        if "engine_stats" in result.metadata:
            engine_stats = result.metadata["engine_stats"]
            logger.info(f"Engine stats included: {len(engine_stats)} metrics")
            logger.info(f"  - Packets processed: {engine_stats.get('packets_processed', 0)}")
            logger.info(f"  - Packets sent: {engine_stats.get('packets_sent', 0)}")
            logger.info(f"  - Errors: {engine_stats.get('errors', 0)}")
        
        # Get current engine statistics
        current_stats = self.engine.get_stats()
        logger.info(f"Current engine statistics:")
        logger.info(f"  - Packets processed: {current_stats.packets_processed}")
        logger.info(f"  - Packets sent: {current_stats.packets_sent}")
        logger.info(f"  - Errors: {current_stats.errors}")
        
        # Get diagnostic statistics
        diag_stats = self.engine.get_diagnostic_statistics()
        logger.info(f"Diagnostic statistics:")
        logger.info(f"  - Total sessions: {diag_stats['diagnostic_system']['total_sessions']}")
        logger.info(f"  - Segments diagnosed: {diag_stats['diagnostic_system']['total_segments_processed']}")
        
        logger.info("Engine integration demo completed\n")
        return result
    
    async def run_all_demos(self):
        """Run all dry run demonstration scenarios."""
        logger.info("Starting Engine Dry Run Testing Demonstration")
        logger.info("=" * 60)
        
        try:
            await self.demonstrate_single_attack_dry_run()
            self.demonstrate_multiple_attack_scenarios()
            await self.demonstrate_performance_analysis()
            await self.demonstrate_validation_testing()
            await self.demonstrate_engine_integration()
            
            logger.info("All engine dry run demonstrations completed successfully!")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise
        finally:
            # Clean up engine
            if self.engine.is_running:
                self.engine.stop()


async def main():
    """Main demo function."""
    demo = EngineDryRunDemo()
    await demo.run_all_demos()


if __name__ == "__main__":
    asyncio.run(main())