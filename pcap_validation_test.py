#!/usr/bin/env python3
"""
PCAP Validation Testing Script

Tests individual attacks with packet capture to validate their real-world effectiveness.
This script performs systematic testing of each attack category with network validation.
"""

import os
import sys
import asyncio
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.registry import AttackRegistry
from core.bypass.pcap.capture_engine import PCAPCaptureEngine
from core.bypass.pcap.analysis_engine import PCAPAnalysisEngine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("pcap_validation.log"), logging.StreamHandler()],
)
LOG = logging.getLogger("PCAPValidation")


@dataclass
class PCAPTestResult:
    """Result of a PCAP validation test."""

    attack_name: str
    attack_category: str
    target_domain: str
    target_port: int
    success: bool
    attack_result: Optional[AttackResult] = None
    pcap_file: Optional[str] = None
    packet_count: int = 0
    capture_duration: float = 0.0
    analysis_results: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class PCAPValidationTester:
    """
    PCAP Validation Testing Engine

    Tests attacks with packet capture to validate their real-world effectiveness
    and ensure they work correctly with actual network traffic.
    """

    def __init__(
        self, capture_interface: str = "auto", output_dir: str = "pcap_validation"
    ):
        """
        Initialize PCAP validation tester.

        Args:
            capture_interface: Network interface for packet capture
            output_dir: Directory to store PCAP files and results
        """
        self.capture_interface = capture_interface
        self.output_dir = output_dir
        self.attack_registry = AttackRegistry()

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Initialize capture and analysis engines
        try:
            self.capture_engine = PCAPCaptureEngine(interface=capture_interface)
            self.analysis_engine = PCAPAnalysisEngine()
        except Exception as e:
            LOG.warning(f"PCAP engines initialization failed: {e}")
            self.capture_engine = None
            self.analysis_engine = None

        # Test configuration
        self.test_domains = [
            ("google.com", 443),
            ("cloudflare.com", 443),
            ("1.1.1.1", 443),
            ("8.8.8.8", 443),
        ]

        self.results = []

    async def run_validation_tests(
        self, attack_categories: Optional[List[str]] = None
    ) -> List[PCAPTestResult]:
        """
        Run PCAP validation tests for specified attack categories.

        Args:
            attack_categories: List of attack categories to test, or None for all

        Returns:
            List of test results
        """
        LOG.info("🔬 Starting PCAP Validation Testing")
        LOG.info("=" * 60)

        if not self.capture_engine or not self.analysis_engine:
            LOG.error("PCAP engines not available, running simplified validation")
            return await self.run_simplified_validation(attack_categories)

        # Get attacks to test
        attacks_to_test = self._get_attacks_to_test(attack_categories)

        LOG.info(
            f"Testing {len(attacks_to_test)} attacks across {len(self.test_domains)} domains"
        )

        total_tests = len(attacks_to_test) * len(self.test_domains)
        completed_tests = 0

        for attack_name, attack_instance in attacks_to_test:
            for domain, port in self.test_domains:
                completed_tests += 1
                LOG.info(
                    f"[{completed_tests}/{total_tests}] Testing {attack_name} against {domain}:{port}"
                )

                try:
                    result = await self._test_attack_with_pcap(
                        attack_name, attack_instance, domain, port
                    )
                    self.results.append(result)

                    # Log result
                    status = "✅ SUCCESS" if result.success else "❌ FAILED"
                    LOG.info(
                        f"  {status}: {result.attack_name} -> {result.target_domain}"
                    )
                    if result.error_message:
                        LOG.warning(f"    Error: {result.error_message}")

                except Exception as e:
                    error_result = PCAPTestResult(
                        attack_name=attack_name,
                        attack_category=getattr(attack_instance, "category", "unknown"),
                        target_domain=domain,
                        target_port=port,
                        success=False,
                        error_message=f"Test execution failed: {str(e)}",
                    )
                    self.results.append(error_result)
                    LOG.error(f"  ❌ ERROR: {attack_name} -> {domain}: {e}")

                # Small delay between tests
                await asyncio.sleep(1.0)

        LOG.info(f"\n🏁 PCAP Validation Testing Completed")
        await self._save_results()
        await self._print_summary()

        return self.results

    async def run_simplified_validation(
        self, attack_categories: Optional[List[str]] = None
    ) -> List[PCAPTestResult]:
        """
        Run simplified validation without PCAP capture.

        Args:
            attack_categories: List of attack categories to test

        Returns:
            List of test results
        """
        LOG.info("🔬 Running Simplified Validation (no PCAP capture)")

        attacks_to_test = self._get_attacks_to_test(attack_categories)

        for attack_name, attack_instance in attacks_to_test:
            for domain, port in self.test_domains:
                try:
                    # Create attack context
                    context = AttackContext(
                        dst_ip=domain,
                        dst_port=port,
                        domain=domain,
                        protocol="tcp",
                        payload=b"GET / HTTP/1.1\r\nHost: "
                        + domain.encode()
                        + b"\r\n\r\n",
                    )

                    # Execute attack
                    attack_result = await attack_instance.execute(context)

                    result = PCAPTestResult(
                        attack_name=attack_name,
                        attack_category=getattr(attack_instance, "category", "unknown"),
                        target_domain=domain,
                        target_port=port,
                        success=attack_result.status == AttackStatus.SUCCESS,
                        attack_result=attack_result,
                    )
                    self.results.append(result)

                    status = "✅ SUCCESS" if result.success else "❌ FAILED"
                    LOG.info(f"  {status}: {attack_name} -> {domain}")

                except Exception as e:
                    error_result = PCAPTestResult(
                        attack_name=attack_name,
                        attack_category=getattr(attack_instance, "category", "unknown"),
                        target_domain=domain,
                        target_port=port,
                        success=False,
                        error_message=str(e),
                    )
                    self.results.append(error_result)
                    LOG.error(f"  ❌ ERROR: {attack_name} -> {domain}: {e}")

        await self._save_results()
        await self._print_summary()
        return self.results

    def _get_attacks_to_test(
        self, categories: Optional[List[str]] = None
    ) -> List[tuple]:
        """Get list of attacks to test."""
        all_attacks = self.attack_registry.get_all_attacks()

        if not categories:
            return list(all_attacks.items())

        filtered_attacks = []
        for name, attack in all_attacks.items():
            if hasattr(attack, "category") and attack.category in categories:
                filtered_attacks.append((name, attack))

        return filtered_attacks

    async def _test_attack_with_pcap(
        self, attack_name: str, attack_instance, domain: str, port: int
    ) -> PCAPTestResult:
        """Test an individual attack with PCAP capture."""
        pcap_filename = f"{attack_name}_{domain}_{port}_{int(time.time())}.pcap"
        pcap_path = os.path.join(self.output_dir, pcap_filename)

        try:
            # Start packet capture
            await self.capture_engine.start_capture(
                filter_expr=f"host {domain}", output_file=pcap_path
            )

            capture_start_time = time.time()

            # Create attack context
            context = AttackContext(
                dst_ip=domain,
                dst_port=port,
                domain=domain,
                protocol="tcp",
                payload=b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\n\r\n",
                params={"pcap_validation": True},
            )

            # Execute attack
            attack_result = await attack_instance.execute(context)

            # Wait a bit for packets to be captured
            await asyncio.sleep(2.0)

            # Stop capture
            packet_count = await self.capture_engine.stop_capture()
            capture_duration = time.time() - capture_start_time

            # Analyze captured packets
            analysis_results = None
            if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
                analysis_results = await self.analysis_engine.analyze_pcap(pcap_path)

            # Determine success
            success = (
                attack_result.status == AttackStatus.SUCCESS
                and packet_count > 0
                and (
                    analysis_results is None
                    or analysis_results.get("bypass_detected", False)
                )
            )

            return PCAPTestResult(
                attack_name=attack_name,
                attack_category=getattr(attack_instance, "category", "unknown"),
                target_domain=domain,
                target_port=port,
                success=success,
                attack_result=attack_result,
                pcap_file=pcap_filename,
                packet_count=packet_count,
                capture_duration=capture_duration,
                analysis_results=analysis_results,
            )

        except Exception as e:
            # Clean up on error
            if hasattr(self.capture_engine, "stop_capture"):
                try:
                    await self.capture_engine.stop_capture()
                except:
                    pass

            return PCAPTestResult(
                attack_name=attack_name,
                attack_category=getattr(attack_instance, "category", "unknown"),
                target_domain=domain,
                target_port=port,
                success=False,
                error_message=str(e),
            )

    async def _save_results(self):
        """Save test results to JSON file."""
        results_file = os.path.join(
            self.output_dir, f"pcap_validation_results_{int(time.time())}.json"
        )

        # Convert results to serializable format
        serializable_results = []
        for result in self.results:
            result_dict = asdict(result)
            # Handle AttackResult serialization
            if result.attack_result:
                result_dict["attack_result"] = {
                    "status": result.attack_result.status.value,
                    "latency_ms": result.attack_result.latency_ms,
                    "packets_sent": result.attack_result.packets_sent,
                    "bytes_sent": result.attack_result.bytes_sent,
                    "connection_established": result.attack_result.connection_established,
                    "data_transmitted": result.attack_result.data_transmitted,
                    "technique_used": result.attack_result.technique_used,
                    "error_message": result.attack_result.error_message,
                }
            serializable_results.append(result_dict)

        with open(results_file, "w") as f:
            json.dump(serializable_results, f, indent=2)

        LOG.info(f"📄 Results saved to: {results_file}")

    async def _print_summary(self):
        """Print test summary."""
        if not self.results:
            LOG.info("No test results to summarize")
            return

        LOG.info("\n" + "=" * 60)
        LOG.info("📊 PCAP VALIDATION SUMMARY")
        LOG.info("=" * 60)

        # Overall statistics
        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results if r.success)
        failed_tests = total_tests - successful_tests

        LOG.info(f"Total Tests: {total_tests}")
        LOG.info(
            f"Successful: {successful_tests} ({successful_tests/total_tests*100:.1f}%)"
        )
        LOG.info(f"Failed: {failed_tests} ({failed_tests/total_tests*100:.1f}%)")

        # Results by category
        categories = {}
        for result in self.results:
            category = result.attack_category
            if category not in categories:
                categories[category] = {"total": 0, "success": 0}
            categories[category]["total"] += 1
            if result.success:
                categories[category]["success"] += 1

        LOG.info(f"\nResults by Category:")
        for category, stats in categories.items():
            success_rate = stats["success"] / stats["total"] * 100
            LOG.info(
                f"  📁 {category.upper()}: {stats['success']}/{stats['total']} ({success_rate:.1f}%)"
            )

        # Results by domain
        domains = {}
        for result in self.results:
            domain = result.target_domain
            if domain not in domains:
                domains[domain] = {"total": 0, "success": 0}
            domains[domain]["total"] += 1
            if result.success:
                domains[domain]["success"] += 1

        LOG.info(f"\nResults by Target:")
        for domain, stats in domains.items():
            success_rate = stats["success"] / stats["total"] * 100
            LOG.info(
                f"  🎯 {domain}: {stats['success']}/{stats['total']} ({success_rate:.1f}%)"
            )

        # Failed tests details
        failed_results = [r for r in self.results if not r.success]
        if failed_results:
            LOG.info(f"\n❌ Failed Tests ({len(failed_results)}):")
            for result in failed_results[:10]:  # Show first 10 failures
                LOG.info(
                    f"  • {result.attack_name} -> {result.target_domain}: {result.error_message}"
                )
            if len(failed_results) > 10:
                LOG.info(f"  ... and {len(failed_results) - 10} more failures")


async def main():
    """Main function for PCAP validation testing."""
    import argparse

    parser = argparse.ArgumentParser(
        description="PCAP Validation Testing for RECON Attacks"
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        help="Attack categories to test (dns, http, tcp, tls, timing, obfuscation, combo)",
    )
    parser.add_argument(
        "--interface", default="auto", help="Network interface for packet capture"
    )
    parser.add_argument(
        "--output-dir",
        default="pcap_validation",
        help="Output directory for PCAP files and results",
    )
    parser.add_argument(
        "--simplified",
        action="store_true",
        help="Run simplified validation without PCAP capture",
    )

    args = parser.parse_args()

    # Create tester
    tester = PCAPValidationTester(
        capture_interface=args.interface, output_dir=args.output_dir
    )

    # Force simplified mode if requested or if PCAP engines not available
    if args.simplified or not tester.capture_engine:
        results = await tester.run_simplified_validation(args.categories)
    else:
        results = await tester.run_validation_tests(args.categories)

    # Print final status
    successful_tests = sum(1 for r in results if r.success)
    total_tests = len(results)

    LOG.info(f"\n🎯 FINAL RESULT: {successful_tests}/{total_tests} tests successful")

    if successful_tests > total_tests * 0.8:
        LOG.info("🎉 EXCELLENT: Most attacks working correctly!")
    elif successful_tests > total_tests * 0.6:
        LOG.info("👍 GOOD: Majority of attacks working correctly")
    elif successful_tests > total_tests * 0.4:
        LOG.info("⚠️  MODERATE: Some attacks need attention")
    else:
        LOG.info("🔧 NEEDS WORK: Many attacks require fixes")


if __name__ == "__main__":
    asyncio.run(main())
