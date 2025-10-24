#!/usr/bin/env python3
"""
System validation for PCAP Analysis System with real domains.
Tests the complete system with x.com and other locked domains.
"""

import os
import sys
import time
import json
import asyncio
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

# Add recon to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

from core.pcap_analysis.pcap_comparator import PCAPComparator
from core.pcap_analysis.strategy_validator import StrategyValidator
from core.pcap_analysis.strategy_config import StrategyConfig


@dataclass
class DomainValidationResult:
    """Result of domain validation."""

    domain: str
    strategy_name: str
    success: bool
    response_time: float
    error_message: Optional[str] = None
    pcap_generated: bool = False
    pcap_file: Optional[str] = None


@dataclass
class SystemValidationReport:
    """Complete system validation report."""

    timestamp: str
    total_domains: int
    successful_domains: int
    failed_domains: int
    success_rate: float
    average_response_time: float
    domain_results: List[DomainValidationResult]
    system_performance: Dict[str, float]
    recommendations: List[str]


class SystemValidator:
    """Validates system performance with real domains."""

    def __init__(self, output_dir: str = "validation_results"):
        """Initialize system validator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = self._setup_logging()

        # Test domains - including x.com and other known blocked domains
        self.test_domains = [
            "x.com",
            "twitter.com",
            "youtube.com",
            "facebook.com",
            "instagram.com",
            "discord.com",
            "reddit.com",
            "linkedin.com",
        ]

        # Test strategies
        self.test_strategies = [
            StrategyConfig(
                name="fake_fakeddisorder_x_com",
                dpi_desync="fake,fakeddisorder",
                split_pos=3,
                ttl=3,
                fooling=["badsum", "badseq"],
            ),
            StrategyConfig(
                name="fake_disorder_standard",
                dpi_desync="fake,disorder",
                split_pos=2,
                ttl=5,
                fooling=["badsum"],
            ),
            StrategyConfig(name="split_only", dpi_desync="split", split_pos=3),
        ]

    def _setup_logging(self) -> logging.Logger:
        """Setup logging for validation."""
        logger = logging.getLogger("system_validator")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def run_complete_validation(self) -> SystemValidationReport:
        """Run complete system validation."""
        self.logger.info("Starting complete system validation...")

        start_time = time.time()
        domain_results = []

        # Test each strategy against each domain
        for strategy in self.test_strategies:
            self.logger.info(f"Testing strategy: {strategy.name}")

            for domain in self.test_domains:
                result = await self._validate_domain_strategy(domain, strategy)
                domain_results.append(result)

                status = "✓" if result.success else "✗"
                self.logger.info(f"  {status} {domain}: {result.response_time:.2f}s")

        # Calculate metrics
        total_domains = len(domain_results)
        successful_domains = sum(1 for r in domain_results if r.success)
        failed_domains = total_domains - successful_domains
        success_rate = (
            (successful_domains / total_domains * 100) if total_domains > 0 else 0
        )

        response_times = [r.response_time for r in domain_results if r.success]
        average_response_time = (
            sum(response_times) / len(response_times) if response_times else 0
        )

        # System performance metrics
        total_time = time.time() - start_time
        system_performance = {
            "total_validation_time": total_time,
            "domains_per_second": total_domains / total_time if total_time > 0 else 0,
            "average_domain_time": (
                total_time / total_domains if total_domains > 0 else 0
            ),
            "memory_usage_mb": self._get_memory_usage(),
            "cpu_usage_percent": self._get_cpu_usage(),
        }

        # Generate recommendations
        recommendations = self._generate_recommendations(
            domain_results, system_performance
        )

        report = SystemValidationReport(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            total_domains=total_domains,
            successful_domains=successful_domains,
            failed_domains=failed_domains,
            success_rate=success_rate,
            average_response_time=average_response_time,
            domain_results=domain_results,
            system_performance=system_performance,
            recommendations=recommendations,
        )

        # Save report
        await self._save_report(report)

        return report

    async def _validate_domain_strategy(
        self, domain: str, strategy: StrategyConfig
    ) -> DomainValidationResult:
        """Validate a specific domain with a strategy."""
        start_time = time.time()

        try:
            validator = StrategyValidator()

            # Test strategy effectiveness
            result = await validator.test_strategy_effectiveness(strategy, [domain])

            response_time = time.time() - start_time

            # Check if PCAP was generated
            pcap_file = None
            pcap_generated = False

            if hasattr(result, "pcap_generated") and result.pcap_generated:
                pcap_file = result.pcap_generated
                pcap_generated = True

            return DomainValidationResult(
                domain=domain,
                strategy_name=strategy.name,
                success=result.success if hasattr(result, "success") else False,
                response_time=response_time,
                pcap_generated=pcap_generated,
                pcap_file=pcap_file,
            )

        except Exception as e:
            response_time = time.time() - start_time

            return DomainValidationResult(
                domain=domain,
                strategy_name=strategy.name,
                success=False,
                response_time=response_time,
                error_message=str(e),
            )

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil

            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0

    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil

            return psutil.cpu_percent(interval=1)
        except ImportError:
            return 0.0

    def _generate_recommendations(
        self,
        domain_results: List[DomainValidationResult],
        performance: Dict[str, float],
    ) -> List[str]:
        """Generate recommendations based on validation results."""
        recommendations = []

        # Analyze success rates by domain
        domain_success = {}
        for result in domain_results:
            if result.domain not in domain_success:
                domain_success[result.domain] = {"total": 0, "success": 0}
            domain_success[result.domain]["total"] += 1
            if result.success:
                domain_success[result.domain]["success"] += 1

        # Find problematic domains
        problematic_domains = []
        for domain, stats in domain_success.items():
            success_rate = stats["success"] / stats["total"] * 100
            if success_rate < 50:
                problematic_domains.append(domain)

        if problematic_domains:
            recommendations.append(
                f"Focus on improving strategies for domains with low success rates: {', '.join(problematic_domains)}"
            )

        # Analyze strategy effectiveness
        strategy_success = {}
        for result in domain_results:
            if result.strategy_name not in strategy_success:
                strategy_success[result.strategy_name] = {"total": 0, "success": 0}
            strategy_success[result.strategy_name]["total"] += 1
            if result.success:
                strategy_success[result.strategy_name]["success"] += 1

        best_strategy = max(
            strategy_success.items(), key=lambda x: x[1]["success"] / x[1]["total"]
        )
        worst_strategy = min(
            strategy_success.items(), key=lambda x: x[1]["success"] / x[1]["total"]
        )

        recommendations.append(
            f"Best performing strategy: {best_strategy[0]} "
            f"({best_strategy[1]['success']}/{best_strategy[1]['total']} success)"
        )

        if worst_strategy[1]["success"] / worst_strategy[1]["total"] < 0.3:
            recommendations.append(
                f"Consider revising strategy: {worst_strategy[0]} "
                f"({worst_strategy[1]['success']}/{worst_strategy[1]['total']} success)"
            )

        # Performance recommendations
        if performance["average_domain_time"] > 10:
            recommendations.append(
                "Consider optimizing domain validation time (currently > 10s per domain)"
            )

        if performance["memory_usage_mb"] > 500:
            recommendations.append(
                "High memory usage detected - consider memory optimization"
            )

        # X.com specific recommendations
        x_com_results = [r for r in domain_results if r.domain == "x.com"]
        if x_com_results:
            x_com_success_rate = (
                sum(1 for r in x_com_results if r.success) / len(x_com_results) * 100
            )
            if x_com_success_rate < 80:
                recommendations.append(
                    f"X.com success rate is {x_com_success_rate:.1f}% - "
                    "focus on improving fake+fakeddisorder strategy implementation"
                )

        return recommendations

    async def _save_report(self, report: SystemValidationReport):
        """Save validation report to file."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # Save JSON report
        json_file = self.output_dir / f"system_validation_{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(asdict(report), f, indent=2, default=str)

        # Save human-readable report
        text_file = self.output_dir / f"system_validation_{timestamp}.txt"
        with open(text_file, "w") as f:
            f.write("PCAP Analysis System Validation Report\n")
            f.write("=" * 50 + "\n\n")

            f.write(f"Timestamp: {report.timestamp}\n")
            f.write(f"Total Domains Tested: {report.total_domains}\n")
            f.write(f"Successful: {report.successful_domains}\n")
            f.write(f"Failed: {report.failed_domains}\n")
            f.write(f"Success Rate: {report.success_rate:.1f}%\n")
            f.write(f"Average Response Time: {report.average_response_time:.2f}s\n\n")

            f.write("System Performance:\n")
            for key, value in report.system_performance.items():
                f.write(f"  {key}: {value:.2f}\n")
            f.write("\n")

            f.write("Domain Results:\n")
            f.write("-" * 30 + "\n")
            for result in report.domain_results:
                status = "✓" if result.success else "✗"
                f.write(
                    f"{status} {result.domain} ({result.strategy_name}): {result.response_time:.2f}s"
                )
                if result.error_message:
                    f.write(f" - Error: {result.error_message}")
                f.write("\n")
            f.write("\n")

            f.write("Recommendations:\n")
            f.write("-" * 20 + "\n")
            for i, rec in enumerate(report.recommendations, 1):
                f.write(f"{i}. {rec}\n")

        self.logger.info(f"Validation report saved to {json_file} and {text_file}")

    async def validate_x_com_specifically(self) -> Dict[str, any]:
        """Specific validation for x.com domain."""
        self.logger.info("Running specific x.com validation...")

        # Test the exact strategy that should work for x.com
        x_com_strategy = StrategyConfig(
            name="x_com_optimized",
            dpi_desync="fake,fakeddisorder",
            split_pos=3,
            split_seqovl=1,
            ttl=3,
            fooling=["badsum", "badseq"],
        )

        result = await self._validate_domain_strategy("x.com", x_com_strategy)

        # Additional x.com specific tests
        pcap_comparison_result = None
        if os.path.exists("recon/recon_x.pcap") and os.path.exists(
            "recon/zapret_x.pcap"
        ):
            try:
                comparator = PCAPComparator()
                pcap_comparison_result = comparator.compare_pcaps(
                    "recon/recon_x.pcap", "recon/zapret_x.pcap"
                )
            except Exception as e:
                self.logger.error(f"PCAP comparison failed: {e}")

        return {
            "domain_validation": asdict(result),
            "pcap_comparison": {
                "available": pcap_comparison_result is not None,
                "similarity_score": (
                    getattr(pcap_comparison_result, "similarity_score", 0)
                    if pcap_comparison_result
                    else 0
                ),
                "packet_differences": (
                    len(getattr(pcap_comparison_result, "sequence_differences", []))
                    if pcap_comparison_result
                    else 0
                ),
            },
            "strategy_analysis": {
                "strategy_name": x_com_strategy.name,
                "parameters": asdict(x_com_strategy),
                "expected_behavior": "Should generate fake packet with TTL=3, split at position 3, apply badsum+badseq",
            },
        }


async def main():
    """Run system validation."""
    import argparse

    parser = argparse.ArgumentParser(description="PCAP Analysis System Validation")
    parser.add_argument(
        "--output-dir", default="validation_results", help="Output directory"
    )
    parser.add_argument(
        "--x-com-only", action="store_true", help="Test only x.com domain"
    )
    parser.add_argument(
        "--quick", action="store_true", help="Quick validation with fewer domains"
    )

    args = parser.parse_args()

    validator = SystemValidator(args.output_dir)

    if args.x_com_only:
        print("🎯 Running x.com specific validation...")
        result = await validator.validate_x_com_specifically()

        print("\nX.com Validation Results:")
        print("=" * 30)
        domain_result = result["domain_validation"]
        status = "✓" if domain_result["success"] else "✗"
        print(f"{status} Domain: {domain_result['domain']}")
        print(f"  Strategy: {domain_result['strategy_name']}")
        print(f"  Response Time: {domain_result['response_time']:.2f}s")
        if domain_result.get("error_message"):
            print(f"  Error: {domain_result['error_message']}")

        pcap_result = result["pcap_comparison"]
        print(f"\nPCAP Comparison Available: {pcap_result['available']}")
        if pcap_result["available"]:
            print(f"Similarity Score: {pcap_result['similarity_score']:.2f}")
            print(f"Packet Differences: {pcap_result['packet_differences']}")

        return 0 if domain_result["success"] else 1

    if args.quick:
        # Reduce test domains for quick validation
        validator.test_domains = ["x.com", "youtube.com", "discord.com"]
        validator.test_strategies = validator.test_strategies[:2]

    print("🚀 Starting complete system validation...")
    report = await validator.run_complete_validation()

    print("\n" + "=" * 50)
    print("📊 SYSTEM VALIDATION REPORT")
    print("=" * 50)

    print(f"Total Domains Tested: {report.total_domains}")
    print(f"Successful: {report.successful_domains} ✓")
    print(f"Failed: {report.failed_domains} ✗")
    print(f"Success Rate: {report.success_rate:.1f}%")
    print(f"Average Response Time: {report.average_response_time:.2f}s")

    print("\nSystem Performance:")
    for key, value in report.system_performance.items():
        print(f"  {key}: {value:.2f}")

    if report.recommendations:
        print("\n📋 Recommendations:")
        for i, rec in enumerate(report.recommendations, 1):
            print(f"{i}. {rec}")

    # Return appropriate exit code
    return 0 if report.success_rate >= 70 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
