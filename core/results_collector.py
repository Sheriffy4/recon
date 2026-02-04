"""
Results Collector for Auto Strategy Discovery System

This module implements results collection and filtering for the auto strategy discovery system,
ensuring that only results for the target domain are collected and reported during discovery sessions.

Requirements: 1.5, 3.3, 3.5 from auto-strategy-discovery spec
"""

import logging
import time
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter

from core.domain_filter import DomainFilter, FilterMode
from core.test_result_models import (
    TestSession,
    TestVerdict,
    PCAPAnalysisResult,
    ValidationResult,
    VerdictType,
)

LOG = logging.getLogger(__name__)

# Import discovery logging (with fallback if not available)
try:
    from core.discovery_logging import get_discovery_logger, get_metrics_collector

    DISCOVERY_LOGGING_AVAILABLE = True
except ImportError:
    DISCOVERY_LOGGING_AVAILABLE = False


class ResultType(Enum):
    """Types of results that can be collected"""

    STRATEGY_TEST = "strategy_test"
    PCAP_ANALYSIS = "pcap_analysis"
    VALIDATION = "validation"
    PERFORMANCE = "performance"
    DISCOVERY_SESSION = "discovery_session"


@dataclass
class CollectionStats:
    """Statistics for result collection operations"""

    total_results: int = 0
    filtered_results: int = 0
    target_domain_results: int = 0
    background_results: int = 0
    collection_errors: int = 0

    # Per-type statistics
    results_by_type: Dict[str, int] = field(default_factory=dict)

    @property
    def filter_rate(self) -> float:
        """Calculate the filtering rate (filtered/total)"""
        return self.filtered_results / self.total_results if self.total_results > 0 else 0.0

    @property
    def target_rate(self) -> float:
        """Calculate the target domain rate (target/total)"""
        return self.target_domain_results / self.total_results if self.total_results > 0 else 0.0


@dataclass
class AggregatedStats:
    """Aggregated statistics for target domain results"""

    domain: str
    total_tests: int = 0
    successful_tests: int = 0
    failed_tests: int = 0

    # Performance metrics
    avg_response_time_ms: float = 0.0
    min_response_time_ms: float = float("inf")
    max_response_time_ms: float = 0.0

    # Strategy effectiveness
    strategies_tested: Set[str] = field(default_factory=set)
    successful_strategies: Set[str] = field(default_factory=set)

    # PCAP analysis aggregates
    total_packets_analyzed: int = 0
    attacks_detected: Counter = field(default_factory=Counter)

    # Validation aggregates
    strategy_matches: int = 0
    strategy_mismatches: int = 0

    # Time range
    first_result_time: Optional[datetime] = None
    last_result_time: Optional[datetime] = None

    @property
    def success_rate(self) -> float:
        """Calculate overall success rate"""
        return self.successful_tests / self.total_tests if self.total_tests > 0 else 0.0

    @property
    def strategy_success_rate(self) -> float:
        """Calculate strategy-level success rate"""
        total_strategies = len(self.strategies_tested)
        return len(self.successful_strategies) / total_strategies if total_strategies > 0 else 0.0


@dataclass
class DiscoveryReport:
    """Comprehensive discovery session report"""

    session_id: str
    target_domain: str
    start_time: datetime
    end_time: Optional[datetime] = None

    # Aggregated statistics
    aggregated_stats: Optional[AggregatedStats] = None

    # Collection metadata
    collection_stats: Optional[CollectionStats] = None

    # Key findings
    best_strategies: List[Dict[str, Any]] = field(default_factory=list)
    discovered_vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # Raw results (filtered to target domain only)
    filtered_results: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Calculate session duration in seconds"""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


class ResultsCollector:
    """
    Results collection and filtering system for auto strategy discovery.

    Provides domain-based filtering to ensure only target domain results
    are collected and aggregated during discovery sessions, filtering out
    unrelated domains and background traffic.

    Key features:
    - Domain-based result filtering using DomainFilter integration
    - Statistics aggregation excluding non-target domains
    - Report generation with target domain isolation
    - Real-time result collection and filtering
    - Comprehensive discovery session reporting
    """

    def __init__(self, domain_filter: Optional[DomainFilter] = None):
        """
        Initialize the ResultsCollector.

        Args:
            domain_filter: Optional DomainFilter instance for domain filtering
        """
        self.domain_filter = domain_filter or DomainFilter()
        self.collected_results: List[Dict[str, Any]] = []
        self.collection_stats = CollectionStats()
        self.current_session_id: Optional[str] = None
        self.session_start_time: Optional[datetime] = None

        # Initialize discovery logging if available
        self._discovery_logger = None
        self._metrics_collector = None
        if DISCOVERY_LOGGING_AVAILABLE:
            try:
                self._discovery_logger = get_discovery_logger()
                self._metrics_collector = get_metrics_collector()
            except Exception as e:
                LOG.warning(f"Failed to initialize discovery logging: {e}")

        LOG.info("ResultsCollector initialized")

    def start_collection_session(self, session_id: str, target_domain: str) -> None:
        """
        Start a new result collection session for a target domain.

        Args:
            session_id: Unique identifier for the collection session
            target_domain: Target domain for filtering results

        Requirements: 1.5, 3.5 (target domain statistics isolation)
        """
        self.current_session_id = session_id
        self.session_start_time = datetime.now()

        # Configure domain filter for discovery mode
        self.domain_filter.configure_filter(target_domain, FilterMode.DISCOVERY)

        # Reset collection state
        self.collected_results.clear()
        self.collection_stats = CollectionStats()

        LOG.info(f"Started collection session '{session_id}' for domain '{target_domain}'")

    def collect_result(self, result: Dict[str, Any], result_type: ResultType) -> bool:
        """
        Collect a single result with domain-based filtering.

        Args:
            result: Result dictionary to collect
            result_type: Type of result being collected

        Returns:
            True if result was collected, False if filtered out

        Requirements: 1.5, 3.3, 3.5 (target domain evaluation isolation)
        """
        self.collection_stats.total_results += 1
        self.collection_stats.results_by_type[result_type.value] = (
            self.collection_stats.results_by_type.get(result_type.value, 0) + 1
        )

        try:
            # Check if result is for target domain using domain filter
            if self._is_result_for_target_domain(result):
                # Add metadata to result
                enriched_result = self._enrich_result(result, result_type)
                self.collected_results.append(enriched_result)
                self.collection_stats.target_domain_results += 1

                # Log result collection if discovery logging is available
                if self._discovery_logger and self.current_session_id:
                    target_domain = self.domain_filter.get_current_target() or "unknown"
                    self._discovery_logger.log_result_collected(
                        self.current_session_id,
                        target_domain,
                        result_type.value,
                        True,
                        "Target domain match",
                    )

                # Record metrics if available
                if self._metrics_collector and self.current_session_id:
                    self._metrics_collector.record_result_collection(self.current_session_id, True)

                LOG.debug(f"Collected {result_type.value} result for target domain")
                return True
            else:
                # Result is for non-target domain - filter it out
                self.collection_stats.background_results += 1
                self.collection_stats.filtered_results += 1

                # Log result filtering if discovery logging is available
                if self._discovery_logger and self.current_session_id:
                    target_domain = self.domain_filter.get_current_target() or "unknown"
                    result_domain = result.get("domain", "unknown")
                    self._discovery_logger.log_result_collected(
                        self.current_session_id,
                        target_domain,
                        result_type.value,
                        False,
                        f"Non-target domain: {result_domain}",
                    )

                # Record metrics if available
                if self._metrics_collector and self.current_session_id:
                    self._metrics_collector.record_result_collection(self.current_session_id, False)

                LOG.debug(f"Filtered out {result_type.value} result for non-target domain")
                return False

        except Exception as e:
            self.collection_stats.collection_errors += 1

            # Log error if discovery logging is available
            if self._discovery_logger and self.current_session_id:
                target_domain = self.domain_filter.get_current_target() or "unknown"
                self._discovery_logger.log_error(
                    self.current_session_id,
                    target_domain,
                    f"Result collection error: {e}",
                    "results_collector",
                    e,
                )

            # Record error metrics if available
            if self._metrics_collector and self.current_session_id:
                self._metrics_collector.record_error(self.current_session_id, "error")

            LOG.warning(f"Error collecting result: {e}")
            return False

    def _is_result_for_target_domain(self, result: Dict[str, Any]) -> bool:
        """
        Check if a result is related to the target domain.

        Uses the domain filter's existing logic for consistency.

        Args:
            result: Result dictionary to check

        Returns:
            True if result is for target domain

        Requirements: 1.5, 3.5 (target domain statistics isolation)
        """
        if not self.domain_filter.is_discovery_mode():
            # Not in discovery mode - collect all results
            return True

        # Use domain filter's existing method for consistency
        return self.domain_filter._is_result_for_target_domain(result)

    def _enrich_result(self, result: Dict[str, Any], result_type: ResultType) -> Dict[str, Any]:
        """
        Enrich result with collection metadata.

        Args:
            result: Original result dictionary
            result_type: Type of result

        Returns:
            Enriched result dictionary
        """
        enriched = result.copy()
        enriched.update(
            {
                "_collection_metadata": {
                    "result_type": result_type.value,
                    "collection_time": datetime.now().isoformat(),
                    "session_id": self.current_session_id,
                    "target_domain": self.domain_filter.get_current_target(),
                }
            }
        )
        return enriched

    def collect_test_session(self, test_session: TestSession) -> bool:
        """
        Collect a test session result.

        Args:
            test_session: TestSession object to collect

        Returns:
            True if collected, False if filtered out
        """
        result = {
            "session": test_session,
            "domain": test_session.domain,
            "strategy_name": test_session.strategy_name,
            "verdict": test_session.verdict.value if test_session.verdict else None,
            "response_time_ms": (
                (test_session.end_time - test_session.start_time) * 1000
                if test_session.end_time
                else None
            ),
        }

        return self.collect_result(result, ResultType.STRATEGY_TEST)

    def collect_pcap_analysis(self, pcap_analysis: PCAPAnalysisResult, domain: str) -> bool:
        """
        Collect a PCAP analysis result.

        Args:
            pcap_analysis: PCAPAnalysisResult object to collect
            domain: Domain associated with the analysis

        Returns:
            True if collected, False if filtered out
        """
        result = {
            "pcap_analysis": pcap_analysis,
            "domain": domain,
            "packet_count": pcap_analysis.packet_count,
            "detected_attacks": pcap_analysis.detected_attacks,
            "strategy_type": pcap_analysis.strategy_type,
        }

        return self.collect_result(result, ResultType.PCAP_ANALYSIS)

    def collect_validation_result(self, validation: ValidationResult, domain: str) -> bool:
        """
        Collect a validation result.

        Args:
            validation: ValidationResult object to collect
            domain: Domain associated with the validation

        Returns:
            True if collected, False if filtered out
        """
        result = {
            "validation": validation,
            "domain": domain,
            "is_valid": validation.is_valid,
            "strategy_match": validation.strategy_match,
            "declared_strategy": validation.declared_strategy,
            "applied_strategy": validation.applied_strategy,
        }

        return self.collect_result(result, ResultType.VALIDATION)

    def get_filtered_results(self) -> List[Dict[str, Any]]:
        """
        Get all collected results (already filtered to target domain).

        Returns:
            List of filtered result dictionaries

        Requirements: 1.5, 3.5 (target domain statistics isolation)
        """
        return self.collected_results.copy()

    def aggregate_statistics(self) -> AggregatedStats:
        """
        Aggregate statistics from collected results, excluding non-target domains.

        Returns:
            AggregatedStats object with target domain statistics

        Requirements: 1.5, 3.3, 3.5 (target domain statistics isolation)
        """
        target_domain = self.domain_filter.get_current_target() or "unknown"
        stats = AggregatedStats(domain=target_domain)

        response_times = []

        for result in self.collected_results:
            result_type = result.get("_collection_metadata", {}).get("result_type")

            # Process strategy test results
            if result_type == ResultType.STRATEGY_TEST.value:
                stats.total_tests += 1

                # Track strategy names
                strategy_name = result.get("strategy_name")
                if strategy_name:
                    stats.strategies_tested.add(strategy_name)

                # Check success/failure
                verdict = result.get("verdict")
                if verdict == VerdictType.SUCCESS.value:
                    stats.successful_tests += 1
                    if strategy_name:
                        stats.successful_strategies.add(strategy_name)
                elif verdict in [VerdictType.FAILURE.value, VerdictType.INCONCLUSIVE.value]:
                    stats.failed_tests += 1

                # Collect response times
                response_time = result.get("response_time_ms")
                if response_time is not None:
                    response_times.append(response_time)

            # Process PCAP analysis results
            elif result_type == ResultType.PCAP_ANALYSIS.value:
                stats.total_packets_analyzed += result.get("packet_count", 0)

                detected_attacks = result.get("detected_attacks", [])
                for attack in detected_attacks:
                    stats.attacks_detected[attack] += 1

            # Process validation results
            elif result_type == ResultType.VALIDATION.value:
                if result.get("strategy_match"):
                    stats.strategy_matches += 1
                else:
                    stats.strategy_mismatches += 1

            # Track time range
            collection_time_str = result.get("_collection_metadata", {}).get("collection_time")
            if collection_time_str:
                try:
                    collection_time = datetime.fromisoformat(collection_time_str)
                    if stats.first_result_time is None or collection_time < stats.first_result_time:
                        stats.first_result_time = collection_time
                    if stats.last_result_time is None or collection_time > stats.last_result_time:
                        stats.last_result_time = collection_time
                except ValueError:
                    pass

        # Calculate response time statistics
        if response_times:
            stats.avg_response_time_ms = sum(response_times) / len(response_times)
            stats.min_response_time_ms = min(response_times)
            stats.max_response_time_ms = max(response_times)
        else:
            stats.min_response_time_ms = 0.0

        LOG.info(
            f"Aggregated statistics for {target_domain}: "
            f"{stats.total_tests} tests, {stats.success_rate:.1%} success rate"
        )

        return stats

    def generate_report(self) -> DiscoveryReport:
        """
        Generate comprehensive discovery report with target domain isolation.

        Returns:
            DiscoveryReport with filtered results and aggregated statistics

        Requirements: 1.5, 3.3, 3.5 (target domain statistics isolation)
        """
        target_domain = self.domain_filter.get_current_target() or "unknown"

        # Generate aggregated statistics
        aggregated_stats = self.aggregate_statistics()

        # Identify best strategies
        best_strategies = self._identify_best_strategies()

        # Generate recommendations
        recommendations = self._generate_recommendations(aggregated_stats)

        # Identify discovered vulnerabilities
        vulnerabilities = self._identify_vulnerabilities(aggregated_stats)

        report = DiscoveryReport(
            session_id=self.current_session_id or "unknown",
            target_domain=target_domain,
            start_time=self.session_start_time or datetime.now(),
            end_time=datetime.now(),
            aggregated_stats=aggregated_stats,
            collection_stats=self.collection_stats,
            best_strategies=best_strategies,
            discovered_vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            filtered_results=self.get_filtered_results(),
        )

        LOG.info(
            f"Generated discovery report for {target_domain}: "
            f"{len(report.filtered_results)} results, "
            f"{report.duration_seconds:.1f}s duration"
        )

        return report

    def _identify_best_strategies(self) -> List[Dict[str, Any]]:
        """Identify the best performing strategies from collected results"""
        strategy_performance = defaultdict(
            lambda: {"tests": 0, "successes": 0, "avg_time": 0.0, "times": []}
        )

        for result in self.collected_results:
            if (
                result.get("_collection_metadata", {}).get("result_type")
                == ResultType.STRATEGY_TEST.value
            ):
                strategy_name = result.get("strategy_name")
                verdict = result.get("verdict")
                response_time = result.get("response_time_ms")

                if strategy_name:
                    perf = strategy_performance[strategy_name]
                    perf["tests"] += 1

                    if verdict == VerdictType.SUCCESS.value:
                        perf["successes"] += 1

                    if response_time is not None:
                        perf["times"].append(response_time)

        # Calculate success rates and average times
        best_strategies = []
        for strategy_name, perf in strategy_performance.items():
            success_rate = perf["successes"] / perf["tests"] if perf["tests"] > 0 else 0.0
            avg_time = sum(perf["times"]) / len(perf["times"]) if perf["times"] else 0.0

            best_strategies.append(
                {
                    "strategy_name": strategy_name,
                    "success_rate": success_rate,
                    "total_tests": perf["tests"],
                    "successful_tests": perf["successes"],
                    "avg_response_time_ms": avg_time,
                }
            )

        # Sort by success rate, then by response time
        best_strategies.sort(
            key=lambda x: (x["success_rate"], -x["avg_response_time_ms"]), reverse=True
        )

        return best_strategies[:5]  # Return top 5

    def _generate_recommendations(self, stats: AggregatedStats) -> List[str]:
        """Generate recommendations based on aggregated statistics"""
        recommendations = []

        if stats.success_rate >= 0.8:
            recommendations.append("High success rate achieved - current strategies are effective")
        elif stats.success_rate < 0.3:
            recommendations.append(
                "Low success rate - consider trying more diverse attack strategies"
            )

        if stats.strategy_success_rate < 0.5:
            recommendations.append(
                "Many strategies failed - target may have advanced DPI protection"
            )

        if stats.total_packets_analyzed > 0:
            most_common_attack = stats.attacks_detected.most_common(1)
            if most_common_attack:
                attack_name, count = most_common_attack[0]
                recommendations.append(
                    f"Most effective attack type: {attack_name} (detected {count} times)"
                )

        if stats.avg_response_time_ms > 5000:
            recommendations.append(
                "High response times detected - consider optimizing strategy parameters"
            )

        return recommendations

    def _identify_vulnerabilities(self, stats: AggregatedStats) -> List[str]:
        """Identify discovered vulnerabilities from aggregated statistics"""
        vulnerabilities = []

        # Analyze attack patterns
        if stats.attacks_detected:
            for attack, count in stats.attacks_detected.most_common(3):
                if count >= 2:  # Attack worked multiple times
                    vulnerabilities.append(
                        f"Vulnerable to {attack} attacks (confirmed {count} times)"
                    )

        # Analyze strategy success patterns
        if stats.strategy_success_rate > 0.5:
            vulnerabilities.append(
                "Multiple bypass strategies effective - DPI has exploitable weaknesses"
            )

        return vulnerabilities

    def end_collection_session(self) -> DiscoveryReport:
        """
        End the current collection session and generate final report.

        Returns:
            Final DiscoveryReport for the session
        """
        report = self.generate_report()

        # Reset session state
        self.current_session_id = None
        self.session_start_time = None

        # Reset domain filter to normal mode
        self.domain_filter.clear_rules()

        LOG.info(f"Ended collection session for {report.target_domain}")

        return report

    def get_collection_stats(self) -> CollectionStats:
        """
        Get current collection statistics.

        Returns:
            Current CollectionStats object
        """
        return self.collection_stats

    def clear_collected_results(self) -> None:
        """Clear all collected results and reset statistics"""
        self.collected_results.clear()
        self.collection_stats = CollectionStats()
        LOG.info("Cleared all collected results")

    def export_results(self, filename: Optional[str] = None) -> str:
        """
        Export collected results to JSON file.

        Args:
            filename: Optional filename (auto-generated if not provided)

        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_domain = self.domain_filter.get_current_target() or "unknown"
            domain_safe = target_domain.replace(".", "_")
            filename = f"discovery_results_{domain_safe}_{timestamp}.json"

        export_data = {
            "session_id": self.current_session_id,
            "target_domain": self.domain_filter.get_current_target(),
            "collection_stats": asdict(self.collection_stats),
            "aggregated_stats": asdict(self.aggregate_statistics()),
            "results": self.collected_results,
            "export_time": datetime.now().isoformat(),
        }

        # Convert sets to lists for JSON serialization
        def convert_sets(obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: convert_sets(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets(item) for item in obj]
            else:
                return obj

        export_data = convert_sets(export_data)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

        LOG.info(f"Exported results to: {filename}")
        return filename


# Example usage and testing
if __name__ == "__main__":
    from core.domain_filter import DomainFilter

    # Create results collector with domain filter
    domain_filter = DomainFilter()
    collector = ResultsCollector(domain_filter)

    # Start collection session
    collector.start_collection_session("test_session_001", "example.com")

    # Simulate collecting some results
    test_results = [
        {
            "domain": "example.com",
            "strategy_name": "split_fake",
            "verdict": "success",
            "response_time_ms": 150,
        },
        {
            "domain": "other.com",  # This should be filtered out
            "strategy_name": "disorder",
            "verdict": "success",
            "response_time_ms": 200,
        },
        {
            "domain": "example.com",
            "strategy_name": "multisplit",
            "verdict": "fail",
            "response_time_ms": 5000,
        },
    ]

    # Collect results
    for result in test_results:
        collected = collector.collect_result(result, ResultType.STRATEGY_TEST)
        print(f"Result for {result['domain']}: {'collected' if collected else 'filtered'}")

    # Generate report
    report = collector.generate_report()
    print(f"\nGenerated report for {report.target_domain}:")
    print(f"  Duration: {report.duration_seconds:.1f}s")
    print(f"  Results collected: {len(report.filtered_results)}")
    print(f"  Success rate: {report.aggregated_stats.success_rate:.1%}")
    print(f"  Collection stats: {report.collection_stats.target_rate:.1%} target domain rate")

    # End session
    final_report = collector.end_collection_session()
    print(f"\nSession ended. Final report generated.")
