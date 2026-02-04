"""
Attack effectiveness monitoring and management.

Handles attack-level monitoring, alternative recommendations, and ranking updates.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict, deque

from core.bypass.attacks.base import AttackResult, AttackStatus
from .models import AttackEffectivenessReport
from .metrics_calculator import (
    calculate_attack_effectiveness_trend,
    calculate_attack_confidence,
)


class AttackManager:
    """
    Manages attack effectiveness monitoring, recommendations, and rankings.

    Responsibilities:
    - Monitor individual attack effectiveness from AttackResult data
    - Recommend alternative attacks when current ones fail
    - Update and maintain attack effectiveness rankings
    - Process attack test queue for continuous improvement
    """

    def __init__(self, attack_adapter, attack_registry, logger=None):
        """
        Initialize AttackManager.

        Args:
            attack_adapter: AttackAdapter instance for attack operations
            attack_registry: AttackRegistry instance for attack metadata
            logger: Optional logger instance
        """
        self.attack_adapter = attack_adapter
        self.attack_registry = attack_registry
        self.logger = logger or logging.getLogger("AttackManager")

        # Attack-level effectiveness tracking
        self.attack_effectiveness_history = defaultdict(lambda: deque(maxlen=100))
        self.attack_performance = defaultdict(dict)
        self.domain_attacks = defaultdict(list)  # domain -> list of effective attacks
        self.attack_rankings = defaultdict(dict)  # category -> {attack_name: ranking_score}

        # Attack discovery and alternatives
        self.attack_alternatives = defaultdict(list)  # failing_attack -> list of alternatives
        self.attack_test_queue = deque()

        # Statistics
        self.stats = {
            "attacks_monitored": 0,
            "attack_reports_generated": 0,
            "attacks_discovered": 0,
        }

        # Initialize rankings from registry
        self._initialize_attack_rankings()

    def monitor_attack_effectiveness(
        self, attack_results: List[AttackResult], domain: Optional[str] = None
    ) -> List[AttackEffectivenessReport]:
        """
        Monitor effectiveness of individual attacks using AttackResult data.

        Args:
            attack_results: List of AttackResult objects from recent executions
            domain: Optional domain to monitor for

        Returns:
            List of AttackEffectivenessReport objects with current effectiveness data
        """
        try:
            self.logger.debug(f"Monitoring attack effectiveness for {len(attack_results)} results")

            reports = []
            attack_stats = defaultdict(
                lambda: {
                    "total_attempts": 0,
                    "successful_attempts": 0,
                    "failed_attempts": 0,
                    "total_latency": 0.0,
                    "last_success": None,
                    "last_failure": None,
                    "category": "unknown",
                    "protocol": "tcp",
                }
            )

            # Process attack results
            for result in attack_results:
                attack_name = result.technique_used or "unknown"
                stats = attack_stats[attack_name]

                stats["total_attempts"] += 1
                stats["total_latency"] += result.latency_ms

                if result.status == AttackStatus.SUCCESS:
                    stats["successful_attempts"] += 1
                    stats["last_success"] = datetime.now()
                else:
                    stats["failed_attempts"] += 1
                    stats["last_failure"] = datetime.now()

                # Get attack info from registry
                attack_info = self.attack_adapter.get_attack_info(attack_name)
                if attack_info:
                    stats["category"] = attack_info.get("category", "unknown")
                    stats["protocol"] = attack_info.get("supported_protocols", ["tcp"])[0]

            # Create effectiveness reports
            for attack_name, stats in attack_stats.items():
                success_rate = 0.0
                if stats["total_attempts"] > 0:
                    success_rate = stats["successful_attempts"] / stats["total_attempts"]

                avg_latency = 0.0
                if stats["total_attempts"] > 0:
                    avg_latency = stats["total_latency"] / stats["total_attempts"]

                # Calculate trend from historical data
                history_key = f"{attack_name}_{domain}" if domain else attack_name
                effectiveness_data = self.attack_effectiveness_history[history_key]

                # Add current measurement
                current_measurement = {
                    "timestamp": datetime.now(),
                    "success_rate": success_rate,
                    "total_attempts": stats["total_attempts"],
                    "successful_attempts": stats["successful_attempts"],
                }
                effectiveness_data.append(current_measurement)

                # Calculate trend and confidence
                trend = calculate_attack_effectiveness_trend(effectiveness_data)
                confidence = calculate_attack_confidence(effectiveness_data)

                # Create report
                report = AttackEffectivenessReport(
                    attack_name=attack_name,
                    domain=domain or "all",
                    success_rate=success_rate,
                    avg_latency_ms=avg_latency,
                    total_attempts=stats["total_attempts"],
                    successful_attempts=stats["successful_attempts"],
                    failed_attempts=stats["failed_attempts"],
                    last_success=stats["last_success"],
                    last_failure=stats["last_failure"],
                    trend=trend,
                    confidence=confidence,
                    category=stats["category"],
                    protocol=stats["protocol"],
                )

                reports.append(report)

                # Update attack performance tracking
                self.attack_performance[domain or "all"][attack_name] = {
                    "success_rate": success_rate,
                    "avg_latency_ms": avg_latency,
                    "trend": trend,
                    "last_updated": datetime.now(),
                    "category": stats["category"],
                }

            self.stats["attack_reports_generated"] += len(reports)
            self.logger.info(f"Generated {len(reports)} attack effectiveness reports")
            return reports

        except Exception as e:
            self.logger.error(f"Error monitoring attack effectiveness: {e}")
            self.logger.exception("Detailed attack effectiveness monitoring error:")
            return []

    def recommend_attack_alternatives(
        self, failing_attacks: List[str], domain: Optional[str] = None
    ) -> List[str]:
        """
        Recommend alternative attacks when current ones fail.

        Args:
            failing_attacks: List of attack names that are failing
            domain: Optional domain context for recommendations

        Returns:
            List of recommended alternative attack names
        """
        try:
            self.logger.info(
                f"Recommending alternatives for {len(failing_attacks)} failing attacks"
            )

            recommendations = []

            for failing_attack in failing_attacks:
                # Get attack info to determine category
                attack_info = self.attack_adapter.get_attack_info(failing_attack)
                if not attack_info:
                    self.logger.warning(f"No info found for failing attack: {failing_attack}")
                    continue

                category = attack_info.get("category", "unknown")

                # Get all attacks in the same category
                category_attacks = self.attack_adapter.get_available_attacks(category=category)

                # Filter out the failing attack
                alternative_attacks = [a for a in category_attacks if a != failing_attack]

                # Sort by effectiveness ranking for this domain
                domain_key = domain or "all"
                if domain_key in self.attack_performance:
                    # Sort by success rate from performance data
                    alternative_attacks.sort(
                        key=lambda a: self.attack_performance[domain_key]
                        .get(a, {})
                        .get("success_rate", 0.0),
                        reverse=True,
                    )
                else:
                    # Sort by global ranking
                    alternative_attacks.sort(
                        key=lambda a: self.attack_rankings[category].get(a, 0.0),
                        reverse=True,
                    )

                # Take top 3 alternatives per failing attack
                top_alternatives = alternative_attacks[:3]
                recommendations.extend(top_alternatives)

                # Store alternatives for future reference
                self.attack_alternatives[failing_attack] = top_alternatives

                self.logger.debug(
                    f"Recommended alternatives for {failing_attack}: {top_alternatives}"
                )

            # Remove duplicates while preserving order
            unique_recommendations = []
            seen = set()
            for attack in recommendations:
                if attack not in seen:
                    unique_recommendations.append(attack)
                    seen.add(attack)

            self.logger.info(f"Recommended {len(unique_recommendations)} alternative attacks")
            return unique_recommendations

        except Exception as e:
            self.logger.error(f"Error recommending attack alternatives: {e}")
            self.logger.exception("Detailed attack recommendation error:")
            return []

    def update_attack_rankings(self, effectiveness_data: Dict[str, Dict[str, float]]):
        """
        Update attack effectiveness rankings based on collected data.

        Args:
            effectiveness_data: Dictionary of domain -> {attack_name: effectiveness_score}
        """
        try:
            self.logger.info(f"Updating attack rankings for {len(effectiveness_data)} domains")

            # Aggregate effectiveness scores by category
            category_scores = defaultdict(lambda: defaultdict(list))

            for domain, attack_scores in effectiveness_data.items():
                for attack_name, score in attack_scores.items():
                    # Get attack category
                    attack_info = self.attack_adapter.get_attack_info(attack_name)
                    if attack_info:
                        category = attack_info.get("category", "unknown")
                        category_scores[category][attack_name].append(score)

            # Calculate average scores and update rankings
            for category, attack_scores in category_scores.items():
                for attack_name, scores in attack_scores.items():
                    if scores:
                        avg_score = sum(scores) / len(scores)
                        self.attack_rankings[category][attack_name] = avg_score

            # Sort rankings within each category
            for category in self.attack_rankings:
                sorted_attacks = sorted(
                    self.attack_rankings[category].items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
                self.attack_rankings[category] = dict(sorted_attacks)

            self.logger.info("Attack rankings updated successfully")

        except Exception as e:
            self.logger.error(f"Error updating attack rankings: {e}")
            self.logger.exception("Detailed attack ranking update error:")

    def monitor_all_attacks(self) -> int:
        """
        Monitor effectiveness of all known attacks.

        Returns:
            Number of attacks monitored
        """
        try:
            # Get recent attack results from adapter statistics
            adapter_stats = self.attack_adapter.get_execution_stats()

            # Simulate attack results for monitoring (in real implementation,
            # this would collect actual AttackResult objects from recent executions)
            if adapter_stats.get("total_executions", 0) > 0:
                # Create mock attack results based on adapter stats
                mock_results = []

                # Get all available attacks
                all_attacks = self.attack_adapter.get_available_attacks()

                for attack_name in all_attacks[:5]:  # Monitor top 5 attacks
                    # Create mock result based on general success rate
                    success_rate = adapter_stats.get("success_rate", 0.5)
                    status = AttackStatus.SUCCESS if success_rate > 0.5 else AttackStatus.ERROR

                    mock_result = AttackResult(
                        status=status,
                        latency_ms=adapter_stats.get("average_execution_time", 50.0),
                        technique_used=attack_name,
                    )
                    mock_results.append(mock_result)

                # Monitor effectiveness
                reports = self.monitor_attack_effectiveness(mock_results)

                # Update statistics
                self.stats["attacks_monitored"] = len(reports)

                # Check for failing attacks
                failing_attacks = [
                    report.attack_name
                    for report in reports
                    if report.success_rate < 0.3 and report.total_attempts > 5
                ]

                if failing_attacks:
                    self.logger.warning(
                        f"Detected {len(failing_attacks)} failing attacks: {failing_attacks}"
                    )

                    # Get alternatives
                    alternatives = self.recommend_attack_alternatives(failing_attacks)
                    if alternatives:
                        self.logger.info(f"Recommended {len(alternatives)} alternative attacks")

                        # Add to test queue
                        for attack in alternatives:
                            if attack not in [item["attack"] for item in self.attack_test_queue]:
                                self.attack_test_queue.append(
                                    {
                                        "attack": attack,
                                        "reason": "alternative_recommendation",
                                        "priority": "medium",
                                    }
                                )

                return len(reports)

        except Exception as e:
            self.logger.error(f"Error monitoring all attacks: {e}")
            return 0

    def process_attack_test_queue(self) -> int:
        """
        Process queued attacks for testing.

        Returns:
            Number of attacks processed
        """
        try:
            if not self.attack_test_queue:
                return 0

            processed_count = 0

            # Process up to 2 attacks per cycle to avoid overload
            for _ in range(min(2, len(self.attack_test_queue))):
                if not self.attack_test_queue:
                    break

                item = self.attack_test_queue.popleft()
                attack_name = item["attack"]

                self.logger.debug(f"Processing attack test queue item: {attack_name}")

                # Test attack effectiveness (simplified simulation)
                attack_info = self.attack_adapter.get_attack_info(attack_name)
                if attack_info:
                    try:
                        # This would be actual testing in real implementation
                        # For now, simulate based on attack category
                        category = attack_info.get("category", "unknown")
                        simulated_success_rate = {
                            "tcp": 0.7,
                            "ip": 0.6,
                            "tls": 0.8,
                            "http": 0.75,
                            "payload": 0.65,
                            "tunneling": 0.55,
                            "combo": 0.85,
                        }.get(category, 0.5)

                        # Update rankings based on test
                        self.attack_rankings[category][attack_name] = simulated_success_rate

                        self.logger.info(
                            f"Tested attack {attack_name}: {simulated_success_rate:.2%} effectiveness"
                        )

                        processed_count += 1

                    except Exception as e:
                        self.logger.error(f"Error testing attack {attack_name}: {e}")

            return processed_count

        except Exception as e:
            self.logger.error(f"Error processing attack test queue: {e}")
            return 0

    def get_attack_stats(self) -> Dict:
        """
        Get attack management statistics.

        Returns:
            Dictionary with attack statistics
        """
        stats = self.stats.copy()

        # Add runtime statistics
        stats["attack_effectiveness_history_size"] = sum(
            len(history) for history in self.attack_effectiveness_history.values()
        )
        stats["attack_rankings_count"] = sum(
            len(rankings) for rankings in self.attack_rankings.values()
        )
        stats["categories_tracked"] = len(self.attack_rankings)
        stats["attack_test_queue_size"] = len(self.attack_test_queue)

        # Add attack performance summary
        if self.attack_performance:
            attack_success_rates = []
            category_stats = defaultdict(list)

            for domain_attacks in self.attack_performance.values():
                for attack_name, attack_data in domain_attacks.items():
                    if "success_rate" in attack_data:
                        success_rate = attack_data["success_rate"]
                        attack_success_rates.append(success_rate)

                        category = attack_data.get("category", "unknown")
                        category_stats[category].append(success_rate)

            if attack_success_rates:
                stats["avg_attack_success_rate"] = sum(attack_success_rates) / len(
                    attack_success_rates
                )

            # Add category-specific statistics
            stats["category_performance"] = {}
            for category, rates in category_stats.items():
                if rates:
                    stats["category_performance"][category] = {
                        "avg_success_rate": sum(rates) / len(rates),
                        "attack_count": len(rates),
                        "best_success_rate": max(rates),
                        "worst_success_rate": min(rates),
                    }

        return stats

    def _initialize_attack_rankings(self):
        """Initialize attack rankings from registry."""
        try:
            # Try to get all attacks from registry
            if hasattr(self.attack_registry, "get_all_attacks"):
                all_attacks = self.attack_registry.get_all_attacks()
            elif hasattr(self.attack_registry, "_attacks"):
                all_attacks = self.attack_registry._attacks
            else:
                self.logger.warning("Could not access attack registry data")
                return

            categories_found = set()
            for attack_name, attack_data in all_attacks.items():
                # Get category from attack metadata
                if isinstance(attack_data, dict):
                    category = attack_data.get("category", "unknown")
                else:
                    category = getattr(attack_data, "category", "unknown")

                categories_found.add(category)

                # Initialize with equal rankings
                self.attack_rankings[category][attack_name] = 0.5  # Neutral starting score

            self.logger.info(f"Initialized attack rankings for {len(categories_found)} categories")

        except Exception as e:
            self.logger.error(f"Error initializing attack rankings: {e}")
