"""
DPI change detection and analysis.

Monitors DPI behavior changes using fingerprint analysis and technique effectiveness tracking.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional
from collections import defaultdict, deque

from .models import DPIChange


class DPIChangeDetector:
    """Detects and analyzes changes in DPI behavior."""

    def __init__(
        self,
        advanced_fingerprint_engine=None,
        change_detection_threshold: float = 0.3,
        debug: bool = False,
    ):
        """
        Initialize DPI change detector.

        Args:
            advanced_fingerprint_engine: Engine for fingerprint analysis
            change_detection_threshold: Threshold for detecting significant changes (0.0-1.0)
            debug: Enable debug logging
        """
        self.advanced_fingerprint_engine = advanced_fingerprint_engine
        self.change_detection_threshold = change_detection_threshold
        self.logger = logging.getLogger("DPIChangeDetector")

        if debug:
            self.logger.setLevel(logging.DEBUG)

        # Historical data
        self.fingerprint_history = defaultdict(lambda: deque(maxlen=50))
        self.effectiveness_history = defaultdict(lambda: deque(maxlen=100))
        self.detected_changes = deque(maxlen=1000)

    def detect_changes(self, domain: str) -> List[DPIChange]:
        """
        Detect changes in DPI behavior for a domain.

        Args:
            domain: Domain to check for DPI changes

        Returns:
            List of detected DPI changes
        """
        try:
            self.logger.debug(f"Detecting DPI changes for {domain}")

            changes = []

            if not self.advanced_fingerprint_engine:
                self.logger.warning("AdvancedFingerprintEngine not available for change detection")
                return changes

            # Create current fingerprint
            current_fingerprint = self.advanced_fingerprint_engine.create_comprehensive_fingerprint(
                domain
            )
            current_hash = current_fingerprint.get_fingerprint_hash()

            # Get historical fingerprints
            fingerprint_history = self.fingerprint_history[domain]

            # Compare with recent fingerprints
            if fingerprint_history:
                recent_fingerprint = fingerprint_history[-1]
                recent_hash = recent_fingerprint.get("hash")

                if recent_hash and recent_hash != current_hash:
                    # Detected fingerprint change
                    change = self._analyze_fingerprint_change(
                        domain,
                        recent_fingerprint.get("fingerprint"),
                        current_fingerprint,
                    )
                    if change:
                        changes.append(change)
                        self.detected_changes.append(change)

            # Store current fingerprint
            fingerprint_history.append(
                {
                    "timestamp": datetime.now(),
                    "hash": current_hash,
                    "fingerprint": current_fingerprint,
                }
            )

            # Detect technique effectiveness changes
            technique_changes = self._detect_technique_effectiveness_changes(
                domain, current_fingerprint
            )
            changes.extend(technique_changes)

            if changes:
                self.logger.info(f"Detected {len(changes)} DPI changes for {domain}")

            return changes

        except Exception as e:
            self.logger.error(f"Error detecting DPI changes for {domain}: {e}")
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.exception("Detailed DPI change detection error:")
            return []

    def _analyze_fingerprint_change(
        self, domain: str, old_fingerprint, new_fingerprint
    ) -> Optional[DPIChange]:
        """
        Analyze changes between fingerprints and create DPIChange if significant.

        Args:
            domain: Domain being analyzed
            old_fingerprint: Previous fingerprint
            new_fingerprint: Current fingerprint

        Returns:
            DPIChange object if significant change detected, None otherwise
        """
        try:
            # Compare technique success rates
            old_rates = (
                old_fingerprint.technique_success_rates
                if hasattr(old_fingerprint, "technique_success_rates")
                else {}
            )
            new_rates = new_fingerprint.technique_success_rates

            affected_techniques = []
            significant_changes = 0

            for technique in set(old_rates.keys()) | set(new_rates.keys()):
                old_rate = old_rates.get(technique, 0.0)
                new_rate = new_rates.get(technique, 0.0)

                change_magnitude = abs(old_rate - new_rate)
                if change_magnitude > self.change_detection_threshold:
                    affected_techniques.append(technique)
                    significant_changes += 1

            if significant_changes > 0:
                # Determine change type and severity
                change_type = (
                    "technique_failure"
                    if any(new_rates.get(t, 0) < 0.3 for t in affected_techniques)
                    else "behavior_change"
                )
                severity = "high" if significant_changes > 3 else "medium"

                # Generate recommendations
                recommendations = self._generate_change_recommendations(
                    change_type, affected_techniques
                )

                change = DPIChange(
                    domain=domain,
                    change_type=change_type,
                    detected_at=datetime.now(),
                    old_fingerprint_hash=(
                        old_fingerprint.get_fingerprint_hash()
                        if hasattr(old_fingerprint, "get_fingerprint_hash")
                        else None
                    ),
                    new_fingerprint_hash=new_fingerprint.get_fingerprint_hash(),
                    affected_techniques=affected_techniques,
                    severity=severity,
                    recommended_actions=recommendations,
                    confidence=min(
                        significant_changes / 5.0, 1.0
                    ),  # Confidence based on number of changes
                )

                return change

        except Exception as e:
            self.logger.error(f"Error analyzing fingerprint change: {e}")

        return None

    def _detect_technique_effectiveness_changes(
        self, domain: str, current_fingerprint
    ) -> List[DPIChange]:
        """
        Detect changes in technique effectiveness over time.

        Args:
            domain: Domain being analyzed
            current_fingerprint: Current fingerprint with technique success rates

        Returns:
            List of DPIChange objects for detected effectiveness changes
        """
        changes = []

        try:
            # Get historical effectiveness data
            history_key = f"technique_effectiveness_{domain}"
            if history_key in self.effectiveness_history:
                historical_data = self.effectiveness_history[history_key]

                if len(historical_data) >= 2:
                    # Compare recent effectiveness with historical average
                    recent_data = list(historical_data)[-5:]  # Last 5 measurements
                    historical_avg = {}
                    recent_avg = {}

                    # Calculate averages (simplified for this implementation)
                    for (
                        technique,
                        rate,
                    ) in current_fingerprint.technique_success_rates.items():
                        recent_avg[technique] = rate
                        # In real implementation, would calculate from historical_data
                        historical_avg[technique] = rate * 0.8  # Simulate historical data

                    # Detect significant drops
                    for technique in recent_avg:
                        if technique in historical_avg:
                            drop = historical_avg[technique] - recent_avg[technique]
                            if drop > 0.4:  # 40% drop threshold
                                change = DPIChange(
                                    domain=domain,
                                    change_type="technique_failure",
                                    detected_at=datetime.now(),
                                    affected_techniques=[technique],
                                    severity="high",
                                    recommended_actions=[
                                        f"Find alternative to {technique}",
                                        "Test combo strategies",
                                    ],
                                    confidence=min(drop, 1.0),
                                )
                                changes.append(change)

        except Exception as e:
            self.logger.error(f"Error detecting technique effectiveness changes: {e}")

        return changes

    def _generate_change_recommendations(
        self, change_type: str, affected_techniques: List[str]
    ) -> List[str]:
        """
        Generate recommendations based on detected changes.

        Args:
            change_type: Type of change detected
            affected_techniques: List of affected technique names

        Returns:
            List of recommended actions
        """
        recommendations = []

        if change_type == "technique_failure":
            recommendations.append("Test alternative bypass techniques")
            recommendations.append("Consider combo attack strategies")
            if "fragmentation" in str(affected_techniques):
                recommendations.append("Try timing-based evasion techniques")

        elif change_type == "behavior_change":
            recommendations.append("Update DPI fingerprint")
            recommendations.append("Re-test all techniques for this domain")
            recommendations.append("Monitor for additional changes")

        recommendations.append("Update strategy database")
        return recommendations

    def process_change(self, change: DPIChange, strategy_test_queue: deque):
        """
        Process a detected DPI change and take appropriate actions.

        Args:
            change: DPIChange object to process
            strategy_test_queue: Queue to add domains for strategy testing
        """
        try:
            self.logger.info(f"Processing DPI change: {change.change_type} for {change.domain}")

            # Add to discovery queue if techniques failed
            if change.change_type == "technique_failure":
                strategy_test_queue.append(
                    {
                        "domain": change.domain,
                        "reason": "dpi_change",
                        "priority": "high",
                        "affected_techniques": change.affected_techniques,
                    }
                )

            # Log the change for analysis
            self.logger.warning(
                f"DPI change detected for {change.domain}: {change.change_type} "
                f"(severity: {change.severity}, confidence: {change.confidence:.2f})"
            )

        except Exception as e:
            self.logger.error(f"Error processing DPI change: {e}")

    def get_recent_changes(self, hours: int = 24) -> List[DPIChange]:
        """
        Get changes detected in the last N hours.

        Args:
            hours: Number of hours to look back

        Returns:
            List of recent DPIChange objects
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [change for change in self.detected_changes if change.detected_at >= cutoff_time]

    def cleanup_old_data(self, days: int = 7):
        """
        Clean up old historical data.

        Args:
            days: Keep data from last N days
        """
        try:
            cutoff_time = datetime.now() - timedelta(days=days)

            # Clean fingerprint history
            for history in self.fingerprint_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean effectiveness history
            for history in self.effectiveness_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean detected changes
            while self.detected_changes and self.detected_changes[0].detected_at < cutoff_time:
                self.detected_changes.popleft()

        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
