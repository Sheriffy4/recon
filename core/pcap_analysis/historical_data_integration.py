"""
Historical Data Integration - Task 11 & 19 Implementation
Data sharing with recon_summary.json for historical context and learning.

This module provides:
1. Seamless data sharing with recon_summary.json
2. Historical context analysis for PCAP comparisons
3. Strategy effectiveness tracking over time
4. Learning from historical patterns and failures
5. Integration with learning engine and predictive analysis
"""

import os
import json
import logging
from typing import Dict, Any, List
from datetime import datetime
from collections import defaultdict, Counter
import statistics

from .learning_engine import LearningEngine
from .predictive_analyzer import PredictiveAnalyzer

LOG = logging.getLogger(__name__)


class HistoricalDataIntegration:
    """
    Integration layer for historical data sharing with recon_summary.json.

    This class provides:
    1. Historical data loading and analysis
    2. Strategy effectiveness tracking
    3. Pattern recognition from historical failures
    4. Predictive analysis based on historical trends
    """

    def __init__(
        self,
        recon_summary_file: str = "recon_summary.json",
        backup_history_days: int = 30,
        enable_learning: bool = True,
    ):

        self.recon_summary_file = recon_summary_file
        self.backup_history_days = backup_history_days
        self.enable_learning = enable_learning

        # Historical data cache
        self.historical_data = {}
        self.effectiveness_trends = {}
        self.failure_patterns = {}
        self.success_patterns = {}

        # Learning components (Task 19)
        if self.enable_learning:
            self.learning_engine = LearningEngine()
            self.predictive_analyzer = PredictiveAnalyzer(self.learning_engine)
        else:
            self.learning_engine = None
            self.predictive_analyzer = None

        # Load historical data
        self._load_historical_data()

        LOG.info(
            f"Historical Data Integration initialized with {len(self.historical_data.get('all_results', []))} historical records"
        )

    def _load_historical_data(self):
        """Load and parse historical data from recon_summary.json"""

        self.historical_data = {
            "all_results": [],
            "strategy_effectiveness": {},
            "fingerprints": {},
            "key_metrics": {},
            "metadata": {},
            "integration_analysis": [],
        }

        try:
            if os.path.exists(self.recon_summary_file):
                with open(self.recon_summary_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Load main sections
                self.historical_data["all_results"] = data.get("all_results", [])
                self.historical_data["strategy_effectiveness"] = data.get(
                    "strategy_effectiveness", {}
                )
                self.historical_data["fingerprints"] = data.get("fingerprints", {})
                self.historical_data["key_metrics"] = data.get("key_metrics", {})
                self.historical_data["metadata"] = data.get("metadata", {})
                self.historical_data["integration_analysis"] = data.get(
                    "integration_analysis", []
                )

                # Analyze historical patterns
                self._analyze_effectiveness_trends()
                self._analyze_failure_patterns()
                self._analyze_success_patterns()

                LOG.info("Historical data loaded and analyzed successfully")
            else:
                LOG.warning(
                    f"Historical data file not found: {self.recon_summary_file}"
                )

        except Exception as e:
            LOG.error(f"Failed to load historical data: {e}")

    def _analyze_effectiveness_trends(self):
        """Analyze strategy effectiveness trends over time"""

        self.effectiveness_trends = {
            "strategy_performance": {},
            "temporal_patterns": {},
            "domain_patterns": {},
            "parameter_effectiveness": {},
        }

        try:
            all_results = self.historical_data.get("all_results", [])

            # Group results by strategy
            strategy_results = defaultdict(list)

            for result in all_results:
                strategy = result.get("strategy", "")
                if strategy:
                    strategy_results[strategy].append(result)

            # Analyze each strategy's performance
            for strategy, results in strategy_results.items():
                success_rates = [r.get("success_rate", 0.0) for r in results]

                if success_rates:
                    self.effectiveness_trends["strategy_performance"][strategy] = {
                        "average_success_rate": statistics.mean(success_rates),
                        "max_success_rate": max(success_rates),
                        "min_success_rate": min(success_rates),
                        "std_deviation": (
                            statistics.stdev(success_rates)
                            if len(success_rates) > 1
                            else 0.0
                        ),
                        "total_attempts": len(results),
                        "successful_attempts": len(
                            [r for r in results if r.get("success_rate", 0.0) > 0]
                        ),
                    }

            # Analyze parameter effectiveness
            self._analyze_parameter_effectiveness(all_results)

        except Exception as e:
            LOG.error(f"Failed to analyze effectiveness trends: {e}")

    def _analyze_parameter_effectiveness(self, all_results: List[Dict[str, Any]]):
        """Analyze effectiveness of specific strategy parameters"""

        parameter_analysis = {
            "ttl_effectiveness": defaultdict(list),
            "split_pos_effectiveness": defaultdict(list),
            "fooling_effectiveness": defaultdict(list),
            "strategy_type_effectiveness": defaultdict(list),
        }

        for result in all_results:
            strategy = result.get("strategy", "")
            success_rate = result.get("success_rate", 0.0)

            # Extract TTL values
            if "ttl=" in strategy:
                try:
                    ttl_part = strategy.split("ttl=")[1].split()[0].rstrip(",)")
                    ttl_value = int(ttl_part)
                    parameter_analysis["ttl_effectiveness"][ttl_value].append(
                        success_rate
                    )
                except:
                    pass

            # Extract split positions
            if "split-pos=" in strategy:
                try:
                    pos_part = strategy.split("split-pos=")[1].split()[0].rstrip(",)")
                    split_pos = int(pos_part)
                    parameter_analysis["split_pos_effectiveness"][split_pos].append(
                        success_rate
                    )
                except:
                    pass

            # Extract fooling methods
            if "fooling=" in strategy:
                try:
                    fooling_part = strategy.split("fooling=")[1].split()[0].rstrip(",)")
                    fooling_methods = (
                        fooling_part.strip("[]").replace("'", "").split(",")
                    )
                    for method in fooling_methods:
                        method = method.strip()
                        if method:
                            parameter_analysis["fooling_effectiveness"][method].append(
                                success_rate
                            )
                except:
                    pass

            # Extract strategy types
            if "fake" in strategy.lower():
                if "disorder" in strategy.lower():
                    parameter_analysis["strategy_type_effectiveness"][
                        "fake_disorder"
                    ].append(success_rate)
                else:
                    parameter_analysis["strategy_type_effectiveness"]["fake"].append(
                        success_rate
                    )
            elif "split" in strategy.lower():
                parameter_analysis["strategy_type_effectiveness"]["split"].append(
                    success_rate
                )

        # Calculate effectiveness statistics for each parameter
        for param_type, param_data in parameter_analysis.items():
            self.effectiveness_trends["parameter_effectiveness"][param_type] = {}

            for param_value, success_rates in param_data.items():
                if success_rates:
                    self.effectiveness_trends["parameter_effectiveness"][param_type][
                        param_value
                    ] = {
                        "average_success_rate": statistics.mean(success_rates),
                        "max_success_rate": max(success_rates),
                        "attempts": len(success_rates),
                        "successful_attempts": len([r for r in success_rates if r > 0]),
                    }

    def _analyze_failure_patterns(self):
        """Analyze patterns in failed strategies"""

        self.failure_patterns = {
            "common_failure_strategies": [],
            "failure_telemetry_patterns": {},
            "failure_parameter_patterns": {},
            "failure_timing_patterns": {},
        }

        try:
            all_results = self.historical_data.get("all_results", [])
            failed_results = [
                r for r in all_results if r.get("success_rate", 0.0) == 0.0
            ]

            # Analyze common failure strategies
            failed_strategies = [r.get("strategy", "") for r in failed_results]
            strategy_failures = Counter(failed_strategies)

            self.failure_patterns["common_failure_strategies"] = [
                {"strategy": strategy, "failure_count": count}
                for strategy, count in strategy_failures.most_common(10)
            ]

            # Analyze failure telemetry patterns
            telemetry_patterns = defaultdict(list)

            for result in failed_results:
                telemetry = result.get("engine_telemetry", {})

                for metric, value in telemetry.items():
                    if isinstance(value, (int, float)):
                        telemetry_patterns[metric].append(value)

            for metric, values in telemetry_patterns.items():
                if values:
                    self.failure_patterns["failure_telemetry_patterns"][metric] = {
                        "average": statistics.mean(values),
                        "max": max(values),
                        "min": min(values),
                        "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0,
                    }

            # Analyze failure parameter patterns
            self._analyze_failure_parameters(failed_results)

        except Exception as e:
            LOG.error(f"Failed to analyze failure patterns: {e}")

    def _analyze_failure_parameters(self, failed_results: List[Dict[str, Any]]):
        """Analyze parameter patterns in failed strategies"""

        parameter_failures = {
            "ttl_failures": defaultdict(int),
            "split_pos_failures": defaultdict(int),
            "fooling_failures": defaultdict(int),
            "strategy_type_failures": defaultdict(int),
        }

        for result in failed_results:
            strategy = result.get("strategy", "")

            # Count TTL failures
            if "ttl=" in strategy:
                try:
                    ttl_part = strategy.split("ttl=")[1].split()[0].rstrip(",)")
                    ttl_value = int(ttl_part)
                    parameter_failures["ttl_failures"][ttl_value] += 1
                except:
                    pass

            # Count split position failures
            if "split-pos=" in strategy:
                try:
                    pos_part = strategy.split("split-pos=")[1].split()[0].rstrip(",)")
                    split_pos = int(pos_part)
                    parameter_failures["split_pos_failures"][split_pos] += 1
                except:
                    pass

            # Count fooling method failures
            if "fooling=" in strategy:
                try:
                    fooling_part = strategy.split("fooling=")[1].split()[0].rstrip(",)")
                    fooling_methods = (
                        fooling_part.strip("[]").replace("'", "").split(",")
                    )
                    for method in fooling_methods:
                        method = method.strip()
                        if method:
                            parameter_failures["fooling_failures"][method] += 1
                except:
                    pass

            # Count strategy type failures
            if "fake" in strategy.lower():
                if "disorder" in strategy.lower():
                    parameter_failures["strategy_type_failures"]["fake_disorder"] += 1
                else:
                    parameter_failures["strategy_type_failures"]["fake"] += 1
            elif "split" in strategy.lower():
                parameter_failures["strategy_type_failures"]["split"] += 1

        self.failure_patterns["failure_parameter_patterns"] = dict(parameter_failures)

    def _analyze_success_patterns(self):
        """Analyze patterns in successful strategies"""

        self.success_patterns = {
            "successful_strategies": [],
            "success_parameter_patterns": {},
            "success_telemetry_patterns": {},
            "success_factors": [],
        }

        try:
            all_results = self.historical_data.get("all_results", [])
            successful_results = [
                r for r in all_results if r.get("success_rate", 0.0) > 0.0
            ]

            if not successful_results:
                LOG.info("No successful strategies found in historical data")
                return

            # Analyze successful strategies
            successful_strategies = [
                (r.get("strategy", ""), r.get("success_rate", 0.0))
                for r in successful_results
            ]
            successful_strategies.sort(key=lambda x: x[1], reverse=True)

            self.success_patterns["successful_strategies"] = [
                {"strategy": strategy, "success_rate": rate}
                for strategy, rate in successful_strategies[:10]
            ]

            # Analyze success parameters
            self._analyze_success_parameters(successful_results)

            # Generate success factors
            self._generate_success_factors(successful_results)

        except Exception as e:
            LOG.error(f"Failed to analyze success patterns: {e}")

    def _analyze_success_parameters(self, successful_results: List[Dict[str, Any]]):
        """Analyze parameter patterns in successful strategies"""

        parameter_successes = {
            "ttl_successes": defaultdict(list),
            "split_pos_successes": defaultdict(list),
            "fooling_successes": defaultdict(list),
            "strategy_type_successes": defaultdict(list),
        }

        for result in successful_results:
            strategy = result.get("strategy", "")
            success_rate = result.get("success_rate", 0.0)

            # Analyze TTL successes
            if "ttl=" in strategy:
                try:
                    ttl_part = strategy.split("ttl=")[1].split()[0].rstrip(",)")
                    ttl_value = int(ttl_part)
                    parameter_successes["ttl_successes"][ttl_value].append(success_rate)
                except:
                    pass

            # Analyze split position successes
            if "split-pos=" in strategy:
                try:
                    pos_part = strategy.split("split-pos=")[1].split()[0].rstrip(",)")
                    split_pos = int(pos_part)
                    parameter_successes["split_pos_successes"][split_pos].append(
                        success_rate
                    )
                except:
                    pass

            # Analyze fooling method successes
            if "fooling=" in strategy:
                try:
                    fooling_part = strategy.split("fooling=")[1].split()[0].rstrip(",)")
                    fooling_methods = (
                        fooling_part.strip("[]").replace("'", "").split(",")
                    )
                    for method in fooling_methods:
                        method = method.strip()
                        if method:
                            parameter_successes["fooling_successes"][method].append(
                                success_rate
                            )
                except:
                    pass

            # Analyze strategy type successes
            if "fake" in strategy.lower():
                if "disorder" in strategy.lower():
                    parameter_successes["strategy_type_successes"][
                        "fake_disorder"
                    ].append(success_rate)
                else:
                    parameter_successes["strategy_type_successes"]["fake"].append(
                        success_rate
                    )
            elif "split" in strategy.lower():
                parameter_successes["strategy_type_successes"]["split"].append(
                    success_rate
                )

        # Calculate success statistics
        for param_type, param_data in parameter_successes.items():
            self.success_patterns["success_parameter_patterns"][param_type] = {}

            for param_value, success_rates in param_data.items():
                if success_rates:
                    self.success_patterns["success_parameter_patterns"][param_type][
                        param_value
                    ] = {
                        "average_success_rate": statistics.mean(success_rates),
                        "max_success_rate": max(success_rates),
                        "attempts": len(success_rates),
                        "total_success": sum(success_rates),
                    }

    def _generate_success_factors(self, successful_results: List[Dict[str, Any]]):
        """Generate success factors from successful strategies"""

        success_factors = []

        # Analyze most successful parameters
        success_params = self.success_patterns.get("success_parameter_patterns", {})

        # TTL success factors
        ttl_successes = success_params.get("ttl_successes", {})
        if ttl_successes:
            best_ttl = max(
                ttl_successes.items(), key=lambda x: x[1]["average_success_rate"]
            )
            success_factors.append(
                f"TTL={best_ttl[0]} shows highest success rate ({best_ttl[1]['average_success_rate']:.1%})"
            )

        # Split position success factors
        split_successes = success_params.get("split_pos_successes", {})
        if split_successes:
            best_split = max(
                split_successes.items(), key=lambda x: x[1]["average_success_rate"]
            )
            success_factors.append(
                f"split_pos={best_split[0]} shows highest success rate ({best_split[1]['average_success_rate']:.1%})"
            )

        # Fooling method success factors
        fooling_successes = success_params.get("fooling_successes", {})
        if fooling_successes:
            best_fooling = max(
                fooling_successes.items(), key=lambda x: x[1]["average_success_rate"]
            )
            success_factors.append(
                f"fooling={best_fooling[0]} shows highest success rate ({best_fooling[1]['average_success_rate']:.1%})"
            )

        # Strategy type success factors
        type_successes = success_params.get("strategy_type_successes", {})
        if type_successes:
            best_type = max(
                type_successes.items(), key=lambda x: x[1]["average_success_rate"]
            )
            success_factors.append(
                f"{best_type[0]} strategy type shows highest success rate ({best_type[1]['average_success_rate']:.1%})"
            )

        self.success_patterns["success_factors"] = success_factors

    def get_historical_context_for_pcap_analysis(
        self, pcap_analysis_results: Dict[str, Any], target_domain: str = None
    ) -> Dict[str, Any]:
        """
        Get historical context relevant to PCAP analysis results.

        Args:
            pcap_analysis_results: Results from PCAP comparison
            target_domain: Target domain for analysis

        Returns:
            Historical context and recommendations
        """

        context = {
            "relevant_historical_strategies": [],
            "parameter_recommendations": {},
            "failure_warnings": [],
            "success_predictions": {},
            "historical_insights": [],
        }

        try:
            # Find relevant historical strategies
            context["relevant_historical_strategies"] = self._find_relevant_strategies(
                pcap_analysis_results
            )

            # Generate parameter recommendations based on history
            context["parameter_recommendations"] = (
                self._generate_parameter_recommendations(pcap_analysis_results)
            )

            # Generate failure warnings
            context["failure_warnings"] = self._generate_failure_warnings(
                pcap_analysis_results
            )

            # Predict success based on historical patterns
            context["success_predictions"] = self._predict_success_from_history(
                pcap_analysis_results
            )

            # Generate historical insights
            context["historical_insights"] = self._generate_historical_insights(
                pcap_analysis_results
            )

        except Exception as e:
            LOG.error(f"Failed to get historical context: {e}")
            context["error"] = str(e)

        return context

    def _find_relevant_strategies(
        self, pcap_analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find historically relevant strategies based on PCAP analysis"""

        relevant_strategies = []

        try:
            # Extract patterns from PCAP analysis
            pcap_comparison = pcap_analysis_results.get("pcap_comparison", {})

            # Look for TTL-related issues
            ttl_issues = any(
                "ttl" in str(issue).lower()
                for issue in pcap_comparison.get("critical_issues", [])
            )

            # Look for split-related issues
            split_issues = any(
                "split" in str(issue).lower()
                for issue in pcap_comparison.get("parameter_differences", [])
            )

            # Look for fake packet issues
            fake_issues = any(
                "fake" in str(issue).lower()
                for issue in pcap_comparison.get("sequence_differences", [])
            )

            # Find strategies that address these issues
            all_results = self.historical_data.get("all_results", [])

            # Also check for direct parameter matches from PCAP analysis
            strategy_params = pcap_analysis_results.get("strategy_params", {})

            for result in all_results:
                strategy = result.get("strategy", "")
                success_rate = result.get("success_rate", 0.0)

                relevance_score = 0

                # Score based on addressing identified issues
                if ttl_issues and "ttl=" in strategy:
                    relevance_score += 0.4

                if split_issues and "split" in strategy:
                    relevance_score += 0.3

                if fake_issues and "fake" in strategy:
                    relevance_score += 0.3

                # Score based on parameter matches
                if strategy_params:
                    if (
                        "ttl" in strategy_params
                        and f"ttl={strategy_params['ttl']}" in strategy
                    ):
                        relevance_score += 0.5

                    if (
                        "split_pos" in strategy_params
                        and f"split_pos={strategy_params['split_pos']}" in strategy
                    ):
                        relevance_score += 0.4

                    if "fooling" in strategy_params:
                        fooling_methods = strategy_params["fooling"]
                        if isinstance(fooling_methods, list):
                            for method in fooling_methods:
                                if method in strategy:
                                    relevance_score += 0.2

                # Bonus for successful strategies
                if success_rate > 0:
                    relevance_score += 0.2

                # Lower threshold and always include some strategies
                if relevance_score > 0.1 or len(relevant_strategies) < 3:
                    relevant_strategies.append(
                        {
                            "strategy": strategy,
                            "success_rate": success_rate,
                            "relevance_score": relevance_score,
                            "addresses_issues": {
                                "ttl_issues": ttl_issues and "ttl=" in strategy,
                                "split_issues": split_issues and "split" in strategy,
                                "fake_issues": fake_issues and "fake" in strategy,
                            },
                        }
                    )

            # Sort by relevance and success rate
            relevant_strategies.sort(
                key=lambda x: (x["relevance_score"], x["success_rate"]), reverse=True
            )

        except Exception as e:
            LOG.error(f"Failed to find relevant strategies: {e}")

        return relevant_strategies[:10]  # Top 10 relevant strategies

    def _generate_parameter_recommendations(
        self, pcap_analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate parameter recommendations based on historical effectiveness"""

        recommendations = {
            "ttl_recommendation": {},
            "split_pos_recommendation": {},
            "fooling_recommendation": {},
            "strategy_type_recommendation": {},
        }

        try:
            success_params = self.success_patterns.get("success_parameter_patterns", {})

            # TTL recommendations
            ttl_successes = success_params.get("ttl_successes", {})
            if ttl_successes:
                best_ttl_item = max(
                    ttl_successes.items(), key=lambda x: x[1]["average_success_rate"]
                )
                recommendations["ttl_recommendation"] = {
                    "recommended_value": best_ttl_item[0],
                    "success_rate": best_ttl_item[1]["average_success_rate"],
                    "attempts": best_ttl_item[1]["attempts"],
                    "reasoning": f"TTL={best_ttl_item[0]} has highest historical success rate",
                }

            # Split position recommendations
            split_successes = success_params.get("split_pos_successes", {})
            if split_successes:
                best_split_item = max(
                    split_successes.items(), key=lambda x: x[1]["average_success_rate"]
                )
                recommendations["split_pos_recommendation"] = {
                    "recommended_value": best_split_item[0],
                    "success_rate": best_split_item[1]["average_success_rate"],
                    "attempts": best_split_item[1]["attempts"],
                    "reasoning": f"split_pos={best_split_item[0]} has highest historical success rate",
                }

            # Fooling method recommendations
            fooling_successes = success_params.get("fooling_successes", {})
            if fooling_successes:
                best_fooling_item = max(
                    fooling_successes.items(),
                    key=lambda x: x[1]["average_success_rate"],
                )
                recommendations["fooling_recommendation"] = {
                    "recommended_value": best_fooling_item[0],
                    "success_rate": best_fooling_item[1]["average_success_rate"],
                    "attempts": best_fooling_item[1]["attempts"],
                    "reasoning": f"fooling={best_fooling_item[0]} has highest historical success rate",
                }

            # Strategy type recommendations
            type_successes = success_params.get("strategy_type_successes", {})
            if type_successes:
                best_type_item = max(
                    type_successes.items(), key=lambda x: x[1]["average_success_rate"]
                )
                recommendations["strategy_type_recommendation"] = {
                    "recommended_type": best_type_item[0],
                    "success_rate": best_type_item[1]["average_success_rate"],
                    "attempts": best_type_item[1]["attempts"],
                    "reasoning": f"{best_type_item[0]} strategy type has highest historical success rate",
                }

        except Exception as e:
            LOG.error(f"Failed to generate parameter recommendations: {e}")

        return recommendations

    def _generate_failure_warnings(
        self, pcap_analysis_results: Dict[str, Any]
    ) -> List[str]:
        """Generate warnings based on historical failure patterns"""

        warnings = []

        try:
            failure_params = self.failure_patterns.get("failure_parameter_patterns", {})

            # Check for high-failure TTL values
            ttl_failures = failure_params.get("ttl_failures", {})
            for ttl_value, failure_count in ttl_failures.items():
                if failure_count > 2:  # Threshold for warning
                    warnings.append(
                        f"Warning: TTL={ttl_value} has failed {failure_count} times historically"
                    )

            # Check for high-failure split positions
            split_failures = failure_params.get("split_pos_failures", {})
            for split_pos, failure_count in split_failures.items():
                if failure_count > 2:
                    warnings.append(
                        f"Warning: split_pos={split_pos} has failed {failure_count} times historically"
                    )

            # Check for high-failure fooling methods
            fooling_failures = failure_params.get("fooling_failures", {})
            for fooling_method, failure_count in fooling_failures.items():
                if failure_count > 2:
                    warnings.append(
                        f"Warning: fooling={fooling_method} has failed {failure_count} times historically"
                    )

        except Exception as e:
            LOG.error(f"Failed to generate failure warnings: {e}")

        return warnings

    def _predict_success_from_history(
        self, pcap_analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Predict success probability based on historical patterns"""

        predictions = {
            "overall_success_probability": 0.0,
            "parameter_success_probabilities": {},
            "strategy_success_probabilities": {},
            "confidence_level": "LOW",
        }

        try:
            # Calculate overall success probability based on historical data
            all_results = self.historical_data.get("all_results", [])
            if all_results:
                successful_results = [
                    r for r in all_results if r.get("success_rate", 0.0) > 0.0
                ]

                if successful_results:
                    success_rates = [
                        r.get("success_rate", 0.0) for r in successful_results
                    ]
                    predictions["overall_success_probability"] = statistics.mean(
                        success_rates
                    )
                    predictions["confidence_level"] = (
                        "MEDIUM" if len(successful_results) > 2 else "LOW"
                    )

                    # Calculate parameter success probabilities
                    param_success = {}
                    for result in successful_results:
                        strategy = result.get("strategy", "")
                        success_rate = result.get("success_rate", 0.0)

                        # Extract TTL
                        if "ttl=" in strategy:
                            try:
                                ttl_part = (
                                    strategy.split("ttl=")[1].split()[0].rstrip(",)")
                                )
                                ttl_value = int(ttl_part)
                                if ttl_value not in param_success:
                                    param_success[ttl_value] = []
                                param_success[ttl_value].append(success_rate)
                            except:
                                pass

                    # Calculate averages
                    for param, rates in param_success.items():
                        predictions["parameter_success_probabilities"][
                            f"ttl_{param}"
                        ] = statistics.mean(rates)

                predictions["overall_success_probability"] = len(
                    successful_results
                ) / len(all_results)

            # Calculate parameter-specific success probabilities
            success_params = self.success_patterns.get("success_parameter_patterns", {})

            for param_type, param_data in success_params.items():
                predictions["parameter_success_probabilities"][param_type] = {}

                for param_value, stats in param_data.items():
                    success_prob = (
                        stats["successful_attempts"] / stats["attempts"]
                        if stats["attempts"] > 0
                        else 0.0
                    )
                    predictions["parameter_success_probabilities"][param_type][
                        param_value
                    ] = success_prob

            # Determine confidence level
            total_historical_data = len(all_results)
            if total_historical_data > 50:
                predictions["confidence_level"] = "HIGH"
            elif total_historical_data > 20:
                predictions["confidence_level"] = "MEDIUM"
            else:
                predictions["confidence_level"] = "LOW"

        except Exception as e:
            LOG.error(f"Failed to predict success from history: {e}")

        return predictions

    def learn_from_successful_fix(
        self,
        fix_data: Dict[str, Any],
        pcap_analysis: Dict[str, Any],
        validation_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Learn from a successful fix and update historical knowledge.
        Task 19: Learning from successful fixes to improve future analysis.

        Args:
            fix_data: Information about the successful fix
            pcap_analysis: Original PCAP analysis that led to the fix
            validation_results: Results of fix validation

        Returns:
            Learning results and updated predictions
        """

        learning_results = {
            "learning_successful": False,
            "patterns_learned": 0,
            "knowledge_updated": False,
            "prediction_improvements": {},
        }

        try:
            if not self.enable_learning or not self.learning_engine:
                LOG.warning("Learning is disabled or learning engine not available")
                return learning_results

            # Learn from the successful fix
            self.learning_engine.learn_from_successful_fix(
                fix_data, pcap_analysis, validation_results
            )

            # Update historical data with learning results
            self._update_historical_data_with_learning(fix_data, validation_results)

            # Get updated predictions for similar scenarios
            strategy_params = fix_data.get("strategy_parameters", {})
            if strategy_params:
                updated_prediction = (
                    self.predictive_analyzer.predict_strategy_effectiveness(
                        strategy_params
                    )
                )
                learning_results["prediction_improvements"] = updated_prediction

            learning_results["learning_successful"] = True
            learning_results["knowledge_updated"] = True

            LOG.info("Successfully learned from fix and updated historical knowledge")

        except Exception as e:
            LOG.error(f"Failed to learn from successful fix: {e}")
            learning_results["error"] = str(e)

        return learning_results

    def get_predictive_analysis(
        self, strategy_params: Dict[str, Any], target_domain: str = None
    ) -> Dict[str, Any]:
        """
        Get predictive analysis for strategy effectiveness.
        Task 19: Predictive analysis for strategy effectiveness.

        Args:
            strategy_params: Strategy parameters to analyze
            target_domain: Target domain for analysis

        Returns:
            Comprehensive predictive analysis
        """

        if not self.enable_learning or not self.predictive_analyzer:
            LOG.warning("Predictive analysis is disabled or not available")
            return {"error": "Predictive analysis not available"}

        try:
            # Get predictive analysis
            prediction = self.predictive_analyzer.predict_strategy_effectiveness(
                strategy_params, target_domain, self.historical_data
            )

            # Add historical context
            historical_context = self.get_historical_context_for_pcap_analysis(
                {"strategy_params": strategy_params}, target_domain
            )

            # Combine results
            combined_analysis = {
                "predictive_analysis": prediction,
                "historical_context": historical_context,
                "analysis_timestamp": datetime.now().isoformat(),
            }

            return combined_analysis

        except Exception as e:
            LOG.error(f"Failed to get predictive analysis: {e}")
            return {"error": str(e)}

    def get_pattern_database_insights(
        self, query: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Get insights from the pattern database.
        Task 19: Pattern database for common DPI bypass issues.

        Args:
            query: Query criteria for pattern matching

        Returns:
            Pattern database insights
        """

        if not self.enable_learning or not self.learning_engine:
            LOG.warning("Pattern database is disabled or not available")
            return {"error": "Pattern database not available"}

        try:
            # Get pattern database
            pattern_db = self.learning_engine.pattern_db

            # Get matching patterns if query provided
            if query:
                matching_patterns = pattern_db.get_matching_patterns(query)
            else:
                matching_patterns = {
                    "failure_patterns": list(
                        pattern_db.patterns["failure_patterns"].values()
                    )[:10],
                    "success_patterns": list(
                        pattern_db.patterns["success_patterns"].values()
                    )[:10],
                    "fix_patterns": list(
                        pattern_db.patterns.get("fix_patterns", {}).values()
                    )[:10],
                }

            # Get learning statistics
            learning_stats = self.learning_engine.get_learning_statistics()

            insights = {
                "matching_patterns": matching_patterns,
                "learning_statistics": learning_stats,
                "pattern_database_size": pattern_db._count_patterns(),
                "insights_timestamp": datetime.now().isoformat(),
            }

            return insights

        except Exception as e:
            LOG.error(f"Failed to get pattern database insights: {e}")
            return {"error": str(e)}

    def optimize_strategy_parameters(
        self, current_params: Dict[str, Any], target_success_rate: float = 0.8
    ) -> Dict[str, Any]:
        """
        Get parameter optimization recommendations.
        Task 19: Predictive analysis for strategy effectiveness.

        Args:
            current_params: Current strategy parameters
            target_success_rate: Desired success rate

        Returns:
            Parameter optimization recommendations
        """

        if not self.enable_learning or not self.predictive_analyzer:
            LOG.warning("Parameter optimization is disabled or not available")
            return {"error": "Parameter optimization not available"}

        try:
            optimization = self.predictive_analyzer.predict_parameter_optimization(
                current_params, target_success_rate
            )

            return optimization

        except Exception as e:
            LOG.error(f"Failed to optimize strategy parameters: {e}")
            return {"error": str(e)}

    def _update_historical_data_with_learning(
        self, fix_data: Dict[str, Any], validation_results: Dict[str, Any]
    ):
        """Update historical data with learning results"""

        try:
            # Add learning entry to historical data
            learning_entry = {
                "timestamp": datetime.now().isoformat(),
                "fix_type": fix_data.get("fix_type", "unknown"),
                "strategy_parameters": fix_data.get("strategy_parameters", {}),
                "success_rate": validation_results.get("success_rate", 0.0),
                "domains_tested": validation_results.get("domains_tested", 0),
                "learning_source": "successful_fix",
            }

            # Add to integration analysis
            if "integration_analysis" not in self.historical_data:
                self.historical_data["integration_analysis"] = []

            self.historical_data["integration_analysis"].append(learning_entry)

            # Update recon_summary.json with learning data
            self._save_learning_data_to_summary(learning_entry)

        except Exception as e:
            LOG.error(f"Failed to update historical data with learning: {e}")

    def _save_learning_data_to_summary(self, learning_entry: Dict[str, Any]):
        """Save learning data to recon_summary.json"""

        try:
            # Load current summary
            summary_data = {}
            if os.path.exists(self.recon_summary_file):
                with open(self.recon_summary_file, "r", encoding="utf-8") as f:
                    summary_data = json.load(f)

            # Add learning history section
            if "learning_history" not in summary_data:
                summary_data["learning_history"] = []

            summary_data["learning_history"].append(learning_entry)

            # Keep only recent learning entries
            if len(summary_data["learning_history"]) > 100:
                summary_data["learning_history"] = summary_data["learning_history"][
                    -100:
                ]

            # Update metadata
            if "metadata" not in summary_data:
                summary_data["metadata"] = {}

            summary_data["metadata"][
                "last_learning_update"
            ] = datetime.now().isoformat()
            summary_data["metadata"]["total_learning_entries"] = len(
                summary_data["learning_history"]
            )

            # Save updated summary
            with open(self.recon_summary_file, "w", encoding="utf-8") as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)

            LOG.debug("Learning data saved to recon_summary.json")

        except Exception as e:
            LOG.error(f"Failed to save learning data to summary: {e}")

    def export_learning_knowledge(
        self, export_file: str = "historical_learning_export.json"
    ) -> bool:
        """
        Export all learning knowledge for backup or sharing.
        Task 19: Learning from successful fixes to improve future analysis.

        Args:
            export_file: File to export knowledge to

        Returns:
            Success status
        """

        if not self.enable_learning or not self.learning_engine:
            LOG.warning("Learning export is disabled or not available")
            return False

        try:
            # Create proper file paths
            base_dir = (
                os.path.dirname(export_file) if os.path.dirname(export_file) else "."
            )
            base_name = os.path.basename(export_file)

            learning_export_file = os.path.join(base_dir, f"learning_{base_name}")
            historical_export_file = os.path.join(base_dir, f"historical_{base_name}")

            # Export learning engine knowledge
            learning_export_success = self.learning_engine.export_learned_knowledge(
                learning_export_file
            )

            # Export historical data
            historical_export = {
                "historical_data": self.historical_data,
                "effectiveness_trends": self.effectiveness_trends,
                "failure_patterns": self.failure_patterns,
                "success_patterns": self.success_patterns,
                "exported_at": datetime.now().isoformat(),
                "export_version": "1.0",
            }

            with open(historical_export_file, "w", encoding="utf-8") as f:
                json.dump(historical_export, f, indent=2, ensure_ascii=False)

            LOG.info("Historical learning knowledge exported successfully")
            return learning_export_success

        except Exception as e:
            LOG.error(f"Failed to export learning knowledge: {e}")
            return False

    def import_learning_knowledge(self, import_file: str) -> bool:
        """
        Import learning knowledge from backup or sharing.
        Task 19: Learning from successful fixes to improve future analysis.

        Args:
            import_file: File to import knowledge from

        Returns:
            Success status
        """

        if not self.enable_learning or not self.learning_engine:
            LOG.warning("Learning import is disabled or not available")
            return False

        try:
            # Create proper file paths
            base_dir = (
                os.path.dirname(import_file) if os.path.dirname(import_file) else "."
            )
            base_name = os.path.basename(import_file)

            learning_import_file = os.path.join(base_dir, f"learning_{base_name}")
            historical_import_file = os.path.join(base_dir, f"historical_{base_name}")

            # Import learning engine knowledge
            learning_import_success = self.learning_engine.import_learned_knowledge(
                learning_import_file
            )

            # Import historical data
            if os.path.exists(historical_import_file):
                with open(historical_import_file, "r", encoding="utf-8") as f:
                    imported_data = json.load(f)

                # Merge historical data
                imported_historical = imported_data.get("historical_data", {})
                for key, value in imported_historical.items():
                    if key in self.historical_data:
                        if isinstance(value, list):
                            self.historical_data[key].extend(value)
                        elif isinstance(value, dict):
                            self.historical_data[key].update(value)
                    else:
                        self.historical_data[key] = value

                # Merge patterns
                self.effectiveness_trends.update(
                    imported_data.get("effectiveness_trends", {})
                )
                self.failure_patterns.update(imported_data.get("failure_patterns", {}))
                self.success_patterns.update(imported_data.get("success_patterns", {}))

            LOG.info("Historical learning knowledge imported successfully")
            return learning_import_success

        except Exception as e:
            LOG.error(f"Failed to import learning knowledge: {e}")
            return False

    def _generate_historical_insights(
        self, pcap_analysis_results: Dict[str, Any]
    ) -> List[str]:
        """Generate insights based on historical analysis"""

        insights = []

        try:
            # Insights from success patterns
            success_factors = self.success_patterns.get("success_factors", [])
            for factor in success_factors:
                insights.append(f"Historical Success: {factor}")

            # Insights from effectiveness trends
            strategy_performance = self.effectiveness_trends.get(
                "strategy_performance", {}
            )
            if strategy_performance:
                best_strategy = max(
                    strategy_performance.items(),
                    key=lambda x: x[1]["average_success_rate"],
                )
                insights.append(
                    f"Best Historical Strategy: {best_strategy[0]} "
                    f"(avg success: {best_strategy[1]['average_success_rate']:.1%})"
                )

            # Insights from failure patterns
            common_failures = self.failure_patterns.get("common_failure_strategies", [])
            if common_failures:
                most_failed = common_failures[0]
                insights.append(
                    f"Most Failed Strategy: {most_failed['strategy']} "
                    f"({most_failed['failure_count']} failures)"
                )

            # Data quality insights
            total_results = len(self.historical_data.get("all_results", []))
            successful_results = len(
                [
                    r
                    for r in self.historical_data.get("all_results", [])
                    if r.get("success_rate", 0.0) > 0
                ]
            )

            if total_results > 0:
                success_rate = successful_results / total_results
                insights.append(
                    f"Historical Data: {total_results} total attempts, "
                    f"{success_rate:.1%} overall success rate"
                )

        except Exception as e:
            LOG.error(f"Failed to generate historical insights: {e}")

        return insights

    def update_historical_data(self, new_analysis_results: Dict[str, Any]) -> bool:
        """Update historical data with new analysis results"""

        try:
            # Load current data
            current_data = {}
            if os.path.exists(self.recon_summary_file):
                with open(self.recon_summary_file, "r", encoding="utf-8") as f:
                    current_data = json.load(f)

            # Add PCAP analysis results to integration analysis section
            if "pcap_integration_history" not in current_data:
                current_data["pcap_integration_history"] = []

            integration_entry = {
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "pcap_historical_integration",
                "results_summary": {
                    "similarity_score": new_analysis_results.get(
                        "pcap_comparison", {}
                    ).get("similarity_score", 0.0),
                    "critical_issues_count": len(
                        new_analysis_results.get("actionable_fixes", [])
                    ),
                    "historical_strategies_found": len(
                        new_analysis_results.get("historical_context", {}).get(
                            "relevant_historical_strategies", []
                        )
                    ),
                    "success_predictions": new_analysis_results.get(
                        "historical_context", {}
                    ).get("success_predictions", {}),
                },
                "historical_insights": new_analysis_results.get(
                    "historical_context", {}
                ).get("historical_insights", []),
            }

            current_data["pcap_integration_history"].append(integration_entry)

            # Update metadata
            if "metadata" not in current_data:
                current_data["metadata"] = {}

            current_data["metadata"][
                "last_pcap_integration"
            ] = datetime.now().isoformat()
            current_data["metadata"]["pcap_integration_count"] = len(
                current_data["pcap_integration_history"]
            )

            # Save updated data
            with open(self.recon_summary_file, "w", encoding="utf-8") as f:
                json.dump(current_data, f, indent=2, ensure_ascii=False)

            LOG.info("Historical data updated with new PCAP analysis results")
            return True

        except Exception as e:
            LOG.error(f"Failed to update historical data: {e}")
            return False

    def get_historical_summary(self) -> Dict[str, Any]:
        """Get summary of historical data and analysis capabilities"""

        summary = {
            "data_statistics": {
                "total_historical_records": len(
                    self.historical_data.get("all_results", [])
                ),
                "successful_strategies": len(
                    [
                        r
                        for r in self.historical_data.get("all_results", [])
                        if r.get("success_rate", 0.0) > 0
                    ]
                ),
                "unique_strategies": len(
                    set(
                        r.get("strategy", "")
                        for r in self.historical_data.get("all_results", [])
                    )
                ),
                "data_file_exists": os.path.exists(self.recon_summary_file),
            },
            "analysis_capabilities": {
                "effectiveness_trends": bool(self.effectiveness_trends),
                "failure_patterns": bool(self.failure_patterns),
                "success_patterns": bool(self.success_patterns),
                "parameter_analysis": bool(
                    self.effectiveness_trends.get("parameter_effectiveness")
                ),
            },
            "insights_available": {
                "success_factors": len(
                    self.success_patterns.get("success_factors", [])
                ),
                "failure_warnings": len(
                    self.failure_patterns.get("common_failure_strategies", [])
                ),
                "parameter_recommendations": len(
                    self.effectiveness_trends.get("parameter_effectiveness", {})
                ),
            },
        }

        return summary


def create_historical_data_integration(
    recon_summary_file: str = "recon_summary.json", backup_history_days: int = 30
) -> HistoricalDataIntegration:
    """
    Factory function to create a HistoricalDataIntegration instance.

    Args:
        recon_summary_file: Path to recon_summary.json
        backup_history_days: Number of days to keep backup history

    Returns:
        Configured HistoricalDataIntegration instance
    """

    return HistoricalDataIntegration(
        recon_summary_file=recon_summary_file, backup_history_days=backup_history_days
    )
