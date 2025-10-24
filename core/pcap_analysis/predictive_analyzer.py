"""
Predictive Analyzer - Task 19 Implementation
Provides predictive analysis for strategy effectiveness based on historical data and learning.

This module provides:
1. Strategy effectiveness prediction
2. Success probability calculation
3. Risk assessment for strategies
4. Optimization recommendations
"""

import logging
import statistics
from typing import Dict, Any, List
from collections import defaultdict

from .learning_engine import LearningEngine

LOG = logging.getLogger(__name__)


class PredictiveAnalyzer:
    """
    Predictive analyzer for strategy effectiveness and success probability.

    This class provides:
    1. Strategy effectiveness prediction based on historical data
    2. Success probability calculation using multiple factors
    3. Risk assessment and confidence scoring
    4. Optimization recommendations
    """

    def __init__(
        self,
        learning_engine: LearningEngine = None,
        historical_data: Dict[str, Any] = None,
    ):

        self.learning_engine = learning_engine or LearningEngine()
        self.historical_data = historical_data or {}

        # Prediction models
        self.effectiveness_model = EffectivenessModel()
        self.risk_model = RiskAssessmentModel()
        self.optimization_model = OptimizationModel()

        LOG.info("Predictive analyzer initialized")

    def predict_strategy_effectiveness(
        self,
        strategy_params: Dict[str, Any],
        target_domain: str = None,
        historical_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Predict strategy effectiveness using multiple prediction models.

        Args:
            strategy_params: Strategy parameters to evaluate
            target_domain: Target domain for prediction
            historical_context: Historical context data

        Returns:
            Comprehensive prediction results
        """

        prediction = {
            "overall_prediction": {},
            "model_predictions": {},
            "confidence_analysis": {},
            "risk_assessment": {},
            "optimization_suggestions": [],
        }

        try:
            # Get learning engine prediction
            learning_prediction = self.learning_engine.predict_strategy_effectiveness(
                strategy_params, target_domain
            )

            # Get effectiveness model prediction
            effectiveness_prediction = self.effectiveness_model.predict(
                strategy_params, self.historical_data
            )

            # Get risk assessment
            risk_assessment = self.risk_model.assess_risk(
                strategy_params, self.historical_data
            )

            # Get optimization suggestions
            optimization_suggestions = self.optimization_model.suggest_optimizations(
                strategy_params, self.historical_data
            )

            # Combine predictions
            prediction["model_predictions"] = {
                "learning_engine": learning_prediction,
                "effectiveness_model": effectiveness_prediction,
                "risk_model": risk_assessment,
            }

            # Calculate overall prediction
            prediction["overall_prediction"] = self._combine_predictions(
                learning_prediction, effectiveness_prediction, risk_assessment
            )

            # Analyze confidence
            prediction["confidence_analysis"] = self._analyze_confidence(
                learning_prediction, effectiveness_prediction, risk_assessment
            )

            prediction["risk_assessment"] = risk_assessment
            prediction["optimization_suggestions"] = optimization_suggestions

        except Exception as e:
            LOG.error(f"Failed to predict strategy effectiveness: {e}")
            prediction["error"] = str(e)

        return prediction

    def _combine_predictions(
        self,
        learning_pred: Dict[str, Any],
        effectiveness_pred: Dict[str, Any],
        risk_pred: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Combine predictions from different models"""

        combined = {
            "predicted_success_rate": 0.0,
            "confidence": 0.0,
            "reliability": "LOW",
            "reasoning": [],
        }

        try:
            # Collect success rate predictions
            success_rates = []
            confidences = []

            # Learning engine prediction
            if learning_pred.get("predicted_success_rate") is not None:
                success_rates.append(learning_pred["predicted_success_rate"])
                confidences.append(learning_pred.get("confidence", 0.0))

            # Effectiveness model prediction
            if effectiveness_pred.get("predicted_success_rate") is not None:
                success_rates.append(effectiveness_pred["predicted_success_rate"])
                confidences.append(effectiveness_pred.get("confidence", 0.0))

            # Calculate weighted average
            if success_rates and confidences:
                # Weight by confidence
                total_weight = sum(confidences)
                if total_weight > 0:
                    weighted_success = (
                        sum(
                            rate * conf
                            for rate, conf in zip(success_rates, confidences)
                        )
                        / total_weight
                    )
                    combined["predicted_success_rate"] = weighted_success
                else:
                    combined["predicted_success_rate"] = statistics.mean(success_rates)

                combined["confidence"] = statistics.mean(confidences)

            # Adjust for risk
            risk_factor = risk_pred.get("risk_score", 0.5)
            combined["predicted_success_rate"] *= (
                1.0 - risk_factor * 0.3
            )  # Reduce by up to 30% based on risk

            # Determine reliability
            if combined["confidence"] > 0.8:
                combined["reliability"] = "HIGH"
            elif combined["confidence"] > 0.5:
                combined["reliability"] = "MEDIUM"
            else:
                combined["reliability"] = "LOW"

            # Add reasoning
            combined["reasoning"] = [
                f"Combined prediction from {len(success_rates)} models",
                f"Confidence level: {combined['confidence']:.1%}",
                f"Risk adjustment applied: {risk_factor:.1%}",
            ]

        except Exception as e:
            LOG.error(f"Failed to combine predictions: {e}")

        return combined

    def _analyze_confidence(self, *predictions) -> Dict[str, Any]:
        """Analyze confidence across different predictions"""

        analysis = {
            "confidence_consistency": 0.0,
            "prediction_agreement": 0.0,
            "reliability_factors": [],
            "confidence_issues": [],
        }

        try:
            confidences = []
            success_rates = []

            for pred in predictions:
                if isinstance(pred, dict):
                    if pred.get("confidence") is not None:
                        confidences.append(pred["confidence"])
                    if pred.get("predicted_success_rate") is not None:
                        success_rates.append(pred["predicted_success_rate"])

            # Analyze confidence consistency
            if confidences:
                if len(confidences) > 1:
                    conf_std = statistics.stdev(confidences)
                    analysis["confidence_consistency"] = max(0.0, 1.0 - conf_std)
                else:
                    analysis["confidence_consistency"] = confidences[0]

            # Analyze prediction agreement
            if success_rates and len(success_rates) > 1:
                rate_std = statistics.stdev(success_rates)
                analysis["prediction_agreement"] = max(0.0, 1.0 - rate_std)
            elif success_rates:
                analysis["prediction_agreement"] = 1.0

            # Identify reliability factors
            if analysis["confidence_consistency"] > 0.8:
                analysis["reliability_factors"].append(
                    "High confidence consistency across models"
                )

            if analysis["prediction_agreement"] > 0.8:
                analysis["reliability_factors"].append(
                    "High agreement between predictions"
                )

            # Identify confidence issues
            if analysis["confidence_consistency"] < 0.5:
                analysis["confidence_issues"].append(
                    "Low confidence consistency between models"
                )

            if analysis["prediction_agreement"] < 0.5:
                analysis["confidence_issues"].append(
                    "Low agreement between predictions"
                )

        except Exception as e:
            LOG.error(f"Failed to analyze confidence: {e}")

        return analysis

    def predict_parameter_optimization(
        self, current_params: Dict[str, Any], target_success_rate: float = 0.8
    ) -> Dict[str, Any]:
        """
        Predict optimal parameter values to achieve target success rate.

        Args:
            current_params: Current strategy parameters
            target_success_rate: Desired success rate

        Returns:
            Parameter optimization predictions
        """

        optimization = {
            "optimized_parameters": {},
            "predicted_improvement": 0.0,
            "optimization_steps": [],
            "confidence": 0.0,
        }

        try:
            # Get current prediction
            current_prediction = self.predict_strategy_effectiveness(current_params)
            current_success_rate = current_prediction["overall_prediction"].get(
                "predicted_success_rate", 0.0
            )

            # Try different parameter combinations
            best_params = current_params.copy()
            best_success_rate = current_success_rate
            optimization_steps = []

            # Optimize TTL
            if "ttl" in current_params:
                ttl_optimization = self._optimize_ttl(current_params)
                if ttl_optimization["success_rate"] > best_success_rate:
                    best_params.update(ttl_optimization["params"])
                    best_success_rate = ttl_optimization["success_rate"]
                    optimization_steps.append(ttl_optimization["step"])

            # Optimize split position
            if "split_pos" in current_params:
                split_optimization = self._optimize_split_pos(current_params)
                if split_optimization["success_rate"] > best_success_rate:
                    best_params.update(split_optimization["params"])
                    best_success_rate = split_optimization["success_rate"]
                    optimization_steps.append(split_optimization["step"])

            # Optimize fooling methods
            if "fooling" in current_params:
                fooling_optimization = self._optimize_fooling(current_params)
                if fooling_optimization["success_rate"] > best_success_rate:
                    best_params.update(fooling_optimization["params"])
                    best_success_rate = fooling_optimization["success_rate"]
                    optimization_steps.append(fooling_optimization["step"])

            optimization["optimized_parameters"] = best_params
            optimization["predicted_improvement"] = (
                best_success_rate - current_success_rate
            )
            optimization["optimization_steps"] = optimization_steps
            optimization["confidence"] = min(len(optimization_steps) / 3.0, 1.0)

        except Exception as e:
            LOG.error(f"Failed to predict parameter optimization: {e}")
            optimization["error"] = str(e)

        return optimization

    def _optimize_ttl(self, current_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize TTL parameter"""

        best_ttl = current_params.get("ttl", 3)
        best_success_rate = 0.0

        # Try different TTL values
        for ttl in [1, 2, 3, 4, 5, 8, 10]:
            test_params = current_params.copy()
            test_params["ttl"] = ttl

            prediction = self.learning_engine.predict_strategy_effectiveness(
                test_params
            )
            success_rate = prediction.get("predicted_success_rate", 0.0)

            if success_rate > best_success_rate:
                best_success_rate = success_rate
                best_ttl = ttl

        return {
            "params": {"ttl": best_ttl},
            "success_rate": best_success_rate,
            "step": f"Optimized TTL from {current_params.get('ttl')} to {best_ttl}",
        }

    def _optimize_split_pos(self, current_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize split position parameter"""

        best_split_pos = current_params.get("split_pos", 3)
        best_success_rate = 0.0

        # Try different split positions
        for split_pos in [1, 2, 3, 4, 5, 8, 10, 15, 20]:
            test_params = current_params.copy()
            test_params["split_pos"] = split_pos

            prediction = self.learning_engine.predict_strategy_effectiveness(
                test_params
            )
            success_rate = prediction.get("predicted_success_rate", 0.0)

            if success_rate > best_success_rate:
                best_success_rate = success_rate
                best_split_pos = split_pos

        return {
            "params": {"split_pos": best_split_pos},
            "success_rate": best_success_rate,
            "step": f"Optimized split_pos from {current_params.get('split_pos')} to {best_split_pos}",
        }

    def _optimize_fooling(self, current_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize fooling methods"""

        current_fooling = current_params.get("fooling", [])
        best_fooling = current_fooling.copy()
        best_success_rate = 0.0

        # Try different fooling method combinations
        fooling_options = ["badsum", "badseq", "md5sig", "tcp_md5sig"]

        for i in range(1, len(fooling_options) + 1):
            from itertools import combinations

            for fooling_combo in combinations(fooling_options, i):
                test_params = current_params.copy()
                test_params["fooling"] = list(fooling_combo)

                prediction = self.learning_engine.predict_strategy_effectiveness(
                    test_params
                )
                success_rate = prediction.get("predicted_success_rate", 0.0)

                if success_rate > best_success_rate:
                    best_success_rate = success_rate
                    best_fooling = list(fooling_combo)

        return {
            "params": {"fooling": best_fooling},
            "success_rate": best_success_rate,
            "step": f"Optimized fooling from {current_fooling} to {best_fooling}",
        }


class EffectivenessModel:
    """Model for predicting strategy effectiveness based on historical patterns"""

    def predict(
        self, strategy_params: Dict[str, Any], historical_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Predict effectiveness using historical patterns"""

        prediction = {
            "predicted_success_rate": 0.0,
            "confidence": 0.0,
            "historical_basis": [],
        }

        try:
            all_results = historical_data.get("all_results", [])
            if not all_results:
                return prediction

            # Find similar strategies
            similar_strategies = []
            for result in all_results:
                similarity = self._calculate_strategy_similarity(
                    strategy_params, result
                )
                if similarity > 0.3:  # Threshold for similarity
                    similar_strategies.append(
                        {"result": result, "similarity": similarity}
                    )

            if similar_strategies:
                # Weight by similarity
                total_weight = sum(s["similarity"] for s in similar_strategies)
                weighted_success = (
                    sum(
                        s["result"].get("success_rate", 0.0) * s["similarity"]
                        for s in similar_strategies
                    )
                    / total_weight
                )

                prediction["predicted_success_rate"] = weighted_success
                prediction["confidence"] = min(len(similar_strategies) / 10.0, 1.0)
                prediction["historical_basis"] = [
                    f"Based on {len(similar_strategies)} similar historical strategies"
                ]

        except Exception as e:
            LOG.error(f"Effectiveness model prediction failed: {e}")

        return prediction

    def _calculate_strategy_similarity(
        self, params1: Dict[str, Any], result: Dict[str, Any]
    ) -> float:
        """Calculate similarity between strategy parameters and historical result"""

        similarity = 0.0
        factors = 0

        try:
            strategy_str = result.get("strategy", "")

            # TTL similarity
            if "ttl" in params1:
                if (
                    f"ttl={params1['ttl']}" in strategy_str
                    or f"ttl={params1['ttl']})" in strategy_str
                ):
                    similarity += 0.3
                factors += 1

            # Split position similarity
            if "split_pos" in params1:
                if (
                    f"split_pos={params1['split_pos']}" in strategy_str
                    or f"split-pos={params1['split_pos']}" in strategy_str
                ):
                    similarity += 0.3
                factors += 1

            # Strategy type similarity
            if "strategy_type" in params1:
                if params1["strategy_type"].lower() in strategy_str.lower():
                    similarity += 0.4
                factors += 1

            # Fooling methods similarity
            if "fooling" in params1 and isinstance(params1["fooling"], list):
                fooling_matches = sum(
                    1 for method in params1["fooling"] if method in strategy_str
                )
                if len(params1["fooling"]) > 0:
                    similarity += 0.2 * (fooling_matches / len(params1["fooling"]))
                factors += 1

            # Normalize by number of factors
            if factors > 0:
                similarity /= factors

        except Exception as e:
            LOG.error(f"Failed to calculate strategy similarity: {e}")

        return similarity


class RiskAssessmentModel:
    """Model for assessing risk of strategy failure"""

    def assess_risk(
        self, strategy_params: Dict[str, Any], historical_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess risk of strategy failure"""

        assessment = {
            "risk_score": 0.5,  # Default medium risk
            "risk_level": "MEDIUM",
            "risk_factors": [],
            "mitigation_suggestions": [],
        }

        try:
            risk_factors = []
            risk_score = 0.0

            # Analyze historical failures
            all_results = historical_data.get("all_results", [])
            failed_results = [
                r for r in all_results if r.get("success_rate", 0.0) == 0.0
            ]

            # TTL risk assessment
            if "ttl" in strategy_params:
                ttl = strategy_params["ttl"]
                ttl_failures = sum(
                    1 for r in failed_results if f"ttl={ttl}" in r.get("strategy", "")
                )
                ttl_total = sum(
                    1 for r in all_results if f"ttl={ttl}" in r.get("strategy", "")
                )

                if ttl_total > 0:
                    ttl_failure_rate = ttl_failures / ttl_total
                    if ttl_failure_rate > 0.7:
                        risk_factors.append(
                            f"TTL={ttl} has high failure rate ({ttl_failure_rate:.1%})"
                        )
                        risk_score += 0.3
                    elif ttl_failure_rate > 0.4:
                        risk_factors.append(
                            f"TTL={ttl} has moderate failure rate ({ttl_failure_rate:.1%})"
                        )
                        risk_score += 0.1

            # Split position risk assessment
            if "split_pos" in strategy_params:
                split_pos = strategy_params["split_pos"]
                if split_pos > 20:
                    risk_factors.append("Large split positions often fail")
                    risk_score += 0.2
                elif split_pos > 50:
                    risk_factors.append(
                        "Very large split positions have high failure risk"
                    )
                    risk_score += 0.4

            # Strategy complexity risk
            if "fooling" in strategy_params and isinstance(
                strategy_params["fooling"], list
            ):
                if len(strategy_params["fooling"]) > 3:
                    risk_factors.append(
                        "Complex fooling combinations may increase failure risk"
                    )
                    risk_score += 0.1

            # Determine risk level
            if risk_score > 0.7:
                assessment["risk_level"] = "HIGH"
            elif risk_score > 0.3:
                assessment["risk_level"] = "MEDIUM"
            else:
                assessment["risk_level"] = "LOW"

            assessment["risk_score"] = min(risk_score, 1.0)
            assessment["risk_factors"] = risk_factors

            # Generate mitigation suggestions
            if risk_score > 0.5:
                assessment["mitigation_suggestions"] = [
                    "Consider testing with simpler parameters first",
                    "Use proven parameter combinations from successful strategies",
                    "Implement fallback strategies for high-risk configurations",
                ]

        except Exception as e:
            LOG.error(f"Risk assessment failed: {e}")

        return assessment


class OptimizationModel:
    """Model for suggesting strategy optimizations"""

    def suggest_optimizations(
        self, strategy_params: Dict[str, Any], historical_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Suggest optimizations for strategy parameters"""

        suggestions = []

        try:
            all_results = historical_data.get("all_results", [])
            successful_results = [
                r for r in all_results if r.get("success_rate", 0.0) > 0.0
            ]

            # TTL optimization suggestions
            if "ttl" in strategy_params:
                ttl_success_rates = defaultdict(list)
                for result in successful_results:
                    strategy_str = result.get("strategy", "")
                    if "ttl=" in strategy_str:
                        try:
                            ttl_part = (
                                strategy_str.split("ttl=")[1].split()[0].rstrip(",)")
                            )
                            ttl_value = int(ttl_part)
                            ttl_success_rates[ttl_value].append(
                                result.get("success_rate", 0.0)
                            )
                        except:
                            pass

                if ttl_success_rates:
                    best_ttl = max(
                        ttl_success_rates.items(), key=lambda x: statistics.mean(x[1])
                    )
                    if best_ttl[0] != strategy_params["ttl"]:
                        suggestions.append(
                            {
                                "type": "parameter_optimization",
                                "parameter": "ttl",
                                "current_value": strategy_params["ttl"],
                                "suggested_value": best_ttl[0],
                                "expected_improvement": statistics.mean(best_ttl[1]),
                                "reasoning": f"TTL={best_ttl[0]} shows better historical success rate",
                            }
                        )

            # Split position optimization suggestions
            if "split_pos" in strategy_params:
                split_success_rates = defaultdict(list)
                for result in successful_results:
                    strategy_str = result.get("strategy", "")
                    if "split_pos=" in strategy_str or "split-pos=" in strategy_str:
                        try:
                            if "split_pos=" in strategy_str:
                                split_part = (
                                    strategy_str.split("split_pos=")[1]
                                    .split()[0]
                                    .rstrip(",)")
                                )
                            else:
                                split_part = (
                                    strategy_str.split("split-pos=")[1]
                                    .split()[0]
                                    .rstrip(",)")
                                )
                            split_value = int(split_part)
                            split_success_rates[split_value].append(
                                result.get("success_rate", 0.0)
                            )
                        except:
                            pass

                if split_success_rates:
                    best_split = max(
                        split_success_rates.items(), key=lambda x: statistics.mean(x[1])
                    )
                    if best_split[0] != strategy_params["split_pos"]:
                        suggestions.append(
                            {
                                "type": "parameter_optimization",
                                "parameter": "split_pos",
                                "current_value": strategy_params["split_pos"],
                                "suggested_value": best_split[0],
                                "expected_improvement": statistics.mean(best_split[1]),
                                "reasoning": f"split_pos={best_split[0]} shows better historical success rate",
                            }
                        )

            # Strategy type suggestions
            strategy_type_success = defaultdict(list)
            for result in successful_results:
                strategy_str = result.get("strategy", "").lower()
                if "fake" in strategy_str and "disorder" in strategy_str:
                    strategy_type_success["fake_disorder"].append(
                        result.get("success_rate", 0.0)
                    )
                elif "fake" in strategy_str:
                    strategy_type_success["fake"].append(
                        result.get("success_rate", 0.0)
                    )
                elif "split" in strategy_str:
                    strategy_type_success["split"].append(
                        result.get("success_rate", 0.0)
                    )

            if strategy_type_success:
                best_type = max(
                    strategy_type_success.items(), key=lambda x: statistics.mean(x[1])
                )
                current_type = strategy_params.get("strategy_type", "").lower()
                if best_type[0] != current_type:
                    suggestions.append(
                        {
                            "type": "strategy_type_optimization",
                            "current_type": current_type,
                            "suggested_type": best_type[0],
                            "expected_improvement": statistics.mean(best_type[1]),
                            "reasoning": f"{best_type[0]} strategy shows better historical success rate",
                        }
                    )

        except Exception as e:
            LOG.error(f"Optimization suggestions failed: {e}")

        return suggestions
