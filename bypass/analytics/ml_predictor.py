"""
Machine Learning predictor for success rate prediction
"""

import numpy as np
import pickle
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

try:
    from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor  # type: ignore[import-untyped]
    from sklearn.linear_model import LinearRegression  # type: ignore[import-untyped]
    from sklearn.preprocessing import StandardScaler  # type: ignore[import-untyped]
    from sklearn.model_selection import train_test_split  # type: ignore[import-untyped]
    from sklearn.metrics import mean_squared_error, r2_score  # type: ignore[import-untyped]

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from .analytics_models import (
    PredictionResult,
    MetricType,
    AttackMetrics,
)
from .metrics_collector import MetricsCollector


class SimplePredictor:
    """Simple predictor using moving averages when sklearn is not available"""

    def __init__(self, window_size: int = 10):
        self.window_size = window_size

    def predict(self, values: List[float]) -> Tuple[float, float]:
        """Predict next value using moving average"""
        if len(values) < 3:
            return 0.0, 0.0

        # Simple moving average
        recent_values = values[-self.window_size :]
        prediction = np.mean(recent_values)

        # Confidence based on variance
        variance = np.var(recent_values)
        confidence = max(0.1, 1.0 - min(variance, 1.0))

        return prediction, confidence

    def fit(self, X: np.ndarray, y: np.ndarray):
        """Dummy fit method for compatibility"""
        pass


class MLPredictor:
    """Machine Learning predictor for bypass engine metrics"""

    def __init__(
        self, metrics_collector: MetricsCollector, model_dir: str = "ml_models"
    ):
        self.metrics_collector = metrics_collector
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)

        # Initialize models
        if SKLEARN_AVAILABLE:
            self.models = {
                "success_rate": RandomForestRegressor(
                    n_estimators=100, random_state=42
                ),
                "response_time": GradientBoostingRegressor(
                    n_estimators=100, random_state=42
                ),
                "reliability": LinearRegression(),
            }
            self.scalers = {
                "success_rate": StandardScaler(),
                "response_time": StandardScaler(),
                "reliability": StandardScaler(),
            }
        else:
            self.models = {
                "success_rate": SimplePredictor(),
                "response_time": SimplePredictor(),
                "reliability": SimplePredictor(),
            }
            self.scalers = {}

        self.feature_columns = [
            "hour_of_day",
            "day_of_week",
            "recent_success_rate",
            "recent_response_time",
            "total_attempts",
            "failure_streak",
            "time_since_last_success",
            "avg_effectiveness",
        ]

        self.trained_models = set()
        self.prediction_cache = {}
        self.cache_ttl = 300  # 5 minutes

    async def train_models(self, min_data_points: int = 50):
        """Train ML models using historical data"""
        print("Training ML prediction models...")

        # Train attack success rate predictor
        await self._train_attack_success_predictor(min_data_points)

        # Train response time predictor
        await self._train_response_time_predictor(min_data_points)

        # Train strategy effectiveness predictor
        await self._train_strategy_predictor(min_data_points)

        print(f"Training completed. Trained models: {self.trained_models}")

    async def _train_attack_success_predictor(self, min_data_points: int):
        """Train attack success rate prediction model"""
        try:
            # Collect training data
            X, y = await self._prepare_attack_training_data()

            if len(X) < min_data_points:
                print(
                    f"Insufficient data for attack success predictor: {len(X)} < {min_data_points}"
                )
                return

            if SKLEARN_AVAILABLE:
                # Split data
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42
                )

                # Scale features
                X_train_scaled = self.scalers["success_rate"].fit_transform(X_train)
                X_test_scaled = self.scalers["success_rate"].transform(X_test)

                # Train model
                self.models["success_rate"].fit(X_train_scaled, y_train)

                # Evaluate
                y_pred = self.models["success_rate"].predict(X_test_scaled)
                mse = mean_squared_error(y_test, y_pred)
                r2 = r2_score(y_test, y_pred)

                print(f"Attack success rate predictor - MSE: {mse:.4f}, R²: {r2:.4f}")

                # Save model
                await self._save_model("success_rate")
            else:
                # Simple predictor doesn't need training
                pass

            self.trained_models.add("success_rate")

        except Exception as e:
            print(f"Error training attack success predictor: {e}")

    async def _train_response_time_predictor(self, min_data_points: int):
        """Train response time prediction model"""
        try:
            # Collect training data
            X, y = await self._prepare_response_time_training_data()

            if len(X) < min_data_points:
                print(
                    f"Insufficient data for response time predictor: {len(X)} < {min_data_points}"
                )
                return

            if SKLEARN_AVAILABLE:
                # Split data
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42
                )

                # Scale features
                X_train_scaled = self.scalers["response_time"].fit_transform(X_train)
                X_test_scaled = self.scalers["response_time"].transform(X_test)

                # Train model
                self.models["response_time"].fit(X_train_scaled, y_train)

                # Evaluate
                y_pred = self.models["response_time"].predict(X_test_scaled)
                mse = mean_squared_error(y_test, y_pred)
                r2 = r2_score(y_test, y_pred)

                print(f"Response time predictor - MSE: {mse:.4f}, R²: {r2:.4f}")

                # Save model
                await self._save_model("response_time")

            self.trained_models.add("response_time")

        except Exception as e:
            print(f"Error training response time predictor: {e}")

    async def _train_strategy_predictor(self, min_data_points: int):
        """Train strategy effectiveness prediction model"""
        try:
            # Collect training data
            X, y = await self._prepare_strategy_training_data()

            if len(X) < min_data_points:
                print(
                    f"Insufficient data for strategy predictor: {len(X)} < {min_data_points}"
                )
                return

            if SKLEARN_AVAILABLE:
                # Split data
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42
                )

                # Scale features
                X_train_scaled = self.scalers["reliability"].fit_transform(X_train)
                X_test_scaled = self.scalers["reliability"].transform(X_test)

                # Train model
                self.models["reliability"].fit(X_train_scaled, y_train)

                # Evaluate
                y_pred = self.models["reliability"].predict(X_test_scaled)
                mse = mean_squared_error(y_test, y_pred)
                r2 = r2_score(y_test, y_pred)

                print(
                    f"Strategy effectiveness predictor - MSE: {mse:.4f}, R²: {r2:.4f}"
                )

                # Save model
                await self._save_model("reliability")

            self.trained_models.add("reliability")

        except Exception as e:
            print(f"Error training strategy predictor: {e}")

    async def _prepare_attack_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for attack success prediction"""
        X, y = [], []

        for attack_id, metrics in self.metrics_collector.attack_metrics.items():
            if metrics.total_attempts < 10:  # Need minimum attempts
                continue

            # Get historical data
            history = await self.metrics_collector.get_metric_history(
                attack_id, MetricType.SUCCESS_RATE, hours=168  # 1 week
            )

            if len(history) < 10:
                continue

            # Create features and targets from time series
            for i in range(5, len(history)):  # Need at least 5 previous points
                features = self._extract_features_from_history(history[:i], metrics)
                target = history[i]["value"]

                X.append(features)
                y.append(target)

        return np.array(X), np.array(y)

    async def _prepare_response_time_training_data(
        self,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for response time prediction"""
        X, y = [], []

        for attack_id, metrics in self.metrics_collector.attack_metrics.items():
            if metrics.total_attempts < 10:
                continue

            # Get historical data
            history = await self.metrics_collector.get_metric_history(
                attack_id, MetricType.RESPONSE_TIME, hours=168
            )

            if len(history) < 10:
                continue

            # Create features and targets
            for i in range(5, len(history)):
                features = self._extract_features_from_history(history[:i], metrics)
                target = history[i]["value"]

                X.append(features)
                y.append(target)

        return np.array(X), np.array(y)

    async def _prepare_strategy_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for strategy effectiveness prediction"""
        X, y = [], []

        for strategy_id, metrics in self.metrics_collector.strategy_metrics.items():
            if metrics.domain_count < 5:
                continue

            # Create features from strategy metrics
            features = [
                metrics.domain_count,
                metrics.successful_domains,
                metrics.failed_domains,
                metrics.avg_effectiveness,
                (datetime.now() - metrics.last_updated).total_seconds()
                / 3600,  # hours since update
                0,  # placeholder for additional features
                0,
                0,
            ]

            target = metrics.success_rate

            X.append(features)
            y.append(target)

        return np.array(X), np.array(y)

    def _extract_features_from_history(
        self, history: List[Dict], metrics: AttackMetrics
    ) -> List[float]:
        """Extract features from historical data"""
        if not history:
            return [0] * len(self.feature_columns)

        now = datetime.now()
        recent_values = [h["value"] for h in history[-5:]]  # Last 5 values

        # Calculate features
        features = [
            now.hour,  # hour_of_day
            now.weekday(),  # day_of_week
            np.mean(recent_values) if recent_values else 0,  # recent_success_rate
            metrics.avg_response_time,  # recent_response_time
            metrics.total_attempts,  # total_attempts
            self._calculate_failure_streak(history),  # failure_streak
            (
                (now - metrics.last_success).total_seconds() / 3600
                if metrics.last_success
                else 24
            ),  # time_since_last_success
            (
                np.mean(recent_values) if recent_values else 0
            ),  # avg_effectiveness (same as success rate for attacks)
        ]

        return features

    def _calculate_failure_streak(self, history: List[Dict]) -> int:
        """Calculate current failure streak"""
        streak = 0
        for record in reversed(history):
            if record["value"] == 0:  # Failure
                streak += 1
            else:
                break
        return streak

    async def predict_success_rate(
        self, entity_id: str, hours_ahead: int = 1
    ) -> Optional[PredictionResult]:
        """Predict success rate for entity"""
        cache_key = f"success_rate_{entity_id}_{hours_ahead}"

        # Check cache
        if cache_key in self.prediction_cache:
            cached_result, timestamp = self.prediction_cache[cache_key]
            if (datetime.now() - timestamp).seconds < self.cache_ttl:
                return cached_result

        if "success_rate" not in self.trained_models:
            return None

        try:
            # Get current metrics
            metrics = await self.metrics_collector.get_attack_metrics(entity_id)
            if not metrics or metrics.total_attempts < 5:
                return None

            # Get recent history
            history = await self.metrics_collector.get_metric_history(
                entity_id, MetricType.SUCCESS_RATE, hours=24
            )

            if len(history) < 5:
                return None

            # Extract features
            features = self._extract_features_from_history(history, metrics)

            if SKLEARN_AVAILABLE and "success_rate" in self.scalers:
                # Use ML model
                features_scaled = self.scalers["success_rate"].transform([features])
                prediction = self.models["success_rate"].predict(features_scaled)[0]

                # Calculate confidence based on model uncertainty
                confidence = min(
                    0.9, max(0.1, 1.0 - abs(prediction - metrics.success_rate))
                )
            else:
                # Use simple predictor
                recent_values = [h["value"] for h in history[-10:]]
                prediction, confidence = self.models["success_rate"].predict(
                    recent_values
                )

            # Ensure prediction is in valid range
            prediction = max(0.0, min(1.0, prediction))

            result = PredictionResult(
                entity_id=entity_id,
                metric_type=MetricType.SUCCESS_RATE,
                predicted_value=prediction,
                confidence=confidence,
                prediction_horizon=hours_ahead,
            )

            # Cache result
            self.prediction_cache[cache_key] = (result, datetime.now())

            return result

        except Exception as e:
            print(f"Error predicting success rate for {entity_id}: {e}")
            return None

    async def predict_response_time(
        self, entity_id: str, hours_ahead: int = 1
    ) -> Optional[PredictionResult]:
        """Predict response time for entity"""
        cache_key = f"response_time_{entity_id}_{hours_ahead}"

        # Check cache
        if cache_key in self.prediction_cache:
            cached_result, timestamp = self.prediction_cache[cache_key]
            if (datetime.now() - timestamp).seconds < self.cache_ttl:
                return cached_result

        if "response_time" not in self.trained_models:
            return None

        try:
            # Get current metrics
            metrics = await self.metrics_collector.get_attack_metrics(entity_id)
            if not metrics or metrics.total_attempts < 5:
                return None

            # Get recent history
            history = await self.metrics_collector.get_metric_history(
                entity_id, MetricType.RESPONSE_TIME, hours=24
            )

            if len(history) < 5:
                return None

            # Extract features
            features = self._extract_features_from_history(history, metrics)

            if SKLEARN_AVAILABLE and "response_time" in self.scalers:
                # Use ML model
                features_scaled = self.scalers["response_time"].transform([features])
                prediction = self.models["response_time"].predict(features_scaled)[0]

                # Calculate confidence
                confidence = min(
                    0.9,
                    max(
                        0.1,
                        1.0
                        - abs(prediction - metrics.avg_response_time)
                        / max(metrics.avg_response_time, 1.0),
                    ),
                )
            else:
                # Use simple predictor
                recent_values = [h["value"] for h in history[-10:]]
                prediction, confidence = self.models["response_time"].predict(
                    recent_values
                )

            # Ensure prediction is positive
            prediction = max(0.1, prediction)

            result = PredictionResult(
                entity_id=entity_id,
                metric_type=MetricType.RESPONSE_TIME,
                predicted_value=prediction,
                confidence=confidence,
                prediction_horizon=hours_ahead,
            )

            # Cache result
            self.prediction_cache[cache_key] = (result, datetime.now())

            return result

        except Exception as e:
            print(f"Error predicting response time for {entity_id}: {e}")
            return None

    async def predict_strategy_effectiveness(
        self, strategy_id: str, hours_ahead: int = 1
    ) -> Optional[PredictionResult]:
        """Predict strategy effectiveness"""
        if "reliability" not in self.trained_models:
            return None

        try:
            # Get current metrics
            metrics = await self.metrics_collector.get_strategy_metrics(strategy_id)
            if not metrics or metrics.domain_count < 3:
                return None

            # Create features
            features = [
                metrics.domain_count,
                metrics.successful_domains,
                metrics.failed_domains,
                metrics.avg_effectiveness,
                (datetime.now() - metrics.last_updated).total_seconds() / 3600,
                0,
                0,
                0,  # placeholder features
            ]

            if SKLEARN_AVAILABLE and "reliability" in self.scalers:
                # Use ML model
                features_scaled = self.scalers["reliability"].transform([features])
                prediction = self.models["reliability"].predict(features_scaled)[0]
                confidence = 0.7  # Default confidence for strategy predictions
            else:
                # Simple prediction based on current success rate
                prediction = metrics.success_rate
                confidence = 0.5

            # Ensure prediction is in valid range
            prediction = max(0.0, min(1.0, prediction))

            result = PredictionResult(
                entity_id=strategy_id,
                metric_type=MetricType.STRATEGY_PERFORMANCE,
                predicted_value=prediction,
                confidence=confidence,
                prediction_horizon=hours_ahead,
            )

            return result

        except Exception as e:
            print(f"Error predicting strategy effectiveness for {strategy_id}: {e}")
            return None

    async def _save_model(self, model_name: str):
        """Save trained model to disk"""
        if not SKLEARN_AVAILABLE:
            return

        model_path = self.model_dir / f"{model_name}_model.pkl"
        scaler_path = self.model_dir / f"{model_name}_scaler.pkl"

        with open(model_path, "wb") as f:
            pickle.dump(self.models[model_name], f)

        with open(scaler_path, "wb") as f:
            pickle.dump(self.scalers[model_name], f)

    async def load_models(self):
        """Load trained models from disk"""
        if not SKLEARN_AVAILABLE:
            return

        for model_name in ["success_rate", "response_time", "reliability"]:
            model_path = self.model_dir / f"{model_name}_model.pkl"
            scaler_path = self.model_dir / f"{model_name}_scaler.pkl"

            if model_path.exists() and scaler_path.exists():
                try:
                    with open(model_path, "rb") as f:
                        self.models[model_name] = pickle.load(f)

                    with open(scaler_path, "rb") as f:
                        self.scalers[model_name] = pickle.load(f)

                    self.trained_models.add(model_name)
                    print(f"Loaded {model_name} model")

                except Exception as e:
                    print(f"Error loading {model_name} model: {e}")

    async def get_prediction_accuracy(
        self, model_name: str, hours: int = 24
    ) -> Dict[str, float]:
        """Calculate prediction accuracy for recent predictions"""
        # This would compare predictions made in the past with actual outcomes
        # For now, return placeholder metrics
        return {
            "mae": 0.1,  # Mean Absolute Error
            "rmse": 0.15,  # Root Mean Square Error
            "accuracy": 0.85,  # Overall accuracy
        }

    async def retrain_if_needed(self):
        """Retrain models if accuracy drops below threshold"""
        for model_name in self.trained_models:
            accuracy = await self.get_prediction_accuracy(model_name)
            if accuracy["accuracy"] < 0.7:  # Threshold
                print(
                    f"Retraining {model_name} model due to low accuracy: {accuracy['accuracy']}"
                )
                await self.train_models()
                break
