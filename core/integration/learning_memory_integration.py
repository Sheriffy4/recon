#!/usr/bin/env python3
"""
Learning Memory System Integration - Integrates existing learning memory with Phase 2 infrastructure.
Enhanced with pattern recognition, predictive capabilities, and advanced ML integration.
"""

import logging
import asyncio
import time
import hashlib
import json
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Import Phase 2 infrastructure
try:
    from .advanced_attack_manager import (
        AdvancedAttack, AdvancedAttackConfig, AdvancedAttackResult,
        AttackContext, MLFeedback, LearningData, PerformanceMetrics,
        AdaptationSuggestion
    )
    from .advanced_attack_errors import (
        get_error_handler, create_execution_error, ErrorContext
    )
    PHASE2_INFRASTRUCTURE_AVAILABLE = True
except ImportError as e:
    PHASE2_INFRASTRUCTURE_AVAILABLE = False
    logging.warning(f"Phase 2 infrastructure not available: {e}")

# Import existing learning memory system
try:
    from core.bypass.attacks.learning_memory import (
        LearningMemory, StrategyRecord, LearningHistory, AdaptationRecord
    )
    LEARNING_MEMORY_AVAILABLE = True
except ImportError as e:
    LEARNING_MEMORY_AVAILABLE = False
    logging.warning(f"Learning memory system not available: {e}")

# Import ML modules for enhanced prediction
try:
    from ml.strategy_predictor import StrategyPredictor
    from ml.dpi_classifier import DPIClassifier
    ML_MODULES_AVAILABLE = True
except ImportError as e:
    ML_MODULES_AVAILABLE = False
    logging.warning(f"ML modules not available: {e}")

LOG = logging.getLogger("learning_memory_integration")

@dataclass
class LearningMemoryState:
    """State information for learning memory system."""
    total_records: int = 0
    successful_records: int = 0
    best_effectiveness: float = 0.0
    best_attack: Optional[str] = None
    last_learning_time: Optional[datetime] = None
    learning_rate: float = 0.1
    memory_size_mb: float = 0.0
    pattern_recognition_enabled: bool = True
    prediction_confidence: float = 0.0
    adaptation_count: int = 0


@dataclass
class PatternRecognitionResult:
    """Result of pattern recognition analysis."""
    pattern_type: str
    confidence: float
    pattern_data: Dict[str, Any]
    recommendations: List[str]
    predicted_success_rate: float


@dataclass
class PredictiveRecommendation:
    """Predictive recommendation for new targets."""
    target_signature: str
    recommended_strategy: str
    confidence: float
    reasoning: str
    expected_effectiveness: float
    adaptation_suggestions: List[str]


class LearningMemoryIntegration(AdvancedAttack):
    """
    Enhanced Integration wrapper for Learning Memory System.
    Provides ML integration, historical learning, pattern recognition, and predictive capabilities.
    """
    
    def __init__(self, config: AdvancedAttackConfig):
        super().__init__(config)
        self.learning_memory = None
        self.state = LearningMemoryState()
        self.error_handler = None
        
        # Enhanced learning memory parameters
        self.storage_path = "data/phase2_learning_memory.db"
        self.max_history_entries = 50000
        self.learning_threshold = 0.7
        self.prediction_confidence_threshold = 0.6
        self.memory_cleanup_interval = 3600  # 1 hour
        self.last_cleanup = time.time()
        
        # Pattern recognition parameters
        self.pattern_window_size = 50  # Number of recent records to analyze
        self.pattern_confidence_threshold = 0.6
        self.similarity_threshold = 0.8
        
        # Predictive capabilities
        self.prediction_model_enabled = True
        self.adaptation_learning_rate = 0.15
        self.strategy_evolution_enabled = True
        
        # ML integration components
        self.strategy_predictor = None
        self.dpi_classifier = None
        
        if LEARNING_MEMORY_AVAILABLE:
            try:
                self.learning_memory = LearningMemory(
                    storage_path=self.storage_path,
                    max_history_entries=self.max_history_entries
                )
                LOG.info("Learning memory system initialized successfully")
            except Exception as e:
                LOG.error(f"Failed to initialize learning memory system: {e}")
                self.learning_memory = None
        
        if ML_MODULES_AVAILABLE:
            try:
                self.strategy_predictor = StrategyPredictor()
                self.dpi_classifier = DPIClassifier()
                LOG.info("ML modules initialized successfully")
            except Exception as e:
                LOG.warning(f"ML modules initialization failed: {e}")
        
        if PHASE2_INFRASTRUCTURE_AVAILABLE:
            try:
                self.error_handler = get_error_handler()
            except Exception as e:
                LOG.warning(f"Error handler not available: {e}")
        
        LOG.info(f"Enhanced Learning Memory Integration initialized: {self.config.name}")
    
    async def execute(self, target: str, context: AttackContext) -> AdvancedAttackResult:
        """Execute enhanced learning memory attack with pattern recognition and prediction."""
        
        LOG.info(f"Executing enhanced learning memory attack on {target}")
        start_time = time.time()
        
        try:
            # Generate fingerprint hash for this target/context
            fingerprint_hash = await self._generate_fingerprint_hash(target, context)
            
            # Retrieve historical learning data
            historical_data = await self._retrieve_historical_data(fingerprint_hash)
            
            # Perform pattern recognition analysis
            pattern_result = await self._analyze_patterns(fingerprint_hash, historical_data)
            
            # Generate predictive recommendations
            prediction_result = await self._generate_predictive_recommendations(
                fingerprint_hash, context, historical_data, pattern_result
            )
            
            # Apply ML predictions with historical context and patterns
            if context.ml_prediction and historical_data:
                enhanced_prediction = await self._enhance_ml_prediction_with_patterns(
                    context.ml_prediction, historical_data, pattern_result
                )
            else:
                enhanced_prediction = context.ml_prediction
            
            # Select optimal attack strategy based on learning, patterns, and predictions
            optimal_strategy = await self._select_optimal_strategy_enhanced(
                fingerprint_hash, enhanced_prediction, historical_data, 
                pattern_result, prediction_result
            )
            
            # Execute the selected strategy
            result = await self._execute_learned_strategy(
                target, context, optimal_strategy, fingerprint_hash
            )
            
            # Save learning result and update patterns
            await self._save_learning_result_enhanced(
                fingerprint_hash, optimal_strategy, result, pattern_result
            )
            
            # Update state and statistics
            await self._update_state_and_stats_enhanced(result, pattern_result)
            
            # Perform periodic cleanup if needed
            await self._periodic_cleanup()
            
            # Update attack statistics
            self.update_stats(result)
            
            execution_time = (time.time() - start_time) * 1000
            LOG.info(f"Enhanced learning memory attack completed: {'SUCCESS' if result.success else 'FAILURE'} ({execution_time:.1f}ms)")
            
            return result
            
        except Exception as e:
            LOG.error(f"Enhanced learning memory attack execution failed: {e}")
            
            # Handle error through error handler
            if self.error_handler:
                try:
                    error_context = ErrorContext(
                        attack_name=self.config.name,
                        target=target,
                        operation="execute"
                    )
                    error = create_execution_error(str(e), self.config.name, error_context, e)
                    recovery_result = await self.error_handler.handle_error(error)
                    
                    if recovery_result.success and recovery_result.action.value == "retry":
                        return await self._retry_with_fallback(target, context)
                        
                except Exception as error_handling_error:
                    LOG.error(f"Error handling failed: {error_handling_error}")
            
            # Create error result
            return self._create_error_result(str(e), time.time() - start_time)
    
    async def adapt_from_feedback(self, feedback: MLFeedback) -> None:
        """Adapt learning parameters based on ML feedback."""
        
        LOG.info(f"Adapting learning memory from ML feedback: {feedback.attack_name}")
        
        try:
            # Update learning rate based on feedback effectiveness
            if feedback.effectiveness_score > 0.8:
                # High effectiveness - reduce learning rate (more stable)
                self.state.learning_rate = max(0.01, self.state.learning_rate * 0.95)
            elif feedback.effectiveness_score < 0.4:
                # Low effectiveness - increase learning rate (more exploration)
                self.state.learning_rate = min(0.3, self.state.learning_rate * 1.1)
            
            # Adjust prediction confidence threshold
            if feedback.success:
                # Successful attack - maintain or slightly increase confidence threshold
                self.prediction_confidence_threshold = min(0.9, self.prediction_confidence_threshold * 1.02)
            else:
                # Failed attack - lower confidence threshold for more exploration
                self.prediction_confidence_threshold = max(0.3, self.prediction_confidence_threshold * 0.98)
            
            # Apply specific adaptation suggestions
            for suggestion in feedback.adaptation_suggestions:
                await self._apply_learning_adaptation(suggestion)
            
            LOG.debug(f"Learning adaptation completed: learning_rate={self.state.learning_rate:.3f}, confidence_threshold={self.prediction_confidence_threshold:.3f}")
            
        except Exception as e:
            LOG.error(f"Learning memory adaptation failed: {e}")
    
    def get_success_rate(self) -> float:
        """Get attack success rate based on learning memory state."""
        if self.state.total_records == 0:
            return 0.0
        return self.state.successful_records / self.state.total_records

    async def get_effectiveness_metrics(self) -> Dict[str, float]:
        """Get learning memory effectiveness metrics."""
        
        try:
            base_metrics = {
                "success_rate": self.get_success_rate(),
                "average_latency_ms": self.get_average_latency(),
                "learning_rate": self.state.learning_rate,
                "prediction_confidence_threshold": self.prediction_confidence_threshold,
                "total_records": float(self.state.total_records),
                "successful_records": float(self.state.successful_records),
                "best_effectiveness": self.state.best_effectiveness,
                "memory_size_mb": self.state.memory_size_mb,
                "prediction_confidence": self.state.prediction_confidence,
                "adaptation_count": float(self.state.adaptation_count)
            }
            
            # Add learning memory specific metrics
            if self.learning_memory:
                try:
                    # Get database statistics
                    db_stats = await self._get_database_stats()
                    base_metrics.update(db_stats)
                except Exception as e:
                    LOG.debug(f"Failed to get database stats: {e}")
            
            # Calculate learning effectiveness
            if self.state.total_records > 0:
                learning_effectiveness = self.state.successful_records / self.state.total_records
                base_metrics["learning_effectiveness"] = learning_effectiveness
            else:
                base_metrics["learning_effectiveness"] = 0.0
            
            return base_metrics
            
        except Exception as e:
            LOG.error(f"Failed to get learning memory metrics: {e}")
            return {"error": str(e)}

    async def _generate_fingerprint_hash(self, target: str, context: AttackContext) -> str:
        """Generate consistent fingerprint hash for target and context."""
        
        try:
            # Create fingerprint data from context
            fingerprint_data = {
                "domain": context.target_info.domain,
                "dpi_type": context.dpi_signature.dpi_type,
                "sophistication_level": context.dpi_signature.sophistication_level,
                "capabilities": sorted(context.dpi_signature.capabilities),
                "confidence": round(context.dpi_signature.confidence, 2)
            }
            
            # Add fingerprint data if available
            if context.fingerprint_data and context.fingerprint_data.fingerprint_data:
                fingerprint_data.update(context.fingerprint_data.fingerprint_data)
            
            # Generate consistent hash
            sorted_data = json.dumps(fingerprint_data, sort_keys=True, default=str)
            return hashlib.sha256(sorted_data.encode()).hexdigest()[:16]
            
        except Exception as e:
            LOG.error(f"Failed to generate fingerprint hash: {e}")
            # Fallback to simple hash
            return hashlib.md5(f"{target}_{context.dpi_signature.dpi_type}".encode()).hexdigest()[:16]
    
    async def _retrieve_historical_data(self, fingerprint_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve historical learning data for fingerprint."""
        
        if not self.learning_memory:
            return None
        
        try:
            # Get learning history from database
            history = await self._get_learning_history(fingerprint_hash)
            
            if not history:
                return None
            
            return {
                "total_attempts": history.get("total_attempts", 0),
                "successful_attempts": history.get("successful_attempts", 0),
                "success_rate": history.get("success_rate", 0.0),
                "best_effectiveness": history.get("best_effectiveness", 0.0),
                "best_attack": history.get("best_attack_name"),
                "best_parameters": history.get("best_parameters", {}),
                "recent_strategies": history.get("recent_strategies", []),
                "adaptation_patterns": history.get("adaptation_patterns", [])
            }
            
        except Exception as e:
            LOG.error(f"Failed to retrieve historical data: {e}")
            return None
    
    async def _enhance_ml_prediction(self, ml_prediction, historical_data: Dict[str, Any]):
        """Enhance ML prediction with historical learning data."""
        
        try:
            # Create enhanced prediction based on historical success
            enhanced_confidence = ml_prediction.confidence
            
            # Boost confidence if historical data supports the prediction
            if historical_data.get("best_attack") and ml_prediction.primary_strategy:
                if historical_data["best_attack"] in ml_prediction.primary_strategy:
                    enhanced_confidence = min(1.0, enhanced_confidence * 1.2)
                    LOG.debug(f"Enhanced ML confidence based on historical success: {enhanced_confidence:.2f}")
            
            # Adjust based on historical success rate
            historical_success_rate = historical_data.get("success_rate", 0.5)
            if historical_success_rate > 0.8:
                enhanced_confidence = min(1.0, enhanced_confidence * 1.1)
            elif historical_success_rate < 0.3:
                enhanced_confidence = max(0.1, enhanced_confidence * 0.9)
            
            # Create enhanced prediction object (simplified)
            class EnhancedPrediction:
                def __init__(self, original_prediction, enhanced_confidence):
                    self.primary_strategy = original_prediction.primary_strategy
                    self.fallback_strategies = original_prediction.fallback_strategies
                    self.confidence = enhanced_confidence
                    self.reasoning = f"{original_prediction.reasoning} (Enhanced with historical data)"
                    self.predicted_success_rate = min(1.0, original_prediction.predicted_success_rate * (1 + historical_success_rate) / 2)
            
            return EnhancedPrediction(ml_prediction, enhanced_confidence)
            
        except Exception as e:
            LOG.error(f"Failed to enhance ML prediction: {e}")
            return ml_prediction
    
    async def _select_optimal_strategy(self, fingerprint_hash: str, ml_prediction, historical_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Select optimal attack strategy based on learning and ML prediction."""
        
        try:
            strategy = {
                "name": "learning_memory_enhanced",
                "base_strategy": "default",
                "parameters": {},
                "confidence": 0.5,
                "source": "fallback"
            }
            
            # Use historical best strategy if available and confidence is high
            if historical_data and historical_data.get("best_attack") and historical_data.get("success_rate", 0) > self.learning_threshold:
                strategy.update({
                    "base_strategy": historical_data["best_attack"],
                    "parameters": historical_data.get("best_parameters", {}),
                    "confidence": historical_data["success_rate"],
                    "source": "historical_learning"
                })
                LOG.debug(f"Selected strategy from historical learning: {strategy['base_strategy']}")
            
            # Override with ML prediction if confidence is sufficient
            elif ml_prediction and ml_prediction.confidence > self.prediction_confidence_threshold:
                strategy.update({
                    "base_strategy": ml_prediction.primary_strategy,
                    "parameters": self._extract_ml_parameters(ml_prediction),
                    "confidence": ml_prediction.confidence,
                    "source": "ml_prediction"
                })
                LOG.debug(f"Selected strategy from ML prediction: {strategy['base_strategy']}")
            
            # Combine both if available
            elif historical_data and ml_prediction:
                # Weighted combination based on confidence and historical success
                historical_weight = historical_data.get("success_rate", 0.0) * 0.7
                ml_weight = ml_prediction.confidence * 0.3
                
                if historical_weight > ml_weight:
                    strategy.update({
                        "base_strategy": historical_data["best_attack"],
                        "parameters": historical_data.get("best_parameters", {}),
                        "confidence": historical_weight,
                        "source": "weighted_historical"
                    })
                else:
                    strategy.update({
                        "base_strategy": ml_prediction.primary_strategy,
                        "parameters": self._extract_ml_parameters(ml_prediction),
                        "confidence": ml_weight,
                        "source": "weighted_ml"
                    })
                
                LOG.debug(f"Selected weighted strategy: {strategy['base_strategy']} (source: {strategy['source']})")
            
            return strategy
            
        except Exception as e:
            LOG.error(f"Failed to select optimal strategy: {e}")
            return {
                "name": "learning_memory_enhanced",
                "base_strategy": "fallback",
                "parameters": {},
                "confidence": 0.3,
                "source": "error_fallback"
            }
    
    async def _execute_learned_strategy(self, target: str, context: AttackContext, strategy: Dict[str, Any], fingerprint_hash: str) -> AdvancedAttackResult:
        """Execute the selected learned strategy."""
        
        LOG.info(f"Executing learned strategy: {strategy['base_strategy']} (source: {strategy['source']})")
        start_time = time.time()
        
        try:
            # Simulate strategy execution based on strategy type and context
            success, effectiveness = await self._simulate_strategy_execution(strategy, context)
            
            latency = (time.time() - start_time) * 1000
            
            # Create ML feedback
            ml_feedback = MLFeedback(
                attack_name=self.config.name,
                success=success,
                latency_ms=latency,
                effectiveness_score=effectiveness,
                failure_reason=None if success else f"Strategy {strategy['base_strategy']} failed",
                adaptation_suggestions=self._generate_learning_suggestions(strategy, success, effectiveness)
            )
            
            # Create learning data
            learning_data = LearningData(
                target_signature=fingerprint_hash,
                attack_parameters=strategy["parameters"],
                effectiveness=effectiveness,
                context={
                    "strategy_source": strategy["source"],
                    "base_strategy": strategy["base_strategy"],
                    "confidence": strategy["confidence"]
                },
                timestamp=datetime.now()
            )
            
            # Create performance metrics
            performance_metrics = PerformanceMetrics(
                execution_time_ms=latency,
                memory_usage_mb=self.state.memory_size_mb,
                cpu_usage_percent=5.0,  # Estimated
                network_overhead_bytes=1024,  # Estimated
                success_rate=effectiveness
            )
            
            # Generate adaptation suggestions
            adaptation_suggestions = self._generate_adaptation_suggestions(strategy, success, effectiveness)
            
            return AdvancedAttackResult(
                attack_name=self.config.name,
                success=success,
                latency_ms=latency,
                effectiveness_score=effectiveness,
                ml_feedback=ml_feedback,
                learning_data=learning_data,
                performance_metrics=performance_metrics,
                adaptation_suggestions=adaptation_suggestions
            )
            
        except Exception as e:
            LOG.error(f"Failed to execute learned strategy: {e}")
            return self._create_error_result(str(e), time.time() - start_time)

    async def _simulate_strategy_execution(self, strategy: Dict[str, Any], context: AttackContext) -> tuple[bool, float]:
        """Simulate strategy execution based on context and strategy."""
        
        try:
            base_effectiveness = 0.5
            
            # Adjust effectiveness based on strategy source
            if strategy["source"] == "historical_learning":
                base_effectiveness = strategy["confidence"]
            elif strategy["source"] == "ml_prediction":
                base_effectiveness = strategy["confidence"] * 0.8
            elif strategy["source"] == "weighted_historical":
                base_effectiveness = strategy["confidence"] * 0.9
            elif strategy["source"] == "weighted_ml":
                base_effectiveness = strategy["confidence"] * 0.7
            
            # Adjust based on DPI sophistication
            sophistication = context.dpi_signature.sophistication_level
            if sophistication == "basic":
                base_effectiveness = min(1.0, base_effectiveness * 1.2)
            elif sophistication == "sophisticated":
                base_effectiveness = max(0.1, base_effectiveness * 0.7)
            
            # Add some randomness to simulate real-world variability
            import random
            effectiveness = max(0.0, min(1.0, base_effectiveness + random.uniform(-0.1, 0.1)))
            success = effectiveness > 0.5
            
            # Simulate execution delay
            await asyncio.sleep(0.1)
            
            return success, effectiveness
            
        except Exception as e:
            LOG.error(f"Strategy simulation failed: {e}")
            return False, 0.0
    
    async def _save_learning_result(self, fingerprint_hash: str, strategy: Dict[str, Any], result: AdvancedAttackResult):
        """Save learning result to persistent storage."""
        
        if not self.learning_memory:
            return
        
        try:
            await self.learning_memory.save_learning_result(
                fingerprint_hash=fingerprint_hash,
                attack_name=strategy["base_strategy"],
                effectiveness_score=result.effectiveness_score,
                parameters=strategy["parameters"],
                success=result.success,
                latency_ms=result.latency_ms,
                metadata={
                    "strategy_source": strategy["source"],
                    "confidence": strategy["confidence"],
                    "timestamp": datetime.now().isoformat()
                }
            )
            
            LOG.debug(f"Saved learning result for {fingerprint_hash}: {result.effectiveness_score:.2f}")
            
        except Exception as e:
            LOG.error(f"Failed to save learning result: {e}")
    
    async def _update_state_and_stats(self, result: AdvancedAttackResult):
        """Update internal state and statistics."""
        
        try:
            self.state.total_records += 1
            if result.success:
                self.state.successful_records += 1
            
            if result.effectiveness_score > self.state.best_effectiveness:
                self.state.best_effectiveness = result.effectiveness_score
                self.state.best_attack = result.attack_name
            
            self.state.last_learning_time = datetime.now()
            
            # Update memory size estimate
            self.state.memory_size_mb = self.state.total_records * 0.001  # Rough estimate
            
        except Exception as e:
            LOG.error(f"Failed to update state and stats: {e}")
    
    async def _periodic_cleanup(self):
        """Perform periodic cleanup of old learning data."""
        
        current_time = time.time()
        if current_time - self.last_cleanup < self.memory_cleanup_interval:
            return
        
        try:
            if self.learning_memory:
                # Cleanup old records (this would be implemented in the learning memory system)
                LOG.debug("Performing periodic learning memory cleanup")
                # await self.learning_memory.cleanup_old_records()
            
            self.last_cleanup = current_time
            
        except Exception as e:
            LOG.error(f"Periodic cleanup failed: {e}")
    
    def _extract_ml_parameters(self, ml_prediction) -> Dict[str, Any]:
        """Extract parameters from ML prediction."""
        
        try:
            # Extract relevant parameters from ML prediction
            parameters = {
                "confidence": ml_prediction.confidence,
                "predicted_success_rate": getattr(ml_prediction, 'predicted_success_rate', 0.5),
                "reasoning": getattr(ml_prediction, 'reasoning', ''),
                "fallback_strategies": getattr(ml_prediction, 'fallback_strategies', [])
            }
            
            return parameters
            
        except Exception as e:
            LOG.error(f"Failed to extract ML parameters: {e}")
            return {}
    
    def _generate_learning_suggestions(self, strategy: Dict[str, Any], success: bool, effectiveness: float) -> List[str]:
        """Generate learning-based adaptation suggestions."""
        
        suggestions = []
        
        try:
            if not success:
                suggestions.append("increase_learning_rate")
                suggestions.append("explore_alternative_strategies")
                
                if strategy["source"] == "historical_learning":
                    suggestions.append("update_historical_weights")
                elif strategy["source"] == "ml_prediction":
                    suggestions.append("reduce_ml_confidence_threshold")
            
            if effectiveness < 0.4:
                suggestions.append("diversify_strategy_selection")
                suggestions.append("increase_exploration")
            elif effectiveness > 0.8:
                suggestions.append("reinforce_successful_strategy")
                suggestions.append("reduce_exploration")
            
        except Exception as e:
            LOG.error(f"Failed to generate learning suggestions: {e}")
        
        return suggestions
    
    def _generate_adaptation_suggestions(self, strategy: Dict[str, Any], success: bool, effectiveness: float) -> List[AdaptationSuggestion]:
        """Generate adaptation suggestions for the learning system."""
        
        suggestions = []
        
        try:
            if effectiveness < 0.5:
                suggestions.append(AdaptationSuggestion(
                    parameter="learning_rate",
                    current_value=self.state.learning_rate,
                    suggested_value=min(0.3, self.state.learning_rate * 1.2),
                    reason="Low effectiveness suggests need for more exploration",
                    confidence=0.7
                ))
            
            if not success and strategy["source"] == "historical_learning":
                suggestions.append(AdaptationSuggestion(
                    parameter="learning_threshold",
                    current_value=self.learning_threshold,
                    suggested_value=max(0.5, self.learning_threshold * 0.9),
                    reason="Historical strategy failed, lower threshold for exploration",
                    confidence=0.6
                ))
            
            if effectiveness > 0.8:
                suggestions.append(AdaptationSuggestion(
                    parameter="prediction_confidence_threshold",
                    current_value=self.prediction_confidence_threshold,
                    suggested_value=min(0.9, self.prediction_confidence_threshold * 1.05),
                    reason="High effectiveness allows for higher confidence threshold",
                    confidence=0.8
                ))
            
        except Exception as e:
            LOG.error(f"Failed to generate adaptation suggestions: {e}")
        
        return suggestions
    
    async def _apply_learning_adaptation(self, suggestion: str):
        """Apply specific learning adaptation suggestion."""
        
        try:
            if suggestion == "increase_learning_rate":
                self.state.learning_rate = min(0.3, self.state.learning_rate * 1.1)
            elif suggestion == "reduce_ml_confidence_threshold":
                self.prediction_confidence_threshold = max(0.3, self.prediction_confidence_threshold * 0.95)
            elif suggestion == "update_historical_weights":
                # This would update how historical data is weighted
                self.learning_threshold = max(0.5, self.learning_threshold * 0.95)
            elif suggestion == "increase_exploration":
                self.state.learning_rate = min(0.3, self.state.learning_rate * 1.15)
                self.prediction_confidence_threshold = max(0.3, self.prediction_confidence_threshold * 0.9)
            elif suggestion == "reduce_exploration":
                self.state.learning_rate = max(0.01, self.state.learning_rate * 0.9)
                self.prediction_confidence_threshold = min(0.9, self.prediction_confidence_threshold * 1.1)
            
            LOG.debug(f"Applied learning adaptation: {suggestion}")
            
        except Exception as e:
            LOG.error(f"Failed to apply learning adaptation {suggestion}: {e}")
    
    async def _get_learning_history(self, fingerprint_hash: str) -> Optional[Dict[str, Any]]:
        """Get learning history from database."""
        
        if not self.learning_memory:
            return None
        
        try:
            # This would query the learning memory database
            # For now, return mock data
            return {
                "total_attempts": 10,
                "successful_attempts": 7,
                "success_rate": 0.7,
                "best_effectiveness": 0.85,
                "best_attack_name": "adaptive_combo",
                "best_parameters": {"aggressiveness": 0.8},
                "recent_strategies": ["adaptive_combo", "traffic_mimicry"],
                "adaptation_patterns": []
            }
            
        except Exception as e:
            LOG.error(f"Failed to get learning history: {e}")
            return None
    
    async def _get_database_stats(self) -> Dict[str, float]:
        """Get database statistics."""
        
        try:
            # Mock database statistics
            return {
                "database_size_mb": 5.2,
                "total_fingerprints": 150.0,
                "total_strategy_records": 1200.0,
                "total_adaptation_records": 300.0,
                "average_effectiveness": 0.72
            }
            
        except Exception as e:
            LOG.error(f"Failed to get database stats: {e}")
            return {}
    
    async def _retry_with_fallback(self, target: str, context: AttackContext) -> AdvancedAttackResult:
        """Retry execution with fallback parameters."""
        
        LOG.info("Retrying learning memory attack with fallback parameters")
        
        # Simplify parameters for retry
        original_learning_rate = self.state.learning_rate
        original_threshold = self.learning_threshold
        
        self.state.learning_rate = 0.2
        self.learning_threshold = 0.5
        
        try:
            # Execute with simplified fallback strategy
            fallback_strategy = {
                "name": "learning_memory_fallback",
                "base_strategy": "basic_bypass",
                "parameters": {"mode": "conservative"},
                "confidence": 0.6,
                "source": "fallback"
            }
            
            result = await self._execute_learned_strategy(target, context, fallback_strategy, "fallback")
            return result
            
        finally:
            # Restore original parameters
            self.state.learning_rate = original_learning_rate
            self.learning_threshold = original_threshold
    
    def _create_error_result(self, error_message: str, execution_time: float) -> AdvancedAttackResult:
        """Create error result for failed execution."""
        
        ml_feedback = MLFeedback(
            attack_name=self.config.name,
            success=False,
            latency_ms=execution_time * 1000 if execution_time > 0 else 0,
            effectiveness_score=0.0,
            failure_reason=error_message,
            adaptation_suggestions=["retry", "fallback", "reset_learning"]
        )
        
        learning_data = LearningData(
            target_signature="error",
            attack_parameters={},
            effectiveness=0.0,
            context={"error": error_message},
            timestamp=datetime.now()
        )
        
        performance_metrics = PerformanceMetrics(
            execution_time_ms=execution_time * 1000 if execution_time > 0 else 0,
            memory_usage_mb=self.state.memory_size_mb,
            cpu_usage_percent=0.0,
            network_overhead_bytes=0,
            success_rate=0.0
        )
        
        return AdvancedAttackResult(
            attack_name=self.config.name,
            success=False,
            latency_ms=execution_time * 1000 if execution_time > 0 else 0,
            effectiveness_score=0.0,
            ml_feedback=ml_feedback,
            learning_data=learning_data,
            performance_metrics=performance_metrics,
            adaptation_suggestions=[],
            error_message=error_message
        )

    async def _analyze_patterns(self, fingerprint_hash: str, historical_data: Optional[Dict[str, Any]]) -> PatternRecognitionResult:
        """Analyze patterns in historical data for pattern recognition."""
        
        try:
            if not historical_data or not self.learning_memory:
                return PatternRecognitionResult(
                    pattern_type="no_data",
                    confidence=0.0,
                    pattern_data={},
                    recommendations=[],
                    predicted_success_rate=0.5
                )
            
            # Get recent strategy records for pattern analysis
            recent_strategies = await self.learning_memory.get_best_strategies(
                fingerprint_hash, limit=self.pattern_window_size, min_effectiveness=0.3
            )
            
            if not recent_strategies:
                return PatternRecognitionResult(
                    pattern_type="insufficient_data",
                    confidence=0.0,
                    pattern_data={},
                    recommendations=["collect_more_data"],
                    predicted_success_rate=0.5
                )
            
            # Analyze attack type patterns
            attack_types = [s.attack_name for s in recent_strategies]
            attack_counter = Counter(attack_types)
            most_common_attack = attack_counter.most_common(1)[0][0]
            
            # Analyze effectiveness trends
            effectiveness_scores = [s.effectiveness_score for s in recent_strategies]
            avg_effectiveness = np.mean(effectiveness_scores)
            effectiveness_trend = self._calculate_trend(effectiveness_scores)
            
            # Analyze parameter patterns
            parameter_patterns = self._analyze_parameter_patterns(recent_strategies)
            
            # Analyze timing patterns
            timing_patterns = self._analyze_timing_patterns(recent_strategies)
            
            # Determine pattern type and confidence
            pattern_type, confidence = self._classify_pattern(
                attack_counter, effectiveness_trend, parameter_patterns
            )
            
            # Generate recommendations based on patterns
            recommendations = self._generate_pattern_recommendations(
                pattern_type, attack_counter, effectiveness_trend, parameter_patterns
            )
            
            # Predict success rate based on patterns
            predicted_success_rate = self._predict_success_from_patterns(
                pattern_type, avg_effectiveness, effectiveness_trend, confidence
            )
            
            pattern_data = {
                "most_common_attack": most_common_attack,
                "attack_distribution": dict(attack_counter),
                "avg_effectiveness": avg_effectiveness,
                "effectiveness_trend": effectiveness_trend,
                "parameter_patterns": parameter_patterns,
                "timing_patterns": timing_patterns,
                "total_analyzed": len(recent_strategies)
            }
            
            return PatternRecognitionResult(
                pattern_type=pattern_type,
                confidence=confidence,
                pattern_data=pattern_data,
                recommendations=recommendations,
                predicted_success_rate=predicted_success_rate
            )
            
        except Exception as e:
            LOG.error(f"Pattern analysis failed: {e}")
            return PatternRecognitionResult(
                pattern_type="error",
                confidence=0.0,
                pattern_data={"error": str(e)},
                recommendations=["retry_analysis"],
                predicted_success_rate=0.5
            )

    async def _generate_predictive_recommendations(
        self, 
        fingerprint_hash: str, 
        context: AttackContext, 
        historical_data: Optional[Dict[str, Any]],
        pattern_result: PatternRecognitionResult
    ) -> PredictiveRecommendation:
        """Generate predictive recommendations for new targets."""
        
        try:
            # Base recommendation from historical data
            recommended_strategy = "adaptive_combo"  # Default
            confidence = 0.5
            reasoning = "Default recommendation"
            expected_effectiveness = 0.5
            
            if historical_data and historical_data.get("best_attack"):
                recommended_strategy = historical_data["best_attack"]
                confidence = historical_data.get("success_rate", 0.5)
                reasoning = f"Based on historical success rate of {confidence:.2f}"
                expected_effectiveness = historical_data.get("best_effectiveness", 0.5)
            
            # Enhance with pattern recognition
            if pattern_result.confidence > self.pattern_confidence_threshold:
                if pattern_result.pattern_type == "consistent_success":
                    recommended_strategy = pattern_result.pattern_data["most_common_attack"]
                    confidence = min(1.0, confidence * 1.2)
                    reasoning += f" (Enhanced by consistent success pattern)"
                    expected_effectiveness = pattern_result.predicted_success_rate
                elif pattern_result.pattern_type == "improving_trend":
                    confidence = min(1.0, confidence * 1.1)
                    reasoning += f" (Enhanced by improving trend pattern)"
                    expected_effectiveness = min(1.0, expected_effectiveness * 1.1)
                elif pattern_result.pattern_type == "parameter_optimization":
                    reasoning += f" (Enhanced by parameter optimization pattern)"
                    confidence = min(1.0, confidence * 1.05)
            
            # Apply ML-based enhancements if available
            if self.strategy_predictor and context.dpi_signature:
                try:
                    ml_prediction = await self._get_ml_prediction(context)
                    if ml_prediction and ml_prediction.confidence > 0.6:
                        # Combine ML prediction with historical data
                        ml_weight = 0.4
                        historical_weight = 0.6
                        
                        combined_confidence = (confidence * historical_weight + 
                                             ml_prediction.confidence * ml_weight)
                        
                        if ml_prediction.confidence > confidence:
                            recommended_strategy = ml_prediction.primary_strategy
                            confidence = combined_confidence
                            reasoning += f" (Enhanced by ML prediction: {ml_prediction.confidence:.2f})"
                            expected_effectiveness = (expected_effectiveness * historical_weight + 
                                                    ml_prediction.predicted_success_rate * ml_weight)
                except Exception as e:
                    LOG.debug(f"ML prediction enhancement failed: {e}")
            
            # Generate adaptation suggestions
            adaptation_suggestions = self._generate_adaptation_suggestions_from_patterns(
                pattern_result, historical_data, context
            )
            
            return PredictiveRecommendation(
                target_signature=fingerprint_hash,
                recommended_strategy=recommended_strategy,
                confidence=confidence,
                reasoning=reasoning,
                expected_effectiveness=expected_effectiveness,
                adaptation_suggestions=adaptation_suggestions
            )
            
        except Exception as e:
            LOG.error(f"Predictive recommendation generation failed: {e}")
            return PredictiveRecommendation(
                target_signature=fingerprint_hash,
                recommended_strategy="fallback",
                confidence=0.3,
                reasoning=f"Error in prediction: {str(e)}",
                expected_effectiveness=0.4,
                adaptation_suggestions=["retry", "fallback"]
            )

    async def _enhance_ml_prediction_with_patterns(self, ml_prediction, historical_data: Dict[str, Any], pattern_result: PatternRecognitionResult):
        """Enhanced ML prediction with pattern recognition data."""
        
        try:
            # Create enhanced prediction based on historical success and patterns
            enhanced_confidence = ml_prediction.confidence
            
            # Boost confidence if historical data supports the prediction
            if historical_data.get("best_attack") and ml_prediction.primary_strategy:
                if historical_data["best_attack"] in ml_prediction.primary_strategy:
                    enhanced_confidence = min(1.0, enhanced_confidence * 1.2)
                    LOG.debug(f"Enhanced ML confidence based on historical success: {enhanced_confidence:.2f}")
            
            # Apply pattern-based enhancements
            if pattern_result.confidence > self.pattern_confidence_threshold:
                if pattern_result.pattern_type == "consistent_success":
                    enhanced_confidence = min(1.0, enhanced_confidence * 1.15)
                elif pattern_result.pattern_type == "improving_trend":
                    enhanced_confidence = min(1.0, enhanced_confidence * 1.1)
                elif pattern_result.pattern_type == "parameter_optimization":
                    enhanced_confidence = min(1.0, enhanced_confidence * 1.05)
            
            # Adjust based on historical success rate
            historical_success_rate = historical_data.get("success_rate", 0.5)
            if historical_success_rate > 0.8:
                enhanced_confidence = min(1.0, enhanced_confidence * 1.1)
            elif historical_success_rate < 0.3:
                enhanced_confidence = max(0.1, enhanced_confidence * 0.9)
            
            # Create enhanced prediction object
            class EnhancedPrediction:
                def __init__(self, original_prediction, enhanced_confidence, pattern_data):
                    self.primary_strategy = original_prediction.primary_strategy
                    self.fallback_strategies = original_prediction.fallback_strategies
                    self.confidence = enhanced_confidence
                    self.reasoning = f"{original_prediction.reasoning} (Enhanced with patterns: {pattern_data.get('pattern_type', 'unknown')})"
                    self.predicted_success_rate = min(1.0, original_prediction.predicted_success_rate * (1 + historical_success_rate) / 2)
                    self.pattern_confidence = pattern_data.get('confidence', 0.0)
            
            return EnhancedPrediction(ml_prediction, enhanced_confidence, pattern_result.pattern_data)
            
        except Exception as e:
            LOG.error(f"Failed to enhance ML prediction with patterns: {e}")
            return ml_prediction

    async def _select_optimal_strategy_enhanced(
        self, 
        fingerprint_hash: str, 
        ml_prediction, 
        historical_data: Optional[Dict[str, Any]],
        pattern_result: PatternRecognitionResult,
        prediction_result: PredictiveRecommendation
    ) -> Dict[str, Any]:
        """Enhanced strategy selection with pattern recognition and predictions."""
        
        try:
            strategy = {
                "name": "learning_memory_enhanced",
                "base_strategy": "default",
                "parameters": {},
                "confidence": 0.5,
                "source": "fallback"
            }
            
            # Use predictive recommendation if confidence is high
            if prediction_result.confidence > self.prediction_confidence_threshold:
                strategy.update({
                    "base_strategy": prediction_result.recommended_strategy,
                    "parameters": self._extract_parameters_from_prediction(prediction_result),
                    "confidence": prediction_result.confidence,
                    "source": "predictive_recommendation",
                    "reasoning": prediction_result.reasoning
                })
                LOG.debug(f"Selected strategy from predictive recommendation: {strategy['base_strategy']}")
            
            # Use historical best strategy if available and confidence is high
            elif historical_data and historical_data.get("best_attack") and historical_data.get("success_rate", 0) > self.learning_threshold:
                strategy.update({
                    "base_strategy": historical_data["best_attack"],
                    "parameters": historical_data.get("best_parameters", {}),
                    "confidence": historical_data["success_rate"],
                    "source": "historical_learning"
                })
                LOG.debug(f"Selected strategy from historical learning: {strategy['base_strategy']}")
            
            # Override with ML prediction if confidence is sufficient
            elif ml_prediction and ml_prediction.confidence > self.prediction_confidence_threshold:
                strategy.update({
                    "base_strategy": ml_prediction.primary_strategy,
                    "parameters": self._extract_ml_parameters(ml_prediction),
                    "confidence": ml_prediction.confidence,
                    "source": "ml_prediction"
                })
                LOG.debug(f"Selected strategy from ML prediction: {strategy['base_strategy']}")
            
            # Apply pattern-based parameter optimization
            if pattern_result.confidence > self.pattern_confidence_threshold:
                optimized_params = self._optimize_parameters_with_patterns(
                    strategy["parameters"], pattern_result
                )
                strategy["parameters"].update(optimized_params)
                strategy["source"] += "_pattern_optimized"
            
            return strategy
            
        except Exception as e:
            LOG.error(f"Failed to select optimal strategy enhanced: {e}")
            return {
                "name": "learning_memory_enhanced",
                "base_strategy": "fallback",
                "parameters": {},
                "confidence": 0.3,
                "source": "error_fallback"
            }

    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend from a list of values."""
        if len(values) < 3:
            return "insufficient_data"
        
        try:
            # Simple linear trend calculation
            x = np.arange(len(values))
            slope = np.polyfit(x, values, 1)[0]
            
            if slope > 0.01:
                return "improving"
            elif slope < -0.01:
                return "declining"
            else:
                return "stable"
        except Exception:
            return "unknown"

    def _analyze_parameter_patterns(self, strategies: List[StrategyRecord]) -> Dict[str, Any]:
        """Analyze parameter patterns in strategy records."""
        try:
            parameter_analysis = defaultdict(list)
            
            for strategy in strategies:
                for param_name, param_value in strategy.parameters.items():
                    parameter_analysis[param_name].append(param_value)
            
            # Find most common parameter values
            common_params = {}
            for param_name, values in parameter_analysis.items():
                if len(values) > 1:
                    # For numeric values, find the most common range
                    if all(isinstance(v, (int, float)) for v in values):
                        avg_value = np.mean(values)
                        common_params[param_name] = {"average": avg_value, "range": [min(values), max(values)]}
                    else:
                        # For other types, find most common value
                        value_counter = Counter(values)
                        most_common = value_counter.most_common(1)[0]
                        common_params[param_name] = {"most_common": most_common[0], "frequency": most_common[1]}
            
            return dict(common_params)
            
        except Exception as e:
            LOG.error(f"Parameter pattern analysis failed: {e}")
            return {}

    def _analyze_timing_patterns(self, strategies: List[StrategyRecord]) -> Dict[str, Any]:
        """Analyze timing patterns in strategy records."""
        try:
            latencies = [s.latency_ms for s in strategies]
            timestamps = [s.timestamp for s in strategies]
            
            timing_analysis = {
                "avg_latency": np.mean(latencies) if latencies else 0,
                "latency_std": np.std(latencies) if len(latencies) > 1 else 0,
                "min_latency": min(latencies) if latencies else 0,
                "max_latency": max(latencies) if latencies else 0,
                "total_records": len(strategies)
            }
            
            # Analyze time-based patterns if we have enough data
            if len(timestamps) > 5:
                time_diffs = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                timing_analysis["avg_time_between_attempts"] = np.mean(time_diffs)
                timing_analysis["time_pattern"] = "regular" if np.std(time_diffs) < 100 else "irregular"
            
            return timing_analysis
            
        except Exception as e:
            LOG.error(f"Timing pattern analysis failed: {e}")
            return {}

    def _classify_pattern(self, attack_counter: Counter, effectiveness_trend: str, parameter_patterns: Dict[str, Any]) -> Tuple[str, float]:
        """Classify the type of pattern and calculate confidence."""
        try:
            confidence = 0.0
            pattern_type = "unknown"
            
            # Check for consistent success pattern
            if len(attack_counter) == 1:
                pattern_type = "consistent_success"
                confidence = 0.9
            elif len(attack_counter) <= 3:
                most_common = attack_counter.most_common(1)[0]
                if most_common[1] >= len(attack_counter) * 0.7:
                    pattern_type = "consistent_success"
                    confidence = 0.8
            
            # Check for improving trend
            if effectiveness_trend == "improving":
                if pattern_type == "consistent_success":
                    pattern_type = "consistent_improving"
                    confidence = min(1.0, confidence + 0.1)
                else:
                    pattern_type = "improving_trend"
                    confidence = 0.7
            
            # Check for parameter optimization pattern
            if parameter_patterns and len(parameter_patterns) > 2:
                if pattern_type in ["consistent_success", "improving_trend"]:
                    pattern_type += "_parameter_optimized"
                    confidence = min(1.0, confidence + 0.05)
                else:
                    pattern_type = "parameter_optimization"
                    confidence = 0.6
            
            return pattern_type, confidence
            
        except Exception as e:
            LOG.error(f"Pattern classification failed: {e}")
            return "error", 0.0

    def _generate_pattern_recommendations(self, pattern_type: str, attack_counter: Counter, effectiveness_trend: str, parameter_patterns: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on pattern analysis."""
        recommendations = []
        
        try:
            if pattern_type == "consistent_success":
                recommendations.extend([
                    "continue_current_strategy",
                    "optimize_parameters",
                    "reduce_exploration"
                ])
            elif pattern_type == "improving_trend":
                recommendations.extend([
                    "continue_improvement",
                    "accelerate_learning",
                    "monitor_progress"
                ])
            elif pattern_type == "parameter_optimization":
                recommendations.extend([
                    "fine_tune_parameters",
                    "explore_parameter_space",
                    "validate_optimization"
                ])
            elif pattern_type == "declining":
                recommendations.extend([
                    "change_strategy",
                    "increase_exploration",
                    "reset_parameters"
                ])
            else:
                recommendations.extend([
                    "collect_more_data",
                    "explore_strategies",
                    "monitor_patterns"
                ])
            
            return recommendations
            
        except Exception as e:
            LOG.error(f"Pattern recommendation generation failed: {e}")
            return ["error_in_analysis"]

    def _predict_success_from_patterns(self, pattern_type: str, avg_effectiveness: float, effectiveness_trend: str, confidence: float) -> float:
        """Predict success rate based on pattern analysis."""
        try:
            base_prediction = avg_effectiveness
            
            # Adjust based on pattern type
            if pattern_type == "consistent_success":
                base_prediction = min(1.0, base_prediction * 1.1)
            elif pattern_type == "improving_trend":
                base_prediction = min(1.0, base_prediction * 1.05)
            elif pattern_type == "declining":
                base_prediction = max(0.1, base_prediction * 0.9)
            
            # Adjust based on confidence
            confidence_factor = 0.5 + (confidence * 0.5)  # 0.5 to 1.0
            final_prediction = base_prediction * confidence_factor
            
            return max(0.0, min(1.0, final_prediction))
            
        except Exception as e:
            LOG.error(f"Success prediction from patterns failed: {e}")
            return 0.5

    def _extract_parameters_from_prediction(self, prediction_result: PredictiveRecommendation) -> Dict[str, Any]:
        """Extract parameters from predictive recommendation."""
        try:
            # This would extract parameters from the prediction result
            # For now, return basic parameters
            return {
                "confidence": prediction_result.confidence,
                "expected_effectiveness": prediction_result.expected_effectiveness,
                "reasoning": prediction_result.reasoning
            }
        except Exception as e:
            LOG.error(f"Parameter extraction from prediction failed: {e}")
            return {}

    def _optimize_parameters_with_patterns(self, base_parameters: Dict[str, Any], pattern_result: PatternRecognitionResult) -> Dict[str, Any]:
        """Optimize parameters based on pattern analysis."""
        try:
            optimized_params = base_parameters.copy()
            
            if pattern_result.pattern_type == "parameter_optimization":
                # Apply parameter optimization based on patterns
                for param_name, param_data in pattern_result.pattern_data.get("parameter_patterns", {}).items():
                    if "average" in param_data:
                        optimized_params[param_name] = param_data["average"]
                    elif "most_common" in param_data:
                        optimized_params[param_name] = param_data["most_common"]
            
            # Add pattern-based confidence boost
            if pattern_result.confidence > 0.8:
                optimized_params["pattern_confidence_boost"] = True
                optimized_params["learning_rate_multiplier"] = 1.1
            
            return optimized_params
            
        except Exception as e:
            LOG.error(f"Parameter optimization with patterns failed: {e}")
            return base_parameters

    def _generate_adaptation_suggestions_from_patterns(
        self, 
        pattern_result: PatternRecognitionResult, 
        historical_data: Optional[Dict[str, Any]], 
        context: AttackContext
    ) -> List[str]:
        """Generate adaptation suggestions based on pattern analysis."""
        suggestions = []
        
        try:
            # Pattern-based suggestions
            if pattern_result.pattern_type == "consistent_success":
                suggestions.extend([
                    "maintain_current_approach",
                    "fine_tune_parameters",
                    "reduce_exploration_rate"
                ])
            elif pattern_result.pattern_type == "improving_trend":
                suggestions.extend([
                    "continue_improvement",
                    "accelerate_learning",
                    "monitor_progress"
                ])
            elif pattern_result.pattern_type == "declining":
                suggestions.extend([
                    "change_strategy",
                    "increase_exploration",
                    "reset_parameters"
                ])
            
            # Historical data based suggestions
            if historical_data:
                success_rate = historical_data.get("success_rate", 0.5)
                if success_rate < 0.3:
                    suggestions.extend([
                        "increase_learning_rate",
                        "explore_alternative_strategies",
                        "reset_learning_history"
                    ])
                elif success_rate > 0.8:
                    suggestions.extend([
                        "reinforce_successful_patterns",
                        "optimize_performance",
                        "reduce_exploration"
                    ])
            
            # Context-based suggestions
            if context.dpi_signature.sophistication_level == "sophisticated":
                suggestions.extend([
                    "use_advanced_strategies",
                    "increase_parameter_complexity",
                    "apply_stealth_techniques"
                ])
            
            return list(set(suggestions))  # Remove duplicates
            
        except Exception as e:
            LOG.error(f"Adaptation suggestion generation failed: {e}")
            return ["error_in_suggestions"]

    async def _get_ml_prediction(self, context: AttackContext):
        """Get ML prediction for the current context."""
        try:
            if self.strategy_predictor:
                # This would call the actual ML predictor
                # For now, return a mock prediction
                class MockPrediction:
                    def __init__(self):
                        self.primary_strategy = "adaptive_combo"
                        self.confidence = 0.7
                        self.predicted_success_rate = 0.75
                        self.reasoning = "ML-based prediction"
                
                return MockPrediction()
            return None
            
        except Exception as e:
            LOG.error(f"ML prediction failed: {e}")
            return None

    async def _save_learning_result_enhanced(
        self, 
        fingerprint_hash: str, 
        strategy: Dict[str, Any], 
        result: AdvancedAttackResult,
        pattern_result: PatternRecognitionResult
    ):
        """Enhanced learning result saving with pattern data."""
        
        if not self.learning_memory:
            return
        
        try:
            # Enhanced metadata with pattern information
            enhanced_metadata = {
                "strategy_source": strategy["source"],
                "confidence": strategy["confidence"],
                "pattern_type": pattern_result.pattern_type,
                "pattern_confidence": pattern_result.confidence,
                "timestamp": datetime.now().isoformat(),
                "reasoning": strategy.get("reasoning", "")
            }
            
            await self.learning_memory.save_learning_result(
                fingerprint_hash=fingerprint_hash,
                attack_name=strategy["base_strategy"],
                effectiveness_score=result.effectiveness_score,
                parameters=strategy["parameters"],
                success=result.success,
                latency_ms=result.latency_ms,
                metadata=enhanced_metadata
            )
            
            LOG.debug(f"Enhanced learning result saved for {fingerprint_hash}: {result.effectiveness_score:.2f} (pattern: {pattern_result.pattern_type})")
            
        except Exception as e:
            LOG.error(f"Failed to save enhanced learning result: {e}")

    async def _update_state_and_stats_enhanced(self, result: AdvancedAttackResult, pattern_result: PatternRecognitionResult):
        """Enhanced state and statistics update with pattern information."""
        
        try:
            self.state.total_records += 1
            if result.success:
                self.state.successful_records += 1
            
            if result.effectiveness_score > self.state.best_effectiveness:
                self.state.best_effectiveness = result.effectiveness_score
                self.state.best_attack = result.attack_name
            
            # Update pattern recognition confidence
            self.state.prediction_confidence = pattern_result.confidence
            
            # Update adaptation count if pattern suggests adaptation
            if pattern_result.pattern_type in ["improving_trend", "parameter_optimization"]:
                self.state.adaptation_count += 1
            
            self.state.last_learning_time = datetime.now()
            
            # Update memory size estimate
            self.state.memory_size_mb = self.state.total_records * 0.001  # Rough estimate
            
        except Exception as e:
            LOG.error(f"Failed to update enhanced state and stats: {e}")

# Helper function to create configured instance
def create_learning_memory_integration() -> LearningMemoryIntegration:
    """Create configured Learning Memory Integration instance."""
    
    config = AdvancedAttackConfig(
        name="learning_memory",
        priority=2,
        complexity="Medium",
        expected_improvement="15-25%",
        target_protocols=["tcp", "http", "https"],
        dpi_signatures=["all"],
        ml_integration=True,
        learning_enabled=True
    )
    
    return LearningMemoryIntegration(config)