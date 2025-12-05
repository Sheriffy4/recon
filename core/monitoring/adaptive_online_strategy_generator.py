"""
Adaptive Online Strategy Generator

Реализует генерацию стратегий на основе анализа живого трафика,
систему быстрой адаптации к изменениям в DPI, машинное обучение
для предсказания эффективных стратегий, A/B тестирование стратегий
в реальном времени и систему обратной связи для улучшения алгоритмов.
"""

import asyncio
import logging
import time
import json
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
import numpy as np
from pathlib import Path

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    RandomForestClassifier = None
    StandardScaler = None

from .real_time_traffic_analyzer import BlockingEvent, BlockingType


class StrategyType(Enum):
    """Типы стратегий обхода"""
    TCP_FRAGMENTATION = "tcp_fragmentation"
    SNI_OBFUSCATION = "sni_obfuscation"
    FAKE_PACKETS = "fake_packets"
    PACKET_REORDERING = "packet_reordering"
    TTL_MANIPULATION = "ttl_manipulation"
    TIMING_ATTACKS = "timing_attacks"
    COMBINED = "combined"


@dataclass
class StrategyCandidate:
    """Кандидат стратегии для тестирования"""
    id: str
    strategy_type: StrategyType
    parameters: Dict[str, Any]
    predicted_success_rate: float
    confidence: float
    generation_method: str
    created_at: float = field(default_factory=time.time)
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'strategy_type': self.strategy_type.value,
            'parameters': self.parameters,
            'predicted_success_rate': self.predicted_success_rate,
            'confidence': self.confidence,
            'generation_method': self.generation_method,
            'created_at': self.created_at,
            'test_results': self.test_results
        }


@dataclass
class ABTestResult:
    """Результат A/B тестирования стратегии"""
    strategy_id: str
    domain: str
    success: bool
    response_time_ms: float
    error_message: Optional[str]
    timestamp: float
    test_group: str  # 'A' or 'B'
    metadata: Dict[str, Any] = field(default_factory=dict)


class OnlineMLPredictor:
    """Предиктор эффективности стратегий на основе машинного обучения"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.OnlineMLPredictor")
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.training_data = []
        self.is_trained = False
        
        if not SKLEARN_AVAILABLE:
            self.logger.warning("scikit-learn not available, ML predictions disabled")
    
    def extract_features(self, blocking_event: BlockingEvent, 
                        domain_history: Dict[str, Any]) -> List[float]:
        """Извлекает признаки для ML модели"""
        features = []
        
        # Признаки блокировки
        features.append(float(blocking_event.blocking_type == BlockingType.TCP_RST_BLOCKING))
        features.append(float(blocking_event.blocking_type == BlockingType.SNI_BLOCKING))
        features.append(float(blocking_event.blocking_type == BlockingType.TLS_HANDSHAKE_BLOCKING))
        features.append(blocking_event.confidence)
        
        # Признаки соединения
        details = blocking_event.details
        features.append(details.get('connection_duration', 0.0))
        features.append(float(details.get('packets_sent', 0)))
        features.append(float(details.get('packets_received', 0)))
        features.append(float(details.get('rst_received', False)))
        
        # Исторические признаки домена
        features.append(domain_history.get('total_attempts', 0))
        features.append(domain_history.get('success_rate', 0.0))
        features.append(domain_history.get('avg_response_time', 0.0))
        features.append(domain_history.get('last_success_hours_ago', 999.0))
        
        # Временные признаки
        hour_of_day = datetime.fromtimestamp(blocking_event.timestamp).hour
        features.append(hour_of_day / 24.0)  # Нормализуем
        
        return features
    
    def add_training_sample(self, features: List[float], strategy_type: StrategyType, 
                          success: bool):
        """Добавляет образец для обучения"""
        if not SKLEARN_AVAILABLE:
            return
        
        # Кодируем тип стратегии
        strategy_encoding = [0.0] * len(StrategyType)
        strategy_encoding[list(StrategyType).index(strategy_type)] = 1.0
        
        full_features = features + strategy_encoding
        self.training_data.append((full_features, float(success)))
        
        # Переобучаем модель если накопилось достаточно данных
        if len(self.training_data) >= 50 and len(self.training_data) % 10 == 0:
            self._retrain_model()
    
    def predict_success_rate(self, features: List[float], 
                           strategy_type: StrategyType) -> Tuple[float, float]:
        """Предсказывает вероятность успеха стратегии"""
        if not SKLEARN_AVAILABLE or not self.is_trained:
            # Возвращаем базовые эвристики
            base_rates = {
                StrategyType.TCP_FRAGMENTATION: 0.7,
                StrategyType.SNI_OBFUSCATION: 0.6,
                StrategyType.FAKE_PACKETS: 0.5,
                StrategyType.PACKET_REORDERING: 0.4,
                StrategyType.TTL_MANIPULATION: 0.3,
                StrategyType.TIMING_ATTACKS: 0.2,
                StrategyType.COMBINED: 0.8
            }
            return base_rates.get(strategy_type, 0.5), 0.3
        
        try:
            # Кодируем тип стратегии
            strategy_encoding = [0.0] * len(StrategyType)
            strategy_encoding[list(StrategyType).index(strategy_type)] = 1.0
            
            full_features = features + strategy_encoding
            full_features = np.array(full_features).reshape(1, -1)
            
            # Нормализуем признаки
            if self.scaler:
                full_features = self.scaler.transform(full_features)
            
            # Получаем предсказание
            prediction = self.model.predict_proba(full_features)[0]
            success_prob = prediction[1] if len(prediction) > 1 else prediction[0]
            
            # Оценка уверенности на основе количества деревьев
            confidence = min(0.9, len(self.training_data) / 200.0)
            
            return float(success_prob), float(confidence)
            
        except Exception as e:
            self.logger.error(f"Error in ML prediction: {e}")
            return 0.5, 0.1
    
    def _retrain_model(self):
        """Переобучает ML модель"""
        if not SKLEARN_AVAILABLE or len(self.training_data) < 10:
            return
        
        try:
            X = np.array([sample[0] for sample in self.training_data])
            y = np.array([sample[1] for sample in self.training_data])
            
            # Инициализируем модель и скейлер
            if self.model is None:
                self.model = RandomForestClassifier(
                    n_estimators=50,
                    max_depth=10,
                    random_state=42
                )
                self.scaler = StandardScaler()
            
            # Нормализуем признаки
            X_scaled = self.scaler.fit_transform(X)
            
            # Обучаем модель
            self.model.fit(X_scaled, y)
            self.is_trained = True
            
            self.logger.info(f"ML model retrained with {len(self.training_data)} samples")
            
        except Exception as e:
            self.logger.error(f"Error retraining ML model: {e}")


class ABTestManager:
    """Менеджер A/B тестирования стратегий"""
    
    def __init__(self, test_ratio: float = 0.2):
        self.test_ratio = test_ratio  # Доля трафика для тестирования новых стратегий
        self.logger = logging.getLogger(f"{__name__}.ABTestManager")
        self.active_tests: Dict[str, Dict[str, Any]] = {}  # domain -> test_info
        self.test_results: deque = deque(maxlen=1000)
        self.strategy_performance: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {'success_count': 0, 'total_count': 0, 'avg_response_time': 0.0}
        )
    
    def should_test_new_strategy(self, domain: str) -> bool:
        """Определяет, следует ли тестировать новую стратегию для домена"""
        # Простая логика: тестируем с заданной вероятностью
        return random.random() < self.test_ratio
    
    def start_ab_test(self, domain: str, strategy_a: StrategyCandidate, 
                     strategy_b: StrategyCandidate, duration_minutes: int = 30):
        """Запускает A/B тест между двумя стратегиями"""
        test_info = {
            'strategy_a': strategy_a,
            'strategy_b': strategy_b,
            'start_time': time.time(),
            'end_time': time.time() + (duration_minutes * 60),
            'results_a': [],
            'results_b': []
        }
        
        self.active_tests[domain] = test_info
        self.logger.info(f"Started A/B test for {domain}: {strategy_a.id} vs {strategy_b.id}")
    
    def get_test_strategy(self, domain: str) -> Optional[Tuple[StrategyCandidate, str]]:
        """Возвращает стратегию для тестирования и группу теста"""
        if domain not in self.active_tests:
            return None
        
        test_info = self.active_tests[domain]
        
        # Проверяем, не истек ли тест
        if time.time() > test_info['end_time']:
            self._finalize_test(domain)
            return None
        
        # Выбираем группу случайно
        group = 'A' if random.random() < 0.5 else 'B'
        strategy = test_info['strategy_a'] if group == 'A' else test_info['strategy_b']
        
        return strategy, group
    
    def record_test_result(self, domain: str, result: ABTestResult):
        """Записывает результат A/B теста"""
        if domain not in self.active_tests:
            return
        
        test_info = self.active_tests[domain]
        
        if result.test_group == 'A':
            test_info['results_a'].append(result)
        else:
            test_info['results_b'].append(result)
        
        self.test_results.append(result)
        
        # Обновляем общую статистику стратегии
        strategy_id = result.strategy_id
        perf = self.strategy_performance[strategy_id]
        perf['total_count'] += 1
        if result.success:
            perf['success_count'] += 1
        
        # Обновляем среднее время ответа
        old_avg = perf['avg_response_time']
        new_avg = (old_avg * (perf['total_count'] - 1) + result.response_time_ms) / perf['total_count']
        perf['avg_response_time'] = new_avg
    
    def _finalize_test(self, domain: str):
        """Завершает A/B тест и определяет победителя"""
        if domain not in self.active_tests:
            return
        
        test_info = self.active_tests[domain]
        results_a = test_info['results_a']
        results_b = test_info['results_b']
        
        if not results_a or not results_b:
            self.logger.warning(f"A/B test for {domain} completed with insufficient data")
            del self.active_tests[domain]
            return
        
        # Вычисляем метрики
        success_rate_a = sum(1 for r in results_a if r.success) / len(results_a)
        success_rate_b = sum(1 for r in results_b if r.success) / len(results_b)
        
        avg_time_a = sum(r.response_time_ms for r in results_a) / len(results_a)
        avg_time_b = sum(r.response_time_ms for r in results_b) / len(results_b)
        
        # Определяем победителя
        winner = 'A' if success_rate_a > success_rate_b else 'B'
        winner_strategy = test_info['strategy_a'] if winner == 'A' else test_info['strategy_b']
        
        self.logger.info(
            f"A/B test completed for {domain}. Winner: Strategy {winner} "
            f"(success rate: {success_rate_a:.2f} vs {success_rate_b:.2f})"
        )
        
        del self.active_tests[domain]
        return winner_strategy
    
    def get_strategy_performance(self, strategy_id: str) -> Dict[str, float]:
        """Возвращает статистику производительности стратегии"""
        perf = self.strategy_performance[strategy_id]
        success_rate = perf['success_count'] / max(1, perf['total_count'])
        
        return {
            'success_rate': success_rate,
            'total_tests': perf['total_count'],
            'avg_response_time_ms': perf['avg_response_time']
        }
cl
ass FeedbackSystem:
    """Система обратной связи для улучшения алгоритмов"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.FeedbackSystem")
        self.feedback_data = deque(maxlen=5000)
        self.strategy_adjustments = defaultdict(dict)
        self.domain_patterns = defaultdict(dict)
        
    def record_feedback(self, strategy_id: str, domain: str, success: bool, 
                       response_time_ms: float, error_details: Optional[str] = None):
        """Записывает обратную связь о результате применения стратегии"""
        feedback = {
            'timestamp': time.time(),
            'strategy_id': strategy_id,
            'domain': domain,
            'success': success,
            'response_time_ms': response_time_ms,
            'error_details': error_details
        }
        
        self.feedback_data.append(feedback)
        self._update_patterns(feedback)
    
    def _update_patterns(self, feedback: Dict[str, Any]):
        """Обновляет паттерны на основе обратной связи"""
        domain = feedback['domain']
        strategy_id = feedback['strategy_id']
        
        # Обновляем паттерны домена
        domain_pattern = self.domain_patterns[domain]
        if 'successful_strategies' not in domain_pattern:
            domain_pattern['successful_strategies'] = set()
            domain_pattern['failed_strategies'] = set()
        
        if feedback['success']:
            domain_pattern['successful_strategies'].add(strategy_id)
        else:
            domain_pattern['failed_strategies'].add(strategy_id)
        
        # Обновляем корректировки стратегий
        if not feedback['success'] and feedback['error_details']:
            adjustments = self.strategy_adjustments[strategy_id]
            error = feedback['error_details']
            
            if 'timeout' in error.lower():
                adjustments['increase_timeout'] = adjustments.get('increase_timeout', 0) + 1
            elif 'rst' in error.lower():
                adjustments['use_fake_packets'] = adjustments.get('use_fake_packets', 0) + 1
            elif 'handshake' in error.lower():
                adjustments['fragment_tls'] = adjustments.get('fragment_tls', 0) + 1
    
    def get_domain_recommendations(self, domain: str) -> Dict[str, Any]:
        """Возвращает рекомендации для домена на основе истории"""
        pattern = self.domain_patterns.get(domain, {})
        
        successful = pattern.get('successful_strategies', set())
        failed = pattern.get('failed_strategies', set())
        
        return {
            'recommended_strategies': list(successful),
            'avoid_strategies': list(failed),
            'confidence': len(successful) / max(1, len(successful) + len(failed))
        }
    
    def get_strategy_adjustments(self, strategy_id: str) -> Dict[str, Any]:
        """Возвращает рекомендуемые корректировки для стратегии"""
        adjustments = self.strategy_adjustments.get(strategy_id, {})
        
        recommendations = {}
        for adjustment, count in adjustments.items():
            if count >= 3:  # Порог для применения корректировки
                recommendations[adjustment] = count
        
        return recommendations


class AdaptiveOnlineStrategyGenerator:
    """Основной класс адаптивного генератора стратегий для онлайн анализа"""
    
    def __init__(self, strategy_cache_file: str = "online_strategies_cache.json"):
        self.logger = logging.getLogger(f"{__name__}.AdaptiveOnlineStrategyGenerator")
        self.strategy_cache_file = Path(strategy_cache_file)
        
        # Компоненты системы
        self.ml_predictor = OnlineMLPredictor()
        self.ab_test_manager = ABTestManager()
        self.feedback_system = FeedbackSystem()
        
        # Кэш стратегий и история
        self.strategy_cache: Dict[str, StrategyCandidate] = {}
        self.domain_history: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.generation_stats = {
            'total_generated': 0,
            'successful_predictions': 0,
            'failed_predictions': 0,
            'ab_tests_completed': 0
        }
        
        # Загружаем кэш
        self._load_strategy_cache()
    
    def generate_strategies_for_blocking(self, blocking_event: BlockingEvent, 
                                       count: int = 3) -> List[StrategyCandidate]:
        """Генерирует стратегии на основе события блокировки"""
        domain = blocking_event.domain
        blocking_type = blocking_event.blocking_type
        
        self.logger.info(f"Generating {count} strategies for {domain} ({blocking_type.value})")
        
        # Получаем историю домена
        domain_hist = self.domain_history[domain]
        
        # Извлекаем признаки для ML
        features = self.ml_predictor.extract_features(blocking_event, domain_hist)
        
        # Генерируем кандидатов стратегий
        candidates = []
        
        # 1. Стратегии на основе типа блокировки
        type_based_strategies = self._generate_type_based_strategies(blocking_type)
        
        # 2. ML-предсказанные стратегии
        ml_strategies = self._generate_ml_predicted_strategies(features, blocking_event)
        
        # 3. Стратегии на основе обратной связи
        feedback_strategies = self._generate_feedback_based_strategies(domain)
        
        # Объединяем и ранжируем
        all_strategies = type_based_strategies + ml_strategies + feedback_strategies
        
        # Ранжируем по предсказанной эффективности
        all_strategies.sort(key=lambda s: s.predicted_success_rate, reverse=True)
        
        # Возвращаем топ-N уникальных стратегий
        unique_strategies = []
        seen_params = set()
        
        for strategy in all_strategies:
            param_key = json.dumps(strategy.parameters, sort_keys=True)
            if param_key not in seen_params and len(unique_strategies) < count:
                unique_strategies.append(strategy)
                seen_params.add(param_key)
        
        # Сохраняем в кэш
        for strategy in unique_strategies:
            self.strategy_cache[strategy.id] = strategy
        
        self.generation_stats['total_generated'] += len(unique_strategies)
        self._save_strategy_cache()
        
        return unique_strategies
    
    def _generate_type_based_strategies(self, blocking_type: BlockingType) -> List[StrategyCandidate]:
        """Генерирует стратегии на основе типа блокировки"""
        strategies = []
        
        if blocking_type == BlockingType.TCP_RST_BLOCKING:
            # Стратегии против RST инъекций
            strategies.extend([
                self._create_strategy_candidate(
                    StrategyType.FAKE_PACKETS,
                    {'fake_count': 2, 'ttl': 1, 'checksum': 'bad'},
                    0.8, 0.7, "rst_blocking_heuristic"
                ),
                self._create_strategy_candidate(
                    StrategyType.TTL_MANIPULATION,
                    {'ttl': 2, 'position': 'before_payload'},
                    0.7, 0.6, "rst_blocking_heuristic"
                )
            ])
        
        elif blocking_type == BlockingType.SNI_BLOCKING:
            # Стратегии против SNI блокировки
            strategies.extend([
                self._create_strategy_candidate(
                    StrategyType.SNI_OBFUSCATION,
                    {'method': 'fragmentation', 'fragment_size': 2},
                    0.9, 0.8, "sni_blocking_heuristic"
                ),
                self._create_strategy_candidate(
                    StrategyType.TCP_FRAGMENTATION,
                    {'split_position': 'sni', 'fragment_count': 3},
                    0.8, 0.7, "sni_blocking_heuristic"
                )
            ])
        
        elif blocking_type == BlockingType.TLS_HANDSHAKE_BLOCKING:
            # Стратегии против TLS блокировки
            strategies.extend([
                self._create_strategy_candidate(
                    StrategyType.TCP_FRAGMENTATION,
                    {'split_position': 'tls_record', 'fragment_count': 2},
                    0.7, 0.6, "tls_blocking_heuristic"
                ),
                self._create_strategy_candidate(
                    StrategyType.PACKET_REORDERING,
                    {'disorder_count': 2, 'delay_ms': 10},
                    0.6, 0.5, "tls_blocking_heuristic"
                )
            ])
        
        return strategies
    
    def _generate_ml_predicted_strategies(self, features: List[float], 
                                        blocking_event: BlockingEvent) -> List[StrategyCandidate]:
        """Генерирует стратегии на основе ML предсказаний"""
        strategies = []
        
        # Тестируем разные типы стратегий
        for strategy_type in StrategyType:
            if strategy_type == StrategyType.COMBINED:
                continue  # Пропускаем комбинированные пока
            
            success_rate, confidence = self.ml_predictor.predict_success_rate(
                features, strategy_type
            )
            
            if success_rate > 0.3:  # Порог для генерации
                # Генерируем параметры на основе типа
                parameters = self._generate_parameters_for_type(strategy_type, blocking_event)
                
                strategy = self._create_strategy_candidate(
                    strategy_type, parameters, success_rate, confidence, "ml_prediction"
                )
                strategies.append(strategy)
        
        return strategies
    
    def _generate_feedback_based_strategies(self, domain: str) -> List[StrategyCandidate]:
        """Генерирует стратегии на основе обратной связи"""
        strategies = []
        
        recommendations = self.feedback_system.get_domain_recommendations(domain)
        
        for strategy_id in recommendations['recommended_strategies']:
            if strategy_id in self.strategy_cache:
                # Создаем вариацию успешной стратегии
                base_strategy = self.strategy_cache[strategy_id]
                varied_params = self._vary_parameters(base_strategy.parameters)
                
                strategy = self._create_strategy_candidate(
                    base_strategy.strategy_type,
                    varied_params,
                    0.8 * recommendations['confidence'],
                    recommendations['confidence'],
                    "feedback_based"
                )
                strategies.append(strategy)
        
        return strategies
    
    def _create_strategy_candidate(self, strategy_type: StrategyType, 
                                 parameters: Dict[str, Any], 
                                 predicted_success_rate: float,
                                 confidence: float, 
                                 generation_method: str) -> StrategyCandidate:
        """Создает кандидата стратегии"""
        strategy_id = f"{strategy_type.value}_{hash(json.dumps(parameters, sort_keys=True))}"
        
        return StrategyCandidate(
            id=strategy_id,
            strategy_type=strategy_type,
            parameters=parameters,
            predicted_success_rate=predicted_success_rate,
            confidence=confidence,
            generation_method=generation_method
        )
    
    def _generate_parameters_for_type(self, strategy_type: StrategyType, 
                                    blocking_event: BlockingEvent) -> Dict[str, Any]:
        """Генерирует параметры для типа стратегии"""
        if strategy_type == StrategyType.TCP_FRAGMENTATION:
            return {
                'split_position': random.choice(['middle', 'sni', 'tls_record']),
                'fragment_count': random.randint(2, 4),
                'fragment_size': random.choice([2, 4, 8])
            }
        
        elif strategy_type == StrategyType.SNI_OBFUSCATION:
            return {
                'method': random.choice(['fragmentation', 'fake_sni', 'case_change']),
                'fragment_size': random.randint(1, 4)
            }
        
        elif strategy_type == StrategyType.FAKE_PACKETS:
            return {
                'fake_count': random.randint(1, 3),
                'ttl': random.randint(1, 3),
                'checksum': random.choice(['bad', 'good'])
            }
        
        elif strategy_type == StrategyType.TTL_MANIPULATION:
            return {
                'ttl': random.randint(1, 5),
                'position': random.choice(['before_payload', 'after_syn'])
            }
        
        elif strategy_type == StrategyType.PACKET_REORDERING:
            return {
                'disorder_count': random.randint(1, 3),
                'delay_ms': random.randint(5, 50)
            }
        
        elif strategy_type == StrategyType.TIMING_ATTACKS:
            return {
                'delay_ms': random.randint(10, 100),
                'jitter_ms': random.randint(1, 10)
            }
        
        return {}
    
    def _vary_parameters(self, base_parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Создает вариацию параметров"""
        varied = base_parameters.copy()
        
        for key, value in varied.items():
            if isinstance(value, int):
                # Варьируем целые числа в пределах ±50%
                variation = max(1, int(value * 0.5))
                varied[key] = value + random.randint(-variation, variation)
                varied[key] = max(1, varied[key])  # Не меньше 1
            
            elif isinstance(value, float):
                # Варьируем дробные числа в пределах ±30%
                variation = value * 0.3
                varied[key] = value + random.uniform(-variation, variation)
                varied[key] = max(0.1, varied[key])  # Не меньше 0.1
        
        return varied
    
    def record_strategy_result(self, strategy_id: str, domain: str, success: bool,
                             response_time_ms: float, error_details: Optional[str] = None):
        """Записывает результат применения стратегии"""
        # Обновляем статистику предсказаний
        if success:
            self.generation_stats['successful_predictions'] += 1
        else:
            self.generation_stats['failed_predictions'] += 1
        
        # Записываем в систему обратной связи
        self.feedback_system.record_feedback(
            strategy_id, domain, success, response_time_ms, error_details
        )
        
        # Обновляем историю домена
        domain_hist = self.domain_history[domain]
        domain_hist['total_attempts'] = domain_hist.get('total_attempts', 0) + 1
        
        if success:
            domain_hist['successful_attempts'] = domain_hist.get('successful_attempts', 0) + 1
            domain_hist['last_success_time'] = time.time()
        
        # Пересчитываем success rate
        domain_hist['success_rate'] = (
            domain_hist.get('successful_attempts', 0) / domain_hist['total_attempts']
        )
        
        # Обновляем среднее время ответа
        old_avg = domain_hist.get('avg_response_time', 0.0)
        total = domain_hist['total_attempts']
        domain_hist['avg_response_time'] = (
            (old_avg * (total - 1) + response_time_ms) / total
        )
        
        # Добавляем образец для ML
        if strategy_id in self.strategy_cache:
            strategy = self.strategy_cache[strategy_id]
            blocking_event = BlockingEvent(
                timestamp=time.time(),
                domain=domain,
                ip="",
                port=443,
                blocking_type=BlockingType.UNKNOWN,
                details={},
                confidence=0.5,
                connection_attempt=None
            )
            features = self.ml_predictor.extract_features(blocking_event, domain_hist)
            self.ml_predictor.add_training_sample(features, strategy.strategy_type, success)
    
    def start_ab_test(self, domain: str, strategy_a: StrategyCandidate, 
                     strategy_b: StrategyCandidate):
        """Запускает A/B тест между стратегиями"""
        self.ab_test_manager.start_ab_test(domain, strategy_a, strategy_b)
    
    def get_test_strategy(self, domain: str) -> Optional[Tuple[StrategyCandidate, str]]:
        """Возвращает стратегию для A/B тестирования"""
        return self.ab_test_manager.get_test_strategy(domain)
    
    def record_ab_test_result(self, result: ABTestResult):
        """Записывает результат A/B теста"""
        self.ab_test_manager.record_test_result(result.domain, result)
        
        # Также записываем в общую систему
        self.record_strategy_result(
            result.strategy_id, result.domain, result.success,
            result.response_time_ms, result.error_message
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику генератора"""
        stats = self.generation_stats.copy()
        stats['cached_strategies'] = len(self.strategy_cache)
        stats['domains_tracked'] = len(self.domain_history)
        stats['active_ab_tests'] = len(self.ab_test_manager.active_tests)
        stats['ml_model_trained'] = self.ml_predictor.is_trained
        stats['training_samples'] = len(self.ml_predictor.training_data)
        
        return stats
    
    def _load_strategy_cache(self):
        """Загружает кэш стратегий из файла"""
        if not self.strategy_cache_file.exists():
            return
        
        try:
            with open(self.strategy_cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for strategy_data in data.get('strategies', []):
                strategy = StrategyCandidate(
                    id=strategy_data['id'],
                    strategy_type=StrategyType(strategy_data['strategy_type']),
                    parameters=strategy_data['parameters'],
                    predicted_success_rate=strategy_data['predicted_success_rate'],
                    confidence=strategy_data['confidence'],
                    generation_method=strategy_data['generation_method'],
                    created_at=strategy_data.get('created_at', time.time()),
                    test_results=strategy_data.get('test_results', [])
                )
                self.strategy_cache[strategy.id] = strategy
            
            self.domain_history.update(data.get('domain_history', {}))
            self.generation_stats.update(data.get('generation_stats', {}))
            
            self.logger.info(f"Loaded {len(self.strategy_cache)} strategies from cache")
            
        except Exception as e:
            self.logger.error(f"Error loading strategy cache: {e}")
    
    def _save_strategy_cache(self):
        """Сохраняет кэш стратегий в файл"""
        try:
            data = {
                'strategies': [strategy.to_dict() for strategy in self.strategy_cache.values()],
                'domain_history': dict(self.domain_history),
                'generation_stats': self.generation_stats,
                'saved_at': time.time()
            }
            
            with open(self.strategy_cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.error(f"Error saving strategy cache: {e}")