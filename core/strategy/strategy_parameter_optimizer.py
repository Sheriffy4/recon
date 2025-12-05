# core/strategy/strategy_parameter_optimizer.py
"""
Strategy Parameter Optimizer - Task 5.3 Implementation
Оптимизация параметров стратегий под характеристики DPI.

Интегрируется с существующим ParametricOptimizer для настройки параметров.
Реализует требования FR-2 для адаптивной системы мониторинга.
"""

import logging
import random
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

LOG = logging.getLogger("strategy_parameter_optimizer")


@dataclass
class ParameterRange:
    """Диапазон значений параметра"""
    name: str
    min_value: Any
    max_value: Any
    step: Optional[Any] = None
    values: Optional[List[Any]] = None  # Дискретные значения
    default: Any = None
    description: str = ""


@dataclass
class OptimizationResult:
    """Результат оптимизации параметров"""
    original_parameters: Dict[str, Any]
    optimized_parameters: Dict[str, Any]
    optimization_method: str
    improvement_score: float
    confidence: float
    explanation: str
    optimization_time: float = 0.0
    iterations_performed: int = 0


class OptimizationMethod(Enum):
    """Методы оптимизации параметров"""
    DPI_ADAPTIVE = "dpi_adaptive"
    HEURISTIC = "heuristic"
    RANDOM_SEARCH = "random_search"
    GRID_SEARCH = "grid_search"
    PRESET_GOOD_VALUES = "preset_good_values"


class StrategyParameterOptimizer:
    """
    Оптимизатор параметров стратегий с интеграцией ParametricOptimizer.
    
    Основные функции:
    - Адаптация параметров под характеристики DPI
    - Использование предустановленных "хороших" значений
    - Интеграция с существующим ParametricOptimizer
    - Генерация объяснений для выбранных параметров
    """
    
    def __init__(self):
        self.parametric_optimizer = None
        
        # Определение диапазонов параметров
        self.parameter_ranges = self._define_parameter_ranges()
        
        # Предустановленные "хорошие" значения
        self.good_values = self._define_good_values()
        
        # DPI-специфичные правила оптимизации
        self.dpi_optimization_rules = self._build_dpi_rules()
        
        # Статистика оптимизации
        self.optimization_stats = {
            "total_optimizations": 0,
            "by_method": {method.value: 0 for method in OptimizationMethod},
            "average_improvement": 0.0,
            "successful_optimizations": 0
        }
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Инициализация интеграционных компонентов"""
        
        # Загружаем ParametricOptimizer (будет инициализирован при необходимости)
        try:
            from core.parametric_optimizer import ParametricOptimizer
            # ParametricOptimizer требует дополнительные параметры для инициализации
            # Будем создавать его по требованию
            LOG.info("ParametricOptimizer доступен для интеграции")
        except ImportError as e:
            LOG.error(f"Не удалось загрузить ParametricOptimizer: {e}")
    
    def _define_parameter_ranges(self) -> Dict[str, ParameterRange]:
        """Определение диапазонов параметров для разных атак"""
        
        ranges = {
            # Общие параметры
            "ttl": ParameterRange(
                name="ttl",
                min_value=1,
                max_value=128,
                values=[1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 128],
                default=3,
                description="Time To Live для пакетов"
            ),
            
            "split_pos": ParameterRange(
                name="split_pos",
                min_value=1,
                max_value=10,
                values=[1, 2, 3, 4, 5, "sni", "random"],
                default=3,
                description="Позиция разделения пакета"
            ),
            
            "split_count": ParameterRange(
                name="split_count",
                min_value=2,
                max_value=32,
                values=[2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 20, 24, 32],
                default=4,
                description="Количество частей при разделении"
            ),
            
            "fooling": ParameterRange(
                name="fooling",
                min_value=None,
                max_value=None,
                values=["badsum", "badseq", "md5sig", "none"],
                default="badsum",
                description="Метод обмана DPI"
            ),
            
            # Специфичные параметры
            "split_seqovl": ParameterRange(
                name="split_seqovl",
                min_value=0,
                max_value=1000,
                values=[0, 1, 2, 4, 8, 16, 20, 30, 50, 100, 200, 336, 500, 1000],
                default=20,
                description="Размер перекрытия последовательностей"
            ),
            
            "disorder_method": ParameterRange(
                name="disorder_method",
                min_value=None,
                max_value=None,
                values=["reverse", "random", "simple"],
                default="reverse",
                description="Метод изменения порядка пакетов"
            ),
            
            "fragment_size": ParameterRange(
                name="fragment_size",
                min_value=8,
                max_value=1024,
                values=[8, 16, 24, 32, 48, 64, 128, 256, 512, 1024],
                default=32,
                description="Размер фрагмента для IP фрагментации"
            ),
            
            "delay_ms": ParameterRange(
                name="delay_ms",
                min_value=0,
                max_value=1000,
                values=[0, 10, 20, 50, 100, 200, 500, 1000],
                default=50,
                description="Задержка в миллисекундах"
            ),
            
            "window_div": ParameterRange(
                name="window_div",
                min_value=1,
                max_value=32,
                values=[1, 2, 4, 6, 8, 10, 16, 32],
                default=6,
                description="Делитель TCP окна"
            ),
            
            "repeats": ParameterRange(
                name="repeats",
                min_value=1,
                max_value=10,
                values=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                default=1,
                description="Количество повторений атаки"
            )
        }
        
        LOG.info(f"Определены диапазоны для {len(ranges)} параметров")
        return ranges
    
    def _define_good_values(self) -> Dict[str, Dict[str, Any]]:
        """Предустановленные "хорошие" значения параметров для разных сценариев"""
        
        good_values = {
            # Значения для разных типов DPI
            "stateless_dpi": {
                "ttl": 2,
                "split_pos": 3,
                "split_count": 8,
                "fooling": "badsum",
                "disorder_method": "reverse"
            },
            
            "stateful_dpi": {
                "ttl": 1,
                "split_pos": 2,
                "split_count": 4,
                "fooling": "badseq",
                "split_seqovl": 20
            },
            
            "active_rst_dpi": {
                "ttl": 1,
                "split_pos": 3,
                "fooling": "badseq",
                "repeats": 2,
                "delay_ms": 10
            },
            
            # Значения для разных атак
            "fake_attack": {
                "ttl": 1,
                "split_pos": "sni",
                "fooling": "badseq",
                "window_div": 6
            },
            
            "multisplit_attack": {
                "split_count": 8,
                "split_pos": "sni",
                "fooling": "badsum",
                "repeats": 1
            },
            
            "disorder_attack": {
                "split_pos": 3,
                "fooling": "badsum",
                "disorder_method": "reverse",
                "ttl": 2
            },
            
            "seqovl_attack": {
                "split_seqovl": 336,
                "split_pos": 76,
                "fooling": "badseq",
                "ttl": 1,
                "repeats": 1
            },
            
            # Значения для разных доменов/сервисов
            "social_media": {
                "split_pos": "sni",
                "split_count": 8,
                "fooling": "badsum",
                "ttl": 2
            },
            
            "video_streaming": {
                "split_count": 4,
                "split_pos": 3,
                "fooling": "badseq",
                "ttl": 3
            },
            
            "messaging": {
                "ttl": 1,
                "split_pos": 2,
                "fooling": "badseq",
                "repeats": 2
            },
            
            # Консервативные значения (fallback)
            "conservative": {
                "ttl": 3,
                "split_pos": 3,
                "split_count": 4,
                "fooling": "badsum",
                "repeats": 1
            },
            
            # Агрессивные значения
            "aggressive": {
                "ttl": 1,
                "split_pos": 2,
                "split_count": 16,
                "fooling": "badseq",
                "repeats": 3,
                "split_seqovl": 100
            }
        }
        
        LOG.info(f"Определены хорошие значения для {len(good_values)} сценариев")
        return good_values
    
    def _build_dpi_rules(self) -> Dict[str, Dict[str, Any]]:
        """Построение правил оптимизации под разные типы DPI"""
        
        rules = {
            # Правила для stateless DPI
            "stateless": {
                "preferred_attacks": ["disorder", "multidisorder", "fake"],
                "parameter_adjustments": {
                    "split_count": lambda x: min(16, x * 2),  # Увеличиваем сложность
                    "disorder_method": "reverse",
                    "ttl": 2
                },
                "avoid_parameters": {
                    "split_seqovl": "stateless DPI не отслеживает последовательности"
                }
            },
            
            # Правила для stateful DPI
            "stateful": {
                "preferred_attacks": ["fake", "seqovl", "multisplit"],
                "parameter_adjustments": {
                    "ttl": 1,  # Минимальный TTL
                    "fooling": "badseq",
                    "split_seqovl": lambda x: max(20, x)
                },
                "avoid_parameters": {
                    "disorder_method": "stateful DPI может восстановить порядок"
                }
            },
            
            # Правила для активного RST DPI
            "active_rst": {
                "preferred_attacks": ["fake", "disorder"],
                "parameter_adjustments": {
                    "ttl": 1,  # Обязательно короткий TTL
                    "fooling": "badseq",
                    "repeats": lambda x: max(2, x)
                },
                "boost_parameters": {
                    "delay_ms": 10  # Небольшая задержка может помочь
                }
            },
            
            # Правила для пассивного DPI
            "passive": {
                "preferred_attacks": ["split", "multisplit"],
                "parameter_adjustments": {
                    "split_count": lambda x: max(2, x // 2),  # Можем использовать простые методы
                    "ttl": 3
                },
                "simplify_parameters": True
            },
            
            # Правила для гибридного DPI
            "hybrid": {
                "preferred_attacks": ["fake", "multisplit", "seqovl"],
                "parameter_adjustments": {
                    "ttl": 1,
                    "split_count": lambda x: min(12, max(6, x)),
                    "fooling": "badseq"
                },
                "use_combinations": True
            }
        }
        
        return rules
    
    def optimize_parameters(self,
                          base_parameters: Dict[str, Any],
                          attack_names: List[str],
                          fingerprint: Optional[Any] = None,
                          method: OptimizationMethod = OptimizationMethod.DPI_ADAPTIVE) -> OptimizationResult:
        """
        Оптимизация параметров стратегии.
        
        Args:
            base_parameters: Базовые параметры
            attack_names: Список атак в стратегии
            fingerprint: DPI fingerprint для адаптации
            method: Метод оптимизации
            
        Returns:
            OptimizationResult с оптимизированными параметрами
        """
        
        start_time = datetime.now()
        
        LOG.info(f"Оптимизация параметров методом {method.value} для атак: {attack_names}")
        
        # Выбираем метод оптимизации
        if method == OptimizationMethod.DPI_ADAPTIVE and fingerprint:
            optimized_params = self._optimize_for_dpi(base_parameters, attack_names, fingerprint)
            explanation = "Адаптация под характеристики DPI"
        elif method == OptimizationMethod.PRESET_GOOD_VALUES:
            optimized_params = self._apply_good_values(base_parameters, attack_names, fingerprint)
            explanation = "Использование предустановленных хороших значений"
        elif method == OptimizationMethod.HEURISTIC:
            optimized_params = self._heuristic_optimization(base_parameters, attack_names)
            explanation = "Эвристическая оптимизация"
        elif method == OptimizationMethod.RANDOM_SEARCH:
            optimized_params = self._random_search_optimization(base_parameters, attack_names)
            explanation = "Случайный поиск оптимальных значений"
        else:
            # Fallback к эвристической оптимизации
            optimized_params = self._heuristic_optimization(base_parameters, attack_names)
            explanation = "Эвристическая оптимизация (fallback)"
        
        # Вычисляем улучшение
        improvement_score = self._calculate_improvement_score(
            base_parameters, optimized_params, attack_names, fingerprint
        )
        
        # Вычисляем уверенность в оптимизации
        confidence = self._calculate_optimization_confidence(
            method, fingerprint, improvement_score
        )
        
        optimization_time = (datetime.now() - start_time).total_seconds()
        
        result = OptimizationResult(
            original_parameters=base_parameters.copy(),
            optimized_parameters=optimized_params,
            optimization_method=method.value,
            improvement_score=improvement_score,
            confidence=confidence,
            explanation=explanation,
            optimization_time=optimization_time,
            iterations_performed=1
        )
        
        # Обновляем статистику
        self._update_optimization_stats(method, improvement_score)
        
        LOG.info(f"Оптимизация завершена за {optimization_time:.3f}с, улучшение: {improvement_score:.2f}")
        
        return result
    
    def _optimize_for_dpi(self,
                         base_parameters: Dict[str, Any],
                         attack_names: List[str],
                         fingerprint: Any) -> Dict[str, Any]:
        """Оптимизация под характеристики DPI"""
        
        optimized = base_parameters.copy()
        
        try:
            # Определяем тип DPI
            dpi_type = getattr(fingerprint, 'dpi_type', None)
            dpi_mode = getattr(fingerprint, 'dpi_mode', None)
            
            if dpi_type:
                dpi_type_str = dpi_type.value if hasattr(dpi_type, 'value') else str(dpi_type)
                
                # Применяем правила для типа DPI
                if dpi_type_str in self.dpi_optimization_rules:
                    rules = self.dpi_optimization_rules[dpi_type_str]
                    
                    # Применяем корректировки параметров
                    adjustments = rules.get("parameter_adjustments", {})
                    for param, adjustment in adjustments.items():
                        if param in optimized:
                            if callable(adjustment):
                                optimized[param] = adjustment(optimized[param])
                            else:
                                optimized[param] = adjustment
                        elif param in self.parameter_ranges:
                            # Добавляем новый параметр
                            if callable(adjustment):
                                optimized[param] = adjustment(self.parameter_ranges[param].default)
                            else:
                                optimized[param] = adjustment
            
            # Применяем правила для режима DPI
            if dpi_mode:
                dpi_mode_str = dpi_mode.value if hasattr(dpi_mode, 'value') else str(dpi_mode)
                
                if dpi_mode_str == "active_rst":
                    optimized["ttl"] = 1
                    optimized["fooling"] = "badseq"
                elif dpi_mode_str == "passive":
                    optimized["ttl"] = max(3, optimized.get("ttl", 3))
            
            # Учитываем поведенческие сигнатуры
            if hasattr(fingerprint, 'behavioral_signatures'):
                signatures = fingerprint.behavioral_signatures
                
                if signatures.get("reassembles_fragments", False):
                    # DPI собирает фрагменты - увеличиваем сложность
                    if "split_count" in optimized:
                        optimized["split_count"] = max(8, optimized["split_count"])
                
                if signatures.get("checksum_validation", False):
                    # DPI проверяет checksum - избегаем badsum
                    if optimized.get("fooling") == "badsum":
                        optimized["fooling"] = "badseq"
                
                if signatures.get("sni_filtering", False):
                    # SNI фильтрация - используем специальные позиции
                    optimized["split_pos"] = "sni"
            
            # Учитываем известные уязвимости
            if hasattr(fingerprint, 'known_weaknesses'):
                for weakness in fingerprint.known_weaknesses:
                    if "fragmentation" in weakness:
                        optimized["split_count"] = max(8, optimized.get("split_count", 4))
                    elif "sni" in weakness:
                        optimized["split_pos"] = "sni"
                    elif "ttl" in weakness:
                        optimized["ttl"] = 1
            
            # Адаптируем под уровень уверенности
            if hasattr(fingerprint, 'confidence'):
                if fingerprint.confidence > 0.8:
                    # Высокая уверенность - агрессивные параметры
                    optimized.update(self._get_aggressive_parameters(attack_names))
                elif fingerprint.confidence < 0.4:
                    # Низкая уверенность - консервативные параметры
                    optimized.update(self._get_conservative_parameters(attack_names))
        
        except Exception as e:
            LOG.warning(f"Ошибка DPI оптимизации: {e}")
        
        return optimized
    
    def _apply_good_values(self,
                          base_parameters: Dict[str, Any],
                          attack_names: List[str],
                          fingerprint: Optional[Any]) -> Dict[str, Any]:
        """Применение предустановленных хороших значений"""
        
        optimized = base_parameters.copy()
        
        # Определяем подходящий набор хороших значений
        good_values_key = self._select_good_values_key(attack_names, fingerprint)
        
        if good_values_key in self.good_values:
            good_params = self.good_values[good_values_key]
            
            # Применяем хорошие значения, но не перезаписываем существующие
            for param, value in good_params.items():
                if param not in optimized or optimized[param] is None:
                    optimized[param] = value
                else:
                    # Смешиваем с существующими значениями
                    optimized[param] = self._blend_parameter_values(
                        optimized[param], value, param
                    )
        
        # Применяем специфичные для атак значения
        for attack_name in attack_names:
            attack_key = f"{attack_name}_attack"
            if attack_key in self.good_values:
                attack_params = self.good_values[attack_key]
                for param, value in attack_params.items():
                    if param not in optimized:
                        optimized[param] = value
        
        return optimized
    
    def _heuristic_optimization(self,
                              base_parameters: Dict[str, Any],
                              attack_names: List[str]) -> Dict[str, Any]:
        """Эвристическая оптимизация параметров"""
        
        optimized = base_parameters.copy()
        
        # Эвристики для разных типов атак
        for attack_name in attack_names:
            if "fake" in attack_name:
                optimized.update({
                    "ttl": 1,
                    "fooling": "badseq",
                    "split_pos": "sni"
                })
            
            elif "multisplit" in attack_name:
                optimized.update({
                    "split_count": 8,
                    "split_pos": "sni",
                    "fooling": "badsum"
                })
            
            elif "disorder" in attack_name:
                optimized.update({
                    "split_pos": 3,
                    "disorder_method": "reverse",
                    "fooling": "badsum"
                })
            
            elif "seqovl" in attack_name:
                optimized.update({
                    "split_seqovl": 336,
                    "split_pos": 76,
                    "fooling": "badseq",
                    "ttl": 1
                })
        
        # Общие эвристики
        if len(attack_names) > 1:
            # Для комбинаций используем более консервативные параметры
            optimized["ttl"] = max(2, optimized.get("ttl", 2))
            optimized["repeats"] = min(2, optimized.get("repeats", 1))
        
        return optimized
    
    def _random_search_optimization(self,
                                  base_parameters: Dict[str, Any],
                                  attack_names: List[str]) -> Dict[str, Any]:
        """Случайный поиск оптимальных п��раметров"""
        
        optimized = base_parameters.copy()
        
        # Случайно выбираем значения из допустимых диапазонов
        for param_name, param_range in self.parameter_ranges.items():
            if param_name in optimized or random.random() < 0.3:  # 30% шанс добавить новый параметр
                if param_range.values:
                    # Выбираем из дискретных значений
                    optimized[param_name] = random.choice(param_range.values)
                elif param_range.min_value is not None and param_range.max_value is not None:
                    # Выбираем из диапазона
                    if isinstance(param_range.min_value, int):
                        optimized[param_name] = random.randint(param_range.min_value, param_range.max_value)
                    else:
                        optimized[param_name] = random.uniform(param_range.min_value, param_range.max_value)
        
        return optimized
    
    def _select_good_values_key(self,
                              attack_names: List[str],
                              fingerprint: Optional[Any]) -> str:
        """Выбор подходящего ключа хороших значений"""
        
        # Приоритет: DPI тип > атака > домен > fallback
        
        if fingerprint:
            # Проверяем тип DPI
            if hasattr(fingerprint, 'dpi_type'):
                dpi_type = fingerprint.dpi_type.value if hasattr(fingerprint.dpi_type, 'value') else str(fingerprint.dpi_type)
                if f"{dpi_type}_dpi" in self.good_values:
                    return f"{dpi_type}_dpi"
            
            # Проверяем режим DPI
            if hasattr(fingerprint, 'dpi_mode'):
                dpi_mode = fingerprint.dpi_mode.value if hasattr(fingerprint.dpi_mode, 'value') else str(fingerprint.dpi_mode)
                if f"{dpi_mode}_dpi" in self.good_values:
                    return f"{dpi_mode}_dpi"
            
            # Проверяем домен для специфичных сервисов
            if hasattr(fingerprint, 'domain'):
                domain = fingerprint.domain.lower()
                if any(social in domain for social in ["twitter", "instagram", "facebook", "tiktok"]):
                    return "social_media"
                elif any(video in domain for video in ["youtube", "netflix", "twitch"]):
                    return "video_streaming"
                elif any(msg in domain for msg in ["telegram", "whatsapp", "discord"]):
                    return "messaging"
        
        # Проверяем основную атаку
        if attack_names:
            primary_attack = attack_names[0]
            if f"{primary_attack}_attack" in self.good_values:
                return f"{primary_attack}_attack"
        
        # Fallback к консервативным значениям
        return "conservative"
    
    def _blend_parameter_values(self, existing_value: Any, good_value: Any, param_name: str) -> Any:
        """Смешивание существующего и хорошего значения параметра"""
        
        # Для числовых параметров берем среднее или более агрессивное значение
        if isinstance(existing_value, (int, float)) and isinstance(good_value, (int, float)):
            if param_name in ["ttl"]:
                # Для TTL берем минимальное (более агрессивное)
                return min(existing_value, good_value)
            elif param_name in ["split_count", "split_seqovl"]:
                # Для count параметров берем максимальное
                return max(existing_value, good_value)
            else:
                # Для остальных берем среднее
                return (existing_value + good_value) // 2 if isinstance(existing_value, int) else (existing_value + good_value) / 2
        
        # Для строковых параметров предпочитаем хорошее значение
        return good_value
    
    def _get_aggressive_parameters(self, attack_names: List[str]) -> Dict[str, Any]:
        """Получение агрессивных параметров"""
        
        base_aggressive = self.good_values.get("aggressive", {})
        
        # Дополнительные агрессивные корректировки
        aggressive_params = base_aggressive.copy()
        
        if any("fake" in attack for attack in attack_names):
            aggressive_params["ttl"] = 1
        
        if any("split" in attack for attack in attack_names):
            aggressive_params["split_count"] = 16
        
        return aggressive_params
    
    def _get_conservative_parameters(self, attack_names: List[str]) -> Dict[str, Any]:
        """Получение консервативных параметров"""
        
        return self.good_values.get("conservative", {})
    
    def _calculate_improvement_score(self,
                                   original_params: Dict[str, Any],
                                   optimized_params: Dict[str, Any],
                                   attack_names: List[str],
                                   fingerprint: Optional[Any]) -> float:
        """Вычисление оценки улучшения параметров"""
        
        # Базовая оценка - количество измененных параметров
        changed_params = sum(1 for key in optimized_params 
                           if key not in original_params or original_params[key] != optimized_params[key])
        
        base_score = min(1.0, changed_params * 0.1)
        
        # Бонус за оптимальные значения
        optimality_bonus = 0.0
        
        for param, value in optimized_params.items():
            if param in self.parameter_ranges:
                param_range = self.parameter_ranges[param]
                
                # Бонус за использование хороших значений
                if param_range.values and value in param_range.values[:3]:  # Топ 3 значения
                    optimality_bonus += 0.05
                
                # Бонус за значение по умолчанию
                if value == param_range.default:
                    optimality_bonus += 0.02
        
        # Бонус за соответствие DPI
        dpi_bonus = 0.0
        if fingerprint:
            # Простая эвристика соответствия
            if hasattr(fingerprint, 'dpi_mode'):
                dpi_mode = fingerprint.dpi_mode.value if hasattr(fingerprint.dpi_mode, 'value') else str(fingerprint.dpi_mode)
                if dpi_mode == "active_rst" and optimized_params.get("ttl") == 1:
                    dpi_bonus += 0.2
        
        total_score = base_score + optimality_bonus + dpi_bonus
        
        return max(0.0, min(1.0, total_score))
    
    def _calculate_optimization_confidence(self,
                                         method: OptimizationMethod,
                                         fingerprint: Optional[Any],
                                         improvement_score: float) -> float:
        """Вычисление уверенности в оптимизации"""
        
        # Базовая уверенность от метода
        method_confidence = {
            OptimizationMethod.DPI_ADAPTIVE: 0.9,
            OptimizationMethod.PRESET_GOOD_VALUES: 0.8,
            OptimizationMethod.HEURISTIC: 0.7,
            OptimizationMethod.RANDOM_SEARCH: 0.4,
            OptimizationMethod.GRID_SEARCH: 0.6
        }
        
        base_confidence = method_confidence.get(method, 0.5)
        
        # Модификатор от fingerprint
        fingerprint_modifier = 1.0
        if fingerprint and hasattr(fingerprint, 'confidence'):
            fingerprint_modifier = 0.7 + (fingerprint.confidence * 0.3)
        
        # Модификатор от улучшения
        improvement_modifier = 0.8 + (improvement_score * 0.4)
        
        total_confidence = base_confidence * fingerprint_modifier * improvement_modifier
        
        return max(0.0, min(1.0, total_confidence))
    
    def _update_optimization_stats(self, method: OptimizationMethod, improvement_score: float):
        """Обновление статистики оптимизации"""
        
        self.optimization_stats["total_optimizations"] += 1
        self.optimization_stats["by_method"][method.value] += 1
        
        if improvement_score > 0.1:  # Считаем успешной если улучшение > 10%
            self.optimization_stats["successful_optimizations"] += 1
        
        # Обновляем среднее улучшение
        total_opts = self.optimization_stats["total_optimizations"]
        current_avg = self.optimization_stats["average_improvement"]
        self.optimization_stats["average_improvement"] = (
            (current_avg * (total_opts - 1) + improvement_score) / total_opts
        )
    
    def generate_parameter_explanation(self, optimization_result: OptimizationResult) -> str:
        """Генерация объяснения для выбранных параметров"""
        
        explanation_parts = []
        
        # Основная информация
        explanation_parts.append(f"🔧 Оптимизация параметров ({optimization_result.optimization_method}):")
        explanation_parts.append(f"   Улучшение: {optimization_result.improvement_score:.2f}")
        explanation_parts.append(f"   Уверенность: {optimization_result.confidence:.2f}")
        
        # Измененные параметры
        changed_params = []
        for param, new_value in optimization_result.optimized_parameters.items():
            old_value = optimization_result.original_parameters.get(param, "не задан")
            if old_value != new_value:
                changed_params.append(f"{param}: {old_value} → {new_value}")
        
        if changed_params:
            explanation_parts.append("   Изменения:")
            for change in changed_params:
                explanation_parts.append(f"      - {change}")
        
        # Объяснение выбора
        explanation_parts.append(f"   💡 {optimization_result.explanation}")
        
        # Объяснение конкретных параметров
        param_explanations = []
        for param, value in optimization_result.optimized_parameters.items():
            if param in self.parameter_ranges:
                param_range = self.parameter_ranges[param]
                param_explanations.append(f"{param}={value}: {param_range.description}")
        
        if param_explanations:
            explanation_parts.append("   Параметры:")
            for explanation in param_explanations[:5]:  # Показываем топ 5
                explanation_parts.append(f"      - {explanation}")
        
        return "\n".join(explanation_parts)
    
    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Получение статистики оптимизации"""
        
        total_opts = self.optimization_stats["total_optimizations"]
        
        return {
            "total_optimizations": total_opts,
            "by_method": self.optimization_stats["by_method"].copy(),
            "successful_optimizations": self.optimization_stats["successful_optimizations"],
            "success_rate": (
                self.optimization_stats["successful_optimizations"] / max(1, total_opts)
            ),
            "average_improvement": self.optimization_stats["average_improvement"],
            "parameter_ranges_defined": len(self.parameter_ranges),
            "good_values_scenarios": len(self.good_values),
            "dpi_rules_count": len(self.dpi_optimization_rules)
        }


# Пример использования
if __name__ == "__main__":
    # Создаем оптимизатор
    optimizer = StrategyParameterOptimizer()
    
    # Тестовые параметры
    base_params = {
        "split_pos": 3,
        "ttl": 3,
        "fooling": "badsum"
    }
    
    # Тестовые атаки
    attacks = ["fake", "multisplit"]
    
    # Оптимизируем параметры
    result = optimizer.optimize_parameters(
        base_params, 
        attacks,
        method=OptimizationMethod.PRESET_GOOD_VALUES
    )
    
    print("Результат оптимизации:")
    print(f"Исходные параметры: {result.original_parameters}")
    print(f"Оптимизированные: {result.optimized_parameters}")
    print(f"Улучшение: {result.improvement_score:.2f}")
    print(f"Уверенность: {result.confidence:.2f}")
    
    # Объяснение
    explanation = optimizer.generate_parameter_explanation(result)
    print(f"\nОбъяснение:\n{explanation}")
    
    # Статистика
    stats = optimizer.get_optimization_statistics()
    print(f"\nСтатистика оптимизатора: {stats}")