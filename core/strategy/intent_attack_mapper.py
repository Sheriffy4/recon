# core/strategy/intent_attack_mapper.py
"""
Intent Attack Mapper - Task 4.2 Implementation
Маппинг Intent'ов на конкретные атаки из AttackRegistry.

Реализует требования FR-2 и FR-3 для адаптивной системы мониторинга.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

LOG = logging.getLogger("intent_attack_mapper")


@dataclass
class AttackMapping:
    """Маппинг Intent'а на конкретную атаку"""
    attack_name: str
    parameters: Dict[str, Any]
    confidence_modifier: float = 1.0
    compatibility_score: float = 1.0
    rationale: str = ""


@dataclass
class GeneratedStrategy:
    """Сгенерированная стратегия на основе Intent'а"""
    name: str
    attack_combination: List[str]
    parameters: Dict[str, Any]
    
    # Метаданные генерации
    generation_method: str
    source_intents: List[str]
    expected_success_rate: float
    rationale: str
    
    # Результаты тестирования
    tested: bool = False
    actual_success_rate: Optional[float] = None
    test_results: List[Any] = field(default_factory=list)


class IntentAttackMapper:
    """
    Маппер для преобразования Intent'ов в конкретные атаки из AttackRegistry.
    
    Интегрируется с существующим AttackRegistry для получения всех доступных атак.
    """
    
    def __init__(self):
        self.attack_registry = None
        self._intent_to_attacks_mapping = self._build_intent_mapping()
        self._load_attack_registry()
    
    def _load_attack_registry(self):
        """Загрузка AttackRegistry"""
        try:
            from core.bypass.attacks import get_attack_registry
            self.attack_registry = get_attack_registry()
            LOG.info(f"Загружен AttackRegistry с {len(self.attack_registry.list_attacks())} атаками")
        except ImportError as e:
            LOG.error(f"Не удалось загрузить AttackRegistry: {e}")
            self.attack_registry = None
    
    def _build_intent_mapping(self) -> Dict[str, List[AttackMapping]]:
        """Построение маппинга Intent'ов на атаки"""
        
        mapping = {
            # SNI Concealment Intents
            "conceal_sni": [
                AttackMapping(
                    attack_name="fake",
                    parameters={"split_pos": "sni", "fooling": "badsum"},
                    confidence_modifier=1.2,
                    compatibility_score=0.9,
                    rationale="Fake packet с badsum для сокрытия SNI"
                ),
                AttackMapping(
                    attack_name="multisplit",
                    parameters={"split_pos": "sni", "split_count": 8},
                    confidence_modifier=1.1,
                    compatibility_score=0.85,
                    rationale="Множественное разделение в позиции SNI"
                ),
                AttackMapping(
                    attack_name="tls_sni_split",
                    parameters={"split_pos": "sni", "fooling": "badseq"},
                    confidence_modifier=1.15,
                    compatibility_score=0.8,
                    rationale="Специализированное разделение TLS SNI"
                )
            ],
            
            "fake_sni": [
                AttackMapping(
                    attack_name="fake",
                    parameters={"split_pos": "sni", "fooling": "badseq", "ttl": 1},
                    confidence_modifier=1.3,
                    compatibility_score=0.9,
                    rationale="Fake packet с коротким TTL для обмана DPI"
                ),
                AttackMapping(
                    attack_name="disorder",
                    parameters={"split_pos": "sni", "fooling": "badsum"},
                    confidence_modifier=1.1,
                    compatibility_score=0.75,
                    rationale="Disorder с fake SNI"
                )
            ],
            
            # Fragmentation Intents
            "record_fragmentation": [
                AttackMapping(
                    attack_name="multisplit",
                    parameters={"split_count": 8, "split_pos": "sni"},
                    confidence_modifier=1.2,
                    compatibility_score=0.9,
                    rationale="Множественная фрагментация TLS записей"
                ),
                AttackMapping(
                    attack_name="tls_chello_frag",
                    parameters={"fragment_size": 16},
                    confidence_modifier=1.15,
                    compatibility_score=0.85,
                    rationale="Фрагментация ClientHello"
                ),
                AttackMapping(
                    attack_name="split",
                    parameters={"split_pos": "random"},
                    confidence_modifier=1.0,
                    compatibility_score=0.8,
                    rationale="Простое разделение записей"
                )
            ],
            
            "ip_fragmentation": [
                AttackMapping(
                    attack_name="ip_basic_fragmentation",
                    parameters={"fragment_size": 32},
                    confidence_modifier=1.1,
                    compatibility_score=0.7,
                    rationale="Базовая IP фрагментация"
                ),
                AttackMapping(
                    attack_name="ip_advanced_fragmentation",
                    parameters={"fragment_size": 16, "overlap": True},
                    confidence_modifier=1.2,
                    compatibility_score=0.6,
                    rationale="Продвинутая IP фрагментация с перекрытием"
                )
            ],
            
            # Decoy Packet Intents
            "short_ttl_decoy": [
                AttackMapping(
                    attack_name="fake",
                    parameters={"ttl": 1, "fooling": "badseq"},
                    confidence_modifier=1.3,
                    compatibility_score=0.9,
                    rationale="Fake packet с TTL=1 для обхода активного DPI"
                ),
                AttackMapping(
                    attack_name="disorder",
                    parameters={"ttl": 2, "fooling": "badsum"},
                    confidence_modifier=1.2,
                    compatibility_score=0.85,
                    rationale="Disorder с коротким TTL"
                )
            ],
            
            "out_of_order_decoy": [
                AttackMapping(
                    attack_name="disorder",
                    parameters={"split_pos": 3, "fooling": "badseq"},
                    confidence_modifier=1.2,
                    compatibility_score=0.9,
                    rationale="Отправка пакетов в неправильном порядке"
                ),
                AttackMapping(
                    attack_name="multidisorder",
                    parameters={"split_positions": [1, 3, 5], "fooling": "badsum"},
                    confidence_modifier=1.15,
                    compatibility_score=0.8,
                    rationale="Множественный disorder для усложнения анализа"
                )
            ],
            
            # Packet Reordering Intents
            "packet_reordering": [
                AttackMapping(
                    attack_name="disorder",
                    parameters={"split_pos": 3},
                    confidence_modifier=1.1,
                    compatibility_score=0.9,
                    rationale="Простое изменение порядка пакетов"
                ),
                AttackMapping(
                    attack_name="multidisorder",
                    parameters={"split_positions": [1, 2, 4]},
                    confidence_modifier=1.2,
                    compatibility_score=0.85,
                    rationale="Сложное изменение порядка в нескольких позициях"
                )
            ],
            
            "sequence_overlap": [
                AttackMapping(
                    attack_name="seqovl",
                    parameters={"overlap_size": 4},
                    confidence_modifier=1.25,
                    compatibility_score=0.8,
                    rationale="Перекрытие TCP последовательностей"
                ),
                AttackMapping(
                    attack_name="fakeddisorder",
                    parameters={"split_pos": 2, "fooling": "badseq"},
                    confidence_modifier=1.15,
                    compatibility_score=0.85,
                    rationale="Fake + disorder для создания перекрытий"
                )
            ],
            
            # Timing Manipulation Intents
            "timing_manipulation": [
                AttackMapping(
                    attack_name="timing_delay",
                    parameters={"delay_ms": 100, "jitter": True},
                    confidence_modifier=1.0,
                    compatibility_score=0.7,
                    rationale="Задержка отправки пакетов"
                ),
                AttackMapping(
                    attack_name="burst_traffic",
                    parameters={"burst_size": 5, "interval_ms": 50},
                    confidence_modifier=0.9,
                    compatibility_score=0.6,
                    rationale="Пакетная отправка трафика"
                )
            ],
            
            # Protocol Evasion Intents
            "tls_extension_manipulation": [
                AttackMapping(
                    attack_name="tls_extension_attacks",
                    parameters={"extension_order": "random", "fake_extensions": True},
                    confidence_modifier=1.1,
                    compatibility_score=0.75,
                    rationale="Манипуляция TLS расширениями"
                ),
                AttackMapping(
                    attack_name="client_hello_fragmentation",
                    parameters={"fragment_extensions": True},
                    confidence_modifier=1.05,
                    compatibility_score=0.8,
                    rationale="Фрагментация ClientHello с расширениями"
                )
            ],
            
            "http_header_manipulation": [
                AttackMapping(
                    attack_name="http_header_attacks",
                    parameters={"header_case": "mixed", "header_order": "random"},
                    confidence_modifier=1.0,
                    compatibility_score=0.7,
                    rationale="Изменение HTTP заголовков"
                ),
                AttackMapping(
                    attack_name="http_method_attacks",
                    parameters={"method_case": "lower"},
                    confidence_modifier=0.9,
                    compatibility_score=0.65,
                    rationale="Манипуляция HTTP методами"
                )
            ],
            
            # Content Obfuscation Intents
            "payload_obfuscation": [
                AttackMapping(
                    attack_name="payload_encryption",
                    parameters={"encryption_method": "xor", "key_rotation": True},
                    confidence_modifier=1.1,
                    compatibility_score=0.6,
                    rationale="Шифрование payload для обхода DPI"
                ),
                AttackMapping(
                    attack_name="payload_encoding",
                    parameters={"encoding": "base64"},
                    confidence_modifier=0.9,
                    compatibility_score=0.7,
                    rationale="Кодирование payload"
                )
            ],
            
            # Fallback Intents
            "basic_fragmentation": [
                AttackMapping(
                    attack_name="split",
                    parameters={"split_pos": 2},
                    confidence_modifier=0.8,
                    compatibility_score=0.9,
                    rationale="Базовое разделение пакета"
                ),
                AttackMapping(
                    attack_name="multisplit",
                    parameters={"split_count": 4},
                    confidence_modifier=0.85,
                    compatibility_score=0.85,
                    rationale="Множественное разделение"
                )
            ],
            
            "simple_reordering": [
                AttackMapping(
                    attack_name="disorder",
                    parameters={"split_pos": 2},
                    confidence_modifier=0.8,
                    compatibility_score=0.9,
                    rationale="Простое изменение порядка"
                )
            ],
            
            "basic_sni_concealment": [
                AttackMapping(
                    attack_name="fake",
                    parameters={"split_pos": "sni", "fooling": "badsum"},
                    confidence_modifier=0.7,
                    compatibility_score=0.8,
                    rationale="Базовое сокрытие SNI"
                )
            ],
            
            # Network Configuration Intents
            "timeout_adjustment": [
                AttackMapping(
                    attack_name="tcp_timeout_adjustment",
                    parameters={"timeout_ms": 5000, "retry_count": 3},
                    confidence_modifier=0.9,
                    compatibility_score=0.95,
                    rationale="Настройка таймаутов TCP соединения"
                ),
                AttackMapping(
                    attack_name="connection_retry",
                    parameters={"max_retries": 5, "backoff": "exponential"},
                    confidence_modifier=0.85,
                    compatibility_score=0.9,
                    rationale="Повторные попытки соединения с экспоненциальной задержкой"
                )
            ],
            
            "ipv6_fallback": [
                AttackMapping(
                    attack_name="ipv6_to_ipv4_fallback",
                    parameters={"prefer_ipv4": True, "fallback_timeout_ms": 1000},
                    confidence_modifier=0.95,
                    compatibility_score=0.9,
                    rationale="Переключение с IPv6 на IPv4 при проблемах"
                ),
                AttackMapping(
                    attack_name="dual_stack_connection",
                    parameters={"try_both": True, "prefer_ipv6": False},
                    confidence_modifier=0.9,
                    compatibility_score=0.85,
                    rationale="Попытка подключения через оба стека протоколов"
                )
            ]
        }
        
        LOG.info(f"Построен маппинг для {len(mapping)} Intent'ов")
        return mapping
    
    def map_intent_to_attacks(self, intent_key: str) -> List[AttackMapping]:
        """
        Получение списка атак для данного Intent'а.
        
        Args:
            intent_key: Ключ Intent'а
            
        Returns:
            Список AttackMapping для данного Intent'а
        """
        
        mappings = self._intent_to_attacks_mapping.get(intent_key, [])
        
        if not mappings:
            LOG.warning(f"Не найден маппинг для Intent'а: {intent_key}")
            return []
        
        # Фильтруем только доступные атаки
        available_mappings = []
        
        if self.attack_registry:
            available_attacks = set(self.attack_registry.list_attacks())
            
            for mapping in mappings:
                if mapping.attack_name in available_attacks:
                    available_mappings.append(mapping)
                else:
                    LOG.debug(f"Атака {mapping.attack_name} недоступна в registry")
        else:
            # Если registry недоступен, возвращаем все маппинги
            available_mappings = mappings
            LOG.warning("AttackRegistry недоступен, возвращаем все маппинги")
        
        LOG.debug(f"Найдено {len(available_mappings)} доступных атак для Intent'а {intent_key}")
        return available_mappings
    
    def generate_strategies_from_intents(self, 
                                       intents: List[Any],
                                       fingerprint: Optional[Any] = None) -> List[GeneratedStrategy]:
        """
        Генерация конкретных стратегий из списка Intent'ов.
        
        Args:
            intents: Список StrategyIntent объектов
            fingerprint: Опциональный DPI fingerprint для адаптации параметров
            
        Returns:
            Список GeneratedStrategy объектов
        """
        
        strategies = []
        
        for intent in intents:
            # Получаем маппинги для данного Intent'а
            attack_mappings = self.map_intent_to_attacks(intent.key)
            
            if not attack_mappings:
                LOG.warning(f"Пропускаем Intent {intent.key} - нет доступных атак")
                continue
            
            # Генерируем стратегии для каждого маппинга
            for mapping in attack_mappings:
                # Адаптируем параметры под fingerprint
                adapted_params = self._adapt_parameters(
                    mapping.parameters, 
                    fingerprint, 
                    intent
                )
                
                # Вычисляем ожидаемую эффективность
                expected_success = self._calculate_expected_success(
                    intent, mapping, fingerprint
                )
                
                strategy = GeneratedStrategy(
                    name=f"{mapping.attack_name}_{intent.key}",
                    attack_combination=[mapping.attack_name],
                    parameters=adapted_params,
                    generation_method="intent_mapping",
                    source_intents=[intent.key],
                    expected_success_rate=expected_success,
                    rationale=f"{intent.rationale} -> {mapping.rationale}"
                )
                
                strategies.append(strategy)
                LOG.debug(f"Сгенерирована стратегия: {strategy.name}")
        
        # Сортируем по ожидаемой эффективности
        strategies.sort(key=lambda s: s.expected_success_rate, reverse=True)
        
        LOG.info(f"Сгенерировано {len(strategies)} стратегий из {len(intents)} Intent'ов")
        return strategies
    
    def _adapt_parameters(self, 
                         base_params: Dict[str, Any], 
                         fingerprint: Optional[Any],
                         intent: Any) -> Dict[str, Any]:
        """Адаптация параметров под DPI fingerprint"""
        
        adapted_params = base_params.copy()
        
        if not fingerprint:
            return adapted_params
        
        try:
            # Адаптация под тип DPI
            if hasattr(fingerprint, 'dpi_type'):
                if fingerprint.dpi_type.value == "stateless":
                    # Для stateless DPI увеличиваем сложность
                    if "split_count" in adapted_params:
                        adapted_params["split_count"] = min(16, adapted_params["split_count"] * 2)
                
                elif fingerprint.dpi_type.value == "stateful":
                    # Для stateful DPI используем более агрессивные параметры
                    if "ttl" in adapted_params:
                        adapted_params["ttl"] = 1  # Минимальный TTL
            
            # Адаптация под режим DPI
            if hasattr(fingerprint, 'dpi_mode'):
                if fingerprint.dpi_mode.value == "active_rst":
                    # Для активного RST используем badseq fooling
                    if "fooling" in adapted_params:
                        adapted_params["fooling"] = "badseq"
            
            # Адаптация под поведенческие сигнатуры
            if hasattr(fingerprint, 'behavioral_signatures'):
                signatures = fingerprint.behavioral_signatures
                
                # Если DPI чувствителен к checksum
                if signatures.get("checksum_validation", False):
                    if "fooling" in adapted_params and adapted_params["fooling"] == "badsum":
                        adapted_params["fooling"] = "badseq"
                
                # Если DPI собирает фрагменты
                if signatures.get("reassembles_fragments", False):
                    if "split_count" in adapted_params:
                        adapted_params["split_count"] = max(8, adapted_params["split_count"])
            
            # Используем parameter_ranges из Intent'а
            if hasattr(intent, 'parameter_ranges'):
                for param, value_range in intent.parameter_ranges.items():
                    if param in adapted_params and isinstance(value_range, list):
                        # Выбираем наиболее агрессивное значение
                        if isinstance(value_range[0], (int, float)):
                            adapted_params[param] = max(value_range)
                        else:
                            adapted_params[param] = value_range[0]
        
        except Exception as e:
            LOG.warning(f"Ошибка адаптации параметров: {e}")
        
        return adapted_params
    
    def _calculate_expected_success(self, 
                                  intent: Any, 
                                  mapping: AttackMapping,
                                  fingerprint: Optional[Any]) -> float:
        """Вычисление ожидаемой эффективности стратегии"""
        
        # Базовая эффективность из Intent'а
        base_success = intent.priority if hasattr(intent, 'priority') else 0.5
        
        # Модификатор от маппинга
        mapping_modifier = mapping.confidence_modifier
        
        # Модификатор совместимости
        compatibility_modifier = mapping.compatibility_score
        
        # Модификатор от fingerprint confidence
        fingerprint_modifier = 1.0
        if fingerprint and hasattr(fingerprint, 'confidence'):
            fingerprint_modifier = 0.8 + (fingerprint.confidence * 0.4)  # 0.8 - 1.2
        
        # Итоговая эффективность
        expected_success = (
            base_success * 
            mapping_modifier * 
            compatibility_modifier * 
            fingerprint_modifier
        )
        
        # Ограничиваем диапазон 0.0 - 1.0
        return max(0.0, min(1.0, expected_success))
    
    def get_available_attacks_for_intent(self, intent_key: str) -> List[str]:
        """Получение списка доступных атак для Intent'а"""
        
        mappings = self.map_intent_to_attacks(intent_key)
        return [mapping.attack_name for mapping in mappings]
    
    def validate_attack_availability(self, attack_name: str) -> bool:
        """Проверка доступности атаки в registry"""
        
        if not self.attack_registry:
            return False
        
        available_attacks = self.attack_registry.list_attacks()
        return attack_name in available_attacks
    
    def get_mapping_statistics(self) -> Dict[str, Any]:
        """Получение статистики маппинга"""
        
        total_intents = len(self._intent_to_attacks_mapping)
        total_mappings = sum(len(mappings) for mappings in self._intent_to_attacks_mapping.values())
        
        available_attacks = 0
        if self.attack_registry:
            registry_attacks = set(self.attack_registry.list_attacks())
            for mappings in self._intent_to_attacks_mapping.values():
                for mapping in mappings:
                    if mapping.attack_name in registry_attacks:
                        available_attacks += 1
        
        return {
            "total_intents": total_intents,
            "total_mappings": total_mappings,
            "available_mappings": available_attacks,
            "registry_loaded": self.attack_registry is not None,
            "registry_attacks_count": len(self.attack_registry.list_attacks()) if self.attack_registry else 0
        }


# Пример использования
if __name__ == "__main__":
    # Создаем маппер
    mapper = IntentAttackMapper()
    
    # Создаем тестовый Intent
    from core.strategy.strategy_intent_engine import StrategyIntent
    
    test_intent = StrategyIntent(
        key="conceal_sni",
        priority=0.9,
        rationale="Тестовое сокрытие SNI",
        parameter_ranges={"split_count": [4, 8, 16]}
    )
    
    # Получаем маппинги
    mappings = mapper.map_intent_to_attacks("conceal_sni")
    print(f"Найдено {len(mappings)} маппингов для conceal_sni:")
    for mapping in mappings:
        print(f"  - {mapping.attack_name}: {mapping.rationale}")
    
    # Генерируем стратегии
    strategies = mapper.generate_strategies_from_intents([test_intent])
    print(f"\nСгенерировано {len(strategies)} стратегий:")
    for strategy in strategies:
        print(f"  - {strategy.name} (эффективность: {strategy.expected_success_rate:.2f})")
    
    # Статистика
    stats = mapper.get_mapping_statistics()
    print(f"\nСтатистика маппера: {stats}")