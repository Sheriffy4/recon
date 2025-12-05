# core/strategy/strategy_intent_engine.py
"""
Strategy Intent Engine (SIE) - Task 4.1 Implementation
Преобразование DPI fingerprint в высокоуровневые намерения стратегий.

Реализует требования FR-2 и FR-3 для адаптивной системы мониторинга.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

LOG = logging.getLogger("strategy_intent_engine")


@dataclass
class StrategyIntent:
    """Высокоуровневое намерение стратегии"""
    key: str  # "conceal_sni", "short_ttl_decoy", etc.
    priority: float  # 0.0 - 1.0
    rationale: str
    preconditions: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    
    # Параметры для оптимизации
    parameter_ranges: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Валидация priority"""
        if not 0.0 <= self.priority <= 1.0:
            raise ValueError(f"Priority must be between 0.0 and 1.0, got {self.priority}")


class IntentCategory(Enum):
    """Категории намерений стратегий"""
    SNI_CONCEALMENT = "sni_concealment"
    FRAGMENTATION = "fragmentation"
    DECOY_PACKETS = "decoy_packets"
    PACKET_REORDERING = "packet_reordering"
    TIMING_MANIPULATION = "timing_manipulation"
    PROTOCOL_EVASION = "protocol_evasion"
    CONTENT_OBFUSCATION = "content_obfuscation"


class StrategyIntentEngine:
    """
    Движок для преобразования DPI fingerprint в высокоуровневые намерения стратегий.
    
    Использует простые правила if/else для сопоставления характеристик DPI с Intent'ами.
    """
    
    def __init__(self):
        self.intent_registry = self._build_intent_registry()
        self.rule_stats = {
            "evaluations": 0,
            "intents_generated": 0,
            "fallback_used": 0
        }
    
    def _build_intent_registry(self) -> Dict[str, StrategyIntent]:
        """Построение реестра доступных намерений"""
        
        intents = {
            # SNI Concealment Intents
            "conceal_sni": StrategyIntent(
                key="conceal_sni",
                priority=0.9,
                rationale="Скрыть SNI от DPI анализа",
                preconditions=["sni_filtering_detected"],
                side_effects=["may_break_sni_dependent_services"],
                parameter_ranges={
                    "split_position": ["sni", "random"],
                    "fooling_method": ["badsum", "badseq", "md5sig"]
                }
            ),
            
            "fake_sni": StrategyIntent(
                key="fake_sni",
                priority=0.85,
                rationale="Отправить поддельный SNI перед настоящим",
                preconditions=["sni_filtering_detected"],
                side_effects=["increased_latency"],
                parameter_ranges={
                    "fake_domain": ["example.com", "google.com"],
                    "ttl": [1, 2, 3]
                }
            ),
            
            # Fragmentation Intents
            "record_fragmentation": StrategyIntent(
                key="record_fragmentation",
                priority=0.8,
                rationale="Фрагментировать TLS записи для обхода DPI",
                preconditions=["vulnerable_to_fragmentation"],
                side_effects=["may_increase_packet_count"],
                parameter_ranges={
                    "split_count": [2, 4, 8, 16],
                    "split_position": ["sni", "random", "fixed"]
                }
            ),
            
            "ip_fragmentation": StrategyIntent(
                key="ip_fragmentation",
                priority=0.75,
                rationale="Фрагментировать на IP уровне",
                preconditions=["ip_fragmentation_allowed"],
                side_effects=["may_be_blocked_by_firewall"],
                parameter_ranges={
                    "fragment_size": [8, 16, 32, 64]
                }
            ),
            
            # Decoy Packet Intents
            "short_ttl_decoy": StrategyIntent(
                key="short_ttl_decoy",
                priority=0.85,
                rationale="Отправить поддельный пакет с коротким TTL",
                preconditions=["active_rst_injection"],
                side_effects=["may_trigger_rate_limiting"],
                parameter_ranges={
                    "ttl": [1, 2, 3],
                    "fooling_method": ["badsum", "badseq"]
                }
            ),
            
            "out_of_order_decoy": StrategyIntent(
                key="out_of_order_decoy",
                priority=0.7,
                rationale="Отправить пакеты в неправильном порядке",
                preconditions=["stateless_dpi"],
                side_effects=["may_confuse_legitimate_middleboxes"],
                parameter_ranges={
                    "disorder_method": ["reverse", "random"],
                    "fake_packet_position": ["first", "middle", "last"]
                }
            ),
            
            # Packet Reordering Intents
            "packet_reordering": StrategyIntent(
                key="packet_reordering",
                priority=0.8,
                rationale="Изменить порядок пакетов для обхода stateless DPI",
                preconditions=["stateless_dpi"],
                side_effects=["may_cause_tcp_retransmissions"],
                parameter_ranges={
                    "reorder_method": ["simple", "complex"],
                    "split_positions": [1, 2, 3, 4]
                }
            ),
            
            "sequence_overlap": StrategyIntent(
                key="sequence_overlap",
                priority=0.75,
                rationale="Создать перекрытие TCP последовательностей",
                preconditions=["stateful_tracking_vulnerable"],
                side_effects=["complex_tcp_state_management"],
                parameter_ranges={
                    "overlap_size": [1, 2, 4, 8]
                }
            ),
            
            # Timing Manipulation Intents
            "timing_manipulation": StrategyIntent(
                key="timing_manipulation",
                priority=0.6,
                rationale="Изменить тайминг отправки пакетов",
                preconditions=["timing_sensitive_dpi"],
                side_effects=["increased_connection_time"],
                parameter_ranges={
                    "delay_ms": [10, 50, 100, 200],
                    "jitter_enabled": [True, False]
                }
            ),
            
            # Protocol Evasion Intents
            "tls_extension_manipulation": StrategyIntent(
                key="tls_extension_manipulation",
                priority=0.7,
                rationale="Манипулировать TLS расширениями",
                preconditions=["weak_tls_parser"],
                side_effects=["may_break_tls_features"],
                parameter_ranges={
                    "extension_order": ["random", "reverse"],
                    "fake_extensions": [True, False]
                }
            ),
            
            "http_header_manipulation": StrategyIntent(
                key="http_header_manipulation",
                priority=0.65,
                rationale="Изменить HTTP заголовки",
                preconditions=["http_content_filtering"],
                side_effects=["may_break_http_features"],
                parameter_ranges={
                    "header_case": ["mixed", "upper", "lower"],
                    "header_order": ["random", "reverse"]
                }
            ),
            
            # Content Obfuscation Intents
            "payload_obfuscation": StrategyIntent(
                key="payload_obfuscation",
                priority=0.6,
                rationale="Обфусцировать содержимое пакетов",
                preconditions=["deep_content_inspection"],
                side_effects=["computational_overhead"],
                parameter_ranges={
                    "obfuscation_method": ["xor", "base64", "compression"]
                }
            ),
            
            # ИСПРАВЛЕНИЕ: Добавлены отсутствующие intent ключи
            "timeout_adjustment": StrategyIntent(
                key="timeout_adjustment",
                priority=0.5,
                rationale="Настройка таймаутов для медленных соединений",
                preconditions=["slow_connection_detected"],
                side_effects=["increased_connection_time"],
                parameter_ranges={
                    "connect_timeout": [5, 10, 15, 30],
                    "read_timeout": [10, 20, 30, 60]
                }
            ),
            
            "ipv6_fallback": StrategyIntent(
                key="ipv6_fallback",
                priority=0.4,
                rationale="Использовать IPv6 если IPv4 заблокирован",
                preconditions=["ipv4_blocked", "ipv6_available"],
                side_effects=["may_not_work_on_ipv4_only_networks"],
                parameter_ranges={
                    "prefer_ipv6": [True, False],
                    "fallback_timeout": [3, 5, 10]
                }
            )
        }
        
        LOG.info(f"Построен реестр из {len(intents)} намерений стратегий")
        return intents
    
    def propose_intents(self, 
                       fingerprint, 
                       failure_report: Optional[Dict[str, Any]] = None) -> List[StrategyIntent]:
        """
        Предлагает Intent'ы на основе DPI fingerprint и анализа неудач.
        
        Args:
            fingerprint: DPIFingerprint объект
            failure_report: Опциональный отчет об анализе неудач
            
        Returns:
            Список StrategyIntent отсортированный по приоритету
        """
        
        self.rule_stats["evaluations"] += 1
        
        intents = []
        
        # Импортируем enum'ы из fingerprint service
        try:
            from core.fingerprint.dpi_fingerprint_service import DPIType, DPIMode, DetectionLayer
        except ImportError:
            LOG.warning("Не удалось импортировать enum'ы из DPI fingerprint service")
            # Fallback enum'ы
            class DPIType(Enum):
                STATEFUL = "stateful"
                STATELESS = "stateless"
                HYBRID = "hybrid"
                UNKNOWN = "unknown"
            
            class DPIMode(Enum):
                PASSIVE = "passive"
                ACTIVE_RST = "active_rst"
                ACTIVE_DROP = "active_drop"
                MIXED = "mixed"
                UNKNOWN = "unknown"
            
            class DetectionLayer(Enum):
                L3_IP = "l3_ip"
                L4_TCP = "l4_tcp"
                L7_TLS = "l7_tls"
                L7_HTTP = "l7_http"
                MULTI_LAYER = "multi_layer"
                UNKNOWN = "unknown"
        
        # Правило 1: SNI-зависимая блокировка
        if self._has_sni_dependency(fingerprint):
            intents.extend([
                self.intent_registry["conceal_sni"],
                self.intent_registry["fake_sni"],
                self.intent_registry["record_fragmentation"]
            ])
            LOG.debug("Добавлены Intent'ы для SNI блокировки")
        
        # Правило 2: Активная RST инъекция
        if fingerprint.dpi_mode == DPIMode.ACTIVE_RST:
            intents.extend([
                self.intent_registry["short_ttl_decoy"],
                self.intent_registry["out_of_order_decoy"]
            ])
            LOG.debug("Добавлены Intent'ы для активной RST инъекции")
        
        # Правило 3: Stateless DPI
        if fingerprint.dpi_type == DPIType.STATELESS:
            intents.extend([
                self.intent_registry["packet_reordering"],
                self.intent_registry["out_of_order_decoy"]
            ])
            LOG.debug("Добавлены Intent'ы для stateless DPI")
        
        # Правило 4: Stateful DPI с уязвимостями
        if fingerprint.dpi_type == DPIType.STATEFUL:
            intents.extend([
                self.intent_registry["sequence_overlap"],
                self.intent_registry["record_fragmentation"]
            ])
            LOG.debug("Добавлены Intent'ы для stateful DPI")
        
        # Правило 5: Уязвимость к фрагментации
        if "vulnerable_to_fragmentation" in fingerprint.known_weaknesses:
            intents.extend([
                self.intent_registry["record_fragmentation"],
                self.intent_registry["ip_fragmentation"]
            ])
            LOG.debug("Добавлены Intent'ы для фрагментации")
        
        # Правило 6: TLS уровень обнаружения
        if fingerprint.detection_layer == DetectionLayer.L7_TLS:
            intents.extend([
                self.intent_registry["conceal_sni"],
                self.intent_registry["tls_extension_manipulation"]
            ])
            LOG.debug("Добавлены Intent'ы для TLS уровня")
        
        # Правило 7: HTTP уровень обнаружения
        if fingerprint.detection_layer == DetectionLayer.L7_HTTP:
            intents.extend([
                self.intent_registry["http_header_manipulation"],
                self.intent_registry["payload_obfuscation"]
            ])
            LOG.debug("Добавлены Intent'ы для HTTP уровня")
        
        # Правило 8: Глубокая инспекция контента
        if fingerprint.behavioral_signatures.get("deep_content_inspection"):
            intents.append(self.intent_registry["payload_obfuscation"])
            LOG.debug("Добавлен Intent для обфускации payload")
        
        # Правило 9: Слабый TLS парсер
        if fingerprint.behavioral_signatures.get("weak_tls_parser"):
            intents.append(self.intent_registry["tls_extension_manipulation"])
            LOG.debug("Добавлен Intent для манипуляции TLS расширениями")
        
        # Учитываем failure report
        if failure_report:
            failure_intents = self._intents_from_failure(failure_report)
            intents.extend(failure_intents)
            LOG.debug(f"Добавлено {len(failure_intents)} Intent'ов из failure report")
        
        # Fallback Intent'ы для неизвестных типов DPI
        if not intents or fingerprint.dpi_type == DPIType.UNKNOWN:
            fallback_intents = self._get_fallback_intents(fingerprint)
            intents.extend(fallback_intents)
            self.rule_stats["fallback_used"] += 1
            LOG.debug(f"Добавлено {len(fallback_intents)} fallback Intent'ов")
        
        # Удаляем дубликаты и сортируем по приоритету
        unique_intents = list({intent.key: intent for intent in intents}.values())
        sorted_intents = sorted(unique_intents, key=lambda x: x.priority, reverse=True)
        
        self.rule_stats["intents_generated"] += len(sorted_intents)
        
        LOG.info(f"Сгенерировано {len(sorted_intents)} Intent'ов для {fingerprint.domain}")
        
        return sorted_intents
    
    def _has_sni_dependency(self, fingerprint) -> bool:
        """Проверка на SNI-зависимую блокировку"""
        return (
            fingerprint.behavioral_signatures.get("sni_filtering", False) or
            fingerprint.detection_layer.value == "l7_tls" or
            any("sni" in weakness for weakness in fingerprint.known_weaknesses)
        )
    
    def _intents_from_failure(self, failure_report: Dict[str, Any]) -> List[StrategyIntent]:
        """Генерация Intent'ов на основе анализа неудач"""
        
        intents = []
        root_cause = failure_report.get("root_cause", "")
        
        if root_cause == "dpi_active_rst_injection":
            intents.extend([
                self.intent_registry["short_ttl_decoy"],
                self.intent_registry["sequence_overlap"]
            ])
        
        elif root_cause == "dpi_reassembles_fragments":
            intents.extend([
                self.intent_registry["packet_reordering"],
                self.intent_registry["timing_manipulation"]
            ])
        
        elif root_cause == "dpi_sni_filtering":
            intents.extend([
                self.intent_registry["conceal_sni"],
                self.intent_registry["fake_sni"]
            ])
        
        elif root_cause == "dpi_content_inspection":
            intents.extend([
                self.intent_registry["payload_obfuscation"],
                self.intent_registry["tls_extension_manipulation"]
            ])
        
        return intents
    
    def _get_fallback_intents(self, fingerprint) -> List[StrategyIntent]:
        """Fallback Intent'ы для неизвестных типов DPI"""
        
        # Базовые Intent'ы с умеренным приоритетом
        fallback_intents = [
            StrategyIntent(
                key="basic_fragmentation",
                priority=0.6,
                rationale="Базовая фрагментация как fallback",
                preconditions=[],
                side_effects=["minimal_impact"]
            ),
            StrategyIntent(
                key="simple_reordering",
                priority=0.55,
                rationale="Простое изменение порядка пакетов",
                preconditions=[],
                side_effects=["minimal_impact"]
            ),
            StrategyIntent(
                key="basic_sni_concealment",
                priority=0.5,
                rationale="Базовое сокрытие SNI",
                preconditions=[],
                side_effects=["may_break_sni_dependent_services"]
            )
        ]
        
        # Повышаем приоритет если confidence высокий
        if fingerprint.confidence > 0.7:
            for intent in fallback_intents:
                intent.priority += 0.1
        
        return fallback_intents
    
    def get_intent_by_key(self, key: str) -> Optional[StrategyIntent]:
        """Получение Intent'а по ключу"""
        return self.intent_registry.get(key)
    
    def list_available_intents(self) -> List[str]:
        """Получение списка доступных Intent'ов"""
        return list(self.intent_registry.keys())
    
    def get_intents_by_category(self, category: IntentCategory) -> List[StrategyIntent]:
        """Получение Intent'ов по категории"""
        
        category_mapping = {
            IntentCategory.SNI_CONCEALMENT: ["conceal_sni", "fake_sni"],
            IntentCategory.FRAGMENTATION: ["record_fragmentation", "ip_fragmentation"],
            IntentCategory.DECOY_PACKETS: ["short_ttl_decoy", "out_of_order_decoy"],
            IntentCategory.PACKET_REORDERING: ["packet_reordering", "sequence_overlap"],
            IntentCategory.TIMING_MANIPULATION: ["timing_manipulation"],
            IntentCategory.PROTOCOL_EVASION: ["tls_extension_manipulation", "http_header_manipulation"],
            IntentCategory.CONTENT_OBFUSCATION: ["payload_obfuscation"]
        }
        
        intent_keys = category_mapping.get(category, [])
        return [self.intent_registry[key] for key in intent_keys if key in self.intent_registry]
    
    def explain_intent_selection(self, 
                                fingerprint, 
                                selected_intents: List[StrategyIntent]) -> Dict[str, str]:
        """Объяснение логики выбора Intent'ов"""
        
        explanations = {}
        
        for intent in selected_intents:
            explanation_parts = [f"Intent '{intent.key}' выбран потому что:"]
            
            # Основное обоснование
            explanation_parts.append(f"- {intent.rationale}")
            
            # Анализ предусловий
            if intent.preconditions:
                met_conditions = []
                for condition in intent.preconditions:
                    if self._check_precondition(fingerprint, condition):
                        met_conditions.append(condition)
                
                if met_conditions:
                    # Фильтруем None значения
                    filtered_conditions = [c for c in met_conditions if c is not None]
                    if filtered_conditions:
                        explanation_parts.append(f"- Выполнены условия: {', '.join(filtered_conditions)}")
            
            # Информация о приоритете
            explanation_parts.append(f"- Приоритет: {intent.priority:.2f}")
            
            # Предупреждения о побочных эффектах
            if intent.side_effects:
                # Фильтруем None значения
                filtered_effects = [e for e in intent.side_effects if e is not None]
                if filtered_effects:
                    explanation_parts.append(f"- Возможные побочные эффекты: {', '.join(filtered_effects)}")
            
            explanations[intent.key] = "\n".join(explanation_parts)
        
        return explanations
    
    def _check_precondition(self, fingerprint, condition: str) -> bool:
        """Проверка выполнения предусловия"""
        
        condition_checks = {
            "sni_filtering_detected": lambda fp: fp.behavioral_signatures.get("sni_filtering", False),
            "vulnerable_to_fragmentation": lambda fp: "vulnerable_to_fragmentation" in fp.known_weaknesses,
            "active_rst_injection": lambda fp: fp.dpi_mode.value == "active_rst",
            "stateless_dpi": lambda fp: fp.dpi_type.value == "stateless",
            "stateful_tracking_vulnerable": lambda fp: fp.dpi_type.value == "stateful",
            "timing_sensitive_dpi": lambda fp: fp.behavioral_signatures.get("timing_sensitive", False),
            "weak_tls_parser": lambda fp: fp.behavioral_signatures.get("weak_tls_parser", False),
            "http_content_filtering": lambda fp: fp.detection_layer.value == "l7_http",
            "deep_content_inspection": lambda fp: fp.behavioral_signatures.get("deep_content_inspection", False),
            "ip_fragmentation_allowed": lambda fp: not fp.behavioral_signatures.get("blocks_ip_fragmentation", False)
        }
        
        check_func = condition_checks.get(condition)
        if check_func:
            try:
                return check_func(fingerprint)
            except Exception as e:
                LOG.warning(f"Ошибка проверки условия {condition}: {e}")
                return False
        
        return False
    
    def update_intent_from_failure(self, 
                                  intent_key: str, 
                                  failure_report: Dict[str, Any]):
        """Обновление Intent'а на основе анализа неудач"""
        
        if intent_key not in self.intent_registry:
            LOG.warning(f"Intent {intent_key} не найден для обновления")
            return
        
        intent = self.intent_registry[intent_key]
        
        # Снижаем приоритет при неудачах
        failure_confidence = failure_report.get("confidence", 0.5)
        if failure_confidence > 0.7:
            # Высокая уверенность в анализе неудачи - значительно снижаем приоритет
            intent.priority *= 0.8
            LOG.info(f"Снижен приоритет Intent'а {intent_key} до {intent.priority:.2f}")
        
        # Добавляем информацию о неудаче в rationale
        root_cause = failure_report.get("root_cause", "unknown")
        if root_cause not in intent.rationale:
            intent.rationale += f" (неудача: {root_cause})"
    
    def generate_explanations(self, 
                            fingerprint, 
                            selected_intents: List[StrategyIntent]) -> Dict[str, str]:
        """Генерация объяснений для каждого предложенного Intent'а"""
        
        explanations = {}
        
        for intent in selected_intents:
            explanation_parts = []
            
            # Основное обоснование
            explanation_parts.append(f"🎯 Intent '{intent.key}':")
            explanation_parts.append(f"   Обоснование: {intent.rationale}")
            explanation_parts.append(f"   Приоритет: {intent.priority:.2f}")
            
            # Анализ DPI характеристик
            dpi_reasons = self._analyze_dpi_match(fingerprint, intent)
            if dpi_reasons:
                # Фильтруем None значения
                filtered_reasons = [r for r in dpi_reasons if r is not None]
                if filtered_reasons:
                    explanation_parts.append(f"   DPI анализ: {', '.join(filtered_reasons)}")
            
            # Предупреждения
            if intent.side_effects:
                # Фильтруем None значения
                filtered_effects = [e for e in intent.side_effects if e is not None]
                if filtered_effects:
                    explanation_parts.append(f"   ⚠️ Побочные эффекты: {', '.join(filtered_effects)}")
            
            # Рекомендуемые параметры
            if intent.parameter_ranges:
                param_info = []
                for param, values in intent.parameter_ranges.items():
                    if isinstance(values, list) and values:
                        param_info.append(f"{param}={values[0]}")
                if param_info:
                    explanation_parts.append(f"   🔧 Параметры: {', '.join(param_info)}")
            
            explanations[intent.key] = "\n".join(explanation_parts)
        
        return explanations
    
    def _analyze_dpi_match(self, fingerprint, intent: StrategyIntent) -> List[str]:
        """Анализ соответствия DPI характеристик Intent'у"""
        
        reasons = []
        
        try:
            # Проверяем тип DPI
            if hasattr(fingerprint, 'dpi_type'):
                dpi_type = fingerprint.dpi_type.value
                
                if intent.key in ["packet_reordering", "out_of_order_decoy"] and dpi_type == "stateless":
                    reasons.append("stateless DPI уязвим к изменению порядка")
                elif intent.key in ["sequence_overlap", "record_fragmentation"] and dpi_type == "stateful":
                    reasons.append("stateful DPI может быть обманут перекрытиями")
            
            # Проверяем режим DPI
            if hasattr(fingerprint, 'dpi_mode'):
                dpi_mode = fingerprint.dpi_mode.value
                
                if intent.key == "short_ttl_decoy" and dpi_mode == "active_rst":
                    reasons.append("активная RST инъекция обходится короткими TTL")
            
            # Проверяем поведенческие сигнатуры
            if hasattr(fingerprint, 'behavioral_signatures'):
                signatures = fingerprint.behavioral_signatures
                
                if intent.key in ["conceal_sni", "fake_sni"] and signatures.get("sni_filtering"):
                    reasons.append("обнаружена фильтрация по SNI")
                
                if intent.key == "record_fragmentation" and signatures.get("reassembles_fragments", False):
                    reasons.append("DPI не собирает фрагменты")
                
                if intent.key == "payload_obfuscation" and signatures.get("deep_content_inspection"):
                    reasons.append("глубокая инспекция контента требует обфускации")
            
            # Проверяем известные уязвимости
            if hasattr(fingerprint, 'known_weaknesses'):
                for weakness in fingerprint.known_weaknesses:
                    if "fragmentation" in weakness and intent.key == "record_fragmentation":
                        reasons.append(f"известная уязвимость: {weakness}")
                    elif "sni" in weakness and intent.key in ["conceal_sni", "fake_sni"]:
                        reasons.append(f"известная уязвимость: {weakness}")
        
        except Exception as e:
            LOG.warning(f"Ошибка анализа DPI соответствия: {e}")
        
        return reasons
    
    def create_fallback_intents_for_unknown_dpi(self, 
                                              fingerprint) -> List[StrategyIntent]:
        """Создание fallback Intent'ов для неизвестных типов DPI"""
        
        fallback_intents = []
        
        # Базовые Intent'ы с адаптивными приоритетами
        base_intents = [
            ("basic_fragmentation", 0.6, "Базовая фрагментация"),
            ("simple_reordering", 0.55, "Простое изменение порядка"),
            ("basic_sni_concealment", 0.5, "Базовое сокрытие SNI")
        ]
        
        for key, priority, rationale in base_intents:
            # Адаптируем приоритет под confidence fingerprint'а
            adapted_priority = priority
            if hasattr(fingerprint, 'confidence'):
                if fingerprint.confidence < 0.3:
                    adapted_priority += 0.1  # Повышаем при низкой уверенности
                elif fingerprint.confidence > 0.8:
                    adapted_priority -= 0.1  # Снижаем при высокой уверенности
            
            intent = StrategyIntent(
                key=key,
                priority=adapted_priority,
                rationale=f"{rationale} (fallback для неизвестного DPI)",
                preconditions=[],
                side_effects=["minimal_impact"],
                parameter_ranges=self._get_conservative_parameters(key)
            )
            
            fallback_intents.append(intent)
        
        LOG.info(f"Создано {len(fallback_intents)} fallback Intent'ов")
        return fallback_intents
    
    def _get_conservative_parameters(self, intent_key: str) -> Dict[str, Any]:
        """Получение консервативных параметров для fallback Intent'ов"""
        
        conservative_params = {
            "basic_fragmentation": {
                "split_count": [2, 4],
                "split_pos": ["random", "fixed"]
            },
            "simple_reordering": {
                "split_pos": [2, 3],
                "disorder_method": ["simple"]
            },
            "basic_sni_concealment": {
                "split_pos": ["sni"],
                "fooling_method": ["badsum", "badseq"]
            }
        }
        
        return conservative_params.get(intent_key, {})
    
    def from_keys(self, 
                 keys: List[str], 
                 base_weight: float = 0.9) -> List[StrategyIntent]:
        """
        Создание StrategyIntent объектов из списка ключей.
        
        НОВЫЙ МЕТОД для интеграции с замкнутым циклом обучения.
        Используется для преобразования intent ключей из SFA и KnowledgeAccumulator
        в объекты StrategyIntent.
        
        Args:
            keys: Список строковых ключей intent'ов
            base_weight: Базовый вес для всех intent'ов (0.0-1.0)
            
        Returns:
            Список объектов StrategyIntent
        """
        intents = []
        
        for key in keys:
            # Проверяем наличие в реестре
            if key in self.intent_registry:
                intent = self.intent_registry[key]
                
                # Создаем копию с обновленным приоритетом
                adjusted_intent = StrategyIntent(
                    key=intent.key,
                    priority=base_weight,  # Используем переданный base_weight
                    rationale=intent.rationale,
                    preconditions=intent.preconditions.copy(),
                    side_effects=intent.side_effects.copy(),
                    parameter_ranges=intent.parameter_ranges.copy()
                )
                
                intents.append(adjusted_intent)
                LOG.debug(f"Создан Intent {key} с приоритетом {base_weight}")
            else:
                LOG.debug(f"Intent ключ '{key}' не найден в реестре, пропускаем")
        
        LOG.info(f"Создано {len(intents)} Intent'ов из {len(keys)} ключей")
        return intents
    
    def validate_intent_keys(self, keys: List[str]) -> Dict[str, bool]:
        """
        Валидация ключей intent'ов.
        
        Args:
            keys: Список ключей для проверки
            
        Returns:
            Словарь {ключ: валиден}
        """
        validation_results = {}
        
        for key in keys:
            is_valid = key in self.intent_registry
            validation_results[key] = is_valid
            
            if not is_valid:
                LOG.warning(f"Невалидный intent ключ: {key}")
        
        valid_count = sum(validation_results.values())
        LOG.info(f"Валидация: {valid_count}/{len(keys)} ключей валидны")
        
        return validation_results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики работы движка"""
        
        return {
            "total_intents_available": len(self.intent_registry),
            "rule_stats": self.rule_stats.copy(),
            "intent_categories": len(IntentCategory),
            "average_intent_priority": sum(intent.priority for intent in self.intent_registry.values()) / len(self.intent_registry)
        }


# Пример использования
if __name__ == "__main__":
    # Создаем движок намерений
    engine = StrategyIntentEngine()
    
    # Создаем тестовый fingerprint
    from core.fingerprint.dpi_fingerprint_service import DPIFingerprint, DPIType, DPIMode, DetectionLayer
    
    test_fingerprint = DPIFingerprint(
        fingerprint_id="test_001",
        domain="example.com",
        ip_address="1.2.3.4",
        dpi_type=DPIType.STATEFUL,
        dpi_mode=DPIMode.ACTIVE_RST,
        detection_layer=DetectionLayer.L7_TLS,
        behavioral_signatures={
            "sni_filtering": True,
            "deep_content_inspection": False
        },
        known_weaknesses=["vulnerable_to_fragmentation"],
        confidence=0.85
    )
    
    # Генерируем Intent'ы
    intents = engine.propose_intents(test_fingerprint)
    
    print(f"Сгенерировано {len(intents)} Intent'ов:")
    for intent in intents:
        print(f"  - {intent.key} (приоритет: {intent.priority:.2f})")
        print(f"    Обоснование: {intent.rationale}")
    
    # Получаем объяснения
    explanations = engine.explain_intent_selection(test_fingerprint, intents[:3])
    
    print("\nОбъяснения выбора Intent'ов:")
    for key, explanation in explanations.items():
        print(f"\n{key}:")
        print(explanation)
    
    # Статистика
    stats = engine.get_statistics()
    print(f"\nСтатистика движка: {stats}")