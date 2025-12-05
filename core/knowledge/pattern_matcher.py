"""
Pattern Matcher - сопоставление паттернов блокировок с правилами из базы знаний.

Этот модуль реализует логику сопоставления FailureReport с правилами
из KnowledgeAccumulator для извлечения рекомендованных intent'ов и tweaks.
"""

import logging
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta

from .knowledge_accumulator import KnowledgeAccumulator, PatternRule

LOG = logging.getLogger("PatternMatcher")


class PatternMatcher:
    """
    Сопоставление паттернов блокировок с правилами из базы знаний.
    
    Основные функции:
    - Загрузка правил из KnowledgeAccumulator
    - Сопоставление FailureReport с условиями правил
    - Извлечение рекомендованных intent'ов и tweaks
    - Приоритизация правил при множественных совпадениях
    """
    
    def __init__(self, knowledge_accumulator: KnowledgeAccumulator):
        """
        Инициализация Pattern Matcher.
        
        Args:
            knowledge_accumulator: Экземпляр KnowledgeAccumulator
        """
        self.knowledge_accumulator = knowledge_accumulator
        self.match_cache = {}  # Кэш для ускорения повторных сопоставлений
        self.cache_ttl = timedelta(hours=1)  # TTL кэша: 1 час
        
        LOG.info("PatternMatcher инициализирован")
    
    def apply_knowledge_rules(self,
                             failure_report: Any,  # FailureReport
                             context: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
        """
        Применение правил базы знаний к отчету о неудаче с профилированием.
        
        Args:
            failure_report: Отчет об анализе неудачи
            context: Контекст (ASN, IP, domain, provider и т.д.)
            
        Returns:
            Tuple[List[str], Dict[str, Any]]: (intent_keys, tweaks)
        """
        import time
        
        method_start_time = time.time()
        
        # Проверяем кэш
        cache_start_time = time.time()
        cache_key = self._create_cache_key(failure_report, context)
        cached_result = self._get_from_cache(cache_key)
        cache_time = time.time() - cache_start_time
        
        if cached_result:
            LOG.debug(f"Использован кэшированный результат сопоставления (время: {cache_time:.3f}s)")
            return cached_result
        
        intent_keys = []
        tweaks = {}
        
        # Получаем все правила
        patterns = self.knowledge_accumulator.patterns
        
        # Находим совпадающие правила с профилированием
        matching_start_time = time.time()
        matching_patterns = []
        for pattern in patterns:
            if self._matches(pattern.conditions, failure_report, context):
                matching_patterns.append(pattern)
        matching_time = time.time() - matching_start_time
        
        if not matching_patterns:
            LOG.debug(f"Нет совпадающих правил, используем fallback (время поиска: {matching_time:.3f}s)")
            result = self._get_fallback_intents(failure_report), {}
            self._cache_result(cache_key, result)
            return result
        
        # Сортируем по confidence
        sort_start_time = time.time()
        matching_patterns.sort(
            key=lambda p: p.metadata.get("confidence", 0.5),
            reverse=True
        )
        sort_time = time.time() - sort_start_time
        
        # Ограничиваем количество правил
        max_patterns = self.knowledge_accumulator.global_settings.get(
            "max_patterns_per_match", 3
        )
        matching_patterns = matching_patterns[:max_patterns]
        
        # Собираем intent'ы и tweaks
        collection_start_time = time.time()
        for pattern in matching_patterns:
            # Добавляем intent'ы
            for rec in pattern.recommend:
                intent_keys.append(rec["intent"])
            
            # Объединяем tweaks (последние имеют приоритет)
            tweaks.update(pattern.tweaks)
        
        # Удаляем дубликаты intent'ов, сохраняя порядок
        intent_keys = list(dict.fromkeys(intent_keys))
        collection_time = time.time() - collection_start_time
        
        # Общее время выполнения
        total_time = time.time() - method_start_time
        
        LOG.info(f"Найдено {len(matching_patterns)} совпадающих правил, "
                f"извлечено {len(intent_keys)} intent'ов "
                f"(время: {total_time:.3f}s, поиск: {matching_time:.3f}s, "
                f"сортировка: {sort_time:.3f}s, сбор: {collection_time:.3f}s)")
        
        result = (intent_keys, tweaks)
        self._cache_result(cache_key, result)
        return result
    
    def _matches(self,
                conditions: Dict[str, Any],
                failure_report: Any,  # FailureReport
                context: Dict[str, Any]) -> bool:
        """
        Проверка соответствия условиям правила.
        
        Args:
            conditions: Условия из PatternRule
            failure_report: Отчет об анализе неудачи
            context: Контекст выполнения
            
        Returns:
            True если все условия выполнены
        """
        
        # Проверка root_cause (обязательное условие)
        if "root_cause" in conditions:
            if failure_report.root_cause.value != conditions["root_cause"]:
                return False
        
        # Проверка indicators.any
        if "indicators.any" in conditions:
            required_indicators = conditions["indicators.any"]
            failure_indicators = failure_report.failure_details.get("indicators", [])
            
            if not any(ind in failure_indicators for ind in required_indicators):
                return False
        
        # Проверка indicators.all
        if "indicators.all" in conditions:
            required_indicators = conditions["indicators.all"]
            failure_indicators = failure_report.failure_details.get("indicators", [])
            
            if not all(ind in failure_indicators for ind in required_indicators):
                return False
        
        # Проверка indicators.none
        if "indicators.none" in conditions:
            forbidden_indicators = conditions["indicators.none"]
            failure_indicators = failure_report.failure_details.get("indicators", [])
            
            if any(ind in failure_indicators for ind in forbidden_indicators):
                return False
        
        # Проверка ASN
        if "asn.any" in conditions:
            required_asns = conditions["asn.any"]
            context_asn = context.get("asn")
            if context_asn not in required_asns:
                return False
        
        # Проверка timing (less than)
        if "rst_timing_ms.lt" in conditions:
            max_timing = conditions["rst_timing_ms.lt"]
            actual_timing = failure_report.failure_details.get("rst_timing_ms", float('inf'))
            if actual_timing >= max_timing:
                return False
        
        # Проверка timing (greater than)
        if "rst_timing_ms.gt" in conditions:
            min_timing = conditions["rst_timing_ms.gt"]
            actual_timing = failure_report.failure_details.get("rst_timing_ms", 0)
            if actual_timing <= min_timing:
                return False
        
        # Проверка connection_established
        if "connection_established" in conditions:
            required = conditions["connection_established"]
            actual = failure_report.failure_details.get("connection_established", False)
            if required != actual:
                return False
        
        # Проверка server_hello.none
        if "server_hello.none" in conditions:
            has_server_hello = failure_report.failure_details.get("has_server_hello", False)
            if has_server_hello:
                return False
        
        # Проверка tls_alerts.none
        if "tls_alerts.none" in conditions:
            tls_alerts = failure_report.failure_details.get("tls_alerts", [])
            if tls_alerts:
                return False
        
        # Проверка dpi_type
        if "dpi_type" in conditions:
            required_type = conditions["dpi_type"]
            actual_type = failure_report.failure_details.get("dpi_type")
            if actual_type != required_type:
                return False
        
        # Проверка fragments_detected
        if "fragments_detected" in conditions:
            required = conditions["fragments_detected"]
            actual = failure_report.failure_details.get("fragments_detected", False)
            if required != actual:
                return False
        
        # Проверка confidence threshold
        min_confidence = self.knowledge_accumulator.global_settings.get(
            "min_confidence_threshold", 0.7
        )
        if failure_report.confidence < min_confidence:
            return False
        
        return True
    
    def _get_fallback_intents(self, failure_report: Any) -> List[str]:
        """
        Fallback intent'ы когда нет совпадающих правил.
        
        Args:
            failure_report: Отчет об анализе неудачи
            
        Returns:
            Список базовых intent'ов для данного типа неудачи
        """
        
        # Используем базовый маппинг из SFA
        fallback_mapping = {
            "DPI_SNI_FILTERING": ["conceal_sni", "record_fragmentation"],
            "DPI_ACTIVE_RST_INJECTION": ["short_ttl_decoy", "sequence_overlap"],
            "DPI_CONTENT_INSPECTION": ["payload_obfuscation", "tls_extension_manipulation"],
            "DPI_REASSEMBLES_FRAGMENTS": ["packet_reordering", "timing_manipulation"],
            "DPI_STATEFUL_TRACKING": ["sequence_overlap", "out_of_order_decoy"],
            "NETWORK_TIMEOUT": ["timeout_adjustment", "ipv6_fallback"],
            "CONNECTION_REFUSED": ["port_randomization", "ipv6_fallback"],
            "TLS_HANDSHAKE_FAILURE": ["tls_extension_manipulation", "record_fragmentation"]
        }
        
        return fallback_mapping.get(failure_report.root_cause.value, ["record_fragmentation"])
    
    def _create_cache_key(self, failure_report: Any, context: Dict[str, Any]) -> str:
        """Создание ключа для кэша."""
        # Создаем ключ на основе основных характеристик
        key_parts = [
            failure_report.root_cause.value,
            str(failure_report.confidence),
            context.get("asn") or "",
            context.get("domain") or "",
            str(sorted(failure_report.failure_details.get("indicators", [])))
        ]
        
        # Фильтруем None значения и конвертируем все в строки
        key_parts = [str(part) if part is not None else "" for part in key_parts]
        
        return "|".join(key_parts)
    
    def _get_from_cache(self, cache_key: str) -> Optional[Tuple[List[str], Dict[str, Any]]]:
        """Получение результата из кэша."""
        if cache_key in self.match_cache:
            cached_data, timestamp = self.match_cache[cache_key]
            
            # Проверяем TTL
            if datetime.now() - timestamp < self.cache_ttl:
                return cached_data
            else:
                # Удаляем устаревший результат
                del self.match_cache[cache_key]
        
        return None
    
    def _cache_result(self, cache_key: str, result: Tuple[List[str], Dict[str, Any]]):
        """Сохранение результата в кэш."""
        self.match_cache[cache_key] = (result, datetime.now())
        
        # Очистка старых записей (простая стратегия)
        if len(self.match_cache) > 1000:
            # Удаляем 20% самых старых записей
            sorted_items = sorted(
                self.match_cache.items(),
                key=lambda x: x[1][1]  # Сортируем по timestamp
            )
            
            items_to_remove = len(sorted_items) // 5  # 20%
            for key, _ in sorted_items[:items_to_remove]:
                del self.match_cache[key]
    
    def clear_cache(self):
        """Очистка кэша."""
        self.match_cache.clear()
        LOG.info("Кэш Pattern Matcher очищен")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Статистика кэша."""
        now = datetime.now()
        valid_entries = sum(
            1 for _, (_, timestamp) in self.match_cache.items()
            if now - timestamp < self.cache_ttl
        )
        
        return {
            "total_entries": len(self.match_cache),
            "valid_entries": valid_entries,
            "expired_entries": len(self.match_cache) - valid_entries,
            "cache_ttl_hours": self.cache_ttl.total_seconds() / 3600
        }
    
    def get_matching_patterns(self,
                             failure_report: Any,  # FailureReport
                             context: Dict[str, Any]) -> List[PatternRule]:
        """
        Получение списка совпадающих правил без применения.
        
        Полезно для отладки и анализа.
        
        Args:
            failure_report: Отчет об анализе неудачи
            context: Контекст выполнения
            
        Returns:
            Список совпадающих PatternRule
        """
        matching_patterns = []
        
        for pattern in self.knowledge_accumulator.patterns:
            if self._matches(pattern.conditions, failure_report, context):
                matching_patterns.append(pattern)
        
        # Сортируем по confidence
        matching_patterns.sort(
            key=lambda p: p.metadata.get("confidence", 0.5),
            reverse=True
        )
        
        return matching_patterns
    
    def explain_match(self,
                     pattern: PatternRule,
                     failure_report: Any,  # FailureReport
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Объяснение почему правило совпадает или не совпадает.
        
        Полезно для отладки правил.
        
        Args:
            pattern: Правило для проверки
            failure_report: Отчет об анализе неудачи
            context: Контекст выполнения
            
        Returns:
            Детальное объяснение сопоставления
        """
        explanation = {
            "pattern_id": pattern.id,
            "matches": False,
            "condition_results": {},
            "overall_result": False
        }
        
        conditions = pattern.conditions
        
        # Проверяем каждое условие отдельно
        for condition_key, condition_value in conditions.items():
            if condition_key == "root_cause":
                result = failure_report.root_cause.value == condition_value
                explanation["condition_results"][condition_key] = {
                    "expected": condition_value,
                    "actual": failure_report.root_cause.value,
                    "matches": result
                }
            
            elif condition_key == "indicators.any":
                failure_indicators = failure_report.failure_details.get("indicators", [])
                result = any(ind in failure_indicators for ind in condition_value)
                explanation["condition_results"][condition_key] = {
                    "expected_any_of": condition_value,
                    "actual": failure_indicators,
                    "matches": result
                }
            
            elif condition_key == "asn.any":
                context_asn = context.get("asn")
                result = context_asn in condition_value
                explanation["condition_results"][condition_key] = {
                    "expected_any_of": condition_value,
                    "actual": context_asn,
                    "matches": result
                }
            
            elif condition_key == "rst_timing_ms.lt":
                actual_timing = failure_report.failure_details.get("rst_timing_ms", float('inf'))
                result = actual_timing < condition_value
                explanation["condition_results"][condition_key] = {
                    "expected_less_than": condition_value,
                    "actual": actual_timing,
                    "matches": result
                }
            
            # Добавляем другие условия по мере необходимости
        
        # Общий результат
        explanation["overall_result"] = self._matches(conditions, failure_report, context)
        explanation["matches"] = explanation["overall_result"]
        
        return explanation