"""
Диспетчер атак DPI обхода.

Этот модуль содержит AttackDispatcher - центральный компонент для:
- Правильной маршрутизации каждого типа атаки к соответствующему обработчику
- Нормализации параметров атак
- Разрешения специальных значений параметров (cipher, sni, midsld)
- Обработки ошибок диспетчеризации
"""

# Standard library imports
import logging
from typing import Any, Dict, List, Optional, Tuple

# Local imports
from ..attacks.attack_registry import AttackRegistry, get_attack_registry
from ..attacks.metadata import SpecialParameterValues, ValidationResult
from ..techniques.primitives import BypassTechniques
from ..filtering.custom_sni import CustomSNIHandler

# Task 11.4: Import operation logger for validation
try:
    from core.operation_logger import get_operation_logger
    OPERATION_LOGGER_AVAILABLE = True
except ImportError:
    OPERATION_LOGGER_AVAILABLE = False
    get_operation_logger = None

logger = logging.getLogger(__name__)

try:
    # CORRECTED: Import the advanced attack and its config from their actual location.
    from ..attacks.tcp.fakeddisorder_attack import (
        FakedDisorderAttack as FixedFakeDisorderAttack,
        FakedDisorderConfig,
    )
    from ..attacks.tcp.manipulation import TCPMultiSplitAttack
    from ..attacks.base import AttackContext, AttackResult, AttackStatus

    ADVANCED_ATTACKS_AVAILABLE = True
    logger.info("✅ Advanced attacks imported successfully")
except ImportError as e:
    logger.warning(f"Advanced attacks not available: {e}")
    ADVANCED_ATTACKS_AVAILABLE = False
    # Создаем заглушки для совместимости

    class AttackContext:
        """Fallback AttackContext class for compatibility when advanced attacks are not available."""

        def __init__(self, **kwargs):
            """Initialize context with arbitrary keyword arguments."""
            for k, v in kwargs.items():
                setattr(self, k, v)

    class AttackResult:
        """Fallback AttackResult class for compatibility when advanced attacks are not available."""

        def __init__(self, status=None, segments=None, error_message=None, **kwargs):
            """Initialize attack result with status, segments, and optional error message."""
            self.status = status
            self.segments = segments or []
            self.error_message = error_message
            for k, v in kwargs.items():
                setattr(self, k, v)

    class AttackStatus:
        """Constants for attack execution status."""

        SUCCESS = "success"
        FAILURE = "failure"
        ERROR = "error"


logger = logging.getLogger(__name__)


class AttackDispatcher:
    """
    Центральный диспетчер для правильной маршрутизации атак DPI обхода.

    Основные функции:
    - Правильная маршрутизация каждого типа атаки к соответствующему обработчику
    - Нормализация и валидация параметров атак
    - Разрешение специальных значений параметров (cipher, sni, midsld)
    - Интеграция с продвинутыми атаками из директории attacks/
    - Fallback на примитивные атаки из primitives.py для обратной совместимости
    - Централизованная обработка ошибок и логирование

    Архитектура:
    1. Приоритет отдается продвинутым атакам из attacks/ (если доступны)
    2. Fallback на примитивные атаки из primitives.py
    3. Все параметры валидируются через AttackRegistry
    4. Специальные значения разрешаются автоматически

    Заменяет проблемный единый блок диспетчеризации в base_engine.py,
    где все атаки выполнялись как fakeddisorder.
    """

    def __init__(
        self, techniques: BypassTechniques, attack_registry: AttackRegistry = None
    ):
        """
        Инициализирует диспетчер атак.

        Args:
            techniques: Экземпляр BypassTechniques для выполнения атак (для обратной совместимости)
            attack_registry: Реестр атак (если None, используется глобальный)
        """
        self.techniques = techniques  # Сохраняем для обратной совместимости
        self.registry = attack_registry or get_attack_registry()

        # Инициализируем нормализатор параметров
        from .parameter_normalizer import ParameterNormalizer

        self.parameter_normalizer = ParameterNormalizer()

        # Инициализируем CustomSNIHandler для управления SNI в фейковых пакетах
        self.custom_sni_handler = CustomSNIHandler()

        # Validate that critical attacks are registered (no longer maintains separate dict)
        self._init_advanced_attacks()

        logger.info(
            f"AttackDispatcher initialized with parameter normalizer and CustomSNIHandler"
        )

    
    
    def resolve_strategy(self, strategy: str) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Разрешает zapret-style стратегию в последовательность атак.

        Поддерживаемые форматы стратегий:
        - Простые: "fake", "disorder", "split"
        - Комбинированные: "fake,disorder", "split,fake"
        - С параметрами: "fake:ttl=3", "disorder:split_pos=10"
        - Сложные: "fake:ttl=3,disorder:split_pos=sni"
        - Параметры без атаки: "hostspell=go-ogle.com" → автоопределение атаки

        Примеры разрешения:
        - "fake" → [("fake", {})]
        - "fake,disorder" → [("fakeddisorder", {})]
        - "disorder,fake" → [("fakeddisorder", {})]
        - "split" → [("split", {})]
        - "fake:ttl=3" → [("fake", {"ttl": 3})]
        - "disorder:split_pos=sni" → [("disorder", {"split_pos": "sni"})]
        - "hostspell=go-ogle.com" → [("http_host_header", {"fake_host": "go-ogle.com"})]

        Args:
            strategy: Zapret-style строка стратегии

        Returns:
            Список кортежей (attack_name, params) для выполнения

        Raises:
            ValueError: Неподдерживаемая стратегия или неверный формат
        """
        if not strategy or not strategy.strip():
            raise ValueError("Strategy cannot be empty")

        strategy = strategy.strip().lower()
        logger.info(f"🔍 Resolving zapret-style strategy: '{strategy}'")

        # Проверяем, является ли это smart_combo стратегией (например, "smart_combo_split_fake")
        if strategy.startswith("smart_combo_"):
            logger.info(f"🔍 Detected smart_combo strategy format: '{strategy}'")
            # Извлекаем атаки из имени: smart_combo_split_fake -> [split, fake]
            parts = strategy.replace("smart_combo_", "").split("_")
            attacks = []
            for part in parts:
                if part and part not in ["smart", "combo"]:
                    attacks.append((part, {}))
            logger.info(f"🔍 Parsed smart_combo into attacks: {[a[0] for a in attacks]}")
            # Разрешаем комбинации атак
            return self._resolve_attack_combinations(attacks)

        # Проверяем, является ли вся стратегия одним параметром (например, hostspell=go-ogle.com)
        if "=" in strategy and ":" not in strategy and "," not in strategy:
            param_name, param_value = strategy.split("=", 1)
            param_name = param_name.strip()
            param_value = param_value.strip()
            
            # Определяем атаку по имени параметра
            attack_name, params = self._infer_attack_from_param(param_name, param_value)
            if attack_name:
                logger.info(f"🔍 Inferred attack '{attack_name}' from parameter '{param_name}={param_value}'")
                return [(attack_name, params)]

        # Разбираем стратегию на компоненты
        components = [comp.strip() for comp in strategy.split(",")]
        logger.debug(f"📋 Strategy components: {components}")

        attacks = []

        for i, component in enumerate(components):
            if not component:
                logger.debug(f"⚠️ Skipping empty component {i}")
                continue

            logger.debug(
                f"🔧 Processing component {i + 1}/{len(components)}: '{component}'"
            )

            # Разбираем компонент на имя атаки и параметры
            if ":" in component:
                attack_name, params_str = component.split(":", 1)
                attack_name = attack_name.strip()
                logger.debug(f"📋 Parsing parameters from '{params_str}'")
                params = self._parse_strategy_params(params_str)
                logger.debug(f"✅ Parsed parameters: {params}")
            else:
                attack_name = component.strip()
                params = {}
                logger.debug(f"📋 No parameters for '{attack_name}'")

            # Нормализуем имя атаки
            logger.debug(f"🔍 Normalizing attack name: '{attack_name}'")
            try:
                normalized_name = self._normalize_attack_type(attack_name)
                logger.debug(f"✅ Normalized: '{attack_name}' → '{normalized_name}'")
                attacks.append((normalized_name, params))
            except Exception as e:
                logger.error(f"❌ Failed to normalize attack '{attack_name}': {e}")
                raise ValueError(
                    f"Invalid attack name in strategy: '{attack_name}'"
                ) from e

        logger.debug(
            f"📊 Parsed attacks before combination: {[(a[0], len(a[1])) for a in attacks]}"
        )

        # Обрабатываем специальные комбинации
        logger.debug("🔄 Resolving attack combinations")
        resolved_attacks = self._resolve_attack_combinations(attacks)

        logger.info(
            f"✅ Strategy '{strategy}' resolved to {
                len(resolved_attacks)} attacks: {
                [
                    a[0] for a in resolved_attacks]}"
        )
        logger.debug(f"📋 Final resolved attacks: {resolved_attacks}")

        return resolved_attacks
    
    def _infer_attack_from_param(self, param_name: str, param_value: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Определяет тип атаки по имени параметра.
        
        Используется для обработки стратегий вида "hostspell=go-ogle.com",
        где имя параметра указывает на тип атаки.
        
        Args:
            param_name: Имя параметра (например, "hostspell", "hostdot")
            param_value: Значение параметра
            
        Returns:
            Кортеж (attack_name, params) или (None, {}) если не удалось определить
        """
        # Маппинг параметров на атаки
        param_to_attack = {
            "hostspell": ("http_host_header", {"fake_host": param_value, "manipulation_type": "replace"}),
            "hostdot": ("http_host_header", {"fake_host": param_value, "manipulation_type": "replace"}),
            "hosttab": ("http_host_header", {"fake_host": param_value, "manipulation_type": "replace"}),
            "hostcase": ("http_header_case", {"case_strategy": "random"}),
        }
        
        if param_name in param_to_attack:
            attack_name, params = param_to_attack[param_name]
            logger.debug(f"🔍 Mapped parameter '{param_name}' to attack '{attack_name}' with params {params}")
            return attack_name, params
        
        logger.debug(f"⚠️ Could not infer attack from parameter '{param_name}'")
        return None, {}

    def _parse_strategy_params(self, params_str: str) -> Dict[str, Any]:
        """
        Парсит параметры из строки стратегии.

        Поддерживаемые форматы:
        - "ttl=3" → {"ttl": 3}
        - "split_pos=sni" → {"split_pos": "sni"}
        - "ttl=3,split_pos=10" → {"ttl": 3, "split_pos": 10}
        - "fooling=badsum+badseq" → {"fooling": ["badsum", "badseq"]}

        Args:
            params_str: Строка с параметрами

        Returns:
            Словарь параметров
        """
        params = {}

        for param_pair in params_str.split(","):
            param_pair = param_pair.strip()
            if "=" not in param_pair:
                continue

            key, value = param_pair.split("=", 1)
            key = key.strip()
            value = value.strip()

            # Обрабатываем специальные значения
            if "+" in value:
                # Список значений: "badsum+badseq"
                params[key] = value.split("+")
            elif value.isdigit():
                # Числовое значение
                params[key] = int(value)
            elif value.lower() in ("true", "false"):
                # Булево значение
                params[key] = value.lower() == "true"
            else:
                # Строковое значение
                params[key] = value

        return params

    def _resolve_attack_combinations(
        self, attacks: List[Tuple[str, Dict[str, Any]]]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Разрешает комбинации атак в оптимизированные варианты.

        Оптимизации:
        - ["fake", "disorder"] → ["fakeddisorder"] (комбинированная атака)
        - ["disorder", "fake"] → ["fakeddisorder"] (порядок не важен)
        - ["split", "fake"] → ["fakeddisorder"] с split_pos
        - ["fake"] → ["fake"] (без изменений)
        - ["disorder"] → ["disorder"] (без изменений)

        Args:
            attacks: Список атак для оптимизации

        Returns:
            Оптимизированный список атак
        """
        if len(attacks) == 1:
            return attacks

        # Извлекаем имена атак для анализа
        attack_names = [attack[0] for attack in attacks]

        # Комбинируем параметры всех атак
        combined_params = {}
        for _, params in attacks:
            combined_params.update(params)

        # Проверяем известные комбинации
        if set(attack_names) == {"fake", "disorder"}:
            logger.debug("Combining 'fake' + 'disorder' → 'fakeddisorder'")
            return [("fakeddisorder", combined_params)]

        # ИСПРАВЛЕНИЕ: fake+split НЕ должны преобразовываться в fakeddisorder!
        # fakeddisorder = fake + disorder, а НЕ fake + split
        # Комментируем неправильный маппинг, чтобы fake и split выполнялись последовательно
        # elif set(attack_names) == {"split", "fake"}:
        #     logger.debug("Combining 'split' + 'fake' → 'fakeddisorder' with split")
        #     return [("fakeddisorder", combined_params)]

        elif "fake" in attack_names and "disorder" in attack_names:
            # CRITICAL FIX: Check if multisplit is also present
            # If so, we need integrated handling via UnifiedAttackDispatcher
            if "multisplit" in attack_names or "split" in attack_names:
                logger.info(
                    "🔄 Found 'fake' + 'multisplit/split' + 'disorder' → using integrated combo mode"
                )
                # Mark this as a combo attack that needs integrated handling
                # The dispatch_attack method will detect this and use UnifiedAttackDispatcher
                combined_params['_use_unified_dispatcher'] = True
                combined_params['_combo_attacks'] = attack_names
                return [("fake_multisplit_disorder_combo", combined_params)]
            
            # Более общий случай с дополнительными атаками (без multisplit)
            logger.debug(
                "Found 'fake' + 'disorder' in complex strategy → using 'fakeddisorder'"
            )
            # Удаляем fake и disorder, добавляем fakeddisorder
            remaining_attacks = [
                (name, params)
                for name, params in attacks
                if name not in {"fake", "disorder"}
            ]
            return [("fakeddisorder", combined_params)] + remaining_attacks

        # Если оптимизация невозможна, возвращаем как есть
        return attacks

    def dispatch_attack(
        self,
        task_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Диспетчеризует атаку к правильному обработчику с двухуровневой архитектурой.

        Алгоритм диспетчеризации:
        1. Нормализация типа атаки (разрешение алиасов)
        2. Проверка на комбинированную атаку (через параметр 'attacks')
        3. Попытка использования продвинутой атаки из attacks/ (приоритет)
        4. Fallback на примитивную атаку из primitives.py
        5. Валидация параметров через AttackRegistry
        6. Разрешение специальных значений (cipher, sni, midsld)
        7. Выполнение атаки и возврат рецепта

        Продвинутые атаки (attacks/) предоставляют:
        - Лучшую совместимость с zapret
        - Более точную логику для каждого типа
        - Асинхронное выполнение с таймаутами

        Примитивные атаки (primitives.py) используются как fallback для:
        - Обратной совместимости
        - Простых случаев
        - Когда продвинутые атаки недоступны

        Args:
            task_type: Тип атаки (fakeddisorder, seqovl, multisplit, etc.) или zapret-style стратегия
            params: Параметры атаки (split_pos, ttl, fooling, etc.)
                   Может содержать 'attacks' для комбинированных атак
            payload: Данные пакета для обработки
            packet_info: Контекст пакета (src_addr, dst_addr, src_port, dst_port)

        Returns:
            Рецепт атаки - список кортежей (данные, смещение, опции) для отправки
            Каждый кортеж представляет один TCP сегмент для инъекции

        Raises:
            ValueError: Неизвестный тип атаки или невалидные параметры
            RuntimeError: Критическая ошибка выполнения атаки
        """
        start_time = self._get_current_time()

        # Generate correlation ID for tracing this connection through all logging stages
        import uuid
        correlation_id = str(uuid.uuid4())[:8]
        
        # Task: Testing-Production Parity - Save original parameters for metadata
        # These are the FULL parameters that define what should be applied
        original_params = params.copy()
        
        # Логируем начало диспетчеризации с correlation ID
        logger.info(
            f"🎯 [CID:{correlation_id}] Starting attack dispatch: type='{task_type}', payload_size={
                len(payload)}, "
            f"src={
                packet_info.get(
                    'src_addr',
                    'unknown')}:{
                    packet_info.get(
                        'src_port',
                        'unknown')}, "
            f"dst={
                            packet_info.get(
                                'dst_addr',
                                'unknown')}:{
                                    packet_info.get(
                                        'dst_port',
                                        'unknown')}"
        )
        
        # REQUIREMENT 5.1: Log complete strategy definition before application
        logger.info(f"📋 [CID:{correlation_id}] Complete strategy definition:")
        logger.info(f"   Type: {task_type}")
        logger.info(f"   Parameters: {params}")
        if 'attacks' in params:
            logger.info(f"   Attack sequence: {params['attacks']}")
        
        logger.debug(f"📋 [CID:{correlation_id}] Attack parameters: {params}")

        try:
            # 0. CRITICAL: Check for integrated combo attack (fake + multisplit + disorder)
            # This requires special handling via UnifiedAttackDispatcher
            if task_type == "fake_multisplit_disorder_combo" or params.get('_use_unified_dispatcher'):
                logger.info(
                    f"🔄 [CID:{correlation_id}] Using UnifiedAttackDispatcher for integrated combo attack"
                )
                return self._dispatch_integrated_combo(
                    params, payload, packet_info, correlation_id
                )
            
            # 1. Проверяем, является ли task_type стратегией (содержит запятые, двоеточия или знак равенства)
            # Знак равенства может указывать на параметр вида "hostspell=go-ogle.com"
            is_strategy = "," in task_type or ":" in task_type
            
            # Проверяем, является ли это smart_combo стратегией (например, "smart_combo_split_fake")
            if task_type.startswith("smart_combo_"):
                is_strategy = True
                logger.debug(f"🔍 [CID:{correlation_id}] Detected smart_combo strategy: '{task_type}'")
            
            # Проверяем, является ли это параметром вида "key=value"
            if "=" in task_type and not is_strategy:
                # Это может быть параметр, который нужно преобразовать в атаку
                param_name = task_type.split("=", 1)[0].strip().lower()
                
                # Список известных параметров, которые должны обрабатываться как стратегии
                known_params = ["hostspell", "hostdot", "hosttab", "hostcase"]
                
                if param_name in known_params:
                    is_strategy = True
                    logger.debug(f"🔍 Detected parameter-style strategy: '{task_type}'")
            
            if is_strategy:
                logger.info(f"🔗 [CID:{correlation_id}] Detected zapret-style strategy: '{task_type}'")

                # Это zapret-style стратегия, разрешаем её
                resolved_attacks = self.resolve_strategy(task_type)
                logger.info(
                    f"📊 [CID:{correlation_id}] Strategy resolved to {
                        len(resolved_attacks)} attacks: {
                        [
                            a[0] for a in resolved_attacks]}"
                )

                # Выполняем все атаки из стратегии последовательно
                all_segments = []
                for i, (attack_name, strategy_params) in enumerate(resolved_attacks):
                    logger.debug(
                        f"🔄 [CID:{correlation_id}] Executing strategy attack {
                            i + 1}/{
                            len(resolved_attacks)}: '{attack_name}' with params {strategy_params}"
                    )

                    # Объединяем параметры стратегии с переданными параметрами
                    merged_params = {**strategy_params, **params}
                    logger.debug(
                        f"🔧 [CID:{correlation_id}] Merged parameters for '{attack_name}': {merged_params}"
                    )

                    # Рекурсивно вызываем dispatch_attack для каждой атаки
                    attack_start_time = self._get_current_time()
                    attack_segments = self.dispatch_attack(
                        attack_name, merged_params, payload, packet_info
                    )
                    attack_execution_time = self._get_current_time() - attack_start_time

                    logger.info(
                        f"✅ [CID:{correlation_id}] Strategy attack '{attack_name}' completed in {
                            attack_execution_time:.3f}s, "
                        f"generated {
                            len(attack_segments)} segments"
                    )
                    all_segments.extend(attack_segments)

                execution_time = self._get_current_time() - start_time
                logger.info(
                    f"🎉 [CID:{correlation_id}] Strategy '{task_type}' executed successfully in {
                        execution_time:.3f}s, "
                    f"generated {
                        len(all_segments)} total segments from {
                        len(resolved_attacks)} attacks"
                )
                
                # REQUIREMENT 5.2: Log each generated packet segment with details
                self._log_segment_details(all_segments, correlation_id)
                
                # Task 11.4: Log operations for validation
                strategy_id = packet_info.get('strategy_id')
                if strategy_id:
                    self._log_operations_for_validation(
                        strategy_id=strategy_id,
                        operation_type='strategy',
                        parameters={'strategy': task_type, 'attacks': [a[0] for a in resolved_attacks]},
                        segments=all_segments,
                        correlation_id=correlation_id
                    )
                    
                    # Task: Testing-Production Parity - Save executed attacks to metadata
                    # This provides a single source of truth for validation
                    # Save FULL strategy specification: type + parameters
                    # This matches exactly what was logged in "Complete strategy definition"
                    try:
                        from core.pcap.metadata_saver import save_pcap_metadata
                        save_pcap_metadata(
                            strategy_id=strategy_id,
                            domain=packet_info.get('domain'),  # For matching with PCAP filename
                            executed_attacks=task_type,
                            strategy_name=packet_info.get('strategy_name'),
                            additional_data={
                                'correlation_id': correlation_id,
                                'attacks': [a[0] for a in resolved_attacks],
                                'parameters': original_params,  # FULL parameters from "Complete strategy definition"
                                'segment_count': len(all_segments),
                                'execution_time': execution_time
                            }
                        )
                        logger.debug(f"📝 [CID:{correlation_id}] Saved metadata for strategy_id={strategy_id[:8] if strategy_id else 'N/A'}, domain={packet_info.get('domain')}")
                    except Exception as e:
                        logger.debug(f"⚠️ Failed to save PCAP metadata: {e}")
                
                return all_segments

            # 2. Check for combination attack (via 'attacks' parameter)
            if 'attacks' in params and isinstance(params['attacks'], list) and len(params['attacks']) > 1:
                # REQUIREMENT 5.3: Log attack type and method being applied
                logger.info(
                    f"🔗 [CID:{correlation_id}] Detected combination attack via 'attacks' parameter: {params['attacks']}"
                )
                logger.info(f"🔗 [CID:{correlation_id}] Attack method: Combination of {len(params['attacks'])} attacks")
                combination_start_time = self._get_current_time()
                
                # Execute combination attack with correlation ID
                result = self._dispatch_combination(
                    params['attacks'],
                    params,
                    payload,
                    packet_info,
                    correlation_id
                )
                
                combination_time = self._get_current_time() - combination_start_time
                execution_time = self._get_current_time() - start_time
                
                # REQUIREMENT 5.4: Log segment count
                logger.info(
                    f"🎉 [CID:{correlation_id}] Combination attack completed in {combination_time:.3f}s "
                    f"(total: {execution_time:.3f}s), generated {len(result)} segments"
                )
                
                # REQUIREMENT 5.2: Log each generated packet segment with details
                self._log_segment_details(result, correlation_id)
                
                # Task 11.4: Log operations for validation
                strategy_id = packet_info.get('strategy_id')
                if strategy_id:
                    self._log_operations_for_validation(
                        strategy_id=strategy_id,
                        operation_type='combination',
                        parameters={'attacks': params['attacks']},
                        segments=result,
                        correlation_id=correlation_id
                    )
                
                return result
            
            # 3. Нормализация типа атаки (одиночная атака)
            logger.debug(f"🔍 [CID:{correlation_id}] Normalizing attack type: '{task_type}'")
            normalized_type = self._normalize_attack_type(task_type)
            
            # REQUIREMENT 5.3: Log attack type and method being applied
            logger.info(
                f"📝 [CID:{correlation_id}] Attack type normalized: '{task_type}' → '{normalized_type}'"
            )
            logger.info(f"🎯 [CID:{correlation_id}] Attack method: Single attack '{normalized_type}'")

            # 4. Нормализация параметров через ParameterNormalizer
            logger.debug(f"⚙️ Starting parameter normalization for '{normalized_type}'")
            normalization_start_time = self._get_current_time()

            normalization_result = self.parameter_normalizer.normalize(
                normalized_type, params, len(payload)
            )

            normalization_time = self._get_current_time() - normalization_start_time
            logger.debug(
                f"⏱️ Parameter normalization completed in {
                    normalization_time:.4f}s"
            )

            if not normalization_result.is_valid:
                logger.error(
                    f"❌ Parameter normalization failed for '{task_type}': {
                        normalization_result.error_message}"
                )
                raise ValueError(
                    f"Parameter normalization failed for attack '{task_type}': {
                        normalization_result.error_message}"
                )

            # Логируем трансформации параметров
            if normalization_result.transformations:
                logger.info(
                    f"🔧 Parameter transformations for '{task_type}': {
                        len(
                            normalization_result.transformations)} changes"
                )
                for transformation in normalization_result.transformations:
                    logger.debug(f"  📋 {transformation}")
            else:
                logger.debug(
                    f"✅ No parameter transformations needed for '{task_type}'"
                )

            if normalization_result.warnings:
                logger.warning(
                    f"⚠️ Parameter warnings for '{task_type}': {len(normalization_result.warnings)} warnings"
                )
                for warning in normalization_result.warnings:
                    logger.warning(f"  ⚠️ {warning}")

            # Используем нормализованные параметры
            normalized_params = normalization_result.normalized_params

            logger.info(
                f"🚀 Dispatching single attack '{task_type}' (normalized: '{normalized_type}')"
            )
            logger.debug(f"📊 Normalized parameters: {normalized_params}")

            # 5. ПРИОРИТЕТ: Пытаемся использовать продвинутую атаку из
            # директории attacks
            logger.debug(
                f"🔍 Checking for advanced attack implementation for '{normalized_type}'"
            )
            advanced_start_time = self._get_current_time()

            advanced_result = self._use_advanced_attack(
                normalized_type, normalized_params, payload, packet_info
            )

            if advanced_result is not None:
                advanced_execution_time = self._get_current_time() - advanced_start_time
                execution_time = self._get_current_time() - start_time
                logger.info(f"🎯 [CID:{correlation_id}] Advanced attack '{task_type}' executed successfully!")
                logger.info(
                    f"⏱️ [CID:{correlation_id}] Timing: advanced_execution={
                        advanced_execution_time:.3f}s, total={
                        execution_time:.3f}s"
                )
                
                # REQUIREMENT 5.4: Log segment count
                logger.info(f"📦 [CID:{correlation_id}] Generated {len(advanced_result)} segments")
                logger.debug(
                    f"📋 [CID:{correlation_id}] Segment details: {
                        [
                            (len(
                                seg[0]), seg[1], list(
                                seg[2].keys())) for seg in advanced_result]}"
                )
                
                # REQUIREMENT 5.2: Log each generated packet segment with details
                self._log_segment_details(advanced_result, correlation_id)
                
                # Task 11.4: Log operations for validation
                strategy_id = packet_info.get('strategy_id')
                if strategy_id:
                    self._log_operations_for_validation(
                        strategy_id=strategy_id,
                        operation_type=normalized_type,
                        parameters=normalized_params,
                        segments=advanced_result,
                        correlation_id=correlation_id
                    )
                
                return advanced_result

            # 6. FALLBACK: Используем примитивные атаки из primitives.py
            logger.info(
                f"⚠️ No advanced attack available for '{normalized_type}', falling back to primitives"
            )
            logger.debug("🔄 Starting primitive attack fallback")

            # Получение обработчика из реестра с улучшенной обработкой ошибок
            logger.debug(f"🔍 Looking up handler for '{normalized_type}' in registry")
            handler_lookup_start = self._get_current_time()

            handler = self.registry.get_attack_handler(normalized_type)
            handler_lookup_time = self._get_current_time() - handler_lookup_start

            if not handler:
                logger.error(f"❌ No handler found for attack type '{normalized_type}'")

                # Попытаемся найти похожие атаки для лучшего сообщения об
                # ошибке
                available_attacks = self.registry.list_attacks()
                similar_attacks = [
                    attack
                    for attack in available_attacks
                    if normalized_type in attack or attack in normalized_type
                ]

                logger.debug(f"📋 Available attacks: {available_attacks}")
                logger.debug(f"🔍 Similar attacks found: {similar_attacks}")

                error_msg = f"No handler found for attack type '{normalized_type}'"
                if similar_attacks:
                    error_msg += (
                        f". Did you mean one of: {', '.join(similar_attacks[:3])}?"
                    )
                else:
                    error_msg += (
                        f". Available attacks: {', '.join(available_attacks[:5])}..."
                    )

                raise ValueError(error_msg)

            logger.debug(
                f"✅ Handler found for '{normalized_type}' in {
                    handler_lookup_time:.4f}s"
            )

            # Валидация параметров через реестр
            logger.debug(
                f"🔍 Validating parameters through registry for '{normalized_type}'"
            )
            validation_start_time = self._get_current_time()

            registry_validation = self.registry.validate_parameters(
                normalized_type, normalized_params
            )
            validation_time = self._get_current_time() - validation_start_time

            if not registry_validation.is_valid:
                logger.error(
                    f"❌ Registry parameter validation failed for '{task_type}': {
                        registry_validation.error_message}"
                )
                raise ValueError(
                    f"Parameter validation failed for '{task_type}': {
                        registry_validation.error_message}"
                )

            logger.debug(
                f"✅ Registry validation completed in {
                    validation_time:.4f}s"
            )

            # Логируем предупреждения валидации
            if registry_validation.warnings:
                logger.warning(
                    f"⚠️ Registry validation warnings for '{task_type}': {
                        len(
                            registry_validation.warnings)} warnings"
                )
                for warning in registry_validation.warnings:
                    logger.warning(f"  ⚠️ {warning}")
            else:
                logger.debug(f"✅ No registry validation warnings for '{task_type}'")

            # Разрешение специальных параметров (если еще не разрешены
            # нормализатором)
            logger.debug(f"🔧 Resolving special parameters for '{normalized_type}'")
            param_resolution_start = self._get_current_time()

            resolved_params = self._resolve_parameters(
                normalized_params, payload, packet_info
            )
            param_resolution_time = self._get_current_time() - param_resolution_start

            logger.debug(
                f"✅ Parameter resolution completed in {
                    param_resolution_time:.4f}s"
            )
            logger.debug(f"📊 Final resolved parameters: {resolved_params}")

            # Создание AttackContext для передачи в обработчик
            logger.debug(f"🏗️ Creating AttackContext for '{normalized_type}'")
            connection_id = f"{
                packet_info.get(
                    'src_addr', 'unknown')}:{
                packet_info.get(
                    'src_port', 0)}->{
                packet_info.get(
                    'dst_addr', '127.0.0.1')}:{
                packet_info.get(
                    'dst_port', 443)}"

            context = AttackContext(
                dst_ip=packet_info.get("dst_addr", "127.0.0.1"),
                dst_port=packet_info.get("dst_port", 443),
                src_ip=packet_info.get("src_addr"),
                src_port=packet_info.get("src_port"),
                payload=payload,
                protocol="tcp",
                connection_id=connection_id,
                params=resolved_params,
            )

            logger.debug(
                f"📋 AttackContext created: connection_id='{connection_id}', payload_size={
                    len(payload)}"
            )

            # Выполнение примитивной атаки
            logger.info(
                f"🎯 Executing primitive attack handler for '{normalized_type}'"
            )
            handler_execution_start = self._get_current_time()

            recipe = handler(context)

            handler_execution_time = self._get_current_time() - handler_execution_start
            logger.debug(
                f"⏱️ Handler execution completed in {
                    handler_execution_time:.4f}s"
            )

            # Валидация результата
            if not recipe or not isinstance(recipe, list):
                logger.error(
                    f"❌ Invalid recipe returned by handler for '{normalized_type}': {
                        type(recipe)}"
                )
                raise RuntimeError(
                    f"Attack handler for '{normalized_type}' returned invalid recipe"
                )

            logger.debug(f"✅ Recipe validation passed: {len(recipe)} segments")
            logger.debug(
                f"📋 Recipe details: {[(len(seg[0]), seg[1], list(seg[2].keys())) for seg in recipe]}"
            )

            execution_time = self._get_current_time() - start_time
            logger.info(f"🎉 [CID:{correlation_id}] Primitive attack '{task_type}' dispatched successfully!")
            logger.info(
                f"⏱️ [CID:{correlation_id}] Timing: handler={
                    handler_execution_time:.3f}s, total={
                    execution_time:.3f}s"
            )
            
            # REQUIREMENT 5.4: Log segment count
            logger.info(f"📦 [CID:{correlation_id}] Generated {len(recipe)} segments")
            
            # REQUIREMENT 5.2: Log each generated packet segment with details
            self._log_segment_details(recipe, correlation_id)
            
            # Task 11.4: Log operations for validation
            strategy_id = packet_info.get('strategy_id')
            if strategy_id:
                self._log_operations_for_validation(
                    strategy_id=strategy_id,
                    operation_type=normalized_type,
                    parameters=resolved_params,
                    segments=recipe,
                    correlation_id=correlation_id
                )

            return recipe

        except Exception as e:
            execution_time = self._get_current_time() - start_time
            logger.error(
                f"💥 Attack '{task_type}' dispatch failed after {
                    execution_time:.3f}s"
            )
            logger.error(f"❌ Error type: {type(e).__name__}")
            logger.error(f"❌ Error message: {e}")
            logger.debug(f"📋 Failed with parameters: {params}")
            logger.debug(f"📋 Payload size: {len(payload)}")
            logger.debug(f"📋 Packet info: {packet_info}")

            # Логируем стек вызовов для отладки
            import traceback

            logger.debug(f"📋 Stack trace:\n{traceback.format_exc()}")

            raise

    def _init_advanced_attacks(self):
        """
        DEPRECATED: This method is no longer needed for registration.
        All attacks are now registered via @register_attack decorator.
        
        This method now only validates that critical attacks are registered
        in the AttackRegistry and logs their availability.
        
        Critical attacks that should be available:
        - fakeddisorder: Основная атака с фейковым пакетом
        - multisplit: Множественное разделение TCP пакетов
        - multidisorder: Множественное разделение с disorder эффектом
        - seqovl: Sequence overlap атака
        """
        if not ADVANCED_ATTACKS_AVAILABLE:
            logger.info("Advanced attacks not available, using primitives only")
            return

        try:
            # Validate that critical attacks are registered in the registry
            critical_attacks = [
                "fakeddisorder",
                "multisplit", 
                "multidisorder",
                "seqovl"
            ]
            
            missing = []
            available = []
            
            for attack_name in critical_attacks:
                handler = self.registry.get_attack_handler(attack_name)
                if not handler:
                    missing.append(attack_name)
                else:
                    available.append(attack_name)
            
            if missing:
                logger.warning(
                    f"⚠️ {len(missing)} critical attacks not registered: {missing}"
                )
            
            if available:
                logger.info(
                    f"✅ All {len(available)} critical attacks registered via @register_attack decorator"
                )
                logger.debug(f"📋 Available critical attacks: {available}")

        except Exception as e:
            logger.error(f"Failed to validate advanced attacks: {e}")
            # Продолжаем работу с примитивными атаками

    def _use_advanced_attack(
        self,
        task_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> Optional[List[Tuple[bytes, int, Dict[str, Any]]]]:
        """
        Simplified: Uses AttackRegistry directly to get and execute attacks.
        
        No need for separate _advanced_attacks dict - the registry handles
        everything with priority-based resolution.

        Процесс выполнения:
        1. Get attack handler from registry (handles priority automatically)
        2. Create AttackContext
        3. Execute attack via handler
        4. Return segments or None for fallback

        Args:
            task_type: Нормализованный тип атаки
            params: Параметры атаки
            payload: Данные пакета
            packet_info: Информация о пакете

        Returns:
            Рецепт атаки (список сегментов) или None если атака недоступна/неуспешна
        """

        if not ADVANCED_ATTACKS_AVAILABLE:
            logger.debug(
                f"🚫 Advanced attacks not available, skipping advanced attack for '{task_type}'"
            )
            return None

        normalized_type = self._normalize_attack_type(task_type)
        logger.debug(
            f"🔍 Checking attack availability in registry for '{normalized_type}'"
        )

        # Get handler from registry - it handles priority resolution automatically
        handler = self.registry.get_attack_handler(normalized_type)
        
        if not handler:
            logger.debug(
                f"🚫 No handler found in registry for '{normalized_type}'"
            )
            return None

        # Check if this is a HIGH or CORE priority attack (advanced implementation)
        entry = self.registry.attacks.get(normalized_type)
        if entry and entry.priority.value < 2:  # CORE=3, HIGH=2, NORMAL=1
            logger.debug(
                f"🚫 Attack '{normalized_type}' has low priority ({entry.priority.name}), using primitive fallback"
            )
            return None

        logger.info(f"🎯 Found advanced attack handler for '{normalized_type}' with priority {entry.priority.name if entry else 'UNKNOWN'}")

        try:
            # Create attack context
            connection_id = f"{
                packet_info.get(
                    'src_addr', '0.0.0.0')}:{
                packet_info.get(
                    'src_port', 0)}->{
                packet_info.get(
                    'dst_addr', '0.0.0.0')}:{
                packet_info.get(
                    'dst_port', 0)}"

            logger.debug("🏗️ Creating AttackContext")
            context = AttackContext(
                connection_id=connection_id,
                payload=payload,
                dst_ip=packet_info.get("dst_addr", "0.0.0.0"),
                dst_port=packet_info.get("dst_port", 443),
                params=params,
            )
            # Add additional attributes
            context.packet_info = packet_info

            logger.debug(
                f"📋 Context: connection_id='{connection_id}', payload_size={len(payload)}"
            )

            # Execute attack via handler
            logger.info(f"🎯 Executing attack '{normalized_type}' via handler, payload_len={len(payload)}, params_keys={list(params.keys())}")
            result = handler(context)
            logger.info(f"🎯 Handler returned: type={type(result)}, is_list={isinstance(result, list)}, len={len(result) if isinstance(result, list) else 'N/A'}")

            if result is None:
                logger.warning(f"⚠️ Attack '{normalized_type}' returned no result")
                return None

            # Handle different result types
            if isinstance(result, list):
                # Handler returned segments directly (primitive style)
                logger.debug(f"Handler returned {len(result)} segments (primitive style)")
                return result
            elif hasattr(result, 'status') and hasattr(result, 'segments'):
                # Handler returned AttackResult (advanced style)
                if result.status == AttackStatus.SUCCESS and result.segments:
                    logger.debug(f"Handler returned {len(result.segments)} segments (advanced style)")
                    return result.segments
                else:
                    logger.warning(f"⚠️ Attack '{normalized_type}' failed")
                    logger.warning(f"❌ Status: {result.status}")
                    if hasattr(result, 'error_message'):
                        logger.warning(f"❌ Error: {result.error_message}")
                    return None
            else:
                logger.warning(f"⚠️ Attack '{normalized_type}' returned unexpected result type: {type(result)}")
                return None

        except Exception as e:
            logger.error(f"💥 Attack '{normalized_type}' execution failed")
            logger.error(f"❌ Exception type: {type(e).__name__}")
            logger.error(f"❌ Exception message: {e}")
            logger.debug(f"📋 Failed with params: {params}")

            # Log stack trace for debugging
            import traceback
            logger.debug(f"📋 Stack trace:\n{traceback.format_exc()}")

            return None

    def _dispatch_integrated_combo(
        self,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        correlation_id: str = None,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Выполняет интегрированную комбо-атаку fake + multisplit + disorder.
        
        Использует UnifiedAttackDispatcher для правильной интеграции:
        1. Split payload на N частей (split_count)
        2. Для каждой части создать fake пакет (fake_mode)
        3. Применить disorder (reverse) ко всем сегментам
        
        Args:
            params: Параметры атаки (ttl, fooling, split_count, fake_mode, disorder_method)
            payload: Данные пакета
            packet_info: Контекст пакета
            correlation_id: ID для трассировки
            
        Returns:
            Список сегментов для отправки
        """
        logger.info(f"🔄 [CID:{correlation_id}] Starting integrated combo attack")
        logger.info(f"   Parameters: {params}")
        
        try:
            # Import UnifiedAttackDispatcher and ComboAttackBuilder
            from ..unified_attack_dispatcher import UnifiedAttackDispatcher
            from ...strategy.combo_builder import ComboAttackBuilder
            
            # Create dispatcher and builder
            combo_builder = ComboAttackBuilder()
            dispatcher = UnifiedAttackDispatcher(combo_builder)
            
            # Extract attacks from params
            combo_attacks = params.get('_combo_attacks', ['fake', 'multisplit', 'disorder'])
            
            # Clean params (remove internal markers)
            clean_params = {k: v for k, v in params.items() if not k.startswith('_')}
            
            # Build recipe
            logger.info(f"🔧 [CID:{correlation_id}] Building recipe for attacks: {combo_attacks}")
            recipe = combo_builder.build_recipe(combo_attacks, clean_params)
            
            # Apply recipe
            logger.info(f"🚀 [CID:{correlation_id}] Applying integrated recipe")
            segments = dispatcher.apply_recipe(recipe, payload, packet_info)
            
            logger.info(
                f"✅ [CID:{correlation_id}] Integrated combo attack completed: "
                f"{len(segments)} segments generated"
            )
            
            # Log segment details
            fake_count = sum(1 for s in segments if s[2].get('is_fake'))
            real_count = len(segments) - fake_count
            logger.info(f"   Fake segments: {fake_count}")
            logger.info(f"   Real segments: {real_count}")
            
            return segments
            
        except ImportError as e:
            logger.error(f"❌ [CID:{correlation_id}] Failed to import UnifiedAttackDispatcher: {e}")
            logger.warning("⚠️ Falling back to sequential execution")
            
            # Fallback: execute attacks sequentially (old behavior)
            combo_attacks = params.get('_combo_attacks', ['fake', 'multisplit', 'disorder'])
            return self._dispatch_combination(
                combo_attacks, params, payload, packet_info, correlation_id
            )
        except Exception as e:
            logger.error(f"❌ [CID:{correlation_id}] Integrated combo attack failed: {e}")
            import traceback
            logger.debug(f"📋 Stack trace:\n{traceback.format_exc()}")
            raise

    def _dispatch_combination(
        self,
        attacks: List[str],
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        correlation_id: str = None,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Выполняет комбинацию атак последовательно.
        
        Этот метод обеспечивает паритет между CLI и service режимами,
        применяя несколько атак в указанном порядке и объединяя результаты.
        
        Алгоритм:
        1. Выполнить каждую атаку из списка последовательно
        2. Извлечь параметры, специфичные для каждой атаки
        3. Собрать все сегменты от всех атак
        4. Применить disorder reordering если указан disorder_method
        
        Args:
            attacks: Список имен атак для выполнения (например, ["multisplit", "disorder"])
            params: Все параметры для всех атак в комбинации
            payload: Данные пакета для обработки
            packet_info: Контекст пакета
            correlation_id: Correlation ID for tracing through logging stages
            
        Returns:
            Объединенный список сегментов от всех атак
            
        Raises:
            ValueError: Если список атак пуст или содержит неизвестные атаки
            RuntimeError: Если выполнение любой атаки завершилось ошибкой
        """
        if not attacks:
            raise ValueError("Empty attacks list in combination")
        
        # Generate correlation ID if not provided
        if correlation_id is None:
            import uuid
            correlation_id = str(uuid.uuid4())[:8]
        
        logger.info(f"📋 [CID:{correlation_id}] Executing combination of {len(attacks)} attacks: {attacks}")
        logger.info(f"🔧 [CID:{correlation_id}] Combination parameters: {params}")
        logger.info(f"🔧 [CID:{correlation_id}] Parameter keys: {list(params.keys())}")
        
        all_segments = []
        
        # Выполняем каждую атаку в последовательности
        for i, attack_name in enumerate(attacks):
            attack_start_time = self._get_current_time()
            
            logger.info(f"🎯 [CID:{correlation_id}] Executing attack {i+1}/{len(attacks)}: '{attack_name}'")
            
            # Извлекаем параметры, специфичные для этой атаки
            attack_params = self._filter_params_for_attack(attack_name, params)
            logger.debug(f"📦 [CID:{correlation_id}] Attack-specific parameters for '{attack_name}': {attack_params}")
            
            try:
                # Рекурсивно вызываем dispatch_attack для каждой атаки
                # Важно: передаем params без 'attacks' чтобы избежать бесконечной рекурсии
                single_attack_params = attack_params.copy()
                if 'attacks' in single_attack_params:
                    del single_attack_params['attacks']
                
                segments = self.dispatch_attack(
                    attack_name,
                    single_attack_params,
                    payload,
                    packet_info
                )
                
                attack_execution_time = self._get_current_time() - attack_start_time
                
                # REQUIREMENT 5.4: Log segment count for each attack in combination
                logger.info(
                    f"✅ [CID:{correlation_id}] Attack '{attack_name}' completed in {attack_execution_time:.3f}s, "
                    f"generated {len(segments)} segments"
                )
                logger.debug(
                    f"📋 [CID:{correlation_id}] Segment details: {[(len(seg[0]), seg[1], list(seg[2].keys())) for seg in segments]}"
                )
                
                all_segments.extend(segments)
                
            except Exception as e:
                logger.error(
                    f"💥 [CID:{correlation_id}] Attack '{attack_name}' failed in combination (attack {i+1}/{len(attacks)})"
                )
                logger.error(f"❌ [CID:{correlation_id}] Error: {e}")
                raise RuntimeError(
                    f"Combination attack failed at '{attack_name}': {e}"
                ) from e
        
        # REQUIREMENT 5.4: Log total segment count before reordering
        logger.info(
            f"📦 [CID:{correlation_id}] All attacks completed, total segments before reordering: {len(all_segments)}"
        )
        
        # Применяем disorder reordering если указан
        if 'disorder' in attacks and 'disorder_method' in params:
            disorder_method = params['disorder_method']
            
            # REQUIREMENT 5.4: Log reordering operations
            logger.info(f"🔀 [CID:{correlation_id}] Applying disorder reordering: method='{disorder_method}'")
            logger.info(f"🔀 [CID:{correlation_id}] Segments before reordering: {len(all_segments)}")
            
            reorder_start_time = self._get_current_time()
            all_segments = self._apply_disorder_reordering(all_segments, disorder_method, correlation_id)
            reorder_time = self._get_current_time() - reorder_start_time
            
            # REQUIREMENT 5.4: Log segment count after reordering
            logger.info(
                f"✅ [CID:{correlation_id}] Disorder reordering completed in {reorder_time:.4f}s, "
                f"final segment count: {len(all_segments)}"
            )
        
        logger.info(
            f"🎉 [CID:{correlation_id}] Combination attack completed successfully: "
            f"{len(attacks)} attacks → {len(all_segments)} segments"
        )
        
        return all_segments
    
    def _filter_params_for_attack(
        self,
        attack_name: str,
        all_params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Извлекает параметры, специфичные для конкретной атаки.
        
        Этот метод фильтрует общий набор параметров комбинации,
        оставляя только те, которые релевантны для данной атаки.
        
        Параметры по атакам:
        - multisplit: split_pos, split_count, positions, fooling
        - disorder: disorder_method
        - fake: ttl, fake_ttl, fooling, custom_sni
        - split: split_pos
        
        Общие параметры (передаются всем атакам):
        - no_fallbacks, forced
        
        Args:
            attack_name: Имя атаки для фильтрации параметров
            all_params: Все параметры комбинации
            
        Returns:
            Отфильтрованный словарь параметров для данной атаки
        """
        # Нормализуем имя атаки
        normalized_name = self._normalize_attack_type(attack_name)
        
        logger.info(f"🔍 Filtering parameters for attack '{normalized_name}'")
        logger.info(f"📦 All available parameters: {list(all_params.keys())}")
        logger.info(f"📦 Parameter values: {all_params}")
        
        # Определяем параметры для каждого типа атаки
        attack_param_map = {
            'multisplit': {
                'split_pos', 'split_count', 'positions', 'fooling', 
                'fooling_methods', 'fake_ttl', 'ttl'
            },
            'multidisorder': {
                'split_pos', 'split_count', 'positions', 'fooling',
                'fooling_methods', 'fake_ttl', 'ttl', 'disorder_method'
            },
            'disorder': {'disorder_method', 'split_pos'},
            'fake': {
                'ttl', 'fake_ttl', 'fooling', 'fooling_methods',
                'custom_sni', 'fake_sni'
            },
            'fakeddisorder': {
                'ttl', 'fake_ttl', 'fooling', 'fooling_methods',
                'custom_sni', 'fake_sni', 'disorder_method', 'split_pos'
            },
            'split': {'split_pos'},
            'seqovl': {'overlap_size', 'fooling', 'fooling_methods'},
        }
        
        # Общие параметры, которые передаются всем атакам
        common_params = {'no_fallbacks', 'forced', 'resolved_custom_sni'}
        
        # Получаем набор параметров для этой атаки
        attack_specific_params = attack_param_map.get(normalized_name, set())
        
        # Фильтруем параметры
        filtered = {}
        for key, value in all_params.items():
            if key in common_params or key in attack_specific_params:
                filtered[key] = value
                logger.debug(f"  ✅ Including parameter '{key}' for '{normalized_name}'")
            else:
                logger.debug(f"  ⏭️ Skipping parameter '{key}' for '{normalized_name}'")
        
        logger.debug(
            f"📋 Filtered {len(filtered)}/{len(all_params)} parameters for '{normalized_name}'"
        )
        
        return filtered
    
    def _apply_disorder_reordering(
        self,
        segments: List[Tuple[bytes, int, Dict[str, Any]]],
        disorder_method: str,
        correlation_id: str = None
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Применяет disorder трансформацию к списку сегментов.
        
        Поддерживаемые методы:
        - "reverse": Обратный порядок сегментов
        - "random": Случайное перемешивание сегментов
        - "swap": Меняет местами первый и последний сегмент
        
        Args:
            segments: Список сегментов для переупорядочивания
            disorder_method: Метод переупорядочивания
            correlation_id: Correlation ID for tracing
            
        Returns:
            Переупорядоченный список сегментов
        """
        if not segments:
            log_prefix = f"[CID:{correlation_id}] " if correlation_id else ""
            logger.warning(f"⚠️ {log_prefix}Empty segments list for disorder reordering")
            return segments
        
        original_count = len(segments)
        log_prefix = f"[CID:{correlation_id}] " if correlation_id else ""
        logger.debug(f"🔀 {log_prefix}Applying disorder method '{disorder_method}' to {original_count} segments")
        
        if disorder_method == 'reverse':
            result = list(reversed(segments))
            logger.debug(f"✅ {log_prefix}Reversed segment order: {original_count} segments")
            
        elif disorder_method == 'random':
            import random
            result = segments.copy()
            random.shuffle(result)
            logger.debug(f"✅ {log_prefix}Randomly shuffled {original_count} segments")
            
        elif disorder_method == 'swap':
            if len(segments) >= 2:
                result = segments.copy()
                result[0], result[-1] = result[-1], result[0]
                logger.debug(f"✅ {log_prefix}Swapped first and last segments")
            else:
                logger.warning(f"⚠️ {log_prefix}Not enough segments to swap (need ≥2, got {len(segments)})")
                result = segments
                
        else:
            logger.warning(
                f"⚠️ {log_prefix}Unknown disorder method '{disorder_method}', "
                f"returning segments unchanged"
            )
            result = segments
        
        # Валидация результата
        if len(result) != original_count:
            logger.error(
                f"❌ {log_prefix}Disorder reordering changed segment count: "
                f"{original_count} → {len(result)}"
            )
            raise RuntimeError(
                f"Disorder reordering corrupted segments: "
                f"count changed from {original_count} to {len(result)}"
            )
        
        return result

    def _normalize_attack_type(self, task_type: str) -> str:
        """
        Нормализует тип атаки, разрешая алиасы и приводя к стандартному формату.

        Процесс нормализации:
        1. Приведение к нижнему регистру
        2. Удаление лишних пробелов
        3. Разрешение алиасов через AttackRegistry
        4. Проверка существования атаки в реестре
        5. Возврат канонического имени атаки

        Поддерживаемые алиасы:
        - fake_disorder -> fakeddisorder
        - seq_overlap -> seqovl
        - multi_split -> multisplit
        - simple_disorder -> disorder
        - и другие, определенные в AttackRegistry

        Args:
            task_type: Исходный тип атаки (может содержать алиасы)

        Returns:
            Канонический тип атаки для использования в системе

        Raises:
            ValueError: Если тип атаки не найден в реестре
        """
        # Приводим к нижнему регистру и убираем лишние пробелы
        normalized = task_type.lower().strip()
        
        # Handle attack= prefix if present (for compatibility with --attack= format)
        if normalized.startswith("attack="):
            normalized = normalized[7:]  # Remove "attack=" prefix
            logger.debug(f"Removed 'attack=' prefix: '{task_type}' -> '{normalized}'")

        # Разрешаем алиасы через реестр
        resolved_type = self.registry.get_canonical_name(normalized)

        # Проверяем, что атака существует в реестре
        if not self.registry.get_attack_handler(resolved_type):
            # Если атака не найдена, попробуем найти похожие
            available_attacks = self.registry.list_attacks()
            similar_attacks = [
                attack
                for attack in available_attacks
                if normalized in attack or attack in normalized
            ]

            error_msg = (
                f"Unknown attack type '{task_type}' (normalized: '{resolved_type}')"
            )
            if similar_attacks:
                error_msg += f". Did you mean one of: {', '.join(similar_attacks[:3])}?"

            raise ValueError(error_msg)

        logger.debug(f"Normalized attack type '{task_type}' -> '{resolved_type}'")
        return resolved_type

    def _resolve_parameters(
        self, params: Dict[str, Any], payload: bytes, packet_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Разрешает специальные значения параметров в конкретные числовые значения.

        Специальные значения split_pos:
        - "cipher": Позиция начала TLS cipher suite в ClientHello
        - "sni": Позиция начала Server Name Indication
        - "midsld": Середина второго уровня домена (для доменно-специфичных атак)

        Дополнительная обработка:
        - Нормализация параметров TTL (fake_ttl <-> ttl)
        - Нормализация fooling методов (fooling_methods <-> fooling)
        - Разрешение positions для multisplit/multidisorder
        - Разрешение custom SNI для fake packets
        - Установка значений по умолчанию

        Алгоритм разрешения позиций:
        1. Анализ TLS ClientHello структуры
        2. Поиск соответствующих полей/расширений
        3. Вычисление оптимальной позиции разделения
        4. Fallback на позицию по умолчанию при ошибках

        Args:
            params: Исходные параметры атаки
            payload: TLS ClientHello данные для анализа
            packet_info: Контекст соединения (адреса, порты)

        Returns:
            Параметры с разрешенными специальными значениями и нормализованными именами
        """
        resolved = params.copy()

        # Разрешаем split_pos
        if "split_pos" in resolved:
            resolved["split_pos"] = self._resolve_split_position(
                resolved["split_pos"], payload, packet_info
            )

        # Разрешаем positions для multisplit/multidisorder
        if "positions" in resolved:
            resolved["positions"] = [
                self._resolve_split_position(pos, payload, packet_info)
                for pos in resolved["positions"]
            ]

        # Разрешаем custom SNI для fake packets
        resolved_sni = self._resolve_custom_sni(resolved)
        if resolved_sni is not None:
            resolved["resolved_custom_sni"] = resolved_sni
            logger.debug(f"Resolved custom SNI: {resolved_sni}")

        # Устанавливаем значения по умолчанию для часто используемых параметров
        if "fake_ttl" not in resolved and "ttl" in resolved:
            resolved["fake_ttl"] = resolved["ttl"]
        elif "ttl" not in resolved and "fake_ttl" in resolved:
            resolved["ttl"] = resolved["fake_ttl"]

        if "fooling_methods" not in resolved and "fooling" in resolved:
            resolved["fooling_methods"] = resolved["fooling"]

        logger.debug(f"Resolved parameters: {resolved}")
        return resolved

    def _resolve_split_position(
        self, split_pos: Any, payload: bytes, packet_info: Dict[str, Any]
    ) -> int:
        """
        Разрешает позицию разделения, включая специальные значения.

        Args:
            split_pos: Позиция разделения (int, str или специальное значение)
            payload: Данные пакета
            packet_info: Информация о пакете

        Returns:
            Разрешенная позиция как int
        """
        # Если None, используем значение по умолчанию
        if split_pos is None:
            return len(payload) // 2

        # Если уже int, возвращаем как есть
        if isinstance(split_pos, int):
            return max(1, min(split_pos, len(payload) - 1))

        # Если строка, пытаемся конвертировать в int
        if isinstance(split_pos, str):
            # Проверяем специальные значения
            if split_pos == SpecialParameterValues.CIPHER:
                return self._find_cipher_position(payload)
            elif split_pos == SpecialParameterValues.SNI:
                return self._find_sni_position(payload)
            elif split_pos == SpecialParameterValues.MIDSLD:
                return self._find_midsld_position(payload, packet_info)
            elif split_pos == SpecialParameterValues.RANDOM or split_pos == "random":
                # Случайная позиция в пределах payload
                import random
                return random.randint(1, max(1, len(payload) - 1))
            else:
                # Пытаемся конвертировать в int
                try:
                    return max(1, min(int(split_pos), len(payload) - 1))
                except ValueError:
                    logger.warning(
                        f"Invalid split_pos value '{split_pos}', using default"
                    )
                    return len(payload) // 2

        # Fallback
        logger.warning(
            f"Unknown split_pos type {
                type(split_pos)}, using default"
        )
        return len(payload) // 2

    def _find_cipher_position(self, payload: bytes) -> int:
        """
        Находит позицию начала TLS cipher suite в ClientHello.

        Args:
            payload: Данные пакета

        Returns:
            Позиция cipher suite или позицию по умолчанию
        """
        try:
            # Проверяем, что это TLS ClientHello
            if len(payload) < 43 or payload[0] != 0x16:
                return len(payload) // 2

            # Пропускаем TLS Record Header (5 bytes)
            # Пропускаем Handshake Header (4 bytes)
            # Пропускаем Version (2 bytes)
            # Пропускаем Random (32 bytes)
            pos = 43

            # Пропускаем Session ID
            if pos < len(payload):
                session_id_len = payload[pos]
                pos += 1 + session_id_len

            # Позиция Cipher Suites Length
            if pos + 2 <= len(payload):
                logger.debug(f"Found cipher position at {pos}")
                return pos

        except Exception as e:
            logger.warning(f"Failed to find cipher position: {e}")

        return len(payload) // 2

    def _find_sni_position(self, payload: bytes) -> int:
        """
        Находит позицию начала Server Name Indication в ClientHello.

        Args:
            payload: Данные пакета

        Returns:
            Позиция SNI или позицию по умолчанию
        """
        try:
            # Ищем SNI extension (тип 0x0000)
            sni_pattern = b"\x00\x00"  # SNI extension type

            # Ищем в TLS extensions
            # Начинаем поиск после заголовков
            pos = payload.find(sni_pattern, 40)
            if pos != -1:
                logger.debug(f"Found SNI position at {pos}")
                return pos

        except Exception as e:
            logger.warning(f"Failed to find SNI position: {e}")

        return len(payload) // 2

    def _find_midsld_position(self, payload: bytes, packet_info: Dict[str, Any]) -> int:
        """
        Находит позицию середины второго уровня домена.

        Args:
            payload: Данные пакета
            packet_info: Информация о пакете

        Returns:
            Позиция середины SLD или позицию по умолчанию
        """
        try:
            # Пытаемся извлечь доменное имя из SNI
            domain = self._extract_domain_from_sni(payload)
            if not domain:
                return len(payload) // 2

            # Находим второй уровень домена
            parts = domain.split(".")
            if len(parts) >= 2:
                sld = parts[-2]  # Второй уровень домена
                mid_pos = len(sld) // 2

                # Ищем позицию этого домена в payload
                domain_bytes = domain.encode("utf-8")
                domain_pos = payload.find(domain_bytes)
                if domain_pos != -1:
                    # Вычисляем позицию середины SLD
                    sld_start = domain_pos + domain.rfind(sld)
                    result_pos = sld_start + mid_pos
                    logger.debug(
                        f"Found midsld position at {result_pos} for domain {domain}"
                    )
                    return result_pos

        except Exception as e:
            logger.warning(f"Failed to find midsld position: {e}")

        return len(payload) // 2

    def _extract_domain_from_sni(self, payload: bytes) -> Optional[str]:
        """
        Извлекает доменное имя из SNI extension.

        Args:
            payload: Данные пакета

        Returns:
            Доменное имя или None
        """
        try:
            # Простой поиск SNI в TLS ClientHello
            # Ищем паттерн SNI extension
            for i in range(len(payload) - 10):
                if payload[
                    i : i + 2
                ] == b"\x00\x00" and i + 9 < len(  # SNI extension type
                    payload
                ):

                    # Пропускаем заголовки extension
                    name_start = i + 9
                    if name_start < len(payload):
                        # Ищем длину имени
                        if name_start + 2 < len(payload):
                            name_len = int.from_bytes(
                                payload[name_start : name_start + 2], "big"
                            )
                            if name_start + 2 + name_len <= len(payload):
                                domain = payload[
                                    name_start + 2 : name_start + 2 + name_len
                                ].decode("utf-8")
                                return domain

        except Exception as e:
            logger.debug(f"Failed to extract domain from SNI: {e}")

        return None

    def get_attack_info(self, attack_type: str) -> Dict[str, Any]:
        """
        Получает полную информацию об атаке из реестра.

        Args:
            attack_type: Тип атаки (может быть алиасом)

        Returns:
            Словарь с информацией об атаке:
            - canonical_name: Каноническое имя
            - aliases: Список алиасов
            - metadata: Метаданные атаки
            - is_available: Доступна ли атака

        Raises:
            ValueError: Если атака не найдена
        """
        try:
            canonical_name = self.registry.get_canonical_name(attack_type)
            metadata = self.registry.get_attack_metadata(canonical_name)

            if not metadata:
                raise ValueError(f"No metadata found for attack '{attack_type}'")

            return {
                "canonical_name": canonical_name,
                "aliases": self.registry.get_attack_aliases(canonical_name),
                "metadata": metadata,
                "is_available": self.registry.get_attack_handler(canonical_name)
                is not None,
                "is_alias": self.registry.is_alias(attack_type),
                "all_names": self.registry.get_all_names_for_attack(canonical_name),
            }
        except Exception as e:
            logger.error(f"Failed to get attack info for '{attack_type}': {e}")
            raise ValueError(f"Attack '{attack_type}' not found in registry") from e

    def list_available_attacks(
        self, category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Получает список всех доступных атак с их информацией.

        Args:
            category: Фильтр по категории (опционально)

        Returns:
            Список словарей с информацией о каждой атаке
        """
        attacks = self.registry.list_attacks(category=category, enabled_only=True)
        attack_info = []

        for attack_name in attacks:
            try:
                info = self.get_attack_info(attack_name)
                attack_info.append(info)
            except Exception as e:
                logger.warning(f"Failed to get info for attack '{attack_name}': {e}")

        return attack_info

    def validate_attack_parameters(
        self, attack_type: str, params: Dict[str, Any]
    ) -> ValidationResult:
        """
        Валидирует параметры атаки через реестр.

        Args:
            attack_type: Тип атаки
            params: Параметры для валидации

        Returns:
            Результат валидации
        """
        try:
            canonical_name = self.registry.get_canonical_name(attack_type)
            return self.registry.validate_parameters(canonical_name, params)
        except Exception as e:
            logger.error(f"Failed to validate parameters for '{attack_type}': {e}")
            from ..attacks.metadata import ValidationResult

            return ValidationResult(
                is_valid=False, error_message=f"Validation failed: {e}"
            )

    def _resolve_custom_sni(self, params: Dict[str, Any]) -> Optional[str]:
        """
        Разрешает custom SNI для использования в fake packets.
        
        Поддерживает как новый параметр custom_sni, так и legacy fake_sni
        для обратной совместимости.
        
        Args:
            params: Параметры атаки, которые могут содержать custom_sni или fake_sni
            
        Returns:
            SNI значение для использования в fake packets или None если не нужно
        """
        try:
            # Check for custom_sni first (preferred), then fake_sni (legacy)
            custom_sni = params.get("custom_sni") or params.get("fake_sni")
            
            if custom_sni is None:
                return None
            
            # Создаем стратегию из параметров для передачи в CustomSNIHandler
            strategy = {"custom_sni": custom_sni}
            
            # Получаем SNI через CustomSNIHandler
            sni_value = self.custom_sni_handler.get_sni_for_strategy(strategy)
            
            logger.debug(f"Custom SNI resolved: {sni_value} (from {'custom_sni' if 'custom_sni' in params else 'fake_sni'})")
            return sni_value
            
        except Exception as e:
            logger.warning(f"Failed to resolve custom SNI: {e}")
            return None

    def _log_segment_details(
        self,
        segments: List[Tuple[bytes, int, Dict[str, Any]]],
        correlation_id: str
    ) -> None:
        """
        Logs detailed information about each generated packet segment.
        
        REQUIREMENT 5.2: Log each generated packet segment with details
        (sequence, length, flags)
        
        Args:
            segments: List of packet segments to log
            correlation_id: Correlation ID for tracing
        """
        if not segments:
            logger.debug(f"📋 [CID:{correlation_id}] No segments to log")
            return
        
        logger.info(f"📋 [CID:{correlation_id}] Segment details ({len(segments)} total):")
        
        for i, segment in enumerate(segments):
            # Segment format: (data, offset, options)
            data, offset, options = segment
            
            # Extract TCP flags if present
            flags = options.get('flags', 'N/A')
            tcp_seq = options.get('tcp_seq', 'N/A')
            tcp_ack = options.get('tcp_ack', 'N/A')
            
            # Log segment details
            logger.info(
                f"   Segment {i+1}/{len(segments)}: "
                f"length={len(data)}, offset={offset}, "
                f"seq={tcp_seq}, ack={tcp_ack}, flags={flags}"
            )
            
            # Log additional options if present
            other_options = {k: v for k, v in options.items() 
                           if k not in ('flags', 'tcp_seq', 'tcp_ack')}
            if other_options:
                logger.debug(
                    f"      [CID:{correlation_id}] Additional options: {other_options}"
                )
            
            # Log first few bytes of data for debugging (hex format)
            if len(data) > 0:
                preview_len = min(16, len(data))
                hex_preview = ' '.join(f'{b:02x}' for b in data[:preview_len])
                if len(data) > preview_len:
                    hex_preview += '...'
                logger.debug(
                    f"      [CID:{correlation_id}] Data preview: {hex_preview}"
                )

    def _log_operations_for_validation(
        self,
        strategy_id: Optional[str],
        operation_type: str,
        parameters: Dict[str, Any],
        segments: List[Tuple[bytes, int, Dict[str, Any]]],
        correlation_id: Optional[str] = None
    ) -> None:
        """
        Log operations for validation purposes.
        
        Task 11.4: Log operations with unique ID, type, parameters, and segment number
        for offline PCAP validation.
        
        Requirements: 1.2 - Log operations for validation
        
        Args:
            strategy_id: Strategy test identifier (if in verification mode)
            operation_type: Type of operation (split, fake, disorder, etc.)
            parameters: Operation-specific parameters
            segments: Generated segments
            correlation_id: Correlation ID for tracing
        """
        if not OPERATION_LOGGER_AVAILABLE or not strategy_id:
            # Operation logging not available or not in verification mode
            return
        
        try:
            operation_logger = get_operation_logger()
            
            # Log each segment as a separate operation
            for segment_num, segment in enumerate(segments, 1):
                data, offset, options = segment
                
                # Build operation parameters
                op_params = {
                    'operation_type': operation_type,
                    'offset': offset,
                    'data_length': len(data),
                    **parameters,  # Include original attack parameters
                    **options  # Include segment-specific options
                }
                
                # Log the operation
                operation_logger.log_operation(
                    strategy_id=strategy_id,
                    operation_type=operation_type,
                    parameters=op_params,
                    segment_number=segment_num,
                    correlation_id=correlation_id
                )
            
            logger.debug(
                f"📝 [CID:{correlation_id}] Logged {len(segments)} operations "
                f"for validation (strategy_id={strategy_id[:8] if strategy_id else 'N/A'})"
            )
            
        except Exception as e:
            logger.warning(
                f"⚠️ [CID:{correlation_id}] Failed to log operations for validation: {e}"
            )
    
    def _get_current_time(self) -> float:
        """Возвращает текущее время для измерения производительности."""
        import time

        return time.time()


def create_attack_dispatcher(techniques: BypassTechniques) -> AttackDispatcher:
    """
    Удобная функция для создания AttackDispatcher.

    Args:
        techniques: Экземпляр BypassTechniques

    Returns:
        Настроенный AttackDispatcher
    """
    return AttackDispatcher(techniques)
