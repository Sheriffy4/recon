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

        # Инициализируем полноценные атаки из директории attacks
        self._advanced_attacks = {}
        self._init_advanced_attacks()

        logger.info(
            f"AttackDispatcher initialized with {
                len(
                    self._advanced_attacks)} advanced attacks and parameter normalizer"
        )

    
    
    def resolve_strategy(self, strategy: str) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Разрешает zapret-style стратегию в последовательность атак.

        Поддерживаемые форматы стратегий:
        - Простые: "fake", "disorder", "split"
        - Комбинированные: "fake,disorder", "split,fake"
        - С параметрами: "fake:ttl=3", "disorder:split_pos=10"
        - Сложные: "fake:ttl=3,disorder:split_pos=sni"

        Примеры разрешения:
        - "fake" → [("fake", {})]
        - "fake,disorder" → [("fakeddisorder", {})]
        - "disorder,fake" → [("fakeddisorder", {})]
        - "split" → [("split", {})]
        - "fake:ttl=3" → [("fake", {"ttl": 3})]
        - "disorder:split_pos=sni" → [("disorder", {"split_pos": "sni"})]

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

        elif set(attack_names) == {"split", "fake"}:
            logger.debug("Combining 'split' + 'fake' → 'fakeddisorder' with split")
            return [("fakeddisorder", combined_params)]

        elif "fake" in attack_names and "disorder" in attack_names:
            # Более общий случай с дополнительными атаками
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
        2. Попытка использования продвинутой атаки из attacks/ (приоритет)
        3. Fallback на примитивную атаку из primitives.py
        4. Валидация параметров через AttackRegistry
        5. Разрешение специальных значений (cipher, sni, midsld)
        6. Выполнение атаки и возврат рецепта

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

        # Логируем начало диспетчеризации
        logger.info(
            f"🎯 Starting attack dispatch: type='{task_type}', payload_size={
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
        logger.debug(f"📋 Attack parameters: {params}")

        try:
            # 1. Проверяем, является ли task_type стратегией (содержит запятые
            # или двоеточия)
            if "," in task_type or ":" in task_type:
                logger.info(f"🔗 Detected zapret-style strategy: '{task_type}'")

                # Это zapret-style стратегия, разрешаем её
                resolved_attacks = self.resolve_strategy(task_type)
                logger.info(
                    f"📊 Strategy resolved to {
                        len(resolved_attacks)} attacks: {
                        [
                            a[0] for a in resolved_attacks]}"
                )

                # Выполняем все атаки из стратегии последовательно
                all_segments = []
                for i, (attack_name, strategy_params) in enumerate(resolved_attacks):
                    logger.debug(
                        f"🔄 Executing strategy attack {
                            i + 1}/{
                            len(resolved_attacks)}: '{attack_name}' with params {strategy_params}"
                    )

                    # Объединяем параметры стратегии с переданными параметрами
                    merged_params = {**strategy_params, **params}
                    logger.debug(
                        f"🔧 Merged parameters for '{attack_name}': {merged_params}"
                    )

                    # Рекурсивно вызываем dispatch_attack для каждой атаки
                    attack_start_time = self._get_current_time()
                    attack_segments = self.dispatch_attack(
                        attack_name, merged_params, payload, packet_info
                    )
                    attack_execution_time = self._get_current_time() - attack_start_time

                    logger.info(
                        f"✅ Strategy attack '{attack_name}' completed in {
                            attack_execution_time:.3f}s, "
                        f"generated {
                            len(attack_segments)} segments"
                    )
                    all_segments.extend(attack_segments)

                execution_time = self._get_current_time() - start_time
                logger.info(
                    f"🎉 Strategy '{task_type}' executed successfully in {
                        execution_time:.3f}s, "
                    f"generated {
                        len(all_segments)} total segments from {
                        len(resolved_attacks)} attacks"
                )
                return all_segments

            # 2. Нормализация типа атаки (одиночная атака)
            logger.debug(f"🔍 Normalizing attack type: '{task_type}'")
            normalized_type = self._normalize_attack_type(task_type)
            logger.info(
                f"📝 Attack type normalized: '{task_type}' → '{normalized_type}'"
            )

            # 3. Нормализация параметров через ParameterNormalizer
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

            # 4. ПРИОРИТЕТ: Пытаемся использовать продвинутую атаку из
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
                logger.info(f"🎯 Advanced attack '{task_type}' executed successfully!")
                logger.info(
                    f"⏱️ Timing: advanced_execution={
                        advanced_execution_time:.3f}s, total={
                        execution_time:.3f}s"
                )
                logger.info(f"📦 Generated {len(advanced_result)} segments")
                logger.debug(
                    f"📋 Segment details: {
                        [
                            (len(
                                seg[0]), seg[1], list(
                                seg[2].keys())) for seg in advanced_result]}"
                )
                return advanced_result

            # 5. FALLBACK: Используем примитивные атаки из primitives.py
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
            logger.info(f"🎉 Primitive attack '{task_type}' dispatched successfully!")
            logger.info(
                f"⏱️ Timing: handler={
                    handler_execution_time:.3f}s, total={
                    execution_time:.3f}s"
            )
            logger.info(f"📦 Generated {len(recipe)} segments")

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
        Инициализирует продвинутые атаки из директории attacks/.

        Регистрирует доступные продвинутые атаки, которые имеют приоритет
        над примитивными реализациями. Продвинутые атаки предоставляют:

        - Лучшую совместимость с zapret
        - Более точную логику для каждого типа атаки
        - Поддержку сложных параметров
        - Асинхронное выполнение с контролем таймаутов

        Зарегистрированные атаки:
        - fakeddisorder: Основная атака с фейковым пакетом
        - multisplit: Множественное разделение TCP пакетов
        - multidisorder: Множественное разделение с disorder эффектом
        - seqovl: Sequence overlap атака

        При недоступности продвинутых атак система автоматически
        переключается на примитивные реализации.
        """
        if not ADVANCED_ATTACKS_AVAILABLE:
            logger.info("Advanced attacks not available, using primitives only")
            return

        try:
            # Регистрируем продвинутые атаки, которые заменят примитивные

            # FakeDisorder - самая важная атака
            self._advanced_attacks["fakeddisorder"] = {
                "class": FixedFakeDisorderAttack,
                "aliases": ["fake_disorder", "fakedisorder"],
                "description": "Полноценная FakeDisorder атака с zapret совместимостью",
            }

            # Multisplit - множественное разделение
            self._advanced_attacks["multisplit"] = {
                "class": TCPMultiSplitAttack,
                "aliases": ["multi_split"],
                "description": "Продвинутое множественное разделение TCP пакетов",
            }

            # Multidisorder - множественное разделение с disorder
            self._advanced_attacks["multidisorder"] = {
                # Используем ту же реализацию с другими параметрами
                "class": FixedFakeDisorderAttack,
                "aliases": ["multi_disorder"],
                "description": "Множественное разделение с disorder эффектом",
            }

            # Note: seqovl is handled by the registry as a CORE attack, not here

            logger.info(
                f"✅ Initialized {len(self._advanced_attacks)} advanced attacks from attacks directory"
            )

        except Exception as e:
            logger.error(f"Failed to initialize advanced attacks: {e}")
            # Продолжаем работу с примитивными атаками

    def _use_advanced_attack(
        self,
        task_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> Optional[List[Tuple[bytes, int, Dict[str, Any]]]]:
        """
        Пытается использовать продвинутую атаку из директории attacks/.

        Процесс выполнения:
        1. Проверка доступности продвинутых атак
        2. Поиск соответствующей реализации для task_type
        3. Создание контекста атаки (AttackContext)
        4. Создание специализированного экземпляра атаки
        5. Выполнение атаки в отдельном потоке с таймаутом
        6. Конвертация результата в формат рецепта

        Особенности:
        - Асинхронные атаки выполняются в новом event loop
        - Синхронные атаки выполняются напрямую
        - Таймаут выполнения: 10 секунд
        - При ошибке возвращается None для fallback

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
            f"🔍 Checking advanced attack availability for '{normalized_type}'"
        )

        # Проверяем, есть ли продвинутая реализация
        if normalized_type not in self._advanced_attacks:
            logger.debug(
                f"🚫 No advanced implementation available for '{normalized_type}'"
            )
            logger.debug(
                f"📋 Available advanced attacks: {
                    list(
                        self._advanced_attacks.keys())}"
            )
            return None

        logger.info(f"🎯 Found advanced attack implementation for '{normalized_type}'")

        try:
            attack_info = self._advanced_attacks[normalized_type]
            attack_class = attack_info["class"]

            logger.debug(
                f"📋 Advanced attack info: {
                    attack_info['description']}"
            )
            logger.debug(f"🏗️ Using attack class: {attack_class.__name__}")

            # Создаем контекст атаки
            connection_id = f"{
                packet_info.get(
                    'src_addr', '0.0.0.0')}:{
                packet_info.get(
                    'src_port', 0)}->{
                packet_info.get(
                    'dst_addr', '0.0.0.0')}:{
                packet_info.get(
                    'dst_port', 0)}"

            logger.debug("🏗️ Creating AttackContext for advanced attack")
            context = AttackContext(
                connection_id=connection_id,
                payload=payload,
                dst_ip=packet_info.get("dst_addr", "0.0.0.0"),
                dst_port=packet_info.get("dst_port", 443),
            )
            # Добавляем дополнительные атрибуты
            context.packet_info = packet_info
            context.params = (
                params  # Исправлено: используем params вместо attack_params
            )

            logger.debug(
                f"📋 Advanced attack context: connection_id='{connection_id}', payload_size={
                    len(payload)}"
            )

            # Создаем и выполняем атаку
            logger.debug(f"🏗️ Creating advanced attack instance for '{normalized_type}'")
            attack_creation_start = self._get_current_time()

            if normalized_type == "fakeddisorder":
                logger.debug("🔧 Creating specialized fakeddisorder attack")
                attack = self._create_fakeddisorder_attack(params)
            elif normalized_type == "multisplit":
                logger.debug("🔧 Creating specialized multisplit attack")
                attack = self._create_multisplit_attack(params)
            elif normalized_type == "multidisorder":
                logger.debug("🔧 Creating specialized multidisorder attack")
                attack = self._create_multidisorder_attack(params)
            elif normalized_type == "seqovl":
                logger.debug("🔧 Creating specialized seqovl attack")
                attack = self._create_seqovl_attack(params)
            else:
                # Общий случай
                logger.debug("🔧 Creating generic attack instance")
                attack = attack_class()

            attack_creation_time = self._get_current_time() - attack_creation_start
            logger.debug(
                f"✅ Attack instance created in {
                    attack_creation_time:.4f}s"
            )

            # Выполняем атаку синхронно (адаптируем async к sync)
            import asyncio
            import concurrent.futures

            def run_attack_in_thread():
                """
                Запускает атаку в отдельном потоке.

                Выполняет атаку асинхронно и сохраняет результат в общей переменной.
                Обрабатывает исключения и устанавливает соответствующий статус результата.
                """
                try:
                    # Проверяем, является ли execute async методом
                    execute_method = attack.execute
                    if asyncio.iscoroutinefunction(execute_method):
                        # Async метод - создаем новый event loop
                        new_loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(new_loop)
                        try:
                            return new_loop.run_until_complete(execute_method(context))
                        finally:
                            new_loop.close()
                    else:
                        # Sync метод - выполняем напрямую
                        return execute_method(context)
                except Exception as e:
                    logger.error(f"Attack execution error: {e}")
                    return None

            try:
                # Выполняем в отдельном потоке
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_attack_in_thread)
                    result = future.result(timeout=10.0)
            except Exception as e:
                logger.error(
                    f"Failed to execute advanced attack in separate thread: {e}"
                )
                return None

            if result is None:
                logger.warning(f"⚠️ Advanced attack '{normalized_type}' returned no result")
                return None

            if result.status == AttackStatus.SUCCESS and result.segments:
                logger.info(
                    f"🎯 Advanced attack '{normalized_type}' executed successfully!"
                )
                logger.info(f"📦 Generated {len(result.segments)} segments")
                logger.debug(
                    f"📋 Segment details: {
                        [
                            (len(
                                seg[0]), seg[1], list(
                                seg[2].keys())) for seg in result.segments]}"
                )
                return result.segments
            else:
                logger.warning(f"⚠️ Advanced attack '{normalized_type}' failed")
                logger.warning(f"❌ Status: {result.status}")
                logger.warning(f"❌ Error: {result.error_message}")
                logger.debug(
                    f"📋 Result details: segments={len(result.segments) if result.segments else 0}"
                )
                return None

        except Exception as e:
            logger.error(f"💥 Advanced attack '{normalized_type}' execution failed")
            logger.error(f"❌ Exception type: {type(e).__name__}")
            logger.error(f"❌ Exception message: {e}")
            logger.debug(f"📋 Failed with params: {params}")

            # Логируем стек вызовов для отладки
            import traceback

            logger.debug(f"📋 Stack trace:\n{traceback.format_exc()}")

            return None

    def _create_fakeddisorder_attack(self, params: Dict[str, Any]):
        """
        Создает настроенную FakeDisorder атаку.

        Args:
            params: Параметры атаки включая split_pos, fake_ttl, fooling_methods

        Returns:
            Настроенный экземпляр FakeDisorderAttack или None если недоступен
        """
        if ADVANCED_ATTACKS_AVAILABLE:
            # Конвертируем параметры в правильный формат для продвинутой атаки
            config = {}

            # Обрабатываем split_pos
            split_pos = params.get("split_pos")
            if isinstance(split_pos, list):
                split_pos = split_pos[0] if split_pos else 3
            config["split_pos"] = split_pos or 3

            # Обрабатываем TTL
            config["ttl"] = params.get("fake_ttl", params.get("ttl", 3))

            # Обрабатываем overlap_size
            config["overlap_size"] = params.get(
                "overlap_size", params.get("split_seqovl", 0)
            )

            # Обрабатываем fooling методы
            config["fooling"] = params.get(
                "fooling_methods", params.get("fooling", ["badsum"])
            )

            # Другие параметры
            config["repeats"] = params.get("repeats", 1)
            config["autottl"] = params.get("autottl")

            logger.debug(f"Creating advanced fakeddisorder with config: {config}")
            # Конструктор FakedDisorderAttack умеет принимать kwargs и сам создаст FakedDisorderConfig
            return FixedFakeDisorderAttack(**config)
        else:
            return None

    def _create_multidisorder_attack(self, params: Dict[str, Any]):
        """
        Создает настроенную MultiDisorder атаку.

        Args:
            params: Параметры атаки включая positions, fooling_methods, fake_ttl

        Returns:
            Настроенный экземпляр MultiDisorderAttack или None если недоступен
        """
        if not ADVANCED_ATTACKS_AVAILABLE:
            return None

        # Адаптируем параметры для multidisorder
        config = params.copy()

        # Для multidisorder используем множественные позиции
        if "positions" not in config and "split_pos" in config:
            split_pos = config["split_pos"]
            if isinstance(split_pos, int):
                # Создаем несколько позиций на основе split_pos
                config["positions"] = [
                    split_pos // 2,
                    split_pos,
                    split_pos + split_pos // 2,
                ]
            else:
                config["positions"] = [3, 10, 20]  # Значения по умолчанию

        return FixedFakeDisorderAttack(**config)

    def _create_multisplit_attack(self, params: Dict[str, Any]):
        """
        Создает настроенную MultiSplit атаку.

        Args:
            params: Параметры атаки включая positions и другие опции разделения

        Returns:
            Настроенный экземпляр MultiSplitAttack или None если недоступен
        """
        if not ADVANCED_ATTACKS_AVAILABLE:
            return None

        # Создаем TCPMultiSplitAttack
        attack = TCPMultiSplitAttack()

        # Устанавливаем параметры атаки
        attack.split_count = params.get("split_count", 3)
        attack.overlap_size = params.get("overlap_size", 0)
        attack.fooling_methods = params.get("fooling", ["badsum"])

        # Если есть positions, вычисляем split_count
        if "positions" in params and params["positions"]:
            attack.split_count = len(params["positions"]) + 1

        return attack

    def _create_seqovl_attack(self, params: Dict[str, Any]):
        """Creates a configured SeqOvl attack using the FakedDisorderAttack class."""
        if not ADVANCED_ATTACKS_AVAILABLE:
            return None

        config = params.copy()
        if "split_seqovl" not in config and "overlap_size" in config:
            config["split_seqovl"] = config["overlap_size"]
        elif "split_seqovl" not in config:
            config["split_seqovl"] = 20  # Default value

        # Call the constructor directly
        return FixedFakeDisorderAttack(**config)

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
