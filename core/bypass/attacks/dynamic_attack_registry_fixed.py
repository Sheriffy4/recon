"""
Dynamic Attack Registry - Автоматическая регистрация сгенерированных стратегий.

Этот модуль расширяет AttackRegistry возможностью автоматически регистрировать
новые стратегии, сгенерированные StrategyDiversifier или другими компонентами.

Основные функции:
- Автоматическое создание алиасов для сгенерированных стратегий
- Парсинг имен стратегий для извлечения базового типа атаки и параметров
- Регистрация временных стратегий для тестирования
- Очистка устаревших динамических регистраций
"""

import logging
import re
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

from .attack_registry import get_attack_registry, AttackRegistry
from .metadata import AttackMetadata

logger = logging.getLogger(__name__)

_DEFAULT_STRATEGY_PATTERNS = [
    re.compile(r"^(?P<base_attack>\w+)_(?P<domain>[\w\.]+_[\w\.]+)_(?P<params>.+)$"),
    re.compile(r"^(?P<base_attack>\w+)_(?P<domain>[\w\.]+)_(?P<params>.+)$"),
    re.compile(r"^(?P<base_attack>\w+)_(?P<params>spl\w+|dis\w+|ttl\w+|foo\w+|ovl\w+).*$"),
]


class DynamicAttackRegistry:
    """
    Расширение AttackRegistry для автоматической регистрации сгенерированных стратегий.
    """

    def __init__(self, base_registry: Optional[AttackRegistry] = None):
        """
        Инициализирует динамический реестр.

        Args:
            base_registry: Базовый реестр атак (если None, используется глобальный)
        """
        self.base_registry = base_registry or get_attack_registry()
        self.dynamic_registrations: Dict[str, datetime] = {}
        self.cleanup_interval = timedelta(hours=1)  # Очистка каждый час
        self.max_dynamic_age = timedelta(hours=24)  # Максимальный возраст динамических регистраций

        # Паттерны для парсинга имен стратегий (оставляем как атрибут для внешней совместимости)
        self.strategy_patterns = list(_DEFAULT_STRATEGY_PATTERNS)

        logger.info("DynamicAttackRegistry initialized")

    def auto_register_strategy(self, strategy_name: str) -> bool:
        """
        Автоматически регистрирует стратегию, если она не найдена в базовом реестре.

        Args:
            strategy_name: Имя стратегии для регистрации

        Returns:
            True если стратегия была зарегистрирована, False иначе
        """
        # Проверяем, есть ли уже такая стратегия
        if self.base_registry.get_attack_handler(strategy_name) is not None:
            return False  # Уже существует

        # Пытаемся распарсить имя стратегии
        parsed = self._parse_strategy_name(strategy_name)
        if not parsed:
            logger.debug(f"Could not parse strategy name: {strategy_name}")
            return False

        base_attack, domain, params = parsed

        # Проверяем, существует ли базовая атака
        base_handler = self.base_registry.get_attack_handler(base_attack)
        if base_handler is None:
            logger.warning(f"Base attack '{base_attack}' not found for strategy '{strategy_name}'")
            return False

        # Получаем метаданные базовой атаки
        base_metadata = self.base_registry.get_attack_metadata(base_attack)
        if base_metadata is None:
            logger.warning(f"Base metadata not found for attack '{base_attack}'")
            return False

        # Создаем метаданные для новой стратегии
        strategy_metadata = self._create_strategy_metadata(
            strategy_name, base_attack, domain, params, base_metadata
        )

        # Регистрируем как алиас базовой атаки
        result = self.base_registry.register_alias(
            alias=strategy_name, canonical_attack=base_attack, metadata=strategy_metadata
        )

        if result.success:
            # Записываем время регистрации для последующей очистки
            self.dynamic_registrations[strategy_name] = datetime.now()
            logger.info(
                f"✅ Auto-registered strategy '{strategy_name}' as alias for '{base_attack}'"
            )
            return True
        else:
            logger.warning(f"Failed to auto-register strategy '{strategy_name}': {result.message}")
            return False

    def _parse_strategy_name(self, strategy_name: str) -> Optional[Tuple[str, str, Dict[str, Any]]]:
        """
        Парсит имя стратегии для извлечения базового типа атаки и параметров.

        Args:
            strategy_name: Имя стратегии для парсинга

        Returns:
            Кортеж (base_attack, domain, params) или None если не удалось распарсить
        """
        for pattern in self.strategy_patterns:
            match = pattern.match(strategy_name)
            if match:
                base_attack = match.group("base_attack")

                # Извлекаем домен если есть
                domain = match.groupdict().get("domain", "unknown")
                if domain:
                    domain = domain.replace("_", ".")

                params_str = match.group("params")

                # Парсим параметры из строки
                params = self._parse_params_string(params_str)

                # Проверяем, существует ли базовая атака
                if self.base_registry.get_attack_handler(base_attack) is not None:
                    return base_attack, domain, params

        # Если стандартные паттерны не сработали, пробуем найти базовую атаку методом исключения
        return self._fallback_parse_strategy_name(strategy_name)

    def _parse_params_string(self, params_str: str) -> Dict[str, Any]:
        """
        Парсит строку параметров в словарь.

        Args:
            params_str: Строка параметров (например, "spl2_dis1")

        Returns:
            Словарь параметров
        """
    def _parse_params_string(self, params_str: str) -> Dict[str, Any]:
        """
        Парсит строку параметров в словарь.

        Args:
            params_str: Строка параметров (например: "spl2_dis1_ttl5")

        Returns:
            Словарь параметров
        """
        params: Dict[str, Any] = {}

        # Паттерны для различных параметров (re.findall -> берём первое совпадение)
        param_patterns: list[tuple[str, str, Any]] = [
            (r"spl(\d+)", "split_pos", int),
            (r"splsni", "split_pos", lambda _m: "sni"),
            (r"splrandom", "split_pos", lambda _m: "random"),
            (r"dis(\d+)", "disorder_count", int),
            (r"ttl(\d+)", "ttl", int),
            (r"foo(\w+)", "fooling", str),
            (r"ovl(\d+)", "overlap_size", int),
        ]

        for pattern, param_name, converter in param_patterns:
            matches = re.findall(pattern, params_str)
            if not matches:
                continue
            raw = matches[0]
            try:
                params[param_name] = converter(raw)  # int/str/лямбда - всё callable
            except Exception:
                logger.debug(
                    "Failed to convert param %s from raw value %r (pattern=%r)",
                    param_name,
                    raw,
                    pattern,
                    exc_info=True,
                )

        logger.debug(f"Parsed params from '{params_str}': {params}")
        return params

    def _fallback_parse_strategy_name(
        self, strategy_name: str
    ) -> Optional[Tuple[str, str, Dict[str, Any]]]:
        """
        Fallback метод для парсинга сложных имен стратегий.
        Пытается найти базовую атаку методом исключения.

        Args:
            strategy_name: Имя стратегии для парсинга

        Returns:
            Кортеж (base_attack, domain, params) или None если не удалось распарсить
        """
        # Получаем список всех доступных атак
        available_attacks = self.base_registry.list_attacks()

        # Сортируем по длине (сначала более длинные, чтобы избежать ложных совпадений)
        available_attacks = sorted(available_attacks, key=len, reverse=True)

        for base_attack in available_attacks:
            if strategy_name.startswith(base_attack + "_"):
                # Нашли потенциальную базовую атаку
                remainder = strategy_name[len(base_attack) + 1 :]  # +1 для подчеркивания

                # Пытаемся разделить остаток на домен и параметры
                parts = remainder.split("_")

                # Ищем параметры (начинающиеся с spl, dis, ttl, foo, ovl)
                param_start_idx = None
                for i, part in enumerate(parts):
                    if re.match(r"^(spl|dis|ttl|foo|ovl)", part):
                        param_start_idx = i
                        break

                if param_start_idx is not None:
                    # Есть параметры
                    domain_parts = parts[:param_start_idx]
                    param_parts = parts[param_start_idx:]

                    domain = ".".join(domain_parts) if domain_parts else "unknown"
                    params_str = "_".join(param_parts)
                    params = self._parse_params_string(params_str)
                else:
                    # Нет параметров, все остальное - домен
                    domain = ".".join(parts) if parts else "unknown"
                    params = {}

                logger.debug(
                    f"Fallback parsed '{strategy_name}': base='{base_attack}', domain='{domain}', params={params}"
                )
                return base_attack, domain, params

        logger.debug(f"Could not parse strategy name: {strategy_name}")
        return None

    def _create_strategy_metadata(
        self,
        strategy_name: str,
        base_attack: str,
        domain: str,
        params: Dict[str, Any],
        base_metadata: AttackMetadata,
    ) -> AttackMetadata:
        """
        Создает метаданные для сгенерированной стратегии.

        Args:
            strategy_name: Имя стратегии
            base_attack: Базовый тип атаки
            domain: Целевой домен
            params: Извлеченные параметры
            base_metadata: Метаданные базовой атаки

        Returns:
            Метаданные для новой стратегии
        """
        # Объединяем параметры базовой атаки с извлеченными
        merged_params = base_metadata.optional_params.copy()
        merged_params.update(params)

        # Создаем описание
        param_desc = ", ".join(f"{k}={v}" for k, v in params.items())
        description = f"Auto-generated {base_attack} strategy for {domain}"
        if param_desc:
            description += f" with parameters: {param_desc}"

        return AttackMetadata(
            name=strategy_name,
            description=description,
            required_params=base_metadata.required_params.copy(),
            optional_params=merged_params,
            aliases=[],  # Динамические стратегии не имеют дополнительных алиасов
            category=base_metadata.category,
        )

    def _remove_alias_from_base_registry(self, alias: str) -> bool:
        """
        Try to remove alias from AttackRegistry using best available mechanism.
        Keeps backward compatibility with older registries by falling back to _aliases.
        """
        if hasattr(self.base_registry, "unregister_alias"):
            try:
                return bool(self.base_registry.unregister_alias(alias))
            except Exception:
                logger.debug("unregister_alias(%r) failed", alias, exc_info=True)
        if hasattr(self.base_registry, "_aliases") and alias in getattr(self.base_registry, "_aliases"):
            del self.base_registry._aliases[alias]
            return True
        return False

    def cleanup_old_registrations(self) -> int:
        """
        Очищает устаревшие динамические регистрации.

        Returns:
            Количество удаленных регистраций
        """
        now = datetime.now()
        to_remove = []

        for strategy_name, registration_time in self.dynamic_registrations.items():
            if now - registration_time > self.max_dynamic_age:
                to_remove.append(strategy_name)

        removed_count = 0
        for strategy_name in to_remove:
            # Удаляем из базового реестра (если это алиас)
            if hasattr(self.base_registry, "is_alias") and self.base_registry.is_alias(strategy_name):
                if self._remove_alias_from_base_registry(strategy_name):
                    logger.debug("Removed expired dynamic alias: %s", strategy_name)
                    removed_count += 1

            # Удаляем из нашего трекинга
            del self.dynamic_registrations[strategy_name]

        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} expired dynamic registrations")

        return removed_count

    def get_dynamic_registrations(self) -> Dict[str, datetime]:
        """
        Возвращает все динамические регистрации с временем создания.

        Returns:
            Словарь {strategy_name: registration_time}
        """
        return self.dynamic_registrations.copy()

    def force_cleanup(self) -> int:
        """
        Принудительно очищает все динамические регистрации.

        Returns:
            Количество удаленных регистраций
        """
        removed_count = 0

        for strategy_name in list(self.dynamic_registrations.keys()):
            # Удаляем из базового реестра (если это алиас)
            if hasattr(self.base_registry, "is_alias") and self.base_registry.is_alias(strategy_name):
                if self._remove_alias_from_base_registry(strategy_name):
                    removed_count += 1

        # Очищаем наш трекинг
        self.dynamic_registrations.clear()

        logger.info(f"Force cleaned up {removed_count} dynamic registrations")
        return removed_count


# Глобальный экземпляр динамического реестра
_global_dynamic_registry = None


def get_dynamic_registry() -> DynamicAttackRegistry:
    """
    Возвращает глобальный экземпляр DynamicAttackRegistry.

    Returns:
        Глобальный экземпляр DynamicAttackRegistry
    """
    global _global_dynamic_registry

    if _global_dynamic_registry is None:
        _global_dynamic_registry = DynamicAttackRegistry()

    return _global_dynamic_registry


def auto_register_if_missing(strategy_name: str) -> bool:
    """
    Удобная функция для автоматической регистрации стратегии, если она отсутствует.

    Args:
        strategy_name: Имя стратегии

    Returns:
        True если стратегия была зарегистрирована или уже существует, False иначе
    """
    registry = get_dynamic_registry()

    # Проверяем, существует ли уже
    if registry.base_registry.get_attack_handler(strategy_name) is not None:
        return True

    # Пытаемся зарегистрировать
    return registry.auto_register_strategy(strategy_name)


def cleanup_dynamic_registrations() -> int:
    """
    Удобная функция для очистки устаревших динамических регистраций.

    Returns:
        Количество удаленных регистраций
    """
    registry = get_dynamic_registry()
    return registry.cleanup_old_registrations()


# Интеграция с AttackRegistry
def patch_attack_registry():
    """
    Патчит AttackRegistry для автоматической регистрации неизвестных стратегий.
    """
    # Idempotency: do not patch twice
    if getattr(AttackRegistry, "_dynamic_registration_patched", False):
        logger.debug("AttackRegistry already patched for dynamic registration")
        return

    original_get_attack_handler = AttackRegistry.get_attack_handler
    AttackRegistry._dynamic_registration_original_get_attack_handler = original_get_attack_handler

    def patched_get_attack_handler(self, attack_type: str):
        """Патченная версия get_attack_handler с автоматической регистрацией."""
        # Сначала пытаемся получить обработчик обычным способом
        handler = original_get_attack_handler(self, attack_type)

        if handler is not None:
            return handler

        # Если не найден, пытаемся автоматически зарегистрировать
        logger.debug(
            "Attack handler not found for %r, attempting auto-registration",
            attack_type,
        )

        dynamic_registry = get_dynamic_registry()
        if dynamic_registry.auto_register_strategy(attack_type):
            # Повторно пытаемся получить обработчик после регистрации
            return original_get_attack_handler(self, attack_type)

        return None

    # Применяем патч
    AttackRegistry.get_attack_handler = patched_get_attack_handler
    AttackRegistry._dynamic_registration_patched = True
    logger.info("✅ Patched AttackRegistry with dynamic registration support")


if __name__ == "__main__":
    # Тестирование
    dynamic_registry = DynamicAttackRegistry()

    # Тестируем парсинг различных имен стратегий
    test_strategies = [
        "disorder_www_googlevideo_com_spl2_dis1",
        "fragmentation_example_com_spl5_spl16",
        "fake_domain_com_splsni",
        "seqovl_test_domain_spl3_ovl2",
        "fooling_site_com_foobadseq",
    ]

    print("Testing strategy name parsing:")
    for strategy in test_strategies:
        parsed = dynamic_registry._parse_strategy_name(strategy)
        if parsed:
            base_attack, domain, params = parsed
            print(f"  {strategy}")
            print(f"    Base: {base_attack}, Domain: {domain}, Params: {params}")
        else:
            print(f"  {strategy} - Could not parse")
        print()

    # Тестируем автоматическую регистрацию
    print("Testing auto-registration:")
    for strategy in test_strategies[:2]:  # Тестируем только первые 2
        success = dynamic_registry.auto_register_strategy(strategy)
        print(f"  {strategy}: {'✅ Registered' if success else '❌ Failed'}")

    print(f"\nDynamic registrations: {len(dynamic_registry.get_dynamic_registrations())}")
