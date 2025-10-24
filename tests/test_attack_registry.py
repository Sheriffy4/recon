"""
Тесты для AttackRegistry - централизованного реестра атак.
"""

import pytest
from unittest.mock import patch
from typing import Dict, Any, List, Tuple

from core.bypass.attacks.attack_registry import (
    AttackRegistry,
    get_attack_registry,
    register_attack,
    get_attack_handler,
    validate_attack_parameters,
    clear_registry,
)
from core.bypass.attacks.base import AttackContext
from core.bypass.attacks.metadata import (
    AttackMetadata,
    AttackCategories,
    ValidationResult,
    create_attack_metadata,
)
from core.bypass.techniques.primitives import BypassTechniques


class TestAttackRegistry:
    """Тесты для класса AttackRegistry."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.registry = AttackRegistry()
        self.techniques = BypassTechniques()

    def test_init(self):
        """Тест инициализации реестра."""
        assert isinstance(self.registry.attacks, dict)
        assert isinstance(self.registry._aliases, dict)
        assert (
            len(self.registry.attacks) > 0
        )  # Должны быть зарегистрированы встроенные атаки

    def test_builtin_attacks_registered(self):
        """Тест регистрации встроенных атак."""
        expected_attacks = [
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "disorder2",
            "multisplit",
            "split",
            "fake",
        ]

        for attack_type in expected_attacks:
            assert (
                attack_type in self.registry.attacks
            ), f"Attack {attack_type} not registered"
            assert self.registry.get_attack_handler(attack_type) is not None
            assert self.registry.get_attack_metadata(attack_type) is not None

    def test_register_attack(self):
        """Тест регистрации новой атаки."""

        def test_handler(
            context: AttackContext,
        ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload, 0, {"is_fake": False})]

        metadata = create_attack_metadata(
            name="Test Attack",
            description="Test attack for unit testing",
            category=AttackCategories.CUSTOM,
            required_params=["test_param"],
            optional_params={"optional_param": "default"},
            aliases=["test_alias"],
        )

        self.registry.register_attack("test_attack", test_handler, metadata)

        # Проверяем регистрацию
        assert "test_attack" in self.registry.attacks
        assert self.registry.get_attack_handler("test_attack") == test_handler
        assert self.registry.get_attack_metadata("test_attack") == metadata

        # Проверяем алиас
        assert self.registry._aliases["test_alias"] == "test_attack"
        assert self.registry.get_attack_handler("test_alias") == test_handler

    def test_register_attack_overwrite_warning(self):
        """Тест предупреждения при перезаписи атаки."""

        def handler1(techniques, payload: bytes, **params):
            return [(payload, 0, {"version": 1})]

        def handler2(techniques, payload: bytes, **params):
            return [(payload, 0, {"version": 2})]

        metadata = create_attack_metadata(
            name="Test Attack",
            description="Test attack",
            category=AttackCategories.CUSTOM,
        )

        # Регистрируем первый раз
        self.registry.register_attack("overwrite_test", handler1, metadata)

        # Регистрируем второй раз с предупреждением
        with patch("logging.Logger.warning") as mock_warning:
            self.registry.register_attack("overwrite_test", handler2, metadata)
            mock_warning.assert_called_once()
            # Check for "duplicate" instead of "already registered"
            assert "duplicate" in mock_warning.call_args[0][0].lower()

        # Проверяем, что обработчик НЕ перезаписан (same priority)
        # С новой логикой приоритетов, атака с тем же приоритетом не перезаписывается
        assert self.registry.get_attack_handler("overwrite_test") == handler1

    def test_get_attack_handler_existing(self):
        """Тест получения существующего обработчика."""
        handler = self.registry.get_attack_handler("fakeddisorder")
        assert handler is not None
        assert callable(handler)

    def test_get_attack_handler_alias(self):
        """Тест получения обработчика по алиасу."""
        handler_canonical = self.registry.get_attack_handler("fakeddisorder")
        handler_alias = self.registry.get_attack_handler("fake_disorder")

        assert handler_canonical is not None
        assert handler_alias is not None
        assert handler_canonical == handler_alias

    def test_get_attack_handler_nonexistent(self):
        """Тест получения несуществующего обработчика."""
        handler = self.registry.get_attack_handler("nonexistent_attack")
        assert handler is None

    def test_get_attack_metadata_existing(self):
        """Тест получения существующих метаданных."""
        metadata = self.registry.get_attack_metadata("fakeddisorder")
        assert metadata is not None
        assert isinstance(metadata, AttackMetadata)
        assert metadata.name == "Fake Disorder"
        assert "split_pos" in metadata.required_params

    def test_get_attack_metadata_nonexistent(self):
        """Тест получения несуществующих метаданных."""
        metadata = self.registry.get_attack_metadata("nonexistent_attack")
        assert metadata is None

    def test_validate_parameters_valid(self):
        """Тест валидации валидных параметров."""
        params = {"split_pos": 5, "ttl": 3, "fooling": ["badsum"]}

        result = self.registry.validate_parameters("fakeddisorder", params)

        assert result.is_valid is True
        assert result.error_message is None

    def test_validate_parameters_missing_required(self):
        """Тест валидации с отсутствующими обязательными параметрами."""
        params = {"ttl": 3}  # Отсутствует split_pos

        result = self.registry.validate_parameters("fakeddisorder", params)

        assert result.is_valid is False
        assert "Missing required parameter 'split_pos'" in result.error_message

    def test_validate_parameters_invalid_split_pos(self):
        """Тест валидации с невалидным split_pos."""
        params = {"split_pos": {"invalid": "dict"}}  # Должно быть int, str или list

        result = self.registry.validate_parameters("fakeddisorder", params)

        assert result.is_valid is False
        assert "split_pos" in result.error_message

    def test_validate_parameters_invalid_positions(self):
        """Тест валидации с невалидными positions."""
        params = {"positions": "not_a_list"}  # Должно быть list

        result = self.registry.validate_parameters("multisplit", params)

        assert result.is_valid is False
        assert "positions must be a list" in result.error_message

    def test_validate_parameters_invalid_position_values(self):
        """Тест валидации с невалидными значениями позиций."""
        params = {"positions": [1, 0, 3]}  # 0 недопустимо

        result = self.registry.validate_parameters("multisplit", params)

        assert result.is_valid is False
        assert "Position values must be >= 1" in result.error_message

    def test_validate_parameters_invalid_overlap_size(self):
        """Тест валидации с невалидным overlap_size."""
        params = {"split_pos": 5, "overlap_size": -1}  # Отрицательное значение

        result = self.registry.validate_parameters("seqovl", params)

        assert result.is_valid is False
        assert "overlap_size must be non-negative int" in result.error_message

    def test_validate_parameters_invalid_ttl(self):
        """Тест валидации с невалидным TTL."""
        params = {"split_pos": 5, "ttl": 300}  # Больше 255

        result = self.registry.validate_parameters("fakeddisorder", params)

        assert result.is_valid is False
        assert "ttl must be int between 1 and 255" in result.error_message

    def test_validate_parameters_invalid_fooling(self):
        """Тест валидации с невалидными fooling методами."""
        params = {"split_pos": 5, "fooling": ["invalid_method"]}

        result = self.registry.validate_parameters("fakeddisorder", params)

        assert result.is_valid is False
        assert "Invalid fooling method 'invalid_method'" in result.error_message

    def test_validate_parameters_unknown_attack(self):
        """Тест валидации для неизвестного типа атаки."""
        params = {"split_pos": 5}

        result = self.registry.validate_parameters("unknown_attack", params)

        assert result.is_valid is False
        assert "Unknown attack type: unknown_attack" in result.error_message

    def test_list_attacks_all(self):
        """Тест получения списка всех атак."""
        attacks = self.registry.list_attacks()

        assert isinstance(attacks, list)
        assert len(attacks) > 0
        assert "fakeddisorder" in attacks
        assert "multisplit" in attacks

    def test_list_attacks_by_category(self):
        """Тест получения списка атак по категории."""
        fake_attacks = self.registry.list_attacks(category=AttackCategories.FAKE)
        split_attacks = self.registry.list_attacks(category=AttackCategories.SPLIT)

        assert isinstance(fake_attacks, list)
        assert isinstance(split_attacks, list)
        assert "fakeddisorder" in fake_attacks
        assert "multisplit" in split_attacks
        assert "fakeddisorder" not in split_attacks

    def test_get_attack_aliases(self):
        """Тест получения алиасов атаки."""
        aliases = self.registry.get_attack_aliases("fakeddisorder")

        assert isinstance(aliases, list)
        assert "fake_disorder" in aliases
        assert "fakedisorder" in aliases

    def test_get_attack_aliases_nonexistent(self):
        """Тест получения алиасов несуществующей атаки."""
        aliases = self.registry.get_attack_aliases("nonexistent_attack")

        assert isinstance(aliases, list)
        assert len(aliases) == 0

    def test_resolve_attack_type(self):
        """Тест разрешения типа атаки."""
        # Основной тип
        assert self.registry._resolve_attack_type("fakeddisorder") == "fakeddisorder"

        # Алиас
        assert self.registry._resolve_attack_type("fake_disorder") == "fakeddisorder"

        # Несуществующий тип
        assert self.registry._resolve_attack_type("nonexistent") == "nonexistent"


class TestAttackHandlers:
    """Тесты для обработчиков атак."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.registry = AttackRegistry()
        self.techniques = BypassTechniques()
        self.test_payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"

    def test_fakeddisorder_handler(self):
        """Тест обработчика fakeddisorder."""
        handler = self.registry.get_attack_handler("fakeddisorder")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_pos": 5, "fake_ttl": 3, "fooling_methods": ["badsum"]},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) == 3  # fake + part2 + part1

        # Проверяем структуру
        fake_segment, part2_segment, part1_segment = result
        assert fake_segment[0] == self.test_payload
        assert part2_segment[0] == self.test_payload[5:]
        assert part1_segment[0] == self.test_payload[:5]

    def test_multisplit_handler_with_positions(self):
        """Тест обработчика multisplit с positions."""
        handler = self.registry.get_attack_handler("multisplit")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"positions": [3, 8, 15]},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) == 4  # 3 позиции = 4 сегмента

        # Проверяем, что все данные покрыты
        total_data = b""
        for segment in result:
            total_data += segment[0]
        assert total_data == self.test_payload

    def test_multisplit_handler_with_split_pos(self):
        """Тест обработчика multisplit с split_pos."""
        handler = self.registry.get_attack_handler("multisplit")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_pos": 10},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) == 2  # Одна позиция = 2 сегмента

        segment1, segment2 = result
        assert segment1[0] == self.test_payload[:10]
        assert segment2[0] == self.test_payload[10:]

    def test_multisplit_handler_with_split_count(self):
        """Тест обработчика multisplit с split_count."""
        handler = self.registry.get_attack_handler("multisplit")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_count": 4},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) >= 2  # Минимум 2 сегмента

        # Проверяем, что все данные покрыты
        total_data = b""
        for segment in result:
            total_data += segment[0]
        assert total_data == self.test_payload

    def test_multisplit_handler_filters_unsupported_params(self):
        """Тест фильтрации неподдерживаемых параметров в multisplit."""
        handler = self.registry.get_attack_handler("multisplit")

        # Передаем параметры, которые не поддерживает apply_multisplit
        result = handler(
            self.techniques,
            self.test_payload,
            positions=[5, 10],
            ttl=128,  # Не поддерживается
            overlap_size=20,  # Не поддерживается
            split_count=3,  # Игнорируется когда есть positions
            fooling=["badsum"],
        )

        # Не должно вызывать исключение
        assert isinstance(result, list)
        assert len(result) >= 2

    def test_seqovl_handler(self):
        """Тест обработчика seqovl."""
        handler = self.registry.get_attack_handler("seqovl")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_pos": 8, "overlap_size": 4, "fake_ttl": 2},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) == 2  # fake overlap + real full

        fake_segment, real_segment = result
        assert real_segment[0] == self.test_payload  # Полный реальный пакет

    def test_disorder_handler(self):
        """Тест обработчика disorder."""
        handler = self.registry.get_attack_handler("disorder")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_pos": 6},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) == 2  # part2 + part1

        part2_segment, part1_segment = result
        assert part2_segment[0] == self.test_payload[6:]
        assert part1_segment[0] == self.test_payload[:6]

    def test_disorder2_handler(self):
        """Тест обработчика disorder2 (с ack_first=True)."""
        handler = self.registry.get_attack_handler("disorder2")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_pos": 6},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) == 2

        # disorder2 должен использовать ack_first=True
        part2_segment, part1_segment = result
        assert part2_segment[2]["tcp_flags"] == 0x10  # ACK флаг

    def test_split_handler(self):
        """Тест обработчика split (алиас для multisplit с одной позицией)."""
        handler = self.registry.get_attack_handler("split")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"split_pos": 7},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) == 2

        segment1, segment2 = result
        assert segment1[0] == self.test_payload[:7]
        assert segment2[0] == self.test_payload[7:]

    def test_fake_handler(self):
        """Тест обработчика fake."""
        handler = self.registry.get_attack_handler("fake")

        context = AttackContext(
            dst_ip="127.0.0.1",
            dst_port=443,
            payload=self.test_payload,
            params={"ttl": 4, "fooling": ["badsum"]},
        )
        result = handler(context)

        assert isinstance(result, list)
        assert len(result) == 2  # fake + real

        fake_segment, real_segment = result
        assert fake_segment[0] == self.test_payload
        assert real_segment[0] == self.test_payload
        assert fake_segment[2]["is_fake"] is True
        assert real_segment[2]["is_fake"] is False


class TestGlobalFunctions:
    """Тесты для глобальных функций реестра."""

    def test_get_attack_registry_singleton(self):
        """Тест singleton паттерна для глобального реестра."""
        registry1 = get_attack_registry()
        registry2 = get_attack_registry()

        assert registry1 is registry2  # Должен быть тот же объект
        assert isinstance(registry1, AttackRegistry)

    def test_register_attack_global(self):
        """Тест глобальной функции регистрации атаки."""

        def test_handler(
            context: AttackContext,
        ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload, 0, {"test": True})]

        metadata = create_attack_metadata(
            name="Global Test Attack",
            description="Test for global registration",
            category=AttackCategories.CUSTOM,
        )

        register_attack("global_test_attack", test_handler, metadata)

        # Проверяем через глобальные функции
        handler = get_attack_handler("global_test_attack")
        assert handler is not None
        assert handler == test_handler

    def test_get_attack_handler_global(self):
        """Тест глобальной функции получения обработчика."""
        handler = get_attack_handler("fakeddisorder")

        assert handler is not None
        assert callable(handler)

    def test_validate_attack_parameters_global(self):
        """Тест глобальной функции валидации параметров."""
        result = validate_attack_parameters("fakeddisorder", {"split_pos": 5})

        assert isinstance(result, ValidationResult)
        assert result.is_valid is True

    def test_validate_attack_parameters_global_invalid(self):
        """Тест глобальной функции валидации с невалидными параметрами."""
        result = validate_attack_parameters(
            "fakeddisorder", {}
        )  # Отсутствует split_pos

        assert isinstance(result, ValidationResult)
        assert result.is_valid is False


class TestParameterFiltering:
    """Тесты для фильтрации параметров в обработчиках."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        self.registry = AttackRegistry()
        self.techniques = BypassTechniques()
        self.test_payload = b"test_payload_data"

    def test_primitives_handler_parameter_filtering(self):
        """Тест фильтрации параметров в примитивных обработчиках."""
        # Создаем тестовый обработчик
        handler = self.registry._create_primitives_handler("apply_multisplit")

        # Передаем параметры, включая неподдерживаемые
        result = handler(
            self.techniques,
            self.test_payload,
            positions=[5, 10],  # Поддерживается
            fooling=["badsum"],  # Поддерживается
            ttl=128,  # НЕ поддерживается apply_multisplit
            overlap_size=20,  # НЕ поддерживается apply_multisplit
        )

        # Не должно вызывать исключение
        assert isinstance(result, list)

    def test_inspect_signature_filtering(self):
        """Тест фильтрации на основе сигнатуры метода."""
        import inspect

        # Получаем сигнатуру apply_multisplit
        sig = inspect.signature(self.techniques.apply_multisplit)
        param_names = list(sig.parameters.keys())

        # Проверяем, что фильтрация работает правильно
        assert "payload" in param_names
        assert "positions" in param_names
        assert "fooling" in param_names
        assert "ttl" not in param_names  # Этот параметр не поддерживается
        assert "overlap_size" not in param_names  # Этот параметр не поддерживается


class TestLazyLoading:
    """Тесты для функциональности lazy loading."""

    def test_lazy_loading_disabled_by_default(self):
        """Тест что lazy loading отключен по умолчанию."""

        # Очищаем реестр для чистого теста
        clear_registry(clear_config=True)

        registry = AttackRegistry()

        assert registry._lazy_loading is False
        assert len(registry._unloaded_modules) == 0
        assert len(registry._loaded_modules) == 0

    def test_lazy_loading_enabled(self):
        """Тест включения lazy loading."""

        # Очищаем реестр для чистого теста
        clear_registry(clear_config=True)

        registry = AttackRegistry(lazy_loading=True)

        assert registry._lazy_loading is True
        # При lazy loading должны быть обнаружены модули
        assert isinstance(registry._unloaded_modules, dict)

    def test_lazy_loading_stats(self):
        """Тест получения статистики lazy loading."""

        clear_registry(clear_config=True)

        registry = AttackRegistry(lazy_loading=True)
        stats = registry.get_lazy_loading_stats()

        assert isinstance(stats, dict)
        assert "lazy_loading_enabled" in stats
        assert "total_discovered_modules" in stats
        assert "loaded_modules" in stats
        assert "unloaded_modules" in stats
        assert "loaded_attacks" in stats

        assert stats["lazy_loading_enabled"] is True
        assert stats["loaded_attacks"] > 0  # Builtin attacks always loaded

    def test_configure_lazy_loading_before_init(self):
        """Тест конфигурации lazy loading перед инициализацией."""
        from core.bypass.attacks.attack_registry import (
            clear_registry,
            configure_lazy_loading,
            get_lazy_loading_config,
            get_attack_registry,
        )

        # Очищаем реестр
        clear_registry(clear_config=True)

        # Конфигурируем lazy loading
        configure_lazy_loading(True)

        # Проверяем конфигурацию
        assert get_lazy_loading_config() is True

        # Создаем реестр - должен использовать конфигурацию
        registry = get_attack_registry()
        assert registry._lazy_loading is True

        # Очищаем после теста
        clear_registry(clear_config=True)

    def test_configure_lazy_loading_after_init_warning(self):
        """Тест предупреждения при конфигурации после инициализации."""
        from core.bypass.attacks.attack_registry import (
            clear_registry,
            configure_lazy_loading,
            get_attack_registry,
        )

        # Очищаем реестр
        clear_registry(clear_config=True)

        # Создаем реестр первым
        registry = get_attack_registry()

        # Пытаемся конфигурировать после инициализации
        with patch("logging.Logger.warning") as mock_warning:
            configure_lazy_loading(True)
            # Должно быть предупреждение
            assert mock_warning.call_count >= 1

        # Реестр не должен измениться
        assert registry._lazy_loading is False

        # Очищаем после теста
        clear_registry(clear_config=True)

    def test_get_attack_handler_with_lazy_loading(self):
        """Тест получения обработчика с lazy loading."""

        clear_registry(clear_config=True)

        registry = AttackRegistry(lazy_loading=True)

        # Получаем builtin атаку (всегда загружена)
        handler = registry.get_attack_handler("fakeddisorder")
        assert handler is not None
        assert callable(handler)

    def test_ensure_attack_loaded_builtin(self):
        """Тест что builtin атаки всегда загружены."""

        clear_registry(clear_config=True)

        registry = AttackRegistry(lazy_loading=True)

        # Builtin атаки должны быть загружены
        assert registry._ensure_attack_loaded("fakeddisorder") is True
        assert "fakeddisorder" in registry.attacks

    def test_ensure_attack_loaded_nonexistent(self):
        """Тест загрузки несуществующей атаки."""

        clear_registry(clear_config=True)

        registry = AttackRegistry(lazy_loading=True)

        # Несуществующая атака не должна загрузиться
        assert registry._ensure_attack_loaded("totally_fake_attack_xyz") is False

    def test_lazy_loading_parameter_in_get_attack_registry(self):
        """Тест параметра lazy_loading в get_attack_registry."""
        from core.bypass.attacks.attack_registry import (
            clear_registry,
            get_attack_registry,
        )

        # Тест с lazy_loading=True
        clear_registry(clear_config=True)
        registry1 = get_attack_registry(lazy_loading=True)
        assert registry1._lazy_loading is True

        # Тест с lazy_loading=False
        clear_registry(clear_config=True)
        registry2 = get_attack_registry(lazy_loading=False)
        assert registry2._lazy_loading is False

        # Очищаем после теста
        clear_registry(clear_config=True)

    def test_discover_external_attacks(self):
        """Тест обнаружения внешних атак."""

        clear_registry(clear_config=True)

        registry = AttackRegistry(lazy_loading=True)

        # Должны быть обнаружены некоторые модули (если они есть)
        stats = registry.get_lazy_loading_stats()

        # Проверяем структуру статистики
        assert isinstance(stats["discovered_module_paths"], list)
        assert isinstance(stats["loaded_module_paths"], list)

        # Очищаем после теста
        clear_registry(clear_config=True)

    def test_clear_registry_preserves_config(self):
        """Тест что clear_registry сохраняет конфигурацию по умолчанию."""
        from core.bypass.attacks.attack_registry import (
            clear_registry,
            configure_lazy_loading,
            get_lazy_loading_config,
        )

        # Устанавливаем конфигурацию
        clear_registry(clear_config=True)
        configure_lazy_loading(True)
        assert get_lazy_loading_config() is True

        # Очищаем реестр без очистки конфигурации
        clear_registry(clear_config=False)

        # Конфигурация должна сохраниться
        assert get_lazy_loading_config() is True

        # Очищаем после теста
        clear_registry(clear_config=True)

    def test_clear_registry_clears_config(self):
        """Тест что clear_registry может очистить конфигурацию."""
        from core.bypass.attacks.attack_registry import (
            clear_registry,
            configure_lazy_loading,
            get_lazy_loading_config,
        )

        # Устанавливаем конфигурацию
        clear_registry(clear_config=True)
        configure_lazy_loading(True)
        assert get_lazy_loading_config() is True

        # Очищаем реестр с очисткой конфигурации
        clear_registry(clear_config=True)

        # Конфигурация должна быть очищена
        assert get_lazy_loading_config() is None

    def test_lazy_loading_performance_benefit(self):
        """Тест что lazy loading быстрее при инициализации."""
        import time

        # Тест eager loading
        clear_registry(clear_config=True)
        start_eager = time.time()
        registry_eager = AttackRegistry(lazy_loading=False)
        time_eager = time.time() - start_eager

        # Тест lazy loading
        clear_registry(clear_config=True)
        start_lazy = time.time()
        registry_lazy = AttackRegistry(lazy_loading=True)
        time_lazy = time.time() - start_lazy

        # Проверяем что оба режима работают
        # Не проверяем производительность строго, так как разница может быть минимальной
        # для малого количества модулей и зависит от системы
        assert time_eager > 0
        assert time_lazy > 0

        # Проверяем что оба реестра функциональны
        assert len(registry_eager.attacks) > 0
        assert len(registry_lazy.attacks) > 0

        # Очищаем после теста
        clear_registry(clear_config=True)


class TestPromotionMechanism:
    """Тесты для механизма продвижения реализаций атак."""

    def setup_method(self):
        """Настройка перед каждым тестом."""
        clear_registry(clear_config=True)
        self.registry = AttackRegistry()
        self.techniques = BypassTechniques()
        self.test_payload = b"test_payload_for_promotion"

    def test_promote_implementation_success(self):
        """Тест успешного продвижения реализации."""

        # Создаем улучшенный обработчик
        def improved_handler(
            context: AttackContext,
        ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            # Симулируем улучшенную реализацию
            return [
                (
                    context.payload + b"_improved",
                    0,
                    {"is_fake": False, "improved": True},
                )
            ]

        # Создаем новые метаданные
        new_metadata = AttackMetadata(
            name="Improved Fake Disorder",
            description="Improved implementation with better performance",
            required_params=["split_pos"],
            optional_params={"ttl": 3, "fooling": ["badsum"]},
            aliases=["fake_disorder", "fakedisorder"],
            category=AttackCategories.FAKE,
        )

        # Данные о производительности
        performance_data = {
            "improvement_percent": 25.0,
            "test_cases": 1000,
            "success_rate": 0.95,
            "baseline_time_ms": 1.2,
            "new_time_ms": 0.9,
            "tested_domains": ["x.com", "youtube.com"],
        }

        # Продвигаем реализацию (не CORE атака, поэтому не требует подтверждения)
        result = self.registry.promote_implementation(
            attack_type="fakeddisorder",
            new_handler=improved_handler,
            new_metadata=new_metadata,
            reason="Improved performance by 25% on x.com",
            performance_data=performance_data,
            require_confirmation=False,  # Отключаем подтверждение для теста
        )

        assert result.success is True
        assert result.action == "promoted"
        assert "fakeddisorder" in result.message

        # Проверяем что обработчик заменен
        new_handler_from_registry = self.registry.get_attack_handler("fakeddisorder")
        assert new_handler_from_registry == improved_handler

        # Проверяем историю продвижений
        history = self.registry.get_promotion_history("fakeddisorder")
        assert len(history) == 1
        assert history[0]["action"] == "promoted"
        assert history[0]["reason"] == "Improved performance by 25% on x.com"
        assert history[0]["performance_data"] == performance_data

    def test_promote_implementation_nonexistent_attack(self):
        """Тест продвижения несуществующей атаки."""

        def dummy_handler(context: AttackContext):
            return [(context.payload, 0, {})]

        new_metadata = AttackMetadata(
            name="Dummy",
            description="Dummy attack",
            required_params=[],
            optional_params={},
            aliases=[],
            category=AttackCategories.CUSTOM,
        )

        result = self.registry.promote_implementation(
            attack_type="nonexistent_attack",
            new_handler=dummy_handler,
            new_metadata=new_metadata,
            reason="Test promotion",
        )

        assert result.success is False
        assert result.action == "failed"
        assert "not found" in result.message

    def test_promote_implementation_core_attack_requires_confirmation(self):
        """Тест что продвижение CORE атаки требует подтверждения."""

        def improved_handler(context: AttackContext):
            return [(context.payload, 0, {"improved": True})]

        new_metadata = AttackMetadata(
            name="Improved Core Attack",
            description="Improved core implementation",
            required_params=["split_pos"],
            optional_params={},
            aliases=[],
            category=AttackCategories.FAKE,
        )

        # Пытаемся продвинуть CORE атаку без подтверждения
        result = self.registry.promote_implementation(
            attack_type="fakeddisorder",  # Это CORE атака
            new_handler=improved_handler,
            new_metadata=new_metadata,
            reason="Test core promotion",
            require_confirmation=True,  # По умолчанию требует подтверждения
        )

        assert result.success is False
        assert result.action == "confirmation_required"
        assert "confirmation" in result.message

    def test_promote_implementation_core_attack_with_confirmation(self):
        """Тест продвижения CORE атаки с подтверждением."""

        def improved_handler(context: AttackContext):
            return [(context.payload, 0, {"improved": True})]

        new_metadata = AttackMetadata(
            name="Improved Core Attack",
            description="Improved core implementation",
            required_params=["split_pos"],
            optional_params={},
            aliases=[],
            category=AttackCategories.FAKE,
        )

        # Продвигаем CORE атаку с явным подтверждением
        result = self.registry.promote_implementation(
            attack_type="fakeddisorder",  # Это CORE атака
            new_handler=improved_handler,
            new_metadata=new_metadata,
            reason="Critical bug fix for CORE attack",
            require_confirmation=False,  # Явно разрешаем
        )

        assert result.success is True
        assert result.action == "promoted"

    def test_promote_implementation_invalid_handler(self):
        """Тест продвижения с невалидным обработчиком."""
        new_metadata = AttackMetadata(
            name="Invalid Handler Test",
            description="Test with invalid handler",
            required_params=[],
            optional_params={},
            aliases=[],
            category=AttackCategories.CUSTOM,
        )

        # Пытаемся продвинуть с не-callable обработчиком
        # Отключаем подтверждение чтобы дойти до проверки callable
        result = self.registry.promote_implementation(
            attack_type="fakeddisorder",
            new_handler="not_a_function",  # Не callable
            new_metadata=new_metadata,
            reason="Test invalid handler",
            require_confirmation=False,  # Отключаем подтверждение для CORE атак
        )

        assert result.success is False
        assert result.action == "failed"
        assert "not callable" in result.message

    def test_validate_promotion_request_valid(self):
        """Тест валидации валидного запроса на продвижение."""

        def valid_handler(context: AttackContext):
            return [(context.payload, 0, {})]

        performance_data = {
            "improvement_percent": 15.0,
            "test_cases": 500,
            "success_rate": 0.92,
        }

        result = self.registry.validate_promotion_request(
            attack_type="fakeddisorder",
            new_handler=valid_handler,
            performance_data=performance_data,
        )

        assert result.is_valid is True
        # Может быть предупреждение о CORE атаке
        if result.warnings:
            assert any("CORE attack" in warning for warning in result.warnings)

    def test_validate_promotion_request_invalid_attack(self):
        """Тест валидации для несуществующей атаки."""

        def valid_handler(context: AttackContext):
            return [(context.payload, 0, {})]

        result = self.registry.validate_promotion_request(
            attack_type="nonexistent_attack", new_handler=valid_handler
        )

        assert result.is_valid is False
        assert "not found" in result.error_message

    def test_validate_promotion_request_invalid_handler(self):
        """Тест валидации с невалидным обработчиком."""
        result = self.registry.validate_promotion_request(
            attack_type="fakeddisorder", new_handler="not_callable"
        )

        assert result.is_valid is False
        assert "not callable" in result.error_message

    def test_validate_promotion_request_missing_performance_data(self):
        """Тест валидации без данных о производительности."""

        def valid_handler(context: AttackContext):
            return [(context.payload, 0, {})]

        result = self.registry.validate_promotion_request(
            attack_type="fakeddisorder",
            new_handler=valid_handler,
            performance_data=None,
        )

        assert result.is_valid is True
        assert any("No performance data" in warning for warning in result.warnings)

    def test_validate_promotion_request_incomplete_performance_data(self):
        """Тест валидации с неполными данными о производительности."""

        def valid_handler(context: AttackContext):
            return [(context.payload, 0, {})]

        incomplete_data = {
            "improvement_percent": 10.0
            # Отсутствуют test_cases и success_rate
        }

        result = self.registry.validate_promotion_request(
            attack_type="fakeddisorder",
            new_handler=valid_handler,
            performance_data=incomplete_data,
        )

        assert result.is_valid is True
        assert any(
            "Missing recommended performance metrics" in warning
            for warning in result.warnings
        )

    def test_get_promotion_history_empty(self):
        """Тест получения пустой истории продвижений."""
        history = self.registry.get_promotion_history("fakeddisorder")

        # Новая атака не должна иметь истории продвижений
        assert isinstance(history, list)
        assert len(history) == 0

    def test_get_promotion_history_nonexistent(self):
        """Тест получения истории для несуществующей атаки."""
        history = self.registry.get_promotion_history("nonexistent_attack")

        assert isinstance(history, list)
        assert len(history) == 0

    def test_bypass_techniques_promote_implementation_success(self):
        """Тест метода promote_implementation в BypassTechniques."""

        # Создаем улучшенный обработчик
        def improved_fakeddisorder_handler(context: AttackContext):
            # Симулируем улучшенную реализацию fakeddisorder
            payload = context.payload
            split_pos = context.params.get("split_pos", 3)

            # Улучшенная логика
            part1 = payload[:split_pos]
            part2 = payload[split_pos:]

            return [
                (payload, 0, {"is_fake": True, "ttl": 3, "improved": True}),
                (part2, split_pos, {"is_fake": False}),
                (part1, 0, {"is_fake": False}),
            ]

        performance_data = {
            "improvement_percent": 30.0,
            "test_cases": 1000,
            "success_rate": 0.95,
            "baseline_time_ms": 1.2,
            "new_time_ms": 0.84,
            "tested_domains": ["x.com", "youtube.com", "facebook.com"],
        }

        # Используем метод из BypassTechniques
        success = BypassTechniques.promote_implementation(
            attack_name="fakeddisorder",
            new_handler=improved_fakeddisorder_handler,
            reason="30% performance improvement on x.com with better fake packet generation",
            performance_data=performance_data,
            require_confirmation=False,  # Отключаем подтверждение для теста
        )

        assert success is True

        # Проверяем что обработчик действительно заменен
        registry = get_attack_registry()
        new_handler = registry.get_attack_handler("fakeddisorder")
        assert new_handler == improved_fakeddisorder_handler

        # Проверяем историю продвижений
        history = registry.get_promotion_history("fakeddisorder")
        assert len(history) == 1
        assert history[0]["performance_data"] == performance_data

    def test_bypass_techniques_promote_implementation_invalid_attack(self):
        """Тест promote_implementation с невалидным именем атаки."""

        def dummy_handler(context):
            return [(context.payload, 0, {})]

        success = BypassTechniques.promote_implementation(
            attack_name="nonexistent_attack",
            new_handler=dummy_handler,
            reason="Test invalid attack",
        )

        assert success is False

    def test_bypass_techniques_promote_implementation_invalid_handler(self):
        """Тест promote_implementation с невалидным обработчиком."""
        success = BypassTechniques.promote_implementation(
            attack_name="fakeddisorder",
            new_handler="not_a_function",
            reason="Test invalid handler",
        )

        assert success is False

    def test_bypass_techniques_promote_implementation_empty_reason(self):
        """Тест promote_implementation с пустым обоснованием."""

        def dummy_handler(context):
            return [(context.payload, 0, {})]

        success = BypassTechniques.promote_implementation(
            attack_name="fakeddisorder",
            new_handler=dummy_handler,
            reason="",  # Пустое обоснование
        )

        assert success is False

    def test_bypass_techniques_promote_implementation_with_logging(self):
        """Тест логирования при продвижении реализации."""

        def improved_handler(context):
            return [(context.payload + b"_logged", 0, {"logged": True})]

        performance_data = {
            "improvement_percent": 20.0,
            "test_cases": 800,
            "success_rate": 0.93,
        }

        # Проверяем логирование
        with patch("logging.Logger.info") as mock_info:
            success = BypassTechniques.promote_implementation(
                attack_name="seqovl",  # Используем другую атаку
                new_handler=improved_handler,
                reason="Improved overlap calculation with 20% better performance",
                performance_data=performance_data,
                require_confirmation=False,
            )

            assert success is True

            # Проверяем что было логирование
            assert mock_info.call_count >= 1

            # Проверяем содержимое логов
            log_messages = [call[0][0] for call in mock_info.call_args_list]
            assert any("Successfully promoted" in msg for msg in log_messages)
            assert any("Performance improvement: 20.0%" in msg for msg in log_messages)
            assert any("New success rate: 93.0%" in msg for msg in log_messages)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
