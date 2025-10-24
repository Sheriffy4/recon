"""
Тесты для проверки исправленных ошибок.
Эти тесты должны предотвратить повторение критических ошибок.
"""

import pytest
from core.bypass.attacks.tcp.fakeddisorder_attack import (
    FakedDisorderAttack,
    FakedDisorderConfig,
)
from core.bypass.attacks.base import AttackContext, AttackStatus
from core.bypass.attacks.attack_registry import get_attack_registry
from core.unified_strategy_loader import UnifiedStrategyLoader


class TestFoolingMethodFixes:
    """Тесты для проверки исправлений fooling методов."""

    def test_split_default_fooling_not_none(self):
        """Проверяет что split атака имеет дефолтный fooling не None."""
        registry = get_attack_registry()
        attack_metadata = registry.get_attack_metadata("split")

        assert attack_metadata is not None, "Split attack должна быть зарегистрирована"
        assert (
            "fooling" in attack_metadata.optional_params
        ), "Split должна иметь fooling параметр"

        fooling = attack_metadata.optional_params["fooling"]
        assert fooling is not None, "Fooling не должен быть None"
        assert fooling != "None", "Fooling не должен быть строкой 'None'"
        assert isinstance(fooling, list), "Fooling должен быть списком"
        assert len(fooling) > 0, "Fooling список не должен быть пустым"
        assert "badsum" in fooling, "Fooling должен содержать 'badsum'"

    def test_multisplit_default_fooling_not_none(self):
        """Проверяет что multisplit атака имеет дефолтный fooling не None."""
        registry = get_attack_registry()
        attack_metadata = registry.get_attack_metadata("multisplit")

        assert (
            attack_metadata is not None
        ), "Multisplit attack должна быть зарегистрирована"
        assert (
            "fooling" in attack_metadata.optional_params
        ), "Multisplit должна иметь fooling параметр"

        fooling = attack_metadata.optional_params["fooling"]
        assert fooling is not None, "Fooling не должен быть None"
        assert fooling != "None", "Fooling не должен быть строкой 'None'"
        assert isinstance(fooling, list), "Fooling должен быть списком"
        assert len(fooling) > 0, "Fooling список не должен быть пустым"

    def test_md5sig_is_valid_fooling_method(self):
        """Проверяет что md5sig является валидным fooling методом."""
        from core.bypass.attacks.metadata import FoolingMethods

        assert (
            "md5sig" in FoolingMethods.ALL
        ), "md5sig должен быть в списке валидных методов"
        assert FoolingMethods.is_valid_method(
            "md5sig"
        ), "md5sig должен проходить валидацию"

    def test_none_string_filtered_in_loader(self):
        """Проверяет что строка 'None' фильтруется в unified_strategy_loader."""
        loader = UnifiedStrategyLoader()

        # Тест с fooling='None'
        params = {"fooling": "None"}
        normalized = loader._normalize_params(params)

        # fooling должен быть удален или не содержать 'None'
        if "fooling" in normalized:
            assert (
                "None" not in normalized["fooling"]
            ), "Строка 'None' не должна быть в fooling"
            assert (
                "none" not in normalized["fooling"]
            ), "Строка 'none' не должна быть в fooling"


class TestSpecialPositionHandling:
    """Тесты для проверки обработки специальных позиций (sni, cipher, midsld)."""

    @pytest.mark.asyncio
    async def test_sni_position_handling_in_fakeddisorder(self):
        """Проверяет что split_pos='sni' правильно обрабатывается."""
        config = FakedDisorderConfig(
            split_pos="sni",
            split_seqovl=0,
            ttl=3,
            autottl=None,
            fooling_methods=["badsum"],
        )

        attack = FakedDisorderAttack(config)

        # Создаем тестовый контекст
        payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n" * 10
        context = AttackContext(
            payload=payload,
            dst_ip="1.1.1.1",
            dst_port=443,
            src_ip="192.168.1.1",
            src_port=12345,
        )

        # Выполняем атаку - не должно быть ошибки сравнения int и str
        result = await attack.execute(context)

        # Проверяем что нет ошибки типа
        assert (
            result.status != AttackStatus.ERROR
            or "not supported between" not in result.error_message
        )

    @pytest.mark.asyncio
    async def test_cipher_position_handling_in_fakeddisorder(self):
        """Проверяет что split_pos='cipher' правильно обрабатывается."""
        config = FakedDisorderConfig(
            split_pos="cipher",
            split_seqovl=0,
            ttl=3,
            autottl=None,
            fooling_methods=["badsum"],
        )

        attack = FakedDisorderAttack(config)

        payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n" * 10
        context = AttackContext(
            payload=payload,
            connection_id="test:443",
            src_addr="192.168.1.1",
            dst_addr="1.1.1.1",
            src_port=12345,
            dst_port=443,
        )

        result = await attack.execute(context)

        # Не должно быть ошибки сравнения типов
        assert (
            result.status != AttackStatus.ERROR
            or "not supported between" not in result.error_message
        )

    @pytest.mark.asyncio
    async def test_multisplit_with_string_positions(self):
        """Проверяет что multisplit правильно обрабатывает строковые позиции."""
        attack = TCPMultiSplitAttack()

        payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n" * 10
        context = AttackContext(
            payload=payload,
            connection_id="test:443",
            src_addr="192.168.1.1",
            dst_addr="1.1.1.1",
            src_port=12345,
            dst_port=443,
            params={"fooling": ["badsum"]},
        )

        # Тест с числовыми строками
        positions = ["10", "20", "30"]
        result = await attack._execute_with_positions(context, positions)

        # Не должно быть ошибки сравнения типов
        assert (
            result.status != AttackStatus.ERROR
            or "not supported between" not in result.error_message
        )

    @pytest.mark.asyncio
    async def test_multisplit_with_special_positions(self):
        """Проверяет что multisplit игнорирует специальные позиции."""
        attack = TCPMultiSplitAttack()

        payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n" * 10
        context = AttackContext(
            payload=payload,
            connection_id="test:443",
            src_addr="192.168.1.1",
            dst_addr="1.1.1.1",
            src_port=12345,
            dst_port=443,
            params={"fooling": ["badsum"]},
        )

        # Тест со специальными позициями - должны быть проигнорированы
        positions = ["sni", "cipher", 10, 20]
        result = await attack._execute_with_positions(context, positions)

        # Не должно быть ошибки
        assert (
            result.status != AttackStatus.ERROR
            or "not supported between" not in result.error_message
        )


class TestSeqovlOverlapHandling:
    """Тесты для проверки обработки overlap в seqovl атаках."""

    @pytest.mark.asyncio
    async def test_seqovl_with_string_split_seqovl(self):
        """Проверяет что split_seqovl правильно конвертируется из строки."""
        config = FakedDisorderConfig(
            split_pos=10,
            split_seqovl="20",  # Строка вместо числа
            ttl=3,
            autottl=None,
            fooling_methods=["badsum"],
        )

        attack = FakedDisorderAttack(config)

        payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n" * 10
        context = AttackContext(
            payload=payload,
            connection_id="test:443",
            src_addr="192.168.1.1",
            dst_addr="1.1.1.1",
            src_port=12345,
            dst_port=443,
        )

        result = await attack.execute(context)

        # Не должно быть ошибки сравнения типов
        assert (
            result.status != AttackStatus.ERROR
            or "not supported between" not in result.error_message
        )


class TestRegistryMethods:
    """Тесты для проверки методов AttackRegistry."""

    def test_get_attack_registry_returns_instance(self):
        """Проверяет что get_attack_registry возвращает экземпляр."""
        registry = get_attack_registry()

        assert registry is not None, "Registry не должен быть None"
        assert hasattr(
            registry, "list_attacks"
        ), "Registry должен иметь метод list_attacks"
        assert hasattr(
            registry, "get_attack_metadata"
        ), "Registry должен иметь метод get_attack_metadata"

    def test_list_attacks_returns_list(self):
        """Проверяет что list_attacks возвращает список."""
        registry = get_attack_registry()
        attacks = registry.list_attacks()

        assert isinstance(attacks, list), "list_attacks должен возвращать список"
        assert len(attacks) > 0, "Должна быть хотя бы одна зарегистрированная атака"

    def test_get_attack_metadata_works(self):
        """Проверяет что get_attack_metadata работает."""
        registry = get_attack_registry()

        # Проверяем известные атаки
        for attack_name in ["split", "fake", "disorder", "multisplit"]:
            attack_metadata = registry.get_attack_metadata(attack_name)
            assert (
                attack_metadata is not None
            ), f"Атака {attack_name} должна быть зарегистрирована"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
