"""
Упрощенные тесты для проверки исправленных ошибок.
"""

import pytest
from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.attacks.metadata import FoolingMethods
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
        print(f"[OK] Split fooling: {fooling}")

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
        print(f"✅ Multisplit fooling: {fooling}")

    def test_md5sig_is_valid_fooling_method(self):
        """Проверяет что md5sig является валидным fooling методом."""
        assert (
            "md5sig" in FoolingMethods.ALL
        ), "md5sig должен быть в списке валидных методов"
        assert FoolingMethods.is_valid_method(
            "md5sig"
        ), "md5sig должен проходить валидацию"
        print(f"✅ md5sig is valid, all methods: {FoolingMethods.ALL}")

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
            print(f"✅ Normalized fooling: {normalized.get('fooling')}")
        else:
            print("✅ fooling был удален (правильно)")


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
        print("✅ Registry имеет все необходимые методы")

    def test_list_attacks_returns_list(self):
        """Проверяет что list_attacks возвращает список."""
        registry = get_attack_registry()
        attacks = registry.list_attacks()

        assert isinstance(attacks, list), "list_attacks должен возвращать список"
        assert len(attacks) > 0, "Должна быть хотя бы одна зарегистрированная атака"
        print(f"✅ Зарегистрировано {len(attacks)} атак")

    def test_get_attack_metadata_works(self):
        """Проверяет что get_attack_metadata работает."""
        registry = get_attack_registry()

        # Проверяем известные атаки
        for attack_name in ["split", "fake", "disorder", "multisplit"]:
            attack_metadata = registry.get_attack_metadata(attack_name)
            assert (
                attack_metadata is not None
            ), f"Атака {attack_name} должна быть зарегистрирована"

        print("✅ Все базовые атаки зарегистрированы")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
