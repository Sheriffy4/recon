"""
Тесты для классов метаданных атак.
"""

import pytest

from core.bypass.attacks.metadata import (
    AttackMetadata,
    AttackCategories,
    ValidationResult,
    AttackExecutionContext,
    AttackParameterTypes,
    SpecialParameterValues,
    FoolingMethods,
    create_attack_metadata,
)


class TestAttackMetadata:
    """Тесты для класса AttackMetadata."""

    def test_valid_metadata_creation(self):
        """Тест создания валидных метаданных."""
        metadata = AttackMetadata(
            name="Test Attack",
            description="Test attack description",
            required_params=["param1", "param2"],
            optional_params={"opt1": "default1", "opt2": 42},
            aliases=["alias1", "alias2"],
            category=AttackCategories.SPLIT,
        )

        assert metadata.name == "Test Attack"
        assert metadata.description == "Test attack description"
        assert metadata.required_params == ["param1", "param2"]
        assert metadata.optional_params == {"opt1": "default1", "opt2": 42}
        assert metadata.aliases == ["alias1", "alias2"]
        assert metadata.category == AttackCategories.SPLIT

    def test_empty_name_validation(self):
        """Тест валидации пустого имени."""
        with pytest.raises(ValueError, match="Attack name cannot be empty"):
            AttackMetadata(
                name="",
                description="Test description",
                required_params=[],
                optional_params={},
                aliases=[],
                category=AttackCategories.SPLIT,
            )

    def test_empty_description_validation(self):
        """Тест валидации пустого описания."""
        with pytest.raises(ValueError, match="Attack description cannot be empty"):
            AttackMetadata(
                name="Test Attack",
                description="",
                required_params=[],
                optional_params={},
                aliases=[],
                category=AttackCategories.SPLIT,
            )

    def test_invalid_required_params_type(self):
        """Тест валидации неправильного типа required_params."""
        with pytest.raises(ValueError, match="required_params must be a list"):
            AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params="not_a_list",
                optional_params={},
                aliases=[],
                category=AttackCategories.SPLIT,
            )

    def test_invalid_optional_params_type(self):
        """Тест валидации неправильного типа optional_params."""
        with pytest.raises(ValueError, match="optional_params must be a dict"):
            AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params=[],
                optional_params="not_a_dict",
                aliases=[],
                category=AttackCategories.SPLIT,
            )

    def test_invalid_aliases_type(self):
        """Тест валидации неправильного типа aliases."""
        with pytest.raises(ValueError, match="aliases must be a list"):
            AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params=[],
                optional_params={},
                aliases="not_a_list",
                category=AttackCategories.SPLIT,
            )

    def test_invalid_category(self):
        """Тест валидации неправильной категории."""
        with pytest.raises(ValueError, match="Invalid category"):
            AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params=[],
                optional_params={},
                aliases=[],
                category="invalid_category",
            )

    def test_valid_categories(self):
        """Тест всех валидных категорий."""
        for category in AttackCategories.ALL:
            metadata = AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params=[],
                optional_params={},
                aliases=[],
                category=category,
            )
            assert metadata.category == category


class TestAttackCategories:
    """Тесты для класса AttackCategories."""

    def test_all_categories_defined(self):
        """Тест определения всех категорий."""
        expected_categories = [
            AttackCategories.SPLIT,
            AttackCategories.DISORDER,
            AttackCategories.FAKE,
            AttackCategories.RACE,
            AttackCategories.OVERLAP,
            AttackCategories.FRAGMENT,
            AttackCategories.TIMING,
            AttackCategories.CUSTOM,
            AttackCategories.DNS,  # Добавлена новая категория
        ]

        assert AttackCategories.ALL == expected_categories

    def test_category_values(self):
        """Тест значений категорий."""
        assert AttackCategories.SPLIT == "split"
        assert AttackCategories.DISORDER == "disorder"
        assert AttackCategories.FAKE == "fake"
        assert AttackCategories.RACE == "race"
        assert AttackCategories.OVERLAP == "overlap"
        assert AttackCategories.FRAGMENT == "fragment"
        assert AttackCategories.TIMING == "timing"
        assert AttackCategories.CUSTOM == "custom"

    def test_all_categories_unique(self):
        """Тест уникальности всех категорий."""
        categories = AttackCategories.ALL
        assert len(categories) == len(set(categories))


class TestValidationResult:
    """Тесты для класса ValidationResult."""

    def test_valid_result_creation(self):
        """Тест создания валидного результата."""
        result = ValidationResult(is_valid=True)

        assert result.is_valid is True
        assert result.error_message is None
        assert result.warnings == []
        assert result.has_warnings() is False

    def test_invalid_result_creation(self):
        """Тест создания невалидного результата."""
        result = ValidationResult(is_valid=False, error_message="Test error message")

        assert result.is_valid is False
        assert result.error_message == "Test error message"
        assert result.warnings == []

    def test_result_with_warnings(self):
        """Тест результата с предупреждениями."""
        result = ValidationResult(is_valid=True, warnings=["Warning 1", "Warning 2"])

        assert result.is_valid is True
        assert result.has_warnings() is True
        assert len(result.warnings) == 2
        assert "Warning 1" in result.warnings
        assert "Warning 2" in result.warnings

    def test_add_warning(self):
        """Тест добавления предупреждения."""
        result = ValidationResult(is_valid=True)

        assert result.has_warnings() is False

        result.add_warning("Test warning")

        assert result.has_warnings() is True
        assert len(result.warnings) == 1
        assert result.warnings[0] == "Test warning"

    def test_add_multiple_warnings(self):
        """Тест добавления нескольких предупреждений."""
        result = ValidationResult(is_valid=True)

        result.add_warning("Warning 1")
        result.add_warning("Warning 2")
        result.add_warning("Warning 3")

        assert result.has_warnings() is True
        assert len(result.warnings) == 3
        assert result.warnings == ["Warning 1", "Warning 2", "Warning 3"]

    def test_warnings_initialization(self):
        """Тест инициализации warnings как None."""
        result = ValidationResult(is_valid=True, warnings=None)

        # После __post_init__ warnings должен быть пустым списком
        assert result.warnings == []
        assert result.has_warnings() is False


class TestAttackExecutionContext:
    """Тесты для класса AttackExecutionContext."""

    def test_basic_context_creation(self):
        """Тест создания базового контекста."""
        packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "8.8.8.8",
            "src_port": 12345,
            "dst_port": 443,
        }

        context = AttackExecutionContext(packet_info=packet_info)

        assert context.packet_info == packet_info
        assert context.connection_info is None
        assert context.strategy_context is None
        assert context.execution_id is None

    def test_full_context_creation(self):
        """Тест создания полного контекста."""
        packet_info = {"src_addr": "192.168.1.1"}
        connection_info = {"connection_id": "conn_123"}
        strategy_context = {"strategy": "multisplit"}
        execution_id = "exec_456"

        context = AttackExecutionContext(
            packet_info=packet_info,
            connection_info=connection_info,
            strategy_context=strategy_context,
            execution_id=execution_id,
        )

        assert context.packet_info == packet_info
        assert context.connection_info == connection_info
        assert context.strategy_context == strategy_context
        assert context.execution_id == execution_id


class TestSpecialParameterValues:
    """Тесты для класса SpecialParameterValues."""

    def test_special_values_defined(self):
        """Тест определения специальных значений."""
        assert SpecialParameterValues.CIPHER == "cipher"
        assert SpecialParameterValues.SNI == "sni"
        assert SpecialParameterValues.MIDSLD == "midsld"

    def test_all_special_values(self):
        """Тест списка всех специальных значений."""
        expected_values = [
            SpecialParameterValues.CIPHER,
            SpecialParameterValues.SNI,
            SpecialParameterValues.MIDSLD,
        ]

        assert SpecialParameterValues.ALL == expected_values

    def test_is_special_value_valid(self):
        """Тест проверки валидных специальных значений."""
        assert SpecialParameterValues.is_special_value("cipher") is True
        assert SpecialParameterValues.is_special_value("sni") is True
        assert SpecialParameterValues.is_special_value("midsld") is True

    def test_is_special_value_invalid(self):
        """Тест проверки невалидных специальных значений."""
        assert SpecialParameterValues.is_special_value("invalid") is False
        assert SpecialParameterValues.is_special_value("") is False
        assert (
            SpecialParameterValues.is_special_value("CIPHER") is False
        )  # Case sensitive


class TestFoolingMethods:
    """Тесты для класса FoolingMethods."""

    def test_fooling_methods_defined(self):
        """Тест определения методов обмана."""
        assert FoolingMethods.BADSUM == "badsum"
        assert FoolingMethods.BADSEQ == "badseq"
        assert FoolingMethods.BADACK == "badack"
        assert FoolingMethods.DATANOACK == "datanoack"
        assert FoolingMethods.HOPBYHOP == "hopbyhop"

    def test_all_fooling_methods(self):
        """Тест списка всех методов обмана."""
        expected_methods = [
            FoolingMethods.BADSUM,
            FoolingMethods.BADSEQ,
            FoolingMethods.BADACK,
            FoolingMethods.DATANOACK,
            FoolingMethods.HOPBYHOP,
        ]

        assert FoolingMethods.ALL == expected_methods

    def test_is_valid_method_valid(self):
        """Тест проверки валидных методов обмана."""
        for method in FoolingMethods.ALL:
            assert FoolingMethods.is_valid_method(method) is True

    def test_is_valid_method_invalid(self):
        """Тест проверки невалидных методов обмана."""
        assert FoolingMethods.is_valid_method("invalid_method") is False
        assert FoolingMethods.is_valid_method("") is False
        assert FoolingMethods.is_valid_method("BADSUM") is False  # Case sensitive


class TestAttackParameterTypes:
    """Тесты для класса AttackParameterTypes."""

    def test_parameter_types_defined(self):
        """Тест определения типов параметров."""
        assert AttackParameterTypes.SPLIT_POSITION == "split_position"
        assert AttackParameterTypes.POSITIONS_LIST == "positions_list"
        assert AttackParameterTypes.TTL_VALUE == "ttl_value"
        assert AttackParameterTypes.OVERLAP_SIZE == "overlap_size"
        assert AttackParameterTypes.FOOLING_METHODS == "fooling_methods"
        assert AttackParameterTypes.BOOLEAN_FLAG == "boolean_flag"
        assert AttackParameterTypes.CUSTOM_DATA == "custom_data"


class TestCreateAttackMetadata:
    """Тесты для фабричной функции create_attack_metadata."""

    def test_create_minimal_metadata(self):
        """Тест создания минимальных метаданных."""
        metadata = create_attack_metadata(
            name="Test Attack",
            description="Test description",
            category=AttackCategories.CUSTOM,
        )

        assert metadata.name == "Test Attack"
        assert metadata.description == "Test description"
        assert metadata.category == AttackCategories.CUSTOM
        assert metadata.required_params == []
        assert metadata.optional_params == {}
        assert metadata.aliases == []

    def test_create_full_metadata(self):
        """Тест создания полных метаданных."""
        metadata = create_attack_metadata(
            name="Full Test Attack",
            description="Full test description",
            category=AttackCategories.SPLIT,
            required_params=["param1", "param2"],
            optional_params={"opt1": "default", "opt2": 42},
            aliases=["alias1", "alias2"],
        )

        assert metadata.name == "Full Test Attack"
        assert metadata.description == "Full test description"
        assert metadata.category == AttackCategories.SPLIT
        assert metadata.required_params == ["param1", "param2"]
        assert metadata.optional_params == {"opt1": "default", "opt2": 42}
        assert metadata.aliases == ["alias1", "alias2"]

    def test_create_metadata_with_none_values(self):
        """Тест создания метаданных с None значениями."""
        metadata = create_attack_metadata(
            name="Test Attack",
            description="Test description",
            category=AttackCategories.CUSTOM,
            required_params=None,
            optional_params=None,
            aliases=None,
        )

        assert metadata.required_params == []
        assert metadata.optional_params == {}
        assert metadata.aliases == []


class TestMetadataIntegration:
    """Интеграционные тесты для метаданных."""

    def test_metadata_with_all_categories(self):
        """Тест создания метаданных со всеми категориями."""
        for category in AttackCategories.ALL:
            metadata = create_attack_metadata(
                name=f"Test {category.title()} Attack",
                description=f"Test attack for {category} category",
                category=category,
            )

            assert metadata.category == category
            assert category in metadata.name.lower()

    def test_metadata_with_all_special_values(self):
        """Тест метаданных со всеми специальными значениями."""
        metadata = create_attack_metadata(
            name="Special Values Attack",
            description="Attack using special parameter values",
            category=AttackCategories.CUSTOM,
            optional_params={
                "split_pos": SpecialParameterValues.CIPHER,
                "sni_pos": SpecialParameterValues.SNI,
                "domain_pos": SpecialParameterValues.MIDSLD,
            },
        )

        assert metadata.optional_params["split_pos"] == "cipher"
        assert metadata.optional_params["sni_pos"] == "sni"
        assert metadata.optional_params["domain_pos"] == "midsld"

    def test_metadata_with_all_fooling_methods(self):
        """Тест метаданных со всеми методами обмана."""
        metadata = create_attack_metadata(
            name="Fooling Methods Attack",
            description="Attack using all fooling methods",
            category=AttackCategories.FAKE,
            optional_params={"fooling": FoolingMethods.ALL},
        )

        assert metadata.optional_params["fooling"] == FoolingMethods.ALL
        assert len(metadata.optional_params["fooling"]) == 5

    def test_validation_result_with_metadata(self):
        """Тест ValidationResult в контексте метаданных."""
        metadata = create_attack_metadata(
            name="Validation Test Attack",
            description="Attack for testing validation",
            category=AttackCategories.SPLIT,
            required_params=["split_pos"],
            optional_params={"ttl": 3},
        )

        # Создаем результат валидации
        result = ValidationResult(is_valid=True)
        result.add_warning(f"Attack '{metadata.name}' uses default TTL value")

        assert result.is_valid is True
        assert result.has_warnings() is True
        assert metadata.name in result.warnings[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
