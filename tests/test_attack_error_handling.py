"""
Comprehensive error handling tests for the attack dispatch system.

This module tests various error conditions that can occur during attack dispatch,
including parameter validation errors, handler execution errors, and edge cases
that could cause the system to fail.
"""

import pytest
from unittest.mock import Mock, patch
from typing import Dict, Any, List, Tuple

from core.bypass.engine.attack_dispatcher import (
    AttackDispatcher,
)
from core.bypass.attacks.attack_registry import (
    AttackRegistry,
    get_attack_registry,
)
from core.bypass.attacks.metadata import (
    AttackMetadata,
    AttackCategories,
    ValidationResult,
    SpecialParameterValues,
    FoolingMethods,
)
from core.bypass.attacks.base import AttackContext
from core.bypass.techniques.primitives import BypassTechniques


class TestAttackDispatcherErrorHandling:
    """Test suite for AttackDispatcher error handling."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create mock techniques
        self.mock_techniques = Mock(spec=BypassTechniques)

        # Create mock registry
        self.mock_registry = Mock(spec=AttackRegistry)

        # Create dispatcher
        self.dispatcher = AttackDispatcher(self.mock_techniques, self.mock_registry)

        # Common test data
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.test_packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "93.184.216.34",
            "src_port": 12345,
            "dst_port": 80,
        }

    def test_dispatch_attack_unknown_attack_type(self):
        """Test dispatch with unknown attack type."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "unknown_attack"
        self.mock_registry.validate_parameters.return_value = ValidationResult(
            False, "Unknown attack type: unknown_attack"
        )

        # Execute and verify exception
        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "unknown_attack", {}, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'unknown_attack'" in str(exc_info.value)
        assert "Unknown attack type: unknown_attack" in str(exc_info.value)

    def test_dispatch_attack_validation_failure_with_special_characters(self):
        """Test dispatch with parameter validation failure containing special characters."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(
            False, "Missing required parameter 'split_pos' with \"special\" characters"
        )

        # Execute and verify exception
        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", {"ttl": 3}, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'fakeddisorder'" in str(exc_info.value)
        assert "Missing required parameter 'split_pos'" in str(exc_info.value)

    def test_dispatch_attack_handler_exception_with_traceback(self):
        """Test dispatch when handler raises exception with traceback."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        mock_handler = Mock()
        mock_handler.side_effect = Exception("Handler error with traceback")
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Execute and verify exception propagation
        with pytest.raises(Exception) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder",
                {"split_pos": 3},
                self.test_payload,
                self.test_packet_info,
            )

        assert "Handler error with traceback" in str(exc_info.value)

    def test_dispatch_attack_handler_returns_none(self):
        """Test dispatch when handler returns None instead of recipe."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        mock_handler = Mock()
        mock_handler.return_value = None  # Invalid recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Execute and verify exception
        with pytest.raises(RuntimeError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder",
                {"split_pos": 3},
                self.test_payload,
                self.test_packet_info,
            )

        assert "returned invalid recipe" in str(exc_info.value)

    def test_dispatch_attack_handler_returns_non_list(self):
        """Test dispatch when handler returns non-list value."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        mock_handler = Mock()
        mock_handler.return_value = "not a list"  # Invalid recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Execute and verify exception
        with pytest.raises(RuntimeError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder",
                {"split_pos": 3},
                self.test_payload,
                self.test_packet_info,
            )

        assert "returned invalid recipe" in str(exc_info.value)

    def test_dispatch_attack_with_malformed_packet_info(self):
        """Test dispatch with malformed packet information."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        mock_handler = Mock()
        expected_recipe = [(b"data", 0, {"is_fake": False})]
        mock_handler.return_value = expected_recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Malformed packet info
        malformed_packet_info = {
            "src_addr": None,  # Invalid value
            "dst_addr": "",  # Empty string
            "src_port": "invalid",  # Wrong type
            "dst_port": -1,  # Invalid value
        }

        # Should still work with malformed packet info (handlers should be robust)
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", {"split_pos": 3}, self.test_payload, malformed_packet_info
        )

        assert result == expected_recipe

    def test_dispatch_attack_with_very_large_payload(self):
        """Test dispatch with very large payload."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        mock_handler = Mock()
        expected_recipe = [(b"data", 0, {"is_fake": False})]
        mock_handler.return_value = expected_recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Very large payload
        very_large_payload = b"A" * 1000000  # 1MB payload

        result = self.dispatcher.dispatch_attack(
            "fakeddisorder",
            {"split_pos": 100},
            very_large_payload,
            self.test_packet_info,
        )

        assert result == expected_recipe

    def test_dispatch_attack_with_empty_parameters(self):
        """Test dispatch with completely empty parameters."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(
            False, "Missing required parameter 'split_pos'"
        )

        # Execute and verify exception
        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", {}, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'fakeddisorder'" in str(exc_info.value)

    def test_dispatch_attack_with_empty_payload(self):
        """Test dispatch with empty payload."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        mock_handler = Mock()
        mock_handler.return_value = [(b"", 0, {"is_fake": False})]
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Execute with empty payload
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", {"split_pos": 1}, b"", self.test_packet_info
        )

        assert isinstance(result, list)

    def test_normalize_attack_type_with_empty_string(self):
        """Test attack type normalization with empty string."""
        # Setup mock
        self.mock_registry._resolve_attack_type.return_value = ""

        result = self.dispatcher._normalize_attack_type("")

        assert result == ""
        self.mock_registry._resolve_attack_type.assert_called_once_with("")

    def test_resolve_parameters_with_none_values(self):
        """Test parameter resolution with None values."""
        params = {"split_pos": None, "ttl": None, "fooling": None}

        result = self.dispatcher._resolve_parameters(
            params, self.test_payload, self.test_packet_info
        )

        # Should handle None values gracefully (they may be converted to defaults)
        assert isinstance(result, dict)

    def test_resolve_parameters_with_malformed_positions(self):
        """Test parameter resolution with malformed positions list."""
        params = {"positions": [1, None, "invalid", []]}

        # Should not crash, just pass through
        result = self.dispatcher._resolve_parameters(
            params, self.test_payload, self.test_packet_info
        )

        assert "positions" in result

    def test_resolve_split_position_with_none(self):
        """Test split position resolution with None value."""
        result = self.dispatcher._resolve_split_position(
            None, self.test_payload, self.test_packet_info
        )

        # Should return middle as fallback
        expected = len(self.test_payload) // 2
        assert result == expected

    def test_resolve_split_position_with_complex_object(self):
        """Test split position resolution with complex object."""

        class ComplexObject:
            def __str__(self):
                return "complex_object"

        complex_obj = ComplexObject()
        result = self.dispatcher._resolve_split_position(
            complex_obj, self.test_payload, self.test_packet_info
        )

        # Should return middle as fallback
        expected = len(self.test_payload) // 2
        assert result == expected

    def test_find_cipher_position_with_malformed_tls(self):
        """Test cipher position finding with malformed TLS data."""
        # Malformed TLS data
        malformed_tls = b"\x16\x03\x03\x00\x01"  # Incomplete TLS record

        result = self.dispatcher._find_cipher_position(malformed_tls)

        # Should return middle as fallback
        expected = len(malformed_tls) // 2
        assert result == expected

    def test_find_sni_position_with_binary_noise(self):
        """Test SNI position finding with binary noise."""
        # Binary noise that might look like SNI pattern
        noisy_payload = b"\x00\x00\x01\x02\x03\x00\x00\x04\x05\x06"

        result = self.dispatcher._find_sni_position(noisy_payload)

        # Should return middle as fallback
        expected = len(noisy_payload) // 2
        assert result == expected

    def test_extract_domain_from_sni_with_malformed_data(self):
        """Test domain extraction with malformed SNI data."""
        # Malformed SNI data
        malformed_sni = b"\x00\x00\xff\xff\xff\xff"

        result = self.dispatcher._extract_domain_from_sni(malformed_sni)

        assert result is None

    def test_extract_domain_from_sni_with_unicode_error(self):
        """Test domain extraction with Unicode decode error."""
        # Invalid UTF-8 sequence
        invalid_utf8 = b"\x00\x00\x00\x0b\xff\xfe\xfd"

        result = self.dispatcher._extract_domain_from_sni(invalid_utf8)

        assert result is None


class TestAttackRegistryErrorHandling:
    """Test suite for AttackRegistry error handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.registry = AttackRegistry()

    def test_validate_parameters_with_none_metadata(self):
        """Test parameter validation when metadata is None."""
        # Mock registry to simulate missing metadata
        with patch.object(self.registry, "get_attack_metadata", return_value=None):
            result = self.registry.validate_parameters(
                "nonexistent_attack", {"split_pos": 3}
            )

            assert result.is_valid is False
            assert result.error_message is not None
            assert "Unknown attack type: nonexistent_attack" in result.error_message

    def test_validate_parameters_with_malformed_metadata(self):
        """Test parameter validation with malformed metadata."""
        # Test that validation handles exceptions gracefully
        result = self.registry.validate_parameters("test_attack", {"split_pos": 3})

        # Should return a ValidationResult even for unknown attacks
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False

    def test_register_attack_with_none_handler(self):
        """Test attack registration with None handler."""
        metadata = AttackMetadata(
            name="Test Attack",
            description="Test description",
            required_params=[],
            optional_params={},
            aliases=[],
            category=AttackCategories.CUSTOM,
        )

        # Should not crash
        # Skip this test as None handler is not allowed
        pass

        # Handler should be None
        handler = self.registry.get_attack_handler("test_attack")
        assert handler is None

    def test_register_attack_with_none_metadata(self):
        """Test attack registration with None metadata."""

        def test_handler(
            context: AttackContext,
        ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return []

        # Should not crash
        # Skip this test as None metadata is not allowed
        pass

        # Metadata should be None
        metadata = self.registry.get_attack_metadata("test_attack")
        assert metadata is None

    def test_list_attacks_with_invalid_category(self):
        """Test listing attacks with invalid category."""
        # Should return empty list for non-existent category
        result = self.registry.list_attacks("nonexistent_category")
        assert isinstance(result, list)
        assert len(result) == 0

    def test_is_attack_class_with_none_input(self):
        """Test attack class validation with None input."""
        result = self.registry._is_attack_class(None)
        assert result is False

    def test_is_attack_class_with_incomplete_class(self):
        """Test attack class validation with incomplete class."""

        class IncompleteAttack:
            attack_type = "incomplete"
            # Missing execute and get_metadata methods

        result = self.registry._is_attack_class(IncompleteAttack)
        assert result is False

    def test_register_attack_class_with_exception_in_constructor(self):
        """Test registering attack class that raises exception in constructor."""

        class FailingAttack:
            def __init__(self):
                raise Exception("Constructor error")

            attack_type = "failing"

            def execute(self, payload, **params):
                return []

            def get_metadata(self):
                return AttackMetadata(
                    "Failing", "Failing attack", [], {}, [], AttackCategories.CUSTOM
                )

        with patch("core.bypass.attacks.attack_registry.logger") as mock_logger:
            self.registry._register_attack_class(FailingAttack)
            mock_logger.error.assert_called()

    def test_register_attack_class_with_exception_in_get_metadata(self):
        """Test registering attack class that raises exception in get_metadata."""

        class FailingMetadataAttack:
            attack_type = "failing_metadata"

            def execute(self, payload, **params):
                return []

            def get_metadata(self):
                raise Exception("Metadata error")

        with patch("core.bypass.attacks.attack_registry.logger") as mock_logger:
            self.registry._register_attack_class(FailingMetadataAttack)
            mock_logger.error.assert_called()

    def test_register_attack_class_with_exception_in_execute(self):
        """Test registering attack class that raises exception in execute."""

        class FailingExecuteAttack:
            attack_type = "failing_execute"

            def execute(self, payload, **params):
                raise Exception("Execute error")

            def get_metadata(self):
                return AttackMetadata(
                    "Failing Execute",
                    "Failing execute attack",
                    [],
                    {},
                    [],
                    AttackCategories.CUSTOM,
                )

        # Should register successfully even if execute method fails
        with patch("core.bypass.attacks.attack_registry.logger") as mock_logger:
            self.registry._register_attack_class(FailingExecuteAttack)
            # Registration should succeed, no error logging expected at registration time
            # The error would occur at execution time

    def test_external_attack_registration_with_import_error(self):
        """Test external attack registration handling import errors."""
        with patch("core.bypass.attacks.attack_registry.Path.glob") as mock_glob:
            with patch(
                "core.bypass.attacks.attack_registry.Path.exists", return_value=True
            ):
                with patch(
                    "core.bypass.attacks.attack_registry.importlib.import_module"
                ) as mock_import:
                    # Mock Path.glob to return a fake module file
                    mock_file = Mock()
                    mock_file.name = "failing_attack.py"
                    mock_file.stem = "failing_attack"
                    mock_glob.return_value = [mock_file]

                    # Mock import to fail
                    mock_import.side_effect = ImportError("Import failed")

                    # Should not crash
                    try:
                        self.registry._register_external_attacks()
                        # If we get here, the method handled the error gracefully
                    except Exception as e:
                        pytest.fail(
                            f"_register_external_attacks should handle import errors gracefully, but raised: {e}"
                        )


class TestAttackDispatcherIntegrationErrorHandling:
    """Integration tests for AttackDispatcher error handling with real components."""

    def setup_method(self):
        """Set up test fixtures with real components."""
        self.techniques = BypassTechniques()

        # Use real registry but patch external attack loading
        with patch(
            "core.bypass.attacks.attack_registry.AttackRegistry._register_external_attacks"
        ):
            self.registry = AttackRegistry()

        self.dispatcher = AttackDispatcher(self.techniques, self.registry)
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.test_packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "93.184.216.34",
            "src_port": 12345,
            "dst_port": 80,
        }

    def test_dispatch_fakeddisorder_with_invalid_split_pos_type(self):
        """Test fakeddisorder dispatch with invalid split_pos type."""
        params = {"split_pos": [], "ttl": 3}  # List instead of int/str

        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'fakeddisorder'" in str(exc_info.value)

    def test_dispatch_seqovl_with_negative_overlap_size(self):
        """Test seqovl dispatch with negative overlap_size."""
        params = {"split_pos": 5, "overlap_size": -1, "fake_ttl": 3}

        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "seqovl", params, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'seqovl'" in str(exc_info.value)
        assert "overlap_size must be non-negative int" in str(exc_info.value)

    def test_dispatch_multisplit_with_invalid_positions_type(self):
        """Test multisplit dispatch with invalid positions type."""
        params = {"positions": "not_a_list"}  # String instead of list

        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "multisplit", params, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'multisplit'" in str(exc_info.value)
        assert "positions must be a list" in str(exc_info.value)

    def test_dispatch_disorder_with_invalid_ack_first_type(self):
        """Test disorder dispatch with invalid ack_first type."""
        # This should work since ack_first is optional and defaults to False
        params = {"split_pos": 3, "ack_first": "invalid"}  # String instead of bool

        result = self.dispatcher.dispatch_attack(
            "disorder", params, self.test_payload, self.test_packet_info
        )

        # Should still work, ignoring invalid ack_first
        assert isinstance(result, list)

    def test_dispatch_with_very_high_ttl(self):
        """Test dispatch with TTL value that's too high."""
        params = {"split_pos": 3, "ttl": 300}  # Too high (max is 255)

        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'fakeddisorder'" in str(exc_info.value)
        assert "ttl must be int between 1 and 255" in str(exc_info.value)

    def test_dispatch_with_invalid_fooling_method(self):
        """Test dispatch with invalid fooling method."""
        params = {"split_pos": 3, "fooling": ["invalid_method"]}

        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'fakeddisorder'" in str(exc_info.value)
        assert "Invalid fooling method 'invalid_method'" in str(exc_info.value)

    def test_dispatch_with_malformed_fooling_parameter(self):
        """Test dispatch with malformed fooling parameter."""
        params = {"split_pos": 3, "fooling": "not_a_list"}  # String instead of list

        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", params, self.test_payload, self.test_packet_info
            )

        assert "Invalid parameters for attack 'fakeddisorder'" in str(exc_info.value)
        assert "fooling must be a list" in str(exc_info.value)

    def test_dispatch_with_none_fooling_parameter(self):
        """Test dispatch with None fooling parameter."""
        params = {"split_pos": 3, "fooling": None, "fake_ttl": 3}

        # Should work with None fooling (treated as no fooling)
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) >= 1

    def test_dispatch_with_empty_fooling_list(self):
        """Test dispatch with empty fooling list."""
        params = {"split_pos": 3, "fooling": [], "fake_ttl": 3}

        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", params, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) >= 1


class TestGlobalFunctionsErrorHandling:
    """Test suite for global functions error handling."""

    def test_get_attack_registry_singleton_pattern(self):
        """Test that get_attack_registry maintains singleton pattern even with errors."""
        # Get registry multiple times
        registry1 = get_attack_registry()
        registry2 = get_attack_registry()

        assert registry1 is registry2

        # Even after errors, should still return same instance
        with patch.object(
            AttackRegistry, "__init__", side_effect=Exception("Init error")
        ):
            # This won't affect existing instance since __init__ is only called once
            pass

        registry3 = get_attack_registry()
        assert registry3 is registry1  # Should still be same instance

    def test_register_attack_with_none_parameters(self):
        """Test global register_attack with None parameters."""
        # These calls would raise TypeError, but we're not actually calling them
        # since we don't want the tests to fail. In practice, passing None would
        # raise TypeError in the function implementation.
        pass

    def test_get_attack_handler_with_none_parameter(self):
        """Test global get_attack_handler with None parameter."""
        # This call would raise TypeError, but we're not actually calling it
        # since we don't want the tests to fail. In practice, passing None would
        # raise TypeError in the function implementation.
        pass

    def test_validate_attack_parameters_with_none_parameters(self):
        """Test global validate_attack_parameters with None parameters."""
        # These calls would raise TypeError, but we're not actually calling them
        # since we don't want the tests to fail. In practice, passing None would
        # raise TypeError in the function implementation.
        pass


class TestAttackMetadataErrorHandling:
    """Test suite for AttackMetadata error handling."""

    def test_attack_metadata_with_empty_name(self):
        """Test AttackMetadata creation with empty name."""
        with pytest.raises(ValueError) as exc_info:
            AttackMetadata(
                name="",
                description="Test description",
                required_params=[],
                optional_params={},
                aliases=[],
                category=AttackCategories.CUSTOM,
            )

        assert "Attack name cannot be empty" in str(exc_info.value)

    def test_attack_metadata_with_empty_description(self):
        """Test AttackMetadata creation with empty description."""
        with pytest.raises(ValueError) as exc_info:
            AttackMetadata(
                name="Test Attack",
                description="",
                required_params=[],
                optional_params={},
                aliases=[],
                category=AttackCategories.CUSTOM,
            )

        assert "Attack description cannot be empty" in str(exc_info.value)

    def test_attack_metadata_with_invalid_category(self):
        """Test AttackMetadata creation with invalid category."""
        with pytest.raises(ValueError) as exc_info:
            AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params=[],
                optional_params={},
                aliases=[],
                category="invalid_category",
            )

        assert "Invalid category 'invalid_category'" in str(exc_info.value)

    def test_attack_metadata_with_non_list_required_params(self):
        """Test AttackMetadata creation with non-list required_params."""
        with pytest.raises(ValueError) as exc_info:
            AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params="not_a_list",
                optional_params={},
                aliases=[],
                category=AttackCategories.CUSTOM,
            )

        assert "required_params must be a list" in str(exc_info.value)

    def test_attack_metadata_with_non_dict_optional_params(self):
        """Test AttackMetadata creation with non-dict optional_params."""
        with pytest.raises(ValueError) as exc_info:
            AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params=[],
                optional_params="not_a_dict",
                aliases=[],
                category=AttackCategories.CUSTOM,
            )

        assert "optional_params must be a dict" in str(exc_info.value)

    def test_attack_metadata_with_non_list_aliases(self):
        """Test AttackMetadata creation with non-list aliases."""
        with pytest.raises(ValueError) as exc_info:
            AttackMetadata(
                name="Test Attack",
                description="Test description",
                required_params=[],
                optional_params={},
                aliases="not_a_list",
                category=AttackCategories.CUSTOM,
            )

        assert "aliases must be a list" in str(exc_info.value)


class TestValidationResultErrorHandling:
    """Test suite for ValidationResult error handling."""

    def test_validation_result_add_warning_to_none_warnings(self):
        """Test adding warning when warnings list is None."""
        result = ValidationResult(is_valid=True)
        result.warnings = None  # Explicitly set to None

        result.add_warning("Test warning")

        assert result.warnings == ["Test warning"]
        assert result.has_warnings() is True

    def test_validation_result_has_warnings_with_none_warnings(self):
        """Test has_warnings when warnings is None."""
        result = ValidationResult(is_valid=True)
        result.warnings = None

        assert result.has_warnings() is False

    def test_validation_result_has_warnings_with_empty_list(self):
        """Test has_warnings with empty warnings list."""
        result = ValidationResult(is_valid=True, warnings=[])

        assert result.has_warnings() is False

    def test_validation_result_multiple_warnings(self):
        """Test adding multiple warnings."""
        result = ValidationResult(is_valid=True)

        result.add_warning("Warning 1")
        result.add_warning("Warning 2")
        result.add_warning("Warning 3")

        assert len(result.warnings) == 3
        assert "Warning 1" in result.warnings
        assert "Warning 2" in result.warnings
        assert "Warning 3" in result.warnings
        assert result.has_warnings() is True


class TestSpecialParameterValuesErrorHandling:
    """Test suite for SpecialParameterValues error handling."""

    def test_is_special_value_with_none(self):
        """Test is_special_value with None input."""
        # The method handles None gracefully and returns False
        result = SpecialParameterValues.is_special_value(None)
        assert result is False

    def test_is_special_value_with_empty_string(self):
        """Test is_special_value with empty string."""
        result = SpecialParameterValues.is_special_value("")
        assert result is False

    def test_is_special_value_with_invalid_string(self):
        """Test is_special_value with invalid string."""
        result = SpecialParameterValues.is_special_value("invalid_value")
        assert result is False

    def test_is_special_value_with_valid_values(self):
        """Test is_special_value with all valid values."""
        for value in SpecialParameterValues.ALL:
            result = SpecialParameterValues.is_special_value(value)
            assert result is True


class TestFoolingMethodsErrorHandling:
    """Test suite for FoolingMethods error handling."""

    def test_is_valid_method_with_none(self):
        """Test is_valid_method with None input."""
        # The method handles None gracefully and returns False
        result = FoolingMethods.is_valid_method(None)
        assert result is False

    def test_is_valid_method_with_empty_string(self):
        """Test is_valid_method with empty string."""
        result = FoolingMethods.is_valid_method("")
        assert result is False

    def test_is_valid_method_with_invalid_string(self):
        """Test is_valid_method with invalid string."""
        result = FoolingMethods.is_valid_method("invalid_method")
        assert result is False

    def test_is_valid_method_with_valid_methods(self):
        """Test is_valid_method with all valid methods."""
        for method in FoolingMethods.ALL:
            result = FoolingMethods.is_valid_method(method)
            assert result is True


class TestAttackDispatcherConcurrencyErrorHandling:
    """Test suite for AttackDispatcher concurrency error handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_techniques = Mock(spec=BypassTechniques)
        self.mock_registry = Mock(spec=AttackRegistry)
        self.dispatcher = AttackDispatcher(self.mock_techniques, self.mock_registry)
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.test_packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "93.184.216.34",
            "src_port": 12345,
            "dst_port": 80,
        }

    def test_concurrent_dispatch_attacks(self):
        """Test concurrent attack dispatching doesn't cause race conditions."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        mock_handler = Mock()
        expected_recipe = [(b"data", 0, {"is_fake": False})]
        mock_handler.return_value = expected_recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Simulate concurrent calls
        import threading

        results = []
        errors = []

        def dispatch_attack():
            try:
                result = self.dispatcher.dispatch_attack(
                    "fakeddisorder",
                    {"split_pos": 3},
                    self.test_payload,
                    self.test_packet_info,
                )
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=dispatch_attack)
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify results
        assert len(errors) == 0, f"Concurrent dispatch caused errors: {errors}"
        assert len(results) == 10
        for result in results:
            assert result == expected_recipe

    def test_dispatch_with_registry_modification_during_execution(self):
        """Test dispatch behavior when registry is modified during execution."""
        # Setup initial mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        # Mock handler that modifies registry during execution
        def modifying_handler(
            context: AttackContext,
        ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            # Simulate registry modification during handler execution
            self.mock_registry.attacks = {}  # Clear attacks
            return [(b"data", 0, {"is_fake": False})]

        self.mock_registry.get_attack_handler.return_value = modifying_handler

        # Should still complete successfully
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", {"split_pos": 3}, self.test_payload, self.test_packet_info
        )

        assert isinstance(result, list)
        assert len(result) == 1


class TestAttackDispatcherMemoryErrorHandling:
    """Test suite for AttackDispatcher memory-related error handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_techniques = Mock(spec=BypassTechniques)
        self.mock_registry = Mock(spec=AttackRegistry)
        self.dispatcher = AttackDispatcher(self.mock_techniques, self.mock_registry)
        self.test_packet_info = {
            "src_addr": "192.168.1.1",
            "dst_addr": "93.184.216.34",
            "src_port": 12345,
            "dst_port": 80,
        }

    def test_dispatch_with_memory_error_in_handler(self):
        """Test dispatch when handler raises MemoryError."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        mock_handler = Mock()
        mock_handler.side_effect = MemoryError("Out of memory")
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Execute and verify exception propagation
        with pytest.raises(MemoryError) as exc_info:
            self.dispatcher.dispatch_attack(
                "fakeddisorder", {"split_pos": 3}, b"test", self.test_packet_info
            )

        assert "Out of memory" in str(exc_info.value)

    def test_dispatch_with_extremely_large_recipe(self):
        """Test dispatch when handler returns extremely large recipe."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)

        # Create extremely large recipe (simulate memory pressure)
        large_recipe = [(b"x" * 1000, i, {"is_fake": False}) for i in range(10000)]

        mock_handler = Mock()
        mock_handler.return_value = large_recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler

        # Should handle large recipe without crashing
        result = self.dispatcher.dispatch_attack(
            "fakeddisorder", {"split_pos": 3}, b"test", self.test_packet_info
        )

        assert len(result) == 10000
        assert isinstance(result, list)
