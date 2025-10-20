"""
Unit tests for AttackRegistry component.

Tests attack registration, parameter validation, handler retrieval,
and metadata management for the DPI bypass attack system.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from core.bypass.attacks.attack_registry import AttackRegistry, get_attack_registry, register_attack, get_attack_handler, validate_attack_parameters
from core.bypass.attacks.metadata import AttackMetadata, AttackCategories, ValidationResult, create_attack_metadata


class TestAttackRegistry:
    """Test suite for AttackRegistry component."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Create fresh registry for each test
        self.registry = AttackRegistry()
    
    def test_init(self):
        """Test AttackRegistry initialization."""
        registry = AttackRegistry()
        
        assert registry is not None
        assert hasattr(registry, 'attacks')
        assert isinstance(registry.attacks, dict)
        assert len(registry.attacks) > 0  # Should have builtin attacks
        
        # Check that builtin attacks are registered
        expected_attacks = ['fakeddisorder', 'seqovl', 'multidisorder', 'disorder', 'disorder2', 'multisplit', 'split', 'fake']
        for attack_type in expected_attacks:
            assert attack_type in registry.attacks
    
    def test_register_attack_basic(self):
        """Test basic attack registration."""
        def test_handler(techniques, payload, **params):
            return [(payload, 0, {"is_fake": False})]
        
        metadata = create_attack_metadata(
            name="Test Attack",
            description="A test attack for unit testing",
            category=AttackCategories.CUSTOM,
            required_params=["test_param"],
            optional_params={"optional_param": "default_value"},
            aliases=["test_alias"]
        )
        
        self.registry.register_attack("test_attack", test_handler, metadata)
        
        assert "test_attack" in self.registry.attacks
        assert self.registry.attacks["test_attack"]["handler"] == test_handler
        assert self.registry.attacks["test_attack"]["metadata"] == metadata
        assert self.registry._aliases["test_alias"] == "test_attack"
    
    def test_register_attack_overwrite_warning(self):
        """Test that overwriting existing attack logs warning."""
        def handler1(techniques, payload, **params):
            return []
        
        def handler2(techniques, payload, **params):
            return []
        
        metadata = create_attack_metadata(
            name="Test Attack",
            description="Test description",
            category=AttackCategories.CUSTOM
        )
        
        # Register first attack
        self.registry.register_attack("test_attack", handler1, metadata)
        
        # Register second attack with same name (should overwrite)
        with patch('core.bypass.attacks.attack_registry.logger') as mock_logger:
            self.registry.register_attack("test_attack", handler2, metadata)
            mock_logger.warning.assert_called_once()
    
    def test_get_attack_handler_valid(self):
        """Test getting handler for valid attack type."""
        handler = self.registry.get_attack_handler("fakeddisorder")
        
        assert handler is not None
        assert callable(handler)
    
    def test_get_attack_handler_alias(self):
        """Test getting handler using alias."""
        handler = self.registry.get_attack_handler("fake_disorder")
        
        assert handler is not None
        assert callable(handler)
    
    def test_get_attack_handler_invalid(self):
        """Test getting handler for invalid attack type."""
        handler = self.registry.get_attack_handler("nonexistent_attack")
        
        assert handler is None
    
    def test_get_attack_metadata_valid(self):
        """Test getting metadata for valid attack type."""
        metadata = self.registry.get_attack_metadata("fakeddisorder")
        
        assert metadata is not None
        assert isinstance(metadata, AttackMetadata)
        assert metadata.name == "Fake Disorder"
        assert metadata.category == AttackCategories.FAKE
    
    def test_get_attack_metadata_alias(self):
        """Test getting metadata using alias."""
        metadata = self.registry.get_attack_metadata("fake_disorder")
        
        assert metadata is not None
        assert isinstance(metadata, AttackMetadata)
        assert metadata.name == "Fake Disorder"
    
    def test_get_attack_metadata_invalid(self):
        """Test getting metadata for invalid attack type."""
        metadata = self.registry.get_attack_metadata("nonexistent_attack")
        
        assert metadata is None
    
    def test_validate_parameters_valid_fakeddisorder(self):
        """Test parameter validation for valid fakeddisorder parameters."""
        params = {
            "split_pos": 3,
            "ttl": 5,
            "fooling": ["badsum"]
        }
        
        result = self.registry.validate_parameters("fakeddisorder", params)
        
        assert result.is_valid is True
        assert result.error_message is None
    
    def test_validate_parameters_missing_required(self):
        """Test parameter validation with missing required parameter."""
        params = {
            "ttl": 5  # Missing required split_pos
        }
        
        result = self.registry.validate_parameters("fakeddisorder", params)
        
        assert result.is_valid is False
        assert "Missing required parameter 'split_pos'" in result.error_message
    
    def test_validate_parameters_invalid_split_pos(self):
        """Test parameter validation with invalid split_pos."""
        params = {
            "split_pos": "invalid_value"  # Not int or special value
        }
        
        result = self.registry.validate_parameters("fakeddisorder", params)
        
        assert result.is_valid is False
        assert result.error_message is not None
        assert result.error_message is not None
        assert "Invalid split_pos value" in result.error_message
    
    def test_validate_parameters_special_split_pos(self):
        """Test parameter validation with special split_pos values."""
        special_values = ["cipher", "sni", "midsld"]
        
        for special_value in special_values:
            params = {"split_pos": special_value}
            result = self.registry.validate_parameters("fakeddisorder", params)
            
            assert result.is_valid is True, f"Failed for special value: {special_value}"
    
    def test_validate_parameters_seqovl(self):
        """Test parameter validation for seqovl attack."""
        params = {
            "split_pos": 5,
            "overlap_size": 20,
            "fake_ttl": 3
        }
        
        result = self.registry.validate_parameters("seqovl", params)
        
        assert result.is_valid is True
    
    def test_validate_parameters_invalid_overlap_size(self):
        """Test parameter validation with invalid overlap_size."""
        params = {
            "split_pos": 5,
            "overlap_size": -1  # Negative value
        }
        
        result = self.registry.validate_parameters("seqovl", params)
        
        assert result.is_valid is False
        assert result.error_message is not None
        assert result.error_message is not None
        assert "overlap_size must be non-negative int" in result.error_message
    
    def test_validate_parameters_invalid_ttl(self):
        """Test parameter validation with invalid TTL."""
        params = {
            "split_pos": 3,
            "ttl": 300  # Too high
        }
        
        result = self.registry.validate_parameters("fakeddisorder", params)
        
        assert result.is_valid is False
        assert result.error_message is not None
        assert result.error_message is not None
        assert "ttl must be int between 1 and 255" in result.error_message
    
    def test_validate_parameters_invalid_fooling(self):
        """Test parameter validation with invalid fooling methods."""
        params = {
            "split_pos": 3,
            "fooling": ["invalid_method"]
        }
        
        result = self.registry.validate_parameters("fakeddisorder", params)
        
        assert result.is_valid is False
        assert result.error_message is not None
        assert result.error_message is not None
        assert "Invalid fooling method 'invalid_method'" in result.error_message
    
    def test_validate_parameters_valid_fooling(self):
        """Test parameter validation with valid fooling methods."""
        valid_methods = ["badsum", "badseq", "badack", "datanoack", "hopbyhop"]
        
        for method in valid_methods:
            params = {
                "split_pos": 3,
                "fooling": [method]
            }
            result = self.registry.validate_parameters("fakeddisorder", params)
            
            assert result.is_valid is True, f"Failed for fooling method: {method}"
    
    def test_validate_parameters_positions_list(self):
        """Test parameter validation for positions parameter."""
        params = {
            "positions": [1, 5, 10]
        }
        
        result = self.registry.validate_parameters("multisplit", params)
        
        assert result.is_valid is True
    
    def test_validate_parameters_invalid_positions_type(self):
        """Test parameter validation with invalid positions type."""
        params = {
            "positions": "not_a_list"
        }
        
        result = self.registry.validate_parameters("multisplit", params)
        
        assert result.is_valid is False
        assert result.error_message is not None
        assert result.error_message is not None
        assert "positions must be a list" in result.error_message
    
    def test_validate_parameters_invalid_position_value(self):
        """Test parameter validation with invalid position value."""
        params = {
            "positions": [1, 0, 5]  # 0 is invalid
        }
        
        result = self.registry.validate_parameters("multisplit", params)
        
        assert result.is_valid is False
        assert result.error_message is not None
        assert result.error_message is not None
        assert "Position values must be >= 1" in result.error_message
    
    def test_validate_parameters_unknown_attack(self):
        """Test parameter validation for unknown attack type."""
        params = {"split_pos": 3}
        
        result = self.registry.validate_parameters("unknown_attack", params)
        
        assert result.is_valid is False
        assert result.error_message is not None
        assert result.error_message is not None
        assert "Unknown attack type: unknown_attack" in result.error_message
    
    def test_list_attacks_all(self):
        """Test listing all attacks."""
        attacks = self.registry.list_attacks()
        
        assert isinstance(attacks, list)
        assert len(attacks) > 0
        assert "fakeddisorder" in attacks
        assert "seqovl" in attacks
    
    def test_list_attacks_by_category(self):
        """Test listing attacks by category."""
        fake_attacks = self.registry.list_attacks(AttackCategories.FAKE)
        disorder_attacks = self.registry.list_attacks(AttackCategories.DISORDER)
        
        assert isinstance(fake_attacks, list)
        assert isinstance(disorder_attacks, list)
        assert "fakeddisorder" in fake_attacks
        assert "disorder" in disorder_attacks
    
    def test_get_attack_aliases(self):
        """Test getting aliases for attack type."""
        aliases = self.registry.get_attack_aliases("fakeddisorder")
        
        assert isinstance(aliases, list)
        assert "fake_disorder" in aliases or "fakedisorder" in aliases
    
    def test_get_attack_aliases_invalid(self):
        """Test getting aliases for invalid attack type."""
        aliases = self.registry.get_attack_aliases("nonexistent_attack")
        
        assert isinstance(aliases, list)
        assert len(aliases) == 0
    
    def test_resolve_attack_type(self):
        """Test internal attack type resolution."""
        # Test direct type
        resolved = self.registry._resolve_attack_type("fakeddisorder")
        assert resolved == "fakeddisorder"
        
        # Test alias resolution
        resolved = self.registry._resolve_attack_type("fake_disorder")
        assert resolved == "fakeddisorder"
        
        # Test unknown type
        resolved = self.registry._resolve_attack_type("unknown")
        assert resolved == "unknown"
    
    def test_builtin_attacks_registration(self):
        """Test that all expected builtin attacks are registered."""
        expected_attacks = {
            "fakeddisorder": AttackCategories.FAKE,
            "seqovl": AttackCategories.OVERLAP,
            "multidisorder": AttackCategories.DISORDER,
            "disorder": AttackCategories.DISORDER,
            "disorder2": AttackCategories.DISORDER,
            "multisplit": AttackCategories.SPLIT,
            "split": AttackCategories.SPLIT,
            "fake": AttackCategories.RACE
        }
        
        for attack_type, expected_category in expected_attacks.items():
            assert attack_type in self.registry.attacks
            metadata = self.registry.get_attack_metadata(attack_type)
            assert metadata is not None
            assert metadata is not None
            assert metadata.category == expected_category
    
    @patch('core.bypass.attacks.attack_registry.Path.glob')
    @patch('core.bypass.attacks.attack_registry.Path.exists')
    @patch('core.bypass.attacks.attack_registry.importlib.import_module')
    @patch('core.bypass.attacks.attack_registry.inspect.getmembers')
    def test_register_external_attacks_success(self, mock_getmembers, mock_import, mock_exists, mock_glob):
        """Test successful registration of external attacks."""
        # Mock Path.exists to return True
        mock_exists.return_value = True
        
        # Mock Path.glob to return a fake module file
        mock_file = Mock()
        mock_file.name = "external_attack.py"
        mock_file.stem = "external_attack"
        mock_glob.return_value = [mock_file]
        
        # Mock external attack class
        mock_attack_class = Mock()
        mock_instance = Mock()
        mock_instance.attack_type = "external_attack"
        mock_instance.get_metadata.return_value = create_attack_metadata(
            name="External Attack",
            description="External test attack",
            category=AttackCategories.CUSTOM
        )
        mock_instance.execute.return_value = []
        mock_attack_class.return_value = mock_instance
        
        # Mock module
        mock_module = Mock()
        mock_import.return_value = mock_module
        
        # Mock inspect.getmembers to return our attack class
        mock_getmembers.return_value = [("ExternalAttack", mock_attack_class)]
        
        # Mock _is_attack_class to return True for our class
        with patch.object(self.registry, '_is_attack_class', return_value=True):
            self.registry._register_external_attacks()
        
        # Verify the external attack was registered
        assert "external_attack" in self.registry.attacks
    
    def test_is_attack_class_valid(self):
        """Test attack class validation."""
        # Valid attack class
        class ValidAttack:
            attack_type = "valid"
            def execute(self, payload, **params):
                return []
            def get_metadata(self):
                return create_attack_metadata("Valid", "Valid attack", AttackCategories.CUSTOM)
        
        assert self.registry._is_attack_class(ValidAttack) is True
    
    def test_is_attack_class_invalid(self):
        """Test attack class validation with invalid class."""
        # Invalid attack class (missing methods)
        class InvalidAttack:
            attack_type = "invalid"
            # Missing execute and get_metadata methods
        
        assert self.registry._is_attack_class(InvalidAttack) is False
    
    def test_multidisorder_handler_with_split_pos(self):
        """Test multidisorder handler parameter conversion from split_pos."""
        handler = self.registry.get_attack_handler("multidisorder")
        
        # Mock techniques object
        mock_techniques = Mock()
        mock_techniques.apply_multidisorder.return_value = []
        
        # Test with split_pos parameter
        assert handler is not None
        assert handler is not None
        result = handler(mock_techniques, b"test_payload", split_pos=5)
        
        # Verify that apply_multidisorder was called with converted positions
        mock_techniques.apply_multidisorder.assert_called_once()
        call_args = mock_techniques.apply_multidisorder.call_args
        positions = call_args[0][1]  # Second argument should be positions
        
        assert isinstance(positions, list)
        assert len(positions) > 0
        assert 5 in positions  # Original split_pos should be included
    
    def test_seqovl_handler_parameter_conversion(self):
        """Test seqovl handler parameter conversion."""
        handler = self.registry.get_attack_handler("seqovl")
        
        # Mock techniques object
        mock_techniques = Mock()
        mock_techniques.apply_seqovl.return_value = []
        
        # Test with parameters
        assert handler is not None
        result = handler(mock_techniques, b"test_payload", split_pos=5, overlap_size=20, fake_ttl=3)
        
        # Verify that apply_seqovl was called with correct parameters
        mock_techniques.apply_seqovl.assert_called_once_with(
            b"test_payload", 5, 20, 3, ['badsum']
        )
    
    def test_disorder2_handler(self):
        """Test disorder2 handler sets ack_first=True."""
        handler = self.registry.get_attack_handler("disorder2")
        
        # Mock techniques object
        mock_techniques = Mock()
        mock_techniques.apply_disorder.return_value = []
        
        # Test disorder2 handler
        result = handler(mock_techniques, b"test_payload", split_pos=3)
        
        # Verify that apply_disorder was called with ack_first=True
        mock_techniques.apply_disorder.assert_called_once_with(b"test_payload", 3, ack_first=True)
    
    def test_split_handler_conversion(self):
        """Test split handler converts to multisplit."""
        handler = self.registry.get_attack_handler("split")
        
        # Mock techniques object
        mock_techniques = Mock()
        mock_techniques.apply_multisplit.return_value = []
        
        # Test split handler
        result = handler(mock_techniques, b"test_payload", split_pos=3)
        
        # Verify that apply_multisplit was called with positions list
        mock_techniques.apply_multisplit.assert_called_once_with(b"test_payload", positions=[3])


class TestAttackRegistryGlobalFunctions:
    """Test suite for global AttackRegistry functions."""
    
    def test_get_attack_registry_singleton(self):
        """Test that get_attack_registry returns singleton instance."""
        registry1 = get_attack_registry()
        registry2 = get_attack_registry()
        
        assert registry1 is registry2
        assert isinstance(registry1, AttackRegistry)
    
    def test_register_attack_global(self):
        """Test global register_attack function."""
        def test_handler(techniques, payload, **params):
            return []
        
        metadata = create_attack_metadata(
            name="Global Test",
            description="Global test attack",
            category=AttackCategories.CUSTOM
        )
        
        # Store original attacks to restore later
        original_attacks = dict(get_attack_registry().attacks)
        
        try:
            register_attack("global_test", test_handler, metadata)
            
            # Verify it was registered in global registry
            registry = get_attack_registry()
            assert "global_test" in registry.attacks
        finally:
            # Clean up: remove the test attack
            registry = get_attack_registry()
            if "global_test" in registry.attacks:
                del registry.attacks["global_test"]
    
    def test_get_attack_handler_global(self):
        """Test global get_attack_handler function."""
        handler = get_attack_handler("fakeddisorder")
        
        assert handler is not None
        assert callable(handler)
    
    def test_validate_attack_parameters_global(self):
        """Test global validate_attack_parameters function."""
        params = {"split_pos": 3}
        
        result = validate_attack_parameters("fakeddisorder", params)
        
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True


class TestAttackRegistryEdgeCases:
    """Test suite for AttackRegistry edge cases and error conditions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.registry = AttackRegistry()
    
    def test_validate_parameters_empty_params(self):
        """Test parameter validation with empty parameters."""
        result = self.registry.validate_parameters("fakeddisorder", {})
        
        assert result.is_valid is False
        assert result.error_message is not None
        assert "Missing required parameter 'split_pos'" in result.error_message
    
    def test_validate_parameters_none_fooling(self):
        """Test parameter validation with None fooling methods."""
        params = {
            "split_pos": 3,
            "fooling": None
        }
        
        result = self.registry.validate_parameters("fakeddisorder", params)
        
        assert result.is_valid is True  # None fooling should be allowed
    
    def test_validate_parameters_fooling_not_list(self):
        """Test parameter validation with fooling not being a list."""
        params = {
            "split_pos": 3,
            "fooling": "badsum"  # Should be list
        }
        
        result = self.registry.validate_parameters("fakeddisorder", params)
        
        assert result.is_valid is False
        assert "fooling must be a list" in result.error_message
    
    def test_register_attack_with_existing_alias(self):
        """Test registering attack with alias that already exists."""
        def handler1(techniques, payload, **params):
            return []
        
        def handler2(techniques, payload, **params):
            return []
        
        metadata1 = create_attack_metadata(
            name="Attack 1",
            description="First attack",
            category=AttackCategories.CUSTOM,
            aliases=["shared_alias"]
        )
        
        metadata2 = create_attack_metadata(
            name="Attack 2", 
            description="Second attack",
            category=AttackCategories.CUSTOM,
            aliases=["shared_alias"]
        )
        
        # Register first attack
        self.registry.register_attack("attack1", handler1, metadata1)
        
        # Register second attack with same alias (should log warning)
        with patch('core.bypass.attacks.attack_registry.logger') as mock_logger:
            self.registry.register_attack("attack2", handler2, metadata2)
            mock_logger.warning.assert_called()
    
    def test_multidisorder_handler_edge_cases(self):
        """Test multidisorder handler with edge case parameters."""
        handler = self.registry.get_attack_handler("multidisorder")
        mock_techniques = Mock()
        mock_techniques.apply_multidisorder.return_value = []
        
        # Test with string split_pos
        assert handler is not None
        result = handler(mock_techniques, b"test", split_pos="3")
        mock_techniques.apply_multidisorder.assert_called()
        
        # Test with invalid split_pos (should use default)
        mock_techniques.reset_mock()
        assert handler is not None
        result = handler(mock_techniques, b"test", split_pos="invalid")
        mock_techniques.apply_multidisorder.assert_called()
        
        # Test with no parameters (should use defaults)
        mock_techniques.reset_mock()
        assert handler is not None
        result = handler(mock_techniques, b"test")
        mock_techniques.apply_multidisorder.assert_called()
    
    def test_external_attack_registration_failure(self):
        """Test handling of external attack registration failures."""
        with patch('core.bypass.attacks.attack_registry.Path.glob') as mock_glob:
            with patch('core.bypass.attacks.attack_registry.Path.exists') as mock_exists:
                with patch('core.bypass.attacks.attack_registry.importlib.import_module') as mock_import:
                    # Mock Path.exists to return True
                    mock_exists.return_value = True
                    
                    # Mock Path.glob to return a fake module file
                    mock_file = Mock()
                    mock_file.name = "failing_attack.py"
                    mock_file.stem = "failing_attack"
                    mock_glob.return_value = [mock_file]
                    
                    # Mock import to fail
                    mock_import.side_effect = ImportError("Module not found")
                    
                    # Call the method - should not crash despite import error
                    try:
                        self.registry._register_external_attacks()
                        # If we get here, the method handled the error gracefully
                        assert True
                    except Exception as e:
                        pytest.fail(f"_register_external_attacks should handle import errors gracefully, but raised: {e}")
    
    def test_register_attack_class_failure(self):
        """Test handling of attack class registration failures."""
        class FailingAttack:
            attack_type = "failing"
            def execute(self, payload, **params):
                return []
            def get_metadata(self):
                raise Exception("Metadata error")
        
        with patch('core.bypass.attacks.attack_registry.logger') as mock_logger:
            self.registry._register_attack_class(FailingAttack)
            mock_logger.error.assert_called()