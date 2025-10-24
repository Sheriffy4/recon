"""
Comprehensive registry integration tests for attack system refactoring.

This test suite covers:
- Builtin attack registration with CORE priority
- Alias resolution system
- Priority system edge cases
- Registry integrity during complex operations
"""

import pytest
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List, Tuple

from core.bypass.attacks.attack_registry import (
    AttackRegistry,
    get_attack_registry,
    clear_registry,
)
from core.bypass.attacks.base import AttackContext
from core.bypass.attacks.metadata import (
    AttackMetadata,
    AttackCategories,
    ValidationResult,
    RegistrationPriority,
    AttackEntry,
    RegistrationResult,
    create_attack_metadata,
)
from core.bypass.techniques.primitives import BypassTechniques


class TestBuiltinAttackRegistration:
    """Test builtin attack registration with CORE priority."""

    def setup_method(self):
        """Setup before each test."""
        clear_registry(clear_config=True)
        self.registry = AttackRegistry()

    def teardown_method(self):
        """Cleanup after each test."""
        clear_registry(clear_config=True)

    def test_all_builtin_attacks_registered_with_core_priority(self):
        """Verify all builtin attacks register with CORE priority."""
        expected_builtin_attacks = [
            "fakeddisorder",
            "seqovl", 
            "multidisorder",
            "disorder",
            "disorder2",
            "multisplit",
            "split",
            "fake",
        ]

        for attack_type in expected_builtin_attacks:
            assert attack_type in self.registry.attacks, f"Builtin attack {attack_type} not registered"
            
            entry = self.registry.attacks[attack_type]
            assert entry.priority == RegistrationPriority.CORE, (
                f"Builtin attack {attack_type} should have CORE priority, "
                f"but has {entry.priority}"
            )
            assert entry.is_canonical is True, f"Builtin attack {attack_type} should be canonical"
            assert entry.handler is not None, f"Builtin attack {attack_type} has no handler"
            assert entry.metadata is not None, f"Builtin attack {attack_type} has no metadata"

    def test_core_attacks_cannot_be_overridden_by_normal_priority(self):
        """Test that CORE attacks cannot be overridden by NORMAL priority."""
        
        def fake_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_fake", 0, {"fake": True})]

        fake_metadata = create_attack_metadata(
            name="Fake Disorder Override",
            description="Attempt to override core fakeddisorder",
            category=AttackCategories.FAKE,
            required_params=["split_pos"],
        )

        # Verify fakeddisorder is registered as CORE
        assert "fakeddisorder" in self.registry.attacks
        original_entry = self.registry.attacks["fakeddisorder"]
        assert original_entry.priority == RegistrationPriority.CORE

        # Attempt to register with NORMAL priority (should fail)
        result = self.registry.register_attack(
            "fakeddisorder",
            fake_handler,
            fake_metadata,
            priority=RegistrationPriority.NORMAL
        )

        assert result.success is False
        assert result.action == "skipped"
        assert "lower priority" in result.message.lower()

        # Verify original handler is still there
        current_entry = self.registry.attacks["fakeddisorder"]
        assert current_entry.handler == original_entry.handler
        assert current_entry.priority == RegistrationPriority.CORE

    def test_core_attacks_cannot_be_overridden_by_high_priority(self):
        """Test that CORE attacks cannot be overridden by HIGH priority."""
        
        def improved_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_improved", 0, {"improved": True})]

        improved_metadata = create_attack_metadata(
            name="Improved Seqovl",
            description="Attempt to override core seqovl with HIGH priority",
            category=AttackCategories.OVERLAP,
            required_params=["split_pos", "overlap_size"],
        )

        # Verify seqovl is registered as CORE
        assert "seqovl" in self.registry.attacks
        original_entry = self.registry.attacks["seqovl"]
        assert original_entry.priority == RegistrationPriority.CORE

        # Attempt to register with HIGH priority (should fail)
        result = self.registry.register_attack(
            "seqovl",
            improved_handler,
            improved_metadata,
            priority=RegistrationPriority.HIGH
        )

        assert result.success is False
        assert result.action == "skipped"
        assert "lower priority" in result.message.lower()

        # Verify original handler is still there
        current_entry = self.registry.attacks["seqovl"]
        assert current_entry.handler == original_entry.handler
        assert current_entry.priority == RegistrationPriority.CORE

    def test_builtin_attacks_have_proper_metadata(self):
        """Test that builtin attacks have proper metadata structure."""
        builtin_attacks = [
            "fakeddisorder", "seqovl", "multidisorder", "disorder", 
            "disorder2", "multisplit", "split", "fake"
        ]

        for attack_type in builtin_attacks:
            entry = self.registry.attacks[attack_type]
            metadata = entry.metadata

            # Check required fields
            assert metadata.name, f"{attack_type} missing name"
            assert metadata.description, f"{attack_type} missing description"
            assert isinstance(metadata.required_params, list), f"{attack_type} required_params not list"
            assert isinstance(metadata.optional_params, dict), f"{attack_type} optional_params not dict"
            assert isinstance(metadata.aliases, list), f"{attack_type} aliases not list"
            assert metadata.category in AttackCategories.ALL, f"{attack_type} invalid category"

    def test_builtin_attacks_source_module(self):
        """Test that builtin attacks are registered from primitives module."""
        builtin_attacks = [
            "fakeddisorder", "seqovl", "multidisorder", "disorder", 
            "disorder2", "multisplit", "split", "fake"
        ]

        for attack_type in builtin_attacks:
            entry = self.registry.attacks[attack_type]
            # Builtin attacks should be registered from attack_registry module
            # (which loads them from primitives)
            assert "attack_registry" in entry.source_module, (
                f"{attack_type} should be registered from attack_registry module, "
                f"but source is {entry.source_module}"
            )


class TestAliasResolutionSystem:
    """Test alias resolution system."""

    def setup_method(self):
        """Setup before each test."""
        clear_registry(clear_config=True)
        self.registry = AttackRegistry()

    def teardown_method(self):
        """Cleanup after each test."""
        clear_registry(clear_config=True)

    def test_all_builtin_aliases_resolve_correctly(self):
        """Verify all builtin aliases resolve to canonical names correctly."""
        # Known aliases for builtin attacks
        expected_aliases = {
            "fake_disorder": "fakeddisorder",
            "fakedisorder": "fakeddisorder",
            "seq_ovl": "seqovl",
            "sequence_overlap": "seqovl",
            "multi_disorder": "multidisorder",
            "multi_split": "multisplit",
        }

        for alias, canonical in expected_aliases.items():
            if alias in self.registry._aliases:
                resolved = self.registry._resolve_attack_type(alias)
                assert resolved == canonical, (
                    f"Alias '{alias}' should resolve to '{canonical}', "
                    f"but resolves to '{resolved}'"
                )

                # Test handler resolution through alias
                canonical_handler = self.registry.get_attack_handler(canonical)
                alias_handler = self.registry.get_attack_handler(alias)
                assert alias_handler == canonical_handler, (
                    f"Alias '{alias}' handler should match canonical '{canonical}' handler"
                )

    def test_alias_conflicts_resolution(self):
        """Test alias conflicts and resolution."""
        
        def handler1(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_1", 0, {"version": 1})]

        def handler2(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_2", 0, {"version": 2})]

        metadata1 = create_attack_metadata(
            name="Test Attack 1",
            description="First test attack",
            category=AttackCategories.CUSTOM,
            aliases=["test_alias", "shared_alias"]
        )

        metadata2 = create_attack_metadata(
            name="Test Attack 2", 
            description="Second test attack",
            category=AttackCategories.CUSTOM,
            aliases=["test_alias2", "shared_alias"]  # Conflicting alias
        )

        # Register first attack
        result1 = self.registry.register_attack("test_attack_1", handler1, metadata1)
        assert result1.success is True

        # Register second attack with conflicting alias
        with patch("logging.Logger.warning") as mock_warning:
            result2 = self.registry.register_attack("test_attack_2", handler2, metadata2)
            assert result2.success is True
            
            # Should have warning about alias conflict
            mock_warning.assert_called()
            warning_msg = mock_warning.call_args[0][0]
            assert "shared_alias" in warning_msg
            assert "already exists" in warning_msg

        # The last registered attack should win the alias
        assert self.registry._aliases["shared_alias"] == "test_attack_2"
        handler_via_alias = self.registry.get_attack_handler("shared_alias")
        assert handler_via_alias == handler2

    def test_alias_resolution_with_nonexistent_canonical(self):
        """Test alias resolution when canonical attack doesn't exist."""
        # Manually add a broken alias (should not happen in normal operation)
        self.registry._aliases["broken_alias"] = "nonexistent_attack"

        resolved = self.registry._resolve_attack_type("broken_alias")
        assert resolved == "nonexistent_attack"  # Should return the target even if it doesn't exist

        handler = self.registry.get_attack_handler("broken_alias")
        assert handler is None  # Should return None for nonexistent target

    def test_circular_alias_prevention(self):
        """Test prevention of circular alias references."""
        # This test ensures the system doesn't create circular references
        # In the current implementation, aliases point directly to canonical names
        
        def test_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload, 0, {})]

        metadata = create_attack_metadata(
            name="Test Attack",
            description="Test attack for circular alias test",
            category=AttackCategories.CUSTOM,
            aliases=["alias1", "alias2"]
        )

        self.registry.register_attack("canonical_attack", test_handler, metadata)

        # Both aliases should point to canonical, not to each other
        assert self.registry._aliases["alias1"] == "canonical_attack"
        assert self.registry._aliases["alias2"] == "canonical_attack"

        # Resolution should work correctly
        assert self.registry._resolve_attack_type("alias1") == "canonical_attack"
        assert self.registry._resolve_attack_type("alias2") == "canonical_attack"


class TestPrioritySystemEdgeCases:
    """Test priority system edge cases."""

    def setup_method(self):
        """Setup before each test."""
        clear_registry(clear_config=True)
        self.registry = AttackRegistry()

    def teardown_method(self):
        """Cleanup after each test."""
        clear_registry(clear_config=True)

    def test_promotion_from_low_to_high_priority(self):
        """Test promotion from LOW to HIGH priority."""
        
        def low_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_low", 0, {"priority": "low"})]

        def high_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_high", 0, {"priority": "high"})]

        low_metadata = create_attack_metadata(
            name="Low Priority Attack",
            description="Attack with low priority",
            category=AttackCategories.CUSTOM,
        )

        high_metadata = create_attack_metadata(
            name="High Priority Attack",
            description="Improved attack with high priority",
            category=AttackCategories.CUSTOM,
        )

        # Register with LOW priority first
        result1 = self.registry.register_attack(
            "test_promotion", low_handler, low_metadata, RegistrationPriority.LOW
        )
        assert result1.success is True
        assert result1.action == "registered"

        # Verify LOW priority registration
        entry = self.registry.attacks["test_promotion"]
        assert entry.priority == RegistrationPriority.LOW
        assert entry.handler == low_handler

        # Register with HIGH priority (should replace)
        result2 = self.registry.register_attack(
            "test_promotion", high_handler, high_metadata, RegistrationPriority.HIGH
        )
        assert result2.success is True
        assert result2.action == "replaced"
        assert result2.previous_priority == RegistrationPriority.LOW
        assert result2.new_priority == RegistrationPriority.HIGH

        # Verify HIGH priority replacement
        entry = self.registry.attacks["test_promotion"]
        assert entry.priority == RegistrationPriority.HIGH
        assert entry.handler == high_handler

    def test_rejection_of_normal_over_core_priority(self):
        """Test rejection of NORMAL over CORE priority."""
        # This is already tested in TestBuiltinAttackRegistration, but we'll test it more thoroughly
        
        def normal_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_normal", 0, {"priority": "normal"})]

        normal_metadata = create_attack_metadata(
            name="Normal Priority Override",
            description="Attempt to override CORE with NORMAL",
            category=AttackCategories.FAKE,
        )

        # Try to override multiple CORE attacks
        core_attacks = ["fakeddisorder", "seqovl", "multidisorder"]
        
        for attack_type in core_attacks:
            original_entry = self.registry.attacks[attack_type]
            assert original_entry.priority == RegistrationPriority.CORE

            result = self.registry.register_attack(
                attack_type, normal_handler, normal_metadata, RegistrationPriority.NORMAL
            )

            assert result.success is False
            assert result.action == "skipped"
            assert "lower priority" in result.message.lower()

            # Verify no change
            current_entry = self.registry.attacks[attack_type]
            assert current_entry.handler == original_entry.handler
            assert current_entry.priority == RegistrationPriority.CORE

    def test_equal_priority_conflict_handling(self):
        """Test equal priority conflict handling."""
        
        def handler1(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_first", 0, {"order": "first"})]

        def handler2(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_second", 0, {"order": "second"})]

        metadata1 = create_attack_metadata(
            name="First Attack",
            description="First attack with NORMAL priority",
            category=AttackCategories.CUSTOM,
        )

        metadata2 = create_attack_metadata(
            name="Second Attack",
            description="Second attack with same NORMAL priority",
            category=AttackCategories.CUSTOM,
        )

        # Register first attack
        result1 = self.registry.register_attack(
            "equal_priority_test", handler1, metadata1, RegistrationPriority.NORMAL
        )
        assert result1.success is True
        assert result1.action == "registered"

        # Register second attack with same priority (should be skipped)
        with patch("logging.Logger.warning") as mock_warning:
            result2 = self.registry.register_attack(
                "equal_priority_test", handler2, metadata2, RegistrationPriority.NORMAL
            )
            assert result2.success is False
            assert result2.action == "skipped"
            assert "same priority" in result2.message.lower()

            # Should have warning
            mock_warning.assert_called()

        # First handler should remain
        entry = self.registry.attacks["equal_priority_test"]
        assert entry.handler == handler1
        assert entry.priority == RegistrationPriority.NORMAL

    def test_priority_ordering_validation(self):
        """Test that priority ordering works correctly."""
        priorities = [
            RegistrationPriority.LOW,
            RegistrationPriority.NORMAL, 
            RegistrationPriority.HIGH,
            RegistrationPriority.CORE
        ]

        # Verify enum values are in correct order
        for i in range(len(priorities) - 1):
            assert priorities[i].value < priorities[i + 1].value, (
                f"Priority ordering incorrect: {priorities[i]} should be less than {priorities[i + 1]}"
            )

    def test_priority_based_replacement_chain(self):
        """Test a chain of priority-based replacements."""
        
        def low_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_low", 0, {"level": "low"})]

        def normal_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_normal", 0, {"level": "normal"})]

        def high_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            return [(context.payload + b"_high", 0, {"level": "high"})]

        base_metadata = create_attack_metadata(
            name="Priority Chain Test",
            description="Test priority replacement chain",
            category=AttackCategories.CUSTOM,
        )

        attack_name = "priority_chain_test"

        # Start with LOW
        result1 = self.registry.register_attack(
            attack_name, low_handler, base_metadata, RegistrationPriority.LOW
        )
        assert result1.success is True
        assert self.registry.attacks[attack_name].handler == low_handler

        # Upgrade to NORMAL
        result2 = self.registry.register_attack(
            attack_name, normal_handler, base_metadata, RegistrationPriority.NORMAL
        )
        assert result2.success is True
        assert result2.action == "replaced"
        assert self.registry.attacks[attack_name].handler == normal_handler

        # Upgrade to HIGH
        result3 = self.registry.register_attack(
            attack_name, high_handler, base_metadata, RegistrationPriority.HIGH
        )
        assert result3.success is True
        assert result3.action == "replaced"
        assert self.registry.attacks[attack_name].handler == high_handler

        # Try to downgrade to NORMAL (should fail)
        result4 = self.registry.register_attack(
            attack_name, normal_handler, base_metadata, RegistrationPriority.NORMAL
        )
        assert result4.success is False
        assert result4.action == "skipped"
        assert self.registry.attacks[attack_name].handler == high_handler  # Should remain HIGH


if __name__ == "__main__":
    pytest.main([__file__, "-v"])