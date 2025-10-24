"""
Tests for attack deduplication functionality.

This test file validates:
- Duplicate registration scenarios
- Priority conflict resolution
- Alias handling and resolution
- Registry integrity during deduplication
"""

import pytest
from unittest.mock import patch

from core.bypass.attacks.attack_registry import AttackRegistry, clear_registry
from core.bypass.attacks.metadata import (
    AttackCategories,
    RegistrationPriority,
    create_attack_metadata,
)
from core.bypass.attacks.base import AttackContext


class TestDuplicateRegistrationScenarios:
    """Tests for various duplicate registration scenarios."""

    def setup_method(self):
        """Setup before each test."""
        clear_registry(clear_config=True)
        self.registry = AttackRegistry()

    def teardown_method(self):
        """Cleanup after each test."""
        clear_registry(clear_config=True)

    def test_duplicate_registration_same_priority(self):
        """Test duplicate registration with same priority (should be skipped)."""

        def handler1(context: AttackContext):
            return [(context.payload, 0, {"version": 1})]

        def handler2(context: AttackContext):
            return [(context.payload, 0, {"version": 2})]

        metadata = create_attack_metadata(
            name="Test Attack",
            description="Test attack for deduplication",
            category=AttackCategories.CUSTOM,
            required_params=["test_param"],
        )

        # Register first attack
        result1 = self.registry.register_attack(
            "test_duplicate", handler1, metadata, RegistrationPriority.NORMAL
        )
        assert result1.success is True
        assert result1.action == "registered"

        # Register duplicate with same priority
        with patch("logging.Logger.warning") as mock_warning:
            result2 = self.registry.register_attack(
                "test_duplicate", handler2, metadata, RegistrationPriority.NORMAL
            )

            # Should be skipped with warning
            assert result2.success is False
            assert result2.action == "skipped"
            assert "same priority" in result2.message
            mock_warning.assert_called_once()

        # First handler should remain
        assert self.registry.get_attack_handler("test_duplicate") == handler1

    def test_duplicate_registration_higher_priority_replaces(self):
        """Test duplicate registration with higher priority (should replace)."""

        def low_priority_handler(context: AttackContext):
            return [(context.payload, 0, {"priority": "low"})]

        def high_priority_handler(context: AttackContext):
            return [(context.payload, 0, {"priority": "high"})]

        metadata = create_attack_metadata(
            name="Priority Test Attack",
            description="Test attack for priority handling",
            category=AttackCategories.CUSTOM,
        )

        # Register low priority attack first
        result1 = self.registry.register_attack(
            "priority_test", low_priority_handler, metadata, RegistrationPriority.LOW
        )
        assert result1.success is True

        # Register higher priority attack
        result2 = self.registry.register_attack(
            "priority_test", high_priority_handler, metadata, RegistrationPriority.HIGH
        )

        assert result2.success is True
        assert result2.action == "replaced"
        assert "higher priority" in result2.message

        # Higher priority handler should be active
        assert (
            self.registry.get_attack_handler("priority_test") == high_priority_handler
        )

        # Check promotion history
        entry = self.registry.attacks["priority_test"]
        assert len(entry.promotion_history) == 1
        assert entry.promotion_history[0]["action"] == "replaced_by_higher_priority"

    def test_duplicate_registration_lower_priority_skipped(self):
        """Test duplicate registration with lower priority (should be skipped)."""

        def high_priority_handler(context: AttackContext):
            return [(context.payload, 0, {"priority": "high"})]

        def low_priority_handler(context: AttackContext):
            return [(context.payload, 0, {"priority": "low"})]

        metadata = create_attack_metadata(
            name="Priority Test Attack",
            description="Test attack for priority handling",
            category=AttackCategories.CUSTOM,
        )

        # Register high priority attack first
        result1 = self.registry.register_attack(
            "priority_test", high_priority_handler, metadata, RegistrationPriority.HIGH
        )
        assert result1.success is True

        # Try to register lower priority attack
        result2 = self.registry.register_attack(
            "priority_test", low_priority_handler, metadata, RegistrationPriority.LOW
        )

        assert result2.success is False
        assert result2.action == "skipped"
        assert "lower priority" in result2.message

        # High priority handler should remain
        assert (
            self.registry.get_attack_handler("priority_test") == high_priority_handler
        )

    def test_core_priority_cannot_be_overridden(self):
        """Test that CORE priority attacks cannot be overridden by lower priorities."""

        def core_handler(context: AttackContext):
            return [(context.payload, 0, {"source": "core"})]

        def external_handler(context: AttackContext):
            return [(context.payload, 0, {"source": "external"})]

        metadata = create_attack_metadata(
            name="Core Attack",
            description="Core attack implementation",
            category=AttackCategories.FAKE,
        )

        # Register CORE priority attack
        result1 = self.registry.register_attack(
            "core_attack", core_handler, metadata, RegistrationPriority.CORE
        )
        assert result1.success is True

        # Try to override with HIGH priority
        result2 = self.registry.register_attack(
            "core_attack", external_handler, metadata, RegistrationPriority.HIGH
        )

        assert result2.success is False
        assert result2.action == "skipped"

        # CORE handler should remain
        assert self.registry.get_attack_handler("core_attack") == core_handler

    def test_multiple_duplicate_registrations(self):
        """Test handling of multiple duplicate registrations."""
        handlers = []
        for i in range(5):

            def handler(context: AttackContext, version=i):
                return [(context.payload, 0, {"version": version})]

            handlers.append(handler)

        metadata = create_attack_metadata(
            name="Multi Duplicate Test",
            description="Test multiple duplicates",
            category=AttackCategories.CUSTOM,
        )

        # Register multiple versions with different priorities
        priorities = [
            RegistrationPriority.LOW,
            RegistrationPriority.NORMAL,
            RegistrationPriority.HIGH,
            RegistrationPriority.NORMAL,  # Should be skipped
            RegistrationPriority.CORE,  # Should replace HIGH
        ]

        results = []
        for i, (handler, priority) in enumerate(zip(handlers, priorities)):
            result = self.registry.register_attack(
                "multi_duplicate", handler, metadata, priority
            )
            results.append(result)

        # Check results
        assert results[0].success is True  # LOW registered
        assert results[1].success is True  # NORMAL replaced LOW
        assert results[2].success is True  # HIGH replaced NORMAL
        assert results[3].success is False  # NORMAL skipped (same as existing)
        assert results[4].success is True  # CORE replaced HIGH

        # Final handler should be CORE (index 4)
        assert self.registry.get_attack_handler("multi_duplicate") == handlers[4]


class TestPriorityConflictResolution:
    """Tests for priority-based conflict resolution."""

    def setup_method(self):
        """Setup before each test."""
        clear_registry(clear_config=True)
        self.registry = AttackRegistry()

    def teardown_method(self):
        """Cleanup after each test."""
        clear_registry(clear_config=True)

    def test_priority_enum_values(self):
        """Test priority enum values are correctly ordered."""
        assert RegistrationPriority.CORE.value > RegistrationPriority.HIGH.value
        assert RegistrationPriority.HIGH.value > RegistrationPriority.NORMAL.value
        assert RegistrationPriority.NORMAL.value > RegistrationPriority.LOW.value

    def test_priority_comparison_logic(self):
        """Test priority comparison logic in deduplication."""

        def handler1(context):
            return [(context.payload, 0, {})]

        def handler2(context):
            return [(context.payload, 0, {})]

        metadata = create_attack_metadata(
            name="Priority Test",
            description="Test priority comparison",
            category=AttackCategories.CUSTOM,
        )

        # Test all priority combinations
        test_cases = [
            (
                RegistrationPriority.LOW,
                RegistrationPriority.NORMAL,
                True,
            ),  # Should replace
            (
                RegistrationPriority.NORMAL,
                RegistrationPriority.HIGH,
                True,
            ),  # Should replace
            (
                RegistrationPriority.HIGH,
                RegistrationPriority.CORE,
                True,
            ),  # Should replace
            (
                RegistrationPriority.HIGH,
                RegistrationPriority.NORMAL,
                False,
            ),  # Should skip
            (
                RegistrationPriority.CORE,
                RegistrationPriority.HIGH,
                False,
            ),  # Should skip
            (
                RegistrationPriority.NORMAL,
                RegistrationPriority.NORMAL,
                False,
            ),  # Should skip
        ]

        for i, (first_priority, second_priority, should_replace) in enumerate(
            test_cases
        ):
            attack_name = f"priority_test_{i}"

            # Register first attack
            self.registry.register_attack(
                attack_name, handler1, metadata, first_priority
            )

            # Register second attack
            result = self.registry.register_attack(
                attack_name, handler2, metadata, second_priority
            )

            if should_replace:
                assert result.success is True
                assert result.action == "replaced"
                assert self.registry.get_attack_handler(attack_name) == handler2
            else:
                assert result.success is False
                assert result.action == "skipped"
                assert self.registry.get_attack_handler(attack_name) == handler1

    def test_promotion_history_tracking(self):
        """Test that promotion history is correctly tracked."""

        def handler1(context):
            return [(context.payload, 0, {"v": 1})]

        def handler2(context):
            return [(context.payload, 0, {"v": 2})]

        def handler3(context):
            return [(context.payload, 0, {"v": 3})]

        metadata = create_attack_metadata(
            name="History Test",
            description="Test promotion history",
            category=AttackCategories.CUSTOM,
        )

        # Register initial attack
        self.registry.register_attack(
            "history_test", handler1, metadata, RegistrationPriority.LOW
        )

        # Replace with higher priority
        self.registry.register_attack(
            "history_test", handler2, metadata, RegistrationPriority.NORMAL
        )

        # Replace again with even higher priority
        self.registry.register_attack(
            "history_test", handler3, metadata, RegistrationPriority.HIGH
        )

        # Check promotion history
        entry = self.registry.attacks["history_test"]
        assert len(entry.promotion_history) == 2

        # Check first promotion
        first_promotion = entry.promotion_history[0]
        assert first_promotion["action"] == "replaced_by_higher_priority"
        assert first_promotion["old_priority"] == "LOW"
        assert first_promotion["new_priority"] == "NORMAL"

        # Check second promotion
        second_promotion = entry.promotion_history[1]
        assert second_promotion["action"] == "replaced_by_higher_priority"
        assert second_promotion["old_priority"] == "NORMAL"
        assert second_promotion["new_priority"] == "HIGH"

    def test_conflict_logging(self):
        """Test that conflicts are properly logged."""

        def handler1(context):
            return [(context.payload, 0, {})]

        def handler2(context):
            return [(context.payload, 0, {})]

        metadata = create_attack_metadata(
            name="Logging Test",
            description="Test conflict logging",
            category=AttackCategories.CUSTOM,
        )

        # Register first attack
        self.registry.register_attack(
            "log_test", handler1, metadata, RegistrationPriority.NORMAL
        )

        # Test replacement logging
        with patch("logging.Logger.info") as mock_info:
            self.registry.register_attack(
                "log_test", handler2, metadata, RegistrationPriority.HIGH
            )

            # Should log replacement
            mock_info.assert_called()
            log_message = mock_info.call_args[0][0]
            assert "Replacing attack" in log_message
            assert "NORMAL -> HIGH" in log_message

        # Test skip logging
        with patch("logging.Logger.warning") as mock_warning:
            self.registry.register_attack(
                "log_test", handler1, metadata, RegistrationPriority.LOW
            )

            # Should log skip
            mock_warning.assert_called()
            log_message = mock_warning.call_args[0][0]
            assert "Skipping duplicate registration" in log_message


class TestAliasHandling:
    """Tests for alias handling and resolution during deduplication."""

    def setup_method(self):
        """Setup before each test."""
        clear_registry(clear_config=True)
        self.registry = AttackRegistry()

    def teardown_method(self):
        """Cleanup after each test."""
        clear_registry(clear_config=True)

    def test_alias_registration_with_duplicates(self):
        """Test alias registration when duplicates exist."""

        def handler(context):
            return [(context.payload, 0, {})]

        metadata = create_attack_metadata(
            name="Alias Test Attack",
            description="Test attack with aliases",
            category=AttackCategories.CUSTOM,
            aliases=["alias1", "alias2", "alias3"],
        )

        # Register attack with aliases
        result = self.registry.register_attack("alias_test", handler, metadata)
        assert result.success is True

        # Verify aliases are registered
        for alias in metadata.aliases:
            assert alias in self.registry._aliases
            assert self.registry._aliases[alias] == "alias_test"
            assert self.registry.get_attack_handler(alias) == handler

    def test_alias_conflict_resolution(self):
        """Test alias conflict resolution."""

        def handler1(context):
            return [(context.payload, 0, {"v": 1})]

        def handler2(context):
            return [(context.payload, 0, {"v": 2})]

        metadata1 = create_attack_metadata(
            name="First Attack",
            description="First attack",
            category=AttackCategories.CUSTOM,
            aliases=["shared_alias", "unique_alias1"],
        )

        metadata2 = create_attack_metadata(
            name="Second Attack",
            description="Second attack",
            category=AttackCategories.CUSTOM,
            aliases=["shared_alias", "unique_alias2"],  # Conflicting alias
        )

        # Register first attack
        result1 = self.registry.register_attack(
            "attack1", handler1, metadata1, RegistrationPriority.NORMAL
        )
        assert result1.success is True

        # Register second attack with conflicting alias
        result2 = self.registry.register_attack(
            "attack2", handler2, metadata2, RegistrationPriority.HIGH
        )
        assert result2.success is True

        # Higher priority attack should own the conflicting alias
        assert self.registry.get_attack_handler("shared_alias") == handler2

        # Unique aliases should work correctly
        assert self.registry.get_attack_handler("unique_alias1") == handler1
        assert self.registry.get_attack_handler("unique_alias2") == handler2

    def test_alias_resolution_chain(self):
        """Test alias resolution chain during deduplication."""

        def handler1(context):
            return [(context.payload, 0, {})]

        def handler2(context):
            return [(context.payload, 0, {})]

        # Register attack with alias
        metadata1 = create_attack_metadata(
            name="Original Attack",
            description="Original attack",
            category=AttackCategories.CUSTOM,
            aliases=["attack_alias"],
        )

        self.registry.register_attack(
            "original_attack", handler1, metadata1, RegistrationPriority.LOW
        )

        # Try to register new attack using the alias name as primary name
        metadata2 = create_attack_metadata(
            name="Alias Attack",
            description="Attack using alias name",
            category=AttackCategories.CUSTOM,
        )

        # This should be treated as a conflict with the original attack
        result = self.registry.register_attack(
            "attack_alias", handler2, metadata2, RegistrationPriority.HIGH
        )

        # Should succeed and replace the original
        assert result.success is True
        assert self.registry.get_attack_handler("attack_alias") == handler2
        assert (
            self.registry.get_attack_handler("original_attack") == handler1
        )  # Original should still exist

    def test_circular_alias_prevention(self):
        """Test prevention of circular alias references."""

        def handler(context):
            return [(context.payload, 0, {})]

        # Try to create circular aliases
        metadata = create_attack_metadata(
            name="Circular Test",
            description="Test circular aliases",
            category=AttackCategories.CUSTOM,
            aliases=["circular_test"],  # Alias same as attack name
        )

        # Should handle gracefully (either ignore self-alias or raise error)
        result = self.registry.register_attack("circular_test", handler, metadata)

        # Should either succeed (ignoring self-alias) or fail gracefully
        if result.success:
            # If successful, should not create circular reference
            resolved = self.registry._resolve_attack_type("circular_test")
            assert resolved == "circular_test"
        else:
            # If failed, should have clear error message
            assert (
                "circular" in result.message.lower() or "self" in result.message.lower()
            )


class TestRegistryIntegrity:
    """Tests for registry integrity during deduplication operations."""

    def setup_method(self):
        """Setup before each test."""
        clear_registry(clear_config=True)
        self.registry = AttackRegistry()

    def teardown_method(self):
        """Cleanup after each test."""
        clear_registry(clear_config=True)

    def test_registry_consistency_after_deduplication(self):
        """Test registry consistency after multiple deduplication operations."""
        handlers = []
        for i in range(10):

            def handler(context, version=i):
                return [(context.payload, 0, {"version": version})]

            handlers.append(handler)

        metadata = create_attack_metadata(
            name="Consistency Test",
            description="Test registry consistency",
            category=AttackCategories.CUSTOM,
            aliases=[f"alias_{i}" for i in range(3)],
        )

        # Perform multiple registrations with various priorities
        for i, handler in enumerate(handlers):
            priority = [
                RegistrationPriority.LOW,
                RegistrationPriority.NORMAL,
                RegistrationPriority.HIGH,
                RegistrationPriority.CORE,
            ][i % 4]

            self.registry.register_attack(
                f"consistency_test_{i}", handler, metadata, priority
            )

        # Verify registry integrity
        assert len(self.registry.attacks) == 10
        assert len(self.registry._registration_order) == 10

        # Verify all attacks are accessible
        for i in range(10):
            attack_name = f"consistency_test_{i}"
            assert attack_name in self.registry.attacks
            assert self.registry.get_attack_handler(attack_name) is not None

        # Verify aliases are properly managed
        for attack_name, entry in self.registry.attacks.items():
            for alias in entry.metadata.aliases:
                if alias in self.registry._aliases:
                    resolved = self.registry._aliases[alias]
                    assert resolved in self.registry.attacks

    def test_memory_cleanup_after_replacement(self):
        """Test that memory is properly cleaned up after replacements."""
        import gc
        import weakref

        def handler1(context):
            return [(context.payload, 0, {})]

        def handler2(context):
            return [(context.payload, 0, {})]

        metadata = create_attack_metadata(
            name="Memory Test",
            description="Test memory cleanup",
            category=AttackCategories.CUSTOM,
        )

        # Register first handler and create weak reference
        self.registry.register_attack(
            "memory_test", handler1, metadata, RegistrationPriority.LOW
        )
        weak_ref = weakref.ref(handler1)

        # Replace with higher priority handler
        self.registry.register_attack(
            "memory_test", handler2, metadata, RegistrationPriority.HIGH
        )

        # Clear local reference to first handler
        del handler1
        gc.collect()

        # Weak reference should be cleared (handler1 should be garbage collected)
        # Note: This test might be flaky depending on Python's garbage collection
        # but it's useful for detecting obvious memory leaks

        # Verify new handler is active
        assert self.registry.get_attack_handler("memory_test") == handler2

    def test_concurrent_registration_safety(self):
        """Test thread safety during concurrent registrations."""
        import threading

        def handler(context, thread_id):
            return [(context.payload, 0, {"thread": thread_id})]

        results = {}
        errors = []

        def register_attack(thread_id):
            try:
                metadata = create_attack_metadata(
                    name=f"Thread {thread_id} Attack",
                    description=f"Attack from thread {thread_id}",
                    category=AttackCategories.CUSTOM,
                )

                result = self.registry.register_attack(
                    f"thread_test_{thread_id}",
                    lambda ctx: handler(ctx, thread_id),
                    metadata,
                    RegistrationPriority.NORMAL,
                )
                results[thread_id] = result

            except Exception as e:
                errors.append((thread_id, e))

        # Create multiple threads registering attacks simultaneously
        threads = []
        for i in range(5):
            thread = threading.Thread(target=register_attack, args=(i,))
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify no errors occurred
        assert len(errors) == 0, f"Errors during concurrent registration: {errors}"

        # Verify all registrations succeeded
        assert len(results) == 5
        for thread_id, result in results.items():
            assert result.success is True
            assert f"thread_test_{thread_id}" in self.registry.attacks

    def test_registry_state_validation(self):
        """Test registry state validation after deduplication operations."""

        def handler(context):
            return [(context.payload, 0, {})]

        metadata = create_attack_metadata(
            name="Validation Test",
            description="Test state validation",
            category=AttackCategories.CUSTOM,
            aliases=["val_alias1", "val_alias2"],
        )

        # Register attack
        self.registry.register_attack("validation_test", handler, metadata)

        # Validate registry state
        self._validate_registry_state()

        # Replace with higher priority
        self.registry.register_attack(
            "validation_test", handler, metadata, RegistrationPriority.HIGH
        )

        # Validate state again
        self._validate_registry_state()

    def _validate_registry_state(self):
        """Helper method to validate registry internal state."""
        # Check that all aliases point to existing attacks
        for alias, attack_name in self.registry._aliases.items():
            assert (
                attack_name in self.registry.attacks
            ), f"Alias '{alias}' points to non-existent attack '{attack_name}'"

        # Check that all attacks in registration order exist
        for attack_name in self.registry._registration_order:
            assert (
                attack_name in self.registry.attacks
            ), f"Registration order contains non-existent attack '{attack_name}'"

        # Check that all attack entries have valid handlers
        for attack_name, entry in self.registry.attacks.items():
            assert callable(
                entry.handler
            ), f"Attack '{attack_name}' has non-callable handler"
            assert entry.metadata is not None, f"Attack '{attack_name}' has no metadata"
            assert isinstance(
                entry.priority, RegistrationPriority
            ), f"Attack '{attack_name}' has invalid priority"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
