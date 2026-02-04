"""Test registry decorator queue functionality."""

import pytest
from core.bypass.attacks.registry.decorator import (
    register_attack,
    get_pending_registrations,
    clear_pending_registrations,
    process_pending_registrations,
)
from core.bypass.attacks.registry.models import RegistrationPriority


class StubRegistry:
    """Stub registry for testing."""

    def __init__(self):
        self.calls = []

    def register_attack(self, **kwargs):
        self.calls.append(kwargs)

        class Result:
            success = True
            message = "ok"

        return Result()


def test_decorator_with_none_name():
    """Test that decorator with name=None uses class name."""
    clear_pending_registrations()

    @register_attack(name=None)
    class TestAttack:
        """Test attack class"""

        pass

    pending = get_pending_registrations()
    assert len(pending) == 1
    assert pending[0]["attack_type"] == "TestAttack"
    assert pending[0]["attack_type"] is not None
    assert pending[0]["metadata"].name == "TestAttack"


def test_decorator_with_explicit_name():
    """Test that decorator with explicit name works."""
    clear_pending_registrations()

    @register_attack(name="custom_attack")
    class AnotherAttack:
        """Another test attack"""

        pass

    pending = get_pending_registrations()

    assert len(pending) == 1
    assert pending[0]["attack_type"] == "custom_attack"


def test_process_pending_registrations():
    """Test that process_pending_registrations works and clears queue."""
    clear_pending_registrations()

    @register_attack(name="test_process")
    class ProcessTestAttack:
        """Process test attack"""

        def execute(self, context):
            return []

    stub_registry = StubRegistry()
    registered = process_pending_registrations(stub_registry)

    assert registered == 1
    assert len(stub_registry.calls) == 1
    assert stub_registry.calls[0]["attack_type"] == "test_process"
    assert len(get_pending_registrations()) == 0  # Queue cleared
