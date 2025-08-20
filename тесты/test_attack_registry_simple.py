# recon/core/bypass/attacks/test_attack_registry_simple.py

"""
Simple unit tests for the modernized attack registry infrastructure.
These tests avoid complex legacy registry interactions to prevent hanging.
"""

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from .attack_definition import (
    AttackDefinition,
    AttackCategory,
    AttackComplexity,
    AttackStability,
    TestCase,
)
from .modern_registry import ModernAttackRegistry, TestResult
from .base import BaseAttack, AttackResult, AttackContext, AttackStatus


class MockAttack(BaseAttack):
    """Mock attack class for testing."""

    def __init__(self):
        self.name = "mock_attack"
        self.category = "tcp_fragmentation"

    def execute(self, context: AttackContext) -> AttackResult:
        """Mock execute method."""
        return AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="mock_technique",
            latency_ms=10.0,
        )


class TestAttackDefinitionSimple(unittest.TestCase):
    """Simple test cases for AttackDefinition class."""

    def setUp(self):
        """Set up test fixtures."""
        self.definition = AttackDefinition(
            id="test_attack",
            name="Test Attack",
            description="A test attack for unit testing",
            category=AttackCategory.TCP_FRAGMENTATION,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
        )

    def test_basic_creation(self):
        """Test basic attack definition creation."""
        self.assertEqual(self.definition.id, "test_attack")
        self.assertEqual(self.definition.name, "Test Attack")
        self.assertEqual(self.definition.category, AttackCategory.TCP_FRAGMENTATION)
        self.assertTrue(self.definition.enabled)
        self.assertFalse(self.definition.deprecated)

    def test_score_validation(self):
        """Test that scores are validated to be in range [0.0, 1.0]."""
        definition = AttackDefinition(
            id="test_score",
            name="Score Test",
            description="Test score validation",
            category=AttackCategory.TCP_FRAGMENTATION,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
            stability_score=1.5,  # Invalid - should be clamped to 1.0
            effectiveness_score=-0.5,  # Invalid - should be clamped to 0.0
            performance_score=0.7,  # Valid
        )

        self.assertEqual(definition.stability_score, 1.0)
        self.assertEqual(definition.effectiveness_score, 0.0)
        self.assertEqual(definition.performance_score, 0.7)

    def test_tag_management(self):
        """Test tag addition and removal."""
        self.definition.add_tag("experimental")
        self.assertTrue(self.definition.has_tag("experimental"))

        removed = self.definition.remove_tag("experimental")
        self.assertTrue(removed)
        self.assertFalse(self.definition.has_tag("experimental"))

    def test_overall_score_calculation(self):
        """Test overall score calculation."""
        self.definition.stability_score = 0.8
        self.definition.effectiveness_score = 0.9
        self.definition.performance_score = 0.7

        # Weighted average: stability=0.5, effectiveness=0.3, performance=0.2
        expected_score = 0.8 * 0.5 + 0.9 * 0.3 + 0.7 * 0.2
        self.assertAlmostEqual(
            self.definition.get_overall_score(), expected_score, places=2
        )


class TestModernAttackRegistrySimple(unittest.TestCase):
    """Simple test cases for ModernAttackRegistry class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create temporary storage path
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / "test_registry.json"

        # Mock the legacy registry to prevent hanging
        with patch(
            "recon.core.bypass.attacks.modern_registry.LegacyAttackRegistry"
        ) as mock_legacy:
            mock_legacy.get_all.return_value = {}  # Empty legacy registry

            # Create registry with temporary storage
            self.registry = ModernAttackRegistry(storage_path=self.storage_path)
            self.registry._auto_save = False  # Disable auto-save for tests

        # Create test attack definition
        self.test_definition = AttackDefinition(
            id="test_attack",
            name="Test Attack",
            description="A test attack",
            category=AttackCategory.TCP_FRAGMENTATION,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
        )

        # Add test case
        test_case = TestCase(
            id="basic_test",
            name="Basic Test",
            description="Basic functionality test",
            target_domain="httpbin.org",
            expected_success=True,
        )
        self.test_definition.add_test_case(test_case)

        # Mock attack class
        self.mock_attack_class = MockAttack

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_attack_registration(self):
        """Test attack registration."""
        # Register attack
        success = self.registry.register_attack(
            self.test_definition, self.mock_attack_class
        )
        self.assertTrue(success)

        # Check registration
        definition = self.registry.get_attack_definition("test_attack")
        self.assertIsNotNone(definition)
        self.assertEqual(definition.id, "test_attack")

        attack_class = self.registry.get_attack_class("test_attack")
        self.assertEqual(attack_class, self.mock_attack_class)

    def test_attack_unregistration(self):
        """Test attack unregistration."""
        # Register first
        self.registry.register_attack(self.test_definition, self.mock_attack_class)

        # Unregister
        success = self.registry.unregister_attack("test_attack")
        self.assertTrue(success)

        # Check unregistration
        definition = self.registry.get_attack_definition("test_attack")
        self.assertIsNone(definition)

    def test_attack_listing(self):
        """Test basic attack listing."""
        # Register attack
        self.registry.register_attack(self.test_definition, self.mock_attack_class)

        # Test listing all attacks
        all_attacks = self.registry.list_attacks()
        self.assertIn("test_attack", all_attacks)

        # Test filtering by category
        tcp_attacks = self.registry.list_attacks(
            category=AttackCategory.TCP_FRAGMENTATION
        )
        self.assertIn("test_attack", tcp_attacks)

        # Test filtering by non-matching category
        http_attacks = self.registry.list_attacks(
            category=AttackCategory.HTTP_MANIPULATION
        )
        self.assertNotIn("test_attack", http_attacks)

    def test_attack_enable_disable(self):
        """Test attack enable/disable functionality."""
        # Register attack
        self.registry.register_attack(self.test_definition, self.mock_attack_class)

        # Initially enabled
        definition = self.registry.get_attack_definition("test_attack")
        self.assertTrue(definition.enabled)

        # Disable
        success = self.registry.disable_attack("test_attack", "Test disable")
        self.assertTrue(success)

        definition = self.registry.get_attack_definition("test_attack")
        self.assertFalse(definition.enabled)

        # Enable
        success = self.registry.enable_attack("test_attack")
        self.assertTrue(success)

        definition = self.registry.get_attack_definition("test_attack")
        self.assertTrue(definition.enabled)

    def test_search_functionality(self):
        """Test attack search functionality."""
        # Register attack with searchable content
        attack = AttackDefinition(
            id="searchable_attack",
            name="Searchable Attack",
            description="This attack is for testing search functionality",
            category=AttackCategory.TCP_FRAGMENTATION,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
        )
        attack.add_tag("searchable")

        self.registry.register_attack(attack, self.mock_attack_class)

        # Search by name
        results = self.registry.search_attacks("searchable")
        self.assertIn("searchable_attack", results)

        # Search by description
        results = self.registry.search_attacks("testing search")
        self.assertIn("searchable_attack", results)

        # Search with no matches
        results = self.registry.search_attacks("nonexistent")
        self.assertEqual(len(results), 0)

    def test_statistics(self):
        """Test registry statistics."""
        # Initial stats
        stats = self.registry.get_stats()
        initial_total = stats["total_attacks"]

        # Register attack
        self.registry.register_attack(self.test_definition, self.mock_attack_class)

        # Check updated stats
        stats = self.registry.get_stats()
        self.assertEqual(stats["total_attacks"], initial_total + 1)
        self.assertEqual(stats["enabled_attacks"], initial_total + 1)

    def test_category_indexing(self):
        """Test category-based retrieval."""
        # Register attacks with different categories
        tcp_attack = AttackDefinition(
            id="tcp_test",
            name="TCP Test",
            description="TCP attack",
            category=AttackCategory.TCP_FRAGMENTATION,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
        )

        http_attack = AttackDefinition(
            id="http_test",
            name="HTTP Test",
            description="HTTP attack",
            category=AttackCategory.HTTP_MANIPULATION,
            complexity=AttackComplexity.SIMPLE,
            stability=AttackStability.STABLE,
        )

        self.registry.register_attack(tcp_attack, self.mock_attack_class)
        self.registry.register_attack(http_attack, self.mock_attack_class)

        # Test category-based retrieval
        tcp_attacks = self.registry.get_attacks_by_category(
            AttackCategory.TCP_FRAGMENTATION
        )
        self.assertIn("tcp_test", tcp_attacks)
        self.assertNotIn("http_test", tcp_attacks)

        http_attacks = self.registry.get_attacks_by_category(
            AttackCategory.HTTP_MANIPULATION
        )
        self.assertIn("http_test", http_attacks)
        self.assertNotIn("tcp_test", http_attacks)


class TestTestCase(unittest.TestCase):
    """Test cases for TestCase class."""

    def test_test_case_creation(self):
        """Test basic test case creation."""
        test_case = TestCase(
            id="test_1",
            name="Basic Test",
            description="Basic functionality test",
            target_domain="httpbin.org",
            expected_success=True,
            test_parameters={"param1": "value1"},
            timeout_seconds=60,
        )

        self.assertEqual(test_case.id, "test_1")
        self.assertEqual(test_case.name, "Basic Test")
        self.assertEqual(test_case.target_domain, "httpbin.org")
        self.assertTrue(test_case.expected_success)
        self.assertEqual(test_case.test_parameters["param1"], "value1")
        self.assertEqual(test_case.timeout_seconds, 60)

    def test_default_validation_criteria(self):
        """Test that default validation criteria are set."""
        test_case = TestCase(
            id="test_1",
            name="Basic Test",
            description="Basic functionality test",
            target_domain="httpbin.org",
            expected_success=True,
        )

        self.assertEqual(
            test_case.validation_criteria, ["http_response", "content_check"]
        )


class TestTestResult(unittest.TestCase):
    """Test cases for TestResult class."""

    def test_test_result_creation(self):
        """Test basic test result creation."""
        result = TestResult(
            attack_id="test_attack",
            test_case_id="test_case_1",
            success=True,
            execution_time_ms=150.5,
            error_message=None,
            metadata={"key": "value"},
        )

        self.assertEqual(result.attack_id, "test_attack")
        self.assertEqual(result.test_case_id, "test_case_1")
        self.assertTrue(result.success)
        self.assertEqual(result.execution_time_ms, 150.5)
        self.assertIsNone(result.error_message)
        self.assertEqual(result.metadata["key"], "value")
        self.assertIsInstance(result.timestamp, datetime)

    def test_test_result_serialization(self):
        """Test test result serialization."""
        result = TestResult(
            attack_id="test_attack",
            test_case_id="test_case_1",
            success=False,
            execution_time_ms=250.0,
            error_message="Test failed",
            metadata={"error_code": 500},
        )

        data = result.to_dict()

        self.assertEqual(data["attack_id"], "test_attack")
        self.assertEqual(data["test_case_id"], "test_case_1")
        self.assertFalse(data["success"])
        self.assertEqual(data["execution_time_ms"], 250.0)
        self.assertEqual(data["error_message"], "Test failed")
        self.assertEqual(data["metadata"]["error_code"], 500)
        self.assertIn("timestamp", data)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
